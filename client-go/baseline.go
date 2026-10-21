package main

// baseline.go — `observe:baseline`, the accounting of what is NORMAL on this
// machine.
//
// The rule: "execution outside" means anything that is not in the baseline.
// Taking the baseline is a scan of the machine and an accounting of what is
// there and what it is doing; a new process after the baseline gets flagged.
//
// So the whole detection story rests on one question — "have I seen this
// before?" — and that question is only as good as what counts as "this". A
// fingerprint that is too loose calls a swapped binary the same program; one
// that is too tight calls every restart a new one and buries the real finding
// under noise. Everything in this file exists to get that one comparison right.
//
// NO MODEL ANYWHERE IN THIS PATH. Every rule here is
// deterministic over typed evidence. The host READS the result; it never
// produces it.
//
// WHAT THE FINGERPRINT IS MADE OF, and why each part earns its place:
//
//	exe digest  the CONTENT of the file the kernel opened, not its path. A path
//	            is a name an attacker can reuse: drop a new binary at
//	            /usr/bin/node and a path-keyed baseline says "seen it". The
//	            digest is the one field that changes when the program changes.
//	user        the same binary run by root and by a person are different facts
//	            about this machine, and collapsing them hides a privilege step.
//	unit        what OWNS the process — the systemd unit, the scheduler entry.
//	            This is what makes a restart the SAME entry: pid, start time and
//	            parent pid all change when a service bounces, and none of them
//	            may be in here for that reason.
//	argv shape  the command line with volatile fields masked (below). A worker
//	            that takes a different port or temp path on every start is the
//	            same program; a worker that grows a --load-extension flag is not.
//
// DELIBERATELY ABSENT: pid, ppid, start time. All three change on every
// restart of the same service, and a baseline that churns is a baseline nobody
// reads.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// baselineVersion is the domain prefix of every fingerprint, for the reason
// sanction.go:425-432 gives: a bump makes it arithmetically impossible for an
// entry hashed under new rules to collide with one hashed under the old, so
// "entries from before the change must not silently match" holds even if every
// other guard were removed by accident.
// BUMPED TO v2 BECAUSE THE ENTRIES CHANGED MEANING, not because the
// fingerprint rules did. A v1 accounting on Linux holds no model endpoints for
// any entry — the unfiltered walk never carried them (baselineWalk says why) —
// while a v2 walk does. The fingerprints still match, so nothing here would
// have caught it: every known process talking to a model would have reported
// `proc_changed [llm_endpoint]` at high, on every pass until somebody retook
// the accounting, with a sentence saying it had "started talking to a model"
// that was not true.
//
// The version is the mechanism that already exists for exactly this: the delta
// refuses to compare across it and asks for a retake in one sentence, instead
// of producing a page of findings that are all the same fact about a software
// upgrade (deltarun.go).
const baselineVersion = "privatae-baseline-v2"

// baselineEntry is one thing that was running, or scheduled to run, when the
// accounting was taken.
type baselineEntry struct {
	FP   string `json:"fp"`
	Kind string `json:"kind"` // process | scheduler | listener
	// What the fingerprint was computed from, kept so a later finding can say
	// WHY two things differ instead of only that they do.
	ExeDigest string `json:"exe_digest,omitempty"`
	Exe       string `json:"exe,omitempty"`
	User      string `json:"user,omitempty"`
	Unit      string `json:"unit,omitempty"`
	ArgvShape string `json:"argv_shape,omitempty"`
	// Descriptive, never fingerprinted: these are how a person reads the entry.
	Signature string   `json:"signature,omitempty"`
	Origin    string   `json:"origin,omitempty"`
	Endpoints []string `json:"llm_endpoints,omitempty"`
	// DigestNote says why ExeDigest is empty when it is. An empty digest with
	// no reason reads as "nothing to see"; it is usually "this box could not
	// look", which is a different fact and the person is entitled to it.
	DigestNote string `json:"digest_note,omitempty"`
}

// baselineFile is the accounting as it sits on disk.
type baselineFile struct {
	Version string `json:"version"`
	TakenAt string `json:"taken_at"`
	// Machine is this box's own identity at the moment of the scan: the bastion
	// binary's digest and the mode it was in. A baseline taken by a different
	// binary is a different measurement and says so.
	BastionDigest  string `json:"bastion_digest,omitempty"`
	BastionVersion string `json:"bastion_version,omitempty"`
	Mode           string `json:"mode,omitempty"`
	// Coverage is which truth this file holds: "all-processes" where the
	// platform has an unfiltered walk, "recognised-only" where it does not. A
	// delta computed against a recognised-only baseline can only ever notice
	// recognised things, and whoever reads this is entitled to know which one
	// they have.
	Coverage string          `json:"coverage"`
	Entries  []baselineEntry `json:"entries"`
	// Unreadable counts the processes this box could see but not identify —
	// another user's, a handle it may not open. NOT an error and NOT zero-able:
	// a baseline taken as one user is a smaller truth than one taken as root,
	// and the number is how the reader knows which they are holding.
	Unreadable int `json:"unreadable"`
	// Digest covers every content field, so a baseline that has been edited on
	// disk does not read as the one that was taken. It is the box's own quick
	// integrity check and the key delta-state.json is filed under — NOT the
	// proof of who took the measurement. That is Attestation.
	Digest string `json:"digest"`
	// Attestation is the signature block (baselinesign.go): the accounting
	// signed with the anchor pairing's operator key, whose certificate the host
	// issued and can verify against its CA and this machine's bound fingerprint.
	// nil when nothing on this machine could sign, and UnsignedReason says why —
	// "unsigned" must never be ambiguous between "this build cannot sign" and
	// "this machine had no key that speaks for it".
	Attestation    *baselineAttestation `json:"attestation,omitempty"`
	UnsignedReason string               `json:"unsigned_reason,omitempty"`
}

// ── the fingerprint ─────────────────────────────────────────────────────────

// baselineFP is the stable identity of one entry.
func baselineFP(kind, exeDigest, user, unit, argvShape string) string {
	sum := sha256.Sum256([]byte(baselineVersion + "\x00" + kind + "\x00" +
		exeDigest + "\x00" + user + "\x00" + unit + "\x00" + argvShape))
	return hex.EncodeToString(sum[:16])
}

// ── the argv shape ──────────────────────────────────────────────────────────

// Volatile fields, masked before the command line is fingerprinted. Each of
// these was chosen because it changes between two runs of the SAME program, so
// leaving it in would report a restart as something new.
var (
	// A number on its own: ports, pids, worker indexes, generation counters.
	reBaselineNum = regexp.MustCompile(`\b\d{2,}\b`)
	// Hex runs of 8+: request ids, container ids, socket names, digests.
	reBaselineHex = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	// Anything under a temp root, to the first separator past it.
	reBaselineTmp = regexp.MustCompile(`(?i)(/tmp/|/var/tmp/|/private/var/folders/|\\Temp\\)[^\s]*`)
	// A UUID in any casing.
	reBaselineUUID = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

// baselineArgvShape masks the volatile parts of a command line.
//
// ORDER MATTERS AND IS NOT ARBITRARY: UUID before hex (a UUID's segments are
// hex and would be eaten piecemeal, producing a different shape depending on
// which ran first), temp paths before numbers (a temp path usually contains
// one), hex before numbers (a digest is digits often enough).
func baselineArgvShape(cmdline string) string {
	s := strings.TrimSpace(cmdline)
	if s == "" {
		return ""
	}
	s = reBaselineUUID.ReplaceAllString(s, "<uuid>")
	s = reBaselineTmp.ReplaceAllString(s, "$1<tmp>")
	s = reBaselineHex.ReplaceAllString(s, "<hex>")
	s = reBaselineNum.ReplaceAllString(s, "<n>")
	return strings.Join(strings.Fields(s), " ")
}

// ── the exe digest ──────────────────────────────────────────────────────────

// baselineMaxDigest caps what this will read. A digest is of an executable, and
// an executable larger than this is not one — it is a data file something is
// pointing at, and reading it would turn an accounting pass into an IO storm.
const baselineMaxDigest = 512 << 20

// baselineExeDigest hashes the file the kernel says the process is running.
//
// The empty return is a NOTE, never an error: a box that cannot read another
// user's executable is the ordinary case for an unprivileged scan, and the
// baseline records how much it could see rather than refusing to exist.
func baselineExeDigest(exe string) (digest, note string) {
	if strings.TrimSpace(exe) == "" {
		return "", "the kernel supplied no path for this process"
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return "", "could not be read by this account"
	}
	if !fi.Mode().IsRegular() {
		return "", "is not a regular file"
	}
	if fi.Size() > baselineMaxDigest {
		return "", fmt.Sprintf("is %d bytes, past the %d-byte cap for hashing an executable",
			fi.Size(), int64(baselineMaxDigest))
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", "could not be opened by this account"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "could not be read to the end"
	}
	return hex.EncodeToString(h.Sum(nil)), ""
}

// ── taking the accounting ───────────────────────────────────────────────────

// baselineFromObservations turns one observe pass into baseline entries.
//
// It takes the observations rather than scanning itself, so that the baseline
// and the per-heartbeat report can never disagree about what is running: they
// read the same plane (agents.go scanAgents), and a delta computed against a
// baseline built from a DIFFERENT scanner would be measuring the two scanners
// against each other.
func baselineFromObservations(obs []agentObs, digestOf func(string) (digest, note string)) ([]baselineEntry, int) {
	out := make([]baselineEntry, 0, len(obs))
	unreadable := 0
	seen := map[string]bool{}
	at := map[string]int{} // fingerprint -> index in out
	for _, a := range obs {
		e := baselineEntryOf(a, digestOf)
		if e.ExeDigest == "" {
			unreadable++
		}
		// One ENTRY per distinct fingerprint, not one per pid. Four workers of
		// the same service are one fact about this machine; recording them
		// four times would make a baseline that grows every restart.
		if seen[e.FP] {
			// THE ENDPOINTS OF EVERY PROCESS BEHIND THAT FINGERPRINT, UNIONED.
			// This kept the FIRST pid's and dropped the rest, while the delta's
			// live side unioned them — so four workers of one service, with only
			// the fourth talking to a model, recorded no endpoint at baseline and
			// then reported `proc_changed[llm_endpoint]` at high on an unchanged
			// machine, every pass until the accounting was retaken. Two sides
			// of one comparison have to aggregate the same way or the comparison
			// measures the aggregation.
			if i, ok := at[e.FP]; ok {
				out[i].Endpoints = unionStrings(out[i].Endpoints, e.Endpoints)
			}
			continue
		}
		seen[e.FP] = true
		at[e.FP] = len(out)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FP < out[j].FP })
	return out, unreadable
}

// baselineWalk is the ONE way this plane looks at the machine — the unfiltered
// process walk where the platform has one, the signature-filtered plane where
// it does not, and in both cases with the model endpoints attached.
//
// THE ENDPOINTS WERE MISSING FROM THE UNFILTERED WALK, WHICH MADE THE WHOLE
// MODEL SIGNAL DEAD ON LINUX — the one platform that has the full walk.
// baselineAllProcesses reads /proc for pid, user, argv, exe,
// unit and parent (baseline_all_linux.go:57-70) and nothing else; only
// scanAgents resolves connections to inference endpoints (agents.go:265-277).
// So both sides of every comparison held an empty endpoint list, and the two
// rules that rest on it — `proc_changed[llm_endpoint]`, and "a new process WITH
// a model endpoint is high" — could not fire on the boxes that matter most.
// Measured here: 0 live entries carrying an endpoint, against 4 observations
// that had one.
//
// The endpoints come from the observe plane rather than being re-derived, for
// the reason baselineFromObservations gives about scanners: two planes that
// answer the same question differently turn every comparison into a comparison
// of the planes. Measured cost of the extra pass: 21-23 ms warm.
//
// The error is the walk NOT happening — the filtered plane failed — and it is
// a third answer, not a flavour of the other two: `complete=false` with no
// error means "this platform has no unfiltered walk, the recognised-only plane
// was used", which is a real accounting with a true coverage label. A failed
// walk returned as `complete=false` would have been SAVED under that label
// with every process inside it (baselineCoverage reads only the bool), and a
// later blind pass would then have read the accounting as scope-agreeing and
// closed findings it never looked at (machinestore.go storeScopeAgrees). So
// the callers get the error and refuse: no accounting, no comparison.
//
// baselineAllProcessesFn is the seam a test uses to stand on the
// recognised-only platforms from linux; production never reassigns it.
var baselineAllProcessesFn = baselineAllProcesses

func baselineWalk() ([]agentObs, bool, error) {
	obs, complete := baselineAllProcessesFn()
	if !complete {
		// The filtered plane already carries its own endpoints — it is where
		// they come from — so there is nothing to attach.
		agents, err := scanAgents()
		if err != nil {
			return nil, false, err
		}
		return agents, false, nil
	}
	agents, err := scanAgents()
	if err != nil {
		return nil, false, err
	}
	byPID := map[int][]string{}
	for _, a := range agents {
		if len(a.LLMEndpoints) > 0 {
			byPID[a.PID] = a.LLMEndpoints
		}
	}
	return baselineAttachEndpoints(obs, byPID), true, nil
}

// baselineAttachEndpoints is the join, by pid. Split out so the wiring is
// testable without a machine that happens to be talking to a model right now.
func baselineAttachEndpoints(obs []agentObs, byPID map[int][]string) []agentObs {
	if len(byPID) == 0 {
		return obs
	}
	for i := range obs {
		if eps, ok := byPID[obs[i].PID]; ok {
			obs[i].LLMEndpoints = eps
		}
	}
	return obs
}

// baselineEntryOf turns ONE observation into an entry. It is split out because
// the delta needs the entry for a single process while keeping the pid that
// produced it (delta.go), and the one thing the delta may never do is build its
// entries differently from the accounting it compares them against — a
// fingerprint computed by two functions is a fingerprint that will drift, and
// the whole plane rests on "have I seen this before?" meaning one thing.
//
// The digest function is a parameter for the same reason: the accounting hashes
// every executable fresh, the per-beat delta reads through a cache
// (deltacache.go), and a caller cannot get the ANSWER to differ — only how long
// it took to arrive.
func baselineEntryOf(a agentObs, digestOf func(string) (digest, note string)) baselineEntry {
	digest, note := digestOf(a.Exe)
	shape := baselineArgvShape(a.Cmdline)
	unit := baselineUnitOf(a)
	return baselineEntry{
		FP:         baselineFP("process", digest, a.User, unit, shape),
		Kind:       "process",
		ExeDigest:  digest,
		Exe:        a.Exe,
		User:       a.User,
		Unit:       unit,
		ArgvShape:  shape,
		Signature:  a.Signature,
		Origin:     a.Origin,
		Endpoints:  a.LLMEndpoints,
		DigestNote: note,
	}
}

// baselineUnitOf is what OWNS a process.
//
// THE FIRST VERSION OF THIS COMMENT OVERSTATED THE COST of doing it properly
// and used that to justify not doing it. It said adding the real unit meant
// "a change to the scanners" — true on darwin and windows, where
// procFacts.Unit is never populated, and false on linux, where origin_linux.go
// already reads the cgroup into it and the classifier throws it away
// afterwards. Carrying it onto agentObs was a handful of
// lines, so it is carried.
func baselineUnitOf(a agentObs) string {
	// The REAL owning unit when the platform supplies one. On linux that is the
	// systemd slice/unit read from the process's cgroup — two different
	// services are then told apart by their unit rather than both reading
	// "service" and relying on digest and argv alone.
	if a.Unit != "" {
		return a.Unit
	}
	// Darwin and windows never populate it, so those fall back to HOW the thing
	// started. Weaker, and named as such rather than papered over.
	if a.Origin == "" {
		return "unknown"
	}
	return a.Origin
}

// baselineFromSchedulers turns the standing jobs into baseline entries.
//
// SCHEDULED WORK IS PART OF WHAT IS NORMAL, and leaving it out was a real
// under-scope: the accounting is meant to hold the standing jobs — cron,
// systemd timers, launchd, scheduled tasks, with the command each would run —
// and baselineEntry.Kind has always documented `process | scheduler | listener`
// while only processes were ever recorded. A cron job added after the baseline
// would have been outside the vocabulary the delta compares against — invisible
// to the thing built to notice new work.
//
// A scheduler entry is fingerprinted on what it WOULD RUN, not on a running
// process: there is no pid and usually no exe to digest until it fires. The
// command's argv shape carries the meaning, and the schedule is deliberately
// NOT in the fingerprint — changing WHEN a known job runs is a different event
// from a new job appearing, and the delta should be able to say which.
func baselineFromSchedulers(entries []schedEntry) []baselineEntry {
	out := make([]baselineEntry, 0, len(entries))
	seen := map[string]bool{}
	for _, e := range entries {
		b := baselineEntryOfSched(e)
		if seen[b.FP] {
			continue
		}
		seen[b.FP] = true
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FP < out[j].FP })
	return out
}

// baselineEntryOfSched turns ONE standing job into an entry — split out beside
// baselineEntryOf, and for the same reason: the delta builds the live side from
// it, so the two sides of every comparison come from one constructor.
func baselineEntryOfSched(e schedEntry) baselineEntry {
	// The signature when the command is recognised — a PROPERTY, never a
	// condition for being recorded. An unrecognised standing job is the
	// interesting one.
	if e.Signature == "" {
		if sig, auto, ok := classifySchedCommand(e.Command); ok {
			e.Signature, e.Automation = sig, auto
		}
	}
	shape := baselineArgvShape(e.Command)
	return baselineEntry{
		FP:   baselineFP("scheduler", "", e.User, e.Kind+":"+e.Name, shape),
		Kind: "scheduler", User: e.User,
		Unit: e.Kind + ":" + e.Name, ArgvShape: shape,
		Signature: e.Signature,
		DigestNote: "a scheduled job is recorded by what it would run; there is no " +
			"executable to digest until it fires",
	}
}

// ── the file ────────────────────────────────────────────────────────────────

func baselinePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "baseline.json"), nil
}

// baselineDigestOf covers every field except Digest itself.
func baselineDigestOf(f baselineFile) (string, error) {
	f.Digest = ""
	// The attestation is derived from the content and must not be part of what
	// it attests; the unsigned reason is provenance metadata, not content.
	f.Attestation = nil
	f.UnsignedReason = ""
	b, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(baselineVersion+"\x00"), b...))
	return hex.EncodeToString(sum[:]), nil
}

// baselineIntegrityNote says what a FAILED digest check means, which is not one
// thing.
//
// baselineDigestOf prefixes with the CURRENT baselineVersion, so every file
// taken under older rules recomputes to a different digest — not because
// anything touched it, but because the constant moved. Both places that report
// this said "it has been changed since it was taken", which after the v2 bump
// would have been false on every machine holding an accounting, and alarming in
// the one place a person goes to check whether their machine has been tampered
// with.
//
// One function, so the two call sites cannot drift about it again.
func baselineIntegrityNote(f *baselineFile, digestOK bool) string {
	if f == nil || digestOK {
		return ""
	}
	if f.Version != baselineVersion {
		return "this accounting was taken as " + f.Version + " and this bastion fingerprints " +
			"as " + baselineVersion + ", so its digest cannot match — it needs to be taken " +
			"again. That is the rules moving, NOT evidence that anything edited it"
	}
	return "this file no longer matches its own digest — it has been changed since it was taken"
}

func baselineSave(f baselineFile) error {
	d, err := baselineDigestOf(f)
	if err != nil {
		return err
	}
	f.Digest = d
	// Sign with the key that speaks for this machine, or record exactly why
	// none does — including a pairing that holds no key at all, which is a
	// REASON, not a failure. A signing FAILURE (a key present but unreadable)
	// is an error: the accounting must not be written as unsigned when it was
	// meant to be signed, because the two are indistinguishable to a reader.
	f.Attestation, f.UnsignedReason = nil, ""
	if cfgs, lErr := loadPairings(); lErr != nil {
		f.UnsignedReason = "pairings unreadable: " + lErr.Error()
	} else if signer, why := baselineSignerPairing(cfgs); signer == nil {
		f.UnsignedReason = why
	} else if sErr := baselineSign(&f, signer); sErr != nil {
		return fmt.Errorf("the accounting could not be signed: %w", sErr)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	p, err := baselinePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	// Re-chmod for the reason loadOrCreateUISecret does (uiauth.go:108-111):
	// os.WriteFile applies its mode only on CREATE, so a file written once
	// under a loose umask keeps those permissions for ever.
	_ = os.Chmod(p, 0o600)
	// The store copy is what the host verifies. Written AFTER the state-dir
	// copy so a failure here leaves the machine with a valid accounting and a
	// stale mirror rather than the reverse; the error still surfaces.
	if err := baselineMirror(b); err != nil {
		return fmt.Errorf("the accounting was written but could not be mirrored into the machine store: %w", err)
	}
	return nil
}

// baselineLoad reads the accounting and reports whether it still matches its
// own digest. A mismatch is returned WITH the file rather than instead of it:
// the caller needs to be able to say "this was edited" and still show what it
// says, which is more useful than refusing to open it.
func baselineLoad() (*baselineFile, bool, error) {
	p, err := baselinePath()
	if err != nil {
		return nil, false, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false, err
	}
	var f baselineFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, false, fmt.Errorf("the baseline on this machine cannot be read: %w", err)
	}
	want, err := baselineDigestOf(f)
	if err != nil {
		return nil, false, err
	}
	return &f, want == f.Digest, nil
}

// baselineNarrowNote is what the last collectBaseline could not read. A package
// var rather than a return value because collectBaseline's signature is already
// four values wide and this is for one printer.
var baselineNarrowNote string

// baselineCoverage names which truth a baseline holds, FOR EACH HALF.
//
// One word was not enough: the file read "all-processes" while the scheduler
// half was still recognised-only, which told a reader the opposite of the truth
// about the half that mattered for persistence.
// Four halves, and the two added later report `unsupported` rather than
// `recognised-only`, because that is a different fact. A scheduler half that
// is recognised-only DID look and saw a filtered subset; a listener half on
// macOS did not look at all. A delta against the first can report a narrow
// truth; against the second it must report that it cannot see the class.
func baselineCoverage(allProcs, allSched, listeners, identities bool) string {
	p, s := "recognised-only", "recognised-only"
	if allProcs {
		p = "all"
	}
	if allSched {
		s = "all"
	}
	l, i := "unsupported", "unsupported"
	if listeners {
		l = "all"
	}
	if identities {
		i = "login-shells"
	}
	return "processes=" + p + ",schedulers=" + s + ",listeners=" + l + ",identities=" + i
}

// baselineCoverageRead marks a class `unread` rather than `unsupported` when
// this platform CAN read it and the reader failed while the accounting was
// being taken (`ss` missing or failing, the account database unreadable). The
// two mean different things to whoever reads the line: `unsupported` is a
// platform that never compares the class, and retaking changes nothing;
// `unread` is an accounting that missed a class it could have held, and
// fixing the access and retaking adds it.
func baselineCoverageRead(coverage string, listenersUnread, identitiesUnread bool) string {
	if listenersUnread {
		coverage = strings.Replace(coverage, "listeners=unsupported", "listeners=unread", 1)
	}
	if identitiesUnread {
		coverage = strings.Replace(coverage, "identities=unsupported", "identities=unread", 1)
	}
	return coverage
}

// baselineHasClass answers whether a coverage line says a class was actually
// looked at. deltaPass uses it to decide which classes it may report on, so a
// baseline taken where a reader was blind can never produce "this machine has
// no listeners" out of an absence of entries.
func baselineHasClass(coverage, class string) bool {
	for _, part := range strings.Split(coverage, ",") {
		k, v, ok := strings.Cut(part, "=")
		if ok && k == class {
			return v != "unsupported" && v != "unread" && v != ""
		}
	}
	// A coverage line written before this class existed says nothing about it,
	// which is the case deltaComparableClasses reports: not looked at.
	return false
}

// ── the op ──────────────────────────────────────────────────────────────────

// cmdObserveBaseline takes the accounting and writes it.
//
// ROOT, for the same reason claim-anchor is: a baseline taken by one user
// records only that user's view of the machine, and a detection story built on
// a partial accounting reports every other account's ordinary work as new. The
// refusal names what a non-root run would miss instead of only saying no.
// collectBaseline builds the accounting. Split out of cmdObserveBaseline so a
// test can hold THE WIRING — which source the baseline is built from — and not
// only that two sources differ. A mutation that pointed this back at the
// signature-filtered plane passed a test that compared the two functions
// directly, because nothing exercised the choice between them.
func collectBaseline() (baselineFile, int, int, bool, error) {
	// EVERYTHING, where the platform can walk it. A baseline built from the
	// signature-filtered plane could only ever contain things already
	// recognised as agents, which makes "not baseline" unable to mean the one
	// thing it has to mean (baseline_all_linux.go says the rest).
	obs, complete, err := baselineWalk()
	if err != nil {
		// REFUSED, not taken blind. An accounting built from a walk that did
		// not happen would record nothing as normal and be labelled as if it
		// had looked; the user is told to run it again.
		return baselineFile{}, 0, 0, false, fmt.Errorf("no baseline taken: the process walk "+
			"failed (%v). An accounting from a walk that did not happen would record "+
			"nothing as normal here; run it again", err)
	}
	// Fresh digests, never the delta's cache: taking an accounting is the one
	// act that defines what everything afterwards is compared against, and it
	// happens once per machine. It pays full price on purpose.
	entries, unreadable := baselineFromObservations(obs, baselineExeDigest)
	// THE UNFILTERED INVENTORY, for the same reason the processes are.
	// scanSchedulers() returns matchScheduled(), which keeps only entries that
	// would run a RECOGNISED agent or automation (schedulers.go:387-398).
	// Measured on this box: 68 standing jobs discovered, 0 surviving that
	// filter — so the baseline recorded "0 scheduled jobs" while 68 existed,
	// and a post-baseline cron job running an unrecognised command, which is
	// the canonical persistence move, would never have been compared against
	// anything. Same defect as the process half, in the half that was
	// missed the first time.
	rawSched, schedKinds, schedSupported := platformSchedulers()
	sched := rawSched
	schedScan := schedScanReport{Supported: schedSupported, Kinds: schedKinds,
		Entries: len(rawSched)}
	entries = append(entries, baselineFromSchedulers(sched)...)
	// LISTENERS AND IDENTITIES, the two classes added after the first two. Both go through
	// the same constructors the live scan uses, for the reason
	// deltaCollectLiveFrom gives at length: the one defect this plane has
	// already shipped twice is the accounting and the live scan folding the
	// same observations differently.
	socks, listenersOK, listenerWhy := deltaListenerReader()
	if listenersOK {
		le, _ := baselineFromListeners(socks)
		entries = append(entries, le...)
	}
	ids := deltaIdentityReader()
	if ids.Supported {
		entries = append(entries, baselineFromIdentities(ids.Accounts)...)
	}
	// WHAT THIS ACCOUNTING COULD NOT SEE, SAID WHILE IT IS BEING TAKEN. Only
	// the delta surfaced these, which is the wrong moment: taking the
	// accounting is the act that defines normal, so somebody doing it with
	// sudoers unreadable should be told THEN, not on a later pass.
	var narrow []string
	if !listenersOK && listenerWhy != "" {
		narrow = append(narrow, "listeners: "+listenerWhy)
	}
	if !ids.Supported && ids.Reason != "" {
		narrow = append(narrow, "identities: "+ids.Reason)
	} else if ids.Partial != "" {
		narrow = append(narrow, "identities: "+ids.Partial)
	}
	baselineNarrowNote = strings.Join(narrow, "; ")
	sort.Slice(entries, func(i, j int) bool { return entries[i].FP < entries[j].FP })
	return baselineFile{
		Version:        baselineVersion,
		TakenAt:        time.Now().UTC().Format(time.RFC3339),
		BastionDigest:  selfDigest(),
		BastionVersion: clientVersion,
		Mode:           boxMode(),
		Coverage: baselineCoverageRead(baselineCoverage(complete, schedSupported, listenersOK, ids.Supported),
			!listenersOK && listenersReadableHere, !ids.Supported && identitiesReadableHere),
		Entries:    entries,
		Unreadable: unreadable,
	}, len(obs), len(sched), schedScan.Supported, nil
}

func cmdObserveBaseline(force bool) error {
	if err := requireMachineAuthority("observe:baseline"); err != nil {
		return err
	}
	if prev, ok, err := baselineLoad(); err == nil && !force {
		state := "taken " + prev.TakenAt
		if note := baselineIntegrityNote(prev, ok); note != "" {
			state += " (" + note + ")"
		}
		return fmt.Errorf("this machine already has a baseline, %s, with %d entries.\n"+
			"Taking a new one REPLACES what counts as normal here, so anything added since "+
			"becomes part of the baseline and stops being reported.\n"+
			"Run `privatae-bastion observe:baseline --force` if that is what you mean",
			state, len(prev.Entries))
	}
	f, seen, schedCount, schedOK, err := collectBaseline()
	if err != nil {
		return err
	}
	if err := baselineSave(f); err != nil {
		return err
	}
	what := "every process this account can see"
	if !strings.Contains(f.Coverage, "processes=all") {
		what = "the automated programs this platform's scanner recognises — NOT every " +
			"process, so a program it does not recognise is absent from this baseline " +
			"and a new one will not be reported"
	}
	p, _ := baselinePath()
	fmt.Printf("baseline taken: %d entries from %d observations (%s) and %d scheduled jobs",
		len(f.Entries), seen, what, schedCount)
	if f.Unreadable > 0 {
		fmt.Printf(", %d of them without a readable executable", f.Unreadable)
	}
	if !schedOK {
		fmt.Printf("\n  NOTE: this platform's schedulers could not be read, so standing " +
			"jobs are NOT in this baseline and a new one will not be reported")
	}
	if baselineNarrowNote != "" {
		// BEFORE THE "written to" LINE, because this is the sentence that
		// decides whether the person should take it again.
		fmt.Printf("\nTHIS ACCOUNTING IS NARROWER THAN IT LOOKS: %s\n"+
			"Whatever this machine could not read is not in what it now calls normal,\n"+
			"so a change to it will not be reported. Fix the access and take it again.\n",
			baselineNarrowNote)
	}
	saved, _, lErr := baselineLoad()
	switch {
	case lErr != nil:
		fmt.Printf("\nwritten to %s\n", p)
	case saved.Attestation != nil:
		fmt.Printf("\nwritten to %s, signed by %s's pairing key and mirrored into the machine store\n",
			p, saved.Attestation.SignedBy)
	default:
		fmt.Printf("\nwritten to %s, UNSIGNED: %s\n", p, saved.UnsignedReason)
	}
	return nil
}

// cmdObserveBaselineShow prints what this machine currently calls normal.
func cmdObserveBaselineShow() error {
	f, ok, err := baselineLoad()
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("this machine has no baseline yet — `privatae-bastion observe:baseline` " +
			"takes one (as an administrator)")
	}
	if err != nil {
		return err
	}
	fmt.Printf("baseline taken %s by bastion %s, mode %s\n", f.TakenAt, f.BastionVersion, f.Mode)
	if note := baselineIntegrityNote(f, ok); note != "" {
		fmt.Printf("WARNING: %s\n", note)
	}
	// Provenance, judged the way the host judges it. Three lines a reader can
	// get: verified (and by whom), signed-but-failing (and which test failed),
	// or unsigned (and the reason the file itself records).
	switch {
	case f.Attestation != nil:
		if n := baselineAttestationNote(f); n != "" {
			fmt.Printf("WARNING: attestation: %s\n", n)
		} else {
			fmt.Printf("signed by %s's pairing key; verified against its CA and this machine's fingerprint\n",
				f.Attestation.SignedBy)
		}
	case f.UnsignedReason != "":
		fmt.Printf("unsigned: %s\n", f.UnsignedReason)
	default:
		fmt.Printf("unsigned: taken by a bastion that did not sign accountings\n")
	}
	fmt.Printf("%d entries", len(f.Entries))
	if f.Unreadable > 0 {
		fmt.Printf(", %d without a readable executable (a baseline taken without "+
			"administrator rights sees less)", f.Unreadable)
	}
	fmt.Println()
	for _, e := range f.Entries {
		who := e.Signature
		if who == "" {
			who = "(unnamed)"
		}
		d := e.ExeDigest
		if d == "" {
			d = "no digest: " + e.DigestNote
		} else {
			// shortDigest, not d[:12]. THIS PANICKED on any digest shorter than
			// twelve characters — which a real sha256 never is, and a
			// hand-edited or truncated file very much can be. So the one
			// command for inspecting an accounting you suspect of having been
			// tampered with crashed on exactly the file you would run it
			// against. Found by a test written for something else entirely.
			d = shortDigest(d)
		}
		fmt.Printf("  %s  %-20s %-10s %s\n", e.FP, who, e.User, d)
	}
	return nil
}
