package main

// sanction.go — LOCAL SANCTION: the user, at their own machine, saying
// "this one is mine".
//
// NO BUILD TAG, on purpose, exactly like agents_parse.go: every judgement in
// here has to be exercised by the one `go test` people actually run, and the
// predicate below is the seam a policy engine will be built on.
//
// ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
//
// This is the harder half of the pitch, and it comes second in the build
// order. The pitch is to identify the good so the bad can be terminated, and
// until this there was no way for a user to say THIS ONE IS MINE. Without
// that, a policy engine's first act is to kill the user's own editor.
// Detection is largely built — four kinds (agents.go:177), origin
// (origin.go), typed evidence (origin.go:53) — and containment is real
// (contain.go). What has been missing is the only input that makes any of it
// safe to act on.
//
// ── TWO MECHANISMS, AND THEY CAN NEVER BE ONE ───────────────────────────────
//
// THE HOST'S TAG. `DelegationToken` (agents.go:203) is read out of the
// process's OWN ENVIRONMENT — `procEnvToken` reads /proc/<pid>/environ for
// PRIVATAE_AGENT_TOKEN (agents_linux.go:149), `ps -E` on darwin
// (agents_darwin.go:192), the PEB on Windows (agents_windows.go:498). An
// environment variable is fixed at exec time by whoever called exec. It can
// mark an agent the HOST LAUNCHED. It can never mark a process that is already
// running, which is every process the user is looking at when they open this
// page.
//
// LOCAL SANCTION is the other half and it cannot use that mechanism at all.
// Nothing here mints a tag, writes to another process, or re-execs anything.
// It records, on this machine, that a person said a program is theirs — and a
// record is the only form this can take, because the thing being marked is
// already running.
//
// ── WHAT IDENTITY A SANCTION IS RECORDED AGAINST ────────────────────────────
//
// agentSanction gets one agentObs (agents.go:166-213) and nothing else, so the
// identity has to be built out of its fields. Taken one at a time:
//
//	PID (agents.go:167)      Worthless. It changes on every exec, and contain.go's
//	                         own header records the shape that makes it worse than
//	                         useless: "An agent under a supervisor comes straight
//	                         back with a new pid." A sanction keyed on a pid is
//	                         void by the next restart.
//	PPID                     The same fact, one level up.
//	Signature (agents.go:180) The TABLE ENTRY that matched (agents.go:34-59) —
//	                         the PRODUCT, not the instance. Stable, and derived
//	                         from the basename of argv[0] (agents_parse.go:47-49),
//	                         so on its own it means "every claude-code on this box
//	                         is mine" and anything that calls itself `claude` is a
//	                         claude-code.
//	Cmdline (agents.go:181)  Stable for one exact invocation and different the
//	                         moment an argument changes. `claude` and
//	                         `claude --resume abc` would be two separate marks.
//	                         That is the shape of control people stop using. Its
//	                         first token — argv[0] — keyed this record before
//	                         the exe identity; see THE FORGERY THIS CLOSES.
//	Exe (agents.go:182-201)  The KERNEL's record of which FILE the process is
//	                         running. The ONLY field in an observation that the
//	                         process did not choose for itself. EMPTY when the
//	                         platform could not read it, and never back-filled.
//	User (agents.go:179)     Coarse alone; load-bearing as a component, because a
//	                         mark must not cross OS accounts on a shared machine.
//	Kind (agents.go:178)     A class, not an identity; load-bearing as a
//	                         component, because "the Claude desktop APP is mine"
//	                         must not quietly also vouch for a claude-code AGENT.
//	Origin, LLMEndpoints,    All vary run to run. An identity built on them would
//	Evidence                 need re-marking whenever the agent talked to a
//	                         different endpoint.
//
// CHOSEN: the four-field tuple (Kind, Signature, Exe, User), fingerprinted.
// The signature stays in the tuple because for an agent that is a SCRIPT the
// kernel's executable is the interpreter, not the agent (see WHAT THIS STILL
// CONCEDES): without the signature, marking one node-hosted agent would vouch
// for every node process the plane observes for that user.
//
// Matched EXACTLY, never normalised. A launcher that spells the same path
// differently (Windows case, a symlink vs its target on macOS) produces a
// different identity and needs its own mark. That is a false NEGATIVE — it shows
// as unsanctioned — and unsanctioned is the safe direction for a wrong answer
// here.
//
// AN OBSERVATION WITH NO KERNEL PATH CANNOT BE MARKED AT ALL. Not "falls back to
// argv[0]", not "matches on the rest of the tuple": addSanction refuses to write
// one and agentSanction answers sanctionWhyNoExe. A fallback would mean the
// forgery below still worked, and would work precisely where this box is most
// blind — a process it cannot read is not a process it may vouch for. The cost
// is real and lands unevenly, so it is named in the platform table below rather
// than discovered later.
//
// ── WHAT EACH PLATFORM ACTUALLY SUPPLIES ────────────────────────────────────
//
//	Linux    /proc/<pid>/exe (agents_linux.go, procExe). A link the KERNEL
//	         maintains from the vnode, resolved: a `#!/bin/bash` script reported
//	         /usr/bin/bash here while its own argv[0] said /bin/bash. Strongest
//	         of the three. Readable for any process of the same user, and for
//	         every process when the bastion runs as root.
//	macOS    The exec path the kernel saved at exec time, read from
//	         KERN_PROCARGS2 (agents_darwin.go, procExe; decoded by
//	         parseProcargs2ExePath). NOT `ps -o comm=`, which three comments in
//	         this tree called the kernel's path and which is argv[0]: Apple's ps
//	         maps comm to just_command (adv_cmds ps/keyword.c:101), and
//	         getproclline (ps/print.c:115) skips the saved exec_path to reach
//	         argv[0]. The saved path is the string PASSED to execve, kept before
//	         namei resolves it (xnu bsd/kern/kern_exec.c exec_save_path), so it
//	         is the path the kernel opened but NOT re-derived from the vnode: a
//	         symlink stays the symlink. Same-user or root only.
//	Windows  QueryFullProcessImageName with PROCESS_QUERY_LIMITED_INFORMATION
//	         (agents_windows.go, winImagePath). NOT Toolhelp32's ExeFile
//	         (origin_windows.go:50), which is a BASENAME with no directory — so
//	         "claude.exe" in %LOCALAPPDATA% and "claude.exe" in %TEMP% were one
//	         string. QUERY_LIMITED is less than the PEB reads need, so a process
//	         whose memory is closed to the bastion can still be marked.
//	other    Empty, always (agents_other.go). That build reports it cannot watch
//	         itself, and now also cannot vouch for anything — which is the honest
//	         pair of statements for a box with no enumerator.
//
// ── WHAT THIS STILL CONCEDES ────────────────────────────────────────────────
//
// The forgery is NOT eliminated. Its price changes, and the price is the claim:
//
//	BEFORE  choose a string. One exec with a chosen argv[0] — free, needs no
//	        access to anything, leaves no trace on disk.
//	AFTER   control a FILE at the sanctioned path. Write access to that exact
//	        path (or to its directory), which for `~/.local/bin/claude` is the
//	        user's own account and for `/usr/local/bin/...` is root.
//
// So an attacker who can already write where the user's agent lives inherits
// the mark, and nothing here pretends otherwise. What it costs them is a
// durable artifact on disk in a place a person can look, instead of a flag on
// one exec.
//
// THREE MORE THINGS IT DOES NOT FIX, each of which has to be said out loud:
//
//   - AN AGENT THAT IS A SCRIPT PINS ITS INTERPRETER, NOT ITSELF. On every
//     platform the kernel's executable for a `#!` script is the interpreter —
//     measured: /usr/bin/bash for a shell script here; macOS stores the shebang
//     line's interpreter explicitly (xnu kern_exec.c, exec_save_path on
//     ip_interp_buffer). For that class the tuple is (agent, <signature>,
//     /usr/bin/node, user), and the only part telling one node-hosted agent
//     from another is the SIGNATURE, which is derived from argv
//     (agents_parse.go:43-68). Interpreter-hosted agents therefore keep an
//     argv-shaped component: the forgery narrows from "any argv[0]" to "that
//     argv[0] AND the same interpreter path", which is a smaller set and not a
//     hard one to enter.
//   - AN EMPTY EXE IS UNMARKABLE, AND A POLICY ENGINE MUST NOT READ THAT AS
//     UNWANTED. sanctionWhyNoExe exists so the two are different answers.
//   - THE PATH IS NOT THE FILE. Nothing here checks that the bytes at that path
//     are the bytes the user vouched for; see THE NEXT RUNG.
//
// Therefore, unchanged in size: **LOCAL SANCTION IS A CONVENIENCE AND VISIBILITY
// CONTROL ON THE USER'S OWN MACHINE. IT IS NOT AN AUTHENTICATION BOUNDARY, AND
// NOTHING DOWNSTREAM MAY TREAT IT AS ONE.** README.md sets the same bar for the
// plane underneath it — the observe plane is "soft and evadable by design:
// visibility and early-warning, never the security wall". This is the same kind
// of thing and the same size of claim.
//
// What it buys, which is not nothing: the UNSANCTIONED SET becomes small enough
// for a person to read, a policy engine gains a way to not kill the user's
// editor on its first run, and the cheapest evasion now needs write access
// somewhere a person can audit.
//
// ── THE FORGERY THIS CLOSES ─────────────────────────────────────────────────
//
// Measured on this box, and it is one line:
//
//	$ bash -c 'exec -a /home/user/.local/bin/claude sleep 25'
//	/proc/<pid>/cmdline  ->  /home/user/.local/bin/claude 25
//	/proc/<pid>/exe      ->  /usr/lib/cargo/bin/coreutils/sleep
//
// Every platform enumerator reads the process's own command line
// (agents_linux.go:41, agents_darwin.go:88, agents_windows.go:374), so while
// argv[0] was in the tuple that process matched a mark made for the real
// claude EXACTLY, without ever touching that file. The test that must never go
// green again is TestAForgedArgv0FromADifferentExecutableIsNotSanctioned.
//
// ── THE NEXT RUNG, NAMED AND NOT BUILT ──────────────────────────────────────
//
// Verify the executable itself rather than its path: Authenticode on Windows
// (WinVerifyTrust), `codesign -v` / the SecStaticCode API on macOS, and on
// Linux no standard equivalent at all — there is no system-wide signature
// scheme for ELF binaries, so it would have to be a hash the user pins.
//
// The tradeoff is the reason it is not here: A CONTENT HASH PINS A VERSION.
// Every legitimate update rewrites the binary, so every update un-sanctions the
// agent, and the user re-marks their editor on a release cadence they do not
// control. That is the same "control they stop using" failure the STORAGE
// section is written around. A signature CHAIN (publisher, not bytes) survives
// updates and is the only version of this worth building — which is why it is
// Windows and macOS first, and why Linux would need something else entirely.
//
// ── THE HOST TAG: THIS BOX CANNOT CHECK IT ──────────────────────────────────
//
// The tag is minted on the HOST as `"del_" + 18 url-safe random bytes`, and
// which tags are live lives in the host's delegations table. The
// reconciliation is explicitly the host's, and its own schema states the rule:
// the bastion observes the tag from the agent's env and reports it; the host
// reconciles, and an observed agent carrying a valid (non-revoked, non-expired)
// tag for its server counts as requested. Nothing in this repo holds a copy of that table; the
// only `del_` in the tree is test fixtures and one comment
// (agents_parse.go:703).
//
// So what this box can check is SHAPE, and the reason string says exactly that
// rather than implying more. A tag whose shape is wrong is NOT sanctioned: a
// real host tag always has the shape, so no real agent is refused by it, and a
// string that is not a host tag is not evidence the host launched anything.
//
// A shape check costs an attacker 24 random characters. It is not a control. It
// is here so the sentence shown to the user can be precise about which of the
// two mechanisms answered.
//
// ── RECORDS WRITTEN BEFORE THIS (v1), AND WHY THEY ARE NOT HONOURED ─────────
//
// A sanctions.json written by the argv[0] version may already be on a machine.
// Every one of those records says "the thing that CALLS ITSELF this is mine",
// which is the sentence this change exists to stop believing. Carrying them
// forward would preserve exactly the forgery being fixed, so:
//
//	NOT MATCHED   A v1 record has no Exe. sanctionRecord.stale() reports that,
//	              matching skips it, and the fingerprint domain moved to
//	              "privatae-sanction-v2" as well — so a v1 key cannot even be
//	              produced by a new observation. Two independent gates, because
//	              one of them being subtly wrong is how this kind of thing
//	              survives a migration.
//	NOT DELETED   It is the user's record of a decision they made. Deleting it
//	              silently would be this program throwing away their state and
//	              telling them nothing. It is kept, shown in its own section of
//	              the page with what it named and WHY it no longer counts, and
//	              the only button on it removes it.
//	RE-MADE, NOT  There is no "upgrade" path that could be honest: the v1 record
//	UPGRADED      holds a string the program chose, and nothing on this machine
//	              can turn that into the file the kernel loaded for a process
//	              that may not even be running. The user marks the live program
//	              again, which is one click on a page they are already on.
//
// The legacy value is retained on the record (sanctionRecord.LegacyArgv0) for
// ONE purpose: so the page can say what the old mark named. It is never an
// input to matching.
//
// ── STORAGE ─────────────────────────────────────────────────────────────────
//
// sanctions.json, beside events.json and the pairing state, in the config dir
// configDir() creates at 0700 (config.go:137-142). Written through atomicWrite
// (ctx.go:133-160 — temp file, chmod 0600, fsync, rename), so a reader never
// sees a half-written blob and a crash mid-write leaves the previous registry
// rather than an empty one.
//
// IT SURVIVES A RESTART, and the restart that matters is this binary's own
// self-update: maybeSelfUpdate replaces the executable and calls os.Exit(0)
// (update.go:127). events.go:35-45 records the same reasoning for the same
// directory. A sanction the user must re-apply after every update is a control
// they stop using, and the moment they stop, the unsanctioned set stops meaning
// anything.
//
// READS CREATE NOTHING. sanctionsPath is built on configDirPath()
// (config.go:129), which resolves the path without creating it — NOT configDir()
// (config.go:137), which is MkdirAll-on-read. agentSanction is a predicate a
// policy engine will call in a loop over every observation, and a predicate that
// creates a directory as a side effect of being asked a question is the exact
// defect ui_approvals_flow_test.go:53-84 exists to stop, which has already been
// written into this codebase twice. The WRITE path creates the directory, via
// atomicWrite's own MkdirAll(0700) at ctx.go:135.
//
// NO IN-MEMORY CACHE. The registry is read from disk on every call. The cheaper
// alternative — a package-level list loaded once, the shape events.go:81-90 uses
// — was rejected on two counts that outweigh the saving, and the saving was
// measured rather than assumed. On this box (go test -bench, EPYC 4345P):
// loadSanctions over a 5-record registry is 4.8µs; scanAgents(), which the
// CALLER must run to produce a single agentObs at all, is 24.2ms. The cache
// would be saving one part in five thousand. What it costs is worse than that:
// package state every test has to reset (events.go:47-57 records the accident
// that shape already caused in this package), and a copy that goes stale the
// moment anything outside this process writes the file.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── the reasons ─────────────────────────────────────────────────────────────

// The `why` a predicate returns is ALWAYS one of these constants. They are the
// stable half of the seam: a policy engine COMPARES (why == sanctionWhyHostTag),
// it never parses the sentence. They are written as sentences because the local
// UI renders them verbatim, and a reason a person cannot read is a reason that
// gets ignored.
//
// The two positive reasons are kept apart because "the host launched it" and
// "you marked it" are different facts and a later policy may want to treat them
// differently — one is an external authority this box cannot check, the other is
// a local record with an audit trail. sanctionWhyBoth exists so that a process
// carrying both does not silently lose one of them: collapsing to either would
// make the other unrecoverable by the caller.
const (
	sanctionWhyHostTag = "The host launched it: this process carries a host-issued " +
		"delegation tag. This machine cannot check whether that tag is still valid — " +
		"only your host can."
	sanctionWhyLocal = "You marked it: someone at this machine recorded this program " +
		"as yours."
	sanctionWhyBoth = "The host launched it — it carries a host-issued delegation tag, " +
		"which only your host can check — and someone at this machine also marked it " +
		"as yours."
	sanctionWhyNone = "Nobody has vouched for this. It carries no host delegation tag, " +
		"and nothing at this machine has marked it as yours."
	sanctionWhyBadTag = "Nobody has vouched for this. It sets PRIVATAE_AGENT_TOKEN to " +
		"something that is not shaped like a tag your host mints, and nothing at this " +
		"machine has marked it as yours."
	// sanctionWhyUnreadable is the one reason that comes back with
	// sanctioned=TRUE without anything having vouched for anything. See
	// agentSanction for why that is the safe direction, and why a caller that
	// RENDERS the verdict has to test for this constant.
	sanctionWhyUnreadable = "Unknown. This machine cannot read its own record of what " +
		"you marked as yours, so it cannot say whether this was vouched for. Nothing " +
		"here may be treated as unvouched until that is fixed."
	// sanctionWhyNoExe (added with the exe identity) is NOT
	// "nobody vouched for this". It is "this machine could not establish what
	// this is", and the two must stay apart for the same reason
	// sanctionWhyUnreadable is its own constant: a caller that terminates
	// things is entitled to treat "I could not identify it" more carefully than
	// "nothing has vouched for it", and it can only do that if the predicate
	// says which one happened. It also tells a UI not to offer a mark button
	// that could only fail.
	sanctionWhyNoExe = "Nobody has vouched for this, and nothing here can. This machine " +
		"could not read which file the process is actually running — the one thing " +
		"about it that cannot be renamed — so there is nothing to mark as yours. Its " +
		"command line is only the name it chose for itself."
)

// ── the host tag's shape ────────────────────────────────────────────────────

// hostTagPrefix and hostTagMinBody are the SHAPE of a tag the host mints:
// `"del_" + 18 url-safe random bytes`, which is 24 base64url characters after
// the prefix.
//
// The check is a FLOOR (16) rather than an equality (24) deliberately. A host
// that changes the entropy or the mint would otherwise make every tagged agent
// on every machine in the fleet read as unsanctioned overnight, and the box
// would be wrong in the direction that gets someone's work killed. 16 is still
// far past anything a person types into a shell by hand, which is the only
// thing this check actually catches.
const (
	hostTagPrefix  = "del_"
	hostTagMinBody = 16
)

// looksLikeHostTag reports whether a delegation tag has the shape the host
// mints. It is NOT validation and nothing here pretends otherwise — see the
// header. The alphabet is base64url, which is what token_urlsafe produces.
func looksLikeHostTag(tok string) bool {
	if !strings.HasPrefix(tok, hostTagPrefix) {
		return false
	}
	body := tok[len(hostTagPrefix):]
	if len(body) < hostTagMinBody {
		return false
	}
	for _, r := range body {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// ── the identity ────────────────────────────────────────────────────────────

// sanctionIdentity is the tuple a local sanction is recorded against. The
// header argues each field; the short version is that this is the most specific
// thing in an agentObs that survives a restart.
type sanctionIdentity struct {
	Kind      string `json:"kind"`
	Signature string `json:"signature"`
	// Exe is the KERNEL's executable path for the process (agents.go, procExe
	// per platform) — the file it is running, not the name it gave itself.
	// EMPTY means this is not an identity: nothing may be marked against it and
	// nothing may match it. The field it replaced was `argv0`, which is why the
	// fingerprint's domain moved to v2.
	Exe  string `json:"exe"`
	User string `json:"user"`
}

// sanctionIdentityOf derives the identity of one observation.
//
// a.Exe is taken VERBATIM. It is deliberately not defaulted, not cleaned up and
// not filled in from a.Cmdline when it is empty: every one of those is the same
// bug wearing a different hat, because the command line is the attacker-chosen
// value this record stopped keying on.
func sanctionIdentityOf(a agentObs) sanctionIdentity {
	return sanctionIdentity{
		Kind:      a.Kind,
		Signature: a.Signature,
		Exe:       a.Exe,
		User:      a.User,
	}
}

// usable reports whether this identity can be marked or matched at all. An
// identity with no kernel path names nothing a later observation could be
// checked against — two different programs the box could not read would share
// it — so it is refused at both ends (addSanction, agentSanction).
func (id sanctionIdentity) usable() bool { return id.Exe != "" }

// fingerprint is the stable id of an identity: the value the UI posts and the
// key the registry is stored under.
//
// A hash rather than the tuple itself, for three reasons that are all about the
// form rather than about secrecy (the record stores the tuple in clear beside
// it): it is fixed-length, it is safe as a map key and a form value with no
// escaping, and a domain prefix means changing the fields cannot silently
// collide with an older record.
//
// THE DOMAIN IS v2 BECAUSE THE THIRD FIELD CHANGED MEANING. v1 hashed argv[0];
// this hashes the kernel's path. Bumping it makes it arithmetically impossible
// for a new observation to land on a v1 key — so the "old marks must not
// silently match" rule holds even if the Exe check below were removed by
// accident. That is the whole reason the prefix was there in the first place.
func (id sanctionIdentity) fingerprint() string {
	sum := sha256.Sum256([]byte("privatae-sanction-v2\x00" + id.Kind + "\x00" +
		id.Signature + "\x00" + id.Exe + "\x00" + id.User))
	return hex.EncodeToString(sum[:16])
}

// describe is the identity in the words the page and the record use. Kept here
// so the page and the audit line can never drift apart.
//
// "run from" rather than "called" on purpose: the value is now the file, and
// the sentence a person reads should say which of the two it is.
func (id sanctionIdentity) describe() string {
	what := id.Signature
	if what == "" {
		what = "an unnamed program"
	}
	if id.Exe != "" {
		what += " run from " + id.Exe
	}
	if id.User != "" {
		what += ", as " + id.User
	}
	return what
}

// ── the record ──────────────────────────────────────────────────────────────

// sanctionBy names the MECHANISM that made a mark, so a record written by a
// later surface (a CLI verb, another page) is distinguishable from this one
// without anybody having to date it.
const sanctionByLocalUI = "local-ui"

// sanctionRecord is one mark. It holds three separate things on purpose:
//
//	the identity     what a future observation is matched against
//	Cmdline          WHAT WAS SANCTIONED, as it looked at the moment of the
//	                 click. Never matched on; it is what lets someone reading
//	                 this record a month later see what the person was actually
//	                 looking at, which the identity alone does not show.
//	By / ByUser / At BY WHOM, HOW and WHEN.
type sanctionRecord struct {
	ID string `json:"id"`
	sanctionIdentity
	Cmdline string    `json:"cmdline,omitempty"`
	At      time.Time `json:"at"`
	By      string    `json:"by"`
	// ByUser is the OS account this program was running as when it wrote the
	// record. It is NOT proof a human did anything — the bastion is commonly
	// root — and it is empty rather than guessed when it cannot be read.
	ByUser string `json:"by_user,omitempty"`
	// LegacyArgv0 decodes the `argv0` field of a v1 record — the identity this
	// registry used before the exe identity. NEVER WRITTEN by this code and never an
	// input to matching; it exists so the page can tell the user what an expired
	// mark named, instead of showing them a record with an empty description and
	// asking them to trust it was theirs. See the header, RECORDS WRITTEN
	// BEFORE THIS.
	LegacyArgv0 string `json:"argv0,omitempty"`
}

// stale reports a record that can no longer vouch for anything: a v1 mark, kept
// for the user to see and remove, keyed on a string the program chose for
// itself. The test is the absence of a kernel path rather than the presence of
// the legacy field, because the property that matters is "there is nothing here
// to check against", which is also true of a hand-edited or truncated record.
func (r sanctionRecord) stale() bool { return !r.usable() }

// describeMark is what the page calls a record. It is NOT the promoted
// describe(): a stale record's path lived in a field the identity no longer
// has, and printing it as "run from …" would state the exact thing this change
// stopped believing. Named rather than shadowing so no call site picks the
// wrong one by accident.
func (r sanctionRecord) describeMark() string {
	if !r.stale() {
		return r.sanctionIdentity.describe()
	}
	what := r.Signature
	if what == "" {
		what = "an unnamed program"
	}
	if r.LegacyArgv0 != "" {
		what += " that called itself " + r.LegacyArgv0
	}
	if r.User != "" {
		what += ", as " + r.User
	}
	return what
}

// sanctionNow is the clock seam, exactly as events.go:89 and
// directive_refusal.go:35 do it: a test pins the timestamp rather than sleeping.
var sanctionNow = time.Now

// sanctionMu serialises read-modify-write. Two POSTs can land at once — the
// page is a browser and a browser will happily send both.
var sanctionMu sync.Mutex

// sanctionsPath is the registry's home. configDirPath(), NOT configDir(): see
// the header. Resolving a path must not create a directory.
func sanctionsPath() (string, error) {
	d, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "sanctions.json"), nil
}

// loadSanctions reads the registry, keyed by fingerprint.
//
// A MISSING FILE IS AN EMPTY REGISTRY AND NOT AN ERROR — that is the ordinary
// state of a machine where nobody has marked anything yet.
//
// AN UNREADABLE OR CORRUPT FILE IS AN ERROR, and this is where it deliberately
// parts company with events.go:128-143, which swallows the same failure. There,
// losing the file loses history. Here, treating an unreadable registry as empty
// would make every marked agent on the machine read as UNSANCTIONED, and the
// thing downstream of this predicate terminates processes. "I could not read it"
// and "there is nothing in it" have to stay different answers.
func loadSanctions() (map[string]sanctionRecord, error) {
	p, err := sanctionsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]sanctionRecord{}, nil
		}
		return nil, err
	}
	var out map[string]sanctionRecord
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if out == nil {
		out = map[string]sanctionRecord{}
	}
	return out, nil
}

// saveSanctionsLocked writes the whole registry. Caller holds sanctionMu.
func saveSanctionsLocked(m map[string]sanctionRecord) error {
	p, err := sanctionsPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b)
}

// sanctionRecords is the registry as a list, newest mark first — the order a
// person reads "what have I vouched for" in.
func sanctionRecords() ([]sanctionRecord, error) {
	m, err := loadSanctions()
	if err != nil {
		return nil, err
	}
	out := make([]sanctionRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At.Equal(out[j].At) {
			return out[i].ID < out[j].ID // a stable page, not a shuffling one
		}
		return out[i].At.After(out[j].At)
	})
	return out, nil
}

// addSanction records one observation as the user's.
//
// IDEMPOTENT, and it keeps the ORIGINAL time: marking something already marked
// returns the existing record untouched. The first mark is the audit fact; a
// second click is not a new decision and must not overwrite when it was made.
//
// IT REFUSES AN OBSERVATION WITH NO KERNEL PATH, with an error the caller shows
// the user. This is the FIRST of the three gates on that rule — refuse the
// write, refuse the match, and a v2 fingerprint domain a v1 key cannot reach —
// and it is the one that keeps the registry itself clean: a record with no Exe
// is a record nothing could ever check, so writing one would only make the
// registry lie about how much has been vouched for.
func addSanction(a agentObs, by string) (sanctionRecord, error) {
	id := sanctionIdentityOf(a)
	if !id.usable() {
		return sanctionRecord{}, errors.New("this machine could not read which file " +
			"that process is running, so there is nothing here that can be marked as " +
			"yours. A command line is a name a program chooses for itself")
	}
	sanctionMu.Lock()
	defer sanctionMu.Unlock()
	m, err := loadSanctions()
	if err != nil {
		return sanctionRecord{}, err
	}
	fp := id.fingerprint()
	if existing, ok := m[fp]; ok {
		return existing, nil
	}
	rec := sanctionRecord{
		ID:               fp,
		sanctionIdentity: id,
		Cmdline:          a.Cmdline,
		At:               sanctionNow().UTC(),
		By:               by,
		ByUser:           currentOSUser(),
	}
	m[fp] = rec
	if err := saveSanctionsLocked(m); err != nil {
		return sanctionRecord{}, err
	}
	return rec, nil
}

// dropSanction removes one mark by id and says whether it was there.
//
// IT TAKES AN ID AND NOTHING ELSE, so a mark can be withdrawn for a program that
// is NO LONGER RUNNING. Requiring a live observation to un-mark would leave every
// record for a program the user has since uninstalled permanently on the machine
// with no way to reach it — which is the accumulation this page exists to prevent.
func dropSanction(id string) (bool, error) {
	sanctionMu.Lock()
	defer sanctionMu.Unlock()
	m, err := loadSanctions()
	if err != nil {
		return false, err
	}
	if _, ok := m[id]; !ok {
		return false, nil
	}
	delete(m, id)
	return true, saveSanctionsLocked(m)
}

// currentOSUser is the account this program is running as, or "" when it cannot
// be read. Never guessed: an empty by_user is an honest "this machine could not
// say", and a made-up one would be worse than no field at all in a record whose
// job is to be auditable.
func currentOSUser() string {
	u, err := user.Current()
	if err != nil || u == nil {
		return ""
	}
	return u.Username
}

// ── the seam ────────────────────────────────────────────────────────────────

// agentSanction reports whether this observation is one the user has
// marked as theirs, and why.
//
// THE CONTRACT, because a policy engine is being built on this:
//
//   - `why` is ALWAYS one of the sanctionWhy* constants above. Compare it;
//     never parse it. It is populated for a false verdict too — "nothing has
//     vouched for this" is the answer the whole product claim is about, and a
//     caller that has to infer it from an empty string will infer wrong.
//   - BOTH mechanisms are accounted for, and a process carrying both comes back
//     as sanctionWhyBoth rather than losing one of them.
//   - The host tag is reported as PRESENT AND WELL-SHAPED, which is all this box
//     can establish (see the header). A caller that needs to know a tag is live
//     must ask the host.
//   - This function creates nothing, writes nothing, and terminates nothing.
//
// AN OBSERVATION WITH NO KERNEL PATH (a.Exe == "") CAN CARRY A HOST TAG BUT CAN
// NEVER CARRY A LOCAL MARK, and the order below says so: the tag is an
// environment variable the host set at exec, which has nothing to do with
// whether this box can read the process's executable, so it is answered first
// and unchanged. Only the LOCAL half depends on the path.
//
// PRECEDENCE for the unsanctioned answers, stated because it is a choice:
// sanctionWhyNoExe outranks sanctionWhyBadTag. A malformed tag is a fact about
// a value this machine READ; no kernel path is a statement that it could not
// identify the program at all, and the second is the more honest headline when
// both are true. It also carries the more useful instruction for a caller —
// "do not offer to mark this, and do not read 'not marked' as 'not wanted'".
//
// WHEN THE REGISTRY CANNOT BE READ it returns (true, sanctionWhyUnreadable), and
// that is the one case where a true verdict does not mean anything vouched for
// anything. The direction is chosen from the asymmetry the whole design rests
// on: a missed rogue agent is a bad day, while a false positive that kills the
// user's own long-running job is the thing they tell other people about. A
// corrupt registry that read as "nothing is
// sanctioned" would hand a policy engine a machine where every process looks
// unvouched-for, which is the one input that turns this whole feature into the
// failure it was built to prevent.
//
// The cost of that choice is that an unreadable registry hides everything, and
// it is worth naming rather than hiding: the file is 0600 in the directory that
// already holds this machine's pairing credentials and TOTP seeds, so anything
// able to corrupt it can already do considerably worse than conceal a process.
// A caller that RENDERS this verdict must test for sanctionWhyUnreadable and say
// so, rather than drawing a tick — ui_approvals_flow_test.go:113-151 is the same
// lesson on the same kind of page: a read that FAILED is not a machine with
// nothing on it.
func agentSanction(a agentObs) (sanctioned bool, why string) {
	tag := a.DelegationToken
	hostTagged := tag != "" && looksLikeHostTag(tag)

	id := sanctionIdentityOf(a)
	if !id.usable() {
		// No local mark can exist for this — addSanction refuses to write one —
		// so the registry has no answer to give and is not even read. That also
		// means an unreadable registry changes nothing here: the verdict would
		// be the same with a perfect one.
		if hostTagged {
			return true, sanctionWhyHostTag
		}
		return false, sanctionWhyNoExe
	}

	m, err := loadSanctions()
	if err != nil {
		return true, sanctionWhyUnreadable
	}
	// The SECOND gate on a v1 record (the first is the v2 fingerprint domain):
	// a record that cannot say which file it vouched for does not vouch, even
	// if its key were somehow reached. Defence in depth against a hand-edited
	// registry, and the property is checked directly rather than inferred.
	rec, found := m[id.fingerprint()]
	marked := found && !rec.stale()

	switch {
	case hostTagged && marked:
		return true, sanctionWhyBoth
	case hostTagged:
		return true, sanctionWhyHostTag
	case marked:
		return true, sanctionWhyLocal
	case tag != "":
		// A tag is set and it is not shaped like one the host mints. Reported
		// as its own reason because it is the one unsanctioned state with
		// something a person can act on in it.
		return false, sanctionWhyBadTag
	}
	return false, sanctionWhyNone
}
