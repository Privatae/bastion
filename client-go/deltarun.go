package main

// deltarun.go — one pass of the detection plane: scan, compare, filter, level,
// remember. And the two places the answer comes out: the operator's own
// `observe:delta`, and the summary line that rides the heartbeat.
//
// WHAT RIDES THE BEAT IS A SUMMARY AND NOT THE FINDINGS, and that is the
// design's staging rather than a shortcut. The counts travel on the beat; the
// findings themselves land in the machine store (machinestore.go), which the
// host reads through `dcn` — searchable, cited by store and path, never pushed
// into a prompt wholesale. `observe:delta` prints the current pass either way.
//
// BOTH HALVES OF THAT ARE NOW BUILT, and this paragraph used to say neither
// was. The host's heartbeat upsert took a fixed list of fields that did not
// include this one, so the summary reached the host's door and no further;
// the host now stores the summary with the heartbeat and narrows it at the
// trust boundary. The store beneath it is
// machinestore.go. Corrected here rather than left standing, because a comment
// that says a shipped thing is missing is how the next reader rebuilds it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// The states of the accounting this box is comparing against. They are reported
// on the beat because a box that CANNOT compare must never read like a box that
// compared and found nothing — the same quiet-versus-blind rule the capability
// list already follows (agents.go:457-464).
const (
	deltaBaselineOK     = "ok"
	deltaBaselineNone   = "none"             // nobody has taken one
	deltaBaselineEdit   = "edited"           // it no longer matches its own digest
	deltaBaselineNoAuth = "not-administered" // this process cannot see the machine the accounting was taken from
	deltaBaselineStale  = "taken-under-older-rules"
)

// deltaReport is one pass, in full.
type deltaReport struct {
	At              string `json:"at"`
	Baseline        string `json:"baseline"`
	BaselineTakenAt string `json:"baseline_taken_at,omitempty"`
	// BaselineDigest is the accounting's own digest (baseline.go:119-122), the
	// same key delta-state.json is filed under. Carried on the report because
	// the machine store's journal needs it per line (machinestore.go): two
	// findings from either side of a retake look comparable and are not, and a
	// `taken_at` cannot tell them apart when a retake produces the same
	// timestamp string. Empty whenever there was nothing to compare against.
	BaselineDigest string `json:"baseline_digest,omitempty"`
	Coverage       string `json:"coverage,omitempty"`
	// Complete is false when this platform has no unfiltered process walk, so
	// only recognised programs were compared. It was already a NOTE on the
	// report; it is a field now because the machine store has to ACT on it —
	// an entry absent from a partial scan must not be journalled as a finding
	// that went away. Carried rather than re-derived so the store and the note
	// can never disagree about the same pass.
	Complete bool `json:"complete"`
	// WalkFailed is why the process walk did not happen this pass. A pass
	// that compared nothing must not be read as scope-agreeing by the store
	// — on a recognised-only platform Complete=false is the NORMAL state and
	// storeScopeAgrees would otherwise close every open finding on it.
	WalkFailed string `json:"walk_failed,omitempty"`
	// Skipped names the entry kinds this pass did not compare (a class the
	// accounting or this pass could not see). The machine store closes no
	// finding of these kinds on this pass: an absence that nothing looked for
	// is not a finding going away.
	Skipped  []string     `json:"skipped,omitempty"`
	Findings []deltaEvent `json:"findings"`
	Filtered []deltaEvent `json:"filtered,omitempty"`
	Critical int          `json:"critical"`
	High     int          `json:"high"`
	Warn     int          `json:"warn"`
	Notice   int          `json:"notice"`
	NewSince string       `json:"new_since,omitempty"`
	// ShortLived is how many came and went during THIS pass; ShortLivedTotal is
	// the running count since the accounting was taken. The design wants the count to
	// ride the beat so a storm of brief processes is visible even though not one
	// of them is a finding.
	ShortLived      int `json:"short_lived"`
	ShortLivedTotal int `json:"short_lived_total"`
	// Scanned and Elapsed are the operator's own numbers: what this cost and
	// how much it looked at.
	Scanned   int      `json:"scanned"`
	Elapsed   string   `json:"elapsed"`
	CacheHits int      `json:"cache_hits"`
	CacheMiss int      `json:"cache_misses"`
	Notes     []string `json:"notes,omitempty"`
}

// deltaSummary is what rides the heartbeat: the counts line, plus the state of the
// accounting it was computed against.
type deltaSummary struct {
	Baseline        string `json:"baseline"`
	BaselineTakenAt string `json:"baseline_taken_at,omitempty"`
	Coverage        string `json:"coverage,omitempty"`
	At              string `json:"at,omitempty"`
	Critical        int    `json:"critical"`
	High            int    `json:"high"`
	Warn            int    `json:"warn"`
	Notice          int    `json:"notice"`
	NewSince        string `json:"new_since,omitempty"`
	ShortLived      int    `json:"short_lived"`
	Filtered        int    `json:"filtered"`
	Note            string `json:"note,omitempty"`
	// WalkFailed: the process walk did not happen this pass, so the zero
	// counts above mean "nothing looked", not "nothing differs". Its own key
	// — the host's reading of a summary is an allowlist on `baseline`, and a
	// failed walk buried in `note` still read as clean.
	WalkFailed string `json:"walk_failed,omitempty"`
	// Skipped: the entry kinds this pass did not compare. Zero counts say
	// nothing about them, so the host must not read the pass as clean; a
	// machine whose only finding is a listener read as clean on every pass
	// where `ss` failed.
	Skipped []string `json:"skipped,omitempty"`
}

func (r deltaReport) summary() deltaSummary {
	return deltaSummary{
		Baseline: r.Baseline, BaselineTakenAt: r.BaselineTakenAt, Coverage: r.Coverage,
		At: r.At, Critical: r.Critical, High: r.High, Warn: r.Warn, Notice: r.Notice,
		NewSince: r.NewSince, ShortLived: r.ShortLived, Filtered: len(r.Filtered),
		Note: strings.Join(r.Notes, "; "), WalkFailed: r.WalkFailed, Skipped: r.Skipped,
	}
}

// ── the live side ───────────────────────────────────────────────────────────

// deltaSight is what each reader said on THE PASS THAT BUILT THE LIVE ENTRIES.
//
// It exists because the guard used to call both readers a SECOND time and
// decide comparability from that answer. Both directions of
// a flip between the two reads were harmful and silent: a first read that
// failed and a second that worked reported every listener gone, and a first
// read that worked and a second that failed DISCARDED a real observed finding —
// measured, a live backdoor on tcp/0.0.0.0:4444 produced zero findings under a
// note saying the table could not be read, when it had been read.
//
// It also halves the work: two full identity scans a minute — every login
// account's authorized_keys, /etc/sudoers, /etc/sudoers.d/*, /etc/group — became
// one.
type deltaSight struct {
	Listeners  bool
	Identities bool
	// Notes is what a reader said about a half it could see only PARTLY — sudo
	// rules it could not open, an AuthorizedKeysFile pointing somewhere it did
	// not look. THIS FIELD EXISTS BECAUSE THE READER'S OWN `Partial` WAS SET
	// AND READ NOWHERE: the class silently went
	// narrow and the pass reported a confident answer over it. A narrowed class
	// is not a blind one — the entries it did produce are real and are still
	// compared — but the person is entitled to know the answer covers less than
	// it looks.
	Notes []string
}

// deltaCollectLive builds the live entries the same way the accounting was
// built — same walk, same fallback, same constructors — while keeping the pids
// the accounting deliberately throws away.
//
// walkErr is the filtered plane failing this pass: live is then empty and
// deltaPass compares nothing — an empty live set against the accounting would
// read every entry as gone.
func deltaCollectLive(digestOf func(string) (string, string)) (live []deltaLiveEntry, scanned int, complete bool, sight deltaSight, walkErr error) {
	obs, complete, walkErr := baselineWalk()
	live, scanned, _ = deltaCollectLiveFrom(obs, digestOf)
	rawSched, _, schedSupported := platformSchedulers()
	if schedSupported {
		seen := map[string]bool{}
		for _, s := range rawSched {
			e := baselineEntryOfSched(s)
			if seen[e.FP] {
				continue
			}
			seen[e.FP] = true
			live = append(live, deltaLiveEntry{Entry: e})
		}
	}
	// The same two classes the accounting takes, through the same constructors.
	// Guarded on the reader being able to look: an unreadable socket
	// table must produce NO listener entries rather than an empty set, because
	// an empty set here would report every listener on the box as gone.
	if socks, ok, _ := deltaListenerReader(); ok {
		sight.Listeners = true
		le, pids := baselineFromListeners(socks)
		for i, e := range le {
			live = append(live, deltaLiveEntry{Entry: e, PIDs: pids[i]})
		}
	}
	if ids := deltaIdentityReader(); ids.Supported {
		sight.Identities = true
		if ids.Partial != "" {
			sight.Notes = append(sight.Notes, ids.Partial)
		}
		for _, e := range baselineFromIdentities(ids.Accounts) {
			live = append(live, deltaLiveEntry{Entry: e})
		}
	}
	return live, scanned, complete, sight, walkErr
}

// deltaCollectLiveFrom is the aggregation, over observations already in hand.
// Split out so a test can hand it the same list the accounting gets and check
// the two sides fold it the same way — which is exactly where they drifted.
func deltaCollectLiveFrom(obs []agentObs, digestOf func(string) (string, string)) (live []deltaLiveEntry, scanned int, complete bool) {
	byFP := map[string]int{} // fp -> index in live
	for _, a := range obs {
		e := baselineEntryOf(a, digestOf)
		if i, seen := byFP[e.FP]; seen {
			live[i].PIDs = append(live[i].PIDs, a.PID)
			// The endpoints of every process behind one fingerprint, unioned:
			// four workers of a service are one entry, and if the fourth is the
			// one talking to a model that fact belongs on the entry. The
			// accounting folds them the same way (baseline.go) — it did not,
			// and the drift reported an unchanged machine as changed.
			live[i].Entry.Endpoints = unionStrings(live[i].Entry.Endpoints, e.Endpoints)
			continue
		}
		byFP[e.FP] = len(live)
		live = append(live, deltaLiveEntry{Entry: e, PIDs: []int{a.PID}})
	}
	return live, len(obs), true
}

func unionStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	have := map[string]bool{}
	for _, s := range a {
		have[s] = true
	}
	for _, s := range b {
		if !have[s] {
			have[s] = true
			a = append(a, s)
		}
	}
	sort.Strings(a)
	return a
}

// ── the pass ────────────────────────────────────────────────────────────────

// Who is running the pass. It decides ONE thing — whether what this binary sees
// of the bastion on disk is written into the shared bookkeeping — and it exists
// because an operator running `observe:delta` from a copy of the binary
// somewhere else would otherwise record THAT copy's digest as what the machine
// last saw, and the daemon's next pass would report a swap that never
// happened. A dev-box hazard rather than a fleet one, and a
// detection plane that can be made to cry wolf by a debugging command is not
// one anybody keeps reading.
type deltaRole int

const (
	deltaRoleDaemon deltaRole = iota
	deltaRoleOperator
)

// deltaPass runs the whole thing once. The cache is the caller's, so the
// daemon's repeated passes share one and a single CLI run gets a cold one.
func deltaPass(dc *digestCache, now time.Time, role deltaRole) deltaReport {
	started := time.Now()
	r := deltaReport{At: stamp(now), Notes: []string{deltaPolicyIsNotSigned}}
	// WITHOUT MACHINE AUTHORITY THE COMPARISON IS NOT WRONG, IT IS MEANINGLESS.
	// The accounting is taken as an administrator (baseline.go:410-413); a pass
	// run as somebody else cannot read most executables, digests them as empty,
	// and would report nearly every process on the box as changed. Saying which
	// it is beats producing a page of false findings.
	if !processIsRoot() {
		r.Baseline = deltaBaselineNoAuth
		r.Notes = append(r.Notes, "this process does not administer the machine, so it cannot see what the accounting saw")
		return r
	}
	base, digestOK, err := baselineLoad()
	if err != nil || base == nil {
		r.Baseline = deltaBaselineNone
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			r.Notes = append(r.Notes, "the accounting on this machine could not be read: "+err.Error())
		}
		return r
	}
	r.Baseline, r.BaselineTakenAt, r.Coverage = deltaBaselineOK, base.TakenAt, base.Coverage
	r.BaselineDigest = base.Digest
	// The attestation, judged the way the host will. A failed signature does
	// not stop the comparison — the digest check above already said whether the
	// content moved — but it rides the notes, and so the beat, because "the
	// accounting on this machine is not this machine's word" is something the
	// host must hear from the box itself rather than discover on a read.
	if n := baselineAttestationNote(base); n != "" {
		r.Notes = append(r.Notes, "attestation: "+n)
	}
	// AN ACCOUNTING TAKEN UNDER OTHER RULES IS NOT COMPARABLE, AND COMPARING IT
	// ANYWAY IS THE LOUDEST WAY TO FAIL. baselineVersion is the domain prefix of
	// every fingerprint (baseline.go:55-60), bumped precisely so entries hashed
	// under old rules cannot collide with new ones — which means that the first
	// pass after such a bump would otherwise report EVERY process on the box as
	// new. One sentence asking for a retake beats 188 findings that are all the
	// same fact about a software upgrade.
	if base.Version != baselineVersion {
		r.Baseline = deltaBaselineStale
		r.Notes = append(r.Notes, "this accounting was taken as "+base.Version+
			" and this bastion fingerprints as "+baselineVersion+
			" — nothing can be compared until it is taken again")
		return r
	}
	if !digestOK {
		r.Baseline = deltaBaselineEdit
		r.Notes = append(r.Notes, "the accounting no longer matches its own digest — it has been changed since it was taken")
	}
	st := deltaStateLoad(base.Digest)
	live, scanned, complete, sight, walkErr := deltaCollectLive(dc.digest)
	r.Scanned, r.Complete = scanned, complete
	var events []deltaEvent
	if walkErr != nil {
		// Not compared, and said so: a pass that could not walk the machine
		// compares nothing, carries WalkFailed so the store closes nothing on
		// it (Complete=false alone is not that guard — see storeScopeAgrees),
		// and the note names the cause rather than blaming the platform.
		r.WalkFailed = walkErr.Error()
		r.Notes = append(r.Notes, "the process walk failed this pass ("+walkErr.Error()+
			"), so nothing was compared — not processes, scheduled jobs, listeners or "+
			"accounts — this is a pass "+
			"that could not look, not a quiet one")
	} else {
		if !complete {
			r.Notes = append(r.Notes, "this platform has no unfiltered process walk, so only programs the scanner recognises were compared")
		}
		// A CLASS IS COMPARED ONLY WHERE BOTH SIDES COULD LOOK, and this is
		// the guard that keeps adding classes from becoming a flood of false
		// findings on the machines least able to check them.
		//
		// The two failure shapes it closes, both reachable:
		//
		//	baseline blind, live sighted   a box whose accounting was taken
		//	                               before `ss` was installed. Every
		//	                               listener on it compares against
		//	                               nothing and comes out as
		//	                               `listener_new` — on a machine where
		//	                               nothing changed.
		//	baseline sighted, live blind   `ss` removed, a home directory that
		//	                               can no longer be read, a pass that
		//	                               lost machine authority. The live side
		//	                               produces no entries of that class and
		//	                               EVERY ONE in the accounting comes out
		//	                               `_gone`.
		//
		// The second is the worse of the two, because "the listeners all
		// stopped" reads as an incident rather than as a blindfold. Both are
		// the same bug: comparing a class against a side that did not measure it.
		r.Notes = append(r.Notes, sight.Notes...)
		accounting := base.Entries
		base.Entries, live, r.Notes, r.Skipped = deltaComparableClasses(base, live, sight, r.Notes)
		st.setBlind(r.Skipped, accounting)
		events = deltaCompare(base.Entries, live)
	}
	// The bastion's own binary, read from DISK on every pass — see
	// deltaSelfOnDisk for why selfDigest() cannot answer this — and compared
	// against what the last pass saw rather than against the accounting.
	wasDigest, wasVersion := st.BastionDigest, st.BastionVersion
	if wasDigest == "" {
		wasDigest, wasVersion = base.BastionDigest, base.BastionVersion
	}
	nowDigest := deltaSelfOnDisk(dc)
	// A BOX THAT CANNOT READ ITS OWN BINARY MUST NOT READ LIKE ONE THAT CHECKED.
	// An empty digest here — the executable deleted from under the daemon, or
	// resolvedSelf failing at start — produces no event, and silence is
	// indistinguishable from "checked, unchanged". It is the same
	// quiet-versus-blind rule this file's own header applies to the accounting.
	if nowDigest == "" {
		r.Notes = append(r.Notes, "this bastion could not read its own binary, so nothing "+
			"here says whether it has been replaced")
	}
	ev := deltaBinaryEvent(wasDigest, wasVersion, nowDigest, clientVersion)
	if ev != nil {
		events = append(events, *ev)
	}
	// A SWAP IS NOT ABSORBED BY HAVING BEEN REPORTED ONCE.
	//
	// This advanced unconditionally, which meant the pass that reported the
	// swap also recorded the swapped binary as the new normal — so the next
	// pass compared equal and the critical was gone. One beat, into a
	// summary the host does not store yet, and an
	// operator running `observe:delta` an hour later read "nothing on this
	// machine is outside what was accounted for". Before the fix the swap was
	// invisible until a restart; after it, visible for sixty seconds and then
	// nowhere. The second is worse, because it looks like it works.
	//
	// So the pair moves forward only when there is nothing to report or the
	// change was the update. A same-version change then repeats on every pass,
	// which is what the design means by a finding being pinned until a human resolves
	// it — and the pin's real lifetime is "until a retake, the next version
	// change, or the loss of delta-state.json", not the retake alone. The last
	// two clear it: measured, a pass with the state removed re-reads the swap as
	// an update against the accounting's older version and then goes quiet.
	// Inside the accepted threat model, since a root
	// intruder can also stop the daemon; said out loud in deltastate.go because
	// that file is now load-bearing and used to describe itself as disposable.
	//
	// Named, because it is the one case this gets wrong: a pass landing in the
	// milliseconds between replaceSelf and the relaunch (update.go:117-127)
	// sees the new binary under the OLD version and calls it a swap. It is one
	// beat, self-correcting — the restarted process reports the update at high
	// on its next pass — and the alternative is machinery that would have to
	// know an update is in flight to suppress the one finding here that must
	// never be suppressed by a flag anything could set.
	if nowDigest != "" && role == deltaRoleDaemon && (ev == nil || ev.Reason == deltaReasonVersionAlso) {
		st.setBastion(nowDigest, clientVersion)
	}
	// A pass that walked nothing must not touch the clocks either: grace
	// (keepMissing) and the noise filter (settleHeld) both read "absent from
	// this pass" as "came back" / "settled", which on an empty pass wipes
	// every gone-clock and every hold — a walk that fails once inside the
	// grace window would then keep a real disappearance from ever maturing,
	// and the pass would count settled holds as short-lived processes it never
	// saw. The binary rung's event is the only one such a pass can carry.
	var findings []deltaEvent
	var filtered []deltaEvent
	if walkErr != nil {
		findings = events
	} else {
		events = deltaApplyGrace(events, st, now)
		findings, filtered = deltaFilter(events, deltaNoiseFor(events, base, live), st, now)
	}
	for i := range findings {
		// deltaBinaryEvent has already levelled itself, where the version
		// comparison that decides high-or-critical is actually made.
		if findings[i].Level == "" {
			findings[i].Level = deltaLevel(findings[i])
		}
		if findings[i].FirstSeen == "" {
			findings[i].FirstSeen = stamp(st.seen(findings[i].FP, now))
		}
		st.noteKind(findings[i].FP, findings[i].Entry.Kind)
	}
	r.Findings, r.Filtered = findings, filtered
	r.tally()
	r.ShortLived = st.settledThisPass
	r.ShortLivedTotal = st.ShortLived
	// The prune reads LastSeen stamps a failed walk never refreshed; days of
	// failed walks would otherwise forget every hold and first-seen silently.
	if walkErr == nil {
		st.prune(now)
	}
	if err := st.save(); err != nil {
		r.Notes = append(r.Notes, "the delta's own bookkeeping could not be written: "+err.Error())
	}
	r.CacheHits, r.CacheMiss, _ = dc.stats()
	r.Elapsed = time.Since(started).Round(time.Millisecond).String()
	return r
}

// deltaSelfOnDisk digests the bastion binary AT ITS PATH, every pass.
//
// selfDigest() cannot answer this, and the reason is easy to miss.
// It is a sync.Once (enforcing.go:35-38): computed on the first beat and frozen
// for the life of the process. A daemon whose on-disk binary is replaced goes
// on comparing its own startup digest to the accounting for ever — so the one
// process in a position to notice the swap is the one that cannot.
//
// Re-reading os.Executable() each pass does not fix it either. A running binary
// cannot be overwritten in place on Linux (ETXTBSY), so replaceSelf renames it
// aside and writes the new one at the original path (update.go:160-169) — and
// /proc/self/exe follows the INODE, which means after a swap it resolves to
// <path>.old. The running image would hash itself and report no change.
//
// So the PATH is captured once, before any swap can have happened, and it is
// the path that gets digested from then on. Through the delta's cache, which is
// keyed on the inode and its change time (deltacache.go): a rename-aside puts a
// new inode at that path, so the swap cannot be served from cache.
// A package-level initialiser rather than a sync.Once, and the difference is
// the whole point: this runs at program start, which is unambiguously before
// any self-update could have moved the binary. A lazy capture would be "before
// the first pass", which is nearly always the same moment and is not the same
// guarantee. It is also a plain var, so a test can point it at a fixture.
var deltaSelfPath = func() string {
	p, err := resolvedSelf()
	if err != nil {
		return ""
	}
	return p
}()

func deltaSelfOnDisk(dc *digestCache) string {
	if deltaSelfPath == "" {
		return ""
	}
	d, _ := dc.digest(deltaSelfPath)
	return d
}

// deltaNoiseFor gathers the live-machine facts the noise filter needs, and gathers ONLY what
// this pass will actually ask about: in steady state there are no new or
// changed processes, and then neither the socket table nor the package database
// is read at all.
// deltaAgeFn is the process-age reader the noise filter uses; a seam so a test
// can say how old a process is without depending on the age of a real one.
var deltaAgeFn = deltaAgeReader

func deltaNoiseFor(events []deltaEvent, base *baselineFile, live []deltaLiveEntry) deltaNoise {
	n := deltaNoise{Self: os.Getpid(), Age: deltaAgeFn()}
	candidates := false
	for _, ev := range events {
		if ev.Kind == deltaProcNew || ev.Kind == deltaProcChanged {
			candidates = true
			break
		}
	}
	if !candidates {
		return n
	}
	n.Parents = processTree()
	n.Packaged = deltaPackagedFn()
	n.Listening, n.Sockets = deltaListeningPIDs()
	// The pids whose OWN entry is in the accounting — what "parent is a
	// baseline entry" is asked against.
	inBase := map[string]bool{}
	for _, e := range base.Entries {
		inBase[e.FP] = true
	}
	n.BaselinePIDs = map[int]bool{}
	for _, l := range live {
		// Accounted PROCESSES only. A listener's identity is its bind point and
		// the holder's chosen name, so a replaced program holding an accounted
		// port would otherwise make its own children read as "started by
		// something the accounting already holds".
		if l.Entry.Kind != "process" || !inBase[l.Entry.FP] {
			continue
		}
		for _, pid := range l.PIDs {
			n.BaselinePIDs[pid] = true
		}
	}
	return n
}

func (r *deltaReport) tally() {
	earliest := ""
	for _, ev := range r.Findings {
		switch ev.Level {
		case deltaCritical:
			r.Critical++
		case deltaHigh:
			r.High++
		case deltaWarn:
			r.Warn++
		default:
			r.Notice++
		}
		if ev.FirstSeen != "" && (earliest == "" || ev.FirstSeen < earliest) {
			earliest = ev.FirstSeen
		}
	}
	r.NewSince = earliest
}

// ── the cadence ─────────────────────────────────────────────────────────────

// deltaRefreshEvery matches the heartbeat (run.go:596) because the design asks for the
// delta "every heartbeat", and the cache in deltacache.go is what buys that.
//
// MEASURED on a live machine, 195 live processes: the first pass
// costs 839 ms, and every pass after it 251-262 ms with no further hashing —
// 47 distinct executables served 195 processes, and after the first pass the
// cache answered all of them. At a minute apart that is under half a percent of
// one core, for a machine-wide comparison. Without the cache every pass pays
// the first one's price for ever.
//
// It runs on its own goroutine, like the host posture (observe_ops.go:821-823)
// and for the same reason — a beat reads the last value and never waits on a
// scan, because a late beat is what flips this box stale on the host.
const deltaRefreshEvery = 60 * time.Second

var (
	deltaMu      sync.Mutex
	deltaLast    *deltaSummary
	deltaAt      time.Time
	deltaRan     bool
	deltaRunning bool
	deltaCache   = &digestCache{}
)

func deltaPayload() *deltaSummary {
	deltaMu.Lock()
	defer deltaMu.Unlock()
	return deltaLast
}

// refreshDelta runs one pass and publishes it, skipping one another goroutine
// has just done.
//
// ONE REFRESHER IS STARTED PER PAIRING — run.go starts it beside the heartbeat,
// and a box serving three hosts runs three heartbeats — so without this a
// three-host machine ran three full passes a minute, three read-modify-writers
// of one delta-state.json, and a short-lived "next pass" that arrived three
// times sooner, which made whether a 40-second process was counted or reported
// depend on how many hosts the box serves. The sibling
// scan documents exactly this shape and guards for it
// (otherbastions.go:356-361); this one did not.
//
// A plain sync.Once would be wrong for the reason given there: the refreshers
// are tied to their pairing's context, so the first one cancelled would take
// the pass down for the whole box.
// THE IN-FLIGHT FLAG IS THE HALF THAT MATTERS, because the refreshers do not
// arrive staggered — run.go starts every active pairing in one loop and each
// calls this immediately, so they arrive together and their tickers stay in
// phase for ever after. A freshness check alone lets all of them past, since
// none has finished yet: measured with three phase-aligned refreshers against a
// cold cache, 124 digest misses against 45 for a single pass — three concurrent
// walks of the machine, and three writers of one state file. The flag is
// what makes the second and third return at once.
func refreshDelta() {
	deltaMu.Lock()
	if deltaRunning || (deltaRan && time.Since(deltaAt) < deltaRefreshEvery/2) {
		deltaMu.Unlock()
		return
	}
	deltaRunning = true
	deltaMu.Unlock()
	defer func() {
		deltaMu.Lock()
		deltaRunning = false
		deltaMu.Unlock()
	}()
	now := time.Now()
	r := deltaPass(deltaCache, now, deltaRoleDaemon)
	// The journal, before the summary is published. A store write that fails
	// must not stop the counts reaching the host — a box whose disk is full
	// still says how many findings it has — so the failure becomes a NOTE on
	// this pass rather than an early return.
	//
	// A note and not a log line, deliberately. run.go's logf is a per-pairing
	// closure (run.go:309) and this pass is box-wide, so it has no host to
	// prefix; more to the point a log line on the machine is invisible to the
	// host, and "the record of what happened here stopped being written" is
	// precisely the thing the host must not learn by noticing an absence.
	// Notes ride the beat (deltaSummary.Note).
	if _, err := storeRecordPass(r, now); err != nil {
		r.Notes = append(r.Notes,
			"this machine's own record of its findings could not be written: "+err.Error())
	}
	s := r.summary()
	deltaMu.Lock()
	deltaLast, deltaAt, deltaRan = &s, time.Now(), true
	deltaMu.Unlock()
}

func runDeltaRefresh(ctx context.Context) {
	refreshDelta()
	storeSweepIfDue(time.Now())
	t := time.NewTicker(deltaRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refreshDelta()
			// Retention rides the pass that is already running rather than a
			// timer of its own. A separate ticker would be a second thing to
			// start, and on a laptop that is asleep more than it is awake a
			// daily ticker fires on uptime rather than on days — storeSweepIfDue
			// compares wall-clock dates, so a box woken after a fortnight sweeps
			// once on the next pass instead of never.
			storeSweepIfDue(time.Now())
		}
	}
}

// ── the operator's own eyes ─────────────────────────────────────────────────

func cmdObserveDelta(asJSON bool) error {
	if err := requireMachineAuthority("observe:delta"); err != nil {
		return err
	}
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	if asJSON {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	switch r.Baseline {
	case deltaBaselineNone:
		return errors.New("this machine has no accounting to compare against — " +
			"`privatae-bastion observe:baseline` takes one (as an administrator)")
	case deltaBaselineEdit:
		fmt.Printf("WARNING: the accounting has been changed since it was taken — " +
			"what follows is measured against an edited file\n")
	}
	fmt.Printf("%d findings against the accounting taken %s (%s), from %d processes in %s\n",
		len(r.Findings), r.BaselineTakenAt, r.Coverage, r.Scanned, r.Elapsed)
	switch {
	case r.WalkFailed != "" && len(r.Findings) > 0:
		// The binary rung read the disk; everything else did not happen. Said
		// so that the finding below is not discounted by "nothing was compared".
		fmt.Printf("the process walk failed this pass (%s): only the bastion-binary check ran — "+
			"the finding(s) below are real; nothing else was compared\n", r.WalkFailed)
	case r.WalkFailed != "":
		// The one sentence a failed walk must never print is the all-clear.
		fmt.Printf("NOTHING WAS COMPARED: the process walk failed this pass (%s) — "+
			"the zero above means nothing looked, not that nothing differs\n", r.WalkFailed)
	case len(r.Findings) == 0:
		fmt.Printf("nothing on this machine is outside what was accounted for\n")
	}
	for _, ev := range r.Findings {
		fmt.Printf("  %-8s %-20s %s\n", ev.Level, ev.Kind, deltaOneLine(ev))
		for _, e := range ev.Evidence {
			fmt.Printf("           %-12s %s\n", e.Tier, e.Signal+": "+e.Value)
		}
	}
	if r.ShortLived > 0 || len(r.Filtered) > 0 {
		fmt.Printf("%d filtered as ordinary (%d came and went before they were old enough to report; %d since the accounting)\n",
			len(r.Filtered), r.ShortLived, r.ShortLivedTotal)
	}
	for _, n := range r.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	return nil
}

// deltaOneLine is how a finding reads to a person: what it is, who runs it, and
// where it runs from — never a fingerprint on its own, which names nothing.
func deltaOneLine(ev deltaEvent) string {
	// THE TWO ADDED CLASSES READ AS PROGRAMS OTHERWISE, and one of them read
	// very badly: an identity_new printed its raw fingerprinted state blob as
	// the subject — "shell=/bin/bash;uid=1010;sudo=false;keys=1;keydigest=k as
	// intern under intern" — with the account name twice and an account called
	// a program by the evidence line. These are not processes
	// and the sentence now says what they are.
	switch ev.Entry.Kind {
	case "identity":
		s := "account " + ev.Entry.Unit
		if sudo, known := ev.Entry.identitySudo(); known && sudo {
			s += " (holds sudo)"
		} else if !known {
			s += " (sudo rights unread)"
		}
		if ev.Reason != "" {
			s += " [" + ev.Reason + "]"
		}
		return s
	case "listener":
		holder := ev.Entry.ArgvShape
		if holder == "" {
			holder = "(unnamed)"
		}
		s := "listening on " + ev.Entry.Unit + ", held by " + holder
		if ev.Reason != "" {
			s += " [" + ev.Reason + "]"
		}
		if len(ev.PIDs) > 0 {
			s += fmt.Sprintf(" (pid %v)", ev.PIDs)
		}
		return s
	}
	who := ev.Entry.Signature
	if who == "" {
		who = ev.Entry.Exe
	}
	if who == "" {
		who = ev.Entry.ArgvShape
	}
	if who == "" {
		who = "(unnamed)"
	}
	s := who
	if ev.Entry.User != "" {
		s += " as " + ev.Entry.User
	}
	// "under unknown" is the fallback baselineUnitOf writes when the platform
	// supplies neither a unit nor an origin, and printing it tells the reader
	// nothing while looking like it does.
	if ev.Entry.Unit != "" && ev.Entry.Unit != "unknown" {
		s += " under " + ev.Entry.Unit
	}
	if ev.Reason != "" {
		s += " [" + ev.Reason + "]"
	}
	if len(ev.PIDs) > 0 {
		s += fmt.Sprintf(" (pid %v)", ev.PIDs)
	}
	return s
}
