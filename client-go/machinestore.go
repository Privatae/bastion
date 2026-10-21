package main

// machinestore.go — the machine's own record, on the machine, for the host to
// read.
//
// WHAT WAS MISSING. The detection plane has computed findings every pass since
// 0.30.0, and they existed nowhere afterwards: `observe:delta` recomputes them
// on demand and the beat carries counts (v146's `detect` column). So the host
// could answer "how many" and could never answer "which ones", and an operator
// reading a machine an hour later saw a fresh pass, not what happened at 03:00.
// Nothing kept the evidence.
//
// This is the keeping. Findings and the alert summaries the box pulled, written
// as files under one root that
// the anchor host reads through `dcn` like any other machine store — a governed
// range-read against a store the user can see and revoke, never a push into the
// host and never a new lane.
//
// THE ACCOUNTING HALF OF AAA IS NOT COMPLETE HERE. `audit_fetch`
// records what the AI ASKED this box to do; what it SAW is op stdout, which is
// still returned down the lane and dropped. That shelf needs the op lane wired
// to a writer and is a later change — said plainly because a store that holds
// two thirds of the record must not be described as holding all of it.
//
// ── A JOURNAL OF TRANSITIONS, NOT A LOG OF PASSES ───────────────────────────
//
// The obvious build appends this pass's findings every pass. That is wrong in a
// way that only shows up in production: a finding is PINNED until a human
// resolves it (deltarun.go:270-273 states the pin for the binary event; the same rule governs findings generally), and the pass
// runs every 60 seconds. One unresolved finding is then 1,440 identical lines a
// day, and the file whose job is to say what happened is mostly a clock.
//
// So a line is written when a finding's state CHANGES:
//
//	opened   this box is reporting this fingerprint for the first time
//	changed  same fingerprint, different material content (level, tier, reason,
//	         endpoints) — a notice that became a critical is not the same finding
//	closed   it was open and this pass did not report it
//
// Replaying the journal in order reconstructs the open set exactly, which is
// what makes it safe to write only the edges. `closed` is NOT the same claim as
// "resolved" and the host must not read it as one: the overwhelmingly common
// reason a finding stops being reported is a retake of the accounting, and
// oversight.py:39-44 makes the same distinction on its side.
//
// ── WHAT IS DELIBERATELY NOT HERE ───────────────────────────────────────────
//
// No content from the user's files, ever. Findings name executables, units and
// argv shapes — the same material the beat's `agents` scan already carries, and
// gated the same way. This store adds no new class of disclosure; it adds
// persistence to a class that already travelled.
//
// The op-id registry deltanoise.go:88-97 wants ("which op started this") is
// still not here. It needs the op lane to record its launches, which is a
// change in mgmt_audit.go, and it is not made by this file — naming it beats
// implying the `bastion-child` filter can say more than "ours".

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// storeRoot is the DCN machine store's root: a directory INSIDE the bastion's
// own state dir, not beside it. The host is granted this path and nothing
// above it, so a read that escapes the root escapes into the bastion's own
// state — pairings, grants, the TOTP secret. dcn.go's path handling is what
// stops that and it is not re-implemented here; the nesting is the second wall,
// so a mistake in the first one lands somewhere harmless rather than on the
// key material.
const storeDirName = "store"

// The three shelves the machine store keeps.
const (
	storeFindings = "findings"
	storeAlerts   = "alerts"
	// storeObserve holds what each observe op RETURNED, one shelf per op:
	// observe/<op>/<date>.jsonl. Reinstated with a call site this time — the
	// round-1 review removed an unreachable writer with an unbounded
	// directory behind it, and this one rides storeAppend's cap and seal like
	// the other two shelves.
	storeObserve = "observe"
)

// storeRetention is how long a day-file is kept. Thirty days is the plan's
// number and it is the one an operator investigating an incident needs: the
// question "was this here last month" is common and "was this here last year"
// is not, and the difference is a bounded directory on somebody's laptop.
const storeRetention = 30 * 24 * time.Hour

// storeDayCap bounds ONE day-file. Derived, not picked, and the derivation is
// stated with the measurement that backs it: the test fixture line is 339 bytes
// and carries NO Evidence, Was, PIDs or Endpoints, so it is the SHORT end, not
// the long one — an earlier version of this comment had that backwards and
// quoted a capacity it could not support. A real finding with evidence runs to
// roughly 1-2 KB, so 4 MiB is on the order of 2,000-4,000 transitions in a day.
// A machine producing more than that is not producing findings, it is producing
// a storm, and the storm is itself the signal — which is why hitting the cap
// writes a line saying so rather than falling silent. Worst case on disk is
// storeRetention x this x the number of shelves; in steady state it is zero,
// because a quiet machine writes no lines at all.
const storeDayCap = 4 << 20

// storeCapped is the last line a capped day-file gets. It is a real journal
// line, so a host replaying the day sees the truncation in band instead of
// inferring it from a gap.
const storeCapped = "day_capped"

// storeDayOpen is the one line a new day-file opens with when findings were
// already open: the open set as of that moment, so the file is self-contained
// for a reader whose window starts inside it.
const storeDayOpen = "day_open"

// storeSnapshotMaxFPs bounds that line. A fingerprint is 32 hex characters
// (baselineFP: hex of 16 bytes), so 256 of them plus the note measure 9,351
// bytes — about 1/450 of the day's ceiling — and the snapshot can never be
// what fills a file. The previous per-finding version could and did, which is
// the whole reason this is a bound and not a loop. (An earlier comment said 16
// characters and 4.5 KB; the conclusion held with a 450x margin, the numbers
// did not.)
const storeSnapshotMaxFPs = 256

// storeStateFile is the writer's own memory of what is open, kept in the state
// dir and NOT in the store — the host has no business reading the bookkeeping
// that decides what it gets told, and a file the host could write is a file
// that could suppress a finding.
const storeStateName = "store-state.json"

// storeMu serializes the writers. refreshDelta already guarantees one delta
// pass at a time (its in-flight flag, deltarun.go:467-478), but the alerts
// refresher runs ONE GOROUTINE PER PAIRING (run.go starts it inside runPairing),
// so on a box serving several hosts those writers genuinely do collide over
// store-alerts.json.
var storeMu sync.Mutex

// ── the journal line ────────────────────────────────────────────────────────

// storeLine is one line of findings/<date>.jsonl.
//
// It carries the WHOLE event, not a reference to one. A journal whose lines
// point at state held elsewhere stops being replayable the moment that state
// moves on, and the state here is explicitly allowed to move on — the
// accounting gets retaken, delta-state.json gets deleted (deltastate.go:25-30).
// The line has to stand on its own or it is not a record.
type storeLine struct {
	// At is when this transition was WRITTEN. Distinct from Event.FirstSeen,
	// which is when the box first noticed the finding: a box that was off for a
	// weekend writes `opened` on Monday for something it first saw on Friday,
	// and collapsing the two would lose that.
	At string `json:"at"`
	// Transition is opened | changed | closed | day_open | day_capped.
	Transition string `json:"transition"`
	// Machine and Version are stamped per line, not per file. A day-file can be
	// read as a range by a host that never saw its header, and a line that
	// cannot say which machine it came from is not evidence.
	Machine string `json:"machine"`
	Version string `json:"version"`
	// Baseline is the digest of the accounting this finding stands against.
	// Without it, two lines from either side of a retake look comparable and
	// are not.
	Baseline string      `json:"baseline,omitempty"`
	Event    *deltaEvent `json:"event,omitempty"`
	// OpenCount and OpenFPs belong to a day_open line and to nothing else: how
	// many findings were open when the day-file was started, and their
	// fingerprints. The COUNT is separate from the list because the list is
	// bounded — a reader must be able to tell "3 open, here they are" from
	// "3,000 open, here are the first 256".
	OpenCount int      `json:"open_count,omitempty"`
	OpenFPs   []string `json:"open_fps,omitempty"`
	// Note carries the reason for a line that is not about one event.
	Note string `json:"note,omitempty"`
}

// storeState is what the writer remembers between passes: the open set, keyed
// by fingerprint, valued by the digest of the event's material content. The
// value is what makes `changed` detectable without keeping the events.
type storeState struct {
	Version string `json:"version"`
	// Baseline is the accounting the open set was built against. A retake
	// invalidates it for the reason deltastate.go:36-38 gives; storeRecordPass
	// closes every open finding explicitly on the pass that notices, rather
	// than the loader dropping them where no line is ever written.
	Baseline string            `json:"baseline"`
	Open     map[string]string `json:"open,omitempty"`
	// OpenKind: open fingerprint -> the entry kind of its finding, so a pass
	// that did not compare a class closes nothing of that class. An open
	// fingerprint with no kind was opened before the listener and identity
	// classes existed, so it is a process or a scheduler, which are never
	// left out one class at a time.
	OpenKind map[string]string `json:"open_kind,omitempty"`
	// Day is the UTC day of the file the open set was last written into, so a
	// rollover can carry the open set into the new one. Empty on a fresh state,
	// which correctly carries nothing.
	Day string `json:"day,omitempty"`
}

// Bumped from v1 when storeState gained Day. A v1 file is MIGRATED, not
// discarded: rejecting it wholesale re-opened every current finding and — the
// part that matters — never closed a finding that had gone away in between,
// because the loader forgot it was ever open. `zzz` open under v1, absent after
// the upgrade, got no `closed` line anywhere, ever. v1 lacks only `day`, which
// reads as "" and costs exactly one skipped snapshot; everything else carries.
const storeStateVersion = "privatae-store-state-v2"

// storeStateVersionsKnown are the versions the loader will carry forward.
var storeStateVersionsKnown = map[string]bool{"privatae-store-state-v1": true, storeStateVersion: true}

// storeAlertStateVersion is the alerts bookkeeping's OWN constant. It shared
// storeStateVersion, so the findings-side bump re-journalled every firing
// alert once on upgrade for a schema that had not changed.
const storeAlertStateVersion = "privatae-store-alerts-v1"

// storeRootPath is storeDir WITHOUT the MkdirAll — the path this box reports on
// its beat as `machine_record_root`. The beat fires every 60 seconds and
// reporting a path must not create a directory as a side effect; configDirPath
// exists for the same reason one level up (config.go:121-128).
func storeRootPath() (string, error) {
	d, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, storeDirName), nil
}

func storeDir() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, storeDirName)
	return p, os.MkdirAll(p, 0o700)
}

// storeShelf is one shelf directory under the root, created on first write.
func storeShelf(name string) (string, error) {
	root, err := storeDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(root, name)
	return p, os.MkdirAll(p, 0o700)
}

func storeStatePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, storeStateName), nil
}

// storeStateLoadRaw reads the state AS IT STANDS, without judging it against
// the current accounting.
//
// THE JUDGING MOVED TO THE CALLER ON PURPOSE. This used to take the current
// baseline digest and return a fresh empty state when it disagreed — which
// meant a retake silently erased the open set before anything could write a
// line about it, and every finding measured against the old accounting left the
// journal without a trace. storeRecordPass now compares the digests itself and
// closes what it is about to stop tracking.
//
// An unreadable or corrupt file is still not an error, for deltaStateLoad's
// reason (deltastate.go:97-106). The consequence here is the safe direction: a
// lost open set re-opens every current finding, so the journal repeats itself.
// It never loses one.
func storeStateLoadRaw() *storeState {
	fresh := &storeState{Version: storeStateVersion, Open: map[string]string{}}
	p, err := storeStatePath()
	if err != nil {
		return fresh
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return fresh
	}
	var st storeState
	if json.Unmarshal(b, &st) != nil {
		return fresh
	}
	if !storeStateVersionsKnown[st.Version] {
		return fresh
	}
	st.Version = storeStateVersion
	if st.Open == nil {
		st.Open = map[string]string{}
	}
	return &st
}

func (s *storeState) save() error {
	p, err := storeStatePath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	// Re-chmod for the reason baselineSave and deltaState.save do: WriteFile
	// applies its mode only on create.
	_ = os.Chmod(p, 0o600)
	return nil
}

// storeEventDigest is the material content of a finding — what has to differ
// for `changed` to be the truth rather than churn.
//
// WHAT IS EXCLUDED IS THE POINT. PIDs are not here: a service restarting gets
// new pids every time and that is not a change in the finding, it is the same
// finding on a new process. FirstSeen is not here either — it is fixed at the
// first sighting by definition, so including it would be inert, and reading it
// as material would make a re-stamp (a deleted delta-state.json) look like the
// finding itself changed.
func storeEventDigest(ev *deltaEvent) string {
	added := append([]string(nil), ev.Added...)
	sort.Strings(added)
	return strings.Join([]string{
		ev.Kind, ev.Reason, ev.Level, ev.Tier,
		// ArgvShape and not a "command" field: a scheduler's command IS its argv
		// shape here (delta.go:305 compares exactly this pair to raise
		// deltaReasonCommand), and on a process it is part of the slot
		// (delta.go:158). One field covers both because the code that decides a
		// `changed` already treats it as one.
		ev.Entry.ExeDigest, ev.Entry.ArgvShape,
		// Was.FP: which baseline entry this displaced. departedAtSlot
		// (delta.go:229-233) can name a DIFFERENT displaced entry across passes
		// while every field above stays equal, so without this "this replaced X"
		// silently becomes "this replaced Y". Narrow, but it is the direction
		// where a real change is swallowed.
		storeWasFP(ev),
		strings.Join(added, ","),
	}, "\x00")
}

// storeWasFP is the fingerprint of the baseline entry a `changed` displaced,
// or "" when the event displaced nothing.
func storeWasFP(ev *deltaEvent) string {
	if ev.Was == nil {
		return ""
	}
	return ev.Was.FP
}

// ── writing ─────────────────────────────────────────────────────────────────

// storeDayPath is the file for one shelf and one day, UTC.
//
// UTC AND NOT LOCAL TIME, because the reader is not on this machine. A fleet
// spanning timezones whose day-files roll at local midnight cannot be asked
// "what happened on the 14th" without knowing where each box stands, and the
// one thing a host reading a store does not have is the box's clock offset.
func storeDayPath(shelf string, now time.Time) (string, error) {
	d, err := storeShelf(shelf)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, now.UTC().Format("2006-01-02")+".jsonl"), nil
}

// storeNoticeReserve is room held back from storeDayCap so the capped-notice
// always fits INSIDE the ceiling.
//
// Without it the notice is written past the cap — measured at 221 bytes over on
// the first run of TestACappedDayFileSaysSoOnceAndThenStops — and then
// storeDayCap is not a ceiling, it is a ceiling plus whatever the last line
// happened to be. Either the notice is exempt and the bound is soft, or room is
// reserved for it and the bound is exact; this takes the second, because a
// bound quoted in a comment as "cannot cross" has to be one. 512 bytes is the
// notice plus headroom for a long hostname. MEASURED AT 319 BYTES after the
// notice text grew; an earlier version of this comment still said 221, which is
// the sort of stale number that makes a bound look safer than it is. Linux caps
// os.Hostname at 64, so 512 holds.
const storeNoticeReserve = 512

// storeSealSuffix marks a day-file that has hit its ceiling. A SIBLING MARKER
// rather than a size test, because a size test cannot seal a file: the line
// that trips the cap may be large and the notice that replaces it small, so the
// file stays under the ceiling and the NEXT small line fits. Measured in review
// — four `day_capped` notices in one file with ordinary lines between them, and
// the notice's own text says the file "stops here". The marker makes sealing a
// fact about the day rather than an inference from its length.
const storeSealSuffix = ".capped"

// storeAppend adds one line to a shelf's day-file, honouring the cap.
//
// RETURNS WHETHER THE LINE WAS WRITTEN, and every caller must act on it. The
// first version returned only an error, so a capped file made a dropped line
// indistinguishable from a written one — and storeRecordPass then recorded the
// finding as open, which meant it was never emitted again on any later pass or
// any later day. A silently swallowed finding is the exact failure this whole
// file exists to prevent.
func storeAppend(shelf string, line any, now time.Time) (bool, error) {
	p, err := storeDayPath(shelf, now)
	if err != nil {
		return false, err
	}
	b, err := json.Marshal(line)
	if err != nil {
		return false, err
	}
	b = append(b, '\n')

	// Sealed: this day said what it had to say and is closed to further lines.
	if _, sErr := os.Stat(p + storeSealSuffix); sErr == nil {
		return false, nil
	}

	fi, err := os.Stat(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	size := int64(0)
	if err == nil {
		size = fi.Size()
	}
	// Checked even when the file does not exist yet, so a single oversized line
	// cannot create a file already past the ceiling.
	if size+int64(len(b)) > storeDayCap-storeNoticeReserve {
		notice, mErr := json.Marshal(storeLine{
			At: stamp(now), Transition: storeCapped, Machine: storeMachineName(),
			Version: clientVersion,
			Note: fmt.Sprintf("this day-file reached its %d-byte ceiling and stops here; "+
				"nothing further is recorded for this UTC day, and a machine producing "+
				"this many transitions in a day is itself the finding",
				storeDayCap),
		})
		if mErr != nil {
			return false, mErr
		}
		if wErr := storeWriteLine(p, append(notice, '\n')); wErr != nil {
			return false, wErr
		}
		// Seal AFTER the notice, so the notice itself is never refused by the
		// seal it creates.
		if wErr := storeWriteLine(p+storeSealSuffix, nil); wErr != nil {
			return false, wErr
		}
		return false, nil
	}
	if wErr := storeWriteLine(p, b); wErr != nil {
		return false, wErr
	}
	return true, nil
}

func storeWriteLine(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Re-chmod, and NOT for the umask reason the other writers in this tree
	// give. A umask only ever clears bits, so an O_CREATE of 0600 cannot come
	// out looser than 0600 however permissive the umask is — the mutation that
	// deletes this line survives a umask-based test, which is how the wrong
	// rationale got caught here.
	//
	// What it actually guards is an EXISTING file whose mode is already loose:
	// O_APPEND|O_CREATE leaves the mode of a file it did not create untouched,
	// so a day-file restored from a backup, copied in with `cp -p`, or written
	// by some earlier build goes on being world-readable for the rest of the
	// day while this process appends the machine's findings to it.
	_ = os.Chmod(p, 0o600)
	_, err = f.Write(b)
	return err
}

func storeMachineName() string {
	hn, _ := os.Hostname()
	return hn
}

// ── the findings journal ────────────────────────────────────────────────────

// storeRecordPass folds one delta pass into the journal and returns how many
// lines it wrote.
//
// IT IS CALLED WITH THE DAEMON'S PASS ONLY. An operator running `observe:delta`
// gets a report and writes nothing, for the same reason deltaRoleOperator does
// not advance the remembered binary pair (delta_test.go:1051): a person looking
// at the machine must not be able to move the record by looking at it.
//
// A pass that could not compare — no authority, no accounting, an accounting
// under other rules — writes NOTHING and closes nothing. This is the one that
// is easy to get wrong: treating "I could not look" as "there is nothing there"
// would close every open finding on the box the moment somebody deleted the
// accounting, and the journal would show a clean resolution of everything.
func storeRecordPass(r deltaReport, now time.Time) (int, error) {
	if r.Baseline != deltaBaselineOK && r.Baseline != deltaBaselineEdit {
		return 0, nil
	}
	storeMu.Lock()
	defer storeMu.Unlock()

	machine, wrote := storeMachineName(), 0
	day := now.UTC().Format("2006-01-02")

	// A line is only remembered as open once it is actually ON DISK. storeAppend
	// refuses a line on a sealed day, and treating a refusal as a write is how
	// the first version lost findings for good.
	// put writes an OPENING-side line (opened / changed) and reports whether it
	// landed. A REFUSAL IS A NO-OP ON THE OPEN SET: an `opened` that did not
	// land was never in the set, so there is nothing to undo; a `changed` that
	// did not land stays recorded under its OLD digest, so the next unsealed day
	// writes `changed` — the truth — rather than a second `opened` with no close
	// between. (An earlier version deleted the entry on any refusal, which
	// produced exactly that double open; the review's mutation removing the
	// delete was the better behaviour.)
	//
	// IT IS NOT USED FOR CLOSES. A refused `closed` must also stay in the open
	// set, and the close loop handles its own refusals the same way — so both
	// sides now share one rule: the set changes only when a line lands.
	put := func(st *storeState, transition string, ev *deltaEvent, note string) (bool, error) {
		ok, err := storeAppend(storeFindings, storeLine{
			At: stamp(now), Transition: transition, Machine: machine,
			Version: clientVersion, Baseline: r.BaselineDigest, Event: ev, Note: note,
		}, now)
		if err != nil || !ok {
			return false, err
		}
		wrote++
		st.Open[ev.FP] = storeEventDigest(ev)
		if ev.Entry.Kind != "" {
			if st.OpenKind == nil {
				st.OpenKind = map[string]string{}
			}
			st.OpenKind[ev.FP] = ev.Entry.Kind
		}
		return true, nil
	}

	st := storeStateLoadRaw()

	// ── A NEW DAY-FILE OPENS WITH ONE SNAPSHOT LINE ─────────────────────────
	//
	// Retention deletes day-files after 30 days, so a finding pinned longer than
	// that had its `opened` line swept while it was still open, and its eventual
	// `closed` referred to a fingerprint the retained window never opened. The
	// day-file has to say what was already open when it started.
	//
	// ONE LINE, NOT ONE PER FINDING, AND THIS IS THE SECOND ATTEMPT. The first
	// wrote a `carried` line per open finding, ahead of the day's opens and
	// closes — and measured in review that is a PERMANENT LOCKUP, not a bad day:
	// a carried line is ~324 bytes, so the carry alone fills a day at ~12,900
	// open findings. Once it does, `closed` (which runs last) is starved first,
	// so the open set can never drain, so the carry never shrinks. Seven
	// simulated days ended with the shelf writing nothing but its own memory of
	// the day it locked, and a new `critical` that was never journalled once.
	// That defeats the cap's own purpose — the storm is meant to BE the signal —
	// and undid the fix whose point was that the next unsealed day takes the
	// refused finding.
	//
	// It was also the "clock" shape this file's header forbids, just amortised:
	// an edge journal turned into a daily O(open set) snapshot.
	//
	// AND IT RUNS BEFORE THE RETAKE-CLOSE. The retake empties the open set; a
	// snapshot taken after it lists nothing, and a day-file that begins with
	// two `closed` lines for fingerprints it never introduced is exactly the
	// un-self-contained file this line exists to prevent (measured in review:
	// `[closed aaa, closed bbb, opened aaa]` with no snapshot). Snapshot first,
	// then the closes, then the opens: `[day_open{aaa,bbb}, closed, closed,
	// opened]` replays correctly from that file alone.
	//
	// So: one bounded line carrying the fingerprints, truncated with a count
	// when there are more than fit. A reader learns exactly what was open and,
	// when the list is cut, that it was cut and by how much — which is strictly
	// more than the per-finding version delivered once it had eaten the day.
	if st.Day != "" && st.Day != day && len(st.Open) > 0 {
		openFPs := make([]string, 0, len(st.Open))
		for fp := range st.Open {
			openFPs = append(openFPs, fp)
		}
		sort.Strings(openFPs)
		total := len(openFPs)
		note := fmt.Sprintf("%d finding(s) were already open when this day-file was "+
			"started; their opening lines are in earlier files, which retention may "+
			"already have swept", total)
		if total > storeSnapshotMaxFPs {
			openFPs = openFPs[:storeSnapshotMaxFPs]
			note += fmt.Sprintf(" — this line names the first %d of them, in fingerprint "+
				"order; the rest are counted, not listed", storeSnapshotMaxFPs)
		}
		ok, err := storeAppend(storeFindings, storeLine{
			At: stamp(now), Transition: storeDayOpen, Machine: machine,
			Version: clientVersion, Baseline: r.BaselineDigest,
			OpenCount: total, OpenFPs: openFPs, Note: note,
		}, now)
		if err != nil {
			return wrote, err
		}
		if ok {
			wrote++
		}
	}
	st.Day = day
	// ── A RETAKE CLOSES WHAT IT MADE INCOMPARABLE ───────────────────────────
	//
	// A retake redefines normal, so findings measured against the old
	// accounting cannot be compared to the new one. The first version silently
	// dropped them — storeStateLoad returned a fresh set on a digest mismatch,
	// so the close loop had nothing to iterate and the old findings vanished
	// from the journal without a line. That also falsified this file's own
	// claim that replaying reconstructs the open set exactly. They are closed
	// explicitly now, and the note says which of the two reasons it was.
	if st.Baseline != r.BaselineDigest {
		old := st.Open
		carried := map[string]string{}
		var prior []string
		for fp := range old {
			prior = append(prior, fp)
		}
		sort.Strings(prior)
		allClosed := true
		for _, fp := range prior {
			ok, err := storeAppend(storeFindings, storeLine{
				At: stamp(now), Transition: "closed", Machine: machine,
				Version: clientVersion, Baseline: r.BaselineDigest,
				Event: &deltaEvent{FP: fp},
				Note: "the accounting was retaken, so this finding is no longer comparable " +
					"and is not being tracked against the new one — that is not the same " +
					"as resolved" + map[bool]string{
					false: ", and anything still present will re-open on this pass",
					true:  "; this pass could not walk the machine, so anything still present re-opens on the next one that can",
				}[r.WalkFailed != ""],
			}, now)
			if err != nil {
				return wrote, err
			}
			if ok {
				wrote++
				continue
			}
			// REFUSED, SO THE CLOSE DID NOT HAPPEN. Keep the entry and, below,
			// do NOT advance the remembered baseline — otherwise the retake
			// branch is never re-entered, nothing retries, and that finding's
			// only line anywhere in the store is its original `opened`.
			// Measured in review as a permanent drop.
			carried[fp] = old[fp]
			allClosed = false
		}
		if allClosed {
			st = &storeState{Version: storeStateVersion, Baseline: r.BaselineDigest,
				Open: map[string]string{}, Day: st.Day}
		} else {
			// Baseline deliberately left at the OLD digest: the next pass, on an
			// unsealed day, re-enters this branch and finishes the job.
			st.Open = carried
		}
	}

	nowOpen := make(map[string]string, len(r.Findings))
	for i := range r.Findings {
		nowOpen[r.Findings[i].FP] = storeEventDigest(&r.Findings[i])
	}

	// opened / changed, in the order the pass reported them.
	for i := range r.Findings {
		ev := &r.Findings[i]
		was, had := st.Open[ev.FP]
		transition := ""
		switch {
		case !had:
			transition = "opened"
		case was != nowOpen[ev.FP]:
			transition = "changed"
		default:
			continue
		}
		if _, err := put(st, transition, ev, ""); err != nil {
			return wrote, err
		}
	}

	// ── closed ──────────────────────────────────────────────────────────────
	//
	// A NARROWER SCAN THAN THE ACCOUNTING CLOSES NOTHING — and the test is the
	// MISMATCH, not incompleteness on its own. That distinction is the fix for a
	// real trap: baseline_all_other.go returns false unconditionally on darwin
	// and windows, so `Complete` is permanently false there. Gating on it alone
	// meant no finding ever closed on a Mac or a Windows box, the open set grew
	// monotonically for the life of the machine, and the day_open snapshot
	// walked it upward for ever.
	//
	// Those platforms are not blind, they are consistently filtered: the
	// accounting was taken through the same recognised-only walk the pass uses
	// (baselineCoverage names each half), so the two sides agree about scope and
	// an absence really is an absence. What must never close is the case where
	// the accounting saw MORE than this pass could — an all-processes baseline
	// compared against a partial walk — because there the missing entry may
	// simply not have been looked at.
	if storeScopeAgrees(r) {
		// A CLASS THIS PASS DID NOT COMPARE CLOSES NOTHING. Its findings are
		// absent from r.Findings because nothing looked for them, not because
		// they went away: an `ss` that fails every other pass would otherwise
		// close and reopen a live finding on every beat, and the journal would
		// say a backdoor on 0.0.0.0:4444 was resolved twelve times in half an
		// hour. The same rule the walk-failure guard applies, one class at a time.
		skipped := map[string]bool{}
		for _, k := range r.Skipped {
			skipped[k] = true
		}
		var gone []string
		for fp := range st.Open {
			if _, still := nowOpen[fp]; !still && !skipped[st.OpenKind[fp]] {
				gone = append(gone, fp)
			}
		}
		// Stable order — map iteration is random and a journal whose line order
		// changes between identical runs cannot be diffed in a test or by a person.
		sort.Strings(gone)
		for _, fp := range gone {
			ok, err := storeAppend(storeFindings, storeLine{
				At: stamp(now), Transition: "closed", Machine: machine,
				Version: clientVersion, Baseline: r.BaselineDigest,
				Event: &deltaEvent{FP: fp},
				Note: "this finding was not reported by the pass that closed it — which " +
					"is not the same as resolved",
			}, now)
			if err != nil {
				return wrote, err
			}
			// ONLY ON A WRITE. A refused close leaves the entry OPEN, because
			// the close did not happen — the next unsealed day writes it. The
			// retake path deleted unconditionally and lost closes permanently
			// (NB2); this is the same rule stated the same way in both places.
			if ok {
				wrote++
				delete(st.Open, fp)
			}
		}
	}
	for fp := range st.OpenKind {
		if _, open := st.Open[fp]; !open {
			delete(st.OpenKind, fp)
		}
	}

	if err := st.save(); err != nil {
		return wrote, err
	}
	return wrote, nil
}

// ── the alerts journal ──────────────────────────────────────────────────────

// storeAlertLine is one line of alerts/<date>.jsonl.
//
// IT CARRIES A FINGERPRINT AND NOT AN ALERT. An Alertmanager fingerprint is a
// hash that resolves to nothing without the Alertmanager — agents.go:678-681
// settled that this is why the counts may ride the beat ungated, and the same
// reasoning is what lets them be written here: this shelf holds no alert names,
// no labels and no hostnames. The rows that do carry labels stay behind
// `observe:alerts`, which is grant-gated.
type storeAlertLine struct {
	At         string `json:"at"`
	Transition string `json:"transition"`
	Machine    string `json:"machine"`
	Version    string `json:"version"`
	FP         string `json:"fp,omitempty"`
	// Counts are the summary AS OF this line, so a reader who joins the journal
	// mid-day has the totals without replaying from the start of it.
	Firing   int    `json:"firing"`
	Critical int    `json:"critical"`
	Warning  int    `json:"warning"`
	Note     string `json:"note,omitempty"`
}

// storeAlertState is the open set for alerts, kept beside the findings one.
type storeAlertState struct {
	Version string   `json:"version"`
	Open    []string `json:"open,omitempty"`
	// Truncated is the "<firing>/<listed>" shape of the last truncation line
	// written, so the notice is written when the truncation CHANGES rather than
	// on every refresh. Without it the shelf became a clock.
	Truncated string `json:"truncated,omitempty"`
}

const storeAlertStateName = "store-alerts.json"

func storeAlertStatePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, storeAlertStateName), nil
}

// storeRecordAlerts journals the alert set's transitions.
//
// A NIL SUMMARY IS NOT AN EMPTY ONE, and this is the same wall the beat puts up
// (observe_pull.go:878-883): nil means this box has no Alertmanager configured
// or has not refreshed yet, so it is not watching anything and must not be read
// as watching nothing. It closes nothing and writes nothing — only a real
// summary that no longer lists a fingerprint closes it.
func storeRecordAlerts(s *alertsSummary, now time.Time) (int, error) {
	if s == nil {
		return 0, nil
	}
	storeMu.Lock()
	defer storeMu.Unlock()

	open := map[string]bool{}
	prevTruncated := ""
	if p, err := storeAlertStatePath(); err == nil {
		if b, rErr := os.ReadFile(p); rErr == nil {
			var st storeAlertState
			if json.Unmarshal(b, &st) == nil && st.Version == storeAlertStateVersion {
				for _, fp := range st.Open {
					open[fp] = true
				}
				prevTruncated = st.Truncated
			}
		}
	}

	firingNow := map[string]bool{}
	for _, fp := range s.Fingerprints {
		firingNow[fp] = true
	}
	machine, wrote := storeMachineName(), 0
	write := func(transition, fp, note string) error {
		ok, err := storeAppend(storeAlerts, storeAlertLine{
			At: stamp(now), Transition: transition, Machine: machine,
			Version: clientVersion, FP: fp, Firing: s.Firing,
			Critical: s.Critical, Warning: s.Warning, Note: note,
		}, now)
		if err != nil {
			return err
		}
		if ok {
			wrote++
		}
		return nil
	}

	// THE OPEN SET FOLLOWS WHAT WAS WRITTEN, not what was firing. A sealed
	// day-file refuses lines, and recording an alert as open whose `firing` line
	// never landed would mean it is never journalled again — the same silent
	// loss the findings shelf had. `write` reports whether the line landed.
	nextOpen := map[string]bool{}
	for fp := range open {
		nextOpen[fp] = true
	}

	fresh := append([]string(nil), s.Fingerprints...)
	sort.Strings(fresh)
	for _, fp := range fresh {
		if open[fp] {
			continue
		}
		before := wrote
		if err := write("firing", fp, ""); err != nil {
			return wrote, err
		}
		if wrote > before {
			nextOpen[fp] = true
		}
	}
	var gone []string
	for fp := range open {
		if !firingNow[fp] {
			gone = append(gone, fp)
		}
	}
	sort.Strings(gone)
	for _, fp := range gone {
		before := wrote
		if err := write("cleared", fp, ""); err != nil {
			return wrote, err
		}
		if wrote > before {
			delete(nextOpen, fp)
		}
	}

	// ONLY WHEN THE TRUNCATION ITSELF CHANGES. Written unconditionally this was
	// a clock: refreshAlerts runs every 60s per pairing, so a fleet sitting on
	// 57 firing alerts wrote 1,440 identical lines a day per host served — the
	// exact shape this file's header forbids, measured in review at 5 refreshes
	// producing 21, 1, 1, 1, 1 lines.
	//
	// THE SUMMARY IS CAPPED AT TWENTY FINGERPRINTS (observe_pull.go's narrowing,
	// mirrored host-side in narrow_alerts). Past that the set this journal sees
	// is a sample, so "cleared" would be a lie about the ones that fell off the
	// end — say so in band rather than letting a truncated list read as the
	// whole one.
	truncated := ""
	if s.Firing > len(s.Fingerprints) {
		truncated = fmt.Sprintf("%d/%d", s.Firing, len(s.Fingerprints))
	}
	// THE STATE ONLY MOVES IF THE LINE LANDED. Saving `truncated` after a
	// refused write meant a sealed day recorded the notice as delivered and the
	// next unsealed day, with the same summary, never wrote it — the value was
	// gone for good. Same rule as the open set: bookkeeping follows the disk.
	truncatedWritten := prevTruncated
	if truncated != "" && truncated != prevTruncated {
		before := wrote
		if err := write("truncated", "", fmt.Sprintf(
			"%d alerts are firing and this summary names %d of them; the rest are "+
				"counted, not listed, so this journal cannot say when they cleared",
			s.Firing, len(s.Fingerprints))); err != nil {
			return wrote, err
		}
		if wrote > before {
			truncatedWritten = truncated
		}
	} else if truncated == "" {
		// No longer truncated: forget the old value so a later truncation is
		// reported again rather than compared against a stale one.
		truncatedWritten = ""
	}

	if wrote == 0 && truncatedWritten == prevTruncated {
		return 0, nil
	}
	stillOpen := make([]string, 0, len(nextOpen))
	for fp := range nextOpen {
		stillOpen = append(stillOpen, fp)
	}
	sort.Strings(stillOpen)
	st := storeAlertState{Version: storeAlertStateVersion, Open: stillOpen, Truncated: truncatedWritten}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return wrote, err
	}
	p, err := storeAlertStatePath()
	if err != nil {
		return wrote, err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return wrote, err
	}
	_ = os.Chmod(p, 0o600)
	return wrote, nil
}

// storeScopeAgrees reports whether this pass looked at as much as the
// accounting it is being compared against.
//
// A complete walk always agrees. An incomplete one agrees only when the
// accounting was itself taken through the recognised-only walk — the
// consistently-filtered platform — which baselineCoverage records as
// `processes=recognised-only` (baseline.go:517-526). An accounting that claims
// `processes=all` compared against a partial walk is the genuine mismatch, and
// the only case where an absence is not evidence.
//
// A pass whose walk FAILED agrees with nothing: it compared no entries, so an
// absence in it is not evidence on any platform — least of all the
// recognised-only ones, where Complete=false is the everyday state and the
// coverage label would otherwise wave the pass through.
func storeScopeAgrees(r deltaReport) bool {
	if r.WalkFailed != "" {
		return false
	}
	if r.Complete {
		return true
	}
	return strings.Contains(r.Coverage, "processes=recognised-only")
}

// ── the observe shelf ───────────────────────────────────────────────────────
//
// THE ACCOUNTING HALF OF AAA. audit_fetch records what the host
// ASKED this box to do. Until now nothing recorded what it SAW: an observe
// op's result went back down the lane and was dropped, so "what did the AI
// learn from this machine" — the question an incident turns on — had no
// answer on either side. Each result is now a line in observe/<op>/<date>.jsonl,
// with WHO asked (the pairing) and WHAT they passed.
//
// WHO CAN READ IT. The store is granted to the anchor host (or the only host on
// a one-host box). On an anchored box a member host with `observe` can run
// these ops, and its results land here where the ANCHOR can read them. That is
// intended and it is not a leak: the anchor administers the machine, can run
// every one of these ops itself, and the record is the machine's — which is
// why each line names the asking host rather than hiding it.

// storeObserveLineMax bounds ONE LINE — the whole line on disk, not just the
// result inside it. The first version bounded `len(result)` alone and recorded
// the host's args verbatim, so a member host with `observe` could send a 5 MiB
// argument to an op that ignores arguments, get a normal answer, and seal the
// shelf for the rest of the UTC day — erasing the record of what it saw. The
// accounting half of AAA, erasable by the party being accounted for. Measured
// in review: one 2,097,461-byte line; a seal on the first frame.
//
// Three walls now: args are kept ONLY for the ops that consume them, each arg
// is cut at storeObserveArgMax, and the marshalled line is measured and the
// result's head shrunk until the whole line fits. A max-size line on disk
// measures storeObserveLineMax exactly, so at the append ceiling of
// storeDayCap-storeNoticeReserve (4,193,792 bytes) at least 127 full-size
// results fit in a day before the cap — 127, not the 128 an earlier comment
// claimed, because the envelope around the result is not free.
//
// WHY 32 KiB. observe:units and observe:sockets on a busy box run to tens of
// KB; at 288 host polls a day a 20 KB result is 5.7 MB, past the day ceiling
// by mid-afternoon. A larger result keeps its first storeObserveHeadKeep bytes
// plus how much was cut — the shape of what was seen, never nothing.
const (
	storeObserveLineMax  = 32 << 10
	storeObserveHeadKeep = 4 << 10
	storeObserveArgMax   = 256
)

// observeArgsRecorded is which ops CONSUME caller arguments, and how many.
// Everything else on the family ignores its args, and an arg nobody reads is
// not part of what was asked — it is bytes the host chose to send, and
// recording them lets the host choose the size of the record. The table is
// pinned against the handlers by TestObserveArgsRecordedMatchesTheHandlers.
var observeArgsRecorded = map[string]int{
	"observe:net":     1, // host[:port], charset-checked before use
	"observe:metrics": 1, // a name from a fixed query table
	"observe:logs":    2, // a name, and an optional minutes window (a whole number)
}

// storeObserveLine is one line of observe/<op>/<date>.jsonl.
//
// WHAT COMES TO REST HERE. Eight of the eleven ops return fixed schemas the
// beat already summarises (posture ints, unit names, sockets, a probe's TLS
// subject). observe:alerts and observe:metrics carry label maps that can name
// namespaces and tenants. observe:logs is the outlier: its result is raw
// production log text, up to the line bound, persisted for 30 days — the one
// payload whose content this repo does not control, and so the one place a
// token or a user identifier can come to rest. Files are 0600 under a 0700
// tree; the reader is the machine's own OS account and the anchor's approved
// store. Named here so the next person choosing what to log through this op
// knows it stays.
type storeObserveLine struct {
	At      string   `json:"at"`
	Op      string   `json:"op"`
	Machine string   `json:"machine"`
	Version string   `json:"version"`
	AskedBy string   `json:"asked_by"`
	Args    []string `json:"args,omitempty"`
	// Result is the op's reply as it was sent, or its first bytes as Head
	// when Truncated; Bytes is the reply's full size either way.
	Result    json.RawMessage `json:"result,omitempty"`
	Head      string          `json:"head,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
	Bytes     int             `json:"bytes,omitempty"`
}

// storeObserveDropped counts results that could not be written, PER SHELF.
// It rides the beat as machine_record_dropped so a record with holes is never
// mistaken for a quiet machine — and it names the shelf, because "there are
// holes somewhere" is not something the host can act on. Process-lifetime and
// monotonic, like a counter should be: a per-window count would make a hole
// disappear when the window closed.
//
// It is one counter for the MACHINE, reported on every pairing's beat. On an
// anchored box a member's beat therefore carries drops another pairing's ops
// caused. That is the record's nature — it is the machine's, not the
// pairing's — and the anchor, which reads the record, is the one that acts.
var (
	storeObserveDroppedMu sync.Mutex
	storeObserveDropped   = map[string]int64{}
)

func storeObserveDroppedAdd(shelf string) {
	storeObserveDroppedMu.Lock()
	storeObserveDropped[shelf]++
	storeObserveDroppedMu.Unlock()
}

// storeObserveDroppedSnapshot is a copy for the beat; nil when nothing dropped.
func storeObserveDroppedSnapshot() map[string]int64 {
	storeObserveDroppedMu.Lock()
	defer storeObserveDroppedMu.Unlock()
	if len(storeObserveDropped) == 0 {
		return nil
	}
	out := make(map[string]int64, len(storeObserveDropped))
	for k, v := range storeObserveDropped {
		out[k] = v
	}
	return out
}

func storeObserveDroppedReset() {
	storeObserveDroppedMu.Lock()
	storeObserveDropped = map[string]int64{}
	storeObserveDroppedMu.Unlock()
}

// storeSafeOpName reduces an op name to one path-safe component. `observe:net`
// becomes `observe-net`; anything outside the allowed set is dropped, and a
// name that reduces to nothing is refused by the caller.
//
// COLLISION IS POSSIBLE IN PRINCIPLE, from two sources: separator folding
// (`observe:k8s`, `observe-k8s` and `observe_k8s` all reduce to
// `observe-k8s`) and, since the lowercasing below, case folding
// (`observe:K8s` and `observe:k8s`). Neither can bite today — the op reaches
// this writer only from the eleven names registered in handlerOps, all
// lowercase, which reduce to eleven distinct directories
// (TestEveryRegisteredOpSanitisesToTheHostsShelfRule walks them) — but a
// future pair like `observe:k8s-nodes` / `observe:k8s_nodes` would interleave
// into one day-file. Whoever adds such a pair renames one of them.
func storeSafeOpName(op string) string {
	var b strings.Builder
	for _, r := range op {
		switch {
		case r >= 'A' && r <= 'Z':
			// Lowercased, so the host's shelf-name rule ([a-z0-9-]) is a fact
			// about what this emits rather than a hope. No registered op has
			// an uppercase letter; this is what makes that a property.
			b.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ':', r == '_', r == '-':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// storeRecordObserve journals one observe result. Never returns an error to
// the op path — the reply to the host must go regardless — but counts what it
// could not write, per shelf.
func storeRecordObserve(op, askedBy string, args []string, result []byte, now time.Time) bool {
	clean := storeSafeOpName(op)
	if clean == "" || !strings.HasPrefix(op, "observe:") {
		return false
	}
	line := storeObserveLine{
		At: stamp(now), Op: op, Machine: storeMachineName(), Version: clientVersion,
		AskedBy: askedBy, Bytes: len(result),
	}
	// Args: only for the ops that read them, only as many as they read, each
	// cut at storeObserveArgMax. An op that ignores its args gets none
	// recorded — those bytes were never part of what was asked.
	if n := observeArgsRecorded[op]; n > 0 && len(args) > 0 {
		if len(args) > n {
			args = args[:n]
		}
		kept := make([]string, 0, len(args))
		for _, a := range args {
			if len(a) > storeObserveArgMax {
				a = a[:storeObserveArgMax] + "…(cut)"
			}
			kept = append(kept, a)
		}
		line.Args = kept
	}
	// A SHORTCUT, not the wall: the loop below is what bounds the line, and a
	// result at the bound cannot fit whole once any envelope surrounds it, so
	// `>` here versus `>=` changes nothing (the review's mutation of it is
	// equivalent by construction). This only spares marshalling a huge result
	// once before the loop truncates it anyway.
	if len(result) > storeObserveLineMax || !json.Valid(result) {
		line.Truncated = true
		line.Head = string(result[:min(len(result), storeObserveHeadKeep)])
	} else {
		line.Result = json.RawMessage(result)
	}
	// THE LINE IS BOUNDED BY CONSTRUCTION. Measure the marshalled line; if it
	// is still over, the head is what gives — halved until it fits. A result
	// under the bound can still produce an over-bound line once the envelope
	// (machine name, args) is around it, which is exactly the gap the first
	// version had.
	for {
		b, err := json.Marshal(line)
		if err != nil {
			storeObserveDroppedAdd(clean)
			return false
		}
		if len(b)+1 <= storeObserveLineMax {
			break
		}
		if !line.Truncated {
			line.Truncated = true
			line.Result = nil
			line.Head = string(result[:min(len(result), storeObserveHeadKeep)])
			continue
		}
		if len(line.Head) == 0 {
			// Nothing left to give: the envelope alone is over the bound,
			// which no real op can produce. Refuse rather than seal the day.
			storeObserveDroppedAdd(clean)
			return false
		}
		line.Head = line.Head[:len(line.Head)/2]
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	ok, err := storeAppend(filepath.Join(storeObserve, clean), line, now)
	if err != nil || !ok {
		storeObserveDroppedAdd(clean)
		return false
	}
	return true
}

// ── retention ───────────────────────────────────────────────────────────────

// storeSweep deletes day-files older than storeRetention across every shelf.
//
// IT READS THE NAME, NOT THE MTIME. A file's mtime moves when it is touched,
// copied or restored from a backup, so a sweep keyed on it deletes by when the
// filesystem was last written rather than by what the file is about — and the
// restore case is exactly when somebody wants the history. The name is the day,
// it was written by this code, and a file whose name does not parse is left
// alone rather than guessed at.
// storeSweepLast is the UTC date the sweep last ran, so it runs once a day
// rather than once a minute. Not persisted: a restart costing one extra walk of
// a directory with at most a few dozen files in it is not worth a file, and the
// walk is cheap precisely because retention keeps the directory small.
var (
	storeSweepMu   sync.Mutex
	storeSweepLast string
)

// storeSweepIfDue runs the sweep at most once per UTC day.
//
// KEYED ON THE DATE AND NOT ON AN INTERVAL. A 24-hour interval on a machine
// that is suspended most of the time measures UPTIME, so a laptop awake two
// hours a day sweeps every twelve days and its store grows past the retention
// it advertises. Comparing dates means a box that wakes after a fortnight
// sweeps on its first pass.
func storeSweepIfDue(now time.Time) {
	day := now.UTC().Format("2006-01-02")
	storeSweepMu.Lock()
	if storeSweepLast == day {
		storeSweepMu.Unlock()
		return
	}
	storeSweepLast = day
	storeSweepMu.Unlock()
	// The error is dropped: a sweep that cannot read its own directory is not a
	// reason to stop journalling, and the next pass tries again tomorrow. What
	// it would cost is disk, which the cap already bounds.
	_, _ = storeSweep(now)
}

func storeSweep(now time.Time) (removed int, err error) {
	root, rErr := storeDir()
	if rErr != nil {
		return 0, rErr
	}
	cutoff := now.UTC().Add(-storeRetention)
	walkErr := filepath.Walk(root, func(p string, fi os.FileInfo, e error) error {
		if e != nil || fi == nil || fi.IsDir() {
			return nil
		}
		// Both shapes this store writes: `<date>.jsonl` and its `<date>.jsonl.capped`
		// seal marker. A name that does not reduce to a date is left alone rather
		// than guessed at — the sweep deletes things, so an unrecognised name is
		// the one case where doing nothing is always right.
		// REQUIRE A SUFFIX THIS STORE WRITES. Trimming optionally meant a bare
		// `2026-07-01` with no extension also parsed and was deleted — measured
		// in review. Nothing else writes into this 0700 directory today, so
		// nothing was at risk; a sweep that deletes a shape its own comment does
		// not claim is a sweep whose blast radius is larger than it reads.
		name := fi.Name()
		switch {
		case strings.HasSuffix(name, ".jsonl"+storeSealSuffix):
			name = strings.TrimSuffix(name, ".jsonl"+storeSealSuffix)
		case strings.HasSuffix(name, ".jsonl"):
			name = strings.TrimSuffix(name, ".jsonl")
		default:
			return nil
		}
		day, pErr := time.Parse("2006-01-02", name)
		if pErr != nil {
			return nil
		}
		if day.Before(cutoff) {
			if os.Remove(p) == nil {
				removed++
			}
		}
		return nil
	})
	return removed, walkErr
}
