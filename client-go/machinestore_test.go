package main

// machinestore_test.go — the machine store's journal.
//
// EVERY TEST HERE DRIVES storeRecordPass AND READS THE FILE BACK. None of them
// asserts a value this test supplied one seam above the line under test — a
// failure earlier rounds kept producing. The fixtures build a deltaReport the
// way deltaPass would; what is checked is what landed on disk.

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// storeReport builds a pass that DID compare, over a COMPLETE scan, holding the
// findings given. Complete matters: a partial scan closes nothing (the platform
// saw only recognised programs), so a helper that left it false would make
// every close-path test silently vacuous.
func storeReport(baselineDigest string, findings ...deltaEvent) deltaReport {
	return deltaReport{
		Baseline: deltaBaselineOK, BaselineDigest: baselineDigest,
		BaselineTakenAt: "2026-09-19T00:00:00Z", Coverage: "all-processes",
		Complete: true, Findings: findings,
	}
}

func storeFinding(fp, level string) deltaEvent {
	return deltaEvent{
		Kind: deltaProcNew, Level: level, Tier: "new", FP: fp,
		Entry: baselineEntry{
			FP: fp, Kind: "process", Exe: "/usr/local/bin/" + fp,
			ExeDigest: "sha256:" + fp, User: "root", ArgvShape: fp + " --serve",
		},
		FirstSeen: "2026-09-19T01:00:00Z",
	}
}

// storeReadJournal returns the journal lines for a day, in file order.
func storeReadJournal(t *testing.T, day time.Time) []storeLine {
	t.Helper()
	p, err := storeDayPath(storeFindings, day)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []storeLine
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var l storeLine
		if err := json.Unmarshal([]byte(ln), &l); err != nil {
			t.Fatalf("a journal line is not valid JSON: %v\n%s", err, ln)
		}
		out = append(out, l)
	}
	return out
}

// THE CENTRAL CLAIM OF THE FILE. A finding is pinned until a human resolves it,
// and the pass runs every 60 seconds — so the difference between a journal and
// a clock is that the second pass writes nothing. If this ever regresses, one
// unresolved finding becomes 1,440 lines a day.
func TestAPinnedFindingIsWrittenOnceNotOncePerPass(t *testing.T) {
	isolateConfigDir(t)
	r := storeReport("base-a", storeFinding("aaa", deltaHigh))
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	n, err := storeRecordPass(r, at)
	if err != nil || n != 1 {
		t.Fatalf("the first sighting must write exactly one line: n=%d err=%v", n, err)
	}
	for i := 0; i < 20; i++ {
		n, err := storeRecordPass(r, at.Add(time.Duration(i+1)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("pass %d re-wrote a finding nothing about which had changed (%d lines)", i+2, n)
		}
	}
	lines := storeReadJournal(t, at)
	if len(lines) != 1 {
		t.Fatalf("21 passes over one unchanged finding wrote %d lines, want 1", len(lines))
	}
	if lines[0].Transition != "opened" {
		t.Fatalf("transition = %q, want opened", lines[0].Transition)
	}
	if lines[0].Event == nil || lines[0].Event.FP != "aaa" {
		t.Fatalf("the line must carry the whole event: %+v", lines[0].Event)
	}
	if lines[0].Baseline != "base-a" {
		t.Fatalf("baseline = %q — a line that cannot name its accounting is not evidence", lines[0].Baseline)
	}
}

// A notice that becomes a critical is not the same finding, and a journal that
// records only `opened` would never say it moved.
func TestAFindingThatChangesLevelIsWrittenAgain(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaNotice)), at); err != nil {
		t.Fatal(err)
	}
	n, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaCritical)), at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("a level change wrote %d lines, want 1", n)
	}
	lines := storeReadJournal(t, at)
	if len(lines) != 2 || lines[1].Transition != "changed" {
		t.Fatalf("want opened then changed, got %s", storeTransitions(lines))
	}
	if lines[1].Event.Level != deltaCritical {
		t.Fatalf("the changed line carries level %q, want critical", lines[1].Event.Level)
	}
}

// PIDs churn on every service restart. If they were material, a machine that
// restarts nginx nightly would write a `changed` line every night about a
// finding that did not change.
func TestARestartAloneIsNotAChange(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	first := storeFinding("aaa", deltaHigh)
	first.PIDs = []int{101, 102}
	second := storeFinding("aaa", deltaHigh)
	second.PIDs = []int{9001, 9002}

	if _, err := storeRecordPass(storeReport("base-a", first), at); err != nil {
		t.Fatal(err)
	}
	n, err := storeRecordPass(storeReport("base-a", second), at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("new pids alone wrote %d lines — pids must not be material", n)
	}
}

func TestAFindingThatStopsBeingReportedIsClosed(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a",
		storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaWarn)), at); err != nil {
		t.Fatal(err)
	}
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, at)
	if len(lines) != 3 {
		t.Fatalf("want 2 opened + 1 closed, got %s", storeTransitions(lines))
	}
	last := lines[2]
	if last.Transition != "closed" || last.Event.FP != "bbb" {
		t.Fatalf("the third line must close bbb: %+v", last)
	}
	// The host must never read `closed` as `resolved` — oversight.py:39-44 makes
	// the same distinction and this is the half that has to say so out loud.
	if !strings.Contains(last.Note, "not the same as resolved") {
		t.Fatalf("a closed line must say what it does not mean: %q", last.Note)
	}
	// And it must not re-close on the next pass.
	n, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), at.Add(2*time.Minute))
	if err != nil || n != 0 {
		t.Fatalf("bbb was closed twice: n=%d err=%v", n, err)
	}
}

// THE DANGEROUS ONE. "I could not look" must never be written as "there is
// nothing there". A pass with no authority, or no accounting, closes nothing —
// otherwise deleting the accounting produces a journal showing every finding on
// the box resolving cleanly, which is the most reassuring possible lie.
func TestAPassThatCouldNotCompareWritesNothingAndClosesNothing(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaCritical)), at); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{deltaBaselineNone, deltaBaselineNoAuth, deltaBaselineStale} {
		blind := deltaReport{Baseline: state}
		n, err := storeRecordPass(blind, at.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("a %q pass wrote %d lines", state, n)
		}
		lines := storeReadJournal(t, at)
		if len(lines) != 1 {
			t.Fatalf("a %q pass changed the journal: %s", state, storeTransitions(lines))
		}
	}
	// And the finding is still open afterwards, so a real pass does not re-open it.
	n, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaCritical)), at.Add(time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("a blind pass lost the open set: n=%d err=%v", n, err)
	}
}

// An `edited` accounting still compares — it is a warning, not a blindness —
// so its findings must be journalled.
func TestAnEditedAccountingStillJournals(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	r := storeReport("base-a", storeFinding("aaa", deltaHigh))
	r.Baseline = deltaBaselineEdit
	n, err := storeRecordPass(r, at)
	if err != nil || n != 1 {
		t.Fatalf("an edited accounting must still journal: n=%d err=%v", n, err)
	}
}

// A retake redefines normal. Findings measured against the old accounting are
// not comparable to the new one (deltastate.go:36-38), so the open set resets —
// and the journal shows the re-open rather than going quiet about it.
func TestARetakeReopensAgainstTheNewAccounting(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), at); err != nil {
		t.Fatal(err)
	}
	// THIS TEST PREVIOUSLY PINNED A BUG. It asserted exactly 2 lines, which is
	// what you get when a retake silently drops the old open set — the finding
	// against base-a left the journal with no line at all, and the file's claim
	// that replaying reconstructs the open set was false. The retake must CLOSE
	// what it stops tracking and then re-open what is still there.
	n, err := storeRecordPass(storeReport("base-b", storeFinding("aaa", deltaHigh)), at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("a retake wrote %d lines, want 2 (close against the old accounting, open against the new)", n)
	}
	lines := storeReadJournal(t, at)
	if len(lines) != 3 {
		t.Fatalf("want opened closed opened, got %s", storeTransitions(lines))
	}
	if lines[1].Transition != "closed" || lines[1].Event.FP != "aaa" {
		t.Fatalf("the retake must close the finding it made incomparable: %+v", lines[1])
	}
	if !strings.Contains(lines[1].Note, "retaken") {
		t.Fatalf("the closing line must say why: %q", lines[1].Note)
	}
	if lines[2].Transition != "opened" || lines[2].Baseline != "base-b" {
		t.Fatalf("the re-opened line must stand against base-b: %+v", lines[2])
	}
}

// A finding that opens while the day-file is SEALED must not be recorded as
// open — otherwise the journal never mentions it again, on any pass or any
// later day, and its eventual `closed` refers to a fingerprint nothing opened.
// This was measured in review as a permanent loss.
func TestAFindingRefusedByTheCapIsNotRecordedAsOpen(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	storeFillToCap(t, day1)

	// Day 1: the finding is refused, so nothing is written for it.
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("crit", deltaCritical)), day1); err != nil {
		t.Fatal(err)
	}
	for _, l := range storeReadJournal(t, day1) {
		if l.Event != nil && l.Event.FP == "crit" {
			t.Fatal("the fixture did not actually seal the day")
		}
	}
	// Day 2: a fresh, unsealed file. The finding must appear as OPENED here.
	day2 := day1.Add(24 * time.Hour)
	n, err := storeRecordPass(storeReport("base-a", storeFinding("crit", deltaCritical)), day2)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("a finding refused by a sealed day was lost for good — it never re-opened")
	}
	lines := storeReadJournal(t, day2)
	found := false
	for _, l := range lines {
		if l.Transition == "opened" && l.Event != nil && l.Event.FP == "crit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("day 2 must open the finding the sealed day refused, got %s", storeTransitions(lines))
	}
}

// The notice is written ONCE and the day is then sealed. Measured in review at
// four notices in one file with ordinary lines between them, while the notice
// itself said the file "stops here".
func TestACappedDaySealsAndNothingFollowsTheNotice(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	storeFillToCap(t, at)

	// Many further passes, each offering new findings of varying size.
	for i := 0; i < 6; i++ {
		if _, err := storeRecordPass(storeReport("base-a",
			storeFinding(fmt.Sprintf("f%d", i), deltaHigh)), at.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	lines := storeReadJournal(t, at)
	notices := 0
	for i, l := range lines {
		if l.Transition == storeCapped {
			notices++
			if i != len(lines)-1 {
				t.Fatalf("a line follows the capped notice at %d of %d: %s",
					i, len(lines), storeTransitions(lines[i:]))
			}
		}
	}
	if notices != 1 {
		t.Fatalf("want exactly one capped notice, got %d", notices)
	}
	p, err := storeDayPath(storeFindings, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + storeSealSuffix); err != nil {
		t.Fatal("the capped day was not sealed")
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > storeDayCap {
		t.Fatalf("the file crossed its ceiling: %d > %d", fi.Size(), storeDayCap)
	}
}

// A PARTIAL SCAN CLOSES NOTHING. On a platform with no unfiltered process walk
// only recognised programs were compared, so an entry missing from the pass may
// never have been looked at — closing it writes "this went away" from a pass
// that did not check.
func TestAPartialScanClosesNothing(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	full := storeReport("base-a", storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaHigh))
	full.Complete = true
	if _, err := storeRecordPass(full, at); err != nil {
		t.Fatal(err)
	}
	partial := storeReport("base-a", storeFinding("aaa", deltaHigh))
	partial.Complete = false
	n, err := storeRecordPass(partial, at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a partial scan closed %d finding(s)", n)
	}
	// A COMPLETE pass that still omits bbb does close it.
	again := storeReport("base-a", storeFinding("aaa", deltaHigh))
	again.Complete = true
	if _, err := storeRecordPass(again, at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, at)
	if lines[len(lines)-1].Transition != "closed" {
		t.Fatalf("a complete pass must still close: %s", storeTransitions(lines))
	}
}

// A CONSISTENTLY FILTERED PLATFORM STILL CLOSES. baseline_all_other.go returns
// false unconditionally on darwin and windows, so Complete is permanently false
// there — gating closes on it alone meant no finding ever closed on a Mac or a
// Windows box and the open set grew for the life of the machine. Those
// platforms are not blind, they are filtered on BOTH sides: the accounting was
// taken through the same recognised-only walk, so the scopes agree and an
// absence really is an absence.
func TestAConsistentlyFilteredPlatformStillCloses(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	filtered := func(findings ...deltaEvent) deltaReport {
		r := storeReport("base-a", findings...)
		r.Complete = false                                                  // the non-Linux walk
		r.Coverage = "processes=recognised-only,schedulers=recognised-only" // and so was the accounting
		return r
	}
	if _, err := storeRecordPass(filtered(
		storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaHigh)), at); err != nil {
		t.Fatal(err)
	}
	if _, err := storeRecordPass(filtered(storeFinding("aaa", deltaHigh)), at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, at)
	if lines[len(lines)-1].Transition != "closed" {
		t.Fatalf("a filtered platform never closed anything: %s", storeTransitions(lines))
	}

	// And the genuine MISMATCH still closes nothing: an all-processes accounting
	// compared against a partial walk may simply not have looked.
	isolateConfigDir(t)
	mismatch := func(findings ...deltaEvent) deltaReport {
		r := storeReport("base-a", findings...)
		r.Complete = false
		r.Coverage = "processes=all,schedulers=all"
		return r
	}
	if _, err := storeRecordPass(mismatch(
		storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaHigh)), at); err != nil {
		t.Fatal(err)
	}
	n, err := storeRecordPass(mismatch(storeFinding("aaa", deltaHigh)), at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a narrower pass than the accounting closed %d finding(s)", n)
	}
}

// Each day-file is self-contained: a finding still open at a rollover is named
// in ONE snapshot line, so a replay whose window starts inside this file still
// knows what was open.
func TestANewDayFileOpensWithOneSnapshotLine(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	r := storeReport("base-a", storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaHigh))
	if _, err := storeRecordPass(r, day1); err != nil {
		t.Fatal(err)
	}
	day2 := day1.Add(24 * time.Hour)
	if _, err := storeRecordPass(r, day2); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, day2)
	if len(lines) != 1 || lines[0].Transition != storeDayOpen {
		t.Fatalf("day 2 must open with ONE snapshot line, got %s", storeTransitions(lines))
	}
	if lines[0].OpenCount != 2 {
		t.Fatalf("snapshot says %d open, want 2", lines[0].OpenCount)
	}
	if strings.Join(lines[0].OpenFPs, ",") != "aaa,bbb" {
		t.Fatalf("snapshot names %v", lines[0].OpenFPs)
	}
	// Not repeated within the day.
	if _, err := storeRecordPass(r, day2.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := len(storeReadJournal(t, day2)); got != 1 {
		t.Fatalf("the snapshot repeated within one day: %d lines", got)
	}
}

// THE LOCKUP THIS REPLACED. The first version wrote one line PER open finding,
// ahead of the day's real work — measured in review as a permanent fixed point
// where the shelf wrote nothing but its own memory and a new critical was never
// journalled at all. A large open set must still leave room for the day's
// findings.
func TestALargeOpenSetDoesNotStarveTheDay(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	var many []deltaEvent
	for i := 0; i < 4000; i++ {
		many = append(many, storeFinding(fmt.Sprintf("f%04d", i), deltaWarn))
	}
	if _, err := storeRecordPass(storeReport("base-a", many...), day1); err != nil {
		t.Fatal(err)
	}
	day2 := day1.Add(24 * time.Hour)
	// The same 4,000 still open, PLUS a new critical.
	withNew := append(append([]deltaEvent(nil), many...), storeFinding("crit", deltaCritical))
	if _, err := storeRecordPass(storeReport("base-a", withNew...), day2); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, day2)
	var snapshots, opened int
	sawCritical := false
	for _, l := range lines {
		switch l.Transition {
		case storeDayOpen:
			snapshots++
		case "opened":
			opened++
			if l.Event != nil && l.Event.FP == "crit" {
				sawCritical = true
			}
		}
	}
	if snapshots != 1 {
		t.Fatalf("want exactly one snapshot line, got %d", snapshots)
	}
	if !sawCritical {
		t.Fatalf("a new critical was starved by the open set: %d lines, %d opened",
			len(lines), opened)
	}
}

// The snapshot is BOUNDED, and says so when it cuts the list — otherwise a
// truncated list reads as the whole open set.
func TestTheSnapshotIsBoundedAndSaysSoWhenItCuts(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	var many []deltaEvent
	for i := 0; i < storeSnapshotMaxFPs+50; i++ {
		many = append(many, storeFinding(fmt.Sprintf("f%04d", i), deltaWarn))
	}
	if _, err := storeRecordPass(storeReport("base-a", many...), day1); err != nil {
		t.Fatal(err)
	}
	day2 := day1.Add(24 * time.Hour)
	if _, err := storeRecordPass(storeReport("base-a", many...), day2); err != nil {
		t.Fatal(err)
	}
	snap := storeReadJournal(t, day2)[0]
	if len(snap.OpenFPs) != storeSnapshotMaxFPs {
		t.Fatalf("listed %d fingerprints, want the bound %d", len(snap.OpenFPs), storeSnapshotMaxFPs)
	}
	if snap.OpenCount != storeSnapshotMaxFPs+50 {
		t.Fatalf("count is %d — the count must be the WHOLE set, not the listed part",
			snap.OpenCount)
	}
	if !strings.Contains(snap.Note, "counted, not listed") {
		t.Fatalf("a cut list must say it was cut: %q", snap.Note)
	}
}

// A box that was off for a week still opens its next day-file with a snapshot.
// Nothing covered the multi-day gap, so a mutation narrowing the test to
// "yesterday only" survived.
func TestAMultiDayGapStillWritesTheSnapshot(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	r := storeReport("base-a", storeFinding("aaa", deltaHigh))
	if _, err := storeRecordPass(r, day1); err != nil {
		t.Fatal(err)
	}
	later := day1.Add(7 * 24 * time.Hour)
	if _, err := storeRecordPass(r, later); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, later)
	if len(lines) != 1 || lines[0].Transition != storeDayOpen {
		t.Fatalf("a box back after a week must still open with a snapshot, got %s",
			storeTransitions(lines))
	}
}

// A REFUSED CLOSE LEAVES THE FINDING OPEN. The close did not happen, so
// forgetting it loses the close for ever — the retake path did exactly that and
// dropped a finding's only record permanently.
func TestARefusedCloseKeepsTheFindingOpen(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a",
		storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaHigh)), day1); err != nil {
		t.Fatal(err)
	}
	storeSealDay(t, day1)
	// bbb goes away while the day is sealed: the close is refused.
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), day1); err != nil {
		t.Fatal(err)
	}
	// The next day must carry the close, not have forgotten it.
	day2 := day1.Add(24 * time.Hour)
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), day2); err != nil {
		t.Fatal(err)
	}
	var closed bool
	for _, l := range storeReadJournal(t, day2) {
		if l.Transition == "closed" && l.Event != nil && l.Event.FP == "bbb" {
			closed = true
		}
	}
	if !closed {
		t.Fatalf("a close refused by a sealed day was lost: %s",
			storeTransitions(storeReadJournal(t, day2)))
	}
}

// A RETAKE ON A SEALED DAY MUST RETRY. If the remembered baseline advances
// while its closes were refused, the retake branch is never re-entered and
// those findings' only line anywhere is their original `opened`.
func TestARetakeRefusedByASealedDayIsRetriedTheNextDay(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a",
		storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaHigh)), day1); err != nil {
		t.Fatal(err)
	}
	storeSealDay(t, day1)
	// The retake lands on a sealed day: every close is refused.
	if _, err := storeRecordPass(storeReport("base-b", storeFinding("aaa", deltaHigh)), day1); err != nil {
		t.Fatal(err)
	}
	day2 := day1.Add(24 * time.Hour)
	if _, err := storeRecordPass(storeReport("base-b", storeFinding("aaa", deltaHigh)), day2); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, l := range storeReadJournal(t, day2) {
		if l.Transition == "closed" && l.Event != nil {
			seen[l.Event.FP] = true
		}
	}
	if !seen["aaa"] || !seen["bbb"] {
		t.Fatalf("the retake's closes were not retried after the seal: %s",
			storeTransitions(storeReadJournal(t, day2)))
	}
}

// storeSealDay fills a day-file to its ceiling so every later line is refused.
func storeSealDay(t *testing.T, day time.Time) {
	t.Helper()
	p, err := storeDayPath(storeFindings, day)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	filler := append(bytesOfLine(t), '\n')
	buf := append([]byte(nil), cur...)
	for len(buf)+len(filler) < storeDayCap-storeNoticeReserve {
		buf = append(buf, filler...)
	}
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := storeWriteLine(p+storeSealSuffix, nil); err != nil {
		t.Fatal(err)
	}
}

// A `changed` that displaces a DIFFERENT baseline entry is a real change, even
// when every other material field is equal.
func TestDisplacingADifferentEntryIsAChange(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	mk := func(wasFP string) deltaEvent {
		ev := storeFinding("aaa", deltaHigh)
		ev.Kind, ev.Reason = deltaProcChanged, deltaReasonExeDigest
		ev.Was = &baselineEntry{FP: wasFP, Kind: "process"}
		return ev
	}
	if _, err := storeRecordPass(storeReport("base-a", mk("old-x")), at); err != nil {
		t.Fatal(err)
	}
	n, err := storeRecordPass(storeReport("base-a", mk("old-y")), at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("displacing a different entry wrote %d lines, want 1", n)
	}
}

// storeFillToCap seals a day-file by filling it to its append ceiling.
func storeFillToCap(t *testing.T, day time.Time) {
	t.Helper()
	p, err := storeDayPath(storeFindings, day)
	if err != nil {
		t.Fatal(err)
	}
	filler := append(bytesOfLine(t), '\n')
	var buf []byte
	for len(buf)+len(filler) < storeDayCap-storeNoticeReserve {
		buf = append(buf, filler...)
	}
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	// Trip the cap so the notice is written and the seal laid down.
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("sealer", deltaWarn)), day); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + storeSealSuffix); err != nil {
		t.Fatal("storeFillToCap did not seal the day")
	}
}

// The day-file rolls on UTC, not local time — a host reading a fleet across
// timezones cannot know each box's offset.
func TestTheJournalRollsOnUTCMidnight(t *testing.T) {
	isolateConfigDir(t)
	// THE TWO INSTANTS MUST DISAGREE ABOUT WHICH DAY IT IS, or this test cannot
	// fail. 08:00 on the 20th in a zone ten hours ahead is 22:00 on the 19th in
	// UTC: local time names a second day-file, UTC names one. The first version
	// of this test used 23:30 in the same zone, which is 13:30 UTC — still the
	// 19th either way, so it passed with the UTC conversion deleted.
	ahead := time.FixedZone("ahead", 10*3600)
	first := time.Date(2026, 9, 19, 13, 0, 0, 0, time.UTC)
	second := time.Date(2026, 9, 20, 8, 0, 0, 0, ahead)
	if second.Format("2006-01-02") == second.UTC().Format("2006-01-02") {
		t.Fatal("the fixture's two clocks agree on the day, so this test cannot fail")
	}
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), first); err != nil {
		t.Fatal(err)
	}
	if _, err := storeRecordPass(storeReport("base-a",
		storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaHigh)), second); err != nil {
		t.Fatal(err)
	}
	if got := len(storeReadJournal(t, first)); got != 2 {
		t.Fatalf("both lines belong to the same UTC day: got %d", got)
	}
}

// The cap writes its notice ONCE and then goes silent — and the notice is in
// band, so a host replaying the day sees the truncation instead of inferring it
// from a gap.
func TestACappedDayFileSaysSoOnceAndThenStops(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	p, err := storeDayPath(storeFindings, at)
	if err != nil {
		t.Fatal(err)
	}
	// Fill to just under the append ceiling with well-formed lines, so the NEXT
	// line is the one that trips the cap. The append ceiling is the cap less
	// the reserve the notice is written out of.
	filler := append(bytesOfLine(t), '\n')
	var buf []byte
	for len(buf)+len(filler) < storeDayCap-storeNoticeReserve {
		buf = append(buf, filler...)
	}
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), at); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, at)
	last := lines[len(lines)-1]
	if last.Transition != storeCapped {
		t.Fatalf("the capping line must be the notice, got %q", last.Transition)
	}
	if !strings.Contains(last.Note, "ceiling") {
		t.Fatalf("the notice must say what happened: %q", last.Note)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	// A further pass with a NEW finding must add nothing at all.
	if _, err := storeRecordPass(storeReport("base-a",
		storeFinding("aaa", deltaHigh), storeFinding("ccc", deltaHigh)), at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("a capped file grew by %d bytes", after.Size()-before.Size())
	}
	if after.Size() > storeDayCap {
		t.Fatalf("the file crossed its own ceiling: %d > %d", after.Size(), storeDayCap)
	}
}

func bytesOfLine(t *testing.T) []byte {
	t.Helper()
	// Computed, not a literal. TestNoFixtureHardcodesAMomentInTime bans a
	// literal `At:` because stepup age-checks that field name; this At is a
	// journal write-stamp and is never age-checked, but the filler's timestamp
	// means nothing to this test either way, so the fixture moves rather than
	// the guard. Widening a scan to admit one benign case is how the next real
	// one gets through.
	b, err := json.Marshal(storeLine{
		At: stamp(time.Now()), Transition: "opened", Machine: "box",
		Version: "test", Baseline: "base-a", Event: &deltaEvent{FP: "filler"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Retention reads the NAME, not the mtime. A restored-from-backup file has a
// fresh mtime and is still a month-old record; a sweep keyed on mtime would
// keep exactly the wrong ones and delete the rest.
func TestTheSweepDeletesByTheDayInTheNameNotTheMtime(t *testing.T) {
	isolateConfigDir(t)
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	shelf, err := storeShelf(storeFindings)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(shelf, "2026-07-01.jsonl")  // 80 days back
	oldSeal := old + storeSealSuffix                 // its seal marker
	keep := filepath.Join(shelf, "2026-09-18.jsonl") // yesterday
	keepSeal := keep + storeSealSuffix
	odd := filepath.Join(shelf, "notes-for-me.jsonl") // not ours
	// A DATE-SHAPED NAME WITH NO SUFFIX THIS STORE WRITES. Trimming the
	// extension optionally meant this parsed as a day and was deleted; nothing
	// else writes into this 0700 dir today, but a sweep whose blast radius is
	// wider than its comment says is a sweep waiting to surprise somebody.
	bare := filepath.Join(shelf, "2026-07-01")
	for _, p := range []string{old, oldSeal, keep, keepSeal, odd, bare} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Every file gets a mtime of RIGHT NOW, so an mtime-based sweep would
		// delete none of them and this test would fail.
		if err := os.Chtimes(p, now, now); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := storeSweep(now)
	if err != nil {
		t.Fatal(err)
	}
	// The day-file AND its seal marker: a sweep blind to the marker leaves a
	// permanent .capped file behind for every day that ever hit its ceiling.
	if removed != 2 {
		t.Fatalf("swept %d files, want 2 (the day-file and its seal)", removed)
	}
	if _, err := os.Stat(oldSeal); !os.IsNotExist(err) {
		t.Fatal("the old day's seal marker survived the sweep")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the 80-day-old day-file survived the sweep")
	}
	for _, p := range []string{keep, keepSeal, odd, bare} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was removed and should not have been", filepath.Base(p))
		}
	}
}

// The store root lives INSIDE the state dir, so a read that escapes it lands on
// the bastion's own state rather than beside the pairings and the TOTP secret.
func TestTheStoreRootIsNestedInsideTheStateDir(t *testing.T) {
	cd := isolateConfigDir(t)
	root, err := storeDir()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(root) != cd {
		t.Fatalf("store root %q is not directly inside the state dir %q", root, cd)
	}
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("store root is %v, want 0700", fi.Mode().Perm())
	}
}

func storeTransitions(lines []storeLine) string {
	var out []string
	for _, l := range lines {
		out = append(out, l.Transition)
	}
	return "[" + strings.Join(out, " ") + "]"
}

// ── the alerts shelf ────────────────────────────────────────────────────────

func storeReadAlerts(t *testing.T, day time.Time) []storeAlertLine {
	t.Helper()
	p, err := storeDayPath(storeAlerts, day)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []storeAlertLine
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var l storeAlertLine
		if err := json.Unmarshal([]byte(ln), &l); err != nil {
			t.Fatalf("alert line is not valid JSON: %v\n%s", err, ln)
		}
		out = append(out, l)
	}
	return out
}

// A refresh runs every few minutes and republishes the same firing set. Like
// the findings journal, only the edges are written.
func TestAnAlertIsJournalledOnceUntilItClears(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	firing := &alertsSummary{Firing: 2, Critical: 1, Warning: 1,
		Fingerprints: []string{"fp-a", "fp-b"}}

	n, err := storeRecordAlerts(firing, at)
	if err != nil || n != 2 {
		t.Fatalf("two firing alerts must write two lines: n=%d err=%v", n, err)
	}
	for i := 0; i < 5; i++ {
		if n, err := storeRecordAlerts(firing, at.Add(time.Duration(i+1)*time.Minute)); err != nil || n != 0 {
			t.Fatalf("an unchanged alert set re-wrote %d lines (err=%v)", n, err)
		}
	}
	// fp-b clears.
	cleared := &alertsSummary{Firing: 1, Critical: 1, Fingerprints: []string{"fp-a"}}
	if n, err := storeRecordAlerts(cleared, at.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("a cleared alert must write one line: n=%d err=%v", n, err)
	}
	lines := storeReadAlerts(t, at)
	if len(lines) != 3 {
		t.Fatalf("want firing firing cleared, got %d lines", len(lines))
	}
	if lines[2].Transition != "cleared" || lines[2].FP != "fp-b" {
		t.Fatalf("the third line must clear fp-b: %+v", lines[2])
	}
	// EVERY count, not just firing. A reader joining the journal mid-day takes
	// its totals from the line; asserting one of the three left the other two
	// untested, which a mutation dropping them proved by surviving.
	if lines[0].Firing != 2 || lines[0].Critical != 1 || lines[0].Warning != 1 {
		t.Fatalf("the opening line must carry all three counts as of itself: %+v", lines[0])
	}
	if lines[2].Firing != 1 || lines[2].Critical != 1 || lines[2].Warning != 0 {
		t.Fatalf("the clearing line must carry the counts as of itself: %+v", lines[2])
	}
}

// NIL IS NOT EMPTY. A box with no Alertmanager configured, or one that has not
// refreshed yet, is not watching anything — it must not be read as watching
// nothing, and it must not clear alerts it can no longer see.
func TestAnUnconfiguredAlertSourceClearsNothing(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordAlerts(&alertsSummary{Firing: 1, Critical: 1,
		Fingerprints: []string{"fp-a"}}, at); err != nil {
		t.Fatal(err)
	}
	n, err := storeRecordAlerts(nil, at.Add(time.Minute))
	if err != nil || n != 0 {
		t.Fatalf("a nil summary wrote %d lines (err=%v)", n, err)
	}
	if got := len(storeReadAlerts(t, at)); got != 1 {
		t.Fatalf("a nil summary changed the journal: %d lines", got)
	}
	// And fp-a is still open, so a real summary does not re-open it.
	if n, err := storeRecordAlerts(&alertsSummary{Firing: 1, Critical: 1,
		Fingerprints: []string{"fp-a"}}, at.Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("the nil summary lost the open set: n=%d err=%v", n, err)
	}
}

// The summary names at most twenty fingerprints. Past that the set is a sample,
// so the journal says so rather than letting a truncated list read as the whole
// one — otherwise alert 21 clearing is indistinguishable from it never firing.
func TestATruncatedAlertSummarySaysSoInBand(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordAlerts(&alertsSummary{Firing: 57, Critical: 3,
		Fingerprints: []string{"fp-a", "fp-b"}}, at); err != nil {
		t.Fatal(err)
	}
	lines := storeReadAlerts(t, at)
	last := lines[len(lines)-1]
	if last.Transition != "truncated" {
		t.Fatalf("a truncated summary must end in a truncated line, got %q", last.Transition)
	}
	if !strings.Contains(last.Note, "57") || !strings.Contains(last.Note, "2") {
		t.Fatalf("the note must name both numbers: %q", last.Note)
	}
}

// ── the sweep's cadence ─────────────────────────────────────────────────────

// Keyed on the DATE, not an interval. An interval measures uptime, so a laptop
// awake two hours a day would sweep every twelve days and its store would grow
// past the retention it advertises.
func TestTheSweepRunsOncePerDayAndNotOncePerUptimeInterval(t *testing.T) {
	isolateConfigDir(t)
	shelf, err := storeShelf(storeFindings)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string) string {
		p := filepath.Join(shelf, name)
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := write("2026-07-01.jsonl")
	day := time.Date(2026, 9, 19, 0, 30, 0, 0, time.UTC)

	storeSweepIfDue(day)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the first call of the day did not sweep")
	}
	// A second old file appearing later the SAME day is not swept again.
	old2 := write("2026-07-02.jsonl")
	storeSweepIfDue(day.Add(23 * time.Hour))
	if _, err := os.Stat(old2); err != nil {
		t.Fatal("the sweep ran twice in one UTC day")
	}
	// The next UTC day sweeps again.
	storeSweepIfDue(day.Add(25 * time.Hour))
	if _, err := os.Stat(old2); !os.IsNotExist(err) {
		t.Fatal("the sweep did not run on the next day")
	}
}

// The truncation notice must not become a clock. Measured in review: written
// unconditionally, five refreshes of an unchanged 57-alert set produced
// 21, 1, 1, 1, 1 lines — and refreshAlerts runs every 60s PER PAIRING.
func TestTheTruncationNoticeIsNotRepeatedOnEveryRefresh(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	big := &alertsSummary{Firing: 57, Critical: 3, Fingerprints: []string{"fp-a", "fp-b"}}

	first, err := storeRecordAlerts(big, at)
	if err != nil || first == 0 {
		t.Fatalf("the first refresh must write: n=%d err=%v", first, err)
	}
	for i := 0; i < 5; i++ {
		n, err := storeRecordAlerts(big, at.Add(time.Duration(i+1)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("refresh %d re-wrote %d line(s) for an unchanged alert set", i+2, n)
		}
	}
	notices := 0
	for _, l := range storeReadAlerts(t, at) {
		if l.Transition == "truncated" {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("want one truncation notice across six refreshes, got %d", notices)
	}
	// A CHANGE in the truncation is still reported — otherwise the count going
	// from 57 to 400 would be invisible.
	n, err := storeRecordAlerts(&alertsSummary{Firing: 400, Critical: 9,
		Fingerprints: []string{"fp-a", "fp-b"}}, at.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("a changed truncation must be reported: n=%d err=%v", n, err)
	}
	// AND THE LISTED HALF COUNTS TOO. Keying the dedup on `firing` alone misses
	// 400/2 -> 400/1: the same number of alerts firing, but the journal now
	// names fewer of them, so its blind spot GREW and the reader must be told.
	if _, err := storeRecordAlerts(&alertsSummary{Firing: 400, Critical: 9,
		Fingerprints: []string{"fp-a"}}, at.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var sawShrink bool
	for _, l := range storeReadAlerts(t, at) {
		if l.Transition == "truncated" && strings.Contains(l.Note, "names 1 of them") {
			sawShrink = true
		}
	}
	if !sawShrink {
		t.Fatal("the listed count shrank from 2 to 1 and no notice said so")
	}
}

// A single line larger than the ceiling must not create a file already past it.
// os.Stat returns ErrNotExist for a missing file, and an earlier version
// skipped the whole cap check in that branch.
func TestAnOversizedFirstLineCannotCreateAnAlreadyOverflowingFile(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	huge := storeFinding("huge", deltaCritical)
	// One evidence line past the ceiling on its own.
	huge.Evidence = []evidence{{Signal: "fixture", Tier: tierVerified,
		Value: strings.Repeat("x", storeDayCap+1)}}

	p, err := storeDayPath(storeFindings, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("the day-file must not exist yet, or this test proves nothing")
	}
	if _, err := storeRecordPass(storeReport("base-a", huge), at); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > storeDayCap {
		t.Fatalf("an oversized first line crossed the ceiling: %d > %d", fi.Size(), storeDayCap)
	}
	lines := storeReadJournal(t, at)
	if len(lines) != 1 || lines[0].Transition != storeCapped {
		t.Fatalf("want a lone capped notice, got %s", storeTransitions(lines))
	}
}

// refreshAlerts had no in-flight guard while refreshDelta did, and run.go
// starts ONE refresher PER PAIRING — so a box serving several hosts runs
// several in phase. Without the guard a slow goroutine holding an older summary
// can take storeMu after a newer one and journal an alert as `firing` that the
// newer pass just journalled as `cleared`: the order of the record inverts.
//
// Driven through the observeHTTPGet seam the suite already uses, so this
// measures the guard rather than asserting it.
func TestOnlyOneAlertsRefreshRunsAtATime(t *testing.T) {
	isolateConfigDir(t)
	defer withEndpointsFile(t, `{"alertmanager":"http://127.0.0.1:9093"}`)()

	release := make(chan struct{})
	var inFlight, calls int32
	origGet := observeHTTPGet
	observeHTTPGet = func(_ context.Context, _ string) ([]byte, int, error) {
		atomic.AddInt32(&calls, 1)
		if atomic.AddInt32(&inFlight, 1) > 1 {
			t.Error("two alerts refreshes were in flight at once")
		}
		<-release
		atomic.AddInt32(&inFlight, -1)
		return []byte(`{"status":"success","data":[]}`), 200, nil
	}
	defer func() { observeHTTPGet = origGet }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); refreshAlerts(context.Background()) }()

	// Wait until the first refresh is genuinely inside the fetch, or this races
	// to a pass rather than measuring anything.
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&calls) == 0 {
		if time.Now().After(deadline) {
			close(release)
			wg.Wait()
			t.Fatal("the first refresh never reached the fetch seam")
		}
		time.Sleep(time.Millisecond)
	}

	// The second must return AT ONCE rather than queueing behind the first.
	done := make(chan struct{})
	go func() { refreshAlerts(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		wg.Wait()
		t.Fatal("a concurrent refresh blocked instead of being refused by the in-flight guard")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("the guarded refresh still fetched: %d calls, want 1", got)
	}
	close(release)
	wg.Wait()
}

// The beat reports where the machine keeps its own record, and reporting it
// must not CREATE the directory: the beat fires every sixty seconds, and a
// path is a claim about where the record is, not an instruction to make one.
func TestTheBeatReportsTheStoreRootWithoutCreatingIt(t *testing.T) {
	isolateConfigDir(t)
	raw := buildHeartbeatBody("", "h", "linux", "test", "pk", "fp", "100.64.0.9", "ep", false, nil, nil, nil)
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	got, _ := body["machine_record_root"].(string)
	want, err := storeRootPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("beat reports %q, want %q", got, want)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("the reported root is not absolute: %q", got)
	}
	if _, err := os.Stat(got); !os.IsNotExist(err) {
		t.Fatalf("building a beat created the store directory %q", got)
	}
}

// ── round 2 verification: the last three ────────────────────────────────────

// A retake that coincides with a rollover must produce a day-file that replays
// on its own: the snapshot runs BEFORE the retake-close. Measured before the
// fix: `[closed aaa, closed bbb, opened aaa]` and no day_open line — two closes
// for fingerprints the file never introduced.
func TestARetakeOnARolloverDayStillOpensWithTheSnapshot(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a",
		storeFinding("aaa", deltaHigh), storeFinding("bbb", deltaHigh)), day1); err != nil {
		t.Fatal(err)
	}
	day2 := day1.Add(24 * time.Hour)
	if _, err := storeRecordPass(storeReport("base-b", storeFinding("aaa", deltaHigh)), day2); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, day2)
	got := storeTransitions(lines)
	if got != "[day_open closed closed opened]" {
		t.Fatalf("day 2 must replay alone: want [day_open closed closed opened], got %s", got)
	}
	if lines[0].OpenCount != 2 || strings.Join(lines[0].OpenFPs, ",") != "aaa,bbb" {
		t.Fatalf("the snapshot must name what the closes are about: %+v", lines[0])
	}
}

// A refused `changed` stays open under its OLD digest, so the next unsealed
// day writes `changed` — not a second `opened` for a finding already announced.
func TestARefusedChangeIsWrittenAsAChangeNotASecondOpen(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaNotice)), day1); err != nil {
		t.Fatal(err)
	}
	storeSealDay(t, day1)
	// Escalates while the day is sealed: the `changed` line is refused.
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaCritical)), day1); err != nil {
		t.Fatal(err)
	}
	day2 := day1.Add(24 * time.Hour)
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaCritical)), day2); err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, l := range storeReadJournal(t, day2) {
		if l.Event != nil && l.Event.FP == "aaa" {
			seen = append(seen, l.Transition)
		}
	}
	if strings.Join(seen, " ") != "changed" {
		t.Fatalf("the escalation must land as one `changed` on day 2, got %v", seen)
	}
}

// The alerts truncation state must not advance on a REFUSED line — a sealed
// alerts day recorded the notice as delivered, and the next day never wrote
// it. The fix was in round 1; nothing exercised the sealed-day path.
func TestATruncationNoticeRefusedByASealedDayIsWrittenTheNextDay(t *testing.T) {
	isolateConfigDir(t)
	day1 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	// Seal the ALERTS shelf for day 1.
	p, err := storeDayPath(storeAlerts, day1)
	if err != nil {
		t.Fatal(err)
	}
	filler := append(bytesOfLine(t), '\n')
	var buf []byte
	for len(buf)+len(filler) < storeDayCap-storeNoticeReserve {
		buf = append(buf, filler...)
	}
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := storeWriteLine(p+storeSealSuffix, nil); err != nil {
		t.Fatal(err)
	}
	big := &alertsSummary{Firing: 57, Critical: 3, Fingerprints: []string{"fp-a"}}
	if _, err := storeRecordAlerts(big, day1); err != nil {
		t.Fatal(err)
	}
	day2 := day1.Add(24 * time.Hour)
	if _, err := storeRecordAlerts(big, day2); err != nil {
		t.Fatal(err)
	}
	var notice bool
	for _, l := range storeReadAlerts(t, day2) {
		if l.Transition == "truncated" {
			notice = true
		}
	}
	if !notice {
		t.Fatal("the truncation notice refused on the sealed day was never written")
	}
}

// A v1 state file is MIGRATED, not discarded: a finding open under v1 that is
// gone after the upgrade gets its `closed` line.
func TestAV1StateFileIsCarriedAcrossTheVersionBump(t *testing.T) {
	isolateConfigDir(t)
	sp, err := storeStatePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(sp), 0o700); err != nil {
		t.Fatal(err)
	}
	v1 := `{"version":"privatae-store-state-v1","baseline":"base-a","open":{"aaa":"x","zzz":"y"}}`
	if err := os.WriteFile(sp, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	// Only aaa is still present; zzz went away during the upgrade window.
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), at); err != nil {
		t.Fatal(err)
	}
	var closedZ bool
	for _, l := range storeReadJournal(t, at) {
		if l.Transition == "closed" && l.Event != nil && l.Event.FP == "zzz" {
			closedZ = true
		}
		if l.Transition == "opened" && l.Event != nil && l.Event.FP == "aaa" {
			t.Fatal("a finding open under v1 was re-opened after the upgrade")
		}
	}
	if !closedZ {
		t.Fatal("a finding open under v1 that went away got no closed line after the upgrade")
	}
}

// ── the observe shelf ───────────────────────────────────────────────────────

func storeReadObserve(t *testing.T, op string, day time.Time) []storeObserveLine {
	t.Helper()
	p, err := storeDayPath(filepath.Join(storeObserve, storeSafeOpName(op)), day)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []storeObserveLine
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var l storeObserveLine
		if err := json.Unmarshal([]byte(ln), &l); err != nil {
			t.Fatalf("observe line is not valid JSON: %v\n%s", err, ln)
		}
		out = append(out, l)
	}
	return out
}

// END TO END THROUGH THE REAL PATH: the management dispatcher, this
// connection's account, writeObserve, the store. Not the writer called by
// hand — the round-1 review removed a writer nothing called, and the proof
// that this one is called is the dispatcher calling it.
func TestAnObserveResultIsRecordedOnTheMachine(t *testing.T) {
	isolateConfigDir(t)
	storeObserveDroppedReset()
	out, errOut, code := driveObserve(t, "observe:host", nil)
	if code != 0 {
		t.Fatalf("observe:host failed: %d %s", code, errOut)
	}
	lines := storeReadObserve(t, "observe:host", time.Now())
	if len(lines) != 1 {
		t.Fatalf("want one recorded result, got %d", len(lines))
	}
	l := lines[0]
	if l.Op != "observe:host" || l.Truncated || len(l.Result) == 0 {
		t.Fatalf("recorded line is not the result: %+v", l)
	}
	// The SAME bytes the host received — a record of a different answer than
	// the one sent is not a record.
	var sent, kept any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &sent); err != nil {
		t.Fatalf("the reply is not JSON: %v", err)
	}
	if err := json.Unmarshal(l.Result, &kept); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sent) != fmt.Sprint(kept) {
		t.Fatal("the recorded result differs from the reply the host received")
	}
	if storeObserveDroppedSnapshot() != nil {
		t.Fatal("a successful record counted as dropped")
	}
}

func TestTheRecordNamesWhoAskedAndWhat(t *testing.T) {
	isolateConfigDir(t)
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if !storeRecordObserve("observe:net", "member.host.privatae.ai", []string{"10.0.0.5:443"},
		[]byte(`{"tcp":"open"}`), now) {
		t.Fatal("a small result was not recorded")
	}
	l := storeReadObserve(t, "observe:net", now)[0]
	if l.AskedBy != "member.host.privatae.ai" || strings.Join(l.Args, ",") != "10.0.0.5:443" {
		t.Fatalf("who/what missing: %+v", l)
	}
	if string(l.Result) != `{"tcp":"open"}` || l.Bytes != len(`{"tcp":"open"}`) {
		t.Fatalf("result not kept whole: %+v", l)
	}
}

// A result past the line bound keeps its first 4 KiB and says how much was
// cut — the shape of what was seen, never nothing, and never a day-file eaten
// by one chatty op.
func TestAnOversizedResultIsKeptAsAHeadWithItsSize(t *testing.T) {
	isolateConfigDir(t)
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	big := []byte(`{"units":"` + strings.Repeat("u", storeObserveLineMax+5000) + `"}`)
	if !storeRecordObserve("observe:units", "h", nil, big, now) {
		t.Fatal("an oversized result was refused outright")
	}
	l := storeReadObserve(t, "observe:units", now)[0]
	if !l.Truncated || len(l.Result) != 0 || len(l.Head) != storeObserveHeadKeep || l.Bytes != len(big) {
		t.Fatalf("truncation shape wrong: truncated=%v result=%d head=%d bytes=%d",
			l.Truncated, len(l.Result), len(l.Head), l.Bytes)
	}
	p, _ := storeDayPath(filepath.Join(storeObserve, "observe-units"), now)
	fi, _ := os.Stat(p)
	if fi.Size() > int64(storeObserveLineMax) {
		t.Fatalf("the line on disk is %d bytes, over the %d bound", fi.Size(), storeObserveLineMax)
	}
}

// Only observe results are recorded here, and an op name cannot choose where
// on disk its record lands.
func TestOnlyObserveOpsAreRecordedAndTheNameCannotEscape(t *testing.T) {
	isolateConfigDir(t)
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	for _, op := range []string{"ctx_get", "dcn_list", "", "uptime"} {
		if storeRecordObserve(op, "h", nil, []byte(`{}`), now) {
			t.Fatalf("%q was recorded on the observe shelf", op)
		}
	}
	if !storeRecordObserve("observe:../../etc", "h", nil, []byte(`{}`), now) {
		t.Fatal("a hostile-looking observe name was refused rather than sanitised")
	}
	root, _ := storeDir()
	p := filepath.Join(root, storeObserve, "observe-etc", "2026-09-19.jsonl")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the sanitised record is not where it must be: %v", err)
	}
}

// A result the record could not keep is COUNTED, and the count rides the beat
// — a record with holes must never read as a quiet machine.
func TestADroppedResultIsCountedOnTheBeatByShelf(t *testing.T) {
	cd := isolateConfigDir(t)
	storeObserveDroppedReset()
	// A regular FILE where the store root must be a directory: every write fails.
	if err := os.MkdirAll(cd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cd, storeDirName), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	if storeRecordObserve("observe:host", "h", nil, []byte(`{}`), time.Now()) {
		t.Fatal("a write into a file-as-directory succeeded")
	}
	storeRecordObserve("observe:sockets", "h", nil, []byte(`{}`), time.Now())
	storeRecordObserve("observe:sockets", "h", nil, []byte(`{}`), time.Now())
	snap := storeObserveDroppedSnapshot()
	if snap["observe-host"] != 1 || snap["observe-sockets"] != 2 {
		t.Fatalf("dropped counts by shelf are wrong: %v", snap)
	}
	raw := buildHeartbeatBody("", "h", "linux", "test", "pk", "fp", "100.64.0.9", "ep", false, nil, nil, nil)
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	d, _ := body["machine_record_dropped"].(map[string]any)
	if d["observe-host"] != 1.0 || d["observe-sockets"] != 2.0 {
		t.Fatalf("the beat does not name the shelves with holes: %v", body["machine_record_dropped"])
	}
	// And an EMPTY OBJECT — never absent — when nothing was dropped and the
	// pairing may observe. Absent has to mean exactly one thing to the host:
	// this pairing is not entitled to say. (The first version omitted the key
	// at zero, and the host could not tell "whole" from "no longer allowed".)
	// A FRESH map: Unmarshal into a populated map merges keys.
	storeObserveDroppedReset()
	raw = buildHeartbeatBody("", "h", "linux", "test", "pk", "fp", "100.64.0.9", "ep", false, nil, nil, nil)
	body = map[string]any{}
	_ = json.Unmarshal([]byte(raw), &body)
	d2, present := body["machine_record_dropped"].(map[string]any)
	if !present || len(d2) != 0 {
		t.Fatalf("a whole record must travel as an empty object, got %v (present=%v)", body["machine_record_dropped"], present)
	}
}

// The sweep reaches the nested observe shelves.
func TestTheSweepReachesTheObserveShelves(t *testing.T) {
	isolateConfigDir(t)
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	dir, err := storeShelf(filepath.Join(storeObserve, "observe-net"))
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "2026-07-01.jsonl")
	keep := filepath.Join(dir, "2026-09-18.jsonl")
	for _, p := range []string{old, keep} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := storeSweep(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("an 80-day-old observe day-file survived the sweep")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("yesterday's observe day-file was swept")
	}
}

// THE ARGS, END TO END. The direct test above hands args to the writer itself,
// so a dispatcher that dropped them survived it. observe:metrics takes a name
// from a fixed table and, with no endpoints file, answers "unconfigured" at
// exit 0 through writeObserve — the one arg-taking op that needs no network.
func TestTheArgsTheHostPassedAreRecordedEndToEnd(t *testing.T) {
	isolateConfigDir(t)
	defer withNoEndpointsFile(t)()
	_, errOut, code := driveObserve(t, "observe:metrics", []string{"up"})
	if code != 0 {
		t.Fatalf("observe:metrics up failed: %d %s", code, errOut)
	}
	lines := storeReadObserve(t, "observe:metrics", time.Now())
	if len(lines) != 1 {
		t.Fatalf("want one recorded result, got %d", len(lines))
	}
	if strings.Join(lines[0].Args, ",") != "up" {
		t.Fatalf("the args the host passed were not recorded: %v", lines[0].Args)
	}
}

// ── the review round ────────────────────────────────────────────────────────

// THE ATTACK, verbatim: a host with `observe` sends an op that IGNORES its
// arguments a 5 MiB argument. The op answers normally. Before the fix the
// record got one 5 MiB line and the shelf was sealed for the day — every later
// result for that op refused, the record of what that host saw erased by that
// host. Now: no args recorded (the op reads none), the line is bounded, the
// shelf stays open, the next result lands.
func TestAHostCannotSealTheObserveShelfWithAHugeArgument(t *testing.T) {
	isolateConfigDir(t)
	storeObserveDroppedReset()
	huge := strings.Repeat("x", 5<<20)
	_, errOut, code := driveObserve(t, "observe:host", []string{huge})
	if code != 0 {
		t.Fatalf("observe:host with a huge (ignored) arg failed: %d %s", code, errOut)
	}
	lines := storeReadObserve(t, "observe:host", time.Now())
	if len(lines) != 1 {
		t.Fatalf("want one line, got %d", len(lines))
	}
	if len(lines[0].Args) != 0 {
		t.Fatalf("an op that ignores its args had %d recorded", len(lines[0].Args))
	}
	p, _ := storeDayPath(filepath.Join(storeObserve, "observe-host"), time.Now())
	fi, _ := os.Stat(p)
	if fi.Size() > storeObserveLineMax {
		t.Fatalf("the line is %d bytes, over the %d bound", fi.Size(), storeObserveLineMax)
	}
	if _, err := os.Stat(p + storeSealSuffix); err == nil {
		t.Fatal("one frame sealed the shelf for the day")
	}
	// The next genuine result still lands.
	if _, _, code := driveObserve(t, "observe:host", nil); code != 0 {
		t.Fatal(code)
	}
	if got := len(storeReadObserve(t, "observe:host", time.Now())); got != 2 {
		t.Fatalf("the shelf was not open to the next result: %d lines", got)
	}
	if storeObserveDroppedSnapshot() != nil {
		t.Fatalf("something was dropped: %v", storeObserveDroppedSnapshot())
	}
}

// An op that READS its args keeps them — bounded, and no more than it reads.
func TestArgsAreKeptOnlyForOpsThatReadThemAndAreBounded(t *testing.T) {
	isolateConfigDir(t)
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	long := strings.Repeat("a", storeObserveArgMax+50)
	if !storeRecordObserve("observe:logs", "h", []string{"kernel", long, "third-arg-nobody-reads"},
		[]byte(`{}`), now) {
		t.Fatal("not recorded")
	}
	l := storeReadObserve(t, "observe:logs", now)[0]
	if len(l.Args) != 2 {
		t.Fatalf("observe:logs reads at most 2 args; %d recorded", len(l.Args))
	}
	if l.Args[0] != "kernel" || !strings.HasSuffix(l.Args[1], "…(cut)") || len(l.Args[1]) > storeObserveArgMax+len("…(cut)") {
		t.Fatalf("args not bounded the way the comment says: %q", l.Args)
	}
}

// THE LINE BOUND, at the boundary. No result of any size may produce a line
// over storeObserveLineMax; a result small enough to fit whole is kept whole.
func TestNoResultOfAnySizeProducesALineOverTheBound(t *testing.T) {
	isolateConfigDir(t)
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	shelf := filepath.Join(storeObserve, "observe-units")
	p, _ := storeDayPath(shelf, now)
	var last int64
	for size := 1; size <= 40000; size += 997 {
		res := []byte(`{"u":"` + strings.Repeat("v", size) + `"}`)
		if !storeRecordObserve("observe:units", "h", nil, res, now) {
			t.Fatalf("size %d refused", size)
		}
		fi, _ := os.Stat(p)
		if fi.Size()-last > storeObserveLineMax {
			t.Fatalf("result of %d bytes produced a %d-byte line", len(res), fi.Size()-last)
		}
		last = fi.Size()
	}
	lines := storeReadObserve(t, "observe:units", now)
	// A result well under the bound is whole; one at the bound is not.
	if lines[0].Truncated {
		t.Fatal("a tiny result was truncated")
	}
	big := []byte(`{"u":"` + strings.Repeat("v", storeObserveLineMax) + `"}`)
	storeRecordObserve("observe:units", "h", nil, big, now)
	lines = storeReadObserve(t, "observe:units", now)
	if l := lines[len(lines)-1]; !l.Truncated || l.Bytes != len(big) {
		t.Fatalf("a result at the bound must be truncated with its size kept: %+v", l)
	}
}

func TestTheOpNameSanitiserHandlesEveryAllowedSeparator(t *testing.T) {
	for in, want := range map[string]string{
		"observe:net":         "observe-net",
		"observe:k8s_nodes-x": "observe-k8s-nodes-x",
		"observe:K8S-Nodes":   "observe-k8s-nodes", // lowercased: the host's [a-z0-9-] rule is a fact
		// BOTH ENDS of the uppercase range. A boundary slip ('A'..'Y', or
		// 'B'..'Z') silently DELETES a letter rather than producing an
		// unreadable name, so the host files the holes under a wrong shelf —
		// and no registered op has an uppercase letter, so the registry walk
		// can never reach this branch. Only a table row can.
		"observe:AZ":     "observe-az",
		"observe:Za":     "observe-za",
		"observe::x::":   "observe--x", // separators kept, ends trimmed
		"observe:../etc": "observe-etc",
		":::":            "",
	} {
		if got := storeSafeOpName(in); got != want {
			t.Fatalf("%q -> %q, want %q", in, got, want)
		}
	}
}

// THE ORDERING. The record is on disk BEFORE the reply goes — the property the
// comment in writeObserve calls load-bearing, which had no test: moving the
// record after the reply passed the whole suite. The seam swaps the sender
// for one that checks the day-file exists at the moment the reply is sent.
func TestTheRecordIsOnDiskBeforeTheReplyIsSent(t *testing.T) {
	isolateConfigDir(t)
	orig := observeSendFrame
	var existedAtSend bool
	observeSendFrame = func(ws *websocket.Conn, kind byte, b []byte) {
		if kind == 'O' {
			p, _ := storeDayPath(filepath.Join(storeObserve, "observe-host"), time.Now())
			_, err := os.Stat(p)
			existedAtSend = err == nil
		}
		orig(ws, kind, b)
	}
	defer func() { observeSendFrame = orig }()
	if _, errOut, code := driveObserve(t, "observe:host", nil); code != 0 {
		t.Fatalf("%d %s", code, errOut)
	}
	if !existedAtSend {
		t.Fatal("the reply was sent before the record was on disk")
	}
}

// The recorded-args table is pinned against the handlers themselves.
func TestObserveArgsRecordedMatchesTheHandlers(t *testing.T) {
	for op := range observeArgOps {
		if observeArgsRecorded[op] == 0 {
			t.Fatalf("%s reads a caller value but records no args", op)
		}
	}
	for op := range observeArgsRecorded {
		if !observeArgOps[op] {
			t.Fatalf("%s records args but the handler ignores them", op)
		}
	}
	// Arities, from the handlers' own checks (observe_ops.go handleObserveNet
	// len(args) != 1; observe_pull.go handleObserveMetrics len(args) != 1;
	// handleObserveLogs len(args) > 2; observe_reads.go folders, journal and
	// cert len(args) > 2, logins len(args) > 1).
	if observeArgsRecorded["observe:net"] != 1 || observeArgsRecorded["observe:metrics"] != 1 ||
		observeArgsRecorded["observe:logs"] != 2 || observeArgsRecorded["observe:folders"] != 2 ||
		observeArgsRecorded["observe:journal"] != 2 || observeArgsRecorded["observe:logins"] != 1 ||
		observeArgsRecorded["observe:cert"] != 2 {
		t.Fatalf("arities drifted from the handlers: %v", observeArgsRecorded)
	}
}

// ── round 2 ─────────────────────────────────────────────────────────────────

// THE WINDOW THE LOOP EXISTS FOR, byte by byte: results under the bound whose
// envelope pushes the line over. The size sweep above steps by 997 and jumps
// clean over it, and the at-the-bound case takes the shortcut path — so the
// loop's own truncation branch was exercised by nothing, and removing
// `line.Result = nil` there passed the suite while dropping 134 sizes.
func TestEveryResultJustUnderTheBoundIsRecordedAndNoLineExceedsIt(t *testing.T) {
	isolateConfigDir(t)
	storeObserveDroppedReset()
	// ONE DAY-FILE PER SIZE. Four hundred max-size lines in one file is over
	// the day cap, and the first version of this test read the seal — doing
	// its job — as the loop dropping results.
	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var maxLine int64
	for i, size := 0, storeObserveLineMax-400; size <= storeObserveLineMax+8; i, size = i+1, size+1 {
		day := start.AddDate(0, 0, i)
		res := []byte(`{"u":"` + strings.Repeat("v", size-7) + `"}`)
		if !storeRecordObserve("observe:units", "h", nil, res, day) {
			t.Fatalf("result of %d bytes was DROPPED — the loop bottomed out instead of truncating", len(res))
		}
		p, _ := storeDayPath(filepath.Join(storeObserve, "observe-units"), day)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() > storeObserveLineMax {
			t.Fatalf("result of %d bytes produced a %d-byte line", len(res), fi.Size())
		}
		if fi.Size() > maxLine {
			maxLine = fi.Size()
		}
	}
	if storeObserveDroppedSnapshot() != nil {
		t.Fatalf("drops: %v", storeObserveDroppedSnapshot())
	}
	// THE NEWLINE IS PINNED AT THE BYTE: a max-size line measures the bound
	// EXACTLY, newline included. Counting the line without its newline let one
	// byte over through; the comment claims exactness, so a test holds it.
	if maxLine != storeObserveLineMax {
		t.Fatalf("largest line is %d bytes, want exactly %d", maxLine, storeObserveLineMax)
	}
}

// The refuse branch: an envelope alone over the bound degrades to a tiny head
// and then refuses — never seals, never writes over the bound. Unreachable in
// production (asked_by is a host name, ≤253 bytes by validHostName), so this is
// the only place the branch runs.
func TestAnImpossibleEnvelopeDegradesThenRefusesWithoutSealing(t *testing.T) {
	isolateConfigDir(t)
	storeObserveDroppedReset()
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	res := []byte(`{"tcp":"open"}`)
	if !storeRecordObserve("observe:net", strings.Repeat("h", 32600), []string{"x"}, res, now) {
		t.Fatal("an envelope with room for a 4-byte head was refused")
	}
	if storeRecordObserve("observe:net", strings.Repeat("h", 32700), []string{"x"}, res, now) {
		t.Fatal("an envelope over the bound on its own was written")
	}
	p, _ := storeDayPath(filepath.Join(storeObserve, "observe-net"), now)
	if _, err := os.Stat(p + storeSealSuffix); err == nil {
		t.Fatal("the refuse branch sealed the day")
	}
	if storeObserveDroppedSnapshot()["observe-net"] != 1 {
		t.Fatalf("the refusal was not counted: %v", storeObserveDroppedSnapshot())
	}
}

// THE ARITIES ARE MEASURED, NOT WRITTEN DOWN. For each op that records args,
// its recorded count must equal the largest argument count the handler
// ACCEPTS, driven through the real dispatcher: n args answers, n+1 refuses.
// A handler that grew an argument would make the shelf silently record one
// too few. observe:net needs the network to answer, so only its refusal side
// is driven; its accepted count is pinned by observe_ops_test's own probe.
func TestRecordedArgCountsMatchWhatTheHandlersAccept(t *testing.T) {
	isolateConfigDir(t)
	defer withNoEndpointsFile(t)()
	// Each op's first argument must be one it accepts, or the refusal is about
	// the NAME rather than the count and proves nothing about arity.
	// And every ACCEPTED position must hold a value the handler accepts —
	// observe:logs's second argument is a minutes window, and "x" there is
	// refused for its shape, which is not an arity refusal either.
	//
	// The four in observe_reads.go answer through their drivers on Linux, so
	// what they read is put in front of them here and nothing on the box that
	// runs the suite is: one unit this machine "has", one TLS listener ss
	// "reports", an empty journal, and a folder of the test's own.
	cert := observeTestCert(t, "box-a.example", []string{"box-a.example"}, nil, time.Now().Add(24*time.Hour))
	port := strconv.Itoa(observeTLSListener(t, cert))
	origExec, origHave, origAccess := observeExec, observeHave, observeJournalAccess
	observeExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name + " " + args[0] {
		case "systemctl list-units":
			return []byte("example.service loaded active running Example\n"), nil
		case "ss -tlnpH":
			return []byte("LISTEN 0 4096 127.0.0.1:" + port + " 0.0.0.0:*\n"), nil
		}
		return nil, nil
	}
	observeHave = func(string) bool { return true }
	observeJournalAccess = func() string { return "" }
	defer func() { observeExec, observeHave, observeJournalAccess = origExec, origHave, origAccess }()
	folder := "/"
	if observeHostSupported {
		folder = t.TempDir()
	}
	accepted := map[string][]string{
		"observe:net":     {"203.0.113.9:443"},
		"observe:metrics": {"up"},
		"observe:logs":    {"kernel", "5"},
		"observe:folders": {folder, "1"},
		"observe:journal": {"example", "5"},
		"observe:logins":  {"24"},
		"observe:cert":    {port, "box-a.example"},
	}
	for op, n := range observeArgsRecorded {
		if len(accepted[op]) != n {
			t.Fatalf("%s: the fixture has %d accepted args, the table says %d", op, len(accepted[op]), n)
		}
		tooMany := append(append([]string(nil), accepted[op]...), "x")
		if _, _, code := driveObserve(t, op, tooMany); code == 0 {
			t.Fatalf("%s accepted %d args but records %d — the table is short", op, n+1, n)
		}
		if op == "observe:net" {
			continue
		}
		if _, errOut, code := driveObserve(t, op, tooMany[:n]); code != 0 {
			t.Fatalf("%s refused %d args (%s) but records %d — the table is long", op, n, errOut, n)
		}
	}
}

// THE CROSS-REPO INVARIANT, ENFORCED. The host rejects a holes map with any
// shelf name outside ^[a-z0-9][a-z0-9-]{0,63}$ as unreadable — and an
// unreadable beat freezes that machine's stored holes under the host's
// COALESCE. So "every shelf name this box emits matches that rule" is a hard
// dependency, and an example table of six names cannot hold it: registering
// an op whose sanitised name is over 64 characters, or teaching the
// sanitiser a new character, would leave the table green and silently
// blank the host's reading of this box. This walks EVERY registered op.
func TestEveryRegisteredOpSanitisesToTheHostsShelfRule(t *testing.T) {
	rule := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	n := 0
	for op := range handlerOps {
		if !strings.HasPrefix(op, "observe:") {
			continue
		}
		n++
		got := storeSafeOpName(op)
		if !rule.MatchString(got) {
			t.Fatalf("%s sanitises to %q, which the host rejects as unreadable", op, got)
		}
	}
	if n < 15 {
		t.Fatalf("only %d observe ops walked — the registry moved and this test is not covering it", n)
	}
}
