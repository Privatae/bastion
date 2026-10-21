package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A walk that did not happen, seen from every consumer that used to read it as
// an empty machine. Each of these was a place where the failure vanished:
// the accounting saved it under a coverage label that later let a blind pass
// close findings, the delta compared nothing against everything, the census
// recorded a clean pass, and the two pages rendered "nothing running".

func failTheWalk(t *testing.T) {
	t.Helper()
	prev := scanProcessesFn
	t.Cleanup(func() { scanProcessesFn = prev })
	scanProcessesFn = func() (map[int]agentObs, error) { return nil, errors.New("read /proc: too many open files") }
}

func TestNoBaselineIsTakenFromAWalkThatDidNotHappen(t *testing.T) {
	failTheWalk(t)
	f, _, _, _, err := collectBaseline()
	if err == nil {
		t.Fatalf("an accounting was built from a failed walk: coverage=%q entries=%d — saved, it would be labelled as if it had looked", f.Coverage, len(f.Entries))
	}
	if !strings.Contains(err.Error(), "no baseline taken") || !strings.Contains(err.Error(), "too many open files") {
		t.Fatalf("the refusal must say no baseline was taken and why: %v", err)
	}
}

func TestADeltaPassOnAFailedWalkComparesNothingAndSaysSo(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	failTheWalk(t)
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleDaemon)
	if r.Complete {
		t.Fatal("a pass that could not walk the machine reported itself complete")
	}
	for _, f := range r.Findings {
		if f.Kind != deltaBinaryChanged {
			t.Fatalf("a pass that walked nothing produced a finding: %+v — an empty live set read every entry as gone", f)
		}
	}
	// Every class the pass would have compared is named, so "no findings" on a
	// failed walk cannot be read as a quiet machine for any of them.
	for _, class := range []string{"processes", "scheduled jobs", "listeners", "accounts"} {
		if !strings.Contains(strings.Join(r.Notes, "\n"), class) {
			t.Fatalf("the note must say %s were not compared either: %v", class, r.Notes)
		}
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "process walk failed this pass") {
		t.Fatalf("the pass must name the failed walk, not blame the platform: %v", r.Notes)
	}
	if strings.Contains(strings.Join(r.Notes, "\n"), "no unfiltered process walk") {
		t.Fatalf("the platform note is the wrong cause for a failed walk: %v", r.Notes)
	}
}

func TestTheCensusRecordsAFailedWalkInsteadOfACleanPass(t *testing.T) {
	prev := observedAgents
	t.Cleanup(func() { observedAgents = prev })
	recordPolicyCensusError(nil)
	observedAgents = func() ([]agentObs, error) { return nil, errors.New("ps sweep: exit 1") }
	policyCensusTick()
	msg, at := policyCensusError()
	if msg == "" || at.IsZero() {
		t.Fatal("a failed walk left the census reading clean — the page would say nothing would have been stopped")
	}
	if !strings.Contains(msg, "walk failed") || !strings.Contains(msg, "ps sweep") {
		t.Fatalf("the census error must name the walk and its cause: %q", msg)
	}
}

func TestThePagesBannerAFailedWalkRatherThanAnEmptyMachine(t *testing.T) {
	prev := observedAgents
	t.Cleanup(func() { observedAgents = prev })
	observedAgents = func() ([]agentObs, error) { return nil, errors.New("read /proc: permission denied") }
	a := collectAgentsView()
	if a.WalkError == "" || a.Observed != 0 || len(a.Rows) != 0 {
		t.Fatalf("the agents page rendered a failed walk as a machine with nothing on it: walk=%q observed=%d", a.WalkError, a.Observed)
	}
	p := collectPolicyView()
	if p.WalkError == "" || len(p.Rows) != 0 {
		t.Fatalf("the policy page rendered a failed walk as nothing to stop: walk=%q rows=%d", p.WalkError, len(p.Rows))
	}
}

// THE STORE CLOSES NOTHING ON A PASS THAT WALKED NOTHING — on the platforms
// where Complete=false is the everyday state. baseline_all_other.go returns
// false unconditionally on darwin and windows, so their accountings are
// labelled processes=recognised-only and storeScopeAgrees waves an incomplete
// pass through by design. A pass whose walk FAILED compared no entries; read
// as scope-agreeing it closed every open finding, pinned criticals included.
func TestAFailedWalkClosesNothingOnARecognisedOnlyPlatform(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	full := storeReport("base-a", storeFinding("aaa", deltaCritical), storeFinding("bbb", deltaHigh))
	full.Complete = false
	full.Coverage = "processes=recognised-only,schedulers=recognised-only"
	if _, err := storeRecordPass(full, at); err != nil {
		t.Fatal(err)
	}
	blind := storeReport("base-a")
	blind.Complete = false
	blind.Coverage = full.Coverage
	blind.WalkFailed = "ps sweep: exit 1"
	n, err := storeRecordPass(blind, at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a pass that walked nothing closed %d finding(s) on a recognised-only platform", n)
	}
	for _, l := range storeReadJournal(t, at) {
		if l.Transition == "closed" {
			t.Fatalf("a failed walk wrote a close: %s", storeTransitions(storeReadJournal(t, at)))
		}
	}
	// The same platform, the walk working and the entry really gone: closes.
	again := storeReport("base-a", storeFinding("aaa", deltaCritical))
	again.Complete = false
	again.Coverage = full.Coverage
	if _, err := storeRecordPass(again, at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, at)
	if lines[len(lines)-1].Transition != "closed" {
		t.Fatalf("a working recognised-only pass must still close: %s", storeTransitions(lines))
	}
}

// The pass itself carries the failure to the store: deltaPass on a failed walk
// must set WalkFailed, or the guard above has nothing to read.
func TestADeltaPassOnAFailedWalkSaysTheWalkFailed(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	failTheWalk(t)
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleDaemon)
	if r.WalkFailed == "" || !strings.Contains(r.WalkFailed, "too many open files") {
		t.Fatalf("the pass did not carry the failed walk to the store: %+v", r.WalkFailed)
	}
	if storeScopeAgrees(r) {
		t.Fatal("the store would read a failed-walk pass as scope-agreeing")
	}
}

// The recognised-only platforms' own path: no unfiltered walk AND the
// filtered plane fails. Reverting that branch to "return the list, blind"
// re-creates a zero-entry accounting saved under processes=recognised-only.
func TestNoBaselineIsTakenOnARecognisedOnlyPlatformWhenTheWalkFails(t *testing.T) {
	prev := baselineAllProcessesFn
	t.Cleanup(func() { baselineAllProcessesFn = prev })
	baselineAllProcessesFn = func() ([]agentObs, bool) { return nil, false }
	failTheWalk(t)
	f, _, _, _, err := collectBaseline()
	if err == nil {
		t.Fatalf("a recognised-only platform took an accounting from a failed walk: coverage=%q entries=%d", f.Coverage, len(f.Entries))
	}
	if !strings.Contains(err.Error(), "no baseline taken") {
		t.Fatalf("the refusal must say so: %v", err)
	}
}

// A list that arrived WITH an error is not believed by the agents page either.
func TestTheAgentsPageDisbelievesAListThatCameWithAnError(t *testing.T) {
	prev := observedAgents
	t.Cleanup(func() { observedAgents = prev })
	observedAgents = func() ([]agentObs, error) {
		return []agentObs{{PID: 4242, Kind: kindAgent, Signature: "claude-code"}}, errors.New("partial walk")
	}
	a := collectAgentsView()
	if a.WalkError == "" || len(a.Rows) != 0 || a.Observed != 0 {
		t.Fatalf("a list that came with an error was rendered: walk=%q rows=%d", a.WalkError, len(a.Rows))
	}
}

// THE BEAT. The detect summary is what the host reads; buried in `note`, a
// failed walk read as baseline=ok with zero counts — the exact shape of clean.
func TestTheBeatSummaryCarriesTheFailedWalk(t *testing.T) {
	r := deltaReport{Baseline: deltaBaselineOK, WalkFailed: "read /proc: too many open files"}
	b, err := json.Marshal(r.summary())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["walk_failed"] != "read /proc: too many open files" {
		t.Fatalf("the summary does not carry the failed walk in its own key: %s", b)
	}
	if b, _ := json.Marshal(deltaReport{Baseline: deltaBaselineOK}.summary()); strings.Contains(string(b), "walk_failed") {
		t.Fatal("a pass that walked must not carry the key")
	}
}

// THE OPERATOR'S PRINT. `observe:delta` printed the all-clear line for a
// pass that walked nothing, with the failure three lines below it.
func TestObserveDeltaNeverPrintsTheAllClearForAFailedWalk(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	failTheWalk(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = pw
	runErr := cmdObserveDelta(false)
	os.Stdout = stdout
	_ = pw.Close()
	var buf strings.Builder
	if _, err := io.Copy(&buf, pr); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	out := buf.String()
	if strings.Contains(out, "nothing on this machine is outside what was accounted for") {
		t.Fatalf("the all-clear was printed for a pass that walked nothing:\n%s", out)
	}
	if !strings.Contains(out, "NOTHING WAS COMPARED") || !strings.Contains(out, "too many open files") {
		t.Fatalf("the print does not say the walk failed:\n%s", out)
	}
}

// THE CLOCKS. Grace (keepMissing) and the noise filter (settleHeld) read
// "absent from this pass" as "came back" / "settled"; on a pass that walked
// nothing that wiped every gone-clock and every hold, and counted the
// settled holds as short-lived processes the pass never saw.
func TestAFailedWalkKeepsTheGoneAndHeldClocks(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := baselineLoad()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st := deltaStateLoad(loaded.Digest)
	st.setMissingSince("fp-gone-nine-minutes", now.Add(-9*time.Minute))
	st.hold("fp-respawner", now.Add(-time.Minute))
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	failTheWalk(t)
	r := deltaPass(&digestCache{}, now, deltaRoleDaemon)
	if r.ShortLived != 0 {
		t.Fatalf("a pass that walked nothing reported %d short-lived process(es)", r.ShortLived)
	}
	after := deltaStateLoad(loaded.Digest)
	if _, ok := after.missingSince("fp-gone-nine-minutes"); !ok {
		t.Fatal("the failed walk wiped the gone-clock: a disappearance can never mature while walks fail inside the grace window")
	}
	if _, ok := after.heldSince("fp-respawner"); !ok {
		t.Fatal("the failed walk settled the hold: a crash-looping process never reaches 'respawning'")
	}
}

// binaryBox stands up an isolated config dir with an accounting whose
// bastion-binary digest is a fixture file; the returned writer swaps it.
func binaryBox(t *testing.T) func(string) string {
	t.Helper()
	isolateConfigDir(t)
	fixture := filepath.Join(t.TempDir(), "privatae-bastion")
	writeBinary := func(body string) string {
		t.Helper()
		if _, err := os.Stat(fixture); err == nil {
			if err := os.Rename(fixture, fixture+".old"); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(fixture, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		d, _ := baselineExeDigest(fixture)
		return d
	}
	oldPath := deltaSelfPath
	deltaSelfPath = fixture
	t.Cleanup(func() { deltaSelfPath = oldPath })
	first := writeBinary("version one")
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	base.BastionDigest, base.BastionVersion = first, clientVersion
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	return writeBinary
}

// THE BINARY RUNG SURVIVES A FAILED WALK. It reads the disk, not the process
// list, and a swapped bastion is the one finding no flag may suppress — so a
// pass that walked nothing still carries it (and the host reads that count
// as real). Nothing pinned `findings = events`; `findings = nil`
// was green.
func TestAFailedWalkStillReportsASwappedBinary(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	writeBinary := binaryBox(t)
	writeBinary("version two — swapped")
	failTheWalk(t)
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleDaemon)
	if r.WalkFailed == "" {
		t.Fatal("the walk did not fail")
	}
	var swapped bool
	for _, f := range r.Findings {
		if f.Kind == deltaBinaryChanged {
			swapped = true
		}
	}
	if !swapped {
		t.Fatalf("a failed-walk pass dropped the swapped-binary finding: %+v", r.Findings)
	}
	if r.Critical+r.High == 0 {
		t.Fatalf("the swap was carried but not counted: critical=%d high=%d", r.Critical, r.High)
	}
}

// THE PRUNE READS STAMPS A FAILED WALK NEVER REFRESHED. Seven days of failed
// walks would otherwise forget every hold and first-seen silently.
func TestAFailedWalkDoesNotPruneTheState(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := baselineLoad()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st := deltaStateLoad(loaded.Digest)
	st.seen("fp-eight-days-quiet", now.Add(-8*24*time.Hour))
	st.hold("fp-eight-days-quiet", now.Add(-8*24*time.Hour))
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	failTheWalk(t)
	deltaPass(&digestCache{}, now, deltaRoleDaemon)
	after := deltaStateLoad(loaded.Digest)
	if _, ok := after.heldSince("fp-eight-days-quiet"); !ok {
		t.Fatal("a failed walk pruned a hold whose stamps it never refreshed")
	}
}

// The print, with a finding: "nothing was compared" directly above a critical
// invites discounting it, so the sentence says what DID run.
func TestObserveDeltaNamesTheBinaryCheckWhenAFailedWalkStillFoundASwap(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	writeBinary := binaryBox(t)
	writeBinary("version two — swapped")
	failTheWalk(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = pw
	runErr := cmdObserveDelta(false)
	os.Stdout = stdout
	_ = pw.Close()
	var buf strings.Builder
	if _, err := io.Copy(&buf, pr); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	out := buf.String()
	if strings.Contains(out, "NOTHING WAS COMPARED") {
		t.Fatalf("a pass that found a swapped binary said nothing was compared:\n%s", out)
	}
	if !strings.Contains(out, "only the bastion-binary check ran") || !strings.Contains(out, "binary") {
		t.Fatalf("the print does not name the check that ran:\n%s", out)
	}
}

// A successful pass still prunes, and a failed pass still SAVES — the prune
// gate must not become a dropped save. The save is pinned through the one
// thing a failed daemon pass writes: the bastion digest it read from disk.
func TestASuccessfulPassPrunesAndAFailedPassStillSaves(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	binaryBox(t)
	loaded, _, err := baselineLoad()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st := deltaStateLoad(loaded.Digest)
	// A first-seen/last-seen pair is what only the PRUNE removes (a hold is
	// also settled by the noise filter on a walked pass, which would pass this
	// test with the prune deleted).
	st.seen("fp-eight-days-quiet", now.Add(-8*24*time.Hour))
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	if deltaStateLoad(loaded.Digest).BastionDigest != "" {
		t.Fatal("fixture: the state already carries a bastion digest")
	}
	failTheWalk(t)
	deltaPass(&digestCache{}, now, deltaRoleDaemon)
	after := deltaStateLoad(loaded.Digest)
	if after.BastionDigest == "" {
		t.Fatal("a failed-walk pass did not save its state (the bastion digest it read is missing)")
	}
	if _, ok := after.FirstSeen["fp-eight-days-quiet"]; !ok {
		t.Fatal("a failed walk pruned")
	}
	scanProcessesFn = scanProcesses // the walk works again
	deltaPass(&digestCache{}, now, deltaRoleDaemon)
	if _, ok := deltaStateLoad(loaded.Digest).FirstSeen["fp-eight-days-quiet"]; ok {
		t.Fatal("a successful pass did not prune an eight-day-old entry")
	}
}

// The retake-close note, on a pass that could not walk, does not promise a
// re-open "on this pass".
func TestTheRetakeNoteOnAFailedWalkDoesNotPromiseAReopenNow(t *testing.T) {
	isolateConfigDir(t)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), at); err != nil {
		t.Fatal(err)
	}
	retaken := storeReport("base-b")
	retaken.WalkFailed = "ps sweep: exit 1"
	if _, err := storeRecordPass(retaken, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	lines := storeReadJournal(t, at)
	var closed *storeLine
	for i := range lines {
		if lines[i].Transition == "closed" {
			closed = &lines[i]
		}
	}
	if closed == nil {
		t.Fatalf("the retake did not close the old finding: %s", storeTransitions(lines))
	}
	if strings.Contains(closed.Note, "re-open on this pass") || !strings.Contains(closed.Note, "could not walk") {
		t.Fatalf("the retake note on a failed walk is wrong: %q", closed.Note)
	}
}
