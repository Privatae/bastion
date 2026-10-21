package main

// delta_blind_class_test.go — a class one pass could not see.
//
// A failed process walk already leaves every clock and the machine store alone
// (the walkErr guard in deltaPass). The listener and identity classes can go
// blind one at a time: `ss` exits non-zero or reads short, an account file
// cannot be opened. Every consumer that reads "absent from this pass" as a
// fact about the machine must then leave that class alone too, or a flaky
// reader turns into findings that close and reopen, and absences that never
// mature. These drive the real deltaPass and the real store, with only the two
// class readers replaced.

import (
	"strings"
	"testing"
	"time"
)

// blindableListeners installs a listener reader that sees `socks` when
// *blind is false and reports a failed read when it is true.
func blindableListeners(t *testing.T, blind *bool, socks []listenSocket) {
	t.Helper()
	oI, oL := deltaIdentityReader, deltaListenerReader
	deltaIdentityReader = func() identityScanReport { return identityScanReport{Supported: true} }
	deltaListenerReader = func() ([]listenSocket, bool, string) {
		if *blind {
			return nil, false, "ss exited 1"
		}
		return socks, true, ""
	}
	t.Cleanup(func() { deltaIdentityReader, deltaListenerReader = oI, oL })
}

func saveFourClassAccounting(t *testing.T, entries []baselineEntry) {
	t.Helper()
	if err := baselineSave(baselineFile{
		Version:  baselineVersion,
		TakenAt:  stamp(time.Now()),
		Coverage: baselineCoverage(true, true, true, true),
		Entries:  entries,
	}); err != nil {
		t.Fatal(err)
	}
}

func findingOfKind(r deltaReport, kind string) *deltaEvent {
	for i := range r.Findings {
		if r.Findings[i].Kind == kind {
			return &r.Findings[i]
		}
	}
	return nil
}

// A listener finding on a box whose `ss` fails every other pass stays OPEN in
// the machine store. It closed and reopened on every flap: twelve times in 25
// passes for a listener on 0.0.0.0:4444.
func TestABlindListenerPassClosesNoListenerFinding(t *testing.T) {
	isolateConfigDir(t)
	if !processIsRoot() {
		t.Skip("the pass refuses without machine authority, which is its own test")
	}
	blind := false
	blindableListeners(t, &blind, []listenSocket{sock("tcp", "0.0.0.0", 4444, "nc", 1)})
	saveFourClassAccounting(t, nil)

	now := time.Date(2026, 9, 23, 3, 0, 0, 0, time.UTC)
	var fp string
	for i := 0; i < 6; i++ {
		blind = i%2 == 1
		at := now.Add(time.Duration(i) * time.Minute)
		r := deltaPass(&digestCache{}, at, deltaRoleOperator)
		if blind && (len(r.Skipped) != 1 || r.Skipped[0] != "listener") {
			t.Fatalf("pass %d could not read the socket table and did not say so: skipped=%v", i, r.Skipped)
		}
		// The heartbeat carries it too: the host reads the summary, and zero
		// counts on a blind pass must not reach it as a clean machine.
		if sum := r.summary(); blind && (len(sum.Skipped) != 1 || sum.Skipped[0] != "listener") {
			t.Fatalf("pass %d: the summary the heartbeat carries does not name the skipped class: %v", i, sum.Skipped)
		}
		if i == 0 {
			ev := findingOfKind(r, deltaListenerNew)
			if ev == nil {
				t.Fatalf("the listener on 0.0.0.0:4444 was not a finding: %v", kindsOf(r.Findings))
			}
			fp = ev.FP
			// The pass itself records the finding's class, which is what the
			// prune reads on a later blind pass.
			if st := deltaStateLoad(r.BaselineDigest); st.SeenKind[fp] != "listener" {
				t.Fatalf("the pass did not record the finding's class: seen_kind=%q", st.SeenKind[fp])
			}
		}
		if _, err := storeRecordPass(r, at); err != nil {
			t.Fatal(err)
		}
	}
	var transitions []string
	for _, l := range storeReadJournal(t, now) {
		if l.Event != nil && l.Event.FP == fp {
			transitions = append(transitions, l.Transition)
		}
	}
	if len(transitions) != 1 || transitions[0] != "opened" {
		t.Fatalf("a finding in a class the pass could not see must stay open; journal for it: %v", transitions)
	}

	// And a pass that DID look and found it gone still closes it.
	blind = false
	deltaListenerReader = func() ([]listenSocket, bool, string) { return nil, true, "" }
	at := now.Add(10 * time.Minute)
	if _, err := storeRecordPass(deltaPass(&digestCache{}, at, deltaRoleOperator), at); err != nil {
		t.Fatal(err)
	}
	transitions = nil
	for _, l := range storeReadJournal(t, now) {
		if l.Event != nil && l.Event.FP == fp {
			transitions = append(transitions, l.Transition)
		}
	}
	if len(transitions) != 2 || transitions[1] != "closed" {
		t.Fatalf("a pass that looked and found it gone must close it: %v", transitions)
	}
}

// A listener that disappears is reported once its absence has lasted the grace
// period, even when every other pass cannot read the socket table. A blind
// pass reset the clock, so it was never reported at all.
func TestABlindPassDoesNotResetTheGoneClock(t *testing.T) {
	isolateConfigDir(t)
	if !processIsRoot() {
		t.Skip("the pass refuses without machine authority, which is its own test")
	}
	ssh, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)})
	blind := false
	blindableListeners(t, &blind, nil) // :22 is gone whenever the table is read
	saveFourClassAccounting(t, ssh)

	now := time.Date(2026, 9, 23, 3, 0, 0, 0, time.UTC)
	reportedAt := -1
	for i := 0; i < 25 && reportedAt < 0; i++ {
		blind = i%2 == 1
		r := deltaPass(&digestCache{}, now.Add(time.Duration(i)*time.Minute), deltaRoleOperator)
		if findingOfKind(r, deltaListenerGone) != nil {
			reportedAt = i
		}
	}
	if reportedAt < 0 {
		t.Fatal("listener_gone for :22 was never reported across 25 passes with every other pass blind")
	}
	if reportedAt < int(deltaGoneGrace/time.Minute) {
		t.Fatalf("reported at pass %d, before the %v grace had passed", reportedAt, deltaGoneGrace)
	}
}

// The class check runs BEFORE the comparison. A socket table that can never be
// read must not turn the accounting's listeners into listener_gone findings,
// however long it stays unreadable. Run after the comparison instead, the
// events were already made and matured on the grace clock.
func TestAClassBlindOnEveryPassProducesNoGoneFindings(t *testing.T) {
	isolateConfigDir(t)
	if !processIsRoot() {
		t.Skip("the pass refuses without machine authority, which is its own test")
	}
	ssh, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)})
	blind := true
	blindableListeners(t, &blind, nil)
	saveFourClassAccounting(t, ssh)

	now := time.Date(2026, 9, 23, 3, 0, 0, 0, time.UTC)
	for _, after := range []time.Duration{0, deltaGoneGrace + time.Minute, 2*deltaGoneGrace + time.Minute} {
		r := deltaPass(&digestCache{}, now.Add(after), deltaRoleOperator)
		for _, ev := range append(append([]deltaEvent{}, r.Findings...), r.Filtered...) {
			if ev.Entry.Kind == "listener" {
				t.Fatalf("a class nobody could read produced %s at +%v", ev.Kind, after)
			}
		}
	}
}

// The prune forgets a first-seen stamp a week after its last sighting, unless
// its class was not looked at on this pass.
func TestThePruneKeepsAClassItCouldNotSee(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	old := stamp(now.Add(-deltaStateForget - time.Hour))
	mk := func() *deltaState {
		return &deltaState{
			FirstSeen: map[string]string{"lst": old, "prc": old},
			LastSeen:  map[string]string{"lst": old, "prc": old},
			SeenKind:  map[string]string{"lst": "listener", "prc": "process"},
		}
	}
	s := mk()
	s.setBlind([]string{"listener"}, nil)
	s.prune(now)
	if _, kept := s.FirstSeen["lst"]; !kept {
		t.Fatal("a listener's first-seen was forgotten on a pass that could not read listeners")
	}
	if _, kept := s.FirstSeen["prc"]; kept {
		t.Fatal("a process the pass could see was not pruned after a week")
	}
	s = mk()
	s.setBlind(nil, nil)
	s.prune(now)
	if _, kept := s.FirstSeen["lst"]; kept {
		t.Fatal("a listener seen by nobody for a week was kept on a pass that could see listeners")
	}
}

// A listener hold is not settled as short-lived by a pass that could not read
// the socket table. A process hold still is.
func TestAListenerHoldIsNotSettledByABlindPass(t *testing.T) {
	lst := deltaListenerHoldPrefix + "tcp\x00x"
	s := &deltaState{Held: map[string]string{lst: stamp(time.Now()), "prc": stamp(time.Now())}}
	s.setBlind([]string{"listener"}, nil)
	if n := s.settleHeld(map[string]bool{}); n != 1 {
		t.Fatalf("settled %d, want only the process hold", n)
	}
	if _, kept := s.Held[lst]; !kept {
		t.Fatal("a listener hold was counted short-lived on a pass that could not see listeners")
	}
	s.setBlind(nil, nil)
	if n := s.settleHeld(map[string]bool{}); n != 1 {
		t.Fatalf("a pass that could see listeners must settle the hold: settled %d", n)
	}
}

// The class maps are bookkeeping for what is still open or still remembered;
// neither may outlive the entry it describes.
func TestTheClassMapsDoNotOutliveTheirEntries(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	old := stamp(now.Add(-deltaStateForget - time.Hour))
	s := &deltaState{
		FirstSeen: map[string]string{"prc": old},
		LastSeen:  map[string]string{"prc": old},
		SeenKind:  map[string]string{"prc": "process"},
	}
	s.setBlind(nil, nil)
	s.prune(now)
	if _, left := s.SeenKind["prc"]; left {
		t.Fatal("the prune forgot a fingerprint but kept its class")
	}

	isolateConfigDir(t)
	at := time.Date(2026, 9, 23, 3, 0, 0, 0, time.UTC)
	ev := storeFinding("aaa", deltaHigh)
	if _, err := storeRecordPass(storeReport("base-a", ev), at); err != nil {
		t.Fatal(err)
	}
	if k := storeStateLoadRaw().OpenKind["aaa"]; k != "process" {
		t.Fatalf("an open finding's class was not recorded: %q", k)
	}
	if _, err := storeRecordPass(storeReport("base-a"), at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	st := storeStateLoadRaw()
	if _, open := st.Open["aaa"]; open {
		t.Fatal("a pass that looked and did not find it left it open")
	}
	if _, left := st.OpenKind["aaa"]; left {
		t.Fatal("a closed finding's class stayed in the open-class map")
	}
}

// An accounting taken while a reader failed on a platform that CAN read the
// class says `unread`, not `unsupported`: the second means a platform that
// never compares the class, and whoever reads the line (the host, a person)
// would be told a retake changes nothing when a retake is exactly the fix.
func TestAnAccountingTakenWithAFailedReaderSaysUnread(t *testing.T) {
	isolateConfigDir(t)
	if !processIsRoot() {
		t.Skip("the accounting refuses without machine authority, which is its own test")
	}
	oI, oL := deltaIdentityReader, deltaListenerReader
	t.Cleanup(func() { deltaIdentityReader, deltaListenerReader = oI, oL })
	deltaListenerReader = func() ([]listenSocket, bool, string) { return nil, false, "ss exited 1" }
	deltaIdentityReader = func() identityScanReport {
		return identityScanReport{Reason: "the account database could not be read"}
	}
	f, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	want := map[bool]string{true: "unread", false: "unsupported"}
	for class, readable := range map[string]bool{"listeners": listenersReadableHere, "identities": identitiesReadableHere} {
		if !strings.Contains(f.Coverage, class+"="+want[readable]) {
			t.Fatalf("%s: a failed reader on a platform that %s read it wrote %q",
				class, map[bool]string{true: "can", false: "cannot"}[readable], f.Coverage)
		}
		if baselineHasClass(f.Coverage, class) {
			t.Fatalf("%s is counted as held by an accounting that could not read it: %q", class, f.Coverage)
		}
	}

	// The same readers working: the classes are held.
	deltaListenerReader = func() ([]listenSocket, bool, string) { return nil, true, "" }
	deltaIdentityReader = func() identityScanReport { return identityScanReport{Supported: true} }
	f, _, _, _, err = collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if listenersReadableHere && (!baselineHasClass(f.Coverage, "listeners") || strings.Contains(f.Coverage, "unread")) {
		t.Fatalf("working readers must hold the classes: %q", f.Coverage)
	}
}

// The noise filter's "started by something the accounting holds" evidence comes
// from accounted PROCESSES only. An accounted listener held by a replaced
// program must not vouch for that program's children.
func TestAnAccountedListenerIsNotABaselineParent(t *testing.T) {
	sshd := baselineEntry{FP: "sshd-real", Kind: "process", User: "root", Unit: "ssh.service",
		ArgvShape: "sshd -D", ExeDigest: "real"}
	port, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)})
	trojan := sshd
	trojan.FP, trojan.ExeDigest = "sshd-trojan", "trojan"
	holder, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 4242)})
	cron := baselineEntry{FP: "cron", Kind: "process", User: "root", Unit: "cron.service",
		ArgvShape: "cron -f", ExeDigest: "c"}
	base := &baselineFile{Entries: append([]baselineEntry{sshd, cron}, port...)}
	live := []deltaLiveEntry{
		{Entry: trojan, PIDs: []int{4242}},
		{Entry: holder[0], PIDs: []int{4242}},
		{Entry: cron, PIDs: []int{77}},
	}
	n := deltaNoiseFor(deltaCompare(base.Entries, live), base, live)
	if n.BaselinePIDs[4242] {
		t.Fatal("an accounted listener made the replaced program holding it a baseline parent")
	}
	if !n.BaselinePIDs[77] {
		t.Fatal("an accounted process running now must still be a baseline parent")
	}
}
