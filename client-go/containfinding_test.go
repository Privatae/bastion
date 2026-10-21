package main

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"
)

// findingRig drives maybeContainFindings from stubs: the comparison's answer,
// the agent map, the parent map and the kill. Nothing real is walked or signalled.
func findingRig(t *testing.T, findings map[string][]int, inBase map[string]bool,
	outcome string, agents []agentObs, parents map[int]int) *[]int {
	t.Helper()
	prevPF, prevObs, prevTree, prevKill := processFindings, observedAgents, processTree, killProcess
	clearResults := func() {
		containResultsMu.Lock()
		containResults = map[string]containResult{}
		containResultsLoaded = true
		if p, err := containResultsPath(); err == nil {
			_ = os.Remove(p)
		}
		containResultsMu.Unlock()
	}
	clearResults()
	t.Cleanup(func() {
		processFindings, observedAgents, processTree, killProcess = prevPF, prevObs, prevTree, prevKill
		clearResults()
	})
	rigProtected = map[int]bool{}
	processFindings = func() (findingView, string) {
		return findingView{findings: findings, inBaseline: inBase, protected: rigProtected}, outcome
	}
	observedAgents = func() ([]agentObs, error) { return agents, nil }
	processTree = func() map[int]int { return parents }
	killed := []int{}
	killProcess = func(pid int) error { killed = append(killed, pid); return nil }
	return &killed
}

// rigProtected is the view's protected set for the current findingRig; a test
// that needs accounting pids in the tree fills it after calling the rig.
var rigProtected map[int]bool

// orders builds a directive body: one order per fingerprint, ids 1..n.
func orders(fps ...string) []byte {
	list := make([]findingOrder, len(fps))
	for i, fp := range fps {
		list[i] = findingOrder{ID: int64(i + 1), FP: fp}
	}
	b, _ := json.Marshal(map[string]any{"contain_findings": list})
	return b
}

func resultsByFP(pairing string) map[string]containResult {
	out := map[string]containResult{}
	for _, r := range containResultsReport(pairing) {
		out[r.FP] = r
	}
	return out
}

// THE WHOLE POINT: a program the delta reports, that the agent plane does not
// recognise, can now be stopped — by its fingerprint, with its tree. And the
// three things that are NOT findings are refused, each with its own word.
//
// MUTATION: skip the inBaseline check.
// RESULT: red — fpBase's outcome is not in_baseline.
// MUTATION: treat a missing fingerprint as killable (drop the len(pids)==0 case).
// RESULT: red — fpGone reports killed/kill_failed instead of not_a_finding.
func TestContainFindingStopsAFindingByFingerprintAndRefusesTheRest(t *testing.T) {
	killed := findingRig(t,
		map[string][]int{"fpNew": {501}},
		map[string]bool{"fpBase": true},
		"", nil, map[int]int{502: 501})

	maybeContainFindings("", "", orders("fpNew", "fpBase", "fpGone"))

	sort.Ints(*killed)
	if !sameInts(*killed, []int{501, 502}) {
		t.Fatalf("killed %v, want the finding and its child [501 502]", *killed)
	}
	got := resultsByFP("")
	if r := got["fpNew"]; r.Outcome != containKilled || r.Stopped != 2 {
		t.Fatalf("fpNew: %+v, want killed with 2 stopped", r)
	}
	if got["fpBase"].Outcome != containInBaseline {
		t.Fatalf("a baseline entry must be refused as such: %+v", got["fpBase"])
	}
	if got["fpGone"].Outcome != containNotFinding {
		t.Fatalf("a fingerprint with nothing running under it: %+v", got["fpGone"])
	}
}

// An app the user is running, and anything this bastion started, are refused
// even when the delta reports them — and nothing is signalled for either.
//
// MUTATION: remove the kindApp refusal.
// RESULT: red — 601 is killed.
// MUTATION: remove the descendsFromSelf refusal.
// RESULT: red — 701 is killed.
func TestContainFindingRefusesAppsAndWhatTheBastionStarted(t *testing.T) {
	self := os.Getpid()
	killed := findingRig(t,
		map[string][]int{"fpApp": {601}, "fpOurs": {701}},
		map[string]bool{}, "",
		[]agentObs{{PID: 601, Kind: kindApp, Signature: "some-ide"}},
		map[int]int{701: self})

	maybeContainFindings("", "", orders("fpApp", "fpOurs"))

	if len(*killed) != 0 {
		t.Fatalf("nothing may be signalled here, killed %v", *killed)
	}
	got := resultsByFP("")
	if got["fpApp"].Outcome != containRefusedApp {
		t.Fatalf("an app: %+v", got["fpApp"])
	}
	if got["fpOurs"].Outcome != containRefusedOurs {
		t.Fatalf("a process this bastion started: %+v", got["fpOurs"])
	}
}

// A comparison that could not happen answers EVERY fingerprint with its reason
// and kills nothing — a box that cannot see must not kill on belief, and the
// host must not read silence as done.
//
// MUTATION: return early without recording results.
// RESULT: red — no results.
func TestContainFindingAnswersEveryOrderWhenItCannotCompare(t *testing.T) {
	for _, outcome := range []string{containNoAuthority, containNoAccount, containWalkFailed} {
		killed := findingRig(t, map[string][]int{"a": {801}}, nil, outcome, nil, nil)
		maybeContainFindings("", "", orders("a", "b"))
		got := resultsByFP("")
		if len(*killed) != 0 || got["a"].Outcome != outcome || got["b"].Outcome != outcome {
			t.Fatalf("outcome %s: killed %v, results %+v", outcome, *killed, got)
		}
		containResultsMu.Lock()
		containResults = map[string]containResult{}
		containResultsMu.Unlock()
	}
}

// RESULTS ARE PER PAIRING, AND THEY LAPSE. One host's answer must not arrive on
// another host's beat — including when both ordered the same thing — and a
// result older than containResultKeep leaves.
//
// MUTATION: key results by order id alone (drop the pairing from the key).
// RESULT: red — host-b's refusal overwrites host-a's kill.
// MUTATION: report every pairing's results.
// RESULT: red — host-b sees host-a's result.
func TestContainResultsArePerPairingAndLapse(t *testing.T) {
	findingRig(t, nil, nil, "", nil, nil)
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	now := base
	prevNow := containNow
	containNow = func() time.Time { return now }
	t.Cleanup(func() { containNow = prevNow })

	recordContainResult("host-a", findingOrder{ID: 1, FP: "fp1"}, containKilled, 1)
	if len(containResultsReport("host-b")) != 0 {
		t.Fatal("host-b received host-a's result")
	}
	recordContainResult("host-b", findingOrder{ID: 1, FP: "fp1"}, containNotAnchor, 0)
	if a := containResultsReport("host-a"); len(a) != 1 || a[0].Outcome != containKilled {
		t.Fatalf("host-a's own answer was lost or overwritten: %+v", a)
	}
	if b := containResultsReport("host-b"); len(b) != 1 || b[0].Outcome != containNotAnchor {
		t.Fatalf("host-b's answer: %+v", b)
	}
	now = base.Add(containResultKeep + time.Second)
	if len(containResultsReport("host-a")) != 0 {
		t.Fatal("a result older than containResultKeep is still reported")
	}
}

// THE KEY IS ALWAYS ON THE BEAT, AN EMPTY LIST WHEN THERE IS NOTHING. Absent is
// what an older box sends, and the host holds an order for that box until it
// lapses; an empty list from this box must not be confused with it.
//
// MUTATION: omit the key when the list is empty.
// RESULT: red — contain_results absent.
func TestHeartbeatAlwaysCarriesContainResults(t *testing.T) {
	findingRig(t, nil, nil, "", nil, nil)
	body := buildHeartbeatBody("", "h", "linux", "0.0.0-test", "", "", "", "", false, nil, nil, nil)
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("heartbeat body is not JSON: %v", err)
	}
	raw, ok := m["contain_results"]
	if !ok {
		t.Fatal("contain_results is absent from the beat")
	}
	if string(raw) != "[]" {
		t.Fatalf("with nothing to report the key must be an empty list, got %s", raw)
	}
}

// A replaced program that keeps its port and its name is still containable.
// A listener's identity is the bind point and the holder's name, both of which
// the replacement controls, so an accounted listener must never protect the pid
// holding it. Pure functions only: no kill path runs here.
func TestAnAccountedListenerNeverProtectsItsHolder(t *testing.T) {
	sshd := baselineEntry{FP: "sshd-real", Kind: "process", User: "root", Unit: "ssh.service",
		ArgvShape: "sshd -D", ExeDigest: "real"}
	port, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)})
	trojan := sshd
	trojan.FP, trojan.ExeDigest = "sshd-trojan", "trojan"
	holder, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 4242)})
	base := append([]baselineEntry{sshd}, port...)
	live := []deltaLiveEntry{
		{Entry: trojan, PIDs: []int{4242}},
		{Entry: holder[0], PIDs: []int{4242}},
	}
	if holder[0].FP != port[0].FP {
		t.Fatal("the listener must match the accounting, or this test proves nothing")
	}
	v := processFindingsFrom(base, live, deltaCompare(base, live))
	if !sameInts(v.findings["sshd-trojan"], []int{4242}) {
		t.Fatalf("the replaced sshd must be a containable finding: %v", v.findings)
	}
	if v.protected[4242] {
		t.Fatal("an accounted listener protected the replaced program holding it; the finding cannot be contained")
	}
}

// THE FILTER, AGAINST THE REAL COMPARISON. The tests above supply the answer;
// this one makes deltaCompare produce it, so the filter that decides what is
// killable is itself under test.
//
// MUTATION: drop `inBaseline[ev.FP]` from the filter.
// RESULT: red — b2 (a baseline program that began talking to a model) is killable.
// MUTATION: drop the Entry.Kind == "process" condition.
// RESULT: red — the listener entry is killable (newKindFor reports any
// non-scheduler kind as proc_new, so the event kind alone does not exclude it).
// MUTATION: drop deltaProcChanged from the accepted kinds.
// RESULT: red — the replaced binary c1 is not killable.
func TestProcessFindingsFromTheRealComparison(t *testing.T) {
	proc := func(fp, argv, digest string, eps ...string) baselineEntry {
		return baselineEntry{FP: fp, Kind: "process", User: "u", Unit: "x",
			ArgvShape: argv, ExeDigest: digest, Endpoints: eps}
	}
	base := []baselineEntry{
		proc("b1", "steady", "d1"),
		proc("b2", "talker", "d2"),
		proc("b3", "replaced", "d3"),
		{FP: "bs", Kind: "scheduler", User: "u", Unit: "cron-a", ArgvShape: "job"},
	}
	live := []deltaLiveEntry{
		{Entry: proc("b1", "steady", "d1"), PIDs: []int{10}},
		{Entry: proc("n1", "brand-new", "dn"), PIDs: []int{11}},
		{Entry: proc("c1", "replaced", "dX"), PIDs: []int{12}},                  // b3's post, new binary
		{Entry: proc("b2", "talker", "d2", "api.example.com"), PIDs: []int{13}}, // same fp, new endpoint
		{Entry: baselineEntry{FP: "s2", Kind: "scheduler", User: "u", Unit: "cron-b", ArgvShape: "job2"}, PIDs: []int{14}},
		{Entry: baselineEntry{FP: "l1", Kind: "listener", User: "u", Unit: "x", ArgvShape: "tcp:4444"}, PIDs: []int{15}},
		{Entry: baselineEntry{FP: "bs", Kind: "scheduler", User: "u", Unit: "cron-a", ArgvShape: "job"}},
	}
	events := deltaCompare(base, live)
	v := processFindingsFrom(base, live, events)
	if len(v.findings) != 2 || !sameInts(v.findings["n1"], []int{11}) || !sameInts(v.findings["c1"], []int{12}) {
		t.Fatalf("findings = %v, want exactly n1:[11] and c1:[12]", v.findings)
	}
	if !v.inBaseline["b2"] || v.inBaseline["n1"] {
		t.Fatalf("inBaseline is the accounting's fingerprints: %v", v.inBaseline)
	}
	// MUTATION: drop the protected-pid collection.
	// RESULT: red — the accounting's own running pids are not protected.
	if !v.protected[10] || !v.protected[13] || v.protected[11] || v.protected[12] {
		t.Fatalf("protected must be exactly the pids whose own entry is in the accounting: %v", v.protected)
	}

	// The design's tier and the comparison's own caveat. A package-managed new
	// binary (tier known) and a change that is only an unreadable digest are
	// findings to READ, not to stop.
	// MUTATION: drop the tierKnown exclusion.  RESULT: red — n1 stays containable.
	// MUTATION: drop the digest_unreadable exclusion.  RESULT: red — c1 stays containable.
	demoted := make([]deltaEvent, 0, len(events))
	for _, ev := range events {
		switch ev.FP {
		case "n1":
			ev.Tier = tierKnown
		case "c1":
			ev.Reason = deltaReasonUnreadable
		}
		demoted = append(demoted, ev)
	}
	if v := processFindingsFrom(base, live, demoted); len(v.findings) != 0 {
		t.Fatalf("a known-tier new binary and an unreadable-digest change must not be containable: %v", v.findings)
	}
}

// THE GUARDS HOLD ACROSS THE WHOLE TREE (review of #100, blocking). A finding
// whose tree holds an accounting entry, an app, or something the bastion
// started: those processes and everything beneath them are spared, the rest
// of the tree is stopped.
//
// MUTATION: killTree(pid, spareFromContain) instead of the tree guard.
// RESULT: red — 902, 912 (accounting + its child) and 903 (app) die.
func TestContainFindingSparesProtectedProcessesInTheTree(t *testing.T) {
	killed := findingRig(t, map[string][]int{"fpRoot": {900}}, map[string]bool{}, "",
		[]agentObs{{PID: 903, Kind: kindApp, Signature: "an-ide"}},
		map[int]int{
			901: 900,           // plain child: stopped
			902: 900, 912: 902, // an accounting entry and its child: spared
			903: 900, 913: 903, // an app the user is running and its helper: spared
		})
	rigProtected[902] = true
	maybeContainFindings("", "", orders("fpRoot"))
	sort.Ints(*killed)
	if !sameInts(*killed, []int{900, 901}) {
		t.Fatalf("killed %v, want only the root and its unprotected child [900 901]", *killed)
	}
}

// A FINDING THAT IS THE BASTION'S OWN LAUNCH CONTEXT is refused by name: the
// shell or service it runs under is an ancestor of this process, and stopping
// it is not an order this box carries out. Siblings under a protected
// ancestor are pruned with it.
//
// MUTATION: drop the bastion-ancestor protection.
// RESULT: red — 900 and 901 die and the outcome is killed.
func TestContainFindingRefusesTheBastionsOwnAncestors(t *testing.T) {
	self := os.Getpid()
	killed := findingRig(t, map[string][]int{"fpShell": {900}}, map[string]bool{}, "", nil,
		map[int]int{self: 904, 904: 900, 901: 900})
	maybeContainFindings("", "", orders("fpShell"))
	if len(*killed) != 0 {
		t.Fatalf("the bastion's launch chain was signalled: %v", *killed)
	}
	if r := resultsByFP("")["fpShell"]; r.Outcome != containRefusedOurs {
		t.Fatalf("outcome %+v, want refused_ours", r)
	}
}

// THE REFUSALS liveProcessFindings MAKES, through the real function with only
// the machine replaced (review of #100: every other test replaced the whole
// function, so none of these was tested).
//
// MUTATION: drop the root check.   RESULT: red (no_authority not returned).
// MUTATION: drop !digestOK.         RESULT: red (an edited accounting is used).
// MUTATION: drop the version check. RESULT: red.
func TestLiveProcessFindingsRefusesWhatItCannotTrust(t *testing.T) {
	prevRoot, prevLoad, prevLive, prevFilter := containIsRoot, containBaselineLoad, containCollectLive, containFilter
	t.Cleanup(func() {
		containIsRoot, containBaselineLoad, containCollectLive, containFilter = prevRoot, prevLoad, prevLive, prevFilter
	})
	good := &baselineFile{Version: baselineVersion, Entries: []baselineEntry{{FP: "b", Kind: "process"}}}
	containFilter = func(ev []deltaEvent, _ *baselineFile, _ []deltaLiveEntry) []deltaEvent { return ev }
	containCollectLive = func() ([]deltaLiveEntry, error) { return nil, nil }
	cases := []struct {
		name   string
		root   bool
		base   *baselineFile
		ok     bool
		err    error
		walk   error
		expect string
	}{
		{"not root", false, good, true, nil, nil, containNoAuthority},
		{"no accounting", true, nil, true, os.ErrNotExist, nil, containNoAccount},
		{"edited accounting", true, good, false, nil, nil, containNoAccount},
		{"other rules", true, &baselineFile{Version: "old"}, true, nil, nil, containNoAccount},
		{"walk failed", true, good, true, nil, os.ErrPermission, containWalkFailed},
		{"all good", true, good, true, nil, nil, ""},
	}
	for _, c := range cases {
		c := c
		containIsRoot = func() bool { return c.root }
		containBaselineLoad = func() (*baselineFile, bool, error) { return c.base, c.ok, c.err }
		containCollectLive = func() ([]deltaLiveEntry, error) { return nil, c.walk }
		if _, got := liveProcessFindings(); got != c.expect {
			t.Errorf("%s: outcome %q, want %q", c.name, got, c.expect)
		}
	}
}

// RESULTS SURVIVE A RESTART (review of #100): an answer recorded before the
// process died is still there — and still stops a re-run — after it starts.
//
// MUTATION: skip containResultsSaveLocked.  RESULT: red.
func TestContainResultsSurviveARestart(t *testing.T) {
	findingRig(t, nil, nil, "", nil, nil)
	recordContainResult("host-a", findingOrder{ID: 7, FP: "fp7"}, containKilled, 3)
	containResultsMu.Lock()
	containResults = map[string]containResult{}
	containResultsLoaded = false // a fresh process
	containResultsMu.Unlock()
	if left := unansweredOrders("host-a", []findingOrder{{ID: 7, FP: "fp7"}}); len(left) != 0 {
		t.Fatalf("an order answered before the restart would run again: %v", left)
	}
	if r := containResultsReport("host-a"); len(r) != 1 || r[0].Outcome != containKilled || r[0].Stopped != 3 {
		t.Fatalf("the answer did not survive the restart: %+v", r)
	}
}

// AN ORDER IS CARRIED OUT ONCE. The same id arriving again (a beat crossed the
// result) must not run again and must not overwrite the first answer.
//
// MUTATION: remove the unansweredOrders filter.
// RESULT: red — the second delivery rewrites "killed" as "not_a_finding".
func TestContainFindingRunsAnOrderOnce(t *testing.T) {
	findings := map[string][]int{"fpNew": {501}}
	killed := findingRig(t, findings, map[string]bool{}, "", nil, map[int]int{})
	maybeContainFindings("", "", orders("fpNew"))
	delete(findings, "fpNew") // it is gone now
	maybeContainFindings("", "", orders("fpNew"))
	if len(*killed) != 1 {
		t.Fatalf("the order ran twice: killed %v", *killed)
	}
	if r := resultsByFP("")["fpNew"]; r.Outcome != containKilled || r.ID != 1 {
		t.Fatalf("the first answer was overwritten: %+v", r)
	}
}

// THE REAL FILTER IS WIRED IN (review of #100): with containFilter left at its
// default, a new process the bastion itself started is filtered by the same
// deltaFilter the pass uses, and so is never containable; the same process
// started by anyone else is.
//
// MUTATION: containFilter returns every event unfiltered.  RESULT: red.
func TestContainFilterIsTheDeltaPassFilter(t *testing.T) {
	// The process's AGE is supplied (an hour), not read from a real process:
	// a real pid's age depends on where the suite runs — pid 1 in a fresh PID
	// namespace is seconds old and reads as short-lived (review of #100).
	self := os.Getpid()
	prevTree, prevAge := processTree, deltaAgeFn
	t.Cleanup(func() { processTree, deltaAgeFn = prevTree, prevAge })
	deltaAgeFn = func() func(int) (time.Duration, bool) {
		return func(int) (time.Duration, bool) { return time.Hour, true }
	}
	base := &baselineFile{Version: baselineVersion, Digest: "d-test",
		Entries: []baselineEntry{{FP: "b", Kind: "process", User: "u", Unit: "x", ArgvShape: "steady"}}}
	live := []deltaLiveEntry{{Entry: baselineEntry{FP: "n1", Kind: "process", User: "u", Unit: "x",
		ArgvShape: "brand-new", Exe: "/nonexistent/test-binary"}, PIDs: []int{71001}}}

	processTree = func() map[int]int { return map[int]int{71001: self} }
	ours := processFindingsFrom(base.Entries, live, containFilter(deltaCompare(base.Entries, live), base, live))
	if len(ours.findings) != 0 {
		t.Fatalf("a process this bastion started must be filtered, got %v", ours.findings)
	}
	processTree = func() map[int]int { return map[int]int{71001: 4242} }
	theirs := processFindingsFrom(base.Entries, live, containFilter(deltaCompare(base.Entries, live), base, live))
	if !sameInts(theirs.findings["n1"], []int{71001}) {
		t.Fatalf("the same process started by someone else must be containable, got %v", theirs.findings)
	}
}

// THE ROOT'S IDENTITY IS CARRIED FROM THE WALK (review of #100): a pid that
// changed hands between the finding walk and the kill is not signalled at all.
//
// MUTATION: killTree(pid, protected) instead of killTreeExpect with the view's
// identity.  RESULT: red — 950 is killed.
func TestContainFindingDoesNotKillARootThatChangedHandsAfterTheWalk(t *testing.T) {
	killed := findingRig(t, map[string][]int{"fpX": {950}}, map[string]bool{}, "", nil, map[int]int{})
	prevPF := processFindings
	processFindings = func() (findingView, string) {
		v, o := prevPF()
		v.identity = map[int]string{950: "at-walk"}
		return v, o
	}
	prevID := procIdentity
	t.Cleanup(func() { procIdentity = prevID })
	procIdentity = func(pid int) (string, bool, bool) { return "someone-else", false, true }
	maybeContainFindings("", "", orders("fpX"))
	if len(*killed) != 0 {
		t.Fatalf("killed a pid whose identity changed since the walk: %v", *killed)
	}
	if r := resultsByFP("")["fpX"]; r.Outcome != containKillFailed {
		t.Fatalf("outcome %+v, want kill_failed (nothing was stopped)", r)
	}
}

// THE AGENT PATH HAS THE SAME TREE GUARD (review of #100): an accounting entry
// or an app inside an agent's tree is spared with its subtree.
//
// MUTATION: killTree(pid, spareFromContain) in maybeContain.  RESULT: red.
func TestAgentContainSparesProtectedProcessesInTheTree(t *testing.T) {
	prevObs, prevTree, prevKill, prevPF := observedAgents, processTree, killProcess, processFindings
	t.Cleanup(func() {
		observedAgents, processTree, killProcess, processFindings = prevObs, prevTree, prevKill, prevPF
	})
	observedAgents = func() ([]agentObs, error) {
		return []agentObs{{PID: 800, Kind: kindAgent, Signature: "claude-code"},
			{PID: 803, Kind: kindApp, Signature: "an-ide"}}, nil
	}
	processTree = func() map[int]int { return map[int]int{801: 800, 802: 800, 812: 802, 803: 800} }
	processFindings = func() (findingView, string) {
		return findingView{protected: map[int]bool{802: true}}, ""
	}
	killed := []int{}
	killProcess = func(pid int) error { killed = append(killed, pid); return nil }
	maybeContain("", "", []byte(`{"contain":[800]}`))
	sort.Ints(killed)
	if !sameInts(killed, []int{800, 801}) {
		t.Fatalf("killed %v, want the agent and its unprotected child [800 801]", killed)
	}
}

// AN AGENT WHOSE OWN FINGERPRINT IS IN THE ACCOUNTING IS STILL STOPPED (review
// of #100, round 3): the tree guard applies BENEATH the agent, never to the
// agent the host named. Before this, such an agent was spared in silence.
//
// MUTATION: killTree(pid, guard) — the guard on the root too.  RESULT: red.
func TestAgentContainStopsAnAgentThatIsItselfInTheAccounting(t *testing.T) {
	prevObs, prevTree, prevKill, prevPF := observedAgents, processTree, killProcess, processFindings
	t.Cleanup(func() {
		observedAgents, processTree, killProcess, processFindings = prevObs, prevTree, prevKill, prevPF
	})
	observedAgents = func() ([]agentObs, error) {
		return []agentObs{{PID: 810, Kind: kindAgent, Signature: "claude-code"}}, nil
	}
	processTree = func() map[int]int { return map[int]int{811: 810} }
	processFindings = func() (findingView, string) {
		return findingView{protected: map[int]bool{810: true}}, ""
	}
	killed := []int{}
	killProcess = func(pid int) error { killed = append(killed, pid); return nil }
	maybeContain("", "", []byte(`{"contain":[810]}`))
	sort.Ints(killed)
	if !sameInts(killed, []int{810, 811}) {
		t.Fatalf("killed %v, want the agent and its child [810 811]", killed)
	}
}
