package main

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// stubStopWorld replaces the scan, the process tree, the accounting and the
// kill with fixed answers and returns the list the kill appends to, so a test
// decides who would die without signalling anything real.
func stubStopWorld(t *testing.T, agents []agentObs, tree map[int]int) *[]int {
	t.Helper()
	prevObs, prevTree, prevKill, prevFind := observedAgents, processTree, killProcess, processFindings
	prevCwd, prevStart, prevArgs := procCwdFn, procStartedFn, procCmdArgsFn
	t.Cleanup(func() {
		observedAgents, processTree, killProcess, processFindings = prevObs, prevTree, prevKill, prevFind
		procCwdFn, procStartedFn, procCmdArgsFn = prevCwd, prevStart, prevArgs
	})
	// Nothing about the real machine's processes leaks into the decision.
	procCwdFn = func(int) string { return "" }
	procStartedFn = func(int) (time.Time, bool) { return time.Time{}, false }
	procCmdArgsFn = func(int) []string { return nil }
	observedAgents = func() ([]agentObs, error) { return agents, nil }
	processTree = func() map[int]int { return tree }
	processFindings = func() (findingView, string) { return findingView{}, "" }
	killed := &[]int{}
	killProcess = func(pid int) error { *killed = append(*killed, pid); return nil }
	return killed
}

var stopTestAgents = []agentObs{
	{PID: 101, Kind: kindAgent, Signature: "claude-code"},
	{PID: 4532, Kind: kindApp, Signature: "claude-desktop"},
}

func TestLocalStopPurposeBindsThePidAndTheSignature(t *testing.T) {
	p, err := purposeForLocalStop(101, "claude-code")
	if err != nil || p != "local_stop|101|claude-code" {
		t.Fatalf("purpose %q %v", p, err)
	}
	got, err := purposeFromDetails(map[string]any{"kind": localStopKind, "pid": "101", "signature": "claude-code"})
	if err != nil || got != p {
		t.Errorf("the request's details give %q (%v), the stop it approves is %q", got, err, p)
	}
	if pid, sig, ok := parseLocalStopPurpose(p); !ok || pid != 101 || sig != "claude-code" {
		t.Errorf("parse(%q) = %d %q %v", p, pid, sig, ok)
	}
	if _, err := purposeForLocalStop(101, "a|b"); err == nil {
		t.Error("a signature holding the field separator was accepted")
	}
	if _, err := purposeForLocalStop(1, "init"); err == nil {
		t.Error("a stop of pid 1 got a purpose")
	}
}

// The owner's stop holds the same lines as a Host's order: never an app the
// person is using, never something the scan did not see as an agent, never
// init or this bastion.
func TestLocalStopRefusesWhatAHostsOrderRefuses(t *testing.T) {
	killed := stubStopWorld(t, stopTestAgents, map[int]int{4533: 4532})
	cases := map[int]string{
		4532:        "an app you are running",
		303:         "not an agent this bastion sees",
		1:           "not an agent this machine may stop",
		os.Getpid(): "not an agent this machine may stop",
	}
	for pid, want := range cases {
		sig := "claude-desktop"
		if got := carryOutLocalStop(pid, sig); !strings.Contains(got, want) {
			t.Errorf("stop %d: %q, want it refused as %q", pid, got, want)
		}
	}
	if len(*killed) != 0 {
		t.Errorf("refused stops signalled %v", *killed)
	}
}

// Approved for one agent, carried out only on that agent: a pid that now
// wears another signature is somebody else.
func TestLocalStopNeedsTheSignatureThatWasApproved(t *testing.T) {
	killed := stubStopWorld(t, []agentObs{{PID: 101, Kind: kindAgent, Signature: "aider"}}, nil)
	if got := carryOutLocalStop(101, "claude-code"); !strings.Contains(got, "not the claude-code that was approved") {
		t.Errorf("a pid that changed hands: %q", got)
	}
	if len(*killed) != 0 {
		t.Errorf("signalled %v", *killed)
	}
}

func TestLocalStopTakesTheTreeAndSaysYouDidIt(t *testing.T) {
	killed := stubStopWorld(t, stopTestAgents, map[int]int{102: 101, 103: 102, 4533: 4532})
	before := len(localEventList)
	got := carryOutLocalStop(101, "claude-code")
	sort.Ints(*killed)
	if want := []int{101, 102, 103}; len(*killed) != 3 || (*killed)[0] != 101 || (*killed)[2] != 103 {
		t.Fatalf("killed %v, want %v", *killed, want)
	}
	if !strings.HasPrefix(got, "You stopped claude-code (pid 101)") {
		t.Errorf("outcome %q", got)
	}
	if len(localEventList) != before+1 || !strings.HasPrefix(localEventList[len(localEventList)-1].Text, "You stopped") {
		t.Error("the stop was not recorded on the machine")
	}
}

// The daemon carries out an approval once, and never one older than the
// window: a stop runs when the person asked for it, not when the daemon
// happens to start.
func TestLocalStopLoopActsOnceAndNeverLate(t *testing.T) {
	uiTestConfigDir(t)
	killed := stubStopWorld(t, stopTestAgents, map[int]int{102: 101})
	dir, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, dir, machineTestSecret)
	purpose, _ := purposeForLocalStop(101, "claude-code")
	approval, err := stepupIssueApproval(dir, codeFor(t, machineTestSecret), purpose)
	if err != nil {
		t.Fatal(err)
	}
	if existingMachineFactorDir() != dir {
		t.Fatalf("the loop would read %q, the factor is at %q", existingMachineFactorDir(), dir)
	}
	now := time.Now()
	localStopOnce(dir, now)
	if len(*killed) != 2 {
		t.Fatalf("first pass killed %v, want the agent and its child", *killed)
	}
	localStopOnce(dir, now.Add(time.Second))
	if len(*killed) != 2 {
		t.Fatalf("the same approval acted twice: %v", *killed)
	}
	if r := localStopResultsLoad(dir)[approval]; !strings.HasPrefix(r.Outcome, "You stopped") {
		t.Errorf("the waiting command would read %q", r.Outcome)
	}
}

func TestLocalStopLoopBurnsALateApprovalWithoutActing(t *testing.T) {
	uiTestConfigDir(t)
	killed := stubStopWorld(t, stopTestAgents, nil)
	dir, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, dir, machineTestSecret)
	purpose, _ := purposeForLocalStop(101, "claude-code")
	approval, err := stepupIssueApproval(dir, codeFor(t, machineTestSecret), purpose)
	if err != nil {
		t.Fatal(err)
	}
	localStopOnce(dir, time.Now().Add(localStopWindow+time.Minute))
	if len(*killed) != 0 {
		t.Fatalf("a late approval acted: %v", *killed)
	}
	if r := localStopResultsLoad(dir)[approval]; !strings.Contains(r.Outcome, "ask again") {
		t.Errorf("the late approval's outcome: %q", r.Outcome)
	}
	if a := approvalsLoad(dir)[approval]; !a.Used {
		t.Error("the late approval was left usable")
	}
}

// A stop asked from the command line is an ordinary request in the owner's
// factor: `approvals --machine` lists it in plain words.
func TestALocalStopIsAnOrdinaryRequestOfTheMachine(t *testing.T) {
	uiTestConfigDir(t)
	dir, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	purpose, _ := purposeForLocalStop(101, "claude-code")
	details := map[string]any{"kind": localStopKind, "pid": "101", "signature": "claude-code"}
	id, err := stepupNewRequest(dir, purpose, details)
	if err != nil {
		t.Fatal(err)
	}
	r := requestsLoad(dir)[id]
	if r.State != "pending" || r.Purpose != purpose {
		t.Fatalf("request %+v", r)
	}
	if got := describeRequest(r); got != "Stop claude-code (pid 101) on this machine, and every process it started." {
		t.Errorf("the owner reads %q", got)
	}
}
