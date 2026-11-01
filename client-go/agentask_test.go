package main

import (
	"strings"
	"testing"
)

func askWorld(t *testing.T, enrol bool) string {
	t.Helper()
	uiTestConfigDir(t)
	stubStopWorld(t, []agentObs{
		{PID: 101, Kind: kindAgent, Signature: "aider", User: "u"},
		{PID: 102, Kind: kindAgent, Signature: "aider", User: "u"},
		{PID: 103, Kind: kindAgent, Signature: "aider", User: "u"},
		{PID: 104, Kind: kindAgent, Signature: "aider", User: "u"},
		{PID: 105, Kind: kindAgent, Signature: "aider", User: "u"},
		{PID: 106, Kind: kindAgent, Signature: "aider", User: "u"},
		{PID: 300, Kind: kindAgent, Signature: "claude-code", User: "u"},
		{PID: 4532, Kind: kindApp, Signature: "claude-desktop", User: "u"},
	}, map[int]int{310: 300, 311: 310}) // 311: a shell the claude-code session started
	prev := homeForUserFn
	t.Cleanup(func() { homeForUserFn = prev })
	homeForUserFn = func(string) string { return "" }
	d, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	if enrol {
		enrolFactorAt(t, d, machineTestSecret)
	}
	return d
}

// An ask from another account becomes a pending request naming the agent
// that asked, from the kernel's pid, and approves nothing.
func TestAnAskBecomesARequestNamingTheAgentThatAsked(t *testing.T) {
	d := askWorld(t, true)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if !r.OK {
		t.Fatalf("refused: %s", r.Why)
	}
	if !strings.Contains(r.Text, "Asked from Claude Code (pid 300), running as u.") {
		t.Errorf("the request reads %q", r.Text)
	}
	pending := sortedPending(requestsLoad(d))
	if len(pending) != 1 {
		t.Fatalf("pending %v", pending)
	}
	for _, a := range approvalsLoad(d) {
		t.Fatalf("an ask produced an approval: %+v", a)
	}
}

func TestAnAskIsRefusedWithoutTheOwnersCodeOrForAnApp(t *testing.T) {
	askWorld(t, false)
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 0); r.OK || !strings.Contains(r.Why, "not set up their code") {
		t.Errorf("no owner code: %+v", r)
	}
	askWorld(t, true)
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 4532}, "u", 0); r.OK || !strings.Contains(r.Why, "an app you are running") {
		t.Errorf("an app: %+v", r)
	}
	if r := fileAsk(agentAskRequest{Op: "approve", PID: 101}, "u", 0); r.OK {
		t.Errorf("an op other than stop was filed: %+v", r)
	}
}

// One account cannot bury the owner in requests.
func TestOneAccountHasAtMostFiveAsksWaiting(t *testing.T) {
	d := askWorld(t, true)
	for i := 0; i < askMaxPendingPer; i++ {
		if r := fileAsk(agentAskRequest{Op: "stop", PID: 101 + i}, "u", 0); !r.OK {
			t.Fatalf("ask %d refused: %s", i+1, r.Why)
		}
	}
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 106}, "u", 0); r.OK || !strings.Contains(r.Why, "already have 5") {
		t.Errorf("the sixth: %+v", r)
	}
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 106}, "other", 0); !r.OK {
		t.Errorf("another account was held to the first one's count: %s", r.Why)
	}
	// Asking again for the same agent is the same request, not another one:
	// it is handed back (so the asker can follow it), and nothing new is filed.
	before := len(sortedPending(requestsLoad(d)))
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 0); !r.OK ||
		requestsLoad(d)[fullRequestID(t, d, r.Request)].Details["pid"] != "101" {
		t.Errorf("a repeat ask past the cap: %+v", r)
	}
	if after := len(sortedPending(requestsLoad(d))); after != before {
		t.Errorf("a repeat ask past the cap filed a new request: %d -> %d pending", before, after)
	}
}
