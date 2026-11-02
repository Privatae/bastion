package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubCode answers the owner's code prompt with code ("" = left empty).
func stubCode(t *testing.T, code string) *int {
	t.Helper()
	asked := 0
	prev := promptOwnerCode
	t.Cleanup(func() { promptOwnerCode = prev })
	promptOwnerCode = func(string) (string, bool) { asked++; return code, code != "" }
	return &asked
}

// From the owner's account, beside the machine's bastion, approve answers a
// stop ask the machine holds, with the owner's code: before, it looked in
// that account's own empty state and said the request did not exist.
func TestTheOwnerApprovesTheMachinesAskThroughTheLane(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if !r.OK {
		t.Fatalf("ask refused: %s", r.Why)
	}
	laneOwner(t, laneTestUID)
	laneSock(t)
	out := captureStdout(t)
	stubCode(t, codeFor(t, machineTestSecret))
	if err := cmdStepupApprove("", true, r.Request); err != nil {
		t.Fatalf("approve through the lane: %v", err)
	}
	if got := requestsLoad(d)[fullRequestID(t, d, r.Request)].State; got != "approved" {
		t.Errorf("the machine's request is %q after the owner approved it", got)
	}
	if got := printedSince(out, 0, "approved."); !strings.Contains(got, "approved.") {
		t.Errorf("printed %q", got)
	}
	// The kernel's name for this account: the harness maps only its uid to
	// the owner's, so the name is the test process's own.
	raw, _ := os.ReadFile(filepath.Join(d, "audit.jsonl"))
	if !strings.Contains(string(raw), `"op":"owner_lane_act"`) ||
		!strings.Contains(string(raw), "from the owner's account ") {
		t.Errorf("the act is not in the audit log with the account that acted:\n%s", raw)
	}
}

// A wrong code approves nothing and counts against the owner's code, as the
// console's does; an empty one sends nothing.
func TestAWrongCodeThroughTheLaneApprovesNothing(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	laneOwner(t, laneTestUID)
	laneSock(t)
	captureStdout(t)
	stubCode(t, "000000")
	err := cmdStepupApprove("", true, r.Request)
	var le *laneError
	if err == nil || errors.As(err, &le) {
		t.Errorf("a wrong code: %v (want the bastion's refusal, not a lane refusal)", err)
	}
	if got := requestsLoad(d)[fullRequestID(t, d, r.Request)].State; got != "pending" {
		t.Errorf("a wrong code left the request %q", got)
	}
	asked := stubCode(t, "")
	if err := cmdStepupApprove("", true, r.Request); err != nil || *asked != 1 {
		t.Errorf("an empty code: %v, asked %d", err, *asked)
	}
	// MUTATION: spend the code without machineCodeSpend. RESULT: red, a wrong
	// code no longer counts.
	stepupMu.Lock()
	n := pipeThrottleLoad(d).Failures
	stepupMu.Unlock()
	if n < 1 {
		t.Errorf("the wrong code was not counted (%d)", n)
	}
}

// Deny takes no code: refusing only takes reach away.
func TestTheOwnerDeniesThroughTheLaneWithNoCode(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	laneOwner(t, laneTestUID)
	laneSock(t)
	captureStdout(t)
	asked := stubCode(t, "")
	if err := cmdStepupDeny("", true, r.Request); err != nil {
		t.Fatalf("deny through the lane: %v", err)
	}
	if got := requestsLoad(d)[fullRequestID(t, d, r.Request)].State; got != "denied" || *asked != 0 {
		t.Errorf("deny left %q, asked for a code %d times", got, *asked)
	}
}

// The local switch from the owner's account: off with nothing, on only with
// the owner's code (the console's switch rule).
func TestTheOwnerSwitchesThroughTheLane(t *testing.T) {
	askFlowWorld(t)
	const host = "box-one.example"
	givenPairing(t, host, pairingActive)
	laneOwner(t, laneTestUID)
	laneSock(t)
	captureStdout(t)
	if err := cmdSwitch([]string{host, "ops", "off"}); err != nil {
		t.Fatalf("switch off: %v", err)
	}
	if !localDenied(host, "ops") {
		t.Fatal("ops is not off after the owner switched it off")
	}
	stubCode(t, "000000")
	if err := cmdSwitch([]string{host, "ops", "on"}); err == nil || !localDenied(host, "ops") {
		t.Errorf("switch on with a wrong code: %v, still off %v", err, localDenied(host, "ops"))
	}
	stubCode(t, codeFor(t, machineTestSecret))
	if err := cmdSwitch([]string{host, "ops", "on"}); err != nil || localDenied(host, "ops") {
		t.Errorf("switch on with the owner's code: %v, still off %v", err, localDenied(host, "ops"))
	}
}

// Any other account is refused every act, with the administrator's command.
func TestAnotherAccountIsRefusedEveryAct(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	laneOwner(t, laneTestUID+1)
	laneSock(t)
	captureStdout(t)
	stubCode(t, codeFor(t, machineTestSecret))
	for name, run := range map[string]func() error{
		"deny":       func() error { return cmdStepupDeny("", true, r.Request) },
		"switch off": func() error { return cmdSwitch([]string{"box-one.example", "ops", "off"}) },
	} {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "acts only for its owner's account") || !strings.Contains(err.Error(), "sudo -H") {
			t.Errorf("%s from another account: %v", name, err)
		}
		if name == "deny" && !strings.Contains(err.Error(), "sudo -H privatae-bastion deny --machine "+r.Request) {
			t.Errorf("the administrator's command does not name the request: %v", err)
		}
	}
	if got := requestsLoad(d)[fullRequestID(t, d, r.Request)].State; got != "pending" {
		t.Errorf("another account's deny left the request %q", got)
	}
	if rep := serveAct(laneTestUID, "lee", agentAskRequest{Act: "approve", Machine: true, ID: r.Request,
		Code: codeFor(t, machineTestSecret)}); rep.OK {
		t.Error("another account approved the machine's request")
	}
}

func TestAnActTheBastionDoesNotHaveFails(t *testing.T) {
	askFlowWorld(t)
	laneOwner(t, laneTestUID)
	if rep := serveAct(laneTestUID, "sam", agentAskRequest{Act: "uninstall"}); rep.OK || !rep.Failed ||
		!strings.Contains(rep.Why, "no act called") {
		t.Errorf("an unknown act: %+v", rep)
	}
}

// Approve through the lane approves the request it showed, or nothing: a
// short prefix sent as typed was found again by the bastion after the code was
// entered, so a request that came to match it meanwhile (the shown one denied,
// another filed) was approved in its place.
func TestTheLaneApprovesOnlyTheRequestItShowed(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if !r.OK {
		t.Fatalf("ask refused: %s", r.Why)
	}
	shown := fullRequestID(t, d, r.Request)
	// Same first character, different from the second on.
	other := shown[:1] + string("0123456789abcdef"[(strings.IndexByte("0123456789abcdef", shown[1])+1)%16]) + shown[2:]
	laneOwner(t, laneTestUID)
	laneSock(t)
	captureStdout(t)
	code := codeFor(t, machineTestSecret)
	prev := promptOwnerCode
	t.Cleanup(func() { promptOwnerCode = prev })
	promptOwnerCode = func(string) (string, bool) {
		// While the person types: the shown request is answered, and another
		// matching the typed prefix is waiting.
		stepupMu.Lock()
		m := requestsLoad(d)
		rec := m[shown]
		m[other] = rec
		_ = requestsSave(d, m)
		stepupMu.Unlock()
		if err := stepupDenyRequest(d, shown); err != nil {
			t.Fatal(err)
		}
		return code, true
	}
	// MUTATION: send the typed prefix (ID: prefix). RESULT: red, the other
	// request is approved.
	err := cmdStepupApprove("", true, shown[:1])
	if got := requestsLoad(d)[other].State; got != "pending" {
		t.Fatalf("a request the person was never shown is %q after they approved the one they were shown (%v)", got, err)
	}
	if err == nil {
		t.Error("approving a request answered meanwhile said nothing")
	}
}

// A Host's request is approved through the lane only for a pairing this
// machine serves, as the console's approve (approvalTarget) refuses the rest.
func TestTheLaneDoesNotApproveForAPairingThisMachineDoesNotServe(t *testing.T) {
	askFlowWorld(t)
	laneOwner(t, laneTestUID)
	const host, id = "box-two.example", "c0ffee00c0ffee00c0ffee00c0ffee00"
	waiting := func(state string) string {
		dcn := givenPairing(t, host, state)
		enrolFactorAt(t, dcn, hostTestSecret)
		if err := requestsSave(dcn, map[string]stepupRequest{id: {Purpose: "test|host", State: "pending",
			At: time.Now().UTC().Format(time.RFC3339)}}); err != nil {
			t.Fatal(err)
		}
		return dcn
	}
	dcn := waiting(pairingPending)
	// MUTATION: drop the approvalTarget check. RESULT: red, approved.
	rep := serveAct(laneTestUID, "sam", agentAskRequest{Act: "approve", Host: host, ID: id[:8], Code: codeFor(t, hostTestSecret)})
	if rep.OK || !strings.Contains(rep.Why, "does not serve") {
		t.Errorf("approve for a pairing the anchor has not approved: %+v", rep)
	}
	if got := requestsLoad(dcn)[id].State; got != "pending" {
		t.Errorf("the request of a pairing this machine does not serve is %q", got)
	}
	// The same act for an active pairing is answered: the refusal above is
	// the pairing's state, not the test's setup.
	dcn = waiting(pairingActive)
	if rep := serveAct(laneTestUID, "sam", agentAskRequest{Act: "approve", Host: host, ID: id[:8],
		Code: codeFor(t, hostTestSecret)}); !rep.OK {
		t.Errorf("approve for an active pairing: %+v", rep)
	}
	if got := requestsLoad(dcn)[id].State; got != "approved" {
		t.Errorf("the active pairing's request is %q", got)
	}
}

// The act's audit line lands in the machine's log, and says what was acted
// on as the bastion resolved it. With no owner's code set up (a switch off
// needs none) it was written to audit.jsonl in the daemon's working
// directory; and a request reached with no --machine, the machine's because
// no Host is paired, was logged as a Host's.
func TestAnOwnerActIsAuditedInTheMachinesLogAsResolved(t *testing.T) {
	uiTestConfigDir(t)
	const host = "box-one.example"
	givenPairing(t, host, pairingActive)
	laneOwner(t, laneTestUID)
	cwd := t.TempDir()
	t.Chdir(cwd)
	if rep := serveAct(laneTestUID, "sam", agentAskRequest{Act: "switch", Host: host, Family: "ops", Off: true}); !rep.OK {
		t.Fatalf("switch off: %+v", rep)
	}
	// MUTATION: audit to existingMachineFactorDir(). RESULT: red, the line is
	// in the working directory.
	if _, err := os.Stat(filepath.Join(cwd, "audit.jsonl")); err == nil {
		t.Error("the act's audit line was written into the daemon's working directory")
	}
	dir, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if !strings.Contains(string(raw), `"op":"owner_lane_act"`) || !strings.Contains(string(raw), "switch "+host+" ops off") {
		t.Errorf("the switch is not in the machine's audit log:\n%s", raw)
	}
}

func TestAnOwnerActOnTheMachinesRequestIsAuditedAsTheMachines(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	laneOwner(t, laneTestUID)
	// No --machine, and no Host paired: the machine's request.
	if rep := serveAct(laneTestUID, "sam", agentAskRequest{Act: "deny", ID: r.Request}); !rep.OK {
		t.Fatalf("deny: %+v", rep)
	}
	raw, _ := os.ReadFile(filepath.Join(d, "audit.jsonl"))
	// MUTATION: name the target from req.Machine. RESULT: red, "a Host's ()".
	if want := "deny the machine's request " + fullRequestID(t, d, r.Request); !strings.Contains(string(raw), want) {
		t.Errorf("the audit line does not say %q:\n%s", want, raw)
	}
}

// Deny for a Host's request is refused, as the console refuses it, for a
// pairing this machine does not serve.
func TestTheLaneDoesNotDenyForAPairingThisMachineDoesNotServe(t *testing.T) {
	askFlowWorld(t)
	const host = "box-pending.example"
	givenPairing(t, host, pairingPending)
	laneOwner(t, laneTestUID)
	rep := serveAct(laneTestUID, "sam", agentAskRequest{Act: "deny", Host: host, ID: "abcd1234"})
	if rep.OK || !strings.Contains(rep.Why, "does not serve") {
		t.Errorf("deny for a pending pairing: %+v", rep)
	}
}

// An act that panics inside the daemon leaves the request lock free: the
// next approval does not hang.
func TestAPanickingActLeavesTheRequestLockFree(t *testing.T) {
	askFlowWorld(t)
	laneOwner(t, laneTestUID)
	prev := requestsLoadHook
	t.Cleanup(func() { requestsLoadHook = prev })
	requestsLoadHook = func() { panic("boom") }
	if rep := serveAct(laneTestUID, "sam", agentAskRequest{Act: "deny", Machine: true, ID: "abcd1234"}); rep.OK || !rep.Failed {
		t.Fatalf("a panicking act: %+v", rep)
	}
	requestsLoadHook = func() {}
	done := make(chan struct{})
	go func() { lockedRequests(existingMachineFactorDir()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the request lock was left held by the panicking act")
	}
}
