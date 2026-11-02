package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The owner's agent reads the switch list, the doctor and the device's asks
// from the machine's bastion over its socket; a read the bastion answers but
// cannot build comes back as that failure, not as a refusal with the
// administrator's command (the administrator would be told the same).
func TestTheSliceThreeReadsGoThroughTheLane(t *testing.T) {
	askFlowWorld(t)
	laneOwner(t, laneTestUID)
	laneSock(t)
	prevSys, prevLatest, prevSandbox := systemInstalled, doctorLatest, doctorSandbox
	t.Cleanup(func() { systemInstalled, doctorLatest, doctorSandbox = prevSys, prevLatest, prevSandbox })
	systemInstalled = func() bool { return true }
	doctorLatest = func() string { return "" }
	doctorSandbox = func() (bool, string) { return true, "" }
	out := captureStdout(t)

	if err := cmdSwitch([]string{"--list", "--json"}); err != nil {
		t.Fatalf("switch --list --json: %v", err)
	}
	var sw switchesRead
	if err := json.Unmarshal([]byte(printedSince(out, 0, "}\n")), &sw); err != nil {
		t.Fatalf("switch --list --json printed %q (%v)", out(), err)
	}

	before := len(out())
	err := cmdDoctor([]string{"--json"})
	var q quietExit
	if err != nil && !errors.As(err, &q) {
		t.Fatalf("doctor through the lane: %v", err)
	}
	var d doctorRead
	if err := json.Unmarshal([]byte(printedSince(out, before, "}\n")), &d); err != nil || len(d.Checks) == 0 {
		t.Fatalf("doctor --json printed %q (%v)", out()[before:], err)
	}
	if c, ok := doctorCheckNamed(d, "owner"); !ok || !c.OK {
		t.Errorf("the machine's doctor, read by its owner, does not find the owner: %+v", d.Checks)
	}

	p, err := deviceShownPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdDeviceApprovals(nil); err != nil {
		t.Fatalf("device-approvals through the lane: %v", err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("device-approvals read through the lane recorded what it printed as shown")
	}

	// MUTATION: drop `r.Failed = true` in serveRead. RESULT: red, the error
	// carries the administrator's command.
	err = cmdOpsList("", true)
	var le *laneError
	if err == nil || errors.As(err, &le) || strings.Contains(err.Error(), "As the administrator") {
		t.Errorf("ops with nothing paired, through the lane: %v", err)
	}
}

// `switch --list` passes the guard beside the system unit, as status does;
// `switch` does too since the owner's account switches through the lane
// (owneracts.go), and only on Windows is it still refused here.
func TestTheGuardLetsSwitchListThroughAndNotSwitch(t *testing.T) {
	prevArgs, prevUnit, prevAuth := os.Args, linuxSystemUnitPresent, systemService.authority
	t.Cleanup(func() { os.Args, linuxSystemUnitPresent, systemService.authority = prevArgs, prevUnit, prevAuth })
	linuxSystemUnitPresent = func() bool { return true }
	systemService.authority = false
	os.Args = []string{"privatae-bastion", "switch", "--list", "--json"}
	if err := guardServiceFork("switch"); err != nil {
		t.Errorf("switch --list beside the system unit: %v", err)
	}
	os.Args = []string{"privatae-bastion", "switch", "box", "ops", "off"}
	if err := guardServiceFork("switch"); err != nil {
		t.Errorf("switch from the owner's account beside the system unit, before the lane could decide: %v", err)
	}
	if err := serviceGuard("windows", serviceGuardKey("switch", os.Args), true, false); err == nil {
		t.Error("switch from an ordinary account beside a Windows service was let through")
	}
}
