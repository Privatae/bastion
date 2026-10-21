//go:build !windows

// Uses withMachineAuthority, which lives behind //go:build !windows (see
// anchor_test.go's header).

package main

// `approvals-owner` (approvals_owner.go): the account whose tray the pipe
// serves is recorded with machine authority, in the service's state, and is
// never changed silently. Every value here is invented.

import (
	"os"
	"strings"
	"testing"
)

const otherTestUser = "S-1-5-21-1111111111-2222222222-3333333333-1002"

func ownerTestBox(t *testing.T) {
	t.Helper()
	uiTestConfigDir(t)
	withMachineAuthority(t, true)
	prevState, prevConsole := ownerServiceState, ownerConsole
	ownerServiceState = func() string { return "" }
	ownerConsole = func() bool { return false }
	t.Cleanup(func() { ownerServiceState, ownerConsole = prevState, prevConsole })
}

func TestApprovalsOwnerNeedsMachineAuthorityTheServiceStateAndAPerson(t *testing.T) {
	ownerTestBox(t)
	withMachineAuthority(t, false)
	if err := cmdApprovalsOwner(pipeTestUser, false); err == nil || !strings.Contains(err.Error(), "machine authority") {
		t.Fatalf("without machine authority: %v", err)
	}
	withMachineAuthority(t, true)
	ownerServiceState = func() string { return "the bastion is not installed as this machine's service yet" }
	if err := cmdApprovalsOwner(pipeTestUser, false); err == nil || !strings.Contains(err.Error(), "system service's state") {
		t.Fatalf("outside the service's state: %v", err)
	}
	ownerServiceState = func() string { return "" }
	for _, bad := range []string{"S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-1001; x", ""} {
		if err := cmdApprovalsOwner(bad, false); err == nil {
			t.Fatalf("%q is no person's account, yet it was recorded", bad)
		}
	}
	if sid, present, _ := approvalsOwnerLoad(); present || sid != "" {
		t.Fatal("a refused command wrote an owner")
	}
}

func TestApprovalsOwnerIsNeverChangedSilently(t *testing.T) {
	ownerTestBox(t)
	if err := cmdApprovalsOwner(pipeTestUser, false); err != nil {
		t.Fatalf("first record: %v", err)
	}
	// The same account again changes nothing.
	if err := cmdApprovalsOwner(pipeTestUser, false); err != nil {
		t.Fatalf("the same account again: %v", err)
	}
	// Another account's run: refused, and the first owner keeps the lane.
	if err := cmdApprovalsOwner(otherTestUser, false); err == nil || !strings.Contains(err.Error(), "stay with it") {
		t.Fatalf("another account must not take the approvals over: %v", err)
	}
	if approvalsOwner() != pipeTestUser {
		t.Fatalf("the owner changed to %q", approvalsOwner())
	}
	// --replace with captured output, as an installer would run it: refused.
	if err := cmdApprovalsOwner(otherTestUser, true); err == nil || !strings.Contains(err.Error(), "Administrator terminal") {
		t.Fatalf("--replace off a console must be refused: %v", err)
	}
	if approvalsOwner() != pipeTestUser {
		t.Fatal("a refused --replace changed the owner")
	}
	// At a terminal, on purpose: handed over.
	ownerConsole = func() bool { return true }
	if err := cmdApprovalsOwner(otherTestUser, true); err != nil {
		t.Fatalf("--replace at a terminal: %v", err)
	}
	if approvalsOwner() != otherTestUser {
		t.Fatal("--replace at a terminal did not hand the approvals over")
	}
}

func TestADamagedOwnerRecordIsNotReplacedQuietly(t *testing.T) {
	ownerTestBox(t)
	p, _ := approvalsOwnerPath()
	if err := atomicWrite(p, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := cmdApprovalsOwner(pipeTestUser, false); err == nil || !strings.Contains(err.Error(), "stay with it") {
		t.Fatalf("a damaged record must be replaced only with --replace: %v", err)
	}
	if raw, _ := os.ReadFile(p); string(raw) != "not json" {
		t.Fatal("the damaged record was rewritten")
	}
}
