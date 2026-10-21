package main

// Machine-authority gate — the Windows-safe half.
//
// Every other test of anchoring lives in files tagged !windows because their
// helpers are unix-only, so this is the only coverage that COMPILES on the
// platform the gate was silently closed on. It deliberately asserts wording and
// shape rather than the privilege answer itself: what processIsRoot() returns
// depends on how the suite was invoked, and a test that demanded a particular
// answer would just be testing the runner.

import (
	"runtime"
	"strings"
	"testing"
)

func TestAdminHowToSpeaksThePlatformsLanguage(t *testing.T) {
	got := adminHowTo()
	if runtime.GOOS == "windows" {
		if !strings.Contains(strings.ToLower(got), "administrator") {
			t.Fatalf("a Windows user needs the Windows instruction, got %q", got)
		}
		if strings.Contains(got, "sudo") {
			t.Fatalf("telling a Windows user to run sudo is how a real instruction becomes noise: %q", got)
		}
		return
	}
	if !strings.Contains(got, "sudo") {
		t.Fatalf("a Unix user needs the sudo instruction, got %q", got)
	}
	if strings.Contains(strings.ToLower(got), "administrator") {
		t.Fatalf("Windows wording leaked onto %s: %q", runtime.GOOS, got)
	}
}

func TestRefusalNamesTheActAndHowToRetryIt(t *testing.T) {
	// A refusal that does not say WHICH command was refused, or what to do
	// instead, is how "claim-anchor must run as root" became a dead end on a
	// platform where nothing could ever satisfy it.
	err := requireMachineAuthority("claim-anchor")
	if err == nil {
		if !processIsRoot() {
			t.Fatal("gate passed while processIsRoot() is false")
		}
		return // running with authority; nothing to assert about the text
	}
	msg := err.Error()
	if !strings.Contains(msg, "claim-anchor") {
		t.Errorf("refusal does not name the act: %q", msg)
	}
	if !strings.Contains(msg, adminHowTo()) {
		t.Errorf("refusal does not say how to retry: %q", msg)
	}
}

func TestTheGateAgreesWithProcessIsRoot(t *testing.T) {
	// One question, one answer. Before this, five call sites each asked
	// os.Geteuid() != 0 by hand — which on Windows is ALWAYS true, so all five
	// were permanently shut there while reading like an ordinary root check.
	if got, want := requireMachineAuthority("x") == nil, processIsRoot(); got != want {
		t.Fatalf("gate says authorized=%v but processIsRoot()=%v", got, want)
	}
}

// Both hints, for EVERY platform, from whatever machine runs the test.
//
// The first version of this asked runtime.GOOS and asserted one branch, so only
// a Windows machine could check the Windows string — and a mutation reverting
// the fix passed clean on the Linux builder. Testing a platform branch means
// driving the branch, not the host.
func TestHintsMatchThePlatformTheyAreFor(t *testing.T) {
	for _, tc := range []struct {
		goos, must, mustNot string
	}{
		{"windows", "privatae-bastion run", "systemctl"},
		{"linux", "systemctl restart privatae-bastion", "privatae-bastion run"},
		{"darwin", "systemctl restart privatae-bastion", "PowerShell"},
	} {
		h := restartHintFor(tc.goos)
		if !contains(h, tc.must) {
			t.Fatalf("%s restart hint must say %q: %q", tc.goos, tc.must, h)
		}
		if contains(h, tc.mustNot) {
			t.Fatalf("%s restart hint must NOT say %q: %q", tc.goos, tc.mustNot, h)
		}
	}
	// Windows has no sudo; unix does not have an Administrator terminal.
	if h := anchorCommandHintFor("windows"); contains(h, "sudo") {
		t.Fatalf("Windows must never be told to sudo: %q", h)
	}
	if h := anchorCommandHintFor("linux"); contains(h, "Administrator") {
		t.Fatalf("Linux must not be told about an Administrator terminal: %q", h)
	}
	// And neither may send the user after a token: claim-anchor stopped taking
	// one in 0.23.0, and a usage string that disagrees with the command IS the
	// bug, because the string is what gets typed.
	for _, goos := range []string{"windows", "linux", "darwin"} {
		if h := anchorCommandHintFor(goos); contains(h, "<token>") {
			t.Fatalf("%s anchor hint must not name a token: %q", goos, h)
		}
	}
}

// status must be able to say WHERE it is running, per platform.
//
// A user with no terminal open has no way of knowing where the bastion is
// running. The honest answer on Windows is that a self-updated bastion is
// DETACHED and has no console, so the start hint and the status output are the
// only places that can tell them. Driven per-platform for the reason the restart
// hint is: a branch only reachable on one OS is a branch nothing checks.
func TestRunCommandHintMatchesThePlatform(t *testing.T) {
	if h := runCommandHintFor("windows"); h != "privatae-bastion run" {
		t.Fatalf("windows starts it directly: %q", h)
	}
	if h := runCommandHintFor("windows"); contains(h, "systemctl") {
		t.Fatalf("windows must never be told systemctl: %q", h)
	}
	for _, goos := range []string{"linux", "darwin"} {
		h := runCommandHintFor(goos)
		if !contains(h, "systemctl start privatae-bastion") {
			t.Fatalf("%s starts the service: %q", goos, h)
		}
	}
}
