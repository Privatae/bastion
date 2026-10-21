//go:build !windows

package main

import "testing"

// Off Windows the guard must stay a no-op, because acquireSingletonLock already
// holds the machine-wide lock there with DIFFERENT semantics — the loser becomes
// a standby that waits for the primary to die, which is what systemd wants.
// Making this refuse instead would turn every standby into a crash.
func TestRunGuardIsANoOpOffWindows(t *testing.T) {
	if err := guardSingleRun(); err != nil {
		t.Fatalf("guardSingleRun must not refuse off Windows: %v", err)
	}
	// And twice, because a standby calls it too.
	if err := guardSingleRun(); err != nil {
		t.Fatalf("a second call must also pass off Windows: %v", err)
	}
}
