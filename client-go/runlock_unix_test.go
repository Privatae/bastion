//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On macOS an administrator's commands read the launchd daemon's own state,
// so an administrator's `run` beside the daemon holds the same WireGuard keys.
// It must be refused before it starts anything, and a Mac without the daemon
// must not be touched at all. Run here against the real flock.
func TestARunBesideTheMacServiceIsRefusedBeforeItStarts(t *testing.T) {
	dir := t.TempDir()
	stateDir := func() (string, error) { return dir, nil }

	// No service: nothing is locked and nothing is written.
	f, err := guardRunBesideService(false, func() (string, error) {
		t.Fatal("the state directory was asked for on a machine with no service")
		return "", nil
	}, tryRunLock)
	if err != nil || f != nil {
		t.Fatalf("with no service: file %v, err %v; want neither", f, err)
	}

	// The daemon starts first and takes the lock.
	daemon, err := guardRunBesideService(true, stateDir, tryRunLock)
	if err != nil || daemon == nil {
		t.Fatalf("the first run did not take the lock: %v", err)
	}

	// An administrator's run beside it is refused, and told how to restart the service.
	if _, err := guardRunBesideService(true, stateDir, tryRunLock); err == nil {
		t.Fatal("a second run beside the service was allowed: it would bring up the same tunnel")
	} else if !strings.Contains(err.Error(), "launchctl kickstart -k system/"+launchdLabel) {
		t.Errorf("the refusal does not say how to restart the service: %v", err)
	}

	// Once the daemon is gone the lock is free again.
	_ = daemon.Close()
	again, err := guardRunBesideService(true, stateDir, tryRunLock)
	if err != nil || again == nil {
		t.Fatalf("the lock was not released with its holder: %v", err)
	}
	_ = again.Close()

	// A lock that cannot be opened is a refusal, not a pass.
	if _, err := guardRunBesideService(true, func() (string, error) {
		return filepath.Join(dir, "missing", "deeper"), nil
	}, tryRunLock); err == nil {
		t.Error("a run lock that could not be opened let the run go ahead")
	}
	if _, err := guardRunBesideService(true, func() (string, error) {
		return "", errors.New("no state directory")
	}, tryRunLock); err == nil {
		t.Error("a missing state directory let the run go ahead")
	}
}

func TestTryRunLockIsExclusiveAcrossOpens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "run.lock")
	a, held, err := tryRunLock(p)
	if err != nil || held || a == nil {
		t.Fatalf("first lock: held=%v err=%v", held, err)
	}
	defer a.Close()
	b, held, err := tryRunLock(p)
	if err != nil || !held || b != nil {
		t.Fatalf("second lock: held=%v err=%v; want held", held, err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("the lock file is not private to its owner: %v %v", fi.Mode(), err)
	}
}
