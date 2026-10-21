//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// tryRunLock opens path and takes an exclusive flock on it without waiting.
// held reports that another open file already holds it. The lock belongs to
// the returned file and the kernel releases it when the process ends, however
// it ends, so a crashed daemon never leaves a stale lock behind.
func tryRunLock(path string) (f *os.File, held bool, err error) {
	f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return f, false, nil
}

// guardRunBesideService is the macOS single-run rule (runguard_darwin.go),
// kept here so the suite runs it on Linux as well.
//
// With no system service it does nothing and touches nothing: a Mac without
// the daemon behaves as it always has. With the service installed, an
// administrator's commands read the daemon's own state (sysservice.go), so an
// administrator's `run` beside the daemon has the same pairings and the same
// WireGuard keys. It would bring its tunnel up before reaching the loopback
// port it then fails to bind, and the host's peer follows whichever copy
// handshook last, which takes the daemon's tunnel down. So every `run` takes a
// lock in the state directory, and one that finds it held stops before it
// starts anything.
func guardRunBesideService(installed bool, stateDir func() (string, error),
	try func(string) (*os.File, bool, error)) (*os.File, error) {
	if !installed {
		return nil, nil
	}
	d, err := stateDir()
	if err != nil {
		return nil, err
	}
	f, held, err := try(filepath.Join(d, "run.lock"))
	if err != nil {
		return nil, errors.New("cannot open the run lock: " + err.Error())
	}
	if held {
		return nil, errors.New("this machine's bastion is already running as the system service, " +
			"with these same pairings.\n" +
			"  A second copy would bring up the same tunnel and knock the service's off it.\n" +
			"  " + serviceRestartHintFor("darwin"))
	}
	return f, nil
}
