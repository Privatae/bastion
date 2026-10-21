//go:build darwin

package main

import (
	"fmt"
	"os"
)

// runGuardFile holds the run lock for the life of the process; the kernel
// releases it when the process ends.
var runGuardFile *os.File

// guardSingleRun on macOS: the rule is guardRunBesideService (runlock_unix.go).
// The launchd daemon takes the lock first, so an administrator's `run` beside
// it is refused with a sentence instead of fighting it for the tunnel.
func guardSingleRun() error {
	f, err := guardRunBesideService(systemService.installed, configDir, tryRunLock)
	if err != nil {
		return err
	}
	runGuardFile = f
	// The daemon, holding the lock, keeps its log in bounds. launchd has no
	// size limit of its own for it.
	if systemService.installed && processIsRoot() {
		if err := keepOneLogAside(darwinDaemonLog, serviceLogCap); err != nil {
			fmt.Printf("service: could not set the log aside: %v\n", err)
		}
	}
	return nil
}
