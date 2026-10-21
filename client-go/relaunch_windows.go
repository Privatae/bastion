//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/windows"
)

// relaunchAfterUpdate restarts this bastion after a self-update swapped its
// binary — because on Windows nothing else will.
//
// update.go ends a successful swap with os.Exit(0), and its comment says why
// that is enough: "systemd Restart=always re-execs the path, now the new
// binary". True on Linux. On Windows there IS no supervisor — deploy/install.ps1
// installs the exe, puts it on PATH, and registers nothing with the Service
// Control Manager. So every Windows self-update has been a clean, silent
// shutdown: the update applies, the process exits, and the machine stops
// heartbeating until someone notices and starts it by hand.
//
// Measured on a real desktop updating 0.23.0 -> 0.23.1: the heartbeat
// stopped at the moment of the swap and the box went dark. It had just
// been anchored, and because the daemon never came back the anchor never reached
// the host either — the machine looked simply unanchored, with nothing anywhere
// saying a process had exited. That is the worst part: the failure has no
// symptom except absence.
//
// So on Windows we start the new binary ourselves before exiting. DETACHED_PROCESS
// plus CREATE_NEW_PROCESS_GROUP so the child does not die with this console, and
// it is deliberately NOT inheriting our handles — a child holding the parent's
// stdio keeps the invoking terminal from ever returning.
//
// Best-effort, and it must stay that way: if the relaunch cannot start, the
// update itself already succeeded and the binary on disk is the new one. Report
// it and exit rather than pretending, so the operator knows to start it.
//
// NOT AS A SERVICE. A networked install runs as a Windows service
// (sysservice_windows.go), and there the Service Control Manager is the
// supervisor: the exit that follows ends the process without reporting a stop,
// which the manager counts as a failure and answers with a restart of the new
// binary. A detached copy started here would be a second bastion outside the
// manager, racing the one it is about to start.
func relaunchAfterUpdate() {
	if runningAsService {
		return
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Printf("self-update: cannot find my own path to restart (%v) — start it again with `privatae-bastion run`\n", err)
		return
	}
	cmd := exec.Command(self, os.Args[1:]...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		fmt.Printf("self-update: could not restart automatically (%v) — the new binary is installed, start it with `privatae-bastion run`\n", err)
		return
	}
	fmt.Printf("self-update: restarted as pid %d\n", cmd.Process.Pid)
	// Do NOT Wait: the child is meant to outlive this process.
	_ = cmd.Process.Release()
}
