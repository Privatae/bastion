//go:build !linux

package main

import "syscall"

// Only Linux watches where a root command connects. Elsewhere every command
// reads as not watched, so the host treats its output as untrusted.

func rootExecWatchStartKernel(sessionID string) *rootExecWatch {
	_ = sessionID
	return &rootExecWatch{fd: -1, Err: "this machine is not Linux, where the watch runs"}
}

func rootExecWatchStopKernel(w *rootExecWatch) ([]rootExecConn, string) {
	if w == nil {
		return nil, "no watch was started"
	}
	return nil, w.Err
}

func rootExecWatchSweep() {}

// No cgroup of its own here: the process-group kill is all there is.
func rootExecWatchKillKernel(w *rootExecWatch) { _ = w }

func rootExecIntoCgroup(attr *syscall.SysProcAttr, fd int) { _, _ = attr, fd }
