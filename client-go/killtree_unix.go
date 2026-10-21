//go:build !windows

package main

import "syscall"

// freezeSupported: unix stops a process with SIGSTOP, which it cannot catch or
// ignore, and a stopped process cannot fork.
const freezeSupported = true

func osStopProcess(pid int) error   { return syscall.Kill(pid, syscall.SIGSTOP) }
func osResumeProcess(pid int) error { return syscall.Kill(pid, syscall.SIGCONT) }
