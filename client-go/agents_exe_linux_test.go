//go:build linux

package main

// procExe against REAL processes on this machine (agents_linux.go).
//
// Everything else about the exe identity is proven with fixtures, which is the
// right way to test a rule. But the CLAIM underneath the whole change is about
// what an operating system does — "argv[0] is chosen by the launcher, the
// executable path is not" — and a fixture cannot establish that. These two
// tests ask the kernel.
//
// Linux only, and that is honest rather than a gap: this is the platform the
// test runner is on, and a claim about macOS or Windows behaviour must not be
// asserted by a Linux box. Their paths are exercised through
// parseProcargs2ExePath and the offsets in agents_windows.go.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The simplest true statement available: this test binary's own executable.
// No fixture, no stub — if procExe cannot answer for a process that is
// certainly running, nothing else in this file means anything.
//
// MUTATION: read /proc/<pid>/cmdline instead of /proc/<pid>/exe in procExe.
// RESULT: red — the answer became the go test command line, which is not a
// path to anything.
func TestProcExeAnswersTheKernelForThisProcess(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("this machine cannot name its own executable: %v", err)
	}
	got := procExe(os.Getpid())
	if got == "" {
		t.Fatal("procExe could not read this process's own executable")
	}
	if got != self {
		t.Errorf("procExe(self) = %q, want %q (os.Executable)", got, self)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("procExe returned a relative path %q — sanitizeExePath must have dropped it", got)
	}
}

// THE MEASUREMENT THE WHOLE CHANGE RESTS ON, run against the kernel rather
// than quoted from a comment: a process can present any argv[0] it likes, and
// /proc/<pid>/exe still names the file that was actually loaded.
//
// This is the forgery TestAForgedArgv0FromADifferentExecutableIsNotSanctioned
// (sanction_test.go) refuses, performed for real. If this test ever fails on a
// platform, the identity in sanction.go is not worth what it claims there and
// the header's cost analysis has to be rewritten.
//
// MUTATION: return sanitizeExePath(procCmdline(pid)) from procExe.
// RESULT: red — exe came back as the forged /tmp/.../claude, matching argv[0]
// exactly, which is the defect this exists to catch.
func TestProcExeIgnoresAForgedArgv0(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("no bash on this machine: %v", err)
	}
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no sleep on this machine: %v", err)
	}
	// A path that does not exist, deliberately: the forgery needs no file at
	// all, which is exactly what made argv[0] worthless as an identity.
	const claimed = "/home/user/.local/bin/claude"

	cmd := exec.Command(bash, "-c", "exec -a "+claimed+" "+sleepBin+" 30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the forger: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// bash execs into sleep in place, keeping the pid. Wait for that to happen
	// rather than sleeping a fixed amount.
	var cmdline, exe string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cmdline, exe = procCmdline(pid), procExe(pid)
		if strings.HasPrefix(cmdline, claimed) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.HasPrefix(cmdline, claimed) {
		t.Fatalf("the forger never took its new name: cmdline=%q", cmdline)
	}

	// What the process SAYS it is.
	if got := argv0(cmdline); got != claimed {
		t.Fatalf("argv[0] = %q, want the forged %q", got, claimed)
	}
	// What the KERNEL says it is.
	if exe == "" {
		t.Fatal("procExe read nothing for a process this test started itself")
	}
	if exe == claimed {
		t.Fatalf("procExe returned the forged path %q — it is reading the command "+
			"line, not /proc/<pid>/exe, and every identity in sanction.go built on "+
			"it is forgeable by one exec", exe)
	}
	if filepath.Base(exe) != "sleep" {
		t.Errorf("procExe = %q, want the sleep binary that is actually running", exe)
	}
	if _, err := os.Stat(exe); err != nil {
		t.Errorf("procExe named %q, which is not a file on this machine: %v", exe, err)
	}
}
