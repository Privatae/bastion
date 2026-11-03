package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// laneSock stands the machine's bastion up on a real unix socket and points
// this process's reads at it, as an agent beside the system service sees it.
func laneSock(t *testing.T) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "ask.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	// The globals are set before the server goroutine starts and restored only
	// after it and every connection it served have returned: a client's
	// connect is no happens-before edge the race detector sees, so a server
	// that read them unordered with these writes is a data race under -race.
	prevPath, prevLane, prevID := readSockPath, readsGoThroughLane, askPeerIdentityFn
	t.Cleanup(func() { readSockPath, readsGoThroughLane, askPeerIdentityFn = prevPath, prevLane, prevID })
	readSockPath = func() string { return sock }
	readsGoThroughLane = func() bool { return true }
	// The kernel's answer, with this process's own uid read as laneTestUID:
	// the suite runs as root, which is never a machine's owner account.
	askPeerIdentityFn = func(c net.Conn) (uint32, string, error) {
		uid, who, err := contextPeerIdentity(c)
		if err == nil && uid == uint32(os.Getuid()) {
			uid = laneTestUID
		}
		return uid, who, err
	}
	var served sync.WaitGroup
	served.Add(1)
	t.Cleanup(func() { _ = ln.Close(); served.Wait() })
	go func() {
		defer served.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			served.Add(1)
			go func() { defer served.Done(); askSockServe(c) }()
		}
	}()
}

const laneTestUID = 1000

// The owner's agent, with no sudo and no browser, reads the machine's status,
// agents and activity from its bastion; the kernel's account decides it.
func TestTheOwnersAgentReadsTheMachineThroughTheLane(t *testing.T) {
	askFlowWorld(t)
	laneOwner(t, laneTestUID)
	laneSock(t)
	out := captureStdout(t)

	if err := cmdStatus([]string{"--json"}); err != nil {
		t.Fatalf("status: %v", err)
	}
	var s statusRead
	if err := json.Unmarshal([]byte(printedSince(out, 0, "}\n")), &s); err != nil || s.Version != clientVersion {
		t.Fatalf("status --json printed %q (%v)", out(), err)
	}
	before := len(out())
	if err := cmdAgents([]string{"--json"}); err != nil {
		t.Fatalf("agents: %v", err)
	}
	got := printedSince(out, before, "untrusted text")
	if !strings.Contains(got, `"signature": "aider"`) || !strings.Contains(got, `"signature": "claude-code"`) {
		t.Errorf("agents through the lane printed %q", got)
	}
	before = len(out())
	if err := cmdActivity(nil); err != nil {
		t.Fatalf("activity: %v", err)
	}
	if got := printedSince(out, before, "\n"); got == "" {
		t.Error("activity through the lane printed nothing")
	}
}

// Another account is told why and how the administrator reads it; the reads
// that mean something with its own permissions fall back to those.
func TestAnotherAccountIsRefusedTheMachinesReads(t *testing.T) {
	askFlowWorld(t)
	laneOwner(t, laneTestUID+1)
	laneSock(t)
	err := cmdStatus(nil)
	if err == nil || !strings.Contains(err.Error(), "answers reads only for its owner's account") ||
		!strings.Contains(err.Error(), "sudo -H privatae-bastion status") {
		t.Errorf("status from another account: %v", err)
	}
	if err := cmdReport([]string{"--out", "-"}); err == nil || !strings.Contains(err.Error(), "sudo -H privatae-bastion report") {
		t.Errorf("report from another account: %v", err)
	}
	out := captureStdout(t)
	if err := cmdSchedules(nil); err != nil {
		t.Errorf("schedules from another account did not fall back to its own: %v", err)
	}
	if printedSince(out, 0, "\n") == "" {
		t.Error("schedules printed nothing")
	}
}

// Installed for the whole machine, with nothing answering on its socket:
// status says so instead of failing.
func TestStatusSaysTheServiceIsNotAnswering(t *testing.T) {
	uiTestConfigDir(t)
	prevPath, prevLane := readSockPath, readsGoThroughLane
	t.Cleanup(func() { readSockPath, readsGoThroughLane = prevPath, prevLane })
	readSockPath = func() string { return filepath.Join(t.TempDir(), "nothing.sock") }
	readsGoThroughLane = func() bool { return true }
	out := captureStdout(t)
	if err := cmdStatus(nil); err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := printedSince(out, 0, "status privatae-bastion"); !strings.Contains(got, "NOT ANSWERING") ||
		!strings.Contains(got, "systemctl status privatae-bastion") {
		t.Errorf("status printed %q", got)
	}
}

// report --out - writes the report to standard output.
func TestReportToStandardOutput(t *testing.T) {
	homeTestWorld(t, true)
	out := captureStdout(t)
	if err := cmdReport([]string{"--out", "-"}); err != nil {
		t.Fatal(err)
	}
	if got := printedSince(out, 0, "No AI model wrote any of this report."); !strings.Contains(got, "# AI agents on ") {
		t.Errorf("report --out - printed %q", got)
	}
}

// An answer larger than the asking side reads is refused by the daemon with
// the reason, not cut off mid-answer, which the asker read as a bastion that
// does not answer at all (and status as NOT ANSWERING).
func TestAnAnswerTooLargeToReadIsRefusedWithTheReason(t *testing.T) {
	askFlowWorld(t)
	laneOwner(t, laneTestUID)
	laneSock(t)
	machineReads["test-huge"] = machineRead{build: func(readOpts) (any, error) {
		return strings.Repeat("x", readMaxBytes), nil
	}}
	t.Cleanup(func() { delete(machineReads, "test-huge") })
	var v string
	err := readViaSock("test-huge", readOpts{}, &v)
	var le *laneError
	if !errors.As(err, &le) || le.down || !strings.Contains(le.why, "--since") {
		t.Errorf("a read too large for the asker: %#v", err)
	}
}
