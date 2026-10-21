//go:build linux

package main

// The Linux half of the noise filter — the three questions only this platform can
// answer, and the one that could be answered wrongly without anyone noticing.

import (
	"os"
	"testing"
)

// HALF A SOCKET TABLE IS NOT A SOCKET TABLE. readSockets returns Supported with
// whatever it got when `ss` runs out of budget (observe_ops_linux.go:160-168),
// and the short-lived rule then checks its listener exemption against a set
// that may simply not contain the socket — silently suppressing the one process
// the exemption exists to protect. By this file's own rule: an exemption that
// cannot be checked is not an exemption.
func TestAPartialSocketTableReadsAsUnreadable(t *testing.T) {
	old := deltaSockets
	t.Cleanup(func() { deltaSockets = old })

	deltaSockets = func() socketsReport {
		return socketsReport{Supported: true, Sockets: []listenSocket{{PID: 7, Port: 443}}}
	}
	pids, ok := deltaListeningPIDs()
	if !ok || !pids[7] {
		t.Fatalf("a complete table read as unusable: ok=%v pids=%v", ok, pids)
	}

	deltaSockets = func() socketsReport {
		return socketsReport{Supported: true, Partial: "tcp: timeout",
			Sockets: []listenSocket{{PID: 7, Port: 443}}}
	}
	if _, ok := deltaListeningPIDs(); ok {
		t.Fatal("a table that timed out half way through reported itself readable. " +
			"The short-lived rule would then hold a process for 'opening no listener' " +
			"on the strength of a list that stopped early.")
	}

	deltaSockets = func() socketsReport { return socketsReport{Reason: "ss not installed"} }
	if _, ok := deltaListeningPIDs(); ok {
		t.Error("a box with no ss reported a readable socket table")
	}
}

// A PROCESS THAT EXITED BETWEEN THE WALK AND THE FILTER IS SHORT-LIVED, not
// unreadable. The filter runs 50-100 ms after the walk — a parent map, the
// package database and two `ss` execs later — so this is the most ordinary
// reason /proc/<pid>/stat is missing, and treating it as "cannot tell" reported
// the shortest-lived processes on the box instead of counting them.
func TestAnExitedProcessCountsAsShortLived(t *testing.T) {
	age := deltaAgeReader()
	// This process exists and has a real age.
	if d, ok := age(os.Getpid()); !ok || d < 0 {
		t.Fatalf("this process read as age %v ok=%v", d, ok)
	}
	// A pid that cannot exist: /proc has no entry, which is what an exited
	// process looks like a few milliseconds later.
	d, ok := age(1 << 30)
	if !ok {
		t.Fatal("a process that is gone read as 'cannot tell its age', so the short-lived " +
			"rule reports it instead of counting it — the exact population the rule exists " +
			"to keep out of the findings")
	}
	if d != 0 {
		t.Errorf("a process that is gone read as %v old, want 0", d)
	}
}

// Linux reads both classes. If either constant said otherwise, an accounting
// taken while `ss` or the account database failed would be written
// `unsupported` again, and every reader of the line would be told a retake
// changes nothing when a retake is exactly the fix.
func TestLinuxReadsBothClassesSoAFailedReaderIsUnread(t *testing.T) {
	if !listenersReadableHere || !identitiesReadableHere {
		t.Fatalf("linux must declare both classes readable: listeners=%v identities=%v",
			listenersReadableHere, identitiesReadableHere)
	}
}
