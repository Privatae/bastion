//go:build linux

package main

import (
	"path/filepath"
	"testing"
)

// The REAL enumerator's failure path, not the seam above it: an unreadable
// /proc must come back as an error. The bug this plane had was an empty map
// with a nil error here, which the heartbeat sent as "looked, nothing there"
// and the host read as a kill order carried out. scanProcessesFn is stubbed
// by every other test, so without this one the guard stops at the seam.
func TestTheLinuxWalkFailsLoudlyWhenProcIsUnreadable(t *testing.T) {
	prev := procRoot
	t.Cleanup(func() { procRoot = prev })
	procRoot = filepath.Join(t.TempDir(), "no-proc-here")
	m, err := scanProcesses()
	if err == nil {
		t.Fatalf("an unreadable %s returned %d processes and no error — an empty map with a nil error is the bug", procRoot, len(m))
	}
	if m != nil {
		t.Fatalf("a failed walk must return no map, got %v", m)
	}
	procRoot = prev
	if _, err := scanProcesses(); err != nil {
		t.Fatalf("the real /proc walk failed on this box: %v", err)
	}
}
