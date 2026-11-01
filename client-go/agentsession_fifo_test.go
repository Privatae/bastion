//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A pipe planted where .git/HEAD belongs must not stall the daemon: a plain
// open would wait for a writer for ever.
func TestAPipeInPlaceOfGitHEADDoesNotStall(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(repo, ".git", "HEAD"), 0o600); err != nil {
		t.Skip("cannot make a fifo here:", err)
	}
	done := make(chan string, 1)
	go func() { done <- gitBranchOf(repo) }()
	select {
	case got := <-done:
		if got != "" {
			t.Errorf("a pipe read as branch %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading .git/HEAD stalled on a pipe")
	}
}
