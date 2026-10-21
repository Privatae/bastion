//go:build !windows

package main

// Tagged !windows for the reason singleton_test.go states: syscall.Umask does
// not exist on that target. The rest of the machine store's tests are portable
// and stay in machinestore_test.go.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A day-file that ALREADY EXISTS with a loose mode is tightened before the
// machine's findings are appended to it.
//
// THIS IS THE TEST THE FIRST VERSION GOT WRONG, and the mutation sweep is what
// said so. That version set the umask to 0 and asserted 0600 — but a umask only
// ever clears bits, so an O_CREATE of 0600 comes out 0600 under every umask
// there is, and deleting the chmod under test left it green. What the chmod
// really guards is the file it did NOT create: O_APPEND|O_CREATE does not touch
// the mode of an existing file, so a day-file restored from a backup or copied
// in with `cp -p` keeps whatever mode it arrived with while this process writes
// the machine's findings into it.
//
// The umask is still set to 0, for a different and now-honest reason: it proves
// the 0644 below is the mode the file really has rather than one the umask
// happened to allow.
func TestAnExistingLooseDayFileIsTightenedBeforeItIsAppendedTo(t *testing.T) {
	isolateConfigDir(t)
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	p, err := storeDayPath(storeFindings, at)
	if err != nil {
		t.Fatal(err)
	}
	// Arrives world-readable, the way a restored or copied file does.
	if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("the fixture is not loose to begin with, so this test cannot fail: %v %v", fi, err)
	}

	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), at); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal file is %v, want 0600 — the machine's own record stayed world-readable", fi.Mode().Perm())
	}
}

// The writer's own state file is bookkeeping the host must not be able to
// reach: a file the host could write is a file that could suppress a finding by
// pre-declaring it open.
func TestTheWritersStateFileIsOwnerOnly(t *testing.T) {
	isolateConfigDir(t)
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	sp, err := storeStatePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(sp), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := storeRecordPass(storeReport("base-a", storeFinding("aaa", deltaHigh)), at); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(sp)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("store state is %v, want 0600", fi.Mode().Perm())
	}
}
