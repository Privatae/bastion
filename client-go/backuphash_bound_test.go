package main

// Gate: the one background hashing job survives a file whose read never
// returns (a network mount that stopped answering). Each file gets a bound;
// past it the job moves on to the other folders, reads nothing more from that
// folder until the stuck read returns, and keeps that read's digest when it
// does.

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func awaitHash(t *testing.T, p, want, why string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Lstat(p); err == nil && cachedHash(p, fi) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(why)
}

func TestAHashReadThatNeverReturnsHoldsUpNoOtherFolder(t *testing.T) {
	const bound = 200 * time.Millisecond
	hashMu.Lock()
	prevBound := hashJobTimeout
	hashJobTimeout = bound
	hashMu.Unlock()
	t.Cleanup(func() { hashMu.Lock(); hashJobTimeout = prevBound; hashMu.Unlock() })
	quiet := opMaskLog
	opMaskLog = func(string, ...any) {}
	t.Cleanup(func() { opMaskLog = quiet })

	dead, live := t.TempDir(), t.TempDir()
	deadFile := filepath.Join(dead, fixtureData)
	deadOther := filepath.Join(dead, "20260101T000000Z.tar.zst.age")
	liveFile := filepath.Join(live, fixtureData)
	for p, b := range map[string]string{deadFile: "stuck", deadOther: "stuck too", liveFile: "answers"} {
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	deadReads := 0
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	prev := hashFileFn
	hashFileFn = func(p string) (string, int64, error) {
		if filepath.Dir(p) == dead {
			mu.Lock()
			deadReads++
			mu.Unlock()
			<-gate
		}
		return hashFile(p)
	}
	t.Cleanup(func() { release(); hashFileFn = prev })
	reads := func() int {
		mu.Lock()
		defer mu.Unlock()
		return deadReads
	}

	requestHash(deadFile)
	deadline := time.Now().Add(5 * time.Second)
	for reads() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the hashing job never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	requestHash(liveFile)
	awaitHash(t, liveFile, sha([]byte("answers")),
		"a read that never returned held up the hashing of every other folder")

	// While the read is stuck, nothing more is read from that folder.
	requestHash(deadOther)
	time.Sleep(3 * bound)
	if n := reads(); n != 1 {
		t.Fatalf("the folder whose read is stuck was read %d times", n)
	}

	// When it returns, its digest is kept, and the folder is read again.
	release()
	awaitHash(t, deadFile, sha([]byte("stuck")), "the stuck read's digest was not kept when it returned")
	requestHash(deadOther)
	awaitHash(t, deadOther, sha([]byte("stuck too")), "the folder was not read again once it answered")
}
