package main

// The digest cache exists for one reason — a pass that hashes every executable
// on the box costs 2.9 s on this machine and the delta runs every minute — and
// it is allowed to exist only if it cannot be talked into a stale answer. These
// tests are that condition, not the speed.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// THE ATTACK THE KEY IS SHAPED AROUND. An in-place overwrite that restores the
// old size and the old modification time defeats every field a cache normally
// keys on. It does not defeat ctime, which the kernel moves on any write and no
// syscall sets — and that is the entire argument for caching a digest in a
// program whose job is to notice when a binary changes.
func TestABinaryRewrittenWithItsOldTimestampIsNotServedFromTheCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no change time through Go's FileInfo; deltaCacheWeakTTL " +
			"covers it there, and deltacache_windows.go says so")
	}
	p := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(p, []byte("AAAAAAAA"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	c := &digestCache{}
	before, _ := c.digest(p)
	if before == "" {
		t.Fatal("the fixture was not hashed at all")
	}
	// Same length, same modification time, different content.
	if err := os.WriteFile(p, []byte("BBBBBBBB"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, _ := c.digest(p)
	if after == before {
		t.Fatalf("the cache returned the OLD digest for a file whose contents had been "+
			"replaced under its original size and timestamp (%s). A digest cache that "+
			"can be defeated by `touch -r` hides exactly the event this plane exists "+
			"to report.", before[:12])
	}
}

// And it does cache — otherwise the property above is held by a cache that
// never hits, which is a different program.
func TestTheCacheHitsWhenNothingMoved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "steady")
	if err := os.WriteFile(p, []byte("hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &digestCache{}
	a, _ := c.digest(p)
	b, _ := c.digest(p)
	if a != b || a == "" {
		t.Fatalf("two reads of one unchanged file gave %q and %q", a, b)
	}
	hits, misses, _ := c.stats()
	if hits != 1 || misses != 1 {
		t.Errorf("hits=%d misses=%d, want 1 and 1 — the second read went the long way "+
			"round, so the 60-second cadence costs a full hash of the box every time", hits, misses)
	}
}

// A FAILURE IS A FACT ABOUT THE MOMENT, NOT ABOUT THE FILE. Caching "could not
// be read" would mean a process whose executable becomes readable — the bastion
// gaining rights, a mount appearing — is told for ever that it could not be
// looked at.
func TestAFileThatBecomesReadableIsDigestedRatherThanRemembered(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "later")
	c := &digestCache{}
	if d, note := c.digest(p); d != "" || note == "" {
		t.Fatalf("a path with no file gave digest %q note %q", d, note)
	}
	if err := os.WriteFile(p, []byte("now it exists"), 0o755); err != nil {
		t.Fatal(err)
	}
	if d, _ := c.digest(p); d == "" {
		t.Fatal("the file exists now and the cache still says it cannot be read")
	}
}

// The cache answers the same thing the uncached path does. It is a speed
// device; the moment it is also a second opinion, the accounting and the delta
// can disagree about what is running.
func TestTheCachedAnswerIsTheUncachedAnswer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "same")
	if err := os.WriteFile(p, []byte("content"), 0o755); err != nil {
		t.Fatal(err)
	}
	want, wantNote := baselineExeDigest(p)
	c := &digestCache{}
	got, gotNote := c.digest(p)
	if got != want || gotNote != wantNote {
		t.Fatalf("cached (%q,%q) != direct (%q,%q)", got, gotNote, want, wantNote)
	}
	// Including the refusals: a directory is not an executable either way.
	d1, n1 := baselineExeDigest(filepath.Dir(p))
	d2, n2 := c.digest(filepath.Dir(p))
	if d1 != d2 || n1 != n2 {
		t.Fatalf("cached (%q,%q) != direct (%q,%q) for a directory", d2, n2, d1, n1)
	}
}

// A weakly-keyed entry is re-hashed on a timer. Held here as a fact about the
// constant rather than by waiting fifteen minutes: if someone lengthens it to
// hours, the Windows hole widens with no test saying so.
func TestTheWeakKeyTTLStaysShortEnoughToMatter(t *testing.T) {
	if deltaCacheWeakTTL > 30*time.Minute {
		t.Fatalf("deltaCacheWeakTTL is %v — on a platform with no change time this is "+
			"how long a size-and-timestamp-preserving overwrite reads as known",
			deltaCacheWeakTTL)
	}
}
