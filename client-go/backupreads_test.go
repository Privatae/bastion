package main

// Gate: pushes and the background hashing keep their reads of backup folders
// in one record. A push is not started in a folder whose hashing read has not
// returned, the hashing does not read a folder whose push read has not
// returned, and the reads of both count toward the one cap.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// heldHashes makes the hashing job's read of any file in dirs block until
// release, and counts the reads it starts in each folder.
type heldHashes struct {
	mu    sync.Mutex
	reads map[string]int
	gate  chan struct{}
	once  sync.Once
}

func holdHashes(t *testing.T, dirs ...string) *heldHashes {
	t.Helper()
	h := &heldHashes{reads: map[string]int{}, gate: make(chan struct{})}
	dead := map[string]bool{}
	for _, d := range dirs {
		dead[d] = true
	}
	hashMu.Lock()
	prevBound := hashJobTimeout
	hashJobTimeout = 200 * time.Millisecond
	hashMu.Unlock()
	quiet := opMaskLog
	opMaskLog = func(string, ...any) {}
	prev := hashFileFn
	hashFileFn = func(p string) (string, int64, error) {
		d := filepath.Dir(p)
		h.mu.Lock()
		h.reads[d]++
		h.mu.Unlock()
		if dead[d] {
			<-h.gate
		}
		return hashFile(p)
	}
	t.Cleanup(func() {
		h.release()
		readsIdle(t)
		eventually(t, "the hashing job ends", func() bool {
			hashMu.Lock()
			defer hashMu.Unlock()
			return !hashRunning
		})
		hashFileFn = prev
		opMaskLog = quiet
		hashMu.Lock()
		hashJobTimeout = prevBound
		hashMu.Unlock()
	})
	return h
}

func (h *heldHashes) release() { h.once.Do(func() { close(h.gate) }) }

func (h *heldHashes) readsIn(dir string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reads[dir]
}

// readsIdle waits until no read of a backup folder is in flight.
func readsIdle(t *testing.T) {
	t.Helper()
	eventually(t, "every read of a backup folder returned", func() bool {
		backupReadMu.Lock()
		defer backupReadMu.Unlock()
		return len(backupReads) == 0
	})
}

// stuckPast waits until dir has a read in flight past its bound.
func stuckPast(t *testing.T, dir string) {
	t.Helper()
	eventually(t, "a read of "+dir+" is past its bound", func() bool {
		_, stuck := folderStuck(dir, time.Now(), pushStallBound(), hashBound())
		return stuck
	})
}

func TestAPushIsNotStartedInAFolderWhoseHashingReadIsStuck(t *testing.T) {
	stubPublicDNS(t)
	shortPushStall(t)
	readsIdle(t)
	root := t.TempDir()
	rel, sum := pushFixture(t, root, []byte(strings.Repeat("a backup ", 1000)))
	abs := filepath.Join(root, fixtureData)
	h := holdHashes(t, root)
	s := newStuckReads(t, root)

	requestHash(abs)
	eventually(t, "the hashing job reads the file", func() bool { return h.readsIn(root) == 1 })
	stuckPast(t, root)

	for i := 0; i < 5; i++ {
		_, errOut, code := startPush(t, root, rel, sum)
		if code == 0 || !strings.Contains(errOut,
			"backup_push: the folder of "+rel+" has not answered the reading of a backup for its digest") {
			t.Fatalf("start %d in a folder whose hashing read is stuck: %d %s", i, code, errOut)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := s.blocked.Load(); n != 0 {
		t.Fatalf("%d push reads started in a folder whose hashing read is stuck", n)
	}

	// When the hashing read returns, its digest is kept and a push starts.
	s.release()
	h.release()
	readsIdle(t)
	awaitHash(t, abs, sum, "the stuck hashing read's digest was not kept when it returned")
	id := pushStarted(t, root, rel, strings.Repeat("ab", 32))
	if st := awaitPush(t, root, id); st["state"] != "failed" || !strings.Contains(st["error"], "sha256 differs") {
		t.Fatalf("a push once the hashing read returned: %v", st)
	}
}

func TestTheHashingDoesNotReadAFolderWhosePushReadIsStuck(t *testing.T) {
	stubPublicDNS(t)
	shortPushStall(t)
	readsIdle(t)
	dead, live := t.TempDir(), t.TempDir()
	rel, sum := pushFixture(t, dead, []byte(strings.Repeat("a backup ", 1000)))
	other := filepath.Join(dead, "20260101T000000Z.tar.zst.age")
	liveFile := filepath.Join(live, fixtureData)
	for p, b := range map[string]string{other: "another backup", liveFile: "answers"} {
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := holdHashes(t)
	s := newStuckReads(t, dead)

	mustFailStuck(t, dead, pushStarted(t, dead, rel, sum))
	stuckPast(t, dead)

	// Asked for a digest in the dead folder, the hashing reads nothing there;
	// a folder that answers is hashed as usual.
	requestHash(other)
	requestHash(liveFile)
	awaitHash(t, liveFile, sha([]byte("answers")), "the hashing job did not read a folder that answers")
	time.Sleep(300 * time.Millisecond)
	if n := h.readsIn(dead); n != 0 {
		t.Fatalf("the hashing read the folder whose push read is stuck %d times", n)
	}
	if n := s.blocked.Load(); n != 1 {
		t.Fatalf("%d reads are blocked on the dead folder; want the push's 1", n)
	}

	// When the push read returns, the folder is hashed again.
	s.release()
	readsIdle(t)
	requestHash(other)
	awaitHash(t, other, sha([]byte("another backup")), "the folder was not hashed once its push read returned")
}

func TestStuckHashingAndPushReadsShareTheCap(t *testing.T) {
	stubPublicDNS(t)
	shortPushStall(t)
	readsIdle(t)
	capReads(t, 2)
	hashDead, pushDead, live := t.TempDir(), t.TempDir(), t.TempDir()
	body := []byte(strings.Repeat("a backup ", 1000))
	rel, sum := pushFixture(t, hashDead, body)
	pushFixture(t, pushDead, body)
	pushFixture(t, live, body)
	liveOther := filepath.Join(live, "20260101T000000Z.tar.zst.age")
	if err := os.WriteFile(liveOther, []byte("answers"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := holdHashes(t, hashDead)
	s := newStuckReads(t, pushDead)

	// One folder's hashing read and another's push read stick: two reads,
	// the cap.
	requestHash(filepath.Join(hashDead, fixtureData))
	eventually(t, "the hashing job reads the dead folder", func() bool { return h.readsIn(hashDead) == 1 })
	mustFailStuck(t, pushDead, pushStarted(t, pushDead, rel, sum))
	stuckPast(t, hashDead)
	stuckPast(t, pushDead)

	// A folder that answers gets neither a push nor a hashing read.
	for i := 0; i < 3; i++ {
		_, errOut, code := startPush(t, live, rel, sum)
		if code == 0 || !strings.Contains(errOut, "backup_push: 2 reads of backup folders have not returned") ||
			!strings.Contains(errOut, "no push starts on this machine until one does") {
			t.Fatalf("start %d with the cap held by a hashing read and a push read: %d %s", i, code, errOut)
		}
	}
	requestHash(liveOther)
	time.Sleep(300 * time.Millisecond)
	if n := h.readsIn(live); n != 0 {
		t.Fatalf("the hashing read a folder %d times with the cap held", n)
	}
	if n, m := s.blocked.Load(), h.readsIn(hashDead); n != 1 || m != 1 {
		t.Fatalf("%d push reads and %d hashing reads were started on the dead folders; want 1 and 1", n, m)
	}
	backupReadMu.Lock()
	inFlight := readsInFlightLocked()
	backupReadMu.Unlock()
	if inFlight != 2 {
		t.Fatalf("%d reads are in flight; the cap is 2", inFlight)
	}

	// Once one returns, the folder that answers is served.
	s.release()
	eventually(t, "the push read frees its slot", func() bool {
		backupReadMu.Lock()
		defer backupReadMu.Unlock()
		return readsInFlightLocked() == 1
	})
	requestHash(liveOther)
	awaitHash(t, liveOther, sha([]byte("answers")), "the hashing did not read a folder that answers once under the cap")
	id := pushStarted(t, live, rel, strings.Repeat("ab", 32))
	if st := awaitPush(t, live, id); st["state"] != "failed" || !strings.Contains(st["error"], "sha256 differs") {
		t.Fatalf("a push once under the cap: %v", st)
	}
}
