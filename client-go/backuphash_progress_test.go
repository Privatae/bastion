package main

// Gate: a read of a backup for its digest counts as stuck only when it has
// gone without an answer for its bound, not when the whole file takes longer
// than that. A large backup on a slow disk whose reads keep returning refuses
// no push from its folder; a read that stops answering still does.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const hashTestBound = 300 * time.Millisecond

// slowHash makes the hashing job read one file a byte at a time, each read
// taking pace: a disk that answers, slowly. After stallAfter reads (when not
// zero) its reads stop answering until finish. finish lets it read at full
// speed.
type slowHash struct {
	reads atomic.Int64
	fast  chan struct{}
	once  sync.Once
	logMu sync.Mutex
	logs  []string
}

func slowHashReads(t *testing.T, file string, pace time.Duration, stallAfter int64) *slowHash {
	t.Helper()
	s := &slowHash{fast: make(chan struct{})}
	hashMu.Lock()
	prevBound, prevRead := hashJobTimeout, hashRead
	hashJobTimeout = hashTestBound
	hashRead = func(f *os.File, p []byte) (int, error) {
		if f.Name() != file {
			return prevRead(f, p)
		}
		select {
		case <-s.fast:
			return prevRead(f, p)
		default:
		}
		if n := s.reads.Add(1); stallAfter > 0 && n > stallAfter {
			<-s.fast
			return prevRead(f, p)
		}
		time.Sleep(pace)
		return prevRead(f, p[:1])
	}
	hashMu.Unlock()
	quiet := opMaskLog
	opMaskLog = func(format string, a ...any) {
		s.logMu.Lock()
		defer s.logMu.Unlock()
		s.logs = append(s.logs, format)
	}
	t.Cleanup(func() {
		s.finish()
		readsIdle(t)
		eventually(t, "the hashing job ends", func() bool {
			hashMu.Lock()
			defer hashMu.Unlock()
			return !hashRunning
		})
		hashMu.Lock()
		hashJobTimeout, hashRead = prevBound, prevRead
		hashMu.Unlock()
		opMaskLog = quiet
	})
	return s
}

func (s *slowHash) finish() { s.once.Do(func() { close(s.fast) }) }

func (s *slowHash) logged(part string) bool {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	for _, l := range s.logs {
		if strings.Contains(l, part) {
			return true
		}
	}
	return false
}

func hashReadInFlight(dir string) bool {
	backupReadMu.Lock()
	defer backupReadMu.Unlock()
	r := backupReads[dir]
	return r != nil && !r.hash.IsZero()
}

// A backup B in a folder that answers, slowly: reading it for its digest
// takes many times the bound, its reads returning all along. A push of
// another backup A in that folder starts and reads A while B is still being
// read.
func TestASlowHashThatKeepsAnsweringRefusesNoPushFromItsFolder(t *testing.T) {
	stubPublicDNS(t)
	shortPushStall(t)
	readsIdle(t)
	root := t.TempDir()
	rel, _ := pushFixture(t, root, []byte(strings.Repeat("a backup ", 1000)))
	big := filepath.Join(root, "20260101T000000Z.tar.zst.age")
	body := bytes.Repeat([]byte("big new backup "), 300)
	if err := os.WriteFile(big, body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := slowHashReads(t, big, 30*time.Millisecond, 0)

	requestHash(big)
	eventually(t, "the hashing job reads the big backup", func() bool { return s.reads.Load() > 0 })
	time.Sleep(3 * hashTestBound)
	if what, stuck := folderStuck(root, time.Now(), pushStallBound(), hashBound()); stuck {
		t.Fatalf("a hash whose reads keep returning made its folder stuck: %s", what)
	}
	// Named with a digest that is not A's, the push reads all of A and fails
	// on the comparison, sending nothing.
	id := pushStarted(t, root, rel, strings.Repeat("ab", 32))
	if st := awaitPush(t, root, id); st["state"] != "failed" || !strings.Contains(st["error"], "sha256 differs") {
		t.Fatalf("a push from a folder being hashed slowly did not read its file: %v", st)
	}
	if !hashReadInFlight(root) {
		t.Fatal("the slow hash ended before the push read its file")
	}
	if !s.logged("is taking more than") || s.logged("has not answered") {
		t.Fatal("the log of a slow hash does not say it is slow, or says it stopped answering")
	}

	s.finish()
	awaitHash(t, big, sha(body), "the slow hash's digest was not kept")
}

// A read for a digest that answers for a while and then goes without an
// answer for the bound still makes its folder stuck: a push there is refused
// with the sentence about the digest, and the read counts toward the cap.
func TestAHashWithNoAnswerForTheBoundStillMarksItsFolderStuck(t *testing.T) {
	stubPublicDNS(t)
	shortPushStall(t)
	readsIdle(t)
	root := t.TempDir()
	rel, sum := pushFixture(t, root, []byte(strings.Repeat("a backup ", 1000)))
	big := filepath.Join(root, "20260101T000000Z.tar.zst.age")
	body := bytes.Repeat([]byte("big new backup "), 300)
	if err := os.WriteFile(big, body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := slowHashReads(t, big, 30*time.Millisecond, 20)

	requestHash(big)
	// Past the bound in all, its reads answering: not stuck.
	eventually(t, "the hashing job reads past the bound", func() bool { return s.reads.Load() >= 15 })
	if what, stuck := folderStuck(root, time.Now(), pushStallBound(), hashBound()); stuck {
		t.Fatalf("a hash whose reads keep returning made its folder stuck: %s", what)
	}

	// Then no answer: stuck, and a push is refused.
	stuckPast(t, root)
	_, errOut, code := startPush(t, root, rel, sum)
	if code == 0 || !strings.Contains(errOut,
		"backup_push: the folder of "+rel+" has not answered the reading of a backup for its digest for more than") {
		t.Fatalf("a push in a folder whose hashing read stopped answering: %d %s", code, errOut)
	}
	backupReadMu.Lock()
	n := stuckReadsLocked(time.Now(), pushStallBound(), hashBound())
	backupReadMu.Unlock()
	if n != 1 {
		t.Fatalf("%d stuck reads counted toward the cap; want the hashing read's 1", n)
	}
	eventually(t, "the log says the read has not answered", func() bool { return s.logged("has not answered") })

	// When it answers again its digest is kept, and a push starts.
	s.finish()
	awaitHash(t, big, sha(body), "the stalled hash's digest was not kept when it answered")
	readsIdle(t)
	id := pushStarted(t, root, rel, strings.Repeat("ab", 32))
	if st := awaitPush(t, root, id); st["state"] != "failed" || !strings.Contains(st["error"], "sha256 differs") {
		t.Fatalf("a push once the hashing read answered: %v", st)
	}
}
