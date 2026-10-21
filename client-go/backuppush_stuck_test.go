package main

// Gate: a push whose file stops answering leaves behind at most one stuck
// read per folder, and at most backupReadsMax on the whole bastion,
// however often a host starts a push there. A start in a folder whose read
// has not returned is refused with a sentence; when the read returns the
// folder is read again. A push that waits for a slot fails on that wait with
// a sentence naming what it waited on, never one blaming its own folder.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stuckReads makes every read of a pushed file block until release, and
// counts the reads blocked at any moment: each one is a goroutine (and, on a
// real mount, an OS thread) that cannot be stopped.
type stuckReads struct {
	gate    chan struct{}
	once    sync.Once
	blocked atomic.Int64
	prev    func(*os.File, []byte) (int, error)
}

// newStuckReads blocks the reads of files in dirs, or of every file when no
// folder is named; the others read as usual.
func newStuckReads(t *testing.T, dirs ...string) *stuckReads {
	t.Helper()
	s := &stuckReads{gate: make(chan struct{})}
	dead := map[string]bool{}
	for _, d := range dirs {
		dead[d] = true
	}
	backupPushHookMu.Lock()
	s.prev = backupPushRead
	prev := s.prev
	backupPushRead = func(f *os.File, p []byte) (int, error) {
		if len(dead) > 0 && !dead[filepath.Dir(f.Name())] {
			return prev(f, p)
		}
		s.blocked.Add(1)
		defer s.blocked.Add(-1)
		<-s.gate
		return 0, errors.New("the mount went away")
	}
	backupPushHookMu.Unlock()
	t.Cleanup(s.release)
	return s
}

// release lets the blocked reads return, and the file answers again.
func (s *stuckReads) release() {
	s.once.Do(func() {
		backupPushHookMu.Lock()
		backupPushRead = s.prev
		backupPushHookMu.Unlock()
		close(s.gate)
	})
}

func shortPushStall(t *testing.T) {
	t.Helper()
	backupPushHookMu.Lock()
	prev := backupPushFileStall
	backupPushFileStall = 200 * time.Millisecond
	backupPushHookMu.Unlock()
	t.Cleanup(func() { backupPushHookMu.Lock(); backupPushFileStall = prev; backupPushHookMu.Unlock() })
}

// pushSlotsIdle waits for reads left blocked by an earlier test to return.
func pushSlotsIdle(t *testing.T) {
	t.Helper()
	eventually(t, "the push slots of an earlier test are freed", func() bool {
		backupReadMu.Lock()
		defer backupReadMu.Unlock()
		return len(backupReads) == 0
	})
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fdsOn counts this process's open descriptors on path, or -1 where the
// system does not list them.
func fdsOn(path string) int {
	dir := "/proc/self/fd"
	if _, err := os.Stat(dir); err != nil {
		dir = "/dev/fd"
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	want, err := filepath.EvalSymlinks(path)
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range ents {
		if l, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil && l == want {
			n++
		}
	}
	return n
}

func startPush(t *testing.T, root, rel, sum string) (string, string, int) {
	t.Helper()
	return driveBackupOp(t, "backup_push", "", root,
		backupPushReq{Op: "start", Path: rel, URL: "https://storage.example/put?sig=1", SHA256: sum, Headers: signedPut})
}

// pushStarted starts a push and returns its job id.
func pushStarted(t *testing.T, root, rel, sum string) string {
	t.Helper()
	out, errOut, code := startPush(t, root, rel, sum)
	if code != 0 {
		t.Fatalf("start refused: %s", errOut)
	}
	var st map[string]string
	if err := json.Unmarshal([]byte(out), &st); err != nil || st["job_id"] == "" {
		t.Fatalf("start reply: %s", out)
	}
	return st["job_id"]
}

func mustFailStuck(t *testing.T, root, id string) {
	t.Helper()
	if st := awaitPush(t, root, id); st["state"] != "failed" || !strings.Contains(st["error"], "stopped answering") {
		t.Fatalf("a push whose file stopped answering reads %v", st)
	}
}

// failures waits for each push to fail and counts the ones whose own read
// stopped answering and the ones that failed waiting, with a sentence that
// holds want, for a slot to read. Any other outcome fails the test.
func failures(t *testing.T, want string, pushes ...[2]string) (stuck, waited int) {
	t.Helper()
	for _, p := range pushes {
		st := awaitPush(t, p[0], p[1])
		switch {
		case st["state"] == "failed" && strings.Contains(st["error"], "stopped answering"):
			stuck++
		case st["state"] == "failed" && strings.Contains(st["error"], "this push waited more than") &&
			strings.Contains(st["error"], want):
			waited++
		default:
			t.Fatalf("a push from a dead folder reads %v", st)
		}
	}
	return stuck, waited
}

// capReads lowers backupReadsMax to n for the test.
func capReads(t *testing.T, n int) {
	t.Helper()
	backupReadMu.Lock()
	prev := backupReadsMax
	backupReadsMax = n
	backupReadMu.Unlock()
	t.Cleanup(func() { backupReadMu.Lock(); backupReadsMax = prev; backupReadMu.Unlock() })
}

func TestRepeatedPushesFromADeadFolderHoldOneRead(t *testing.T) {
	stubPublicDNS(t)
	shortPushStall(t)
	pushSlotsIdle(t)
	root := t.TempDir()
	rel, sum := pushFixture(t, root, []byte(strings.Repeat("a backup ", 1000)))
	abs := filepath.Join(root, fixtureData)
	s := newStuckReads(t)

	// Two starts back to back, before either is known to be stuck: one read
	// blocks, the other push waits for the folder and fails at the same
	// bound without a read of its own, saying the folder has not answered.
	a := pushStarted(t, root, rel, sum)
	b := pushStarted(t, root, rel, sum)
	if stuck, waited := failures(t, "the folder of "+rel+" has not answered an earlier push",
		[2]string{root, a}, [2]string{root, b}); stuck != 1 || waited != 1 {
		t.Fatalf("%d pushes failed on their own read and %d waiting for the folder; want 1 and 1", stuck, waited)
	}
	eventually(t, "one read is left blocked and one descriptor open", func() bool {
		f := fdsOn(abs)
		return s.blocked.Load() == 1 && (f == -1 || f == 1)
	})
	time.Sleep(100 * time.Millisecond)
	g0, f0 := runtime.NumGoroutine(), fdsOn(abs)

	for i := 0; i < 10; i++ {
		out, errOut, code := startPush(t, root, rel, sum)
		if code == 0 {
			t.Fatalf("start %d in a folder whose read has not returned was accepted: %s", i, out)
		}
		if !strings.Contains(errOut, "backup_push: the folder of "+rel+" has not answered an earlier push") ||
			!strings.Contains(errOut, "nothing more is sent from that folder until it answers") {
			t.Fatalf("start %d refused without the sentence: %s", i, errOut)
		}
	}
	eventually(t, "the refused starts leave no goroutine behind", func() bool {
		return runtime.NumGoroutine() <= g0+3
	})
	if n := s.blocked.Load(); n != 1 {
		t.Fatalf("%d reads are blocked on the dead folder after repeated starts; want 1", n)
	}
	if f := fdsOn(abs); f != f0 {
		t.Fatalf("%d descriptors are open on the file after repeated starts; was %d", f, f0)
	}
}

func TestAPushFolderIsReadAgainWhenItsReadReturns(t *testing.T) {
	stubPublicDNS(t)
	shortPushStall(t)
	pushSlotsIdle(t)
	root := t.TempDir()
	rel, sum := pushFixture(t, root, []byte(strings.Repeat("a backup ", 1000)))
	s := newStuckReads(t)
	mustFailStuck(t, root, pushStarted(t, root, rel, sum))
	if _, errOut, code := startPush(t, root, rel, sum); code == 0 || !strings.Contains(errOut, "has not answered an earlier push") {
		t.Fatalf("a start while the read is stuck: %d %s", code, errOut)
	}

	s.release()
	eventually(t, "the returned read frees its folder", func() bool {
		backupReadMu.Lock()
		defer backupReadMu.Unlock()
		return len(backupReads) == 0
	})
	// Read to the end this time: a digest that is not the file's fails on
	// the comparison, which only a full read reaches.
	id := pushStarted(t, root, rel, strings.Repeat("ab", 32))
	if st := awaitPush(t, root, id); st["state"] != "failed" || !strings.Contains(st["error"], "sha256 differs") {
		t.Fatalf("the folder was not read again once its read returned: %v", st)
	}
}

func TestStuckPushReadsAreCappedPerBastion(t *testing.T) {
	stubPublicDNS(t)
	shortPushStall(t)
	pushSlotsIdle(t)
	capReads(t, 2)

	type folder struct{ root, rel, sum string }
	var fs []folder
	for i := 0; i < 4; i++ {
		root := t.TempDir()
		rel, sum := pushFixture(t, root, []byte(strings.Repeat("a backup ", 1000)))
		fs = append(fs, folder{root, rel, sum})
	}
	s := newStuckReads(t)

	// Three dead folders started at once: two reads block, the third push
	// waits for a slot and fails at the bound without a read of its own,
	// saying the cap is held.
	var ps [][2]string
	for _, f := range fs[:3] {
		ps = append(ps, [2]string{f.root, pushStarted(t, f.root, f.rel, f.sum)})
	}
	if stuck, waited := failures(t, "2 reads of backup folders have not returned", ps...); stuck != 2 || waited != 1 {
		t.Fatalf("%d pushes failed on their own read and %d waiting for a slot; want 2 and 1", stuck, waited)
	}
	time.Sleep(100 * time.Millisecond)
	if n := s.blocked.Load(); n != 2 {
		t.Fatalf("%d reads are blocked; the cap is 2", n)
	}

	// A folder that answers is refused too while the cap is held.
	f := fs[3]
	_, errOut, code := startPush(t, f.root, f.rel, f.sum)
	if code == 0 || !strings.Contains(errOut, "backup_push: 2 reads of backup folders have not returned") ||
		!strings.Contains(errOut, "no push starts on this machine until one does") {
		t.Fatalf("a start with the cap held: %d %s", code, errOut)
	}
	if n := s.blocked.Load(); n != 2 {
		t.Fatalf("%d reads are blocked after a refused start; want 2", n)
	}

	s.release()
	eventually(t, "the returned reads free their slots", func() bool {
		backupReadMu.Lock()
		defer backupReadMu.Unlock()
		return len(backupReads) == 0
	})
	id := pushStarted(t, f.root, f.rel, strings.Repeat("ab", 32))
	if st := awaitPush(t, f.root, id); st["state"] != "failed" || !strings.Contains(st["error"], "sha256 differs") {
		t.Fatalf("a push after the reads returned: %v", st)
	}
}

// A push already under way in a folder that answers, waiting for a slot while
// other folders' reads hold the cap, fails with the sentence about those
// folders, not one blaming its own: the wait is not a read of its file.
func TestAPushWaitingForASlotIsNotBlamedOnItsOwnFolder(t *testing.T) {
	stubPublicDNS(t)
	pushSlotsIdle(t)
	// Long enough that the third start is taken before the two stuck reads
	// are past the bound, even on a loaded machine.
	backupPushHookMu.Lock()
	prevStall := backupPushFileStall
	backupPushFileStall = time.Second
	backupPushHookMu.Unlock()
	t.Cleanup(func() { backupPushHookMu.Lock(); backupPushFileStall = prevStall; backupPushHookMu.Unlock() })
	capReads(t, 2)

	dead1, dead2, healthy := t.TempDir(), t.TempDir(), t.TempDir()
	body := []byte(strings.Repeat("a backup ", 1000))
	rel, sum := pushFixture(t, dead1, body)
	pushFixture(t, dead2, body)
	pushFixture(t, healthy, body)
	s := newStuckReads(t, dead1, dead2)

	a := pushStarted(t, dead1, rel, sum)
	b := pushStarted(t, dead2, rel, sum)
	eventually(t, "both dead folders hold a read", func() bool { return s.blocked.Load() == 2 })
	// Neither read is past the bound yet, so this start is taken; its first
	// operation waits for a slot.
	c := pushStarted(t, healthy, rel, sum)
	mustFailStuck(t, dead1, a)
	mustFailStuck(t, dead2, b)
	st := awaitPush(t, healthy, c)
	if st["state"] != "failed" || strings.Contains(st["error"], "stopped answering") ||
		!strings.Contains(st["error"], "this push waited more than 1s for a turn to read its file: "+
			"2 reads of backup folders have not returned") {
		t.Fatalf("a push from a folder that answers, waiting for a slot, reads %v", st)
	}
	if n := s.blocked.Load(); n != 2 {
		t.Fatalf("%d reads are blocked; the cap is 2", n)
	}
}
