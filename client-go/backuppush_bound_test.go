package main

// Gate: a push whose file stops answering (a network mount that died while
// the job reads it) does not stay pending: a read of the file that does not
// return within the bound fails the job with a sentence, whether it is stuck
// checking the digest or sending.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// deadMountReads makes every read of a pushed file block until the test ends,
// then fail, as a read of a mount that went away does.
func deadMountReads(t *testing.T) {
	t.Helper()
	gate := make(chan struct{})
	var once sync.Once
	backupPushHookMu.Lock()
	prev := backupPushRead
	backupPushRead = func(f *os.File, p []byte) (int, error) {
		<-gate
		return 0, errors.New("the mount went away")
	}
	backupPushHookMu.Unlock()
	t.Cleanup(func() {
		once.Do(func() { close(gate) })
		backupPushHookMu.Lock()
		backupPushRead = prev
		backupPushHookMu.Unlock()
	})
}

func TestAPushFromAFolderThatStopsAnsweringFails(t *testing.T) {
	allowLoopbackFetch(t)
	backupPushHookMu.Lock()
	prevStall := backupPushFileStall
	backupPushFileStall = 200 * time.Millisecond
	backupPushHookMu.Unlock()
	t.Cleanup(func() { backupPushHookMu.Lock(); backupPushFileStall = prevStall; backupPushHookMu.Unlock() })

	for _, phase := range []string{"checking the digest", "sending"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			_, sum := pushFixture(t, root, []byte(strings.Repeat("a backup ", 1000)))
			abs := filepath.Join(root, fixtureData)
			if phase == "sending" {
				// The digest is known, so the first read is the upload's.
				fi, err := os.Lstat(abs)
				if err != nil {
					t.Fatal(err)
				}
				noteHash(abs, fi, sum)
			}
			srv, _, _ := uploadServer(t, 200)
			deadMountReads(t)
			job := pushJob(root, sum)
			done := make(chan struct{})
			go func() { runBackupPush(job, srv.URL+"/put", abs); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("a push whose file stopped answering is still running")
			}
			backupJobsMu.Lock()
			state, msg := job.State, job.Error
			backupJobsMu.Unlock()
			if state != "failed" || !strings.Contains(msg, "stopped answering") {
				t.Fatalf("the job reads %s %q", state, msg)
			}
		})
	}
}
