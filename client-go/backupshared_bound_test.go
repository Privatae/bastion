package main

// Gate: a folder shared with a host, on a network mount that stopped
// answering, holds up nothing. backup_list answers at once with the rest and
// names the folder; backup_push from it is refused with a sentence. The same
// bound as the host's own backup folder (opmask.go).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// blockReadDir makes reading dir block until the test ends.
func blockReadDir(t *testing.T, dir string) {
	t.Helper()
	gate := make(chan struct{})
	prev := backupReadDirFn
	backupReadDirFn = func(p string) ([]os.DirEntry, error) {
		if p == dir {
			<-gate
		}
		return prev(p)
	}
	t.Cleanup(func() {
		close(gate)
		waitProbeIdle("list:" + dir)
		backupReadDirFn = prev
	})
}

// blockResolve makes resolving a file under dir (the push path) block until
// the test ends.
func blockResolve(t *testing.T, dir string) {
	t.Helper()
	gate := make(chan struct{})
	prev := backupResolvePathFn
	backupResolvePathFn = func(root, rpath string) (string, bool) {
		if root == dir {
			<-gate
		}
		return prev(root, rpath)
	}
	t.Cleanup(func() {
		close(gate)
		waitProbeIdle("push:" + dir)
		backupResolvePathFn = prev
	})
}

// waitProbeIdle waits for the probe of key to return, so the function it
// calls can be put back without a race.
func waitProbeIdle(key string) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		opProbeMu.Lock()
		busy := opProbeInFlight[key]
		opProbeMu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type listReply struct {
	Backups     []backupListEntry   `json:"backups"`
	Unavailable []backupUnavailable `json:"unavailable"`
}

func listReplyAs(t *testing.T, self, root string) (listReply, time.Duration) {
	t.Helper()
	type res struct {
		out, errOut string
		code        int
	}
	done := make(chan res, 1)
	start := time.Now()
	go func() {
		out, errOut, code := driveBackupOpAs(t, self, "backup_list", "", root, map[string]string{"op": "list"})
		done <- res{out, errOut, code}
	}()
	select {
	case r := <-done:
		if r.code != 0 {
			t.Fatalf("backup_list exited %d: %s", r.code, r.errOut)
		}
		var rep listReply
		if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
			t.Fatalf("list reply: %v %s", err, r.out)
		}
		return rep, time.Since(start)
	case <-time.After(5 * time.Second):
		t.Fatal("backup_list hung on a shared folder that does not answer")
	}
	return listReply{}, 0
}

func TestASharedFolderThatDoesNotAnswerHoldsUpNothing(t *testing.T) {
	root, _ := opMaskFixture(t) // pairing nas.host.privatae.ai, probe bound 100ms
	const self = "nas.host.privatae.ai"
	pushFixture(t, root, []byte("own backup"))
	good, deadList, deadResolve, deadPush := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	for dir, name := range map[string]string{good: "good", deadList: "dead-list", deadResolve: "dead-resolve",
		deadPush: "dead-push"} {
		pushFixture(t, dir, []byte(name))
		if _, err := addBackupShare(self, root, dir, name); err != nil {
			t.Fatal(err)
		}
	}
	// hangFolder first: its cleanup waits for every probe, so it runs last.
	hangFolder(t, deadResolve) // the folder hangs as soon as it is resolved
	blockReadDir(t, deadList)  // the folder answers a resolve, then hangs when read
	blockResolve(t, deadPush)  // resolving a file in it hangs

	for i := 0; i < 2; i++ { // the second time, the first probes are still stuck
		rep, took := listReplyAs(t, self, root)
		if took > 2*time.Second {
			t.Fatalf("the listing waited %s", took)
		}
		folders := map[string]bool{}
		for _, b := range rep.Backups {
			folders[b.Folder] = true
		}
		if !folders["."] || !folders["shared/good"] {
			t.Fatalf("the folders that answer were not listed: %+v", rep.Backups)
		}
		down := map[string]string{}
		for _, u := range rep.Unavailable {
			down[u.Folder] = u.Why
		}
		for _, f := range []string{"shared/dead-list", "shared/dead-resolve"} {
			if folders[f] || !strings.Contains(down[f], "does not answer") {
				t.Fatalf("%s: listed %v, unavailable %q", f, folders[f], down[f])
			}
		}
	}

	for _, c := range []struct{ name, why string }{
		{"dead-resolve", "does not answer"}, {"dead-push", "does not answer"},
	} {
		start := time.Now()
		_, why := backupResolveFile(self, root, "shared/"+c.name+"/"+fixtureData)
		if !strings.Contains(why, c.why) || time.Since(start) > 2*time.Second {
			t.Fatalf("push from %s: %q after %s", c.name, why, time.Since(start))
		}
	}
	if abs, why := backupResolveFile(self, root, "shared/good/"+fixtureData); why != "" || abs != filepath.Join(good, fixtureData) {
		t.Fatalf("a shared folder that answers stopped working: %q %q", abs, why)
	}
}

// A shared folder swapped for a link to this bastion's own state after it was
// shared is not listed and not sent from.
func TestASharedFolderThatNowReachesTheBastionsStateIsLeftOut(t *testing.T) {
	root, conf := opMaskFixture(t)
	const self = "nas.host.privatae.ai"
	base := t.TempDir()
	shared := filepath.Join(base, "old")
	_ = os.MkdirAll(shared, 0o700)
	if _, err := addBackupShare(self, root, shared, "old"); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(shared)
	if err := os.Symlink(conf, shared); err != nil {
		t.Skip("no symlinks here")
	}
	_ = os.WriteFile(filepath.Join(conf, fixtureData), []byte("not a backup"), 0o600)
	rep, _ := listReplyAs(t, self, root)
	for _, b := range rep.Backups {
		if b.Folder == "shared/old" {
			t.Fatal("a shared folder that now is the configuration folder was listed")
		}
	}
	if len(rep.Unavailable) != 1 || rep.Unavailable[0].Folder != "shared/old" {
		t.Fatalf("unavailable: %+v", rep.Unavailable)
	}
	if _, why := backupResolveFile(self, root, "shared/old/"+fixtureData); why == "" {
		t.Fatal("a file in the configuration folder could be sent")
	}
}
