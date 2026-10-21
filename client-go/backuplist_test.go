package main

// Gate: backup_list tells a host which backups this machine holds for it —
// its own folder and the folders the person shared with it — with the
// digests backup_push needs, and never reads a file inside the dispatch.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func listVia(t *testing.T, root string) []backupListEntry {
	t.Helper()
	return listViaAs(t, "", root)
}

func listViaAs(t *testing.T, self, root string) []backupListEntry {
	t.Helper()
	out, errOut, code := driveBackupOpAs(t, self, "backup_list", "", root, map[string]string{"op": "list"})
	if code != 0 {
		t.Fatalf("list exited %d: %s", code, errOut)
	}
	var reply struct {
		Backups []backupListEntry `json:"backups"`
	}
	if err := json.Unmarshal([]byte(out), &reply); err != nil || reply.Backups == nil {
		t.Fatalf("list reply: %v %s", err, out)
	}
	return reply.Backups
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// holdHashing replaces the hashing job's reader with one that waits until
// released, and counts the files it was asked to read.
func holdHashing(t *testing.T) (release func(), calls *int) {
	t.Helper()
	gate := make(chan struct{})
	n := 0
	prev := hashFileFn
	hashFileFn = func(p string) (string, int64, error) {
		hashMu.Lock()
		n++
		hashMu.Unlock()
		<-gate
		return hashFile(p)
	}
	var once bool
	release = func() {
		if !once {
			once = true
			close(gate)
		}
	}
	t.Cleanup(func() { release(); hashFileFn = prev })
	return release, &n
}

func awaitListed(t *testing.T, root string, ok func([]backupListEntry) bool) []backupListEntry {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if l := listBackups("", root); ok(l) {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the listing never showed what was expected")
	return nil
}

func TestBackupListShowsTheBackupsAtTheTopOfTheFolder(t *testing.T) {
	root := t.TempDir()
	data := []byte("data of the backup")
	side := []byte("sidecar")
	_ = os.WriteFile(filepath.Join(root, fixtureStamp+".tar.zst.age"), data, 0o600)
	_ = os.WriteFile(filepath.Join(root, fixtureStamp+".key.age"), side, 0o600)
	_ = os.WriteFile(filepath.Join(root, "20260101T000000Z.key.age"), side, 0o600)
	_ = os.WriteFile(filepath.Join(root, "notes.txt"), []byte("mine"), 0o600)
	_ = os.MkdirAll(filepath.Join(root, "sub"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "sub", "20260201T000000Z.tar.zst.age"), data, 0o600)
	_ = os.Symlink(filepath.Join(root, fixtureStamp+".tar.zst.age"), filepath.Join(root, "20260301T000000Z.tar.zst.age"))

	l := listVia(t, root)
	if len(l) != 2 || l[0].Stamp != fixtureStamp || l[1].Stamp != "20260101T000000Z" {
		t.Fatalf("listed %+v", l)
	}
	e := l[0]
	if e.Folder != "." || !e.HasData || !e.HasSidecar || e.DataBytes != int64(len(data)) || e.SidecarBytes != int64(len(side)) {
		t.Fatalf("entry %+v", e)
	}
	if l[1].HasData || !l[1].HasSidecar || l[1].DataBytes != 0 {
		t.Fatalf("a sidecar alone reads %+v", l[1])
	}
	l = awaitListed(t, root, func(l []backupListEntry) bool { return l[0].DataSHA256 != "" && l[0].SidecarSHA256 != "" })
	if l[0].DataSHA256 != sha(data) || l[0].SidecarSHA256 != sha(side) {
		t.Fatalf("digests %+v", l[0])
	}
}

// A listing never waits for a file to be read: an unknown digest is "" and
// one background job reads it; the digest appears on a later listing.
func TestBackupListNeverWaitsForHashing(t *testing.T) {
	root := t.TempDir()
	data := []byte("a large backup, as far as this test is concerned")
	_ = os.WriteFile(filepath.Join(root, fixtureData), data, 0o600)
	release, calls := holdHashing(t)

	done := make(chan []backupListEntry, 1)
	go func() { done <- listBackups("", root) }()
	select {
	case l := <-done:
		if len(l) != 1 || l[0].DataSHA256 != "" {
			t.Fatalf("listed %+v", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listing waited for the file to be hashed")
	}
	// Listing again while the job is reading the file starts no second read.
	deadline := time.Now().Add(5 * time.Second)
	for {
		hashMu.Lock()
		n := *calls
		hashMu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the hashing job never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = listBackups("", root)
	release()
	l := awaitListed(t, root, func(l []backupListEntry) bool { return l[0].DataSHA256 != "" })
	if l[0].DataSHA256 != sha(data) {
		t.Fatal("wrong digest")
	}
	hashMu.Lock()
	n := *calls
	hashMu.Unlock()
	if n != 1 {
		t.Fatalf("the file was read %d times", n)
	}
}

// A digest is known only for the file it was taken of: a new size or
// modification time makes it unknown again, and the new one is read.
func TestBackupListDigestFollowsTheFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, fixtureData)
	_ = os.WriteFile(p, []byte("first"), 0o600)
	awaitListed(t, root, func(l []backupListEntry) bool { return l[0].DataSHA256 == sha([]byte("first")) })

	_ = os.WriteFile(p, []byte("second, longer"), 0o600)
	if l := listBackups("", root); l[0].DataSHA256 != "" {
		t.Fatalf("a changed size kept the old digest: %s", l[0].DataSHA256)
	}
	awaitListed(t, root, func(l []backupListEntry) bool { return l[0].DataSHA256 == sha([]byte("second, longer")) })

	// Same size, new time.
	_ = os.WriteFile(p, []byte("third, longer!"), 0o600)
	later := time.Now().Add(time.Hour)
	_ = os.Chtimes(p, later, later)
	if l := listBackups("", root); l[0].DataSHA256 != "" {
		t.Fatalf("a changed modification time kept the old digest: %s", l[0].DataSHA256)
	}
	awaitListed(t, root, func(l []backupListEntry) bool { return l[0].DataSHA256 == sha([]byte("third, longer!")) })
}

// What this bastion fetched is listed with the digest it recorded, without
// reading the file.
func TestBackupListUsesTheRecordOfWhatArrived(t *testing.T) {
	root := t.TempDir()
	data := []byte("fetched earlier")
	_ = os.WriteFile(filepath.Join(root, fixtureData), data, 0o600)
	if err := recordArrival(root, fixtureData, sha(data), time.Now()); err != nil {
		t.Fatal(err)
	}
	hashMu.Lock()
	hashCache = map[string]hashEntry{} // as after a restart
	hashMu.Unlock()
	_, calls := holdHashing(t)
	if l := listBackups("", root); l[0].DataSHA256 != sha(data) {
		t.Fatalf("the recorded digest was not used: %+v", l[0])
	}
	time.Sleep(50 * time.Millisecond)
	hashMu.Lock()
	n := *calls
	hashMu.Unlock()
	if n != 0 {
		t.Fatal("a recorded file was read to hash it")
	}
}

// A folder shared with a pairing is listed for that pairing, under
// shared/<name>; not for another, not for an anonymous caller, and not once
// taken back.
func TestBackupListShowsOnlyFoldersSharedWithThisHost(t *testing.T) {
	lost := t.TempDir()
	_ = os.WriteFile(filepath.Join(lost, fixtureData), []byte("the lost host's"), 0o600)
	const newHost, other = "new.host.privatae.ai", "other.host.privatae.ai"
	root := t.TempDir()
	s, err := addBackupShare(newHost, root, lost, "Old Host.example")
	if err != nil {
		t.Fatal(err)
	}
	if s.Slug != "old-host.example" || strings.ContainsAny(s.Slug, "/ ") {
		t.Fatalf("slug %q", s.Slug)
	}
	if _, err := addBackupShare(newHost, root, lost, "again"); err == nil {
		t.Fatal("the same folder was shared twice")
	}
	if _, err := addBackupShare("", root, t.TempDir(), "nobody"); err == nil {
		t.Fatal("a folder was shared with no host")
	}
	if _, err := addBackupShare(newHost, root, root, "self"); err == nil {
		t.Fatal("a host's own folder was shared with it")
	}
	l := listViaAs(t, newHost, root)
	if len(l) != 1 || l[0].Folder != "shared/"+s.Slug {
		t.Fatalf("listed %+v", l)
	}
	if l := listViaAs(t, other, t.TempDir()); len(l) != 0 {
		t.Fatalf("a pairing it was not shared with lists %+v", l)
	}
	if l := listViaAs(t, "", root); len(l) != 0 {
		t.Fatalf("an anonymous caller with the same folder lists %+v", l)
	}
	if err := dropBackupShare(newHost, s.Slug); err != nil {
		t.Fatal(err)
	}
	if l := listViaAs(t, newHost, root); len(l) != 0 {
		t.Fatalf("a folder taken back is still listed: %+v", l)
	}
}
