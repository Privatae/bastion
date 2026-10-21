package main

// Gate: each host's backup folder is its own. Two pairings whose folders are
// the same, or one inside the other, are refused on every backup op, and so
// is a folder over the bastion's own configuration, keys or records.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func savePairingWithRoot(t *testing.T, host, root string) {
	t.Helper()
	c := &Config{HostName: host, WGPrivateKey: "k", BastionTunnelIP: "fd00:9::a:1", BackupRoot: root}
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
}

func TestBackupRootsAreEachHostsOwn(t *testing.T) {
	uiTestConfigDir(t)
	const a, b = "a.host.privatae.ai", "b.host.privatae.ai"
	base := t.TempDir()
	rootA := filepath.Join(base, "a")
	_ = os.MkdirAll(rootA, 0o700)
	savePairingWithRoot(t, a, rootA)

	savePairingWithRoot(t, b, filepath.Join(base, "b"))
	if why := backupRootProblem(a, rootA); why != "" {
		t.Fatalf("separate folders were refused: %s", why)
	}
	cases := map[string]string{
		"the same folder":        rootA,
		"a folder inside it":     filepath.Join(rootA, "sub"),
		"a folder containing it": base,
	}
	link := filepath.Join(t.TempDir(), "link-to-a")
	if err := os.Symlink(rootA, link); err == nil {
		cases["the same folder through a link"] = link
	}
	for name, other := range cases {
		savePairingWithRoot(t, b, other)
		why := backupRootProblem(a, rootA)
		if why == "" || !strings.Contains(why, b) {
			t.Errorf("%s: not refused (%q)", name, why)
		}
	}
	// On the lane: every backup op is refused before its handler runs.
	savePairingWithRoot(t, b, rootA)
	_, errOut, code := driveBackupOpAs(t, a, "backup_list", "", rootA, map[string]string{"op": "list"})
	if code == 0 || !strings.Contains(errOut, "backup_root of its own") {
		t.Fatalf("a shared backup folder was listed: %d %s", code, errOut)
	}
	// And the person cannot share a folder with a host whose own folder is
	// not its own.
	if err := cmdBackupShare(a, "", t.TempDir()); err == nil || !strings.Contains(err.Error(), "backup_root of its own") {
		t.Fatal("a share was given to a host whose backup folder another host also uses")
	}
}

func TestBackupRootNeverOverlapsTheBastionsOwnState(t *testing.T) {
	cfg := uiTestConfigDir(t)
	confDir, _ := configDirPath()
	keys, _ := backupKeysDir()
	state, _ := backupStateDir()
	bad := map[string]string{
		"the home folder":           cfg,
		"the configuration folder":  confDir,
		"the backup keys":           keys,
		"inside the backup keys":    filepath.Join(keys, "x"),
		"the backup records":        state,
		"inside the backup records": filepath.Join(state, "x"),
		"the pairings":              filepath.Join(confDir, "pairings"),
		"inside the DCN state":      filepath.Join(confDir, "dcn", "h.host.privatae.ai"),
		"another config subfolder":  filepath.Join(confDir, "context"),
		"the backups folder itself": filepath.Join(confDir, "backups"),
	}
	for name, root := range bad {
		if why := backupRootProblem("h.host.privatae.ai", root); why == "" {
			t.Errorf("%s (%s) was accepted as a backup folder", name, root)
		}
	}
	def := (&Config{HostName: "h.host.privatae.ai"}).backupRootPath()
	for _, ok := range []string{def, filepath.Join(confDir, "backups", "any", "depth"), t.TempDir()} {
		if why := backupRootProblem("h.host.privatae.ai", ok); why != "" {
			t.Fatalf("%s was refused: %s", ok, why)
		}
	}
	if _, err := addBackupShare("h.host.privatae.ai", def, confDir, "conf"); err == nil {
		t.Fatal("the configuration folder was shared with a host")
	}
}

// Folders shared with a pairing go when it is unpaired.
func TestUnpairTakesBackTheSharesOfThatPairing(t *testing.T) {
	uiTestConfigDir(t)
	const h, other = "gone.host.privatae.ai", "stays.host.privatae.ai"
	savePairingWithRoot(t, h, t.TempDir())
	if _, err := addBackupShare(h, t.TempDir(), t.TempDir(), "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := addBackupShare(other, t.TempDir(), t.TempDir(), "y"); err != nil {
		t.Fatal(err)
	}
	prev := unpairNeedsRoot
	unpairNeedsRoot = func() bool { return false }
	t.Cleanup(func() { unpairNeedsRoot = prev })
	if _, err := unpairHost(h); err != nil {
		t.Fatal(err)
	}
	if len(sharesFor(h)) != 0 {
		t.Fatal("an unpaired host kept the folders shared with it")
	}
	if len(sharesFor(other)) != 1 {
		t.Fatal("another host's share went with it")
	}
}

// A backup folder the person put outside the configuration folder (a NAS
// mount) is off limits to ops like the rest of this box's record: no op may
// name it, anything in it, or a folder holding it, as an effect.
func TestOpsCannotTouchAHostsBackupFolder(t *testing.T) {
	uiTestConfigDir(t)
	nas := filepath.Join(t.TempDir(), "nas", "backups")
	_ = os.MkdirAll(nas, 0o700)
	savePairingWithRoot(t, "nas.host.privatae.ai", nas)
	offs, err := opOffLimits()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range offs {
		found = found || o == nas
	}
	if !found {
		t.Fatalf("the backup folder %s is not off limits: %v", nas, offs)
	}
	for _, p := range []string{nas, filepath.Join(nas, fixtureData), filepath.Dir(nas)} {
		off, err := underOffLimits(p)
		if err != nil || off == "" {
			t.Errorf("%s is not refused as an op path: %q %v", p, off, err)
		}
		if err := effectOK(p + "/"); err == nil {
			t.Errorf("%s is accepted as an op effect", p)
		}
	}
	// An action op's root verb cannot be pointed at it either.
	if err := opVerbArgOK(&opManifest{}, "verb", "path", filepath.Join(nas, fixtureData)); err == nil ||
		!strings.Contains(err.Error(), "own record") {
		t.Errorf("an action op's path argument reached the backup folder: %v", err)
	}
	if off, _ := underOffLimits(filepath.Join(t.TempDir(), "elsewhere")); off != "" {
		t.Fatalf("an unrelated folder is refused: %s", off)
	}
}

// The bastion's own folders are compared as they resolve: a backup folder
// that is a link to the configuration folder, or a configuration folder
// reached through a link, is refused all the same.
func TestBackupRootOverlapIsJudgedAsItResolves(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "cfg-link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("no symlinks here")
	}
	t.Setenv("XDG_CONFIG_HOME", link)
	t.Setenv("HOME", link)
	t.Setenv("AppData", link)
	conf, _ := configDirPath()
	_ = os.MkdirAll(conf, 0o700)
	realConf := filepath.Join(real, "privatae-bastion")
	for name, root := range map[string]string{
		"the configuration folder by its real path": realConf,
		"inside it by its real path":                filepath.Join(realConf, "pairings"),
	} {
		if why := backupRootProblem("h.host.privatae.ai", root); why == "" {
			t.Errorf("%s (%s) was accepted", name, root)
		}
	}
	if why := backupRootProblem("h.host.privatae.ai", filepath.Join(realConf, "backups", "h")); why != "" {
		t.Fatalf("the default folder by its real path was refused: %s", why)
	}
}

// The daemon never touches the backup folder when it starts: the lane gets
// the folder's path, and each backup op checks and creates it (with a
// bound). Read from the source, because starting the real daemon here would
// need a pairing and a tunnel.
func TestDaemonStartDoesNotTouchTheBackupFolder(t *testing.T) {
	src, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "backupRoot()") || !strings.Contains(string(src), "cfg.backupRootPath(), mgmtWorkerCount") {
		t.Fatal("run.go creates or resolves the backup folder at start instead of passing its path to the lane")
	}
}

// pushStatusVia runs backup_push status, a backup op that writes (so it is
// the one that creates the folder), and returns its exit and stderr.
func pushStatusVia(t *testing.T, root string) (int, string) {
	t.Helper()
	_, errOut, code := driveBackupOp(t, "backup_push", "", root, backupPushReq{Op: "status", JobID: "bp-none"})
	return code, errOut
}

// The folder is made by the first backup op that writes, not by a listing:
// backup_list is a read and creates nothing.
func TestTheBackupFolderIsCreatedOnFirstBackupOp(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-yet")
	l := listVia(t, root)
	if len(l) != 0 {
		t.Fatalf("listed %+v", l)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("backup_list, a read, created the backup folder: %v", err)
	}
	if code, errOut := pushStatusVia(t, root); code != 0 {
		t.Fatalf("backup_push status: %d %s", code, errOut)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		t.Fatal("the first backup op that writes did not create the backup folder")
	}
}

// A backup folder that errors when created refuses that op with the reason,
// and the next op tries again: no restart needed.
func TestABackupFolderThatCannotBeCreatedIsRetriedPerOp(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nas")
	prev := backupMkdirFn
	backupMkdirFn = func(string, os.FileMode) error { return errors.New("read-only file system") }
	code, errOut := pushStatusVia(t, root)
	backupMkdirFn = prev
	if code == 0 || !strings.Contains(errOut, "cannot be created") || !strings.Contains(errOut, "read-only") {
		t.Fatalf("a folder that cannot be created: %d %s", code, errOut)
	}
	if l := listVia(t, root); len(l) != 0 {
		t.Fatalf("listed %+v", l)
	}
}

// A backup folder that does not answer refuses that host's backup ops
// quickly, with a sentence, and the rest of its lane goes on.
func TestABackupFolderThatDoesNotAnswerRefusesOnlyItsBackupOps(t *testing.T) {
	opMaskFixture(t)
	root := filepath.Join(t.TempDir(), "nas")
	_ = os.MkdirAll(root, 0o700)
	hangFolder(t, root)
	for i := 0; i < 2; i++ {
		start := time.Now()
		_, errOut, code := driveBackupOp(t, "backup_list", "", root, map[string]string{"op": "list"})
		if code == 0 || !strings.Contains(errOut, "does not answer") {
			t.Fatalf("a folder that does not answer: %d %s", code, errOut)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("the op waited %s", el)
		}
	}
	// The same lane still answers an op that needs no backup folder.
	out, _, code := driveBackupOp(t, "backup_reseal", t.TempDir(), root, resealReq{Op: "status", JobID: "br-none"})
	if code != 0 || !strings.Contains(out, "unknown") {
		t.Fatalf("the rest of the lane stopped: %d %s", code, out)
	}
	// A creation that hangs is bounded the same way.
	fresh := filepath.Join(t.TempDir(), "fresh")
	gate := make(chan struct{})
	prev := backupMkdirFn
	backupMkdirFn = func(p string, m os.FileMode) error {
		if p == fresh {
			<-gate
		}
		return prev(p, m)
	}
	t.Cleanup(func() {
		close(gate)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			opProbeMu.Lock()
			busy := opProbeInFlight["mkdir:"+fresh]
			opProbeMu.Unlock()
			if !busy {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		backupMkdirFn = prev
	})
	start := time.Now()
	code, errOut := pushStatusVia(t, fresh)
	if code == 0 || !strings.Contains(errOut, "does not answer") || time.Since(start) > 2*time.Second {
		t.Fatalf("a creation that hangs: %d %s after %s", code, errOut, time.Since(start))
	}
}
