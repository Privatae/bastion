package main

// Tests for second-bastion detection.
//
// Every test here drives scanOtherBastionsIn against a temp tree. NOTHING calls
// scanOtherBastions(): these tests run as root on Linux, so that would read the
// real /etc/passwd and stat the real home directories of whatever machine the
// suite runs on. The live-state accidents in this repo both came from a test
// reaching for a real path, so the split exists to make that impossible here.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakePasswd writes a passwd file for the given name→home pairs and returns its
// path. uid starts at 1000 and increments, which is close enough to a real file
// for a scan that only reads name, uid and home.
func fakePasswd(t *testing.T, dir string, homes map[string]string) string {
	t.Helper()
	var b strings.Builder
	uid := 1000
	for name, home := range homes {
		fmt.Fprintf(&b, "%s:x:%d:%d::%s:/bin/bash\n", name, uid, uid, home)
		uid++
	}
	p := filepath.Join(dir, "passwd")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// mkStateDir builds <home>/.config/<state dir> with n pairing files.
func mkStateDir(t *testing.T, home string, n int) string {
	t.Helper()
	sd := filepath.Join(home, ".config", "privatae-bastion")
	if err := os.MkdirAll(filepath.Join(sd, "pairings"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		f := filepath.Join(sd, "pairings", fmt.Sprintf("host%d.json", i))
		if err := os.WriteFile(f, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return sd
}

func TestScanSkipsOurOwnStateDir(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "root")
	mine := mkStateDir(t, home, 2)
	pw := fakePasswd(t, root, map[string]string{"root": home})

	got := scanOtherBastionsIn(pw, []string{mine})
	if got == nil {
		t.Fatal("scan returned nil (did not look) when it should have looked")
	}
	if len(got) != 0 {
		t.Fatalf("our own state dir was reported as another bastion: %+v", got)
	}
}

func TestScanFindsAPairedSecondBastion(t *testing.T) {
	root := t.TempDir()
	mineHome := filepath.Join(root, "root")
	mine := mkStateDir(t, mineHome, 1)
	otherHome := filepath.Join(root, "eve")
	mkStateDir(t, otherHome, 3)
	pw := fakePasswd(t, root, map[string]string{"root": mineHome, "eve": otherHome})

	got := scanOtherBastionsIn(pw, []string{mine})
	if len(got) != 1 {
		t.Fatalf("want exactly one finding, got %+v", got)
	}
	if got[0].Kind != obPaired {
		t.Errorf("a state dir with pairings must be %q, got %q", obPaired, got[0].Kind)
	}
	if got[0].User != "eve" {
		t.Errorf("want user eve, got %q", got[0].User)
	}
	if got[0].Pairings != 3 {
		t.Errorf("want 3 pairings counted, got %d", got[0].Pairings)
	}
	if got[0].LastChange == "" {
		t.Error("a finding with no timestamp cannot be told apart from an old one")
	}
}

func TestScanTellsSetUpApartFromPaired(t *testing.T) {
	root := t.TempDir()
	otherHome := filepath.Join(root, "eve")
	mkStateDir(t, otherHome, 0) // initialised, never paired
	pw := fakePasswd(t, root, map[string]string{"eve": otherHome})

	got := scanOtherBastionsIn(pw, []string{filepath.Join(root, "root", ".config", "privatae-bastion")})
	if len(got) != 1 || got[0].Kind != obState {
		t.Fatalf("an unpaired state dir must be %q, got %+v", obState, got)
	}
	if got[0].Pairings != 0 {
		t.Errorf("want 0 pairings, got %d", got[0].Pairings)
	}
}

func TestScanFindsABinaryWithNoStateDir(t *testing.T) {
	for _, name := range bastionBinaryNames {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			otherHome := filepath.Join(root, "eve")
			binDir := filepath.Join(otherHome, ".local", "bin")
			if err := os.MkdirAll(binDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			pw := fakePasswd(t, root, map[string]string{"eve": otherHome})

			got := scanOtherBastionsIn(pw, []string{filepath.Join(root, "root", ".config", "privatae-bastion")})
			if len(got) != 1 || got[0].Kind != obBinary {
				t.Fatalf("want one %q finding, got %+v", obBinary, got)
			}
			if !strings.HasSuffix(got[0].BinaryPath, name) {
				t.Errorf("want the binary path reported, got %q", got[0].BinaryPath)
			}
		})
	}
}

func TestScanPrefersTheStateDirOverTheBinary(t *testing.T) {
	// A user with both must be reported ONCE, as the more serious finding —
	// otherwise one installation reads as two and the count is wrong.
	root := t.TempDir()
	otherHome := filepath.Join(root, "eve")
	mkStateDir(t, otherHome, 1)
	binDir := filepath.Join(otherHome, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "privatae-bastion"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	pw := fakePasswd(t, root, map[string]string{"eve": otherHome})

	got := scanOtherBastionsIn(pw, []string{filepath.Join(root, "root", ".config", "privatae-bastion")})
	if len(got) != 1 {
		t.Fatalf("one installation must produce one finding, got %+v", got)
	}
	if got[0].Kind != obPaired {
		t.Errorf("want %q, got %q", obPaired, got[0].Kind)
	}
}

func TestScanOrdersWorstFirst(t *testing.T) {
	root := t.TempDir()
	homes := map[string]string{}
	// binary-only
	bHome := filepath.Join(root, "bob")
	bin := filepath.Join(bHome, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "privatae-bastion"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	homes["bob"] = bHome
	// unpaired state dir
	aHome := filepath.Join(root, "amy")
	mkStateDir(t, aHome, 0)
	homes["amy"] = aHome
	// paired — the serious one, and alphabetically last, so ordering by name
	// alone would bury it
	zHome := filepath.Join(root, "zoe")
	mkStateDir(t, zHome, 2)
	homes["zoe"] = zHome
	pw := fakePasswd(t, root, homes)

	got := scanOtherBastionsIn(pw, []string{filepath.Join(root, "root", ".config", "privatae-bastion")})
	if len(got) != 3 {
		t.Fatalf("want 3 findings, got %+v", got)
	}
	want := []string{obPaired, obState, obBinary}
	for i, w := range want {
		if got[i].Kind != w {
			t.Errorf("position %d: want %q, got %q (full: %+v)", i, w, got[i].Kind, got)
		}
	}
}

func TestScanReturnsEmptyNotNilOnACleanMachine(t *testing.T) {
	// The nil-vs-empty contract: "I looked and found none" must travel as an
	// empty slice so the host's COALESCE can clear a finding that was dealt
	// with. nil means "I did not look" and makes the caller omit the key.
	root := t.TempDir()
	home := filepath.Join(root, "root")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	pw := fakePasswd(t, root, map[string]string{"root": home})

	got := scanOtherBastionsIn(pw, []string{filepath.Join(home, ".config", "privatae-bastion")})
	if got == nil {
		t.Fatal("a clean machine must report empty, never nil — nil means 'did not look'")
	}
	if len(got) != 0 {
		t.Fatalf("want no findings, got %+v", got)
	}
}

func TestScanReturnsNilWhenUsersCannotBeRead(t *testing.T) {
	got := scanOtherBastionsIn(filepath.Join(t.TempDir(), "no-such-passwd"), []string{"/root/.config/privatae-bastion"})
	if got != nil {
		t.Fatalf("an unreadable passwd means we did not look; want nil, got %+v", got)
	}
}

func TestReadPasswdSkipsJunkAndSharedHomes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "passwd")
	body := strings.Join([]string{
		"# a comment",
		"root:x:0:0::/root:/bin/bash",
		"malformed-line-with-too-few-fields",
		"nouid:x:notanumber:0::/home/nouid:/bin/sh",
		"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin",
		"sys1:x:1:1::/:/usr/sbin/nologin",
		"dup1:x:101:101::/var/run/shared:/usr/sbin/nologin",
		"dup2:x:102:102::/var/run/shared:/usr/sbin/nologin",
		"",
	}, "\n")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	users, err := readPasswdUsers(p)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, u := range users {
		names = append(names, u.Name)
	}
	// root and the FIRST of the shared-home pair; everything else is skipped.
	if len(users) != 2 || names[0] != "root" || names[1] != "dup1" {
		t.Fatalf("want [root dup1], got %v", names)
	}
}

func TestDescribeNamesTheUserAndThePath(t *testing.T) {
	// The journal line is what an operator on the box reads, so it has to carry
	// the same two facts the host is sent: who, and where.
	cases := []otherBastion{
		{Kind: obPaired, User: "eve", StateDir: "/home/eve/.config/privatae-bastion", Pairings: 2},
		{Kind: obState, User: "eve", StateDir: "/home/eve/.config/privatae-bastion"},
		{Kind: obBinary, User: "eve", BinaryPath: "/home/eve/.local/bin/privatae-bastion"},
	}
	for _, c := range cases {
		s := describeOtherBastion(c)
		if !strings.Contains(s, "eve") {
			t.Errorf("%s: description does not name the user: %q", c.Kind, s)
		}
		where := c.StateDir
		if where == "" {
			where = c.BinaryPath
		}
		if !strings.Contains(s, where) {
			t.Errorf("%s: description does not give the path: %q", c.Kind, s)
		}
	}
}

// ── review findings ─────────────────────────────────────────────────────────

func TestASymlinkedStateDirCannotForgeAFinding(t *testing.T) {
	// os.Stat follows links and the ownership exclusion is a string
	// compare, so before the Lstat fix an unprivileged user could run
	//     ln -s /root/.config/<state dir> ~/.config/<state dir>
	// and make the anchor's inbox say "eve is running a second bastion and it
	// is serving 2 Hosts of its own" — a forged red security alert, from one
	// command, indistinguishable from a real one.
	root := t.TempDir()
	mineHome := filepath.Join(root, "root")
	mine := mkStateDir(t, mineHome, 2)

	eveHome := filepath.Join(root, "eve")
	if err := os.MkdirAll(filepath.Join(eveHome, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mine, filepath.Join(eveHome, ".config", "privatae-bastion")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	pw := fakePasswd(t, root, map[string]string{"root": mineHome, "eve": eveHome})

	got := scanOtherBastionsIn(pw, []string{mine})
	if len(got) != 0 {
		t.Fatalf("a symlink to OUR OWN state dir forged a finding: %+v", got)
	}
}

func TestASymlinkedPairingsDirCannotInflateTheCount(t *testing.T) {
	// The same forgery one level down: a real state dir of one's own, with
	// `pairings` linked at root's, would report root's hosts as eve's.
	root := t.TempDir()
	mineHome := filepath.Join(root, "root")
	mine := mkStateDir(t, mineHome, 3)

	eveHome := filepath.Join(root, "eve")
	eveState := filepath.Join(eveHome, ".config", "privatae-bastion")
	if err := os.MkdirAll(eveState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(mine, "pairings"), filepath.Join(eveState, "pairings")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	pw := fakePasswd(t, root, map[string]string{"root": mineHome, "eve": eveHome})

	got := scanOtherBastionsIn(pw, []string{mine})
	if len(got) != 1 {
		t.Fatalf("want eve's own (empty) state dir reported once, got %+v", got)
	}
	if got[0].Pairings != 0 || got[0].Kind != obState {
		t.Fatalf("a linked pairings dir inflated the count to %d (%s) — that reads as "+
			"'serving Hosts you never approved'", got[0].Pairings, got[0].Kind)
	}
}

func TestASymlinkedBinaryIsNotAFinding(t *testing.T) {
	root := t.TempDir()
	eveHome := filepath.Join(root, "eve")
	binDir := filepath.Join(eveHome, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "some-other-program")
	if err := os.WriteFile(real, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(binDir, "privatae-bastion")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	pw := fakePasswd(t, root, map[string]string{"eve": eveHome})

	got := scanOtherBastionsIn(pw, []string{filepath.Join(root, "root", ".config", "privatae-bastion")})
	if len(got) != 0 {
		t.Fatalf("a link named privatae-bastion proves nothing about what it points at: %+v", got)
	}
}

func TestTheScanNeverReportsTheReadersOwnBastion(t *testing.T) {
	// The marker is not repointed once written, so a daemon whose own
	// config dir stops matching it (XDG_CONFIG_HOME, a renamed dir) would
	// otherwise report ITSELF as "a second bastion serving Hosts you never
	// approved" — to its own hosts. Both dirs must be excluded, not either.
	root := t.TempDir()
	rootHome := filepath.Join(root, "root")
	markerDir := mkStateDir(t, rootHome, 2)      // what the marker names
	otherOwn := filepath.Join(root, "elsewhere") // where this process runs from
	if err := os.MkdirAll(filepath.Join(otherOwn, "pairings"), 0o700); err != nil {
		t.Fatal(err)
	}
	pw := fakePasswd(t, root, map[string]string{"root": rootHome})

	// marker names markerDir; our own configDirPath() is otherOwn
	got := scanOtherBastionsIn(pw, []string{markerDir, otherOwn})
	if len(got) != 0 {
		t.Fatalf("the reader's own bastion was reported as somebody else's: %+v", got)
	}
	// and with ONLY the marker excluded (the old behaviour) the own dir under a
	// scanned home would have come back — pin that the list form is what fixes it
	got2 := scanOtherBastionsIn(pw, []string{otherOwn})
	if len(got2) != 1 {
		t.Fatalf("expected the marker dir to surface when it is not excluded, got %+v", got2)
	}
}

func TestScannedAtIsEmptyUntilAScanCompletes(t *testing.T) {
	// A scan that stops completing keeps publishing its last answer; if
	// that answer is [] the host reads "clean" for ever. The age has to travel
	// with the finding, and it must be absent before there is one.
	otherBastionMu.Lock()
	ran, at := otherBastionRan, otherBastionAt
	otherBastionRan, otherBastionAt = false, time.Time{}
	otherBastionMu.Unlock()
	t.Cleanup(func() {
		otherBastionMu.Lock()
		otherBastionRan, otherBastionAt = ran, at
		otherBastionMu.Unlock()
	})

	if s := otherBastionsScannedAt(); s != "" {
		t.Fatalf("no scan has completed; want empty, got %q", s)
	}
	if p := otherBastionsPayload(); p != nil {
		t.Fatalf("no scan has completed; want nil payload, got %+v", p)
	}

	otherBastionMu.Lock()
	otherBastionRan, otherBastionAt = true, time.Now()
	otherBastionMu.Unlock()
	if s := otherBastionsScannedAt(); s == "" {
		t.Fatal("a completed scan must publish when it ran")
	}
}
