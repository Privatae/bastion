package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// carryTree is a per-user bastion's state folder as an install finds it.
func carryTree(t *testing.T) (from, to string) {
	t.Helper()
	root := t.TempDir()
	from = filepath.Join(root, "account", "privatae-bastion")
	to = filepath.Join(root, "service", "privatae-bastion")
	files := map[string]string{
		"pairings/box-one.example.test.json": `{"host_name":"box-one.example.test","bearer":"mcp_test",` +
			`"context_root":"` + filepath.Join(from, "context", "box-one.example.test") + `",` +
			`"dcn_dir":"` + filepath.Join(from, "dcn", "box-one.example.test") + `",` +
			`"backup_root":"/mnt/nas/backups"}`,
		"dcn/box-one.example.test/grants.json": `{"folders":["/home/someone/notes"]}`,
		"context/box-one.example.test/blob":    "context bytes",
		"ui.secret":                            "account secret",
		"run.lock":                             "",
		"run.holder.json":                      `{"pid":1}`,
		"ui.addr":                              "127.0.0.1:7880",
		"bastion.log":                          "a log line",
	}
	for rel, body := range files {
		p := filepath.Join(from, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return from, to
}

// An install that moves the bastion from an account to the service brings
// its pairings with it: the service serves the same Hosts with the same keys,
// the paths that named the account's folder name the service's, nothing that
// belongs to a running bastion comes along, and the account's copy is gone.
//
// MUTATION: return before copyStateTree in carryStateInto. RESULT: red (the
// service has no pairing). Drop the rebaseJSONPaths call. RESULT: red (the
// pairing's context folder is still the account's).
func TestAServiceInstallCarriesTheAccountsPairingsIntoTheService(t *testing.T) {
	from, to := carryTree(t)
	res, err := carryStateInto(from, to)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Hosts, ",") != "box-one.example.test" {
		t.Fatalf("carried %v", res.Hosts)
	}
	raw, err := os.ReadFile(filepath.Join(to, "pairings", "box-one.example.test.json"))
	if err != nil {
		t.Fatalf("the service has no pairing: %v", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Bearer != "mcp_test" || c.HostName != "box-one.example.test" {
		t.Errorf("the pairing changed on the way: %+v", c)
	}
	if c.ContextRoot != filepath.Join(to, "context", "box-one.example.test") || c.DCNDir != filepath.Join(to, "dcn", "box-one.example.test") {
		t.Errorf("the pairing's folders still name the account's state: context %q, dcn %q", c.ContextRoot, c.DCNDir)
	}
	if c.BackupRoot != "/mnt/nas/backups" {
		t.Errorf("a path outside the state folder was rewritten: %q", c.BackupRoot)
	}
	if b, _ := os.ReadFile(filepath.Join(to, "dcn", "box-one.example.test", "grants.json")); !strings.Contains(string(b), "/home/someone/notes") {
		t.Errorf("the grants did not come along unchanged: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(to, "context", "box-one.example.test", "blob")); string(b) != "context bytes" {
		t.Errorf("the context store did not come along: %q", b)
	}
	for _, n := range []string{"run.lock", "run.holder.json", "ui.addr", "bastion.log"} {
		if _, err := os.Stat(filepath.Join(to, n)); err == nil {
			t.Errorf("%s belongs to the running bastion it was carried from, not to its state", n)
		}
	}
	if _, err := os.Stat(from); !os.IsNotExist(err) {
		t.Errorf("the account's copy, keys included, is still there: %v", err)
	}
	if line := carryReport(res, from); !strings.Contains(line, "box-one.example.test") || !strings.Contains(line, "nothing needs pairing again") {
		t.Errorf("the install does not say what it carried: %q", line)
	}
}

// A service that already serves a Host is never merged into, and the
// account's state stays where it was.
func TestACarryNeverMergesIntoAServiceThatServesAHost(t *testing.T) {
	from, to := carryTree(t)
	p := filepath.Join(to, "pairings", "box-two.example.test.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"host_name":"box-two.example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := carryStateInto(from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 0 || !strings.Contains(res.Note, "box-two.example.test") {
		t.Fatalf("carried into a serving service: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(from, "pairings", "box-one.example.test.json")); err != nil {
		t.Errorf("the account's pairing was touched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(to, "pairings", "box-one.example.test.json")); err == nil {
		t.Error("the account's pairing was merged in")
	}
}

// Not while a bastion still runs from the folder: its next write would be
// lost, and two bastions would hold the same keys.
func TestACarryWaitsForTheAccountsBastionToStop(t *testing.T) {
	prev := carryLockPatience
	t.Cleanup(func() { carryLockPatience = prev })
	carryLockPatience = 300 * time.Millisecond
	from, to := carryTree(t)
	f, err := os.OpenFile(filepath.Join(from, "run.lock"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := flockFileNB(f); err != nil {
		t.Fatal(err)
	}
	if _, err := carryStateInto(from, to); err == nil || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("carried while the account's bastion ran: %v", err)
	}
	if _, err := os.Stat(filepath.Join(to, "pairings")); err == nil {
		t.Error("the service got a pairing from a running bastion")
	}
	if _, err := os.Stat(filepath.Join(from, "pairings", "box-one.example.test.json")); err != nil {
		t.Errorf("the account's state was touched: %v", err)
	}
}

// A file the service already has is the service's: kept, and counted.
func TestACarryKeepsWhatTheServiceAlreadyHas(t *testing.T) {
	from, to := carryTree(t)
	if err := os.MkdirAll(to, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, "ui.secret"), []byte("service secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := carryStateInto(from, to)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(to, "ui.secret")); string(b) != "service secret" {
		t.Errorf("the service's own file was replaced: %q", b)
	}
	if res.Kept != 1 {
		t.Errorf("kept %d files, want 1", res.Kept)
	}
}

// The carry removes the folder it carried from, so it refuses anything but a
// bastion's own state folder, and does nothing for a folder with no pairing.
func TestACarryTouchesOnlyABastionsStateFolder(t *testing.T) {
	root := t.TempDir()
	other := filepath.Join(root, "Documents")
	if err := os.MkdirAll(filepath.Join(other, "pairings"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "pairings", "x.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := carryStateInto(other, filepath.Join(root, "service", "privatae-bastion")); err == nil {
		t.Fatal("a folder that is not a bastion's was carried, and would have been removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("the folder was touched: %v", err)
	}
	empty := filepath.Join(root, "account", "privatae-bastion")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if res, err := carryStateInto(empty, filepath.Join(root, "service", "privatae-bastion")); err != nil || len(res.Hosts) != 0 {
		t.Fatalf("a folder with no pairing: %+v, %v", res, err)
	}
	if _, err := os.Stat(empty); err != nil {
		t.Errorf("a folder with nothing to carry was removed: %v", err)
	}
}

func TestRebasePathMovesOnlyPathsUnderTheFolder(t *testing.T) {
	from, to := "/a/privatae-bastion", "/b/privatae-bastion"
	for in, want := range map[string]string{
		"/a/privatae-bastion":          "/b/privatae-bastion",
		"/a/privatae-bastion/dcn/x":    "/b/privatae-bastion/dcn/x",
		"/a/privatae-bastion-old/dcn":  "/a/privatae-bastion-old/dcn",
		"/a/other":                     "/a/other",
		"mcp_/a/privatae-bastion/fake": "mcp_/a/privatae-bastion/fake",
	} {
		if got, _ := rebasePath(in, from, to); got != want {
			t.Errorf("rebasePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A grant file beside a pairing (pairings/<host>.grant.json, anchor.go) is
// not a pairing: it names no Host the service serves, and a service holding
// only one is not one that serves a Host.
func TestACarryCountsOnlyPairingsAsHosts(t *testing.T) {
	from, _ := carryTree(t)
	if err := os.WriteFile(filepath.Join(from, "pairings", "box-one.example.test"+pairingGrantSuffix), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := pairingHosts(from)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(hosts, ",") != "box-one.example.test" {
		t.Fatalf("hosts %v, want only box-one.example.test", hosts)
	}
}

// A bastion killed a moment ago (the installer's Stop-Process) can hold its
// run lock for a moment after it is gone; the carry waits for it rather than
// failing the install.
func TestACarryWaitsAMomentForAJustStoppedBastionsLock(t *testing.T) {
	from, to := carryTree(t)
	f, err := os.OpenFile(filepath.Join(from, "run.lock"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := flockFileNB(f); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = f.Close()
	}()
	res, err := carryStateInto(from, to)
	if err != nil {
		t.Fatalf("a lock released 300 ms in failed the carry: %v", err)
	}
	if strings.Join(res.Hosts, ",") != "box-one.example.test" {
		t.Fatalf("carried %v", res.Hosts)
	}
}

// The account's version of a file the service already has is not lost when
// the account's folder is removed: it is kept beside the service's.
func TestACarryKeepsTheAccountsVersionOfAFileTheServiceHas(t *testing.T) {
	from, to := carryTree(t)
	if err := os.MkdirAll(to, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, "ui.secret"), []byte("service secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := carryStateInto(from, to)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(to, "ui.secret")); string(b) != "service secret" {
		t.Errorf("the service's own file was replaced: %q", b)
	}
	if b, err := os.ReadFile(filepath.Join(to, "ui.secret"+carryAsideSuffix)); err != nil || string(b) != "account secret" {
		t.Errorf("the account's version is gone with its folder: %q, %v", b, err)
	}
	if line := carryReport(res, from); !strings.Contains(line, carryAsideSuffix) {
		t.Errorf("the install does not say where the account's version went: %q", line)
	}
}

// A state folder that is a link to elsewhere is walked as nothing at all; the
// carry must not report the pairings moved, nor remove anything, when the
// service did not get them.
func TestACarryRemovesNothingUnlessTheServiceHasEveryPairing(t *testing.T) {
	from, to := carryTree(t)
	link := filepath.Join(filepath.Dir(filepath.Dir(from)), "linked", "privatae-bastion")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(from, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if _, err := carryStateInto(link, to); err == nil {
		t.Fatal("the carry reported success with no pairing in the service")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("the account's state folder was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(from, "pairings", "box-one.example.test.json")); err != nil {
		t.Errorf("the account's pairing was touched: %v", err)
	}
}

// A copy that fails part way takes back what it wrote: a service left with
// some of the pairings would never be carried into again (it serves a Host),
// and would serve those few.
func TestACarryThatFailsPartWayLeavesTheServiceAsItWas(t *testing.T) {
	from, to := carryTree(t)
	second := filepath.Join(from, "pairings", "box-two.example.test.json")
	if err := os.WriteFile(second, []byte(`{"host_name":"box-two.example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := carryWriteFile
	t.Cleanup(func() { carryWriteFile = prev })
	carryWriteFile = func(p string, b []byte, m os.FileMode) error {
		if filepath.Base(p) == "box-two.example.test.json" {
			return errors.New("disk full")
		}
		return prev(p, b, m)
	}
	if _, err := carryStateInto(from, to); err == nil {
		t.Fatal("a failed copy reported success")
	}
	if hosts, _ := pairingHosts(to); len(hosts) != 0 {
		t.Errorf("the service was left serving %v of the account's pairings", hosts)
	}
	if b, err := os.ReadFile(filepath.Join(to, "ui.secret")); err == nil {
		t.Errorf("a file the failed copy wrote was left in the service: %q", b)
	}
	if _, err := os.Stat(second); err != nil {
		t.Errorf("the account's state was touched: %v", err)
	}
}

// Once the service holds every pairing, a source folder that cannot be
// removed is said, not a failure: failing would leave the service stopped,
// and the machine as silent as the empty start this carry replaces.
func TestACarryWhoseSourceCannotBeRemovedStillSucceeds(t *testing.T) {
	from, to := carryTree(t)
	prev := carryRemoveAll
	t.Cleanup(func() { carryRemoveAll = prev })
	carryRemoveAll = func(string) error { return errors.New("in use by another process") }
	res, err := carryStateInto(from, to)
	if err != nil {
		t.Fatalf("a carry that moved every pairing failed the install: %v", err)
	}
	if hosts, _ := pairingHosts(to); strings.Join(hosts, ",") != "box-one.example.test" {
		t.Errorf("the service holds %v", hosts)
	}
	if line := carryReport(res, from); !strings.Contains(line, "delete that folder") {
		t.Errorf("the install does not say the account's copy is still there: %q", line)
	}
}
