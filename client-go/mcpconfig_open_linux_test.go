//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A config path that is, or links to, something other than a regular file
// is never OPENED for reading. Opening is not harmless: a device's driver
// runs on open (a watchdog arms, a serial line toggles DTR), so a symlink at
// ~/.cursor/mcp.json pointing at one would let any account make this root
// service act on hardware. inotify reports every real open of the target;
// the reader's look at what the path is must not be one.
func TestMCPReadFileNeverOpensANonRegularTarget(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "target")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot make a FIFO here: %v", err)
	}
	link := filepath.Join(dir, "mcp.json")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	ino, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Skipf("no inotify: %v", err)
	}
	defer unix.Close(ino)
	if _, err := unix.InotifyAddWatch(ino, fifo, unix.IN_OPEN); err != nil {
		t.Skipf("cannot watch: %v", err)
	}
	var scan mcpConfigScan
	for _, p := range []string{link, fifo} {
		if b, ok := mcpReadFile(p, &scan); ok || b != nil {
			t.Fatalf("%s read as a config file", p)
		}
	}
	buf := make([]byte, 4096)
	if n, _ := unix.Read(ino, buf); n > 0 {
		t.Fatalf("the FIFO was opened %d time(s) by the reader", n/unix.SizeofInotifyEvent)
	}
	if scan.Unreadable != 2 {
		t.Fatalf("scan: %+v", scan)
	}
	// A regular file through a symlink is still read, as the client would.
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link2 := filepath.Join(dir, "link2.json")
	if err := os.Symlink(real, link2); err != nil {
		t.Fatal(err)
	}
	if _, ok := mcpReadFile(link2, &scan); !ok {
		t.Fatal("a symlink to a regular file was not read")
	}
}

// A file in one account's home, or in a project that account listed, is read
// only when that account or root owns it. Otherwise one account could point
// its own config path, or its list of projects, at another account's files
// and have this service read them on its behalf.
func TestReadMCPConfigsSkipsAFileAnotherAccountOwns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make files owned by other uids")
	}
	const owner, other = 42101, 42102
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home", "demo")
	victim := filepath.Join(root, "victim")
	write := func(p, body string, uid int) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(victim, "secret.json"), `{"mcpServers": {"victim-file": {"command": "demo-v"}}}`, other)
	write(filepath.Join(victim, ".mcp.json"), `{"mcpServers": {"victim-project": {"command": "demo-w"}}}`, other)
	write(filepath.Join(root, "rootowned.json"), `{"mcpServers": {"root-file": {"command": "demo-r"}}}`, 0)
	projJSON, _ := json.Marshal(victim)
	write(filepath.Join(home, ".claude.json"), `{"mcpServers": {"own": {"command": "demo-o"}}, "projects": {`+string(projJSON)+`: {}}}`, owner)
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(victim, "secret.json"), filepath.Join(home, ".cursor", "mcp.json")); err != nil {
		t.Fatal(err)
	}
	// A dotfile manager's link to a root-owned file is the account's own.
	if err := os.MkdirAll(filepath.Join(home, ".codeium", "windsurf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "rootowned.json"), filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, owner, owner); err != nil {
		t.Fatal(err)
	}

	oldH, oldS, oldOS := mcpHomesFn, mcpSystemFn, mcpGOOS
	t.Cleanup(func() { mcpHomesFn, mcpSystemFn, mcpGOOS = oldH, oldS, oldOS })
	mcpGOOS = "linux"
	mcpHomesFn = func() ([]mcpHome, bool) {
		return []mcpHome{{Dir: home, ConfigDir: filepath.Join(home, ".config")}}, true
	}
	mcpSystemFn = func() []mcpSource { return nil }

	got, scan := readMCPConfigs()
	names := map[string]bool{}
	for _, o := range got {
		names[o.Name] = true
	}
	if names["victim-file"] || names["victim-project"] {
		t.Errorf("read another account's file on this account's behalf: %v", names)
	}
	if !names["own"] || !names["root-file"] {
		t.Errorf("the account's own and root-owned files must still be read: %v", names)
	}
	if scan.ForeignOwner != 2 {
		t.Errorf("scan: %+v", scan)
	}
}
