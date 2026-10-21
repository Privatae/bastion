package main

// Multi-homing walls (0.10.0). The single-config daemon meant pairing to a new host
// silently unpaired the previous one — re-pairing a desktop to a second host killed
// the first host's embed lane. These pin the pairings/ layout, the legacy migration, the
// duplicate-pair refusal, port assignment, and per-host DCN state isolation.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// isolateConfigDir points os.UserConfigDir at a temp dir (unix: $XDG_CONFIG_HOME)
// so config tests never touch the real config dir.
func isolateConfigDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("test drives os.UserConfigDir via XDG_CONFIG_HOME (unix only)")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "privatae-bastion")
}

// TestLegacyConfigMigration: a pre-0.10.0 config.json must move to
// pairings/<host_name>.json with its IMPLICIT defaults made EXPLICIT — the legacy
// shared <configDir>/context (existing blobs) and <configDir>/dcn (the TOFU-pinned
// verify key + grants + audit) — so existing state survives the layout change.
func TestLegacyConfigMigration(t *testing.T) {
	cd := isolateConfigDir(t)
	if err := os.MkdirAll(cd, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := map[string]string{
		"host_name":   "tenant-3.host.privatae.ai",
		"bearer":      "mcp_x",
		"listen_addr": "127.0.0.1:7878",
	}
	raw, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(cd, "config.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cfgs, err := loadPairings()
	if err != nil {
		t.Fatalf("loadPairings: %v", err)
	}
	if len(cfgs) != 1 || cfgs[0].HostName != "tenant-3.host.privatae.ai" {
		t.Fatalf("migrated pairings = %+v, want the one legacy host", cfgs)
	}
	if got, want := cfgs[0].ContextRoot, filepath.Join(cd, "context"); got != want {
		t.Errorf("ContextRoot = %q, want the explicit legacy default %q", got, want)
	}
	if got, want := cfgs[0].DCNDir, filepath.Join(cd, "dcn"); got != want {
		t.Errorf("DCNDir = %q, want the explicit legacy default %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(cd, "pairings", "tenant-3.host.privatae.ai.json")); err != nil {
		t.Errorf("pairings/<host>.json missing after migration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cd, "config.json")); !os.IsNotExist(err) {
		t.Errorf("legacy config.json must be retired after migration (err=%v)", err)
	}

	// Idempotent: loading again changes nothing and invents nothing.
	again, err := loadPairings()
	if err != nil || len(again) != 1 || again[0].DCNDir != cfgs[0].DCNDir {
		t.Fatalf("second load = (%v, %v), want the same single pairing", again, err)
	}
}

// TestCheckPairConflict: pairing an already-paired host must be REFUSED (never the
// silent overwrite that unpaired a real host), and --replace must target only an
// existing pairing — both checked pre-redeem so a refusal can't burn the token.
func TestCheckPairConflict(t *testing.T) {
	cfgs := []*Config{
		{HostName: "tenant-3.host.privatae.ai"},
		{HostName: "tenant-122.host.privatae.ai"},
	}

	if _, err := checkPairConflict(cfgs, "tenant-122", false); err == nil {
		t.Fatal("pairing an already-paired host must be refused without --replace")
	}
	got, err := checkPairConflict(cfgs, "tenant-122", true)
	if err != nil || got == nil || got.HostName != "tenant-122.host.privatae.ai" {
		t.Fatalf("--replace on a paired host = (%v, %v), want its existing pairing", got, err)
	}
	if got, err := checkPairConflict(cfgs, "tenant-9", false); err != nil || got != nil {
		t.Fatalf("a NEW host must pair cleanly, got (%v, %v)", got, err)
	}
	if _, err := checkPairConflict(cfgs, "tenant-9", true); err == nil {
		t.Fatal("--replace on an unpaired host must be refused (nothing to replace)")
	}
	// "tenant-1" is a prefix of tenant-122's host name but a different handle —
	// it must NOT collide.
	if got, err := checkPairConflict(cfgs, "tenant-1", false); err != nil || got != nil {
		t.Fatalf("handle 'tenant-1' must not match tenant-122, got (%v, %v)", got, err)
	}
}

// TestNextListenAddr: each pairing gets the first free loopback port from 7878 up,
// so hosts never share a local control address.
func TestNextListenAddr(t *testing.T) {
	if got := nextListenAddr(nil); got != "127.0.0.1:7878" {
		t.Errorf("first pairing = %q, want 127.0.0.1:7878", got)
	}
	cfgs := []*Config{{ListenAddr: "127.0.0.1:7878"}}
	if got := nextListenAddr(cfgs); got != "127.0.0.1:7879" {
		t.Errorf("second pairing = %q, want 127.0.0.1:7879", got)
	}
	cfgs = append(cfgs, &Config{ListenAddr: "127.0.0.1:7880"})
	if got := nextListenAddr(cfgs); got != "127.0.0.1:7879" {
		t.Errorf("gap fill = %q, want 127.0.0.1:7879", got)
	}
	cfgs = append(cfgs, &Config{ListenAddr: "127.0.0.1:7879"})
	if got := nextListenAddr(cfgs); got != "127.0.0.1:7881" {
		t.Errorf("all taken = %q, want 127.0.0.1:7881", got)
	}
}

// TestFindPairingHostFlag: --host resolution — exact host, exact handle, unique
// prefix; ambiguity is an error, not a guess.
func TestFindPairingHostFlag(t *testing.T) {
	cfgs := []*Config{
		{HostName: "tenant-3.host.privatae.ai"},
		{HostName: "tenant-122.host.privatae.ai"},
	}
	for _, key := range []string{"tenant-3.host.privatae.ai", "tenant-3", "tenant-3."} {
		c, err := findPairing(cfgs, key)
		if err != nil || c == nil || c.HostName != "tenant-3.host.privatae.ai" {
			t.Errorf("findPairing(%q) = (%v, %v), want tenant-3", key, c, err)
		}
	}
	if c, err := findPairing(cfgs, "nope"); err != nil || c != nil {
		t.Errorf("no match must be (nil, nil), got (%v, %v)", c, err)
	}
	if _, err := findPairing(cfgs, "tenant-"); err == nil {
		t.Error("an ambiguous prefix must be an error, never a guess")
	}
}

// TestPerHostDcnDirs: the DCN state (TOFU pin + grants + audit) must be per host —
// a pin synced for one host may never verify (or even be visible to) another's ops.
func TestPerHostDcnDirs(t *testing.T) {
	cd := isolateConfigDir(t)
	a := &Config{HostName: "tenant-3.host.privatae.ai"}
	b := &Config{HostName: "tenant-122.host.privatae.ai"}
	dirA, dirB := a.dcnDir(), b.dcnDir()
	if dirA == "" || dirB == "" || dirA == dirB {
		t.Fatalf("per-host dcn dirs must differ: %q vs %q", dirA, dirB)
	}
	for _, dir := range []string{dirA, dirB} {
		if got := filepath.Dir(dir); got != filepath.Join(cd, "dcn") {
			t.Errorf("dcn dir %q not under <configDir>/dcn/<host>", dir)
		}
	}

	// A pin saved for host A must not leak into host B's (empty, default-deny) file.
	if err := dcnSaveFile(dirA, &dcnGrantFile{VerifyPubkey: "pin-A",
		Stores: map[string]dcnGrantRec{}}); err != nil {
		t.Fatal(err)
	}
	fa, err := dcnLoadFile(dirA)
	if err != nil || fa.VerifyPubkey != "pin-A" {
		t.Fatalf("host A pin = (%v, %v), want pin-A", fa, err)
	}
	fb, err := dcnLoadFile(dirB)
	if err != nil || fb.VerifyPubkey != "" {
		t.Fatalf("host B must see NO pin (default-deny), got (%v, %v)", fb, err)
	}
}

// A --replace that renames the pairing must leave exactly ONE pairing file.
// A Host address move makes a host's own name change under it, and
// saveLocked writes pairings/<host_name>.json — so without the cleanup the box
// keeps both, cmdRun starts both, and they collide on the ListenAddr the
// replacement deliberately inherits. That is a daemon that refuses to start on
// a machine which was just successfully re-paired.
func TestRemoveStalePairingFileLeavesExactlyOnePairing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	old := &Config{HostName: "acme-old.host.privatae.ai", ListenAddr: "127.0.0.1:7878"}
	if err := old.save(); err != nil {
		t.Fatalf("save old: %v", err)
	}
	fresh := &Config{HostName: "acme.host.privatae.ai", ListenAddr: "127.0.0.1:7878"}
	if err := fresh.save(); err != nil {
		t.Fatalf("save new: %v", err)
	}
	if got, err := loadPairings(); err != nil || len(got) != 2 {
		t.Fatalf("precondition: want 2 pairings, got %d (%v)", len(got), err)
	}

	if err := removeStalePairingFile(old.HostName); err != nil {
		t.Fatalf("removeStalePairingFile: %v", err)
	}
	got, err := loadPairings()
	if err != nil {
		t.Fatalf("loadPairings: %v", err)
	}
	if len(got) != 1 || got[0].HostName != fresh.HostName {
		t.Fatalf("want only %s, got %v", fresh.HostName, hostNames(got))
	}
	// Idempotent: a second call (a retry, or a crash between save and remove)
	// must not turn a clean box into an error.
	if err := removeStalePairingFile(old.HostName); err != nil {
		t.Fatalf("second remove should be a no-op, got %v", err)
	}
}
