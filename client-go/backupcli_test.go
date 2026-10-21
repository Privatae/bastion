package main

// Gate: restoring a lost host from a backup kept on this machine reseals the
// chosen backup's key to the new host and to nothing else, and refuses a
// backup it cannot find.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestRestorePlanResealsTheChosenBackupForTheNewHost(t *testing.T) {
	fx := newBackupFixture(t, "")
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, fixtureStamp+".key.age"), fx.sidecar(t), 0o600)
	_ = os.WriteFile(filepath.Join(dir, fixtureStamp+".tar.zst.age"), []byte("ciphertext"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "20260101T000000Z.tar.zst.age"), []byte("no sidecar"), 0o600)

	l, err := listBackupDir(dir)
	if err != nil || len(l) != 2 || l[0].Stamp != fixtureStamp || l[0].Sidecar == "" || l[1].Sidecar != "" {
		t.Fatalf("listing: %v %+v", err, l)
	}

	newHost, _ := age.GenerateX25519Identity()
	out := filepath.Join(t.TempDir(), "resealed.age")
	flags := map[string]string{"--dir": dir, "--stamp": fixtureStamp, "--to": newHost.Recipient().String(),
		"--out": out, "--identity": fx.recoveryFile}
	if err := cmdBackupRestorePlan(flags); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := armorOpen(t, sealed, newHost); !bytes.Equal(got, fx.plain) {
		t.Fatal("the new host received a different record")
	}
	// Never overwrites a file already there.
	if err := cmdBackupRestorePlan(flags); err == nil {
		t.Fatal("a second reseal overwrote the first")
	}
	flags["--stamp"] = "20260101T000000Z"
	flags["--out"] = filepath.Join(t.TempDir(), "x.age")
	if err := cmdBackupRestorePlan(flags); err == nil || !strings.Contains(err.Error(), "with a sidecar") {
		t.Fatalf("a backup with no sidecar was not refused as such: %v", err)
	}
}
