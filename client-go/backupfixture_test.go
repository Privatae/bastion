package main

// The backup fixtures are made when a test runs, never committed: a key in
// the repository, even a test key, is one more secret-shaped string for a
// scanner to flag and for a person to wonder about. When the age command is
// there, the sidecar is written by it, in the shape a host writes, so the
// cross-language check reads a file this code did not produce.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const fixtureStamp = "20260928T020000Z"

// fixtureEntity is the host number the fixture sidecar names, and the
// pairing fixtureHost is the one paired to that host (withFixturePairings).
const (
	fixtureEntity = 42
	fixtureHost   = "h42.host.privatae.ai"
)

type backupFixture struct {
	dir          string
	recovery     *age.X25519Identity // a key the sidecar is sealed to
	recoveryFile string              // the same key as an age identity file
	sidecarFile  string              // <stamp>.key.age
	plain        []byte              // the sealed record, byte for byte
	byAgeCommand bool
}

// newBackupFixture makes a sidecar for fixtureStamp sealed to a fresh key,
// written by the age command at bin when bin is not "", else by this code:
// host fixtureEntity's backup kept in platform storage (b/).
func newBackupFixture(t *testing.T, bin string) *backupFixture {
	t.Helper()
	return newBackupFixtureAs(t, bin, "b", fixtureEntity)
}

// newBackupFixtureAs is newBackupFixture for the backup of host entity kept
// under sub: "b" (platform storage) or "s" (staged there, the shape of a
// backup kept only on a bastion).
func newBackupFixtureAs(t *testing.T, bin, sub string, entity int64) *backupFixture {
	t.Helper()
	dir := t.TempDir()
	rec, _ := age.GenerateX25519Identity()
	one, _ := age.GenerateX25519Identity()
	fx := &backupFixture{dir: dir, recovery: rec,
		recoveryFile: filepath.Join(dir, "recovery.txt"),
		sidecarFile:  filepath.Join(dir, fixtureStamp+".key.age")}
	if err := os.WriteFile(fx.recoveryFile, []byte(rec.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx.plain, _ = json.Marshal(backupSidecar{V: 1, Kind: sidecarKind, Identity: one.String(),
		Object: sub + "/" + fixtureStamp + ".tar.zst.age", EntityID: entity, Stamp: fixtureStamp,
		MadeAt: "2026-09-28T02:00:00Z"})
	if bin != "" {
		plainFile := filepath.Join(dir, "sidecar.json")
		_ = os.WriteFile(plainFile, fx.plain, 0o600)
		out, err := exec.Command(bin, "-a", "-r", rec.Recipient().String(), "-o", fx.sidecarFile, plainFile).CombinedOutput()
		if err != nil {
			t.Fatalf("age could not write the fixture sidecar: %v %s", err, out)
		}
		fx.byAgeCommand = true
		return fx
	}
	var b bytes.Buffer
	aw := armor.NewWriter(&b)
	w, _ := age.Encrypt(aw, rec.Recipient())
	_, _ = w.Write(fx.plain)
	_ = w.Close()
	_ = aw.Close()
	if err := os.WriteFile(fx.sidecarFile, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return fx
}

func (fx *backupFixture) sidecar(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(fx.sidecarFile)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// installAsBastionKey makes the fixture's key the one this bastion holds.
func (fx *backupFixture) installAsBastionKey(t *testing.T) {
	t.Helper()
	keys := withBackupKeysDir(t)
	raw, _ := recipientRaw(fx.recovery.Recipient())
	fp := backupKeyFingerprint(raw)
	_ = os.WriteFile(filepath.Join(keys, fp+".txt"), []byte(fx.recovery.String()+"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(keys, "active"), []byte(fp+"\n"), 0o600)
}

// fixtureWho is the pairing fixtureHost as the reseal lane binds it.
var fixtureWho = resealWho{Name: fixtureHost, Number: fixtureEntity}
