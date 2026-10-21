package main

// Gate: the backup key is made here, kept as a plain age key file, never
// overwritten, and every string that names a key round-trips through age's own
// parser. The bech32 here is an encoding of public keys only; these tests hold
// it to age's.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// ageBinary is the real age command for the cross-language checks. AGE_BIN
// names one explicitly; otherwise `age` on PATH; otherwise the test skips.
func ageBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("AGE_BIN"); p != "" {
		return p
	}
	if p, err := exec.LookPath("age"); err == nil {
		return p
	}
	// CI installs a pinned age release and sets this, so the cross-language
	// checks cannot pass there by skipping.
	if os.Getenv("PRIVATAE_REQUIRE_AGE") != "" {
		t.Fatal("PRIVATAE_REQUIRE_AGE is set and no age binary was found (AGE_BIN or PATH)")
	}
	t.Skip("no age binary (set AGE_BIN) — the cross-language half is skipped")
	return ""
}

func withBackupKeysDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := backupKeysDir
	backupKeysDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { backupKeysDir = prev })
	return dir
}

func TestBech32RoundTripsAgeRecipients(t *testing.T) {
	for i := 0; i < 64; i++ {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := recipientRaw(id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 32 {
			t.Fatalf("raw key is %d bytes", len(raw))
		}
		enc, err := bech32Encode("age", raw)
		if err != nil {
			t.Fatal(err)
		}
		if enc != id.Recipient().String() {
			t.Fatalf("bech32 of the raw key %s differs from age's %s", enc, id.Recipient())
		}
	}
	// A random 32 bytes encodes to something age itself accepts.
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	enc, _ := bech32Encode("age", raw)
	if _, err := age.ParseX25519Recipient(enc); err != nil {
		t.Fatalf("age refuses our encoding: %v", err)
	}
	// One changed character is caught by the checksum.
	bad := enc[:10] + string("qp"[boolIdx(enc[10] == 'q')]) + enc[11:]
	if _, _, err := bech32Decode(bad); err == nil {
		t.Fatal("a corrupted recipient decoded")
	}
}

func boolIdx(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestParseBackupRecipientAcceptsBothForms(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	raw, _ := recipientRaw(id.Recipient())
	a, err := parseBackupRecipient(id.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseBackupRecipient(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatalf("the two forms of one key disagree: %s vs %s", a, b)
	}
	for _, bad := range []string{"", "age1nope", base64.StdEncoding.EncodeToString(raw[:31]), "not base64 !!"} {
		if _, err := parseBackupRecipient(bad); err == nil {
			t.Errorf("%q was accepted as a key", bad)
		}
	}
}

func TestBackupKeyInitKeepsAPlainAgeKeyAndNeverOverwrites(t *testing.T) {
	dir := withBackupKeysDir(t)
	k1, err := backupKeyInit(false)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(k1.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", fi.Mode().Perm())
	}
	// It is a plain age identity file: age's own parser reads it.
	f, _ := os.Open(k1.Path)
	ids, err := age.ParseIdentities(f)
	f.Close()
	if err != nil || len(ids) != 1 {
		t.Fatalf("the key file is not an age identity file: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(k1.PubB64)
	if backupKeyFingerprint(raw) != k1.Fingerprint || filepath.Base(k1.Path) != k1.Fingerprint+".txt" {
		t.Fatal("the fingerprint does not name the key")
	}

	if _, err := backupKeyInit(false); err == nil {
		t.Fatal("a second init without --replace overwrote the key")
	}
	k2, err := backupKeyInit(true)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Fingerprint == k1.Fingerprint {
		t.Fatal("--replace did not make a new key")
	}
	active, all, err := backupKeysLoad()
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.Fingerprint != k2.Fingerprint {
		t.Fatal("the new key is not the active one")
	}
	if len(all) != 2 {
		t.Fatalf("the replaced key was not kept: %d keys", len(all))
	}
	// Both still open what was sealed to them.
	got, err := backupIdentities()
	if err != nil || len(got) != 2 {
		t.Fatalf("identities: %v %d", err, len(got))
	}
	for _, k := range []*backupKeyFile{k1, k2} {
		r, _ := age.ParseX25519Recipient(k.Recipient)
		var ct bytes.Buffer
		w, _ := age.Encrypt(&ct, r)
		_, _ = w.Write([]byte("sealed to " + k.Fingerprint))
		_ = w.Close()
		rd, err := age.Decrypt(&ct, got...)
		if err != nil {
			t.Fatalf("key %s no longer opens its backups: %v", k.Fingerprint, err)
		}
		b, _ := io.ReadAll(rd)
		if !strings.HasSuffix(string(b), k.Fingerprint) {
			t.Fatal("wrong plaintext")
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ctx-") {
			t.Fatalf("a temporary file survived: %s", e.Name())
		}
	}
}

// Cross-language: the key file this bastion keeps is read by the real age
// command the same way filippo.io/age reads it here.
func TestBackupKeyFileOpensWithTheAgeCommand(t *testing.T) {
	bin := ageBinary(t)
	withBackupKeysDir(t)
	k, err := backupKeyInit(false)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := age.ParseX25519Recipient(k.Recipient)
	ct := filepath.Join(t.TempDir(), "x.age")
	f, _ := os.Create(ct)
	w, _ := age.Encrypt(f, r)
	_, _ = w.Write([]byte("a backup"))
	_ = w.Close()
	_ = f.Close()
	out, err := exec.Command(bin, "-d", "-i", k.Path, ct).CombinedOutput()
	if err != nil || string(out) != "a backup" {
		t.Fatalf("age -d -i <key file> failed: %v %s", err, out)
	}
}
