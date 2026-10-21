package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// The shared vector. client-go/release_sign_test.go holds the same three
// values; if the statement format changes on one side only, one of the two
// tests fails.
var (
	vectorSeed     = strings.Repeat("\x01", ed25519.SeedSize)
	vectorManifest = []byte(`{"version":"1.2.3","binaries":{}}`)
)

func vectorKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed([]byte(vectorSeed)) }

func TestSharedVector(t *testing.T) {
	priv := vectorKey()
	sum := sha256.Sum256(vectorManifest)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Statement("bastion", "1.2.3", hex.EncodeToString(sum[:]))))
	if sig != sharedVectorSig {
		t.Fatalf("the statement format changed: signature is now %s", sig)
	}
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if got, err := VerifyManifest("bastion", vectorManifest, []byte(sig), []string{pub}); err != nil || got != pub {
		t.Fatalf("verify: %v", err)
	}
}

const sharedVectorSig = "tr5h3oXjBDmwvwQiZSriW4T6Y6oBFQDymfofLEGXMdTJSXfoQAKN+ajhCs89FO9vdCEZH3Y8mYzYXPZ7RzZVDw=="

// The C-Series Cloud vector. The box's updater (vm/cloud in the C-Series
// tree) checks the same seed, manifest and signature, so a change to how a
// cseries-cloud statement is built fails on both sides.
var cloudVectorManifest = []byte(`{"version":"1.2.3","images":{}}`)

const cloudVectorSig = "69+ug9q0ndTtLijHaOlpD8aFiQcO9/TRvmB+4jLNNrDSbMzx1mvDlOXzOgxDvQLTWa8LZmqxHABLF75kxYl4Bw=="

func TestCloudKindSignsAndVerifiesOnlyAsItself(t *testing.T) {
	priv := vectorKey()
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	sum := sha256.Sum256(cloudVectorManifest)
	if err := checkStatement("cseries-cloud", "1.2.3", hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("a cseries-cloud statement must be signable: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Statement("cseries-cloud", "1.2.3", hex.EncodeToString(sum[:]))))
	if sig != cloudVectorSig {
		t.Fatalf("the cseries-cloud statement changed: signature is now %s", sig)
	}
	if got, err := VerifyManifest("cseries-cloud", cloudVectorManifest, []byte(sig), []string{pub}); err != nil || got != pub {
		t.Fatalf("verify: %v", err)
	}
	for _, other := range []string{"bastion", "bastion-agent"} {
		if _, err := VerifyManifest(other, cloudVectorManifest, []byte(sig), []string{pub}); err == nil {
			t.Fatalf("a cseries-cloud signature must not pass as %s", other)
		}
	}
	bastionSig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Statement("bastion", "1.2.3", hex.EncodeToString(sum[:])))))
	if _, err := VerifyManifest("cseries-cloud", cloudVectorManifest, bastionSig, []string{pub}); err == nil {
		t.Fatal("a bastion signature must not pass as a cseries-cloud signature")
	}
}

// The C-Series App Store catalog. The C-Series Host's public store reader
// builds the same statement and asserts these exact bytes for it, so a change
// to the text on either side fails a test.
var storeVectorCatalog = []byte(`{"version":"1.2.3","apps":[]}`)

const storeVectorSig = "+wAepICIvr4vLfhhbbONLJjP2KnoEysh7hMZjZtgRbqrxVcUiHKSWbzP3AoOKemvH7oHjRMkpqQAX/GVlmjWDg=="

func TestStoreKindSignsAndVerifiesOnlyAsItself(t *testing.T) {
	want := "privatae-release-signature-v1\ncseries-store\n1.2.3\n" + strings.Repeat("ab", 32) + "\n"
	if got := string(Statement("cseries-store", "1.2.3", strings.Repeat("ab", 32))); got != want {
		t.Fatalf("the cseries-store statement is %q, the C-Series reader builds %q", got, want)
	}
	priv := vectorKey()
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	sum := sha256.Sum256(storeVectorCatalog)
	if err := checkStatement("cseries-store", "1.2.3", hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("a cseries-store statement must be signable: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Statement("cseries-store", "1.2.3", hex.EncodeToString(sum[:]))))
	if sig != storeVectorSig {
		t.Fatalf("the cseries-store statement changed: signature is now %s", sig)
	}
	if got, err := VerifyManifest("cseries-store", storeVectorCatalog, []byte(sig), []string{pub}); err != nil || got != pub {
		t.Fatalf("verify: %v", err)
	}
	for _, other := range []string{"bastion", "bastion-agent", "cseries-cloud"} {
		if _, err := VerifyManifest(other, storeVectorCatalog, []byte(sig), []string{pub}); err == nil {
			t.Fatalf("a cseries-store signature must not pass as %s", other)
		}
		otherSig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Statement(other, "1.2.3", hex.EncodeToString(sum[:])))))
		if _, err := VerifyManifest("cseries-store", storeVectorCatalog, otherSig, []string{pub}); err == nil {
			t.Fatalf("a %s signature must not pass as a cseries-store signature", other)
		}
	}
}

func TestSealAndOpen(t *testing.T) {
	priv := vectorKey()
	kf, err := seal(priv.Seed(), priv.Public().(ed25519.PublicKey), []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := open(kf, []byte("correct horse battery"))
	if err != nil || !got.Equal(priv) {
		t.Fatalf("the right passphrase must open the key: %v", err)
	}
	if _, err := open(kf, []byte("wrong horse battery")); err == nil {
		t.Fatal("a wrong passphrase must not open the key")
	}
	kf.Pub = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := open(kf, []byte("correct horse battery")); err == nil {
		t.Fatal("a key file whose public key was swapped must not open")
	}
}

func TestVerifyRefusesTheWrongKindOrAChangedManifest(t *testing.T) {
	priv := vectorKey()
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	sum := sha256.Sum256(vectorManifest)
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Statement("bastion", "1.2.3", hex.EncodeToString(sum[:])))))
	if _, err := VerifyManifest("bastion-agent", vectorManifest, sig, []string{pub}); err == nil {
		t.Fatal("a bastion signature must not pass as an agent signature")
	}
	if _, err := VerifyManifest("bastion", []byte(`{"version":"1.2.4","binaries":{}}`), sig, []string{pub}); err == nil {
		t.Fatal("a changed manifest must not verify")
	}
}

func TestSignRefusesAnythingThatIsNotAStatement(t *testing.T) {
	good := strings.Repeat("a", 64)
	for _, c := range [][3]string{
		{"other", "1.2.3", good},
		{"bastion", "1.2.3\nextra", good},
		{"bastion", "1.2.3", "abc"},
		{"bastion", "1.2.3", strings.Repeat("A", 64)},
	} {
		if err := checkStatement(c[0], c[1], c[2]); err == nil {
			t.Fatalf("%q must be refused", c)
		}
	}
	if err := checkStatement("bastion-agent", "0.1.12", good); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedKeysReadsWhatTheCompilerSees(t *testing.T) {
	dir := t.TempDir()
	write := func(src string) string {
		p := dir + "/release_sign.go"
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	k1 := strings.Repeat("A", 43) + "="
	k2 := strings.Repeat("B", 43) + "="
	for name, c := range map[string]struct {
		src  string
		want int
	}{
		"empty":     {"package main\nvar productionReleaseKeys = []string{}\nfunc x() {\n\t_ = \"" + k1 + "\"\n}\n", 0},
		"one line":  {"package main\nvar productionReleaseKeys = []string{\"" + k1 + "\", \"" + k2 + "\"}\n", 2},
		"commented": {"package main\nvar productionReleaseKeys = []string{\n\t// \"" + k2 + "\",\n\t\"" + k1 + "\",\n}\n", 1},
		"var block": {"package main\nvar (\n\tother = 1\n\tproductionReleaseKeys = []string{\n\t\t\"" + k1 + "\",\n\t\t\"" + k2 + "\",\n\t}\n)\n", 2},
	} {
		keys, err := PinnedKeys(write(c.src))
		if err != nil || len(keys) != c.want {
			t.Fatalf("%s: got %v %v, want %d keys", name, keys, err, c.want)
		}
	}
}

func TestOpenRefusesOutOfRangeSettings(t *testing.T) {
	priv := vectorKey()
	kf, err := seal(priv.Seed(), priv.Public().(ed25519.PublicKey), []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*keyFile){
		func(k *keyFile) { k.Time = 0 },
		func(k *keyFile) { k.Thread = 0 },
		func(k *keyFile) { k.Memory = 1 << 31 },
	} {
		bad := *kf
		mutate(&bad)
		if _, err := open(&bad, []byte("correct horse battery")); err == nil {
			t.Fatal("out-of-range settings must be refused, not run")
		}
	}
}
