package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ed25519SPKIPrefix is the DER that wraps a raw Ed25519 public key in the
// SubjectPublicKeyInfo openssl reads (RFC 8410).
var ed25519SPKIPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

func installShVar(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^` + name + `='([^']*)'$`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("install.sh sets no %s", name)
	}
	return string(m[1])
}

func spkiToRaw(t *testing.T, b64 string) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(der) != len(ed25519SPKIPrefix)+ed25519.PublicKeySize || !bytes.HasPrefix(der, ed25519SPKIPrefix) {
		t.Fatalf("not an Ed25519 public key: %q (%v)", b64, err)
	}
	return der[len(ed25519SPKIPrefix):]
}

// The installer checks a release with exactly the keys a bastion checks its
// updates with: a key rotated in release_sign.go and not here would make
// every install refuse, or accept a key the bastions no longer do.
func TestInstallShPinsTheReleaseKeysTheBastionChecks(t *testing.T) {
	keys := strings.Fields(installShVar(t, "RELEASE_KEYS"))
	if len(keys) != len(productionReleaseKeys) {
		t.Fatalf("install.sh pins %d release keys, release_sign.go %d", len(keys), len(productionReleaseKeys))
	}
	for i, k := range keys {
		if got := base64.StdEncoding.EncodeToString(spkiToRaw(t, k)); got != productionReleaseKeys[i] {
			t.Errorf("install.sh key %d is %s, release_sign.go has %s", i, got, productionReleaseKeys[i])
		}
	}
}

// The probe is what tells "this openssl cannot check" from "the signature is
// wrong". A probe that did not verify would make every system read as unable,
// and every install skip the signature with a note.
func TestInstallShProbeSignatureVerifies(t *testing.T) {
	pub := spkiToRaw(t, installShVar(t, "SIG_PROBE_KEY"))
	sig, err := base64.StdEncoding.DecodeString(installShVar(t, "SIG_PROBE_SIG"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte("privatae-installer-probe-v1\n"), sig) {
		t.Fatal("the probe signature does not verify under the probe key")
	}
}

// sigHarness is release_signature_check from install.sh, with the release
// keys replaced by key and the download host by base, run on manifest.
func sigHarness(t *testing.T, pub ed25519.PublicKey, base string, manifest []byte, onlyPATH ...bool) (string, error) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	vars := regexp.MustCompile(`(?ms)^RELEASE_KEYS=.*?^SIG_PROBE_SIG='[^']*'$`).FindString(s)
	fn := regexp.MustCompile(`(?ms)^release_signature_check\(\) \{.*?^\}$`).FindString(s)
	if vars == "" || fn == "" {
		t.Fatal("install.sh's release_signature_check or its keys moved")
	}
	if len(onlyPATH) > 0 && onlyPATH[0] {
		// Only the openssl on PATH: a Mac with Homebrew's openssl@3 would
		// otherwise find a real one at its fixed path.
		loop := regexp.MustCompile(`(?m)^  for c in openssl [^;]*; do$`)
		if !loop.MatchString(fn) {
			t.Fatal("install.sh's openssl candidates moved")
		}
		fn = loop.ReplaceAllString(fn, "  for c in openssl; do")
	}
	der := append(append([]byte{}, ed25519SPKIPrefix...), pub...)
	vars = regexp.MustCompile(`(?m)^RELEASE_KEYS='[^']*'$`).ReplaceAllString(vars,
		"RELEASE_KEYS='"+base64.StdEncoding.EncodeToString(der)+"'")
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "man.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d, "v"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "die() { echo \"ERROR: $*\" >&2; exit 1; }\nSHACMD=sha256sum\nsha_of() { $SHACMD \"$1\" | cut -d' ' -f1; }\n" +
		"base='" + base + "'\n" + vars + "\n" + fn + "\nrelease_signature_check \"$1\" \"$2\"\necho RETURNED\n"
	sh := filepath.Join(d, "h.sh")
	if err := os.WriteFile(sh, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", sh, filepath.Join(d, "man.json"), filepath.Join(d, "v")).CombinedOutput()
	return string(out), err
}

func releaseSigFor(priv ed25519.PrivateKey, manifest []byte, version string) (name, b64 string) {
	sum := sha256.Sum256(manifest)
	stmt := releaseStatement("bastion", version, hex.EncodeToString(sum[:]))
	return "/version.json." + hex.EncodeToString(sum[:8]) + ".sig",
		base64.StdEncoding.EncodeToString(ed25519.Sign(priv, stmt))
}

func TestInstallShRefusesAReleaseWhoseSignatureDoesNotVerify(t *testing.T) {
	requireTools(t, "sh", "openssl", "sha256sum", "curl")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	manifest := []byte("{\n  \"version\": \"9.9.9\",\n  \"binaries\": {}\n}\n")
	name, good := releaseSigFor(priv, manifest, "9.9.9")
	_, wrongKey := releaseSigFor(other, manifest, "9.9.9")
	_, wrongVersion := releaseSigFor(priv, manifest, "9.9.8")
	serve := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := serve[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(v))
	}))
	defer srv.Close()

	// The check needs an openssl that does Ed25519; without one it only
	// notes it, which TestInstallShSaysWhenItCannotCheckTheSignature covers.
	// Whether this one can is asked of openssl here, never read off the
	// installer's note: a probe broken in install.sh would print that note on
	// every machine, and this test would skip while every install skipped the
	// signature.
	// MUTATION: break the probe's pkeyutl flags in install.sh. RESULT: red here
	// (it skipped before).
	if !opensslChecksEd25519(t) {
		skipOrFail(t, "the openssl here does not check Ed25519 signatures")
	}
	serve[name] = good
	out, err := sigHarness(t, pub, srv.URL, manifest)
	if err != nil || strings.Contains(out, "no openssl here can check") ||
		!strings.Contains(out, "Release signature verified (version 9.9.9)") || !strings.Contains(out, "RETURNED") {
		t.Fatalf("a good signature: %v\n%s", err, out)
	}
	for what, sig := range map[string]string{"another key's": wrongKey, "another version's": wrongVersion} {
		serve[name] = sig
		// MUTATION: return 0 after the key loop. RESULT: red, these install.
		if out, err := sigHarness(t, pub, srv.URL, manifest); err == nil || strings.Contains(out, "RETURNED") ||
			!strings.Contains(out, "does not verify") {
			t.Errorf("%s signature: %v\n%s", what, err, out)
		}
	}
	serve[name] = "not base64 at all !"
	if out, err := sigHarness(t, pub, srv.URL, manifest); err == nil || !strings.Contains(out, "malformed") {
		t.Errorf("a malformed signature: %v\n%s", err, out)
	}
	delete(serve, name)
	if out, err := sigHarness(t, pub, srv.URL, manifest); err == nil || !strings.Contains(out, "cannot fetch the release's signature") {
		t.Errorf("no signature: %v\n%s", err, out)
	}
}

// opensslChecksEd25519 says, without install.sh, whether the openssl on PATH
// verifies an Ed25519 signature made here, and refuses one over another
// message.
func opensslChecksEd25519(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		return false
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der := append(append([]byte{}, ed25519SPKIPrefix...), pub...)
	d := t.TempDir()
	files := map[string][]byte{
		"k.pem": []byte("-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END PUBLIC KEY-----\n"),
		"m":     []byte("capability\n"),
		"other": []byte("capability?\n"),
		"s":     ed25519.Sign(priv, []byte("capability\n")),
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(d, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	verify := func(msg string) bool {
		return exec.Command("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", filepath.Join(d, "k.pem"), "-rawin",
			"-in", filepath.Join(d, msg), "-sigfile", filepath.Join(d, "s")).Run() == nil
	}
	return verify("m") && !verify("other")
}

// An openssl that passes every signature is no check: the installer must not
// take it for one and print "verified" over a signature no pinned key made.
// It is set aside like one that cannot check; a later candidate that can
// still checks.
func TestInstallShTakesNoOpensslThatPassesEverySignature(t *testing.T) {
	requireTools(t, "sh", "openssl", "sha256sum", "curl")
	systemSSL, _ := exec.LookPath("openssl")
	fake := t.TempDir()
	if err := os.WriteFile(filepath.Join(fake, "openssl"),
		[]byte("#!/bin/sh\ncase \"$1\" in pkeyutl) exit 0 ;; esac\nexec '"+systemSSL+"' \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	manifest := []byte("{\n  \"version\": \"9.9.9\",\n  \"binaries\": {}\n}\n")
	name, forged := releaseSigFor(other, manifest, "9.9.9")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != name {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(forged))
	}))
	defer srv.Close()
	// MUTATION: drop the probe's second verify (the one that must fail).
	// RESULT: red, "Release signature verified" over the forged signature.
	out, _ := sigHarness(t, pub, srv.URL, manifest)
	if strings.Contains(out, "Release signature verified") ||
		!(strings.Contains(out, "no openssl here can check") || strings.Contains(out, "does not verify")) {
		t.Errorf("an openssl that passes everything was taken for a check:\n%s", out)
	}
}

// SECURITY.md sends a reader who does not trust our website to a copy of
// install.sh read from this repository. Run without sudo, that copy installs
// for the whole machine through a root step that fetches the installer from
// the website again (whole_machine_script) and runs that, so the copy read
// checks nothing itself. The page has to say how the copy must be run.
func TestSecurityMdSaysHowAReadCopyOfTheInstallerMustRun(t *testing.T) {
	sh, err := os.ReadFile(filepath.Join("..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sh), `whole_machine_script="https://privatae.ai/bastion/install.sh"`) {
		t.Fatal("install.sh's root step no longer fetches the website's installer: re-read SECURITY.md's first-install paragraph, then this test")
	}
	raw, err := os.ReadFile(filepath.Join("..", "SECURITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	sec := strings.Join(strings.Fields(string(raw)), " ")
	for _, want := range []string{
		"`sudo sh install.sh`",
		"`sh install.sh --just-me`",
		"fetches the installer from our website again",
		"an older release we signed",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("SECURITY.md does not say %q", want)
		}
	}
}

// With no openssl that can check Ed25519, the check says so and returns, so
// the digest check still runs; it never reads as verified.
func TestInstallShSaysWhenItCannotCheckTheSignature(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	fake := t.TempDir()
	if err := os.WriteFile(filepath.Join(fake, "openssl"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	out, err := sigHarness(t, pub, "http://127.0.0.1:1", []byte("{\"version\": \"9.9.9\"}\n"), true)
	if err != nil || !strings.Contains(out, "no openssl here can check") || strings.Contains(out, "verified") ||
		!strings.Contains(out, "RETURNED") {
		t.Errorf("no capable openssl: %v\n%s", err, out)
	}
}

// The check runs on every install, after the manifest is fetched and before
// any digest is read out of it: a digest from an unchecked manifest is the
// thing the signature exists to stop.
func TestInstallShChecksTheSignatureBeforeReadingTheDigest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	fetch := strings.Index(s, `curl -fsSL "$base/version.json" -o "$man"`)
	check := strings.Index(s, "\nrelease_signature_check \"$man\" \"$vdir\"\n")
	digest := strings.Index(s, "expected=$(awk")
	if fetch < 0 || check < 0 || digest < 0 || !(fetch < check && check < digest) {
		t.Fatalf("install.sh must fetch the manifest, check its signature, then read its digest (at %d, %d, %d)",
			fetch, check, digest)
	}
}

// requireTools skips without one of these tools, unless CI says the check
// must run (PRIVATAE_REQUIRE_OPENSSL=1, .gitea/workflows/ci.yml): there a
// missing tool is a failure, so the signature check cannot quietly go untested.
func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			skipOrFail(t, tool+" is not installed here")
		}
	}
}

func skipOrFail(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("PRIVATAE_REQUIRE_OPENSSL") == "1" {
		t.Fatalf("%s, and PRIVATAE_REQUIRE_OPENSSL=1 says this check must run", why)
	}
	t.Skip(why)
}
