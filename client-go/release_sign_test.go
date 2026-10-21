package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The suite signs its stub manifests with a key of its own. The production
// list is left untouched in productionReleaseKeys, and a test below holds it
// to account on its own.
var testReleasePriv ed25519.PrivateKey

func init() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	testReleasePriv = priv
	releaseKeys = []string{base64.StdEncoding.EncodeToString(pub)}
}

func testReleaseSig(kind string, body []byte) []byte {
	var m struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(body, &m)
	sum := sha256.Sum256(body)
	msg := releaseStatement(kind, m.Version, hex.EncodeToString(sum[:]))
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(testReleasePriv, msg)) + "\n")
}

// signedStub wraps a stub publisher so every manifest it serves has a valid
// signature beside it, the way a real publish does. The signature request is
// answered from what the manifest request returned, without calling the inner
// handler again, so a test counting manifest fetches still counts manifests.
func signedStub(kind string, inner http.Handler) http.Handler {
	var mu sync.Mutex
	sigs := map[string][]byte{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := strings.CutSuffix(r.URL.Path, ".sig"); ok {
			if i := strings.LastIndex(p, "."); i > 0 {
				p = p[:i] // drop the digest: <manifest>.<16 hex>.sig
			}
			mu.Lock()
			s, found := sigs[p]
			mu.Unlock()
			if !found {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(s)
			return
		}
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r)
		mu.Lock()
		sigs[r.URL.Path] = testReleaseSig(kind, rec.Body.Bytes())
		mu.Unlock()
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

func TestASignedManifestVerifies(t *testing.T) {
	body := []byte(`{"version":"1.2.3","binaries":{}}`)
	if err := verifyReleaseSignature(releaseKindBastion, body, testReleaseSig(releaseKindBastion, body)); err != nil {
		t.Fatalf("a manifest signed by a pinned key must verify: %v", err)
	}
}

func TestATamperedManifestIsRefused(t *testing.T) {
	body := []byte(`{"version":"1.2.3","binaries":{"linux-amd64":{"sha256":"aa"}}}`)
	sig := testReleaseSig(releaseKindBastion, body)
	changed := bytes.Replace(body, []byte(`"aa"`), []byte(`"bb"`), 1)
	if err := verifyReleaseSignature(releaseKindBastion, changed, sig); err == nil {
		t.Fatal("a manifest whose digest was changed after signing must be refused")
	}
}

func TestAManifestSignedByAnotherKeyIsRefused(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(`{"version":"1.2.3"}`)
	sum := sha256.Sum256(body)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(other, releaseStatement(releaseKindBastion, "1.2.3", hex.EncodeToString(sum[:]))))
	if err := verifyReleaseSignature(releaseKindBastion, body, []byte(sig)); err == nil {
		t.Fatal("a signature from a key this build does not pin must be refused")
	}
}

func TestAMalformedSignatureIsRefused(t *testing.T) {
	body := []byte(`{"version":"1.2.3"}`)
	for _, sig := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if err := verifyReleaseSignature(releaseKindBastion, body, []byte(sig)); err == nil {
			t.Fatalf("signature %q must be refused", sig)
		}
	}
}

func TestNoPinnedKeyRefusesEverything(t *testing.T) {
	old := releaseKeys
	releaseKeys = nil
	t.Cleanup(func() { releaseKeys = old })
	body := []byte(`{"version":"1.2.3"}`)
	if err := verifyReleaseSignature(releaseKindBastion, body, testReleaseSig(releaseKindBastion, body)); err == nil {
		t.Fatal("with no key pinned nothing can be verified, so nothing may pass")
	}
}

// The production build must pin well-formed keys. With none, every field
// bastion that takes this release would refuse every later update, and the
// only way out would be a reinstall by hand.
func TestProductionPinsAReleaseKey(t *testing.T) {
	// Two: the primary and an offline spare (SECURITY.md). With one, losing
	// it would strand every machine on this release.
	if len(productionReleaseKeys) < 2 {
		t.Fatalf("productionReleaseKeys pins %d key(s); a release needs the primary and a spare",
			len(productionReleaseKeys))
	}
	for _, k := range productionReleaseKeys {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			t.Fatalf("release key %q is not base64 of a 32-byte ed25519 public key", k)
		}
	}
}

// fetchManifest is the one door for both readers, so an unsigned manifest
// reaches neither the updater nor the page.
func TestAnUnsignedManifestIsNotRead(t *testing.T) {
	freshVersionState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"version":"99.0.0","binaries":{}}`))
	}))
	t.Cleanup(srv.Close)
	manifestURL = srv.URL + "/version.json"
	if _, err := fetchManifest(); err == nil {
		t.Fatal("a manifest with no signature must not be returned")
	}
	checkLatestPublished()
	if got := updateAvailable(); got != "" {
		t.Fatalf("an unsigned manifest reached the page: %q", got)
	}
}

// Each manifest's signature has its own file, named by the manifest's digest,
// so a publish in between cannot pair one manifest with another's signature.
func TestTheSignatureURLNamesTheManifest(t *testing.T) {
	a, _ := releaseSigURL("https://example.test/bastion/version.json", []byte("one"))
	b, _ := releaseSigURL("https://example.test/bastion/version.json", []byte("two"))
	if !strings.HasPrefix(a, "https://example.test/bastion/version.json.") || !strings.HasSuffix(a, ".sig") ||
		len(a) != len("https://example.test/bastion/version.json.")+16+len(".sig") {
		t.Fatalf("unexpected signature url %s", a)
	}
	if a == b {
		t.Fatal("two different manifests must have different signature files")
	}
}

// The shared vector. deploy/release-sign/main_test.go holds the same seed,
// manifest and signature; if the statement format changes on one side only,
// one of the two tests fails.
func TestTheSigningToolAndTheBastionAgreeOnTheStatement(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	body := []byte(`{"version":"1.2.3","binaries":{}}`)
	const toolSig = "tr5h3oXjBDmwvwQiZSriW4T6Y6oBFQDymfofLEGXMdTJSXfoQAKN+ajhCs89FO9vdCEZH3Y8mYzYXPZ7RzZVDw=="
	old := releaseKeys
	releaseKeys = []string{base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))}
	t.Cleanup(func() { releaseKeys = old })
	if err := verifyReleaseSignature(releaseKindBastion, body, []byte(toolSig)); err != nil {
		t.Fatalf("a signature made by deploy/release-sign must verify here: %v", err)
	}
}

// A bastion manifest's signature must not pass for an agent manifest.
func TestASignatureIsBoundToItsKind(t *testing.T) {
	body := []byte(`{"version":"1.2.3","files":{}}`)
	if err := verifyReleaseSignature(releaseKindAgent, body, testReleaseSig(releaseKindBastion, body)); err == nil {
		t.Fatal("a bastion signature passed as an agent signature")
	}
}

// The agent's manifest is held to the same rule as the bastion's: served
// without a valid signature, it is not read at all.
func TestAnUnsignedAgentManifestIsNotRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"version":"9.9.9","files":{}}`))
	}))
	t.Cleanup(srv.Close)
	old := faManifestURL
	t.Cleanup(func() { faManifestURL = old })
	faManifestURL = srv.URL + "/bastion-agent/version.json"
	if _, _, _, err := faFetchManifest(); err == nil {
		t.Fatal("an agent manifest with no signature must not be returned")
	}
	// Signed as a BASTION manifest: the right key, the wrong kind.
	srv2 := httptest.NewServer(signedStub(releaseKindBastion, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"9.9.9","files":{}}`))
	})))
	t.Cleanup(srv2.Close)
	faManifestURL = srv2.URL + "/bastion-agent/version.json"
	if _, _, _, err := faFetchManifest(); err == nil {
		t.Fatal("a bastion signature must not admit an agent manifest")
	}
}
