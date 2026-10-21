package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Release manifests are signed.
//
// The bastion's binary and the agent's .pyz were already checked against a
// sha256, but the sha256 came from a manifest served by the same origin as the
// bytes. Anyone who could change what that origin serves (the edge, the cache
// in front of it, the DNS pointing at it) could change both, and the check
// would pass. A signature moves the trust from "whoever serves these files" to
// "whoever holds the release key", and that key is kept offline on the key
// holder's own computer, away from the edges, the release machine and the
// platform.
//
// Every manifest is published with a detached signature beside it:
// <manifest>.<first 16 hex of its sha256>.sig (releaseSigURL) holds the base64 ed25519 signature over a short statement
// naming what was released and the sha256 of the manifest's exact bytes:
//
//	privatae-release-signature-v1
//	<kind: bastion | bastion-agent>
//	<version, as the manifest says>
//	<sha256 of the manifest, hex>
//
// The statement is what the key holder reads and signs, on their own
// computer, with deploy/release-sign; this file rebuilds it from the bytes it
// downloaded. The bytes that are hashed are the bytes that are then decoded,
// so there is no canonical form to disagree about, and the kind stops a
// bastion manifest's signature from passing as an agent manifest's.
//
// A missing or bad signature is a refusal, the same as a sha256 mismatch:
// the machine stays on what it runs and tries again on the next directive or
// reconcile. There is no fallback to an unsigned manifest.

// productionReleaseKeys are the public halves of the release signing keys,
// base64 of the raw 32-byte ed25519 key. More than one is accepted so a key
// can be rotated: the next key ships in a release signed by the current one,
// and the old one is dropped a release later.
//
// deploy/release-verify.sh reads this list from the source, so keep one
// quoted key per line.
var productionReleaseKeys = []string{
	"tWOyZm38DwTwbawSnvExQG/CQsVJBKYWc46arCBZj9E=", // primary
	"CKL+J0VSdqrfY4AmxChvylJ1ha4e8GvcrYF2o17Ah+g=", // spare, kept offline
}

// releaseKeys is what verification reads. A var, separate from the
// production list, so a test can sign with its own key while another test
// still checks the production list itself.
var releaseKeys = productionReleaseKeys

// releaseSigURL is where the signature for the manifest at manifestURL lives:
// beside it, named by the first 8 bytes of the manifest's sha256
// (version.json -> version.json.<16 hex>.sig). Each manifest has its own
// signature file and publishing never removes one, so a machine that read the
// manifest a moment before a publish replaced it still finds the signature
// that belongs to what it read, and no cache can pair a manifest with another
// manifest's signature.
func releaseSigURL(manifestURL string, body []byte) (string, error) {
	u, err := url.Parse(manifestURL)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	u.Path += "." + hex.EncodeToString(sum[:8]) + ".sig"
	return u.String(), nil
}

// releaseFetchTimeout bounds each of the two small fetches (manifest and
// signature). The directed update runs them on the heartbeat, so a hung edge
// must not hold that loop for the binary download's two minutes.
var releaseFetchTimeout = 20 * time.Second

// releaseFetchMax caps what is read for a manifest or a signature. Both are a
// few kilobytes; anything larger is not one.
const releaseFetchMax = 1 << 20

func fetchSmall(u string) ([]byte, error) {
	c := &http.Client{Timeout: releaseFetchTimeout}
	resp, err := c.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch %s: %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, releaseFetchMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > releaseFetchMax {
		return nil, fmt.Errorf("fetch %s: larger than a release manifest can be", u)
	}
	return b, nil
}

const (
	releaseKindBastion = "bastion"
	releaseKindAgent   = "bastion-agent"
)

// releaseStatement is the exact text a release signature covers.
// deploy/release-sign/main.go Statement builds the same text; a shared test
// vector in both test suites keeps the two identical.
func releaseStatement(kind, version, sha256hex string) []byte {
	return []byte("privatae-release-signature-v1\n" + kind + "\n" + version + "\n" + sha256hex + "\n")
}

// verifyReleaseSignature checks sig (the .sig file's contents) over the
// statement for the manifest body, against every accepted release key.
func verifyReleaseSignature(kind string, body, sig []byte) error {
	if len(releaseKeys) == 0 {
		return errors.New("this build pins no release key, so no manifest can be verified")
	}
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.Version == "" || strings.ContainsAny(m.Version, "\r\n") {
		return errors.New("release manifest names no usable version")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("release signature is malformed")
	}
	sum := sha256.Sum256(body)
	msg := releaseStatement(kind, m.Version, hex.EncodeToString(sum[:]))
	for _, k := range releaseKeys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), msg, raw) {
			return nil
		}
	}
	return errors.New("release signature does not verify against any pinned release key")
}

// fetchSignedManifest downloads the manifest at u and its signature, and
// returns the manifest's bytes only if the signature verifies for kind.
func fetchSignedManifest(u, kind string) ([]byte, error) {
	body, err := fetchSmall(u)
	if err != nil {
		return nil, err
	}
	sigURL, err := releaseSigURL(u, body)
	if err != nil {
		return nil, err
	}
	sig, err := fetchSmall(sigURL)
	if err != nil {
		return nil, fmt.Errorf("manifest %s: signature: %w", u, err)
	}
	if err := verifyReleaseSignature(kind, body, sig); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", u, err)
	}
	return body, nil
}
