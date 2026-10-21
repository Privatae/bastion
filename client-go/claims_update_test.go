package main

// Verified releases: the self-updater checks the binary's SHA-256 against the
// signed manifest before anything is swapped. Driven through maybeSelfUpdate
// with a signed manifest served on loopback; a digest that does not match the
// downloaded bytes must leave the running binary exactly as it was.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestADigestMismatchNeverSwapsTheBinary(t *testing.T) {
	uiTestConfigDir(t) // a local, unanchored box: the directive gate passes
	freshVersionState(t)
	t.Cleanup(func() { clearDirectiveRefusal("self-update") })
	clientVersion = "0.1.0"

	self, err := resolvedSelf()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("not the bastion")
	right := sha256.Sum256(payload)
	other := sha256.Sum256([]byte("some other build"))
	cases := []struct{ name, digest string }{
		{"another build's digest", hex.EncodeToString(other[:])},
		{"no digest", ""},
		{"a truncated digest", hex.EncodeToString(right[:])[:63]},
		{"half the digest", hex.EncodeToString(right[:16])},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var downloads atomic.Int64
			mux := http.NewServeMux()
			var srv *httptest.Server
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) {
				key := runtime.GOOS + "-" + runtime.GOARCH
				if runtime.GOOS == "windows" {
					key += ".exe"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"version":  "0.2.0",
					"binaries": map[string]any{key: map[string]any{"url": srv.URL + "/dl", "sha256": c.digest}},
				})
			})
			mux.HandleFunc("/dl", func(w http.ResponseWriter, r *http.Request) {
				downloads.Add(1)
				_, _ = w.Write(payload)
			})
			srv = httptest.NewServer(signedStub(releaseKindBastion, mux))
			defer srv.Close()
			manifestURL = srv.URL + "/version.json"

			// A swap would exit this process; returning at all is the first half
			// of the assertion.
			maybeSelfUpdate("h.host.privatae.ai", "", []byte(`{"update":{"version":"0.2.0"}}`))

			if downloads.Load() != 1 {
				t.Fatalf("the update must get as far as the download for this to test the digest (%d downloads)", downloads.Load())
			}
			after, err := os.ReadFile(self)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(after) != sha256.Sum256(before) {
				t.Fatal("the running binary changed after a digest mismatch")
			}
			if _, err := os.Stat(self + ".old"); err == nil {
				t.Fatal("the running binary was moved aside after a digest mismatch")
			}
		})
	}
}
