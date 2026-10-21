//go:build !windows

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A replayed older agent manifest carries a valid signature. It must not
// move an installed agent backwards.
func TestAnOlderSignedAgentManifestDoesNotDowngrade(t *testing.T) {
	withConfigDir(t)
	base, err := faBaseDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	installed := []byte("installed 0.2.0")
	if err := os.WriteFile(filepath.Join(base, "freeagent.pyz"), installed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "freeagent.version"), []byte("0.2.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := faManifestURL
	t.Cleanup(func() { faManifestURL = old })
	downloads := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/m.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"0.1.0","files":{"bastion-agent-0.1.0.pyz":{"url":"` +
			"http://" + r.Host + `/dl","sha256":"00"}}}`))
	})
	mux.HandleFunc("/dl", func(w http.ResponseWriter, r *http.Request) { downloads++ })
	srv := httptest.NewServer(signedStub(releaseKindAgent, mux))
	t.Cleanup(srv.Close)
	faManifestURL = srv.URL + "/m.json"

	_, v, err := faEnsurePyz()
	if err != nil || v != "0.2.0" {
		t.Fatalf("an older manifest must leave 0.2.0 in place: %v %q", err, v)
	}
	if downloads != 0 {
		t.Fatal("an older manifest must not download anything")
	}
	if got, _ := os.ReadFile(filepath.Join(base, "freeagent.pyz")); !bytes.Equal(got, installed) {
		t.Fatal("the installed agent was replaced")
	}
}
