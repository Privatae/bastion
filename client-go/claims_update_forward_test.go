//go:build !windows

package main

// Bastion updates (0.44.0): on an anchored box a move to a NEWER version needs
// no approval, because the release signature is the approval for it. A move to
// an older version, or to one this binary cannot compare with its own, still
// needs the person's approval bound to that version. Tagged !windows for the
// anchored-box fixture (setupBox, anchor_test.go).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// updateBeat is a heartbeat response directing a self-update and carrying no
// approval.
func updateBeat(version string) []byte {
	return []byte(`{"update":{"version":"` + version + `"}}`)
}

// A newer version reaches the signed manifest with no approval. The rest of the
// gate still holds: a member's directive and the local switch both refuse it.
func TestANewerSignedReleaseNeedsNoApproval(t *testing.T) {
	setupBox(t)
	freshVersionState(t)
	t.Cleanup(func() { clearDirectiveRefusal("self-update") })
	clientVersion = "0.44.0"
	var fetches atomic.Int64
	man := httptest.NewServer(signedStub(releaseKindBastion, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		_, _ = w.Write([]byte(`{"version":"0.45.0","binaries":{}}`))
	})))
	defer man.Close()
	manifestURL = man.URL + "/version.json"

	maybeSelfUpdate(tMember, "", updateBeat("0.45.0"))
	if fetches.Load() != 0 {
		t.Fatal("a member's directive must be refused before any fetch, newer version or not")
	}
	maybeSelfUpdate(tAnchor, "", updateBeat("0.45.0"))
	if fetches.Load() != 1 {
		t.Fatalf("the anchor's directive to a newer version must reach the signed manifest with no approval, got %d fetches", fetches.Load())
	}
	if r := directiveRefusalReport(); r != nil {
		t.Fatalf("the update passed, so the member's refusal is no longer reported: %v", r)
	}
	if err := localDenySet(tAnchor, localFamilyDirectives, true); err != nil {
		t.Fatal(err)
	}
	maybeSelfUpdate(tAnchor, "", updateBeat("0.45.0"))
	if fetches.Load() != 1 {
		t.Fatal("switched off here, a newer version must not fetch either")
	}
}

// The host learns the rule from the box itself, on the enforcing report every
// beat carries, so it never has to infer it from a version number. A build
// that cannot read its own version gates every update, and says so.
func TestTheBoxTellsTheHostAForwardUpdateNeedsNoApproval(t *testing.T) {
	setupBox(t)
	freshVersionState(t)
	clientVersion = "0.44.0"
	if v, _ := buildEnforcingReport("", nil)["update_forward_needs_no_approval"].(bool); !v {
		t.Fatal("the enforcing report must say a forward update needs no approval")
	}
	for _, own := range []string{"dev", "0.44.0-rc1", ""} {
		clientVersion = own
		if v, _ := buildEnforcingReport("", nil)["update_forward_needs_no_approval"].(bool); v {
			t.Fatalf("a build running %q can compare nothing, so it must not say so", own)
		}
	}
}

// Older, unstamped and suffixed versions are refused without an approval, and
// the host is told an approval is what is missing. With one, an older version
// proceeds.
func TestAnOlderOrUncomparableVersionStillNeedsAnApproval(t *testing.T) {
	setupBox(t)
	freshVersionState(t)
	t.Cleanup(func() { clearDirectiveRefusal("self-update") })
	var fetches atomic.Int64
	man := httptest.NewServer(signedStub(releaseKindBastion, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		_, _ = w.Write([]byte(`{"version":"0.43.1","binaries":{}}`))
	})))
	defer man.Close()
	manifestURL = man.URL + "/version.json"

	cases := []struct{ running, target string }{
		{"0.44.0", "0.43.1"},     // older
		{"0.44.0", "0.9.0"},      // older, and above 0.44.0 as a string
		{"0.44.0", "0.44"},       // the running release, spelled shorter
		{"dev", "0.45.0"},        // an unstamped build cannot say what is newer
		{"0.44.0", "0.45.0-rc1"}, // nor can a suffixed target
	}
	for _, c := range cases {
		clientVersion = c.running
		clearDirectiveRefusal("self-update")
		maybeSelfUpdate(tAnchor, "", updateBeat(c.target))
		if fetches.Load() != 0 {
			t.Fatalf("%s on a box running %s, with no approval, must be refused before any fetch", c.target, c.running)
		}
		if r := directiveRefusalReport(); r == nil || !strings.Contains(fmt.Sprint(r), "approval") {
			t.Fatalf("%s on a box running %s: the host must be told an approval is missing: %v", c.target, c.running, r)
		}
	}
	clientVersion = "0.44.0"
	maybeSelfUpdate(tAnchor, "", testDirective(t, directiveSelfUpdate, []string{"0.43.1"}, string(updateBeat("0.43.1"))))
	if fetches.Load() != 1 {
		t.Fatal("approved, a move to an older version proceeds")
	}
}

// Without an approval, the only thing that installs is a newer SIGNED release
// that is exactly the target. A signed manifest for another version (an old one
// served again by a download server, say) is not downloaded, and neither is an
// unsigned manifest for the target itself. The binary's digest never matches
// the payload here, so even a broken gate could not swap the test binary.
func TestTheForwardPathInstallsNothingButTheSignedTarget(t *testing.T) {
	setupBox(t)
	freshVersionState(t)
	t.Cleanup(func() { clearDirectiveRefusal("self-update") })
	clientVersion = "0.44.0"
	key := runtime.GOOS + "-" + runtime.GOARCH
	elsewhere := sha256.Sum256([]byte("some other build"))
	var served atomic.Value
	var downloads atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": served.Load().(string),
			"binaries": map[string]any{key: map[string]any{
				"url": "http://" + r.Host + "/dl", "sha256": hex.EncodeToString(elsewhere[:])}},
		})
	})
	mux.HandleFunc("/dl", func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		_, _ = w.Write([]byte("not the bastion"))
	})
	signed := httptest.NewServer(signedStub(releaseKindBastion, mux))
	defer signed.Close()
	unsigned := httptest.NewServer(mux)
	defer unsigned.Close()

	manifestURL = signed.URL + "/version.json"
	served.Store("0.43.1")
	maybeSelfUpdate(tAnchor, "", updateBeat("0.45.0"))
	if downloads.Load() != 0 {
		t.Fatal("a signed manifest for another version must not be downloaded from")
	}

	manifestURL = unsigned.URL + "/version.json"
	served.Store("0.45.0")
	maybeSelfUpdate(tAnchor, "", updateBeat("0.45.0"))
	if downloads.Load() != 0 {
		t.Fatal("an unsigned manifest must not be downloaded from, even for the target")
	}

	// The control: signed and naming the target, the download does happen (and
	// the digest mismatch then stops the swap).
	manifestURL = signed.URL + "/version.json"
	maybeSelfUpdate(tAnchor, "", updateBeat("0.45.0"))
	if downloads.Load() != 1 {
		t.Fatalf("a signed manifest naming the target must be downloaded from with no approval, got %d", downloads.Load())
	}
}
