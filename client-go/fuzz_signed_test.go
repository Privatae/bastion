package main

// Fuzz targets for the signed inputs that need no box state: release
// manifests and the box's own owner and anchor claims. The ones that verify
// against keys pinned on an anchored box are in fuzz_grants_test.go.

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// A release manifest is read only if its signature verifies for its kind
// (release_sign.go). Whatever bytes arrive as the manifest and the signature,
// verification never panics, and it succeeds only for the exact manifest that
// was signed, with the exact signature, for the kind it was signed for.
func FuzzReleaseSignatureIsBoundToItsManifestAndKind(f *testing.F) {
	signed := []byte(`{"version":"1.2.3","binaries":{"linux-amd64":{"sha256":"00"}}}`)
	sig := testReleaseSig(releaseKindBastion, signed)
	f.Add(signed, sig, false)
	f.Add(signed, sig, true)
	f.Add([]byte(`{"version":"1.2.3\n","binaries":{}}`), sig, false)
	f.Add([]byte(`{"version":"1.2.4","binaries":{"linux-amd64":{"sha256":"00"}}}`), sig, false)
	f.Add(signed, []byte("  "+string(bytes.TrimSpace(sig))+"\r\n"), false)
	f.Add([]byte(`{"version":1}`), []byte("x"), false)
	f.Add([]byte{}, []byte{}, false)
	f.Fuzz(func(t *testing.T, body, s []byte, agent bool) {
		kind := releaseKindBastion
		if agent {
			kind = releaseKindAgent
		}
		err := verifyReleaseSignature(kind, body, s)
		if err != nil {
			return
		}
		// The same signature can be spelled more than one way in base64
		// (line breaks, unused low bits); what must match is its bytes.
		got, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(s)))
		want, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if kind != releaseKindBastion || !bytes.Equal(body, signed) || !bytes.Equal(got, want) {
			t.Fatalf("a %s manifest verified that is not the one signed for bastion:\n%q\n%q", kind, body, s)
		}
	})
}

// The box signs its owner claim and its anchor claim with the same key, so the
// two signing inputs must never be the same bytes, and two different anchor
// claims whose names pass claimNameOK must never be the same bytes either.
func FuzzOwnerAndAnchorClaimsNeverShareSignedBytes(f *testing.F) {
	f.Add("Acme", "host.a", "2026-01-01T00:00:00Z", "Acme", "host.a", "2026-01-01T00:00:00Z")
	f.Add("x\nhost", "h", "t", "x", "host\nh", "t")
	f.Add("anchor\nx", "h", "t", "x", "h", "t")
	f.Add("a", "b\nc", "t", "a\nb", "c", "t")
	f.Fuzz(func(t *testing.T, o1, h1, a1, o2, h2, a2 string) {
		if bytes.Equal(anchorSigningInput(o1, h1, a1), ownerSigningInput(o2, a2)) {
			t.Fatalf("an anchor claim (%q, %q, %q) and an owner claim (%q, %q) sign the same bytes", o1, h1, a1, o2, a2)
		}
		for _, n := range []string{o1, h1, o2, h2} {
			if claimNameOK(n) != nil {
				return
			}
		}
		same := o1 == o2 && h1 == h2 && a1 == a2
		if !same && bytes.Equal(anchorSigningInput(o1, h1, a1), anchorSigningInput(o2, h2, a2)) {
			t.Fatalf("two different anchor claims sign the same bytes: (%q, %q, %q) and (%q, %q, %q)", o1, h1, a1, o2, h2, a2)
		}
		if o1 != o2 || a1 != a2 {
			if bytes.Equal(ownerSigningInput(o1, a1), ownerSigningInput(o2, a2)) {
				t.Fatalf("two different owner claims sign the same bytes: (%q, %q) and (%q, %q)", o1, a1, o2, a2)
			}
		}
	})
}
