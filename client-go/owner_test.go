package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// A machine with no claim reports none. This is the NORMAL state, not an error:
// claim-owner is optional and an unclaimed box must work exactly as before.
func TestNoClaimReportsNothing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if got := currentOwnerClaim(); got != nil {
		t.Fatalf("an unclaimed machine must report no owner, got %+v", got)
	}
	body := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if contains(body, "owner_claim") {
		t.Errorf("heartbeat carried an owner_claim on an unclaimed machine:\n%s", body)
	}
}

// writeClaim forges a claim file directly (the real one needs root), signing it
// the same way cmdClaimOwner does so the verify path sees a genuine claim.
func writeClaim(t *testing.T, owner, claimedAt string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, ownerSigningInput(owner, claimedAt))
	f := ownerFile{
		Owner:      owner,
		ClaimedAt:  claimedAt,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		Signature:  base64.StdEncoding.EncodeToString(sig),
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	p, err := ownerKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestValidClaimTravelsOnTheHeartbeat(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writeClaim(t, "Acme IT", "2026-09-07T12:00:00Z")

	got := currentOwnerClaim()
	if got == nil {
		t.Fatal("a validly signed claim must be reported")
	}
	if got.Owner != "Acme IT" {
		t.Errorf("owner = %q, want %q", got.Owner, "Acme IT")
	}
	body := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if !contains(body, "owner_claim") || !contains(body, "Acme IT") {
		t.Errorf("heartbeat did not carry the owner claim:\n%s", body)
	}
	// The PRIVATE key must never leave the machine — it IS the claim.
	if contains(body, got.PublicKey) && contains(body, "private_key") {
		t.Errorf("heartbeat carried a private_key field:\n%s", body)
	}
}

// THE ATTACK THIS GUARDS: hand-editing owner.json to a different name. The file
// is 0600 root-owned, but a root user editing their own box is exactly who this
// is meant to be honest about — and the signature is over the name, so a renamed
// claim no longer verifies. It must then report NOTHING rather than travelling
// for the host to reject: an unverifiable claim must never look like a claim.
func TestTamperedOwnerNameIsNotReported(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writeClaim(t, "Acme IT", "2026-09-07T12:00:00Z")

	p, _ := ownerKeyPath()
	raw, _ := os.ReadFile(p)
	var f ownerFile
	_ = json.Unmarshal(raw, &f)
	f.Owner = "Someone Else" // signature still covers "Acme IT"
	b, _ := json.MarshalIndent(f, "", "  ")
	_ = os.WriteFile(p, b, 0o600)

	if got := currentOwnerClaim(); got != nil {
		t.Fatalf("a tampered owner name must not be reported, got %+v", got)
	}
	body := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if contains(body, "Someone Else") {
		t.Errorf("a forged owner name reached the heartbeat:\n%s", body)
	}
}

// A truncated or malformed file is "no claim", never a crash and never a
// half-reported owner.
func TestMalformedClaimIsNoClaim(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, err := ownerKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	for _, junk := range []string{"", "{", `{"owner":"x"}`, `{"owner":"x","claimed_at":"y","public_key":"!!","signature":"!!"}`} {
		if err := os.WriteFile(p, []byte(junk), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := currentOwnerClaim(); got != nil {
			t.Errorf("malformed claim %q was reported as %+v", junk, got)
		}
	}
}

// claim-owner refuses without root — running as root IS the proof, so a claim
// minted without it would attest nothing. As root, the same test drives the
// command for real instead of skipping: whichever way this suite runs, one of
// the two halves exercises cmdClaimOwner rather than only its helpers.
func TestClaimOwner(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if os.Geteuid() != 0 {
		if err := cmdClaimOwner("Acme IT"); err == nil {
			t.Fatal("claim-owner must refuse when not root")
		}
		if got := currentOwnerClaim(); got != nil {
			t.Fatal("a refused claim must not have been written")
		}
		return
	}

	if err := cmdClaimOwner("Acme IT"); err != nil {
		t.Fatalf("claim-owner as root: %v", err)
	}
	got := currentOwnerClaim()
	if got == nil || got.Owner != "Acme IT" {
		t.Fatalf("the signed claim did not round-trip: %+v", got)
	}
	if got.Signature == "" || got.PublicKey == "" || got.ClaimedAt == "" {
		t.Fatalf("claim is missing a field: %+v", got)
	}

	// The key file must not be world-readable — the private key IS the claim.
	p, _ := ownerKeyPath()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("owner key mode = %o, want 600", st.Mode().Perm())
	}

	// Re-claiming under a new name KEEPS the machine's key. Rotating it would
	// make an ordinary rename indistinguishable from a different machine
	// answering — the one signal a peer actually needs from this.
	first := got.PublicKey
	if err := cmdClaimOwner("Acme IT (EU)"); err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	again := currentOwnerClaim()
	if again == nil || again.Owner != "Acme IT (EU)" {
		t.Fatalf("re-claim did not take: %+v", again)
	}
	if again.PublicKey != first {
		t.Errorf("re-claiming rotated the machine key (%s -> %s); a rename must not look like a different machine",
			first, again.PublicKey)
	}
	if again.Signature == got.Signature {
		t.Error("the signature did not change with the owner name")
	}
}
