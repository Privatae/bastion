package main

// Machine ownership — who owns this box, said by someone with root on it.
//
// Chosen over binding the machine to an organisation identity and over a
// plain self-declared label: whoever can run root on the
// machine IS the owner. It proves exactly one thing honestly — someone with
// root asserted this — and that is the only true statement available on a
// sovereign network with no directory to appeal to. Binding to an org would
// import the external trust anchor the architecture exists to avoid.
//
// It is OPTIONAL. A machine with no claim works exactly as it does today: the
// host's bastion inspector simply shows no owner line. Where a claim exists it
// renders as a plain name beside "machine" and "platform" — it answers "whose
// box is this", nothing more. Never an authorization input; the moment
// something starts trusting it, it has become a credential a root user on any
// box can mint for themselves.
//
// The key lives beside the pairings, root-owned and 0600, and never leaves the
// machine. What travels is the owner name, the time, and a signature over both
// under this machine's key. The signature is not there to make the name
// authoritative — it is there so the name cannot be changed by editing the
// file, and so a key that CHANGES on a box that already had one is visible as a
// different machine answering.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ownerClaim is what travels on every pairing's heartbeat once claimed.
type ownerClaim struct {
	Owner     string `json:"owner"`      // the name root asserted
	ClaimedAt string `json:"claimed_at"` // RFC3339, when it was signed
	PublicKey string `json:"public_key"` // base64 ed25519 public key
	Signature string `json:"signature"`  // base64 sig over "<owner>\n<claimed_at>"
}

// ownerKeyPath is the machine's owner key: beside the pairings, but NOT inside
// pairings/ — it belongs to the box, not to any one host it serves.
func ownerKeyPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "owner.json"), nil
}

// ownerSigningInput is the exact byte sequence signed and verified. Kept in one
// function so the signer and any verifier cannot drift apart.
//
// Prefixed with a kind tag since 0.16.0: the anchor claim (anchor.go) is signed
// by this same key, and untagged inputs let one claim's bytes read as the
// other's. Claims signed by 0.14.0 (untagged) no longer verify and read as "no
// claim"; re-running claim-owner re-signs. Whether any installed box still
// carries an untagged claim is unverified: 0.14.0 was published, but
// claim-owner is a manual root step that few installs take.
func ownerSigningInput(owner, claimedAt string) []byte {
	return []byte("owner\n" + owner + "\n" + claimedAt)
}

type ownerFile struct {
	Owner      string `json:"owner"`
	ClaimedAt  string `json:"claimed_at"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Signature  string `json:"signature"`
}

// cmdClaimOwner writes the machine's owner claim. Root only: there is no
// authority above the box to ask, so the ability to run root here is what
// stands behind the name.
func cmdClaimOwner(owner string) error {
	if err := requireMachineAuthority("claim-owner"); err != nil {
		return err
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return errors.New("usage: privatae-bastion claim-owner <name>")
	}
	if err := claimNameOK(owner); err != nil {
		return fmt.Errorf("owner: %w", err)
	}
	f, err := writeOwnerClaim(owner)
	if err != nil {
		return err
	}
	fmt.Printf("owner claim signed for %q\n", owner)
	fmt.Printf("  key      %s\n", f.PublicKey)
	fmt.Printf("  claimed  %s\n", f.ClaimedAt)
	fmt.Println("  It travels on the next heartbeat to every host this machine serves,")
	fmt.Println("  and shows as the owner on this machine's card. It grants nothing.")
	return nil
}

// loadOrCreateOwnerKey returns the machine's key, creating it on first use.
//
// A machine keeps ONE key across re-claims — owner re-claims and anchor
// (re-)claims alike (anchor.go signs with this same key). Rotating it on every
// claim would make an ordinary rename indistinguishable from a different
// machine answering, which is the one signal a peer actually needs.
func loadOrCreateOwnerKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	path, err := ownerKeyPath()
	if err != nil {
		return nil, nil, err
	}
	if raw, e := os.ReadFile(path); e == nil {
		var prev ownerFile
		if json.Unmarshal(raw, &prev) == nil && prev.PrivateKey != "" {
			if b, e2 := base64.StdEncoding.DecodeString(prev.PrivateKey); e2 == nil && len(b) == ed25519.PrivateKeySize {
				priv := ed25519.PrivateKey(b)
				return priv.Public().(ed25519.PublicKey), priv, nil
			}
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate owner key: %w", err)
	}
	// Persist the key the moment it exists, even with no owner name yet (an
	// anchor claimed before any owner claim). Otherwise the next claim would
	// mint a second key and the anchor and owner claims would name different
	// machines. A key-only file is "no claim" to currentOwnerClaim (no owner).
	f := ownerFile{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write owner key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, nil, fmt.Errorf("install owner key: %w", err)
	}
	return pub, priv, nil
}

// writeOwnerClaim signs and installs the owner claim under the machine key
// (the file also carries the key). Shared by claim-owner and claim-anchor.
func writeOwnerClaim(owner string) (*ownerFile, error) {
	if err := claimNameOK(owner); err != nil {
		return nil, fmt.Errorf("owner: %w", err)
	}
	path, err := ownerKeyPath()
	if err != nil {
		return nil, err
	}
	pub, priv, err := loadOrCreateOwnerKey()
	if err != nil {
		return nil, err
	}
	claimedAt := time.Now().UTC().Format(time.RFC3339)
	sig := ed25519.Sign(priv, ownerSigningInput(owner, claimedAt))
	f := ownerFile{
		Owner:      owner,
		ClaimedAt:  claimedAt,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		Signature:  base64.StdEncoding.EncodeToString(sig),
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	// 0600: the private key is the claim. Written to a temp file and renamed so
	// a crash mid-write cannot leave a machine with a truncated key and no way
	// to prove anything.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return nil, fmt.Errorf("write owner claim: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("install owner claim: %w", err)
	}
	return &f, nil
}

// currentOwnerClaim reads the claim for the heartbeat. Returns nil when the box
// has never been claimed (the normal, supported state) or when the file is
// unreadable or malformed — an unverifiable claim must be ABSENT rather than
// half-reported, so a host never shows "owned" off a corrupt file.
func currentOwnerClaim() *ownerClaim {
	path, err := ownerKeyPath()
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var f ownerFile
	if json.Unmarshal(raw, &f) != nil {
		return nil
	}
	if f.Owner == "" || f.ClaimedAt == "" || f.PublicKey == "" || f.Signature == "" {
		return nil
	}
	// Verify our OWN claim before sending it. A file edited by hand — the obvious
	// way to try to forge an owner name — fails here and is reported as no claim
	// at all, rather than travelling for the host to reject.
	pub, err := base64.StdEncoding.DecodeString(f.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), ownerSigningInput(f.Owner, f.ClaimedAt), sig) {
		return nil
	}
	return &ownerClaim{
		Owner:     f.Owner,
		ClaimedAt: f.ClaimedAt,
		PublicKey: f.PublicKey,
		Signature: f.Signature,
	}
}
