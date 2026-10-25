//go:build !windows

// Tagged !windows like anchor_test.go, whose box helpers (setupBox, driveOp,
// signTerms) it uses; beatnow_test.go runs the signal and the loop everywhere.

package main

import (
	"crypto/ed25519"
	"os"
	"testing"
	"time"
)

// optest v0.16.145: an approval left every Host on the machine reading
// "pending" until the next 60-second beat. A grant that flips a pairing active,
// and a revoke, ask every pairing to beat now; a refused grant, and a re-sync
// of a pairing that is already active, change no state and ask nothing.
func TestPairingStateChangeBeatsEveryHost(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	hn, _ := os.Hostname()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	kick, stop := subscribeBeatNow()
	defer stop()

	_, otherPriv, _ := ed25519.GenerateKey(nil)
	terms, sig := signTerms(t, otherPriv, grantTerms(tMember, []string{"observe"}, future))
	if _, _, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 126 {
		t.Fatalf("a grant under another key must be refused (126): %d", code)
	}
	if signalled(kick, 100*time.Millisecond) {
		t.Fatal("a refused grant asked for a beat")
	}

	terms, sig = signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("a good grant must be accepted: exit %d, %s", code, errOut)
	}
	if loadState(t, tMember) != pairingActive {
		t.Fatal("grant_sync must flip the pairing active")
	}
	if !signalled(kick, time.Second) {
		t.Fatal("a grant that flipped a pairing active did not ask every pairing to beat now")
	}

	terms, sig = signTerms(t, priv, grantTerms(tMember, []string{"observe", "dcn"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("a re-sync of an active pairing must be accepted: exit %d, %s", code, errOut)
	}
	if signalled(kick, 100*time.Millisecond) {
		t.Fatal("a re-sync that changed no pairing state asked for a beat")
	}

	terms, sig = signTerms(t, priv, map[string]any{"anchor": tAnchor, "issued_at": time.Now().UTC().Format(time.RFC3339),
		"kind": "pairing_revoke", "server": hn, "subject": tMember})
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_drop", []string{tMember, terms, sig}); code != 0 {
		t.Fatalf("a good revoke must be accepted: %d %s", code, errOut)
	}
	if loadState(t, tMember) != pairingRevoked {
		t.Fatal("grant_drop must mark the pairing revoked")
	}
	if !signalled(kick, time.Second) {
		t.Fatal("a revoke did not ask every pairing to beat now")
	}
}
