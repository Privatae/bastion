//go:build !windows

package main

// Tagged !windows because it borrows setupBox and writePairingState from
// anchor_test.go, which is itself !windows — the repo guard
// (TestATestFileBorrowingAUnixFixtureCarriesTheTag) exists so a borrowed unix
// fixture cannot make `GOOS=windows go vet` red, and it caught exactly that
// when this test first landed untagged. The rest of the signing tests build
// their own fixtures and stay portable in baselinesign_test.go.

import "testing"

func TestAnAnchorPairingThatIsNotActiveDoesNotSign(t *testing.T) {
	// A REAL anchored box (setupBox claims tAnchor as the anchor), whose anchor
	// pairing is then revoked. The first version of this test never claimed an
	// anchor, so it exercised the unanchored branch and the mutation that made
	// the anchored branch ignore pairing state survived it.
	setupBox(t)
	writePairingState(t, tAnchor, pairingRevoked)
	if currentAnchor() == nil {
		t.Fatal("the fixture is not anchored, so this test proves nothing")
	}
	cfgs, err := loadPairings()
	if err != nil {
		t.Fatal(err)
	}
	signer, why := baselineSignerPairing(cfgs)
	if signer != nil {
		t.Fatalf("a revoked anchor pairing signed: %s", signer.HostName)
	}
	if why != baselineUnsignedAnchorGone {
		t.Fatalf("the reason must be the named constant, got %q", why)
	}
	// And the pending state is refused the same way.
	writePairingState(t, tAnchor, pairingPending)
	cfgs, _ = loadPairings()
	if signer, why := baselineSignerPairing(cfgs); signer != nil || why != baselineUnsignedAnchorGone {
		t.Fatalf("a pending anchor pairing must not sign: %v %q", signer, why)
	}
}
