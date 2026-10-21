//go:build !windows

package main

import (
	"path/filepath"
	"testing"
)

// TestPairAnchorsANetworkedMachineToItsFirstHost: on a networked machine with
// no anchor, the first pairing anchors it (as claim-anchor with no token
// would), so a server is not left refusing everything until claim-anchor is
// run by hand. A local machine,
// an already anchored one, a second pairing, or a caller without machine
// authority are left as they were.
func TestPairAnchorsANetworkedMachineToItsFirstHost(t *testing.T) {
	held := true
	old := machineAuthorityHeld
	machineAuthorityHeld = func() bool { return held }
	t.Cleanup(func() { machineAuthorityHeld = old })

	box := func(t *testing.T, networked bool) {
		t.Helper()
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
		if networked {
			if err := setBoxMode(modeNetworked); err != nil {
				t.Fatal(err)
			}
		}
	}
	only := func(t *testing.T, host string) (*Config, []*Config) {
		t.Helper()
		all, err := loadPairings()
		if err != nil {
			t.Fatal(err)
		}
		return pairingFor(all, host), all
	}

	t.Run("networked, no anchor, first pairing: anchored and active", func(t *testing.T) {
		held = true
		box(t, true)
		writePairingState(t, tMember, pairingPending)
		cfg, all := only(t, tMember)
		anchored, err := anchorFirstNetworkedPairing(cfg, all)
		if err != nil || !anchored {
			t.Fatalf("the first pairing on a networked box must anchor it: anchored=%v err=%v", anchored, err)
		}
		if a := currentAnchor(); a == nil || a.AnchorHost != tMember {
			t.Fatalf("anchor = %+v, want %s", a, tMember)
		}
		if got := loadState(t, tMember); got != pairingActive {
			t.Fatalf("the anchor never waits on itself: state %q", got)
		}
		// The installer's claim-anchor after it finds the work done.
		if err := cmdClaimAnchor("", false, "", ""); err != nil {
			t.Fatalf("claim-anchor after pair must succeed: %v", err)
		}
	})

	t.Run("local machine: not anchored", func(t *testing.T) {
		held = true
		box(t, false)
		writePairing(t, tMember)
		cfg, all := only(t, tMember)
		if anchored, err := anchorFirstNetworkedPairing(cfg, all); anchored || err != nil {
			t.Fatalf("a local machine must not be anchored: %v %v", anchored, err)
		}
		if currentAnchor() != nil {
			t.Fatal("a local machine has no anchor")
		}
	})

	t.Run("already anchored: a new pairing stays pending", func(t *testing.T) {
		held = true
		box(t, true)
		writePairing(t, tAnchor)
		if err := writeAnchor("Acme", tAnchor); err != nil {
			t.Fatal(err)
		}
		writePairingState(t, tMember, pairingPending)
		cfg, all := only(t, tMember)
		if anchored, err := anchorFirstNetworkedPairing(cfg, all); anchored || err != nil {
			t.Fatalf("an anchored machine must not be re-anchored: %v %v", anchored, err)
		}
		if a := currentAnchor(); a == nil || a.AnchorHost != tAnchor {
			t.Fatalf("anchor moved: %+v", a)
		}
		if got := loadState(t, tMember); got != pairingPending {
			t.Fatalf("a later host waits for the anchor's approval: state %q", got)
		}
	})

	t.Run("a second pairing on an unanchored machine: left for claim-anchor --host", func(t *testing.T) {
		held = true
		box(t, true)
		writePairing(t, tAnchor)
		writePairingState(t, tMember, pairingPending)
		cfg, all := only(t, tMember)
		if anchored, err := anchorFirstNetworkedPairing(cfg, all); anchored || err != nil {
			t.Fatalf("with two pairings the person picks the anchor: %v %v", anchored, err)
		}
	})

	t.Run("no machine authority: not anchored", func(t *testing.T) {
		held = true
		box(t, true) // set-mode networked itself needs machine authority
		writePairingState(t, tMember, pairingPending)
		held = false
		cfg, all := only(t, tMember)
		if anchored, err := anchorFirstNetworkedPairing(cfg, all); anchored || err != nil {
			t.Fatalf("without machine authority nothing is anchored: %v %v", anchored, err)
		}
	})
}
