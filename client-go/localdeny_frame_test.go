//go:build !windows

package main

// The local switch, driven through the REAL management frame path — which is
// what makes these unix-only: driveOp lives in anchor_test.go, tagged !windows
// because the pairing fixtures under it are.
//
// Kept out of localdeny_test.go so that file keeps running on Windows. The
// invariant tests there hold the same rule from the predicate's side and do not
// need a frame.

import (
	"os"
	"strings"
	"testing"
)

// ── the box most of them actually are ───────────────────────────────────────

// THE SWITCH HAS TO WORK ON A LOCAL BASTION, and for a while it did not.
//
// It is the same shape as three earlier findings — the claim asserted at a
// layer nothing wires to. The deny check
// sat below capsAllow's `a == nil` return, and handleMgmtConnFor only called
// capsAllow at all when the box was anchored. So on a machine with no anchor —
// one person, one host, which is what a local bastion IS — the page offered the
// switch, wrote the denial, answered "can no longer read your files" and tagged
// the card "switched off by you", while every op went on being served.
//
// A security control that reports success and does nothing is worse than no
// control: the person stops watching the thing they think they turned off.
//
// Driven through the real predicate AND the real frame path, because the bug
// lived in the gap between them: capsAllow was correct in isolation and was not
// being asked.
func TestTheSwitchWorksOnAnUnanchoredLocalBastion(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"
	givenPairing(t, host, pairingActive)

	// The fixture IS the case: no anchor, no mode file.
	if currentAnchor() != nil {
		t.Fatal("fixture is anchored — this test is about the box that is not")
	}
	if boxMode() != modeLocal {
		t.Fatalf("fixture mode is %q, want local", boxMode())
	}
	if why := capsAllow(host, "dcn_list"); why != "" {
		t.Fatalf("a local bastion refused dcn_list before anything was switched off: %q", why)
	}

	if err := localDenySet(host, "dcn", true); err != nil {
		t.Fatal(err)
	}

	for _, op := range []string{"dcn_list", "dcn_search", "ctx_get", "backup_fetch"} {
		if why := capsAllow(host, op); why == "" {
			t.Errorf("%s is STILL ALLOWED after the person at this machine switched "+
				"dcn off. The page told them it would be refused.", op)
		}
	}
	// The predicate is not the wall — the frame path is. Ask the thing a host
	// actually reaches.
	_, errOut, code := driveOp(t, host, "dcn_list", nil)
	if code != 126 {
		t.Errorf("dcn_list through the real mgmt path exited %d, want 126 (refused)", code)
	}
	if !strings.Contains(errOut, "switched off on this machine") {
		t.Errorf("the host was not told WHY it was refused: %q", errOut)
	}
	// And nothing else moved: a switch that took more than it was asked for
	// would be its own incident.
	if why := capsAllow(host, "observe:host"); why != "" {
		t.Errorf("switching off dcn also refused observe: %q", why)
	}
	if why := capsAllow(host, "session:open"); why != "" {
		t.Errorf("switching off dcn also refused session: %q", why)
	}
}

// AND AN UNANCHORED NETWORKED BOX STILL REFUSES EVERYTHING, with the refusal
// that names the fix. Moving the deny check above the anchor lookup must not
// put a deny-list sentence in front of the one a person can act on.
func TestAnUnanchoredNetworkedBoxStillSaysItIsUnanchored(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"
	givenPairing(t, host, pairingActive)
	// The mode file directly rather than setBoxMode, which needs machine
	// authority (privilege.go). This suite is run as an unprivileged user as
	// well as root — and that is the run that caught the last predicate to be
	// wrong in this function (anchor.go:491-493), so it has to stay runnable
	// there.
	p, err := modePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if boxMode() != modeNetworked {
		t.Fatalf("fixture mode is %q, want networked", boxMode())
	}
	if err := localDenySet(host, "dcn", true); err != nil {
		t.Fatal(err)
	}
	why := capsAllow(host, "dcn_list")
	if why == "" {
		t.Fatal("an unanchored NETWORKED box allowed an op")
	}
	if !strings.Contains(why, "NOT ANCHORED") {
		t.Errorf("the refusal is %q — a person whose box serves nothing needs the "+
			"sentence that tells them to anchor it, not one about a switch they set", why)
	}
}
