package main

// The local switch (localdeny.go). One invariant matters more than every other
// property here, and it is asserted by driving the REAL gate over the REAL op
// vocabulary rather than by reasoning about the code:
//
//	A LOCAL SWITCH CAN ONLY EVER REMOVE REACH.
//
// If it could add any, the machine would become a place to escalate FROM, which
// inverts the product. So the test below runs every op this box answers,
// against every capability family, with the switch on and off, and fails if any
// combination is allowed with the switch that was refused without it.

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// anchoredBox is the state capsAllow needs: a real anchor with its key pinned,
// and a REAL SIGNED grant for `self`. It reuses the given page's own fixtures
// (uigiven_test.go) rather than hand-writing records, because capsAllow reads
// them through verifyAnchorRecord — an unsigned stand-in would be refused for
// the wrong reason and every assertion below would pass without testing
// anything.
func anchoredBox(t *testing.T, self string, caps []string) {
	t.Helper()
	uiTestConfigDir(t)
	priv := givenAnchoredBox(t)
	// The PAIRING as well as the grant. A signed grant for a host this machine
	// has never paired with is not a state that occurs — and localDenySet now
	// refuses a host it has not heard of, so a fixture without one was testing
	// against something the machine would never see.
	givenPairing(t, self, pairingActive)
	givenSignedGrant(t, priv, self, caps)
}

// ── the invariant ───────────────────────────────────────────────────────────

// THE SWITCH NEVER WIDENS. Every op, every family, both states.
//
// THE FIXTURE IS A NARROW GRANT, AND THAT IS THE WHOLE TEST. The first version
// used a pairing granted allCaps — so almost every op was ALLOWED before the
// switch, `before != ""` was false, and the widening branch never ran. A
// mutation that made the switch return "allowed" instead of a refusal passed
// it. A test for "X cannot turn a refusal into an allow" has to be run against
// things that are REFUSED.
func TestTheLocalSwitchCanOnlyEverRemoveReach(t *testing.T) {
	const self = "h1.host.privatae.ai"
	ops := mgmtOpVocabulary()
	if len(ops) < 10 {
		t.Fatalf("only %d ops in the vocabulary — this check has stopped seeing them", len(ops))
	}

	// One family granted. Every op outside it is refused, which is the
	// population this invariant is about.
	const granted = "observe"
	refusedBefore := 0
	for _, fam := range allCaps {
		for _, op := range ops {
			anchoredBox(t, self, []string{granted})

			before := capsAllow(self, op)
			if before == "" {
				continue // in-grant: nothing for the switch to widen
			}
			refusedBefore++
			if err := localDenySet(self, fam, true); err != nil {
				t.Fatalf("switching %s off: %v", fam, err)
			}
			if after := capsAllow(self, op); after == "" {
				t.Fatalf("op %q was REFUSED with %q switched on, and ALLOWED once it was "+
					"switched off.\n  before: %s\n"+
					"A local switch that turns a refusal into an allow is an escalation "+
					"path on the user's own machine.", op, fam, before)
			}
		}
	}
	if refusedBefore == 0 {
		t.Fatal("no op was refused by the narrow grant, so the widening branch never " +
			"ran and this test proved nothing — exactly how its first version passed " +
			"a mutation that made the switch widen")
	}
	t.Logf("%d refused (op, family) pairs checked for widening", refusedBefore)
}

// Turning it back on clears the denial and restores exactly what the GRANT
// allowed — never more. Driven against a pairing with a NARROW grant, so
// "restored" cannot be confused with "widened".
func TestTurningItBackOnRestoresTheGrantAndNotMore(t *testing.T) {
	const self = "h1.host.privatae.ai"
	narrow := []string{"observe"}
	anchoredBox(t, self, narrow)

	// An op outside the grant is refused before the switch is ever touched.
	outside := "harness:run"
	if capsAllow(self, outside) == "" {
		t.Fatalf("%s is allowed by a grant of %v, so this test cannot tell "+
			"restoring from widening", outside, narrow)
	}
	for _, fam := range allCaps {
		if err := localDenySet(self, fam, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, fam := range allCaps {
		if err := localDenySet(self, fam, false); err != nil {
			t.Fatal(err)
		}
	}
	if why := capsAllow(self, outside); why == "" {
		t.Error("after switching everything off and back on, an op the grant never " +
			"included is allowed. Turning a switch back on must clear a local denial " +
			"and nothing else.")
	}
	// And the op the grant DID include works again.
	if why := capsAllow(self, "observe:agents"); why != "" {
		t.Errorf("an op inside the grant is still refused after switching back on: %s", why)
	}
}

// ── it applies to the anchor too ────────────────────────────────────────────

// ON A ONE-HOST MACHINE THE ONLY PAIRING IS THE ANCHOR. A switch that exempted
// it would be a button with no effect on exactly the computer this feature was
// asked for.
func TestTheSwitchAppliesToTheAnchorPairing(t *testing.T) {
	uiTestConfigDir(t)
	givenAnchoredBox(t)
	anchor := gAnchorHost
	if why := capsAllow(anchor, "dcn_search"); why != "" {
		t.Fatalf("the anchor pairing is refused before any switch: %s", why)
	}
	if err := localDenySet(anchor, "dcn", true); err != nil {
		t.Fatal(err)
	}
	why := capsAllow(anchor, "dcn_search")
	if why == "" {
		t.Error("the anchor host is exempt from the local switch. On a machine paired " +
			"to one host — which IS its anchor — that makes the control do nothing at " +
			"all, which is the case it was built for.")
	}
	if !strings.Contains(why, "switched off on this machine") {
		t.Errorf("the refusal does not say a person switched it off: %q", why)
	}
}

// ── failure directions ──────────────────────────────────────────────────────

// AN UNREADABLE DENY LIST BLOCKS NOTHING. A corrupt file must not stop the
// machine serving its host — that is a far worse outcome than a switch not
// taking effect, and the page reports the read error separately.
func TestAnUnreadableDenyListBlocksNothing(t *testing.T) {
	const self = "h1.host.privatae.ai"
	anchoredBox(t, self, allCaps)
	p, err := localDenyPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if why := capsAllow(self, "observe:agents"); why != "" {
		t.Errorf("a corrupt deny list refused an op: %q. Failing closed here means one "+
			"bad file stops this machine serving its host.", why)
	}
	// And it is reported rather than swallowed.
	if _, err := localDenyLoad(); err == nil {
		t.Error("the unreadable list was loaded without an error, so nothing can tell " +
			"the person their switches are not in effect")
	}
}

// A family this machine does not know is REFUSED rather than stored: a deny
// entry nothing will ever match is a switch that silently does nothing.
func TestAnUnknownCapabilityIsRefusedNotStored(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "h1.host.privatae.ai", pairingActive)
	err := localDenySet("h1.host.privatae.ai", "everything", true)
	if err == nil {
		t.Fatal("an unknown capability was accepted")
	}
	if !strings.Contains(err.Error(), "not a capability") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if got := localDenyFamilies("h1.host.privatae.ai"); len(got) != 0 {
		t.Errorf("it was stored anyway: %v", got)
	}
}

// Writing a fresh file over one that did not parse would discard whatever the
// person had already switched off.
func TestAnUnreadableListIsNotOverwritten(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "h1.host.privatae.ai", pairingActive)
	p, err := localDenyPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localDenySet("h1.host.privatae.ai", "dcn", true); err == nil {
		t.Error("a switch was written over a file that could not be read, silently " +
			"discarding whatever was already switched off")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "{not json" {
		t.Errorf("the unreadable file was replaced: %q", string(b))
	}
}

// The file names which hosts a person has cut off from what. Private.
func TestTheDenyListIsWrittenPrivate(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "h1.host.privatae.ai", pairingActive)
	if err := localDenySet("h1.host.privatae.ai", "dcn", true); err != nil {
		t.Fatal(err)
	}
	p, err := localDenyPath()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not carry the same meaning here")
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("local-deny.json is %o, want 600", got)
	}
}

// Switching one family off leaves the others alone.
func TestSwitchingOneFamilyOffLeavesTheRestAlone(t *testing.T) {
	const self = "h1.host.privatae.ai"
	anchoredBox(t, self, allCaps)
	if err := localDenySet(self, "dcn", true); err != nil {
		t.Fatal(err)
	}
	got := localDenyFamilies(self)
	want := []string{"dcn"}
	sort.Strings(got)
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("switched off = %v, want %v", got, want)
	}
	if why := capsAllow(self, "observe:agents"); why != "" {
		t.Errorf("switching dcn off also refused an observe op: %s", why)
	}
}

// A SWITCH CANNOT LIE BY TYPO. Deny-only means a bogus host is harmless to the
// gate — nothing matches it — but the page would answer "X can no longer read
// your files" about a host never paired here.
func TestSwitchingOffAHostThisMachineNeverHeardOfIsRefused(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "real.host.privatae.ai", pairingActive)

	err := localDenySet("typo.host.privatae.ai", "dcn", true)
	if err == nil {
		t.Fatal("a host this machine has never paired with was accepted, so the page " +
			"would confirm an action about a host that does not exist here")
	}
	if !strings.Contains(err.Error(), "no host called") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	// The real one still works, so this is a guard and not a wall.
	if err := localDenySet("real.host.privatae.ai", "dcn", true); err != nil {
		t.Errorf("a paired host was refused: %v", err)
	}
}
