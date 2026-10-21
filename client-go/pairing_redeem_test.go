//go:build !windows

package main

// pairing_redeem — the anchor host hands this box a token minted by
// ANOTHER host, and the box redeems it without anyone standing at the machine.
//
// The op does a network redeem against the platform's enrolment ingress on the
// happy path, so what is pinned here is everything AROUND that: who may call
// it, where it refuses to run at all, and that a bad token costs no call.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeToken is a well-formed token for a host that does not exist. Well-formed
// matters: a malformed one is refused before the network, so it could never
// prove the gates below run first.
func fakeToken(handle string) string {
	return "skb_" + base64.RawURLEncoding.EncodeToString([]byte(handle+".secret-that-is-not-real"))
}

// THE GATE IS THE NAME. handleMgmtConnFor refuses any op called "pairing_*"
// from a pairing that is not the anchor, before the handler runs (mgmt.go). Had
// this op been called anything else it would have fallen through to capsAllow,
// where opFamily returns "" for an unknown op and "" means ALLOW — i.e. it
// would have been served to every member pairing on the box. This test is the
// one that fails if someone renames it.
func TestPairingRedeemIsAnchorOnly(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference", "observe", "dcn", "harness", "egress", "models"}, nil)

	_, errOut, code := driveOp(t, tMember, "pairing_redeem", []string{fakeToken("friend")})
	if code == 0 {
		t.Fatal("a MEMBER pairing redeemed a token — this op admits a host to the machine")
	}
	if !strings.Contains(errOut, "anchor") {
		t.Fatalf("the refusal must say it is the anchor's op, got %q", errOut)
	}
	// Belt: even a member holding EVERY caps family is refused, because the gate
	// is not a caps family a grant could name.
	//
	// This used to assert opFamily("pairing_redeem") == "", which was the right
	// claim under the old contract, where "" was the only way to say "no grant
	// reaches this". It is not the right SHAPE of the claim, and it is no
	// longer true: capsAllowIn default-denies an op in no
	// family, so leaving this one unclassified would refuse it everywhere rather
	// than only for members, and opFamily now answers "anchor" for the whole
	// pairing_* prefix. The security claim is unchanged and is asserted directly
	// below — the family must be one NO grant can carry, i.e. absent from
	// allCaps. Same form TestStepupKindFamilies uses for the stepup floor.
	fam := opFamily("pairing_redeem")
	if fam == "" {
		t.Fatal("pairing_redeem is in no caps family at all — under default-deny that " +
			"refuses it for every pairing including the anchor's own lane, and it hides " +
			"the op from the classification sweep")
	}
	for _, c := range allCaps {
		if c == fam {
			t.Fatalf("pairing_redeem resolved to caps family %q, which IS in allCaps %v — "+
				"an anchor could grant it to a member, and this op admits a host to the "+
				"machine. It must be gated by the anchor-only prefix, not by a grantable "+
				"family", fam, allCaps)
		}
	}
	// And the anonymous lane (no pairing identity) is refused too.
	if _, _, code := driveOp(t, "", "pairing_redeem", []string{fakeToken("friend")}); code == 0 {
		t.Fatal("an anonymous mgmt connection redeemed a token")
	}
}

// The op must be answerable at all — i.e. it is in the table the dispatcher
// reads, so it can never be "gated but unimplemented" or the reverse.
func TestPairingRedeemIsInTheOpTable(t *testing.T) {
	if _, ok := handlerOps["pairing_redeem"]; !ok {
		t.Fatal("pairing_redeem is not in handlerOps — the dispatcher would fall through to the exec allowlist")
	}
	found := false
	for _, op := range mgmtOpVocabulary() {
		found = found || op == "pairing_redeem"
	}
	if !found {
		t.Fatal("pairing_redeem is missing from the enforcing report's op vocabulary — " +
			"the box would answer an op it does not declare")
	}
}

// A LOCAL bastion serves ONE host and cannot be anchored (claim-anchor refuses
// outside networked mode), so a second host arriving through a remote op is
// exactly what that rule exists to prevent.
func TestPairingRedeemRefusedOnALocalBox(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := modePath()
	if err := os.WriteFile(p, []byte(`{"mode":"local"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writePairing(t, tAnchor)
	_, errOut, code := driveOp(t, tAnchor, "pairing_redeem", []string{fakeToken("friend")})
	if code == 0 {
		t.Fatal("a local bastion redeemed a token handed to it remotely")
	}
	if !strings.Contains(errOut, "anchor") {
		t.Fatalf("the refusal must explain it needs an anchor, got %q", errOut)
	}
}

// An unanchored NETWORKED box serves nothing at all, on every lane.
func TestPairingRedeemRefusedOnAnUnanchoredNetworkedBox(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := modePath()
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writePairing(t, tAnchor)
	_, errOut, code := driveOp(t, tAnchor, "pairing_redeem", []string{fakeToken("friend")})
	if code == 0 {
		t.Fatal("an unanchored networked box redeemed a token")
	}
	if !strings.Contains(errOut, "NOT ANCHORED") {
		t.Fatalf("the refusal must be the unanchored one, got %q", errOut)
	}
}

// A malformed token is refused before any network call, and the arguments are
// checked before that.
func TestPairingRedeemRefusesABadToken(t *testing.T) {
	setupBox(t)
	if _, _, code := driveOp(t, tAnchor, "pairing_redeem", []string{}); code == 0 {
		t.Fatal("pairing_redeem with no token must fail")
	}
	_, errOut, code := driveOp(t, tAnchor, "pairing_redeem", []string{"not-a-token"})
	if code == 0 {
		t.Fatal("a malformed token must be refused")
	}
	if !strings.Contains(errOut, "malformed") {
		t.Fatalf("got %q", errOut)
	}
	// The secret half of a token must never come back out in an error.
	if strings.Contains(errOut, "secret-that-is-not-real") {
		t.Fatal("the token's secret appeared in a refusal")
	}
}

// The remote redeem goes through pairWithToken, so it inherits EVERY wall that
// stands in front of `privatae-bastion pair` — and both of the ones that can
// fire here fire BEFORE the network call, which is what keeps a refusal from
// burning a single-use token (pair.go: the singleton guard is first, conflicts
// are checked pre-redeem). Whichever of the two this machine hits, the
// handler's own reporting is the same, and that is what this pins: the refusal
// and its audit line carry the HANDLE, never the secret.
func TestPairingRedeemRefusalsHappenBeforeTheRedeemCallGoesOut(t *testing.T) {
	setupBox(t) // tAnchor is paired on this box; its handle is "anchor"
	out, errOut, code := driveOp(t, tAnchor, "pairing_redeem", []string{fakeToken(handleOf(tAnchor))})
	if code == 0 {
		t.Fatalf("redeeming a token for a host already paired must be refused, got out=%q", out)
	}
	preRedeem := strings.Contains(errOut, "already paired") || // checkPairConflict
		strings.Contains(errOut, "another bastion owns this machine") // singletonGuardForPair
	if !preRedeem {
		t.Fatalf("the refusal did not come from one of the pre-redeem walls — a token may have "+
			"been burned on a call that was always going to fail: %q", errOut)
	}
	if strings.Contains(errOut, "secret-that-is-not-real") {
		t.Fatal("the token's secret appeared in a refusal")
	}
	d, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(d, "pairing_audit.jsonl"))
	if err != nil {
		t.Fatalf("the refusal wrote no audit line: %v", err)
	}
	if strings.Contains(string(raw), "secret-that-is-not-real") {
		t.Fatalf("the pairing audit recorded the token secret: %s", raw)
	}
	if !strings.Contains(string(raw), `"subject": "anchor"`) &&
		!strings.Contains(string(raw), `"subject":"anchor"`) {
		t.Fatalf("the audit line must name the handle it was asked to redeem: %s", raw)
	}
}

// A host the anchor REVOKED can be shared with again without anyone walking to
// the machine — `pair` needs --replace to touch an existing pairing, and a
// revoked one is still existing, so the plain path answered "already paired"
// and the second share needed a terminal.
func TestRedeemReopensARevokedPairingButNeverRotatesALiveOne(t *testing.T) {
	setupBox(t)
	writePairingState(t, tMember, pairingRevoked)
	if !revokedPairingFor(handleOf(tMember)) {
		t.Fatal("a revoked pairing must be re-openable by a fresh token")
	}
	if !revokedPairingFor(tMember) {
		t.Fatal("the full host_name must match too — pairingFor takes either")
	}
	// A live pairing is NOT replaceable through this lane: rotating a serving
	// host's credentials is not what a sharing offer asked for.
	for _, state := range []string{pairingActive, pairingPending} {
		writePairingState(t, tMember, state)
		if revokedPairingFor(handleOf(tMember)) {
			t.Fatalf("a %s pairing must not be replaceable through the remote redeem", state)
		}
	}
	// And an unknown handle is not a replace either — it is a new pairing.
	if revokedPairingFor("stranger") {
		t.Fatal("an unknown handle must not read as a replace")
	}
}
