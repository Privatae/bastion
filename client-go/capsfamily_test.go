//go:build !windows

// Uses setupBox / driveOp / writePairingState / signTerms / grantTerms /
// tAnchor / tMember from anchor_test.go, which are unix-only. buildtags_test.go
// enforces the tag.

package main

// The caps ceiling cannot be reached by an op nobody classified.
//
// capsAllow used to return "" — allowed — for any op opFamily did not know, so
// a member pairing holding any verified grant could be asked for it whatever
// the anchor had granted. The tests here are the standing guard against that
// returning: one for the DEFAULT (an unclassified op is refused), and one for
// the CLASS (no op on this lane is unclassified in the first place).

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// EVERY op this box will answer must map to a family. This is the gate that
// stops the next op added to either table from silently failing open: without
// it, a new handler is reachable by any pairing holding any grant, and nothing
// anywhere says so out loud.
//
// Both tables, because they are two different doors into the same lane —
// handlerOps is the no-exec handlers, p8AllowedOps the shell allowlist — and
// handleMgmtConnFor puts the same ceiling in front of both.
func TestEveryOpOnTheMgmtLaneHasAFamily(t *testing.T) {
	check := func(table string, ops []string) {
		t.Helper()
		var unclassified []string
		for _, op := range ops {
			if opFamily(op) == "" {
				unclassified = append(unclassified, op)
			}
		}
		if len(unclassified) > 0 {
			t.Fatalf("these %s ops are in NO capability family:\n    %s\n"+
				"capsAllowIn default-denies an unclassified op, so each of these is refused for\n"+
				"every member pairing on an anchored box — including ones the anchor meant to\n"+
				"grant. Give each a family in opFamily (anchor.go). If the op genuinely\n"+
				"authorizes nothing, say so explicitly with capsFamilyNone at its gate rather\n"+
				"than by leaving it unclassified.", table, strings.Join(unclassified, "\n    "))
		}
	}
	handlers := make([]string, 0, len(handlerOps))
	for k := range handlerOps {
		handlers = append(handlers, k)
	}
	check("handlerOps", handlers)

	p8 := make([]string, 0, len(p8AllowedOps))
	for k := range p8AllowedOps {
		p8 = append(p8, k)
	}
	check("p8AllowedOps", p8)
	check("sessionOps", sessionOps)

	// And the check must not have gone vacuous: an op nobody has classified
	// still has no family, or the assertion above proves nothing.
	if opFamily("some_future_op") != "" {
		t.Fatal("opFamily now answers for an unknown op — the check above asserts nothing")
	}
}

// The DEFAULT itself: an op in no family is refused, and the refusal says so
// rather than quoting a family it does not have.
func TestUnclassifiedOpIsDefaultDenied(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe", "dcn", "session"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}

	// A broadly-granted member is still refused an op in no family.
	why := capsAllow(tMember, "some_op_in_no_family")
	if why == "" {
		t.Fatal("an op in no capability family must be refused on an anchored box")
	}
	if !strings.Contains(why, "no capability family") {
		t.Fatalf("the refusal must say the op is in no family, got %q", why)
	}

	// The ANCHOR pairing is unaffected: it returns before the family check,
	// because its user is the admin of this machine.
	if why := capsAllow(tAnchor, "some_op_in_no_family"); why != "" {
		t.Fatalf("the anchor pairing must stay unconstrained: %s", why)
	}

	// And a LOCAL box gates nothing at all — capsAllow returns on a nil anchor
	// long before the family check, which is what keeps every local
	// bastion unchanged by this.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if boxMode() != modeLocal {
		t.Fatalf("a box with no mode file must be local, got %s", boxMode())
	}
	if why := capsAllow(tMember, "some_op_in_no_family"); why != "" {
		t.Fatalf("a LOCAL bastion must not be gated by this: %s", why)
	}
}

// stepupDetails builds the b64 details argument for one request kind.
func stepupDetails(t *testing.T, d map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// A step-up is gated on the family of the thing being APPROVED.
//
// The bypass this closes: a pairing granted only "observe" could raise a
// step-up for any of the four kinds that DO authorize a capability of this
// machine — a DCN store grant or move plan, a root shell, a model download —
// with a purpose and details of its own choosing, putting the prompt in front
// of the user. It could not self-approve. The fifth kind, critical_action,
// stays reachable by any pairing holding a verified grant and that is
// deliberate, not a leftover: the box is not the enforcer there (the platform
// executes once it sees an approval), the second factor is per pairing dir, and
// approving one consumes no capability of this machine — so there is no family
// that could honestly be named for it. See stepupKindFamily.
//
// The regression it avoids: gating all five as "dcn" would stop a session-only
// pairing raising the step-up session:root requires.
func TestStepupIsGatedOnTheApprovedFamily(t *testing.T) {
	// observe only: every kind refused, including the one it might be thought
	// to be entitled to by holding a grant at all.
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	for _, kind := range []string{"dcn_store_grant", "dcn_move_plan", "session_root", "model_pull"} {
		args := []string{"p", stepupDetails(t, map[string]any{"kind": kind})}
		_, errOut, code := driveOp(t, tMember, "stepup_request", args)
		if code != 126 || !strings.Contains(errOut, "caps") {
			t.Fatalf("an observe-only pairing must be refused a %s step-up: %d %s", kind, code, errOut)
		}
	}

	// session only: the root-shell step-up is its own lane's and must pass the
	// ceiling, while a dcn one is still refused.
	priv = setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig = signTerms(t, priv, grantTerms(tMember, []string{"session"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	args := []string{"p", stepupDetails(t, map[string]any{"kind": "session_root"})}
	if _, errOut, _ := driveOp(t, tMember, "stepup_request", args); strings.Contains(errOut, "caps") {
		t.Fatalf("a session pairing must pass the ceiling for a session_root step-up: %s", errOut)
	}
	args = []string{"p", stepupDetails(t, map[string]any{"kind": "dcn_store_grant"})}
	if _, errOut, code := driveOp(t, tMember, "stepup_request", args); code != 126 ||
		!strings.Contains(errOut, "caps") {
		t.Fatalf("a session pairing must still be refused a dcn step-up: %d %s", code, errOut)
	}

	// models only: the model_pull step-up passes, a root shell does not.
	priv = setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig = signTerms(t, priv, grantTerms(tMember, []string{modelGateOpFamily}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	args = []string{"p", stepupDetails(t, map[string]any{"kind": "model_pull"})}
	if _, errOut, _ := driveOp(t, tMember, "stepup_request", args); strings.Contains(errOut, "caps") {
		t.Fatalf("a models pairing must pass the ceiling for a model_pull step-up: %s", errOut)
	}
	args = []string{"p", stepupDetails(t, map[string]any{"kind": "session_root"})}
	if _, errOut, code := driveOp(t, tMember, "stepup_request", args); code != 126 ||
		!strings.Contains(errOut, "caps") {
		t.Fatalf("a models pairing must be refused a root-shell step-up: %d %s", code, errOut)
	}
}

// The kind→family map is the whole gate, so it is asserted directly: a wrong
// entry here is a bypass that no amount of frame-level testing would name.
func TestStepupKindFamilies(t *testing.T) {
	for kind, want := range map[string]string{
		"dcn_store_grant": "dcn",
		"dcn_move_plan":   "dcn",
		"session_root":    "session",
		"model_pull":      modelGateOpFamily,
		// The box is not the enforcer for a platform critical action, so no
		// capability of THIS machine is being authorized and there is no family
		// to name. Holding a verified grant is the ceiling.
		"critical_action": capsFamilyNone,
		// Anything purposeFromDetails would refuse anyway.
		"":             capsFamilyNone,
		"made_up_kind": capsFamilyNone,
	} {
		if got := stepupKindFamily(kind); got != want {
			t.Errorf("stepupKindFamily(%q) = %q, want %q", kind, got, want)
		}
	}
	// Every kind purposeFromDetails accepts must be mapped here, or a real
	// approval flow is refused for a pairing that should hold it. The list is
	// the switch in purposeFromDetails (stepup.go).
	for _, kind := range []string{"dcn_store_grant", "dcn_move_plan", "session_root",
		"critical_action", "model_pull"} {
		fam := stepupKindFamily(kind)
		if fam == "" {
			t.Fatalf("kind %q maps to the empty family, which default-denies every "+
				"pairing including ones that should hold it", kind)
		}
		if fam == capsFamilyNone {
			continue
		}
		found := false
		for _, c := range allCaps {
			found = found || c == fam
		}
		if !found {
			t.Fatalf("kind %q maps to family %q, which is not in allCaps %v — ungrantable, "+
				"so this approval flow could never be opened for any pairing", kind, fam, allCaps)
		}
	}
}

// The local UI decides whether to show a family as HELD by probing capsAllow
// with one representative op (uigiven.go:484). Under default-deny an
// unclassified probe reads as "not held" for every pairing, so the machine's
// own admin page would quietly show a family the pairing does have as absent.
// The probes are all classified today; this keeps a rename from changing that.
func TestEveryUIProbeIsClassified(t *testing.T) {
	for _, f := range uiGivenFamilies {
		fam := opFamily(f.Probe)
		if fam == "" {
			t.Fatalf("the %q family probes with %q, which is in no capability family — "+
				"capsAllow default-denies it, so this family would read as NOT HELD on the "+
				"local UI for every pairing that actually holds it", f.Name, f.Probe)
		}
		if fam != f.Name {
			t.Fatalf("the %q family probes with %q, which resolves to family %q — the probe "+
				"must test its OWN family or the page reports the wrong one", f.Name, f.Probe, fam)
		}
	}
}
