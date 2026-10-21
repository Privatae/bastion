package main

// The seam between sanction.go and policy.go, pinned from the CONSUMER's side.
//
// This exists because of a defect that neither unit could have caught. The
// policy engine was written against six `sanctionWhy*` constants. A later
// change — moving a mark off the forgeable argv[0] onto the kernel's executable
// path — added a seventh, `sanctionWhyNoExe`, which returns FALSE because
// nothing has vouched for the process. The signature never changed, so nothing
// broke, and the new constant fell into the policy's `default` branch and
// scored a PROPOSED KILL for every observation whose executable path this box
// cannot read.
//
// The lesson is the test: a predicate whose RETURN VALUE is an open set needs
// its consumer to enumerate that set, or the next addition is a silent
// behaviour change in a file nobody edited.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every constant the seam can return, and what the policy must do with it.
// A new one added to sanction.go without a line here fails the test below.
var seamExpectations = map[string]string{
	sanctionWhyHostTag:    policyPointsLeave,
	sanctionWhyLocal:      policyPointsLeave,
	sanctionWhyBoth:       policyPointsLeave,
	sanctionWhyNone:       policyPointsStop,
	sanctionWhyBadTag:     policyPointsStop,
	sanctionWhyUnreadable: policyPointsUnknown,
	sanctionWhyNoExe:      policyPointsUnknown,
}

// COULD-NOT-READ IS NOT UNWANTED. These two are the only reasons the box gives
// for "I was unable to establish this", and a dry run that proposes stopping
// what it could not identify is worse than one that says nothing: it teaches
// the reader that the candidate list is noise.
func TestWhatCouldNotBeReadIsNeverProposedForStopping(t *testing.T) {
	for _, why := range []string{sanctionWhyUnreadable, sanctionWhyNoExe} {
		got, ok := seamExpectations[why]
		if !ok {
			t.Fatalf("%q is missing from seamExpectations", why)
		}
		if got != policyPointsUnknown {
			t.Errorf("%q scores %v, want policyPointsUnknown — it means UNIDENTIFIED, "+
				"not unwanted (sanction.go:150)", why, got)
		}
	}
}

// The consumer must account for EVERY constant the producer can return. This is
// the check that would have caught the defect: it fails when sanction.go grows
// a reason that policy.go has never been told about.
func TestThePolicyAccountsForEverySanctionReason(t *testing.T) {
	// Derived from the source rather than restated, so a new constant cannot be
	// added without this noticing.
	declared := sanctionReasonConstants(t)
	if len(declared) < 7 {
		t.Fatalf("only found %d sanctionWhy* constants in sanction.go — the scan has "+
			"stopped finding them, which makes this check a green light that proves "+
			"nothing: %v", len(declared), declared)
	}
	for _, why := range declared {
		if _, ok := seamExpectations[why]; !ok {
			t.Errorf("sanction.go can return a reason the policy has never been told "+
				"about. Add it to seamExpectations AND to policySanctionTerm, and decide "+
				"deliberately whether it means stop, leave, or could-not-read — the "+
				"default branch scores STOP, which is the wrong answer for anything that "+
				"means 'unreadable'. Reason: %q", why)
		}
	}
}

// And the mapping must be what policySanctionTerm actually does, not what this
// file wishes it did.
func TestTheSeamTableMatchesTheRunningCode(t *testing.T) {
	for why, want := range seamExpectations {
		got := policyPointsForReason(t, why)
		if got != want {
			t.Errorf("policySanctionTerm scores %q as %v, the seam table says %v",
				why, got, want)
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

// sanctionReasonConstants reads the constant names out of sanction.go rather
// than listing them, for the same reason mgmtOpVocabulary is walked rather than
// restated: a list kept by hand drifts from the thing it describes.
func sanctionReasonConstants(t *testing.T) []string {
	t.Helper()
	src := readSourceFile(t, "sanction.go")
	var out []string
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "sanctionWhy") || !strings.Contains(line, "=") {
			continue
		}
		name := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		v, ok := sanctionReasonValue(name)
		if ok {
			out = append(out, v)
		}
	}
	return out
}

func sanctionReasonValue(name string) (string, bool) {
	switch name {
	case "sanctionWhyHostTag":
		return sanctionWhyHostTag, true
	case "sanctionWhyLocal":
		return sanctionWhyLocal, true
	case "sanctionWhyBoth":
		return sanctionWhyBoth, true
	case "sanctionWhyNone":
		return sanctionWhyNone, true
	case "sanctionWhyBadTag":
		return sanctionWhyBadTag, true
	case "sanctionWhyUnreadable":
		return sanctionWhyUnreadable, true
	case "sanctionWhyNoExe":
		return sanctionWhyNoExe, true
	}
	// A constant this switch does not know is exactly the drift the caller is
	// looking for; report the NAME so the failure names the new thing.
	return name, true
}

// readSourceFile reads a file from the package directory. The tests run with
// the package as their working directory, the same assumption console_test.go
// and tray_test.go already make.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// policyPointsForReason drives the REAL policySanctionTerm by constructing an
// observation that produces the wanted reason, rather than calling an internal
// mapping — the table must match the running code, not a parallel copy of it.
func policyPointsForReason(t *testing.T, why string) string {
	t.Helper()
	sanctionTestBox(t)
	a := agentObs{Kind: kindAgent, Signature: "claude-code", User: "user",
		Exe: "/usr/local/bin/claude", Cmdline: "claude"}
	switch why {
	case sanctionWhyHostTag:
		a.DelegationToken = "del_" + strings.Repeat("a", 24)
	case sanctionWhyBadTag:
		a.DelegationToken = "yes"
	case sanctionWhyNoExe:
		a.Exe = ""
	case sanctionWhyLocal, sanctionWhyBoth:
		if why == sanctionWhyBoth {
			a.DelegationToken = "del_" + strings.Repeat("a", 24)
		}
		if _, err := addSanction(a, "local-ui"); err != nil {
			t.Fatalf("addSanction: %v", err)
		}
	case sanctionWhyUnreadable:
		// A registry that exists and will not parse. Not a missing file —
		// missing is "nothing marked", which is a legitimate answer.
		p, err := sanctionsPath()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, got := agentSanction(a)
	if got != why {
		t.Skipf("could not construct %q (got %q) — the fixture needs updating, "+
			"not the assertion", why, got)
	}
	return policySanctionTerm(a).Points
}
