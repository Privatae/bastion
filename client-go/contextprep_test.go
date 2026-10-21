//go:build !windows

// Tagged to match anchor_test.go, which is where setupBox, driveOp and the
// grant helpers live. Without this the WINDOWS test build fails on `undefined:
// setupBox` — verified with GOOS=windows go vet. The capability itself
// (contextprep.go) is platform-neutral and builds everywhere; only these gates
// borrow the anchored-box fixture.

package main

// Gates for the context-preparation capability (contextprep.go).
//
// The defect each test guards is named in its comment. The first one is the
// reason this file exists: the caps gate fails OPEN on an unrecognised op
// name, so a rename can silently hand every member pairing a lane the anchor
// never granted, with nothing visibly broken.

import (
	"strings"
	"testing"
	"time"
)

// resetPrepCache clears the 10-minute probe cache so one test's probe cannot
// decide another's result.
func resetPrepCache() {
	prepCache.Lock()
	prepCache.at = time.Time{}
	prepCache.tools = nil
	prepCache.scan = prepScanReport{}
	prepCache.Unlock()
}

// THE IMPORTANT ONE. capsAllow maps an op to a family with opFamily, and
// opFamily returns "" for a name it does not know — at which point capsAllow
// RETURNS "" TOO, meaning allow (anchor.go:476-479). So an op named outside
// the known prefixes is ungated on an anchored box: every member pairing may
// drive it, no error, no log line, nothing to notice. The "ctx_" prefix is
// what puts this lane in the dcn family, and it is not cosmetic.
func TestPrepGateOpResolvesToARealFamily(t *testing.T) {
	fam := opFamily(prepGateOp)
	if fam == "" {
		t.Fatalf("prepGateOp %q maps to NO caps family — capsAllow fails open on an "+
			"unknown op, so this lane would be ungated for every member pairing on an "+
			"anchored box. Name it with a prefix opFamily knows (anchor.go:411).", prepGateOp)
	}
	if fam != prepGateOpFamily {
		t.Fatalf("prepGateOp %q is family %q, not the declared %q — the gate and the "+
			"declaration disagree", prepGateOp, fam, prepGateOpFamily)
	}
	// And the family must be one the anchor can actually grant, or no pairing
	// could ever be given this lane.
	found := false
	for _, c := range allCaps {
		if c == fam {
			found = true
		}
	}
	if !found {
		t.Fatalf("family %q is not in allCaps %v — ungrantable", fam, allCaps)
	}
}

// A tool table entry with a missing field would probe garbage or advertise a
// job the host cannot ask for.
func TestPrepToolTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range prepToolTable {
		if tool.Name == "" {
			t.Fatalf("prepTool entry with no name: %+v — the host asks for a job by name", tool)
		}
		// A BUILTIN HAS NO BINARY AND MUST HAVE A PROOF. The two halves swap:
		// a job with a program is checked by running the program, and a job this
		// binary does itself is checked by doing it. What neither may be is
		// unchecked, so the requirement moves rather than relaxing.
		if tool.Builtin {
			if tool.Bin != "" || len(tool.Args) > 0 {
				t.Fatalf("%q is builtin but carries a program to run: %+v — a builtin "+
					"has nothing to exec, and a half-filled entry would probe the wrong thing",
					tool.Name, tool)
			}
			if tool.Prove == nil {
				t.Fatalf("%q is builtin with no Prove — there is no exit code to stand in "+
					"for the capability, so a builtin that is never proved is advertised on "+
					"faith", tool.Name)
			}
		} else if tool.Bin == "" || len(tool.Args) == 0 {
			t.Fatalf("incomplete prepTool entry: %+v — every tool needs the job name "+
				"the host asks for, the binary, and an argv that proves it runs", tool)
		}
		if seen[tool.Name] {
			t.Fatalf("duplicate prep tool name %q — the host looks tools up by name", tool.Name)
		}
		seen[tool.Name] = true
	}
}

// Availability is the EXIT CODE, never the output. `pdftotext -v` prints its
// banner to stderr and exits 0, so a probe that required stdout would report a
// working poppler as absent (measured). Conversely a binary that
// exits non-zero is not available however much it printed.
func TestPrepProbeUsesExitCodeNotOutput(t *testing.T) {
	// exits 0, prints nothing: available, no version.
	ok, ver := probePrepTool(prepTool{Name: "silent", Bin: "true", Args: []string{}})
	if !ok {
		t.Fatal("a tool that exits 0 with no output must count as AVAILABLE — " +
			"absent output is not absent capability")
	}
	if ver != "" {
		t.Fatalf("expected no version from a silent tool, got %q", ver)
	}
	// exits non-zero: not available.
	if ok, _ := probePrepTool(prepTool{Name: "fails", Bin: "false", Args: []string{}}); ok {
		t.Fatal("a tool that exits non-zero must NOT be advertised")
	}
	// missing binary: not available, and no panic.
	if ok, _ := probePrepTool(prepTool{
		Name: "gone", Bin: "privatae-no-such-binary-9f3c", Args: []string{"-v"},
	}); ok {
		t.Fatal("a missing binary must NOT be advertised")
	}
}

// A chatty or hostile binary must not be able to inflate the heartbeat body.
func TestFirstLineTrimsAndCaps(t *testing.T) {
	if got := firstLine("  tesseract 5.5.0\nmore\nlines\n"); got != "tesseract 5.5.0" {
		t.Fatalf("firstLine kept more than the first line: %q", got)
	}
	if got := firstLine(strings.Repeat("x", 500)); len(got) != 120 {
		t.Fatalf("firstLine must cap at 120 chars, got %d", len(got))
	}
	if got := firstLine("   \n  "); got != "" {
		t.Fatalf("whitespace-only output must be empty, got %q", got)
	}
}

// On an anchored box a member pairing with no dcn grant must get NO capability
// AND no probe: advertising a lane the op will refuse is a control that fails
// after the user has already chosen it (mirror.go:63-67's stated reason), and
// probing for a pairing that cannot use the result is work done for nothing.
func TestPrepWithheldFromMemberWithoutDCN(t *testing.T) {
	setupBox(t)
	resetPrepCache()

	tools, scan, ok := prepCapable(tMember)
	if ok {
		t.Fatal("a member pairing holding no grant must not be offered context-prep")
	}
	if len(tools) != 0 || scan.Supported {
		t.Fatalf("a withheld capability must report nothing, got tools=%v scan=%+v", tools, scan)
	}
	prepCache.Lock()
	probed := !prepCache.at.IsZero()
	prepCache.Unlock()
	if probed {
		t.Fatal("the probe RAN for a pairing that is refused at the op — withheld " +
			"must skip the probe entirely, as the inference lanes do (agents.go:351)")
	}
}

// THE CASE THE FAIL-OPEN ACTUALLY BITES. A member holding NO grant is
// default-denied before opFamily is ever consulted (anchor.go:473-475), so it
// stays refused even with the op misnamed — which makes the test above a poor
// guard on its own. The real exposure is a pairing that HAS a verified grant
// for some OTHER family: there capsAllow reaches opFamily, and an unrecognised
// op name returns allow. This is the assertion that fails when the "ctx_"
// prefix is dropped.
func TestPrepWithheldFromMemberGrantedAnotherFamily(t *testing.T) {
	priv := setupBox(t)
	resetPrepCache()

	// A real, signed, verified grant — for observe only. Nothing about this
	// pairing is malformed; it simply was not given the dcn family.
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("could not install the observe-only grant: %d %s", code, errOut)
	}

	if _, _, ok := prepCapable(tMember); ok {
		t.Fatal("a pairing granted 'observe' was offered context-prep — the op name " +
			"no longer resolves to the dcn family, so capsAllow fell through to its " +
			"allow branch (anchor.go:476-479)")
	}
}

// The anchor pairing is unconstrained (its user IS the machine's admin), so it
// sees whatever this box actually has. This asserts the gate lets the anchor
// through; whether any tool is installed is the box's business, not the gate's.
func TestPrepReachesTheAnchor(t *testing.T) {
	setupBox(t)
	resetPrepCache()

	tools, scan, ok := prepCapable(tAnchor)
	if !scan.Supported {
		t.Fatal("the anchor pairing must reach the probe — it holds every family")
	}
	if scan.Probed != len(prepToolTable) {
		t.Fatalf("scan must report every tool it tried: probed=%d table=%d",
			scan.Probed, len(prepToolTable))
	}
	if scan.Found != len(tools) {
		t.Fatalf("scan.Found %d disagrees with the tool list length %d", scan.Found, len(tools))
	}
	// The capability travels only when something was actually found — a box
	// with the lane granted but no tools installed must read as "nothing here",
	// not as a working feature.
	if ok != (len(tools) > 0) {
		t.Fatalf("capability %v disagrees with %d tools found", ok, len(tools))
	}
	for _, tool := range tools {
		if tool.Name == "" {
			t.Fatalf("advertised tool missing its identity: %+v", tool)
		}
		// A builtin names no program because there is none. It still has to say
		// SOMETHING about itself, or a machine card shows a job with a blank
		// where every other row says what does the work.
		if tool.Builtin {
			if tool.Bin != "" {
				t.Fatalf("a builtin advertised a program to install: %+v", tool)
			}
			if tool.Version == "" {
				t.Fatalf("a builtin advertised with nothing said about it: %+v", tool)
			}
			continue
		}
		if tool.Bin == "" {
			t.Fatalf("advertised tool missing its identity: %+v", tool)
		}
	}
}

// ADVERTISING IS A PROMISE. Every tool in prepToolTable travels to the host in
// the heartbeat, is offered by the host's machine picker, and is what the
// host filters machines by tool on — so a name here that ctx_extract cannot
// actually run tells a user their machine can do something it will then refuse.
//
// That happened: ocr and video-frames were advertised for a day with no entry in
// extractArgv, and the refusal even read "this box runs only the jobs it
// advertises", which had quietly stopped being true. This is the same
// quiet-vs-blind rule the rest of this file enforces, pointed the other way —
// claiming MORE than you can do is as dishonest as claiming less.
func TestAdvertisedToolsCanActuallyRun(t *testing.T) {
	for _, tool := range prepToolTable {
		_, single := extractArgv[tool.Name]
		_, multi := extractMulti[tool.Name]
		frames := frameTools[tool.Name]
		_, stt := transcribeTools[tool.Name]
		if !single && !multi && !frames && !stt {
			t.Fatalf("prepToolTable advertises %q but no runner can run it — it is in "+
				"none of extractArgv, extractMulti, frameTools or transcribeTools. The "+
				"heartbeat would offer a job ctx_extract then refuses. Add the runner in "+
				"the same change that adds the tool, or do not advertise it.", tool.Name)
		}
		// EXACTLY ONE RUNNER. Two means the answer shape is undecided:
		// handleCtxExtract picks one and the host reads the reply expecting the
		// other's, which for the text/frames pair is a clip filed as zero
		// chunks of nothing and called a success.
		n := 0
		for _, in := range []bool{single, multi, frames, stt} {
			if in {
				n++
			}
		}
		if n > 1 {
			t.Fatalf("%q is claimed by more than one runner (argv=%v multi=%v "+
				"frames=%v transcribe=%v) — one tool, one answer shape",
				tool.Name, single, multi, frames, stt)
		}
	}
}

// And the reverse: a runner with nothing advertising it is unreachable, because
// handleCtxExtract requires the name to be in prepToolTable too.
func TestEveryArgvIsAdvertised(t *testing.T) {
	names := []string{}
	for name := range extractArgv {
		names = append(names, name)
	}
	for name := range extractMulti {
		names = append(names, name)
	}
	for name := range frameTools {
		names = append(names, name)
	}
	for name := range transcribeTools {
		names = append(names, name)
	}
	for _, name := range names {
		found := false
		for _, tool := range prepToolTable {
			if tool.Name == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("ctx_extract can run %q but prepToolTable never advertises it — "+
				"no host will ever ask for it", name)
		}
	}
}
