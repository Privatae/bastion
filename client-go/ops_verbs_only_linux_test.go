package main

// ops_verbs_only_linux_test.go — an op with no program (interpreter: none)
// runs on a machine with no overlay (the edges), through op_dry_run and an
// approved op_apply, with only the verbs' own tools. Stand-ins for systemd
// and the probe; nothing here needs root.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestVerbsOnlyOpRunsWithNoOverlay(t *testing.T) {
	noOverlay(t)
	prevProbe := opVerbProbe
	opVerbProbe = func([]opVerbLine) string { return "" }
	t.Cleanup(func() { opVerbProbe = prevProbe })
	var calls []string
	state := map[string]string{"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed", "MainPID": "0"}
	prevCtl, prevJournal := opSystemctl, opJournalctl
	opSystemctl = func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "show" {
			var b strings.Builder
			for k, v := range state {
				fmt.Fprintf(&b, "%s=%s\n", k, v)
			}
			return b.String(), nil
		}
		if args[0] == "restart" {
			state["ActiveState"], state["SubState"], state["MainPID"] = "active", "running", "42"
		}
		return "", nil
	}
	opJournalctl = func(_ context.Context, _ ...string) (string, error) { return "started\n", nil }
	t.Cleanup(func() { opSystemctl, opJournalctl = prevCtl, prevJournal })

	dcn, priv := opTestBox(t)
	enrollFactor(t, dcn)
	files := verbsOnlyFiles(false)
	sha, _ := opDirDigest(files)
	terms := opTerm(opKindRun, sha, `{}`, "", 1, time.Hour, "root")
	terms["op"] = "restart-web"
	pair := signTermsPair(t, priv, terms)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(files))}, "", dcn); code != 0 {
		t.Fatalf("held: %s", errOut)
	}
	out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair}, "", dcn)
	if code != 0 {
		t.Fatalf("the dry run on a machine with no overlay: %d %s", code, errOut)
	}
	var rep opReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Changes) != 2 || rep.ChangesSHA256 == "" ||
		!strings.Contains(rep.Changes[0].Note, "failed/failed → restarted") {
		t.Fatalf("the dry run is the verbs' own read: %v %s", err, out)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "restart") {
			t.Fatal("a verb never runs in a dry run")
		}
	}
	// The apply, approved for exactly that change list.
	terms["changes_sha256"] = rep.ChangesSHA256
	purpose, err := purposeForOpRun(&opTerms{Server: terms["server"].(string), Op: "restart-web", SHA256: sha,
		Params: `{}`, Expires: terms["expires"].(string), Changes: rep.ChangesSHA256})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b32decode(tSecret)
	approval, err := stepupIssueApproval(dcn, hotp(raw, time.Now().Unix()/stepupPeriod), purpose)
	if err != nil {
		t.Fatal(err)
	}
	terms["approval"] = approval
	out, errOut, code = driveJob(t, tAnchor, mgmtJob{Op: "op_apply", Args: signTermsPair(t, priv, terms)}, "", dcn)
	if code != 0 {
		t.Fatalf("the apply: %d %s", code, errOut)
	}
	rep = opReport{}
	_ = json.Unmarshal([]byte(out), &rep)
	if len(rep.Verbs) != 1 || !rep.Verbs[0].OK || len(rep.Checks) != 1 || !rep.Checks[0].OK || rep.VerifyError != "" {
		t.Fatalf("the unit restarted and its log checked: %s", out)
	}
	if n := countPrefix(calls, "restart web.service"); n != 1 {
		t.Fatalf("restarted once: %v", calls)
	}

	// A machine without a verb's tool refuses the run, and that is the
	// machine's state, never the host's strike.
	opVerbProbe = func(lines []opVerbLine) string {
		return "unit.restart web.service runs systemctl, which is not installed here"
	}
	pair2 := signTermsPair(t, priv, terms)
	_, errOut, code = driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair2}, "", dcn)
	if code != 126 || !strings.Contains(errOut, noVerbToolHere) || refusalCounts("op_dry_run", errOut) {
		t.Fatalf("a missing tool: %d %q", code, errOut)
	}
}

func countPrefix(xs []string, p string) int {
	n := 0
	for _, x := range xs {
		if strings.HasPrefix(x, p) {
			n++
		}
	}
	return n
}

func TestVerbsReportNamesEachVerbsTool(t *testing.T) {
	prev := opLookPath
	opLookPath = func(file string) (string, error) {
		if file == "systemctl" || file == "journalctl" {
			return "/usr/bin/" + file, nil
		}
		return "", fmt.Errorf("not found")
	}
	t.Cleanup(func() { opLookPath = prev })
	rep := opVerbsReport()
	for _, verb := range opVerbNames() {
		if _, ok := rep[verb]; !ok {
			t.Fatalf("every verb is on the beat: %v", rep)
		}
	}
	if !processIsRoot() {
		if v := rep["unit.restart"].(map[string]any); v["ok"] != false {
			t.Fatalf("a bastion that is not root runs no verb: %v", v)
		}
		return
	}
	if v := rep["unit.restart"].(map[string]any); v["ok"] != true {
		t.Fatalf("systemctl here: %v", v)
	}
	if v := rep["k8s.set_image"].(map[string]any); v["ok"] != false || !strings.Contains(v["why"].(string), "kubectl") {
		t.Fatalf("no kubectl here: %v", v)
	}
	if v := rep["logs.check"].(map[string]any); v["ok"] != true {
		t.Fatalf("the journal is enough for a unit's log: %v", v)
	}
}

// k8s.set_image runs git as well as kubectl (its ancestry check fetches the
// source), so a machine with kubectl and no git is told it cannot run the
// verb, before any run, never by a failed apply.
//
// RESULT: red before — k8s.set_image named kubectl alone.
func TestSetImageNeedsGitForItsAncestryCheck(t *testing.T) {
	tools := opVerbTools("k8s.set_image", nil)
	if strings.Join(tools, ",") != "kubectl,git" {
		t.Fatalf("k8s.set_image runs kubectl and git: %v", tools)
	}
	if got := opVerbTools("tree.checkout", nil); strings.Join(got, ",") != "git" {
		t.Fatalf("tree.checkout runs git: %v", got)
	}
	prev := opLookPath
	opLookPath = func(file string) (string, error) {
		if file == "kubectl" {
			return "/usr/bin/kubectl", nil
		}
		return "", fmt.Errorf("not found")
	}
	t.Cleanup(func() { opLookPath = prev })
	if !processIsRoot() {
		return // a bastion that is not root runs no verb at all
	}
	line := setImageLine("sha256:" + strings.Repeat("2", 64))
	if why := opVerbProbe([]opVerbLine{line}); !strings.Contains(why, "git") {
		t.Fatalf("a machine with kubectl and no git cannot run k8s.set_image: %q", why)
	}
	if v := opVerbsReport()["k8s.set_image"].(map[string]any); v["ok"] != false || !strings.Contains(v["why"].(string), "git") {
		t.Fatalf("the beat says so: %v", v)
	}
}
