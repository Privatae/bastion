package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// holdActionOp puts an action op in the pairing's store, as op_sync would.
func holdActionOp(t *testing.T, dcn, man, program string) (string, *opManifest) {
	t.Helper()
	m, err := parseOpManifest([]byte(man))
	if err != nil {
		t.Fatalf("%v\n%s", err, man)
	}
	files := []opFile{
		{Path: "op.yaml", Mode: 0o644, B64: base64.StdEncoding.EncodeToString([]byte(man))},
		{Path: "run", Mode: 0o755, B64: base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\n" + program + "\n"))},
	}
	sha, err := opDirDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := opInstall(dcn, sha, files); err != nil {
		t.Fatal(err)
	}
	return sha, m
}

// A whole ship, for real, on this machine: a build whose receipt carries the
// digest, a root roll that takes it from that receipt (adopting the live image
// as the first roll), and a check that fails; the failed check's receipt
// undoes the roll, to the image that was live before it.
func TestAShipPlanRunsEachLineOnceAndUndoesOnAFailedCheck(t *testing.T) {
	requireActionSandbox(t)
	dcn := planBox(t)
	useAncestry(t, func(_, _, _ string, _ []string) error { return nil })
	commit := strings.Repeat("7", 40)
	digest := "sha256:" + strings.Repeat("5", 64)
	old := tImage + "@sha256:" + strings.Repeat("4", 64)
	f := &fakeKube{containers: map[string]string{"bridge": old}}
	useFakeKube(t, f)

	head := `version: 1.0.0
summary: A step of the ship under test.
kind: action
target: machine
interpreter: /bin/sh
time_limit: 30
`
	res := fmt.Sprintf(`{"images":[{"image":"%s","digest":"%s","source":"%s","commit":"%s"}]}`, tImage, digest, tRepo, commit)
	buildSHA, _ := holdActionOp(t, dcn, "name: bridge-build\n"+head+"privilege: user\nparams:\n  commit: {type: string, max_len: 40}\nmodes: [dry_run, apply, verify]\nundo: none\n",
		`[ "$PRIVATAE_OP_MODE" = apply ] && printf '%s' '`+res+`' > "$PRIVATAE_OP_RESULT"; true`)
	rollSHA, rollM := holdActionOp(t, dcn, "name: bridge-roll\n"+head+"privilege: root\nparams:\n  digest: {type: string, max_len: 71}\n"+
		"verbs:\n  - {verb: k8s.set_image, namespace: ds, kind: deployment, name: bridge, container: bridge, image: "+tImage+", digest: \"{{digest}}\", repo: \""+tRepo+"\"}\n"+
		"modes: [dry_run, apply, verify]\nundo: none\n", "true")
	// The check: its apply succeeds, its verify (the probe) fails — a failed
	// CHECK, which is what may start an undo of an earlier line.
	checkSHA, _ := holdActionOp(t, dcn, "name: bridge-check\n"+head+"privilege: user\nparams: {}\nmodes: [dry_run, apply, verify]\nundo: none\n",
		`[ "$PRIVATAE_OP_MODE" = verify ] && { echo "the bridge does not answer"; exit 1; }; true`)

	hn := planHost()
	rollLine := shipPlanLine{N: 2, Step: "roll", Machine: hn, Op: "bridge-roll", OpSHA256: rollSHA, Params: `{}`,
		Inputs: map[string]string{"digest": "build.digest"}, Undo: true, AdoptLive: true}
	rollLine.Verbs = planVerbsForShow(rollM, &rollLine)
	draft := map[string]any{"kind": shipPlanKind, "plan": map[string]any{
		"pipeline": "bridge", "commit": commit, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"lines": []any{
			shipPlanLine{N: 1, Step: "build", Machine: hn, Op: "bridge-build", OpSHA256: buildSHA, Params: fmt.Sprintf(`{"commit":"%s"}`, commit)},
			rollLine,
			shipPlanLine{N: 3, Step: "check", Machine: hn, Op: "bridge-check", OpSHA256: checkSHA, Params: `{}`},
		}}}
	// Through JSON, as the pod sends it.
	raw, _ := json.Marshal(draft)
	var details map[string]any
	_ = json.Unmarshal(raw, &details)
	b64, p := signPlan(t, dcn, details, planCode(t))
	if !p.Root || !p.CodeGiven {
		t.Fatal("a plan with a roll is root, approved with the code")
	}
	encode := func(rs ...any) string {
		b, _ := json.Marshal(rs)
		return base64.StdEncoding.EncodeToString(b)
	}
	receiptOf := func(out map[string]any) opSignedReceipt {
		return out["receipt"].(opSignedReceipt)
	}

	// 1. The build: its receipt names the image it pushed, at the plan's commit.
	out1, err := planRunLine(dcn, b64, "1", "", nil)
	if err != nil || out1["ok"] != true {
		t.Fatalf("the build ran: %v %v", out1["error"], err)
	}
	r1 := receiptOf(out1)
	// The roll cannot run before the build's receipt is handed to it...
	if _, err := planRunLine(dcn, b64, "2", "", nil); err == nil || !strings.Contains(err.Error(), "runs only after line 1") {
		t.Fatalf("the roll before its build: %v", err)
	}
	// 2. ...and with it, rolls exactly the digest the build reported.
	out2, err := planRunLine(dcn, b64, "2", encode(r1), nil)
	if err != nil || out2["ok"] != true {
		t.Fatalf("the roll ran: %v %v", out2["error"], err)
	}
	if f.containers["bridge"] != tImage+"@"+digest {
		t.Fatalf("the workload runs the built digest: %s", f.containers["bridge"])
	}
	if _, _, c, ok := opRolledCommit(digest); !ok || c != commit {
		t.Fatal("the roll is recorded, so the next plan moves forward from it")
	}
	// A replay of the same line is refused: it succeeded, so no attempt is left
	// to it, whatever the plan allowed.
	if _, err := planRunLine(dcn, b64, "2", encode(r1), nil); err == nil || !strings.Contains(err.Error(), "already succeeded") {
		t.Fatalf("a replayed line: %v", err)
	}
	// 3. The check (after the build and the roll, their receipts with it)
	// fails, and says so in its signed receipt.
	r2 := receiptOf(out2)
	out3, err := planRunLine(dcn, b64, "3", encode(r1, r2), nil)
	if err != nil || out3["ok"] != true || !strings.Contains(fmt.Sprint(out3["verify_error"]), "verify exited 1") {
		t.Fatalf("the check ran and its verify failed: %v %v", out3, err)
	}
	// The pod that lost an answer reads it back, and nothing is spent.
	if path, _ := planReceiptsPath(p.Nonce, 3); path != "" {
		raw, _ := os.ReadFile(path)
		var kept []opSignedReceipt
		_ = json.Unmarshal(raw, &kept)
		if len(kept) != 1 {
			t.Fatalf("line 3's receipt is kept for op_plan_status: %d", len(kept))
		}
	}
	failed, _ := json.Marshal(receiptOf(out3))
	// The failed check undoes the roll, to the image live before it.
	undo, err := planUndoLine(b64, "2", base64.StdEncoding.EncodeToString(failed))
	if err != nil || undo["ok"] != true {
		t.Fatalf("the undo ran: %v %v", undo, err)
	}
	if f.containers["bridge"] != old {
		t.Fatalf("the workload is back on %s, got %s", old, f.containers["bridge"])
	}
	path, _ := planRunPath(p.Nonce, 2)
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the roll's record is kept for its undo")
	}
	// A plan whose roll names a digest no step of it built (bound in its
	// params, not taken from a receipt) rolls nothing.
	foreign := "sha256:" + strings.Repeat("6", 64)
	stray := shipPlanLine{N: 1, Step: "roll", Machine: hn, Op: "bridge-roll", OpSHA256: rollSHA,
		Params: fmt.Sprintf(`{"digest":"%s"}`, foreign), AdoptLive: true}
	stray.Verbs = planVerbsForShow(rollM, &stray)
	raw, _ = json.Marshal(map[string]any{"kind": shipPlanKind, "plan": map[string]any{
		"pipeline": "bridge", "commit": commit, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"lines": []any{stray}}})
	details = nil
	_ = json.Unmarshal(raw, &details)
	b64b, _ := signPlan(t, dcn, details, planCodeAt(1)) // the first code is spent
	outS, err := planRunLine(dcn, b64b, "1", "", nil)
	if err != nil || outS["ok"] != false || !strings.Contains(fmt.Sprint(outS["error"]), "no step of this plan built") {
		t.Fatalf("a digest no step of the plan built: %v %v", outS["error"], err)
	}
	if f.containers["bridge"] != old {
		t.Fatalf("nothing was rolled: %s", f.containers["bridge"])
	}
}

// An undo takes back only what the line left: a workload or tree that moved
// since is someone else's change, and is left alone.
func TestAnUndoLeavesWhatMovedSinceAlone(t *testing.T) {
	setupBox(t)
	was, set, other := tImage+"@sha256:"+strings.Repeat("1", 64), tImage+"@sha256:"+strings.Repeat("2", 64), tImage+"@sha256:"+strings.Repeat("3", 64)
	f := &fakeKube{containers: map[string]string{"bridge": other}}
	useFakeKube(t, f)
	v := setImageLine("sha256:" + strings.Repeat("2", 64))
	if _, err := planUndoVerb(context.Background(), v, was, set); err == nil || !strings.Contains(err.Error(), "moved since") {
		t.Fatalf("a workload that moved since: %v", err)
	}
	if len(f.sets()) != 0 {
		t.Fatal("it was set anyway")
	}
	f.containers["bridge"] = was
	if note, err := planUndoVerb(context.Background(), v, was, set); err != nil || !strings.Contains(note, "already") {
		t.Fatalf("already back where it started: %q %v", note, err)
	}
	f.containers["bridge"] = set
	if _, err := planUndoVerb(context.Background(), v, was, set); err != nil || f.containers["bridge"] != was {
		t.Fatalf("what the line left is taken back: %v %s", err, f.containers["bridge"])
	}
}

// An undo puts the state back first and only then restarts the unit, so the
// unit starts on what was put back, never on the failed code.
func TestAnUndoRestartsTheUnitOnlyAfterPuttingTheStateBack(t *testing.T) {
	dcn := planBox(t)
	was, set := tImage+"@sha256:"+strings.Repeat("1", 64), tImage+"@sha256:"+strings.Repeat("2", 64)
	var order []string
	f := &fakeKube{containers: map[string]string{"bridge": set}}
	prevK := opKubectl
	opKubectl = func(ctx context.Context, args ...string) (string, error) {
		if len(args) >= 3 && args[2] == "set" {
			order = append(order, "set image")
		}
		return f.run(ctx, args...)
	}
	prevS := opSystemctl
	opSystemctl = func(_ context.Context, args ...string) (string, error) {
		if args[0] == "show" {
			return "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=1\n", nil
		}
		order = append(order, "systemctl "+args[0])
		return "", nil
	}
	t.Cleanup(func() { opKubectl, opSystemctl = prevK, prevS })
	d := planDraft(false)
	lines := d["plan"].(map[string]any)["lines"].([]any)
	lines = append(lines, map[string]any{"n": 3, "step": "check", "machine": planHost(), "op": "bridge-check",
		"op_sha256": strings.Repeat("e", 64), "params": `{}`})
	d["plan"].(map[string]any)["lines"] = lines
	b64, p := signPlan(t, dcn, d, "")
	raw, _ := base64.StdEncoding.DecodeString(b64)
	var e shipPlanEnvelope
	_ = json.Unmarshal(raw, &e)
	_, sha, _ := planOpen(e)
	// Line 2 set the image, then restarted the unit.
	rec := planRunRecord{Plan: p.Nonce, N: 2, Attempt: 1, State: planStatePassed,
		Verbs: []opVerbLine{setImageLine("sha256:" + strings.Repeat("2", 64)), {Verb: "unit.restart", Args: map[string]string{"unit": "app.service"}}},
		Froms: []string{was, ""}, Tos: []string{set, ""}}
	path, _ := planRunPath(p.Nonce, 2)
	body, _ := json.Marshal(rec)
	_ = os.WriteFile(path, body, 0o600)
	failed, _ := lineReceiptSign(lineReceipt{Plan: p.Nonce, PlanSHA256: sha, Pipeline: p.Pipeline, Commit: p.Commit,
		N: 3, Step: "check", Machine: planHost(), OK: true, VerifyError: "verify exited 1", Attempt: 1})
	fb, _ := json.Marshal(failed)
	out, err := planUndoLine(b64, "2", base64.StdEncoding.EncodeToString(fb))
	if err != nil || out["ok"] != true {
		t.Fatalf("the undo ran: %v %v", out, err)
	}
	if strings.Join(order, ", ") != "set image, systemctl restart" {
		t.Fatalf("the image goes back before the unit restarts: %v", order)
	}
	if f.containers["bridge"] != was {
		t.Fatal("the image is back")
	}
}

// Moving a tree back never overwrites a file the machine keeps.
func TestAnUndoOfATreeNeverOverwritesAnIgnoredFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for the tree's ownership checks")
	}
	// A name is matched as itself, never as a pathspec: ":(literal)k.env"
	// read as one names k.env, and would miss the file.
	for _, name := range []string{".env", "[ab].env", ":(literal)k.env"} {
		t.Run(name, func(t *testing.T) {
			setupBox(t)
			useFileRepos(t)
			// c1 tracks the file; c2 stops tracking it (it is ignored from then on).
			origin, tree, c1, c2 := twoCommitRepo(t, func(o string) {
				_ = os.WriteFile(filepath.Join(o, name), []byte("FROM-REPO\n"), 0o644)
				_ = os.WriteFile(filepath.Join(o, ".gitignore"), []byte("*.env\n"), 0o644)
				gitT(t, o, "--literal-pathspecs", "add", "-f", "--", name)
			}, func(o string) {
				gitT(t, o, "--literal-pathspecs", "rm", "-q", "--cached", "--", name)
				_ = os.WriteFile(filepath.Join(o, "a.txt"), []byte("two\n"), 0o644)
			})
			line := opVerbLine{Verb: "tree.checkout", Args: map[string]string{"path": tree, "repo": "file://" + origin, "commit": c2}}
			if _, err := opTreeDo(context.Background(), line, nil, ""); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(tree, name), []byte("LOCAL-SECRET\n"), 0o600)
			if _, err := planUndoVerb(context.Background(), line, c1, c2); err == nil || !strings.Contains(err.Error(), "a file this machine keeps") {
				t.Fatalf("an undo over an ignored file: %v", err)
			}
			if b, _ := os.ReadFile(filepath.Join(tree, name)); string(b) != "LOCAL-SECRET\n" {
				t.Fatalf("the kept file was overwritten: %q", b)
			}
		})
	}
}

// shipRig is a three-line ship on this machine: build (its receipt carries
// the digest), roll (root, sets the image, undoable, two attempts), check.
// rollProgram and checkProgram are the roll's and the check's programs.
func shipRig(t *testing.T, buildProgram, rollProgram, checkProgram string, checkAttempts int) (dcn, b64 string, f *fakeKube, old, built string) {
	t.Helper()
	requireActionSandbox(t)
	dcn = planBox(t)
	useAncestry(t, func(_, _, _ string, _ []string) error { return nil })
	commit := strings.Repeat("7", 40)
	digest := "sha256:" + strings.Repeat("5", 64)
	old = tImage + "@sha256:" + strings.Repeat("4", 64)
	built = tImage + "@" + digest
	f = &fakeKube{containers: map[string]string{"bridge": old}}
	useFakeKube(t, f)
	head := "version: 1.0.0\nsummary: A step of the ship under test.\nkind: action\ntarget: machine\ninterpreter: /bin/sh\ntime_limit: 30\n"
	res := fmt.Sprintf(`{"images":[{"image":"%s","digest":"%s","source":"%s","commit":"%s"}]}`, tImage, digest, tRepo, commit)
	if buildProgram == "" {
		buildProgram = `[ "$PRIVATAE_OP_MODE" = apply ] && printf '%s' '` + res + `' > "$PRIVATAE_OP_RESULT"; true`
	} else {
		buildProgram = strings.ReplaceAll(buildProgram, "RESULT", res)
	}
	buildSHA, _ := holdActionOp(t, dcn, "name: bridge-build\n"+head+"privilege: user\nparams:\n  commit: {type: string, max_len: 40}\nmodes: [dry_run, apply, verify]\nundo: none\n", buildProgram)
	rollSHA, rollM := holdActionOp(t, dcn, "name: bridge-roll\n"+head+"privilege: root\nparams:\n  digest: {type: string, max_len: 71}\n"+
		"verbs:\n  - {verb: k8s.set_image, namespace: ds, kind: deployment, name: bridge, container: bridge, image: "+tImage+", digest: \"{{digest}}\", repo: \""+tRepo+"\"}\n"+
		"modes: [dry_run, apply, verify]\nundo: none\n", rollProgram)
	checkSHA, _ := holdActionOp(t, dcn, "name: bridge-check\n"+head+"privilege: user\nparams: {}\nmodes: [dry_run, apply, verify]\nundo: none\n", checkProgram)
	hn := planHost()
	rollLine := shipPlanLine{N: 2, Step: "roll", Machine: hn, Op: "bridge-roll", OpSHA256: rollSHA, Params: `{}`,
		Inputs: map[string]string{"digest": "build.digest"}, Undo: true, AdoptLive: true, Attempts: 2}
	rollLine.Verbs = planVerbsForShow(rollM, &rollLine)
	draft := map[string]any{"kind": shipPlanKind, "plan": map[string]any{
		"pipeline": "bridge", "commit": commit, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"lines": []any{
			shipPlanLine{N: 1, Step: "build", Machine: hn, Op: "bridge-build", OpSHA256: buildSHA, Params: fmt.Sprintf(`{"commit":"%s"}`, commit), Attempts: 2},
			rollLine,
			shipPlanLine{N: 3, Step: "check", Machine: hn, Op: "bridge-check", OpSHA256: checkSHA, Params: `{}`, Attempts: checkAttempts},
		}}}
	raw, _ := json.Marshal(draft)
	var details map[string]any
	_ = json.Unmarshal(raw, &details)
	b64, _ = signPlan(t, dcn, details, planCode(t))
	return dcn, b64, f, old, built
}

func rigReceipts(outs ...map[string]any) string {
	var rs []opSignedReceipt
	for _, o := range outs {
		rs = append(rs, o["receipt"].(opSignedReceipt))
	}
	b, _ := json.Marshal(rs)
	return base64.StdEncoding.EncodeToString(b)
}

func rigReceipt(o map[string]any) string {
	b, _ := json.Marshal(o["receipt"].(opSignedReceipt))
	return base64.StdEncoding.EncodeToString(b)
}

// failKubeAt makes the listed kubectl calls of a kind (set, rollout) fail,
// counted from 1.
func failKubeAt(t *testing.T, kind string, calls ...int) {
	t.Helper()
	count := 0
	prev := opKubectl
	opKubectl = func(ctx context.Context, args ...string) (string, error) {
		if len(args) >= 3 && args[2] == kind {
			count++
			for _, n := range calls {
				if count == n {
					return "boom", fmt.Errorf("exit 1")
				}
			}
		}
		return prev(ctx, args...)
	}
	t.Cleanup(func() { opKubectl = prev })
}

// Two calls for the same line at once: the second is refused while the first
// runs, and once the first passed nothing runs the line again.
func TestALineRunsOneAttemptAtATime(t *testing.T) {
	dcn, b64, _, _, _ := shipRig(t, `[ "$PRIVATAE_OP_MODE" = apply ] && { sleep 3; printf '%s' 'RESULT' > "$PRIVATAE_OP_RESULT"; }; true`, "true", "true", 1)
	type res struct {
		out map[string]any
		err error
	}
	first := make(chan res, 1)
	go func() {
		out, err := planRunLine(dcn, b64, "1", "", nil)
		first <- res{out, err}
	}()
	time.Sleep(700 * time.Millisecond)
	if _, err := planRunLine(dcn, b64, "1", "", nil); err == nil || !strings.Contains(err.Error(), "attempt 1 of line 1 is running here") {
		t.Fatalf("a second attempt while the first runs: %v", err)
	}
	r := <-first
	if r.err != nil || r.out["ok"] != true {
		t.Fatalf("the first attempt: %v %v", r.out, r.err)
	}
	if _, err := planRunLine(dcn, b64, "1", "", nil); err == nil || !strings.Contains(err.Error(), "already succeeded") {
		t.Fatalf("an attempt after one passed: %v", err)
	}
}

// A roll whose first attempt set the image and failed, and whose retry
// passed; the check then fails: the undo goes back to the image before the
// FIRST attempt, not to where the failed attempt left it — and the line, once
// undone, never runs again.
func TestAnUndoAfterARetryGoesBackToBeforeTheFirstAttempt(t *testing.T) {
	dcn, b64, f, old, built := shipRig(t, "", "true", `[ "$PRIVATAE_OP_MODE" = verify ] && { echo "the bridge does not answer"; exit 1; }; true`, 1)
	failKubeAt(t, "rollout", 1)
	b1, err := planRunLine(dcn, b64, "1", "", nil)
	if err != nil || b1["ok"] != true {
		t.Fatalf("build: %v %v", b1, err)
	}
	a1, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
	if err != nil || a1["ok"] != false || f.containers["bridge"] != built {
		t.Fatalf("roll attempt 1 sets the image and fails its rollout: %v %v %s", a1, err, f.containers["bridge"])
	}
	a2, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
	if err != nil || a2["ok"] != true {
		t.Fatalf("roll attempt 2: %v %v", a2, err)
	}
	c, err := planRunLine(dcn, b64, "3", rigReceipts(b1, a2), nil)
	if err != nil || c["verify_error"] == "" {
		t.Fatalf("the check fails: %v %v", c, err)
	}
	u, err := planUndoLine(b64, "2", rigReceipt(c))
	if err != nil || u["ok"] != true {
		t.Fatalf("the undo: %v %v", u, err)
	}
	if f.containers["bridge"] != old {
		t.Fatalf("the undo went back to %s, not to %s from before the first attempt", f.containers["bridge"], old)
	}
	if _, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil); err == nil || !strings.Contains(err.Error(), "was undone") {
		t.Fatalf("a line run after its undo: %v", err)
	}
}

// Only the latest attempt's failure undoes the line itself, and never once an
// attempt passed.
func TestOnlyTheLatestAttemptsFailureUndoesTheLine(t *testing.T) {
	t.Run("an attempt passed after it", func(t *testing.T) {
		dcn, b64, f, _, built := shipRig(t, "", "true", "true", 1)
		failKubeAt(t, "set", 1)
		b1, _ := planRunLine(dcn, b64, "1", "", nil)
		a1, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
		if err != nil || a1["ok"] != false {
			t.Fatalf("roll attempt 1 fails: %v %v", a1, err)
		}
		a2, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
		if err != nil || a2["ok"] != true {
			t.Fatalf("roll attempt 2 passes: %v %v", a2, err)
		}
		if _, err := planUndoLine(b64, "2", rigReceipt(a1)); err == nil || !strings.Contains(err.Error(), "passed here") {
			t.Fatalf("attempt 1's failure after attempt 2 passed: %v", err)
		}
		if f.containers["bridge"] != built {
			t.Fatal("the shipped image stays")
		}
	})
	t.Run("both attempts failed", func(t *testing.T) {
		dcn, b64, f, old, built := shipRig(t, "", "true", "true", 1)
		failKubeAt(t, "rollout", 1, 2)
		b1, _ := planRunLine(dcn, b64, "1", "", nil)
		a1, _ := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
		a2, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
		if err != nil || a1["ok"] != false || a2["ok"] != false || f.containers["bridge"] != built {
			t.Fatalf("both attempts fail with the image set: %v %v %v", a1, a2, err)
		}
		if _, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil); err == nil || !strings.Contains(err.Error(), "all it may") {
			t.Fatalf("a third attempt of two: %v", err)
		}
		if _, err := planUndoLine(b64, "2", rigReceipt(a1)); err == nil || !strings.Contains(err.Error(), "latest attempt here is 2") {
			t.Fatalf("an earlier attempt's failure: %v", err)
		}
		u, err := planUndoLine(b64, "2", rigReceipt(a2))
		if err != nil || u["ok"] != true || f.containers["bridge"] != old {
			t.Fatalf("the latest attempt's failure undoes to before the first: %v %v %s", u, err, f.containers["bridge"])
		}
	})
}

// A later line's failed check undoes an earlier line only on its last
// allowed attempt: a retry of the check may still pass.
func TestALaterLinesCheckUndoesOnlyOnItsLastAttempt(t *testing.T) {
	dcn, b64, f, old, _ := shipRig(t, "", "true", `[ "$PRIVATAE_OP_MODE" = verify ] && exit 1; true`, 2)
	b1, _ := planRunLine(dcn, b64, "1", "", nil)
	r1, _ := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
	c1, err := planRunLine(dcn, b64, "3", rigReceipts(b1, r1), nil)
	if err != nil || c1["verify_error"] == "" {
		t.Fatalf("check attempt 1 fails: %v %v", c1, err)
	}
	if _, err := planUndoLine(b64, "2", rigReceipt(c1)); err == nil || !strings.Contains(err.Error(), "only its last attempt") {
		t.Fatalf("attempt 1 of 2 of the check: %v", err)
	}
	c2, err := planRunLine(dcn, b64, "3", rigReceipts(b1, r1), nil)
	if err != nil || c2["verify_error"] == "" {
		t.Fatalf("check attempt 2 fails: %v %v", c2, err)
	}
	if u, err := planUndoLine(b64, "2", rigReceipt(c2)); err != nil || u["ok"] != true || f.containers["bridge"] != old {
		t.Fatalf("the last attempt's failed check undoes the roll: %v %v", u, err)
	}
}

// A verb the machine cannot record for its undo does not run.
func TestAVerbThatCannotBeRecordedDoesNotRun(t *testing.T) {
	dcn, b64, f, old, _ := shipRig(t, "", `[ "$PRIVATAE_OP_MODE" = apply ] && sleep 2; true`, "true", 1)
	b1, _ := planRunLine(dcn, b64, "1", "", nil)
	p, _, _, _ := planDecodeArgs([]string{b64, "2"})
	go func() {
		// While the roll's program runs, the record stops being this attempt's.
		time.Sleep(700 * time.Millisecond)
		planLineMu.Lock()
		defer planLineMu.Unlock()
		rec, _ := planLoadRun(p.Nonce, 2)
		rec.Attempt = 9
		_ = planSaveRun(rec)
	}()
	r, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
	if err != nil || r["ok"] != false || !strings.Contains(fmt.Sprint(r["error"]), "could not be recorded") {
		t.Fatalf("the roll: %v %v", r, err)
	}
	if f.containers["bridge"] != old {
		t.Fatal("the image was set with no record of it")
	}
}

// An attempt the bastion died in: settled at startup from its kept receipt,
// or, with none, as failed with a signed receipt saying so; the next attempt
// may then run, and the pod reads the settled receipt.
func TestAnAttemptTheBastionDiedInIsSettled(t *testing.T) {
	dcn := planBox(t)
	b64, p := signPlan(t, dcn, planDraft(false), "")
	raw, _ := base64.StdEncoding.DecodeString(b64)
	var e shipPlanEnvelope
	_ = json.Unmarshal(raw, &e)
	_, sha, _ := planOpen(e)
	l := &p.Lines[1]
	l.Attempts = 3
	tmpl := lineReceipt{Plan: p.Nonce, PlanSHA256: sha, Pipeline: p.Pipeline, Commit: p.Commit, N: 2, Step: l.Step, Machine: planHost()}
	k, err := planBeginAttempt(p, l, tmpl)
	if err != nil || k != 1 {
		t.Fatalf("attempt 1: %d %v", k, err)
	}
	if _, err := planBeginAttempt(p, l, tmpl); err == nil || !strings.Contains(err.Error(), "is running here") {
		t.Fatalf("a second attempt while this process runs the first: %v", err)
	}
	died := func() {
		planLineMu.Lock()
		defer planLineMu.Unlock()
		rec, _ := planLoadRun(p.Nonce, 2)
		rec.Proc = "gone:1:1"
		_ = planSaveRun(rec)
	}
	died()
	planSettleStopped()
	got := planKeptReceipt(p.Nonce, 2, 1)
	if got == nil || !got.failed() || !strings.Contains(got.Error, "stopped when the bastion") {
		t.Fatalf("the stopped attempt's receipt: %+v", got)
	}
	if k, err := planBeginAttempt(p, l, tmpl); err != nil || k != 2 {
		t.Fatalf("attempt 2 after a settled attempt 1: %d %v", k, err)
	}
	// Attempt 2 passed and its receipt was kept, and the process died before
	// it recorded the end: settled as passed, from the receipt.
	pass := tmpl
	pass.Attempt, pass.OK = 2, true
	s, _ := lineReceiptSign(pass)
	if err := planKeepReceipt(p.Nonce, 2, s); err != nil {
		t.Fatal(err)
	}
	died()
	if _, err := planBeginAttempt(p, l, tmpl); err == nil || !strings.Contains(err.Error(), "already succeeded") {
		t.Fatalf("an attempt after a passed one the bastion died before recording: %v", err)
	}
}

// The undo's rules against the line's record, each on its own.
func TestAnUndoMatchesTheReceiptToTheLinesRecord(t *testing.T) {
	cases := []struct {
		name  string
		rec   planRunRecord
		fr    lineReceipt
		later bool
		want  string
	}{
		{"while an attempt runs", planRunRecord{N: 2, Attempt: 1, State: planStateRunning}, lineReceipt{N: 3, Attempt: 1, OK: true, VerifyError: "x"}, true, "running here"},
		{"twice", planRunRecord{N: 2, Attempt: 1, State: planStateUndone}, lineReceipt{N: 2, Attempt: 1}, false, "undone here already"},
		{"a later failure of a line that did not pass", planRunRecord{N: 2, Attempt: 2, State: planStateFailed}, lineReceipt{N: 3, Attempt: 1, OK: true, VerifyError: "x"}, true, "did not pass here"},
		{"its own failure once an attempt passed", planRunRecord{N: 2, Attempt: 2, State: planStatePassed}, lineReceipt{N: 2, Attempt: 2}, false, "passed here"},
		{"an earlier attempt's failure", planRunRecord{N: 2, Attempt: 2, State: planStateFailed}, lineReceipt{N: 2, Attempt: 1}, false, "latest attempt here is 2"},
	}
	for _, c := range cases {
		if err := planUndoAllowed(&c.rec, &c.fr, c.later); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := planUndoAllowed(&planRunRecord{N: 2, Attempt: 2, State: planStateFailed}, &lineReceipt{N: 2, Attempt: 2}, false); err != nil {
		t.Errorf("the latest attempt's failure: %v", err)
	}
	if err := planUndoAllowed(&planRunRecord{N: 2, Attempt: 1, State: planStatePassed}, &lineReceipt{N: 3, Attempt: 1, OK: true, VerifyError: "x"}, true); err != nil {
		t.Errorf("a later failure of a line that passed: %v", err)
	}
}

// An attempt the spent ledger and the record disagree on does not run, and a
// line's record outlives its plan only by planKeepAfterExpiry.
func TestALinesRecordAndLedgerAgreeAndAreLetGo(t *testing.T) {
	dcn := planBox(t)
	_, p := signPlan(t, dcn, planDraft(false), "")
	l := &p.Lines[1]
	l.Attempts = 2
	if _, err := planSpendAttempt(p, l); err != nil {
		t.Fatal(err)
	}
	if _, err := planBeginAttempt(p, l, lineReceipt{}); err == nil || !strings.Contains(err.Error(), "out of order") {
		t.Fatalf("an attempt spent with no record of it: %v", err)
	}
	keep := func(nonce, exp string) (string, string) {
		rec := &planRunRecord{Plan: nonce, N: 1, Attempt: 1, State: planStatePassed, Expires: exp}
		if err := planSaveRun(rec); err != nil {
			t.Fatal(err)
		}
		_ = planKeepReceipt(nonce, 1, opSignedReceipt{})
		a, _ := planRunPath(nonce, 1)
		b, _ := planReceiptsPath(nonce, 1)
		return a, b
	}
	oldRec, oldRcpt := keep("oldplan", time.Now().Add(-planKeepAfterExpiry-time.Hour).UTC().Format(time.RFC3339))
	newRec, newRcpt := keep("newplan", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	planSettleStopped()
	for _, f := range []string{oldRec, oldRcpt} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s outlived its plan", f)
		}
	}
	for _, f := range []string{newRec, newRcpt} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s was let go early", f)
		}
	}
}

// A retry whose target something else moved since the first attempt does not
// run: an undo to before that attempt would take the other change back.
func TestARetryLeavesATargetSomethingElseMovedAlone(t *testing.T) {
	dcn, b64, f, _, _ := shipRig(t, "", "true", "true", 1)
	failKubeAt(t, "set", 1)
	b1, _ := planRunLine(dcn, b64, "1", "", nil)
	a1, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
	if err != nil || a1["ok"] != false {
		t.Fatalf("roll attempt 1 fails before it sets anything: %v %v", a1, err)
	}
	// Another pipeline rolls the workload (a security fix, say).
	fix := tImage + "@sha256:" + strings.Repeat("3", 64)
	f.containers["bridge"] = fix
	a2, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
	if err != nil || a2["ok"] != false || !strings.Contains(fmt.Sprint(a2["error"]), "something else moved it since") {
		t.Fatalf("the retry over a moved target: %v %v", a2, err)
	}
	if f.containers["bridge"] != fix {
		t.Fatalf("the retry rolled over the other change: %s", f.containers["bridge"])
	}
	u, err := planUndoLine(b64, "2", rigReceipt(a2))
	if err != nil {
		t.Fatalf("the undo on the retry's failure: %v", err)
	}
	if u["ok"] != false || f.containers["bridge"] != fix {
		t.Fatalf("the undo took the other change back: %v %s", u, f.containers["bridge"])
	}
}

// Only a process known to be gone settles its attempt: a /proc that cannot
// be read is no answer.
func TestOnlyAProcessKnownToBeGoneIsSettled(t *testing.T) {
	if planProc == "" || planProcGone(planProc) {
		t.Fatalf("this process reads as gone: %q", planProc)
	}
	parts := strings.Split(planProc, ":")
	if !planProcGone(parts[0] + ":" + parts[1] + ":1") {
		t.Error("another process under this pid is not this one")
	}
	if !planProcGone(parts[0] + ":999999999:1") {
		t.Error("a pid that is not there")
	}
	prev := planProcRoot
	t.Cleanup(func() { planProcRoot = prev })
	planProcRoot = t.TempDir() // no boot id, no processes: nothing reads
	if planProcGone(planProc) || planProcGone(parts[0]+":999999999:1") {
		t.Error("a /proc that does not read settled an attempt")
	}
}

// A target something else moves while the line's program runs is left
// alone: the verb refuses the state it finds, so no undo can take the other
// change back.
func TestATargetMovedWhileTheProgramRunsIsLeftAlone(t *testing.T) {
	dcn, b64, f, _, _ := shipRig(t, "", `[ "$PRIVATAE_OP_MODE" = apply ] && sleep 3; true`, `[ "$PRIVATAE_OP_MODE" = verify ] && exit 1; true`, 1)
	b1, _ := planRunLine(dcn, b64, "1", "", nil)
	fix := tImage + "@sha256:" + strings.Repeat("3", 64)
	var mu sync.Mutex
	prev := opKubectl
	opKubectl = func(ctx context.Context, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return prev(ctx, args...)
	}
	t.Cleanup(func() { opKubectl = prev })
	go func() {
		time.Sleep(1500 * time.Millisecond)
		mu.Lock()
		f.containers["bridge"] = fix // another pipeline rolls it
		mu.Unlock()
	}()
	r, err := planRunLine(dcn, b64, "2", rigReceipts(b1), nil)
	if err != nil || r["ok"] != false || !strings.Contains(fmt.Sprint(r["error"]), "something else moved it since") {
		t.Fatalf("the roll over a target moved while its program ran: %v %v", r, err)
	}
	if f.containers["bridge"] != fix {
		t.Fatalf("the roll set over the other change: %s", f.containers["bridge"])
	}
	// Its own failure is the latest attempt's: the undo finds nothing of
	// this line on the workload, and leaves the other change in place.
	if _, err := planUndoLine(b64, "2", rigReceipt(r)); err != nil {
		t.Fatalf("the undo: %v", err)
	}
	if f.containers["bridge"] != fix {
		t.Fatalf("the undo took the other change back: %s", f.containers["bridge"])
	}
}

// A verb refuses a target in any other state than the one it was approved
// and recorded to move from.
func TestAVerbMovesOnlyFromTheStateItWasApprovedToMoveFrom(t *testing.T) {
	if err := opMovedSince("a", "a"); err != nil {
		t.Errorf("the approved state: %v", err)
	}
	if err := opMovedSince("b", ""); err != nil {
		t.Errorf("a verb with no state (a unit): %v", err)
	}
	if err := opMovedSince("b", "a"); err == nil {
		t.Error("another state")
	}
	setupBox(t)
	live, next := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	issueReceipt(t, live, strings.Repeat("a", 40))
	issueReceipt(t, next, strings.Repeat("b", 40))
	if err := opRecordRoll(live, opRollRec{Image: tImage, Source: tRepo, Commit: strings.Repeat("a", 40)}); err != nil {
		t.Fatal(err)
	}
	useAncestry(t, func(_, _, _ string, _ []string) error { return nil })
	f := &fakeKube{containers: map[string]string{"bridge": tImage + "@" + live}}
	useFakeKube(t, f)
	if _, err := opImageDo(context.Background(), setImageLine(next), nil, nil, tImage+"@sha256:"+strings.Repeat("9", 64)); err == nil || !strings.Contains(err.Error(), "something else moved it since") || len(f.sets()) != 0 {
		t.Fatalf("an image in another state than approved: %v %v", err, f.sets())
	}
	// Something else rolls it while the ancestry fetch runs: read again
	// right before the write, and nothing is set.
	fix := tImage + "@sha256:" + strings.Repeat("3", 64)
	useAncestry(t, func(_, _, _ string, _ []string) error { f.containers["bridge"] = fix; return nil })
	if _, err := opImageDo(context.Background(), setImageLine(next), nil, nil, tImage+"@"+live); err == nil || !strings.Contains(err.Error(), "something else moved it since") || len(f.sets()) != 0 || f.containers["bridge"] != fix {
		t.Fatalf("an image rolled while the ancestry was fetched: %v %v", err, f.sets())
	}
	f.containers["bridge"] = tImage + "@" + live
	useAncestry(t, func(_, _, _ string, _ []string) error { return nil })
	if _, err := opImageDo(context.Background(), setImageLine(next), nil, nil, tImage+"@"+live); err != nil || len(f.sets()) != 1 {
		t.Fatalf("the image in the approved state: %v %v", err, f.sets())
	}
}

// The same for a tree: a move approved from another commit than the tree is
// at does not run.
func TestATreeMovesOnlyFromTheCommitItWasApprovedToMoveFrom(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for the tree's ownership checks")
	}
	setupBox(t)
	useFileRepos(t)
	origin, tree, c1, c2 := twoCommitRepo(t, func(string) {}, func(o string) {
		_ = os.WriteFile(filepath.Join(o, "a.txt"), []byte("two\n"), 0o644)
	})
	line := opVerbLine{Verb: "tree.checkout", Args: map[string]string{"path": tree, "repo": "file://" + origin, "commit": c2}}
	if _, err := opTreeDo(context.Background(), line, nil, strings.Repeat("9", 40)); err == nil || !strings.Contains(err.Error(), "something else moved it since") {
		t.Fatalf("a tree at another commit than approved: %v", err)
	}
	if head := gitT(t, tree, "rev-parse", "HEAD"); head != c1 {
		t.Fatalf("the tree moved: %s", head)
	}
	// Something else moves it while the fetch runs: read again right before
	// the move, and it is left where the other change put it.
	prev := opTreeBeforeMove
	var other string
	opTreeBeforeMove = func(path string) {
		gitT(t, path, "commit", "-q", "--allow-empty", "-m", "someone else")
		other = gitT(t, path, "rev-parse", "HEAD")
	}
	if _, err := opTreeDo(context.Background(), line, nil, c1); err == nil || !strings.Contains(err.Error(), "something else moved it since") {
		t.Fatalf("a tree moved while the fetch ran: %v", err)
	}
	opTreeBeforeMove = prev
	if head := gitT(t, tree, "rev-parse", "HEAD"); head != other {
		t.Fatalf("the other change was moved over: %s", head)
	}
	gitT(t, tree, "reset", "-q", "--keep", c1)
	if _, err := opTreeDo(context.Background(), line, nil, c1); err != nil {
		t.Fatalf("the tree at the approved commit: %v", err)
	}
}

// Two changes this bastion makes to one workload never interleave between a
// read and a write: the second waits for the first, then finds it moved.
func TestTwoChangesToOneTargetNeverInterleave(t *testing.T) {
	setupBox(t)
	live, a, b := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("3", 64)
	issueReceipt(t, live, strings.Repeat("a", 40))
	issueReceipt(t, a, strings.Repeat("b", 40))
	issueReceipt(t, b, strings.Repeat("c", 40))
	if err := opRecordRoll(live, opRollRec{Image: tImage, Source: tRepo, Commit: strings.Repeat("a", 40)}); err != nil {
		t.Fatal(err)
	}
	useAncestry(t, func(_, _, _ string, _ []string) error { return nil })
	f := &fakeKube{containers: map[string]string{"bridge": tImage + "@" + live}}
	var mu sync.Mutex
	gets := 0
	paused, release := make(chan struct{}), make(chan struct{})
	prev := opKubectl
	opKubectl = func(ctx context.Context, args ...string) (string, error) {
		mu.Lock()
		out, err := f.run(ctx, args...)
		pause := false
		if len(args) >= 3 && args[2] == "get" {
			gets++
			pause = gets == 2 // the first roll's second read, one command before its write
		}
		mu.Unlock()
		if pause {
			close(paused)
			<-release
		}
		return out, err
	}
	t.Cleanup(func() { opKubectl = prev })
	first := make(chan error, 1)
	go func() {
		_, err := opImageDo(context.Background(), setImageLine(a), nil, nil, tImage+"@"+live)
		first <- err
	}()
	<-paused
	second := make(chan error, 1)
	go func() {
		_, err := opImageDo(context.Background(), setImageLine(b), nil, nil, tImage+"@"+live)
		second <- err
	}()
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	early := gets
	mu.Unlock()
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("the first roll: %v", err)
	}
	err := <-second
	if early != 2 {
		t.Fatalf("the second roll read the workload while the first was between its read and its write (%d reads)", early)
	}
	if err == nil || !strings.Contains(err.Error(), "something else moved it since") || f.containers["bridge"] != tImage+"@"+a {
		t.Fatalf("the second roll after the first: %v, live %s", err, f.containers["bridge"])
	}
}

// An undo reads its target again right before it writes: a change made
// since its first read is left alone.
func TestAnUndoReadsItsTargetAgainBeforeItWrites(t *testing.T) {
	t.Run("an image", func(t *testing.T) {
		from, to := tImage+"@sha256:"+strings.Repeat("1", 64), tImage+"@sha256:"+strings.Repeat("2", 64)
		fix := tImage + "@sha256:" + strings.Repeat("3", 64)
		f := &fakeKube{containers: map[string]string{"bridge": to}}
		gets := 0
		prev := opKubectl
		opKubectl = func(ctx context.Context, args ...string) (string, error) {
			out, err := f.run(ctx, args...)
			if len(args) >= 3 && args[2] == "get" {
				if gets++; gets == 1 {
					f.containers["bridge"] = fix // rolled right after the undo's first read
				}
			}
			return out, err
		}
		t.Cleanup(func() { opKubectl = prev })
		if _, err := planUndoVerb(context.Background(), setImageLine("sha256:"+strings.Repeat("2", 64)), from, to); err == nil || !strings.Contains(err.Error(), "something else moved it since") {
			t.Fatalf("an undo over a roll made after its first read: %v", err)
		}
		if f.containers["bridge"] != fix || len(f.sets()) != 0 {
			t.Fatalf("the other roll was taken back: %s %v", f.containers["bridge"], f.sets())
		}
	})
	t.Run("a tree", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root for the tree's ownership checks")
		}
		setupBox(t)
		useFileRepos(t)
		origin, tree, c1, c2 := twoCommitRepo(t, func(string) {}, func(o string) {
			_ = os.WriteFile(filepath.Join(o, "a.txt"), []byte("two\n"), 0o644)
		})
		line := opVerbLine{Verb: "tree.checkout", Args: map[string]string{"path": tree, "repo": "file://" + origin, "commit": c2}}
		if _, err := opTreeDo(context.Background(), line, nil, c1); err != nil {
			t.Fatal(err)
		}
		prev := opTreeBeforeMove
		t.Cleanup(func() { opTreeBeforeMove = prev })
		var other string
		opTreeBeforeMove = func(path string) {
			gitT(t, path, "commit", "-q", "--allow-empty", "-m", "someone else")
			other = gitT(t, path, "rev-parse", "HEAD")
		}
		if _, err := planUndoVerb(context.Background(), line, c1, c2); err == nil || !strings.Contains(err.Error(), "something else moved it since") {
			t.Fatalf("an undo over a commit made after its first read: %v", err)
		}
		if head := gitT(t, tree, "rev-parse", "HEAD"); head != other {
			t.Fatalf("the other commit was taken back: %s", head)
		}
	})
}

// A tree move and an undo wait for a change in flight on the same target.
func TestAChangeWaitsForOneInFlightOnTheSameTarget(t *testing.T) {
	waits := func(t *testing.T, line opVerbLine, run func() error, reached func() bool) {
		t.Helper()
		unlock := opLockTarget(line)
		done := make(chan error, 1)
		go func() { done <- run() }()
		time.Sleep(300 * time.Millisecond)
		if reached() {
			unlock()
			<-done
			t.Fatal("it read the target while another change held it")
		}
		unlock()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("it never ran once the other change was done")
		}
	}
	t.Run("an image undo", func(t *testing.T) {
		line := setImageLine("sha256:" + strings.Repeat("2", 64))
		f := &fakeKube{containers: map[string]string{"bridge": tImage + "@sha256:" + strings.Repeat("2", 64)}}
		var mu sync.Mutex
		prev := opKubectl
		opKubectl = func(ctx context.Context, args ...string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			return f.run(ctx, args...)
		}
		t.Cleanup(func() { opKubectl = prev })
		waits(t, line, func() error {
			_, err := planUndoVerb(context.Background(), line, tImage+"@sha256:"+strings.Repeat("1", 64), tImage+"@sha256:"+strings.Repeat("2", 64))
			return err
		}, func() bool { mu.Lock(); defer mu.Unlock(); return len(f.calls) > 0 })
	})
	for _, undo := range []bool{false, true} {
		name := "a tree move"
		if undo {
			name = "a tree undo"
		}
		t.Run(name, func(t *testing.T) {
			if os.Geteuid() != 0 {
				t.Skip("needs root for the tree's ownership checks")
			}
			setupBox(t)
			useFileRepos(t)
			origin, tree, c1, c2 := twoCommitRepo(t, func(string) {}, func(o string) {
				_ = os.WriteFile(filepath.Join(o, "a.txt"), []byte("two\n"), 0o644)
			})
			line := opVerbLine{Verb: "tree.checkout", Args: map[string]string{"path": tree, "repo": "file://" + origin, "commit": c2}}
			if undo {
				if _, err := opTreeDo(context.Background(), line, nil, c1); err != nil {
					t.Fatal(err)
				}
			}
			var mu sync.Mutex
			hit := false
			prev := opTreeBeforeMove
			t.Cleanup(func() { opTreeBeforeMove = prev })
			opTreeBeforeMove = func(string) { mu.Lock(); hit = true; mu.Unlock() }
			waits(t, line, func() error {
				if undo {
					_, err := planUndoVerb(context.Background(), line, c1, c2)
					return err
				}
				_, err := opTreeDo(context.Background(), line, nil, c1)
				return err
			}, func() bool { mu.Lock(); defer mu.Unlock(); return hit })
		})
	}
}
