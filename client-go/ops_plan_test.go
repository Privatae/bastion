//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// planBox makes this box both the person's approval device and a machine
// that has pinned it, with the device holding this machine's key: the setup
// a real device and a real machine reach through device-init, pin-device and
// pin-machine. dcn is the pairing dir the asks come in on (its factor checks
// the code).
func planBox(t *testing.T) (dcn string) {
	t.Helper()
	dcn, _ = opTestBox(t)
	pub, err := deviceInit()
	if err != nil {
		t.Fatal(err)
	}
	if err := pinDeviceKey(pub); err != nil {
		t.Fatal(err)
	}
	line := machineKeyLine()
	f := strings.Fields(line)
	if len(f) != 4 || f[1] != "pin-machine" {
		t.Fatalf("the machine prints the pin-machine line: %q", line)
	}
	if err := pinMachineKey(f[2], f[3]); err != nil {
		t.Fatal(err)
	}
	// The code is checked against the factor on the device's OWN pairing
	// (deviceFactorDir), whatever the ask said.
	fdir, err := deviceFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrollFactor(t, fdir)
	return dcn
}

func planCode(t *testing.T) string { return planCodeAt(0) }

// planCodeAt is the code `windows` periods from now: a code is spent once, so
// a second root plan in the same period takes the next one (inside the drift
// the check allows).
func planCodeAt(windows int64) string {
	raw, _ := b32decode(tSecret)
	return hotp(raw, time.Now().Unix()/stepupPeriod+windows)
}

func planHost() string { h, _ := os.Hostname(); return h }

var planDraftSeq int

// planDraft is a two-line ship on this machine: a build (program only) and a
// roll that takes the build's digest. Each draft differs (the device takes
// the same draft twice as the same ask).
func planDraft(root bool) map[string]any {
	planDraftSeq++
	hn := planHost()
	sha1, sha2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	roll := map[string]any{"n": 2, "step": "roll", "machine": hn, "op": "bridge-roll", "op_sha256": sha2,
		"params": `{}`, "inputs": map[string]any{"digest": "build.digest"}, "undo": true}
	if root {
		roll["verbs"] = []any{map[string]any{"verb": "unit.restart", "args": map[string]any{"unit": "x.service"}}}
	}
	return map[string]any{"kind": shipPlanKind, "plan": map[string]any{
		"pipeline": "bridge", "commit": strings.Repeat("c", 40),
		"expires": time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339),
		"lines": []any{
			map[string]any{"n": 1, "step": "build", "machine": hn, "op": "bridge-build", "op_sha256": sha1, "params": `{"x":"` + strconv.Itoa(planDraftSeq) + `"}`},
			roll,
		}}}
}

// signPlan files a draft on the device and approves it, returning the signed
// envelope as a machine receives it (base64 of the envelope's JSON).
func signPlan(t *testing.T, dcn string, details map[string]any, code string) (string, *shipPlan) {
	t.Helper()
	id, err := deviceNewPlanRequest(details)
	if err != nil {
		t.Fatal(err)
	}
	env, err := deviceApproveWithCode(id, code)
	if err != nil {
		t.Fatal(err)
	}
	var e shipPlanEnvelope
	if err := json.Unmarshal([]byte(env), &e); err != nil {
		t.Fatal(err)
	}
	p, _, err := planOpen(e)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString([]byte(env)), p
}

func TestTheDeviceSignsOnlyAPlanWhoseMachinesItPinned(t *testing.T) {
	dcn := planBox(t)
	// A machine the device never pinned: refused at the ask.
	d := planDraft(false)
	d["plan"].(map[string]any)["lines"].([]any)[0].(map[string]any)["machine"] = "stranger-1"
	if _, err := deviceNewPlanRequest(d); err == nil || !strings.Contains(err.Error(), "has not pinned stranger-1") {
		t.Fatalf("an unpinned machine: %v", err)
	}
	// A pinned one: the device fills in its OWN key for the machine, never
	// one the pod sent, and the words name every step.
	d = planDraft(false)
	d["plan"].(map[string]any)["machines"] = map[string]any{planHost(): base64.StdEncoding.EncodeToString(make([]byte, 32))}
	id, err := deviceNewPlanRequest(d)
	if err != nil {
		t.Fatal(err)
	}
	words := deviceRequestsLoad()[id].Words
	for _, want := range []string{"Ship bridge at commit cccccccccccc", "1. build on " + planHost(), "2. roll on " + planHost(),
		"digest = the digest step build builds", "may be undone"} {
		if !strings.Contains(words, want) {
			t.Errorf("the words say %q:\n%s", want, words)
		}
	}
	env, err := deviceApproveWithCode(id, "")
	if err != nil {
		t.Fatal(err)
	}
	var e shipPlanEnvelope
	_ = json.Unmarshal([]byte(env), &e)
	p, _, err := planOpen(e)
	if err != nil {
		t.Fatal(err)
	}
	own, _, _ := loadOrCreateOwnerKey()
	if p.Machines[planHost()] != base64.StdEncoding.EncodeToString(own) {
		t.Fatal("the plan carries the key the device pinned, not the pod's")
	}
	// Versions only go up.
	_, p2 := signPlan(t, dcn, planDraft(false), "")
	if p2.Version != p.Version+1 {
		t.Fatalf("the next plan for the pipeline is version %d, got %d", p.Version+1, p2.Version)
	}
}

func TestARootPlanNeedsTheCodeOnTheDevice(t *testing.T) {
	planBox(t)
	id, err := deviceNewPlanRequest(planDraft(true))
	if err != nil {
		t.Fatal(err)
	}
	if !deviceRequestsLoad()[id].NeedsCode {
		t.Fatal("a plan with verbs needs the code")
	}
	if _, err := deviceApproveWithCode(id, ""); err == nil || !strings.Contains(err.Error(), "with your code") {
		t.Fatalf("no code: %v", err)
	}
	if _, err := deviceApproveWithCode(id, "000000"); err == nil || !strings.Contains(err.Error(), "code") {
		t.Fatalf("a wrong code: %v", err)
	}
	env, err := deviceApproveWithCode(id, planCode(t))
	if err != nil {
		t.Fatal(err)
	}
	var e shipPlanEnvelope
	_ = json.Unmarshal([]byte(env), &e)
	p, _, err := planOpen(e)
	if err != nil || !p.Root || !p.CodeGiven {
		t.Fatalf("signed, root, with the code: %+v %v", p, err)
	}
	// "Approve all shown" never signs a root plan.
	id2, _ := deviceNewPlanRequest(planDraft(true))
	if p, _ := deviceShownPath(); p != "" {
		raw, _ := json.Marshal([]string{id2})
		_ = atomicWrite(p, raw)
	}
	if err := cmdDeviceApprove("all"); err != nil {
		t.Fatal(err)
	}
	if deviceRequestsLoad()[id2].State != "pending" {
		t.Fatal("approve-all signed a root plan")
	}
}

// The phase 2 gate: each of these is refused by the machine.
func TestAMachineRefusesEveryPlanItShouldNot(t *testing.T) {
	dcn := planBox(t)
	b64, p := signPlan(t, dcn, planDraft(false), "")
	envOf := func(b64 string) shipPlanEnvelope {
		raw, _ := base64.StdEncoding.DecodeString(b64)
		var e shipPlanEnvelope
		_ = json.Unmarshal(raw, &e)
		return e
	}
	reseal := func(mut func(*shipPlan)) string {
		e := envOf(b64)
		body, _ := base64.StdEncoding.DecodeString(e.Payload)
		var q shipPlan
		_ = json.Unmarshal(body, &q)
		mut(&q)
		nb, _ := json.Marshal(q)
		e.Payload = base64.StdEncoding.EncodeToString(nb) // the old signature, new bytes
		raw, _ := json.Marshal(e)
		return base64.StdEncoding.EncodeToString(raw)
	}
	// A tampered line: the device's signature no longer covers it.
	for name, bad := range map[string]string{
		"a changed op":      reseal(func(q *shipPlan) { q.Lines[0].OpSHA256 = strings.Repeat("f", 64) }),
		"changed params":    reseal(func(q *shipPlan) { q.Lines[0].Params = `{"x":"changed"}` }),
		"another commit":    reseal(func(q *shipPlan) { q.Commit = strings.Repeat("d", 40) }),
		"a longer life":     reseal(func(q *shipPlan) { q.Expires = time.Now().Add(time.Hour).UTC().Format(time.RFC3339) }),
		"root claimed code": reseal(func(q *shipPlan) { q.CodeGiven = true }),
	} {
		if _, err := planRunLine(dcn, bad, "1", "", nil); err == nil || !strings.Contains(err.Error(), "signature does not verify") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The wrong machine: a line for another host.
	d := planDraft(false)
	lines := d["plan"].(map[string]any)["lines"].([]any)
	lines[0].(map[string]any)["machine"] = "elsewhere-2"
	pub2, _, _ := ed25519.GenerateKey(nil)
	_ = pinMachineKey("elsewhere-2", base64.StdEncoding.EncodeToString(pub2))
	wrong, _ := signPlan(t, dcn, d, "")
	if _, err := planRunLine(dcn, wrong, "1", "", nil); err == nil || !strings.Contains(err.Error(), "is for elsewhere-2") {
		t.Errorf("a line for another machine: %v", err)
	}
	// A key other than this machine's own: the device pinned someone else
	// under this machine's name.
	_ = unpinMachineKey(planHost())
	_ = pinMachineKey(planHost(), base64.StdEncoding.EncodeToString(pub2))
	impostor, _ := signPlan(t, dcn, planDraft(false), "")
	if _, err := planRunLine(dcn, impostor, "1", "", nil); err == nil || !strings.Contains(err.Error(), "another key for this machine") {
		t.Errorf("a key that differs from this machine's: %v", err)
	}
	_ = unpinMachineKey(planHost())
	own := strings.Fields(machineKeyLine())[3]
	_ = pinMachineKey(planHost(), own)
	// A device this machine never pinned.
	if err := unpinDeviceKey(p.Device); err != nil {
		t.Fatal(err)
	}
	if _, err := planRunLine(dcn, b64, "1", "", nil); err == nil || !strings.Contains(err.Error(), "has not pinned") {
		t.Errorf("an unpinned device: %v", err)
	}
	_ = pinDeviceKey(p.Device)
	// A missing receipt, and a foreign one: line 2 takes build's digest.
	if _, err := planRunLine(dcn, b64, "2", "", nil); err == nil || !strings.Contains(err.Error(), "no successful receipt of it came") {
		t.Errorf("a missing receipt: %v", err)
	}
	_, sha, _ := planOpen(envOf(b64))
	good := lineReceipt{Plan: p.Nonce, PlanSHA256: sha, Pipeline: p.Pipeline, Commit: p.Commit, N: 1, Step: "build",
		Machine: planHost(), OK: true, Images: []opResultImage{{Image: "forge.example.com/acme/web",
			Digest: "sha256:" + strings.Repeat("1", 64), Source: "https://forge.example.com/acme/app.git", Commit: p.Commit}}}
	fpub, fpriv, _ := ed25519.GenerateKey(nil)
	foreign := good
	foreign.V, foreign.Key = 1, base64.StdEncoding.EncodeToString(fpub)
	fraw, _ := json.Marshal(foreign)
	fs := opSignedReceipt{PayloadType: lineReceiptPayloadType, Payload: base64.StdEncoding.EncodeToString(fraw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(fpriv, dssePAE(lineReceiptPayloadType, fraw)))}
	if _, err := lineReceiptVerify(fs, p, sha); err == nil || !strings.Contains(err.Error(), "does not name") {
		t.Errorf("a foreign receipt: %v", err)
	}
	// A receipt of another plan, and one of a failed build, feed nothing.
	_, p3 := signPlan(t, dcn, planDraft(false), "")
	otherPlan := good
	otherPlan.Plan = p3.Nonce
	s3, _ := lineReceiptSign(otherPlan)
	if _, err := lineReceiptVerify(s3, p, sha); err == nil || !strings.Contains(err.Error(), "another plan") {
		t.Errorf("another plan's receipt: %v", err)
	}
	failedBuild := good
	failedBuild.OK = false
	s4, _ := lineReceiptSign(failedBuild)
	if _, _, err := planInputs(p, sha, &p.Lines[1], []opSignedReceipt{s4}); err == nil || !strings.Contains(err.Error(), "succeeded") {
		t.Errorf("a failed build's receipt: %v", err)
	}
	s5, _ := lineReceiptSign(good)
	params, _, err := planInputs(p, sha, &p.Lines[1], []opSignedReceipt{s5})
	if err != nil || !strings.Contains(params, "sha256:"+strings.Repeat("1", 64)) {
		t.Fatalf("the build's receipt fills the roll's digest: %q %v", params, err)
	}
	// An expired plan.
	d = planDraft(false)
	d["plan"].(map[string]any)["expires"] = time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339)
	soon, _ := signPlan(t, dcn, d, "")
	time.Sleep(3 * time.Second)
	if _, err := planRunLine(dcn, soon, "1", "", nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired plan: %v", err)
	}
	// A replayed line: spent once.
	if err := planSpend(p, "1"); err != nil {
		t.Fatal(err)
	}
	if err := planSpend(p, "1"); err == nil || !strings.Contains(err.Error(), "ran already") {
		t.Errorf("a replayed line: %v", err)
	}
	// An older plan than one this machine ran for the pipeline.
	_ = planRecordVersion(p.Pipeline, p3.Version)
	if _, err := planLineFor(p, 1); err == nil || !strings.Contains(err.Error(), "is older") {
		t.Errorf("an older version: %v", err)
	}
}

func TestAnUndoNeedsAFailedLaterLineOfThePlan(t *testing.T) {
	dcn := planBox(t)
	b64, p := signPlan(t, dcn, planDraft(false), "")
	raw, _ := base64.StdEncoding.DecodeString(b64)
	var e shipPlanEnvelope
	_ = json.Unmarshal(raw, &e)
	_, sha, _ := planOpen(e)
	rec := func(n int, ok bool, verr string) string {
		s, _ := lineReceiptSign(lineReceipt{Plan: p.Nonce, PlanSHA256: sha, Pipeline: p.Pipeline, Commit: p.Commit,
			N: n, Step: p.Lines[n-1].Step, Machine: planHost(), OK: ok, VerifyError: verr, Attempt: 1})
		b, _ := json.Marshal(s)
		return base64.StdEncoding.EncodeToString(b)
	}
	// Line 1 is not marked undoable in this plan; line 2 is.
	if _, err := planUndoLine(b64, "1", rec(2, false, "")); err == nil || !strings.Contains(err.Error(), "not one the plan lets be undone") {
		t.Errorf("an undo the plan does not allow: %v", err)
	}
	// An earlier line's failure, or any success, starts no undo of line 2.
	for name, r := range map[string]string{"an earlier failure": rec(1, false, ""), "a success": rec(1, true, ""),
		"its own success": rec(2, true, "")} {
		if _, err := planUndoLine(b64, "2", r); err == nil || !strings.Contains(err.Error(), "LATER line") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Its own failure may take back what it did — but it never ran here.
	if _, err := planUndoLine(b64, "2", rec(2, false, "")); err == nil || !strings.Contains(err.Error(), "no record of running line 2") {
		t.Errorf("its own failure, on a machine that never ran it: %v", err)
	}
	// A three-line plan: line 3's failed check undoes line 2, once, and only
	// to what this machine recorded before line 2 ran.
	d := planDraft(false)
	lines := d["plan"].(map[string]any)["lines"].([]any)
	lines = append(lines, map[string]any{"n": 3, "step": "check", "machine": planHost(), "op": "bridge-check",
		"op_sha256": strings.Repeat("e", 64), "params": `{}`})
	d["plan"].(map[string]any)["lines"] = lines
	b64, p = signPlan(t, dcn, d, "")
	raw, _ = base64.StdEncoding.DecodeString(b64)
	_ = json.Unmarshal(raw, &e)
	_, sha, _ = planOpen(e)
	if _, err := planUndoLine(b64, "2", rec(3, true, "")); err == nil || !strings.Contains(err.Error(), "LATER line") {
		t.Errorf("a later line that passed: %v", err)
	}
	// A later line whose APPLY failed (a bad credential the pod handed can
	// do that) is not a failed check, and starts nothing.
	if _, err := planUndoLine(b64, "2", rec(3, false, "")); err == nil || !strings.Contains(err.Error(), "LATER line") {
		t.Errorf("a later line whose apply failed: %v", err)
	}
	if _, err := planUndoLine(b64, "2", rec(3, true, "verify exited 1")); err == nil || !strings.Contains(err.Error(), "no record of running line 2") {
		t.Errorf("a line this machine never ran: %v", err)
	}
	path, _ := planRunPath(p.Nonce, 2)
	body, _ := json.Marshal(planRunRecord{Plan: p.Nonce, N: 2, Attempt: 1, State: planStatePassed})
	_ = os.WriteFile(path, body, 0o600)
	out, err := planUndoLine(b64, "2", rec(3, true, "verify exited 1"))
	if err != nil || out["ok"] != true {
		t.Fatalf("a failed check of a later line undoes it: %v %v", out, err)
	}
	if _, err := planUndoLine(b64, "2", rec(3, true, "logs.check failed")); err == nil || !strings.Contains(err.Error(), "undone here already") {
		t.Errorf("an undo is spent once: %v", err)
	}
}

// The device's words and the plan's form: nothing a pod writes can redraw,
// hide or reorder what the person reads, and a line shows only verbs this
// bastion runs with their own arguments.
func TestAPlanCarriesNothingThatCouldHideWhatThePersonReads(t *testing.T) {
	planBox(t)
	mut := func(f func(l map[string]any)) map[string]any {
		d := planDraft(false)
		f(d["plan"].(map[string]any)["lines"].([]any)[1].(map[string]any))
		return d
	}
	for name, d := range map[string]map[string]any{
		"an escape in an input's image": mut(func(l map[string]any) {
			l["inputs"] = map[string]any{"digest": "build.digest:x\x1b[2A\x1b[2K\r"}
		}),
		"a line break in params":         mut(func(l map[string]any) { l["params"] = "{\"a\":\"x\n   (FAKE)\"}" }),
		"a direction override in params": mut(func(l map[string]any) { l["params"] = "{\"a\":\"\u202egnp.exe\"}" }),
		"a key twice in params":          mut(func(l map[string]any) { l["params"] = `{"a":"1","a":"2"}` }),
		"a verb this bastion does not run": mut(func(l map[string]any) {
			l["verbs"] = []any{map[string]any{"verb": "shell.run\x1b[2A", "args": map[string]any{}}}
		}),
		"an argument name the verb does not take": mut(func(l map[string]any) {
			l["verbs"] = []any{map[string]any{"verb": "unit.restart", "args": map[string]any{"unit": "x.service", "note\x1b[1A": "y"}}}
		}),
		"a control character in a verb's value": mut(func(l map[string]any) {
			l["verbs"] = []any{map[string]any{"verb": "unit.restart", "args": map[string]any{"unit": "x.service\r"}}}
		}),
	} {
		if _, err := deviceNewPlanRequest(d); err == nil {
			t.Errorf("%s: filed", name)
		}
	}
	// C1 too: U+009B is a whole escape sequence's opener on its own, U+0085 a line break.
	if got := wordsSafe("a\x1b[2Ab\u202ec\nd\u009b2Ae\u0085f"); strings.ContainsAny(got, "\x1b\u202e\n\u009b\u0085") {
		t.Fatalf("the words carry no control or direction character: %q", got)
	}
	// An input that names its image reads right.
	d := planDraft(false)
	d["plan"].(map[string]any)["lines"].([]any)[1].(map[string]any)["inputs"] = map[string]any{"digest": "build.digest:forge.example.com/acme/web"}
	id, err := deviceNewPlanRequest(d)
	if err != nil {
		t.Fatal(err)
	}
	if w := deviceRequestsLoad()[id].Words; !strings.Contains(w, "digest = the digest of forge.example.com/acme/web that step build builds") {
		t.Fatalf("the words: %s", w)
	}
}

// A line runs only after every line before it succeeded, and runs at most
// as many times as the plan allows.
func TestLinesRunInOrderAndOnlyAsOftenAsThePlanAllows(t *testing.T) {
	dcn := planBox(t)
	d := planDraft(false)
	lines := d["plan"].(map[string]any)["lines"].([]any)
	lines = append(lines, map[string]any{"n": 3, "step": "check", "machine": planHost(), "op": "bridge-check",
		"op_sha256": strings.Repeat("e", 64), "params": `{}`, "attempts": 2})
	d["plan"].(map[string]any)["lines"] = lines
	b64, p := signPlan(t, dcn, d, "")
	raw, _ := base64.StdEncoding.DecodeString(b64)
	var e shipPlanEnvelope
	_ = json.Unmarshal(raw, &e)
	_, sha, _ := planOpen(e)
	sign := func(n int, ok bool) opSignedReceipt {
		s, _ := lineReceiptSign(lineReceipt{Plan: p.Nonce, PlanSHA256: sha, Pipeline: p.Pipeline, Commit: p.Commit,
			N: n, Step: p.Lines[n-1].Step, Machine: planHost(), OK: ok})
		return s
	}
	enc := func(rs ...opSignedReceipt) string {
		b, _ := json.Marshal(rs)
		return base64.StdEncoding.EncodeToString(b)
	}
	// The check before the build and the roll: refused, nothing spent.
	if _, err := planRunLine(dcn, b64, "3", "", nil); err == nil || !strings.Contains(err.Error(), "runs only after line 1") {
		t.Fatalf("a line before the ones before it: %v", err)
	}
	if _, err := planRunLine(dcn, b64, "3", enc(sign(1, true)), nil); err == nil || !strings.Contains(err.Error(), "runs only after line 2") {
		t.Fatalf("a line after only some of the ones before it: %v", err)
	}
	if _, err := planRunLine(dcn, b64, "3", enc(sign(1, true), sign(2, false)), nil); err == nil || !strings.Contains(err.Error(), "runs only after line 2") {
		t.Fatalf("a line after one that failed: %v", err)
	}
	// Attempts: line 3 may run twice, and no more.
	l := &p.Lines[2]
	for want := 1; want <= 2; want++ {
		if k, err := planSpendAttempt(p, l); err != nil || k != want {
			t.Fatalf("attempt %d: %d %v", want, k, err)
		}
	}
	if _, err := planSpendAttempt(p, l); err == nil || !strings.Contains(err.Error(), "all it may") {
		t.Fatalf("a third attempt: %v", err)
	}
}

// signPlanRaw signs any plan with this device's key, as a device that was
// changed (or a forged one holding the key) could: the machine's own checks
// must hold even then.
func signPlanRaw(t *testing.T, p *shipPlan) string {
	t.Helper()
	f, err := deviceKeyLoad()
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := base64.StdEncoding.DecodeString(f.Priv)
	p.Device = f.Pub
	body, _ := json.Marshal(p)
	env := shipPlanEnvelope{PayloadType: shipPlanPayloadType, Payload: base64.StdEncoding.EncodeToString(body),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(priv), dssePAE(shipPlanPayloadType, body)))}
	raw, _ := json.Marshal(env)
	return base64.StdEncoding.EncodeToString(raw)
}

// A root line runs only from a plan that says the code was given, whatever
// signed it; and a line runs only with the verbs its held op declares.
func TestARootLineNeedsTheCodeAndTheOpsOwnVerbs(t *testing.T) {
	dcn := planBox(t)
	own := strings.Fields(machineKeyLine())[3]
	p := &shipPlan{V: shipPlanVersion, Kind: shipPlanKind, Pipeline: "bridge", Version: 1, Commit: strings.Repeat("c", 40),
		Nonce: strings.Repeat("9", 32), Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Root: true,
		Machines: map[string]string{planHost(): own},
		Lines: []shipPlanLine{{N: 1, Step: "roll", Machine: planHost(), Op: "bridge-roll", OpSHA256: strings.Repeat("b", 64),
			Params: `{}`, Verbs: []opVerbLine{{Verb: "unit.restart", Args: map[string]string{"unit": "x.service"}}}}}}
	if _, err := planRunLine(dcn, signPlanRaw(t, p), "1", "", nil); err == nil || !strings.Contains(err.Error(), "approved with your code") {
		t.Fatalf("a root line without the code: %v", err)
	}
	// The verbs a line shows must be exactly the held op's.
	man := `name: bridge-roll
version: 1.0.0
summary: Restart the bridge.
kind: action
target: machine
privilege: root
interpreter: /bin/sh
time_limit: 30
params: {}
verbs:
  - {verb: unit.restart, unit: ceigas-governance-bridge.service}
modes: [dry_run, apply, verify]
undo: none
`
	m, err := parseOpManifest([]byte(man))
	if err != nil {
		t.Fatal(err)
	}
	l := shipPlanLine{N: 1, Step: "roll", Op: "bridge-roll", Params: `{}`}
	l.Verbs = planVerbsForShow(m, &l)
	if err := planLineMatchesOp(&l, m, `{}`); err != nil {
		t.Fatalf("the op's own verbs: %v", err)
	}
	l.Verbs = []opVerbLine{{Verb: "unit.restart", Args: map[string]string{"unit": "something-harmless.service"}}}
	if err := planLineMatchesOp(&l, m, `{}`); err == nil || !strings.Contains(err.Error(), "other verbs") {
		t.Fatalf("a line that shows other verbs than the op runs: %v", err)
	}
	l.Verbs = nil
	if err := planLineMatchesOp(&l, m, `{}`); err == nil {
		t.Fatal("a line that shows no verbs for a root op")
	}
}

// The approvals page: a root plan's card asks for the code, and "approve all
// shown" leaves it waiting, even when its id is posted.
func TestThePageAsksTheCodeForARootPlanAndNeverApprovesItWithAll(t *testing.T) {
	planBox(t)
	root, err := deviceNewPlanRequest(planDraft(true))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := deviceNewPlanRequest(planDraft(false))
	b, _ := deviceNewPlanRequest(planDraft(false))
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	body := uiGet(t, h, "/fragments/approvals", cookie).Body.String()
	// The card's approve form: the one posting to /device/approve with its id.
	asked := false
	for _, f := range strings.Split(body, `<form hx-post="/device/approve" `)[1:] {
		f = f[:strings.Index(f, "</form>")]
		if strings.Contains(f, `value="`+root+`"`) {
			asked = strings.Contains(f, `name="code"`)
		} else if strings.Contains(f, `name="code"`) {
			t.Error("a plan that needs no code is asked for one")
		}
	}
	if !asked {
		t.Fatal("the root plan's card asks for the code")
	}
	all := body[strings.Index(body, `class="approve-all"`):]
	all = all[:strings.Index(all, "</form>")]
	if strings.Contains(all, root) || !strings.Contains(all, a) || !strings.Contains(all, b) || !strings.Contains(all, "Approve all 2 shown") {
		t.Fatalf("approve-all holds the two plans that need no code, not the root one: %q", all)
	}
	w := uiPost(t, h, "/device/approve-shown", url.Values{"id": {a, b, root}}, cookie)
	if !strings.Contains(w.Body.String(), "wait for your code") || deviceStateOf(root) != "pending" {
		t.Fatalf("a root plan posted to approve-all stays waiting: %q", w.Body.String())
	}
	if w := uiPost(t, h, "/device/approve", url.Values{"id": {root}}, cookie); !strings.Contains(w.Body.String(), "Not approved") {
		t.Fatalf("approved without the code: %q", w.Body.String())
	}
	if w := uiPost(t, h, "/device/approve", url.Values{"id": {root}, "code": {planCode(t)}}, cookie); !strings.Contains(w.Body.String(), "Approved") ||
		deviceStateOf(root) != "approved" {
		t.Fatalf("approved with the code: %q", w.Body.String())
	}
}
