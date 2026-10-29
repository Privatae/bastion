//go:build !windows

package main

// ops_skill_bounds_test.go — a grant held to a window and a rate on the
// machine (ops_bounds.go): "not now" is no strike and spends nothing, the run
// log holds across a restart and refuses being edited, a grant dies with the
// key that approved it, and a drop goes through a quarantine. And the op with
// no program (interpreter: none): no run file, no sandbox needed, while a
// program op still needs one.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func userFixture() []opFile {
	files := opFixture("/srv/optest", "")
	files[0].B64 = base64.StdEncoding.EncodeToString([]byte(strings.Replace(fmt.Sprintf(opTestManifest, "/srv/optest"),
		"privilege: root", "privilege: user", 1)))
	return files
}

// grantBox installs a user grant with these bounds under a console approval,
// and stands in for the sandbox: each run under it is counted, never run.
func grantBox(t *testing.T, bounds string, uses int, approve func(dcn, purpose string) string) (dcn, nonce string, ran *int) {
	t.Helper()
	dcn, priv := opTestBox(t)
	files := userFixture()
	sha, _ := opDirDigest(files)
	gt := opTerm(opKindGrant, sha, "", bounds, uses, time.Hour, "user")
	purpose, err := purposeForOpGrant(&opTerms{Server: gt["server"].(string), Op: "write-hello", SHA256: sha,
		Bounds: bounds, Expires: gt["expires"].(string), Uses: uses})
	if err != nil {
		t.Fatal(err)
	}
	if approve == nil {
		approve = grantConsoleApproval(t)
	}
	gt["approval"] = approve(dcn, purpose)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, gt), bundleB64(files))}, "", dcn); code != 0 {
		t.Fatalf("the grant installs: %d %s", code, errOut)
	}
	n := 0
	prev := opGrantExec
	opGrantExec = func(_ string, tm *opTerms, mode, _, _ string, _ []string) (*opReport, *opRunRecord, error) {
		n++
		id, _ := newID()
		return &opReport{Mode: mode, Changes: []opChange{}}, &opRunRecord{ID: id, Op: tm.Op, SHA256: tm.SHA256, Mode: mode}, nil
	}
	t.Cleanup(func() { opGrantExec = prev })
	return dcn, gt["nonce"].(string), &n
}

func grantConsoleApproval(t *testing.T) func(dcn, purpose string) string {
	return func(dcn, purpose string) string {
		t.Helper()
		enrollFactor(t, dcn)
		raw, _ := b32decode(tSecret)
		a, err := stepupIssueApproval(dcn, hotp(raw, time.Now().Unix()/stepupPeriod), purpose)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
}

func atClock(t *testing.T, at *time.Time) {
	prev := opNow
	opNow = func() time.Time { return *at }
	t.Cleanup(func() { opNow = prev })
}

const grantParams = `{"name":"x","count":1,"kind":"a"}`

func grantApply(t *testing.T, dcn, nonce string) (string, string, int) {
	t.Helper()
	return driveJob(t, tAnchor, mgmtJob{Op: "op_grant_run", Args: []string{nonce, opModeApply, grantParams}}, "", dcn)
}

func strikes() int { return len(quarantineLoad().Pairing[tAnchor].refusalsNow()) }

func usesLeft(t *testing.T, dcn, nonce string) int {
	t.Helper()
	rec, ok := opsLoad(dcn).Grants[nonce]
	if !ok {
		t.Fatal("no record")
	}
	return rec.UsesLeft
}

// ── the grammar ─────────────────────────────────────────────────────────────

func TestGrantRunBoundsGrammar(t *testing.T) {
	setupBox(t)
	m, _ := parseOpManifest([]byte(fmt.Sprintf(opTestManifest, "/srv/optest")))
	for _, ok := range []string{
		`{"_window":{"from":"02:00","to":"04:00"}}`,
		`{"_window":{"days":["mon","fri"],"from":"22:00","to":"06:00","tz":"Europe/Berlin"},"count":{"max":2}}`,
		`{"_rate":{"per_day":3,"min_interval_s":600}}`,
		`{"_rate":{"per_day":1}}`,
		`{"_window":null,"_rate":null}`,
	} {
		if _, err := parseGrantBounds(m, ok); err != nil {
			t.Errorf("%s parses: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{
		"an unknown run bound":     `{"_when":{"from":"02:00","to":"04:00"}}`,
		"a day that is not one":    `{"_window":{"days":["mon","funday"],"from":"02:00","to":"04:00"}}`,
		"a day named twice":        `{"_window":{"days":["mon","mon"],"from":"02:00","to":"04:00"}}`,
		"no days at all":           `{"_window":{"days":[],"from":"02:00","to":"04:00"}}`,
		"a window of no length":    `{"_window":{"from":"02:00","to":"02:00"}}`,
		"a clock past 23:59":       `{"_window":{"from":"24:00","to":"02:00"}}`,
		"a zone nobody has":        `{"_window":{"from":"02:00","to":"04:00","tz":"Mars/Olympus"}}`,
		"the machine's local zone": `{"_window":{"from":"02:00","to":"04:00","tz":"Local"}}`,
		"a field the window lacks": `{"_window":{"from":"02:00","to":"04:00","every":"day"}}`,
		"a rate that bounds none":  `{"_rate":{}}`,
		"zero a day":               `{"_rate":{"per_day":0}}`,
		"more a day than uses":     `{"_rate":{"per_day":1001}}`,
		"an interval past 30 days": `{"_rate":{"min_interval_s":2592001}}`,
		"a field the rate lacks":   `{"_rate":{"per_hour":3}}`,
		"a rate as a string":       `{"_rate":"3/day"}`,
	} {
		if _, err := parseGrantBounds(m, bad); err == nil {
			t.Errorf("%s must be refused: %s", name, bad)
		}
	}
	// A window that wraps midnight belongs to the day it opens on.
	b, _ := parseGrantBounds(m, `{"_window":{"days":["fri"],"from":"22:00","to":"06:00","tz":"UTC"}}`)
	for at, want := range map[string]bool{
		"2026-10-30T23:00:00Z": true,  // Friday night
		"2026-10-31T03:00:00Z": true,  // Saturday morning, the Friday window
		"2026-10-30T03:00:00Z": false, // Friday morning: Thursday's window, not listed
		"2026-10-31T07:00:00Z": false,
	} {
		ts, _ := time.Parse(time.RFC3339, at)
		if got := b.Window.inside(ts); got != want {
			t.Errorf("%s inside=%v, want %v", at, got, want)
		}
	}
}

// ── not now: the window ─────────────────────────────────────────────────────

func TestGrantOutsideItsWindowIsNotNowAndSpendsNothing(t *testing.T) {
	// Thursday noon UTC; the window is Monday 02:00-04:00 in Berlin.
	now, _ := time.Parse(time.RFC3339, "2026-10-29T12:00:00Z")
	atClock(t, &now)
	dcn, nonce, ran := grantBox(t, `{"_window":{"days":["mon"],"from":"02:00","to":"04:00","tz":"Europe/Berlin"}}`, 5, nil)
	before := strikes()
	out, errOut, code := grantApply(t, dcn, nonce)
	if code != opNotNowExit || !strings.Contains(out, `"state":"not_now"`) || !strings.Contains(out, `"bound":"_window"`) {
		t.Fatalf("outside the window: not now: %d %s %s", code, out, errOut)
	}
	// Berlin is UTC+1 after 25 October: Monday 02:00 there is 01:00 UTC.
	if !strings.Contains(out, `"next":"2026-11-02T01:00:00Z"`) {
		t.Fatalf("it says when the window opens: %s", out)
	}
	if *ran != 0 || usesLeft(t, dcn, nonce) != 5 || strikes() != before {
		t.Fatalf("nothing ran, no use spent, no strike: ran=%d uses=%d strikes %d->%d", *ran, usesLeft(t, dcn, nonce), before, strikes())
	}
	// A dry run changes nothing and is never held to the window.
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_grant_run", Args: []string{nonce, opModeDryRun, grantParams}}, "", dcn); code != 0 {
		t.Fatalf("a dry run outside the window: %d %s", code, errOut)
	}
	// Bad params outside the window are still refused, with the strike.
	if _, _, code := driveJob(t, tAnchor, mgmtJob{Op: "op_grant_run", Args: []string{nonce, opModeApply, `{"name":"x","count":9,"kind":"a"}`}}, "", dcn); code != 126 {
		t.Fatalf("arguments outside the op are refused, window or not: %d", code)
	}
	now, _ = time.Parse(time.RFC3339, "2026-11-02T01:30:00Z")
	if _, errOut, code := grantApply(t, dcn, nonce); code != 0 || *ran != 2 || usesLeft(t, dcn, nonce) != 4 {
		t.Fatalf("inside the window it runs and spends one use: %d %s ran=%d uses=%d", code, errOut, *ran, usesLeft(t, dcn, nonce))
	}
}

// ── not now: the rate ───────────────────────────────────────────────────────

func TestGrantInsideItsMinIntervalDoesNotRun(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	atClock(t, &now)
	dcn, nonce, ran := grantBox(t, `{"_rate":{"min_interval_s":600}}`, 5, nil)
	if _, errOut, code := grantApply(t, dcn, nonce); code != 0 {
		t.Fatalf("the first run: %d %s", code, errOut)
	}
	before := strikes()
	first := now
	now = now.Add(5 * time.Minute)
	out, _, code := grantApply(t, dcn, nonce)
	if code != opNotNowExit || !strings.Contains(out, `"bound":"_rate"`) ||
		!strings.Contains(out, `"next":"`+first.Add(10*time.Minute).Format(time.RFC3339)+`"`) {
		t.Fatalf("five minutes after a run, with ten approved between: not now: %d %s", code, out)
	}
	if *ran != 1 || usesLeft(t, dcn, nonce) != 4 || strikes() != before {
		t.Fatalf("the second did not run, spend or strike: ran=%d uses=%d", *ran, usesLeft(t, dcn, nonce))
	}
	now = first.Add(11 * time.Minute)
	if _, _, code := grantApply(t, dcn, nonce); code != 0 || *ran != 2 {
		t.Fatalf("past the interval it runs: %d", code)
	}
}

func TestGrantPerDayHoldsAcrossARestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	atClock(t, &now)
	dcn, nonce, ran := grantBox(t, `{"_rate":{"per_day":2}}`, 10, nil)
	start := now
	for i := 0; i < 2; i++ {
		if _, errOut, code := grantApply(t, dcn, nonce); code != 0 {
			t.Fatalf("run %d: %d %s", i, code, errOut)
		}
		now = now.Add(time.Hour)
	}
	// The run log is on disk, in the record, not in this process.
	raw, err := os.ReadFile(opsFilePath(dcn))
	if err != nil {
		t.Fatal(err)
	}
	var f opsFile
	if json.Unmarshal(raw, &f) != nil || len(f.Grants[nonce].Runs) != 2 {
		t.Fatalf("both runs are in ops.json: %s", raw)
	}
	// A restart: another process reads the same record. Copy the pairing's
	// state to a fresh place and ask there.
	moved := t.TempDir()
	if err := copyTree(dcn, moved); err != nil {
		t.Fatal(err)
	}
	out, _, code := grantApply(t, moved, nonce)
	if code != opNotNowExit || !strings.Contains(out, "2 run(s) in the last 24 hours") {
		t.Fatalf("the third run in a day, after a restart: not now: %d %s", code, out)
	}
	if *ran != 2 {
		t.Fatalf("it did not run: %d", *ran)
	}
	// 24 hours after the first, one slot is free again.
	now = start.Add(24*time.Hour + time.Second)
	if _, errOut, code := grantApply(t, moved, nonce); code != 0 {
		t.Fatalf("a day after the first run: %d %s", code, errOut)
	}
}

func copyTree(from, to string) error {
	return filepath.Walk(from, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, raw, info.Mode().Perm())
	})
}

// ── the record ──────────────────────────────────────────────────────────────

func TestGrantWithATamperedRunLogIsNoGrant(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	atClock(t, &now)
	for name, edit := range map[string]func(r *opGrantRec){
		"the run taken out and the use given back": func(r *opGrantRec) { r.Runs = nil; r.UsesLeft++ },
		"the run taken out":                        func(r *opGrantRec) { r.Runs = nil },
		"a use given back":                         func(r *opGrantRec) { r.UsesLeft++ },
		"the run moved a day back":                 func(r *opGrantRec) { r.Runs[0] = now.Add(-25 * time.Hour).Format(time.RFC3339Nano) },
		"another approver":                         func(r *opGrantRec) { r.Approver = "console:0000" },
		"no seal (an older bastion's record)":      func(r *opGrantRec) { r.MAC = "" },
	} {
		t.Run(name, func(t *testing.T) {
			dcn, nonce, ran := grantBox(t, `{"_rate":{"per_day":1}}`, 5, nil)
			if _, errOut, code := grantApply(t, dcn, nonce); code != 0 {
				t.Fatalf("the first run: %d %s", code, errOut)
			}
			f := opsLoad(dcn)
			r := f.Grants[nonce]
			edit(&r)
			f.Grants[nonce] = r
			if err := opsSave(dcn, f); err != nil {
				t.Fatal(err)
			}
			_, errOut, code := grantApply(t, dcn, nonce)
			if code != 126 || (!strings.Contains(errOut, "does not check out") && !strings.Contains(errOut, "approve it again")) {
				t.Fatalf("an edited record holds no grant: %d %q", code, errOut)
			}
			if *ran != 1 {
				t.Fatalf("nothing ran under it: %d", *ran)
			}
		})
	}
}

func TestGrantDiesWithTheKeyThatApprovedIt(t *testing.T) {
	var pub string
	byDevice := func(_, purpose string) string {
		var err error
		if pub, err = deviceInit(); err != nil {
			t.Fatal(err)
		}
		if err := pinDeviceKey(pub); err != nil {
			t.Fatal(err)
		}
		a, err := deviceSign(purpose, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	dcn, nonce, ran := grantBox(t, `{"count":{"max":2}}`, 5, byDevice)
	if rec := opsLoad(dcn).Grants[nonce]; rec.Approver != "device:"+pub {
		t.Fatalf("the approving key is kept with the grant: %q", rec.Approver)
	}
	// The grant as the pairing holds it, in the pairing's own state folder
	// (unpinning walks every pairing's).
	cfgs, err := loadPairings()
	if err != nil {
		t.Fatal(err)
	}
	home := pairingFor(cfgs, tAnchor).dcnDir()
	if err := copyTree(dcn, home); err != nil {
		t.Fatal(err)
	}
	dcn = home
	if _, errOut, code := grantApply(t, dcn, nonce); code != 0 {
		t.Fatalf("a run under it: %d %s", code, errOut)
	}
	if err := unpinDeviceKey(pub); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := grantApply(t, dcn, nonce); code != 126 || !strings.Contains(errOut, "no longer pinned") {
		t.Fatalf("its key unpinned, the grant is dead: %d %q", code, errOut)
	}
	// Unpinning drops what the key approved, so pinning it again does not
	// bring the grant back.
	if n := opsDropApprovedBy("device:" + pub); n != 1 {
		t.Fatalf("one grant dropped with its key: %d", n)
	}
	if err := pinDeviceKey(pub); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := grantApply(t, dcn, nonce); code != 126 || !strings.Contains(errOut, "no such op grant") {
		t.Fatalf("pinned again, the grant stays dropped: %d %q", code, errOut)
	}
	if *ran != 1 {
		t.Fatalf("one run only: %d", *ran)
	}
	// A console approval dies with the factor: re-enrolled is another one.
	dcn2, nonce2, _ := grantBox(t, `{"count":{"max":2}}`, 5, nil)
	if err := stepupSave(dcn2, &stepupFile{SecretB32: tSecret, EnrolledAt: "2026-10-29T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := grantApply(t, dcn2, nonce2); code != 126 || !strings.Contains(errOut, "no longer pinned") {
		t.Fatalf("its factor re-enrolled, the grant is dead: %d %q", code, errOut)
	}
}

// ── taking it back ──────────────────────────────────────────────────────────

func TestGrantDropGoesThroughAQuarantine(t *testing.T) {
	if !opTightens("op_grant_drop") || !ownApproval("op_grant_drop") {
		t.Fatal("op_grant_drop is a tighten: no approval, no quarantine")
	}
	dcn, nonce, _ := grantBox(t, `{"count":{"max":2}}`, 5, nil)
	now := time.Now()
	for i := 0; i < quarantineStrikes; i++ {
		noteRefusal(tAnchor, "op_apply", "test strike", true, now)
	}
	if quarantinedUntil(tAnchor, time.Now()).IsZero() {
		t.Fatal("the host is quarantined here")
	}
	if _, errOut, code := grantApply(t, dcn, nonce); code != 126 || !strings.Contains(errOut, "quarantined") {
		t.Fatalf("a run while quarantined is refused: %d %q", code, errOut)
	}
	out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_grant_drop", Args: []string{nonce}}, "", dcn)
	if code != 0 || !strings.Contains(out, nonce) {
		t.Fatalf("a drop while quarantined goes through: %d %s %s", code, out, errOut)
	}
	if _, _, err := opsHeldGrant(dcn, nonce); err == nil {
		t.Fatal("the grant is gone")
	}
	// A drop of what is not held is already done; all takes every one.
	if out, _, code := driveJob(t, tAnchor, mgmtJob{Op: "op_grant_drop", Args: []string{nonce}}, "", dcn); code != 0 || !strings.Contains(out, `"dropped":[]`) {
		t.Fatalf("dropping it again: %d %s", code, out)
	}
	dcn2, nonce2, _ := grantBox(t, `{"count":{"max":2}}`, 5, nil)
	for i := 0; i < quarantineStrikes; i++ {
		noteRefusal(tAnchor, "op_apply", "test strike", true, time.Now())
	}
	if out, _, code := driveJob(t, tAnchor, mgmtJob{Op: "op_grant_drop", Args: []string{"all"}}, "", dcn2); code != 0 || !strings.Contains(out, nonce2) {
		t.Fatalf("drop all: %d %s", code, out)
	}
}

// ── interpreter: none ───────────────────────────────────────────────────────

const verbsOnlyManifest = `name: restart-web
version: 1.0.0
summary: Restart the web service.
kind: action
target: machine
privilege: root
interpreter: none
time_limit: 120
verbs:
  - {verb: unit.restart, unit: web.service}
  - {verb: logs.check, unit: web.service, must_not: "emerg", lines: "200"}
modes: [dry_run, apply, verify]
undo: none
`

func verbsOnlyFiles(withRun bool) []opFile {
	files := []opFile{{Path: "op.yaml", Mode: 0o644, B64: base64.StdEncoding.EncodeToString([]byte(verbsOnlyManifest))}}
	if withRun {
		files = append(files, opFile{Path: "run", Mode: 0o755, B64: base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\nid\n"))})
	}
	return files
}

func TestVerbsOnlyManifest(t *testing.T) {
	setupBox(t)
	m, err := parseOpManifest([]byte(verbsOnlyManifest))
	if err != nil || !m.verbsOnly() {
		t.Fatalf("a verbs-only op parses: %v", err)
	}
	for name, bad := range map[string]string{
		"interpreter none on a files op": strings.Replace(fmt.Sprintf(opTestManifest, "/srv/optest"), "interpreter: /bin/sh", "interpreter: none", 1),
		"no verbs":                       strings.Replace(strings.Replace(verbsOnlyManifest, "privilege: root", "privilege: user", 1), "verbs:\n  - {verb: unit.restart, unit: web.service}\n  - {verb: logs.check, unit: web.service, must_not: \"emerg\", lines: \"200\"}\n", "", 1),
		"a destination":                  strings.Replace(verbsOnlyManifest, "time_limit: 120\n", "time_limit: 120\ndestinations: [\"forge.example.com:443\"]\n", 1),
		"a builder":                      strings.Replace(verbsOnlyManifest, "time_limit: 120\n", "time_limit: 120\nbuilder: true\n", 1),
		"a credential no verb names":     strings.Replace(verbsOnlyManifest, "time_limit: 120\n", "time_limit: 120\ncredentials: [forge-read]\n", 1),
		"a read":                         strings.Replace(verbsOnlyManifest, "time_limit: 120\n", "time_limit: 120\nreads: [\"/srv/data/\"]\n", 1),
	} {
		if _, err := parseOpManifest([]byte(bad)); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestVerbsOnlyOpShippingRunIsRefused(t *testing.T) {
	dcn, priv := opTestBox(t)
	files := verbsOnlyFiles(true)
	sha, _ := opDirDigest(files)
	run := opTerm(opKindRun, sha, `{}`, "", 1, time.Hour, "root")
	run["op"] = "restart-web"
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, run), bundleB64(files))}, "", dcn); code != 126 || !strings.Contains(errOut, "ships no run") {
		t.Fatalf("a verbs-only op that ships a program is refused: %d %q", code, errOut)
	}
	files = verbsOnlyFiles(false)
	sha, _ = opDirDigest(files)
	run["sha256"] = sha
	if out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, run), bundleB64(files))}, "", dcn); code != 0 || !strings.Contains(out, `"held"`) {
		t.Fatalf("without it, held: %d %s %s", code, out, errOut)
	}
	// And a program op without its run is refused, as before.
	prog := opFixture("/srv/optest", "")[:1]
	psha, _ := opDirDigest(prog)
	pr := opTerm(opKindRun, psha, grantParams, "", 1, time.Hour, "root")
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, pr), bundleB64(prog))}, "", dcn); code != 126 || !strings.Contains(errOut, "needs op.yaml and run") {
		t.Fatalf("a program op with no run: %d %q", code, errOut)
	}
}

func noOverlay(t *testing.T) {
	ps, pa := opSandboxCheck, opActionCheck
	opSandboxCheck = func() (bool, string) { return false, "the kernel offers no overlay filesystem" }
	opActionCheck = func() (bool, string) { return false, "the kernel offers no overlay filesystem" }
	t.Cleanup(func() { opSandboxCheck, opActionCheck = ps, pa })
}

func TestProgramOpStillRefusedWithoutTheSandbox(t *testing.T) {
	noOverlay(t)
	dcn, priv := opTestBox(t)
	files := opFixture("/srv/optest", "")
	sha, _ := opDirDigest(files)
	pair := signTermsPair(t, priv, opTerm(opKindRun, sha, grantParams, "", 1, time.Hour, "root"))
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(files))}, "", dcn); code != 0 {
		t.Fatalf("held: %s", errOut)
	}
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair}, "", dcn); code != 126 || !strings.Contains(errOut, noSandboxHere) {
		t.Fatalf("a files op with no sandbox: %d %q", code, errOut)
	}
	// An action op with a program and verbs: the program needs the sandbox.
	man := strings.Replace(verbsOnlyManifest, "interpreter: none", "interpreter: /bin/sh", 1)
	afiles := []opFile{{Path: "op.yaml", Mode: 0o644, B64: base64.StdEncoding.EncodeToString([]byte(man))},
		{Path: "run", Mode: 0o755, B64: base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\n"))}}
	asha, _ := opDirDigest(afiles)
	at := opTerm(opKindRun, asha, `{}`, "", 1, time.Hour, "root")
	at["op"] = "restart-web"
	apair := signTermsPair(t, priv, at)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(apair, bundleB64(afiles))}, "", dcn); code != 0 {
		t.Fatalf("held: %s", errOut)
	}
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: apair}, "", dcn); code != 126 || !strings.Contains(errOut, noSandboxHere) {
		t.Fatalf("an action op with a program and no sandbox: %d %q", code, errOut)
	}
}
