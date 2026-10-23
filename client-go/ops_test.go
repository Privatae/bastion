//go:build !windows

package main

// ops_test.go — rung 6: the op format, the
// two terms, the store, and the executor's mutation suite. The unprivileged
// tests cover the manifest, params, bounds, digest, terms and the upper-dir
// reader; the sandbox itself runs where the daemon would (root, Linux,
// overlay) and is skipped elsewhere with the reason.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const opTestManifest = `name: write-hello
version: 1.0.0
summary: Write hello.txt under the test folder.
target: machine
privilege: root
interpreter: /bin/sh
time_limit: 30
params:
  name: {type: string, max_len: 32}
  count: {type: integer, min: 1, max: 5}
  kind: {type: enum, values: [a, b]}
effects:
  files: ["%s/"]
modes: [dry_run, apply, verify]
undo: none
`

// opTestRun is the op's program: the params arrive as JSON on stdin, the
// mode as --mode; it writes one file under the effects folder (dry_run and
// apply alike — the sandbox is what makes the dry run harmless), and verify
// checks it is there. EXTRA lets a test make it misbehave.
const opTestRun = `#!/bin/sh
read -r params
mode="$2"
case "$mode" in
  dry_run|apply)
    mkdir -p "%s"
    printf 'hello %%s\n' "$params" > "%s/hello.txt"
    %s
    ;;
  verify)
    test -f "%s/hello.txt"
    ;;
esac
`

func opFixture(effectsRoot, extra string) []opFile {
	man := fmt.Sprintf(opTestManifest, effectsRoot)
	run := fmt.Sprintf(opTestRun, effectsRoot, effectsRoot, extra, effectsRoot)
	return []opFile{
		{Path: "op.yaml", Mode: 0o644, B64: base64.StdEncoding.EncodeToString([]byte(man))},
		{Path: "run", Mode: 0o755, B64: base64.StdEncoding.EncodeToString([]byte(run))},
	}
}

// opTestBox: an anchored box whose pairing dir pins a signing key we hold.
func opTestBox(t *testing.T) (dcn string, priv ed25519.PrivateKey) {
	t.Helper()
	setupBox(t)
	dcn = t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := dcnSaveFile(dcn, &dcnGrantFile{Stores: map[string]dcnGrantRec{},
		VerifyPubkey: base64.StdEncoding.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	return dcn, priv
}

func opTerm(kind, sha, params, bounds string, uses int, ttl time.Duration, privilege string) map[string]any {
	hn, _ := os.Hostname()
	m := map[string]any{"kind": kind, "entity": 9001, "op": "write-hello", "version": "1.0.0", "sha256": sha,
		"server": hn, "privilege": privilege, "expires": time.Now().Add(ttl).UTC().Format(time.RFC3339),
		"uses": uses, "nonce": "0123456789abcdef0123456789abcdef"}
	if kind == opKindRun {
		m["params"] = params
	} else {
		m["bounds"] = bounds
	}
	return m
}

func bundleB64(files []opFile) string {
	raw, _ := json.Marshal(files)
	return base64.StdEncoding.EncodeToString(raw)
}

// ── the manifest ────────────────────────────────────────────────────────────

func TestOpManifestRefusesWhatRungSixDoesNotCarry(t *testing.T) {
	ownRecord, _ := configDirPath()
	good := fmt.Sprintf(opTestManifest, "/srv/optest")
	if _, err := parseOpManifest([]byte(good)); err != nil {
		t.Fatalf("the fixture must parse: %v", err)
	}
	bad := map[string]string{
		"a name with capitals":           strings.Replace(good, "name: write-hello", "name: WriteHello", 1),
		"no version shape":               strings.Replace(good, "version: 1.0.0", "version: v1", 1),
		"an interpreter of its own":      strings.Replace(good, "interpreter: /bin/sh", "interpreter: /usr/bin/perl", 1),
		"a time limit past the box":      strings.Replace(good, "time_limit: 30", "time_limit: 6000", 1),
		"a relative effect":              strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["srv/optest/"]`, 1),
		"the root as an effect":          strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/"]`, 1),
		"an effect under /proc":          strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/proc/sys/kernel"]`, 1),
		"a placeholder in effects":       strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/srv/{name}/"]`, 1),
		"a unit effect":                  strings.Replace(good, "effects:\n", "effects:\n  units: [nginx]\n", 1),
		"no verify mode":                 strings.Replace(good, "modes: [dry_run, apply, verify]", "modes: [dry_run, apply]", 1),
		"undo unstated":                  strings.Replace(good, "undo: none", "undo: maybe", 1),
		"a host-target op":               strings.Replace(good, "target: machine", "target: host", 1),
		"an integer with no bounds":      strings.Replace(good, "count: {type: integer, min: 1, max: 5}", "count: {type: integer}", 1),
		"a string with no max":           strings.Replace(good, "name: {type: string, max_len: 32}", "name: {type: string}", 1),
		"the box's own record":           strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["`+ownRecord+`/"]`, 1),
		"a glob into the record":         strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["`+ownRecord+`/dcn/*"]`, 1),
		"a folder holding the record":    strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["`+filepath.Dir(ownRecord)+`/"]`, 1),
		"a glob into the record (json)":  strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["`+ownRecord+`/*.json"]`, 1),
		"a glob over that folder":        strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["`+filepath.Dir(ownRecord)+`/*"]`, 1),
		"a glob over its parent":         strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["`+filepath.Dir(filepath.Dir(ownRecord))+`/*/*"]`, 1),
		"a glob naming the record":       strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/etc/privatae-*"]`, 1),
		"a glob through the record":      strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/etc/*/observe.kubeconfig"]`, 1),
		"a ? into the record":            strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/etc/privatae-bastio?"]`, 1),
		"a class into the record":        strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/etc/privatae-bastio[n]/x"]`, 1),
		"a class holding a slash":        strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/etc/privatae-bastion[/]x"]`, 1),
		"a glob under /var/lib/privatae": strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/var/lib/privatae/*/x"]`, 1),
		"an escaped letter":              strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/etc/privatae-bastio\\n"]`, 1),
		"an escaped slash":               strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/etc/privatae-bastion\\/observe.kubeconfig"]`, 1),
		"an escape past /proc":           strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["/pro\\c/sys"]`, 1),
	}
	// A glob beside the record is fine: a `*` never crosses a `/`, so
	// /etc/*.conf names nothing inside /etc/privatae-bastion — and the folder
	// itself is refused at run time and masked in the sandbox.
	// A class that would match a `/` under a whole-path filepath.Match is
	// harmless here: effectCovers matches segment by segment with equal
	// counts, so these can name only a sibling of the record, never inside
	// it — and they parse.
	// (/var/lib/*/state used to stand here; it could name /var/lib/rancher/state,
	// a credential store, and is refused as sensitive now — ops_view_test.go.)
	for _, ok := range []string{`/etc/*.conf`, `/opt/*/state`, `/etc/privatae-bastion[^a]observe.kubeconfig`,
		`/etc/privatae-bastion[.-0]observe.kubeconfig`, `/var/lib/privatae/bastion[^x]*`} {
		if _, err := parseOpManifest([]byte(strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["`+ok+`"]`, 1))); err != nil {
			t.Errorf("a glob beside the record is allowed: %s: %v", ok, err)
		}
	}
	for _, folder := range []string{`/etc/`, `/var/lib/`, `/var/lib/privatae/`} {
		if _, err := parseOpManifest([]byte(strings.Replace(good, `files: ["/srv/optest/"]`, `files: ["`+folder+`"]`, 1))); err == nil {
			t.Errorf("a folder holding this machine's record is refused: %s", folder)
		}
	}
	for name, m := range bad {
		if _, err := parseOpManifest([]byte(m)); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestOpParamsAndBoundsAreChecked(t *testing.T) {
	m, _ := parseOpManifest([]byte(fmt.Sprintf(opTestManifest, "/srv/optest")))
	ok := `{"name":"x","count":3,"kind":"a"}`
	if _, err := checkParams(m, ok); err != nil {
		t.Fatalf("good params: %v", err)
	}
	for name, p := range map[string]string{
		"missing":        `{"name":"x","count":3}`,
		"undeclared":     `{"name":"x","count":3,"kind":"a","extra":1}`,
		"out of range":   `{"name":"x","count":9,"kind":"a"}`,
		"not an int":     `{"name":"x","count":2.5,"kind":"a"}`,
		"bad enum":       `{"name":"x","count":3,"kind":"z"}`,
		"string too big": `{"name":"` + strings.Repeat("y", 40) + `","count":3,"kind":"a"}`,
		"not an object":  `[1,2]`,
	} {
		if _, err := checkParams(m, p); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	// A path root written with a trailing slash accepts the bare root.
	pm := &opManifest{Params: map[string]opParam{"dest": {Type: "path", Root: "/srv/data/"}}}
	if _, err := checkParams(pm, `{"dest":"/srv/data"}`); err != nil {
		t.Fatalf("the root itself is under the root: %v", err)
	}
	if _, err := checkParams(pm, `{"dest":"/srv/datax"}`); err == nil {
		t.Fatal("a sibling is not under the root")
	}
	vals, _ := checkParams(m, ok)
	b, err := parseBounds(m, `{"count":{"min":1,"max":2},"kind":{"values":["a"]},"name":{"values":["x"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBounds(m, b, vals); err == nil {
		t.Fatal("count 3 is outside the approved 1..2")
	}
	vals2, _ := checkParams(m, `{"name":"x","count":2,"kind":"a"}`)
	if err := checkBounds(m, b, vals2); err != nil {
		t.Fatalf("inside the bounds: %v", err)
	}
	if _, err := parseBounds(m, `{"nothing":{"min":1}}`); err == nil {
		t.Fatal("a bound naming no param is refused")
	}
	// The card shows the bounds as sent, so every field must be one the box
	// enforces for that param's type, inside the op's own bound.
	for name, bad := range map[string]string{
		"a field nobody reads":          `{"count":{"min":1,"max":2,"root":"/x"}}`,
		"values on an integer":          `{"count":{"values":["1"]}}`,
		"min/max on an enum":            `{"kind":{"min":1}}`,
		"wider than the op":             `{"count":{"min":0,"max":9}}`,
		"a value the op lacks":          `{"kind":{"values":["z"]}}`,
		"a string past max_len":         `{"name":{"values":["` + strings.Repeat("y", 40) + `"]}}`,
		"an empty values list":          `{"kind":{"values":[]}}`,
		"an integer bound with nothing": `{"count":{}}`,
	} {
		if _, err := parseBounds(m, bad); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestOpDigestIsTheFramedSHA256(t *testing.T) {
	files := []opFile{
		{Path: "run", Mode: 0o755, B64: base64.StdEncoding.EncodeToString([]byte("b"))},
		{Path: "op.yaml", Mode: 0o644, B64: base64.StdEncoding.EncodeToString([]byte("a"))},
	}
	got, err := opDirDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	// Pinned against nac_ops.op_dir_digest on the pod (the same vector).
	if got != "3392b4eb3a6c228079e011fed9e829b250d93a5ce2ff1ed5b4a3f1e8a0cd774d" {
		t.Fatalf("fixed vector: %s", got)
	}
	files[0].B64 = base64.StdEncoding.EncodeToString([]byte("c"))
	if got2, _ := opDirDigest(files); got2 == got {
		t.Fatal("one changed byte is a different op")
	}
	if err := opBundleOK([]opFile{{Path: "../x", B64: "YQ=="}, {Path: "op.yaml", B64: "YQ=="}, {Path: "run", B64: "YQ=="}}); err == nil {
		t.Fatal("a path that escapes is refused")
	}
	if err := opBundleOK([]opFile{{Path: "op.yaml", B64: "YQ=="}}); err == nil {
		t.Fatal("run is required")
	}
}

func TestEffectCovers(t *testing.T) {
	eff := []string{"/etc/app/", "/var/log/app/*.log", "/etc/one.conf"}
	for p, want := range map[string]bool{
		"/etc/app/x.conf":        true,
		"/etc/app/sub/y":         true,
		"/etc/app":               true,
		"/etc/application/x":     false,
		"/var/log/app/a.log":     true,
		"/var/log/app/sub/a.log": false,
		"/etc/one.conf":          true,
		"/etc/one.conf.bak":      false,
		"/":                      false,
	} {
		if effectCovers(eff, p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
	// A class never spans a /: the glob and the path are matched segment by
	// segment with equal counts (the gate uses the same definition).
	for p, want := range map[string]bool{
		"/etc/x/y":  false, // [^a] and [+-0] match a / under filepath.Match; never across segments
		"/etc/xby":  true,
		"/etc/x-y":  true,
		"/etc/xay":  false,
		"/etc/x/":   false,
		"/etc/x_yz": false,
	} {
		if effectCovers([]string{"/etc/x[^a]y", "/etc/x[+-0]y"}, p) != want {
			t.Errorf("class: %s: want %v", p, want)
		}
	}
	if effectCovers([]string{"/var/log/*/*.log"}, "/var/log/app/a.log") != true || effectCovers([]string{"/var/log/*/*.log"}, "/var/log/a.log") != false {
		t.Error("a glob covers only paths with the same number of segments")
	}
}

func TestOpRunStatusReadsTheCommitNotTheVerify(t *testing.T) {
	dcn, _ := opTestBox(t)
	_ = os.MkdirAll(opsRunsDir(dcn), 0o700)
	write := func(id, nonce, kind, mode, errText string, commit []string) {
		raw, _ := json.Marshal(opRunRecord{ID: id, At: time.Now().UTC().Format(time.RFC3339), Kind: kind, Op: "x", SHA256: strings.Repeat("a", 64),
			Mode: mode, Nonce: nonce, Error: errText, Commit: commit, Report: &opReport{ChangesSHA256: strings.Repeat("c", 64)}})
		_ = os.WriteFile(filepath.Join(opsRunsDir(dcn), id+".json"), raw, 0o600)
	}
	write("r1", "n-verify", opKindRun, opModeApply, "verify: the sandbox could not start", []string{"created /srv/x"})
	write("r2", "n-commit", opKindRun, opModeApply, "commit: disk full (1 change(s) landed before it)", []string{"created /srv/x"})
	write("r3", "n-grant", opKindGrant, opModeApply, "", []string{"created /srv/y"})
	for nonce, want := range map[string]bool{"n-verify": true, "n-commit": false} {
		st, _, code := driveJob(t, tAnchor, mgmtJob{Op: "op_run_status", Args: []string{nonce}}, "", dcn)
		var status map[string]any
		_ = json.Unmarshal([]byte(st), &status)
		if code != 0 || status["found"] != true || status["applied"] != want {
			t.Fatalf("%s: applied=%v wanted %v: %s", nonce, status["applied"], want, st)
		}
	}
	st, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "op_run_status", Args: []string{"n-grant"}}, "", dcn)
	var status map[string]any
	_ = json.Unmarshal([]byte(st), &status)
	if status["found"] != false {
		t.Fatalf("a run under a grant carries the grant's nonce and never answers here: %s", st)
	}
}

// ── the terms: the mutation suite ───────────────────────────────────────────

func TestOpTermsMutationsAreEachRefused(t *testing.T) {
	dcn, priv := opTestBox(t)
	files := opFixture("/srv/optest", "")
	sha, _ := opDirDigest(files)
	good := opTerm(opKindRun, sha, `{"name":"x","count":1,"kind":"a"}`, "", 1, time.Hour, "root")
	terms, sig := signTerms(t, priv, good)
	if _, err := verifyOpTerms(dcn, terms, sig, opKindRun); err != nil {
		t.Fatalf("good terms verify: %v", err)
	}
	hn, _ := os.Hostname()
	mut := func(f func(m map[string]any)) []string {
		m := opTerm(opKindRun, sha, `{"name":"x","count":1,"kind":"a"}`, "", 1, time.Hour, "root")
		f(m)
		return signTermsPair(t, priv, m)
	}
	cases := map[string]struct {
		terms, sig string
		kind       string
		want       string
	}{
		"expired":             {"", "", opKindRun, "expired"},
		"open-ended":          {"", "", opKindRun, "no expiry"},
		"too long-lived":      {"", "", opKindRun, "longer than"},
		"two uses":            {"", "", opKindRun, "one use"},
		"other server":        {"", "", opKindRun, "this box is"},
		"malformed sha256":    {"", "", opKindRun, "malformed sha256"},
		"no nonce":            {"", "", opKindRun, "no nonce"},
		"wrong kind":          {"", "", opKindGrant, "not \"op_grant\""},
		"root grant":          {"", "", opKindGrant, "never reusable"},
		"grant no bounds":     {"", "", opKindGrant, "carries its bounds"},
		"grant too many uses": {"", "", opKindGrant, "uses 1.."},
	}
	set := func(name string, pair []string) { c := cases[name]; c.terms, c.sig = pair[0], pair[1]; cases[name] = c }
	set("expired", mut(func(m map[string]any) { m["expires"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) }))
	set("open-ended", mut(func(m map[string]any) { m["expires"] = "" }))
	set("too long-lived", mut(func(m map[string]any) { m["expires"] = time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339) }))
	set("two uses", mut(func(m map[string]any) { m["uses"] = 2 }))
	set("other server", mut(func(m map[string]any) { m["server"] = hn + "-other" }))
	set("malformed sha256", mut(func(m map[string]any) { m["sha256"] = strings.Repeat("z", 64) }))
	set("no nonce", mut(func(m map[string]any) { m["nonce"] = "" }))
	set("wrong kind", mut(func(m map[string]any) {}))
	set("root grant", signTermsPair(t, priv, opTerm(opKindGrant, sha, "", `{}`, 5, time.Hour, "root")))
	set("grant no bounds", signTermsPair(t, priv, opTerm(opKindGrant, sha, "", "", 5, time.Hour, "user")))
	set("grant too many uses", signTermsPair(t, priv, opTerm(opKindGrant, sha, "", `{}`, 5000, time.Hour, "user")))
	for name, c := range cases {
		_, err := verifyOpTerms(dcn, c.terms, c.sig, c.kind)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want refusal containing %q, got %v", name, c.want, err)
		}
	}
	// Signed by another key.
	_, other, _ := ed25519.GenerateKey(nil)
	ot, os_ := signTerms(t, other, good)
	if _, err := verifyOpTerms(dcn, ot, os_, opKindRun); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("another key: %v", err)
	}
	// Tampered after signing.
	raw, _ := base64.StdEncoding.DecodeString(terms)
	tampered := base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"uses":1`, `"uses":2`, 1)))
	if _, err := verifyOpTerms(dcn, tampered, sig, opKindRun); err == nil {
		t.Fatal("tampered terms must not verify")
	}
}

// ── sync, and the grant's install spends the approval ───────────────────────

func TestOpSyncHoldsTheOpAndInstallsAGrantOnce(t *testing.T) {
	dcn, priv := opTestBox(t)
	enrollFactor(t, dcn)
	files := opFixture("/srv/optest", "")
	sha, _ := opDirDigest(files)
	// The bundle must hash to the sha256 the terms name.
	wrong := signTermsPair(t, priv, opTerm(opKindRun, strings.Repeat("0", 64), `{"name":"x","count":1,"kind":"a"}`, "", 1, time.Hour, "root"))
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: []string{wrong[0], wrong[1], bundleB64(files)}}, "", dcn); code != 126 || !strings.Contains(errOut, "does not hash") {
		t.Fatalf("a bundle that does not hash to the terms' sha256 is refused: %d %q", code, errOut)
	}
	run := signTermsPair(t, priv, opTerm(opKindRun, sha, `{"name":"x","count":1,"kind":"a"}`, "", 1, time.Hour, "root"))
	out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: []string{run[0], run[1], bundleB64(files)}}, "", dcn)
	if code != 0 || !strings.Contains(out, `"held"`) {
		t.Fatalf("op_sync with op_run terms holds the op: %d %s %s", code, out, errOut)
	}
	if _, err := opLoad(dcn, sha); err != nil {
		t.Fatalf("held and re-hashed: %v", err)
	}
	// A grant installs under the person's approval — spent once.
	gt := opTerm(opKindGrant, sha, "", `{"count":{"min":1,"max":2}}`, 3, time.Hour, "user")
	// The fixture is privilege root; a grant is user only, and the manifest must agree.
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, gt), bundleB64(files))}, "", dcn); code != 126 || !strings.Contains(errOut, "disagree") {
		t.Fatalf("a user grant for a root manifest is refused: %d %q", code, errOut)
	}
	ufiles := []opFile{
		{Path: "op.yaml", Mode: 0o644, B64: base64.StdEncoding.EncodeToString([]byte(strings.Replace(fmt.Sprintf(opTestManifest, "/srv/optest"), "privilege: root", "privilege: user", 1)))},
		files[1],
	}
	usha, _ := opDirDigest(ufiles)
	gt["sha256"] = usha
	purpose, err := purposeForOpGrant(&opTerms{Server: gt["server"].(string), Op: "write-hello", SHA256: usha,
		Bounds: gt["bounds"].(string), Expires: gt["expires"].(string), Uses: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, gt), bundleB64(ufiles))}, "", dcn); code != 126 || !strings.Contains(errOut, "approval") {
		t.Fatalf("a grant without the person's approval is refused: %d %q", code, errOut)
	}
	raw, _ := b32decode(tSecret)
	approval, err := stepupIssueApproval(dcn, hotp(raw, time.Now().Unix()/stepupPeriod), purpose)
	if err != nil {
		t.Fatal(err)
	}
	gt["approval"] = approval
	out, errOut, code = driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, gt), bundleB64(ufiles))}, "", dcn)
	if code != 0 || !strings.Contains(out, `"grant"`) {
		t.Fatalf("an approved grant installs: %d %s %s", code, out, errOut)
	}
	if _, rec, err := opsHeldGrant(dcn, gt["nonce"].(string)); err != nil || rec.UsesLeft != 3 {
		t.Fatalf("held with its uses: %v %v", err, rec)
	}
	// Dropped at the console, it cannot come back under the same approval.
	if ok, _ := opsDropGrant(dcn, gt["nonce"].(string), "test"); !ok {
		t.Fatal("drop")
	}
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, gt), bundleB64(ufiles))}, "", dcn); code != 126 || !strings.Contains(errOut, "already used") {
		t.Fatalf("a dropped grant is not re-installed under a spent approval: %d %q", code, errOut)
	}
	// The device signs op kinds (they name the machine) and the card reads.
	words := describeRequest(stepupRequest{Details: map[string]any{"kind": opKindGrant, "op": "write-hello", "version": "1.0.0",
		"server": gt["server"], "privilege": "user", "bounds": gt["bounds"], "uses": float64(3), "expires": gt["expires"],
		"sha256": usha, "summary": "Write hello.txt.", "effects": []any{"/srv/optest/"}}})
	for _, want := range []string{"FROM NOW ON", "write-hello 1.0.0", "up to 3 runs", "/srv/optest/", "identity: sha256"} {
		if !strings.Contains(words, want) {
			t.Fatalf("the card must say %q: %s", want, words)
		}
	}
	if p, err := purposeFromDetails(map[string]any{"kind": opKindGrant, "op": "write-hello", "version": "1.0.0",
		"server": gt["server"], "privilege": "user", "bounds": gt["bounds"], "uses": float64(3), "expires": gt["expires"], "sha256": usha}); err != nil || p != purpose {
		t.Fatalf("the details derive the same purpose the box enforces: %v %s", err, p)
	}
}

func signTermsPair(t *testing.T, priv ed25519.PrivateKey, m map[string]any) []string {
	t.Helper()
	a, b := signTerms(t, priv, m)
	return []string{a, b}
}

func TestOffLimitsCarryBothSpellingsAndRefuseWhenUnreadable(t *testing.T) {
	realDir := t.TempDir()
	link := filepath.Join(t.TempDir(), "cfg-link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skip("no symlinks here")
	}
	t.Setenv("XDG_CONFIG_HOME", link)
	offs, err := opOffLimits()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{filepath.Join(link, "privatae-bastion"): false, filepath.Join(realDir, "privatae-bastion"): false}
	for _, o := range offs {
		if _, ok := want[o]; ok {
			want[o] = true
		}
	}
	for p, seen := range want {
		if !seen {
			t.Fatalf("the record is protected as spelled and as it resolves; missing %s in %v", p, offs)
		}
	}
	// The other key material this daemon keeps on disk is in the set too.
	for _, p := range []string{"/var/lib/privatae/freeagent", "/etc/privatae-bastion", "/var/lib/privatae/bastion"} {
		found := false
		for _, o := range offs {
			if o == p {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s is off limits; got %v", p, offs)
		}
	}
	// A pairing file that does not parse: the record cannot be enumerated,
	// and every op is refused rather than one DCN dir left unprotected.
	pd, _ := pairingsDir()
	_ = os.MkdirAll(pd, 0o700)
	_ = os.WriteFile(filepath.Join(pd, "broken.json"), []byte("{not json"), 0o600)
	if _, err := opOffLimits(); err == nil {
		t.Fatal("unreadable pairings refuse ops")
	}
	if err := effectOK("/srv/x/"); err == nil {
		t.Fatal("an effect cannot be judged when the record cannot be enumerated")
	}
}

// ── the sandbox itself: root, Linux, overlay ────────────────────────────────

func requireSandbox(t *testing.T) {
	t.Helper()
	if ok, why := opSandboxAvailable(); !ok {
		t.Skip("no sandbox here: " + why)
	}
	// The fixtures' effects are folders under here; the folder itself must
	// exist so creating it is not a change outside the effects.
	if err := os.MkdirAll(opTestRoot, 0o755); err != nil {
		t.Fatal(err)
	}
}

const opTestRoot = "/srv/privatae-optest"

// opProbeRun is a python3 op that tries what the sandbox must deny: a dial
// to the host's sshd and a write under /proc. It prints a marker for each
// one that succeeds.
const opProbeRun = `#!/usr/bin/python3
import socket, sys
sys.stdin.readline()
try:
    socket.create_connection(("127.0.0.1", 22), 1).close(); print("NET-OPEN")
except Exception as e:
    print("net:", e)
try:
    open("/proc/sys/kernel/hostname", "w").write("x"); print("PROC-WRITTEN")
except Exception as e:
    print("proc:", e)
`

func TestOpThatWritesOutsideItsEffectsIsRefusedBeforeAnyoneIsAsked(t *testing.T) {
	requireSandbox(t)
	dcn, priv := opTestBox(t)
	root := filepath.Join(opTestRoot, fmt.Sprintf("e%d", time.Now().UnixNano()))
	outside := root + "-outside"
	t.Cleanup(func() { _ = os.RemoveAll(root); _ = os.RemoveAll(outside) })
	cases := map[string]string{
		"a file outside the effects": fmt.Sprintf(`mkdir -p %s; echo x > %s/leak`, outside, outside),
		"a symlink inside them":      fmt.Sprintf(`ln -s /etc/passwd %s/link`, root),
		"a hardlink inside them":     fmt.Sprintf(`ln %s/hello.txt %s/hard`, root, root),
		"a write to /etc":            `echo x >> /etc/hostname`,
	}
	for name, extra := range cases {
		files := opFixture(root, extra)
		sha, _ := opDirDigest(files)
		run := opTerm(opKindRun, sha, `{"name":"x","count":1,"kind":"a"}`, "", 1, time.Hour, "root")
		pair := signTermsPair(t, priv, run)
		if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(files))}, "", dcn); code != 0 {
			t.Fatalf("%s: sync: %s", name, errOut)
		}
		_, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair}, "", dcn)
		if code != 126 || !strings.Contains(errOut, "refused") {
			t.Errorf("%s: the dry run must be refused: %d %q", name, code, errOut)
		}
		if _, err := os.Stat(outside + "/leak"); err == nil {
			t.Errorf("%s: nothing lands from a dry run", name)
		}
		_ = os.RemoveAll(root)
	}
	// The sandbox has no network and a masked /proc: an op that dials the
	// host's sshd or writes there fails inside, and nothing reaches out.
	if c, err := net.DialTimeout("tcp", "127.0.0.1:22", time.Second); err != nil {
		t.Logf("no sshd on loopback here; the network half of the probe is not exercised: %v", err)
	} else {
		c.Close()
	}
	man := strings.Replace(fmt.Sprintf(opTestManifest, root), "interpreter: /bin/sh", "interpreter: python3", 1)
	files := []opFile{
		{Path: "op.yaml", Mode: 0o644, B64: base64.StdEncoding.EncodeToString([]byte(man))},
		{Path: "run", Mode: 0o755, B64: base64.StdEncoding.EncodeToString([]byte(opProbeRun))},
	}
	sha, _ := opDirDigest(files)
	run := opTerm(opKindRun, sha, `{"name":"x","count":1,"kind":"a"}`, "", 1, time.Hour, "root")
	pair := signTermsPair(t, priv, run)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(files))}, "", dcn); code != 0 {
		t.Fatalf("probe sync: %s", errOut)
	}
	out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair}, "", dcn)
	if code != 0 {
		t.Fatalf("the probe op changes nothing and must run: %d %s", code, errOut)
	}
	if strings.Contains(out, "NET-OPEN") || strings.Contains(out, "PROC-WRITTEN") {
		t.Fatalf("the sandbox must have no network and no writable /proc: %s", out)
	}
	if !strings.Contains(out, "net:") || !strings.Contains(out, "proc:") {
		t.Fatalf("both probes must have run and been refused: %s", out)
	}
}

func TestOpTimeLimitAndGrantRuns(t *testing.T) {
	requireSandbox(t)
	dcn, priv := opTestBox(t)
	enrollFactor(t, dcn)
	root := filepath.Join(opTestRoot, fmt.Sprintf("g%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	// Time limit: an op that sleeps past it is killed and refused.
	slow := opFixture(root, "sleep 5")
	slow[0].B64 = base64.StdEncoding.EncodeToString([]byte(strings.Replace(fmt.Sprintf(opTestManifest, root), "time_limit: 30", "time_limit: 1", 1)))
	sha, _ := opDirDigest(slow)
	run := opTerm(opKindRun, sha, `{"name":"x","count":1,"kind":"a"}`, "", 1, time.Hour, "root")
	pair := signTermsPair(t, priv, run)
	driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(slow))}, "", dcn)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair}, "", dcn); code != 126 || !strings.Contains(errOut, "time limit") {
		t.Fatalf("past the time limit: %d %q", code, errOut)
	}
	// A grant (user): runs inside its bounds, spends uses on apply, refuses outside them.
	// Its last line writes /dev/null, which a user-privilege op must be able
	// to do (the sandbox's device nodes are 0666, past the umask).
	ufiles := opFixture(root, "echo x > /dev/null")
	ufiles[0].B64 = base64.StdEncoding.EncodeToString([]byte(strings.Replace(fmt.Sprintf(opTestManifest, root), "privilege: root", "privilege: user", 1)))
	usha, _ := opDirDigest(ufiles)
	gt := opTerm(opKindGrant, usha, "", `{"count":{"min":1,"max":2}}`, 2, time.Hour, "user")
	purpose, _ := purposeForOpGrant(&opTerms{Server: gt["server"].(string), Op: "write-hello", SHA256: usha, Bounds: gt["bounds"].(string), Expires: gt["expires"].(string), Uses: 2})
	raw, _ := b32decode(tSecret)
	approval, err := stepupIssueApproval(dcn, hotp(raw, time.Now().Unix()/stepupPeriod), purpose)
	if err != nil {
		t.Fatal(err)
	}
	gt["approval"] = approval
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(signTermsPair(t, priv, gt), bundleB64(ufiles))}, "", dcn); code != 0 {
		t.Fatalf("grant sync: %s", errOut)
	}
	nonce := gt["nonce"].(string)
	// The user-privilege op writes under a root the session user may not own:
	// give it a folder that user can write.
	_ = os.MkdirAll(root, 0o777)
	_ = os.Chmod(root, 0o777) // past the umask
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_grant_run", Args: []string{nonce, opModeApply, `{"name":"x","count":3,"kind":"a"}`}}, "", dcn); code != 126 || !strings.Contains(errOut, "approved range") {
		t.Fatalf("outside the bounds: %d %q", code, errOut)
	}
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_grant_run", Args: []string{nonce, opModeApply, `{"name":"x","count":2,"kind":"a"}`}}, "", dcn); code != 0 {
		t.Fatalf("inside the bounds: %d %s", code, errOut)
	}
	if _, rec, _ := opsHeldGrant(dcn, nonce); rec == nil || rec.UsesLeft != 1 {
		t.Fatalf("one use spent: %+v", rec)
	}
	driveJob(t, tAnchor, mgmtJob{Op: "op_grant_run", Args: []string{nonce, opModeApply, `{"name":"x","count":2,"kind":"a"}`}}, "", dcn)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_grant_run", Args: []string{nonce, opModeApply, `{"name":"x","count":2,"kind":"a"}`}}, "", dcn); code != 126 || !strings.Contains(errOut, "no uses left") {
		t.Fatalf("uses exhausted: %d %q", code, errOut)
	}
	if got, err := os.ReadFile(root + "/hello.txt"); err != nil || !strings.Contains(string(got), "count") {
		t.Fatalf("the grant's applies landed: %v", err)
	}
}

// ── refusals: a strike for the host, never for the box's own state ─────────

func TestOpRefusalsCountAsStrikesExceptTheBoxsOwnState(t *testing.T) {
	requireSandbox(t)
	dcn, priv := opTestBox(t)
	root := filepath.Join(opTestRoot, fmt.Sprintf("s%d", time.Now().UnixNano()))
	outside := root + "-outside"
	t.Cleanup(func() { _ = os.RemoveAll(root); _ = os.RemoveAll(outside) })
	files := opFixture(root, fmt.Sprintf(`mkdir -p %s; echo x > %s/leak`, outside, outside))
	sha, _ := opDirDigest(files)
	run := opTerm(opKindRun, sha, `{"name":"x","count":1,"kind":"a"}`, "", 1, time.Hour, "root")
	pair := signTermsPair(t, priv, run)
	driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(files))}, "", dcn)
	before := len(quarantineLoad().Pairing[tAnchor].refusalsNow())
	if _, _, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair}, "", dcn); code != 126 {
		t.Fatal("refused")
	}
	if after := len(quarantineLoad().Pairing[tAnchor].refusalsNow()); after != before+1 {
		t.Fatalf("a run outside its effects is a strike against the host: %d -> %d", before, after)
	}
	// The box's own state is never the host's strike.
	if refusalCounts("op_dry_run", "op_dry_run refused: "+noSandboxHere+": no overlay") {
		t.Fatal("a box that cannot sandbox is not the host's fault")
	}
	if !refusalCounts("op_apply", "op_apply refused: this op_run was applied already") {
		t.Fatal("a second apply of the same op_run is the host's strike")
	}
}

func (e *quarantineEntry) refusalsNow() []string {
	if e == nil {
		return nil
	}
	return e.Refusals
}

func TestOpRemovingAFolderLandsExactlyThat(t *testing.T) {
	requireSandbox(t)
	dcn, priv := opTestBox(t)
	root := filepath.Join(opTestRoot, fmt.Sprintf("d%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	_ = os.MkdirAll(filepath.Join(root, "old", "deeper"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "old", "a.txt"), []byte("a\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "old", "deeper", "b.txt"), []byte("b\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "keep.txt"), []byte("keep\n"), 0o644)
	files := opFixture(root, fmt.Sprintf(`rm -rf %s/old; rm -f %s/keep.txt`, root, root))
	sha, _ := opDirDigest(files)
	params := `{"name":"x","count":1,"kind":"a"}`
	run := opTerm(opKindRun, sha, params, "", 1, time.Hour, "root")
	pair := signTermsPair(t, priv, run)
	driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(files))}, "", dcn)
	out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair}, "", dcn)
	if code != 0 {
		t.Fatalf("dry run: %s", errOut)
	}
	var rep opReport
	_ = json.Unmarshal([]byte(out), &rep)
	kinds := map[string]string{}
	notes := map[string]string{}
	for _, c := range rep.Changes {
		kinds[c.Path] = c.Kind
		notes[c.Path] = c.Note
	}
	if kinds[root+"/old"] != "removed_dir" || !strings.Contains(notes[root+"/old"], "3 entries") || kinds[root+"/keep.txt"] != "removed" || kinds[root+"/hello.txt"] != "created" {
		t.Fatalf("the dry run names the removed folder (with what it holds), the removed file and the created one: %+v", rep.Changes)
	}
	if _, err := os.Stat(filepath.Join(root, "old", "a.txt")); err != nil {
		t.Fatal("a dry run removes nothing")
	}
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	run["changes_sha256"] = rep.ChangesSHA256
	purpose, _ := purposeForOpRun(&opTerms{Server: run["server"].(string), Op: "write-hello", SHA256: sha, Params: params, Expires: run["expires"].(string), Changes: rep.ChangesSHA256})
	run["approval"], _ = deviceSign(purpose, time.Minute)
	pair = signTermsPair(t, priv, run)
	out, errOut, code = driveJob(t, tAnchor, mgmtJob{Op: "op_apply", Args: pair}, "", dcn)
	if code != 0 {
		t.Fatalf("apply: %s", errOut)
	}
	_ = json.Unmarshal([]byte(out), &rep)
	if _, err := os.Stat(filepath.Join(root, "old")); err == nil {
		t.Fatal("the folder the person saw removed is removed")
	}
	if _, err := os.Stat(filepath.Join(root, "keep.txt")); err == nil {
		t.Fatal("the file the person saw removed is removed")
	}
	if got, _ := os.ReadFile(filepath.Join(root, "hello.txt")); !strings.HasPrefix(string(got), "hello ") {
		t.Fatal("the created file landed")
	}
	if len(rep.Committed) != 3 || rep.VerifyError != "" {
		t.Fatalf("three changes committed, verified: %+v", rep)
	}
}

// The record is masked INSIDE the sandbox: an op cannot read the keys, and
// cannot remove or write the folder, whatever this side's path checks miss.
func TestOpSandboxMasksTheMachinesOwnRecord(t *testing.T) {
	requireSandbox(t)
	cfgHome := filepath.Join(opTestRoot, fmt.Sprintf("cfg%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.RemoveAll(cfgHome) })
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	record := filepath.Join(cfgHome, "privatae-bastion")
	_ = os.MkdirAll(record, 0o700)
	_ = os.WriteFile(filepath.Join(record, "owner.json"), []byte("SECRET-KEY-MATERIAL"), 0o600)
	root := filepath.Join(opTestRoot, fmt.Sprintf("m%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	opDir := filepath.Join(opTestRoot, fmt.Sprintf("op%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.RemoveAll(opDir) })
	_ = os.MkdirAll(opDir, 0o755)
	extra := fmt.Sprintf(`cat %s/owner.json; ls -A %s | wc -l; echo x > %s/planted 2>/dev/null && echo WROTE; rm -rf %s 2>/dev/null && echo RM-OK; test -e %s/owner.json && echo STILL-THERE-INSIDE; true`,
		record, record, record, record, record)
	for _, f := range opFixture(root, extra) {
		raw, _ := base64.StdEncoding.DecodeString(f.B64)
		_ = os.WriteFile(filepath.Join(opDir, f.Path), raw, os.FileMode(f.Mode))
	}
	m, err := parseOpManifest([]byte(fmt.Sprintf(opTestManifest, root)))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(opTestRoot, 0o755)
	rep, err := opRunSandboxed(opDir, m, opModeDryRun, `{"name":"x","count":1,"kind":"a"}`)
	if rep != nil {
		defer rep.cleanup()
	}
	if err != nil {
		t.Fatalf("the op itself succeeds (its probes fail quietly): %v", err)
	}
	// Since the closed view (ops_view.go) the record is not in the op's view
	// at all: nothing under it can be read or written, and `rm -rf` of a path
	// that is not there succeeds without touching the real one (checked below).
	if strings.Contains(rep.Output, "SECRET-KEY-MATERIAL") || strings.Contains(rep.Output, "WROTE") {
		t.Fatalf("the record must be unreadable and unwritable inside the sandbox: %q", rep.Output)
	}
	if strings.Contains(rep.Output, "STILL-THERE-INSIDE") {
		t.Fatalf("the mask hides the record's contents: %q", rep.Output)
	}
	for _, c := range rep.Changes {
		if strings.HasPrefix(c.Path, cfgHome) {
			t.Fatalf("nothing under the record is a change: %+v", c)
		}
	}
	if raw, _ := os.ReadFile(filepath.Join(record, "owner.json")); string(raw) != "SECRET-KEY-MATERIAL" {
		t.Fatal("the real record is untouched")
	}
}
