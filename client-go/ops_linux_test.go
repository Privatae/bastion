package main

// The parts of the op executor that exist only on Linux, where the sandbox
// runs: the upper-dir reader, the host's mount table, and the sandboxed dry
// run. The rest of the op tests are in ops_test.go and run on every unix.

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

// ── the upper-dir reader (no sandbox needed) ────────────────────────────────

func TestUpperChangesReadCreatedModifiedAndLinks(t *testing.T) {
	lower := t.TempDir()
	upper := t.TempDir()
	_ = os.MkdirAll(filepath.Join(lower, "etc/app"), 0o755)
	_ = os.WriteFile(filepath.Join(lower, "etc/app/a.conf"), []byte("one\ntwo\n"), 0o644)
	_ = os.WriteFile(filepath.Join(lower, "etc/app/same"), []byte("same\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(upper, "etc/app"), 0o755)
	_ = os.WriteFile(filepath.Join(upper, "etc/app/a.conf"), []byte("one\nthree\n"), 0o644)
	_ = os.WriteFile(filepath.Join(upper, "etc/app/new.txt"), []byte("hi\n"), 0o600)
	_ = os.WriteFile(filepath.Join(upper, "etc/app/same"), []byte("same\n"), 0o644)
	_ = os.Symlink("/etc/passwd", filepath.Join(upper, "etc/app/link"))
	_ = os.MkdirAll(filepath.Join(upper, "var/new-dir"), 0o750)
	// The walker names every change as the path it lands on under the
	// overlay's host root (a fixture root here; "/" or a mount point live).
	changes, err := opUpperChanges(upper, lower)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]opChange{}
	for _, c := range changes {
		got[strings.TrimPrefix(c.Path, lower)] = c
	}
	if got["/etc/app/a.conf"].Kind != "modified" || !strings.Contains(got["/etc/app/a.conf"].Diff, "- two") || !strings.Contains(got["/etc/app/a.conf"].Diff, "+ three") {
		t.Fatalf("modified with a diff: %+v", got["/etc/app/a.conf"])
	}
	if got["/etc/app/new.txt"].Kind != "created" || got["/etc/app/new.txt"].Mode != "0600" || got["/etc/app/new.txt"].src != filepath.Join(upper, "etc/app/new.txt") {
		t.Fatalf("created, with where it sits in the layer: %+v", got["/etc/app/new.txt"])
	}
	if _, ok := got["/etc/app/same"]; ok {
		t.Fatal("a file copied up and written back unchanged is not a change")
	}
	if got["/etc/app/link"].Kind != "symlink" {
		t.Fatalf("a symlink is named as one: %+v", got["/etc/app/link"])
	}
	if got["/var/new-dir"].Kind != "created_dir" {
		t.Fatalf("a new directory: %+v", got["/var/new-dir"])
	}
	m := &opManifest{Effects: opEffects{Files: []string{lower + "/etc/app/"}}}
	rep := &opReport{Changes: changes}
	if why := opEffectsViolation(m, rep); !strings.Contains(why, "symlink") {
		t.Fatalf("the link is refused first: %s", why)
	}
	rep.Changes = []opChange{got["/var/new-dir"]}
	if why := opEffectsViolation(m, rep); !strings.Contains(why, "outside") {
		t.Fatalf("a change outside the effects is refused: %s", why)
	}
	rep.Changes = []opChange{got["/etc/app/a.conf"], got["/etc/app/new.txt"]}
	if why := opEffectsViolation(m, rep); why != "" {
		t.Fatalf("changes inside the effects pass: %s", why)
	}
	// Whatever the effects say, the box's own record is never a change: the
	// pinned key, ops.json, the nonce ledger.
	own, _ := configDirPath()
	m2 := &opManifest{Effects: opEffects{Files: []string{own + "/"}}}
	rep.Changes = []opChange{{Path: own + "/dcn/anchor/dcn_grant.json", Kind: "modified"}}
	if why := opEffectsViolation(m2, rep); !strings.Contains(why, "own record") {
		t.Fatalf("the machine's own record is refused even inside matching effects: %s", why)
	}
	// A folder ABOVE the record, removed: takes the record with it — refused.
	m3 := &opManifest{Effects: opEffects{Files: []string{filepath.Dir(own) + "/"}}}
	rep.Changes = []opChange{{Path: filepath.Dir(own), Kind: "removed_dir"}}
	if why := opEffectsViolation(m3, rep); !strings.Contains(why, "own record") {
		t.Fatalf("a folder holding the record is refused: %s", why)
	}
	// A folder removed that holds a mount the sandbox never looked into.
	if mounts, err := opHostMounts(); err == nil {
		for _, mt := range mounts {
			if mt.Point == "/" || filepath.Dir(mt.Point) == "/" && strings.Count(mt.Point, "/") == 1 && filepath.Dir(mt.Point) == "/" {
				// a mount directly under /: its parent is /, which effects never name
				continue
			}
			parent := filepath.Dir(mt.Point)
			if parent == "/" {
				continue
			}
			m4 := &opManifest{Effects: opEffects{Files: []string{parent + "/"}}}
			rep.Changes = []opChange{{Path: parent, Kind: "removed_dir"}}
			if why := opEffectsViolation(m4, rep); !strings.Contains(why, "holds a mount") {
				t.Fatalf("removing %s, which holds the mount %s, is refused: %s", parent, mt.Point, why)
			}
			break
		}
	}
}

func TestHostMountsAndEffectPrefix(t *testing.T) {
	mounts := []opHostMount{{"/", "ext4"}, {"/srv", "xfs"}, {"/srv/share", "nfs4"}, {"/proc", "proc"}, {"/home", "ext4"}}
	for p, want := range map[string]string{
		"/etc/x":        "/",
		"/srv/a/b":      "/srv",
		"/srv/share/x":  "/srv/share",
		"/srv/shared/x": "/srv",
		"/home":         "/home",
		"/homely/x":     "/",
	} {
		if got := opMountOf(mounts, p).Point; got != want {
			t.Errorf("%s: on %s, want %s", p, got, want)
		}
	}
	for e, want := range map[string]string{
		"/etc/app/":          "/etc/app",
		"/var/log/app/*.log": "/var/log/app",
		"/etc/one.conf":      "/etc/one.conf",
		"/srv/share/[ab]*/x": "/srv/share",
	} {
		if got := opEffectPrefix(e); got != want {
			t.Errorf("%s: prefix %s, want %s", e, got, want)
		}
	}
	live, err := opHostMounts()
	if err != nil {
		t.Skip("no mountinfo here")
	}
	if opMountOf(live, "/").Point != "/" {
		t.Fatal("the root is always a mount")
	}
}

func TestOpDryRunShowsTheChangeAndApplyCommitsExactlyThat(t *testing.T) {
	requireSandbox(t)
	dcn, priv := opTestBox(t)
	root := filepath.Join(opTestRoot, fmt.Sprintf("r%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	files := opFixture(root, "")
	sha, _ := opDirDigest(files)
	params := `{"name":"x","count":1,"kind":"a"}`
	run := opTerm(opKindRun, sha, params, "", 1, time.Hour, "root")
	pair := signTermsPair(t, priv, run)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(files))}, "", dcn); code != 0 {
		t.Fatalf("sync: %s", errOut)
	}
	out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_dry_run", Args: pair}, "", dcn)
	if code != 0 {
		t.Fatalf("dry run: %d %s", code, errOut)
	}
	var rep opReport
	_ = json.Unmarshal([]byte(out), &rep)
	if len(rep.Changes) != 2 || rep.Changes[0].Kind != "created_dir" || rep.Changes[1].Path != root+"/hello.txt" || rep.Changes[1].Kind != "created" {
		t.Fatalf("the dry run names the folder and the file it would create: %+v", rep.Changes)
	}
	if !strings.Contains(rep.Changes[1].Diff, "+ hello "+params) {
		t.Fatalf("with the file's text: %q", rep.Changes[1].Diff)
	}
	if _, err := os.Stat(root); err == nil {
		t.Fatal("a dry run commits nothing")
	}
	if len(rep.ChangesSHA256) != 64 || rep.ChangesSHA256 != opChangesDigest(rep.Changes) {
		t.Fatalf("the report names its change list: %q", rep.ChangesSHA256)
	}
	// An apply binds the change list the dry run showed: terms without it
	// are refused before any approval is looked at.
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_apply", Args: pair}, "", dcn); code != 126 || !strings.Contains(errOut, "changes_sha256") {
		t.Fatalf("apply binds the dry run: %d %q", code, errOut)
	}
	run["changes_sha256"] = rep.ChangesSHA256
	pair = signTermsPair(t, priv, run)
	// Apply without the approval: refused; with it: the same change lands.
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_apply", Args: pair}, "", dcn); code != 126 || !strings.Contains(errOut, "approval") {
		t.Fatalf("apply spends an approval: %d %q", code, errOut)
	}
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	changes := rep.ChangesSHA256
	// An approval the device signed for another op, other params, or another
	// machine is not this one's: the purpose binds all of them.
	for name, other := range map[string]*opTerms{
		"another op":      {Server: run["server"].(string), Op: "write-hello", SHA256: strings.Repeat("1", 64), Params: params, Expires: run["expires"].(string), Changes: changes},
		"other params":    {Server: run["server"].(string), Op: "write-hello", SHA256: sha, Params: `{"name":"y","count":1,"kind":"a"}`, Expires: run["expires"].(string), Changes: changes},
		"another machine": {Server: run["server"].(string) + "-2", Op: "write-hello", SHA256: sha, Params: params, Expires: run["expires"].(string), Changes: changes},
		"other changes":   {Server: run["server"].(string), Op: "write-hello", SHA256: sha, Params: params, Expires: run["expires"].(string), Changes: strings.Repeat("2", 64)},
	} {
		p, _ := purposeForOpRun(other)
		a, _ := deviceSign(p, time.Minute)
		run["approval"] = a
		if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_apply", Args: signTermsPair(t, priv, run)}, "", dcn); code != 126 || !strings.Contains(errOut, "approval") {
			t.Fatalf("%s: an approval for something else is refused: %d %q", name, code, errOut)
		}
	}
	// Five refused writes just happened: the box has closed this host's write
	// lanes (the quarantine, tested on its own). The person lifts it here.
	quarantineClear(tAnchor)
	// Terms whose change list is not what this machine's run produces land
	// nothing, approval or not — the approval was for the list on the card.
	{
		otherRun := opTerm(opKindRun, sha, params, "", 1, time.Hour, "root")
		otherRun["nonce"] = "fedcba9876543210fedcba9876543210"
		otherRun["changes_sha256"] = strings.Repeat("2", 64)
		p, _ := purposeForOpRun(&opTerms{Server: run["server"].(string), Op: "write-hello", SHA256: sha, Params: params,
			Expires: otherRun["expires"].(string), Changes: strings.Repeat("2", 64)})
		a, _ := deviceSign(p, time.Minute)
		otherRun["approval"] = a
		if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_apply", Args: signTermsPair(t, priv, otherRun)}, "", dcn); code != 126 || !strings.Contains(errOut, "other than what the dry run showed") {
			t.Fatalf("a different change list lands nothing: %d %q", code, errOut)
		}
		if _, err := os.Stat(root); err == nil {
			t.Fatal("refused before commit means nothing landed")
		}
		// Its nonce is burned (one attempt per approval) and its status says
		// refused, not applied — what a host that lost the answer must read.
		st, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "op_run_status", Args: []string{otherRun["nonce"].(string)}}, "", dcn)
		var status map[string]any
		_ = json.Unmarshal([]byte(st), &status)
		if status["found"] != true || status["applied"] != false || status["nonce_burned"] != true || !strings.Contains(fmt.Sprint(status["error"]), "other than") {
			t.Fatalf("a refused apply reads as refused, never applied: %s", st)
		}
	}
	purpose, _ := purposeForOpRun(&opTerms{Server: run["server"].(string), Op: "write-hello", SHA256: sha, Params: params, Expires: run["expires"].(string), Changes: changes})
	if p2, err := purposeFromDetails(map[string]any{"kind": opKindRun, "op": "write-hello", "version": "1.0.0", "server": run["server"],
		"privilege": "root", "params": params, "expires": run["expires"], "sha256": sha, "changes_sha256": changes, "uses": float64(1)}); err != nil || p2 != purpose {
		t.Fatalf("the device derives the apply's purpose from the details, change list included: %v %s", err, p2)
	}
	approval, _ := deviceSign(purpose, time.Minute)
	run["approval"] = approval
	pair = signTermsPair(t, priv, run)
	quarantineClear(tAnchor)
	out, errOut, code = driveJob(t, tAnchor, mgmtJob{Op: "op_apply", Args: pair}, "", dcn)
	if code != 0 {
		t.Fatalf("apply: %d %s", code, errOut)
	}
	_ = json.Unmarshal([]byte(out), &rep)
	got, err := os.ReadFile(root + "/hello.txt")
	if err != nil || string(got) != "hello "+params+"\n" {
		t.Fatalf("the diff the person saw is the diff that landed: %q %v", got, err)
	}
	if len(rep.Committed) != 2 || rep.VerifyError != "" {
		t.Fatalf("committed and verified: %+v", rep)
	}
	// The same signed op_run cannot be applied twice.
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "op_apply", Args: pair}, "", dcn); code != 126 || !strings.Contains(errOut, "applied already") {
		t.Fatalf("one use: %d %q", code, errOut)
	}
	// A host that lost the answer asks what became of the run — a read.
	st, _, code := driveJob(t, tAnchor, mgmtJob{Op: "op_run_status", Args: []string{run["nonce"].(string)}}, "", dcn)
	var status map[string]any
	_ = json.Unmarshal([]byte(st), &status)
	if code != 0 || status["found"] != true || status["applied"] != true || status["nonce_burned"] != true || status["changes_sha256"] != rep.ChangesSHA256 {
		t.Fatalf("the run's status names it applied: %s", st)
	}
	st, _, _ = driveJob(t, tAnchor, mgmtJob{Op: "op_run_status", Args: []string{"never-sent-nonce-0000"}}, "", dcn)
	_ = json.Unmarshal([]byte(st), &status)
	if status["found"] != false || status["nonce_burned"] != false {
		t.Fatalf("a run that never arrived: not found, nonce unburned: %s", st)
	}
	// The record: the dry run, the refused apply with the other list, the apply.
	entries, _ := os.ReadDir(opsRunsDir(dcn))
	if len(entries) != 3 {
		t.Fatalf("every run is recorded: %d", len(entries))
	}
}

// The closed view, run for real: an op reads what it declared and the system
// base, and every other file — a sibling of its own folder, a folder beside
// it, /etc/shadow — reads as empty. A declared path that has come to resolve
// onto a credential store since it was accepted is refused at run time.
func TestOpSandboxShowsOnlyTheBaseAndWhatTheOpDeclared(t *testing.T) {
	requireSandbox(t)
	setupBox(t)
	n := time.Now().UnixNano()
	root := filepath.Join(opTestRoot, fmt.Sprintf("v%d", n))
	sibling := filepath.Join(opTestRoot, fmt.Sprintf("s%d.txt", n))
	readme := filepath.Join(opTestRoot, fmt.Sprintf("readme%d.txt", n))
	hiddenDir := filepath.Join(opTestRoot, fmt.Sprintf("hd%d", n))
	link := filepath.Join(opTestRoot, fmt.Sprintf("ln%d", n))
	opDir := filepath.Join(opTestRoot, fmt.Sprintf("op%d", n))
	for _, p := range []string{root, sibling, readme, hiddenDir, link, opDir} {
		p := p
		t.Cleanup(func() { _ = os.RemoveAll(p) })
	}
	_ = os.MkdirAll(hiddenDir, 0o755)
	_ = os.MkdirAll(opDir, 0o755)
	_ = os.WriteFile(sibling, []byte("HIDDEN-SIBLING\n"), 0o644)
	_ = os.WriteFile(readme, []byte("DECLARED-READ\n"), 0o644)
	_ = os.WriteFile(filepath.Join(hiddenDir, "secret"), []byte("HIDDEN-DIR\n"), 0o644)
	extra := fmt.Sprintf(`cat %s %s %s/secret 2>/dev/null; echo "SHADOW=$(grep -c '^root:' /etc/shadow 2>/dev/null)"; echo "PY=$(/usr/bin/python3 -c 'print(6*7)' 2>&1)"; true`,
		readme, sibling, hiddenDir)
	for _, f := range opFixture(root, extra) {
		raw, _ := base64.StdEncoding.DecodeString(f.B64)
		_ = os.WriteFile(filepath.Join(opDir, f.Path), raw, os.FileMode(f.Mode))
	}
	man := strings.Replace(fmt.Sprintf(opTestManifest, root), "modes:", fmt.Sprintf("reads: [%q, %q]\nmodes:", readme, link), 1)
	m, err := parseOpManifest([]byte(man))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := opRunSandboxed(opDir, m, opModeDryRun, `{"name":"x","count":1,"kind":"a"}`)
	if rep != nil {
		defer rep.cleanup()
	}
	if err != nil {
		t.Fatalf("the op runs: %v", err)
	}
	for _, want := range []string{"DECLARED-READ", "SHADOW=0", "PY=42"} {
		if !strings.Contains(rep.Output, want) {
			t.Fatalf("want %q in the op's output: %q", want, rep.Output)
		}
	}
	for _, never := range []string{"HIDDEN-SIBLING", "HIDDEN-DIR"} {
		if strings.Contains(rep.Output, never) {
			t.Fatalf("%q is outside what the op declared and must read as empty: %q", never, rep.Output)
		}
	}
	if len(rep.Changes) != 2 || rep.Changes[1].Path != root+"/hello.txt" {
		t.Fatalf("the op still writes what it declared: %+v", rep.Changes)
	}
	// The declared read becomes a link onto a credential store after the op
	// was accepted: the run is refused, as what it now names.
	if _, err := os.Stat("/etc/ssh"); err == nil {
		if err := os.Symlink("/etc/ssh", link); err != nil {
			t.Fatal(err)
		}
		rep2, err := opRunSandboxed(opDir, m, opModeDryRun, `{"name":"x","count":1,"kind":"a"}`)
		if rep2 != nil {
			rep2.cleanup()
		}
		if err == nil || !strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("a declared path that now resolves onto /etc/ssh is refused: %v", err)
		}
	}
}

// A read on a mount the sandbox does not carry (a network share, a tmpfs)
// would show an empty folder and a dry run that looks right: refused, like an
// effect there. Against a mount table, so it runs everywhere.
func TestOpEffectOrReadOnAMountTheSandboxDoesNotCarryIsRefused(t *testing.T) {
	mounts := []opHostMount{{Point: "/", FSType: "ext4"}, {Point: "/srv", FSType: "xfs"}, {Point: "/mnt/share", FSType: "nfs4"}}
	for _, c := range []struct {
		declared string
		forms    []string
		want     string
	}{
		{"/etc/nginx/site.conf", []string{"/etc/nginx/site.conf"}, ""},
		{"/srv/app/", []string{"/srv/app"}, ""},
		{"/mnt/share/cfg", []string{"/mnt/share/cfg"}, "/mnt/share/cfg is on a nfs4 mount"},
		{"/mnt/share/*.conf", []string{"/mnt/share/*.conf"}, "/mnt/share/*.conf is on a nfs4 mount"},
		// A link on a carried disk that resolves onto the share: judged as it resolves.
		{"/srv/app/cfg", []string{"/srv/app/cfg", "/mnt/share/cfg"}, "/srv/app/cfg is on a nfs4 mount"},
	} {
		err := opUncarriedDeclared(mounts, c.declared, c.forms)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: got %v, want %q", c.declared, err, c.want)
		}
	}
}
