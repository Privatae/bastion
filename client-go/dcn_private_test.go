package main

// Two things a host holding `read` on a folder must never reach through the
// file ops (list, stat, read_range), nor move with a plan:
//   - what an exclude of several folders names. The Host's default excludes
//     carry ".config/gcloud", and a pattern with a "/" was compared with one
//     folder name at a time, so it matched nothing: a shared home folder
//     served its gcloud credentials;
//   - the local search agent's own folder, .agent, which holds the plaintext
//     of every file the agent read, whatever the grant excludes.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// dcnDefaultExcludes is the exclude list the Host proposes for a new folder.
var dcnDefaultExcludes = []string{
	".ssh", ".gnupg", ".aws", ".azure", ".config/gcloud", ".kube",
	".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore",
	"id_rsa*", "id_ed25519*", "*.token", "credentials*", ".netrc",
	".git-credentials", "*history",
}

// syncExcluding installs a read grant for the store with these excludes,
// through the real grant_sync op.
func (fx *dcnStoreFixture) syncExcluding(t *testing.T, excludes []string) {
	t.Helper()
	rec := signedRec(t, fx.priv, map[string]any{"kind": "dcn_store_grant", "class": "machine",
		"root": fx.store, "mask": []string{"read"}, "excludes": excludes,
		"expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	payload, _ := json.Marshal(map[string]any{"store_id": 1, "terms_canonical": rec.TermsCanonical,
		"signature": rec.Signature, "verify_pubkey": base64.StdEncoding.EncodeToString(fx.pub)})
	_, why, exit := dcnRunOp(t, func(ws *websocket.Conn) {
		handleDcnGrantSync(ws, fx.dir, []string{base64.StdEncoding.EncodeToString(payload)})
	})
	if exit != 0 {
		t.Fatalf("grant_sync: exit %d: %s", exit, why)
	}
}

func (fx *dcnStoreFixture) put(t *testing.T, rel, body string) {
	t.Helper()
	p := filepath.Join(fx.store, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// listed is what dcn_list returns under prefix, and its exit code.
func (fx *dcnStoreFixture) listed(t *testing.T, prefix string) ([]string, int) {
	t.Helper()
	obj, _, exit := fx.op(t, handleDcnList, map[string]any{"prefix": prefix})
	var paths []string
	files, _ := obj["files"].([]any)
	for _, f := range files {
		if m, ok := f.(map[string]any); ok {
			p, _ := m["path"].(string)
			paths = append(paths, p)
		}
	}
	return paths, exit
}

// A pattern with a "/" names that run of folders, wherever it sits in the
// path, each folder compared as the file system compares names. Judged per
// platform from any OS.
func TestDcnAMultiFolderExcludeMatchesThatRunAnywhere(t *testing.T) {
	for _, c := range []struct {
		goos, path string
		want       bool
	}{
		{"linux", ".config/gcloud/access_tokens.db", true},
		{"linux", ".config/gcloud", true},
		{"linux", "home/.config/gcloud/x", true},
		{"linux", "a/b/.config/gcloud/configurations/config_default", true},
		{"linux", ".config/gcloudx", false},
		{"linux", ".config/gcloudx/access_tokens.db", false},
		{"linux", ".configx/gcloud/x", false},
		{"linux", ".config/other/gcloud/x", false},
		{"linux", "gcloud/.config/x", false},
		{"linux", ".config", false},
		{"linux", ".config/settings.ini", false},
		{"linux", ".Config/gcloud/x", false}, // another folder on Linux
		{"darwin", ".Config/GCloud/access_tokens.db", true},
		{"darwin", "home/.CONFIG/gcloud/x", true},
		{"darwin", ".config/gcloudx/x", false},
		{"windows", ".CONFIG/GCLOUD/access_tokens.db", true},
		{"windows", "home/.config./gcloud /x", true},
		{"windows", ".config/gcloudx/x", false},
		// one-folder patterns as before
		{"linux", "deep/.ssh/config", true},
		{"linux", "certs/server.key", true},
		{"linux", "notes/ssh-notes.txt", false},
		{"windows", ".SSH/id_rsa", true},
	} {
		if got := dcnExcludedOn(c.goos, dcnDefaultExcludes, c.path); got != c.want {
			t.Errorf("%s: %q excluded=%v, want %v", c.goos, c.path, got, c.want)
		}
	}
	// A pattern's own slashes at either end, or doubled, name the same run.
	for _, pat := range []string{".config/gcloud/", "/.config/gcloud", ".config//gcloud"} {
		if !dcnExcludedOn("linux", []string{pat}, "home/.config/gcloud/x") {
			t.Errorf("%q must exclude home/.config/gcloud/x", pat)
		}
	}
}

// The default exclude of gcloud's folder holds on every op a host sends, at the
// top of a home folder and inside one, and however the path is spelled.
func TestDcnTheDefaultGcloudExcludeHoldsOnEveryOp(t *testing.T) {
	fx := newDcnStoreFixture(t)
	fx.put(t, ".config/gcloud/access_tokens.db", "GCLOUD-TOKEN")
	fx.put(t, "home/.config/gcloud/credentials.db", "NESTED-TOKEN")
	fx.put(t, ".config/gcloudx/ok.txt", "NEAR-MISS")
	fx.put(t, ".config/settings.ini", "SETTINGS")
	fx.syncExcluding(t, dcnDefaultExcludes)

	paths, exit := fx.listed(t, "")
	if exit != 0 {
		t.Fatalf("list: exit %d", exit)
	}
	have := map[string]bool{}
	for _, p := range paths {
		have[p] = true
		if strings.Contains(p, ".config/gcloud/") {
			t.Errorf("list returned %q, under an excluded folder", p)
		}
	}
	for _, p := range []string{".config/gcloudx/ok.txt", ".config/settings.ini", "a.txt"} {
		if !have[p] {
			t.Errorf("list left out %q, which no exclude names (got %v)", p, paths)
		}
	}
	if paths, exit := fx.listed(t, "home/.config"); exit != 0 || len(paths) != 0 {
		t.Errorf("list under home/.config: exit %d, %v; want nothing", exit, paths)
	}
	for _, prefix := range []string{".config/gcloud", "home/.config/gcloud"} {
		if _, exit := fx.listed(t, prefix); exit != 126 {
			t.Errorf("list of %q: exit %d, want 126", prefix, exit)
		}
	}
	for _, p := range []string{".config/gcloud", ".config/gcloud/access_tokens.db",
		"home/.config/gcloud/credentials.db", " .config/gcloud/access_tokens.db",
		"docs/../.config/gcloud/access_tokens.db"} {
		if obj, _, exit := fx.op(t, handleDcnStat, map[string]any{"path": p}); exit != 126 {
			t.Errorf("stat %q: exit %d %v, want 126", p, exit, obj)
		}
		if got, _, exit := fx.read(t, p); exit != 126 || strings.Contains(got, "TOKEN") {
			t.Errorf("read_range %q: exit %d %q, want 126 and nothing", p, exit, got)
		}
	}
	if got, why, exit := fx.read(t, ".config/gcloudx/ok.txt"); exit != 0 || got != "NEAR-MISS" {
		t.Errorf("a folder only named like gcloud's must read: exit %d %q %s", exit, got, why)
	}
	if problems := dcnCheckPlan(fx.store, dcnDefaultExcludes, []dcnMove{
		{From: ".config/gcloud/access_tokens.db", To: "out.db"}}); len(problems) == 0 {
		t.Error("a move out of gcloud's folder must be refused")
	}
	if problems := dcnCheckPlan(fx.store, dcnDefaultExcludes, []dcnMove{
		{From: "a.txt", To: "home/.config/gcloud/a.txt"}}); len(problems) == 0 {
		t.Error("a move into gcloud's folder must be refused")
	}
	if err := os.Symlink(filepath.Join(".config", "gcloud"), filepath.Join(fx.store, "gc")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got, _, exit := fx.read(t, "gc/access_tokens.db"); exit != 126 || got == "GCLOUD-TOKEN" {
		t.Errorf("read through a link to gcloud's folder: exit %d %q, want 126", exit, got)
	}
}

// The agent's folder is refused on every op a host sends: at the store's top,
// inside a folder another grant shares (where that store's agent keeps its
// own), through a link, and however it is spelled. The grant here excludes
// nothing, so the refusal is not the grant's to give or take.
func TestDcnTheAgentsFolderIsNeverServed(t *testing.T) {
	fx := newDcnStoreFixture(t)
	fx.put(t, ".agent/extract/ab/report.txt", "PLAINTEXT-OF-A-FILE")
	fx.put(t, ".agent/manifest.yaml", "manifest")
	fx.put(t, "proj/.agent/extract/x.txt", "NESTED-PLAINTEXT")
	fx.put(t, "proj/readme.md", "README")
	fx.syncExcluding(t, nil)

	paths, exit := fx.listed(t, "")
	if exit != 0 {
		t.Fatalf("list: exit %d", exit)
	}
	have := map[string]bool{}
	for _, p := range paths {
		have[p] = true
		if strings.Contains("/"+p, "/.agent/") {
			t.Errorf("list returned %q, inside an agent's folder", p)
		}
	}
	if !have["a.txt"] || !have["proj/readme.md"] {
		t.Errorf("list left out the folder's own files: %v", paths)
	}
	for _, prefix := range []string{".agent", ".agent/extract", "proj/.agent"} {
		if _, exit := fx.listed(t, prefix); exit != 126 {
			t.Errorf("list of %q: exit %d, want 126", prefix, exit)
		}
	}
	for _, p := range []string{".agent", ".agent/extract/ab/report.txt", ".agent/manifest.yaml",
		"proj/.agent/extract/x.txt", " .agent/manifest.yaml", "docs/../.agent/extract/ab/report.txt"} {
		if obj, _, exit := fx.op(t, handleDcnStat, map[string]any{"path": p}); exit != 126 {
			t.Errorf("stat %q: exit %d %v, want 126", p, exit, obj)
		}
		if got, _, exit := fx.read(t, p); exit != 126 || strings.Contains(got, "PLAINTEXT") {
			t.Errorf("read_range %q: exit %d %q, want 126 and nothing", p, exit, got)
		}
	}
	for _, m := range []dcnMove{{From: ".agent/extract/ab/report.txt", To: "out.txt"},
		{From: "a.txt", To: ".agent/a.txt"}, {From: "a.txt", To: "proj/.agent/a.txt"}} {
		if problems := dcnCheckPlan(fx.store, nil, []dcnMove{m}); len(problems) == 0 {
			t.Errorf("a move %q -> %q must be refused", m.From, m.To)
		}
	}

	// The bastion's own report of a plan it applied still goes into
	// .agent/plans, through the real plan op.
	hn, _ := os.Hostname()
	rec := signedRec(t, fx.priv, map[string]any{"kind": "dcn_move_plan", "store_id": 1, "plan_id": 41,
		"server": hn, "root": fx.store, "archive": "Archive",
		"moves":   []map[string]any{{"from": "a.txt", "to": "Archive/a.txt"}},
		"expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	payload, _ := json.Marshal(map[string]any{"terms_canonical": rec.TermsCanonical,
		"signature": rec.Signature, "mode": "apply"})
	out, why, exit := dcnRunOp(t, func(ws *websocket.Conn) {
		handleDcnPlanApply(ws, fx.dir, []string{"1", base64.StdEncoding.EncodeToString(payload)})
	})
	if exit != 0 || !strings.Contains(out, `"ok"`) {
		t.Fatalf("plan apply: exit %d %s %s", exit, out, why)
	}
	if b, err := os.ReadFile(filepath.Join(fx.store, ".agent", "plans", "41.json")); err != nil ||
		!strings.Contains(string(b), `"state": "ok"`) {
		t.Fatalf("the plan's report was not written into .agent/plans: %q %v", b, err)
	}

	if err := os.Symlink(filepath.Join(".agent", "extract", "ab", "report.txt"), filepath.Join(fx.store, "notes.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(".agent", filepath.Join(fx.store, "ag")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"notes.txt", "ag/extract/ab/report.txt", "ag/manifest.yaml"} {
		if got, _, exit := fx.read(t, p); exit != 126 || strings.Contains(got, "PLAINTEXT") {
			t.Errorf("read_range %q, a link into .agent: exit %d %q, want 126", p, exit, got)
		}
	}
	if _, exit := fx.listed(t, "ag"); exit != 126 {
		t.Errorf("list of a link to .agent: exit %d, want 126", exit)
	}
}

// The agent's folder is named as the file system names it, and on every OS
// regardless of case, as the agent's own walker treats it: a ".Agent" left on
// a volume that ignores case is the agent's folder.
func TestDcnTheAgentsFolderIsMatchedHoweverTheNameIsCased(t *testing.T) {
	for _, c := range []struct {
		goos, path string
		want       bool
	}{
		{"linux", ".agent/extract/x", true},
		{"linux", ".AGENT/extract/x", true},
		{"darwin", ".Agent/vectors.db", true},
		{"windows", ".AGENT/extract/x", true},
		{"windows", ".agent./extract/x", true},
		{"windows", ".agent /extract/x", true},
		{"windows", ".agent::$INDEX_ALLOCATION/x", true},
		{"linux", "deep/.agent", true},
		{"linux", ".agentx/x", false},
		{"linux", "agent/x", false},
		{"linux", "notes/.agent-old/x", false},
		{"darwin", "docs/readme.md", false},
	} {
		if got := dcnExcludedOn(c.goos, nil, c.path); got != c.want {
			t.Errorf("%s: %q refused=%v, want %v", c.goos, c.path, got, c.want)
		}
	}
}
