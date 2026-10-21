package main

// DCN handler walls — the verification gates that are testable without a
// live relay: signature verify + tamper + expiry (dcnVerifyRec), the path sandbox
// incl. symlink escape (dcnResolvePath), excludes matching, and mask checks.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signedRec(t *testing.T, priv ed25519.PrivateKey, terms map[string]any) dcnGrantRec {
	t.Helper()
	canonical, err := json.Marshal(terms)
	if err != nil {
		t.Fatal(err)
	}
	return dcnGrantRec{
		TermsCanonical: base64.StdEncoding.EncodeToString(canonical),
		Signature:      base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical)),
	}
}

func TestDcnVerifyRec(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	terms := map[string]any{"kind": "dcn_store_grant", "class": "machine",
		"server": "box1", "root": "/data", "mask": []string{"read"},
		"expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)}

	rec := signedRec(t, priv, terms)
	got, err := dcnVerifyRec(pubB64, rec)
	if err != nil || got.Root != "/data" {
		t.Fatalf("valid grant must verify: %v", err)
	}

	// Tamper: widen the mask inside the canonical bytes → signature must fail.
	bad := terms
	bad["mask"] = []string{"read", "write"}
	canonical, _ := json.Marshal(bad)
	tampered := dcnGrantRec{TermsCanonical: base64.StdEncoding.EncodeToString(canonical),
		Signature: rec.Signature}
	if _, err := dcnVerifyRec(pubB64, tampered); err == nil {
		t.Fatal("a grant mutated after signing must NOT verify")
	}

	// Wrong key → fail.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := dcnVerifyRec(base64.StdEncoding.EncodeToString(otherPub), rec); err == nil {
		t.Fatal("a grant must not verify under a different pinned key")
	}

	// Signed expiry in the past → fail (the signed expiry is authoritative).
	terms["mask"] = []string{"read"}
	terms["expires"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := dcnVerifyRec(pubB64, signedRec(t, priv, terms)); err == nil {
		t.Fatal("an expired grant must NOT verify")
	}
}

func TestDcnResolvePathSandbox(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "a.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, ok := dcnResolvePath(root, "sub/a.txt"); !ok {
		t.Fatal("an in-root path must resolve")
	}
	for _, esc := range []string{"../etc/passwd", "sub/../../x", "/etc/passwd", ""} {
		if _, ok := dcnResolvePath(root, esc); ok {
			t.Fatalf("path %q must be rejected (traversal wall)", esc)
		}
	}

	// Symlink escape: a link inside the store pointing outside it must be refused.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "leak")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, ok := dcnResolvePath(root, "leak/secret"); ok {
		t.Fatal("a symlink pointing outside the root must be rejected (store escape)")
	}

	// A missing path inside the root is fine (stat-of-missing → typed gone, not escape).
	if _, ok := dcnResolvePath(root, "sub/nope.txt"); !ok {
		t.Fatal("a missing in-root path must still resolve (it becomes state=gone)")
	}

	// A broken link is fine as the last part (a stat reads it as gone, a move
	// renames the link itself); a path THROUGH it is refused.
	if err := os.Symlink(filepath.Join(outside, "missing"), filepath.Join(root, "broken")); err != nil {
		t.Fatal(err)
	}
	if _, ok := dcnResolvePath(root, "broken"); !ok {
		t.Fatal("a broken link inside the root must still resolve as itself")
	}
	if _, ok := dcnResolvePath(root, "broken/x"); ok {
		t.Fatal("a path through a broken link must be refused")
	}
	if len(dcnCheckPlan(root, nil, []dcnMove{{From: "broken", To: "sub/moved-link"}})) != 0 {
		t.Fatal("moving a broken link renames the link, and must pass")
	}
}

func TestDcnExcludes(t *testing.T) {
	excludes := []string{".ssh", "*.key", ".env*", "id_rsa*"}
	for _, hit := range []string{".ssh/id_rsa", "deep/.ssh/config", "certs/server.key",
		".env.production", "keys/id_rsa.pub"} {
		if !dcnExcluded(excludes, hit) {
			t.Fatalf("%q must be excluded", hit)
		}
	}
	// A host's path is judged as cleanRel will open it: these are spelled with
	// whitespace cleanRel trims, and a ".." it resolves.
	for _, hit := range []string{" .ssh/id_rsa", "certs/server.key ", "\t.env", "docs/../.ssh/x"} {
		if !dcnExcludedAsSent(excludes, "/srv/store", hit) {
			t.Fatalf("%q must be excluded as sent", hit)
		}
	}
	for _, ok := range []string{"docs/readme.md", "ssh-notes.txt", "envelope.pdf"} {
		if dcnExcluded(excludes, ok) {
			t.Fatalf("%q must NOT be excluded", ok)
		}
	}
}

// Names are compared the way each platform's file system tells them apart.
// Judged per platform from any OS, so a Windows or macOS rule is tested on Linux.
func TestDcnExcludesCompareNamesAsTheFileSystemDoes(t *testing.T) {
	excludes := []string{".ssh", "*.key"}
	for _, c := range []struct {
		goos, path string
		want       bool
	}{
		{"linux", ".SSH/id_rsa", false}, // a different folder on Linux
		{"darwin", ".SSH/id_rsa", true},
		{"windows", ".SSH/id_rsa", true},
		{"windows", ".ssh./id_rsa", true},
		{"windows", ".ssh /id_rsa", true},
		{"windows", "certs/server.key::$DATA", true},
		{"windows", "certs/SERVER.KEY", true},
		{"linux", "certs/server.key.", false},
		{"darwin", "docs/readme.md", false},
		{"windows", "docs/readme.md", false},
	} {
		if got := dcnExcludedOn(c.goos, excludes, c.path); got != c.want {
			t.Errorf("%s: %q excluded=%v, want %v", c.goos, c.path, got, c.want)
		}
	}
}

// A link inside the store to an excluded folder opens that folder, so a path
// through it is excluded, for a read and for a move alike.
func TestDcnExcludesHoldThroughALinkInsideTheStore(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ssh", "id_rsa"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".ssh", filepath.Join(root, "keys")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(".ssh/id_rsa", filepath.Join(root, "key")); err != nil {
		t.Fatal(err)
	}
	excludes := []string{".ssh"}
	for _, p := range []string{"keys/id_rsa", "keys", "key", " keys/id_rsa"} {
		if !dcnExcludedAsSent(excludes, root, p) {
			t.Errorf("%q opens the excluded .ssh, and must be excluded", p)
		}
	}
	if dcnExcludedAsSent(excludes, root, "docs/new.txt") {
		t.Error("a path that leads nowhere excluded must not be")
	}
	if len(dcnCheckPlan(root, excludes, []dcnMove{{From: "keys/id_rsa", To: "moved"}})) == 0 {
		t.Error("a move out of the excluded folder through a link must be refused")
	}
	if len(dcnCheckPlan(root, excludes, []dcnMove{{From: "docs", To: "keys/x"}})) == 0 {
		t.Error("a move into the excluded folder through a link must be refused")
	}
}

func TestDcnMask(t *testing.T) {
	terms := &dcnTerms{Mask: []string{"read", "search"}}
	if !dcnHasMask(terms, "read") || dcnHasMask(terms, "write") {
		t.Fatal("mask membership check broken")
	}
	if dcnHasMask(terms, "delete") {
		t.Fatal("delete can never be in a mask")
	}
}

// A revoke reaches the box — pushed (dcn_grant_drop)
// or reconciled from the heartbeat reply — instead of living on until the signed
// expiry. The absent field is "no instruction", never "drop everything".
func TestDcnGrantDropAndReconcile(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	mk := func(server string) dcnGrantRec {
		return signedRec(t, priv, map[string]any{"kind": "dcn_store_grant", "class": "machine",
			"server": server, "root": "/data", "mask": []string{"read"},
			"expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	}
	f := &dcnGrantFile{VerifyPubkey: base64.StdEncoding.EncodeToString(pub),
		Stores: map[string]dcnGrantRec{"1": mk("box1"), "2": mk("box1"), "3": mk("box1")}}
	if err := dcnSaveFile(dir, f); err != nil {
		t.Fatal(err)
	}
	stores := func() map[string]dcnGrantRec {
		g, err := dcnLoadFile(dir)
		if err != nil {
			t.Fatal(err)
		}
		return g.Stores
	}

	// 1. absent field → nothing happens
	r := maybeReconcileGrants([]byte(`{"ok":true}`), dir)
	if len(r.Dropped)+len(r.Stale)+len(r.Missing) != 0 || len(stores()) != 3 {
		t.Fatalf("no dcn_grants field must be a no-op: %+v stores=%d", r, len(stores()))
	}
	if reconcileReport(dir) != nil {
		t.Fatal("a clean reconcile must leave no pending report")
	}

	// 2. host lists 1 (same sig), 2 (different sig), 9 (not on disk); 3 unlisted
	body := []byte(`{"dcn_grants":{"stores":[{"store_id":1,"signature":"` + f.Stores["1"].Signature +
		`"},{"store_id":2,"signature":"different"},{"store_id":9,"signature":"x"}]}}`)
	r = maybeReconcileGrants(body, dir)
	if len(r.Dropped) != 0 || len(stores()) != 3 {
		t.Fatalf("ONE unlisted reply must not drop (a sync in flight is unlisted by timing): %+v", r)
	}
	r = maybeReconcileGrants(body, dir)
	if len(r.Dropped) != 1 || r.Dropped[0] != 3 {
		t.Fatalf("store 3 (unlisted twice) must be dropped: %+v", r)
	}
	if len(r.Stale) != 1 || r.Stale[0] != 2 {
		t.Fatalf("store 2 (signature differs) must be reported stale, not dropped: %+v", r)
	}
	if len(r.Missing) != 1 || r.Missing[0] != 9 {
		t.Fatalf("store 9 (listed, not on disk) must be reported missing: %+v", r)
	}
	s := stores()
	if _, ok := s["3"]; ok {
		t.Fatal("dropped store must be gone from grants.json")
	}
	if _, ok := s["2"]; !ok {
		t.Fatal("a stale store must stay on disk (the box never fabricates or discards a valid grant on a hint)")
	}
	if rep := reconcileReport(dir); rep == nil || len(rep.Stale) != 1 || len(rep.Missing) != 1 {
		t.Fatalf("drift must be carried for the next heartbeat: %+v", rep)
	}

	// 3. explicit empty list (twice) → the host says this box holds nothing → all dropped
	maybeReconcileGrants([]byte(`{"dcn_grants":{"stores":[]}}`), dir)
	r = maybeReconcileGrants([]byte(`{"dcn_grants":{"stores":[]}}`), dir)
	if len(r.Dropped) != 2 || len(stores()) != 0 {
		t.Fatalf("an explicit empty set must drop every store: %+v stores=%d", r, len(stores()))
	}

	// 4. pushed drop on an absent store is a clean no-op, not an error
	if present, err := dcnDropStore(dir, 42, "test"); err != nil || present {
		t.Fatalf("dropping an unknown store: present=%v err=%v", present, err)
	}
	// audit rows landed for the drops
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if !strings.Contains(string(raw), `"op":"grant_drop"`) {
		t.Fatal("grant drops must be audited on the box")
	}
}
