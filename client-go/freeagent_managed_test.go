//go:build !windows

// Tagged !windows. It always WAS unix-only — it calls faTestUser,
// which lives in freeagent_drop_test.go behind `//go:build !windows` — so this
// file has never compiled for Windows and `GOOS=windows go vet ./...` has been
// red on it the whole time. The tag does not remove any coverage; it states the
// dependency that was already there and lets vet run clean on the target, which
// is what makes a REAL Windows regression visible instead of being lost in a
// failure everyone has learned to scroll past.

package main

// The managed lane, proven on this box: the artifact fetch with hash
// verification, the identity, the manifest rendered from a grant, and —
// when a real freeagent .pyz and python3 are available (FREEAGENT_TEST_PYZ)
// — the whole thing end to end: a signed grant with 'search' brings up a
// local agent that answers /health and /catalog over mTLS to this box.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func stubPublish(t *testing.T, pyz []byte, sha string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/bastion-agent/version.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"version": "9.9.9", "files": map[string]any{
			"bastion-agent-9.9.9.pyz": map[string]any{"url": srv.URL + "/bastion-agent/dl/bastion-agent-9.9.9.pyz", "sha256": sha}}})
	})
	mux.HandleFunc("/bastion-agent/dl/bastion-agent-9.9.9.pyz", func(w http.ResponseWriter, r *http.Request) { w.Write(pyz) })
	srv = httptest.NewServer(signedStub(releaseKindAgent, mux))
	t.Cleanup(srv.Close)
	return srv
}

func withConfigDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	switch {
	case os.Getenv("XDG_CONFIG_HOME") != "" || true:
		t.Setenv("XDG_CONFIG_HOME", d) // UserConfigDir on linux
		t.Setenv("HOME", d)
		t.Setenv("AppData", d)
	}
	// The environment alone does NOT isolate faBaseDir. On a ROOT install it
	// prefers faStateBase() — "/var/lib/privatae/freeagent"
	// (freeagent_drop.go:318-326) — which no environment variable reaches. So
	// `go test` as root wrote a fake runtime into the LIVE bastion's state, and
	// a later case could return that cached copy instead of exercising the code
	// under test. Measured: a run left a 27-byte freeagent.pyz and version
	// 2.2.2 under that base, on a machine with an active bastion. Isolation
	// is the override the drop tests already use.
	// The machine marker is machine-scoped, and claim-anchor now consults it
	// (singleton.go). Without this, an anchor test on a box that HAS a marker
	// gets the singleton refusal instead of the refusal it is asserting — which
	// is exactly what happened.
	oldMarker := markerPathOverride
	markerPathOverride = filepath.Join(d, "machine.json")
	t.Cleanup(func() { markerPathOverride = oldMarker })
	oldBase := faStateBaseOverride
	faStateBaseOverride = filepath.Join(d, "state")
	if err := os.MkdirAll(faStateBaseOverride, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { faStateBaseOverride = oldBase })
	return d
}

func TestFaEnsurePyzVerifiesHash(t *testing.T) {
	withConfigDir(t)
	body := []byte("#!/usr/bin/env python3\nfake")
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])
	srv := stubPublish(t, body, good)
	old := faManifestURL
	faManifestURL = srv.URL + "/bastion-agent/version.json"
	t.Cleanup(func() { faManifestURL = old })

	p, v, err := faEnsurePyz()
	if err != nil || v != "9.9.9" {
		t.Fatalf("good hash must install: %v %q", err, v)
	}
	got, _ := os.ReadFile(p)
	if string(got) != string(body) {
		t.Fatal("installed bytes differ")
	}
	// same version again: no re-download needed (still returns the copy)
	if _, v2, err := faEnsurePyz(); err != nil || v2 != "9.9.9" {
		t.Fatalf("cached copy: %v", err)
	}
	// a tampered file is refused and the old copy stays
	bad := stubPublish(t, append(body, 'x'), good)
	faManifestURL = bad.URL + "/bastion-agent/version.json"
	_ = os.Remove(filepath.Join(filepath.Dir(p), "freeagent.version"))
	if _, _, err := faEnsurePyz(); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("hash mismatch must refuse, got %v", err)
	}
	// Refused means the installed agent is the one that was verified, byte for
	// byte: a refusal after the tampered bytes were written would still run them.
	if got, err := os.ReadFile(p); err != nil || string(got) != string(body) {
		t.Fatalf("after a refused download the installed agent must be unchanged: %v %q", err, got)
	}
	// offline with an installed copy: still served
	faManifestURL = "http://127.0.0.1:9/nope"
	_ = atomicWrite(filepath.Join(filepath.Dir(p), "freeagent.version"), []byte("9.9.9\n"))
	if p2, v3, err := faEnsurePyz(); err != nil || p2 != p || v3 != "9.9.9" {
		t.Fatalf("offline must fall back to the installed copy: %v", err)
	}
}

func TestFaEnsureIdentity(t *testing.T) {
	dir := t.TempDir()
	cert, key, _, err := faEnsureIdentity(dir, "store-7")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(cert)
	blk, _ := pem.Decode(raw)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || c.Subject.CommonName != "store-7" || !c.IsCA {
		t.Fatalf("cert: %v cn=%q ca=%v", err, c.Subject.CommonName, c.IsCA)
	}
	pool := x509.NewCertPool()
	pool.AddCert(c)
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("must be its own root: %v", err)
	}
	st, _ := os.Stat(key)
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("key must be private, mode %v", st.Mode())
	}
	// idempotent: same files on the second call
	c2, k2, _, _ := faEnsureIdentity(dir, "store-7")
	if c2 != cert || k2 != key {
		t.Fatal("identity must be minted once")
	}
}

func TestFaManifestText(t *testing.T) {
	terms := &dcnTerms{Class: "machine", Root: `C:\Users\user\Documents\context`,
		Mask: []string{"read", "search", "index"}, Excludes: []string{".ssh", "*.key"}}
	m := faManifestText("store-1", "store-1", terms, "daily", "age1abc", "qwen3-embedding:4b", 2560)
	for _, want := range []string{
		`roots: ["C:\\Users\\user\\Documents\\context"]`, `exclude: [".ssh", "*.key"]`,
		"mask: [read, search, index]", "stages: [walk, extract, sanitize, chunk, embed, catalog, seal]",
		"sweep: daily", "catalog: host", "plaintext: never", "dim: 2560", `model: "qwen3-embedding:4b"`} {
		if !strings.Contains(m, want) {
			t.Fatalf("manifest missing %q:\n%s", want, m)
		}
	}
	// no embedding model on the box → no chunk/embed; no recipient → no seal, local catalog
	m = faManifestText("store-2", "store-2", terms, "", "", "", 0)
	if !strings.Contains(m, "stages: [walk, extract, sanitize, catalog]") || !strings.Contains(m, "catalog: local") ||
		!strings.Contains(m, "sweep: hourly") {
		t.Fatalf("degraded manifest wrong:\n%s", m)
	}
	// read-only grant: no index → catalog needs index; only walk/extract/sanitize
	ro := &dcnTerms{Root: "/data", Mask: []string{"read"}}
	m = faManifestText("s", "s", ro, "15m", "", "m", 4)
	if !strings.Contains(m, "stages: [walk, extract, sanitize]") || !strings.Contains(m, "mask: [read]") {
		t.Fatalf("read-only manifest wrong:\n%s", m)
	}
}

func TestFaManagedConfigFromPortFile(t *testing.T) {
	dir := t.TempDir()
	faMgr.Lock()
	faMgr.inst[4242] = &faInstance{StoreID: 4242, Dir: dir, Cert: "c", Key: "k"}
	faMgr.Unlock()
	t.Cleanup(func() { faStop(4242) })
	if _, ok := faManagedConfig(4242); ok {
		t.Fatal("no port file → not configured")
	}
	os.WriteFile(filepath.Join(dir, "port"), []byte("18473\n"), 0o600)
	c, ok := faManagedConfig(4242)
	if !ok || c.Addr != "127.0.0.1:18473" || c.CA != "c" {
		t.Fatalf("port file → config, got %+v %v", c, ok)
	}
	if _, ok := faConfigFor(4242); !ok {
		t.Fatal("faConfigFor must prefer the managed instance")
	}
	t.Setenv("PRIVATAE_BASTION_AGENT_ADDR", "")
	if _, ok := faConfigFor(1); ok {
		t.Fatal("unknown store with no env → absent")
	}
	if !strings.Contains(faAbsentReason(1), "no local agent") {
		t.Fatal("absent reason for an unknown store")
	}
}

// End to end with the real artifact: FREEAGENT_TEST_PYZ=/path/to/freeagent-x.pyz
func TestFaManagedEndToEnd(t *testing.T) {
	pyzPath := os.Getenv("FREEAGENT_TEST_PYZ")
	if pyzPath == "" {
		t.Skip("set FREEAGENT_TEST_PYZ to the built freeagent .pyz")
	}
	if _, _, err := faPython(); err != nil {
		t.Skip(err.Error())
	}
	withConfigDir(t)
	pyz, err := os.ReadFile(pyzPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pyz)
	srv := stubPublish(t, pyz, hex.EncodeToString(sum[:]))
	old := faManifestURL
	faManifestURL = srv.URL + "/bastion-agent/version.json"
	t.Cleanup(func() { faManifestURL = old })

	// a corpus and a signed grant with 'search'
	corpus := t.TempDir()
	os.WriteFile(filepath.Join(corpus, "note.txt"), []byte("routers and firewalls, mail m@example.com\n"), 0o600)
	dcnDir := t.TempDir()
	// As root the agent is DROPPED to the folder's owner (freeagent_drop.go):
	// the corpus must belong to a real user, and the state base must be a
	// traversable chain like /var/lib/privatae/freeagent is.
	var owner *user.User
	if processIsRoot() {
		owner = faTestUser(t)
		if owner == nil {
			t.Skip("root, and no ordinary user account on this box to drop to")
		}
		uid, _ := strconv.Atoi(owner.Uid)
		gid, _ := strconv.Atoi(owner.Gid)
		makeTraversable(t, corpus)
		for _, p := range []string{corpus, filepath.Join(corpus, "note.txt")} {
			if err := os.Chown(p, uid, gid); err != nil {
				t.Fatal(err)
			}
		}
		base := t.TempDir()
		makeTraversable(t, base)
		oldBase := faStateBaseOverride
		faStateBaseOverride = base
		t.Cleanup(func() { faStateBaseOverride = oldBase })
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	terms := map[string]any{"kind": "dcn_store_grant", "class": "machine", "server": "box",
		"root": corpus, "mask": []string{"read", "search", "index"}, "excludes": []string{".git"},
		"sweep": "manual", "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	rec := signedRec(t, priv, terms)
	f := &dcnGrantFile{VerifyPubkey: base64.StdEncoding.EncodeToString(pub),
		Stores: map[string]dcnGrantRec{"1": rec}}
	if err := dcnSaveFile(dcnDir, f); err != nil {
		t.Fatal(err)
	}

	faReconcile(dcnDir) // what the daemon does at start
	t.Cleanup(func() { faStop(1) })
	stateDir, err := faStoreDir(dcnDir, 1)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(120 * time.Second)
	var c freeagentConfig
	for time.Now().Before(deadline) {
		faMgr.Lock()
		inst := faMgr.inst[1]
		state, detail := "", ""
		if inst != nil {
			state, detail = inst.State, inst.Detail
		}
		faMgr.Unlock()
		if state == "failed" || state == "missing-python" {
			t.Fatalf("managed install %s: %s", state, detail)
		}
		if cfg, ok := faManagedConfig(1); ok {
			c = cfg
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if c.Addr == "" {
		st, _ := os.ReadFile(filepath.Join(stateDir, "serve.log"))
		t.Fatalf("serve never wrote its port; serve.log:\n%s", st)
	}
	// health over mTLS with the box's identity
	var body []byte
	var status int
	for time.Now().Before(deadline) {
		status, body, err = freeagentCall(c, http.MethodGet, "/health", nil)
		if err == nil && status == 200 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil || status != 200 || !strings.Contains(string(body), `"serving": true`) {
		t.Fatalf("health: %d %v %s", status, err, body)
	}
	// the sweep ran: the catalog answers, sanitized
	for time.Now().Before(deadline) {
		status, body, err = freeagentCall(c, http.MethodGet, "/catalog", nil)
		if err == nil && status == 200 && strings.Contains(string(body), "note.txt") {
			break
		}
		time.Sleep(time.Second)
	}
	if status != 200 || !strings.Contains(string(body), "[PII_EMAIL_1]") || strings.Contains(string(body), "m@example.com") {
		sl, _ := os.ReadFile(filepath.Join(stateDir, "sweep.log"))
		t.Fatalf("catalog: %d %s\nsweep.log:\n%s", status, body, sl)
	}
	// files-and-folders: the agent lives in <root>/.agent, its output too, and
	// the walk never indexed it; secrets stayed in the bastion's state dir
	agentDir := filepath.Join(corpus, ".agent")
	for _, f := range []string{"manifest.yaml", "catalog.jsonl", "walk.jsonl"} {
		if _, err := os.Stat(filepath.Join(agentDir, f)); err != nil {
			t.Fatalf("%s must live in <root>/.agent: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(agentDir, "sanitize", "vault.db")); err == nil {
		t.Fatal("the vault must NOT be inside the folder")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "vault.db")); err != nil {
		t.Fatal("the vault must be in the bastion's state dir")
	}
	if _, err := os.Stat(filepath.Join(agentDir, "host.key")); err == nil {
		t.Fatal("the identity key must NOT be inside the folder")
	}
	wm, _ := os.ReadFile(filepath.Join(agentDir, "walk.jsonl"))
	if strings.Contains(string(wm), ".agent") {
		t.Fatal("the walk must not index .agent")
	}
	gi, _ := os.ReadFile(filepath.Join(agentDir, ".gitignore"))
	if !strings.Contains(string(gi), "!manifest.yaml") {
		t.Fatal(".agent/.gitignore must keep the stores out of a member's repo")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "out")); err == nil {
		t.Fatal("pre-0.13.3 residue dir/out must be removed")
	}
	// the reply maps like any local agent reply
	m, _, ok := freeagentMap("search", status, body, err)
	if !ok || m["state"] != "ok" {
		t.Fatal("mapping")
	}
	// the drop held: every child this daemon runs is the folder's owner, and
	// the state it was handed belongs to that owner
	if owner != nil {
		faOwnChildren.Lock()
		pids := []int{}
		for pid := range faOwnChildren.pid {
			pids = append(pids, pid)
		}
		faOwnChildren.Unlock()
		if len(pids) == 0 {
			t.Fatal("serve must be running as a tracked child")
		}
		for _, pid := range pids {
			st, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
			if err != nil {
				continue // exited between the snapshot and the read
			}
			for _, line := range strings.Split(string(st), "\n") {
				if strings.HasPrefix(line, "Uid:") && !strings.Contains(line, "\t"+owner.Uid+"\t") {
					t.Fatalf("child %d is not running as %s: %s", pid, owner.Username, line)
				}
			}
		}
		for _, p := range []string{stateDir, filepath.Join(stateDir, "host.key"), filepath.Join(stateDir, "vault.db"),
			filepath.Join(agentDir, "manifest.yaml"), filepath.Join(agentDir, "catalog.jsonl")} {
			if u, _, err := faPathOwner(p); err != nil || strconv.Itoa(int(u)) != owner.Uid {
				t.Fatalf("%s must belong to %s (uid %d, %v)", p, owner.Username, u, err)
			}
		}
	}
	// the signature names a cert the child can read but not replace: on a
	// root install that is the root-owned public copy
	if owner != nil {
		mf, _ := os.ReadFile(filepath.Join(agentDir, "manifest.yaml"))
		_, _, pubDir, _ := faStoreDirs(dcnDir, 1)
		want := "cert: " + filepath.Join(pubDir, "host.crt") + "\n"
		if !strings.Contains(string(mf), want) {
			t.Fatalf("the signature must name the public cert, want %q in:\n%s", want, mf)
		}
		if u, _, _ := faPathOwner(filepath.Join(pubDir, "host.crt")); u != 0 {
			t.Fatal("the public cert must stay root-owned")
		}
	}
	// heartbeat sees it
	adv, allOK := faManagedProbe()
	if !adv || !allOK {
		t.Fatalf("managed probe: %v %v", adv, allOK)
	}
	st := faManagedStatus()["1"].(map[string]any)
	if st["state"] != "running" || st["serving"] != true || st["version"] != "9.9.9" {
		t.Fatalf("status: %v", st)
	}

	// a `manual` sweep runs ONCE — with a 1s backoff,
	// a supervised sweep would have several runs on record by now
	oldBackoff := faRestartBackoff
	faRestartBackoff = time.Second
	t.Cleanup(func() { faRestartBackoff = oldBackoff })
	time.Sleep(3 * time.Second)
	runs, _ := os.ReadFile(filepath.Join(corpus, ".agent", "run.jsonl"))
	if n := strings.Count(string(runs), "\n"); n != 1 {
		t.Fatalf("manual sweep must run exactly once, run.jsonl has %d lines", n)
	}

	// a re-approved grant with narrower terms restarts
	// the instance under the new manifest (new excludes, new serve port)
	before, _ := faSnapshot(1)
	terms2 := map[string]any{}
	for k, v := range terms {
		terms2[k] = v
	}
	terms2["excludes"] = []string{".git", ".ssh", "*.key"}
	rec2 := signedRec(t, priv, terms2)
	f.Stores["1"] = rec2
	if err := dcnSaveFile(dcnDir, f); err != nil {
		t.Fatal(err)
	}
	faReconcile(dcnDir)
	deadline = time.Now().Add(60 * time.Second)
	var after faInstance
	for time.Now().Before(deadline) {
		after, _ = faSnapshot(1)
		if after.State == "running" && after.Text != before.Text {
			if c2, ok := faManagedConfig(1); ok && c2.Addr != c.Addr {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	if after.Text == before.Text || !strings.Contains(after.Text, `"*.key"`) {
		t.Fatalf("instance must restart under the re-approved terms; text unchanged: %q", after.Detail)
	}
	man, _ := os.ReadFile(after.Manifest)
	if !strings.Contains(string(man), `".ssh"`) || !strings.Contains(string(man), "signature:") {
		t.Fatal("re-rendered manifest must carry the new excludes and be re-signed")
	}
	// unchanged terms on the next reconcile: no restart (same port)
	c3, _ := faManagedConfig(1)
	faReconcile(dcnDir)
	time.Sleep(time.Second)
	c4, _ := faManagedConfig(1)
	if c3.Addr != c4.Addr {
		t.Fatal("identical terms must not restart the instance")
	}

	// A fresh identity with a surviving manifest (new layout, wiped base, a
	// re-pair): the manifest must be re-signed under the new cert, or the
	// gate refuses it and serve answers 503 forever.
	faStop(1)
	_, privDir, _, _ := faStoreDirs(dcnDir, 1)
	if err := os.RemoveAll(filepath.Join(privDir, "host.key")); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(privDir, "host.crt"))
	before3 := after
	faReconcile(dcnDir)
	deadline = time.Now().Add(60 * time.Second)
	var c9 freeagentConfig
	for time.Now().Before(deadline) {
		if cfg, ok := faManagedConfig(1); ok && cfg.Addr != "" {
			if st, _ := faSnapshot(1); st.State == "running" && st.Cert != "" {
				if _, body, err := freeagentCall(cfg, http.MethodGet, "/health", nil); err == nil && strings.Contains(string(body), `"serving": true`) {
					c9 = cfg
					break
				}
			}
		}
		if st, _ := faSnapshot(1); st.State == "failed" {
			t.Fatalf("re-identity: %s", st.Detail)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if c9.Addr == "" {
		sl, _ := os.ReadFile(filepath.Join(stateDir, "serve.log"))
		t.Fatalf("after a fresh identity the manifest must be re-signed and served (was %q); serve.log:\n%s", before3.State, sl)
	}
}

func TestFaChildEnvIsAnAllowlist(t *testing.T) {
	t.Setenv("PRIVATAE_SECRET_LIKE_THING", "nope")
	t.Setenv("PATH", "/usr/bin")
	env := strings.Join(faChildEnv(&faInstance{Dir: t.TempDir(), Cert: "c", Key: "k"}), "\n")
	if strings.Contains(env, "PRIVATAE_SECRET_LIKE_THING") {
		t.Fatal("daemon environment must not leak to the child")
	}
	for _, want := range []string{"PATH=/usr/bin", "FREEAGENT_CA_ROOT=c", "FREEAGENT_TLS_KEY=k",
		"EMBED_URL=http://127.0.0.1:11434", "FREEAGENT_VAULT_DIR="} {
		if !strings.Contains(env, want) {
			t.Fatalf("child env missing %s", want)
		}
	}
}

// The legacy name is retired on this side (0.42.0): one manifest address, one
// artifact name. Older bastions still read the legacy ones, which is the
// publish script's concern, not this binary's.

// recordingTransport answers every request 404 and records its URL, so a test
// can see every address a fetch tried, including ones it was never pointed at.
type recordingTransport struct{ urls []string }

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.urls = append(r.urls, req.URL.String())
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

func TestFaFetchManifestTriesOnlyTheNewAddress(t *testing.T) {
	if faManifestURL != "https://privatae.ai/bastion-agent/version.json" {
		t.Fatalf("manifest address = %q", faManifestURL)
	}
	// The production address, with nothing leaving the machine: every request
	// is answered here. A failed fetch must not go on to any other address.
	rec := &recordingTransport{}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = rec
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	if _, _, _, err := faFetchManifest(); err == nil {
		t.Fatal("a 404 must fail the fetch")
	}
	if len(rec.urls) != 1 || rec.urls[0] != faManifestURL {
		t.Fatalf("requested %v; want only %s", rec.urls, faManifestURL)
	}
}

func TestFaFetchManifestErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/bad/version.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":"1.0.0","files":["not","a","map"]}`))
	})
	srv := httptest.NewServer(signedStub(releaseKindAgent, mux))
	t.Cleanup(srv.Close)
	old := faManifestURL
	t.Cleanup(func() { faManifestURL = old })

	// Signed and versioned, but not a manifest this reads: refused, not read
	// as an empty one.
	faManifestURL = srv.URL + "/bad/version.json"
	if _, _, _, err := faFetchManifest(); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("a malformed manifest must be refused, got %v", err)
	}
	// Not served: the error names the address that failed.
	faManifestURL = srv.URL + "/nope/version.json"
	if _, _, _, err := faFetchManifest(); err == nil || !strings.Contains(err.Error(), "/nope/") {
		t.Fatalf("want the failing address in the error, got %v", err)
	}
}

func TestFaEnsurePyzReadsOnlyTheNewArtifactName(t *testing.T) {
	body := []byte("#!/usr/bin/env python3\nfake")
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])
	old := faManifestURL
	t.Cleanup(func() { faManifestURL = old })

	// A DISTINCT version per case, deliberately. faEnsurePyz returns the cached
	// copy early when the installed version matches the manifest's, so reusing
	// one version would let a later case pass without reaching the name lookup.
	serve := func(files map[string]string, version string) (*httptest.Server, chan string) {
		mux := http.NewServeMux()
		var srv *httptest.Server
		served := make(chan string, 4)
		mux.HandleFunc("/m.json", func(w http.ResponseWriter, r *http.Request) {
			m := map[string]any{}
			for name, path := range files {
				m[name] = map[string]any{"url": srv.URL + path, "sha256": good}
			}
			json.NewEncoder(w).Encode(map[string]any{"version": version, "files": m})
		})
		for _, path := range files {
			path := path
			mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) { served <- path; w.Write(body) })
		}
		srv = httptest.NewServer(signedStub(releaseKindAgent, mux))
		t.Cleanup(srv.Close)
		return srv, served
	}

	withConfigDir(t)
	srv, _ := serve(map[string]string{"bastion-agent-1.1.1.pyz": "/new"}, "1.1.1")
	faManifestURL = srv.URL + "/m.json"
	if _, v, err := faEnsurePyz(); err != nil || v != "1.1.1" {
		t.Fatalf("the artifact name must install: %v %q", err, v)
	}

	// Both names, as the publish script writes while older bastions need the
	// legacy one. The URL proves which entry was downloaded.
	withConfigDir(t)
	srv, served := serve(map[string]string{"bastion-agent-4.4.4.pyz": "/new", "freeagent-4.4.4.pyz": "/legacy"}, "4.4.4")
	faManifestURL = srv.URL + "/m.json"
	if _, v, err := faEnsurePyz(); err != nil || v != "4.4.4" {
		t.Fatalf("both names present must install: %v %q", err, v)
	}
	select {
	case which := <-served:
		if which != "/new" {
			t.Fatalf("downloaded %s; only the new name is read", which)
		}
	default:
		t.Fatal("nothing was downloaded")
	}

	// Only the legacy name: refused, and the error names what was sought.
	withConfigDir(t)
	srv, served = serve(map[string]string{"freeagent-2.2.2.pyz": "/legacy"}, "2.2.2")
	faManifestURL = srv.URL + "/m.json"
	_, _, err := faEnsurePyz()
	if err == nil || !strings.Contains(err.Error(), "bastion-agent-2.2.2.pyz") {
		t.Fatalf("a manifest with only the legacy name must be refused, got %v", err)
	}
	select {
	case which := <-served:
		t.Fatalf("downloaded %s from a manifest it should have refused", which)
	default:
	}
}
