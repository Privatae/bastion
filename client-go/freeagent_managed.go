package main

// local agent, MANAGED: the bastion installs and runs the user's local agent
// itself, from the signed store grant, so a member does nothing but approve
// the store (the step-up they already do) and have Python on the box.
//
// For each synced machine-store grant whose mask includes 'search':
//   1. fetch the agent .pyz from privatae.ai/bastion-agent/version.json and
//      verify its sha256 — the same hash-verified path the bastion's own
//      self-update uses (update.go);
//   2. mint a P-256 key + self-signed cert (CN = the store's local agent id).
//      That one identity is the local agent's TLS cert, its CA root AND the
//      manifest signing key. The bastion is the only client, and the real
//      authorization is the signed DCN grant this box already enforces on
//      every op (dcn.go) — the local agent's gate then only has to prove the
//      manifest was written by this box;
//   3. write the manifest FROM THE GRANT (root, excludes, mask, sweep),
//      seal to the user's registered backup key when the host sent one
//      (seal_recipient in grant sync; an age recipient), pick the local
//      ollama embedding model and learn its dimension by probing, and sign
//      the manifest with the local agent's own `sign` (so the canonical bytes
//      are exactly what its gate verifies);
//   4. supervise `sweep` (the cadence loop) and `serve` (mTLS on
//      127.0.0.1:0, the real port read back from a port file) as child
//      processes with restart backoff, logs under the store's directory.
//
// dcn_search / doc-form dcn_read_range prefer the managed instance for the
// store; PRIVATAE_BASTION_AGENT_* env remains the manual escape hatch for a
// local agent someone runs by hand (freeagent.go). The heartbeat's
// `freeagent` capability means at least one instance is serving; the
// per-store detail (state, version, what is missing — e.g. "python") rides
// in `freeagent_stores` so the Network app can say the one thing to fix.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// faManifestURL is the agent's published manifest. A var so tests can point it
// at a stub.
//
// Bastions from 0.20.0 to 0.41.x also tried the legacy
// privatae.ai/freeagent/version.json when this one failed. That fallback ended
// in 0.42.0. A box that cannot reach this address keeps the agent it has
// installed (faEnsurePyz), so losing the second address costs an update, not
// the agent.
var faManifestURL = "https://privatae.ai/bastion-agent/version.json"

// faFetchManifest returns the published manifest, with the URL it came from
// and the decoded document. An answer that verifies but does not parse as a
// manifest is an error, not an empty manifest.
func faFetchManifest() ([]byte, string, faPublished, error) {
	u := faManifestURL
	// Signed like the bastion's own manifest (release_sign.go): the pyz
	// digest below is only worth what the manifest carrying it is worth.
	body, err := fetchSignedManifest(u, releaseKindAgent)
	if err != nil {
		return nil, "", faPublished{}, err
	}
	var pub faPublished
	if err := json.Unmarshal(body, &pub); err != nil || pub.Version == "" {
		return nil, "", faPublished{}, fmt.Errorf("manifest %s: malformed", u)
	}
	return body, u, pub, nil
}

const (
	faOllamaAddr     = "127.0.0.1:11434"
	faEmbedProbeText = "freeagent embedding probe"
	faReconcileEvery = 10 * time.Minute // retries missing-python/failed; picks up rotated recipients
)

// var so a test can shorten it
var faRestartBackoff = 60 * time.Second

type faInstance struct {
	StoreID   int64
	Dir       string // the child's state: vault, port, logs, its key copy (owner-owned on a root install)
	PrivDir   string // root-private: the minted identity, recipient, manifest staging (== Dir when not dropping)
	PubDir    string // root-owned, readable: host.crt the signature names (== Dir when not dropping)
	AgentDir  string // <root>/.agent — the agent WITH its folder: manifest + prepared output
	CN        string
	Cert, Key string // Cert: the readable cert (PubDir); Key: the daemon's copy (PrivDir)
	ChildKey  string // the key the child serves with (a copy in Dir when dropping; "" = Key)
	Manifest  string
	State     string // installing | running | missing-python | failed
	Detail    string
	Version   string // artifact version the instance runs
	Text      string // the manifest body it was signed from — a change restarts it
	Serving   bool
	// ensuring is true from the moment faEnsureStore hands off to its goroutine
	// until that goroutine returns. State is NOT a substitute: a RUNNING
	// instance keeps State "running" while it re-fetches, so a grant re-sync
	// arriving mid-fetch started a second concurrent ensure for the same store
	// — two downloads, two identity/manifest passes, two restarts of the same
	// children. The window is a fetch, and this change made a fetch longer by
	// trying a second manifest address.
	ensuring bool
	owner    *faOwner // who the children run as (freeagent_drop.go); nil until resolved
	cancel   context.CancelFunc
}

// faSnapshot copies the fields a reader needs, under the lock.
func faSnapshot(storeID int64) (faInstance, bool) {
	faMgr.Lock()
	defer faMgr.Unlock()
	inst, ok := faMgr.inst[storeID]
	if !ok {
		return faInstance{}, false
	}
	return *inst, true
}

var faMgr = struct {
	sync.Mutex
	inst map[int64]*faInstance
}{inst: map[int64]*faInstance{}}

// ── locations ───────────────────────────────────────────────────────────────

// faBaseDir holds the runtime (.pyz + version). A root install keeps it under
// the traversable state base so a dropped child can read it (freeagent_drop.go);
// a non-root install keeps it in configDir.
func faBaseDir() (string, error) {
	if base := faStateBase(); base != "" {
		p := filepath.Join(base, "runtime")
		return p, faMkdirAllMode(p, 0o755)
	}
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "freeagent")
	return p, os.MkdirAll(p, 0o700)
}

// faStoreDir is the store's private state (identity, vault, port, logs). On a
// root install it is <base>/<pairing>/<storeID>: every ancestor 0755 root, the
// leaf 0700 and — once the owner is resolved — owned by the store's uid, so
// the dropped child can reach its own state without configDir being opened.
// A non-root install keeps <dcnDir>/freeagent/<storeID>.
func faStoreDir(dcnDir string, storeID int64) (string, error) {
	dir, _, _, err := faStoreDirs(dcnDir, storeID)
	return dir, err
}

// ── python ──────────────────────────────────────────────────────────────────

// faPython finds a Python >= 3.8. Windows first tries the launcher (`py -3`),
// because the Store's `python3` alias is a stub that opens the Store and
// exits non-zero — the version check below rejects it like any other miss.
func faPython() (string, []string, error) {
	var candidates [][]string
	if runtime.GOOS == "windows" {
		candidates = [][]string{{"py", "-3"}, {"python"}, {"python3"}}
	} else {
		candidates = [][]string{{"python3"}, {"python"}}
	}
	for _, c := range candidates {
		exe, err := exec.LookPath(c[0])
		if err != nil {
			continue
		}
		args := append(append([]string{}, c[1:]...), "-c", "import sys; print('%d.%d' % sys.version_info[:2])")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		probe := exec.CommandContext(ctx, exe, args...)
		hideConsole(probe) // console_windows.go
		out, err := probe.Output()
		cancel()
		if err != nil {
			continue
		}
		parts := strings.SplitN(strings.TrimSpace(string(out)), ".", 2)
		if len(parts) != 2 {
			continue
		}
		maj, _ := strconv.Atoi(parts[0])
		min, _ := strconv.Atoi(parts[1])
		if maj > 3 || (maj == 3 && min >= 8) {
			return exe, c[1:], nil
		}
	}
	return "", nil, errors.New("no Python >= 3.8 on PATH")
}

// faSignManifest signs the agent's manifest with the key this bastion minted
// (faEnsureIdentity), in Go: the agent prints the exact bytes its gate checks
// (`payload`), the bastion signs them, and the agent records the signature
// (`sign --value`). The agent's gate verifies in its own standard library, so
// no step needs openssl — which Windows does not ship: every Windows agent
// used to stop at `missing-openssl` and its store was never indexed.
func faSignManifest(python string, pyArgs []string, pyz, staged, keyPath, certPath string, env []string) error {
	run := func(args ...string) ([]byte, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, python, append(append([]string{}, pyArgs...), args...)...)
		cmd.Env = env
		hideConsole(cmd) // console_windows.go
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.Bytes(), stderr.Bytes(), err
	}
	payload, errOut, err := run(pyz, "payload", staged)
	if err != nil {
		// The agent's own words when it said any; the exec/timeout error always.
		return fmt.Errorf("payload: %v: %s", err, strings.TrimSpace(string(errOut)))
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	blk, _ := pem.Decode(kb)
	if blk == nil || blk.Type != "EC PRIVATE KEY" {
		return errors.New("key: not a PEM EC private key")
	}
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	out, errOut, err := run(pyz, "sign", staged, "--value", base64.StdEncoding.EncodeToString(sig),
		"--cert", certPath)
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)+string(errOut)))
	}
	return nil
}

// ── the artifact ────────────────────────────────────────────────────────────

type faPublished struct {
	Version string `json:"version"`
	Files   map[string]struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

// faMinAgentVersion: the oldest agent that signs its manifest the way
// faSignManifest drives it (`payload` + `sign --value`).
const faMinAgentVersion = "0.1.11"

// faVersionLess compares dotted numeric versions ("0.1.9" < "0.1.11"). An
// unparseable or empty version counts as older than any real one.
func faVersionLess(a, b string) bool {
	pa, pb := strings.Split(strings.TrimSpace(a), "."), strings.Split(strings.TrimSpace(b), ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			n, err := strconv.Atoi(pa[i])
			if err != nil {
				return true
			}
			x = n
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// faEnsurePyz downloads the published local agent when the local copy is
// absent or a different version; sha256-verified before it is written.
// Returns the pyz path and its version.
func faEnsurePyz() (string, string, error) {
	base, err := faBaseDir()
	if err != nil {
		return "", "", err
	}
	pyz := filepath.Join(base, "freeagent.pyz")
	verFile := filepath.Join(base, "freeagent.version")
	_, _, pub, err := faFetchManifest()
	if err != nil {
		// offline, or nothing served anything usable: a previously installed
		// copy still serves.
		if _, e := os.Stat(pyz); e == nil {
			v, _ := os.ReadFile(verFile)
			return pyz, strings.TrimSpace(string(v)), nil
		}
		return "", "", fmt.Errorf("agent manifest: %w", err)
	}
	if v, _ := os.ReadFile(verFile); strings.TrimSpace(string(v)) == pub.Version {
		if _, e := os.Stat(pyz); e == nil {
			return pyz, pub.Version, nil
		}
	}
	// Never step backwards. A signature proves a manifest was once published,
	// not that it is the current one, so a replayed older manifest would
	// otherwise reinstall an agent with bugs already fixed. The publish script
	// refuses to publish a version that is not newer, so the real channel only
	// moves forward and this refuses nothing it sends.
	if v, _ := os.ReadFile(verFile); len(v) > 0 && faVersionLess(pub.Version, string(v)) {
		if _, e := os.Stat(pyz); e == nil {
			return pyz, strings.TrimSpace(string(v)), nil
		}
	}
	// Only the new artifact name. The legacy freeagent-<v>.pyz entry is for
	// bastions older than 0.20.0, which build that name themselves and read it
	// from the legacy address.
	name := "bastion-agent-" + pub.Version + ".pyz"
	f, ok := pub.Files[name]
	if !ok {
		return "", "", fmt.Errorf("agent manifest: no entry for %s", name)
	}
	data, err := download(f.URL)
	if err != nil {
		return "", "", err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != strings.ToLower(f.SHA256) {
		return "", "", errors.New("freeagent download: sha256 mismatch — refusing to install")
	}
	if err := atomicWrite(pyz, data); err != nil {
		return "", "", err
	}
	if err := atomicWrite(verFile, []byte(pub.Version+"\n")); err != nil {
		return "", "", err
	}
	if faStateBase() != "" {
		// atomicWrite makes 0600; a dropped child must read the runtime. It is
		// the published artifact — world-readable costs nothing.
		_ = os.Chmod(pyz, 0o644)
		_ = os.Chmod(verFile, 0o644)
		if err := faShareRuntime(filepath.Dir(pyz)); err != nil {
			return "", "", fmt.Errorf("the runtime cannot be shared with the agent's account: %w", err)
		}
	}
	return pyz, pub.Version, nil
}

// ── identity ────────────────────────────────────────────────────────────────

// faEnsureIdentity mints the store's local agent identity once: P-256 key and a
// self-signed cert with CN = cn (the manifest's owner.host), 10 years. Used
// as TLS server cert, CA root and manifest signing key — the bastion is the
// only party on either end.
//
// minted reports whether this call created the identity — a manifest signed
// under an earlier one must then be re-signed.
func faEnsureIdentity(dir, cn string) (certPath, keyPath string, minted bool, err error) {
	certPath = filepath.Join(dir, "host.crt")
	keyPath = filepath.Join(dir, "host.key")
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, false, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", false, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // it is its own root (FREEAGENT_CA_ROOT)
		DNSNames:              []string{cn, "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", "", false, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", false, err
	}
	if err := atomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})); err != nil {
		return "", "", false, err
	}
	_ = os.Chmod(keyPath, 0o600)
	if err := atomicWrite(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return "", "", false, err
	}
	return certPath, keyPath, true, nil
}

// ── embedding model on this box ─────────────────────────────────────────────

// faEmbedModel picks the local ollama's embedding model (first tag naming
// "embed") and learns its dimension by embedding a probe. ("", 0) when the
// box has none: the manifest then stops at catalog and search is refused
// with a reason the host can show.
func faEmbedModel() (string, int) {
	cl := &http.Client{Timeout: 30 * time.Second}
	resp, err := cl.Get("http://" + faOllamaAddr + "/api/tags")
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if json.NewDecoder(resp.Body).Decode(&tags) != nil {
		return "", 0
	}
	model := ""
	for _, m := range tags.Models {
		if strings.Contains(strings.ToLower(m.Name), "embed") {
			model = m.Name
			break
		}
	}
	if model == "" {
		return "", 0
	}
	body, _ := json.Marshal(map[string]any{"model": model, "input": []string{faEmbedProbeText}})
	r2, err := cl.Post("http://"+faOllamaAddr+"/api/embed", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", 0
	}
	defer r2.Body.Close()
	var out struct {
		Embeddings [][]float64 `json:"embeddings"`
	}
	if json.NewDecoder(r2.Body).Decode(&out) != nil || len(out.Embeddings) == 0 {
		return "", 0
	}
	return model, len(out.Embeddings[0])
}

// ── the manifest ────────────────────────────────────────────────────────────

func yamlStr(s string) string {
	b, _ := json.Marshal(s) // a JSON string is a valid YAML scalar
	return string(b)
}

// faManifestText renders the local agent manifest from the grant. mask is the
// grant's mask restricted to what a local agent understands; stages depend on
// what the box can do (embedding model → chunk+embed; recipient → seal).
func faManifestText(id, cn string, terms *dcnTerms, sweep, recipient, embedModel string, embedDim int) string {
	mask := []string{"read"}
	for _, m := range terms.Mask {
		if (m == "search" || m == "index") && !containsStr(mask, m) {
			mask = append(mask, m)
		}
	}
	stages := []string{"walk", "extract", "sanitize"}
	canIndex := containsStr(mask, "index")
	if canIndex && embedModel != "" && embedDim > 0 {
		stages = append(stages, "chunk", "embed")
	}
	if canIndex {
		stages = append(stages, "catalog")
		if recipient != "" {
			stages = append(stages, "seal")
		}
	}
	sw := "hourly"
	switch sweep {
	case "15m", "hourly", "daily", "manual":
		sw = sweep
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by the bastion from signed store grant %s — do not edit; the grant is the source.\n", id)
	fmt.Fprintf(&b, "freeagent: 1\nid: %s\nowner:\n  host: %s\n", yamlStr(id), yamlStr(cn))
	fmt.Fprintf(&b, "scope:\n  roots: [%s]\n", yamlStr(terms.Root))
	if len(terms.Excludes) > 0 {
		var ex []string
		for _, e := range terms.Excludes {
			ex = append(ex, yamlStr(e))
		}
		fmt.Fprintf(&b, "  exclude: [%s]\n", strings.Join(ex, ", "))
	}
	fmt.Fprintf(&b, "mask: [%s]\nstages: [%s]\n", strings.Join(mask, ", "), strings.Join(stages, ", "))
	b.WriteString("sanitize:\n  mode: flag\n")
	if containsStr(stages, "embed") {
		fmt.Fprintf(&b, "embed:\n  model: %s\n  dim: %d\n  chunk: {size_tokens: 512, overlap_tokens: 64}\n", yamlStr(embedModel), embedDim)
	}
	fmt.Fprintf(&b, "sweep: %s\n", sw)
	catalogSink := "local"
	if containsStr(stages, "seal") {
		catalogSink = "host"
	}
	fmt.Fprintf(&b, "sink:\n  catalog: %s\n  vectors: local\n  plaintext: never\n", catalogSink)
	return b.String()
}

// ── supervision ─────────────────────────────────────────────────────────────

// faChildEnv is an ALLOWLIST, not the daemon's environment: the platform
// bearer and anything else the daemon might carry never reach a child or
// the external tools the extract stage spawns from it.
func faChildEnv(inst *faInstance) []string {
	env := []string{
		"FREEAGENT_CA_ROOT=" + inst.Cert,
		"FREEAGENT_TLS_CERT=" + inst.Cert,
		"FREEAGENT_TLS_KEY=" + firstNonEmpty(inst.ChildKey, inst.Key),
		// the vault holds plaintext PII values: keep it in the bastion's state
		// dir, never inside the folder (which may be cloud-synced)
		"FREEAGENT_VAULT_DIR=" + inst.Dir,
		"EMBED_URL=http://" + faOllamaAddr,
		"PYTHONUNBUFFERED=1",
		"PYTHONIOENCODING=utf-8",
	}
	passthrough := []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
		"SystemRoot", "SYSTEMROOT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
		"ComSpec", "PATHEXT", "XDG_CONFIG_HOME"}
	if inst.owner != nil && inst.owner.drop {
		// A dropped child is told who it is and keeps only the daemon's
		// variables that are not about the daemon's own account (faDropEnv,
		// per platform): its home is the owner's, or the owner's state dir when
		// the account has none.
		set, keep := faDropEnv(inst.owner, inst.Dir)
		env = append(env, set...)
		passthrough = keep
	}
	for _, k := range passthrough {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	if r := faRecipientOf(inst); r != "" {
		env = append(env, "FREEAGENT_OWNER_RECIPIENT="+r)
	}
	return env
}

// faOwnChildren holds the pids of the local agent children this daemon is
// running right now, so the agent OBSERVE plane can exclude them.
//
// Without this, every box with a managed local agent reports its own component
// as an unsanctioned agent on every heartbeat: the sweep is `python3
// freeagent.pyz ...` talking to the local embedder, which is precisely the
// shape of the "interpreter with a connection to an inference port" the
// network signal now looks for. The user would be alerted, forever, about the
// thing they approved.
var faOwnChildren = struct {
	sync.Mutex
	pid map[int]bool
}{pid: map[int]bool{}}

func faTrackPID(pid int) {
	if pid <= 0 {
		return
	}
	faOwnChildren.Lock()
	faOwnChildren.pid[pid] = true
	faOwnChildren.Unlock()
}

func faUntrackPID(pid int) {
	faOwnChildren.Lock()
	delete(faOwnChildren.pid, pid)
	faOwnChildren.Unlock()
}

// faIsOwnChild reports whether a pid is a local agent this daemon started.
func faIsOwnChild(pid int) bool {
	faOwnChildren.Lock()
	defer faOwnChildren.Unlock()
	return faOwnChildren.pid[pid]
}

// faRunOnce runs one child to completion and returns its error.
// Start+Wait rather than Run (which is exactly those two) so the child's pid is
// known while it lives and the observe plane can exclude it.
func faRunOnce(ctx context.Context, inst *faInstance, logName, python string, pyArgs []string, args ...string) error {
	faMgr.Lock()
	owner := inst.owner
	faMgr.Unlock()
	// The log is opened INSIDE the child's dir by os.Root and checked to be a
	// plain single-link file before the child gets the fd: a link
	// planted by the child must never become root's append handle. A refusal
	// is an error the supervisor reports and retries; it never starts a child
	// on a bad handle.
	lf, err := faOpenLog(inst.Dir, logName, owner)
	if err != nil {
		return err
	}
	defer lf.Close()
	cmd := exec.CommandContext(ctx, python, append(append([]string{}, pyArgs...), args...)...)
	cmd.Dir = inst.Dir
	cmd.Env = faChildEnv(inst)
	// The drop (freeagent_drop.go): the three functional children run as the
	// granted folder's owner on a root install; nil = the daemon's own user.
	cmd.SysProcAttr = owner.sysProcAttr()
	// AFTER the drop, never before: sysProcAttr() returns nil on Windows
	// (freeagent_drop_windows.go), so setting the flags first would assign a
	// struct and then have it replaced by that nil. console_windows.go.
	hideConsole(cmd)
	cmd.Stdout, cmd.Stderr = lf, lf
	// faStartChild: an ordinary start, except on Windows with a drop, where the
	// child is created under the owner's own token (freeagent_drop_windows.go).
	child, err := faStartChild(ctx, cmd, owner)
	if err != nil {
		return err
	}
	pid := child.Pid()
	faTrackPID(pid)
	defer faUntrackPID(pid)
	return child.Wait()
}

// faRunChild supervises a long-running child (serve; a cadenced sweep):
// restart after faRestartBackoff whenever it exits while the instance is
// alive. A `manual` sweep is NOT supervised — it exits after one run by
// contract, and re-running it every backoff would be an IO storm against a
// term the user signed.
func faRunChild(ctx context.Context, inst *faInstance, logName string, python string, pyArgs []string, args ...string) {
	for ctx.Err() == nil {
		err := faRunOnce(ctx, inst, logName, python, pyArgs, args...)
		if ctx.Err() != nil {
			return
		}
		faMgr.Lock()
		inst.Detail = fmt.Sprintf("%s exited: %v; restarting in %s", logName, err, faRestartBackoff)
		faMgr.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(faRestartBackoff):
		}
	}
}

// faRecipientOf reads the store's recipient from the ROOT-PRIVATE dir: it is
// read by root and handed to the child as an env value, so it must never sit
// where the child could replace it with a link to a root file.
func faRecipientOf(inst *faInstance) string {
	b, err := os.ReadFile(filepath.Join(firstNonEmpty(inst.PrivDir, inst.Dir), "recipient"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// faManagedConfig is the client config for a store's managed instance, or
// false when none is running (port file absent).
func faManagedConfig(storeID int64) (freeagentConfig, bool) {
	inst, ok := faSnapshot(storeID)
	if !ok {
		return freeagentConfig{}, false
	}
	p, err := faReadIn(inst.Dir, "port") // written by the child; never follow a link out of its dir
	if err != nil {
		return freeagentConfig{}, false
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(p)))
	if err != nil || port <= 0 {
		return freeagentConfig{}, false
	}
	return freeagentConfig{Addr: "127.0.0.1:" + strconv.Itoa(port), Cert: inst.Cert, Key: inst.Key, CA: inst.Cert}, true
}

// ── ensure / reconcile ──────────────────────────────────────────────────────

// faEnsureStore installs (idempotently) and runs the local agent for one store.
// Called after a successful grant sync and at daemon start for every synced
// grant with 'search'. Never blocks the caller: the work runs in its own
// goroutine and reports through the instance state.
func faEnsureStore(dcnDir string, storeID int64, terms *dcnTerms, sweep, recipient string) {
	if !dcnHasMask(terms, "search") || terms.Root == "" {
		return
	}
	dir, priv, pub, err := faStoreDirs(dcnDir, storeID)
	if err != nil {
		return
	}
	cn := "store-" + strconv.FormatInt(storeID, 10)
	faMgr.Lock()
	inst, ok := faMgr.inst[storeID]
	if !ok {
		inst = &faInstance{StoreID: storeID, Dir: dir, PrivDir: priv, PubDir: pub, CN: cn, State: "installing"}
		faMgr.inst[storeID] = inst
	} else if inst.State == "installing" || inst.ensuring {
		faMgr.Unlock()
		return // one ensure at a time per store — see faInstance.ensuring
	}
	inst.ensuring = true
	faMgr.Unlock()

	go func() {
		// Cleared on EVERY exit from this goroutine, including the failure
		// returns below — a flag left set would wedge the store out of every
		// future ensure, which is worse than the double-ensure it prevents.
		defer func() {
			faMgr.Lock()
			inst.ensuring = false
			faMgr.Unlock()
		}()
		fail := func(state, detail string) {
			faMgr.Lock()
			inst.State, inst.Detail = state, detail
			faMgr.Unlock()
		}
		// Who the agent runs as — decided before anything is fetched or
		// written, and a refusal is the store's state (the card says why).
		owner, err := faResolveOwner(terms.Root, dir)
		if err != nil {
			fail("failed", err.Error())
			return
		}
		faMgr.Lock()
		inst.owner = owner
		faMgr.Unlock()
		python, pyArgs, err := faPython()
		if err != nil {
			fail("missing-python", err.Error())
			return
		}
		pyz, version, err := faEnsurePyz()
		if err != nil {
			fail("failed", err.Error())
			return
		}
		// The manifest is signed through the agent's `payload` / `sign --value`
		// (faSignManifest), which an older agent does not have. A cached older
		// copy (the release manifest unreachable) or a release not yet
		// published is named as that, not left to fail as an unknown flag.
		if faVersionLess(version, faMinAgentVersion) {
			fail("failed", fmt.Sprintf("the installed agent is %s and this bastion needs %s or "+
				"newer; it is fetched on the next retry once published", version, faMinAgentVersion))
			return
		}
		// The identity is minted and kept in the root-private dir; the child
		// gets a copy of the key in its own dir and reads the cert from the
		// root-owned public dir — the path its manifest signature names, which
		// it can verify but never replace.
		cert, key, minted, err := faEnsureIdentity(priv, cn)
		if err != nil {
			fail("failed", "identity: "+err.Error())
			return
		}
		if recipient != "" {
			_ = atomicWrite(filepath.Join(priv, "recipient"), []byte(recipient+"\n"))
		}
		// The state leaf is the child's from here: its path is root-owned all
		// the way down (faStoreDirs), so this by-path chown cannot be steered.
		if err := faOwn(owner, dir); err != nil {
			fail("failed", "state dir: "+err.Error())
			return
		}
		// One handle per directory root writes into, verified to be the
		// owner's, held for the whole ensure (freeagent_drop.go faOpenOwned).
		rDir, err := faOpenOwned(dir, owner)
		if err != nil {
			fail("failed", "state dir: "+err.Error())
			return
		}
		defer rDir.Close()
		childKey, childCert := key, cert
		if owner.drop {
			kb, err := os.ReadFile(key)
			if err == nil {
				err = faOwnedWrite(rDir, "host.key", kb, 0o600, owner)
			}
			if err != nil {
				fail("failed", "key copy: "+err.Error())
				return
			}
			childKey = filepath.Join(dir, "host.key")
			rPub, err := os.OpenRoot(pub)
			if err != nil {
				fail("failed", "cert publish: "+err.Error())
				return
			}
			cb, err := os.ReadFile(cert)
			if err == nil {
				err = faOwnedWrite(rPub, "host.crt", cb, 0o644, nil)
			}
			rPub.Close()
			if err != nil {
				fail("failed", "cert publish: "+err.Error())
				return
			}
			if err := faSharePub(pub, owner); err != nil {
				fail("failed", "cert publish: "+err.Error())
				return
			}
			childCert = filepath.Join(pub, "host.crt")
			// vault, port, logs, key copy: the child's, re-applied every ensure
			if err := faOwnTree(rDir, ".", owner); err != nil {
				fail("failed", "state dir ownership: "+err.Error())
				return
			}
		}
		model, dim := faEmbedModel()
		text := faManifestText(cn, cn, terms, sweep, recipient, model, dim)
		// files-and-folders: the agent lives in <root>/.agent (manifest +
		// outputs); the walker always excludes it. Secrets stay in inst.Dir.
		// Created and written by name inside the folder (os.Root): a `.agent`
		// the child replaced with a link out of the folder is refused.
		// agentRoot/agentRel address the agent dir INSIDE its parent's handle:
		// the folder's for <root>/.agent, the state leaf's for the fallback.
		agentRoot, agentRel, agentParent := rDir, "out", dir
		agentNote := ""
		var rFolder *os.Root
		inFolder := faAgentDirInFolder(owner)
		if inFolder {
			rFolder, err = faOpenOwned(terms.Root, owner)
			if err == nil {
				err = faOwnedMkdir(rFolder, ".agent", owner)
			}
		} else {
			// Not a fault in the folder: on this platform the bastion writes
			// nothing into it (faAgentDirInFolder), and the card says so plainly.
			err = errors.New(faAgentKeptInStateNote)
		}
		if err == nil {
			defer rFolder.Close()
			agentRoot, agentRel, agentParent = rFolder, ".agent", terms.Root
			// what a member may commit from .agent is the DEFINITION, never the
			// stores (the extract store is plaintext text of every file)
			_ = faOwnedWrite(rFolder, ".agent/.gitignore", []byte("*\n!manifest.yaml\n!.gitignore\n"), 0o600, owner)
			// residue from a pre-0.13.3 install: outputs used to live in the
			// state dir (private); nothing reads them now
			_ = rDir.RemoveAll("out")
			_ = rDir.Remove("manifest.yaml")
		} else {
			// a read-only root (archive mount, read-only share) can still be
			// walked and searched: the agent then lives in the bastion's
			// state dir instead, and the store card says so
			if rFolder != nil {
				rFolder.Close()
			}
			agentNote = faAgentDirNote(inFolder, err)
			if err := faOwnedMkdir(rDir, "out", owner); err != nil {
				fail("failed", "agent dir: "+err.Error())
				return
			}
		}
		agentDir := filepath.Join(agentParent, agentRel)
		manifestRel := agentRel + "/manifest.yaml"

		// Same manifest, same artifact, already running → nothing to do. A
		// re-approved grant with different terms (excludes, mask, sweep, a
		// recipient registered later) or a new artifact version restarts the
		// instance under the new manifest — the early return used to come
		// before this comparison.
		faMgr.Lock()
		unchanged := inst.State == "running" && inst.Text == text && inst.Version == version && inst.cancel != nil
		faMgr.Unlock()
		if unchanged {
			return
		}
		fail("installing", "")
		manifest := filepath.Join(agentDir, "manifest.yaml")
		old, _ := agentRoot.ReadFile(manifestRel)
		// Re-sign unless the body is unchanged AND its signature names the
		// cert the child will verify against: a fresh identity (new layout,
		// a wiped base, a re-pair) with a surviving manifest would otherwise
		// keep a signature the gate refuses.
		if minted || !bytes.HasPrefix(old, []byte(text)) || !bytes.Contains(old, []byte("cert: "+childCert+"\n")) {
			// `sign` runs root-side over a ROOT-PRIVATE staging copy — never
			// in place inside the folder, where the child could swap the file
			// for a link between the write and the sign. Only the
			// finished bytes are placed in .agent, by name, then handed over.
			staged := filepath.Join(priv, "manifest.yaml")
			if err := atomicWrite(staged, []byte(text)); err != nil {
				fail("failed", "manifest: "+err.Error())
				return
			}
			if err := faSignManifest(python, pyArgs, pyz, staged, key, childCert,
				faChildEnv(&faInstance{Dir: priv, Cert: cert, Key: key})); err != nil {
				fail("failed", "sign: "+err.Error())
				return
			}
			signed, err := os.ReadFile(staged)
			if err == nil {
				err = faOwnedWrite(agentRoot, manifestRel, signed, 0o600, owner)
			}
			if err != nil {
				fail("failed", "manifest place: "+err.Error())
				return
			}
		} else if err := faOwnIn(agentRoot, manifestRel, owner); err != nil {
			fail("failed", "manifest ownership: "+err.Error())
			return
		}
		// an .agent subtree left by an earlier root run (extract/<xx>/) must be
		// the owner's too, or the child's os.replace into it fails
		if err := faOwnTree(agentRoot, agentRel, owner); err != nil {
			fail("failed", "agent dir ownership: "+err.Error())
			return
		}
		faMgr.Lock()
		if inst.cancel != nil {
			inst.cancel() // stop the previous children before the new ones bind
		}
		inst.Cert, inst.Key, inst.ChildKey, inst.Manifest, inst.Version, inst.Text = childCert, key, childKey, manifest, version, text
		inst.AgentDir = agentDir
		inst.State, inst.Detail = "running", agentNote
		ctx, cancel := context.WithCancel(context.Background())
		inst.cancel = cancel
		faMgr.Unlock()
		outDir := agentDir
		_ = os.Remove(filepath.Join(dir, "port"))
		if sweep == "manual" {
			go func() {
				_ = faRunOnce(ctx, inst, "sweep.log", python, pyArgs, pyz, "sweep", manifest, "--out", outDir, "--once")
			}()
		} else {
			go faRunChild(ctx, inst, "sweep.log", python, pyArgs, pyz, "sweep", manifest, "--out", outDir)
		}
		go faRunChild(ctx, inst, "serve.log", python, pyArgs, pyz, "serve", manifest, "--out", outDir,
			"--bind", "127.0.0.1:0", "--port-file", filepath.Join(dir, "port"))
	}()
}

// faReconcileLoop runs faReconcile at start and every faReconcileEvery, so a
// box that lacked Python (or openssl, or was offline for the download) picks
// the install up once the gap is fixed, and a changed artifact or recipient
// is applied without a daemon restart.
func faReconcileLoop(ctx context.Context, dcnDir string) {
	for {
		faReconcile(dcnDir)
		select {
		case <-ctx.Done():
			return
		case <-time.After(faReconcileEvery):
		}
	}
}

// faReconcile brings up managed instances for every synced grant that carries
// 'search' — at daemon start, so a restart never loses a running local agent.
func faReconcile(dcnDir string) {
	if dcnDir == "" {
		return
	}
	f, err := dcnLoadFile(dcnDir)
	if err != nil || f.VerifyPubkey == "" {
		return
	}
	for id, rec := range f.Stores {
		terms, err := dcnVerifyRec(f.VerifyPubkey, rec)
		if err != nil {
			continue
		}
		sid, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			continue
		}
		faEnsureStore(dcnDir, sid, terms, sweepFromCanonical(rec.TermsCanonical), rec.SealRecipient)
	}
}

// sweepFromCanonical reads the optional `sweep` from the signed terms bytes.
func sweepFromCanonical(termsB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(termsB64)
	if err != nil {
		return ""
	}
	var t struct {
		Sweep string `json:"sweep"`
	}
	if json.Unmarshal(raw, &t) != nil {
		return ""
	}
	switch t.Sweep {
	case "15m", "hourly", "daily", "manual":
		return t.Sweep
	}
	return ""
}

// faManagedProbe reports (anyManaged, allServing) and refreshes each
// instance's Serving flag by probing its /health over mTLS.
func faManagedProbe() (bool, bool) {
	faMgr.Lock()
	ids := make([]int64, 0, len(faMgr.inst))
	for id := range faMgr.inst {
		ids = append(ids, id)
	}
	faMgr.Unlock()
	if len(ids) == 0 {
		return false, false
	}
	all := true
	for _, id := range ids {
		serving := false
		if c, ok := faManagedConfig(id); ok {
			status, body, err := freeagentCallTimeout(c, http.MethodGet, "/health", nil, freeagentProbeTimeout)
			if err == nil && status == http.StatusOK {
				var h struct {
					OK      bool `json:"ok"`
					Serving bool `json:"serving"`
				}
				serving = json.Unmarshal(body, &h) == nil && h.OK && h.Serving
			}
		}
		faMgr.Lock()
		if inst, ok := faMgr.inst[id]; ok {
			inst.Serving = serving
		}
		faMgr.Unlock()
		if !serving {
			all = false
		}
	}
	return true, all
}

// faManagedStatus is the heartbeat's per-store detail.
func faManagedStatus() map[string]any {
	faMgr.Lock()
	defer faMgr.Unlock()
	out := map[string]any{}
	for id, inst := range faMgr.inst {
		out[strconv.FormatInt(id, 10)] = map[string]any{
			"state": inst.State, "serving": inst.Serving, "version": inst.Version, "detail": inst.Detail,
		}
	}
	return out
}

// faStop tears down a store's managed instance (grant revoked / re-synced
// without search).
func faStop(storeID int64) {
	faMgr.Lock()
	defer faMgr.Unlock()
	if inst, ok := faMgr.inst[storeID]; ok {
		if inst.cancel != nil {
			inst.cancel()
		}
		delete(faMgr.inst, storeID)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
