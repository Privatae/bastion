//go:build !windows

// Tagged to match anchor_test.go, which is where setupBox, driveOp,
// writePairingState and the grant helpers live. Without this the WINDOWS test
// build fails on `undefined: setupBox` — and note WHICH command catches it:
// `GOOS=windows go build ./...` passes, because build does not compile test
// files. Only `GOOS=windows go vet ./...` (or `go test`) sees this. Reporting a
// green cross-BUILD as a green cross-target is how this has shipped red
// before; run vet.
//
// The lane itself (modelswap.go) is platform-neutral and builds everywhere.
// Only these gates borrow the anchored-box fixture.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── a stand-in model daemon ────────────────────────────────────────────────
//
// Every response shape below was MEASURED against ollama 0.34.0
// (see modelswap.go's header) — including the one that matters most, a failed
// pull answering HTTP 200 with the failure only in the body.

type fakeDaemon struct {
	srv *httptest.Server
	// pullStatus / pullBody are what /api/pull answers. pullBody is a STREAM:
	// one JSON object per line, the shape measured against ollama 0.34.0.
	pullStatus int
	pullBody   string
	// pulls counts how many times /api/pull was actually reached. The refusal
	// tests assert it stays ZERO — proving the download did not happen, rather
	// than only that the op returned an error.
	pulls int
	// embedFixed makes /api/embed return ONE constant vector whatever it is
	// asked — the endpoint the second probe gate exists to catch.
	embedFixed bool
	// embedFail makes /api/embed answer the way ollama does for a model that
	// cannot embed: HTTP 501 with an error body (measured on qwen3:0.6b).
	embedFail  bool
	tags       []string
	deleted    []string
	deleteHTTP int
}

func newFakeDaemon(t *testing.T, f *fakeDaemon) *fakeDaemon {
	t.Helper()
	if f.pullStatus == 0 {
		f.pullStatus = 200
	}
	if f.pullBody == "" {
		// The real stream shape: manifest, then each layer announcing its size
		// BEFORE its bytes move, then success.
		f.pullBody = "{\"status\":\"pulling manifest\"}\n" +
			"{\"status\":\"pulling sha256:aaa\",\"digest\":\"sha256:aaa\",\"total\":1000}\n" +
			"{\"status\":\"success\"}\n"
	}
	if f.deleteHTTP == 0 {
		f.deleteHTTP = 200
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		ms := []map[string]any{}
		for _, n := range f.tags {
			ms = append(ms, map[string]any{"name": n, "model": n})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"models": ms})
	})
	mux.HandleFunc("/api/pull", func(w http.ResponseWriter, r *http.Request) {
		f.pulls++
		w.WriteHeader(f.pullStatus)
		fmt.Fprint(w, f.pullBody)
	})
	mux.HandleFunc("/api/delete", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if f.deleteHTTP != 200 {
			w.WriteHeader(f.deleteHTTP)
			fmt.Fprintf(w, `{"error":"model '%s' not found"}`, req.Model)
			return
		}
		f.deleted = append(f.deleted, req.Model)
	})
	mux.HandleFunc("/api/embed", func(w http.ResponseWriter, r *http.Request) {
		if f.embedFail {
			w.WriteHeader(501)
			fmt.Fprint(w, `{"error":"This server does not support embeddings."}`)
			return
		}
		var req struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		text := ""
		if len(req.Input) > 0 {
			text = req.Input[0]
		}
		// A tiny deterministic "model": the vector depends on the input unless
		// embedFixed says otherwise. Deterministic on purpose — a real embedder
		// answers the same text identically, which is gate one.
		vec := []float64{1, 0, 0, 0}
		if !f.embedFixed && text == modelProbeTextB {
			vec = []float64{0, 1, 0, 0}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"embeddings": [][]float64{vec}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	t.Setenv("OLLAMA_ADDR", strings.TrimPrefix(f.srv.URL, "http://"))
	resetModelDaemonCache()
	return f
}

// driveModelOp runs one model:* op against a fresh per-pairing root and hands
// the root back so a test can inspect the ownership ledger.
func driveModelOp(t *testing.T, self, op string, args []string, root string) (string, string, int, string) {
	t.Helper()
	if root == "" {
		root = t.TempDir()
	}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConnFor(ws, self, "", root, "")
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	job, _ := json.Marshal(mgmtJob{Op: op, Args: args, Approval: testApproval(t, op, args)})
	if err := c.WriteMessage(websocket.BinaryMessage, append([]byte("C"), job...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errOut string
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch data[0] {
		case 'O':
			out += string(data[1:])
		case 'R':
			errOut += string(data[1:])
		case 'X':
			var code int
			fmt.Sscanf(string(data[1:]), "%d", &code)
			return out, errOut, code, root
		}
	}
}

// ── the gate ───────────────────────────────────────────────────────────────

// An op name outside opFamily's vocabulary is an UNGATED op: capsAllow returns
// "" for family "" (anchor.go:476-479). This is the test that catches a rename.
func TestModelOpsResolveToTheModelsFamily(t *testing.T) {
	for _, op := range []string{"model:list", "model:pull", "model:drop"} {
		fam := opFamily(op)
		if fam == "" {
			t.Fatalf("%q maps to NO caps family — capsAllow fails open on an unknown op, "+
				"so this lane would be ungated for every member pairing on an anchored box", op)
		}
		if fam != modelGateOpFamily {
			t.Fatalf("%q is family %q, not the declared %q", op, fam, modelGateOpFamily)
		}
	}
	// "model:" must not be swallowed by the "mode:" prefix above it, which means
	// harness — a collision would silently hand this lane to every harness grant.
	if opFamily("mode:dispatch") != "harness" {
		t.Fatal("the mode: prefix stopped meaning harness")
	}
	if opFamily(modelGateOp) == "harness" {
		t.Fatal("model: collided with mode: — a harness grant would carry model management")
	}
	found := false
	for _, c := range allCaps {
		found = found || c == modelGateOpFamily
	}
	if !found {
		t.Fatalf("family %q is not in allCaps %v — ungrantable", modelGateOpFamily, allCaps)
	}
}

// THE ONE THAT MATTERS: a new capability must not silently widen an existing
// grant. The member here holds a real, signed, verified grant — for `inference`,
// the family that already carries the right to USE this box's loaded models. It
// must still be refused every model:* op. Using an inference-granted member
// rather than an ungranted one is deliberate: an ungranted pairing is
// default-denied at anchor.go:472-475 before the family is ever consulted, so it
// would pass this test even if the family check did nothing at all.
func TestModelOpsRefusedToAMemberGrantedInference(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"inference", "observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("could not install the inference grant: %d %s", code, errOut)
	}
	// The grant is real: an op inside it reaches its handler.
	if _, errOut, code := driveOp(t, tMember, "uptime", nil); code == 126 && contains(errOut, "caps") {
		t.Fatalf("the observe grant did not take, so this test proves nothing: %s", errOut)
	}
	if why := capsAllow(tMember, "inference"); why != "" {
		t.Fatalf("the inference grant did not take, so this test proves nothing: %s", why)
	}

	for _, op := range []string{"model:list", "model:pull", "model:drop"} {
		why := capsAllow(tMember, op)
		if why == "" {
			t.Fatalf("%q was ALLOWED to a pairing granted inference — adding model management "+
				"silently widened every existing inference grant", op)
		}
		if !contains(why, "models") {
			t.Fatalf("the refusal must name the family it wanted: %s", why)
		}
		_, errOut, code, _ := driveModelOp(t, tMember, op, []string{`{"model":"x","role":"embed"}`}, "")
		if code != 126 || !contains(errOut, "caps") {
			t.Fatalf("%q must be refused at the ceiling, before the handler: %d %s", op, code, errOut)
		}
	}
	// And the anchor pairing, which holds every family, is not refused.
	if why := capsAllow(tAnchor, modelGateOp); why != "" {
		t.Fatalf("the anchor must reach the lane: %s", why)
	}
}

// The heartbeat must not offer a control the box would refuse: a pairing outside
// the family sees no model-swap capability even with a daemon answering.
func TestModelSwapCapabilityWithheldOutsideTheFamily(t *testing.T) {
	priv := setupBox(t)
	newFakeDaemon(t, &fakeDaemon{tags: []string{"all-minilm:latest"}})
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"inference"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	if modelSwapCapable(tMember) {
		t.Fatal("a pairing granted only inference was advertised model management")
	}
	if !modelSwapCapable(tAnchor) {
		t.Fatal("the anchor, with a daemon answering, must be advertised model management")
	}
	raw := buildHeartbeatBody(tMember, "box", "linux", "test", "pk", "fp", "", "", false, nil, nil, nil)
	var body struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	for _, c := range body.Capabilities {
		if c == modelSwapCapability {
			t.Fatal("the heartbeat advertised model-swap to a pairing that would be refused it")
		}
	}
}

// ── never unload a model the host did not put there ────────────────────────

func TestDropRefusesAModelThisHostDidNotPlace(t *testing.T) {
	f := newFakeDaemon(t, &fakeDaemon{tags: []string{"the-users-own-llama"}})
	// An unanchored box gates nothing at the caps layer (capsAllow returns "" —
	// anchor.go:462-465), so this test exercises the OWNERSHIP rule alone.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, errOut, code, root := driveModelOp(t, tAnchor, "model:drop", []string{`{"model":"the-users-own-llama"}`}, "")
	if code == 0 {
		t.Fatal("a model this host never placed was removed")
	}
	if !contains(errOut, "did not put") {
		t.Fatalf("the refusal must say why: %s", errOut)
	}
	if len(f.deleted) != 0 {
		t.Fatalf("the daemon was asked to delete anyway: %v", f.deleted)
	}
	// The ledger is what makes it droppable, and nothing else.
	if err := recordPlaced(root, "the-users-own-llama", placedModel{PlacedAt: "now", Role: "embed"}); err != nil {
		t.Fatal(err)
	}
	out, errOut, code, _ := driveModelOp(t, tAnchor, "model:drop", []string{`{"model":"the-users-own-llama"}`}, root)
	if code != 0 {
		t.Fatalf("a model in this host's ledger must be droppable: %d %s", code, errOut)
	}
	if !contains(out, `"removed":true`) {
		t.Fatalf("unexpected answer: %s", out)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "the-users-own-llama" {
		t.Fatalf("the daemon was not asked to delete it: %v", f.deleted)
	}
	if placedByThisHost(root, "the-users-own-llama") {
		t.Fatal("the ledger still claims a removed model")
	}
}

// One host's ledger is not another's: the per-pairing root is the mechanism.
func TestOneHostsLedgerDoesNotAuthoriseAnother(t *testing.T) {
	newFakeDaemon(t, &fakeDaemon{tags: []string{"m"}})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	rootA, rootB := t.TempDir(), t.TempDir()
	if err := recordPlaced(rootA, "m", placedModel{PlacedAt: "now", Role: "embed"}); err != nil {
		t.Fatal(err)
	}
	if !placedByThisHost(rootA, "m") {
		t.Fatal("host A must own what it placed")
	}
	if placedByThisHost(rootB, "m") {
		t.Fatal("host B was handed ownership of a model host A placed")
	}
	if _, _, code, _ := driveModelOp(t, tAnchor, "model:drop", []string{`{"model":"m"}`}, rootB); code == 0 {
		t.Fatal("host B dropped a model host A placed")
	}
}

// An unreadable or absent ledger must DENY, never allow.
func TestAnAbsentLedgerDenies(t *testing.T) {
	root := t.TempDir()
	if placedByThisHost(root, "anything") {
		t.Fatal("an empty ledger claimed ownership")
	}
	if err := os.WriteFile(modelsPlacedPath(root), []byte("not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if placedByThisHost(root, "anything") {
		t.Fatal("a corrupt ledger claimed ownership — this lane must fail closed")
	}
}

// ── probe before commit ────────────────────────────────────────────────────

// MEASURED: a streaming pull of a model that does not exist answers HTTP 200 and
// reports the failure only in the body. Reporting on the status alone would have
// told the user a model was installed that was never downloaded.
func TestAFailedPullInsideA200IsNotASuccess(t *testing.T) {
	newFakeDaemon(t, &fakeDaemon{
		pullStatus: 200,
		pullBody:   "{\"status\":\"pulling manifest\"}\n{\"error\":\"pull model manifest: file does not exist\"}\n",
	})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// A REAL approval, so this test reaches the daemon and actually exercises
	// the 200-with-an-error case. Without one it would be refused at the gate
	// and pass for the wrong reason.
	root := t.TempDir()
	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "nope", "embed", 1<<20, "")
	// The lane is async now (see modelswap.go's ASYNC block), so the failure is
	// on the JOB rather than on the frame. Same property, one poll later.
	job := pullToCompletion(t, tAnchor, root, "nope", "embed", 1<<20, approval)
	if job["state"] != "failed" {
		t.Fatalf("a failed pull reported as success: %v", job)
	}
	if why, _ := job["error"].(string); !contains(why, "was not downloaded") {
		t.Fatalf("the refusal must say the download failed: %v", job)
	}
	if placedByThisHost(root, "nope") {
		t.Fatal("a model that was never downloaded was written into the ownership ledger")
	}
}

// A download that succeeded proves only that bytes arrived. A model whose
// behaviour does not check out is reported NOT available — and stays droppable,
// because this host did put those bytes on that disk.
func TestAModelThatDownloadsButFailsItsProbeIsNotAvailable(t *testing.T) {
	newFakeDaemon(t, &fakeDaemon{embedFixed: true})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "constant", "embed", 1<<20, "")
	job := pullToCompletion(t, tAnchor, root, "constant", "embed", 1<<20, approval)
	if job["state"] != "done" {
		t.Fatalf("the job itself should finish, not error: %v", job)
	}
	if job["available"] != false || job["downloaded"] != true {
		t.Fatalf("a fixed-vector endpoint downloaded but is not available: %v", job)
	}
	if why, _ := job["why"].(string); !contains(why, "fixed vector") {
		t.Fatalf("the reason must name what was wrong: %v", job)
	}
	if !placedByThisHost(root, "constant") {
		t.Fatal("a downloaded model must stay droppable even when its probe fails, " +
			"or a bad pull leaves bytes on the user's disk that nothing may remove")
	}
}

// The same discipline for a model that cannot do the role at all: ollama answers
// HTTP 501 for /api/embed on a text model (measured on qwen3:0.6b).
func TestAModelThatCannotDoTheRoleIsNotAvailable(t *testing.T) {
	newFakeDaemon(t, &fakeDaemon{embedFail: true})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "a-chat-model", "embed", 1<<20, "")
	job := pullToCompletion(t, tAnchor, root, "a-chat-model", "embed", 1<<20, approval)
	if job["available"] != false {
		t.Fatalf("a model that cannot embed must not be reported as an embedder: %v", job)
	}
}

func TestAGoodPullIsAvailableWithItsMeasuredWidth(t *testing.T) {
	newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "good", "embed", 1<<20, "")
	job := pullToCompletion(t, tAnchor, root, "good", "embed", 1<<20, approval)
	if d, _ := job["dim"].(float64); job["available"] != true || d != 4 {
		t.Fatalf("a model that passes both gates is available at the width MEASURED: %v", job)
	}
	if !placedByThisHost(root, "good") {
		t.Fatal("a pulled model must be recorded as this host's")
	}
}

// A role with no probe would mean reporting a model as working without checking
// it, which is the thing this lane exists to prevent.
func TestPullRefusesARoleItCannotProbe(t *testing.T) {
	newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull", []string{`{"model":"x","role":"transcribe"}`}, "")
	if code == 0 || !contains(errOut, "role must be") {
		t.Fatalf("an unprobeable role must be refused: %d %s", code, errOut)
	}
}

// model:list says which models are present AND which are this host's to remove.
// A host that could not tell them apart could not make an honest proposal.
func TestListSeparatesWhatThisHostPlaced(t *testing.T) {
	newFakeDaemon(t, &fakeDaemon{tags: []string{"theirs", "ours"}})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	if err := recordPlaced(root, "ours", placedModel{PlacedAt: "now", Role: "embed", Dim: 384}); err != nil {
		t.Fatal(err)
	}
	out, errOut, code, _ := driveModelOp(t, tAnchor, "model:list", nil, root)
	if code != 0 {
		t.Fatalf("%d %s", code, errOut)
	}
	var got struct {
		Models []modelEntry `json:"models"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(got.Models) != 2 {
		t.Fatalf("both models must be listed: %s", out)
	}
	for _, m := range got.Models {
		if m.Model == "ours" && !m.PlacedHere {
			t.Fatal("a model this host placed was not marked as such")
		}
		if m.Model == "theirs" && m.PlacedHere {
			t.Fatal("a model the USER pulled was claimed by this host")
		}
	}
}

// The op vocabulary the box reports must include these, or the host cannot know
// the lane exists — handlerOps is the single table both read (mgmt.go:50-52).
func TestModelOpsAreInTheReportedVocabulary(t *testing.T) {
	for _, op := range []string{"model:list", "model:pull", "model:drop"} {
		if _, ok := handlerOps[op]; !ok {
			t.Fatalf("%q is not in handlerOps", op)
		}
	}
}

// ── against a REAL model daemon ────────────────────────────────────────────
//
// Opt-in, because it downloads a model: set PRIVATAE_MODEL_DAEMON_E2E to the
// address of a running ollama (e.g. 127.0.0.1:11434). The fakes above pin the
// SHAPES this code handles; this pins that the shapes are the real ones.
//
// Run against ollama 0.34.0 (container, all-minilm 46 MB) — the run
// that produced the numbers in modelswap.go's header.
func TestAgainstARealModelDaemon(t *testing.T) {
	addr := os.Getenv("PRIVATAE_MODEL_DAEMON_E2E")
	if addr == "" {
		t.Skip("set PRIVATAE_MODEL_DAEMON_E2E=<host:port> to run this")
	}
	t.Setenv("OLLAMA_ADDR", addr)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	resetModelDaemonCache()
	if !modelDaemonReachable() {
		t.Fatalf("no daemon at %s", addr)
	}

	// The whole real flow, including the user's approval on this machine.
	root := t.TempDir()
	enrollFactor(t, root)

	// A model that does not exist must not be reported as installed, and must
	// not enter the ownership ledger.
	badApproval := proposeAndApprove(t, root, "privatae-no-such-model-xyz", "embed", 1<<30, "")
	_, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{pullArg("privatae-no-such-model-xyz", "embed", 1<<30, "", badApproval)}, root)
	if code == 0 {
		t.Fatal("a pull of a nonexistent model reported success")
	}
	t.Logf("nonexistent pull refused: %s", strings.TrimSpace(errOut))
	if placedByThisHost(root, "privatae-no-such-model-xyz") {
		t.Fatal("a model that was never downloaded entered the ledger")
	}

	// A real embedding model: downloaded, probed, available at its MEASURED
	// width, and then droppable because this host placed it.
	// An UNAPPROVED pull of a real model must not download it — proved against
	// the real daemon, not only the fake.
	if _, _, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{pullArg("all-minilm", "embed", 1<<30, "", "")}, root); code != 126 {
		t.Fatalf("an unapproved pull must be refused against a real daemon too: %d", code)
	}
	if tags := realTags(t, addr); contains(tags, "all-minilm") {
		t.Fatal("the unapproved pull downloaded the model anyway")
	}

	// Its OWN root: a TOTP code is burned once per 30s window
	// (stepupVerifyAndBurn), so two approvals a second apart in one state dir is
	// a replay and is correctly refused. Real users do not approve twice inside
	// one window; a test does.
	root2 := t.TempDir()
	enrollFactor(t, root2)
	approval := proposeAndApprove(t, root2, "all-minilm", "embed", 1<<30, "")
	out, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{pullArg("all-minilm", "embed", 1<<30, "", approval)}, root2)
	if code != 0 {
		t.Fatalf("pull: %d %s", code, errOut)
	}
	if !contains(out, `"available":true`) {
		t.Fatalf("a real embedding model must pass both probe gates: %s", out)
	}
	t.Logf("pull: %s", out)
	if !placedByThisHost(root2, "all-minilm") {
		t.Fatal("a pulled model must be this host's to drop")
	}
	out, errOut, code, _ = driveModelOp(t, tAnchor, "model:drop", []string{`{"model":"all-minilm"}`}, root2)
	if code != 0 {
		t.Fatalf("drop: %d %s", code, errOut)
	}
	t.Logf("drop: %s", out)
	if placedByThisHost(root2, "all-minilm") {
		t.Fatal("the ledger still claims a removed model")
	}
}

// ── the approval gate (machine-side, by the owner) ─────────────────────────

const tSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// enrollFactor puts a confirmed second factor in this pairing's state dir, the
// same way TestStepupRequestFlow does (stepup_test.go:117).
func enrollFactor(t *testing.T, root string) {
	t.Helper()
	if err := stepupSave(root, &stepupFile{SecretB32: tSecret,
		EnrolledAt: "2026-08-29T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
}

func pullDetails(model, role string, maxBytes int64, replaces string) map[string]any {
	return map[string]any{"kind": "model_pull", "model": model, "role": role,
		"max_bytes": float64(maxBytes), "replaces": replaces}
}

// proposeAndApprove walks the whole real flow: the host files a request, the
// box rebuilds the purpose from the details, the user approves on the machine
// with their code. Returns the approval id.
func proposeAndApprove(t *testing.T, root, model, role string, maxBytes int64, replaces string) string {
	t.Helper()
	d := pullDetails(model, role, maxBytes, replaces)
	purpose, err := purposeFromDetails(d)
	if err != nil {
		t.Fatalf("purpose: %v", err)
	}
	id, err := stepupNewRequest(root, purpose, d)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	raw, _ := b32decode(tSecret)
	code := hotp(raw, time.Now().Unix()/stepupPeriod)
	approval, err := stepupApproveRequest(root, id, code)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return approval
}

func pullArg(model, role string, maxBytes int64, replaces, approval string) string {
	b, _ := json.Marshal(modelReq{Model: model, Role: role, MaxBytes: maxBytes,
		Replaces: replaces, Approval: approval})
	return string(b)
}

// THE ONE THAT CLOSES THE GAP. The capability is granted — a real
// signed pairing grant carrying "models" on an anchored box, so capsAllow
// passes and the op reaches its handler. In all three cases the user has NOT
// approved this pull, and in all three the download must not happen.
//
// The assertion is on the fake daemon's pull COUNTER, not on the exit code: an
// op can return an error after having already downloaded a model, and that
// distinction is the entire finding this test exists to pin.
func TestCapabilityGrantedIsNotEnoughToPull(t *testing.T) {
	priv := setupBox(t)
	f := newFakeDaemon(t, &fakeDaemon{})
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"models"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("could not install the models grant: %d %s", code, errOut)
	}
	// The capability really is granted: the ceiling lets model:pull through.
	if why := capsAllow(tMember, "model:pull"); why != "" {
		t.Fatalf("the models grant did not take, so this test proves nothing: %s", why)
	}

	root := t.TempDir()
	enrollFactor(t, root)

	// ── case 1: NO approval at all ────────────────────────────────────────
	_, errOut, code, _ := driveModelOp(t, tMember, "model:pull",
		[]string{pullArg("qwen3", "generate", 1<<20, "", "")}, root)
	if code != 126 {
		t.Fatalf("case absent: want a refusal (126), got %d %s", code, errOut)
	}
	if f.pulls != 0 {
		t.Fatalf("case absent: the download HAPPENED (%d pulls) — the capability alone was sufficient", f.pulls)
	}
	if !contains(errOut, "was not downloaded") {
		t.Fatalf("case absent: a refusal must say no model was downloaded: %s", errOut)
	}

	// ── case 2: the user REFUSED it on the machine ────────────────────────
	d := pullDetails("qwen3", "generate", 1<<20, "")
	purpose, err := purposeFromDetails(d)
	if err != nil {
		t.Fatal(err)
	}
	id, err := stepupNewRequest(root, purpose, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := stepupDenyRequest(root, id); err != nil {
		t.Fatal(err)
	}
	if r := requestsLoad(root)[id]; r.State != "denied" || r.Approval != "" {
		t.Fatalf("case refused: the request must be denied with no approval: %+v", r)
	}
	_, errOut, code, _ = driveModelOp(t, tMember, "model:pull",
		[]string{pullArg("qwen3", "generate", 1<<20, "", "")}, root)
	if code != 126 || f.pulls != 0 {
		t.Fatalf("case refused: want a refusal and no download, got %d with %d pulls: %s", code, f.pulls, errOut)
	}
	// And "no" cannot be worn down by asking again.
	if _, err := stepupNewRequest(root, purpose, d); err == nil {
		t.Fatal("case refused: a denied proposal must not be re-askable")
	}

	// ── case 3: the approval EXPIRED ──────────────────────────────────────
	// Approve for real, then age the approval past its TTL exactly as
	// approvalsLoad does (stepup.go:446-450) — it forgets anything older.
	root3 := t.TempDir()
	enrollFactor(t, root3)
	approval := proposeAndApprove(t, root3, "qwen3", "generate", 1<<20, "")
	m := approvalsLoad(root3)
	a := m[approval]
	a.At = time.Now().Add(-stepupApprovalTTL - time.Hour).UTC().Format(time.RFC3339)
	m[approval] = a
	if err := approvalsSave(root3, m); err != nil {
		t.Fatal(err)
	}
	if _, ok := approvalsLoad(root3)[approval]; ok {
		t.Fatal("case expired: the approval should have aged out")
	}
	_, errOut, code, _ = driveModelOp(t, tMember, "model:pull",
		[]string{pullArg("qwen3", "generate", 1<<20, "", approval)}, root3)
	if code != 126 || f.pulls != 0 {
		t.Fatalf("case expired: want a refusal and no download, got %d with %d pulls: %s", code, f.pulls, errOut)
	}

	// Control: with a LIVE approval the same op does download, so the three
	// refusals above are the gate working and not the lane being broken.
	root4 := t.TempDir()
	enrollFactor(t, root4)
	good := proposeAndApprove(t, root4, "qwen3", "generate", 1<<20, "")
	job := pullToCompletion(t, tMember, root4, "qwen3", "generate", 1<<20, good)
	if job["state"] != "done" || job["downloaded"] != true {
		t.Fatalf("control: an approved pull must go through: %v", job)
	}
	if f.pulls != 1 {
		t.Fatalf("control: exactly one download expected, got %d", f.pulls)
	}
}

// An approval authorizes THIS pull, never "a pull". Every field the user read is
// bound, so changing any of them leaves the approval not matching.
func TestApprovalBindsToTheProposalTheUserRead(t *testing.T) {
	f := newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "qwen3", "generate", 4<<20, "llama2")

	for _, c := range []struct {
		name string
		arg  string
	}{
		{"another model", pullArg("something-else", "generate", 4<<20, "llama2", approval)},
		{"another role", pullArg("qwen3", "embed", 4<<20, "llama2", approval)},
		{"a bigger ceiling", pullArg("qwen3", "generate", 40<<20, "llama2", approval)},
		{"a different replacement", pullArg("qwen3", "generate", 4<<20, "mistral", approval)},
	} {
		_, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull", []string{c.arg}, root)
		if code != 126 {
			t.Fatalf("%s: an approval for one proposal must not cover it: %d %s", c.name, code, errOut)
		}
		if f.pulls != 0 {
			t.Fatalf("%s: the download happened anyway", c.name)
		}
	}
	// The exact proposal still works. Polled to completion rather than left
	// running: a gate that walks away from a live download can perturb the next
	// one, and the async shape makes that possible where it was not before.
	out, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{pullArg("qwen3", "generate", 4<<20, "llama2", approval)}, root)
	if code != 0 {
		t.Fatalf("the approved proposal itself must pass: %d %s", code, errOut)
	}
	if job := pollUntilFinished(t, tAnchor, root, mustJSON(t, out)["id"].(string)); job["state"] != "done" {
		t.Fatalf("the approved proposal itself must finish: %v", job)
	}
}

// One yes funds one download.
func TestAnApprovalIsSingleUse(t *testing.T) {
	f := newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "qwen3", "generate", 1<<20, "")
	// The approval is burned when the DOWNLOAD lands, which is now off the frame
	// — so wait for the job, then ask again. The property is unchanged; only the
	// moment you can observe it moved. The companion case, two starts INSIDE one
	// download, is TestTwoStartsOnOneApprovalDownloadOnce.
	if job := pullToCompletion(t, tAnchor, root, "qwen3", "generate", 1<<20, approval); job["state"] != "done" {
		t.Fatalf("first pull: %v", job)
	}
	_, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{pullArg("qwen3", "generate", 1<<20, "", approval)}, root)
	if code != 126 {
		t.Fatalf("a spent approval must not fund a second download: %d %s", code, errOut)
	}
	if f.pulls != 1 {
		t.Fatalf("exactly one download expected, got %d", f.pulls)
	}
}

// A machine with no second factor cannot have models pulled onto it. This is
// where the lane is deliberately stricter than stepupGate, which treats an
// unenrolled box as ungated (stepup.go:524-529) — falling through to the caps
// grant would rebuild the hole the approval exists to close.
func TestUnenrolledMachineCannotHaveAModelPulled(t *testing.T) {
	f := newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir() // no enrollFactor
	if stepupEnrolled(root) {
		t.Fatal("this root must not be enrolled")
	}
	// stepupGate, the lane this one diverges from, would allow it.
	if err := stepupGate(root, "", "model_pull|x|embed|1|"); err != nil {
		t.Fatalf("precondition: stepupGate is a no-op unenrolled, got %v", err)
	}
	_, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{pullArg("qwen3", "generate", 1<<20, "", "")}, root)
	if code != 126 || f.pulls != 0 {
		t.Fatalf("an unenrolled machine must refuse: %d, %d pulls, %s", code, f.pulls, errOut)
	}
	if !contains(errOut, "stepup-enroll") {
		t.Fatalf("the refusal must say how to enroll: %s", errOut)
	}
}

// The size is a CEILING the download is held to, not a number the user had to
// take on trust. A model that announces more than was approved is stopped.
func TestADownloadBiggerThanApprovedIsStopped(t *testing.T) {
	newFakeDaemon(t, &fakeDaemon{pullBody: "{\"status\":\"pulling manifest\"}\n" +
		"{\"status\":\"pulling sha256:aaa\",\"digest\":\"sha256:aaa\",\"total\":900}\n" +
		"{\"status\":\"pulling sha256:bbb\",\"digest\":\"sha256:bbb\",\"total\":900}\n" +
		"{\"status\":\"success\"}\n"})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)
	// Approved for 1000 bytes; the two layers sum to 1800.
	approval := proposeAndApprove(t, root, "fat", "embed", 1000, "")
	job := pullToCompletion(t, tAnchor, root, "fat", "embed", 1000, approval)
	if job["state"] != "failed" {
		t.Fatalf("a download past the approved ceiling must not be reported as done: %v", job)
	}
	if why, _ := job["error"].(string); !contains(why, "larger than you approved") {
		t.Fatalf("the reason must name what happened: %v", job)
	}
	if a, ok := approvalsLoad(root)[approval]; !ok || a.Used {
		t.Fatalf("a stopped download must not spend the approval: %+v", a)
	}
	if placedByThisHost(root, "fat") {
		t.Fatal("a stopped download must not enter the ownership ledger")
	}
}

// The words the user reads are the words the box enforces — the same rule
// stepupNewRequest applies to every other kind (stepup.go:557-564).
func TestTheProposalTheUserReadsIsWhatIsEnforced(t *testing.T) {
	root := t.TempDir()
	enrollFactor(t, root)
	d := pullDetails("qwen3:8b", "generate", 4831838208, "llama2")
	purpose, err := purposeFromDetails(d)
	if err != nil {
		t.Fatal(err)
	}
	if purpose != "model_pull|qwen3:8b|generate|4831838208|llama2" {
		t.Fatalf("unexpected purpose: %s", purpose)
	}
	// A host naming one purpose while sending details for another is refused.
	if _, err := stepupNewRequest(root, "model_pull|qwen3:8b|generate|1|llama2", d); err == nil {
		t.Fatal("details that do not produce the purpose must be refused")
	}
	id, err := stepupNewRequest(root, purpose, d)
	if err != nil {
		t.Fatal(err)
	}
	desc := describeRequest(requestsLoad(root)[id])
	for _, want := range []string{"qwen3:8b", "4.5 GB", "text generation", "llama2", "DOWNLOAD"} {
		if !contains(desc, want) {
			t.Fatalf("the user must be able to read %q before approving:\n%s", want, desc)
		}
	}
	// A pull needs a ceiling at all: an unbounded ask cannot be proposed.
	if _, err := purposeForModelPull("m", "embed", 0, ""); err == nil {
		t.Fatal("a pull with no byte ceiling must not be proposable")
	}
}

// realTags reads the live daemon's model list, for the E2E test's own checks.
func realTags(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/api/tags")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
