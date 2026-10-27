//go:build !windows

package main

// Sharing ONE model off this machine with another host.
//
// The sentence under test throughout: a pairing approved with caps
// ["inference"] and models ["qwen4-embed"] can use qwen4-embed here and NOTHING
// else — not another model, not the PII sterilizer, and not the half of
// ollama's API that changes what is on the user's disk.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// grantTermsModels is grantTerms with the `models` field. Separate so every
// existing test keeps signing terms with NO models key at all — which is the
// case that has to keep meaning "unscoped".
func grantTermsModels(subject string, caps, models []string, expires string) map[string]any {
	t := grantTerms(subject, caps, expires)
	t["models"] = models
	return t
}

// syncGrant approves `subject` on the box with caps+models, through the real
// mgmt frame path as the anchor.
func syncGrant(t *testing.T, priv ed25519.PrivateKey, subject string, caps, models []string) {
	t.Helper()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	var terms, sig string
	if models == nil {
		terms, sig = signTerms(t, priv, grantTerms(subject, caps, future))
	} else {
		terms, sig = signTerms(t, priv, grantTermsModels(subject, caps, models, future))
	}
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant_sync: %d %s", code, errOut)
	}
}

// ── the scope itself ───────────────────────────────────────────────────────

func TestModelScopeReadsTheSignedGrant(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)

	// No models key: UNSCOPED. Every grant signed before the field existed is this case,
	// and it must keep meaning exactly what it meant.
	syncGrant(t, priv, tMember, []string{"inference"}, nil)
	if s := pairingModelScope(tMember); s.scoped {
		t.Fatal("a grant with no models list must be unscoped")
	}
	if !pairingModelScope(tMember).allowsModel("anything:latest") {
		t.Fatal("an unscoped pairing may use any model")
	}
	if !pairingModelScope(tMember).allowsPII() {
		t.Fatal("an unscoped pairing keeps the PII lane it had before")
	}

	// Named models: scoped, and the named one only.
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	s := pairingModelScope(tMember)
	if !s.scoped {
		t.Fatal("a grant naming models must be scoped")
	}
	if !s.allowsModel("qwen4-embed") {
		t.Fatal("the named model must be allowed")
	}
	if !s.allowsModel("qwen4-embed:latest") {
		t.Fatal("ollama's default tag is the same model")
	}
	if s.allowsModel("llama3:70b") {
		t.Fatal("a model outside the list must be refused")
	}
	if s.allowsModel("qwen4-embed:q8") {
		t.Fatal("a bare repo name must NOT open another tag — that is a silent widening")
	}
	if s.allowsPII() {
		t.Fatal("the sterilizer is not a model; a scoped grant must not include it unnamed")
	}

	// The reserved entry, and it is not a model.
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed", "pii"})
	s = pairingModelScope(tMember)
	if !s.allowsPII() {
		t.Fatal("'pii' in the list must include the sterilizer")
	}
	if s.allowsModel("pii") {
		t.Fatal("'pii' must name the lane, never a model")
	}

	// The anchor user is the machine's admin: never scoped.
	if pairingModelScope(tAnchor).scoped {
		t.Fatal("the anchor pairing must stay unscoped")
	}
}

// A pairing with no verifiable grant holds no `inference` at all (capsAllow
// refuses it), so the scope it gets never decides anything — but it must still
// be the NARROWEST answer, not the widest, in case a caller ever forgets the
// caps check.
func TestUngrantedPairingScopeFailsClosed(t *testing.T) {
	setupBox(t)
	writePairingState(t, tMember, pairingPending)
	s := pairingModelScope(tMember)
	if !s.scoped || s.allowsModel("anything") || s.allowsPII() {
		t.Fatalf("a pairing with no grant must get an empty scope, got %+v", s)
	}
	if !pairingModelScope("").scoped {
		t.Fatal("an anonymous lane must get an empty scope")
	}
}

// ── the policy, as a table ─────────────────────────────────────────────────

func TestFilterVerdictPolicy(t *testing.T) {
	scoped := scopeFromTerms([]string{"qwen4-embed"})
	unscoped := unscopedModels()
	embedBody := []byte(`{"model":"qwen4-embed","input":"hello"}`)
	otherBody := []byte(`{"model":"llama3:70b","input":"hello"}`)

	cases := []struct {
		name           string
		path           string
		body           []byte
		lane           inferenceLane
		scope          modelScope
		mayManage      bool
		wantRefused    bool
		wantMentioning string
	}{
		// The store-mutating half of ollama's API is the `models` family's, and
		// a raw splice served it to anything holding `inference`.
		{"pull refused without the models cap", "/api/pull", nil, laneOllama, unscoped, false, true, "models"},
		{"delete refused without the models cap", "/api/delete", nil, laneOllama, unscoped, false, true, "models"},
		{"create refused without the models cap", "/api/create", nil, laneOllama, unscoped, false, true, "models"},
		{"blob upload refused without the models cap", "/api/blobs/sha256:ab", nil, laneOllama, unscoped, false, true, "models"},
		{"pull allowed with the models cap", "/api/pull", nil, laneOllama, unscoped, true, false, ""},
		// An unscoped pairing is otherwise unchanged.
		{"unscoped generate passes", "/api/generate", otherBody, laneOllama, unscoped, false, false, ""},
		{"unscoped unknown path passes", "/api/whatever", nil, laneOllama, unscoped, false, false, ""},
		// Scoped: the model decides.
		{"scoped embed on the named model", "/api/embed", embedBody, laneOllama, scoped, false, false, ""},
		{"scoped embed on another model", "/api/embed", otherBody, laneOllama, scoped, false, true, "llama3:70b"},
		{"scoped chat on another model", "/v1/chat/completions", otherBody, laneLLM, scoped, false, true, "llama3:70b"},
		{"scoped request naming no model", "/api/embed", []byte(`{"input":"x"}`), laneOllama, scoped, false, true, "name the model"},
		{"scoped show by the older `name` key", "/api/show", []byte(`{"name":"llama3:70b"}`), laneOllama, scoped, false, true, "llama3:70b"},
		// Scoped reads that carry no model, and deny-by-default for the rest.
		{"scoped tags list is served (and filtered later)", "/api/tags", nil, laneOllama, scoped, false, false, ""},
		{"scoped version is harmless", "/api/version", nil, laneOllama, scoped, false, false, ""},
		{"scoped unknown path is refused", "/api/whatever", nil, laneOllama, scoped, false, true, "not served"},
		// The llm lane has no store-mutating surface of its own.
		{"llm lane does not police /api/pull", "/api/pull", nil, laneLLM, unscoped, false, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			why, code := filterVerdict(c.path, c.body, c.lane, c.scope, c.mayManage)
			if c.wantRefused != (why != "") {
				t.Fatalf("refused=%v, want %v (why=%q)", why != "", c.wantRefused, why)
			}
			if !c.wantRefused {
				return
			}
			if code != http.StatusForbidden {
				t.Fatalf("status %d, want 403", code)
			}
			if !strings.Contains(why, c.wantMentioning) {
				t.Fatalf("refusal %q does not mention %q — the caller cannot act on it", why, c.wantMentioning)
			}
		})
	}
}

// ── the filter on a real connection ────────────────────────────────────────

// fakeOllama answers the handful of routes the filter cares about and records
// what actually reached it — the point of most of these assertions is that a
// refused request never arrives at all. Its handler runs on the server's
// goroutines, beside the test's (and a pairing's beat probes it on its own),
// so the record is read through requests(), under the lock.
type fakeOllama struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

// requests is a copy of what reached the fake so far.
func (f *fakeOllama) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.seen)
}

func newFakeOllama(t *testing.T) *fakeOllama {
	t.Helper()
	f := &fakeOllama{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen4-embed:latest","size":42},` +
				`{"name":"llama3:70b","size":9}]}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"qwen4-embed"},{"id":"llama3:70b"}]}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// roundTrip drives one request through serveInferenceFiltered and returns the
// response. The filter is given one side of a pipe, exactly as the forward
// gives it an accepted tunnel connection — and it reads the pairing's scope out
// of the signed grant on disk, so every case here goes through the real
// terms -> verify -> scope path rather than a scope handed in by the test.
func roundTrip(t *testing.T, upstream string, lane inferenceLane, self string,
	method, path, body string) *http.Response {
	t.Helper()
	client, server := net.Pipe()
	go serveInferenceFiltered(server, upstream, lane, self)
	req, err := http.NewRequest(method, "http://filter"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	errc := make(chan error, 1)
	go func() { errc <- req.Write(client) }()
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write request: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close(); client.Close() })
	return resp
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFilteredForwardRefusesAnotherModelAndNeverForwardsIt(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	up := newFakeOllama(t)
	addr := up.srv.Listener.Addr().String()

	resp := roundTrip(t, addr, laneOllama, tMember, "POST", "/api/embed",
		`{"model":"llama3:70b","input":"x"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	if b := bodyOf(t, resp); !strings.Contains(b, "llama3:70b") || !strings.Contains(b, "qwen4-embed") {
		t.Fatalf("the refusal must name what was asked for and what is shared: %s", b)
	}
	if len(up.requests()) != 0 {
		t.Fatalf("a refused request reached the upstream: %v", up.requests())
	}

	resp = roundTrip(t, addr, laneOllama, tMember, "POST", "/api/embed",
		`{"model":"qwen4-embed","input":"x"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the shared model must work: %d", resp.StatusCode)
	}
	if len(up.requests()) != 1 || up.requests()[0] != "POST /api/embed" {
		t.Fatalf("the allowed request must reach the upstream once: %v", up.requests())
	}
}

func TestFilteredForwardRefusesTheStoreMutatingHalf(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, nil) // inference, NOT models
	up := newFakeOllama(t)
	addr := up.srv.Listener.Addr().String()

	if !inferenceFilterNeeded(tMember, laneOllama, pairingModelScope(tMember)) {
		t.Fatal("a pairing without the models cap must be filtered on the ollama lane — " +
			"a raw splice serves /api/pull and /api/delete to it")
	}
	for _, p := range []string{"/api/pull", "/api/delete", "/api/create", "/api/copy", "/api/push"} {
		resp := roundTrip(t, addr, laneOllama, tMember, "POST", p, `{"model":"anything"}`)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", p, resp.StatusCode)
		}
	}
	if len(up.requests()) != 0 {
		t.Fatalf("a store-mutating request reached ollama: %v", up.requests())
	}
	// ...and using a model is untouched by that refusal.
	if resp := roundTrip(t, addr, laneOllama, tMember, "POST", "/api/embed",
		`{"model":"anything"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("an unscoped pairing must still USE models: %d", resp.StatusCode)
	}
}

// On an ANCHORED box the ollama lane is filtered for every pairing — the
// anchor and a pairing holding `models` included — because changing which
// models are on a fleet machine is the gated model:pull / model:drop, and a
// raw splice that served /api/pull was a way around that (0.33.0). The llm
// lane has no store-mutating surface and stays a raw splice for an unscoped
// pairing; a LOCAL box keeps the raw ollama splice a `models` holder had.
func TestPairingWithModelsCapKeepsTheRawSplice(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference", "models"}, nil)
	if !inferenceFilterNeeded(tMember, laneOllama, pairingModelScope(tMember)) {
		t.Fatal("on an anchored box the ollama lane is filtered even for a models holder")
	}
	if !inferenceFilterNeeded(tAnchor, laneOllama, pairingModelScope(tAnchor)) {
		t.Fatal("on an anchored box the anchor's ollama lane is filtered too")
	}
	if inferenceFilterNeeded(tMember, laneLLM, unscopedModels()) {
		t.Fatal("the llm lane must not be filtered for an unscoped pairing")
	}
	// A local box: the pairing is the authorization, the raw splice stays.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writePairing(t, tAnchor)
	if inferenceFilterNeeded(tAnchor, laneOllama, pairingModelScope(tAnchor)) {
		t.Fatal("a local box keeps the unfiltered path")
	}
}

// And the filtered path refuses the store-mutating half for the ANCHOR on an
// anchored box: /api/pull through the forward is not a way around model:pull.
func TestAnchoredBoxRefusesModelChangesThroughTheForwardForTheAnchor(t *testing.T) {
	setupBox(t)
	up := newFakeOllama(t)
	addr := up.srv.Listener.Addr().String()
	for _, p := range []string{"/api/pull", "/api/delete", "/api/create"} {
		resp := roundTrip(t, addr, laneOllama, tAnchor, "POST", p, `{"model":"anything"}`)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s for the anchor: status %d, want 403", p, resp.StatusCode)
		}
	}
	if len(up.requests()) != 0 {
		t.Fatalf("a store-mutating request from the anchor reached ollama: %v", up.requests())
	}
	if resp := roundTrip(t, addr, laneOllama, tAnchor, "POST", "/api/embed", `{"model":"anything"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("the anchor still USES models: %d", resp.StatusCode)
	}
}

func TestFilteredForwardFiltersTheModelLists(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	up := newFakeOllama(t)
	addr := up.srv.Listener.Addr().String()

	resp := roundTrip(t, addr, laneOllama, tMember, "GET", "/api/tags", "")
	body := bodyOf(t, resp)
	if strings.Contains(body, "llama3:70b") {
		t.Fatalf("/api/tags offered a model this pairing cannot use: %s", body)
	}
	if !strings.Contains(body, "qwen4-embed") {
		t.Fatalf("/api/tags dropped the shared model: %s", body)
	}
	// Fields the filter has never heard of must survive — it re-marshals the
	// original entry rather than rebuilding it.
	if !strings.Contains(body, `"size":42`) {
		t.Fatalf("filtering must not strip fields off a kept entry: %s", body)
	}

	resp = roundTrip(t, addr, laneLLM, tMember, "GET", "/v1/models", "")
	body = bodyOf(t, resp)
	if strings.Contains(body, "llama3:70b") || !strings.Contains(body, "qwen4-embed") {
		t.Fatalf("/v1/models was not filtered to the scope: %s", body)
	}
	if !strings.Contains(body, `"object":"list"`) {
		t.Fatalf("the envelope around the list must survive: %s", body)
	}
}

// filterModelListJSON on its own: the shapes both dialects use, and a body it
// cannot parse (which must be an error, never a pass-through).
// A list the filter has to REWRITE must arrive in a form it can read. Go's own
// transport asks for gzip unprompted, so without dropping Accept-Encoding on
// those paths the filter would meet compressed bytes and answer 502 for a
// perfectly good model list.
func TestModelListRequestsDoNotAskForCompression(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	seen := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Accept-Encoding")
		_, _ = w.Write([]byte(`{"models":[{"name":"qwen4-embed:latest"}]}`))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	client, server := net.Pipe()
	go serveInferenceFiltered(server, addr, laneOllama, tMember)
	req, _ := http.NewRequest("GET", "http://filter/api/tags", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _ = req.Write(client) }()
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	defer client.Close()
	if got := <-seen; got != "" {
		t.Fatalf("the upstream was asked for %q on a path we rewrite", got)
	}
	if b := bodyOf(t, resp); !strings.Contains(b, "qwen4-embed") {
		t.Fatalf("the filtered list did not come back: %s", b)
	}
}

func TestFilterModelListJSON(t *testing.T) {
	scope := scopeFromTerms([]string{"qwen4-embed"})
	out, err := filterModelListJSON([]byte(`{"models":[{"model":"qwen4-embed:latest"},{"model":"x"}]}`),
		"/api/tags", scope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"x"`) {
		t.Fatalf("the `model` key is ollama's other spelling and must be read too: %s", out)
	}
	if _, err := filterModelListJSON([]byte("not json"), "/api/tags", scope); err == nil {
		t.Fatal("an unparsable list must be an error — passing it through unfiltered is the one thing this must not do")
	}
}

// ── PII: refused unless named ──────────────────────────────────────────────

func TestPIILaneRefusedWhenScopedWithoutIt(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)

	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	refuse := piiScopeRefuser(tMember)
	a, b := net.Pipe()
	defer b.Close()
	if !refuse(a) {
		t.Fatal("a pairing scoped to models must be refused the sterilizer")
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("the refused connection must be closed")
	}

	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed", "pii"})
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	if piiScopeRefuser(tMember)(c) {
		t.Fatal("naming 'pii' must open the sterilizer")
	}
	// Unscoped keeps what it had.
	syncGrant(t, priv, tMember, []string{"inference"}, nil)
	e, f := net.Pipe()
	defer e.Close()
	defer f.Close()
	if piiScopeRefuser(tMember)(e) {
		t.Fatal("an unscoped pairing must keep the PII lane")
	}
}

// ── the heartbeat tells the same story ─────────────────────────────────────

func TestHeartbeatAdvertisesOnlyTheSharedModel(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})

	// One server stands in for ollama, the OpenAI-compatible server and the
	// PII probe: each is asked a different path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/tags"):
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen4-embed:latest"},{"name":"llama3:70b"}]}`))
		case strings.HasPrefix(r.URL.Path, "/v1/models"):
			_, _ = w.Write([]byte(`{"data":[{"id":"qwen4-embed"},{"id":"llama3:70b"}]}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	t.Setenv("OLLAMA_ADDR", addr)
	t.Setenv("PRIVATAE_LLM_ADDR", addr)
	t.Setenv("PRIVATAE_PII_ADDR", addr)

	var hb struct {
		Caps      []string `json:"capabilities"`
		Models    []string `json:"models"`
		LLMModels []string `json:"llm_models"`
		PiiPort   *int     `json:"pii_port"`
	}
	body := buildHeartbeatBody(tMember, "box", "linux", "test", "pub", "fp", addr, "", false, nil, nil, nil)
	if err := json.Unmarshal([]byte(body), &hb); err != nil {
		t.Fatal(err)
	}
	for _, m := range append(append([]string{}, hb.Models...), hb.LLMModels...) {
		if strings.Contains(m, "llama3") {
			t.Fatalf("the beat offered a model this pairing cannot use: %v / %v", hb.Models, hb.LLMModels)
		}
	}
	if len(hb.Models) != 1 || !strings.HasPrefix(hb.Models[0], "qwen4-embed") {
		t.Fatalf("models = %v, want just the shared one", hb.Models)
	}
	if hb.PiiPort != nil {
		t.Fatalf("pii_port travelled for a scoped pairing that did not name 'pii': %v", *hb.PiiPort)
	}
	for _, c := range hb.Caps {
		if c == "pii" {
			t.Fatal("the beat advertised the sterilizer to a pairing scoped to models")
		}
	}

	// Nothing shared that this box actually serves: the lane is withheld
	// entirely rather than advertised and then refused at every call.
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"not-on-this-box"})
	body = buildHeartbeatBody(tMember, "box", "linux", "test", "pub", "fp", addr, "", false, nil, nil, nil)
	hb.Caps, hb.Models = nil, nil
	if err := json.Unmarshal([]byte(body), &hb); err != nil {
		t.Fatal(err)
	}
	for _, c := range hb.Caps {
		if c == "embed" || c == "llm-openai" {
			t.Fatalf("a scope with no model on this box must withhold the lane, got caps %v", hb.Caps)
		}
	}
}

// The unscoped beat is unchanged — the regression guard for every pairing that
// predates this field.
func TestHeartbeatUnchangedForAnUnscopedPairing(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/tags") {
			_, _ = w.Write([]byte(`{"models":[{"name":"a:latest"},{"name":"b:latest"}]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	t.Setenv("OLLAMA_ADDR", addr)
	var hb struct {
		Caps   []string `json:"capabilities"`
		Models []string `json:"models"`
	}
	if err := json.Unmarshal([]byte(buildHeartbeatBody(tMember, "box", "linux", "test", "pub", "fp", addr, "", false, nil, nil, nil)), &hb); err != nil {
		t.Fatal(err)
	}
	if len(hb.Models) != 2 {
		t.Fatalf("an unscoped pairing must see every model: %v", hb.Models)
	}
}

// ── belt: the request body is read, not streamed past the check ────────────

func TestOversizedBodyIsRefusedNotForwarded(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	up := newFakeOllama(t)
	big := bytes.Repeat([]byte("a"), 16)
	// A body whose declared length exceeds the cap would be refused; here the
	// point is only that the request is BUFFERED before the verdict, so the
	// model check reads the same bytes the upstream would have.
	resp := roundTrip(t, up.srv.Listener.Addr().String(), laneOllama, tMember, "POST", "/api/embed",
		`{"input":"`+string(big)+`"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a request naming no model must be refused: %d", resp.StatusCode)
	}
	if len(up.requests()) != 0 {
		t.Fatalf("it reached the upstream anyway: %v", up.requests())
	}
}

// ── what review turned up ──────────────────────────────────────────────────

// A pairing holding BOTH `models` and a model list could rename any model on
// the box INTO its scope: /api/copy {"source":"llama3:70b","destination":
// "qwen4-embed"}, then use it. A ceiling you can walk around by renaming is not
// a ceiling, so a scoped pairing does not manage models whatever else it holds.
func TestAScopedPairingCannotRenameAModelIntoItsScope(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference", "models"}, []string{"qwen4-embed"})
	up := newFakeOllama(t)
	addr := up.srv.Listener.Addr().String()

	if !inferenceFilterNeeded(tMember, laneOllama, pairingModelScope(tMember)) {
		t.Fatal("a scoped pairing must be filtered even when it also holds `models`")
	}
	for _, p := range []string{"/api/copy", "/api/create", "/api/pull", "/api/delete"} {
		resp := roundTrip(t, addr, laneOllama, tMember, "POST", p,
			`{"source":"llama3:70b","destination":"qwen4-embed"}`)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 — the scope must outrank the cap", p, resp.StatusCode)
		}
		if b := bodyOf(t, resp); !strings.Contains(b, "scoped") {
			t.Fatalf("%s: the refusal must say why: %s", p, b)
		}
	}
	if len(up.requests()) != 0 {
		t.Fatalf("a rename reached ollama: %v", up.requests())
	}
}

// The deny list is matched on a CLEANED path. `/api/pull/` and `//api/pull` are
// the same endpoint to the upstream's router but three different map keys, and
// an exact-match deny list that misses two of them has two holes.
func TestStorePathVariantsAreStillRefused(t *testing.T) {
	scope := unscopedModels()
	for _, p := range []string{"/api/pull/", "//api/pull", "/API/Pull", "/api/./pull", "/api/foo/../pull"} {
		req, err := http.NewRequest("POST", "http://x"+p, nil)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		got := requestPath(req)
		if why, _ := filterVerdict(got, nil, laneOllama, scope, false); why == "" {
			t.Fatalf("%q normalised to %q and was ALLOWED — the store deny list has a hole", p, got)
		}
	}
}

// A PRESENT list is a scope even when nothing in it survives trimming. The
// first cut set `scoped` only when it kept an entry, so a malformed ceiling
// failed open into no ceiling at all.
func TestAnAllBlankModelListIsStillAScope(t *testing.T) {
	s := scopeFromTerms([]string{"", "   "})
	if !s.scoped || s.allowsModel("anything") || s.allowsPII() {
		t.Fatalf("a present-but-blank list must be the narrowest scope, got %+v", s)
	}
	if unscopedModels().scoped {
		t.Fatal("an ABSENT list is still unscoped")
	}
}

// Two requests over ONE connection: keep-alive has to survive a refusal, and
// the scope is re-read each time, so a grant narrowed mid-connection takes
// effect on the very next request rather than when the peer happens to hang up.
func TestOneConnectionCarriesSeveralRequestsAndRereadsTheGrant(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed", "llama3:70b"})
	up := newFakeOllama(t)
	client, server := net.Pipe()
	defer client.Close()
	go serveInferenceFiltered(server, up.srv.Listener.Addr().String(), laneOllama, tMember)
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(client)

	send := func(model string) int {
		req, _ := http.NewRequest("POST", "http://filter/api/embed",
			strings.NewReader(`{"model":"`+model+`","input":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		errc := make(chan error, 1)
		go func() { errc <- req.Write(client) }()
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("write: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := send("qwen4-embed"); code != http.StatusOK {
		t.Fatalf("first request: %d", code)
	}
	if code := send("llama3:70b"); code != http.StatusOK {
		t.Fatalf("second request on the same connection: %d", code)
	}
	// The anchor narrows the grant while the connection is open and idle.
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	if code := send("llama3:70b"); code != http.StatusForbidden {
		t.Fatalf("a narrowed grant must bite on the NEXT request, got %d", code)
	}
	if code := send("qwen4-embed"); code != http.StatusOK {
		t.Fatalf("...and the model still shared must keep working: %d", code)
	}
}

// A streaming answer must stream, and a HEAD must come back without a body.
func TestStreamingAndHeadSurviveTheFilter(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		fl, _ := w.(http.Flusher)
		for i := 0; i < 3; i++ { // chunked, no Content-Length
			_, _ = w.Write([]byte(`{"response":"tok"}` + "\n"))
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	resp := roundTrip(t, addr, laneOllama, tMember, "POST", "/api/generate",
		`{"model":"qwen4-embed","prompt":"x"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if b := bodyOf(t, resp); strings.Count(b, "tok") != 3 {
		t.Fatalf("the streamed chunks did not all arrive: %q", b)
	}
	if resp.ContentLength != -1 {
		t.Fatalf("a streamed answer must stay unlengthed, got %d", resp.ContentLength)
	}
	head := roundTrip(t, addr, laneOllama, tMember, "HEAD", "/api/version", "")
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD: %d", head.StatusCode)
	}
	if b := bodyOf(t, head); b != "" {
		t.Fatalf("a HEAD answer must carry no body, got %q", b)
	}
}

// An Expect: 100-continue would make ReadResponse hand back the interim 1xx as
// though it were the answer, leaving the real one unread and desyncing the
// connection. The body is already buffered here, so the header is dropped.
func TestExpectContinueDoesNotDesyncTheConnection(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	gotExpect := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExpect <- r.Header.Get("Expect")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client, server := net.Pipe()
	defer client.Close()
	go serveInferenceFiltered(server, srv.Listener.Addr().String(), laneOllama, tMember)
	req, _ := http.NewRequest("POST", "http://filter/api/embed",
		strings.NewReader(`{"model":"qwen4-embed","input":"x"}`))
	req.Header.Set("Expect", "100-continue")
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	errc := make(chan error, 1)
	go func() { errc <- req.Write(client) }()
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer resp.Body.Close()
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d — an interim 1xx was forwarded as the answer", resp.StatusCode)
	}
	if e := <-gotExpect; e != "" {
		t.Fatalf("the upstream was asked for %q; the body was already in hand", e)
	}
}

// One approved peer must not be able to push unbounded bytes into this process
// by never terminating a header. http.ReadRequest has no cap of its own.
func TestAnEndlessHeaderIsCutOff(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	up := newFakeOllama(t)
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		serveInferenceFiltered(server, up.srv.Listener.Addr().String(), laneOllama, tMember)
		close(done)
	}()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	go func() {
		_, _ = client.Write([]byte("POST /api/embed HTTP/1.1\r\nHost: x\r\nX-Pad: "))
		junk := bytes.Repeat([]byte("a"), 64<<10)
		for i := 0; i < (maxFilteredHeaderBytes/len(junk))+8; i++ {
			if _, err := client.Write(junk); err != nil {
				return
			}
		}
	}()
	select {
	case <-done: // the filter gave up, which is the whole point
	case <-time.After(25 * time.Second):
		t.Fatal("an endless header was read without limit")
	}
	client.Close()
	if len(up.requests()) != 0 {
		t.Fatalf("it reached the upstream: %v", up.requests())
	}
}

// WHAT IS RUNNING ON SOMEONE'S COMPUTER IS NOT A SYSTEM RESOURCE.
//
// `agents` and `schedulers` rode every beat to every paired host regardless of
// its ceiling — scanAgents() takes no pairing identity — so a host approved for
// one model still received the machine's process list and its scheduled jobs.
// That made the sentence this whole feature exists for false.
func TestTheObservePlanesPayloadIsGatedOnObserve(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	t.Setenv("OLLAMA_ADDR", "127.0.0.1:1")
	// The tool-server reader looks in an empty home, not this machine's.
	oldHomes, oldSys := mcpHomesFn, mcpSystemFn
	t.Cleanup(func() { mcpHomesFn, mcpSystemFn = oldHomes, oldSys })
	empty := t.TempDir()
	mcpHomesFn = func() ([]mcpHome, bool) { return []mcpHome{{Dir: empty, ConfigDir: empty}}, true }
	mcpSystemFn = func() []mcpSource { return nil }

	beat := func(self string) map[string]any {
		t.Helper()
		var m map[string]any
		body := buildHeartbeatBody(self, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	hasCap := func(m map[string]any, want string) bool {
		list, _ := m["capabilities"].([]any)
		for _, c := range list {
			if s, _ := c.(string); s == want {
				return true
			}
		}
		return false
	}

	// A pairing scoped to one model holds no `observe`: the payload is ABSENT,
	// not empty — an empty list would read as "nothing is running here".
	syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
	m := beat(tMember)
	for _, k := range []string{"agents", "agent_scan", "agent_scan_ok", "schedulers", "scheduler_scan",
		// The store root names the operator's OS account; it is path material
		// like the rest and travels only with `observe`. The holes map travels
		// with it: absent must mean "not entitled", and only that.
		"machine_record_root", "machine_record_dropped",
		// The tool servers agent clients declare name files, servers and
		// command lines: observe material like the agent list.
		"tool_servers", "tool_server_scan"} {
		if _, present := m[k]; present {
			t.Fatalf("%q travelled to a pairing that cannot observe — that is the machine's "+
				"process list going to a host approved for one model", k)
		}
	}
	if hasCap(m, "agent-observe") || hasCap(m, "scheduler-observe") || hasCap(m, "tool-server-observe") {
		t.Fatalf("the observe capabilities were advertised to a pairing outside the family: %v",
			m["capabilities"])
	}

	// Granted `observe`, the same beat carries them again.
	syncGrant(t, priv, tMember, []string{"inference", "observe"}, []string{"qwen4-embed"})
	m = beat(tMember)
	if r, _ := m["machine_record_root"].(string); r == "" {
		t.Fatal("granted observe, the beat must say where the machine's record is")
	}
	if _, present := m["agents"]; !present {
		t.Fatal("a pairing granted observe must still get the agent list")
	}
	if _, present := m["schedulers"]; !present {
		t.Fatal("a pairing granted observe must still get the scheduler inventory")
	}
	if _, present := m["tool_servers"]; !present || !hasCap(m, "tool-server-observe") {
		t.Fatal("a pairing granted observe must get the declared tool servers and their capability")
	}

	// The anchor holds every family, and an unanchored box gates nothing — the
	// two cases that must not change, which between them cover nearly every install.
	if _, present := beat(tAnchor)["agents"]; !present {
		t.Fatal("the anchor pairing must keep the observe payload")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := modePath()
	if err := os.WriteFile(p, []byte(`{"mode":"local"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writePairing(t, tAnchor)
	if _, present := beat(tAnchor)["agents"]; !present {
		t.Fatal("a local bastion gates nothing and must be unchanged")
	}
}
