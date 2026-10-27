package main

// The inference forwards, with an opinion.
//
// serveOllamaForward / serveLLMForward (run.go) are raw TCP splices: bytes in,
// bytes out, nothing looked at. That is the right shape for an UNCONSTRAINED
// pairing and it stays the path for one. It cannot be the shape for a pairing
// whose grant names models, for a reason that is worth stating plainly rather
// than discovering later: A MODEL NAME LIVES IN THE HTTP BODY. A TCP connection
// carries no model, so there is nothing an accept-time check could look at —
// per-model enforcement is only possible one layer in, where the request is.
//
// So when a scope is in force this file terminates HTTP on the forward, decides
// each request on its own, and proxies the rest untouched. Two things are
// enforced, and they are different:
//
//	1. THE MODEL. A request naming a model outside the grant is refused 403 and
//	   never reaches the upstream. A request on a model-bearing path that names
//	   NO model is also refused: "which model" is the whole question here, and a
//	   request that does not answer it cannot be checked (ollama would fall back
//	   to its own default, which is a model nobody approved).
//
//	2. THE BOX'S MODEL STORE. ollama's API on the very same port also serves
//	   /api/pull, /api/delete, /api/create, /api/copy and /api/push — downloading
//	   gigabytes onto the user's disk and deleting models off it. Those are the
//	   `models` caps family's own powers (anchor.go opFamily, modelswap.go), kept
//	   deliberately separate from `inference` so that "use what is loaded" and
//	   "decide what is on this machine" are different permissions. Through a raw
//	   splice that separation was not enforced at all: anything holding
//	   `inference` could reach them. A pairing that does not hold `models` is now
//	   refused those paths here, scoped or not.
//
// And one thing is filtered on the way BACK: the model LISTS (/api/tags,
// /api/ps, /v1/models). Same rule the heartbeat follows (agents.go) — offering
// a model that will then be refused is a lie about reachability, and the
// friend's host would put it in a picker.
//
// Everything outside the allow-list is refused when a scope is in force. Deny
// by default, like capsAllow: a path nobody has thought about is not a path
// this lane serves.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
)

const (
	// maxFilteredReqBody bounds a buffered request. An embedding call can carry
	// a real batch of text, so this is generous; past it the request is refused
	// rather than forwarded unread, because forwarding unread is how the model
	// check gets skipped on exactly the request that wanted to skip it.
	maxFilteredReqBody = 64 << 20
	// maxFilteredListBody bounds a response we must REWRITE (the model lists).
	// Only these are buffered; every other response streams through.
	maxFilteredListBody = 8 << 20
	// maxFilteredHeaderBytes bounds one request's line + headers.
	// http.ReadRequest has no cap of its own; ollama's server uses 1 MB.
	maxFilteredHeaderBytes = 1 << 20
	filteredIdleTimeout    = 10 * time.Minute
)

// inferenceLane is which forward is being served — they have different HTTP
// surfaces, and only ollama's carries the store-mutating half.
type inferenceLane int

const (
	laneOllama inferenceLane = iota
	laneLLM
)

func (l inferenceLane) String() string {
	if l == laneLLM {
		return "llm"
	}
	return "ollama"
}

// storeMutatingPaths are the ollama endpoints that CHANGE what is on this
// machine. Exact paths, matched after stripping the query. /api/blobs/ is a
// prefix: it takes a digest in the path and is how a create uploads layers.
var storeMutatingPaths = map[string]bool{
	"/api/pull": true, "/api/push": true, "/api/create": true,
	"/api/copy": true, "/api/delete": true,
}

// modelBearingPaths name a model in their JSON body. A scoped pairing's request
// to one of these is read and checked.
var modelBearingPaths = map[string]bool{
	"/api/embed": true, "/api/embeddings": true, "/api/generate": true,
	"/api/chat": true, "/api/show": true,
	"/v1/embeddings": true, "/v1/chat/completions": true, "/v1/completions": true,
}

// modelListPaths return a list of models and are rewritten on the way back.
var modelListPaths = map[string]bool{
	"/api/tags": true, "/api/ps": true, "/v1/models": true,
}

// harmlessReadPaths are the remaining reads a scoped pairing may make: they
// name no model and change nothing.
var harmlessReadPaths = map[string]bool{
	"/api/version": true, "/health": true, "/": true,
}

// inferenceFilterNeeded decides whether this pairing's connections go through
// the filter or stay a raw splice. Unscoped AND allowed to manage models means
// there is nothing this file could enforce, so such a pairing (every anchor,
// and any member granted both) keeps the byte-for-byte path it had before.
func inferenceFilterNeeded(self string, lane inferenceLane, scope modelScope) bool {
	if scope.scoped {
		return true
	}
	// The store-mutating half only exists on ollama's port. On an ANCHORED box
	// it is filtered for every pairing, the anchor included: changing which
	// models are on a fleet machine is model:pull / model:drop on the
	// management lane, where it spends the person's approval (writes.go) — a
	// raw splice that let the anchor POST /api/pull was a way around that.
	return lane == laneOllama && (currentAnchor() != nil || capsAllow(self, modelGateOp) != "")
}

// proxyInference serves ONE accepted connection on an inference forward. The
// scope is read here, per connection, for the same reason inferenceRefuser
// re-checks caps per connection (run.go): a grant is re-signed while the daemon
// runs, and a narrowed re-approval has to take effect without a restart.
//
// With nothing to enforce it is the original raw splice, byte for byte.
func proxyInference(in net.Conn, upstream string, lane inferenceLane, self string) {
	proxyInferenceVia(in, dialUpstream(upstream), lane, self, spliceConnVia)
}

// upstreamDial opens the connection to the service behind a forward.
type upstreamDial func() (net.Conn, error)

// dialUpstream is the forwards' dial: TCP to the address, 5 s.
func dialUpstream(upstream string) upstreamDial {
	return func() (net.Conn, error) { return net.DialTimeout("tcp", upstream, 5*time.Second) }
}

// proxyInferenceVia is proxyInference with the dial, and the pass-through for
// a connection with nothing to enforce, in the caller's hands. The serve lane
// (servelane.go) uses it so its connections take the same decision and the
// same filter as the tunnel's, while the dial goes to the address it vetted
// and is watched by its idle bound.
func proxyInferenceVia(in net.Conn, dial upstreamDial, lane inferenceLane, self string, pass func(net.Conn, upstreamDial)) {
	if inferenceFilterNeeded(self, lane, pairingModelScope(self)) {
		serveInferenceFilteredVia(in, dial, lane, self)
		return
	}
	pass(in, dial)
}

// spliceConn is what the forwards did before this file existed, unchanged and
// in one place now that three call sites share it.
func spliceConn(in net.Conn, upstream string) {
	spliceConnVia(in, dialUpstream(upstream))
}

func spliceConnVia(in net.Conn, dial upstreamDial) {
	defer in.Close()
	out, err := dial()
	if err != nil {
		return
	}
	defer out.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, in); done <- struct{}{} }()
	go func() { _, _ = io.Copy(in, out); done <- struct{}{} }()
	<-done
}

// serveInferenceFiltered proxies one accepted connection with this pairing's
// scope applied. It owns `in` and closes it. Errors are silent by design: this
// is a data-plane proxy and a peer that hangs up mid-request is normal.
//
// It takes no scope ARGUMENT on purpose: the scope is read from the signed
// grant on every request below, so there is nowhere for a caller — including a
// test — to hand it one the grant does not say.
func serveInferenceFiltered(in net.Conn, upstream string, lane inferenceLane, self string) {
	serveInferenceFilteredVia(in, dialUpstream(upstream), lane, self)
}

func serveInferenceFilteredVia(in net.Conn, dial upstreamDial, lane inferenceLane, self string) {
	defer in.Close()
	out, err := dial()
	if err != nil {
		writeFilterError(in, nil, http.StatusBadGateway, "the service behind this lane is not answering")
		return
	}
	defer out.Close()
	capped := &capReader{r: in, n: -1}
	br := bufio.NewReader(capped)
	bo := bufio.NewReader(out)
	for {
		// The deadline covers the HEADERS AND THE BODY, not just the first line:
		// a peer that sends a request line and then stops would otherwise park
		// this goroutine on the body read for as long as the process lives.
		_ = in.SetReadDeadline(time.Now().Add(filteredIdleTimeout))
		// The request line and headers get their own allowance, because
		// http.ReadRequest has none: textproto keeps growing a line buffer, so
		// one approved peer sending a header it never terminates could push
		// gigabytes into this process. ollama's own server caps this at 1 MB;
		// the body is bounded separately, below, so the allowance is lifted
		// once the headers are parsed.
		capped.allow(maxFilteredHeaderBytes)
		req, err := http.ReadRequest(br)
		capped.allow(-1)
		if err != nil {
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, maxFilteredReqBody+1))
		req.Body.Close()
		_ = in.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		if len(body) > maxFilteredReqBody {
			writeFilterError(in, req, http.StatusRequestEntityTooLarge,
				"request body too large for a scoped inference lane")
			return
		}
		// Read the grant AFTER the request arrives, never before waiting for
		// it. A pairing grant is re-signed while the daemon runs — a narrowed
		// re-approval arrives as a grant_sync that restarts nothing — and a
		// keep-alive connection under continuous use never reaches its idle
		// deadline, so a scope read at accept could outlive the approval it
		// came from for as long as the peer keeps talking. Reading at the TOP
		// of the loop has the same bug one request smaller: the value is taken
		// before the blocking read, so it is always the scope as of the
		// PREVIOUS request. Same reasoning as inferenceRefuser re-checking caps
		// per connection (run.go), one level finer, and it costs a file read on
		// a lane that carries a handful of requests a minute.
		scope := pairingModelScope(self)
		// Never through the forward on an anchored box — see inferenceFilterNeeded.
		mayManageModels := currentAnchor() == nil && capsAllow(self, modelGateOp) == ""
		path := requestPath(req)
		if why, code := filterVerdict(path, body, lane, scope, mayManageModels); why != "" {
			if !writeFilterError(in, req, code, why) {
				return
			}
			continue
		}
		// Re-frame with the buffered body: Content-Length, never chunked, so
		// the upstream reads exactly what was checked. A body of zero bytes
		// becomes a NIL body rather than an empty one — Go's outgoingLength
		// returns -1 for a non-nil empty Body, which sends the request chunked,
		// and a chunked GET is a thing some servers simply refuse.
		if len(body) == 0 {
			req.Body = nil
		} else {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		req.ContentLength = int64(len(body))
		req.TransferEncoding = nil
		req.URL.Scheme, req.URL.Host = "", ""
		// The body is already here, in full, so a 100-continue handshake can
		// only cost a round trip — and it would cost more than that: ReadResponse
		// hands back the interim 1xx as though it were the answer (skipping them
		// is Transport's job, not its own), so the real response would be left
		// unread in the buffer and the next request would read it instead.
		req.Header.Del("Expect")
		// A list we are about to REWRITE must come back in a form we can read.
		// The caller is an ordinary HTTP client and Go's transport adds
		// Accept-Encoding: gzip by itself, so without this the filter would meet
		// a gzipped body, fail to parse it, and answer 502 for a model list that
		// was perfectly fine. Dropped only for the paths that get rewritten —
		// every other response streams through with its encoding untouched.
		if scope.scoped && modelListPaths[path] {
			req.Header.Del("Accept-Encoding")
		}
		if err := req.Write(out); err != nil {
			return
		}
		resp, err := http.ReadResponse(bo, req)
		// Belt for the same 1xx problem, in case an upstream sends one
		// unprompted: skip interim responses rather than forwarding one as the
		// answer and desyncing the connection. Bounded, so a server stuck
		// emitting them cannot hold this goroutine.
		for i := 0; err == nil && resp.StatusCode/100 == 1 && i < 4; i++ {
			resp.Body.Close()
			resp, err = http.ReadResponse(bo, req)
		}
		if err != nil {
			writeFilterError(in, req, http.StatusBadGateway, "the service behind this lane closed the connection")
			return
		}
		if scope.scoped && modelListPaths[path] && resp.StatusCode == http.StatusOK {
			if !writeFilteredList(in, resp, path, scope) {
				return
			}
		} else if err := resp.Write(in); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		if resp.Close || req.Close {
			return
		}
	}
}

// capReader bounds how much one phase of a request may read. `allow(n)` sets
// the allowance for what comes next; allow(-1) lifts it. It wraps the CONN, not
// the bufio above it, so the buffering that makes keep-alive work is untouched.
type capReader struct {
	r net.Conn
	n int64 // remaining; <0 = unlimited
}

func (c *capReader) allow(n int64) { c.n = n }

func (c *capReader) Read(p []byte) (int, error) {
	if c.n == 0 {
		return 0, fmt.Errorf("request headers exceeded %d bytes", maxFilteredHeaderBytes)
	}
	if c.n > 0 && int64(len(p)) > c.n {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	if c.n > 0 {
		c.n -= int64(n)
	}
	return n, err
}

// requestPath is the path the POLICY is decided on: lowercased, cleaned, and
// without a trailing slash. Cleaning matters — `/api/pull/` and `//api/pull`
// are the same endpoint to a Go/Gin router but three different map keys, and an
// exact-match deny list that misses two of them is a deny list with two holes.
// Query is dropped: nothing here is decided on it.
func requestPath(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	p := path.Clean("/" + strings.TrimPrefix(strings.ToLower(req.URL.Path), "/"))
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// filterVerdict is the whole policy, pure and testable: "" to forward, or the
// refusal sentence and the status to answer with.
func filterVerdict(path string, body []byte, lane inferenceLane, scope modelScope, mayManageModels bool) (string, int) {
	if lane == laneOllama && (storeMutatingPaths[path] || strings.HasPrefix(path, "/api/blobs/")) {
		// SCOPE BEATS THE CAP HERE, and the order is the whole point. A pairing
		// holding both `models` and a model list could otherwise POST
		// /api/copy {"source":"llama3:70b","destination":"qwen4-embed"} and use
		// the result — renaming any model on the box INTO its scope. A ceiling
		// you can walk around by renaming is not a ceiling, so a scoped pairing
		// does not manage models, whatever else it was granted.
		if scope.scoped {
			return "refused: " + path + " changes which models are on this machine, and this " +
				"pairing is scoped to named models (" + scope.describe() + ") — which a rename " +
				"would walk straight around.", http.StatusForbidden
		}
		if mayManageModels {
			return "", 0
		}
		return "refused: " + path + " changes which models are on this machine. That is the " +
			"'models' capability, which this pairing was not granted — 'inference' is the right " +
			"to USE what is already loaded.", http.StatusForbidden
	}
	if !scope.scoped {
		return "", 0
	}
	if modelListPaths[path] || harmlessReadPaths[path] {
		return "", 0
	}
	if modelBearingPaths[path] {
		name := modelNameFromBody(body)
		if name == "" {
			return "refused: this pairing may use " + scope.describe() + " on this machine, so every " +
				"request has to name the model it wants; this one names none.", http.StatusForbidden
		}
		if !scope.allowsModel(name) {
			return "refused: model '" + name + "' is not shared with this host. This pairing may use " +
				scope.describe() + " on this machine.", http.StatusForbidden
		}
		return "", 0
	}
	return "refused: " + path + " is not served to a pairing scoped to named models (" +
		scope.describe() + ").", http.StatusForbidden
}

// modelNameFromBody pulls the model out of a request body. `model` is what both
// dialects use today; `name` is ollama's older spelling, still accepted by
// /api/show and /api/delete, so a check that only read `model` would wave
// through a request that named its model the old way.
func modelNameFromBody(body []byte) string {
	var b struct {
		Model string `json:"model"`
		Name  string `json:"name"`
	}
	if json.Unmarshal(body, &b) != nil {
		return ""
	}
	if s := strings.TrimSpace(b.Model); s != "" {
		return s
	}
	return strings.TrimSpace(b.Name)
}

// writeFilteredList rewrites a model-list response to the models this scope
// allows. A list too large to buffer is answered 502 rather than passed
// through: an unfiltered list is the one thing this function exists to prevent.
// Returns false when the connection should be dropped.
func writeFilteredList(in net.Conn, resp *http.Response, path string, scope modelScope) bool {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFilteredListBody+1))
	if err != nil || len(raw) > maxFilteredListBody {
		writeFilterError(in, nil, http.StatusBadGateway, "model list too large to filter")
		return false
	}
	out, err := filterModelListJSON(raw, path, scope)
	if err != nil {
		writeFilterError(in, nil, http.StatusBadGateway, "model list could not be filtered")
		return false
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.TransferEncoding = nil
	resp.Header.Set("Content-Length", fmt.Sprint(len(out)))
	resp.Header.Del("Content-Encoding") // we rewrote the bytes; any encoding is now wrong
	return resp.Write(in) == nil
}

// filterModelListJSON keeps every field of every entry the scope allows and
// drops the rest. Deliberately re-marshals the ORIGINAL entries rather than
// rebuilding them, so fields this code has never heard of (sizes, digests,
// capabilities, quantization) survive untouched.
func filterModelListJSON(raw []byte, path string, scope modelScope) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	listKey, nameKeys := "models", []string{"name", "model"}
	if path == "/v1/models" {
		listKey, nameKeys = "data", []string{"id"}
	}
	rawList, ok := doc[listKey]
	if !ok {
		return raw, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(rawList, &entries); err != nil {
		return nil, err
	}
	kept := []json.RawMessage{}
	for _, e := range entries {
		var fields map[string]any
		if json.Unmarshal(e, &fields) != nil {
			continue // an entry we cannot read is an entry we cannot vouch for
		}
		name := ""
		for _, k := range nameKeys {
			if s, _ := fields[k].(string); strings.TrimSpace(s) != "" {
				name = s
				break
			}
		}
		if scope.allowsModel(name) {
			kept = append(kept, e)
		}
	}
	nl, err := json.Marshal(kept)
	if err != nil {
		return nil, err
	}
	doc[listKey] = nl
	return json.Marshal(doc)
}

// writeFilterError answers one request with a refusal the caller can read. JSON
// with an `error` string: both dialects surface that field, so the sentence
// reaches a person instead of becoming "unexpected status 403". Returns false
// when the connection cannot continue.
func writeFilterError(in net.Conn, req *http.Request, code int, why string) bool {
	body, _ := json.Marshal(map[string]string{"error": why})
	resp := &http.Response{
		StatusCode:    code,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	return resp.Write(in) == nil
}
