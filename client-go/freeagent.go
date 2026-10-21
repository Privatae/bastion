package main

// local agent lane — the box-side bridge between a DCN machine store and the
// bastion agent that indexes it (its own repository). The
// agent is the user's own program on the user's own
// machine: it walks, extracts, sterilizes and embeds the store LOCALLY and
// serves two governed ops over mutual TLS — `search` (sanitized chunks) and
// `read_range` by document id (a bounded slice of the SANITIZED text). This
// file forwards those two ops and nothing else.
//
// The trust model stacks, it does not replace:
//   1. the pod gate default-denies un-granted DCN ops;
//   2. THIS BOX re-verifies the synced signed grant on every op (dcn.go) —
//      `search` needs the 'search' mask, `read_range` the 'read' mask;
//   3. the local agent verifies the presented client certificate against its
//      CA root and serves the CN it names. The cert this box presents is the
//      owner's CA-issued pair (PRIVATAE_BASTION_AGENT_CERT/KEY), so a local agent
//      whose manifest names a different owner refuses this box.
//
// Opt-in, absent-when-unset, exactly like the PII lane: no PRIVATAE_BASTION_AGENT_ADDR
// means no probe, no capability, no handler reachable — an unpaired box is
// unaffected. Unlike the PII lane this is NOT a raw TCP splice: the local agent
// is mTLS-only and the identity must come from this box, so the bridge is an
// HTTPS client, not a port forward.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	freeagentTimeout      = 60 * time.Second // one search/read call
	freeagentProbeTimeout = 5 * time.Second  // the heartbeat probe: pii uses 3s; never stall a beat
	freeagentIdle         = 30 * time.Second // keep-alive idle cap on the ONE shared client
	freeagentMaxK         = 50
	freeagentMaxRangeChar = 64 * 1024
	freeagentMaxBody      = 4 << 20 // a search reply is tens of KB; cap the read regardless
)

// freeagentConfig is the operator's opt-in, read fresh per call so a changed
// env takes effect on the next op after a restart without a code path to
// cache it wrong.
type freeagentConfig struct {
	Addr string // host:port of the local agent serve endpoint (mesh or local)
	Cert string // PEM: the client identity this box presents
	Key  string
	CA   string // PEM: the root the local agent's server cert must chain to
}

func freeagentEnv() (freeagentConfig, bool) {
	c := freeagentConfig{
		Addr: strings.TrimSpace(os.Getenv("PRIVATAE_BASTION_AGENT_ADDR")),
		Cert: strings.TrimSpace(os.Getenv("PRIVATAE_BASTION_AGENT_CERT")),
		Key:  strings.TrimSpace(os.Getenv("PRIVATAE_BASTION_AGENT_KEY")),
		CA:   strings.TrimSpace(os.Getenv("PRIVATAE_BASTION_AGENT_CA")),
	}
	return c, c.Addr != ""
}

// One client per config, built once and reused: a Transport per call leaked
// one keep-alive connection per heartbeat on both ends (measured: 20 calls,
// 20 open server-side connections). The local agent's server is
// HTTP/1.1 keep-alive on a thread per connection, so idle connections are
// capped here (freeagentIdle) and the transport is shared.
var (
	faMu      sync.Mutex
	faClients = map[freeagentConfig]*http.Client{} // one per config: several managed stores + the env lane
)

func freeagentClient(c freeagentConfig) (*http.Client, error) {
	faMu.Lock()
	defer faMu.Unlock()
	if cl, ok := faClients[c]; ok {
		return cl, nil
	}
	cl, err := freeagentNewClient(c)
	if err != nil {
		return nil, err
	}
	faClients[c] = cl
	return cl, nil
}

// freeagentNewClient builds the mTLS client. Every one of the three files is
// required: the local agent refuses a connection with no client cert, and a
// client that skipped server verification would hand the owner's identity to
// whatever answered on that port.
func freeagentNewClient(c freeagentConfig) (*http.Client, error) {
	if c.Cert == "" || c.Key == "" || c.CA == "" {
		return nil, errors.New("PRIVATAE_BASTION_AGENT_CERT, _KEY and _CA are all required (mTLS lane)")
	}
	pair, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, fmt.Errorf("freeagent client identity: %w", err)
	}
	caPEM, err := os.ReadFile(c.CA)
	if err != nil {
		return nil, fmt.Errorf("freeagent CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("freeagent CA: no certificate in file")
	}
	tr := &http.Transport{IdleConnTimeout: freeagentIdle, MaxIdleConns: 2, TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
		// The endpoint is addressed by mesh IP; the server cert names the
		// machine, not necessarily that IP. Chain verification against the CA
		// stays on (RootCAs); hostname matching is what we relax, and only
		// that.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no server certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if c, err := x509.ParseCertificate(raw); err == nil {
					inter.AddCert(c)
				}
			}
			// ServerAuth only: ExtKeyUsageAny would let any CA member's
			// clientAuth device cert pose as the local agent.
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}}
	return &http.Client{Transport: tr, Timeout: freeagentTimeout}, nil
}

// freeagentCallTimeout is freeagentCall with a per-request deadline shorter
// than the client's (the probe must never stall a heartbeat).
func freeagentCallTimeout(c freeagentConfig, method, path string, body any, d time.Duration) (int, []byte, error) {
	return freeagentDo(c, method, path, body, d)
}

// freeagentCall does one JSON request. Returns the HTTP status and body; a
// transport failure is the error (the local agent is down or unreachable —
// the box maps that to the typed 'offline').
func freeagentCall(c freeagentConfig, method, path string, body any) (int, []byte, error) {
	return freeagentDo(c, method, path, body, freeagentTimeout)
}

func freeagentDo(c freeagentConfig, method, path string, body any, d time.Duration) (int, []byte, error) {
	cl, err := freeagentClient(c)
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, "https://"+c.Addr+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	resp, err := cl.Do(req.WithContext(ctx))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, freeagentMaxBody))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, out, nil
}

// faConfigFor is the client config for a store: the MANAGED instance the
// bastion runs for it (freeagent_managed.go) when there is one, else the
// operator's PRIVATAE_BASTION_AGENT_* env for a hand-run agent.
func faConfigFor(storeID int64) (freeagentConfig, bool) {
	if c, ok := faManagedConfig(storeID); ok {
		return c, true
	}
	return freeagentEnv()
}

// faAbsentReason says WHY there is no local agent to ask, in the words the
// host should relay: a missing Python is the member's one manual step.
func faAbsentReason(storeID int64) string {
	inst, ok := faSnapshot(storeID)
	if ok {
		switch inst.State {
		case "missing-python":
			return "local agent needs Python 3.8+ on this machine (install it; the bastion retries every 10 minutes)"
		case "installing":
			return "local agent is being installed on this machine; try again shortly"
		case "running":
			return "local agent is starting on this machine; try again shortly"
		default:
			return "local agent install failed on this machine: " + inst.Detail
		}
	}
	return "no local agent on this box (grant has no 'search' mask, and PRIVATAE_BASTION_AGENT_ADDR unset)"
}

// freeagentProbe reports (advertised, healthy) for the heartbeat. Advertised
// means the env is set (the lane exists on this box); healthy means the
// local agent answered /health over mTLS and says it is serving — a set env with
// a dead or refusing local agent is the distinct signal the host wants before
// routing a search here.
func freeagentProbe() (bool, bool) {
	c, on := freeagentEnv()
	if !on {
		return false, false
	}
	status, body, err := freeagentCallTimeout(c, http.MethodGet, "/health", nil, freeagentProbeTimeout)
	if err != nil || status != http.StatusOK {
		return true, false
	}
	var h struct {
		OK      bool `json:"ok"`
		Serving bool `json:"serving"`
	}
	if json.Unmarshal(body, &h) != nil {
		return true, false
	}
	return true, h.OK && h.Serving
}

// freeagentMap turns a local agent HTTP reply into the DCN typed envelope the
// host already understands (state ok|refused|gone|offline). The
// local agent's own 403 (grant/mask) and 503 (manifest not
// serving) are refusals with the reason it gave; 404 on read_range is gone.
func freeagentMap(op string, status int, body []byte, err error) (map[string]any, string, bool) {
	if err != nil {
		return map[string]any{"state": "offline", "detail": "freeagent: " + err.Error()}, "", true
	}
	var payload map[string]any
	malformed := json.Unmarshal(body, &payload) != nil || payload == nil
	if malformed {
		payload = map[string]any{}
	}
	reason, _ := payload["error"].(string)
	switch {
	case status == http.StatusOK && malformed:
		// a 200 that is not a JSON object is not a successful empty search
		return nil, "freeagent: malformed reply", false
	case status == http.StatusOK:
		payload["state"] = "ok"
		payload["sanitized"] = true
		return payload, "", true
	case status == http.StatusNotFound && op == "read_range":
		return map[string]any{"state": "gone", "detail": reason}, "", true
	case status == http.StatusForbidden || status == http.StatusServiceUnavailable:
		if reason == "" {
			reason = fmt.Sprintf("freeagent refused (HTTP %d)", status)
		}
		return nil, "freeagent: " + reason, false
	case status == http.StatusBadGateway:
		return map[string]any{"state": "offline", "detail": "freeagent: " + reason}, "", true
	default:
		if reason == "" {
			reason = fmt.Sprintf("freeagent HTTP %d", status)
		}
		return nil, "freeagent: " + reason, false
	}
}

// handleDcnSearch — op `dcn_search`: args = <store_id> <json {query, k}>. Gated
// by the synced grant with the 'search' mask, then forwarded to the
// local agent's /search. Hits are sanitized windows with document ids the host
// feeds back to read_range.
func handleDcnSearch(ws *websocket.Conn, dir string, args []string) {
	storeID, a, ok := dcnParseArgs(ws, args)
	if !ok {
		return
	}
	terms := dcnLoadGrantMask(ws, dir, "search", storeID, "", "search")
	if terms == nil {
		return
	}
	c, on := faConfigFor(storeID)
	if !on {
		dcnRefuse(ws, dir, "search", storeID, "", faAbsentReason(storeID))
		return
	}
	q := strings.TrimSpace(a.Query)
	if q == "" {
		sendMgmt(ws, 'R', []byte("search: query required\n"))
		sendMgmtExit(ws, 1)
		return
	}
	k := a.K
	if k <= 0 {
		k = 5
	}
	if k > freeagentMaxK {
		k = freeagentMaxK // clamp, as the schema says "max 50"; never a silent reset
	}
	status, body, err := freeagentCall(c, http.MethodPost, "/search",
		map[string]any{"query": q, "k": k})
	payload, why, ok := freeagentMap("search", status, body, err)
	if !ok {
		dcnRefuse(ws, dir, "search", storeID, "", why)
		return
	}
	payload["root"] = terms.Root
	dcnResult(ws, dir, "search", storeID, "", payload)
}

// handleDcnCatalog — op `dcn_catalog`: args = <store_id> <json {kind?, prefix?,
// offset?, limit?}>. The local agent's prepared MAP of the folder — directory
// cards (kind "dirs", default: sizes, types, newest change, keywords, entity
// counts per folder) or file cards (kind "files") — gated by the synced
// grant's 'read' mask, and only meaningful when the grant also carries
// 'index' (that is what makes the local agent build a catalog at all). Paged
// through to the local agent (prefix/offset/limit → total/next_offset), so a
// large store never hits the reply cap; a reply that does is refused with
// the truth, never reported as a corrupt local agent.
func handleDcnCatalog(ws *websocket.Conn, dir string, args []string) {
	storeID, a, ok := dcnParseArgs(ws, args)
	if !ok {
		return
	}
	kind := a.Kind
	if kind == "" {
		kind = "dirs"
	}
	if kind != "dirs" && kind != "files" {
		sendMgmt(ws, 'R', []byte("catalog: kind must be dirs or files\n"))
		sendMgmtExit(ws, 1)
		return
	}
	terms := dcnLoadGrantMask(ws, dir, "catalog", storeID, "kind:"+kind, "read")
	if terms == nil {
		return
	}
	if !dcnHasMask(terms, "index") {
		dcnRefuse(ws, dir, "catalog", storeID, "kind:"+kind,
			"catalog needs the 'index' mask on this grant (re-approve the store with index)")
		return
	}
	c, on := faConfigFor(storeID)
	if !on {
		dcnRefuse(ws, dir, "catalog", storeID, "kind:"+kind, faAbsentReason(storeID))
		return
	}
	path := "/catalog"
	if kind == "dirs" {
		path = "/catalog/dirs"
	}
	q := url.Values{}
	if a.Prefix != "" {
		q.Set("prefix", a.Prefix)
	}
	if a.Offset > 0 {
		q.Set("offset", strconv.Itoa(a.Offset))
	}
	if a.Limit > 0 {
		q.Set("limit", strconv.Itoa(a.Limit))
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	status, body, err := freeagentCall(c, http.MethodGet, path, nil)
	if err == nil && status == http.StatusOK && len(body) >= freeagentMaxBody {
		dcnRefuse(ws, dir, "catalog", storeID, "kind:"+kind,
			fmt.Sprintf("catalog page exceeds %d bytes; ask for fewer cards (limit) or a prefix", freeagentMaxBody))
		return
	}
	if err == nil && status == http.StatusNotFound {
		// not a permission outcome: the first sweep has not produced a catalog yet
		dcnResult(ws, dir, "catalog", storeID, "kind:"+kind, map[string]any{
			"state": "offline", "detail": "no catalog yet — the local agent's first sweep has not finished; try again later"})
		return
	}
	payload, why, ok := freeagentMap("catalog", status, body, err)
	if !ok {
		dcnRefuse(ws, dir, "catalog", storeID, "kind:"+kind, why)
		return
	}
	payload["root"] = terms.Root
	dcnResult(ws, dir, "catalog", storeID, "kind:"+kind, payload)
}

// handleDcnReadRangeDoc — the `doc` form of dcn_read_range: a bounded slice of
// the SANITIZED text for a document id the local agent produced. Gated by the
// 'read' mask like the path form. Returned as text (`content`), never bytes:
// the sanitized store is UTF-8 by construction.
func handleDcnReadRangeDoc(ws *websocket.Conn, dir string, storeID int64, a *dcnOpArgs) {
	terms := dcnLoadGrantMask(ws, dir, "read_range", storeID, "", "read")
	if terms == nil {
		return
	}
	c, on := faConfigFor(storeID)
	if !on {
		dcnRefuse(ws, dir, "read_range", storeID, "doc:"+a.Doc, faAbsentReason(storeID))
		return
	}
	start := a.StartByte
	if start < 0 {
		start = 0
	}
	end := a.EndByte
	if end <= start || end > start+freeagentMaxRangeChar {
		end = start + freeagentMaxRangeChar
	}
	status, body, err := freeagentCall(c, http.MethodPost, "/read_range",
		map[string]any{"doc": a.Doc, "start": start, "end": end})
	payload, why, ok := freeagentMap("read_range", status, body, err)
	if !ok {
		dcnRefuse(ws, dir, "read_range", storeID, "doc:"+a.Doc, why)
		return
	}
	if text, has := payload["text"]; has {
		payload["content"] = text
		delete(payload, "text")
	}
	payload["root"] = terms.Root
	dcnResult(ws, dir, "read_range", storeID, "doc:"+a.Doc, payload)
}
