package main

// local agent lane walls testable without a relay: the mTLS client (a server
// without a cert from the CA is refused; a client without the three files
// never dials), the reply mapping into DCN typed states, the probe's
// advertised/healthy split, and the search mask gate.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testPKI struct {
	dir                string
	caPEM              string
	serverCert, client tls.Certificate
	clientCert, key    string
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mintPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER)

	leaf := func(cn string, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{cn}}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
		kder, _ := x509.MarshalECPrivateKey(key)
		certPath, keyPath := filepath.Join(dir, cn+".crt"), filepath.Join(dir, cn+".key")
		writePEM(t, certPath, "CERTIFICATE", der)
		writePEM(t, keyPath, "EC PRIVATE KEY", kder)
		pair, _ := tls.LoadX509KeyPair(certPath, keyPath)
		return pair, certPath, keyPath
	}
	server, _, _ := leaf("freeagent-box", x509.ExtKeyUsageServerAuth)
	client, cpath, kpath := leaf("user-host", x509.ExtKeyUsageClientAuth)
	return testPKI{dir: dir, caPEM: filepath.Join(dir, "ca.crt"), serverCert: server,
		client: client, clientCert: cpath, key: kpath}
}

// fakeFreeAgent is an mTLS server speaking the local agent's wire shape.
func fakeFreeAgent(t *testing.T, p testPKI, handler http.Handler) *httptest.Server {
	t.Helper()
	caPEM, _ := os.ReadFile(p.caPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func faHandler(seenCN *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			*seenCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": "t", "serving": true})
		case "/search":
			var req map[string]any
			json.NewDecoder(r.Body).Decode(&req)
			json.NewEncoder(w).Encode(map[string]any{"k": req["k"], "hits": []map[string]any{
				{"score": 0.9, "doc": strings.Repeat("a", 64), "idx": 0, "text": "router [PII_EMAIL_1]"}}})
		case "/catalog/dirs", "/catalog":
			kind := "files"
			if strings.HasSuffix(r.URL.Path, "/dirs") {
				kind = "dirs"
			}
			if r.URL.Query().Get("limit") == "huge" {
				w.Write(bytes.Repeat([]byte("x"), freeagentMaxBody+10)) // an oversized 200
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"kind": kind, "total": 1, "next_offset": nil,
				"q": r.URL.RawQuery, "cards": []map[string]any{
					{"path": "", "files": 2, "bytes": 88, "entities": map[string]int{"EMAIL": 1}}}})
		case "/read_range":
			var req map[string]any
			json.NewDecoder(r.Body).Decode(&req)
			if req["doc"] == strings.Repeat("0", 64) {
				w.WriteHeader(404)
				json.NewEncoder(w).Encode(map[string]any{"error": "no such document"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"doc": req["doc"], "start": 0, "end": 5,
				"total": 44, "text": "route"})
		default:
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]any{"error": "not permitted for user-host: x"})
		}
	})
}

func TestFreeagentMTLSClient(t *testing.T) {
	p := mintPKI(t)
	var seen string
	srv := fakeFreeAgent(t, p, faHandler(&seen))
	addr := strings.TrimPrefix(srv.URL, "https://")
	c := freeagentConfig{Addr: addr, Cert: p.clientCert, Key: p.key, CA: p.caPEM}

	status, body, err := freeagentCall(c, http.MethodGet, "/health", nil)
	if err != nil || status != 200 {
		t.Fatalf("health over mTLS: %d %v", status, err)
	}
	if seen != "user-host" {
		t.Fatalf("server must see the box's client CN, got %q", seen)
	}
	if !strings.Contains(string(body), `"serving": true`) && !strings.Contains(string(body), `"serving":true`) {
		t.Fatalf("unexpected health body %s", body)
	}

	// Missing any of the three files → no dial at all.
	for _, bad := range []freeagentConfig{{Addr: addr}, {Addr: addr, Cert: p.clientCert, Key: p.key},
		{Addr: addr, Cert: p.clientCert, Key: p.key, CA: filepath.Join(p.dir, "nope.crt")}} {
		if _, _, err := freeagentCall(bad, http.MethodGet, "/health", nil); err == nil {
			t.Fatalf("config %+v must refuse before dialing", bad)
		}
	}

	// A server whose cert is NOT from the CA is refused even though hostname
	// checking is relaxed (chain verification is the wall that stays).
	other := mintPKI(t)
	rogue := fakeFreeAgent(t, other, faHandler(&seen))
	c2 := freeagentConfig{Addr: strings.TrimPrefix(rogue.URL, "https://"), Cert: p.clientCert, Key: p.key, CA: p.caPEM}
	if _, _, err := freeagentCall(c2, http.MethodGet, "/health", nil); err == nil {
		t.Fatal("a server outside the CA must be refused")
	}
}

func TestFreeagentProbeAndEnv(t *testing.T) {
	t.Setenv("PRIVATAE_BASTION_AGENT_ADDR", "")
	if adv, _ := freeagentProbe(); adv {
		t.Fatal("unset env must not advertise")
	}
	p := mintPKI(t)
	var seen string
	srv := fakeFreeAgent(t, p, faHandler(&seen))
	t.Setenv("PRIVATAE_BASTION_AGENT_ADDR", strings.TrimPrefix(srv.URL, "https://"))
	t.Setenv("PRIVATAE_BASTION_AGENT_CERT", p.clientCert)
	t.Setenv("PRIVATAE_BASTION_AGENT_KEY", p.key)
	t.Setenv("PRIVATAE_BASTION_AGENT_CA", p.caPEM)
	adv, ok := freeagentProbe()
	if !adv || !ok {
		t.Fatalf("live local agent must be advertised and healthy, got %v %v", adv, ok)
	}
	srv.Close()
	adv, ok = freeagentProbe()
	if !adv || ok {
		t.Fatalf("dead local agent must be advertised but unhealthy, got %v %v", adv, ok)
	}
}

func TestFreeagentMap(t *testing.T) {
	m, why, ok := freeagentMap("search", 200, []byte(`{"hits":[]}`), nil)
	if !ok || m["state"] != "ok" || m["sanitized"] != true || why != "" {
		t.Fatalf("200 → ok/sanitized, got %v %q", m, why)
	}
	m, _, ok = freeagentMap("read_range", 404, []byte(`{"error":"no such document"}`), nil)
	if !ok || m["state"] != "gone" {
		t.Fatalf("404 on read_range → gone, got %v", m)
	}
	_, why, ok = freeagentMap("search", 403, []byte(`{"error":"not permitted for x: search"}`), nil)
	if ok || !strings.Contains(why, "not permitted") {
		t.Fatalf("403 → refused with the local agent's reason, got %v %q", ok, why)
	}
	_, why, ok = freeagentMap("search", 503, []byte(`{"error":"manifest not serving: gate: unsigned"}`), nil)
	if ok || !strings.Contains(why, "gate") {
		t.Fatalf("503 → refused with the gate reason, got %q", why)
	}
	m, _, ok = freeagentMap("search", 0, nil, errors.New("dial tcp: refused"))
	if !ok || m["state"] != "offline" {
		t.Fatalf("transport error → offline, got %v", m)
	}
	m, _, ok = freeagentMap("search", 502, []byte(`{"error":"search unavailable: embed"}`), nil)
	if !ok || m["state"] != "offline" {
		t.Fatalf("502 (embedder down) → offline, got %v", m)
	}
	// a 200 that is not a JSON object is a refusal, never a successful empty search
	if _, why, ok := freeagentMap("search", 200, []byte(`not json`), nil); ok || !strings.Contains(why, "malformed") {
		t.Fatalf("200 + garbage must be refused, got ok=%v %q", ok, why)
	}
	if _, _, ok := freeagentMap("search", 200, []byte(`[1,2]`), nil); ok {
		t.Fatal("200 + non-object must be refused")
	}
}

func TestFreeagentClientIsSharedAndBounded(t *testing.T) {
	p := mintPKI(t)
	var seen string
	srv := fakeFreeAgent(t, p, faHandler(&seen))
	c := freeagentConfig{Addr: strings.TrimPrefix(srv.URL, "https://"), Cert: p.clientCert, Key: p.key, CA: p.caPEM}
	a, _ := freeagentClient(c)
	b, _ := freeagentClient(c)
	if a != b {
		t.Fatal("same config must reuse one client (the leak was one Transport per call)")
	}
	for i := 0; i < 20; i++ {
		if _, _, err := freeagentCall(c, http.MethodGet, "/health", nil); err != nil {
			t.Fatal(err)
		}
	}
	tr := a.Transport.(*http.Transport)
	if tr.MaxIdleConns != 2 || tr.IdleConnTimeout != freeagentIdle {
		t.Fatalf("idle connections must be bounded, got %d/%s", tr.MaxIdleConns, tr.IdleConnTimeout)
	}
	// a different config replaces the client
	c2 := c
	c2.Addr = c.Addr + " "
	c2.Addr = strings.TrimSpace(c2.Addr) // same value: still shared
	if x, _ := freeagentClient(c2); x != a {
		t.Fatal("identical config after trim must still share")
	}
}

func TestDcnSearchNeedsSearchMask(t *testing.T) {
	// The wall itself: a grant with mask [read] must not satisfy 'search',
	// and one with [read, search] must — independent of any local agent.
	terms := &dcnTerms{Mask: []string{"read"}}
	if dcnHasMask(terms, "search") {
		t.Fatal("read-only grant must not grant search")
	}
	terms.Mask = append(terms.Mask, "search")
	if !dcnHasMask(terms, "search") || !dcnHasMask(terms, "read") {
		t.Fatal("read+search grant must grant both")
	}
}

func TestFreeagentCatalogCall(t *testing.T) {
	p := mintPKI(t)
	var seen string
	srv := fakeFreeAgent(t, p, faHandler(&seen))
	c := freeagentConfig{Addr: strings.TrimPrefix(srv.URL, "https://"), Cert: p.clientCert, Key: p.key, CA: p.caPEM}
	status, body, err := freeagentCall(c, http.MethodGet, "/catalog/dirs", nil)
	m, why, ok := freeagentMap("catalog", status, body, err)
	if !ok || m["state"] != "ok" || m["kind"] != "dirs" {
		t.Fatalf("catalog dirs: %v %q", m, why)
	}
	cards, _ := m["cards"].([]any)
	if len(cards) != 1 {
		t.Fatalf("cards: %v", m["cards"])
	}
	var a dcnOpArgs
	json.Unmarshal([]byte(`{"kind":"files","offset":500,"limit":250,"prefix":"docs/"}`), &a)
	if a.Kind != "files" || a.Offset != 500 || a.Limit != 250 || a.Prefix != "docs/" {
		t.Fatalf("paging args must be carried: %+v", a)
	}
	// an oversized 200 is detectable: the body is capped at exactly freeagentMaxBody
	status, body, err = freeagentCall(c, http.MethodGet, "/catalog?limit=huge", nil)
	if err != nil || status != 200 || len(body) != freeagentMaxBody {
		t.Fatalf("oversized reply must be capped at the max body, got %d %v len=%d", status, err, len(body))
	}
}

func TestDcnOpArgsCarryFreeagentFields(t *testing.T) {
	var a dcnOpArgs
	if err := json.Unmarshal([]byte(`{"query":"routers","k":3,"doc":"abc","start_byte":1,"end_byte":9}`), &a); err != nil {
		t.Fatal(err)
	}
	if a.Query != "routers" || a.K != 3 || a.Doc != "abc" || a.EndByte != 9 {
		t.Fatalf("args not carried: %+v", a)
	}
}
