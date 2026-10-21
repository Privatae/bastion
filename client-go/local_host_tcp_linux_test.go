//go:build linux

// A Host with no platform in a VM on this machine: the pairing on the Host's
// enroll port over TLS pinned to the Host CA the owner hands over, and the
// lanes on its lane port (pair_tcp.go).
//
// Uses the fixtures of local_host_linux_test.go (newTestCA, startLaneHostOn,
// runFor, pairingBox...) and stubCoders, so it carries the same build tag.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tcpEnrollHost is a Host's enroll port: HTTPS on loopback with serverCert,
// answering a redeem the way the Host does, the CSR signed by signer and
// naming ca as its CA.
type tcpEnrollHost struct {
	srv    *httptest.Server
	url    string
	ca     *testCA
	signer *testCA
	lane   string
	hits   atomic.Int32
	mu     sync.Mutex
	last   redeemReq
	path   string
	sni    string
	edit   func(map[string]any)
}

func startTCPEnrollHost(t *testing.T, ca *testCA, serverCert tls.Certificate, lane string) *tcpEnrollHost {
	t.Helper()
	h := &tcpEnrollHost{ca: ca, signer: ca, lane: lane}
	h.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		var req redeemReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		h.mu.Lock()
		h.last, h.path, h.sni = req, r.Method+" "+r.URL.Path, r.TLS.ServerName
		signer, ca, edit, lane := h.signer, h.ca, h.edit, h.lane
		h.mu.Unlock()
		ans := map[string]any{"operator_cert": signer.signCSR(req.OperatorCSR), "ca_cert": ca.pem,
			"bearer": "mcp_tcp_" + fmt.Sprint(h.hits.Load()), "transport": "tcp", "lane_address": lane,
			"host_handle": "home", "host_name": "home.example.test"}
		if edit != nil {
			edit(ans)
		}
		_ = json.NewEncoder(w).Encode(ans)
	}))
	h.srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	h.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
	h.url = "https://" + h.srv.Listener.Addr().String() + "/v1/local/redeem"
	return h
}

func (h *tcpEnrollHost) set(fn func(h *tcpEnrollHost)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn(h)
}

// writeCA writes a CA certificate where --host-ca can read it.
func writeCA(t *testing.T, ca *testCA) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "host-ca.pem")
	if err := os.WriteFile(p, []byte(ca.pem), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func homeToken() string { return "skb_aG9tZS5zZWNyZXQteA" } // base64url("home.secret-x")

// ── 1. pair --redeem-url https://… --host-ca ─────────────────────────────────

// SECURITY: an https redeem URL and its --host-ca are checked before the token
// is read. A URL that is not https://<host>/<path>, an https URL without
// --host-ca, a --host-ca with a unix or platform pairing, and a --host-ca
// that is missing, not PEM or not a CA all dial nothing and save nothing.
func TestATCPRedeemIsCheckedBeforeTheToken(t *testing.T) {
	if _, _, err := decodeToken(homeToken()); err != nil {
		t.Fatalf("the test token must decode: %v", err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	addr := tcp.Addr().String()
	cfgHome := pairingBox(t)
	ca := writeCA(t, newTestCA(t, "home host CA"))
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	_ = os.WriteFile(notPEM, []byte("hello"), 0o600)
	leaf := filepath.Join(t.TempDir(), "leaf.pem")
	k, csr, _ := genOperatorCSR("fp-x", true)
	_ = k
	_ = os.WriteFile(leaf, []byte(newTestCA(t, "x").signCSR(csr)), 0o600)
	for _, c := range []struct{ url, ca string }{
		{"https://user@" + addr + "/v1/local/redeem", ca},
		{"https://" + addr + "/v1/local/redeem?x=1", ca},
		{"https://" + addr + "/v1/local/redeem#x", ca},
		{"https://" + addr + "/v1/../redeem", ca},
		{"https://" + addr, ca},
		{"https://127.0.0.1:0/v1/local/redeem", ca},
		{"https://127.0.0.1:99999/v1/local/redeem", ca},
		{"https:///v1/local/redeem", ca},
		{"http://" + addr + "/v1/local/redeem", ca},
		{"https://" + addr + "/v1/local/redeem", ""},
		{"https://" + addr + "/v1/local/redeem", filepath.Join(t.TempDir(), "absent.pem")},
		{"https://" + addr + "/v1/local/redeem", notPEM},
		{"https://" + addr + "/v1/local/redeem", leaf},
		{"unix:///run/privatae-host/enroll.sock", ca},
		{"", ca},
	} {
		if _, _, err := pairWithTokenVia(homeToken(), c.url, c.ca, false, false); err == nil {
			t.Errorf("pair --redeem-url %q --host-ca %q must be refused", c.url, c.ca)
		}
	}
	if accepted.Load() != 0 {
		t.Fatalf("a refused redeem dialled the enroll port %d times", accepted.Load())
	}
	_ = filepath.Walk(cfgHome, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".json") {
			t.Errorf("a refused redeem left %s", p)
		}
		return nil
	})
}

// SECURITY: the redeem trusts the --host-ca alone and checks the name
// host.cseries.internal. An enroll port whose certificate another CA signed
// (the platform's, a public one, anyone's), or that carries another name, is
// dialled and gets nothing: the token is never sent.
func TestTheTCPRedeemTrustsOnlyTheHostCAUnderItsName(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "home host CA")
	caFile := writeCA(t, ca)
	for name, cert := range map[string]tls.Certificate{
		"another CA":   newTestCA(t, "impostor").serverCert(t, tcpServerName),
		"another name": ca.serverCert(t, "home.example.test"),
	} {
		h := startTCPEnrollHost(t, ca, cert, "127.0.0.1:1")
		if _, _, err := pairWithTokenVia(homeToken(), h.url, caFile, false, false); err == nil {
			t.Fatalf("%s: the redeem must be refused", name)
		}
		if n := h.hits.Load(); n != 0 {
			t.Fatalf("%s: the token reached an enroll port the bastion must not trust (%d requests)", name, n)
		}
	}
}

// SECURITY: the redeem goes to the URL given and nowhere else. An enroll port
// that answers with a redirect, even one the Host CA vouches for, gets a
// refusal: a followed 307 would send the body with the token's secret in it
// to the address the redirect names, here in plain HTTP.
func TestTheTCPRedeemFollowsNoRedirect(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "home host CA")
	plain := laneListener(t)
	defer plain.Close()
	var reached atomic.Int32
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			reached.Add(1)
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = io.Copy(io.Discard, c)
			c.Close()
		}
	}()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+plain.Addr().String()+"/v1/local/redeem", http.StatusTemporaryRedirect)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t, tcpServerName)}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	u := "https://" + srv.Listener.Addr().String() + "/v1/local/redeem"
	if _, _, err := pairWithTokenVia(homeToken(), u, writeCA(t, ca), false, false); err == nil ||
		!strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("a redirecting enroll port must be refused as it answered, got %v", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the redeem followed the redirect to %s (%d connections)", plain.Addr(), n)
	}
	if cfgs, _ := loadPairings(); len(cfgs) != 0 {
		t.Fatal("a refused redeem saved a pairing")
	}
}

// The redeem goes to the URL given, with today's body, under the name
// host.cseries.internal, and the pairing records transport tcp, the lane's
// address and the Host CA. Its file carries no socket paths.
func TestPairOverTheEnrollPortRecordsATCPPairing(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "home host CA")
	h := startTCPEnrollHost(t, ca, ca.serverCert(t, tcpServerName), "127.0.0.1:18811")
	cfg, _, err := pairWithTokenVia(homeToken(), h.url, writeCA(t, ca), false, false)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	req, path, sni := h.last, h.path, h.sni
	h.mu.Unlock()
	if path != "POST /v1/local/redeem" || sni != tcpServerName {
		t.Fatalf("the redeem is POST /v1/local/redeem under %s: %q %q", tcpServerName, path, sni)
	}
	if req.Secret != "secret-x" || req.Handle != "home" || !strings.Contains(req.OperatorCSR, "CERTIFICATE REQUEST") {
		t.Fatalf("the body is today's redeem body: %+v", req)
	}
	if got := strings.Join(csrURIs(parseTestCSR(t, req.OperatorCSR)), " "); got != fpSANPrefix+cfg.Fingerprint+" "+hostFPSANPrefix+cfg.Fingerprint {
		t.Fatalf("a Host with no platform gets the fingerprint under both names: %s", got)
	}
	if !cfg.tcpTransport() || cfg.LaneAddr != "127.0.0.1:18811" || cfg.CACert != ca.pem || cfg.HostName != "home.example.test" ||
		cfg.Bearer == "" || cfg.LaneSocket != "" || cfg.RunsDir != "" || cfg.Endpoint != "" {
		t.Fatalf("the pairing: %+v", cfg)
	}
	pd, _ := pairingsDir()
	raw, _ := os.ReadFile(filepath.Join(pd, "home.example.test.json"))
	if !strings.Contains(string(raw), `"transport": "tcp"`) || !strings.Contains(string(raw), `"lane_addr": "127.0.0.1:18811"`) ||
		strings.Contains(string(raw), "lane_socket") || strings.Contains(string(raw), "runs_dir") {
		t.Fatalf("the file: %s", raw)
	}
}

// SECURITY: the answer is checked before anything is saved: the CA in it must
// be the --host-ca, the operator certificate signed by it, the lane on the
// redeem URL's host, the transport tcp. The CA is pinned: a --replace under
// another --host-ca is refused; the same CA rotates the credentials. A unix
// --replace of a tcp pairing is refused before anything is dialled.
func TestATCPAnswerIsCheckedAndTheCAPinned(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "home host CA")
	caFile := writeCA(t, ca)
	h := startTCPEnrollHost(t, ca, ca.serverCert(t, tcpServerName), "127.0.0.1:18811")
	other := newTestCA(t, "someone else")
	for name, edit := range map[string]func(h *tcpEnrollHost){
		"a CA other than --host-ca":            func(h *tcpEnrollHost) { h.ca = other },
		"an operator cert the CA did not sign": func(h *tcpEnrollHost) { h.signer = other },
		"a lane on another host":               func(h *tcpEnrollHost) { h.lane = "192.0.2.10:18811" },
		"a lane that is not host:port":         func(h *tcpEnrollHost) { h.lane = "127.0.0.1" },
		"transport unix": func(h *tcpEnrollHost) {
			h.edit = func(a map[string]any) { a["transport"] = "unix" }
		},
		"no bearer": func(h *tcpEnrollHost) {
			h.edit = func(a map[string]any) { delete(a, "bearer") }
		},
	} {
		h.set(func(h *tcpEnrollHost) { h.ca, h.signer, h.lane, h.edit = ca, ca, "127.0.0.1:18811", nil })
		h.set(edit)
		if _, _, err := pairWithTokenVia(homeToken(), h.url, caFile, false, false); err == nil {
			t.Fatalf("%s must be refused", name)
		}
		if cfgs, _ := loadPairings(); len(cfgs) != 0 {
			t.Fatalf("%s: a refused answer saved a pairing", name)
		}
	}
	h.set(func(h *tcpEnrollHost) { h.ca, h.signer, h.lane, h.edit = ca, ca, "127.0.0.1:18811", nil })
	first, _, err := pairWithTokenVia(homeToken(), h.url, caFile, false, false)
	if err != nil {
		t.Fatal(err)
	}
	// Another Host CA on a --replace: refused before the redeem dials, so the
	// token never reaches a port that CA vouches for; the pairing unchanged.
	h.set(func(h *tcpEnrollHost) { h.ca, h.signer = other, other })
	h2 := startTCPEnrollHost(t, other, other.serverCert(t, tcpServerName), "127.0.0.1:18811")
	if _, _, err := pairWithTokenVia(homeToken(), h2.url, writeCA(t, other), true, false); err == nil ||
		!strings.Contains(err.Error(), "paired with") {
		t.Fatalf("a --replace under another Host CA must be refused, got %v", err)
	}
	if n := h2.hits.Load(); n != 0 {
		t.Fatalf("a --replace under another Host CA sent the token to that CA's enroll port (%d requests)", n)
	}
	cfgs, _ := loadPairings()
	if c := pairingFor(cfgs, "home"); c == nil || c.CACert != ca.pem || c.Bearer != first.Bearer {
		t.Fatalf("the refused replace changed the pairing: %+v", c)
	}
	h.set(func(h *tcpEnrollHost) { h.ca, h.signer = ca, ca })
	again, _, err := pairWithTokenVia(homeToken(), h.url, caFile, true, false)
	if err != nil || again.Bearer == first.Bearer || again.ListenAddr != first.ListenAddr || again.FirstSeen != first.FirstSeen {
		t.Fatalf("the same CA rotates the credentials and keeps the pairing's place: %v %+v", err, again)
	}
	var dialled atomic.Int32
	old := unixRedeemDial
	unixRedeemDial = func(ctx context.Context, sock string) (net.Conn, error) { dialled.Add(1); return old(ctx, sock) }
	t.Cleanup(func() { unixRedeemDial = old })
	if _, _, err := pairWithTokenAt(homeToken(), "unix:///run/privatae-host/enroll.sock", true, false); err == nil ||
		!strings.Contains(err.Error(), "over TCP") || dialled.Load() != 0 {
		t.Fatalf("a unix --replace of a tcp pairing is refused before dialling: %v (dialled %d)", err, dialled.Load())
	}
}

// ── 2. the lane on the lane port ─────────────────────────────────────────────

// tcpPairingFor is a tcp pairing with an operator certificate from ca, its
// lanes going to lane.
func tcpPairingFor(t *testing.T, ca *testCA, host, lane string) *Config {
	t.Helper()
	cert, key := ca.operatorPair(t)
	return &Config{HostName: host, Transport: transportTCP, LaneAddr: lane, CACert: ca.pem,
		OperatorCert: cert, OperatorKey: key, Bearer: "mcp_tcp_lane_bearer", OperatorSecret: "local",
		ListenAddr: "127.0.0.1:0", WGPrivateKey: testWGKey(t)}
}

func laneListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// SECURITY: the TCP lane refuses a Host without the pinned CA. A lane port
// whose certificate another CA signed, or that names anything but
// host.cseries.internal (the Host's own name included), is dialled and gets
// nothing: no heartbeat, no worker.
func TestTheTCPLaneRefusesAPeerWithoutThePinnedCA(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	ca := newTestCA(t, "home host CA")
	for name, cert := range map[string]tls.Certificate{
		"another CA":          newTestCA(t, "impostor").serverCert(t, tcpServerName),
		"the Host's own name": ca.serverCert(t, "home.example.test"),
	} {
		ln := laneListener(t)
		h := startLaneHostOn(t, ln, cert, ca)
		cfg := tcpPairingFor(t, ca, "home.example.test", ln.Addr().String())
		if err := runFor(t, cfg, 1500*time.Millisecond); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if h.accepted.Load() == 0 {
			t.Fatalf("%s: the lanes never dialled the port, so this proves nothing", name)
		}
		if n := h.handled.Load(); n != 0 {
			t.Fatalf("%s: the bastion talked to a lane port it must not trust (%d requests)", name, n)
		}
	}
}

// SECURITY: the TCP lane never goes without the bearer, and presents the
// operator certificate (the lane port requires one and verifies it against
// the Host CA). The protocol is the unix lane's: the worker pools, the
// heartbeat, and a harness job served on a parked worker, every handshake
// under host.cseries.internal.
func TestTheTCPLaneCarriesTheCertTheBearerAndTheSameProtocol(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	ca := newTestCA(t, "home host CA")
	ln := laneListener(t)
	h := startLaneHostOn(t, ln, ca.serverCert(t, tcpServerName), ca)
	cfg := tcpPairingFor(t, ca, "home.example.test", ln.Addr().String())

	none := *cfg
	none.Bearer = ""
	if err := runFor(t, &none, time.Second); err == nil || !strings.Contains(err.Error(), "bearer") {
		t.Fatalf("a pairing with no bearer must not start, got %v", err)
	}
	if h.accepted.Load() != 0 {
		t.Fatal("a pairing with no bearer dialled the lane")
	}

	h.jobs <- []byte(`{"harness_id":"h1","mode":"echo","prompt":"hello over the port"}`)
	if err := runFor(t, cfg, 2500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	hellos, beats := h.snapshot()
	if len(beats) == 0 || beats[0] != "Bearer "+cfg.Bearer {
		t.Fatalf("the heartbeat carries the bearer: %q", beats)
	}
	count := map[string]int{}
	for _, hl := range hellos {
		path, msg, _ := strings.Cut(hl, " ")
		if !strings.HasPrefix(msg, "BEARER "+cfg.Bearer) {
			t.Fatalf("a worker opened without the bearer: %q", hl)
		}
		if strings.Contains(msg, "lane=session") {
			path += " session"
		}
		count[path]++
	}
	h.mu.Lock()
	maxPark, sni := h.maxPark, append([]string(nil), h.sni...)
	h.mu.Unlock()
	if maxPark != harnessWorkerCount || count["/bastion-harness"] < harnessWorkerCount ||
		count["/bastion-harness session"] != sessionWorkerCount ||
		count["/bastion-mgmt"] != mgmtWorkerCount || count["/bastion-egress"] != egressWorkerCount {
		t.Fatalf("the worker pools over the port: %v, parked at once %d", count, maxPark)
	}
	for _, n := range sni {
		if n != tcpServerName {
			t.Fatalf("a lane handshake asked for %q, not %s", n, tcpServerName)
		}
	}
	if len(sni) == 0 {
		t.Fatal("no verified handshake was recorded")
	}
	select {
	case r := <-h.replies:
		if !strings.HasSuffix(r, "exit=0") {
			t.Fatalf("the harness job over the port: %s", r)
		}
	default:
		t.Fatal("a parked harness worker served no job")
	}
}

// ── 3. no coder runs over TCP ────────────────────────────────────────────────

// A run's control plane is a tunnel port or a socket in a unix pairing's runs
// directory; a tcp pairing has neither, so its run-up is refused before any
// container starts, and every other pairing's is not.
func TestARunUpForATCPPairingIsRefusedBeforeAnyContainer(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 2)
	ca := newTestCA(t, "home host CA")
	if err := tcpPairingFor(t, ca, "tcp.example.test", "127.0.0.1:18811").save(); err != nil {
		t.Fatal(err)
	}
	b, code := runCoder(upSpec("run-tcp-000001", "tcp.example.test"))
	m := decode(t, b)
	if code == 0 || m["started"] == true || !strings.Contains(fmt.Sprint(m["error"]), "over TCP") {
		t.Fatalf("run-up for a tcp pairing: %d %s", code, b)
	}
	f.mu.Lock()
	for _, c := range f.calls {
		if len(c) > 1 && c[1] == "run" {
			t.Fatalf("a container was started for a tcp pairing: %q", c)
		}
	}
	f.mu.Unlock()
	if b, code := runCoder(upSpec("run-other-0001", "h.example")); code != 0 || decode(t, b)["started"] != true {
		t.Fatalf("another pairing's run-up still starts: %d %s", code, b)
	}
}

// When the pairings cannot be read, which transport a run would use is not
// known, so its run-up is refused before any container starts, as a tcp
// pairing's is.
func TestARunUpIsRefusedWhenThePairingsCannotBeRead(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 2)
	ca := newTestCA(t, "home host CA")
	if err := tcpPairingFor(t, ca, "tcp.example.test", "127.0.0.1:18811").save(); err != nil {
		t.Fatal(err)
	}
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pd, "broken.example.test.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPairings(); err == nil {
		t.Fatal("the broken file must make the pairings unreadable, or this proves nothing")
	}
	b, code := runCoder(upSpec("run-tcp-000002", "tcp.example.test"))
	m := decode(t, b)
	if code == 0 || m["started"] == true || !strings.Contains(fmt.Sprint(m["error"]), "pairings") {
		t.Fatalf("run-up with unreadable pairings: %d %s", code, b)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if len(c) > 1 && c[1] == "run" {
			t.Fatalf("a container was started while the pairings could not be read: %q", c)
		}
	}
}
