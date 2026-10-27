//go:build linux

// A standalone Host owns its own bastion: the pairing over the Host's enroll
// socket, the lanes over its lane socket, coder runs as sockets in its runs
// directory, the workspace engine and the owner's image prefix.
//
// Uses setupBox / withMarkerAt / uiTestConfigDir / stubCoders and the other
// unix-only fixtures, so it carries a build tag (buildtags_test.go).

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// shortDir is a directory whose socket paths fit a sockaddr_un (108 bytes);
// t.TempDir() under a long test name does not.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "plh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// signCSR is what the Host's redeem does with the bastion's CSR. It never
// calls t.Fatal: it runs on a server goroutine.
func (ca *testCA) signCSR(csrPEM string) string {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil {
		return ""
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return ""
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: csr.Subject, URIs: csr.URIs,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// operatorPair is an operator key and a certificate for it signed by ca.
func (ca *testCA) operatorPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	k, csr, err := genOperatorCSR("fp-test", true)
	if err != nil {
		t.Fatal(err)
	}
	return ca.signCSR(csr), k
}

// serverCert is the Host's lane certificate for name.
func (ca *testCA) serverCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// enrollHost is a Host's enroll socket: it answers a redeem the way the
// design says, signing the CSR with signer and naming ca as its CA.
type enrollHost struct {
	sock   string
	dir    string
	ca     *testCA
	signer *testCA
	hits   atomic.Int32
	mu     sync.Mutex
	last   redeemReq
	path   string
	edit   func(map[string]any)
}

func startEnrollHost(t *testing.T, dir string, ca *testCA) *enrollHost {
	t.Helper()
	h := &enrollHost{sock: filepath.Join(dir, "enroll.sock"), dir: dir, ca: ca, signer: ca}
	ln, err := net.Listen("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		var req redeemReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		h.mu.Lock()
		h.last, h.path = req, r.Method+" "+r.URL.Path
		signer, ca, edit := h.signer, h.ca, h.edit
		h.mu.Unlock()
		ans := map[string]any{"operator_cert": signer.signCSR(req.OperatorCSR), "ca_cert": ca.pem,
			"bearer": "mcp_test_" + fmt.Sprint(h.hits.Load()), "transport": "unix",
			"lane_socket": filepath.Join(h.dir, "lane.sock"), "runs_dir": filepath.Join(h.dir, "runs"), "host_handle": "denz"}
		if edit != nil {
			edit(ans)
		}
		_ = json.NewEncoder(w).Encode(ans)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return h
}

func (h *enrollHost) set(fn func(h *enrollHost)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn(h)
}

func denzToken() string {
	return "skb_" + base64.RawURLEncoding.EncodeToString([]byte("denz.secret-x"))
}

func pairingBox(t *testing.T) string {
	t.Helper()
	d := uiTestConfigDir(t)
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	return d
}

// ── 1. pair --redeem-url ────────────────────────────────────────────────────

func TestParsePairArgs(t *testing.T) {
	for _, c := range []struct {
		args            []string
		token, url, cas string
		replace, ok     bool
	}{
		{[]string{"skb_x"}, "skb_x", "", "", false, true},
		{[]string{"--replace", "skb_x"}, "skb_x", "", "", true, true},
		{[]string{"--redeem-url", "unix:///run/privatae-host/enroll.sock", "skb_x"}, "skb_x", "unix:///run/privatae-host/enroll.sock", "", false, true},
		{[]string{"skb_x", "--redeem-url=unix:///a/b.sock", "--replace"}, "skb_x", "unix:///a/b.sock", "", true, true},
		{[]string{"--redeem-url", "https://127.0.0.1:8810/v1/local/redeem", "--host-ca", "/x/ca.pem", "skb_x"},
			"skb_x", "https://127.0.0.1:8810/v1/local/redeem", "/x/ca.pem", false, true},
		{[]string{"--host-ca=/x/ca.pem", "skb_x", "--redeem-url=https://127.0.0.1:8810/v1/local/redeem"},
			"skb_x", "https://127.0.0.1:8810/v1/local/redeem", "/x/ca.pem", false, true},
		// No token parses, and pairToken refuses it with the usage; - parses,
		// and pairToken reads the token from standard input (pair_stdin.go).
		{[]string{}, "", "", "", false, true},
		{[]string{"--replace"}, "", "", "", true, true},
		{[]string{"-"}, "-", "", "", false, true},
		{[]string{"--replace", "-"}, "-", "", "", true, true},
		{[]string{"a", "b"}, "", "", "", false, false},
		{[]string{"-", "skb_x"}, "", "", "", false, false},
		{[]string{"--redeem", "x", "skb_x"}, "", "", "", false, false},
		{[]string{"--host-ca"}, "", "", "", false, false},
	} {
		tok, u, cas, rep, err := parsePairArgs(c.args)
		if (err == nil) != c.ok || (c.ok && (tok != c.token || u != c.url || cas != c.cas || rep != c.replace)) {
			t.Errorf("%q: got %q %q %q %v %v", c.args, tok, u, cas, rep, err)
		}
	}
}

// SECURITY: a unix redeem URL can't point at a TCP address. Every network
// spelling is refused before the token is read: nothing is dialled (a TCP
// listener at the named address gets no connection), nothing is created.
func TestAUnixRedeemURLCannotPointAtATCPAddress(t *testing.T) {
	if p, err := parseUnixRedeemURL("unix:///run/privatae-host/enroll.sock"); err != nil || p != "/run/privatae-host/enroll.sock" {
		t.Fatalf("the design's URL: %q %v", p, err)
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
	var dialled atomic.Int32
	old := unixRedeemDial
	unixRedeemDial = func(ctx context.Context, sock string) (net.Conn, error) { dialled.Add(1); return old(ctx, sock) }
	t.Cleanup(func() { unixRedeemDial = old })
	for _, bad := range []string{
		"unix://" + addr, "unix://" + addr + "/enroll.sock", "unix://[::1]:8443/enroll.sock",
		"unix://localhost/run/privatae-host/enroll.sock", "unix://user@/run/x.sock",
		"tcp://" + addr, "http://" + addr + "/bastion/enroll/redeem", "https://api.privatae.ai",
		"unix:run/x.sock", "unix:///run/../etc/x.sock", "unix:///run//x.sock", "unix:///run/x.sock/", "unix:///",
		"unix:///run/x.sock?h=" + addr, "unix:///run/x.sock#" + addr, "unix:///run/%2e%2e/x.sock",
	} {
		if _, err := parseUnixRedeemURL(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
		if _, _, err := pairWithTokenAt(denzToken(), bad, false, false); err == nil {
			t.Errorf("pair with %q must be refused", bad)
		}
	}
	if dialled.Load() != 0 || accepted.Load() != 0 {
		t.Fatalf("a refused redeem URL dialled something: unix %d, tcp %d", dialled.Load(), accepted.Load())
	}
	_ = filepath.Walk(cfgHome, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".json") {
			t.Errorf("a refused redeem left %s", p)
		}
		return nil
	})
}

// The redeem goes over the socket with the same body, and the pairing records
// transport unix, the lane socket, the runs directory and the Host's CA. A
// platform pairing's file is what it was: none of the new keys.
func TestPairOverTheEnrollSocketRecordsAUnixPairing(t *testing.T) {
	pairingBox(t)
	dir := shortDir(t)
	ca := newTestCA(t, "denz host CA")
	h := startEnrollHost(t, dir, ca)
	cfg, _, err := pairWithTokenAt(denzToken(), "unix://"+h.sock, false, false)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	req, path := h.last, h.path
	h.mu.Unlock()
	if path != "POST "+unixRedeemPath {
		t.Fatalf("the redeem is POST %s, got %q", unixRedeemPath, path)
	}
	if req.Secret != "secret-x" || req.Handle != "denz" || req.WGPublicKey == "" || req.Platform != "linux" ||
		!strings.Contains(req.OperatorCSR, "CERTIFICATE REQUEST") || req.Hostname == "" {
		t.Fatalf("the body is today's redeem body: %+v", req)
	}
	if !cfg.unixTransport() || cfg.LaneSocket != filepath.Join(dir, "lane.sock") || cfg.RunsDir != filepath.Join(dir, "runs") ||
		cfg.HostName != "denz" || cfg.CACert != ca.pem || cfg.Bearer == "" || cfg.Endpoint != "" || cfg.HostTunnelIP != "" {
		t.Fatalf("the pairing: %+v", cfg)
	}
	pd, _ := pairingsDir()
	raw, _ := os.ReadFile(filepath.Join(pd, "denz.json"))
	if !strings.Contains(string(raw), `"transport": "unix"`) {
		t.Fatalf("the file records the transport: %s", raw)
	}
	plat, _ := json.Marshal(&Config{HostName: "acme.host.privatae.ai", Endpoint: "203.0.113.7:51820"})
	for _, k := range []string{"transport", "lane_socket", "runs_dir"} {
		if strings.Contains(string(plat), k) {
			t.Fatalf("a platform pairing's file carries %q: %s", k, plat)
		}
	}
	// The platform's spelling of the fields is read too.
	pairingBox(t)
	h.set(func(h *enrollHost) {
		h.edit = func(a map[string]any) {
			a["operator_crt"], a["ca_crt"], a["host_name"] = a["operator_cert"], a["ca_cert"], "denz2"
			delete(a, "operator_cert")
			delete(a, "ca_cert")
		}
	})
	if c, _, err := pairWithTokenAt(denzToken(), "unix://"+h.sock, false, false); err != nil || c.HostName != "denz2" {
		t.Fatalf("operator_crt / ca_crt / host_name: %v %+v", err, c)
	}
}

// The Host's CA is pinned: a --replace that brings another CA is refused and
// changes nothing; the same CA rotates the credentials. An answer whose
// operator cert the CA did not sign, or whose sockets sit outside the shared
// directory, saves nothing. A platform --replace of a unix pairing is refused
// before the platform's redeem is called.
func TestAUnixPairingPinsTheHostsCA(t *testing.T) {
	pairingBox(t)
	dir := shortDir(t)
	ca := newTestCA(t, "denz host CA")
	h := startEnrollHost(t, dir, ca)
	first, _, err := pairWithTokenAt(denzToken(), "unix://"+h.sock, false, false)
	if err != nil {
		t.Fatal(err)
	}
	other := newTestCA(t, "someone else")
	h.set(func(h *enrollHost) { h.ca, h.signer = other, other })
	if _, _, err := pairWithTokenAt(denzToken(), "unix://"+h.sock, true, false); err == nil || !strings.Contains(err.Error(), "different CA") {
		t.Fatalf("a later different CA must be refused, got %v", err)
	}
	cfgs, _ := loadPairings()
	if c := pairingFor(cfgs, "denz"); c == nil || c.CACert != ca.pem || c.Bearer != first.Bearer {
		t.Fatalf("the refused replace changed the pairing: %+v", c)
	}
	h.set(func(h *enrollHost) { h.ca, h.signer = ca, other })
	if _, _, err := pairWithTokenAt(denzToken(), "unix://"+h.sock, true, false); err == nil || !strings.Contains(err.Error(), "not signed by the CA") {
		t.Fatalf("an operator cert the CA did not sign must be refused, got %v", err)
	}
	for _, k := range []string{"lane_socket", "runs_dir"} {
		k := k
		h.set(func(h *enrollHost) {
			h.signer = ca
			h.edit = func(a map[string]any) { a[k] = "/etc/" + k }
		})
		if _, _, err := pairWithTokenAt(denzToken(), "unix://"+h.sock, true, false); err == nil || !strings.Contains(err.Error(), "not inside") {
			t.Fatalf("%s outside the shared directory must be refused, got %v", k, err)
		}
	}
	h.set(func(h *enrollHost) { h.edit = func(a map[string]any) { a["transport"] = "wireguard" } })
	if _, _, err := pairWithTokenAt(denzToken(), "unix://"+h.sock, true, false); err == nil {
		t.Fatal("an answer that is not transport unix must be refused")
	}
	h.set(func(h *enrollHost) { h.edit = nil })
	again, _, err := pairWithTokenAt(denzToken(), "unix://"+h.sock, true, false)
	if err != nil || again.Bearer == first.Bearer || again.ListenAddr != first.ListenAddr || again.FirstSeen != first.FirstSeen {
		t.Fatalf("the same CA rotates the credentials and keeps the pairing's place: %v %+v", err, again)
	}

	var platformHits atomic.Int32
	plat := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { platformHits.Add(1) })}
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = plat.Serve(pl) }()
	defer plat.Close()
	old := redeemURLBase
	redeemURLBase = "http://" + pl.Addr().String()
	t.Cleanup(func() { redeemURLBase = old })
	if _, _, err := pairWithToken(denzToken(), true, false); err == nil || !strings.Contains(err.Error(), "Host on this machine") {
		t.Fatalf("a platform --replace of a unix pairing must be refused, got %v", err)
	}
	if platformHits.Load() != 0 {
		t.Fatal("the refusal came after the platform redeem; the token would be burned")
	}
}

// ── 2. the lane over the socket ─────────────────────────────────────────────

// laneHost is a Host's lane socket: mutual TLS with its certificate, the
// bastion's operator certificate required and checked against clientCA, and
// the routes the lanes use. It records every hello and heartbeat, and hands
// each job on jobs to the next parked harness worker.
type laneHost struct {
	accepted atomic.Int32
	handled  atomic.Int32
	mu       sync.Mutex
	hellos   []string // "<path> <first message>"
	beats    []string // each heartbeat's Authorization
	jobs     chan []byte
	replies  chan string
	parked   int // harness workers connected now and not yet given a job
	maxPark  int
	sni      []string // the server name each verified handshake asked for
}

type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func startLaneHost(t *testing.T, sock string, cert tls.Certificate, clientCA *testCA) *laneHost {
	t.Helper()
	raw, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	return startLaneHostOn(t, raw, cert, clientCA)
}

// startLaneHostOn is startLaneHost on a listener already made: the lane
// socket, or a Host's lane port (local_host_tcp_linux_test.go).
func startLaneHostOn(t *testing.T, raw net.Listener, cert tls.Certificate, clientCA *testCA) *laneHost {
	t.Helper()
	h := &laneHost{jobs: make(chan []byte, 4), replies: make(chan string, 4)}
	pool := x509.NewCertPool()
	pool.AddCert(clientCA.cert)
	ln := tls.NewListener(countingListener{raw, &h.accepted}, &tls.Config{Certificates: []tls.Certificate{cert},
		ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			h.mu.Lock()
			h.sni = append(h.sni, cs.ServerName)
			h.mu.Unlock()
			return nil
		}})
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/network/bastions/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		h.handled.Add(1)
		h.mu.Lock()
		h.beats = append(h.beats, r.Header.Get("Authorization"))
		h.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	})
	ws := func(w http.ResponseWriter, r *http.Request) {
		h.handled.Add(1)
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, hello, err := c.ReadMessage()
		if err != nil {
			return
		}
		h.mu.Lock()
		h.hellos = append(h.hellos, r.URL.Path+" "+string(hello))
		h.mu.Unlock()
		if r.URL.Path == "/bastion-harness" && !strings.Contains(string(hello), "lane=") {
			h.mu.Lock()
			h.parked++
			h.maxPark = max(h.maxPark, h.parked)
			h.mu.Unlock()
			unpark := func() { h.mu.Lock(); h.parked--; h.mu.Unlock() }
			select {
			case job := <-h.jobs:
				unpark()
				_ = c.WriteMessage(websocket.BinaryMessage, append([]byte{'H'}, job...))
				reply := ""
				for {
					_, m, err := c.ReadMessage()
					if err != nil || len(m) == 0 {
						break
					}
					if m[0] == 'J' {
						reply = string(m[1:])
					}
					if m[0] == 'X' {
						h.replies <- reply + " exit=" + string(m[1:])
						break
					}
				}
				return
			case <-r.Context().Done():
				unpark()
				return
			}
		}
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}
	for _, p := range []string{"/bastion-harness", "/bastion-mgmt", "/bastion-egress", "/bastion-serve"} {
		mux.HandleFunc(p, ws)
	}
	srv := &http.Server{Handler: mux, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return h
}

func (h *laneHost) snapshot() (hellos, beats []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.hellos...), append([]string(nil), h.beats...)
}

// unixPairingFor is a unix pairing with an operator certificate from ca.
func unixPairingFor(t *testing.T, ca *testCA, host, dir string) *Config {
	t.Helper()
	cert, key := ca.operatorPair(t)
	return &Config{HostName: host, Transport: transportUnix, LaneSocket: filepath.Join(dir, "lane.sock"),
		RunsDir: filepath.Join(dir, "runs"), CACert: ca.pem, OperatorCert: cert, OperatorKey: key,
		Bearer: "mcp_lane_bearer", OperatorSecret: "local", ListenAddr: "127.0.0.1:0", WGPrivateKey: testWGKey(t)}
}

// laneTestProcess keeps the box-wide loops out of the test process: the coder
// watchdog and reaper would otherwise act on other tests' stubbed runs.
func laneTestProcess(t *testing.T) {
	coderInitOnce.Do(func() {})
	prev := ctxSourcePullerFn()
	t.Cleanup(func() { setCtxSourcePuller(prev) })
}

// runFor runs the pairing for d, then stops it.
func runFor(t *testing.T, cfg *Config, d time.Duration) error {
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- runPairing(ctx, cfg) }()
	select {
	case err := <-errc:
		cancel()
		return err
	case <-time.After(d):
	}
	cancel()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the pairing did not stop")
	}
	return nil
}

// SECURITY: the unix lane refuses a peer without the pinned CA. A lane
// server whose certificate another CA signed, or that names another host, is
// dialled and gets nothing: no heartbeat, no worker.
func TestTheUnixLaneRefusesAPeerWithoutThePinnedCA(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	ca := newTestCA(t, "denz host CA")
	for name, cert := range map[string]tls.Certificate{
		"another CA":   newTestCA(t, "impostor").serverCert(t, "denz"),
		"another name": ca.serverCert(t, "someone-else"),
	} {
		dir := shortDir(t)
		cfg := unixPairingFor(t, ca, "denz", dir)
		h := startLaneHost(t, cfg.LaneSocket, cert, ca)
		if err := runFor(t, cfg, 1500*time.Millisecond); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if h.accepted.Load() == 0 {
			t.Fatalf("%s: the lanes never dialled the socket, so this proves nothing", name)
		}
		if n := h.handled.Load(); n != 0 {
			t.Fatalf("%s: the bastion talked to a lane server it must not trust (%d requests)", name, n)
		}
	}
}

// SECURITY: the lane never goes without the bearer. A unix pairing that
// holds none does not start and dials nothing; one that holds it presents it
// on every lane: the heartbeat, and the first frame of every worker.
//
// And the lane protocol is the tunnel's: two parked harness workers (plus the
// session pool's), the management and egress workers, the heartbeat, and a
// harness job served on a parked worker.
func TestTheUnixLaneCarriesTheBearerAndTheSameProtocol(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	ca := newTestCA(t, "denz host CA")
	dir := shortDir(t)
	cfg := unixPairingFor(t, ca, "denz", dir)
	h := startLaneHost(t, cfg.LaneSocket, ca.serverCert(t, "denz"), ca)

	none := *cfg
	none.Bearer = ""
	if err := runFor(t, &none, time.Second); err == nil || !strings.Contains(err.Error(), "bearer") {
		t.Fatalf("a pairing with no bearer must not start, got %v", err)
	}
	if h.accepted.Load() != 0 {
		t.Fatal("a pairing with no bearer dialled the lane")
	}

	h.jobs <- []byte(`{"harness_id":"h1","mode":"echo","prompt":"hello over the socket"}`)
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
	// The worker that served the job parks again, so the harness pool is
	// read as how many were parked at once: the pool's two.
	h.mu.Lock()
	maxPark := h.maxPark
	h.mu.Unlock()
	if maxPark != harnessWorkerCount || count["/bastion-harness"] < harnessWorkerCount ||
		count["/bastion-harness session"] != sessionWorkerCount ||
		count["/bastion-mgmt"] != mgmtWorkerCount || count["/bastion-egress"] != egressWorkerCount ||
		count["/bastion-serve"] != serveWorkerCount {
		t.Fatalf("the worker pools over the socket: %v, parked at once %d", count, maxPark)
	}
	select {
	case r := <-h.replies:
		if !strings.HasSuffix(r, "exit=0") {
			t.Fatalf("the harness job over the socket: %s", r)
		}
	default:
		t.Fatal("a parked harness worker served no job")
	}
}

// SECURITY: the anchored-box coder grant rule applies to a unix pairing.
// Over the unix lane, run-up without the standing coder grant is refused at
// the gate; with the grant the person approved, it passes.
func TestTheCoderGrantRuleAppliesToAUnixPairing(t *testing.T) {
	priv := setupBox(t)
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	laneTestProcess(t)
	ca := newTestCA(t, "denz host CA")
	dir := shortDir(t)
	cfg := unixPairingFor(t, ca, tAnchor, dir) // the anchor itself: the widest a pairing gets
	cfg.ListenAddr = "127.0.0.1:0"
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	h := startLaneHost(t, cfg.LaneSocket, ca.serverCert(t, tAnchor), ca)
	img := coderDefaultImagePrefix + "harness-workspace@sha256:" + strings.Repeat("ab", 32)
	up := map[string]any{"mode": "coder", "coder_op": "run-up", "run_id": "run-unix-00001", "engine": "workspace",
		"image": img, "uid": 10005, "creds_dir": "/home/privatae/.ws", "control_cap": strings.Repeat("c", 43)}
	job, _ := json.Marshal(up)
	h.jobs <- job
	if err := runFor(t, cfg, 2500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-h.replies:
		if !strings.Contains(r, "coder grant") || !strings.HasSuffix(r, "exit=126") {
			t.Fatalf("run-up over the unix lane without a coder grant: %s", r)
		}
	default:
		t.Fatal("the run-up was never answered")
	}
	dcn := cfg.dcnDir()
	spec := harnessSpec{Mode: "coder", CoderOp: "run-up", RunID: "run-unix-00001", Engine: "workspace", Image: img}
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	good := coderGrantTerms(tAnchor, []string{"workspace"}, 2, 30)
	approveCoderGrant(t, good)
	if _, errOut, code := driveDirOp(t, tAnchor, dcn, "coder_grant_sync", []string{coderGrantPayload(t, priv, 7, good)}); code != 0 {
		t.Fatalf("the approved workspace grant installs: %d %s", code, errOut)
	}
	if why := harnessGate(tAnchor, dcn, spec); why != "" {
		t.Fatalf("with the standing grant the unix pairing's run-up passes the gate: %q", why)
	}
}

// ── 3. run forwards on sockets ──────────────────────────────────────────────

// stubCoderSockets records the group a socket is handed to and closes every
// run socket at the end.
func stubCoderSockets(t *testing.T, gid int, groupErr error) *[][3]int {
	t.Helper()
	oldLookup, oldChown := coderLookupGroup, coderSockChown
	var mu sync.Mutex
	var chowns [][3]int
	coderLookupGroup = func(string) (int, error) { return gid, groupErr }
	coderSockChown = func(p string, uid, g int) error {
		mu.Lock()
		chowns = append(chowns, [3]int{uid, g, 0})
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		coderLookupGroup, coderSockChown = oldLookup, oldChown
		coderSockMu.Lock()
		var ids []string
		for id := range coderSocks {
			ids = append(ids, id)
		}
		coderSockDirs = map[string]string{}
		coderSockLastNote = ""
		coderSockMu.Unlock()
		for _, id := range ids {
			coderCloseRunSocket(id)
		}
	})
	return &chowns
}

// SECURITY: a run socket is refused to a different pairing. The owner's run
// is served in the owner's runs directory, 0660 and handed to the
// privatae-host group, and reaches the run's control socket; another
// pairing's runs directory never gets it, another pairing cannot open it, and
// the per-connection wall refuses it.
func TestARunSocketIsTheOwningPairingsOnly(t *testing.T) {
	cfgHome := t.TempDir()
	_ = os.Chmod(cfgHome, 0o755)
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	stubCoders(t)
	coderOn(t, 4)
	chowns := stubCoderSockets(t, 4242, nil)
	shared := shortDir(t)
	runsA, runsB := filepath.Join(shared, "runs-a"), filepath.Join(shared, "runs-b")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoderSockets(ctx, "a.example", runsA)
	startCoderSockets(ctx, "b.example", runsB)

	b, code := runCoder(upSpec("run-sock-00001", "a.example"))
	m := decode(t, b)
	sock := filepath.Join(runsA, "run-sock-00001.sock")
	if code != 0 || m["control_socket"] != sock {
		t.Fatalf("run-up answers with the run's socket: %d %s", code, b)
	}
	fi, err := os.Lstat(sock)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Fatalf("the run socket is a socket, 0660: %v %v", fi, err)
	}
	if got := *chowns; len(got) == 0 || got[len(got)-1][0] != 0 || got[len(got)-1][1] != 4242 {
		t.Fatalf("the socket goes to root and the privatae-host group: %v", got)
	}
	if d, err := os.Lstat(runsA); err != nil || d.Mode().Perm() != 0o750 {
		t.Fatalf("the runs directory the bastion makes is 0750: %v %v", d, err)
	}
	coderReconcileSockets("b.example")
	if ents, _ := os.ReadDir(runsB); len(ents) != 0 {
		t.Fatalf("another pairing's runs directory never gets the run: %v", ents)
	}
	if _, err := coderOpenRunSocket("b.example", "run-sock-00001"); err == nil {
		t.Fatal("another pairing cannot open the owner's run socket")
	}
	rec, _ := loadCoderRecord("run-sock-00001")
	now := time.Now()
	if why := coderSocketRefusal("a.example", rec, now); why != "" {
		t.Fatalf("the owner passes the wall: %q", why)
	}
	if why := coderSocketRefusal("b.example", rec, now); !strings.Contains(why, "another host") {
		t.Fatalf("another pairing is refused at the wall: %q", why)
	}
	if why := coderSocketRefusal("a.example", rec, now.Add(48*time.Hour)); why == "" {
		t.Fatal("a run past its deadline is refused")
	}

	// End to end: the owner's socket reaches the run's control socket, as
	// the engine's uid; the wall closes it once the record names another host.
	R, _ := coderRunDir("run-sock-00001")
	_ = os.Chmod(filepath.Dir(R), 0o755)
	_ = os.Chmod(R, 0o755)
	ctl := filepath.Join(R, "ctl", coderControlSock)
	_ = os.Remove(ctl)
	uid := serveControlSocket(t, ctl)
	rec.UID = uid
	if err := saveCoderRecord(R, rec); err != nil {
		t.Fatal(err)
	}
	// The pairing's lane: the Host's lane door, mutual TLS under its CA. The
	// process serving it is who may connect.
	caA := newTestCA(t, "host a CA")
	laneA := filepath.Join(shared, "lane-a.sock")
	cfgA := unixPairingFor(t, caA, "a.example", shared)
	cfgA.LaneSocket = laneA
	startLaneHost(t, laneA, caA.serverCert(t, "a.example"), caA)
	dialA, tlsA, err := unixLaneDialer(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	setCoderSockLane("a.example", laneA, dialA, tlsA)
	t.Cleanup(func() { setCoderSockLane("a.example", "", nil, nil) })
	ask := func() string {
		c, err := net.Dial("unix", sock)
		if err != nil {
			return "<dial: " + err.Error() + ">"
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, _ := io.ReadAll(c)
		return string(got)
	}
	if got := ask(); got != "pong" {
		t.Fatalf("the owner reaches the run through its socket: %q", got)
	}
	// Another Host on this machine is in the same group and could connect:
	// a process that does not serve the pairing's lane gets nothing.
	if err := os.Lchown(laneA, 4321, -1); err != nil {
		t.Fatal(err)
	}
	if got := ask(); got != "" {
		t.Fatalf("a process other than the pairing's lane owner gets nothing: %q", got)
	}
	_ = os.Lchown(laneA, os.Getuid(), -1)
	// The shared directory is group-writable, so while Host A is down another
	// Host can bind its own socket at A's lane path and own it. It answers with
	// its own CA's certificate for A's name, and gets nothing.
	caB := newTestCA(t, "host b CA")
	squat := filepath.Join(shared, "lane-squat.sock")
	startLaneHost(t, squat, caB.serverCert(t, "a.example"), caB)
	cfgSquat := *cfgA
	cfgSquat.LaneSocket = squat
	dialS, tlsS, err := unixLaneDialer(&cfgSquat)
	if err != nil {
		t.Fatal(err)
	}
	setCoderSockLane("a.example", squat, dialS, tlsS)
	if got := ask(); got != "" {
		t.Fatalf("a socket at the lane path that is not the pairing's Host serves nobody: %q", got)
	}
	setCoderSockLane("a.example", "", nil, nil)
	if got := ask(); got != "" {
		t.Fatalf("with no lane known for the pairing, nothing is served: %q", got)
	}
	setCoderSockLane("a.example", laneA, dialA, tlsA)
	if got := ask(); got != "pong" {
		t.Fatalf("the lane's own process reaches the run again: %q", got)
	}
	rec.Owner = "b.example"
	_ = saveCoderRecord(R, rec)
	if got := ask(); got != "" {
		t.Fatalf("a run that is not this pairing's gets nothing: %q", got)
	}
	coderReconcileSockets("a.example")
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatal("the socket goes once the run is not the pairing's")
	}
}

// The socket goes at run-down and at the watchdog's stop, and a stopped run
// does not get it back. A machine with no privatae-host group gets a
// root-only socket and says why.
func TestARunSocketGoesAtRunDownAndAtTheWatchdogsStop(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 4)
	chowns := stubCoderSockets(t, -1, fmt.Errorf("group: unknown group privatae-host"))
	runs := filepath.Join(shortDir(t), "runs")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoderSockets(ctx, "a.example", runs)

	if _, code := runCoder(upSpec("run-down-00001", "a.example")); code != 0 {
		t.Fatal("run-up")
	}
	sock := filepath.Join(runs, "run-down-00001.sock")
	if _, err := os.Lstat(sock); err != nil {
		t.Fatal(err)
	}
	if got := *chowns; got[len(got)-1][1] != 0 || !strings.Contains(coderSockLastNote, "does not exist") {
		t.Fatalf("no group: root, with the reason logged: %v %q", got, coderSockLastNote)
	}
	if b, code := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: "run-down-00001", owner: "a.example"}); code != 0 {
		t.Fatalf("run-down: %s", b)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatal("run-down removes the run's socket")
	}

	if _, code := runCoder(upSpec("run-watch-0001", "a.example")); code != 0 {
		t.Fatal("run-up")
	}
	sock = filepath.Join(runs, "run-watch-0001.sock")
	if _, err := os.Lstat(sock); err != nil {
		t.Fatal(err)
	}
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 10 << 20, true }
	if stopped, _ := (&coderGuard{}).round(); stopped != "run-watch-0001" {
		t.Fatalf("the watchdog stops the run: %q (%v)", stopped, f.has("kill"))
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatal("the watchdog's stop removes the run's socket")
	}
	coderReconcileSockets("a.example")
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatal("a stopped run does not get its socket back")
	}
}

// SECURITY: a run socket is made only in a runs directory root alone can
// change. The socket is chmod-ed and chown-ed by its path, and both follow a
// symlink. The Host names runs_dir and writes the shared directory, so a runs
// directory it can write (its own, a group-writable one, or one under a
// directory it owns) would let it swap the fresh socket for a link to any
// file between bind and chmod, and that file would become 0660 and the Host
// group's: /etc/shadow, say. The swap is done here in the group lookup, which
// runs between the two, as a Host watching its directory would.
func TestARunsDirectoryTheHostCanChangeGetsNoSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the runs directory is handed to another uid")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	coderOn(t, 8)
	stubCoderSockets(t, 4242, nil)
	shared := shortDir(t)
	if err := os.Chmod(shared, os.ModeSticky|0o770); err != nil { // the design's 1770
		t.Fatal(err)
	}
	const hostUID = 4321
	victim := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(victim, []byte("root:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mkdir := func(p string, mode os.FileMode, uid, gid int) string {
		t.Helper()
		if err := os.Mkdir(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, uid, gid); err != nil {
			t.Fatal(err)
		}
		return p
	}
	hostDir := mkdir(filepath.Join(shared, "host-owned"), 0o755, hostUID, hostUID)
	cases := []struct{ name, runs string }{
		{"a runs directory the Host owns", mkdir(filepath.Join(shared, "runs-host"), 0o750, hostUID, hostUID)},
		{"a group-writable runs directory", mkdir(filepath.Join(shared, "runs-gw"), 0o770, 0, 4242)},
		{"a runs directory under one the Host owns", mkdir(filepath.Join(hostDir, "runs"), 0o750, 0, 4242)},
	}
	for i, c := range cases {
		runs := c.runs
		coderLookupGroup = func(string) (int, error) {
			ents, _ := os.ReadDir(runs)
			for _, e := range ents {
				p := filepath.Join(runs, e.Name())
				if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
					_ = os.Rename(p, p+".moved")
					_ = os.Symlink(victim, p)
				}
			}
			return 4242, nil
		}
		host := fmt.Sprintf("h%d.example", i)
		ctx, cancel := context.WithCancel(context.Background())
		startCoderSockets(ctx, host, runs)
		b, _ := runCoder(upSpec(fmt.Sprintf("run-swap-%05d", i), host))
		cancel()
		if fi, err := os.Stat(victim); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: the bastion chmod-ed the file a link pointed at: %v %v", c.name, fi.Mode().Perm(), err)
		}
		if m := decode(t, b); m["control_socket"] != nil || m["started"] == true {
			t.Fatalf("%s: run-up must not get a socket there: %s", c.name, b)
		}
		if !strings.Contains(string(b), "runs directory") {
			t.Fatalf("%s: the refusal names the runs directory: %s", c.name, b)
		}
	}

	// The design's layout passes: the shared directory 1770 and sticky, runs/
	// made by the bastion, 0750 root.
	coderLookupGroup = func(string) (int, error) { return 4242, nil }
	runs := filepath.Join(shared, "runs")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoderSockets(ctx, "ok.example", runs)
	b, code := runCoder(upSpec("run-swap-ok001", "ok.example"))
	if m := decode(t, b); code != 0 || m["control_socket"] != filepath.Join(runs, "run-swap-ok001.sock") {
		t.Fatalf("the design's layout gets its socket: %d %s", code, b)
	}
	// The same shared directory without the sticky bit lets the Host move
	// root's runs/ away and make its own: refused.
	if err := os.Chmod(shared, 0o770); err != nil {
		t.Fatal(err)
	}
	b, _ = runCoder(upSpec("run-swap-ok002", "ok.example"))
	if m := decode(t, b); m["control_socket"] != nil || !strings.Contains(string(b), "writable by others") {
		t.Fatalf("a shared directory the Host can rename in is refused: %s", b)
	}
}

// A run socket is opened only for a run that is the pairing's and still up
// when the socket is made. The reconcile loop reads every record and then
// opens the sockets it wants, so a run-down between the two used to leave a
// socket for a run that no longer existed until the next poll, and another
// pairing that started a run under the same run_id meanwhile was refused its
// socket, and so its run.
func TestARunSocketOpensOnlyForALiveRunOfThePairing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	coderOn(t, 4)
	stubCoderSockets(t, 4242, nil)
	shared := shortDir(t)
	runsA, runsB := filepath.Join(shared, "runs-a"), filepath.Join(shared, "runs-b")
	// Registered without the loop, so nothing else opens or closes sockets.
	coderSockMu.Lock()
	coderSockDirs["a.example"], coderSockDirs["b.example"] = runsA, runsB
	coderSockMu.Unlock()

	// What the loop does with a snapshot read before a run-down.
	if p, err := coderOpenRunSocket("a.example", "run-gone-00001"); err == nil || p != "" {
		t.Fatalf("a run with no record gets no socket: %q %v", p, err)
	}
	if _, err := os.Lstat(filepath.Join(runsA, "run-gone-00001.sock")); !os.IsNotExist(err) {
		t.Fatalf("a socket was made for a run that does not exist: %v", err)
	}
	// Another pairing reuses the run_id and gets its socket.
	b, code := runCoder(upSpec("run-gone-00001", "b.example"))
	if m := decode(t, b); code != 0 || m["control_socket"] != filepath.Join(runsB, "run-gone-00001.sock") {
		t.Fatalf("the reused run_id's owner gets its socket: %d %s", code, b)
	}
	// A stale snapshot of the first pairing still gets nothing.
	if _, err := coderOpenRunSocket("a.example", "run-gone-00001"); err == nil {
		t.Fatal("a pairing opens a socket for another pairing's run")
	}
	if ents, _ := os.ReadDir(runsA); len(ents) != 0 {
		t.Fatalf("the first pairing's runs directory got a socket: %v", ents)
	}
	// A run the watchdog stopped gets none.
	R, _ := coderRunDir("run-gone-00001")
	rec, _ := loadCoderRecord("run-gone-00001")
	coderCloseRunSocket("run-gone-00001")
	rec.StoppedBy = "memory"
	if err := saveCoderRecord(R, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := coderOpenRunSocket("b.example", "run-gone-00001"); err == nil {
		t.Fatal("a stopped run gets a socket")
	}
	if ents, _ := os.ReadDir(runsB); len(ents) != 0 {
		t.Fatalf("a stopped run's socket came back: %v", ents)
	}
}

// SECURITY: coder egress still refuses the machine's own addresses for a run
// a Host on this machine owns: the proxy is the run's, whatever the
// transport of the pairing that started it.
func TestAUnixPairingsRunStillCannotReachThisMachine(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	coderOn(t, 2)
	stubCoderSockets(t, 4242, nil)
	stubLocalAddrs(t, "127.0.0.1/8", "198.51.100.7/24")
	stubResolve(t, map[string][]string{"me.example": {"198.51.100.7"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoderSockets(ctx, "denz", filepath.Join(shortDir(t), "runs"))
	if b, code := runCoder(upSpec("run-egr-000001", "denz")); code != 0 {
		t.Fatalf("run-up: %s", b)
	}
	R, _ := coderRunDir("run-egr-000001")
	for _, req := range []string{
		"CONNECT 127.0.0.1:22 HTTP/1.1\r\n\r\n",
		"CONNECT 198.51.100.7:443 HTTP/1.1\r\n\r\n",
		"CONNECT me.example:8080 HTTP/1.1\r\n\r\n",
		"GET http://198.51.100.7:9000/ HTTP/1.1\r\nHost: 198.51.100.7\r\n\r\n",
	} {
		c, err := serviceDialSocket(filepath.Join(R, "egress", coderEgressSock), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte(req))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if !strings.HasPrefix(line, "HTTP/1.1 403") {
			t.Fatalf("%q from a unix pairing's run must be refused: %q", req, line)
		}
	}
}

// ── 4. the workspace engine and the owner's image prefix ────────────────────

func TestTheOwnersImagePrefix(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if !isCoderEngine("workspace") {
		t.Fatal("workspace is a coding engine")
	}
	if (coderConfig{}).imagePrefix() != "git.privatae.ai/privatae-harness/" {
		t.Fatal("the default prefix is today's")
	}
	if b, _ := json.Marshal(coderConfig{Enabled: true}); strings.Contains(string(b), "image_prefix") {
		t.Fatalf("a machine that never set a prefix keeps its file's bytes: %s", b)
	}
	c, err := coderApplySet(coderConfig{}, []string{"--image-prefix", "localhost/privatae-harness/", "--engines", "workspace"}, 4)
	if err != nil || c.ImagePrefix != "localhost/privatae-harness/" || len(c.Engines) != 1 || c.Engines[0] != "workspace" {
		t.Fatalf("set: %+v %v", c, err)
	}
	if d, err := coderApplySet(c, []string{"--image-prefix", "default"}, 4); err != nil || d.ImagePrefix != "" {
		t.Fatalf("default clears it: %+v %v", d, err)
	}
	for _, ok := range []string{"registry.example.com:5000/team/", "local/", "a.b/c-d/e_f/", "privatae-harness/"} {
		if why := coderPrefixRefusal(ok); why != "" {
			t.Errorf("%q: %s", ok, why)
		}
	}
	for _, bad := range []string{"", "no-slash", "Upper/x/", "a//b/", "x@y/", "../", "-a/", "a b/", "/abs/", "a/.b/", strings.Repeat("a", 201) + "/"} {
		if _, err := coderApplySet(coderConfig{}, []string{"--image-prefix", bad}, 4); err == nil {
			t.Errorf("--image-prefix %q must be refused", bad)
		}
	}

	digest := "@sha256:" + strings.Repeat("0f", 32)
	if why := coderImageRefusal("localhost/privatae-harness/harness-workspace"+digest, "workspace", "localhost/privatae-harness/"); why != "" {
		t.Fatal(why)
	}
	for _, bad := range []string{
		coderDefaultImagePrefix + "harness-workspace" + digest, // the default, when the owner set another
		"localhost/privatae-harness/harness-codex" + digest,    // another engine's image
		"localhost/privatae-harness/harness-workspace:latest",  // a tag, not a digest
		"localhost/privatae-harness/harness-workspace@sha256:abc",
		"localhost/privatae-harness/x/harness-workspace" + digest,
	} {
		if why := coderImageRefusal(bad, "workspace", "localhost/privatae-harness/"); why == "" {
			t.Errorf("%q must be refused", bad)
		}
	}

	// Run-up validates against the configured prefix; pull credentials are
	// for that prefix's registry.
	if err := saveCoderConfig(coderConfig{Enabled: true, Max: 2, MemPerRun: 2048, CPUsPerRun: 1,
		Engines: []string{"workspace"}, ImagePrefix: "localhost/privatae-harness/"}); err != nil {
		t.Fatal(err)
	}
	s := upSpec("run-pref-00001", "h")
	s.Engine, s.Image, s.Pull = "workspace", "localhost/privatae-harness/harness-workspace"+digest, nil
	if why := coderSpecRefusal(s); why != "" {
		t.Fatalf("the owner's prefix passes: %s", why)
	}
	s.Pull = &coderPull{Registry: "localhost", Username: "u", Password: "p"}
	if why := coderSpecRefusal(s); why != "" {
		t.Fatalf("credentials for the prefix's registry pass: %s", why)
	}
	s.Pull.Registry = gitForgeHost
	if why := coderSpecRefusal(s); why == "" {
		t.Fatal("credentials for another registry are refused")
	}
	s.Pull, s.Image = nil, testCoderImage
	if why := coderSpecRefusal(s); why == "" {
		t.Fatal("an image under the default prefix is refused once the owner set another")
	}
}

// An image built or loaded on this machine has no repo digest in Docker's
// classic store. It runs by its ID, with no pull and no credentials, when the
// image with that ID carries a tag of the named repository; not when the ID
// differs, or the tag is another repository's.
func TestALocalImageRunsByItsIDWithoutAPull(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	if err := saveCoderConfig(coderConfig{Enabled: true, Max: 4, MemPerRun: 2048, CPUsPerRun: 1,
		Engines: []string{"workspace"}, ImagePrefix: "localhost/privatae-harness/"}); err != nil {
		t.Fatal(err)
	}
	id := "sha256:" + strings.Repeat("7c", 32)
	repo := "localhost/privatae-harness/harness-workspace"
	var answer string
	base := coderRun
	coderRun = func(d time.Duration, name string, args ...string) (string, error) {
		if len(args) == 5 && args[0] == "image" && args[2] == "--format" {
			base(d, name, args...) // recorded, and fails like a missing image
			if args[4] == id && answer != "" {
				return answer, nil
			}
			return "Error: No such image", fmt.Errorf("exit 1")
		}
		return base(d, name, args...)
	}
	spec := func(runID string) harnessSpec {
		s := upSpec(runID, "denz")
		s.Engine, s.Image, s.Pull = "workspace", repo+"@"+id, nil
		return s
	}
	pulls := func() int { return len(f.has("pull")) + len(f.has("--config")) }

	answer = id + `|["` + repo + `:local"]`
	b, code := runCoder(spec("run-local-0001"))
	m := decode(t, b)
	if code != 0 || m["started"] != true || m["local_image_id"] != id || m["pull_s"] != float64(0) || pulls() != 0 {
		t.Fatalf("a local image runs with no pull: %d %s (pulls %d)", code, b, pulls())
	}
	runs := f.has("run")
	if last := runs[len(runs)-1]; last[len(last)-1] != id {
		t.Fatalf("the container starts from the image ID: %v", last[len(last)-1])
	}
	for name, a := range map[string]string{
		"another repository's tag": id + `|["localhost/other/harness-workspace:local"]`,
		"another ID":               "sha256:" + strings.Repeat("aa", 32) + `|["` + repo + `:local"]`,
		"no tag at all":            id + `|[]`,
	} {
		answer = a
		before := pulls()
		b, _ := runCoder(spec("run-local-" + fmt.Sprint(len(name))))
		if pulls() == before {
			t.Fatalf("%s: must not be taken as the image, so it is pulled: %s", name, b)
		}
		if strings.Contains(string(b), "local_image_id") {
			t.Fatalf("%s: %s", name, b)
		}
	}
	if coderTagRepo("registry.example.com:5000/team/harness-workspace:v1") != "registry.example.com:5000/team/harness-workspace" ||
		coderTagRepo("registry.example.com:5000/team/harness-workspace") != "registry.example.com:5000/team/harness-workspace" {
		t.Fatal("a registry port stays in the repository")
	}
}
