//go:build linux

// The serve lane (servelane.go) over a tcp pairing: a Host in a VM on this
// machine reaches the model servers set here by service name, through the
// forwards' own filter, within the lane's bounds, and the pairing's beat says
// what it serves.
//
// Uses the fixtures of local_host_linux_test.go and local_host_tcp_linux_test.go
// (newTestCA, tcpPairingFor, laneListener, pairingBox...), so it carries the
// same build tag.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// serveHost is a Host's lane port as the serve lane meets it: the lane
// port's mutual TLS, every worker route kept parked, each beat recorded
// whole, and each /bastion-serve worker handed to the test once it has sent
// its hello.
type serveHost struct {
	mu      sync.Mutex
	beats   []map[string]any
	hellos  []string
	workers chan *websocket.Conn
}

func startServeHost(t *testing.T, raw net.Listener, cert tls.Certificate, clientCA *testCA) *serveHost {
	t.Helper()
	h := &serveHost{workers: make(chan *websocket.Conn, 64)}
	pool := x509.NewCertPool()
	pool.AddCert(clientCA.cert)
	ln := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert})
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/network/bastions/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		h.mu.Lock()
		h.beats = append(h.beats, m)
		h.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	})
	mux.HandleFunc("/bastion-serve", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_, hello, err := c.ReadMessage()
		if err != nil {
			c.Close()
			return
		}
		h.mu.Lock()
		h.hellos = append(h.hellos, string(hello))
		h.mu.Unlock()
		h.workers <- c // the test owns it from here
	})
	park := func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}
	for _, p := range []string{"/bastion-harness", "/bastion-mgmt", "/bastion-egress"} {
		mux.HandleFunc(p, park)
	}
	srv := &http.Server{Handler: mux, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		for {
			select {
			case c := <-h.workers:
				c.Close()
			default:
				return
			}
		}
	})
	return h
}

// take is the next parked serve worker.
func (h *serveHost) take(t *testing.T) *websocket.Conn {
	t.Helper()
	select {
	case c := <-h.workers:
		t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("no /bastion-serve worker parked on the Host within 10 s")
	}
	return nil
}

// ask sends the 'S' frame for service and returns the bastion's answer: "A",
// or "E" and the reason.
func ask(t *testing.T, c *websocket.Conn, service string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"service": service})
	return askRaw(t, c, websocket.BinaryMessage, append([]byte{'S'}, b...))
}

func askRaw(t *testing.T, c *websocket.Conn, mt int, frame []byte) string {
	t.Helper()
	if err := c.WriteMessage(mt, frame); err != nil {
		t.Fatalf("send the first frame: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, m, err := c.ReadMessage()
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatalf("no answer to the first frame: %v", err)
	}
	return string(m)
}

// beat is the first beat the Host received, waiting up to 10 s.
func (h *serveHost) beat(t *testing.T) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		if len(h.beats) > 0 {
			b := h.beats[0]
			h.mu.Unlock()
			return b
		}
		h.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no heartbeat reached the Host within 10 s")
	return nil
}

// runInBackground runs the pairing until the test ends.
func runInBackground(t *testing.T, cfg *Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runPairing(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the pairing did not stop")
		}
		// A stopped (revoked) pairing's streams end with it: each one's worker
		// is closed. Waited for here too because a stream's last act is its
		// audit line, in the pairing's directory, which the test then removes.
		deadline := time.Now().Add(5 * time.Second)
		for {
			v, ok := serveInFlight.Load(cfg.HostName)
			if !ok || v.(*atomic.Int32).Load() == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d streams still open 5 s after the pairing stopped", v.(*atomic.Int32).Load())
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// serveLaneBox is an unanchored local machine with a tcp pairing to a
// stand-in Host on 127.0.0.1, running. host keeps each test's pairing (and its
// stream count) its own.
func serveLaneBox(t *testing.T, host string) (*serveHost, *Config) {
	t.Helper()
	pairingBox(t)
	laneTestProcess(t)
	ca := newTestCA(t, "home host CA")
	ln := laneListener(t)
	h := startServeHost(t, ln, ca.serverCert(t, tcpServerName), ca)
	cfg := tcpPairingFor(t, ca, host, ln.Addr().String())
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	return h, cfg
}

// laneConn is the Host's end of an accepted job: 'D' frames both ways, 'E'
// for the end, as the Host's relay frames a spliced connection.
func laneConn(c *websocket.Conn) net.Conn { return &wsConn{ws: c} }

// chatRequest writes one streaming chat request on conn and returns the reader
// its response is read from.
func chatRequest(t *testing.T, conn net.Conn, model string) (*http.Response, *http.Request) {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"hello"}]}`, model)
	req, _ := http.NewRequest(http.MethodPost, "http://serve/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(conn); err != nil {
		t.Fatalf("write the request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read the response: %v", err)
	}
	return resp, req
}

// ── 1. a chat streams ───────────────────────────────────────────────────────

// streamingServer is a stand-in OpenAI-compatible server. Its chat answer is
// three chunks; after the first it waits until the test says the Host has
// read it, and records whether it had to give up waiting.
type streamingServer struct {
	srv      *httptest.Server
	sawFirst chan struct{}
	gated    atomic.Bool
	seen     atomic.Int32
}

func newStreamingServer(t *testing.T) *streamingServer {
	t.Helper()
	s := &streamingServer{sawFirst: make(chan struct{})}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.seen.Add(1)
		switch r.URL.Path {
		case "/v1/chat/completions":
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"test-model:latest"}]}`))
			return
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"chunk\":1}\n\n")
		fl.Flush()
		select {
		case <-s.sawFirst:
			s.gated.Store(true)
		case <-time.After(10 * time.Second):
		}
		_, _ = io.WriteString(w, "data: {\"chunk\":2}\n\n")
		fl.Flush()
		_, _ = io.WriteString(w, "data: {\"chunk\":3}\n\n")
		fl.Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// SECURITY (and the lane's purpose): over a tcp pairing, the Host asks for a
// service by name and a chat streams from the server set here. The Host reads
// chunk 1 before the server writes chunk 3, so nothing in the path holds a
// response back: not the lane's framing, not the pass-through an unscoped
// pairing gets, not the filter a pairing without `models` gets.
//
// MUTATION: drop the serve workers from runUnixPairing.
// RESULT: red — no /bastion-serve worker ever parks on the Host.
func TestTheServeLaneStreamsAChatOverATCPPairing(t *testing.T) {
	for _, c := range []struct {
		name, service, env string
		modelsOff          bool
	}{
		{"llm, passed through", "llm", "PRIVATAE_LLM_ADDR", false},
		{"ollama, through the filter", "ollama", "OLLAMA_ADDR", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStreamingServer(t)
			t.Setenv(c.env, s.srv.Listener.Addr().String())
			h, cfg := serveLaneBox(t, "stream-"+c.service+".example.test")
			if c.modelsOff {
				if err := localDenySet(cfg.HostName, "models", true); err != nil {
					t.Fatal(err)
				}
				if !inferenceFilterNeeded(cfg.HostName, laneOllama, pairingModelScope(cfg.HostName)) {
					t.Fatal("with models off the ollama lane must be filtered, or this case proves nothing")
				}
			}
			runInBackground(t, cfg)
			ws := h.take(t)
			if got := ask(t, ws, c.service); got != "A" {
				t.Fatalf("the lane must accept %s: %q", c.service, got)
			}
			conn := laneConn(ws)
			resp, _ := chatRequest(t, conn, "test-model")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("the chat answered %d", resp.StatusCode)
			}
			br := bufio.NewReader(resp.Body)
			var got []string
			first := false
			for {
				line, err := br.ReadString('\n')
				if strings.HasPrefix(line, "data: ") {
					got = append(got, strings.TrimSpace(line))
					if !first && strings.Contains(line, `"chunk":1`) {
						first = true
						close(s.sawFirst)
					}
				}
				if err != nil || strings.Contains(line, "[DONE]") {
					break
				}
			}
			if !first {
				t.Fatalf("the stream never carried chunk 1: %q", got)
			}
			if !s.gated.Load() {
				t.Fatal("the server wrote chunk 3 before the Host read chunk 1: the lane held the stream back")
			}
			want := []string{`data: {"chunk":1}`, `data: {"chunk":2}`, `data: {"chunk":3}`, `data: [DONE]`}
			if !slices.Equal(got, want) {
				t.Fatalf("the stream arrived as %q", got)
			}
		})
	}
}

// ── 2. a service, never an address ──────────────────────────────────────────

// SECURITY: the Host names a service and the target is the one set on this
// machine. A first frame naming an address, a name the lane does not carry, a
// frame that is not 'S', a target set to a computer that is not this one, and
// a service with no target each answer 'E' with a reason, and nothing is
// dialled: a listener at the address named gets no connection.
//
// MUTATION: in serveVetTarget, skip the ownDestination check.
// RESULT: red — ollama with OLLAMA_ADDR on another computer is accepted.
func TestTheServeLaneTakesAServiceNameNeverAnAddress(t *testing.T) {
	named, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer named.Close()
	var reached atomic.Int32
	go func() {
		for {
			c, err := named.Accept()
			if err != nil {
				return
			}
			reached.Add(1)
			c.Close()
		}
	}()
	t.Setenv("OLLAMA_ADDR", "192.0.2.10:11434") // TEST-NET-1: never this machine
	t.Setenv("PRIVATAE_LLM_ADDR", "")
	t.Setenv("PRIVATAE_PII_ADDR", "198.51.100.7:"+portOf(named))
	h, cfg := serveLaneBox(t, "names.example.test")
	runInBackground(t, cfg)

	for _, c := range []struct {
		name  string
		frame []byte
		mt    int
		want  []string
	}{
		{"an address for a service", sFrame(named.Addr().String()), websocket.BinaryMessage,
			[]string{"Erefused: ", "never takes an address"}},
		{"a name the lane does not carry", sFrame("nas"), websocket.BinaryMessage,
			[]string{"Erefused: ", `"nas" is not a service`}},
		{"a URL for a service", sFrame("http://" + named.Addr().String() + "/api/tags"), websocket.BinaryMessage,
			[]string{"Erefused: ", "is not a service"}},
		{"a frame that is not S", []byte("D" + "GET / HTTP/1.1\r\n\r\n"), websocket.BinaryMessage,
			[]string{"Erefused: ", "the first frame on this lane is 'S'"}},
		{"a text frame", []byte(`S{"service":"ollama"}`), websocket.TextMessage,
			[]string{"Erefused: ", "the first frame on this lane is 'S'"}},
		{"an S frame past its bound", append(sFrame("ollama"), make([]byte, serveHelloMax)...), websocket.BinaryMessage,
			[]string{"Erefused: ", "at most 1024 bytes"}},
		{"ollama set to another computer", sFrame("ollama"), websocket.BinaryMessage,
			[]string{"Erefused: ", "OLLAMA_ADDR", "192.0.2.10 is not this machine"}},
		{"pii set to another computer", sFrame("pii"), websocket.BinaryMessage,
			[]string{"Erefused: ", "PRIVATAE_PII_ADDR", "198.51.100.7 is not this machine"}},
		{"llm with nothing set", sFrame("llm"), websocket.BinaryMessage,
			[]string{"Eunavailable: ", "PRIVATAE_LLM_ADDR"}},
	} {
		ws := h.take(t)
		got := askRaw(t, ws, c.mt, c.frame)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: the answer %q does not carry %q", c.name, got, w)
			}
		}
		if !strings.HasPrefix(got, "E") {
			t.Errorf("%s: answered %q, not E", c.name, got)
		}
		// Refused means closed: nothing after the E.
		_ = ws.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, m, err := ws.ReadMessage(); err == nil {
			t.Errorf("%s: the worker carried on after its refusal: %q", c.name, m)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := reached.Load(); n != 0 {
		t.Fatalf("a refused job dialled the address it named (%d connections)", n)
	}
}

func sFrame(service string) []byte {
	b, _ := json.Marshal(map[string]string{"service": service})
	return append([]byte{'S'}, b...)
}

func portOf(ln net.Listener) string {
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}

// A target set by name is resolved and each address checked; the addresses
// dialled are the ones checked, every one of them, in the resolver's order.
// 0.0.0.0 is a listen address and dials as loopback (once, if loopback is
// there already). This machine's own interface address passes.
func TestServeVetTargetChecksEveryAddressItWouldDial(t *testing.T) {
	old := serveLookupIP
	t.Cleanup(func() { serveLookupIP = old })
	serveLookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "localhost":
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}}, nil
		case "v6first.example.test":
			return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("0.0.0.0")}}, nil
		case "mixed.example.test":
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("192.0.2.10")}}, nil
		}
		return nil, fmt.Errorf("no such host")
	}
	for target, want := range map[string][]string{
		"127.0.0.1:11434":          {"127.0.0.1:11434"},
		"[::1]:8080":               {"[::1]:8080"},
		"0.0.0.0:11434":            {"127.0.0.1:11434"},
		"[::]:11434":               {"[::1]:11434"},
		"localhost:11434":          {"127.0.0.1:11434", "[::1]:11434"},
		"v6first.example.test:80":  {"[::1]:80", "127.0.0.1:80"},
		"mixed.example.test:11434": nil,
		"nowhere.example.test:80":  nil,
		"192.0.2.10:11434":         nil,
		"198.51.100.9:80":          nil,
		"127.0.0.1":                nil,
		"127.0.0.1:0":              nil,
		"127.0.0.1:99999":          nil,
	} {
		got, why := serveVetTarget(target)
		if !slices.Equal(got, want) || (want == nil) != (why != "") {
			t.Errorf("%q: dial %q (%q), want %q", target, got, why, want)
		}
	}
	ips, err := ownInterfaceIPs()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		a := net.JoinHostPort(ip.String(), "11434")
		if got, why := serveVetTarget(a); !slices.Equal(got, []string{a}) {
			t.Errorf("this machine's own address %s is refused: %q", a, why)
		}
	}
}

// ── 3. the forwards' walls, unchanged ───────────────────────────────────────

// SECURITY: the lane keeps every wall the tunnel forwards keep. With
// `inference` switched off at this machine, a job is refused before any dial.
// With `models` off, /api/pull and /api/delete are refused 403 and never reach
// ollama, while a chat does. On an anchored machine they are refused to the
// anchor itself. A pairing scoped to a model is refused another one with 403,
// which never reaches the server, and is served its own.
func TestTheServeLaneKeepsTheForwardsWalls(t *testing.T) {
	t.Run("inference off at the machine", func(t *testing.T) {
		// A raw listener, so a dial by the serve job is seen even though the
		// Host sends it nothing: a connection that does not open with a beat's
		// probe (GET /api/tags, which any pairing's beat in this process may
		// send to OLLAMA_ADDR) is the job's.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		var jobDials atomic.Int32
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					b := make([]byte, len("GET /api/tags "))
					if _, err := io.ReadFull(c, b); err != nil || string(b) != "GET /api/tags " {
						jobDials.Add(1)
					}
				}()
			}
		}()
		t.Setenv("OLLAMA_ADDR", ln.Addr().String())
		h, cfg := serveLaneBox(t, "walls-off.example.test")
		if err := localDenySet(cfg.HostName, "inference", true); err != nil {
			t.Fatal(err)
		}
		runInBackground(t, cfg)
		got := ask(t, h.take(t), "ollama")
		if !strings.HasPrefix(got, "Erefused: ") {
			t.Fatalf("with inference off the job must be refused: %q", got)
		}
		time.Sleep(2500 * time.Millisecond)
		if n := jobDials.Load(); n != 0 {
			t.Fatalf("a refused job dialled ollama (%d connections)", n)
		}
	})
	pullAndDelete := func(t *testing.T, h *serveHost, up *fakeOllama) {
		t.Helper()
		for _, p := range []string{"/api/pull", "/api/delete"} {
			ws := h.take(t)
			if got := ask(t, ws, "ollama"); got != "A" {
				t.Fatalf("%s: the job must be accepted, and refused by the filter: %q", p, got)
			}
			conn := laneConn(ws)
			req, _ := http.NewRequest(http.MethodPost, "http://serve"+p, strings.NewReader(`{"model":"test-model"}`))
			if err := req.Write(conn); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "models") {
				t.Fatalf("%s over the lane: %d %s", p, resp.StatusCode, b)
			}
		}
		for _, s := range up.requests() {
			if strings.Contains(s, "/api/pull") || strings.Contains(s, "/api/delete") {
				t.Fatalf("a refused store request reached ollama: %q", up.requests())
			}
		}
	}
	t.Run("models off at the machine", func(t *testing.T) {
		up := newFakeOllama(t)
		t.Setenv("OLLAMA_ADDR", up.srv.Listener.Addr().String())
		h, cfg := serveLaneBox(t, "walls-models.example.test")
		if err := localDenySet(cfg.HostName, "models", true); err != nil {
			t.Fatal(err)
		}
		runInBackground(t, cfg)
		pullAndDelete(t, h, up)
	})
	t.Run("an anchored machine, as its anchor", func(t *testing.T) {
		up := newFakeOllama(t)
		t.Setenv("OLLAMA_ADDR", up.srv.Listener.Addr().String())
		h, cfg := serveLaneBox(t, "walls-anchor.example.test")
		p, _ := modePath()
		if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeAnchor("Acme IT", cfg.HostName); err != nil {
			t.Fatal(err)
		}
		if currentAnchor() == nil || capsAllow(cfg.HostName, "inference") != "" {
			t.Fatal("the pairing must be this machine's anchor, holding inference, or this case proves nothing")
		}
		runInBackground(t, cfg)
		pullAndDelete(t, h, up)
	})
	t.Run("a pairing scoped to one model", func(t *testing.T) {
		priv := setupBox(t)
		withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
		laneTestProcess(t)
		up := newFakeOllama(t)
		t.Setenv("PRIVATAE_LLM_ADDR", up.srv.Listener.Addr().String())
		ca := newTestCA(t, "home host CA")
		ln := laneListener(t)
		h := startServeHost(t, ln, ca.serverCert(t, tcpServerName), ca)
		member := tcpPairingFor(t, ca, tMember, ln.Addr().String())
		member.State = pairingPending
		if err := member.save(); err != nil {
			t.Fatal(err)
		}
		syncGrant(t, priv, tMember, []string{"inference"}, []string{"qwen4-embed"})
		cfgs, err := loadPairings()
		if err != nil {
			t.Fatal(err)
		}
		cfg := pairingFor(cfgs, tMember)
		if cfg == nil || !cfg.active() || !cfg.tcpTransport() {
			t.Fatalf("the member's tcp pairing must be active after the grant: %+v", cfg)
		}
		runInBackground(t, cfg)
		for model, want := range map[string]int{"llama3:70b": http.StatusForbidden, "qwen4-embed": http.StatusOK} {
			ws := h.take(t)
			if got := ask(t, ws, "llm"); got != "A" {
				t.Fatalf("the member holds inference, so the job is accepted: %q", got)
			}
			resp, _ := chatRequest(t, laneConn(ws), model)
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != want {
				t.Fatalf("%s over the scoped lane: %d %s", model, resp.StatusCode, b)
			}
		}
		chats := 0
		for _, s := range up.requests() {
			if s == "POST /v1/chat/completions" {
				chats++
			}
		}
		if chats != 1 {
			t.Fatalf("only the scoped model's request may reach the server: %q", up.requests())
		}
	})
}

// ── 4. the bounds ───────────────────────────────────────────────────────────

// SECURITY: one pairing holds at most 16 streams open here. Sixteen run at
// once; the 17th is answered 'E' busy with the reason and dials nothing; once
// one ends, the next is accepted.
func TestTheServeLaneHoldsSixteenStreamsAndRefusesTheSeventeenth(t *testing.T) {
	var held, opened atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			_, _ = w.Write([]byte(`{}`)) // the beat's probe
			return
		}
		opened.Add(1)
		held.Add(1)
		defer held.Add(-1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"chunk\":1}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	t.Setenv("PRIVATAE_LLM_ADDR", srv.Listener.Addr().String())
	h, cfg := serveLaneBox(t, "sixteen.example.test")
	runInBackground(t, cfg)

	var streams []*websocket.Conn
	for i := 0; i < serveMaxInFlight; i++ {
		ws := h.take(t)
		if got := ask(t, ws, "llm"); got != "A" {
			t.Fatalf("stream %d of %d must be accepted: %q", i+1, serveMaxInFlight, got)
		}
		resp, _ := chatRequest(t, laneConn(ws), "test-model")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream %d: %d", i+1, resp.StatusCode)
		}
		streams = append(streams, ws)
	}
	if n := held.Load(); n != serveMaxInFlight {
		t.Fatalf("the server holds %d streams, want %d at once", n, serveMaxInFlight)
	}
	got := ask(t, h.take(t), "llm")
	if !strings.HasPrefix(got, "Ebusy: ") || !strings.Contains(got, "16 streams") {
		t.Fatalf("the 17th stream must be answered busy with the reason: %q", got)
	}
	if n := opened.Load(); n != serveMaxInFlight {
		t.Fatalf("the refused 17th reached the server (%d requests)", n)
	}
	// One ends; the next is accepted.
	streams[0].Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ws := h.take(t)
		got := ask(t, ws, "llm")
		if got == "A" {
			break
		}
		if !strings.HasPrefix(got, "Ebusy: ") || time.Now().After(deadline) {
			t.Fatalf("after a stream ended the next must be accepted: %q", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// SECURITY: a stream with no byte either way for the idle bound is closed,
// both ends, on a pass-through and through the filter: a server that answers
// headers and then nothing does not hold the stream (or this machine's slot)
// for ever. A stream that keeps sending, for several times the bound, is not
// cut: the bound is on silence, never on a response's length.
func TestTheServeLaneClosesAStreamIdleForTheBound(t *testing.T) {
	old := serveIdleTimeout
	serveIdleTimeout = 400 * time.Millisecond
	t.Cleanup(func() { serveIdleTimeout = old })

	// silent answers headers and then holds the connection, recording when
	// this machine closes it.
	silentClosed := make(chan time.Time, 4)
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.URL.Path != "/v1/chat/completions" {
					// The beat's probes get an ordinary answer.
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
				_, _ = io.Copy(io.Discard, br)
				silentClosed <- time.Now()
			}(c)
		}
	}()
	// steady sends a chunk every 100 ms for 1.6 s: four times the bound.
	steady := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 1; i <= 16; i++ {
			fmt.Fprintf(w, "data: {\"chunk\":%d}\n\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(steady.Close)

	for _, c := range []struct {
		name, service, env string
		modelsOff          bool
	}{
		{"a pass-through", "llm", "PRIVATAE_LLM_ADDR", false},
		{"through the filter", "ollama", "OLLAMA_ADDR", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(c.env, silent.Addr().String())
			h, cfg := serveLaneBox(t, "idle-"+c.service+".example.test")
			if c.modelsOff {
				if err := localDenySet(cfg.HostName, "models", true); err != nil {
					t.Fatal(err)
				}
			}
			runInBackground(t, cfg)
			ws := h.take(t)
			if got := ask(t, ws, c.service); got != "A" {
				t.Fatalf("accept: %q", got)
			}
			conn := laneConn(ws)
			resp, _ := chatRequest(t, conn, "test-model")
			start := time.Now()
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, err := io.Copy(io.Discard, resp.Body)
			took := time.Since(start)
			if err == nil {
				t.Fatal("a silent stream must end in a close, not a complete answer")
			}
			if took < 300*time.Millisecond || took > 3*time.Second {
				t.Fatalf("the silent stream was closed after %v; the bound is %v", took, serveIdleTimeout)
			}
			select {
			case <-silentClosed:
			case <-time.After(3 * time.Second):
				t.Fatal("the server's end of the silent stream was left open")
			}

			t.Setenv(c.env, steady.Listener.Addr().String())
			ws = h.take(t)
			if got := ask(t, ws, c.service); got != "A" {
				t.Fatalf("accept: %q", got)
			}
			resp, _ = chatRequest(t, laneConn(ws), "test-model")
			b, err := io.ReadAll(resp.Body)
			if err != nil || !strings.Contains(string(b), `"chunk":16`) || !strings.Contains(string(b), "[DONE]") {
				t.Fatalf("a stream that keeps sending was cut: %v %q", err, b)
			}
		})
	}
}

// ── 5. the beat says what is served ─────────────────────────────────────────

func capsOf(m map[string]any) []string {
	var out []string
	if l, ok := m["capabilities"].([]any); ok {
		for _, c := range l {
			out = append(out, fmt.Sprint(c))
		}
	}
	return out
}

func strsOf(v any) []string {
	out := []string{}
	if l, ok := v.([]any); ok {
		for _, c := range l {
			out = append(out, fmt.Sprint(c))
		}
	}
	return out
}

// SECURITY (an honest beat): a tcp pairing's beat lists in lane_serves what
// its serve lane carries, and advertises a model lane only when its service
// is there. With ollama answering here, llm unset and pii set to another
// computer, the beat carries lane_serves ["ollama"] and `embed` with its
// models, and no `llm-openai`, `pii`, pii_port, llm_port, `services` or
// `coders`, none of which runs on a tcp pairing. With all three served, all
// three are listed and advertised, pii_ok with them and pii_port still not. A
// unix pairing's beat lists its lane too and keeps `coders` (its runs have a
// socket); a tunnel pairing's beat has no lane_serves.
//
// MUTATION: have heartbeatPayload call buildHeartbeatBody (the tunnel's beat).
// RESULT: red — no lane_serves, and pii and services advertised with nothing
// serving them.
func TestATCPPairingsBeatAdvertisesOnlyWhatItServes(t *testing.T) {
	up := newFakeOllama(t)
	t.Setenv("OLLAMA_ADDR", up.srv.Listener.Addr().String())
	t.Setenv("PRIVATAE_LLM_ADDR", "")
	t.Setenv("PRIVATAE_PII_ADDR", "192.0.2.10:9")
	stubServiceRuntime(t, "docker")
	stubCoders(t)
	h, cfg := serveLaneBox(t, "beat.example.test")
	coderOn(t, 2)
	if !servicesCapable(cfg.HostName) || coderHeartbeat(cfg.HostName) == nil {
		t.Fatal("the slots and coder runs must be available on this machine, or their absence proves nothing")
	}
	runInBackground(t, cfg)
	beat := h.beat(t)
	caps := capsOf(beat)
	if got := strsOf(beat["lane_serves"]); !slices.Equal(got, []string{"ollama"}) {
		t.Fatalf("lane_serves: %q (the beat: %v)", got, beat)
	}
	if !slices.Contains(caps, "embed") || !slices.Contains(strsOf(beat["models"]), "qwen4-embed:latest") {
		t.Fatalf("ollama is served, so embed and its models are advertised: %q %v", caps, beat["models"])
	}
	for _, c := range []string{"llm-openai", "pii", serviceCapability, coderCapability} {
		if slices.Contains(caps, c) {
			t.Errorf("a tcp pairing advertises %q, which nothing serves on it: %q", c, caps)
		}
	}
	for _, k := range []string{"pii_port", "pii_ok", "services", "coders"} {
		if _, ok := beat[k]; ok {
			t.Errorf("a tcp pairing's beat carries %q: %v", k, beat[k])
		}
	}
	if beat["llm_port"] != float64(0) {
		t.Errorf("no port listens for the llm server on a tcp pairing: llm_port %v", beat["llm_port"])
	}

	// All three served.
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(health.Close)
	t.Setenv("PRIVATAE_LLM_ADDR", up.srv.Listener.Addr().String())
	t.Setenv("PRIVATAE_PII_ADDR", health.Listener.Addr().String())
	var all map[string]any
	if err := json.Unmarshal([]byte(heartbeatPayload(cfg, nil, "box", "pub")), &all); err != nil {
		t.Fatal(err)
	}
	if got := strsOf(all["lane_serves"]); !slices.Equal(got, []string{"ollama", "llm", "pii"}) {
		t.Fatalf("lane_serves with all three set: %q", got)
	}
	caps = capsOf(all)
	for _, c := range []string{"embed", "llm-openai", "pii"} {
		if !slices.Contains(caps, c) {
			t.Errorf("%q is served, so it is advertised: %q", c, caps)
		}
	}
	if all["pii_ok"] != true || all["pii_port"] != nil || !slices.Contains(strsOf(all["llm_models"]), "qwen4-embed") {
		t.Errorf("pii_ok %v, pii_port %v, llm_models %v", all["pii_ok"], all["pii_port"], all["llm_models"])
	}

	// A unix pairing: its lane, and its coder runs (a socket each).
	unix := *cfg
	unix.Transport, unix.LaneAddr, unix.LaneSocket, unix.RunsDir = transportUnix, "", "/run/privatae-host/lane.sock", "/run/privatae-host/runs"
	var u map[string]any
	_ = json.Unmarshal([]byte(heartbeatPayload(&unix, nil, "box", "pub")), &u)
	if _, ok := u["lane_serves"]; !ok || slices.Contains(capsOf(u), serviceCapability) || !slices.Contains(capsOf(u), coderCapability) {
		t.Errorf("a unix pairing: lane_serves %v, caps %q", u["lane_serves"], capsOf(u))
	}
	// A tunnel pairing: the forwards, no lane.
	tunnel := *cfg
	tunnel.Transport, tunnel.LaneAddr = "", ""
	var tb map[string]any
	_ = json.Unmarshal([]byte(heartbeatPayload(&tunnel, nil, "box", "pub")), &tb)
	if _, ok := tb["lane_serves"]; ok || tb["pii_port"] != float64(piiForwardPort) {
		t.Errorf("a tunnel pairing: lane_serves %v, pii_port %v", tb["lane_serves"], tb["pii_port"])
	}
}

// The lane writes one audit line per job: the service, the address dialled
// and the bytes each way for a served one; the reason for a refused one.
func TestTheServeLaneAuditsEachJob(t *testing.T) {
	up := newFakeOllama(t)
	t.Setenv("OLLAMA_ADDR", up.srv.Listener.Addr().String())
	h, cfg := serveLaneBox(t, "audit.example.test")
	runInBackground(t, cfg)
	ws := h.take(t)
	if got := ask(t, ws, "ollama"); got != "A" {
		t.Fatalf("accept: %q", got)
	}
	conn := laneConn(ws)
	req, _ := http.NewRequest(http.MethodGet, "http://serve/api/tags", nil)
	req.Close = true
	_ = req.Write(conn)
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	ws.Close()
	if got := ask(t, h.take(t), "10.0.0.2:11434"); !strings.HasPrefix(got, "E") {
		t.Fatalf("refuse: %q", got)
	}
	path := filepath.Join(cfg.dcnDir(), "audit.jsonl")
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, _ := os.ReadFile(path)
		var served, refused map[string]any
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil || m["op"] != "serve" {
				continue
			}
			switch m["decision"] {
			case "served":
				served = m
			case "refused":
				refused = m
			}
		}
		if served != nil && refused != nil {
			if served["service"] != "ollama" || served["target"] != up.srv.Listener.Addr().String() ||
				served["bytes_from_host"].(float64) <= 0 || served["bytes_to_host"].(float64) <= 0 {
				t.Fatalf("the served line: %v", served)
			}
			if !strings.Contains(fmt.Sprint(refused["reason"]), "never takes an address") {
				t.Fatalf("the refused line: %v", refused)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no served and refused lines in %s: %s", path, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
