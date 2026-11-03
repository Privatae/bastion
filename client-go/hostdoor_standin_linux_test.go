//go:build linux

package main

// A stand-in for a Host that connects to a server (docs/host-connects.md):
// it pairs through a window with the code, then keeps hostSpareConns idle
// lane connections open to the server's door and serves the lane routes of
// newLaneHost over them. The end-to-end run (hostdoor_e2e_linux_test.go)
// runs it in a network namespace behind a NAT.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hostSpareConns is how many idle connections the stand-in keeps open, the
// number docs/host-connects.md asks a Host to keep.
const hostSpareConns = 4

type standinHost struct {
	ca     *testCA
	handle string
	name   string
	server string // the door, host:port

	// pairing
	pairLeaf tls.Certificate // leaf + CA, as a pairing presents them
	lieLeaf  bool            // prove over another certificate (a relayed proof)
	badProof bool            // check the bastion's proof against the wrong code
	bearerN  atomic.Int32
	mu       sync.Mutex
	done     []windowDoneReq
	csrs     int

	// lanes
	lane    *laneHost
	handler http.Handler
	laneTLS *tls.Config
	dials   atomic.Int32
	idle    atomic.Int32
	open    atomic.Int32
}

func newStandinHost(t *testing.T, ca *testCA, handle, name, server string) *standinHost {
	t.Helper()
	pl := ca.serverCert(t, tcpServerName)
	pl.Certificate = append(pl.Certificate, ca.cert.Raw)
	h := &standinHost{ca: ca, handle: handle, name: name, server: server, pairLeaf: pl}
	h.lane, h.handler, h.laneTLS = newLaneHost(ca.serverCert(t, tcpServerName), ca)
	return h
}

// pair connects to the door and pairs with code. It returns what the
// bastion's done said, or the error that ended the exchange.
func (h *standinHost) pair(code string) (windowDoneReq, error) {
	norm := normalizeWindowCode(code)
	raw, err := net.DialTimeout("tcp", h.server, 5*time.Second)
	if err != nil {
		return windowDoneReq{}, err
	}
	tc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{h.pairLeaf}, NextProtos: []string{pairALPN},
		MinVersion: tls.VersionTLS13})
	_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return windowDoneReq{}, fmt.Errorf("handshake: %w", err)
	}
	leafSum := sha256.Sum256(h.pairLeaf.Certificate[0])
	if h.lieLeaf {
		leafSum = sha256.Sum256([]byte("another connection's certificate"))
	}
	caSum := sha256.Sum256(h.ca.cert.Raw)
	var nb, nh []byte
	gotDone := make(chan windowDoneReq, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pair/hello", func(w http.ResponseWriter, r *http.Request) {
		var req windowHelloReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		nb, _ = hex.DecodeString(req.Nonce)
		nh = make([]byte, 32)
		_, _ = rand.Read(nh)
		_ = json.NewEncoder(w).Encode(windowHelloResp{V: 1, HostHandle: h.handle, HostName: h.name,
			Nonce: hex.EncodeToString(nh), Proof: windowProof(norm, "host", leafSum[:], caSum[:], nb, nh)})
	})
	mux.HandleFunc("/v1/pair/redeem", func(w http.ResponseWriter, r *http.Request) {
		var req windowRedeemReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		key := norm
		if h.badProof {
			key = "0000000000000000000Z"
		}
		real := sha256.Sum256(h.pairLeaf.Certificate[0])
		if req.Proof != windowProof(key, "bastion", real[:], caSum[:], nb, nh) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "this server did not prove the code"})
			return
		}
		h.mu.Lock()
		h.csrs++
		h.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"operator_cert": h.ca.signCSR(req.OperatorCSR), "ca_cert": h.ca.pem,
			"bearer": fmt.Sprintf("mcp_dials_%s_%d", h.handle, h.bearerN.Add(1)), "transport": windowTransport,
			"host_handle": h.handle, "host_name": h.name})
	})
	mux.HandleFunc("/v1/pair/done", func(w http.ResponseWriter, r *http.Request) {
		var req windowDoneReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		h.mu.Lock()
		h.done = append(h.done, req)
		h.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
		gotDone <- req
	})
	ln := &oneConnListener{c: tc, closed: make(chan struct{})}
	srv := &http.Server{Handler: mux, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	select {
	case d := <-gotDone:
		return d, nil
	case <-ln.gone():
		return windowDoneReq{}, errors.New("the server closed the pairing connection")
	case <-time.After(20 * time.Second):
		return windowDoneReq{}, errors.New("no done within 20 s")
	}
}

// oneConnListener hands out one connection, then blocks until closed.
type oneConnListener struct {
	c      net.Conn
	once   sync.Once
	closed chan struct{}
	cmu    sync.Mutex
	shut   bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = &watchClose{Conn: l.c, l: l} })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) gone() <-chan struct{} { return l.closed }

func (l *oneConnListener) Close() error {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	if !l.shut {
		l.shut = true
		close(l.closed)
	}
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

type watchClose struct {
	net.Conn
	l *oneConnListener
}

func (w *watchClose) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	var ne net.Error
	if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
		_ = w.l.Close() // the http server's own read aborts are timeouts
	}
	return n, err
}

// serveLanes keeps hostSpareConns idle connections open to the door until
// ctx ends, serving the lane routes over each, and closes them all at the end
// (a Host that stops). Redials back off from 100 ms to 2 s.
func (h *standinHost) serveLanes(ctx context.Context) {
	acc := make(chan net.Conn)
	ln := &chanListener{c: acc, done: ctx.Done(), addr: &net.TCPAddr{}}
	srv := &http.Server{Handler: h.handler, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(ln) }()
	var all sync.Map
	kick := make(chan struct{}, 64)
	wait := 100 * time.Millisecond
	for ctx.Err() == nil {
		if h.idle.Load() >= hostSpareConns || h.open.Load() >= 64 {
			select {
			case <-kick:
			case <-time.After(time.Second):
			case <-ctx.Done():
			}
			continue
		}
		h.dials.Add(1)
		d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 25 * time.Second}
		raw, err := d.DialContext(ctx, "tcp", h.server)
		if err == nil {
			tc := tls.Server(raw, h.laneTLS)
			_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
			if err = tc.HandshakeContext(ctx); err == nil {
				_ = tc.SetDeadline(time.Time{})
				h.idle.Add(1)
				h.open.Add(1)
				c := &usedConn{Conn: tc, h: h, kick: kick}
				all.Store(c, true)
				select {
				case acc <- c:
				case <-ctx.Done():
					_ = c.Close()
				}
				wait = 100 * time.Millisecond
				continue
			}
			_ = raw.Close()
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
		wait = min(2*wait, 2*time.Second)
	}
	_ = srv.Close()
	all.Range(func(k, _ any) bool { _ = k.(*usedConn).Close(); return true })
}

// usedConn tells the stand-in when a lane first speaks on a connection (it
// is no longer idle) and when it closes.
type usedConn struct {
	net.Conn
	h      *standinHost
	kick   chan struct{}
	used   atomic.Bool
	closed atomic.Bool
}

func (c *usedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.used.CompareAndSwap(false, true) {
		c.h.idle.Add(-1)
		c.nudge()
	}
	return n, err
}

func (c *usedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.used.CompareAndSwap(false, true) {
			c.h.idle.Add(-1)
		}
		c.h.open.Add(-1)
		c.nudge()
	}
	return c.Conn.Close()
}

func (c *usedConn) nudge() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

type chanListener struct {
	c    chan net.Conn
	done <-chan struct{}
	addr net.Addr
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

// TestStandinHostProcess is the stand-in as a process of its own, for the
// end-to-end run behind a NAT (scripts/e2e-host-connects.sh) and on another
// machine's bastion. Skipped unless STANDIN_MODE is set:
//
//	STANDIN_MODE=pair  STANDIN_STATE=<dir> STANDIN_SERVER=<host:port> STANDIN_CODE=<code>
//	STANDIN_MODE=serve STANDIN_STATE=<dir> STANDIN_SERVER=<host:port>
//
// The CA is kept in STANDIN_STATE, so a restarted stand-in is the same Host.
func TestStandinHostProcess(t *testing.T) {
	mode := os.Getenv("STANDIN_MODE")
	if mode == "" {
		t.Skip("the stand-in Host process (scripts/e2e-host-connects.sh)")
	}
	dir, server := os.Getenv("STANDIN_STATE"), os.Getenv("STANDIN_SERVER")
	handle := firstNonEmpty(os.Getenv("STANDIN_HANDLE"), "home")
	name := firstNonEmpty(os.Getenv("STANDIN_NAME"), handle+".cseries.localhost")
	ca := standinCA(t, dir, name)
	h := newStandinHost(t, ca, handle, name, server)
	logf := func(f string, a ...any) {
		fmt.Printf(time.Now().UTC().Format("15:04:05.000Z ")+"standin "+f+"\n", a...)
	}
	switch mode {
	case "pair":
		d, err := h.pair(os.Getenv("STANDIN_CODE"))
		if err != nil {
			logf("PAIR FAILED: %v", err)
			t.Fatal(err)
		}
		logf("PAIRED: done=%+v csrs=%d", d, h.csrs)
	case "serve":
		h.lane.jobs <- []byte(`{"harness_id":"e2e","mode":"echo","prompt":"a job over a connection the Host opened"}`)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go h.serveLanes(ctx)
		var lb, lh int
		for {
			time.Sleep(time.Second)
			hellos, beats := h.lane.snapshot()
			if len(beats) != lb || len(hellos) != lh {
				logf("lanes: dials=%d open=%d idle=%d beats=%d worker-hellos=%d", h.dials.Load(), h.open.Load(), h.idle.Load(), len(beats), len(hellos))
				lb, lh = len(beats), len(hellos)
			}
			select {
			case r := <-h.lane.replies:
				logf("HARNESS JOB served over a Host-opened connection: %s", r)
			default:
			}
		}
	}
}

// standinCA is the stand-in's CA, made once and kept in dir.
func standinCA(t *testing.T, dir, cn string) *testCA {
	_ = os.MkdirAll(dir, 0o700)
	cp, kp := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if c, err := os.ReadFile(cp); err == nil {
		k, _ := os.ReadFile(kp)
		cb, _ := pem.Decode(c)
		kb, _ := pem.Decode(k)
		if cb != nil && kb != nil {
			cert, err1 := x509.ParseCertificate(cb.Bytes)
			key, err2 := x509.ParseECPrivateKey(kb.Bytes)
			if err1 == nil && err2 == nil {
				return &testCA{cert: cert, key: key, pem: string(c)}
			}
		}
	}
	ca := newTestCA(t, cn+" stand-in CA")
	kd, _ := x509.MarshalECPrivateKey(ca.key)
	_ = os.WriteFile(cp, []byte(ca.pem), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return ca
}
