package main

// hostdoor.go: the door a Host connects to when this server can't reach it.
//
// A Host on a person's own computer sits behind their home router: a server
// on the internet can't open a connection to it, but it can open one to the
// server. So for such a pairing (Config.HostDials) the Host opens the TCP
// connections, to this server's door, and the lanes run over them exactly as
// they run over a connection this bastion dialled to a Host's lane port: this
// bastion is the TLS client, the Host's CA is the only root, the Host's
// certificate must name host.cseries.internal, and this bastion presents its
// operator certificate. Only the TCP direction is the other way round.
//
// One port serves every such pairing, and the Host's certificate says which
// pairing a connection is for: the door does the TLS handshake itself, as the
// client, and a connection whose Host certificate does not verify under the
// pinned CA of exactly one pairing it serves is closed before a byte of a lane
// crosses it. What passes is held, idle, in that pairing's pool, and a lane
// that would have dialled takes one from there instead (hostDoorDial). The TLS
// is already done, so the lane runs on it as it is (lanedial.go).
//
// The door is bound only while a pairing of this kind is served here (or the
// person has a pairing window open on it, pair_window.go). It never dials,
// never forwards a byte anywhere (a connection it keeps is a lane of a pairing
// it already serves, and nothing else is ever read from it), and the only
// thing it answers before a Host has proved itself is the TLS handshake. The
// Host keeps a few idle connections open and opens another each time one is
// taken; when it goes away, its connections close and it opens new ones when
// it is back. This server never reconnects to it: it can't.
//
// The wire contract the Host implements is docs/host-connects.md.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// doorDefaultAddr is where the door listens: every address of the
	// machine, IPv4 and IPv6, port 8812 (beside the Host's own 8810/8811).
	doorDefaultAddr = ":8812"
	// The two protocols a Host can name in the handshake (ALPN): a lane
	// connection of a pairing this server serves, or a pairing through an
	// open window. The Host chooses; the door offers the second only while a
	// window is open.
	laneALPN = "privatae-lane/1"
	pairALPN = "privatae-pair/1"
	// A connection has this long to finish its TLS handshake.
	doorHandshakeTimeout = 10 * time.Second
	// At most this many handshakes are in progress at once, and this many
	// from one address (an IPv6 address counts as its /64, which one machine
	// is commonly given whole): a scan or a flood costs the door a bounded
	// number of goroutines.
	doorMaxHandshakes          = 256
	doorMaxHandshakesPerSource = 8
	// Of those, this many are kept for addresses a Host proved itself from
	// within doorKnownHostFor (doorRememberHost): a stranger is admitted only
	// while fewer than doorMaxHandshakes-doorReservedHandshakes are in
	// progress, so strangers from any number of addresses never hold the last
	// slots, and the person's own Host reconnects at its first try while the
	// port is flooded. The reserve holds every handshake of 8 such addresses
	// at once; one Host connects from one.
	doorReservedHandshakes = 64
	// Random early drop for strangers, as OpenSSH's MaxStartups (default
	// 10:30:100): with fewer than doorEarlyDropStart handshakes in progress a
	// stranger is always admitted (a new Host pairing, Hosts redialling after
	// this bastion restarted); from there a stranger is refused with a chance
	// that starts at doorEarlyDropRate and rises in a line to certain at the
	// strangers' limit. A flood then fills the strangers' share slowly and
	// never the reserve.
	doorEarlyDropStart = 64
	doorEarlyDropRate  = 0.3
	// An address a Host proved itself from is remembered for this long after
	// its last verified handshake, in memory only (never written anywhere,
	// gone when the bastion stops), at most doorKnownHostsMax of them. A Host
	// connected keeps it fresh; this covers one away for a week (a laptop
	// shut over a holiday) whose home address did not change.
	doorKnownHostFor  = 7 * 24 * time.Hour
	doorKnownHostsMax = 64
	// A pairing holds at most this many idle connections; one more is closed.
	// The Host keeps hostSpareConns idle (docs/host-connects.md), so this is
	// far above anything a well-behaved Host opens.
	doorMaxIdle = 32
	// TCP keepalive on every connection the door keeps, under the 30 s a
	// home router's NAT may forget an idle connection after.
	doorKeepAlive = 25 * time.Second
	// A refusal from one address is written to the audit once per this, and
	// at most doorRefusalAuditSources addresses are written per period: a
	// scan from many addresses must not fill the audit or this map either.
	doorRefusalAuditEvery   = 10 * time.Minute
	doorRefusalAuditSources = 256
)

// doorTakeWait is how long a lane waits for its Host's next connection. A
// lane's own context can cut it shorter.
const doorTakeWait = egressDialTimeout

// hostOpenedConn is a connection a Host opened to the door, its TLS done. Idle
// in a pool, a watcher reads it, so a connection the Host or the network closed
// leaves the pool at once; a lane that takes one stops the watcher first.
type hostOpenedConn struct {
	*tls.Conn
	p      *doorPairing
	state  atomic.Int32 // connIdle, connTaken, connDead
	done   chan struct{}
	werr   error // the watcher's read result, set before done closes
	closed atomic.Bool
}

const (
	connIdle int32 = iota
	connTaken
	connDead
)

// Close closes the connection and counts it gone, once. It audits nothing
// and calls nothing but the close: every Close in this program can reach it
// as far as the static checks can tell (claims_static_test.go), so the
// "disconnected" audit is written by the pairing's own loop (auditLoop).
func (c *hostOpenedConn) Close() error {
	err := c.Conn.Close()
	if c.closed.CompareAndSwap(false, true) {
		c.p.connClosed()
	}
	return err
}

// watch reads the idle connection. A Host sends nothing on a connection until
// a lane has spoken on it, so any read that returns is the end of it, unless
// the read was the take's own stop.
func (c *hostOpenedConn) watch() {
	var b [1]byte
	n, err := c.Conn.Read(b[:])
	if n > 0 {
		err = errors.New("the Host sent data on a connection no lane had used")
	}
	c.werr = err
	close(c.done)
	if c.state.CompareAndSwap(connIdle, connDead) {
		_ = c.Close()
	}
}

// claim takes an idle connection for a lane: the watcher stopped, its read
// deadline cleared. False when the connection is dead (and it is closed).
func (c *hostOpenedConn) claim() bool {
	if !c.state.CompareAndSwap(connIdle, connTaken) {
		return false
	}
	_ = c.Conn.SetReadDeadline(time.Unix(1, 0))
	<-c.done
	var ne net.Error
	if c.werr != nil && !(errors.As(c.werr, &ne) && ne.Timeout()) {
		_ = c.Close()
		return false
	}
	_ = c.Conn.SetReadDeadline(time.Time{})
	return true
}

// doorPairing is one pairing the door serves: its pinned CA, the operator
// certificate it presents, and its idle connections.
type doorPairing struct {
	host  string
	roots *x509.CertPool
	cert  tls.Certificate
	idle  chan *hostOpenedConn
	gone  chan struct{} // the last connection closed (auditLoop)
	live  atomic.Int32  // connections open now, idle or taken
	from  atomic.Value  // string: the address the last connection came from

	// mu orders put against drain: once stopped, no connection is held.
	mu      sync.Mutex
	stopped bool
}

func (p *doorPairing) connClosed() {
	if p.live.Add(-1) == 0 {
		select {
		case p.gone <- struct{}{}:
		default:
		}
	}
}

// auditLoop writes "disconnected" each time the pairing's last connection
// closes, until quit. Off Close's path on purpose (hostOpenedConn.Close).
func (p *doorPairing) auditLoop(quit <-chan struct{}) {
	for {
		select {
		case <-p.gone:
			if p.live.Load() == 0 {
				from, _ := p.from.Load().(string)
				pairingAudit("host_disconnected", p.host, "its last connection to this server closed (from "+from+")")
			}
		case <-quit:
			return
		}
	}
}

// put holds a verified connection for the pairing's lanes.
func (p *doorPairing) put(tc *tls.Conn, src string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		// The pairing stopped while this connection was in its handshake.
		_ = tc.Close()
		return
	}
	c := &hostOpenedConn{Conn: tc, p: p, done: make(chan struct{})}
	p.from.Store(src)
	if p.live.Add(1) == 1 {
		pairingAudit("host_connected", p.host, "connected to this server from "+src)
		// Back from away: it hears from this server now, not on the minute.
		defer kickBeats()
	}
	select {
	case p.idle <- c:
		go c.watch()
	default:
		// More idle connections than any Host keeps: this one is closed.
		c.state.Store(connDead)
		_ = c.Close()
	}
}

// take is a lane's dial: the next idle connection the Host opened, waiting at
// most doorTakeWait for one.
func (p *doorPairing) take(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, doorTakeWait)
	defer cancel()
	for {
		select {
		case c := <-p.idle:
			if c.claim() {
				return c, nil
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("%s has not connected to this server within %s (your Host connects to this server; "+
				"it does when it is running and can reach it)", p.host, doorTakeWait)
		}
	}
}

// drain closes every idle connection: the pairing stopped.
func (p *doorPairing) drain() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	for {
		select {
		case c := <-p.idle:
			if c.state.CompareAndSwap(connIdle, connDead) {
				_ = c.Close()
			}
		default:
			return
		}
	}
}

// hostDoor is one listening door.
type hostDoor struct {
	addr string
	// lanes: this door serves pairings' lanes (the running bastion's door).
	// A pairing window opened with no bastion holding the port is served by
	// a door of its own that serves the window alone.
	lanes bool

	mu        sync.Mutex
	ln        net.Listener
	pairings  map[string]*doorPairing
	refs      int
	inflight  int
	perSource map[string]int
	refused   map[string]time.Time
	win       windowState
	closed    bool
	// draw is the early drop's random number in [0, 1) (doorDraw).
	draw func() float64
}

// doorDraw is where a new door's early drop draws from. A variable so a test
// can fix it; nothing else assigns it.
var doorDraw = rand.Float64

func newHostDoor(addr string, lanes bool) *hostDoor {
	return &hostDoor{addr: addr, lanes: lanes, pairings: map[string]*doorPairing{},
		perSource: map[string]int{}, refused: map[string]time.Time{}, draw: doorDraw}
}

// listenDoor binds addr with keepalive on every accepted connection.
func listenDoor(addr string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: doorKeepAlive}
	return lc.Listen(context.Background(), "tcp", addr)
}

// serve accepts until the listener closes.
func (d *hostDoor) serve(ln net.Listener) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		src := remoteHost(raw.RemoteAddr())
		if !d.admitHandshake(sourceKey(src)) {
			_ = raw.Close()
			continue
		}
		go d.handle(raw, src)
	}
}

func remoteHost(a net.Addr) string {
	if a == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

// sourceKey is the address the per-source limits count: an IPv4 address as
// it is, an IPv6 address as its /64.
func sourceKey(h string) string {
	ip := net.ParseIP(h)
	if ip == nil || ip.To4() != nil {
		return h
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// admitHandshake takes a handshake slot for src (a sourceKey), or refuses:
// the global and per-source limits for everyone, and for a source no Host
// proved itself from lately, the strangers' share and its early drop.
func (d *hostDoor) admitHandshake(src string) bool {
	known := doorKnownHost(src, time.Now())
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inflight >= doorMaxHandshakes || d.perSource[src] >= doorMaxHandshakesPerSource {
		return false
	}
	if !known && !d.admitStranger(d.inflight) {
		return false
	}
	d.inflight++
	d.perSource[src]++
	return true
}

// admitStranger is the early drop for a stranger's handshake with n in
// progress. Called with d.mu held.
func (d *hostDoor) admitStranger(n int) bool {
	full := doorMaxHandshakes - doorReservedHandshakes
	switch {
	case n < doorEarlyDropStart:
		return true
	case n >= full:
		return false
	}
	drop := doorEarlyDropRate + (1-doorEarlyDropRate)*float64(n-doorEarlyDropStart)/float64(full-doorEarlyDropStart)
	return d.draw() >= drop
}

// doorKnown is the addresses (sourceKeys) a Host proved itself from, each
// with when it is forgotten. In memory only: an address is never written to
// disk, and a bastion that restarts knows none until its Hosts connect again.
var doorKnown struct {
	sync.Mutex
	until map[string]time.Time
}

// doorRememberHost notes that a Host proved itself from src (a sourceKey):
// its certificate verified under a pairing's pinned CA, or it paired through
// the window with the code.
func doorRememberHost(src string, now time.Time) {
	doorKnown.Lock()
	defer doorKnown.Unlock()
	if doorKnown.until == nil {
		doorKnown.until = map[string]time.Time{}
	}
	if _, ok := doorKnown.until[src]; !ok && len(doorKnown.until) >= doorKnownHostsMax {
		oldest := ""
		for k, t := range doorKnown.until {
			if !now.Before(t) {
				delete(doorKnown.until, k)
				continue
			}
			if oldest == "" || t.Before(doorKnown.until[oldest]) {
				oldest = k
			}
		}
		if len(doorKnown.until) >= doorKnownHostsMax {
			delete(doorKnown.until, oldest)
		}
	}
	doorKnown.until[src] = now.Add(doorKnownHostFor)
}

// doorKnownHost is whether a Host proved itself from src within
// doorKnownHostFor.
func doorKnownHost(src string, now time.Time) bool {
	doorKnown.Lock()
	defer doorKnown.Unlock()
	t, ok := doorKnown.until[src]
	if ok && !now.Before(t) {
		delete(doorKnown.until, src)
		return false
	}
	return ok
}

func (d *hostDoor) handshakeDone(src string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inflight--
	if d.perSource[src]--; d.perSource[src] <= 0 {
		delete(d.perSource, src)
	}
}

// match is the pairing whose pinned CA the Host's certificate verifies under,
// for host.cseries.internal: exactly one, or a refusal.
func (d *hostDoor) match(chain []*x509.Certificate) (*doorPairing, error) {
	if len(chain) == 0 {
		return nil, errors.New("the connection presented no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var hit *doorPairing
	for _, p := range d.pairings {
		if _, err := chain[0].Verify(x509.VerifyOptions{Roots: p.roots, Intermediates: inter, DNSName: tcpServerName}); err != nil {
			continue
		}
		if hit != nil {
			return nil, errors.New("the certificate verifies for more than one pairing here — refusing")
		}
		hit = p
	}
	if hit == nil {
		return nil, errors.New("the certificate is not that of a Host this server serves")
	}
	return hit, nil
}

// handle does the TLS handshake as the client and keeps the connection only
// for what the Host proved: a lane of the one pairing its certificate names,
// or a pairing through the open window.
func (d *hostDoor) handle(raw net.Conn, src string) {
	released := false
	release := func() {
		if !released {
			released = true
			d.handshakeDone(sourceKey(src))
		}
	}
	defer release()
	_ = raw.SetDeadline(time.Now().Add(doorHandshakeTimeout))
	win := d.openWindow()
	var protos []string
	if d.lanes {
		protos = append(protos, laneALPN)
	}
	if win != nil {
		protos = append(protos, pairALPN)
	}
	if len(protos) == 0 {
		_ = raw.Close()
		return
	}
	var matched *doorPairing
	var pairCA *x509.Certificate
	cfg := &tls.Config{
		ServerName: tcpServerName, MinVersion: tls.VersionTLS13, NextProtos: protos,
		// The chain is checked in VerifyConnection against the pinned CAs
		// alone (or, for a pairing, against the CA it carries, which the code
		// then vouches for): the system roots play no part.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			var err error
			switch {
			case cs.NegotiatedProtocol == laneALPN && d.lanes:
				matched, err = d.match(cs.PeerCertificates)
			case cs.NegotiatedProtocol == pairALPN && win != nil:
				pairCA, err = chainCA(cs.PeerCertificates)
			default:
				err = fmt.Errorf("the connection named no protocol this server speaks (%q)", cs.NegotiatedProtocol)
			}
			return err
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if matched != nil {
				return &matched.cert, nil
			}
			// A pairing: this bastion holds no certificate from the Host yet.
			return &tls.Certificate{}, nil
		},
	}
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		d.refuse(src, err)
		_ = raw.Close()
		return
	}
	release()
	switch tc.ConnectionState().NegotiatedProtocol {
	case laneALPN:
		_ = raw.SetDeadline(time.Time{})
		d.mu.Lock()
		live := !d.closed && d.pairings[matched.host] == matched
		d.mu.Unlock()
		if !live {
			_ = tc.Close()
			return
		}
		doorRememberHost(sourceKey(src), time.Now())
		matched.put(tc, src)
	case pairALPN:
		d.serveWindow(tc, win, pairCA, src)
	}
}

// refuse audits a refused connection, once per address per
// doorRefusalAuditEvery: a scan of the port must not fill the audit.
func (d *hostDoor) refuse(src string, err error) {
	key := sourceKey(src)
	d.mu.Lock()
	last, seen := d.refused[key]
	now := time.Now()
	if seen && now.Sub(last) < doorRefusalAuditEvery {
		d.mu.Unlock()
		return
	}
	if len(d.refused) >= doorRefusalAuditSources {
		for k, t := range d.refused {
			if now.Sub(t) >= doorRefusalAuditEvery {
				delete(d.refused, k)
			}
		}
		if len(d.refused) >= doorRefusalAuditSources {
			// This period's share of the audit is spent.
			d.mu.Unlock()
			return
		}
	}
	d.refused[key] = now
	d.mu.Unlock()
	pairingAudit("door_refused", src, "refused: "+err.Error())
}

// chainCA is the CA a pairing Host's chain carries, checked to sign its leaf
// for host.cseries.internal. The code proves the Host holds it
// (pair_window.go); nothing else does.
func chainCA(chain []*x509.Certificate) (*x509.Certificate, error) {
	if len(chain) < 2 {
		return nil, errors.New("the Host presented no certificate authority with its certificate")
	}
	for _, c := range chain[1:] {
		if !c.IsCA {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(c)
		if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, DNSName: tcpServerName}); err == nil {
			return c, nil
		}
	}
	return nil, errors.New("the Host's certificate is not signed by a certificate authority it presented, for " + tcpServerName)
}

// ── the running bastion's doors ─────────────────────────────────────────────

var doors struct {
	sync.Mutex
	m map[string]*hostDoor
}

// doorBindRetry is how often a door that could not bind tries again (the
// port is held by a pairing window's own door until that window closes).
var doorBindRetry = 2 * time.Second

// newDoorPairing is cfg as the door serves it: its pinned CA, its operator
// certificate, an empty pool.
func newDoorPairing(cfg *Config) (*doorPairing, error) {
	cert, err := tls.X509KeyPair([]byte(cfg.OperatorCert), []byte(cfg.OperatorKey))
	if err != nil {
		return nil, fmt.Errorf("operator cert/key: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cfg.CACert)) {
		return nil, errors.New("bad CA cert in config")
	}
	return &doorPairing{host: cfg.HostName, roots: roots, cert: cert, idle: make(chan *hostOpenedConn, doorMaxIdle),
		gone: make(chan struct{}, 1)}, nil
}

// doorOpen registers an active host-dials pairing with the door on its
// address, binding the door if this is its first pairing. The returned
// release unregisters it and closes the door after its last pairing.
func doorOpen(cfg *Config) (func(), error) {
	p, err := newDoorPairing(cfg)
	if err != nil {
		return nil, err
	}
	addr := cfg.doorAddr()
	quit := make(chan struct{})
	go p.auditLoop(quit)
	doors.Lock()
	if doors.m == nil {
		doors.m = map[string]*hostDoor{}
	}
	d := doors.m[addr]
	first := d == nil
	if first {
		d = newHostDoor(addr, true)
		doors.m[addr] = d
	}
	d.mu.Lock()
	if _, dup := d.pairings[cfg.HostName]; dup {
		d.mu.Unlock()
		doors.Unlock()
		close(quit)
		return nil, fmt.Errorf("%s is already served on %s", cfg.HostName, addr)
	}
	d.pairings[cfg.HostName] = p
	d.refs++
	d.mu.Unlock()
	doors.Unlock()
	if first {
		go d.bindLoop()
	}
	return func() {
		defer close(quit)
		doors.Lock()
		d.mu.Lock()
		if d.pairings[cfg.HostName] == p {
			delete(d.pairings, cfg.HostName)
		}
		d.refs--
		last := d.refs == 0
		if last {
			d.closed = true
			delete(doors.m, addr)
		}
		ln := d.ln
		d.mu.Unlock()
		doors.Unlock()
		p.drain()
		if last && ln != nil {
			_ = ln.Close()
		}
		if last {
			// The rule stays while a pairing on this port is still active
			// (the bastion stopping is not the pairing going) or a window
			// is open on it; otherwise it goes now.
			doorFirewallRelease(addr)
		}
	}, nil
}

// bindLoop binds the door and serves it, trying again while the port is held
// and the door still has a pairing.
func (d *hostDoor) bindLoop() {
	logged := false
	for {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()
		ln, err := listenDoor(d.addr)
		if err == nil {
			d.mu.Lock()
			if d.closed {
				d.mu.Unlock()
				_ = ln.Close()
				return
			}
			d.ln = ln
			d.mu.Unlock()
			fmt.Printf("door: your Host connects to this server on %s (TCP)\n", d.addr)
			// The way in through this machine's own firewall, while the door
			// is in use (doorfw.go); removed when its last pairing goes. Beside
			// serving, never before it: a firewall command that hangs (each
			// may take doorFWExecWait) never holds the door shut.
			go func() {
				still := func() bool { d.mu.Lock(); defer d.mu.Unlock(); return !d.closed }
				if said := doorFirewallEnsureWhile(d.addr, still); said != "" {
					fmt.Println("door: " + said)
				}
			}()
			d.serve(ln)
			return
		}
		if !logged {
			fmt.Printf("door: cannot listen on %s yet (%v); trying again every %s\n", d.addr, err, doorBindRetry)
			logged = true
		}
		time.Sleep(doorBindRetry)
	}
}

// hostDoorDial is a host-dials pairing's lane dial: the next connection its
// Host opened to the door.
func hostDoorDial(cfg *Config) func(ctx context.Context) (net.Conn, error) {
	addr, host := cfg.doorAddr(), cfg.HostName
	return func(ctx context.Context) (net.Conn, error) {
		doors.Lock()
		d := doors.m[addr]
		doors.Unlock()
		if d == nil {
			return nil, fmt.Errorf("no door is open on %s for %s", addr, host)
		}
		d.mu.Lock()
		p := d.pairings[host]
		d.mu.Unlock()
		if p == nil {
			return nil, fmt.Errorf("%s is not served on %s", host, addr)
		}
		return p.take(ctx)
	}
}

// hostDialsLaneDialer is localLaneDialer for a pairing whose Host connects
// to this server. The TLS configuration is the one the door uses, kept for
// the lanes' own use; every connection the dial returns has it done.
func hostDialsLaneDialer(cfg *Config) (func(ctx context.Context) (net.Conn, error), *tls.Config, error) {
	if cfg.Bearer == "" {
		return nil, nil, errors.New("this pairing holds no bearer, and its lane never opens without one")
	}
	cert, err := tls.X509KeyPair([]byte(cfg.OperatorCert), []byte(cfg.OperatorKey))
	if err != nil {
		return nil, nil, fmt.Errorf("operator cert/key: %w", err)
	}
	tc, err := hostCATLS(cfg.CACert, &cert)
	if err != nil {
		return nil, nil, fmt.Errorf("bad CA cert in config: %w", err)
	}
	return hostDoorDial(cfg), tc, nil
}

// doorAddr is where this pairing's Host connects: the address it was paired
// on, or the default.
func (c *Config) doorAddr() string {
	if strings.TrimSpace(c.DoorAddr) != "" {
		return c.DoorAddr
	}
	return doorDefaultAddr
}

// doorPort is the door's port, for the person's words.
func doorPort(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return addr
}
