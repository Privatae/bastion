//go:build linux

package main

// The door's handshake slots under a flood: the global and per-source caps,
// the share kept for addresses a Host proved itself from, and the random
// early drop for strangers (hostdoor.go, admitHandshake).

import (
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// freshDoorMemory forgets every Host address, before and after the test.
func freshDoorMemory(t *testing.T) {
	t.Helper()
	reset := func() {
		doorKnown.Lock()
		doorKnown.until = nil
		doorKnown.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// neverDrops is a draw the early drop never refuses on (it refuses when the
// draw is below the drop chance, which is under 1 short of the limit).
func neverDrops() float64 { return math.Nextafter(1, 0) }

// alwaysDrops is a draw the early drop refuses on wherever it applies.
func alwaysDrops() float64 { return 0 }

func strangersShare() int { return doorMaxHandshakes - doorReservedHandshakes }

// The global and per-source caps hold for everyone, a known Host's address
// included, and strangers never take the reserved share, however lucky.
func TestTheHandshakeCapsStillHold(t *testing.T) {
	freshDoorMemory(t)
	now := time.Now()
	d := newHostDoor(":0", true)
	d.draw = neverDrops
	// Strangers: admitted up to their share, from enough addresses, and not
	// one more.
	for i := 0; i < strangersShare(); i++ {
		if !d.admitHandshake(fmt.Sprintf("203.0.113.%d", i/doorMaxHandshakesPerSource)) {
			t.Fatalf("stranger handshake %d refused below the strangers' share", i)
		}
	}
	if d.admitHandshake("198.51.100.200") {
		t.Fatalf("a stranger took a slot of the reserve (%d in progress)", d.inflight)
	}
	// Known addresses: the rest, 8 from each, and then nothing for anyone.
	for i := 0; d.inflight < doorMaxHandshakes; i++ {
		src := fmt.Sprintf("198.51.100.%d", i)
		doorRememberHost(src, now)
		for j := 0; j < doorMaxHandshakesPerSource; j++ {
			if !d.admitHandshake(src) {
				t.Fatalf("handshake %d of known %s refused with %d in progress", j, src, d.inflight)
			}
		}
		if d.inflight < doorMaxHandshakes && d.admitHandshake(src) {
			t.Fatalf("known %s got a ninth handshake", src)
		}
	}
	doorRememberHost("192.0.2.1", now)
	if d.inflight != doorMaxHandshakes || d.admitHandshake("192.0.2.1") {
		t.Fatalf("a handshake past the global cap of %d (%d in progress)", doorMaxHandshakes, d.inflight)
	}
	// A known address is held to 8 at once on an empty door too.
	e := newHostDoor(":0", true)
	for j := 0; j < doorMaxHandshakesPerSource; j++ {
		if !e.admitHandshake("192.0.2.1") {
			t.Fatal("a known address was refused on an empty door")
		}
	}
	if e.admitHandshake("192.0.2.1") {
		t.Fatal("a known address got a ninth handshake at once")
	}
}

// Strangers are dropped early as the door fills: never below the start,
// with the chance rising from the rate to certain at the strangers' share.
// A known Host's address is never early-dropped.
func TestStrangersAreDroppedEarlyAsTheDoorFills(t *testing.T) {
	freshDoorMemory(t)
	d := newHostDoor(":0", true)
	full := strangersShare()
	for _, c := range []struct {
		n      int
		draw   float64
		admits bool
	}{
		{0, 0, true},
		{doorEarlyDropStart - 1, 0, true},
		{doorEarlyDropStart, doorEarlyDropRate - 0.01, false},
		{doorEarlyDropStart, doorEarlyDropRate + 0.01, true},
		{(doorEarlyDropStart + full) / 2, (1+doorEarlyDropRate)/2 - 0.01, false},
		{(doorEarlyDropStart + full) / 2, (1+doorEarlyDropRate)/2 + 0.01, true},
		{full - 1, 0.99, false},
		{full - 1, neverDrops(), true},
		{full, neverDrops(), false},
	} {
		draw := c.draw
		d.draw = func() float64 { return draw }
		if got := d.admitStranger(c.n); got != c.admits {
			t.Fatalf("with %d in progress and a draw of %v: admitted %v, want %v", c.n, c.draw, got, c.admits)
		}
	}
	// Through admitHandshake: an unlucky stranger is refused at the start,
	// a known address with the same draw is not, up to the global cap.
	d = newHostDoor(":0", true)
	d.draw = alwaysDrops
	for i := 0; i < doorEarlyDropStart; i++ {
		if !d.admitHandshake(fmt.Sprintf("203.0.113.%d", i)) {
			t.Fatalf("stranger %d refused below the start", i)
		}
	}
	if d.admitHandshake("203.0.113.250") {
		t.Fatal("an unlucky stranger was admitted past the start")
	}
	doorRememberHost("198.51.100.7", time.Now())
	d.inflight = doorMaxHandshakes - 1
	if !d.admitHandshake("198.51.100.7") {
		t.Fatal("a known Host's address was early-dropped")
	}
}

// An address is remembered for doorKnownHostFor after its last verified
// handshake, in a bounded memory that forgets the oldest first.
func TestAHostAddressIsRememberedForAWhileAndBounded(t *testing.T) {
	freshDoorMemory(t)
	now := time.Now()
	doorRememberHost("198.51.100.7", now)
	if !doorKnownHost("198.51.100.7", now.Add(doorKnownHostFor-time.Second)) {
		t.Fatal("forgotten before its time")
	}
	if doorKnownHost("198.51.100.7", now.Add(doorKnownHostFor)) {
		t.Fatal("remembered past its time")
	}
	if doorKnownHost("198.51.100.8", now) {
		t.Fatal("an address no Host proved itself from is known")
	}
	// A fresh handshake renews it.
	doorRememberHost("198.51.100.7", now)
	doorRememberHost("198.51.100.7", now.Add(doorKnownHostFor-time.Second))
	if !doorKnownHost("198.51.100.7", now.Add(doorKnownHostFor+time.Hour)) {
		t.Fatal("a renewed address was forgotten")
	}
	// Bounded: the oldest goes first, the newest stays.
	for i := 0; i < 2*doorKnownHostsMax; i++ {
		doorRememberHost(fmt.Sprintf("2001:db8:%x::/64", i), now.Add(time.Duration(i)*time.Second))
	}
	doorKnown.Lock()
	n := len(doorKnown.until)
	doorKnown.Unlock()
	if n > doorKnownHostsMax {
		t.Fatalf("the memory holds %d addresses, at most %d", n, doorKnownHostsMax)
	}
	last := now.Add(time.Duration(2*doorKnownHostsMax) * time.Second)
	if !doorKnownHost(fmt.Sprintf("2001:db8:%x::/64", 2*doorKnownHostsMax-1), last) {
		t.Fatal("the newest address was forgotten")
	}
	if doorKnownHost("2001:db8:0::/64", last) {
		t.Fatal("the oldest address outlived a full memory")
	}
}

// pipeDoor is a door served over in-memory connections from any address the
// test names, with one pairing for ca's Host.
type pipeDoor struct {
	d       *hostDoor
	p       *doorPairing
	ca      *testCA
	conns   chan net.Conn
	quit    chan struct{}
	accepts atomic.Int64
	pushed  int64
	mu      sync.Mutex
	ends    []net.Conn
}

func (l *pipeDoor) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.quit:
		return nil, net.ErrClosed
	}
}
func (l *pipeDoor) Close() error   { return nil }
func (l *pipeDoor) Addr() net.Addr { return &net.TCPAddr{Port: 8812} }

type fromConn struct {
	net.Conn
	from net.Addr
}

func (c fromConn) RemoteAddr() net.Addr { return c.from }

func newPipeDoor(t *testing.T) *pipeDoor {
	t.Helper()
	ca := newTestCA(t, "home host CA")
	cfg := hostDialsPairingFor(t, ca, "home.cseries.localhost", ":8812")
	p, err := newDoorPairing(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l := &pipeDoor{d: newHostDoor(":8812", true), p: p, ca: ca, conns: make(chan net.Conn), quit: make(chan struct{})}
	l.d.pairings[cfg.HostName] = p
	go l.d.serve(l)
	t.Cleanup(func() {
		close(l.quit)
		l.mu.Lock()
		for _, c := range l.ends {
			_ = c.Close()
		}
		l.mu.Unlock()
		p.drain()
		doorWaitFor(t, 15*time.Second, "every handshake to end", func() bool { return l.inflight() == 0 })
	})
	return l
}

// connect hands the door a connection from ip and waits until the door has
// admitted or closed it. It returns the far end.
func (l *pipeDoor) connect(t *testing.T, ip string) net.Conn {
	t.Helper()
	near, far := net.Pipe()
	l.mu.Lock()
	l.ends = append(l.ends, far)
	l.mu.Unlock()
	l.conns <- fromConn{Conn: near, from: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
	l.pushed++
	for l.accepts.Load() <= l.pushed {
		time.Sleep(50 * time.Microsecond)
	}
	return far
}

// stranger connects from ip and never answers the handshake: a slot held
// until the handshake's time runs out.
func (l *pipeDoor) stranger(t *testing.T, ip string) {
	far := l.connect(t, ip)
	go func() { _, _ = io.Copy(io.Discard, far) }()
}

// host connects from ip as the pairing's Host and returns how long its
// handshake took, or the error that ended it.
func (l *pipeDoor) host(t *testing.T, ip string, within time.Duration) (time.Duration, error) {
	t.Helper()
	start := time.Now()
	far := l.connect(t, ip)
	s := tls.Server(far, &tls.Config{Certificates: []tls.Certificate{l.ca.serverCert(t, tcpServerName)},
		NextProtos: []string{laneALPN}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert})
	_ = s.SetDeadline(start.Add(within))
	err := s.Handshake()
	_ = s.SetDeadline(time.Time{})
	return time.Since(start), err
}

func (l *pipeDoor) inflight() int {
	l.d.mu.Lock()
	defer l.d.mu.Unlock()
	return l.d.inflight
}

// hostReconnectBound is how long the person's own Host may take to get a
// connection through a flooded door: its first try is admitted, so this is
// one handshake over an in-memory connection, with room for -race and a
// loaded machine. A refused try instead costs the Host's backoff (1 s, then
// doubling to 30 s, docs/host-connects.md).
const hostReconnectBound = 2 * time.Second

// SECURITY: 64 addresses flooding the door hold every slot strangers may
// take, and the person's own Host, connecting from the address it proved
// itself from, gets in at its first try, every time, within
// hostReconnectBound. The same Host from an address it never proved itself
// from waits like any stranger; what the reserve keeps is the address.
func TestTheOwnHostGetsInWhileStrangersFloodTheDoor(t *testing.T) {
	pairingBox(t)
	freshDoorMemory(t)
	l := newPipeDoor(t)
	const home = "198.51.100.7"
	// Before the flood: a Host that connected once is known by its address.
	if _, err := l.host(t, home, hostReconnectBound); err != nil {
		t.Fatalf("the Host's first connection: %v", err)
	}
	doorWaitFor(t, 5*time.Second, "the connection in the pool", func() bool { return l.p.live.Load() == 1 })
	if !doorKnownHost(home, time.Now()) {
		t.Fatal("a Host's verified connection did not make its address known")
	}
	// The flood: 64 addresses, round and round, until every slot strangers
	// may hold is held, with the real random early drop.
	attempts := 0
	for l.inflight() < strangersShare() {
		if attempts++; attempts > 50000 {
			t.Fatalf("the flood holds %d slots after %d connections", l.inflight(), attempts)
		}
		l.stranger(t, fmt.Sprintf("203.0.113.%d", attempts%64))
	}
	// Full for strangers: from any address, new or flooding, none gets in.
	for i := 0; i < 64; i++ {
		l.stranger(t, fmt.Sprintf("192.0.2.%d", i))
	}
	if n := l.inflight(); n != strangersShare() {
		t.Fatalf("strangers hold %d slots, at most %d", n, strangersShare())
	}
	// The Host reconnects: each of its spare connections at the first try.
	for i := 0; i < hostSpareConns; i++ {
		took, err := l.host(t, home, hostReconnectBound)
		if err != nil {
			t.Fatalf("the Host's connection %d during the flood (after %d flood connections): %v", i, attempts, err)
		}
		if took > hostReconnectBound {
			t.Fatalf("the Host's connection %d took %s, bound %s", i, took, hostReconnectBound)
		}
		t.Logf("the Host's connection %d through the flood (%d flood connections): %s", i, attempts, took)
	}
	doorWaitFor(t, 5*time.Second, "the Host's connections in the pool", func() bool {
		return l.p.live.Load() == 1+hostSpareConns
	})
	// The same Host from an address it never proved itself from: refused.
	if _, err := l.host(t, "198.51.100.99", hostReconnectBound); err == nil {
		t.Fatal("an unknown address got past a door full for strangers")
	}
}

// A Host never seen before pairs through the window when nobody floods the
// door, even with a draw the early drop would refuse on, and its address is
// known from then on, so its lane connections count as its own.
func TestANewHostPairsWhenNobodyFloods(t *testing.T) {
	pairingBox(t)
	freshDoorMemory(t)
	prev := doorDraw
	doorDraw = alwaysDrops
	t.Cleanup(func() { doorDraw = prev })
	addr := freeDoorAddr(t)
	code, out, res := openWindowFor(t, addr)
	ca := newTestCA(t, "home host CA")
	h := newStandinHost(t, ca, "home", "home.cseries.localhost", addr)
	done, err := h.pair(formatWindowCode(code))
	if err != nil {
		t.Fatalf("%v\n%s", err, pairingAuditText(t))
	}
	if done.State != pairingActive {
		t.Fatalf("done: %+v", done)
	}
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("pair --open: %v\n%s", err, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pair --open never saw the pairing end its window")
	}
	host, _, _ := net.SplitHostPort(addr)
	if !doorKnownHost(sourceKey(host), time.Now()) {
		t.Fatal("a Host that paired through the window is not known by its address")
	}
}

// SECURITY: only a verified handshake for a pairing the door still serves
// makes an address known: a certificate under another CA does not, nor the
// Host's own certificate once the door has stopped serving its pairing.
func TestOnlyAServedHostsVerifiedHandshakeMakesItsAddressKnown(t *testing.T) {
	pairingBox(t)
	freshDoorMemory(t)
	l := newPipeDoor(t)
	// handshake connects from ip with cert and waits for the door's verdict,
	// the connection closing, so whatever the door does for it is done.
	handshake := func(ip string, cert tls.Certificate) {
		far := l.connect(t, ip)
		s := tls.Server(far, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{laneALPN},
			MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert})
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))
		if err := s.Handshake(); err == nil {
			_, _ = s.Read(make([]byte, 1))
		}
		_ = s.Close()
	}
	const impostorIP, stoppedIP = "198.51.100.60", "198.51.100.61"
	impostor := newTestCA(t, "impostor")
	handshake(impostorIP, impostor.serverCert(t, tcpServerName))
	if doorKnownHost(impostorIP, time.Now()) {
		t.Fatal("a certificate under another CA made its address known")
	}
	l.d.mu.Lock()
	l.d.closed = true
	l.d.mu.Unlock()
	handshake(stoppedIP, l.ca.serverCert(t, tcpServerName))
	if doorKnownHost(stoppedIP, time.Now()) {
		t.Fatal("a handshake for a pairing the door no longer serves made its address known")
	}
}
