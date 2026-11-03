//go:build linux

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// A connection that finishes its handshake after its pairing stopped is
// closed, never held idle with a watcher nobody will ever stop.
func TestAConnectionPutAfterThePairingStoppedIsClosed(t *testing.T) {
	pairingBox(t)
	p := &doorPairing{host: "home", idle: make(chan *hostOpenedConn, doorMaxIdle)}
	p.drain()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	p.put(tls.Client(a, &tls.Config{InsecureSkipVerify: true}), "192.0.2.1")
	if n, live := len(p.idle), p.live.Load(); n != 0 || live != 0 {
		t.Fatalf("a stopped pairing holds %d idle connections, %d live", n, live)
	}
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the connection was left open (read %d, %v)", n, err)
	}
}

// Every connection that was offered the window while it was open runs into
// the same rules when its exchange starts: a window closed by the fifth wrong
// code, inside a wrong code's wait, or closed at the terminal, starts nothing.
func TestAWindowClosedDuringAHandshakeStartsNothing(t *testing.T) {
	pairingBox(t)
	addr := freeDoorAddr(t)
	w := &pairWindow{ID: "w1", Code: strings.Repeat("A", windowCodeLen), Door: addr,
		Expires: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
	if err := saveWindowFile(w); err != nil {
		t.Fatal(err)
	}
	d := newHostDoor(addr, false)
	if d.openWindow() == nil {
		t.Fatal("the window is not offered")
	}

	d.win.failures = windowMaxFailures
	if d.windowBegin(w) {
		t.Fatal("a pairing started after the fifth wrong code")
	}
	d.win.failures, d.win.next = 1, time.Now().Add(time.Hour)
	if d.windowBegin(w) {
		t.Fatal("a pairing started inside a wrong code's wait")
	}
	d.win.failures, d.win.next = 0, time.Time{}
	removeWindow(w.ID)
	if d.windowBegin(w) {
		t.Fatal("a pairing started on a window closed at the terminal")
	}
}

// A window closed at the terminal while the exchange runs: the Host is not
// asked to sign anything.
func TestAWindowClosedDuringTheExchangeIsNeverRedeemed(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "home host CA")
	var mu sync.Mutex
	var paths []string
	c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		return nil, fmt.Errorf("no Host here")
	})}
	w := &pairWindow{ID: "gone", Code: strings.Repeat("A", windowCodeLen), Door: ":8812"}
	_, res := windowCommit(c, w, windowHelloResp{HostHandle: "home", HostName: "home.cseries.localhost"}, ca.pem,
		func() string { return "proof" })
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 0 || !strings.Contains(res.Error, "window closed") {
		t.Fatalf("a closed window was redeemed: requests %v, result %+v", paths, res)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// One IPv6 machine is one source: its /64 counts as one address.
func TestTheHandshakeLimitCountsAnIPv6NetworkAsOneSource(t *testing.T) {
	d := newHostDoor(":0", true)
	for i := 1; i <= doorMaxHandshakesPerSource; i++ {
		if !d.admitHandshake(sourceKey(fmt.Sprintf("2001:db8:1:2::%x", i))) {
			t.Fatalf("handshake %d refused", i)
		}
	}
	if d.admitHandshake(sourceKey("2001:db8:1:2::ffff")) {
		t.Fatal("a ninth handshake from one /64 was admitted")
	}
	if !d.admitHandshake(sourceKey("2001:db8:1:3::1")) || !d.admitHandshake(sourceKey("192.0.2.7")) {
		t.Fatal("another source was refused")
	}
}

// A scan from many addresses writes a bounded number of refusals.
func TestAScanFromManyAddressesDoesNotFillTheAudit(t *testing.T) {
	pairingBox(t)
	d := newHostDoor(":0", true)
	for i := 0; i < 4*doorRefusalAuditSources; i++ {
		d.refuse(fmt.Sprintf("2001:db8:%x::1", i), errors.New("scan"))
	}
	if n := strings.Count(pairingAuditText(t), `"door_refused"`); n > doorRefusalAuditSources {
		t.Fatalf("%d refusals audited from a scan, at most %d", n, doorRefusalAuditSources)
	}
	if len(d.refused) > doorRefusalAuditSources {
		t.Fatalf("the refusal map grew to %d", len(d.refused))
	}
}
