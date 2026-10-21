package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestKeepaliveUnblocksParkedReaderOnDeadPeer is the regression guard for the worker-lane
// hang: a parked ReadMessage must return (not block forever) once the peer stops answering
// pings. It stands up a WS server that upgrades, reads the BEARER, then goes SILENT — never
// reads again, so gorilla's server auto-pong never fires (no pong) and it sends no pings.
// The client arms keepalive with short timings and parks on ReadMessage; the read deadline
// must fire and unblock it.
func TestKeepaliveUnblocksParkedReaderOnDeadPeer(t *testing.T) {
	up := websocket.Upgrader{}
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Read exactly the BEARER hello, then stop reading entirely: no auto-pong, no
		// ping, no close frame — the "silently dead tunnel" the fix targets.
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
		<-hold // keep the socket open but utterly unresponsive
		_ = c.Close()
	}))
	defer srv.Close()
	defer close(hold)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()
	if err := ws.WriteMessage(websocket.TextMessage, []byte("BEARER test")); err != nil {
		t.Fatalf("write bearer: %v", err)
	}

	// 40ms ping, 120ms read timeout: a healthy pong would keep resetting the deadline,
	// but this server never pongs, so the parked read must error within ~120ms.
	stop := armWSKeepaliveEvery(ws, 40*time.Millisecond, 120*time.Millisecond)
	defer stop()

	readErr := make(chan error, 1)
	go func() { _, _, e := ws.ReadMessage(); readErr <- e }()

	select {
	case e := <-readErr:
		if e == nil {
			t.Fatal("parked read returned nil error; expected a timeout/close on the dead peer")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parked ReadMessage did NOT unblock — the worker lane would hang forever (regression)")
	}
}

// TestKeepaliveHealthyStaysUp is the other half: on a live peer that answers pings with
// pongs, the parked read must NOT be killed by the deadline. A gorilla server that keeps
// ReadMessage-ing auto-pongs the client's pings, so the deadline keeps resetting.
func TestKeepaliveHealthyStaysUp(t *testing.T) {
	up := websocket.Upgrader{}
	var wg sync.WaitGroup
	wg.Add(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		// Keep reading so gorilla auto-pongs the client's pings (the healthy case). Runs
		// until the client hangs up.
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := ws.WriteMessage(websocket.TextMessage, []byte("BEARER test")); err != nil {
		t.Fatalf("write bearer: %v", err)
	}

	stop := armWSKeepaliveEvery(ws, 40*time.Millisecond, 120*time.Millisecond)

	readErr := make(chan error, 1)
	go func() { _, _, e := ws.ReadMessage(); readErr <- e }()

	// Over 500ms (~12 ping intervals, > 4 read timeouts) the pongs must keep the read
	// alive. A premature error means we'd be tearing down healthy lanes.
	select {
	case e := <-readErr:
		t.Fatalf("healthy parked read errored early (%v) — keepalive is killing live lanes", e)
	case <-time.After(500 * time.Millisecond):
		// still parked & alive — correct
	}

	stop()
	_ = ws.Close()
	wg.Wait()
}
