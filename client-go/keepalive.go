package main

import (
	"time"

	"github.com/gorilla/websocket"
)

// The worker lanes (egress / mgmt / harness) are reverse-relay WebSockets the bastion
// opens TO the host and then PARKS on — blocked in ReadMessage until the host dispatches
// a job. The transport is the WireGuard tunnel through the host's pod-Hub. When that Hub's
// userspace netstack vanishes (a pod roll or Hub sidecar restart) the TCP session is
// severed with NO FIN/RST reaching us — so a parked ReadMessage blocks FOREVER and the
// lane stays dark until the process is restarted by hand. (The heartbeat and the
// per-request lanes self-heal because they dial per request; only these long-parked
// workers are affected.)
//
// armWSKeepalive makes that silently-dead tunnel observable. The bastion pings the host
// on an interval and holds a read deadline that every pong (or server-initiated ping)
// pushes forward. Lose the peer -> pongs stop -> the read deadline fires -> the parked
// ReadMessage returns an error -> the worker loop's reconnect kicks in. On a healthy lane
// the deadline never trips: the host's WebSocket layer answers our pings with pongs at the
// protocol level (below the app handler), so an idle-but-alive worker is refreshed every
// interval.
const (
	wsPingInterval = 20 * time.Second
	wsReadTimeout  = 70 * time.Second // > 3 ping intervals: tolerate a couple of dropped pongs
	wsWriteWait    = 10 * time.Second
)

// armWSKeepalive installs the read deadline + pong/ping handlers and starts a background
// pinger for one worker connection. It MUST be called from the worker's own goroutine
// BEFORE that goroutine starts reading: SetReadDeadline / SetPongHandler / SetPingHandler
// are read-side state, and the returned stop() is the only other toucher of the ping
// goroutine. WriteControl (the ping) is safe to call concurrently with the worker's
// WriteMessage sends, per gorilla's concurrency contract. Call the returned stop() once
// the job finishes (normally) so the pinger exits; it is safe to call exactly once.
func armWSKeepalive(ws *websocket.Conn) (stop func()) {
	return armWSKeepaliveEvery(ws, wsPingInterval, wsReadTimeout)
}

// armWSKeepaliveEvery is armWSKeepalive with injectable timings (tests use short ones).
func armWSKeepaliveEvery(ws *websocket.Conn, interval, timeout time.Duration) (stop func()) {
	extend := func() { _ = ws.SetReadDeadline(time.Now().Add(timeout)) }
	extend()
	ws.SetPongHandler(func(string) error { extend(); return nil })
	// A server-initiated ping is also proof of life: keep gorilla's default pong reply
	// AND push the deadline (the host's server pings by default — belt and suspenders).
	ws.SetPingHandler(func(appData string) error {
		extend()
		_ = ws.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(wsWriteWait))
		return nil
	})
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(wsWriteWait)); err != nil {
					// Write failed => the peer is gone and the buffer won't drain.
					// Force-close so the parked reader unblocks immediately instead of
					// waiting out the full read deadline.
					_ = ws.Close()
					return
				}
			}
		}
	}()
	return func() { close(done) }
}
