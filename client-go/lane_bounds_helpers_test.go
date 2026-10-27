package main

// The helpers lane_bounds.go and harness.go added for the reads that were
// inline before (the heartbeat reply in run.go, the agent's /run reply in
// driveHarnessAgent, the drains in harness.go and rootexec.go). They have no
// counterpart on main to run against.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// boxLaneHost stands up the HOST side of one worker socket (host runs on the
// upgraded server end) and returns the box side, dialled.
func boxLaneHost(t *testing.T, host func(c *websocket.Conn)) *websocket.Conn {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		host(c)
	}))
	t.Cleanup(srv.Close)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	return ws
}

// endless is a body that never ends; served counts what was taken from it.
type endless struct{ served *atomic.Int64 }

func (e endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'z'
	}
	e.served.Add(int64(len(p)))
	return len(p), nil
}

func TestHeartbeatReplyIsReadOnlyToItsBound(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = io.Copy(w, io.LimitReader(endless{&served}, 64<<20))
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, ok := readHeartbeatReply(resp)
	resp.Body.Close()
	if ok || body != nil {
		t.Fatalf("a 64 MiB heartbeat reply was taken (%d bytes)", len(body))
	}

	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"dcn_grants":{"stores":[]}}`))
	}))
	defer small.Close()
	resp, err = http.Get(small.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, ok = readHeartbeatReply(resp)
	resp.Body.Close()
	if !ok || !strings.Contains(string(body), "dcn_grants") {
		t.Fatalf("an ordinary reply was not taken: ok=%v %q", ok, body)
	}
}

func TestHarnessRunReplyIsReadOnlyToItsBound(t *testing.T) {
	var served atomic.Int64
	if _, err := readHarnessRunReply(endless{&served}); err == nil || !strings.Contains(err.Error(), "more than the 16 MiB") {
		t.Fatalf("an endless /run reply: %v", err)
	}
	if n := served.Load(); n > 17<<20 {
		t.Fatalf("an endless /run reply was read to %d MiB", n>>20)
	}
	big := append([]byte(`{"ok":true,"pad":"`), bytes.Repeat([]byte{'a'}, 15<<20)...)
	big = append(big, `"}`...)
	if rb, err := readHarnessRunReply(bytes.NewReader(big)); err != nil || len(rb) != len(big) {
		t.Fatalf("a 15 MiB reply the lane carries: %d bytes, %v", len(rb), err)
	}
}

// A drained lane holds no frame whole, and ends when the host goes away.
func TestDrainLaneHoldsNoFrame(t *testing.T) {
	const frame = 64 << 20
	payload := bytes.Repeat([]byte{'d'}, frame)
	start := make(chan struct{})
	box := boxLaneHost(t, func(c *websocket.Conn) {
		<-start
		_ = c.WriteMessage(websocket.BinaryMessage, payload)
	})
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	close(start)
	done := make(chan error, 1)
	go func() { done <- drainLane(box) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("drainLane did not return after the host went away")
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("draining a %d MiB frame allocated %d MiB", frame>>20, grew>>20)
	}
}
