package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// heldHost stands in for a Host's lane port: it counts each worker's hello,
// then either closes the socket with the code a Host gives a machine it holds,
// or parks it.
type heldHost struct {
	hellos atomic.Int32
	hold   atomic.Bool
	tls    *tls.Config
	dial   func(ctx context.Context) (net.Conn, error)
	url    string
}

func startHeldHost(t *testing.T) *heldHost {
	t.Helper()
	h := &heldHost{}
	h.hold.Store(true)
	up := websocket.Upgrader{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
		h.hellos.Add(1)
		if h.hold.Load() {
			_ = c.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(laneHeldCloseCode, "this bastion is quarantined"), time.Now().Add(time.Second))
			return
		}
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	h.tls = &tls.Config{RootCAs: pool, ServerName: "example.com"}
	addr := srv.Listener.Addr().String()
	h.dial = func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	h.url = "wss://example.com/lane"
	return h
}

// shortHolds makes the holds short enough for a test. Set before any worker
// runs, and never from a parallel subtest.
func shortHolds(t *testing.T, first, max time.Duration) {
	t.Helper()
	f, m := laneHoldFirst, laneHoldMax
	laneHoldFirst, laneHoldMax = first, max
	t.Cleanup(func() { laneHoldFirst, laneHoldMax = f, m })
}

// ownHold gives a test its own pairing's hold, and forgets it after.
func ownHold(t *testing.T, host string) {
	t.Helper()
	laneHolds.Delete(host)
	t.Cleanup(func() { laneHolds.Delete(host) })
}

// Every lane's pool, so a lane added later without the hold is caught.
func lanePools(dir string) map[string]func(ctx context.Context, host string, h *heldHost, n int) {
	return map[string]func(ctx context.Context, host string, h *heldHost, n int){
		"egress": func(ctx context.Context, host string, h *heldHost, n int) {
			var d net.Dialer
			runEgressWorkers(ctx, host, h.url, h.tls, h.dial, "b", d.DialContext, n)
		},
		"serve": func(ctx context.Context, host string, h *heldHost, n int) {
			runServeWorkers(ctx, host, dir, h.url, h.tls, h.dial, "b", n)
		},
		"mgmt": func(ctx context.Context, host string, h *heldHost, n int) {
			runMgmtWorkers(ctx, host, h.url, h.tls, h.dial, "b", dir, dir, dir, n)
		},
		"harness": func(ctx context.Context, host string, h *heldHost, n int) {
			runHarnessWorkers(ctx, host, dir, h.url, h.tls, h.dial, "b", n)
		},
		"session": func(ctx context.Context, host string, h *heldHost, n int) {
			runSessionWorkers(ctx, host, h.url, h.tls, h.dial, "b", n,
				sessionEnv{CtxRoot: dir, DcnDir: dir, HostName: host, Server: "test"})
		},
	}
}

// A Host that holds this machine closes every worker socket with 4403. No
// worker of any lane dials it again before the hold is over: one hello per
// worker, where a pool used to dial again at once or a second later, 30 to 80
// times a second from one held machine.
func TestEveryLanePoolWaitsOutAHostThatHoldsThisMachine(t *testing.T) {
	shortHolds(t, 3*time.Second, time.Minute)
	for lane, run := range lanePools(t.TempDir()) {
		t.Run(lane, func(t *testing.T) {
			t.Parallel()
			host := "held-" + lane + ".example.test"
			ownHold(t, host)
			h := startHeldHost(t)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			const n = 2
			go run(ctx, host, h, n)
			time.Sleep(2 * time.Second)
			if got := h.hellos.Load(); got != n {
				t.Fatalf("%d dials within the hold from %d workers; want one each", got, n)
			}
		})
	}
}

// A beat whose reply says quarantined stops the lanes before any of them
// dials, and the first beat that no longer says it brings them back at once.
func TestABeatThatSaysQuarantinedStopsTheLanesUntilOneDoesNot(t *testing.T) {
	host := "quarantined.example.test"
	shortHolds(t, time.Hour, time.Hour)
	ownHold(t, host)
	h := startHeldHost(t)
	h.hold.Store(false)
	laneHoldFor(host).fromBeat(host, beatSaysQuarantined([]byte(`{"ok":true,"quarantined":true}`)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	const n = 2
	go lanePools(t.TempDir())["mgmt"](ctx, host, h, n)
	time.Sleep(700 * time.Millisecond)
	if got := h.hellos.Load(); got != 0 {
		t.Fatalf("%d dials while the Host says it holds this machine", got)
	}
	laneHoldFor(host).fromBeat(host, beatSaysQuarantined([]byte(`{"ok":true}`)))
	deadline := time.Now().Add(3 * time.Second)
	for h.hellos.Load() < n && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := h.hellos.Load(); got != n {
		t.Fatalf("after the release, %d of %d workers parked again", got, n)
	}
}

// A pool's workers are refused together, so a refusal inside a hold is that
// hold's; each hold after one runs out is twice as long, up to the most; a
// refusal long after the last starts again from the first; a release ends a
// hold at once.
func TestAHoldDoublesOncePerHoldUpToItsMost(t *testing.T) {
	host := "doubling.example.test"
	shortHolds(t, time.Second, 4*time.Second)
	ownHold(t, host)
	h := laneHoldFor(host)
	expire := func() {
		h.mu.Lock()
		h.until = time.Now().Add(-time.Millisecond)
		h.mu.Unlock()
	}
	wait := func() time.Duration {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.wait
	}
	h.refused(host)
	h.refused(host)
	h.refused(host)
	if got := wait(); got != time.Second {
		t.Fatalf("three refusals in one hold: %s, want the first hold", got)
	}
	var got []string
	for range 3 {
		expire()
		h.refused(host)
		got = append(got, wait().String())
	}
	if strings.Join(got, " ") != "2s 4s 4s" {
		t.Fatalf("holds after the first: %v, want 2s 4s 4s", got)
	}
	expire()
	h.mu.Lock()
	h.last = time.Now().Add(-9 * time.Second)
	h.mu.Unlock()
	h.refused(host)
	if got := wait(); got != time.Second {
		t.Fatalf("a refusal after a long quiet: %s, want the first hold again", got)
	}
	h.fromBeat(host, true)
	h.fromBeat(host, false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if !h.waitClear(ctx) {
		t.Fatal("a release must end the hold at once")
	}
}

func TestBeatSaysQuarantinedReadsOnlyTheHostsTrue(t *testing.T) {
	for body, want := range map[string]bool{
		`{"ok":true,"quarantined":true}`:  true,
		`{"ok":true,"quarantined":false}`: false,
		`{"ok":true}`:                     false,
		`{"quarantined":"yes"}`:           false,
		`not json`:                        false,
		``:                                false,
	} {
		if got := beatSaysQuarantined([]byte(body)); got != want {
			t.Errorf("%q: %v, want %v", body, got, want)
		}
	}
}
