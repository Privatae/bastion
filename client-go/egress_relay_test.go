//go:build !windows

// The egress worker pool (egress_relay.go: runEgressWorkers) against a
// stand-in Host's /bastion-egress: how fast workers park again after a job
// they took and after one they refused. Uses localEgressFixture
// (egress_local_test.go), so it carries the same build tag.

package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// egressHost is a Host's /bastion-egress as the pool meets it: every worker
// that parks is counted and handed the job job(n) (n is its place in line),
// and what the bastion answered is read to its end.
type egressHost struct {
	parked atomic.Int32
	ok     atomic.Int32 // answers that began "HTTP/1.1 200"
}

func startEgressHost(t *testing.T, job func(n int32) string) (*egressHost, string, func(context.Context) (net.Conn, error)) {
	t.Helper()
	h := &egressHost{}
	up := websocket.Upgrader{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		if _, _, err := c.ReadMessage(); err != nil { // BEARER
			return
		}
		n := h.parked.Add(1)
		if err := c.WriteMessage(websocket.BinaryMessage, append([]byte{'D'}, job(n)...)); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var answer strings.Builder
		for {
			_, m, err := c.ReadMessage()
			if err != nil || len(m) == 0 || m[0] == 'E' {
				break
			}
			answer.Write(m[1:])
		}
		if strings.HasPrefix(answer.String(), "HTTP/1.1 200") {
			h.ok.Add(1)
		}
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Start()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	return h, "ws://" + addr + "/bastion-egress", dial
}

// runEgressPool runs egressWorkerCount workers for the test's life, and at its
// end stops them and waits until each has exited: a worker still vetting a job
// would otherwise read the fixture's stubs while the test's cleanup puts them
// back.
func runEgressPool(t *testing.T, wsURL string, dialHost func(context.Context) (net.Conn, error), dialOut egressDialer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	wait := runEgressWorkers(ctx, "home.host.example", wsURL, nil, dialHost, "test-bearer", dialOut, egressWorkerCount)
	t.Cleanup(func() {
		cancel()
		done := make(chan struct{})
		go func() { wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the egress workers did not exit 10 s after the pool stopped")
		}
	})
}

// SECURITY (this machine's resources): a Host that answers every parked egress
// worker with a job this machine refuses (a request for this machine, a line
// that is no request) cannot make it dial, handshake and refuse in a loop as
// fast as the Host answers. Each worker that refused waits before it parks
// again, so the pool costs at most egressWorkerCount dials a second.
//
// MUTATION: in runEgressWorkers, park again at once whatever handleEgressConn
// reports (as the pool did).
// RESULT: red — hundreds of workers park in the 2 s window.
func TestARefusingHostCannotSpinTheEgressWorkers(t *testing.T) {
	localEgressFixture(t)
	var dialled atomic.Int32
	dialOut := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialled.Add(1)
		return nil, io.EOF
	}
	h, wsURL, dialHost := startEgressHost(t, func(n int32) string {
		if n%2 == 0 {
			return "NOT-A-REQUEST\r\n"
		}
		return "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n"
	})
	runEgressPool(t, wsURL, dialHost, dialOut)
	time.Sleep(2 * time.Second)
	// egressWorkerCount park at the start, then each worker once a second:
	// about 12 in 2 s. A pool that parks again at once makes hundreds.
	n := h.parked.Load()
	t.Logf("%d workers parked in 2 s", n)
	if limit := int32(egressWorkerCount * 4); n > limit {
		t.Fatalf("%d egress workers parked in 2 s on a Host that refuses every job (at most %d): the pool re-dials in a loop", n, limit)
	}
	if n < egressWorkerCount {
		t.Fatalf("only %d workers parked: the pool did not run, so the count proves nothing", n)
	}
	if d := dialled.Load(); d != 0 {
		t.Fatalf("a refused job was dialled out %d times", d)
	}
}

// The person's own traffic is not slowed: a worker that took a job parks again
// at once, so 40 jobs through 4 workers finish in a fraction of the time one
// wait per job would take (40 / 4 x egressRefusedWait = 10 s).
//
// MUTATION: in runEgressWorkers, wait egressRefusedWait after every job.
// RESULT: red — 40 jobs need about 10 s.
func TestEgressWorkersParkAgainAtOnceAfterAJobTheyTook(t *testing.T) {
	localEgressFixture(t)
	dialOut := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "198.51.100.9:443" {
			t.Errorf("dialled %q, not the address the request named", addr)
		}
		ours, theirs := net.Pipe()
		_ = theirs.Close() // the destination accepts and ends at once
		return ours, nil
	}
	h, wsURL, dialHost := startEgressHost(t, func(int32) string {
		return "CONNECT 198.51.100.9:443 HTTP/1.1\r\nHost: 198.51.100.9:443\r\n\r\n"
	})
	start := time.Now()
	runEgressPool(t, wsURL, dialHost, dialOut)
	const jobs = 40
	deadline := start.Add(10 * time.Second)
	for h.ok.Load() < jobs && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	took := time.Since(start)
	t.Logf("%d accepted jobs answered in %v", h.ok.Load(), took)
	if got := h.ok.Load(); got < jobs {
		t.Fatalf("only %d of %d accepted jobs were answered 200 in %v", got, jobs, took)
	}
	if limit := 3 * egressRefusedWait; took > limit {
		t.Fatalf("%d accepted jobs took %v (over %v): a worker that took a job waited before it parked again", jobs, took, limit)
	}
}
