//go:build !windows

package main

// What a paired host sends down the harness, session, root-exec and mirror
// lanes, and what a coder run sends its egress proxy, is read at the size this
// machine chose (lane_bounds.go). Every test here drives only code that main
// already has, so each one also runs against main, where it fails.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// hostSendsAJob is a host that writes one job frame while it reads the box's
// replies, and reports whether its write completed and what came back.
type hostResult struct {
	werr   error
	frames map[byte][]byte
}

func hostSendsAJob(frame []byte, out chan<- hostResult) func(c *websocket.Conn) {
	return hostSendsAJobAs(func(c *websocket.Conn) error {
		return c.WriteMessage(websocket.BinaryMessage, frame)
	}, out)
}

// writeInPieces writes msg as ONE message carried by many small frames: the
// writer flushes a continuation frame each time its 4 KiB buffer fills
// (gorilla's default write buffer), so a bound that counted a frame instead
// of the message would let all of it through.
func writeInPieces(msg []byte) func(c *websocket.Conn) error {
	return func(c *websocket.Conn) error {
		w, err := c.NextWriter(websocket.BinaryMessage)
		if err != nil {
			return err
		}
		for off := 0; off < len(msg); off += 1 << 10 {
			if _, err := w.Write(msg[off:min(off+1<<10, len(msg))]); err != nil {
				return err
			}
		}
		return w.Close()
	}
}

func hostSendsAJobAs(write func(c *websocket.Conn) error, out chan<- hostResult) func(c *websocket.Conn) {
	return func(c *websocket.Conn) {
		got := map[byte][]byte{}
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
			for {
				_, d, err := c.ReadMessage()
				if err != nil || len(d) == 0 {
					return
				}
				got[d[0]] = append(got[d[0]], d[1:]...)
				if d[0] == 'X' {
					return
				}
			}
		}()
		werr := write(c)
		<-readDone
		out <- hostResult{werr, got}
	}
}

// jsonFrame is tag + a JSON object whose field `pad` carries n bytes of 'a'.
func jsonFrame(tag byte, head string, n int) []byte {
	b := make([]byte, 0, len(head)+n+16)
	b = append(b, tag)
	b = append(b, head...)
	b = append(b, `,"pad":"`...)
	b = append(b, bytes.Repeat([]byte{'a'}, n)...)
	b = append(b, `"}`...)
	return b
}

// A harness spec far past the bound is not read to its end: the box answers
// that it is too large, names the bound, and closes, so the host's write of
// the rest fails. On main the box read all of it into memory, then ran it.
func TestHarnessWorkerStopsReadingASpecPastItsBound(t *testing.T) {
	const frame = 96 << 20
	out := make(chan hostResult, 1)
	box := boxLaneHost(t, hostSendsAJob(jsonFrame('H', `{"harness_id":"big","mode":"echo","prompt":"ping"`, frame), out))
	handleHarnessConn(box, "", "")
	_ = box.Close()
	r := <-out
	if r.werr == nil {
		t.Fatalf("the box read the whole %d MiB spec (it replied %.200q); it must stop at its bound", frame>>20, r.frames['J'])
	}
	if !strings.Contains(string(r.frames['J']), "more than the 32 MiB") || string(r.frames['X']) != "1" {
		t.Fatalf("want a refusal naming the 32 MiB bound and exit 1: J=%.200q X=%q", r.frames['J'], r.frames['X'])
	}
}

// The bound counts the whole message, not one frame of it: a spec past the
// bound, sent as one message in thousands of 4 KiB frames, is refused the same
// way and not read to its end. On main the box read all of it.
func TestHarnessWorkerBoundCountsEveryFrameOfTheSpec(t *testing.T) {
	const frame = 40 << 20
	out := make(chan hostResult, 1)
	spec := jsonFrame('H', `{"harness_id":"pieces","mode":"echo","prompt":"ping"`, frame)
	box := boxLaneHost(t, hostSendsAJobAs(writeInPieces(spec), out))
	handleHarnessConn(box, "", "")
	_ = box.Close()
	r := <-out
	if r.werr == nil {
		t.Fatalf("the box read the whole %d MiB spec sent in small frames (it replied %.200q); it must stop at its bound", frame>>20, r.frames['J'])
	}
	if !strings.Contains(string(r.frames['J']), "more than the 32 MiB") || string(r.frames['X']) != "1" {
		t.Fatalf("want a refusal naming the 32 MiB bound and exit 1: J=%.200q X=%q", r.frames['J'], r.frames['X'])
	}
}

// The same for a session spec sent in small frames.
func TestSessionWorkerBoundCountsEveryFrameOfTheSpec(t *testing.T) {
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	withSink(t)
	const frame = 64 << 20
	out := make(chan hostResult, 1)
	spec := jsonFrame('S', `{"op":"session:open","session_id":"sess-pieces"`, frame)
	box := boxLaneHost(t, hostSendsAJobAs(writeInPieces(spec), out))
	handleSessionWorkerConn(box, "", env)
	_ = box.Close()
	r := <-out
	if r.werr == nil {
		t.Fatalf("the box read the whole %d MiB session spec sent in small frames (E=%q X=%q); it must stop at its bound",
			frame>>20, r.frames['E'], r.frames['X'])
	}
	if !strings.Contains(string(r.frames['E']), "more than the 1024 KiB") || string(r.frames['X']) != "1" {
		t.Fatalf("want a refusal naming the bound and exit 1: E=%q X=%q", r.frames['E'], r.frames['X'])
	}
}

// A spec the lane can carry still runs: a tree as large as the most this lane
// hands back (12 MiB in base64), with room on top, past the 16 MiB a host
// takes in.
func TestHarnessWorkerTakesALargeSpecTheLaneCarries(t *testing.T) {
	out := make(chan hostResult, 1)
	box := boxLaneHost(t, hostSendsAJob(jsonFrame('H', `{"harness_id":"tree","mode":"echo","prompt":"ping","worktree_b64":"dGFy"`, 20<<20), out))
	handleHarnessConn(box, "", "")
	r := <-out
	if r.werr != nil {
		t.Fatalf("the host could not send a 20 MiB spec: %v", r.werr)
	}
	var res map[string]any
	if err := json.Unmarshal(r.frames['J'], &res); err != nil || res["ok"] != true || res["echo"] != "ping" {
		t.Fatalf("a 20 MiB spec did not run: J=%.300q X=%q", r.frames['J'], r.frames['X'])
	}
}

// The same on a session worker: an S frame far past its 1 MiB bound is
// refused by name and not read to its end.
func TestSessionWorkerStopsReadingASpecPastItsBound(t *testing.T) {
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	withSink(t) // a box that wrongly took the spec opens no real shell
	const frame = 64 << 20
	out := make(chan hostResult, 1)
	box := boxLaneHost(t, hostSendsAJob(jsonFrame('S', `{"op":"session:open","session_id":"sess-big"`, frame), out))
	handleSessionWorkerConn(box, "", env)
	_ = box.Close()
	r := <-out
	if r.werr == nil {
		t.Fatalf("the box read the whole %d MiB session spec (E=%q X=%q); it must stop at its bound",
			frame>>20, r.frames['E'], r.frames['X'])
	}
	if !strings.Contains(string(r.frames['E']), "more than the 1024 KiB") || string(r.frames['X']) != "1" {
		t.Fatalf("want a refusal naming the bound and exit 1: E=%q X=%q", r.frames['E'], r.frames['X'])
	}
}

// A session spec near its bound (a grant, and room the size of a root command
// escaped six times over) still opens a terminal.
func TestSessionWorkerOpensASpecNearItsBound(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	withFake(t)
	// Here the test is the host: it takes the server end, and the box runs on
	// the dialled end.
	hostEnd := make(chan *websocket.Conn, 1)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	boxEnd := boxLaneHost(t, func(c *websocket.Conn) { hostEnd <- c; <-hold })
	b := <-hostEnd
	head := fmt.Sprintf(`{"op":"session:open","session_id":"sess-near","grant_terms_b64":%q,"grant_sig_b64":%q`, terms, sig)
	done := make(chan struct{})
	go func() { defer close(done); handleSessionWorkerConn(boxEnd, "", env) }()
	if err := b.WriteMessage(websocket.BinaryMessage, jsonFrame('S', head, 900<<10)); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteMessage(websocket.BinaryMessage, []byte("Ihello\n")); err != nil {
		t.Fatal(err)
	}
	got := readUntil(t, b, 'O', 5*time.Second)
	if string(got['O']) != "hello\n" {
		t.Fatalf("a 900 KiB spec did not open a terminal: %q", got)
	}
	_ = b.Close()
	<-done
}

// sinkProc is a terminal that counts what is typed into it and prints nothing.
type sinkProc struct {
	n      atomic.Int64
	killed chan struct{}
	once   sync.Once
}

func (p *sinkProc) Read(b []byte) (int, error)  { <-p.killed; return 0, io.EOF }
func (p *sinkProc) Write(b []byte) (int, error) { p.n.Add(int64(len(b))); return len(b), nil }
func (p *sinkProc) Resize(c, r int) error       { return nil }
func (p *sinkProc) Wait() int                   { <-p.killed; return 0 }
func (p *sinkProc) Kill()                       { p.once.Do(func() { close(p.killed) }) }
func (p *sinkProc) User() string                { return "sink" }
func (p *sinkProc) Shell() string               { return "/bin/sink" }

func withSink(t *testing.T) *sinkProc {
	t.Helper()
	sp := &sinkProc{killed: make(chan struct{})}
	old := sessionSpawn
	sessionSpawn = func(op, shell string, cols, rows int) (sessionProc, error) { return sp, nil }
	t.Cleanup(func() { sessionSpawn = old; sp.Kill() })
	return sp
}

func waitFor(d time.Duration, cond func() bool) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// Terminal input is streamed into the pty: a 16 MiB paste, the most a host
// relays in one frame, all arrives, and the box never holds it whole.
func TestSessionInputIsStreamedIntoTheTerminal(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	sp := withSink(t)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, GrantB64: terms, SigB64: sig, SessionID: "sess-paste"})
	const paste = 16 << 20
	frame := append([]byte{'I'}, bytes.Repeat([]byte{'x'}, paste)...)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	if !waitFor(20*time.Second, func() bool { return sp.n.Load() >= paste }) {
		t.Fatalf("the terminal got %d of %d bytes", sp.n.Load(), paste)
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("typing a %d MiB paste allocated %d MiB: the frame was held whole", paste>>20, grew>>20)
	}
}

// One frame of input past the most a host relays ends the session, and the
// terminal never receives all of it.
func TestSessionInputFramePastItsBoundEndsTheSession(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	sp := withSink(t)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, GrantB64: terms, SigB64: sig, SessionID: "sess-huge"})
	const frame = 17 << 20
	go func() {
		_ = ws.WriteMessage(websocket.BinaryMessage, append([]byte{'I'}, bytes.Repeat([]byte{'x'}, frame)...))
	}()
	ended := func() bool {
		select {
		case <-sp.killed:
			return true
		default:
			return false
		}
	}
	if !waitFor(20*time.Second, ended) {
		t.Fatalf("a %d MiB input frame did not end the session; the terminal got %d bytes", frame>>20, sp.n.Load())
	}
	if n := sp.n.Load(); n >= frame {
		t.Fatalf("the terminal received all %d bytes of a frame past the bound", n)
	}
}

// The mirror forwarder streams a host frame into the replica's socket: reading
// 4 KiB of a 64 MiB frame does not need the frame held whole.
func TestMirrorForwarderStreamsAHostFrame(t *testing.T) {
	const frame = 64 << 20
	payload := bytes.Repeat([]byte{'m'}, frame)
	start := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, _, _ = c.ReadMessage() // the BEARER hello
		<-start
		_ = c.WriteMessage(websocket.BinaryMessage, payload)
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	dialer := &websocket.Dialer{NetDialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
	boxEnd, replica := net.Pipe()
	defer replica.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pipeMirrorConn(ctx, boxEnd, dialer, "ws://"+addr+"/", "b")
	buf := make([]byte, 4096)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	close(start)
	_ = replica.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(replica, buf); err != nil || buf[0] != 'm' {
		t.Fatalf("the replica read: %v", err)
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("passing 4 KiB of a %d MiB host frame to the replica allocated %d MiB: the frame was held whole",
			frame>>20, grew>>20)
	}
}

// The forwarder carries at most eight connections at once. It listens on a
// fixed port (5433), so the test needs that port free: run it in its own
// network namespace on a machine where something already holds it.
func TestMirrorForwarderCapsConnectionsInFlight(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:5433")
	if err != nil {
		t.Skipf("127.0.0.1:5433 is in use here (%v); run this test in its own network namespace", err)
	}
	_ = probe.Close()
	var live, most atomic.Int64
	release := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		n := live.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		<-release
		live.Add(-1)
	}))
	defer srv.Close()
	defer close(release)
	addr := srv.Listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveMirrorForward(ctx, "127.0.0.1", "127.0.0.0/8", "ws://"+addr+"/", nil,
		func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", addr) }, "b")
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	if !waitFor(5*time.Second, func() bool {
		c, err := net.Dial("tcp", "127.0.0.1:5433")
		if err == nil {
			conns = append(conns, c)
		}
		return err == nil
	}) {
		t.Fatal("the forwarder never listened")
	}
	for i := 1; i < 12; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:5433")
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	waitFor(3*time.Second, func() bool { return most.Load() >= 12 })
	if m := most.Load(); m != 8 {
		t.Fatalf("12 local connections made %d WebSockets to the host at once; want 8", m)
	}
}

// A coder run's egress proxy reads a request head under a bound: a request
// line that never ends is not read to its end.
func TestCoderEgressHeadIsBounded(t *testing.T) {
	boxEnd, runEnd := net.Pipe()
	var refused int64
	done := make(chan struct{})
	go func() { defer close(done); handleCoderEgressConn(boxEnd, nil, &refused) }()
	chunk := bytes.Repeat([]byte{'a'}, 64<<10)
	_, _ = runEnd.Write([]byte("GET http://example.invalid/"))
	sent := 0
	var werr error
	for sent < 8<<20 {
		_ = runEnd.SetWriteDeadline(time.Now().Add(5 * time.Second))
		var n int
		n, werr = runEnd.Write(chunk)
		sent += n
		if werr != nil {
			break
		}
	}
	_ = runEnd.Close()
	<-done
	if werr == nil {
		t.Fatalf("the proxy read %d MiB of a request line with no end; it must stop at a bound", sent>>20)
	}
}

// A coder run's proxy carries at most 1024 connections at once; the next is
// answered 503 at once, never left waiting.
func TestCoderEgressCapsConnectionsInFlight(t *testing.T) {
	dir := t.TempDir()
	run := "lane-bounds-test"
	if err := coderListenEgress(run, dir, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	defer coderCloseEgress(run)
	sock := filepath.Join(dir, coderEgressSock)
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for i := 0; i < 1024; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
				t.Skipf("this process may not open %d sockets: %v", 2*1024, err)
			}
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	// Every one of them is idle in its head, so the proxy holds them all.
	time.Sleep(200 * time.Millisecond)
	extra, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	conns = append(conns, extra)
	_ = extra.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, _ := io.ReadAll(io.LimitReader(extra, 256))
	if !strings.HasPrefix(string(line), "HTTP/1.1 503") {
		t.Fatalf("connection 1025 of one run got %q; want a 503 at once", line)
	}
}
