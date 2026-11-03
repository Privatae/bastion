//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// freeDoorAddr is a loopback port nothing listens on.
func freeDoorAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	_ = ln.Close()
	return a
}

// syncBuf is a bytes.Buffer two goroutines can share.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// openWindowFor runs `pair --open` on addr in the background and returns the
// code it shows, its output, and its result.
func openWindowFor(t *testing.T, addr string) (code string, out *syncBuf, result <-chan error) {
	t.Helper()
	prevPoll := windowPollEvery
	windowPollEvery = 20 * time.Millisecond
	t.Cleanup(func() { windowPollEvery = prevPoll })
	out = &syncBuf{}
	res := make(chan error, 1)
	go func() { res <- cmdPairOpen(addr, out) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if w := loadOpenWindow(); w != nil && strings.Contains(out.String(), formatWindowCode(w.Code)) {
			return w.Code, out, res
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pair --open showed no code: %q", out.String())
	return "", nil, nil
}

func pairingAuditText(t *testing.T) string {
	t.Helper()
	d, _ := configDir()
	b, _ := os.ReadFile(filepath.Join(d, "pairing_audit.jsonl"))
	return string(b)
}

// The code the person reads is the code both sides key the proofs with,
// however it is typed back.
func TestTheWindowCodeIsReadBackHoweverItIsTyped(t *testing.T) {
	c, err := newWindowCode()
	if err != nil || normalizeWindowCode(c) != c || len(c) != windowCodeLen {
		t.Fatalf("a fresh code is not normalised: %q %v", c, err)
	}
	f := formatWindowCode(c)
	if strings.Count(f, "-") != 3 || normalizeWindowCode(f) != c || normalizeWindowCode(strings.ToLower(f)) != c {
		t.Fatalf("the shown code %q does not read back as %q", f, c)
	}
	if normalizeWindowCode("O1IL0-00000-00000-00000") != "01110000000000000000" {
		t.Fatal("O, I and L read as the digits they look like")
	}
	for _, bad := range []string{"", "ABCDE", c + "0", strings.Replace(c, c[:1], "U", 1)} {
		if normalizeWindowCode(bad) != "" {
			t.Fatalf("%q is not a code", bad)
		}
	}
	for args, want := range map[string]string{"--open": doorDefaultAddr, "--open --port 9443": ":9443", "--port=9443 --open": ":9443"} {
		got, ok, err := parsePairOpenArgs(strings.Fields(args))
		if !ok || err != nil || got != want {
			t.Fatalf("%s: %q %v %v", args, got, ok, err)
		}
	}
	for _, args := range []string{"--open --port 0", "--open --port x", "--open skb_x"} {
		if _, ok, err := parsePairOpenArgs(strings.Fields(args)); !ok || err == nil {
			t.Fatalf("%s must be refused", args)
		}
	}
	if _, ok, _ := parsePairOpenArgs([]string{"skb_x"}); ok {
		t.Fatal("a token pair is not --open")
	}
}

// A Host that connects pairs through the window: the code proved both ways,
// the pairing saved with its CA pinned and no address to dial, the window
// closed after one use, and each step in the audit.
func TestAHostThatConnectsPairsThroughTheWindow(t *testing.T) {
	pairingBox(t)
	addr := freeDoorAddr(t)
	code, out, res := openWindowFor(t, addr)
	ca := newTestCA(t, "home host CA")
	h := newStandinHost(t, ca, "home", "home.cseries.localhost", addr)
	done, err := h.pair(formatWindowCode(code))
	if err != nil {
		t.Fatalf("%v\n%s", err, pairingAuditText(t))
	}
	if done.State != pairingActive || done.HostName != "home.cseries.localhost" {
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
	if !strings.Contains(out.String(), "Your Host connects to this server") || !strings.Contains(out.String(), "Paired with home.cseries.localhost") {
		t.Fatalf("what the person reads:\n%s", out.String())
	}
	cfgs, _ := loadPairings()
	c := pairingFor(cfgs, "home")
	if c == nil || !c.hostDials() || c.DoorAddr != addr || c.LaneAddr != "" || !sameCAs(c.CACert, ca.pem) ||
		!strings.HasPrefix(c.Bearer, "mcp_dials_home_") || operatorCertRefusal(c.OperatorCert, ca.pem, c.OperatorKey) != nil {
		t.Fatalf("the pairing: %+v", c)
	}
	if w := readWindowFile(); w != nil {
		t.Fatalf("the window outlived its pairing: %+v", w)
	}
	// One use: the same code again finds no window.
	if _, err := h.pair(code); err == nil {
		t.Fatal("a used code paired again")
	}
	a := pairingAuditText(t)
	for _, op := range []string{`"window_opened"`, `"window_paired"`} {
		if !strings.Contains(a, op) {
			t.Fatalf("the audit has no %s:\n%s", op, a)
		}
	}
}

// SECURITY: a wrong code gets nothing, costs a wait that doubles, and the
// fifth closes the window. A proof made over another certificate (one
// relayed from another connection) is a wrong code. A Host never signs for a
// server that did not prove the code.
func TestAWrongCodeIsThrottledAndClosesTheWindow(t *testing.T) {
	pairingBox(t)
	prev := windowFailWait
	windowFailWait = 100 * time.Millisecond
	t.Cleanup(func() { windowFailWait = prev })
	addr := freeDoorAddr(t)
	code, _, res := openWindowFor(t, addr)
	ca := newTestCA(t, "home host CA")
	h := newStandinHost(t, ca, "home", "home.cseries.localhost", addr)

	relayed := newStandinHost(t, ca, "home", "home.cseries.localhost", addr)
	relayed.lieLeaf = true
	if _, err := relayed.pair(code); err == nil {
		t.Fatal("a proof over another certificate paired")
	}
	// The wait after it: the next try, at once, is not even offered a pairing.
	if _, err := h.pair(code); err == nil || !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("a try inside the wait must be refused at the handshake, got %v", err)
	}
	wrong := "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ"
	for i := 2; i <= windowMaxFailures; i++ {
		time.Sleep(time.Duration(1<<(i-2))*windowFailWait + 50*time.Millisecond)
		if _, err := h.pair(wrong); err == nil {
			t.Fatalf("wrong code %d paired", i)
		}
	}
	select {
	case err := <-res:
		if err == nil || !strings.Contains(err.Error(), "wrong codes") {
			t.Fatalf("pair --open after %d wrong codes: %v", windowMaxFailures, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the window stayed open after five wrong codes")
	}
	if _, err := h.pair(code); err == nil {
		t.Fatal("the right code paired after the window closed")
	}
	cfgs, _ := loadPairings()
	if len(cfgs) != 0 || h.csrs != 0 || relayed.csrs != 0 {
		t.Fatalf("a wrong code got something: %d pairings, %d CSRs signed", len(cfgs), h.csrs+relayed.csrs)
	}
	if n := strings.Count(pairingAuditText(t), `"window_wrong_code"`); n != windowMaxFailures {
		t.Fatalf("%d wrong codes audited, want %d", n, windowMaxFailures)
	}

	// The Host's side: a server whose proof does not check gets no signature.
	addr2 := freeDoorAddr(t)
	code2, _, res2 := openWindowFor(t, addr2)
	strict := newStandinHost(t, ca, "home", "home.cseries.localhost", addr2)
	strict.badProof = true
	if d, err := strict.pair(code2); err != nil || d.State != "refused" {
		t.Fatalf("a Host refusing the server's proof: %+v %v", d, err)
	}
	if err := <-res2; err == nil {
		t.Fatal("the window reported a pairing the Host refused")
	}
	if cfgs, _ := loadPairings(); len(cfgs) != 0 || strict.csrs != 0 {
		t.Fatal("a pairing was kept that the Host never signed for")
	}
}

// hostDialsPairingFor is a host-dials pairing with an operator certificate
// from ca and its door on addr.
func hostDialsPairingFor(t *testing.T, ca *testCA, host, addr string) *Config {
	t.Helper()
	c := tcpPairingFor(t, ca, host, "")
	c.HostDials, c.DoorAddr = true, addr
	c.Bearer = "mcp_dials_lane_bearer"
	return c
}

// runPairingBG runs the pairing until the returned stop.
func runPairingBG(t *testing.T, cfg *Config) (stop func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- runPairing(ctx, cfg) }()
	return func() error {
		cancel()
		select {
		case err := <-errc:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("the pairing did not stop")
		}
		return nil
	}
}

func doorWaitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The lanes run over the connections the Host opens, exactly as over a
// dialled lane port: the heartbeat with the bearer, every worker pool, a
// harness job on a parked worker, every handshake under host.cseries.internal
// and with the operator certificate (the stand-in requires and verifies it).
// The door is bound only while the pairing is served, and the bastion never
// dials anything.
func TestTheLanesRunOverTheConnectionsTheHostOpens(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	ca := newTestCA(t, "home host CA")
	addr := freeDoorAddr(t)
	cfg := hostDialsPairingFor(t, ca, "home.cseries.localhost", addr)
	h := newStandinHost(t, ca, "home", cfg.HostName, addr)
	h.lane.jobs <- []byte(`{"harness_id":"h1","mode":"echo","prompt":"hello over a Host-opened connection"}`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.serveLanes(ctx)

	stop := runPairingBG(t, cfg)
	doorWaitFor(t, 10*time.Second, "the heartbeat and every worker", func() bool {
		hellos, beats := h.lane.snapshot()
		return len(beats) > 0 && len(hellos) >= harnessWorkerCount+sessionWorkerCount+mgmtWorkerCount+egressWorkerCount+serveWorkerCount
	})
	select {
	case r := <-h.lane.replies:
		if !strings.HasSuffix(r, "exit=0") {
			t.Fatalf("the harness job: %s", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a parked harness worker served no job")
	}
	hellos, beats := h.lane.snapshot()
	if beats[0] != "Bearer "+cfg.Bearer {
		t.Fatalf("the heartbeat carries the bearer: %q", beats)
	}
	count := map[string]int{}
	for _, hl := range hellos {
		path, msg, _ := strings.Cut(hl, " ")
		if !strings.HasPrefix(msg, "BEARER "+cfg.Bearer) {
			t.Fatalf("a worker opened without the bearer: %q", hl)
		}
		if strings.Contains(msg, "lane=session") {
			path += " session"
		}
		count[path]++
	}
	if count["/bastion-harness"] < harnessWorkerCount || count["/bastion-harness session"] != sessionWorkerCount ||
		count["/bastion-mgmt"] != mgmtWorkerCount || count["/bastion-egress"] != egressWorkerCount ||
		count["/bastion-serve"] != serveWorkerCount {
		t.Fatalf("the worker pools over Host-opened connections: %v", count)
	}
	h.lane.mu.Lock()
	sni := append([]string(nil), h.lane.sni...)
	h.lane.mu.Unlock()
	for _, n := range sni {
		if n != tcpServerName {
			t.Fatalf("a handshake asked for %q", n)
		}
	}
	if !strings.Contains(pairingAuditText(t), `"host_connected"`) {
		t.Fatal("the Host's connection is not in the audit")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	// Closed with its last pairing.
	doorWaitFor(t, 5*time.Second, "the door to close", func() bool {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
		}
		return err == nil
	})
}

// SECURITY: the door keeps a connection only from the Host whose pinned CA
// its certificate verifies under, for host.cseries.internal, naming the lane
// protocol. Another CA, the right CA under another name, no protocol, and a
// pairing protocol with no window open all end at the handshake: nothing is
// pooled and no lane ever runs on them.
func TestTheDoorRefusesAnythingButItsPinnedHost(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	ca := newTestCA(t, "home host CA")
	addr := freeDoorAddr(t)
	cfg := hostDialsPairingFor(t, ca, "home.cseries.localhost", addr)
	stop := runPairingBG(t, cfg)
	defer stop()
	doorWaitFor(t, 5*time.Second, "the door", func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	})
	impostor := newTestCA(t, "impostor")
	cases := map[string]struct {
		cert   tls.Certificate
		protos []string
	}{
		"another CA":          {impostor.serverCert(t, tcpServerName), []string{laneALPN}},
		"the Host's own name": {ca.serverCert(t, "home.cseries.localhost"), []string{laneALPN}},
		"no protocol":         {ca.serverCert(t, tcpServerName), nil},
		"pairing, no window":  {ca.serverCert(t, tcpServerName), []string{pairALPN}},
	}
	for name, tc := range cases {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		s := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{tc.cert}, NextProtos: tc.protos,
			ClientAuth: tls.RequestClientCert})
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))
		herr := s.Handshake()
		if herr == nil {
			// TLS 1.3: the server's side can finish before the client's
			// verdict arrives; the verdict is the connection closing.
			_, herr = s.Read(make([]byte, 1))
		}
		if herr == nil {
			t.Fatalf("%s: the door kept the connection", name)
		}
		if got := len(s.ConnectionState().PeerCertificates); got != 0 {
			t.Fatalf("%s: the door presented this bastion's certificate to a stranger", name)
		}
		_ = raw.Close()
	}
	// Nothing was pooled: a lane's dial finds no connection. Its wait is
	// cut short by the context: doorTakeWait is a constant, read by every
	// lane, an earlier test's still running ones too.
	short, cancelShort := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelShort()
	if c, err := hostDoorDial(cfg)(short); err == nil {
		_ = c.Close()
		t.Fatal("a refused connection reached the pool")
	}
	if !strings.Contains(pairingAuditText(t), `"door_refused"`) {
		t.Fatal("the refusals are not in the audit")
	}
}

// The Host redials, the bastion never does: a Host that stops and comes back
// gets its lanes again, and so does a bastion that restarts, all on
// connections the Host opens. A connection the Host closes while idle leaves
// the pool at once.
func TestTheHostReconnectsAfterEitherSideRestarts(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	ca := newTestCA(t, "home host CA")
	addr := freeDoorAddr(t)
	cfg := hostDialsPairingFor(t, ca, "home.cseries.localhost", addr)
	h := newStandinHost(t, ca, "home", cfg.HostName, addr)
	beats := func() int { _, b := h.lane.snapshot(); return len(b) }

	stop := runPairingBG(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	go h.serveLanes(ctx)
	doorWaitFor(t, 10*time.Second, "the first heartbeat", func() bool { return beats() >= 1 })

	// The Host stops: every connection closes, and the pool empties.
	cancel()
	doorWaitFor(t, 5*time.Second, "the pool to empty", func() bool {
		doors.Lock()
		d := doors.m[addr]
		doors.Unlock()
		d.mu.Lock()
		p := d.pairings[cfg.HostName]
		d.mu.Unlock()
		return p.live.Load() == 0
	})
	doorWaitFor(t, 5*time.Second, "the Host going away in the audit", func() bool {
		return strings.Contains(pairingAuditText(t), `"host_disconnected"`)
	})
	// It comes back: a beat at once (the reconnect brings the lanes up; the
	// beat loop's next tick or a new run sends it).
	n := beats()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go h.serveLanes(ctx2)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	// The bastion restarts while the Host keeps redialling.
	stop = runPairingBG(t, cfg)
	defer stop()
	doorWaitFor(t, 15*time.Second, "a heartbeat after both restarts", func() bool { return beats() > n })
	if h.dials.Load() < 2*hostSpareConns {
		t.Fatalf("the Host opened %d connections over two runs", h.dials.Load())
	}
}

// The terminal closing the window and a door committing a pairing on it are
// one rename each, across processes: whichever comes first wins. A window
// closed first is never claimed; a window claimed first is reported as the
// pairing it made, never "nothing was paired".
func TestClosingAWindowAndClaimingItCannotBothWin(t *testing.T) {
	pairingBox(t)
	open := func(id string) {
		w := &pairWindow{ID: id, Code: "0123456789ABCDEFGHJK", Door: ":8812", Opened: time.Now().UTC().Format(time.RFC3339),
			Expires: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
		if err := saveWindowFile(w); err != nil {
			t.Fatal(err)
		}
	}
	open("a")
	if removeWindow("a") {
		t.Fatal("an unclaimed window closed as claimed")
	}
	if claimWindow("a") {
		t.Fatal("a window closed at the terminal was claimed")
	}
	open("b")
	if !claimWindow("b") {
		t.Fatal("an open window could not be claimed")
	}
	if !removeWindow("b") {
		t.Fatal("closing a claimed window did not say it was claimed")
	}
	endWindow("b", windowResult{Host: "home.cseries.localhost", State: pairingActive})
	if res := awaitClaimedResult("b"); res == nil || res.Host != "home.cseries.localhost" {
		t.Fatalf("the claimed window's result: %+v", res)
	}
	if claimedWindow("b") != nil {
		t.Fatal("the claimed file outlived its result")
	}
}
