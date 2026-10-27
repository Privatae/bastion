package main

// The serve lane (/bastion-serve): how a Host with no platform reaches the
// model servers on this machine.
//
// Over the tunnel the Host dials a forward on the tunnel's stack
// (serveOllamaForward and serveLLMForward in run.go, servePIIForward in
// pii.go). A local pairing (a Host on this machine's socket, or in a VM on
// it over TCP) has no tunnel, so those forwards are absent. This lane turns
// the direction round, as egress does: this machine parks worker WebSockets
// on the Host, and the Host hands each one connection.
//
// THE HOST NAMES A SERVICE, NEVER AN ADDRESS. Its first frame on a worker is
// 'S' + {"service":"ollama"}. The address that service reaches is the one set
// on this machine (OLLAMA_ADDR, PRIVATAE_LLM_ADDR, PRIVATAE_PII_ADDR), read by
// the functions the tunnel forwards read, and it must be this machine: a
// server on another computer on the LAN is refused. Nothing the Host sends
// can name, change or widen a target. The bastion answers 'A' and carries
// the connection, or 'E' + a reason and closes, having dialled nothing.
//
// After 'A' the worker is a wsConn ('D' + bytes, 'E' for the end, both ways)
// handed to the forwards' own code: ollama and llm through proxyInference's
// decision and filter (the model scope, /api/pull and /api/delete refused
// without `models`, the list rewrite, its size bounds), pii through the PII
// scope and a pass-through. The `inference` family is checked on every
// connection, as inferenceRefuser does at a forward's accept.
//
// Bounds, per pairing: 16 streams in flight across the services, the 17th
// answered 'E' busy; a stream with no byte either way for 10 minutes is
// closed, on every service; a response's length is not capped, because a
// long generation is the person's own traffic.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// serveWorkerCount workers stay parked per pairing. A replacement is
	// dialled as soon as one takes a job, so a long stream never holds up the
	// next request.
	serveWorkerCount = 2
	// serveMaxInFlight is the streams one pairing may hold open here at once.
	// It protects this machine and must never be what slows the person down:
	// ollama runs one request per model at a time and queues 512 more, and the
	// Host's own client holds at most 10 connections per server, so a request
	// waits in the server's queue before it waits here.
	serveMaxInFlight = 16
	// serveHelloMax bounds the 'S' frame. A service name and its JSON fit in a
	// fraction of it; anything longer is not a request this lane reads.
	serveHelloMax = 1024
	// serveTargetLookup bounds resolving a target set by name (localhost:11434).
	serveTargetLookup = 2 * time.Second
)

// serveIdleTimeout closes a stream that has carried no byte either way for
// this long. The filter's own read bound (filteredIdleTimeout) covers a request
// being read; this covers the rest: a server that answers headers and then
// nothing, and a pass-through, which has no bound of its own. A var so a test
// can shorten it.
var serveIdleTimeout = filteredIdleTimeout

// serveService is one service the lane carries: its name on the wire, where
// its target is read, which forward's code serves it.
type serveService struct {
	name   string
	envVar string // named in a refusal, so the person knows what to set
	target func() string
	filter bool          // through proxyInference's decision and filter
	lane   inferenceLane // the filter's lane, when filter
}

// serveServices is every service the lane knows, in the order the beat lists
// them. A name not in it is refused before anything is read or dialled.
var serveServices = []serveService{
	{name: "ollama", envVar: "OLLAMA_ADDR", target: localOllamaAddr, filter: true, lane: laneOllama},
	{name: "llm", envVar: "PRIVATAE_LLM_ADDR", target: llmTarget, filter: true, lane: laneLLM},
	{name: "pii", envVar: "PRIVATAE_PII_ADDR", target: piiTarget},
}

func serveServiceNamed(name string) (serveService, bool) {
	for _, s := range serveServices {
		if s.name == name {
			return s, true
		}
	}
	return serveService{}, false
}

// serveLookupIP resolves a target set by name. A seam so a test can answer.
var serveLookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// serveVetTarget checks the address set on this machine for a service and
// returns the addresses to dial, or the reason it is refused. Every address
// the target names must be this machine: loopback, an address on its
// interfaces, or one the kernel delivers here (ownaddr.go), which takes in a
// server in a container on a network made on this machine. A server on
// another computer is refused: a device the bastion does not run on is the
// device lane's problem, solved there with pinning. 0.0.0.0 and :: are listen
// addresses, and dialling one reaches this machine, so each is dialled as
// loopback of its family. The addresses dialled are the ones checked, never
// the name again.
//
// Every address checked is returned, in the resolver's order, and the dial
// tries them in turn (serveDial, servePick), as the OS dialler does with a
// name: localhost answers ::1 first on most systems, and ollama listens on
// 127.0.0.1 only by default, so dialling the first address alone fails where
// a plain dial of the name reaches it.
func serveVetTarget(target string) ([]string, string) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Sprintf("%q is not host:port", target)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Sprintf("%q has no port between 1 and 65535", target)
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), serveTargetLookup)
		as, err := serveLookupIP(ctx, host)
		cancel()
		if err != nil || len(as) == 0 {
			return nil, fmt.Sprintf("%q could not be resolved on this machine", host)
		}
		for _, a := range as {
			ips = append(ips, a.IP)
		}
	}
	for i, ip := range ips {
		switch {
		case ip.IsUnspecified() && ip.To4() != nil:
			ips[i] = net.IPv4(127, 0, 0, 1)
		case ip.IsUnspecified():
			ips[i] = net.IPv6loopback
		}
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			continue
		}
		own, err := ownDestination([]net.IP{ip})
		if err != nil {
			return nil, fmt.Sprintf("this machine could not tell whether %s is its own address (%v)", ip, err)
		}
		if !own {
			return nil, fmt.Sprintf("%s is not this machine; the lane reaches only servers on the computer it runs on", ip)
		}
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		a := net.JoinHostPort(ip.String(), port)
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, ""
}

// serveDialTimeout bounds one dial of a service's addresses, all of them
// together, as the forwards' dial (dialUpstream) bounds its one address.
const serveDialTimeout = 5 * time.Second

// serveDial dials the checked addresses in turn (dialEach: the next starts
// when one fails, or has not answered within the Happy Eyeballs delay) and
// returns the first that answers, with the address it was dialled at. Only
// these addresses are dialled.
func serveDial(addrs []string, timeout time.Duration) (net.Conn, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var mu sync.Mutex
	at := map[net.Conn]string{}
	d := &net.Dialer{}
	c, err := dialEach(ctx, func(ctx context.Context, network, a string) (net.Conn, error) {
		c, err := d.DialContext(ctx, network, a)
		if err == nil {
			mu.Lock()
			at[c] = a
			mu.Unlock()
		}
		return c, err
	}, addrs)
	if err != nil {
		return nil, "", err
	}
	mu.Lock()
	defer mu.Unlock()
	return c, at[c], nil
}

// servePick is the one address an HTTP client here is given for a target
// whose check returned several (the beat's probes, model management): the
// first that accepts a connection, tried in turn as serveDial does, or the
// first checked when none does, so the request fails as it would have. One
// address is returned as it is, with nothing dialled.
func servePick(addrs []string) string {
	if len(addrs) == 1 {
		return addrs[0]
	}
	c, a, err := serveDial(addrs, serveTargetLookup)
	if err != nil {
		return addrs[0]
	}
	_ = c.Close()
	return a
}

// serveTargetFor is the addresses a service dials here, or why it does not.
// The beat and the lane both ask it, so what the beat says is served is what
// the lane reaches (the rule env.go states for the forwards).
func serveTargetFor(s serveService) ([]string, string) {
	t := s.target()
	if t == "" {
		return nil, "unavailable: no " + s.name + " server is set on this machine (" + s.envVar + ")"
	}
	addrs, why := serveVetTarget(t)
	if why != "" {
		return nil, "refused: the " + s.name + " server set on this machine (" + s.envVar + ") is refused: " + why
	}
	return addrs, ""
}

// serveInFlight counts each pairing's open streams, keyed by host name, so a
// pairing restarted while its streams still run counts them.
var serveInFlight sync.Map // string -> *atomic.Int32

func serveAcquire(self string) bool {
	v, _ := serveInFlight.LoadOrStore(self, new(atomic.Int32))
	n := v.(*atomic.Int32)
	for {
		cur := n.Load()
		if cur >= serveMaxInFlight {
			return false
		}
		if n.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func serveRelease(self string) {
	if v, ok := serveInFlight.Load(self); ok {
		v.(*atomic.Int32).Add(-1)
	}
}

// serveHello is the 'S' frame's JSON. Fields this build does not know are
// ignored, so a Host may add one without breaking an older bastion.
type serveHello struct {
	Service string `json:"service"`
}

// serveVerdict decides one job before anything is dialled: the service, the
// family, the PII scope, the target. It returns the service and the addresses,
// or the reason the job is refused.
func serveVerdict(self, name string) (serveService, []string, string) {
	s, ok := serveServiceNamed(name)
	if !ok {
		return s, nil, "refused: " + strconv.Quote(truncate(name, 64)) + " is not a service this lane carries " +
			"(ollama, llm or pii). The lane takes a service's name and reaches the server set on this machine for it; " +
			"it never takes an address."
	}
	if why := capsAllow(self, "inference"); why != "" {
		return s, nil, "refused: " + why
	}
	if s.name == "pii" && !pairingModelScope(self).allowsPII() {
		return s, nil, "refused: this pairing is scoped to named models and the PII sterilizer was not one of them " +
			"(approve with 'pii' in the model list to share it)"
	}
	addrs, why := serveTargetFor(s)
	if why != "" {
		return s, nil, why
	}
	return s, addrs, ""
}

// serveJob serves the one job a parked worker is given. taken is called once
// the job is accepted (its stream counted, before 'A'), so the pool parks a
// replacement while this one works. It reports whether a job was accepted. A
// refused job (malformed, refused, busy) reports false, and its worker waits
// before it parks again: the replacement is not dialled at once, so a Host
// that answers every worker with a frame it knows is refused cannot make this
// machine dial, handshake and write an audit line in a loop as fast as it
// answers.
func serveJob(ws *websocket.Conn, self, dcnDir string, taken func()) bool {
	mt, r, err := ws.NextReader()
	if err != nil {
		return false
	}
	refuse := func(service, why string) {
		_ = ws.WriteMessage(websocket.BinaryMessage, append([]byte{'E'}, why...))
		serveAudit(dcnDir, map[string]any{"service": service, "decision": "refused", "reason": why})
	}
	raw, err := io.ReadAll(io.LimitReader(r, serveHelloMax+1))
	if err != nil {
		return false
	}
	var hello serveHello
	if mt != websocket.BinaryMessage || len(raw) == 0 || raw[0] != 'S' || len(raw) > serveHelloMax ||
		json.Unmarshal(raw[1:], &hello) != nil {
		// Malformed: answered, not audited (as a malformed terminal request is not).
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte("Erefused: the first frame on this lane is 'S' and "+
			"{\"service\":\"<name>\"}, at most 1024 bytes"))
		return false
	}
	s, addrs, why := serveVerdict(self, hello.Service)
	if why != "" {
		refuse(truncate(hello.Service, 64), why)
		return false
	}
	if !serveAcquire(self) {
		refuse(s.name, fmt.Sprintf("busy: this pairing already has %d streams open on this machine, "+
			"which is as many as it may hold; try again when one ends", serveMaxInFlight))
		return false
	}
	defer serveRelease(self)
	taken()
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte{'A'}); err != nil {
		return true
	}
	w := newServeWatch(serveIdleTimeout)
	in := w.wrap(&wsConn{ws: ws})
	var reachedMu sync.Mutex
	reached := ""
	dial := func() (net.Conn, error) {
		out, a, err := serveDial(addrs, serveDialTimeout)
		if err != nil {
			return nil, err
		}
		reachedMu.Lock()
		reached = a
		reachedMu.Unlock()
		return w.wrap(out), nil
	}
	if s.filter {
		proxyInferenceVia(in, dial, s.lane, self, servePass)
	} else {
		servePass(in, dial)
	}
	w.stop()
	fromHost, toHost := w.counts()
	reachedMu.Lock()
	target := reached
	reachedMu.Unlock()
	if target == "" {
		target = strings.Join(addrs, " ") // none answered, or none was dialled
	}
	serveAudit(dcnDir, map[string]any{"service": s.name, "target": target, "decision": "served",
		"bytes_from_host": fromHost, "bytes_to_host": toHost, "idle_closed": w.idleClosed()})
	return true
}

// servePass is the lane's pass-through: egress's splice, which keeps a
// half-close (the Host's 'E' ends what it sends, and the answer still comes
// back), where the tunnel's spliceConn ends both directions with the first.
func servePass(in net.Conn, dial upstreamDial) {
	out, err := dial()
	if err != nil {
		_ = in.Close()
		return
	}
	splice(in, in, out)
}

// serveWatch is the idle bound of one stream. Both ends are wrapped; any byte
// read or written on either one counts, and once none has for the bound,
// both are closed, which unblocks whichever copy or read is waiting.
type serveWatch struct {
	bound    time.Duration
	last     atomic.Int64 // unix nanoseconds of the last byte
	fromHost atomic.Int64
	toHost   atomic.Int64
	mu       sync.Mutex
	conns    []net.Conn
	host     net.Conn
	done     chan struct{}
	once     sync.Once
	idled    atomic.Bool
}

func newServeWatch(bound time.Duration) *serveWatch {
	w := &serveWatch{bound: bound, done: make(chan struct{})}
	w.last.Store(time.Now().UnixNano())
	go w.run()
	return w
}

func (w *serveWatch) run() {
	tick := w.bound / 4
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	if tick > 5*time.Second {
		tick = 5 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-t.C:
			if time.Since(time.Unix(0, w.last.Load())) >= w.bound {
				w.idled.Store(true)
				w.mu.Lock()
				for _, c := range w.conns {
					_ = c.Close()
				}
				w.mu.Unlock()
				return
			}
		}
	}
}

func (w *serveWatch) stop() { w.once.Do(func() { close(w.done) }) }

func (w *serveWatch) idleClosed() bool { return w.idled.Load() }

func (w *serveWatch) counts() (fromHost, toHost int64) { return w.fromHost.Load(), w.toHost.Load() }

// wrap watches c. The first conn wrapped is the Host's: what is read from it
// came from the Host, what is written to it goes back.
func (w *serveWatch) wrap(c net.Conn) net.Conn {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.host == nil {
		w.host = c
	}
	w.conns = append(w.conns, c)
	return &serveWatched{Conn: c, w: w, host: w.host == c}
}

type serveWatched struct {
	net.Conn
	w    *serveWatch
	host bool
}

func (c *serveWatched) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.w.last.Store(time.Now().UnixNano())
		if c.host {
			c.w.fromHost.Add(int64(n))
		}
	}
	return n, err
}

func (c *serveWatched) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.w.last.Store(time.Now().UnixNano())
		if c.host {
			c.w.toHost.Add(int64(n))
		}
	}
	return n, err
}

// CloseWrite passes a half-close through, so splice can end one direction.
func (c *serveWatched) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// serveAudit writes one line per job to the pairing's audit log, the file
// dcnAudit writes, and to the system log.
func serveAudit(dir string, rec map[string]any) {
	if dir == "" {
		return
	}
	rec["ts"] = time.Now().UTC().Format(time.RFC3339)
	rec["op"] = "serve"
	raw, _ := json.Marshal(rec)
	auditToSystemLog(auditFilePairingD, auditPairingOfDir(dir), raw)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	fh, err := os.OpenFile(filepath.Join(dir, auditFilePairingD), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	_, _ = fh.Write(append(raw, '\n'))
}

// serveRetryMax is the longest a worker waits before dialling again while the
// Host answers the lane's upgrade and refuses it. A Host that predates the
// lane does that (an unknown WebSocket route is a 404, or a 403 from a server
// that closes it before accepting), and two workers dialling it every 3 s
// for good would be work for nothing on the person's machine. A Host that
// cannot be reached at all (restarting) is dialled every 3 s, as egress is.
var serveRetryMax = time.Minute

// serveRefusedWait is how long a worker waits before it parks again after its
// WebSocket closed while parked, or after its job was refused. With
// serveWorkerCount workers, a Host that refuses or misuses every job costs
// this machine at most that many dials a second.
var serveRefusedWait = time.Second

// localPairings counts the runs of each pairing with a Host that has no
// platform (runUnixPairing), by host name, while they run. A count, not a
// flag, so a run that is still stopping when the same pairing starts again
// cannot unmark the new one.
var localPairings sync.Map // string -> *atomic.Int32

// markLocalPairing records that self runs as a pairing with a Host that has no
// platform, until the returned func is called.
func markLocalPairing(self string) func() {
	v, _ := localPairings.LoadOrStore(self, new(atomic.Int32))
	n := v.(*atomic.Int32)
	n.Add(1)
	var once sync.Once
	return func() { once.Do(func() { n.Add(-1) }) }
}

// isLocalPairing reports whether self is running as a pairing with a Host that
// has no platform.
func isLocalPairing(self string) bool {
	v, ok := localPairings.Load(self)
	return ok && v.(*atomic.Int32).Load() > 0
}

// modelDaemonTarget is the address model management (modelswap.go: the
// model-swap probe in the beat, model:list, model:pull and its probes,
// model:drop) dials for the pairing self, or the reason it dials nothing.
// For a Host with no platform it is the serve lane's own ollama target, under
// the same rule: OLLAMA_ADDR (else loopback) only when every address it names
// is this machine, and the address dialled is one of those checked: the first
// that answers, tried in turn (servePick). A bastion serves only the computer
// it runs on, and managing the models on another computer is serving it. A
// tunnel pairing keeps OLLAMA_ADDR wherever it points, as its forwards do.
func modelDaemonTarget(self string) (string, string) {
	t := localOllamaAddr()
	if !isLocalPairing(self) {
		return t, ""
	}
	addrs, why := serveVetTarget(t)
	if why != "" {
		s, _ := serveServiceNamed("ollama")
		serveTargetNotice(self, s, t, why)
		return "", "refused: the model server set on this machine (OLLAMA_ADDR) is not used for this Host: " + why
	}
	return servePick(addrs), ""
}

// serveTargetNoticed is the last refusal said at the machine for each pairing
// and service, so the console carries it once, and again only when it changes.
var serveTargetNoticed sync.Map // "<self>\x00<service>" -> string

// serveTargetNotice says at this machine, in plain words, that the server set
// here for a service is not used for the Host with no platform, and why. A
// refusal that only the Host hears leaves the person who set the address with
// nothing on their own screen to explain why the model is missing.
func serveTargetNotice(self string, s serveService, target, why string) {
	key := self + "\x00" + s.name
	// The beat and a model op can refuse the same target at once; only the one
	// that records this reason says it.
	for {
		prev, loaded := serveTargetNoticed.LoadOrStore(key, why)
		if !loaded {
			break
		}
		if prev.(string) == why {
			return
		}
		if serveTargetNoticed.CompareAndSwap(key, prev, why) {
			break
		}
	}
	fmt.Printf("[%s] %s=%s is not used for the Host on this computer: %s. Set %s to a server on this "+
		"computer, or unset it.\n", self, s.envVar, target, why, s.envVar)
}

// serveTargetNoticeClear forgets what was said for a service that is fine
// again, so a later refusal is said again.
func serveTargetNoticeClear(self string, s serveService) {
	serveTargetNoticed.Delete(self + "\x00" + s.name)
}

// runServeWorkers keeps n workers parked on the Host's /bastion-serve for the
// pairing self, each serving one job (serveJob). A worker that takes a job
// starts its replacement at once and ends with the job; one whose WebSocket
// dies while parked dials again. pctx is the pairing's context: a revoked
// pairing's workers exit.
func runServeWorkers(pctx context.Context, self, dcnDir, wsURL string, tlsCfg *tls.Config,
	dialHost func(ctx context.Context) (net.Conn, error), bearer string, n int) {
	dialer := &websocket.Dialer{
		NetDialContext:   func(ctx context.Context, network, addr string) (net.Conn, error) { return dialHost(ctx) },
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 20 * time.Second,
	}
	var spawn func()
	spawn = func() {
		go func() {
			wait := 3 * time.Second
			for pctx.Err() == nil {
				ctx, cancel := context.WithTimeout(pctx, 25*time.Second)
				ws, resp, err := dialer.DialContext(ctx, wsURL, http.Header{})
				cancel()
				if err != nil {
					if resp != nil {
						sleepCtx(pctx, wait)
						wait = min(2*wait, serveRetryMax)
					} else {
						sleepCtx(pctx, 3*time.Second)
					}
					continue
				}
				wait = 3 * time.Second
				if err := ws.WriteMessage(websocket.TextMessage, []byte("BEARER "+bearer)); err != nil {
					_ = ws.Close()
					sleepCtx(pctx, time.Second)
					continue
				}
				stopKA := armWSKeepalive(ws)
				unpark := context.AfterFunc(pctx, func() { _ = ws.Close() })
				took := serveJob(ws, self, dcnDir, spawn)
				unpark()
				stopKA()
				_ = ws.Close()
				if took {
					return
				}
				// Closed while parked (a Host restart), or the job refused: not
				// straight back, so a Host that closes or misuses every worker is
				// not dialled in a loop.
				sleepCtx(pctx, serveRefusedWait)
			}
		}()
	}
	for i := 0; i < n; i++ {
		spawn()
	}
}

// laneServeReport is what a local pairing's beat says of its serve lane.
type laneServeReport struct {
	served    []string // lane_serves
	models    []string // ollama's, filtered to the scope
	llmModels []string // the llm server's, filtered to the scope
	piiOK     bool
}

// laneServes is what this pairing serves over the lane right now, for the
// beat: each service whose target is set and is this machine, whose server
// answers its probe, and whose family the pairing holds. A scoped pairing
// with no model left in a server's list is not served that server, as the
// tunnel's beat withholds a lane with nothing in it.
func laneServes(self string) laneServeReport {
	rep := laneServeReport{served: []string{}, models: []string{}, llmModels: []string{}}
	if capsAllow(self, "inference") != "" {
		return rep
	}
	scope := pairingModelScope(self)
	for _, s := range serveServices {
		t := s.target()
		if t == "" {
			continue
		}
		addrs, why := serveVetTarget(t)
		if why != "" {
			serveTargetNotice(self, s, t, why)
			continue
		}
		serveTargetNoticeClear(self, s)
		addr := servePick(addrs)
		switch s.name {
		case "ollama":
			ok, models := ollamaModelsAt([]string{addr})
			models = scope.filterModels(models)
			if !ok || (scope.scoped && len(models) == 0) {
				continue
			}
			if models != nil {
				rep.models = models
			}
		case "llm":
			ok, models := openAICompatModelsAt(addr)
			models = scope.filterModels(models)
			if !ok || (scope.scoped && len(models) == 0) {
				continue
			}
			if models != nil {
				rep.llmModels = models
			}
		case "pii":
			if !scope.allowsPII() {
				continue
			}
			if _, healthy := piiProbeAt(addr); !healthy {
				continue
			}
			rep.piiOK = true
		}
		rep.served = append(rep.served, s.name)
	}
	return rep
}
