package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func TestCandidateList(t *testing.T) {
	got := candidateList([]string{" [2604:2dc0:100:589b::36]:51820 ", "203.0.113.10:52054", ""}, "203.0.113.10:52054")
	want := []string{"[2604:2dc0:100:589b::36]:51820", "203.0.113.10:52054"}
	if !sameList(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// An older host sends no list: the single endpoint is the list.
	if got := candidateList(nil, "203.0.113.10:52054"); !sameList(got, []string{"203.0.113.10:52054"}) {
		t.Fatalf("single: %v", got)
	}
	// The v4 entry is appended when the list omits it, never dropped.
	if got := candidateList([]string{"[2604::1]:51820"}, "1.2.3.4:52001"); !sameList(got, []string{"[2604::1]:51820", "1.2.3.4:52001"}) {
		t.Fatalf("append: %v", got)
	}
}

func TestParseRotateTarget(t *testing.T) {
	// New host: ordered list.
	c, pk := parseRotateTarget([]byte(`{"ok":true,"rotate_endpoint":{"endpoint":"1.2.3.4:52054","endpoints":["[2604::36]:51820","1.2.3.4:52054"],"endpoint_pubkey":"PK="}}`))
	if pk != "PK=" || !sameList(c, []string{"[2604::36]:51820", "1.2.3.4:52054"}) {
		t.Fatalf("new host: %v %q", c, pk)
	}
	// Old host: only endpoint.
	c, pk = parseRotateTarget([]byte(`{"rotate_endpoint":{"endpoint":"1.2.3.4:52054","endpoint_pubkey":"PK="}}`))
	if pk != "PK=" || !sameList(c, []string{"1.2.3.4:52054"}) {
		t.Fatalf("old host: %v %q", c, pk)
	}
	// No directive.
	if c, _ := parseRotateTarget([]byte(`{"ok":true}`)); len(c) != 0 {
		t.Fatalf("no directive: %v", c)
	}
}

type fakeDev struct{ dump string }

func (f fakeDev) IpcGet() (string, error) { return f.dump, nil }

func TestLastHandshake(t *testing.T) {
	if !lastHandshake(fakeDev{"private_key=00\npublic_key=11\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n"}).IsZero() {
		t.Fatal("zero handshake should be zero time")
	}
	got := lastHandshake(fakeDev{"public_key=11\nendpoint=[::1]:1\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n"})
	if !got.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("got %v", got)
	}
	if !lastHandshake(fakeDev{"public_key=11\n"}).IsZero() {
		t.Fatal("no field should be zero time")
	}
}

func TestFailedRecently(t *testing.T) {
	s := rotateState{failed: map[string]probeFailure{}}
	if s.failedRecently("a") {
		t.Fatal("fresh state")
	}
	s.markFailed("a")
	if !s.failedRecently("a") {
		t.Fatal("just failed")
	}
	s.failed["a"] = probeFailure{at: time.Now().Add(-rotateRetryAfter - time.Second), count: 1}
	if s.failedRecently("a") {
		t.Fatal("expired failure still skipped")
	}
	// A FIRST failure is probably-transient and is retried in minutes, not parked for
	// an hour (during a mass pairing every failed v6 probe succeeded on its next
	// attempt once the burst was over).
	s.failed["a"] = probeFailure{at: time.Now().Add(-90 * time.Second), count: 1}
	if !s.failedRecently("a") {
		t.Fatal("a 90s-old first failure is still inside the short grace")
	}
	s.failed["a"] = probeFailure{at: time.Now().Add(-3 * time.Minute), count: 1}
	if s.failedRecently("a") {
		t.Fatal("a first failure must be retried within minutes, not held for an hour")
	}
	// Repeated failures back off: the third failure is skipped for 2 h, so a failure
	// 61 min old is still recent.
	s.markFailed("a")
	s.failed["a"] = probeFailure{at: time.Now().Add(-61 * time.Minute), count: 3}
	if !s.failedRecently("a") {
		t.Fatal("third failure should back off past an hour")
	}
	s.markFailed("b")
	s.clear("b")
	if s.failedRecently("b") {
		t.Fatal("cleared failure still skipped")
	}
}

func TestRetryAfterBacksOffAndCaps(t *testing.T) {
	// First failure: the short grace. Then the hour, doubling.
	if retryAfter(1) != rotateRetryFirst || retryAfter(0) != rotateRetryFirst {
		t.Fatalf("first: %v %v", retryAfter(1), retryAfter(0))
	}
	if retryAfter(2) != time.Hour || retryAfter(3) != 2*time.Hour || retryAfter(4) != 4*time.Hour {
		t.Fatalf("backoff: %v %v %v", retryAfter(2), retryAfter(3), retryAfter(4))
	}
	// Capped within a day, not a week: a candidate that comes back is picked up the
	// same day, while a candidate that never answers costs one disruptive probe a day
	// rather than four (each probe swaps the live peer for up to rotateProbeTimeout).
	if retryAfter(20) != rotateRetryMax || rotateRetryMax > 24*time.Hour {
		t.Fatalf("cap: %v (max %v)", retryAfter(20), rotateRetryMax)
	}
}

// The route guard. A candidate on an address family this machine does
// not have must be refused from the ROUTING TABLE, before probeAndCommit swaps the
// live peer — the failure it replaces cost a real tunnel outage per retry on every
// IPv4-only bastion.
func TestEndpointRoutableRefusesWhenTheKernelHasNoRoute(t *testing.T) {
	orig := dialForRouteCheck
	defer func() { dialForRouteCheck = orig }()

	// The kernel's answer on a machine with no IPv6 path at all.
	dialForRouteCheck = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if network != "udp" {
			t.Fatalf("route check must use udp (it must not open a stream): %q", network)
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connect: network is unreachable")}
	}
	err := endpointRoutable("[2604:2dc0:100:589b::4a]:51820")
	if !errors.Is(err, errNoLocalPath) {
		t.Fatalf("want errNoLocalPath, got %v", err)
	}
	// The underlying reason survives into the message: a person reading the log has
	// to be able to tell "no IPv6 here" from "that name would not resolve".
	if !strings.Contains(err.Error(), "network is unreachable") {
		t.Fatalf("underlying cause dropped: %v", err)
	}

	// A route exists: the guard steps aside and the real handshake probe decides.
	// net.Pipe stands in for the connected socket; only Close is used.
	dialForRouteCheck = func(network, address string, timeout time.Duration) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	}
	if err := endpointRoutable("15.204.198.155:20074"); err != nil {
		t.Fatalf("routable endpoint refused: %v", err)
	}
}

// A standing local condition is stated once, not once a minute.
func TestNotePathlessReportsOnlyTheFirstTime(t *testing.T) {
	s := rotateState{failed: map[string]probeFailure{}} // noPath deliberately nil, as the package var is
	ep := "[2604:2dc0:100:589b::4a]:51820"
	if !s.notePathless(ep) {
		t.Fatal("the first sighting is the one worth logging")
	}
	if s.notePathless(ep) {
		t.Fatal("every later beat must stay quiet")
	}
	// If the path comes back and is lost again, that is news again.
	s.clearPathless(ep)
	if !s.notePathless(ep) {
		t.Fatal("a path lost a second time must be reported again")
	}
	// An unroutable candidate is NOT a probe failure: it must not consume the
	// backoff, or a machine that gains IPv6 waits out a day before using it.
	if s.failedRecently(ep) {
		t.Fatal("the route guard must not mark the candidate failed")
	}
}

// failuresRecordedFor lists the probe targets with a failure recorded for the
// entry ep, whatever the key.
func failuresRecordedFor(ep string) []string {
	rotation.mu.Lock()
	defer rotation.mu.Unlock()
	var out []string
	for k := range rotation.failed {
		if strings.HasPrefix(k, ep+" ") {
			out = append(out, k)
		}
	}
	return out
}

// The property the guard exists for: it runs BEFORE the live peer is touched, and
// what it refuses is not recorded as a probe failure. Both are invisible to the
// two tests above — a mutation pass deleted the guard call from
// probeAndCommit and they stayed green, which is what this test closes.
//
// dev is nil ON PURPOSE. swapPeer dereferences it, so if a refactor ever moves
// the guard after the swap this panics instead of quietly passing.
func TestProbeAndCommitRefusesUnroutableBeforeTouchingTheLivePeer(t *testing.T) {
	orig := dialForRouteCheck
	ep := "[2604:2dc0:100:589b::4a]:51820"
	defer func() {
		dialForRouteCheck = orig
		rotation.clearPathless(ep)
		for _, k := range failuresRecordedFor(ep) {
			rotation.clear(k)
		}
	}()
	dialForRouteCheck = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connect: network is unreachable")}
	}

	cfg := &Config{Endpoint: "15.204.198.155:20074", EndpointPubKey: "OLD="}
	err := probeAndCommit(cfg, nil, ep, "NEW=", []string{ep, cfg.Endpoint})
	if !errors.Is(err, errNoLocalPath) {
		t.Fatalf("want errNoLocalPath before any peer swap, got %v", err)
	}
	// Not a probe failure: "no route from here" costs nothing to re-test, and
	// consuming the backoff would park a machine that gains IPv6 for up to a day.
	// Checked under every key, not only the one probed: a failure recorded for
	// this entry under the key the machine runs would park it just the same.
	if got := failuresRecordedFor(ep); len(got) != 0 {
		t.Fatalf("an unroutable candidate must not consume the probe backoff, recorded %q", got)
	}
	// The live endpoint is untouched: nothing was committed.
	if cfg.Endpoint != "15.204.198.155:20074" || cfg.EndpointPubKey != "OLD=" {
		t.Fatalf("config moved on a refused candidate: %s %s", cfg.Endpoint, cfg.EndpointPubKey)
	}
}

// ── a host moving the machine to a new Hub key on the same entries ───────────
//
// A host can change the key a machine pins without changing where it dials: its
// Hub answers the old key and the new one side by side while its machines move,
// and the heartbeat directive names the same entries with the new key. These
// tests drive the probe and failover paths with the live-device steps stubbed:
// probeStub says which (entry, key) pairs complete a handshake.

const (
	kmV4 = "203.0.113.10:52054"
	kmV6 = "[2001:db8::4a]:51820"
)

type probeStub struct {
	answers map[string]bool // entry + " " + key -> a handshake completes
	lastHS  time.Time       // what liveLastHandshake reports
	on      string          // the (entry, key) the device was last swapped to
}

func stubLiveProbe(t *testing.T, s *probeStub) {
	t.Helper()
	swap, hs, last, dial := livePeerSwap, liveHandshake, liveLastHandshake, dialForRouteCheck
	livePeerSwap = func(_ *Config, _ *device.Device, endpoint, pubkey string) error {
		s.on = endpoint + " " + pubkey
		return nil
	}
	liveHandshake = func(*device.Device, time.Time, time.Duration) bool { return s.answers[s.on] }
	liveLastHandshake = func(*device.Device) time.Time { return s.lastHS }
	dialForRouteCheck = func(string, string, time.Duration) (net.Conn, error) {
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	rotation.mu.Lock()
	failed, noPath := rotation.failed, rotation.noPath
	rotation.failed, rotation.noPath = map[string]probeFailure{}, nil
	rotation.mu.Unlock()
	t.Cleanup(func() {
		livePeerSwap, liveHandshake, liveLastHandshake, dialForRouteCheck = swap, hs, last, dial
		rotation.mu.Lock()
		rotation.failed, rotation.noPath = failed, noPath
		rotation.mu.Unlock()
	})
}

// pairedOn writes a pairing file for a machine on endpoint with key, and returns
// the running copy of it.
func pairedOn(t *testing.T, endpoint, key string, endpoints ...string) *Config {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := &Config{HostName: "member.host.example", WGPrivateKey: "k",
		Endpoint: endpoint, EndpointPubKey: key, Endpoints: endpoints}
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(pd, cfg.HostName+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func pairingFile(t *testing.T, cfg *Config) string {
	t.Helper()
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(pd, cfg.HostName+".json")
}

func onDisk(t *testing.T, cfg *Config) Config {
	t.Helper()
	raw, err := os.ReadFile(pairingFile(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	var d Config
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func directive(endpoint string, endpoints []string, key string) []byte {
	b, _ := json.Marshal(map[string]any{"rotate_endpoint": map[string]any{
		"endpoint": endpoint, "endpoints": endpoints, "endpoint_pubkey": key}})
	return b
}

// A dead spell on the key the machine runs must not hold up a move to a new key.
// Failover marked every entry failed under the OLD key; under the new key nothing
// has been tried, so the move goes ahead as soon as the host asks.
func TestAKeyMoveIsNotHeldByAPathFailureUnderTheOldKey(t *testing.T) {
	cfg := pairedOn(t, kmV4, "OLD=", kmV4, kmV6)
	s := &probeStub{answers: map[string]bool{}}
	stubLiveProbe(t, s)

	maybeFailover(cfg, nil, time.Now().Add(-time.Hour)) // no handshake for an hour: every entry fails
	if cfg.Endpoint != kmV4 || cfg.EndpointPubKey != "OLD=" {
		t.Fatalf("failover moved with nothing answering: %s %s", cfg.Endpoint, cfg.EndpointPubKey)
	}

	s.answers[kmV6+" NEW="], s.answers[kmV4+" NEW="] = true, true
	maybeRotateEndpoint(directive(kmV4, []string{kmV6, kmV4}, "NEW="), cfg, nil)
	if cfg.EndpointPubKey != "NEW=" {
		t.Fatalf("key move held back by failures recorded under the old key: still on %s %s",
			cfg.Endpoint, cfg.EndpointPubKey)
	}
	if d := onDisk(t, cfg); d.EndpointPubKey != "NEW=" {
		t.Fatalf("moved but not saved: disk has %q", d.EndpointPubKey)
	}
}

// A probe of a key the Hub does not answer yet says nothing about the entry under
// the key the machine runs. It must not keep the machine off its preferred entry.
func TestAFailedKeyProbeDoesNotHoldTheMachineOffItsPreferredEntry(t *testing.T) {
	cfg := pairedOn(t, kmV4, "OLD=", kmV6, kmV4)
	s := &probeStub{answers: map[string]bool{kmV6 + " OLD=": true, kmV4 + " OLD=": true}}
	stubLiveProbe(t, s)

	// The host asks for a key its Hub does not answer yet: both probes fail.
	maybeRotateEndpoint(directive(kmV4, []string{kmV6, kmV4}, "NEW="), cfg, nil)
	if cfg.Endpoint != kmV4 || cfg.EndpointPubKey != "OLD=" {
		t.Fatalf("committed a key nothing answered: %s %s", cfg.Endpoint, cfg.EndpointPubKey)
	}
	// It goes back to asking for the preferred entry on the key the machine runs.
	maybeRotateEndpoint(directive(kmV4, []string{kmV6, kmV4}, "OLD="), cfg, nil)
	if cfg.Endpoint != kmV6 {
		t.Fatalf("held off the preferred entry by a failed probe of another key: on %s", cfg.Endpoint)
	}
}

// A committed move whose save failed must reach disk on a later beat. Until it
// does, a restart comes up on the old key, and once the host retires that key the
// machine is stranded: the heartbeat that could correct it rides the dead tunnel.
func TestAMoveWhoseSaveFailedIsSavedOnALaterBeat(t *testing.T) {
	cfg := pairedOn(t, kmV4, "OLD=", kmV4)
	s := &probeStub{answers: map[string]bool{kmV4 + " NEW=": true}, lastHS: time.Now()}
	stubLiveProbe(t, s)
	path := pairingFile(t, cfg)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// The save fails: the file cannot be read back for its read-modify-write.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	maybeRotateEndpoint(directive(kmV4, []string{kmV4}, "NEW="), cfg, nil)
	if cfg.EndpointPubKey != "NEW=" {
		t.Fatalf("the live move should have committed: %s", cfg.EndpointPubKey)
	}

	// The cause clears. The file still names the old key.
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	// The next beat: failover's check (the path is alive) and the same directive.
	maybeFailover(cfg, nil, time.Now().Add(-time.Hour))
	maybeRotateEndpoint(directive(kmV4, []string{kmV4}, "NEW="), cfg, nil)
	if d := onDisk(t, cfg); d.EndpointPubKey != "NEW=" || d.Endpoint != kmV4 {
		t.Fatalf("a restart would come up on %s %s, not the key the tunnel runs on",
			d.Endpoint, d.EndpointPubKey)
	}
}

// An unpaired host's file is gone; a pending save must not bring it back or be
// retried forever.
func TestAPendingSaveForAnUnpairedHostIsDropped(t *testing.T) {
	cfg := pairedOn(t, kmV4, "OLD=", kmV4)
	stubLiveProbe(t, &probeStub{lastHS: time.Now()})
	rotation.setUnsaved(cfg, true)
	if err := os.Remove(pairingFile(t, cfg)); err != nil {
		t.Fatal(err)
	}
	maybeFailover(cfg, nil, time.Now())
	if _, err := os.Stat(pairingFile(t, cfg)); !os.IsNotExist(err) {
		t.Fatalf("a retried save recreated an unpaired host's file: %v", err)
	}
	if rotation.isUnsaved(cfg) {
		t.Fatal("a save for an unpaired host is still pending")
	}
}

// A host paired again (`pair --replace`, or unpair then pair) gets a new file
// with its own WireGuard key, and a daemon already running keeps the copy it
// started with. A save that copy left pending must not write its entry and Hub
// key into the new pairing: they were pinned for the key that was replaced, and
// the new pairing would come up on them at its next start.
func TestAPendingSaveNeverWritesIntoAPairingMadeAgain(t *testing.T) {
	cfg := pairedOn(t, kmV4, "OLD=", kmV4)
	stubLiveProbe(t, &probeStub{answers: map[string]bool{kmV4 + " NEW=": true}, lastHS: time.Now()})
	path := pairingFile(t, cfg)

	// The move commits; its save fails.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	maybeRotateEndpoint(directive(kmV4, []string{kmV4}, "NEW="), cfg, nil)
	if cfg.EndpointPubKey != "NEW=" || !rotation.isUnsaved(cfg) {
		t.Fatalf("setup: want a committed move with its save pending, got %s pending=%v",
			cfg.EndpointPubKey, rotation.isUnsaved(cfg))
	}

	// The host is paired again while the daemon runs.
	again := Config{HostName: cfg.HostName, WGPrivateKey: "k-again",
		Endpoint: kmV6, EndpointPubKey: "AGAIN=", Endpoints: []string{kmV6, kmV4}}
	b, _ := json.Marshal(again)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	maybeFailover(cfg, nil, time.Now())
	if d := onDisk(t, cfg); d.Endpoint != again.Endpoint || d.EndpointPubKey != again.EndpointPubKey ||
		!sameList(d.Endpoints, again.Endpoints) {
		t.Fatalf("the old pairing's pending save wrote %s %s %v into the new one",
			d.Endpoint, d.EndpointPubKey, d.Endpoints)
	}
	if rotation.isUnsaved(cfg) {
		t.Fatal("a save for a pairing that was made again is still pending")
	}
}

// One process serves several pairings, each beating on its own goroutine
// (run.go). Two of them move to their own host's new key at the same time,
// and one of the two cannot save at first: its retry lands on a later beat,
// and neither pairing's save, retry or failure reaches the other's file or
// memory. Run with -race, this is the concurrent case the tests above cannot
// show.
func TestTwoPairingsMoveTheirKeysAtOnce(t *testing.T) {
	stubLiveProbe(t, &probeStub{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	type pairing struct {
		cfg              *Config
		dev              *device.Device // identity only: the stubs never call it
		v6, v4, old, new string
	}
	ps := []*pairing{
		{v6: "[2001:db8::a]:51820", v4: "203.0.113.10:52001", old: "OLD-A=", new: "NEW-A="},
		{v6: "[2001:db8::b]:51820", v4: "203.0.113.10:52002", old: "OLD-B=", new: "NEW-B="},
	}
	answers := map[string]bool{}
	for i, p := range ps {
		p.dev = new(device.Device)
		p.cfg = &Config{HostName: []string{"a.host.example", "b.host.example"}[i],
			WGPrivateKey: "k" + p.old, Endpoint: p.v4, EndpointPubKey: p.old, Endpoints: []string{p.v6, p.v4}}
		b, _ := json.Marshal(p.cfg)
		if err := os.WriteFile(filepath.Join(pd, p.cfg.HostName+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		answers[p.v6+" "+p.new] = true
	}
	var mu sync.Mutex
	on := map[*device.Device]string{}
	livePeerSwap = func(_ *Config, dev *device.Device, endpoint, pubkey string) error {
		mu.Lock()
		on[dev] = endpoint + " " + pubkey
		mu.Unlock()
		return nil
	}
	liveHandshake = func(dev *device.Device, _ time.Time, _ time.Duration) bool {
		mu.Lock()
		defer mu.Unlock()
		return answers[on[dev]]
	}
	liveLastHandshake = func(*device.Device) time.Time { return time.Now() }

	beat := func() {
		var wg sync.WaitGroup
		for _, p := range ps {
			wg.Add(1)
			go func(p *pairing) {
				defer wg.Done()
				maybeFailover(p.cfg, p.dev, time.Now())
				maybeRotateEndpoint(directive(p.v4, []string{p.v6, p.v4}, p.new), p.cfg, p.dev)
			}(p)
		}
		wg.Wait()
	}

	aFile := filepath.Join(pd, ps[0].cfg.HostName+".json")
	good, err := os.ReadFile(aFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aFile, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	beat() // both move; A's save fails
	if !rotation.isUnsaved(ps[0].cfg) || rotation.isUnsaved(ps[1].cfg) {
		t.Fatalf("want only A's save pending, got A=%v B=%v",
			rotation.isUnsaved(ps[0].cfg), rotation.isUnsaved(ps[1].cfg))
	}
	if err := os.WriteFile(aFile, good, 0o600); err != nil {
		t.Fatal(err)
	}
	beat() // A's retry lands; B has nothing to do
	for _, p := range ps {
		var d Config
		raw, err := os.ReadFile(filepath.Join(pd, p.cfg.HostName+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		if d.Endpoint != p.v6 || d.EndpointPubKey != p.new || d.WGPrivateKey != "k"+p.old {
			t.Errorf("%s on disk: %s %s (key %s); want %s %s", p.cfg.HostName,
				d.Endpoint, d.EndpointPubKey, d.WGPrivateKey, p.v6, p.new)
		}
		if p.cfg.Endpoint != p.v6 || p.cfg.EndpointPubKey != p.new {
			t.Errorf("%s in memory: %s %s", p.cfg.HostName, p.cfg.Endpoint, p.cfg.EndpointPubKey)
		}
		if rotation.isUnsaved(p.cfg) {
			t.Errorf("%s: a save is still pending", p.cfg.HostName)
		}
	}
}

// The commit's log line says a failed save will be retried only when it will
// be: not for a pairing whose file is gone.
func TestTheCommitLineSaysRetriedOnlyWhenItIs(t *testing.T) {
	commitLine := func(t *testing.T, breakFile func(path string)) string {
		t.Helper()
		cfg := pairedOn(t, kmV4, "OLD=", kmV4)
		stubLiveProbe(t, &probeStub{answers: map[string]bool{kmV4 + " NEW=": true}, lastHS: time.Now()})
		breakFile(pairingFile(t, cfg))
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout := os.Stdout
		os.Stdout = w
		maybeRotateEndpoint(directive(kmV4, []string{kmV4}, "NEW="), cfg, nil)
		os.Stdout = stdout
		_ = w.Close()
		out, _ := io.ReadAll(r)
		return string(out)
	}
	if got := commitLine(t, func(p string) { _ = os.WriteFile(p, []byte("{"), 0o600) }); !strings.Contains(got, "retried every beat") {
		t.Errorf("a save that will be retried must say so: %q", got)
	}
	if got := commitLine(t, func(p string) { _ = os.Remove(p) }); !strings.Contains(got, "config save failed") ||
		strings.Contains(got, "retried") {
		t.Errorf("a save for a gone pairing is not retried and must not say it is: %q", got)
	}
}

// pendingOnTheBeat reads endpoint_save_pending off the body a beat of cfg's
// run would send. A beat that observes agents resolves the remote inference
// hosts (resolveLLMIPs); the cache is filled first, so the test sends no DNS
// query off the machine.
func pendingOnTheBeat(t *testing.T, cfg *Config) any {
	t.Helper()
	llmIPMu.Lock()
	prev, prevAt := llmIPCache, llmIPCacheAt
	llmIPCache, llmIPCacheAt = map[string]string{}, time.Now()
	llmIPMu.Unlock()
	defer func() {
		llmIPMu.Lock()
		llmIPCache, llmIPCacheAt = prev, prevAt
		llmIPMu.Unlock()
	}()
	var m map[string]any
	if err := json.Unmarshal([]byte(heartbeatPayload(cfg, fakeDev{}, "box", "pub")), &m); err != nil {
		t.Fatal(err)
	}
	v, ok := m["endpoint_save_pending"]
	if !ok {
		t.Fatal("the beat carries no endpoint_save_pending")
	}
	return v
}

// Each beat says whether its pairing runs on a move its file does not hold
// yet. The host retires its old Hub key from the Hub's handshake view, which
// cannot see a machine's disk; a machine running on the new key whose save
// keeps failing would restart onto the retired one and be stranded. So the
// beat says so from the failed save until a later beat saves the move.
func TestTheBeatSaysWhileAMoveIsNotSaved(t *testing.T) {
	cfg := pairedOn(t, kmV4, "OLD=", kmV4)
	stubLiveProbe(t, &probeStub{answers: map[string]bool{kmV4 + " NEW=": true}, lastHS: time.Now()})
	path := pairingFile(t, cfg)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if v := pendingOnTheBeat(t, cfg); v != false {
		t.Fatalf("before any move: %v", v)
	}

	// The move commits and its save fails.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	maybeRotateEndpoint(directive(kmV4, []string{kmV4}, "NEW="), cfg, nil)
	if v := pendingOnTheBeat(t, cfg); v != true {
		t.Fatalf("a committed move whose save failed: %v", v)
	}

	// A run started again from the file runs on what the file holds, so it
	// has nothing pending, whatever the run before it left unsaved.
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if v := pendingOnTheBeat(t, loadedPairing(t, cfg.HostName)); v != false {
		t.Fatalf("a run started from its file reports a save it does not have: %v", v)
	}

	// The next beat's retry saves the move.
	maybeFailover(cfg, nil, time.Now())
	if d := onDisk(t, cfg); d.EndpointPubKey != "NEW=" {
		t.Fatalf("setup: the retry should have saved the move: %s", d.EndpointPubKey)
	}
	if v := pendingOnTheBeat(t, cfg); v != false {
		t.Fatalf("after a later beat saved the move: %v", v)
	}
}
