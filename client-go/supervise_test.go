package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// supervised gives a test the daemon's supervisor: a root context, the fatal
// error channel and an empty registry, all put back when the test ends.
func supervised(t *testing.T) chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 16)
	supervisor.Lock()
	prevCtx, prevErrc, prevRuns, prevStart := supervisor.ctx, supervisor.errc, supervisor.runs, supervisor.start
	supervisor.ctx, supervisor.errc, supervisor.runs, supervisor.start = ctx, errc, map[string]*pairingRun{}, startPairing
	supervisor.Unlock()
	t.Cleanup(func() {
		cancel()
		supervisor.Lock()
		supervisor.ctx, supervisor.errc, supervisor.runs, supervisor.start = prevCtx, prevErrc, prevRuns, prevStart
		supervisor.Unlock()
	})
	return errc
}

// runningAs registers cfg as running, the way startPairing does, with no
// tunnel behind it. Cancelled, it leaves the registry and then closes done, in
// that order, as a real run does. Returns the run's context.
func runningAs(t *testing.T, cfg *Config) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	run := &pairingRun{cancel: cancel, done: make(chan struct{}), cfg: cfg}
	supervisor.Lock()
	supervisor.runs[cfg.HostName] = run
	supervisor.Unlock()
	go func() {
		<-ctx.Done()
		supervisor.Lock()
		if supervisor.runs[cfg.HostName] == run {
			delete(supervisor.runs, cfg.HostName)
		}
		supervisor.Unlock()
		close(run.done)
	}()
	t.Cleanup(cancel)
	return ctx
}

func writePairingFile(t *testing.T, c Config) {
	t.Helper()
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	if err := os.WriteFile(filepath.Join(pd, c.HostName+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadedPairing(t *testing.T, host string) *Config {
	t.Helper()
	cfgs, err := loadPairings()
	if err != nil {
		t.Fatal(err)
	}
	c := pairingFor(cfgs, host)
	if c == nil {
		t.Fatalf("%s is not paired", host)
	}
	return c
}

// A stopped run's heartbeat can outlive it: a beat stuck on a dead tunnel
// returns after the run was stopped, even after the same pairing (same key)
// was started again, and runs the save retry its copy left pending. That
// copy's entry and Hub key are older than the new run's. None of it may reach
// the file, and the new run's own pending save must still land.
func TestAStoppedRunsLateRetryNeverWrites(t *testing.T) {
	old := pairedOn(t, kmV4, "OLD=", kmV4)
	stubLiveProbe(t, &probeStub{answers: map[string]bool{kmV4 + " NEW=": true, kmV6 + " NEWER=": true},
		lastHS: time.Now()})
	supervised(t)
	runningAs(t, old)
	path := pairingFile(t, old)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	setFile := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The run moves to a new key and cannot save it.
	setFile([]byte("{"))
	maybeRotateEndpoint(directive(kmV4, []string{kmV4}, "NEW="), old, nil)
	if old.EndpointPubKey != "NEW=" {
		t.Fatalf("setup: the move should have committed: %s", old.EndpointPubKey)
	}
	// It is stopped with its beat stuck, and the pairing is started again
	// from its file, which still holds the same WireGuard key.
	setFile(good)
	stopPairing(old.HostName)
	again := loadedPairing(t, old.HostName)
	// The new run moves on, and its save fails too.
	setFile([]byte("{"))
	maybeRotateEndpoint(directive(kmV4, []string{kmV6, kmV4}, "NEWER="), again, nil)
	if again.Endpoint != kmV6 || again.EndpointPubKey != "NEWER=" {
		t.Fatalf("setup: the new run's move should have committed: %s %s", again.Endpoint, again.EndpointPubKey)
	}
	setFile(good)

	// The old run's stuck beat comes back and runs its retry.
	maybeFailover(old, nil, time.Now())
	if d := onDisk(t, old); d.Endpoint != kmV4 || d.EndpointPubKey != "OLD=" {
		t.Fatalf("the stopped run's late retry wrote %s %s", d.Endpoint, d.EndpointPubKey)
	}
	// The new run's next beat saves its own move.
	maybeFailover(again, nil, time.Now())
	if d := onDisk(t, again); d.Endpoint != kmV6 || d.EndpointPubKey != "NEWER=" {
		t.Fatalf("the new run's move was not saved: the file has %s %s", d.Endpoint, d.EndpointPubKey)
	}
}

// A run that ends by itself is out of the registry, so the pairing can be
// started again; its copy writes nothing from then on, the same as a run that
// was stopped.
func TestARunThatEndedWritesNothing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	errc := supervised(t)
	const host = "member.host.example"
	writePairingFile(t, Config{HostName: host, WGPrivateKey: "k", BastionTunnelIP: "not-an-address"})
	cfg := loadedPairing(t, host)
	if !startPairing(cfg) {
		t.Fatal("setup: the pairing was not started")
	}
	select {
	case <-errc: // runPairing refused the address and returned
	case <-time.After(5 * time.Second):
		t.Fatal("setup: the run did not end")
	}
	cfg.Endpoint = "203.0.113.99:1"
	if err := cfg.saveEndpoints(); err == nil {
		t.Error("a write through an ended run's copy succeeded")
	}
	if d := loadedPairing(t, host); d.Endpoint != "" {
		t.Fatalf("an ended run's copy wrote %q", d.Endpoint)
	}
}

// `pair --replace` from a shell, or an unpair and a pair inside one supervise
// period, writes the pairing again with a new WireGuard key while the daemon
// runs the copy it started with. The supervisor restarts that run with the new
// file. A run whose file holds its own key is left alone.
func TestSuperviseRestartsAPairingMadeAgainWithItsNewFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	errc := supervised(t)
	const host = "member.host.example"
	writePairingFile(t, Config{HostName: host, WGPrivateKey: "old-key", BastionTunnelIP: "fd00:9::a:1"})
	old := runningAs(t, loadedPairing(t, host))

	superviseOnce()
	if old.Err() != nil {
		t.Fatal("a run whose file holds its own key was stopped")
	}

	// Paired again. The new file's tunnel address is a marker the new run
	// reports back: runPairing refuses it, naming it, before it raises a
	// device, and the supervisor forwards that error.
	writePairingFile(t, Config{HostName: host, WGPrivateKey: "new-key", BastionTunnelIP: "from-the-new-file"})
	superviseOnce()
	if old.Err() == nil {
		t.Fatal("the run holding the replaced key is still up")
	}
	select {
	case err := <-errc:
		if !strings.Contains(err.Error(), `"from-the-new-file"`) {
			t.Fatalf("a run started, but not from the new file: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no run was started with the new file")
	}
}
