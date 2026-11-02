//go:build linux

// A pairing's run and its heartbeat stop together (run.go): uses the serve
// lane's fixtures (servelane_linux_test.go), so it carries the same build tag.

package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// A pairing stopped while a beat is out acts on nothing that beat brings
// back. The run waits for its heartbeat and the beat's request ends with the
// run, so its last-OK time, and anything else the reply would have set off
// (a grant reconcile into the pairing's folder, a contain, an update), never
// lands after the stop, when an unpair or a revoke removes what is left.
func TestAStoppedPairingsLastBeatWritesNothingAfterTheStop(t *testing.T) {
	h, cfg := serveLaneBox(t, "beat-stop.example.test")
	arrived, release := make(chan struct{}, 1), make(chan struct{})
	h.mu.Lock()
	h.beatArrived, h.beatRelease = arrived, release
	h.mu.Unlock()
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runPairing(ctx, cfg) }()
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("no beat reached the Host")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the pairing did not stop while its beat was out")
	}
	// The Host answers the beat only now, after the run has returned.
	close(release)
	released = true
	time.Sleep(500 * time.Millisecond)
	p, err := pairingStatePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("the stopped pairing's last beat recorded its time after the stop")
	}
}
