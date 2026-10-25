package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// signalled reports whether ch carries a signal within d.
func signalled(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// One signal reaches every registered loop, a burst is one pending signal per
// loop, and a loop that stopped is not signalled.
func TestKickBeatsReachesEveryLoopOnce(t *testing.T) {
	a, stopA := subscribeBeatNow()
	defer stopA()
	b, stopB := subscribeBeatNow()
	gone, stopGone := subscribeBeatNow()
	stopGone()
	kickBeats()
	kickBeats()
	kickBeats()
	stopB()
	for name, ch := range map[string]<-chan struct{}{"a": a, "b": b} {
		if !signalled(ch, time.Second) {
			t.Fatalf("loop %s was not asked to beat", name)
		}
		if signalled(ch, 50*time.Millisecond) {
			t.Fatalf("loop %s holds more than one pending beat after a burst", name)
		}
	}
	if signalled(gone, 50*time.Millisecond) {
		t.Fatal("a loop that unregistered was still signalled")
	}
}

// The beat loop beats on a kick without waiting for its tick, and the
// tick-only step (path failover) does not run for it.
func TestRunBeatLoopBeatsOnKick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var beats, ticks atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		runBeatLoop(ctx, time.Hour, func() { ticks.Add(1) }, func() { beats.Add(1) })
	}()
	// The loop registers inside its goroutine; keep asking until it hears.
	deadline := time.Now().Add(3 * time.Second)
	for beats.Load() == 0 && time.Now().Before(deadline) {
		kickBeats()
		time.Sleep(10 * time.Millisecond)
	}
	if beats.Load() == 0 {
		t.Fatal("a kicked beat loop did not beat before its 1-hour tick")
	}
	if ticks.Load() != 0 {
		t.Fatal("a kicked beat ran the tick-only step")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the beat loop did not return when its context ended")
	}
	beatNow.Lock()
	left := len(beatNow.subs)
	beatNow.Unlock()
	if left != 0 {
		t.Fatalf("a returned beat loop stayed registered (%d left)", left)
	}
}
