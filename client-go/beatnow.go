package main

import (
	"context"
	"sync"
	"time"
)

// A beat out of turn, for every pairing on this box.
//
// Each running pairing beats its own Host on a 60-second ticker, and every
// beat carries the box's pairings as `peers` with the state of each (peers.go).
// That is how every Host on the machine learns that a pairing went active or was
// revoked. A pairing_grant_sync or pairing_grant_drop changes that state on disk
// at once, but nothing beat: every Host kept the old state for up to a minute.
// So a pairing approved a second after a beat still read as pending for the
// next minute, and a Host asking to connect to it in that time was refused. The
// anchor Host can read its own confirmed grant, but no other Host on the
// machine has one, and a revoke reached the other Hosts no sooner.
//
// So a change to a pairing's state asks every running pairing's beat loop to beat
// now. The signal carries nothing: the beat reads the pairings from disk as it
// always does, so it reports the state the change wrote. One pending signal per
// loop is kept and the rest are dropped, so a burst of changes is one extra beat
// per Host, never one per change.

var beatNow = struct {
	sync.Mutex
	subs map[chan struct{}]struct{}
}{subs: map[chan struct{}]struct{}{}}

// subscribeBeatNow registers one beat loop. The channel holds at most one
// pending signal; stop unregisters it.
func subscribeBeatNow() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	beatNow.Lock()
	beatNow.subs[ch] = struct{}{}
	beatNow.Unlock()
	return ch, func() {
		beatNow.Lock()
		delete(beatNow.subs, ch)
		beatNow.Unlock()
	}
}

// kickBeats asks every registered beat loop to beat now. It never blocks: a
// loop that already has a signal pending, or is mid-beat, beats once more.
func kickBeats() {
	beatNow.Lock()
	defer beatNow.Unlock()
	for ch := range beatNow.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// runBeatLoop beats every `every`, and also whenever kickBeats asks. beforeTick
// runs before a ticked beat only (the tunnel's path failover, which belongs to
// the clock, not to a pairing change); it may be nil. It returns when ctx ends.
func runBeatLoop(ctx context.Context, every time.Duration, beforeTick, beat func()) {
	kick, stop := subscribeBeatNow()
	defer stop()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if beforeTick != nil {
				beforeTick()
			}
			beat()
		case <-kick:
			beat()
		}
	}
}
