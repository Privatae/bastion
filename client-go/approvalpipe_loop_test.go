package main

// The approvals pipe's accept loop (pipeAcceptLoop, approvalpipe.go), driven
// with a fake pipe so its one invariant is checked off Windows: from the first
// instance until the service stops, the pipe's name always has one of our
// instances open, so no other process can create it in between.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePipeInstances counts open instances and records every moment one of
// ours closed with none left open while the loop was still serving.
type fakePipeInstances struct {
	mu       sync.Mutex
	open     int
	made     int
	gaps     []string
	stop     <-chan struct{}
	stopping bool
	// script is what each connect returns, in order; after it, connect waits
	// for stop.
	script   []error
	connects int
}

func (f *fakePipeInstances) create() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.made++
	f.open++
	return f.made, nil
}

func (f *fakePipeInstances) release(id int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open--
	if f.open == 0 && !f.stopping {
		f.gaps = append(f.gaps, fmt.Sprintf("instance %d closed with none of ours open", id))
	}
}

func (f *fakePipeInstances) connect(int) error {
	f.mu.Lock()
	i := f.connects
	f.connects++
	f.mu.Unlock()
	if i < len(f.script) {
		return f.script[i]
	}
	<-f.stop
	f.mu.Lock()
	f.stopping = true
	f.mu.Unlock()
	return errPipeStopped
}

func (f *fakePipeInstances) snapshot() (connects, open int, gaps []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connects, f.open, append([]string(nil), f.gaps...)
}

func TestThePipeNameAlwaysHasOneOfOurInstancesOpen(t *testing.T) {
	stop := make(chan struct{})
	// A client that connects and closes at once fails the connect; it can do
	// that on purpose, as often as it likes. Mixed with clients that are served.
	closed := errors.New("the client closed before the connect")
	f := &fakePipeInstances{stop: stop, script: []error{closed, closed, nil, closed, nil, closed}}
	served := make(chan int, 8)
	done := make(chan error, 1)
	go func() {
		done <- pipeAcceptLoop[int](f, stop, 2, time.Millisecond, func(string, ...any) {}, nil, func(id int) { served <- id })
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Fatal("the loop did not serve the connected clients")
		}
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if n, _, _ := f.snapshot(); n > len(f.script) {
			break // waiting for the next client
		}
		if time.Now().After(deadline) {
			t.Fatal("the loop never came back to wait for the next client")
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the loop ended with %v, want nil on stop", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not end on stop")
	}
	if _, _, gaps := f.snapshot(); len(gaps) > 0 {
		t.Fatalf("the pipe's name was free while the service served it, so another process could have created it:\n  %v", gaps)
	}
	// And nothing is left open once the served clients are done.
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, open, _ := f.snapshot(); open == 0 {
			break
		}
		if time.Now().After(deadline) {
			_, open, _ := f.snapshot()
			t.Fatalf("%d instance(s) still open after stop", open)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestThePipeIsRetriedWithBackoffWhenItsNameIsTaken(t *testing.T) {
	// What each attempt to serve does: fail before it holds the name (another
	// process created it first), or hold the name (ready) and then fail or stop.
	type attempt struct {
		ready bool
		err   error
	}
	taken := errors.New("cannot create the pipe: the name is held by another process")
	broke := errors.New("the next instance could not be created")
	attempts := []attempt{{false, taken}, {false, taken}, {false, taken}, {true, broke}, {false, taken}, {true, nil}}
	var n int
	var waits []time.Duration
	var logs []string
	pipeServeRetrying(func(ready func()) error {
		if n >= len(attempts) {
			t.Fatal("served again after it stopped")
		}
		a := attempts[n]
		n++
		if a.ready {
			ready()
		}
		return a.err
	}, func(d time.Duration) bool {
		waits = append(waits, d)
		return true
	}, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })

	if n != len(attempts) {
		t.Fatalf("%d attempts, want %d: a failed start must be tried again", n, len(attempts))
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, time.Second, 2 * time.Second}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Fatalf("waits %v, want %v (doubling, and starting again once the name was held)", waits, want)
	}
	// Once per series of attempts, and once when it is serving again.
	retrying, again := 0, 0
	for _, l := range logs {
		switch {
		case strings.Contains(l, "retrying"):
			retrying++
		case strings.Contains(l, "serving again"):
			again++
		}
	}
	if retrying != 2 || again != 2 || len(logs) != 4 {
		t.Fatalf("log lines %q: want one per series of failed attempts (2) and one per recovery (2)", logs)
	}
}

func TestThePipeRetryWaitIsCappedAndEndsWithTheService(t *testing.T) {
	var waits []time.Duration
	tries := 0
	pipeServeRetrying(func(func()) error {
		tries++
		return errors.New("the name is held by another process")
	}, func(d time.Duration) bool {
		waits = append(waits, d)
		return len(waits) < 12 // the service stops during the twelfth wait
	}, func(string, ...any) {})
	if tries != 12 {
		t.Fatalf("%d attempts, want 12: none after the service stopped", tries)
	}
	if last := waits[len(waits)-1]; last != pipeRetryMax {
		t.Fatalf("the wait grew to %v, want it capped at %v", last, pipeRetryMax)
	}
}
