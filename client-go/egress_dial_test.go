package main

// dialEach, which both egress lanes dial through: an address whose packets go
// nowhere must not hold up the next one for its share of the dial budget, the
// way the OS dialler's Happy Eyeballs never did when it was given the name.

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type closeRecordingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeRecordingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// MUTATION: dial the addresses one after another, each with an even share of
// what is left of the budget.
// RESULT: red — the second address waits out the first one's share (2 s here).
func TestDialEachDoesNotWaitOutAnAddressThatGoesNowhere(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var mu sync.Mutex
	var dialled []string
	abandoned := make(chan struct{})
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, addr)
		mu.Unlock()
		if addr == "[2001:db8::30]:443" {
			<-ctx.Done() // no answer and no error: the packets go nowhere
			close(abandoned)
			return nil, ctx.Err()
		}
		a, b := net.Pipe()
		go func() { _ = b.Close() }()
		return a, nil
	}
	began := time.Now()
	c, err := dialEach(ctx, dial, []string{"[2001:db8::30]:443", "198.51.100.30:443"})
	took := time.Since(began)
	if err != nil {
		t.Fatalf("the second address answers: %v", err)
	}
	_ = c.Close()
	if took > 1500*time.Millisecond {
		t.Fatalf("the second address waited %v for the first", took)
	}
	select {
	case <-abandoned:
	case <-time.After(2 * time.Second):
		t.Fatal("the attempt left in flight must be cancelled once another answers")
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"[2001:db8::30]:443", "198.51.100.30:443"}; !reflect.DeepEqual(dialled, want) {
		t.Fatalf("only the vetted addresses, in order: got %v, want %v", dialled, want)
	}
}

// A connection that answers after another already won is closed, not leaked;
// an address that fails at once hands over to the next without waiting; and
// when every address fails the last error is returned.
func TestDialEachClosesALateWinnerAndReturnsTheLastError(t *testing.T) {
	late := make(chan *closeRecordingConn, 1)
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		switch addr {
		case "198.51.100.31:443":
			time.Sleep(2 * dialEachStagger) // answers, but after the second address did
			a, b := net.Pipe()
			go func() { _ = b.Close() }()
			rc := &closeRecordingConn{Conn: a}
			late <- rc
			return rc, nil
		case "198.51.100.32:443":
			a, b := net.Pipe()
			go func() { _ = b.Close() }()
			return a, nil
		}
		return nil, errors.New("refused: " + addr)
	}
	c, err := dialEach(context.Background(), dial, []string{"198.51.100.31:443", "198.51.100.32:443"})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case rc := <-late:
		deadline := time.Now().Add(2 * time.Second)
		for !rc.closed.Load() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !rc.closed.Load() {
			t.Fatal("a connection that answered after the winner must be closed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the slow attempt never answered")
	}

	began := time.Now()
	_, err = dialEach(context.Background(), dial, []string{"198.51.100.33:443", "198.51.100.34:443"})
	if err == nil || err.Error() != "refused: 198.51.100.34:443" {
		t.Fatalf("every address failed, so the last error: %v", err)
	}
	if took := time.Since(began); took >= dialEachStagger {
		t.Fatalf("a failed address hands over at once, not after the stagger: %v", took)
	}
	if _, err := dialEach(context.Background(), dial, nil); err == nil {
		t.Fatal("no address is an error")
	}
}
