package main

// When a Host holds this machine (its owner quarantined it there), the Host
// refuses every worker socket of every lane with close code 4403, and says
// "quarantined": true on each beat it answers. The lane workers park a pool of
// sockets per lane and used to dial again at once (mgmt, harness, session) or
// a second after a close (egress, serve), so one held machine whose tunnel
// stayed up dialled the Host 30 to 80 times a second, each one a TLS
// handshake. A pairing's workers now share one hold:
//
//   - a socket the Host closes with 4403 holds every worker of that pairing for
//     laneHoldFirst, doubling with each hold up to laneHoldMax;
//   - a beat that says quarantined stops them dialling until a beat no longer
//     does, which is how the owner's release reaches this machine.
//
// The hold is the pairing's, so another Host this machine is paired with is
// never slowed by it.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// laneHeldCloseCode is the close code a Host gives a worker socket of a
// machine it holds (the Host's quarantine gate).
const laneHeldCloseCode = 4403

// The first hold, and the longest. Variables so a test can shorten them.
var (
	laneHoldFirst = 5 * time.Second
	laneHoldMax   = 5 * time.Minute
)

type laneHold struct {
	mu          sync.Mutex
	wait        time.Duration // the last hold's length; the next one doubles it
	until       time.Time     // no worker of the pairing dials before this
	last        time.Time     // when the last hold began
	quarantined bool          // what the last beat said
	wake        chan struct{} // closed when the beat lifts a quarantine
}

var laneHolds sync.Map // host name -> *laneHold

func laneHoldFor(host string) *laneHold {
	if h, ok := laneHolds.Load(host); ok {
		return h.(*laneHold)
	}
	h, _ := laneHolds.LoadOrStore(host, &laneHold{wake: make(chan struct{})})
	return h.(*laneHold)
}

// refused is a worker socket the Host closed with 4403. The workers of a pool
// are refused together, so a refusal while a hold is on is that hold's and
// does not lengthen it. A refusal long after the last hold starts again from
// laneHoldFirst.
func (h *laneHold) refused(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if now.Before(h.until) {
		return
	}
	switch {
	case h.wait == 0 || now.Sub(h.last) > 2*laneHoldMax:
		h.wait = laneHoldFirst
	default:
		h.wait = min(2*h.wait, laneHoldMax)
	}
	h.last = now
	h.until = now.Add(h.wait)
	fmt.Printf("[%s] the Host refused a lane: it holds this machine; its lanes dial again in %s\n", host, h.wait)
}

// fromBeat is what a beat's reply said. A release ends the hold at once and
// starts the next one from laneHoldFirst.
func (h *laneHold) fromBeat(host string, quarantined bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case quarantined && !h.quarantined:
		h.quarantined = true
		fmt.Printf("[%s] the Host holds this machine (quarantined there): its lanes wait until its owner releases it\n", host)
	case !quarantined && h.quarantined:
		h.quarantined = false
		h.wait, h.until = 0, time.Time{}
		close(h.wake)
		h.wake = make(chan struct{})
		fmt.Printf("[%s] the Host released this machine: its lanes are back\n", host)
	}
}

// waitClear blocks a worker until it may dial: the hold is over and the last
// beat did not say quarantined. A worker waits a little past the hold's end,
// a different little for each, so a pool does not dial in one burst. False
// when ctx ends first.
func (h *laneHold) waitClear(ctx context.Context) bool {
	for {
		h.mu.Lock()
		quarantined, until, wake := h.quarantined, h.until, h.wake
		h.mu.Unlock()
		if ctx.Err() != nil {
			return false
		}
		var t *time.Timer
		var timer <-chan time.Time
		switch {
		case quarantined:
			// Only a beat lifts it.
		case time.Now().Before(until):
			d := time.Until(until)
			t = time.NewTimer(d + rand.N(d/10+time.Millisecond))
			timer = t.C
		default:
			return true
		}
		select {
		case <-ctx.Done():
		case <-wake:
		case <-timer:
		}
		if t != nil {
			t.Stop()
		}
	}
}

// watchHeldClose reports, once the socket has been read to its end, whether
// the Host closed it with laneHeldCloseCode.
func watchHeldClose(ws *websocket.Conn) (held func() bool) {
	var got atomic.Bool
	def := ws.CloseHandler()
	ws.SetCloseHandler(func(code int, text string) error {
		if code == laneHeldCloseCode {
			got.Store(true)
		}
		return def(code, text)
	})
	return got.Load
}

// beatSaysQuarantined reads the "quarantined" a Host puts on the beat's reply
// for a machine it holds. A reply without it, or one that cannot be read, is
// not a hold.
func beatSaysQuarantined(body []byte) bool {
	var r struct {
		Quarantined bool `json:"quarantined"`
	}
	return json.Unmarshal(body, &r) == nil && r.Quarantined
}
