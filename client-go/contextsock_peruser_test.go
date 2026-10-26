package main

import (
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// One person cannot take every slot: past their own share they are told the
// daemon is busy at once, while slots remain for everyone else. Before, one
// user's idle connections, re-dialled as each deadline ran out, held all of
// them and every other user's ask was refused.
func TestOneUserCannotHoldEveryContextSockSlot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix-socket peer credentials on windows; contextsock_windows.go says why")
	}
	const share = 4 // contextSockMaxPerUser
	// A test before this one may still be releasing its slots.
	if n := contextSockSlotsHeld(t, 0); n != 0 {
		t.Fatalf("%d slots still held from an earlier test", n)
	}
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go contextSockAccept(ln)

	var held []net.Conn
	defer func() {
		for _, h := range held {
			_ = h.Close()
		}
	}()
	for i := 0; i < share; i++ {
		h, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, h)
	}
	// Wait until the daemon has given those four their slots (a fixed sleep
	// lost this race on a loaded machine and handed the 5th one first).
	if n := contextSockSlotsHeld(t, share); n != share {
		t.Fatalf("the daemon gave %d slots to %d idle connections of one user", n, share)
	}

	extra, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, rerr := extra.Read(buf)
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatalf("one user held %d idle connections and a %dth was still given a slot: "+
			"one user can take all %d", share, share+1, contextSockMaxInFlight)
	}
	if !strings.Contains(string(buf[:n]), "busy") {
		t.Fatalf("past one user's share the ask got %q; it must be told the daemon is busy", buf[:n])
	}
}

// contextSockSlotsHeld waits up to 10 s for the per-user slots held across
// all users to reach want, and returns the count it last saw.
func contextSockSlotsHeld(t *testing.T, want int) int {
	t.Helper()
	n := -1
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		contextSockUsers.Lock()
		n = 0
		for _, k := range contextSockUsers.held {
			n += k
		}
		contextSockUsers.Unlock()
		if n == want {
			break
		}
	}
	return n
}
