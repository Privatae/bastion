package main

// The context socket is 0666: every user on the machine may connect, and the
// daemon behind it runs as root (or SYSTEM). So what one connection can make
// the daemon hold must be bounded by the daemon, not by the asker.

import (
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// An ask is a folder path and a display name. A client that streams a request
// with no end gets the daemon to read only a bounded amount of it, then a
// reply and a close; before, the decoder kept every byte until the 30 s
// deadline, and nothing capped how many such connections were open.
func TestAContextAskWithNoEndIsReadOnlyToABound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix-socket peer credentials on windows; contextsock_windows.go says why")
	}
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		contextSockServe(c)
	}()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const total = 16 << 20
	chunk := []byte(strings.Repeat("a", 64<<10))
	sent := 0
	if _, err := c.Write([]byte(`{"root":"`)); err != nil {
		t.Fatal(err)
	}
	for sent < total {
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Write(chunk)
		sent += n
		if err != nil {
			break
		}
	}
	// The kernel's socket buffers hold a few hundred KiB the daemon never
	// read; anything near the whole stream means the daemon read it all.
	if sent >= 4<<20 {
		t.Fatalf("the daemon accepted %d MiB of one ask with no end; it must stop at a bound", sent>>20)
	}
}

// Asks in flight are capped: a connection past the cap is closed at once, so
// many idle or endless connections cannot multiply the bound above.
func TestContextAsksInFlightAreCapped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix-socket peer credentials on windows; contextsock_windows.go says why")
	}
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Every connection here is the same user; lift the per-user share so the
	// overall cap is what this test meets (TestOneUserCannotHoldEveryContextSockSlot
	// holds the share).
	oldShare := contextSockMaxPerUser
	contextSockMaxPerUser = contextSockMaxInFlight
	t.Cleanup(func() { contextSockMaxPerUser = oldShare })
	go contextSockAccept(ln)

	var held []net.Conn
	defer func() {
		for _, h := range held {
			_ = h.Close()
		}
	}()
	// Each of these sends nothing and holds its slot until its deadline.
	for i := 0; i < contextSockMaxInFlight; i++ {
		h, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, h)
	}
	// Give the daemon's accept loop time to take every held connection.
	time.Sleep(200 * time.Millisecond)

	extra, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, rerr := extra.Read(buf)
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatalf("a connection past the cap of %d was left open; it must be refused", contextSockMaxInFlight)
	}
	if n > 0 && !strings.Contains(string(buf[:n]), "busy") {
		t.Fatalf("a connection past the cap got %q; it must be told the daemon is busy", buf[:n])
	}

	// Once a held connection goes, a new ask gets a slot again.
	_ = held[0].Close()
	held = held[1:]
	time.Sleep(200 * time.Millisecond)
	again, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	_ = again.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, rerr = again.Read(buf)
	if ne, ok := rerr.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("after a slot was freed, a new ask was not served (read %q, %v)", buf[:n], rerr)
	}
}
