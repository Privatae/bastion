//go:build linux

package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func serveIdentity(t *testing.T, path, who string) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skip("no unix sockets here: " + err.Error())
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(who))
			_ = c.Close()
		}
	}()
	return ln
}

// A link at the socket's name is never followed, and a plain file is not a socket.
func TestServiceDialSocketRefusesALinkAndAFile(t *testing.T) {
	dir := t.TempDir()
	decoy := serveIdentity(t, filepath.Join(dir, "decoy.sock"), "DECOY")
	defer decoy.Close()
	link := filepath.Join(dir, "gitea.sock")
	if err := os.Symlink(filepath.Join(dir, "decoy.sock"), link); err != nil {
		t.Fatal(err)
	}
	if c, err := serviceDialSocket(link, time.Second); err == nil {
		c.Close()
		t.Fatal("a symlink at the socket name must not be dialled")
	}
	_ = os.Remove(link)
	_ = os.WriteFile(link, []byte("x"), 0o600)
	if c, err := serviceDialSocket(link, time.Second); err == nil {
		c.Close()
		t.Fatal("a plain file is not a socket")
	}
}

// THE RACE the review found: the container renames a link to a same-uid host
// socket into place between the check and the dial. With the inode pinned,
// every connection that succeeds reaches the real server — never the decoy.
func TestServiceDialSocketSurvivesARenameRace(t *testing.T) {
	dir := t.TempDir()
	real := serveIdentity(t, filepath.Join(dir, "real.sock"), "SERVER")
	defer real.Close()
	decoy := serveIdentity(t, filepath.Join(dir, "decoy.sock"), "DECOY")
	defer decoy.Close()
	name := filepath.Join(dir, "gitea.sock")
	if err := os.Link(filepath.Join(dir, "real.sock"), name); err != nil {
		t.Skip("hard links to sockets unsupported here: " + err.Error())
	}
	var stop atomic.Bool
	go func() {
		for !stop.Load() {
			_ = os.Symlink(filepath.Join(dir, "decoy.sock"), name+".l")
			_ = os.Rename(name+".l", name)
			_ = os.Link(filepath.Join(dir, "real.sock"), name+".r")
			_ = os.Rename(name+".r", name)
		}
	}()
	defer stop.Store(true)
	reached := map[string]int{}
	for i := 0; i < 400; i++ {
		c, err := serviceDialSocket(name, time.Second)
		if err != nil {
			reached["refused"]++
			continue
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		b, _ := io.ReadAll(c)
		c.Close()
		reached[string(b)]++
	}
	if reached["DECOY"] > 0 {
		t.Fatalf("a dial reached the decoy through a renamed link: %v", reached)
	}
	if reached["SERVER"] == 0 {
		t.Fatalf("the real server was never reached: %v", reached)
	}
	t.Logf("outcomes over 400 racing dials: %v", reached)
}
