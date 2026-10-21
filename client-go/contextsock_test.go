package main

// The socket exists for one claim: THE DAEMON LEARNS WHO IS ASKING FROM THE
// KERNEL, NOT FROM THE ASKER. These tests are that claim, exercised with two
// real uids where the platform allows it.

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A connection from THIS process is identified as this process's user, read off
// the socket rather than sent along it.
func TestTheDaemonReadsThePeerUserFromTheKernel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix-socket peer credentials on windows; contextsock_windows.go says why")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	errs := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer c.Close()
		u, err := contextPeerUser(c)
		if err != nil {
			errs <- err
			return
		}
		got <- u
	}()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	select {
	case err := <-errs:
		t.Fatalf("reading the peer identity failed: %v", err)
	case u := <-got:
		if u == "" {
			t.Fatal("the kernel gave no identity at all")
		}
		// It must be THIS process's user, whatever that is.
		want := strconv.Itoa(os.Getuid())
		if !strings.Contains(u, want) && u != currentUserName(t) {
			t.Errorf("peer identified as %q; this process is uid %s (%s)",
				u, want, currentUserName(t))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never identified the peer")
	}
}

func currentUserName(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("id", "-un").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// THE CLAIM THAT MATTERS: a client cannot name itself. The request type carries
// no user field at all, so there is nothing to forge — asserted on the wire
// format rather than on behaviour, because the absence IS the design.
func TestTheAskRequestCarriesNoIdentityToForge(t *testing.T) {
	// READ THE TYPE, NOT A MARSHALLED VALUE. The first version marshalled a
	// struct literal, so a field added with `json:",omitempty"` would serialize
	// to nothing and pass — the same "measures the wrong thing" shape as a
	// count-not-content assertion.
	rt := reflect.TypeOf(contextAskRequest{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		tag := strings.ToLower(rt.Field(i).Tag.Get("json"))
		// WHOLE WORDS, not substrings. "as" matched any field containing those
		// two letters, so an innocent Alias or Last would have tripped it
		// later for no reason — and a guard that cries
		// wolf is one the next person deletes.
		for _, forgeable := range []string{"user", "uid", "username", "token", "asuser", "onbehalfof"} {
			if name == forgeable || strings.HasPrefix(tag, forgeable+",") || tag == forgeable {
				t.Errorf("contextAskRequest carries field %q (json %q). Anything the "+
					"client can put in this struct is something the client can lie "+
					"about; the identity is read off the connection by the daemon, and "+
					"that only holds if no field here competes with it.",
					rt.Field(i).Name, rt.Field(i).Tag.Get("json"))
			}
		}
	}
	if rt.NumField() == 0 {
		t.Fatal("contextAskRequest has no fields at all — this check would pass for ever")
	}
	// And the reply echoes the resolved user, so a person can see whose ask it
	// was recorded as.
	var rep contextAskReply
	if err := json.Unmarshal([]byte(`{"ok":true,"user":"user"}`), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.User != "user" {
		t.Errorf("the reply does not carry the resolved user: %+v", rep)
	}
}

// A SECOND, DIFFERENT USER — the case the whole socket exists for. Root only,
// because only root can become somebody else to make the point.
func TestADifferentUserIsIdentifiedAsThatUser(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() != 0 {
		t.Skip("needs root on unix to connect as a second uid")
	}
	dir, err := os.MkdirTemp("", "ctxsock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Traversable by anyone, listable by nobody — the shape contextSockListen
	// uses, so this exercises the real permission story and not a 0777 stand-in.
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(sock, 0o666); err != nil {
		t.Fatal(err)
	}

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if u, err := contextPeerUser(c); err == nil {
			got <- u
		}
	}()

	// uid 65534 (nobody) connects. If the kernel is the source, the daemon sees
	// 65534 — not root, which is what this process is.
	cmd := exec.Command("setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
		"python3", "-c",
		"import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);import time;time.sleep(1)",
		sock)
	if err := cmd.Start(); err != nil {
		t.Skipf("could not become a second user here: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	select {
	case u := <-got:
		if strings.Contains(u, "0") && !strings.Contains(u, "65534") && u != "nobody" {
			t.Errorf("a connection from uid 65534 was identified as %q — if this reads as "+
				"root, the daemon is reporting ITSELF rather than the asker, and the "+
				"username ceiling means nothing", u)
		}
		if !strings.Contains(u, "65534") && u != "nobody" {
			t.Errorf("uid 65534 was identified as %q, want nobody/65534", u)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server never identified the second user")
	}
}

// ── the test that would have caught dead code ───────────────────────────────

// THE REAL LISTENER, WIRED TO THE REAL CLIENT. Both existing tests built their
// own listener and dialled that exact path, so nothing ever checked that
// startContextSock and contextAskViaSock agree about WHERE the socket is. They
// did not: the listener bound <cfg>/context.sock.d/context.sock and the client
// dialled <cfg>/context.sock, so every ask fell back silently and the whole
// feature was dead as shipped.
//
// A unit test per side cannot see that. This one starts the actual daemon-side
// listener and calls the actual client entry point, with nothing in between.
func TestTheListenerAndTheClientAgreeOnWhereTheSocketIs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix-socket peer credentials on windows; contextsock_windows.go says why")
	}
	if os.Getuid() != 0 {
		t.Skip("binding the machine-wide socket needs root")
	}
	p, err := contextSockPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Skipf("something is already listening at %s on this box", p)
	}

	done := make(chan struct{})
	startContextSock(done)
	defer close(done)

	// Wait for the bind rather than sleeping a fixed time.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the daemon never bound %s — the path the client will dial", p)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer os.Remove(p)

	// The client's own entry point. `available` is the whole assertion: false
	// means it could not reach the daemon, which is what shipped.
	_, _, note, available := contextAskViaSock("/nonexistent-folder-for-this-test", "probe")
	if !available {
		t.Fatalf("the client could not reach the listener the daemon just started. "+
			"That is the shape the socket shipped in: available=false on every ask, a "+
			"silent fall back to a path that fails for non-root, and a daemon log line "+
			"naming an address nothing listens on. note=%q", note)
	}
}

// The socket has to be reachable BY ANOTHER USER, which is the only reason it
// exists. A path inside a 0700 config dir is not.
func TestTheSocketPathIsTraversableByAnotherUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not this platform's mechanism")
	}
	p, err := contextSockPath()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p, ".config") || strings.Contains(p, "AppData") {
		t.Fatalf("the socket path is %s, inside a per-user config dir. The daemon and "+
			"the person resolve DIFFERENT paths there, so they can never meet — which "+
			"is exactly the case this endpoint exists for.", p)
	}
	if !strings.HasPrefix(p, "/var/run") && !strings.HasPrefix(p, "/run") {
		t.Errorf("the socket is at %s; it belongs somewhere machine-wide and root-owned "+
			"so no other uid can squat it", p)
	}
}

// A socket at the right path owned by somebody else is NOT the daemon, and the
// client must refuse rather than hand it a folder path.
func TestASocketNotOwnedByRootIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a non-root view, or is not this platform's mechanism")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "impostor.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if why := contextSockDialable(sock); why == "" {
		t.Error("a socket owned by this non-root test process was accepted as the " +
			"machine's bastion")
	}
}
