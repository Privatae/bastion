package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dialHandler hands one real loopback connection to handleEgressConn (standing in for a
// worker WS the bastion opened to the host). dialOut is a loopback dialer standing in for
// the user's real internet.
func dialHandler(t *testing.T, dialOut egressDialer) (net.Conn, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		handleEgressConn(c, dialOut, "")
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
	return cli, func() { cli.Close(); ln.Close() }
}

// redirectDial stands in for the user's internet: the lane asks for a public
// destination, and this dials the loopback backend instead, recording what the
// lane asked for. The lane never reaches loopback itself.
func redirectDial(backend string, asked *[]string) egressDialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		*asked = append(*asked, addr)
		return (&net.Dialer{}).DialContext(ctx, network, backend)
	}
}

// CONNECT establishes a raw tunnel; bytes flow both ways through it.
func TestEgressConnConnectTunnel(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c) // echo
	}()

	var asked []string
	cli, cleanup := dialHandler(t, redirectDial(backend.Addr().String(), &asked))
	defer cleanup()
	fmt.Fprint(cli, "CONNECT 198.51.100.20:443 HTTP/1.1\r\nHost: 198.51.100.20:443\r\n\r\n")
	br := bufio.NewReader(cli)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT: expected 200, got %q (err %v)", status, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CONNECT headers: %v", err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	if _, err := cli.Write([]byte("ping-through-tunnel")); err != nil {
		t.Fatal(err)
	}
	want := "ping-through-tunnel"
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("reading tunnel echo: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("tunnel echo mismatch: got %q", string(buf))
	}
	if len(asked) != 1 || asked[0] != "198.51.100.20:443" {
		t.Fatalf("the lane must dial the address it vetted: %v", asked)
	}
}

func TestEgressConnPlainHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain-http-ok")
	}))
	defer backend.Close()

	var asked []string
	cli, cleanup := dialHandler(t, redirectDial(strings.TrimPrefix(backend.URL, "http://"), &asked))
	defer cleanup()
	fmt.Fprint(cli, "GET http://198.51.100.21/ HTTP/1.1\r\nHost: 198.51.100.21\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(cli)
	if !strings.Contains(string(body), "plain-http-ok") {
		t.Fatalf("plain HTTP forward: got %q", string(body))
	}
	if len(asked) != 1 || asked[0] != "198.51.100.21:80" {
		t.Fatalf("the lane must dial the address it vetted: %v", asked)
	}
}

func TestEgressConnDialFailure(t *testing.T) {
	failDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("no route")
	}
	cli, cleanup := dialHandler(t, failDial)
	defer cleanup()
	fmt.Fprint(cli, "CONNECT 198.51.100.22:443 HTTP/1.1\r\n\r\n")
	status, _ := bufio.NewReader(cli).ReadString('\n')
	if !strings.Contains(status, "502") {
		t.Fatalf("expected 502 on dial failure, got %q", status)
	}
}

func TestEnsurePort(t *testing.T) {
	for _, c := range []struct{ in, def, want string }{
		{"api.x.ai:443", "443", "api.x.ai:443"},
		{"api.x.ai", "80", "api.x.ai:80"},
		{"[2001:db8::1]:8080", "443", "[2001:db8::1]:8080"},
		{"[2001:db8::1]", "443", "[2001:db8::1]:443"},
	} {
		if got := ensurePort(c.in, c.def); got != c.want {
			t.Errorf("ensurePort(%q,%q)=%q want %q", c.in, c.def, got, c.want)
		}
	}
}
