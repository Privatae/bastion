//go:build !windows

// Tagged !windows: it borrows setupBox (anchor_test.go) and stubOwnAddrs
// (ownaddr_test.go).

package main

// The egress lane on a local (unanchored) box. It refuses this machine and
// its link-local addresses, so a host cannot reach this machine's services
// (ollama above all) around the switches that govern them, and, since
// 2026-10-26, the network around it as well: the LAN and the mesh
// (egress_network_test.go). An anchored box is unchanged: the public internet
// only.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// answerEgressNames answers the egress lane's name lookups from m.
func answerEgressNames(t *testing.T, m map[string][]string) {
	t.Helper()
	old := egressResolve
	t.Cleanup(func() { egressResolve = old })
	egressResolve = func(_ context.Context, host string) ([]net.IPAddr, error) {
		ips, ok := m[strings.ToLower(host)]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []net.IPAddr
		for _, s := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(s)})
		}
		return out, nil
	}
}

// A machine with a LAN address of its own and an AnyIP range, and names that
// answer with this machine, with the LAN and with the public internet.
func localEgressFixture(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if currentAnchor() != nil || boxMode() != modeLocal {
		t.Fatal("the fixture must be a local, unanchored box")
	}
	stubOwnAddrs(t, []string{"127.0.0.1/8", "::1/128", "192.168.50.7/24", "fe80::7/64"}, localRange("203.0.113.0/24"))
	answerEgressNames(t, map[string][]string{
		"ollama.example.test": {"127.0.0.1"},
		"mixed.example.test":  {"198.51.100.8", "127.0.0.1"},
		"self.example.test":   {"192.168.50.7"},
		"nas.example.test":    {"192.168.50.30"},
		"dual.example.test":   {"2001:db8::8", "198.51.100.8"},
		"site.example.test":   {"198.51.100.9"},
	})
}

// MUTATION: restore the early return for an unanchored box in egressVettedAddrs.
// RESULT: red — 127.0.0.1:11434 is handed to the dial, and a name is dialled
// as a name instead of the address that was vetted.
func TestLocalEgressRefusesThisMachineAndTheLAN(t *testing.T) {
	localEgressFixture(t)
	ctx := context.Background()
	for _, hp := range []string{
		"127.0.0.1:11434", "127.9.9.9:80", "localhost:11434", "ollama.localhost:80", "[::1]:11434",
		"0.0.0.0:11434", "0.1.2.3:80", "[::]:80",
		"[::ffff:127.0.0.1]:11434", "[64:ff9b::7f00:1]:11434", "[2002:7f00:1::]:80", "[64:ff9b:1::5]:80",
		"169.254.169.254:80", "[fe80::1]:80",
		"192.168.50.7:11434", // this machine's own LAN address
		"203.0.113.5:80",     // a range a `local` route delivers here
		"ollama.example.test:11434", "mixed.example.test:443", "self.example.test:11434",
		"unknown.example.test:443",
		// the network around this machine (egress_network_test.go has the rest)
		"192.168.50.20:8080", "10.1.2.3:443", "172.16.4.4:22", "[fd12:3456::9]:80", "100.64.0.9:80",
		"nas.example.test:443",
	} {
		if addr, why := egressVettedAddr(ctx, hp); why == "" || addr != "" {
			t.Errorf("%s must be refused on a local box, got dial %q", hp, addr)
		}
	}
	for hp, want := range map[string][]string{
		"198.51.100.8:443":      {"198.51.100.8:443"},
		"site.example.test:443": {"198.51.100.9:443"},
		"dual.example.test:443": {"[2001:db8::8]:443", "198.51.100.8:443"},
	} {
		got, why := egressVettedAddrs(ctx, hp)
		if why != "" || !reflect.DeepEqual(got, want) {
			t.Errorf("%s is the internet, so a local box dials %v: got %v %q", hp, want, got, why)
		}
	}
}

// The anchored lane keeps its own wording and still refuses the LAN that a
// local box reaches.
func TestAnchoredEgressStillRefusesTheLAN(t *testing.T) {
	setupBox(t)
	stubOwnAddrs(t, []string{"127.0.0.1/8", "::1/128", "192.168.50.7/24"}, localRange("203.0.113.0/24"))
	ctx := context.Background()
	for _, hp := range []string{"192.168.50.20:8080", "10.1.2.3:443", "[fd12:3456::9]:80", "100.64.0.9:80", "127.0.0.1:11434"} {
		if addr, why := egressVettedAddr(ctx, hp); addr != "" || !strings.Contains(why, "only on an anchored machine") {
			t.Errorf("%s must be refused on an anchored box as before, got %q %q", hp, addr, why)
		}
	}
	if addr, why := egressVettedAddr(ctx, "198.51.100.8:443"); why != "" || addr != "198.51.100.8:443" {
		t.Fatalf("the public internet passes: %q %q", addr, why)
	}
}

// Through the lane itself, with a real dialer: a request for this machine is
// answered 403 and never reaches the listener; a public name is dialled at
// its vetted address; a dual-stack name falls back to its second address.
func TestLocalEgressLaneNeverDialsThisMachine(t *testing.T) {
	localEgressFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	ask := func(dial egressDialer, req string) string {
		srv, cli := net.Pipe()
		go handleEgressConn(srv, dial, "home.host.example")
		_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(cli, req)
		line, _ := bufio.NewReader(cli).ReadString('\n')
		cli.Close()
		return line
	}
	netDial := (&net.Dialer{Timeout: 2 * time.Second}).DialContext
	target := ln.Addr().String()
	for _, req := range []string{
		"CONNECT " + target + " HTTP/1.1\r\n\r\n",
		"GET http://" + target + "/api/tags HTTP/1.1\r\nHost: " + target + "\r\n\r\n",
		"CONNECT localhost:" + strings.Split(target, ":")[1] + " HTTP/1.1\r\n\r\n",
	} {
		if line := ask(netDial, req); !strings.HasPrefix(line, "HTTP/1.1 403") {
			t.Errorf("a local box must refuse %q, answered %q", req, line)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the lane reached this machine's listener %d times", n)
	}

	var asked []string
	recording := func(_ context.Context, _, addr string) (net.Conn, error) {
		asked = append(asked, addr)
		return nil, errors.New("stop here")
	}
	if line := ask(recording, "CONNECT site.example.test:443 HTTP/1.1\r\n\r\n"); !strings.HasPrefix(line, "HTTP/1.1 502") {
		t.Fatalf("a public destination is dialled (and this dial fails): %q", line)
	}
	if !reflect.DeepEqual(asked, []string{"198.51.100.9:443"}) {
		t.Fatalf("the vetted address, never the name: %v", asked)
	}

	asked = nil
	fallback := func(_ context.Context, _, addr string) (net.Conn, error) {
		asked = append(asked, addr)
		if strings.HasPrefix(addr, "[") {
			return nil, errors.New("network is unreachable")
		}
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(b, b) }()
		return a, nil
	}
	if line := ask(fallback, "CONNECT dual.example.test:443 HTTP/1.1\r\n\r\n"); !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("a dual-stack name answers from its second address: %q", line)
	}
	if want := []string{"[2001:db8::8]:443", "198.51.100.8:443"}; !reflect.DeepEqual(asked, want) {
		t.Fatalf("each vetted address in turn: got %v, want %v", asked, want)
	}
}

// What docs/models.md tells a person with a local box to do: switch `models`
// off for the host. The forward then filters store-changing requests, and the
// egress lane is no way around it, since it never reaches this machine's
// ollama, on loopback or on the machine's own LAN address.
func TestLocalModelsSwitchLeavesNoEgressRouteToOllama(t *testing.T) {
	localEgressFixture(t)
	const host = "home.host.example"
	writePairingState(t, host, pairingActive)
	if inferenceFilterNeeded(host, laneOllama, pairingModelScope(host)) {
		t.Fatal("an unscoped local pairing is a raw splice before the switch, so this test would prove nothing")
	}
	if err := localDenySet(host, "models", true); err != nil {
		t.Fatal(err)
	}
	if !inferenceFilterNeeded(host, laneOllama, pairingModelScope(host)) {
		t.Fatal("with `models` off the ollama forward must filter /api/pull")
	}
	var dialled []string
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialled = append(dialled, addr)
		return nil, errors.New("stop here")
	}
	for _, dest := range []string{"127.0.0.1:11434", "localhost:11434", "192.168.50.7:11434", "[::1]:11434"} {
		srv, cli := net.Pipe()
		go handleEgressConn(srv, dial, host)
		_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(cli, "POST http://%s/api/pull HTTP/1.1\r\nHost: %s\r\n\r\n", dest, dest)
		line, _ := bufio.NewReader(cli).ReadString('\n')
		cli.Close()
		if !strings.HasPrefix(line, "HTTP/1.1 403") {
			t.Errorf("egress to %s must be refused: %q", dest, line)
		}
	}
	if len(dialled) != 0 {
		t.Fatalf("nothing for this machine may be dialled: %v", dialled)
	}
}
