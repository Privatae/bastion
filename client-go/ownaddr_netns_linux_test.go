//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const ownAddrNetnsEnv = "PRIVATAE_TEST_OWNADDR_NETNS"

// THE KERNEL'S OWN ANSWER, IN A REAL NETWORK NAMESPACE. A `local` route
// (AnyIP) makes the kernel deliver a whole range to this machine although no
// interface holds those addresses, so a service on 0.0.0.0 answers on every
// one of them. This runs the test binary again in a private user and network
// namespace (as `unshare -rn` does), adds `local 192.0.2.0/24` and
// `local 2001:db8:a::/64` on lo, a broadcast, two anycast and a multicast
// route, proves a 0.0.0.0 listener answers on the local ranges, and then asks
// every lane that dials for someone else: a coder run's proxy and the anchored
// egress lane (each vetted, and each end to end over its own connection with a
// real dialer, answering 403), and the backup lanes' URL check and dial wall.
// Each address, the IPv4-mapped and NAT64 forms of each IPv4 one, and a name
// for each are refused, each lane's reason read so that a name the lane could
// not resolve (refused for that) does not count; nothing reaches the
// listener, and an address or name with a unicast route or no route passes.
// The lookup itself is checked against the kernel's local, broadcast,
// anycast, multicast, unicast and no-route answers, so the unicast answer is
// read even on a machine with no default route. Skipped where a private
// namespace cannot be made.
//
// MUTATION: set ownRouteLookup to nil (the interface check alone).
// RESULT: red — the AnyIP destinations are vetted and reach the listener.
// MUTATION: in routeKindOfType, test `!= unix.RTN_LOCAL`.
// RESULT: red — the broadcast and anycast destinations pass every lane.
func TestAnyIPDestinationsAreRefusedInARealNamespace(t *testing.T) {
	if os.Getenv(ownAddrNetnsEnv) != "1" {
		if _, err := exec.LookPath("ip"); err != nil {
			if _, err := os.Stat("/usr/sbin/ip"); err != nil {
				t.Skip("needs ip(8)")
			}
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestAnyIPDestinationsAreRefusedInARealNamespace$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), ownAddrNetnsEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		out, err := cmd.CombinedOutput()
		if cmd.ProcessState == nil {
			t.Skipf("no private user and network namespace here: %v", err)
		}
		t.Logf("in a private network namespace:\n%s", out)
		if strings.Contains(string(out), "--- SKIP") {
			t.Skip("the namespaced run could not set up its routes")
		}
		if err != nil {
			t.Fatalf("the namespaced run failed: %v", err)
		}
		if !strings.Contains(string(out), "--- PASS: TestAnyIPDestinationsAreRefusedInARealNamespace") {
			t.Fatal("the namespaced run did not run")
		}
		return
	}

	ipBin, err := exec.LookPath("ip")
	if err != nil {
		ipBin = "/usr/sbin/ip"
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"route", "add", "local", "192.0.2.0/24", "dev", "lo"},
		{"-6", "route", "add", "local", "2001:db8:a::/64", "dev", "lo"},
		// Plain unicast routes, so the kernel's unicast answer is read here
		// whatever routes the machine running the tests has (a box with no
		// default route answers every public address with no route at all).
		{"route", "add", "198.51.100.0/24", "dev", "lo"},
		{"-6", "route", "add", "2001:db8:b::/64", "dev", "lo"},
		// The other route types the kernel answers with, none of them unicast:
		// each is this machine, so a lookup that took only `local` as this
		// machine would let them through.
		{"route", "add", "broadcast", "198.51.101.255", "dev", "lo"},
		{"route", "add", "anycast", "198.51.102.0/24", "dev", "lo"},
		{"-6", "route", "add", "anycast", "2001:db8:d::/64", "dev", "lo"},
		{"route", "add", "multicast", "233.252.0.0/24", "dev", "lo"},
	} {
		if out, err := exec.Command(ipBin, args...).CombinedOutput(); err != nil {
			t.Skipf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	// The real kernel's three answers, read by the real rtnetlink lookup.
	for addr, want := range map[string]routeKind{
		"192.0.2.55": routeThisMachine, "2001:db8:a::55": routeThisMachine, "::ffff:192.0.2.55": routeThisMachine,
		"198.51.100.9": routeLeaves, "2001:db8:b::9": routeLeaves,
		"203.0.113.9": routeNowhere, "2001:db8:c::9": routeNowhere,
		"198.51.101.255": routeThisMachine, // broadcast
		"198.51.102.5":   routeThisMachine, // anycast
		"2001:db8:d::5":  routeThisMachine, // anycast
		"233.252.0.5":    routeThisMachine, // multicast
	} {
		if got, err := ownRouteLookup(net.ParseIP(addr)); err != nil || got != want {
			t.Errorf("route lookup %s: got kind %d err %v, want kind %d", addr, got, err, want)
		}
	}
	ln, err := net.Listen("tcp", ":0") // 0.0.0.0 and [::]
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var hits atomic.Int64
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
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	// The hazard is real here: the listener answers on both AnyIP ranges.
	for _, a := range []string{"192.0.2.55", "2001:db8:a::55"} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(a, port), 2*time.Second)
		if err != nil {
			t.Fatalf("the 0.0.0.0 listener should answer on %s: %v", a, err)
		}
		c.Close()
	}
	for deadline := time.Now().Add(2 * time.Second); hits.Load() < 2 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() != 2 {
		t.Fatalf("the listener saw %d of the 2 direct connections", hits.Load())
	}
	ownAddrReset()

	names := map[string][]string{"anyip.example": {"192.0.2.55"}, "anyip6.example": {"2001:db8:a::55"},
		"bcast.example": {"198.51.101.255"}, "anycast.example": {"198.51.102.5"}, "anycast6.example": {"2001:db8:d::5"},
		"unicast.example": {"198.51.100.9"}, "unicast6.example": {"2001:db8:b::9"},
		"nowhere.example": {"203.0.113.9"}, "nowhere6.example": {"2001:db8:c::9"}}
	stubResolve(t, names)
	stubEgressResolve(t, names)
	ctx := context.Background()
	targets := []string{
		net.JoinHostPort("192.0.2.55", port), net.JoinHostPort("2001:db8:a::55", port),
		net.JoinHostPort("::ffff:192.0.2.55", port), net.JoinHostPort("64:ff9b::c000:237", port),
		"anyip.example:" + port, "anyip6.example:" + port,
		// Broadcast and anycast routes: this machine too, by address and by name.
		net.JoinHostPort("198.51.101.255", port), net.JoinHostPort("198.51.102.5", port),
		net.JoinHostPort("2001:db8:d::5", port), net.JoinHostPort("::ffff:198.51.102.5", port),
		"bcast.example:" + port, "anycast6.example:" + port,
		// The IPv4-mapped and NAT64 forms of the broadcast and anycast addresses.
		net.JoinHostPort("::ffff:198.51.101.255", port), net.JoinHostPort("64:ff9b::c633:65ff", port),
		net.JoinHostPort("64:ff9b::c633:6605", port), "anycast.example:" + port,
	}
	// A unicast route and no route at all are both not this machine, by address
	// and by name: each passes, and the address to dial is the one vetted.
	passes := map[string]string{
		"198.51.100.9:443": "198.51.100.9:443", "203.0.113.9:443": "203.0.113.9:443",
		"[2001:db8:b::9]:443": "[2001:db8:b::9]:443", "[2001:db8:c::9]:443": "[2001:db8:c::9]:443",
		"unicast.example:443": "198.51.100.9:443", "unicast6.example:443": "[2001:db8:b::9]:443",
		"nowhere.example:443": "203.0.113.9:443", "nowhere6.example:443": "[2001:db8:c::9]:443",
	}
	// Each refusal must be the this-machine refusal. A name the lane's resolver
	// could not answer would be refused too ("does not resolve"), so a refusal
	// alone would not show the name was resolved and its address vetted.
	for _, hp := range targets {
		if got, why := coderVettedAddr(ctx, hp, nil); !strings.Contains(why, "never this machine") {
			t.Errorf("coder run: %s is this machine and must be refused as such, got dial %q, %q", hp, got, why)
		}
	}
	for hp, want := range passes {
		if got, why := coderVettedAddr(ctx, hp, nil); why != "" || got != want {
			t.Errorf("coder run: %s leaves this machine or goes nowhere, so it passes as %s: %q %q", hp, want, got, why)
		}
	}
	// The same requests, sent to each lane's socket with its real dialer.
	requests := []string{
		"CONNECT " + targets[0] + " HTTP/1.1\r\n\r\n",
		"CONNECT " + targets[1] + " HTTP/1.1\r\n\r\n",
		"CONNECT " + targets[2] + " HTTP/1.1\r\n\r\n",
		"CONNECT " + targets[4] + " HTTP/1.1\r\n\r\n",
		"CONNECT " + targets[5] + " HTTP/1.1\r\n\r\n",
		"CONNECT " + targets[6] + " HTTP/1.1\r\n\r\n",
		"CONNECT " + targets[7] + " HTTP/1.1\r\n\r\n",
		"CONNECT " + targets[10] + " HTTP/1.1\r\n\r\n",
		"GET http://" + targets[0] + "/ HTTP/1.1\r\nHost: 192.0.2.55\r\n\r\n",
		"GET http://" + targets[4] + "/ HTTP/1.1\r\nHost: anyip.example\r\n\r\n",
	}
	ask := func(c net.Conn, req string) string {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte(req))
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		return line
	}

	// A coder run's proxy end to end.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	oldChown := coderChown
	t.Cleanup(func() { coderChown = oldChown })
	coderChown = func(string, int, int) error { return nil }
	dir := t.TempDir()
	if err := coderListenEgress("run-anyip", dir, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	defer coderCloseEgress("run-anyip")
	for _, req := range requests {
		c, err := net.Dial("unix", dir+"/"+coderEgressSock)
		if err != nil {
			t.Fatal(err)
		}
		if line := ask(c, req); !strings.HasPrefix(line, "HTTP/1.1 403") {
			t.Errorf("the proxy must refuse %q, answered %q", req, line)
		}
	}

	// The anchored egress lane, in the same namespace: the vetting, then the
	// lane end to end as the anchor host, with a real dialer.
	setupBox(t)
	for _, hp := range targets {
		if addr, why := egressVettedAddr(ctx, hp); !strings.Contains(why, "that is this machine") {
			t.Errorf("anchored egress: %s is this machine and must be refused as such, got %q, %q", hp, addr, why)
		}
	}
	for hp, want := range passes {
		if addr, why := egressVettedAddr(ctx, hp); why != "" || addr != want {
			t.Errorf("anchored egress: %s leaves this machine or goes nowhere, so it passes as %s: %q %q", hp, want, addr, why)
		}
	}
	dialer := (&net.Dialer{Timeout: 2 * time.Second}).DialContext
	for _, req := range requests {
		srv, cli := net.Pipe()
		go handleEgressConn(srv, dialer, tAnchor)
		if line := ask(cli, req); !strings.HasPrefix(line, "HTTP/1.1 403") {
			t.Errorf("the anchored lane must refuse %q, answered %q", req, line)
		}
	}

	// The backup lanes' wall: refused at the URL check and at the dial.
	stubBackupLookup(t, names)
	for _, hp := range targets {
		if err := validateBackupURL("https://" + hp + "/b.tar"); err == nil || !strings.Contains(err.Error(), "on this machine or this network") {
			t.Errorf("backup: %s is this machine and must be refused as such: %v", hp, err)
		}
	}
	for hp := range passes {
		if err := validateBackupURL("https://" + hp + "/b.tar"); err != nil {
			t.Errorf("backup: %s leaves this machine or goes nowhere, so it passes: %v", hp, err)
		}
	}
	for _, a := range []string{"192.0.2.55", "2001:db8:a::55", "198.51.101.255", "198.51.102.5", "2001:db8:d::5"} {
		if backupDialAllowed(net.ParseIP(a)) {
			t.Errorf("backup: the dial to %s is this machine and must be refused", a)
		}
	}
	for _, a := range []string{"198.51.100.9", "203.0.113.9", "2001:db8:b::9"} {
		if !backupDialAllowed(net.ParseIP(a)) {
			t.Errorf("backup: %s leaves this machine or goes nowhere, so it passes", a)
		}
	}

	time.Sleep(100 * time.Millisecond)
	if n := hits.Load(); n != 2 {
		t.Fatalf("nothing the lanes were asked for may reach the listener: it saw %d connections after the 2 direct ones", n-2)
	}
}

// stubEgressResolve answers the anchored lane's name lookups from m.
func stubEgressResolve(t *testing.T, m map[string][]string) {
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

// stubBackupLookup answers the backup lanes' name lookups from m.
func stubBackupLookup(t *testing.T, m map[string][]string) {
	t.Helper()
	old := backupLookupIP
	t.Cleanup(func() { backupLookupIP = old })
	backupLookupIP = func(host string) ([]net.IP, error) {
		if ip := net.ParseIP(host); ip != nil {
			return []net.IP{ip}, nil
		}
		ips, ok := m[strings.ToLower(host)]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []net.IP
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

// Only a unicast route leaves this machine. Every other route type the kernel
// can answer with is this machine: a lookup that took only `local` as this
// machine would pass broadcast, anycast and multicast destinations.
//
// MUTATION: in routeKindOfType, test `!= unix.RTN_LOCAL` instead of
// `== unix.RTN_UNICAST`.
// RESULT: red — broadcast, anycast and multicast read as leaving.
func TestOnlyAUnicastRouteLeavesThisMachine(t *testing.T) {
	if got := routeKindOfType(unix.RTN_UNICAST); got != routeLeaves {
		t.Fatalf("a unicast route leaves the machine: got kind %d", got)
	}
	for name, typ := range map[string]uint8{
		"local": unix.RTN_LOCAL, "broadcast": unix.RTN_BROADCAST, "anycast": unix.RTN_ANYCAST,
		"multicast": unix.RTN_MULTICAST, "unspec": unix.RTN_UNSPEC, "nat": unix.RTN_NAT, "xresolve": unix.RTN_XRESOLVE,
	} {
		if got := routeKindOfType(typ); got != routeThisMachine {
			t.Errorf("a %s route is this machine: got kind %d", name, got)
		}
	}
}
