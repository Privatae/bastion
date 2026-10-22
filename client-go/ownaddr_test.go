//go:build !windows

// Tagged !windows: the anchored-lane test borrows setupBox (anchor_test.go).

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// stubOwnAddrs fixes what this machine takes as its own for one test: these
// interface addresses, and the kernel's route answer from route (nil: no
// route lookup, the interface check alone, as on a platform without one).
// It records every address the route lookup was asked about.
func stubOwnAddrs(t *testing.T, ifaces []string, route func(net.IP) (routeKind, error)) *[]string {
	t.Helper()
	oldIf, oldRoute := ownInterfaceAddrs, ownRouteLookup
	t.Cleanup(func() { ownInterfaceAddrs, ownRouteLookup = oldIf, oldRoute; ownAddrReset() })
	ownInterfaceAddrs = func() ([]net.Addr, error) {
		var out []net.Addr
		for _, a := range ifaces {
			ip, n, err := net.ParseCIDR(a)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, &net.IPNet{IP: ip, Mask: n.Mask})
		}
		return out, nil
	}
	asked := &[]string{}
	if route != nil {
		ownRouteLookup = func(ip net.IP) (routeKind, error) {
			*asked = append(*asked, ip.String())
			return route(ip)
		}
	} else {
		ownRouteLookup = nil
	}
	ownAddrReset()
	return asked
}

// localRange is a kernel with `ip route add local <cidr> dev lo` for each
// cidr (AnyIP): those addresses are delivered here although no interface
// holds them; everything else leaves by a unicast route.
func localRange(cidrs ...string) func(net.IP) (routeKind, error) {
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	return func(ip net.IP) (routeKind, error) {
		for _, n := range nets {
			if n.Contains(ip) {
				return routeThisMachine, nil
			}
		}
		return routeLeaves, nil
	}
}

var loopbackOnly = []string{"127.0.0.1/8", "::1/128"}

// The kernel's answer decides, for the address and for the IPv4 address an
// IPv4-mapped, NAT64 or 6to4 address carries; no route and a unicast route
// are not this machine, and a lookup that fails is an error.
//
// MUTATION: skip the route lookup in ownDestination.
// RESULT: red — every address below is reported as not this machine.
func TestOwnDestinationAsksTheKernel(t *testing.T) {
	asked := stubOwnAddrs(t, loopbackOnly, localRange("203.0.113.0/24", "2001:db8:a::/64"))
	for _, s := range []string{"203.0.113.5", "::ffff:203.0.113.5", "64:ff9b::cb00:7105",
		"2002:cb00:7105::1", "2001:db8:a::5"} {
		own, err := ownDestination([]net.IP{net.ParseIP("93.184.216.34"), net.ParseIP(s)})
		if err != nil || !own {
			t.Errorf("%s is delivered to this machine: own=%v err=%v", s, own, err)
		}
	}
	if own, err := ownDestination([]net.IP{net.ParseIP("198.51.100.9")}); err != nil || own {
		t.Fatalf("a unicast route leaves the machine: own=%v err=%v", own, err)
	}
	// The NAT64 form was asked about as the IPv4 address it carries.
	found := false
	for _, a := range *asked {
		found = found || a == "203.0.113.5"
	}
	if !found {
		t.Fatalf("the embedded IPv4 address was never looked up: %v", *asked)
	}

	stubOwnAddrs(t, loopbackOnly, func(net.IP) (routeKind, error) { return routeNowhere, nil })
	if own, err := ownDestination([]net.IP{net.ParseIP("198.51.100.9")}); err != nil || own {
		t.Fatalf("no route is not this machine: own=%v err=%v", own, err)
	}
	stubOwnAddrs(t, loopbackOnly, func(net.IP) (routeKind, error) { return 0, errors.New("netlink: no buffer space") })
	if _, err := ownDestination([]net.IP{net.ParseIP("198.51.100.9")}); err == nil {
		t.Fatal("a failed route lookup cannot decide")
	}
	// Without a route lookup (other platforms) the interfaces still decide.
	stubOwnAddrs(t, []string{"127.0.0.1/8", "198.51.100.7/24"}, nil)
	if own, _ := ownDestination([]net.IP{net.ParseIP("::ffff:198.51.100.7")}); !own {
		t.Fatal("an interface address is this machine without a route lookup")
	}
}

// A coder run cannot reach an address the kernel delivers here through a
// `local` route, by any spelling; a failed lookup refuses; allow_lan is still
// the one exception.
//
// MUTATION: skip the route lookup in ownDestination.
// RESULT: red — the AnyIP destinations are vetted and dialled.
func TestCoderEgressRefusesAnAddressTheKernelDeliversHere(t *testing.T) {
	stubOwnAddrs(t, loopbackOnly, localRange("203.0.113.0/24", "2001:db8:a::/64"))
	ctx := context.Background()
	for _, hp := range []string{"203.0.113.5:80", "[::ffff:203.0.113.5]:80", "[64:ff9b::cb00:7105]:80",
		"[2002:cb00:7105::1]:80", "[2001:db8:a::5]:22"} {
		if got, why := coderVettedAddr(ctx, hp, nil); why == "" {
			t.Errorf("%s is this machine and must be refused, got dial %s", hp, got)
		}
	}
	if got, why := coderVettedAddr(ctx, "198.51.100.9:443", nil); why != "" || got != "198.51.100.9:443" {
		t.Fatalf("an address that leaves the machine passes: %q %q", got, why)
	}
	if got, why := coderVettedAddr(ctx, "203.0.113.5:80", []string{"203.0.113.5"}); why != "" || got != "203.0.113.5:80" {
		t.Fatalf("allow_lan stays the one exception: %q %q", got, why)
	}
	stubOwnAddrs(t, loopbackOnly, func(net.IP) (routeKind, error) { return 0, errors.New("netlink: denied") })
	if _, why := coderVettedAddr(ctx, "198.51.100.9:443", nil); why == "" {
		t.Fatal("a failed route lookup refuses")
	}
}

// The anchored egress lane refuses this machine too: an address on its NIC
// and an address a `local` route delivers here, in every spelling, and a
// failed lookup. A neighbour passes, and a local box refuses this machine too.
//
// MUTATION: drop the ownDestination check from egressVettedAddr.
// RESULT: red — the machine's own addresses are vetted and dialled.
func TestAnchoredEgressRefusesThisMachinesOwnAddresses(t *testing.T) {
	setupBox(t)
	stubOwnAddrs(t, []string{"127.0.0.1/8", "198.51.100.7/24"}, localRange("203.0.113.0/24"))
	ctx := context.Background()
	for _, hp := range []string{"198.51.100.7:8080", "[::ffff:198.51.100.7]:8080", "203.0.113.5:80",
		"[::ffff:203.0.113.5]:80", "[64:ff9b::cb00:7105]:80", "[2002:c633:6407::1]:22"} {
		addr, why := egressVettedAddr(ctx, hp)
		if why == "" || addr != "" {
			t.Errorf("%s is this machine and must be refused on an anchored box, got %q", hp, addr)
		} else if !strings.Contains(why, "this machine") {
			t.Errorf("%s: the refusal names why: %q", hp, why)
		}
	}
	if addr, why := egressVettedAddr(ctx, "198.51.100.8:443"); why != "" || addr != "198.51.100.8:443" {
		t.Fatalf("a neighbour on the subnet is the internet: %q %q", addr, why)
	}
	stubOwnAddrs(t, loopbackOnly, func(net.IP) (routeKind, error) { return 0, errors.New("netlink: denied") })
	if _, why := egressVettedAddr(ctx, "198.51.100.8:443"); why == "" {
		t.Fatal("a failed route lookup refuses on an anchored box")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubOwnAddrs(t, []string{"127.0.0.1/8", "198.51.100.7/24"}, localRange("203.0.113.0/24"))
	for _, hp := range []string{"198.51.100.7:8080", "203.0.113.5:80"} {
		if addr, why := egressVettedAddr(ctx, hp); why == "" || addr != "" {
			t.Errorf("%s is this machine and must be refused on a local box too, got %q", hp, addr)
		}
	}
}

// The backup lanes (backup_fetch, backup_push) refuse this machine too: at
// the URL check, for an address and for a name, and at the dial. An address
// on this machine's NIC and one a `local` route delivers here are refused in
// every spelling, and a failed lookup refuses; a neighbour passes.
//
// MUTATION: drop the ownDestination check from backupAddrAllowed (isPublicIP
// alone, as before 0.50.0).
// RESULT: red — the machine's own public addresses pass both walls.
func TestBackupLanesRefuseThisMachinesOwnAddresses(t *testing.T) {
	stubOwnAddrs(t, []string{"127.0.0.1/8", "198.51.100.7/24"}, localRange("203.0.113.0/24"))
	prev := backupLookupIP
	t.Cleanup(func() { backupLookupIP = prev })
	backupLookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "nic.example":
			return []net.IP{net.ParseIP("198.51.100.7")}, nil
		case "anyip.example":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("203.0.113.5")}, nil
		case "neighbour.example":
			return []net.IP{net.ParseIP("198.51.100.8")}, nil
		}
		if ip := net.ParseIP(host); ip != nil {
			return []net.IP{ip}, nil
		}
		return nil, errors.New("no such host")
	}
	for _, h := range []string{"198.51.100.7", "[::ffff:198.51.100.7]", "203.0.113.5", "[::ffff:203.0.113.5]",
		"[64:ff9b::cb00:7105]", "[2002:c633:6407::1]", "nic.example", "anyip.example"} {
		err := validateBackupURL("https://" + h + "/b.tar")
		if err == nil {
			t.Errorf("backup: %s is this machine and must be refused", h)
		} else if !strings.Contains(err.Error(), "on this machine") {
			t.Errorf("backup: %s: the refusal names why: %v", h, err)
		}
	}
	for _, a := range []string{"198.51.100.7", "::ffff:198.51.100.7", "203.0.113.5", "64:ff9b::cb00:7105"} {
		if backupDialAllowed(net.ParseIP(a)) {
			t.Errorf("backup: the dial to %s is this machine and must be refused", a)
		}
	}
	if err := validateBackupURL("https://neighbour.example/b.tar"); err != nil {
		t.Fatalf("a neighbour on the subnet is the internet: %v", err)
	}
	if !backupDialAllowed(net.ParseIP("198.51.100.8")) {
		t.Fatal("the dial to a neighbour on the subnet passes")
	}
	stubOwnAddrs(t, loopbackOnly, func(net.IP) (routeKind, error) { return 0, errors.New("netlink: denied") })
	if err := validateBackupURL("https://198.51.100.8/b.tar"); err == nil {
		t.Fatal("a failed route lookup refuses the URL")
	}
	if backupDialAllowed(net.ParseIP("198.51.100.8")) {
		t.Fatal("a failed route lookup refuses the dial")
	}
}
