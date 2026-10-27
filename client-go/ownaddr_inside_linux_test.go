//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The rule alone, over link tables written out here: which links keep a
// packet on this machine.
func TestInsideMachineReadsTheLinkAndABridgesPorts(t *testing.T) {
	links := map[uint32]linkInfo{
		1:  {kind: ""},                   // lo
		2:  {kind: ""},                   // a network card
		3:  {kind: "bridge"},             // docker0
		4:  {kind: "veth", master: 3},    // a container's link on docker0
		5:  {kind: "veth"},               // a pod's link, routed to directly (Calico)
		6:  {kind: "bridge"},             // virbr0
		7:  {kind: "dummy", master: 6},   // libvirt's placeholder port
		8:  {kind: "tun", master: 6},     // a VM's tap
		9:  {kind: "bridge"},             // br0 on a server: the LAN
		10: {kind: "", master: 9},        // its network card
		11: {kind: "veth", master: 9},    // and a container bridged onto the LAN
		12: {kind: "bridge"},             // a Docker network with no container yet
		13: {kind: "wireguard"},          // a VPN
		14: {kind: "vxlan"},              // a tunnel to other machines (flannel.1)
		15: {kind: "bridge"},             // a bridge over a VLAN of the card
		16: {kind: "vlan", master: 15},   //
		17: {kind: "bridge"},             // a bridge with a bridge as its port
		18: {kind: "bridge", master: 17}, //
		19: {kind: "tun"},                // a VPN's tun
		20: {kind: "macvlan"},            // a macvlan over the card
	}
	for oif, want := range map[uint32]bool{
		1: false, 2: false, 3: true, 4: true, 5: true, 6: true, 9: false, 12: true,
		13: false, 14: false, 15: false, 17: false, 19: false, 20: false,
		99: false, // not in the table: linkInsideMachine refuses it before asking
	} {
		if got := insideMachine(links, oif); got != want {
			t.Errorf("link %d (%q): inside this machine = %v, want %v", oif, links[oif].kind, got, want)
		}
	}
}

// A link dump's answers, written out here: the kind and master of each link,
// NLMSG_DONE ends it, and a dump that ended on an error (the status NLMSG_DONE
// carries) or was interrupted is not taken as the whole table.
//
// MUTATION: return done at NLMSG_DONE without reading its status.
// RESULT: red — a dump that stopped on EMSGSIZE, missing its later links, is
// taken as the table.
func TestReadLinkDumpReadsKindsMastersAndTheDumpsStatus(t *testing.T) {
	ne := binary.NativeEndian
	attr := func(typ uint16, val []byte) []byte {
		b := make([]byte, (unix.SizeofRtAttr+len(val)+3)&^3)
		ne.PutUint16(b[0:], uint16(unix.SizeofRtAttr+len(val)))
		ne.PutUint16(b[2:], typ)
		copy(b[unix.SizeofRtAttr:], val)
		return b
	}
	u32 := func(v uint32) []byte { b := make([]byte, 4); ne.PutUint32(b, v); return b }
	link := func(seq, idx, master uint32, kind string, flags uint16) syscall.NetlinkMessage {
		d := make([]byte, unix.SizeofIfInfomsg)
		ne.PutUint32(d[4:], idx)
		if kind != "" {
			d = append(d, attr(unix.IFLA_LINKINFO, attr(unix.IFLA_INFO_KIND, append([]byte(kind), 0)))...)
		}
		if master != 0 {
			d = append(d, attr(unix.IFLA_MASTER, u32(master))...)
		}
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWLINK, Flags: flags, Seq: seq}, Data: d}
	}
	doneWith := func(seq uint32, errno syscall.Errno) syscall.NetlinkMessage {
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE, Seq: seq}, Data: u32(uint32(-int32(errno)))}
	}

	links := map[uint32]linkInfo{}
	done, intr, err := readLinkDump([]syscall.NetlinkMessage{
		link(7, 3, 0, "bridge", 0), link(7, 4, 3, "veth", 0), link(7, 2, 0, "", 0),
		link(8, 9, 0, "bridge", 0), // another request's answer
		doneWith(7, 0),
	}, 7, links)
	if err != nil || !done || intr {
		t.Fatalf("a whole dump: done %v interrupted %v err %v", done, intr, err)
	}
	want := map[uint32]linkInfo{3: {kind: "bridge"}, 4: {kind: "veth", master: 3}, 2: {}}
	if len(links) != len(want) {
		t.Fatalf("links %v, want %v", links, want)
	}
	for i, l := range want {
		if links[i] != l {
			t.Errorf("link %d: %+v, want %+v", i, links[i], l)
		}
	}

	if done, _, err := readLinkDump([]syscall.NetlinkMessage{link(7, 3, 0, "bridge", 0), doneWith(7, unix.EMSGSIZE)},
		7, map[uint32]linkInfo{}); err == nil || done {
		t.Errorf("a dump that ended on EMSGSIZE is an error, got done %v err %v", done, err)
	}
	if _, intr, err := readLinkDump([]syscall.NetlinkMessage{link(7, 3, 0, "bridge", unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR)},
		7, map[uint32]linkInfo{}); err != nil || !intr {
		t.Errorf("an answer marked interrupted marks the dump, got %v %v", intr, err)
	}
	if done, intr, err := readLinkDump([]syscall.NetlinkMessage{link(7, 3, 0, "bridge", 0)}, 7, map[uint32]linkInfo{}); done || intr || err != nil {
		t.Errorf("a batch without NLMSG_DONE is not the end: %v %v %v", done, intr, err)
	}
	errMsg := doneWith(7, unix.EPERM)
	errMsg.Header.Type = unix.NLMSG_ERROR
	if _, _, err := readLinkDump([]syscall.NetlinkMessage{errMsg}, 7, map[uint32]linkInfo{}); !errors.Is(err, unix.EPERM) {
		t.Errorf("an NLMSG_ERROR in the dump is its error, got %v", err)
	}
}

const insideNetnsEnv = "PRIVATAE_TEST_INSIDE_NETNS"

// THE KERNEL'S OWN ANSWER FOR NETWORKS INSIDE THIS MACHINE. The local egress
// lane keeps the person's LAN, but a container or VM on a network made on
// this machine is a service on this machine, reached around its switches the
// same way loopback is. In a private user and network namespace this builds
// the networks Docker, libvirt and Calico make (a bridge whose only port is a
// veth, a bridge whose ports are a dummy and nothing else, a bridge with no
// port yet, a veth routed to directly, and the same with an IPv6 range and a
// public range), and links that leave the machine: a bridge over a VLAN,
// which stands for a bridge over the network card; a route straight over a
// dummy, which stands for the card itself; veths that carry this machine's
// main-table default routes, as a container's own veth does; and routes
// through a gateway. It asks the real rtnetlink lookup, the local egress lane
// on an unanchored box, a coder run's proxy and the backup lanes' wall.
//
// MUTATION: return routeLeaves for every unicast route (drop the link check).
// RESULT: red — every inside address passes the local lane, the public one
// passes the coder lane.
// MUTATION: count "dummy" as an outward port.
// RESULT: red — the libvirt-style bridge is the LAN.
// MUTATION: drop the main-table default-route links from the judgement.
// RESULT: red — from a machine that is itself a container, the network on its
// own veths (IPv4, a multipath default's second veth, IPv6) is this machine.
// MUTATION: skip a default route's RTA_MULTIPATH nexthops.
// RESULT: red — both veths of the multipath default are inside.
// MUTATION: count a default route in any table, not only main.
// RESULT: red — the veth whose default is in table 100 leaves.
// MUTATION: judge the out link of a route through a gateway too.
// RESULT: red — from a machine that is itself a container, the internet
// (IPv4 and IPv6) and a LAN behind a router VM are this machine, and every
// lane refuses them.
func TestNetworksInsideThisMachineAreThisMachine(t *testing.T) {
	if os.Getenv(insideNetnsEnv) != "1" {
		if _, err := exec.LookPath("ip"); err != nil {
			if _, err := os.Stat("/usr/sbin/ip"); err != nil {
				t.Skip("needs ip(8)")
			}
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestNetworksInsideThisMachineAreThisMachine$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), insideNetnsEnv+"=1")
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
			t.Skip("the namespaced run could not build its networks")
		}
		if err != nil {
			t.Fatalf("the namespaced run failed: %v", err)
		}
		if !strings.Contains(string(out), "--- PASS: TestNetworksInsideThisMachineAreThisMachine") {
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
		// Docker: a bridge whose only port is a container's veth, with an IPv6
		// range too, and a second network on a public range.
		{"link", "add", "br-ctr", "type", "bridge"},
		{"link", "add", "vh0", "type", "veth", "peer", "name", "vc0"},
		{"link", "set", "vh0", "master", "br-ctr"},
		{"addr", "add", "172.31.5.1/24", "dev", "br-ctr"},
		{"-6", "addr", "add", "2001:db8:5::1/64", "dev", "br-ctr", "nodad"},
		{"link", "add", "br-pub", "type", "bridge"},
		{"link", "add", "vh1", "type", "veth", "peer", "name", "vc1"},
		{"link", "set", "vh1", "master", "br-pub"},
		{"addr", "add", "203.0.113.1/24", "dev", "br-pub"},
		// libvirt: a bridge whose port is a dummy.
		{"link", "add", "br-vm", "type", "bridge"},
		{"link", "add", "dvm0", "type", "dummy"},
		{"link", "set", "dvm0", "master", "br-vm"},
		{"addr", "add", "192.168.122.1/24", "dev", "br-vm"},
		// A Docker network no container has joined yet.
		{"link", "add", "br-empty", "type", "bridge"},
		{"addr", "add", "172.29.0.1/24", "dev", "br-empty"},
		// Calico: a pod's veth, routed to directly (the route is added once
		// the link is up, below).
		{"link", "add", "cali0", "type", "veth", "peer", "name", "cali0p"},
		// The LAN: a bridge over a VLAN of a card, and the card itself.
		{"link", "add", "dlan0", "type", "dummy"},
		{"link", "add", "link", "dlan0", "name", "dlan0.7", "type", "vlan", "id", "7"},
		{"link", "add", "br-lan", "type", "bridge"},
		{"link", "set", "dlan0.7", "master", "br-lan"},
		{"addr", "add", "10.77.0.1/24", "dev", "br-lan"},
		// The way out through a veth: this machine is itself a container, and
		// its default routes go through its veths to a gateway, the machine it
		// runs on: IPv4 over two (a multipath default), IPv6 over a third. A
		// veth that carries a main-table default leads out of this machine, so
		// the network on it is the LAN, not inside.
		{"link", "add", "ctr0", "type", "veth", "peer", "name", "ctr0p"},
		{"addr", "add", "10.88.0.2/24", "dev", "ctr0"},
		{"link", "add", "ctr1", "type", "veth", "peer", "name", "ctr1p"},
		{"addr", "add", "10.89.0.2/24", "dev", "ctr1"},
		{"link", "add", "ctr6", "type", "veth", "peer", "name", "ctr6p"},
		{"-6", "addr", "add", "2001:db8:88::2/64", "dev", "ctr6", "nodad"},
		// A veth with a default route in another table only: still inside.
		{"link", "add", "pbr0", "type", "veth", "peer", "name", "pbr0p"},
		{"addr", "add", "10.91.0.2/24", "dev", "pbr0"},
		// A range routed through a veth with this machine's own address on it
		// as the gateway: the kernel answers it as on the link, so it is
		// inside, whatever the gateway.
		{"link", "add", "cilh", "type", "veth", "peer", "name", "ciln"},
		{"addr", "add", "10.66.0.191/32", "dev", "cilh"},
	} {
		if out, err := exec.Command(ipBin, args...).CombinedOutput(); err != nil {
			t.Skipf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	for _, l := range []string{"br-ctr", "vh0", "vc0", "br-pub", "vh1", "vc1", "br-vm", "dvm0", "br-empty",
		"cali0", "cali0p", "dlan0", "dlan0.7", "br-lan", "ctr0", "ctr0p", "ctr1", "ctr1p", "ctr6", "ctr6p",
		"pbr0", "pbr0p", "cilh", "ciln"} {
		if out, err := exec.Command(ipBin, "link", "set", l, "up").CombinedOutput(); err != nil {
			t.Skipf("ip link set %s up: %v %s", l, err, out)
		}
	}
	// The card: a link with no kind cannot be made here, so a route over the
	// VLAN's lower link stands for it. A dummy as the route's own link leaves:
	// only a bridge's ports are read for dummies.
	for _, args := range [][]string{
		{"route", "add", "172.30.9.0/24", "dev", "cali0"},
		{"route", "add", "192.168.50.0/24", "dev", "dlan0"},
		// Through a gateway on an inside link, the packet goes where that
		// gateway sends it: the internet from a container, a LAN behind a
		// router VM on a bridge of taps.
		{"route", "add", "default", "nexthop", "via", "10.88.0.1", "dev", "ctr0", "nexthop", "via", "10.89.0.1", "dev", "ctr1"},
		{"-6", "route", "add", "default", "via", "2001:db8:88::1", "dev", "ctr6"},
		{"route", "add", "default", "via", "10.91.0.1", "dev", "pbr0", "table", "100"},
		{"route", "add", "192.168.60.0/24", "via", "192.168.122.254", "dev", "br-vm"},
		{"route", "add", "10.66.0.0/24", "via", "10.66.0.191", "dev", "cilh"},
	} {
		if out, err := exec.Command(ipBin, args...).CombinedOutput(); err != nil {
			t.Skipf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	ownAddrReset()

	inside := []string{"172.31.5.9", "2001:db8:5::9", "203.0.113.9", "192.168.122.9", "172.29.0.9", "172.30.9.9",
		"10.66.0.9", "10.91.0.9"}
	leaves := []string{"10.77.0.9", "192.168.50.9", "198.51.100.9", "2001:db8:ff::9", "192.168.60.9",
		"10.88.0.9", "10.89.0.9", "2001:db8:88::9"}
	for _, a := range inside {
		if got, err := ownRouteLookup(net.ParseIP(a)); err != nil || got != routeThisMachine {
			t.Errorf("route lookup %s: got kind %d err %v, want this machine", a, got, err)
		}
	}
	for _, a := range leaves {
		if got, err := ownRouteLookup(net.ParseIP(a)); err != nil || got != routeLeaves {
			t.Errorf("route lookup %s: got kind %d err %v, want leaves", a, got, err)
		}
	}

	// The local egress lane on an unanchored box: an inside address, by address
	// and by name, is refused as this machine; the LAN is refused as the network
	// around it; the public internet passes.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if currentAnchor() != nil || boxMode() != modeLocal {
		t.Fatal("the namespaced run must be a local, unanchored box")
	}
	names := map[string][]string{"db.example.test": {"172.31.5.9"}, "vm.example.test": {"192.168.122.9"},
		"nas.example.test": {"10.77.0.9"}}
	stubEgressResolve(t, names)
	ctx := context.Background()
	for _, hp := range []string{"172.31.5.9:5432", "[2001:db8:5::9]:5432", "203.0.113.9:443", "192.168.122.9:22",
		"172.29.0.9:80", "172.30.9.9:8080", "10.66.0.9:80", "10.91.0.9:80", "db.example.test:5432", "vm.example.test:22"} {
		if got, why := egressVettedAddrs(ctx, hp); !strings.Contains(why, "that is this machine") {
			t.Errorf("local egress: %s is on a network inside this machine and must be refused as this machine, got %v %q", hp, got, why)
		}
	}
	for _, hp := range []string{"10.77.0.9:445", "192.168.50.9:631", "nas.example.test:445", "192.168.60.9:445",
		"10.88.0.9:80", "10.89.0.9:80"} {
		if got, why := egressVettedAddrs(ctx, hp); !strings.Contains(why, "approved lanes") {
			t.Errorf("local egress: %s is the LAN and must be refused as the network around this machine, got %v %q", hp, got, why)
		}
	}
	for hp, want := range map[string]string{"198.51.100.9:443": "198.51.100.9:443",
		"[2001:db8:ff::9]:443": "[2001:db8:ff::9]:443", "[2001:db8:88::9]:80": "[2001:db8:88::9]:80"} {
		if got, why := egressVettedAddrs(ctx, hp); why != "" || len(got) != 1 || got[0] != want {
			t.Errorf("local egress: %s leaves this machine for the internet and passes as %s: %v %q", hp, want, got, why)
		}
	}
	// A coder run's proxy refuses the public range on an inside network too
	// (its private ranges it refuses by class already).
	if got, why := coderVettedAddr(ctx, "203.0.113.9:443", nil); !strings.Contains(why, "never this machine") {
		t.Errorf("coder run: 203.0.113.9 is on a network inside this machine, got dial %q, %q", got, why)
	}
	// From a machine that is itself a container, the internet is through its
	// veth: a coder run's proxy and the backup lanes still reach it.
	if got, why := coderVettedAddr(ctx, "198.51.100.9:443", nil); why != "" || got != "198.51.100.9:443" {
		t.Errorf("coder run: 198.51.100.9 is through the gateway and passes, got dial %q, %q", got, why)
	}
	if !backupAddrAllowed(net.ParseIP("2001:db8:ff::9")) || !backupAddrAllowed(net.ParseIP("198.51.100.9")) {
		t.Error("backup: an address through the gateway leaves this machine and is allowed")
	}
}
