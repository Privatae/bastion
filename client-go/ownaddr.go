package main

// ownaddr.go — is a destination THIS machine?
//
// The outbound lanes that dial for someone else (the egress lane,
// egress.go; a coder run's proxy, coder_egress.go; the backup
// lanes' fetch and push, backupfetch.go) must never be turned back on the
// machine itself: a service listening on 0.0.0.0 here
// answers on every address the kernel delivers locally, not only on loopback
// and the private ranges internalIP refuses.
//
// Two checks, and a destination either one names is this machine:
//
//   - the addresses on this machine's interfaces (net.InterfaceAddrs), which
//     catches a public address on a NIC (a VPS, a server with its own IP);
//   - on Linux, the kernel's own routing decision for the address
//     (RTM_GETROUTE, the lookup `ip route get` makes; ownaddr_linux.go). An
//     address the kernel delivers locally need not be on any interface: a
//     `local` route (`ip route add local 192.0.2.0/24 dev lo`, AnyIP) makes a
//     whole range this machine. Only a route of type unicast leaves the
//     machine; local, broadcast, anycast and multicast routes are refused.
//     A destination on a link that stays on this machine is refused too: a
//     container's veth, or a bridge whose every port is a veth, a tap or a
//     dummy (the bridge networks Docker, Podman, LXD and libvirt make here).
//     A container or VM on one of them is a service on this machine. A route
//     through a gateway on such a link leaves: the gateway sends the packet
//     on, as the machine a container runs on does for the container. A link
//     a main-table default route goes out of is never inside: it is this
//     machine's way out, so a bastion in a container keeps the network on
//     its own veth, its LAN included.
//
// The IPv4 address inside an IPv4-mapped, NAT64 (64:ff9b::/96) or 6to4
// (2002::/16) address is checked as well, since that is what such an address
// reaches. Anything that cannot be decided refuses.
//
// What neither check sees: a public address that reaches this machine only
// through a 1:1 NAT in front of it (a cloud's elastic or floating IP that is
// on no interface and in no local route). The bastion does not learn its own
// public address from anywhere, so a run that names that address is dialled
// out to the NAT, which hairpins it back if the provider allows hairpinning.

import (
	"net"
	"sync"
	"time"
)

// ownInterfaceAddrs lists the addresses on this machine's interfaces. A seam
// so a test can put a public address on a NIC.
var ownInterfaceAddrs = net.InterfaceAddrs

// routeKind is what the kernel does with a packet to an address.
type routeKind int

const (
	routeLeaves      routeKind = iota // a unicast route: the packet leaves this machine
	routeThisMachine                  // local, broadcast, anycast, multicast or any other non-unicast type
	routeNowhere                      // no route at all (unreachable, prohibited): the dial cannot be made
)

// ownRouteLookup asks the kernel how it routes ip. Set by ownaddr_linux.go;
// nil where no lookup is built, and then only the interface check applies.
// A seam so a test can supply the kernel's answer.
var ownRouteLookup func(ip net.IP) (routeKind, error)

// The interface addresses, re-read at most every ownAddrTTL so an address
// added or changed (DHCP, a new interface) is seen within seconds without
// listing interfaces on every connection. A failed read is never cached.
var ownAddrTTL = 2 * time.Second

var ownAddrCache struct {
	mu  sync.Mutex
	at  time.Time
	ips []net.IP
}

func ownInterfaceIPs() ([]net.IP, error) {
	ownAddrCache.mu.Lock()
	defer ownAddrCache.mu.Unlock()
	if !ownAddrCache.at.IsZero() && time.Since(ownAddrCache.at) < ownAddrTTL {
		return ownAddrCache.ips, nil
	}
	addrs, err := ownInterfaceAddrs()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ips = append(ips, v.IP)
		case *net.IPAddr:
			ips = append(ips, v.IP)
		}
	}
	ownAddrCache.ips, ownAddrCache.at = ips, time.Now()
	return ips, nil
}

// ownAddrReset drops the cached interface addresses (tests swap the seam).
func ownAddrReset() {
	ownAddrCache.mu.Lock()
	ownAddrCache.at, ownAddrCache.ips = time.Time{}, nil
	ownAddrCache.mu.Unlock()
}

// ownAddrForms: ip, plus the IPv4 address a NAT64 or 6to4 address carries.
// An IPv4-mapped address needs no extra form: To4 already reads it as IPv4,
// for the comparison (net.IP.Equal) and for the route lookup alike.
func ownAddrForms(ip net.IP) []net.IP {
	forms := []net.IP{ip}
	if ip.To4() == nil && len(ip) == net.IPv6len {
		if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
			ip[4]|ip[5]|ip[6]|ip[7]|ip[8]|ip[9]|ip[10]|ip[11] == 0 {
			forms = append(forms, net.IPv4(ip[12], ip[13], ip[14], ip[15]))
		}
		if ip[0] == 0x20 && ip[1] == 0x02 {
			forms = append(forms, net.IPv4(ip[2], ip[3], ip[4], ip[5]))
		}
	}
	return forms
}

// ownDestination reports whether any of addrs is this machine. An error means
// it could not tell (the interfaces could not be read, or the kernel's route
// lookup failed), and every caller refuses on it.
func ownDestination(addrs []net.IP) (bool, error) {
	local, err := ownInterfaceIPs()
	if err != nil {
		return false, err
	}
	for _, ip := range addrs {
		forms := ownAddrForms(ip)
		for _, f := range forms {
			for _, l := range local {
				if f.Equal(l) {
					return true, nil
				}
			}
		}
		if ownRouteLookup == nil {
			continue
		}
		for _, f := range forms {
			kind, err := ownRouteLookup(f)
			if err != nil {
				return false, err
			}
			if kind == routeThisMachine {
				return true, nil
			}
		}
	}
	return false, nil
}
