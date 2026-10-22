//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func init() { ownRouteLookup = netlinkRouteKind }

var netlinkRouteSeq atomic.Uint32

// netlinkRouteKind asks the kernel, over rtnetlink, how it routes a packet to
// ip: one RTM_GETROUTE request carrying RTA_DST, the lookup `ip route get`
// makes. The answer's rtm_type is the route type the kernel would use for a
// connection from this process (same uid, no mark, no bound device, which is
// how the egress dialers dial).
//
// A unicast route straight onto a link that stays inside this machine, with
// no gateway, is this machine too (insideMachine): a container's or VM's
// address on a bridge network Docker, Podman, LXD or libvirt made here
// reaches a service on this machine. A route through a gateway leaves, and
// so does one out of a link a main-table default route goes out of.
//
// No route at all (ENETUNREACH, EHOSTUNREACH, or EACCES from a prohibit
// route) is routeNowhere: the kernel delivers such a packet nowhere, locally
// included, and the dial fails on its own. So does an IPv6 lookup on a kernel
// with no IPv6 stack (EAFNOSUPPORT, EOPNOTSUPP): nothing there is local over
// IPv6. Every other failure is an error, and the caller refuses.
func netlinkRouteKind(ip net.IP) (routeKind, error) {
	family, addr := unix.AF_INET6, ip.To16()
	if v4 := ip.To4(); v4 != nil {
		family, addr = unix.AF_INET, v4
	}
	if addr == nil {
		return 0, errors.New("not an IP address")
	}
	fd, err := netlinkSocket()
	if err != nil {
		return 0, fmt.Errorf("route lookup: %w", err)
	}
	defer unix.Close(fd)

	// nlmsghdr | rtmsg | rtattr(RTA_DST) + address, each 4-byte aligned.
	attrLen := unix.SizeofRtAttr + len(addr)
	total := unix.SizeofNlMsghdr + unix.SizeofRtMsg + (attrLen+3)&^3
	req := make([]byte, total)
	ne := binary.NativeEndian
	seq := netlinkRouteSeq.Add(1)
	ne.PutUint32(req[0:], uint32(total))
	ne.PutUint16(req[4:], unix.RTM_GETROUTE)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST)
	ne.PutUint32(req[8:], seq)
	ne.PutUint32(req[12:], 0)
	rt := req[unix.SizeofNlMsghdr:]
	rt[0] = byte(family)        // rtm_family
	rt[1] = byte(len(addr) * 8) // rtm_dst_len: the whole address
	a := rt[unix.SizeofRtMsg:]
	ne.PutUint16(a[0:], uint16(attrLen))
	ne.PutUint16(a[2:], unix.RTA_DST)
	copy(a[unix.SizeofRtAttr:], addr)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("route lookup: %w", err)
	}

	buf := make([]byte, 8192)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("route lookup: %w", err)
		}
		if sa, ok := from.(*unix.SockaddrNetlink); !ok || sa.Pid != 0 {
			continue // only the kernel answers this
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return 0, fmt.Errorf("route lookup: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return 0, errors.New("route lookup: short error message")
				}
				errno := unix.Errno(-int32(ne.Uint32(m.Data[0:4])))
				switch {
				case errno == 0:
					return 0, errors.New("route lookup: acknowledged with no route")
				case errno == unix.ENETUNREACH || errno == unix.EHOSTUNREACH || errno == unix.EACCES:
					return routeNowhere, nil
				case family == unix.AF_INET6 && (errno == unix.EAFNOSUPPORT || errno == unix.EOPNOTSUPP):
					return routeNowhere, nil
				}
				return 0, fmt.Errorf("route lookup: %w", errno)
			case unix.RTM_NEWROUTE:
				if len(m.Data) < unix.SizeofRtMsg {
					return 0, errors.New("route lookup: short route message")
				}
				kind := routeKindOfType(m.Data[7]) // rtm_type
				if kind != routeLeaves {
					return kind, nil
				}
				oif, gw, err := routeOutLink(&m)
				if err != nil {
					return 0, fmt.Errorf("route lookup: %w", err)
				}
				if oif == 0 {
					return routeLeaves, nil // no single link named (a multipath route)
				}
				if gw {
					// Handed to a gateway, the packet goes where that machine
					// sends it on: the internet, from the machine a container
					// runs on; the LAN behind a router VM. The destination is
					// not on the out link, so the link says nothing about it.
					return routeLeaves, nil
				}
				inside, err := linkInsideMachine(oif)
				if err != nil {
					return 0, fmt.Errorf("route lookup: %w", err)
				}
				if inside {
					return routeThisMachine, nil
				}
				return routeLeaves, nil
			}
		}
	}
}

// netlinkSocket opens an rtnetlink socket that gives up on a reply after 2 s.
func netlinkSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	tv := unix.Timeval{Sec: 2}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// routeOutLink reads the link a route answer sends the packet out of
// (RTA_OIF), 0 when the answer names none, and whether the answer hands the
// packet to a gateway (RTA_GATEWAY, or RTA_VIA for a gateway of the other
// family) rather than to the destination on the link itself. The kernel
// answers a route whose gateway is one of this machine's own addresses as on
// the link, with no gateway, so the link decides there.
func routeOutLink(m *syscall.NetlinkMessage) (oif uint32, gw bool, err error) {
	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return 0, false, err
	}
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.RTA_OIF:
			if len(a.Value) < 4 {
				return 0, false, errors.New("short output link attribute")
			}
			oif = binary.NativeEndian.Uint32(a.Value)
		case unix.RTA_GATEWAY, unix.RTA_VIA:
			gw = true
		}
	}
	return oif, gw, nil
}

// linkInfo is what insideMachine reads of a link.
type linkInfo struct {
	kind   string // IFLA_INFO_KIND ("veth", "bridge", "tun", "vlan", ...); "" for a network card or loopback
	master uint32 // IFLA_MASTER: the bridge or bond it is a port of; 0 for none
}

// innerPortKinds are the bridge ports that keep a bridge inside this machine:
// a veth (a container's link), a tun (the kernel kind of a tap, a VM's network
// card) and a dummy (libvirt's placeholder port).
var innerPortKinds = map[string]bool{"veth": true, "tun": true, "dummy": true}

// insideMachine reports whether a packet sent out of link oif stays on this
// machine: oif is a veth, whose other end is a container's network namespace
// here, or a bridge whose every port is an inner port, which is the network
// Docker, Podman, LXD and libvirt each make for their containers and VMs (a
// bridge with no port yet included). A bridge with any other port (a network
// card, a bond, a VLAN) is the person's LAN, and every other link leaves this
// machine: a network card, a VPN (wireguard, tun), a tunnel to other machines
// (vxlan, ipip).
func insideMachine(links map[uint32]linkInfo, oif uint32) bool {
	switch links[oif].kind {
	case "veth":
		return true
	case "bridge":
		for idx, l := range links {
			if idx != oif && l.master == oif && !innerPortKinds[l.kind] {
				return false
			}
		}
		return true
	}
	return false
}

// The link table and the links a default route goes out of, re-read
// together at most every ownAddrTTL, as the interface addresses are. A link
// missing from a cached table (a network made since) reads both again; one
// missing from a fresh table cannot be judged. A failed read of either is an
// error, and the caller refuses.
var linkCache struct {
	mu     sync.Mutex
	at     time.Time
	links  map[uint32]linkInfo
	wayOut map[uint32]bool
}

// linkInsideMachine: insideMachine for oif, unless a main-table default route
// goes out of oif. Such a link is this machine's way out to the world, not a
// network inside it: a bastion that is itself in a container reaches its LAN
// (or the machine it runs on and its other containers) over its own veth,
// and a host whose default route goes through a router VM reaches that VM
// over the bridge of taps it shares with it.
func linkInsideMachine(oif uint32) (bool, error) {
	linkCache.mu.Lock()
	defer linkCache.mu.Unlock()
	fresh := linkCache.at.IsZero() || time.Since(linkCache.at) >= ownAddrTTL
	if !fresh {
		if _, ok := linkCache.links[oif]; !ok {
			fresh = true
		}
	}
	if fresh {
		links, err := dumpLinks()
		if err != nil {
			return false, err
		}
		wayOut, err := dumpDefaultRouteLinks()
		if err != nil {
			return false, err
		}
		linkCache.links, linkCache.wayOut, linkCache.at = links, wayOut, time.Now()
	}
	if _, ok := linkCache.links[oif]; !ok {
		return false, fmt.Errorf("link %d is not in the link table", oif)
	}
	if linkCache.wayOut[oif] {
		return false, nil
	}
	return insideMachine(linkCache.links, oif), nil
}

// dumpLinks lists every link with its kind and master (RTM_GETLINK, the dump
// `ip -d link` reads).
func dumpLinks() (map[uint32]linkInfo, error) {
	var links map[uint32]linkInfo
	err := dumpRetried("link dump", unix.RTM_GETLINK, unix.SizeofIfInfomsg, func() func(*syscall.NetlinkMessage) error {
		links = map[uint32]linkInfo{}
		return func(m *syscall.NetlinkMessage) error { return addLink(links, m) }
	})
	if err != nil {
		return nil, err
	}
	return links, nil
}

// dumpDefaultRouteLinks lists the links an IPv4 (0.0.0.0/0) or IPv6 (::/0)
// unicast default route in the main table goes out of, every nexthop's link
// of a multipath default included. One RTM_GETROUTE dump of family AF_UNSPEC
// answers both families (rtnetlink dumps each family's routes for it), one
// round trip where two per-family dumps would be two. No single-address
// lookup can stand in: RTM_GETROUTE without a dump answers for a destination,
// never for a route, and the destination 0.0.0.0 is answered as this machine.
func dumpDefaultRouteLinks() (map[uint32]bool, error) {
	var out map[uint32]bool
	err := dumpRetried("route dump", unix.RTM_GETROUTE, unix.SizeofRtMsg, func() func(*syscall.NetlinkMessage) error {
		out = map[uint32]bool{}
		return func(m *syscall.NetlinkMessage) error { return addDefaultRouteLinks(out, m) }
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// dumpRetried takes a dump (netlinkDump), and takes it again from the start
// when the kernel marks it interrupted (the table changed while it ran), up
// to three times; start gives each attempt an empty table to fill.
func dumpRetried(what string, msgType uint16, hdrLen int, start func() func(*syscall.NetlinkMessage) error) error {
	for try := 0; ; try++ {
		interrupted, err := netlinkDump(msgType, hdrLen, start())
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if !interrupted || try == 2 {
			return nil
		}
	}
}

// netlinkDump sends one dump request of msgType, its family header hdrLen
// bytes of zero (every family, everything), and hands each answer to add.
func netlinkDump(msgType uint16, hdrLen int, add func(*syscall.NetlinkMessage) error) (bool, error) {
	fd, err := netlinkSocket()
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	total := unix.SizeofNlMsghdr + hdrLen
	req := make([]byte, total)
	ne := binary.NativeEndian
	seq := netlinkRouteSeq.Add(1)
	ne.PutUint32(req[0:], uint32(total))
	ne.PutUint16(req[4:], msgType)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], seq)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, err
	}
	interrupted := false
	buf := make([]byte, 65536)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}
		if sa, ok := from.(*unix.SockaddrNetlink); !ok || sa.Pid != 0 {
			continue
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return false, err
		}
		done, intr, err := readDump(msgs, seq, add)
		if err != nil {
			return false, err
		}
		interrupted = interrupted || intr
		if done {
			return interrupted, nil
		}
	}
}

// readDump hands one batch of a dump's answers to add: done at NLMSG_DONE,
// interrupted when the kernel marks an answer NLM_F_DUMP_INTR. NLMSG_DONE
// carries the dump's own status, and a dump that stopped on an error (one the
// kernel could not fit, say) ends with that error in it and the answers after
// it missing, so it is an error here, as an NLMSG_ERROR is.
func readDump(msgs []syscall.NetlinkMessage, seq uint32, add func(*syscall.NetlinkMessage) error) (done, interrupted bool, err error) {
	ne := binary.NativeEndian
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Seq != seq {
			continue
		}
		if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
			interrupted = true
		}
		switch m.Header.Type {
		case unix.NLMSG_DONE:
			if len(m.Data) >= 4 {
				if errno := unix.Errno(-int32(ne.Uint32(m.Data[0:4]))); errno != 0 {
					return false, false, errno
				}
			}
			return true, interrupted, nil
		case unix.NLMSG_ERROR:
			if len(m.Data) >= 4 {
				if errno := unix.Errno(-int32(ne.Uint32(m.Data[0:4]))); errno != 0 {
					return false, false, errno
				}
			}
			return false, false, errors.New("ended with no answer")
		default:
			if err := add(m); err != nil {
				return false, false, err
			}
		}
	}
	return false, interrupted, nil
}

// readLinkDump is readDump for a link dump, into links.
func readLinkDump(msgs []syscall.NetlinkMessage, seq uint32, links map[uint32]linkInfo) (done, interrupted bool, err error) {
	return readDump(msgs, seq, func(m *syscall.NetlinkMessage) error { return addLink(links, m) })
}

// addLink reads a link's index, kind and master into links.
func addLink(links map[uint32]linkInfo, m *syscall.NetlinkMessage) error {
	if m.Header.Type != unix.RTM_NEWLINK {
		return nil
	}
	if len(m.Data) < unix.SizeofIfInfomsg {
		return errors.New("short link message")
	}
	ne := binary.NativeEndian
	idx := ne.Uint32(m.Data[4:8]) // ifi_index
	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return err
	}
	var li linkInfo
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.IFLA_MASTER:
			if len(a.Value) >= 4 {
				li.master = ne.Uint32(a.Value)
			}
		case unix.IFLA_LINKINFO:
			li.kind = linkInfoKind(a.Value)
		}
	}
	links[idx] = li
	return nil
}

// addDefaultRouteLinks adds to out the links an IPv4 or IPv6 unicast default
// route of the main table goes out of: its RTA_OIF, and each nexthop's link
// in its RTA_MULTIPATH. Every other route is passed over.
func addDefaultRouteLinks(out map[uint32]bool, m *syscall.NetlinkMessage) error {
	if m.Header.Type != unix.RTM_NEWROUTE {
		return nil
	}
	if len(m.Data) < unix.SizeofRtMsg {
		return errors.New("short route message")
	}
	family, dstLen, table, rtype := m.Data[0], m.Data[1], uint32(m.Data[4]), m.Data[7]
	if (family != unix.AF_INET && family != unix.AF_INET6) || dstLen != 0 || rtype != unix.RTN_UNICAST {
		return nil
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return err
	}
	ne := binary.NativeEndian
	var links []uint32
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.RTA_TABLE: // the table's id when it does not fit rtm_table
			if len(a.Value) >= 4 {
				table = ne.Uint32(a.Value)
			}
		case unix.RTA_OIF:
			if len(a.Value) >= 4 {
				links = append(links, ne.Uint32(a.Value))
			}
		case unix.RTA_MULTIPATH: // struct rtnexthop, each followed by its own attributes
			for b := a.Value; len(b) >= unix.SizeofRtNexthop; {
				l := int(ne.Uint16(b[0:2]))
				if l < unix.SizeofRtNexthop || l > len(b) {
					return errors.New("bad multipath nexthop")
				}
				links = append(links, ne.Uint32(b[4:8])) // rtnh_ifindex
				next := (l + 3) &^ 3
				if next >= len(b) {
					break
				}
				b = b[next:]
			}
		}
	}
	if table != unix.RT_TABLE_MAIN {
		return nil
	}
	for _, l := range links {
		if l != 0 {
			out[l] = true
		}
	}
	return nil
}

// linkInfoKind reads IFLA_INFO_KIND out of a nested IFLA_LINKINFO.
func linkInfoKind(b []byte) string {
	ne := binary.NativeEndian
	for len(b) >= unix.SizeofRtAttr {
		l := int(ne.Uint16(b[0:2]))
		if l < unix.SizeofRtAttr || l > len(b) {
			return ""
		}
		if ne.Uint16(b[2:4]) == unix.IFLA_INFO_KIND {
			return strings.TrimRight(string(b[unix.SizeofRtAttr:l]), "\x00")
		}
		next := (l + 3) &^ 3
		if next > len(b) {
			return ""
		}
		b = b[next:]
	}
	return ""
}

// routeKindOfType reads a route's rtm_type: only a unicast route leaves this
// machine. Local, broadcast, anycast, multicast and every other type are
// delivered here or cannot be told apart from it, so they are this machine.
func routeKindOfType(rtmType uint8) routeKind {
	if rtmType == unix.RTN_UNICAST {
		return routeLeaves
	}
	return routeThisMachine
}
