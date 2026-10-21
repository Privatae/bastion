//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"

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
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return 0, fmt.Errorf("route lookup: %w", err)
	}
	defer unix.Close(fd)
	tv := unix.Timeval{Sec: 2}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return 0, fmt.Errorf("route lookup: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("route lookup: %w", err)
	}

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
				return routeKindOfType(m.Data[7]), nil // rtm_type
			}
		}
	}
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
