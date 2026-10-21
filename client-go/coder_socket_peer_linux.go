//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"syscall"
	"time"
)

// coderLaneProbeTimeout bounds the lane handshake one run socket connection
// waits on. The lane door is on this machine and answers in milliseconds.
const coderLaneProbeTimeout = 3 * time.Second

// coderPeerRefusal is the run socket's second wall: WHO connected. A run
// socket is served to the group every Host on this machine is in, so the
// pairing check alone (coderSocketRefusal) would let Host B reach Host A's run
// on a machine paired with both. The process that connects must have the uid
// of the process serving the pairing's lane, read on every connection because
// the Host re-creates its lane socket when it restarts:
//
//   - the kernel's record of who connected (SO_PEERCRED, servicePeerUID) must
//     be the owner of the lane socket (Lstat, never followed), which refuses
//     another uid at once;
//   - and the process listening on the lane socket must prove it is the
//     pairing's Host: the lanes' own mutual TLS handshake (the Host's pinned
//     CA, the pairing's host name) must complete, and the kernel's record of
//     who listens there must be that same uid.
//
// WHY the handshake. The shared directory is group-writable (1770), so while
// Host A is down or restarting and its lane socket is gone, Host B can bind a
// socket of its own at that path. Its owner is then B, and B would pass the
// first check; it cannot pass the handshake, which needs A's lane key.
//
// The uid is the whole of what this tells apart: two Hosts that run as the
// same uid are the same process here (each one's own bind-mounted shared
// directory is what keeps them apart). No lane registered refuses: there is
// nothing to compare against.
func coderPeerRefusal(self string, c net.Conn) string {
	coderSockMu.Lock()
	lane, ok := coderSockLanes[self]
	coderSockMu.Unlock()
	if !ok || lane.path == "" || lane.dial == nil || lane.tls == nil {
		return "no lane socket is known for this pairing"
	}
	fi, err := os.Lstat(lane.path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return "the pairing's lane socket is not there"
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "the pairing's lane socket's owner could not be read"
	}
	uid, err := servicePeerUID(c)
	if err != nil {
		return "who connected could not be read"
	}
	if uid != st.Uid {
		return "the process that connected is not the one serving this pairing's lane"
	}
	served, err := coderLaneServerUID(lane)
	if err != nil {
		return "the pairing's lane socket is not served by the pairing's Host"
	}
	if served != uid {
		return "the process that connected is not the one serving this pairing's lane"
	}
	return ""
}

// coderLaneServerUID dials the pairing's lane socket the way its lanes do,
// completes the mutual TLS handshake (so the listener holds the pairing's
// Host's lane key), and returns the uid the kernel recorded for that listener.
func coderLaneServerUID(lane coderLane) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), coderLaneProbeTimeout)
	defer cancel()
	raw, err := lane.dial(ctx)
	if err != nil {
		return 0, err
	}
	defer raw.Close()
	uid, err := servicePeerUID(raw)
	if err != nil {
		return 0, err
	}
	if err := tls.Client(raw, lane.tls.Clone()).HandshakeContext(ctx); err != nil {
		return 0, err
	}
	return uid, nil
}
