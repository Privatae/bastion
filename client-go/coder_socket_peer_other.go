//go:build !linux

package main

import "net"

// coderPeerRefusal: coder runs are Linux only (coderHostReady), so no run
// socket is ever served here; any connection is refused.
func coderPeerRefusal(self string, c net.Conn) string {
	return "coder run sockets are served on Linux only"
}
