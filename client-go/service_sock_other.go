//go:build !linux

package main

import (
	"errors"
	"net"
	"time"
)

// serviceDialSocket: only Linux can pin the socket's inode across the dial
// (/proc/self/fd), and a name re-resolved at dial time can be swapped by the
// container that owns the directory. So the slot forward refuses elsewhere.
func serviceDialSocket(sock string, timeout time.Duration) (net.Conn, error) {
	return nil, errors.New("the service slot forward needs Linux to pin the server's socket")
}
