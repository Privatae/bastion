//go:build !linux && !darwin

package main

import (
	"errors"
	"net"
)

// servicePeerUID has no peer-credential source on this platform, so a slot's
// socket cannot be proven to be the server's — the forward refuses.
func servicePeerUID(c net.Conn) (uint32, error) {
	return 0, errors.New("peer credentials are not available on this platform")
}
