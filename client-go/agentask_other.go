//go:build !linux

package main

import "net"

// Off Linux only the account is named; the asking agent is not walked to.
func askPeerPID(net.Conn) int { return 0 }
