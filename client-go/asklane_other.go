//go:build !windows

package main

import (
	"net"
	"time"
)

// dialAskLane connects to the machine's bastion's ask socket at p.
func dialAskLane(p string) (askConn, error) {
	return net.DialTimeout("unix", p, 3*time.Second)
}

// askLaneAddr is where the lane is, as a message names it.
func askLaneAddr(p string) string { return p }

// startAskPipe is the Windows service's; ask.sock serves here (agentask.go).
func startAskPipe(<-chan struct{}) {}
