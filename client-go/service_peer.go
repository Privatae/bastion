//go:build linux || darwin

package main

import (
	"errors"
	"net"
)

// servicePeerUID is the uid the kernel stamped on the OTHER end of a unix
// socket connection at connect() time (SO_PEERCRED / LOCAL_PEERCRED via
// contextPeerUID). It is who is actually listening, whatever the path said.
func servicePeerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var cerr error
	if err := raw.Control(func(fd uintptr) { uid, cerr = contextPeerUID(fd) }); err != nil {
		return 0, err
	}
	return uid, cerr
}
