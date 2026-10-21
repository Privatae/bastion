//go:build linux

package main

import "golang.org/x/sys/unix"

// SO_PEERCRED: the kernel stamps the peer's credentials onto the socket at
// connect() and they are never re-read, so this is who connected.
func contextPeerUID(fd uintptr) (uint32, error) {
	cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}
