//go:build darwin

package main

import "golang.org/x/sys/unix"

// LOCAL_PEERCRED is darwin's SO_PEERCRED: the kernel's record of the process on
// the other end, from the kernel, not from anything it sent. x/sys exposes it
// as GetsockoptXucred (syscall_darwin.go:486); there is no Getpeereid wrapper
// in this version, which is why this reads the Xucred directly.
func contextPeerUID(fd uintptr) (uint32, error) {
	x, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return x.Uid, nil
}
