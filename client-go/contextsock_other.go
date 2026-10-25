//go:build !linux && !darwin && !windows

package main

// The release builds linux, darwin and windows (deploy/build.sh). Any other
// unix (freebsd, openbsd) still builds, with the local context socket unable
// to tell who is on the other end: contextPeerUser then fails, and
// contextSockServe answers every connection with that reason and forwards
// nothing. An ask that cannot be attributed is refused, never let through.
func contextPeerUID(uintptr) (uint32, error) { return 0, errContextSockUnsupported }
