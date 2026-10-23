//go:build !windows && !linux

package main

import "golang.org/x/sys/unix"

// openTreeEntry opens the entry name in the folder dfd with flags, for
// packFolder. These systems have no open that runs no driver code, so a
// special file swapped in since the look is opened (O_NONBLOCK, O_NOCTTY),
// then closed unread by packOpened.
func openTreeEntry(dfd int, name string, flags int) (int, error) {
	return unix.Openat(dfd, name, flags, 0)
}
