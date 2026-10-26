//go:build darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// dcnNoLinkStat describes the directory at p opened with O_NOFOLLOW_ANY, which
// fails on a link in any component (macOS 11 and later).
func dcnNoLinkStat(p string) (os.FileInfo, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW_ANY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	return f.Stat()
}
