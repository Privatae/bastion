//go:build linux

package main

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// dcnNoLinkStat describes the directory at p (absolute, clean) reached one
// component at a time with O_NOFOLLOW, so a link anywhere in the path fails
// instead of being followed. O_PATH: a component the bastion may traverse but
// not list (a home at 0711) still opens.
func dcnNoLinkStat(p string) (os.FileInfo, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, errors.New("not an absolute path")
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" {
			continue
		}
		if c == "." || c == ".." {
			_ = unix.Close(fd)
			return nil, errors.New("not a clean path")
		}
		next, err := unix.Openat(fd, c, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(next, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(next)
			return nil, errors.New("a component is not a directory")
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	return f.Stat()
}
