package main

import (
	"errors"
	"strconv"

	"golang.org/x/sys/unix"
)

// openTreeEntry opens the entry name in the folder dfd with flags, for
// packFolder.
//
// A folder is opened directly: with O_DIRECTORY the kernel refuses anything
// that is not a folder before it opens it. Anything else is first opened as a
// path only (O_PATH), which runs no driver code, so a device, pipe or terminal
// swapped in since the look is never opened: opening some devices does
// something by itself (a watchdog arms, a tape rewinds on close). Only a plain
// file is then opened for reading, through /proc/self/fd, which reaches the
// file the path fd holds and no other.
func openTreeEntry(dfd int, name string, flags int) (int, error) {
	if flags&unix.O_DIRECTORY != 0 {
		return unix.Openat(dfd, name, flags, 0)
	}
	pfd, err := unix.Openat(dfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, errNotPlainFile
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pfd), flags&^unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		// No /proc mounted: open by name as other systems do. packOpened
		// still checks that what was opened is the file that was looked at.
		return unix.Openat(dfd, name, flags, 0)
	}
	return fd, err
}
