//go:build linux

package main

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// mcpOpenRegular opens path for reading only if what it names, after any
// symlinks, is a regular file, without ever opening anything else. The first
// open is O_PATH: it resolves the path and pins the inode but does not open
// the file (no driver runs, a FIFO does not wait). Only once fstat says
// regular is that same inode reopened for reading through /proc/self/fd, so
// swapping the path between the look and the read reaches nothing new.
func mcpOpenRegular(path string) (*os.File, string, error) {
	pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return nil, "", &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, "", errMCPNotRegular
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pfd), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", &os.PathError{Op: "reopen", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, "", errMCPNotRegular
	}
	return f, mcpFileOwner(fi), nil
}
