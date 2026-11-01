//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

var errNotOwnedRegular = errors.New("not a regular file owned by that account")

// openOwned opens a file the agent's account controls, for the daemon that
// may be running as the machine's administrator. It never follows a final
// symlink (O_NOFOLLOW), never waits on a pipe planted in its place
// (O_NONBLOCK, then a regular-file check), and, when uid >= 0, refuses a
// file another account owns, which also catches a symlinked directory on the
// way: whatever the path walked through, the file it reached has to be the
// agent account's own.
func openOwned(path string, uid int) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || (uid >= 0 && int(st.Uid) != uid) {
		_ = syscall.Close(fd)
		return nil, errNotOwnedRegular
	}
	return os.NewFile(uintptr(fd), path), nil
}
