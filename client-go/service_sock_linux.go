//go:build linux

package main

import (
	"errors"
	"net"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// serviceDialSocket connects to EXACTLY the socket inode at sock, never to
// whatever a name resolves to at dial time. The container owns the directory
// the socket lives in, and a plain Lstat-then-Dial leaves a window in which it
// can rename a link (to a host socket owned by the same uid — a rootless
// container runtime's, say) into place. So: open the name with O_PATH|O_NOFOLLOW
// (a symlink fails to open, it is never followed), confirm on the FD that it is
// a socket, and connect through /proc/self/fd/N — the kernel resolves that to
// the inode already held, whatever happens to the name afterwards. The peer's
// uid is still checked after connect (spliceUnix) as a second wall.
func serviceDialSocket(sock string, timeout time.Duration) (net.Conn, error) {
	fd, err := unix.Open(sock, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, errors.New("not a socket")
	}
	return net.DialTimeout("unix", "/proc/self/fd/"+strconv.Itoa(fd), timeout)
}
