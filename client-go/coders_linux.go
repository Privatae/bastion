//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// coderSocketOwner: (owner uid, true) when p is a unix socket itself — Lstat,
// so a symlink is seen as a symlink and never followed.
func coderSocketOwner(p string) (int, bool) {
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return -1, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, false
	}
	return int(st.Uid), true
}

// coderFileOwner is the uid that owns fi (an Lstat result).
func coderFileOwner(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, false
	}
	return int(st.Uid), true
}

// coderReadMemInfo is MemTotal and MemAvailable in bytes (ops_memory_linux.go).
func coderReadMemInfo() (total, avail uint64, ok bool) { return opMemInfo() }

// coderReadPSIMem is the machine's memory "full avg10" (coderParsePSIFull);
// ok is false on a kernel without pressure stall information.
func coderReadPSIMem() (float64, bool) {
	b, err := os.ReadFile(filepath.Join(coderProcFS, "pressure", "memory"))
	if err != nil {
		return 0, false
	}
	return coderParsePSIFull(string(b))
}

// coderListenUnix listens on dir/name. A run directory's path can be longer
// than a unix socket address holds (108 bytes: the config dir, coders/runs/,
// a 63-character run id, egress/egress.sock), so the bind goes through
// /proc/self/fd/<dir fd>/name, which the kernel resolves to the directory
// already opened — short, whatever the real path is.
func coderListenUnix(dir, name string) (net.Listener, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return net.Listen("unix", "/proc/self/fd/"+strconv.Itoa(fd)+"/"+name)
}
