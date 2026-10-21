//go:build darwin

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// mcpOpenRegular opens path for reading only if what it names, after any
// symlinks, is a regular file, without ever opening anything else. macOS has
// no O_PATH, so the links are resolved first, the resolved path is required
// to be a regular file, and it is then opened with O_NOFOLLOW_ANY: a link
// put in its place since the look makes the open fail rather than lead
// somewhere new, and a device can only sit in devfs, which the look already
// refused. The opened file must be the one looked at.
func mcpOpenRegular(path string) (*os.File, string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, "", err
	}
	lst, err := os.Lstat(resolved)
	if err != nil {
		return nil, "", err
	}
	if !lst.Mode().IsRegular() {
		return nil, "", errMCPNotRegular
	}
	fd, err := unix.Open(resolved, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return nil, "", &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(fi, lst) {
		f.Close()
		return nil, "", errMCPNotRegular
	}
	return f, mcpFileOwner(fi), nil
}
