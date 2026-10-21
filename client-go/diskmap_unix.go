//go:build !windows

package main

// The two platform questions the disk map asks, answered for unix: what device
// is this on, and what counts as a volume root.

import (
	"io/fs"
	"os"
	"syscall"
)

// dmDeviceOf is the device id of a path, and whether the platform would say.
//
// The second return is not decoration. A walk that cannot identify a device
// must NOT fall back to "same device as everything" — that would silently
// re-enable mount crossing, which is how a walk of / ends up inside an NFS
// share and takes four minutes. dmScan reads this once per root and skips the
// crossing test entirely when it is false, so the behaviour is "no boundary
// check" rather than "a boundary check that always passes".
func dmDeviceOf(path string) (uint64, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, false
	}
	return dmDeviceOfInfo(fi)
}

// dmDeviceOfInfo reads the device out of a FileInfo already in hand, so the
// walk does not pay for a second lstat per directory.
//
// The uint64 conversion is load-bearing across the two unixes this ships to:
// syscall.Stat_t.Dev is uint64 on linux and int32 on darwin, so a typed
// comparison would not compile on both. Widening both to uint64 compares the
// same bits either way — the value is only ever tested for equality against
// another device from the same platform, never interpreted.
func dmDeviceOfInfo(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return uint64(st.Dev), true
}

// dmVolumeRoots on unix is the filesystem root, and there is exactly one.
//
// The rejected alternative was reading /proc/self/mountinfo (linux) or running
// `mount` (darwin) to add every local filesystem as its own root. It is the
// better answer eventually and it is not the right answer for this unit: it is
// a fourth platform-specific parser, it needs a filesystem-type allow-list
// nobody has agreed (is a fuse mount local? is an overlay?), and getting that
// list wrong walks a network share. What it would buy is already visible
// without it — dmScan names every boundary it refused to cross, so a user with
// a second disk SEES that /mnt/data was not entered, which is the difference
// between a limitation and a lie.
func dmVolumeRoots() (roots []string, notes []string) {
	return []string{"/"}, nil
}
