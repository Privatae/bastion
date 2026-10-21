//go:build !windows

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// flockFile takes an exclusive advisory lock on f (blocking). Released by
// closing f. Advisory is enough: every writer of a pairing file is this
// binary, and every one of them goes through withPairingsLock.
func flockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

// flockFileNB is flockFile without the wait: it fails immediately when another
// process holds the lock, so an interactive `run` can say "already running"
// instead of hanging as an invisible standby (singleton.go).
func flockFileNB(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
