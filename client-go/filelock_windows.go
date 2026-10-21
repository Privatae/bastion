//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// flockFile takes an exclusive lock on f (blocking) via LockFileEx. Released
// by closing f (Windows releases file locks with the handle).
func flockFile(f *os.File) error {
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol)
}

// flockFileNB is flockFile without the wait — LOCKFILE_FAIL_IMMEDIATELY. Present
// so the package builds on Windows; the singleton itself is Linux-only today
// (singleton.go).
func flockFileNB(f *os.File) error {
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
}
