//go:build windows

package main

// The WEAK cache key on Windows, and it is named weak because it is.
//
// Go hands back a syscall.Win32FileAttributeData from FileInfo.Sys(): creation,
// last-access and last-write times, plus the size. There is no file identity
// (no volume serial + file index without opening a handle) and no change time,
// so a file overwritten in place with its size, write time and creation time
// restored keys identically to the original. deltaCacheWeakTTL is what covers
// that, and `false` here is what turns it on.

import (
	"os"
	"strconv"
	"syscall"
)

func statIdentity(fi os.FileInfo) (string, bool) {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return "", false
	}
	return strconv.FormatInt(fi.Size(), 10) + ":" +
		strconv.FormatInt(d.LastWriteTime.Nanoseconds(), 10) + ":" +
		strconv.FormatInt(d.CreationTime.Nanoseconds(), 10), false
}
