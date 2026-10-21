//go:build linux

package main

// The strong cache key on Linux: device, inode, size, and the inode's change
// time. deltacache.go says why ctime is the field that matters.

import (
	"os"
	"strconv"
	"syscall"
)

func statIdentity(fi os.FileInfo) (string, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" +
		strconv.FormatUint(st.Ino, 10) + ":" +
		strconv.FormatInt(fi.Size(), 10) + ":" +
		strconv.FormatInt(st.Ctim.Sec, 10) + "." +
		strconv.FormatInt(st.Ctim.Nsec, 10), true
}
