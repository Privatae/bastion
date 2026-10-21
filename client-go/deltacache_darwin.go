//go:build darwin

package main

// The strong cache key on macOS. Same four fields as Linux; the Stat_t field
// for the inode change time is spelled Ctimespec here, which is the whole
// reason this is a separate file rather than one `unix` build tag.

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
		strconv.FormatInt(st.Ctimespec.Sec, 10) + "." +
		strconv.FormatInt(st.Ctimespec.Nsec, 10), true
}
