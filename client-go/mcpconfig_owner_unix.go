//go:build linux || darwin

package main

import (
	"os"
	"strconv"
	"syscall"
)

// mcpAdminOwners: root owns files in any account's home without that being
// another account's file.
var mcpAdminOwners = map[string]bool{"0": true}

// mcpFileOwner is the uid that owns an opened file, as mcpOwnerAllowed
// compares it.
func mcpFileOwner(fi os.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Uid), 10)
	}
	return mcpOwnerUnknown // matches no account and not root: the file is skipped
}

// mcpPathOwner is the uid that owns an account's home: the account whose
// files are read there. A home that cannot be looked at gives root, so only
// root-owned files would be read in it.
func mcpPathOwner(dir string) string {
	st, err := os.Stat(dir)
	if err != nil {
		return "0"
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(s.Uid), 10)
	}
	return "0"
}
