//go:build !linux && !darwin && !windows

package main

import "os"

// No account list on this platform (mcpconfig_other.go), so the reader never
// gets here; this keeps the package building. A path is still opened only
// when it was a regular file, and the opened file must be the one looked at.
func mcpOpenRegular(path string) (*os.File, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if !st.Mode().IsRegular() {
		return nil, "", errMCPNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(fi, st) {
		f.Close()
		return nil, "", errMCPNotRegular
	}
	return f, mcpOwnerUnknown, nil
}

var mcpAdminOwners = map[string]bool{}

// mcpPathOwner: no owner model here, so no owner check.
func mcpPathOwner(string) string { return mcpNoOwnerCheck }
