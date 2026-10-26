//go:build !linux && !darwin

package main

import "os"

// dcnNoLinkStat on a platform with no open that refuses a link in every
// component (Windows): the final component is judged without following it.
// The store is still reached only through its os.Root and only while its real
// path matches the pin; what this leaves is a swap of a folder above the
// store, by someone who can rename it, timed between the two opens.
func dcnNoLinkStat(p string) (os.FileInfo, error) {
	return os.Lstat(p)
}
