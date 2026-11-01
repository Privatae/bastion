//go:build windows

package main

import (
	"errors"
	"os"
)

// openOwned on Windows: no owner check by account number (accounts are SIDs
// here), and a symlink needs privilege to create; the file must be regular.
func openOwned(path string, _ int) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("not a regular file")
	}
	return f, nil
}
