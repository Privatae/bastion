//go:build darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// stdioIsConsole: both standard input and standard output are a terminal, not
// a file or a pipe.
func stdioIsConsole() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		if _, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA); err != nil {
			return false
		}
	}
	return true
}

// stdinIsConsole: standard input alone is a terminal (pair_stdin.go).
func stdinIsConsole() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TIOCGETA)
	return err == nil
}
