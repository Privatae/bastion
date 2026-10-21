//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// stdioIsConsole: both standard input and standard output are a console, not
// a file or a pipe.
func stdioIsConsole() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil &&
		windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode) == nil
}

// stdinIsConsole: standard input alone is a console (pair_stdin.go).
func stdinIsConsole() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil
}
