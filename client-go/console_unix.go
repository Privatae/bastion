//go:build !windows

package main

import "os/exec"

// hideConsole is a no-op everywhere but Windows: there is no such thing as a
// console window to suppress, and a child started by a daemon inherits its
// file descriptors and nothing else. See console_windows.go for the whole
// reasoning — it is the file worth reading.
func hideConsole(cmd *exec.Cmd) {}
