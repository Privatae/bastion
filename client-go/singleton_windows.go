//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// stdinIsTerminal — the Windows console equivalent. Present so the package
// builds; the singleton itself is Linux-only in step 1 (singleton.go).
func stdinIsTerminal() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil
}

// ownerUID — not applicable on Windows; the singleton is Linux-only in step 1.
func ownerUID(fi os.FileInfo) (uint32, bool) { return 0, false }
