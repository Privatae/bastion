//go:build windows

package main

import "fmt"

// Windows has no pty in this build (ConPTY is a later step). The lane answers with a
// plain message and exit 1 — "cannot", not "refused" — so the host can say so.
func spawnSessionProc(op, shell string, cols, rows int) (sessionProc, error) {
	_, _, _, _ = op, shell, cols, rows
	return nil, fmt.Errorf("interactive sessions are not available on Windows yet")
}

// processIsRoot moved to privilege_windows.go — it is a machine-authority
// question, not a terminal one, and living here (returning a flat false beside
// the pty stub) is how it went unnoticed that it locked Windows out of
// anchoring entirely.
