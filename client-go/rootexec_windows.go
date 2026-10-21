//go:build windows

package main

import (
	"errors"
	"io"
)

// Root commands ride the session lane, which has no Windows build yet: the
// lane answers "cannot", exit 1, so the host can say so.
func startRootExec(command string, stdout, stderr io.Writer, cgroupFD int) (rootExecProc, error) {
	_, _, _, _ = command, stdout, stderr, cgroupFD
	return nil, errors.New("root commands are not available on Windows yet")
}
