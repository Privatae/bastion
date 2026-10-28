//go:build windows

package main

import (
	"io"
	"os"
)

// openControllingTerminal opens the console this process is attached to,
// CONIN$ for the answer and CONOUT$ for the question, whatever its standard
// input is: install.ps1 pipes the pairing code into `pair -`, and the person
// still answers in the PowerShell window. It fails with no console (a
// service, a scheduled task with no window).
func openControllingTerminal() (io.Reader, io.Writer, func(), error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, errNoTerminal
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		_ = in.Close()
		return nil, nil, nil, errNoTerminal
	}
	return in, out, func() { _ = in.Close(); _ = out.Close() }, nil
}
