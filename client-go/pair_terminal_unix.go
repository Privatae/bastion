//go:build !windows

package main

import (
	"io"
	"os"
)

// openControllingTerminal opens /dev/tty, this process's controlling terminal
// whatever its standard input is. It fails with no terminal (a service, a
// pipe from `ssh host cmd` without -t, cron).
func openControllingTerminal() (io.Reader, io.Writer, func(), error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, errNoTerminal
	}
	return f, f, func() { _ = f.Close() }, nil
}
