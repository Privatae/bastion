//go:build linux

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// stdinIsTerminal distinguishes a person at a shell from the service. It decides
// which way the machine lock waits: a human who typed `run` wants "already
// running" immediately, while the unit must BLOCK so a restart queues behind the
// dying primary instead of exiting and being restarted every two seconds — the
// crash-loop the lock exists to end.
//
// It is a real isatty (TCGETS), not a character-device test. os.ModeCharDevice —
// which the first draft used — is TRUE for /dev/null, and every installed daemon
// has stdin on /dev/null: the installed unit sets no StandardInput, so systemd's
// default (null) applies. The daemon therefore took the fail-fast branch in the
// only deployment shape that exists, and the blocking standby the design asks
// for was unreachable. Measured on 18 of 18 reachable boxes in one deployment.
func stdinIsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// ownerUID reports the owning uid of a stat result. Used to refuse locking inside
// a runtime directory root does not own.
func ownerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
