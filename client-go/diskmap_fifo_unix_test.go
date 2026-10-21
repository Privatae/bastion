//go:build !windows

package main

import "syscall"

// dmMkfifo makes a named pipe. It is a test-only helper and it deliberately
// lives OUTSIDE diskmap.go: TestTheWalkerNeverOpensAFile parses that file and
// would see a syscall the walk has no business making.
func dmMkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }
