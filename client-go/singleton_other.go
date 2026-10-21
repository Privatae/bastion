//go:build !linux && !windows

package main

import "os"

// stdinIsTerminal on platforms with no singleton in step 1. False is the safe
// answer: it selects the WAITING branch, which is the service's behaviour, and
// acquireSingletonLock returns early on these platforms anyway (singleton.go).
func stdinIsTerminal() bool { return false }

// ownerUID — not determinable portably; the singleton is Linux-only in step 1,
// and acquireSingletonLock returns before this on those platforms anyway.
func ownerUID(fi os.FileInfo) (uint32, bool) { return 0, false }
