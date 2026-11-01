//go:build !linux

package main

import (
	"strings"
	"time"
)

// Off Linux the folder and start time are not read yet; the agent's own
// session record still is (claudeCodeSelf), unverified, since procIdentity has
// no start time to check it against there.
func osProcCwd(int) string                { return "" }
func osProcStarted(int) (time.Time, bool) { return time.Time{}, false }
func osProcCmdArgs(pid int) []string      { return strings.Fields(procCmdline(pid)) }
