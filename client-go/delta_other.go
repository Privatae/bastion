//go:build !linux

package main

// macOS and Windows answer none of the noise filter's three platform questions yet, and this
// file is where that is said out loud rather than left as an absent symbol.
//
// The consequence is written into deltanoise.go and is the safe direction: a
// rule whose inputs cannot be read does not fire, so these boxes report a
// finding where Linux would have counted it or demoted it. More rows, never
// fewer — a filter that failed closed here would turn "this build cannot read a
// process age" into a quiet machine, which is the one outcome a detection plane
// may not produce.
//
// What each would take: macOS has process start times through `ps -o lstart=`
// and listeners through `lsof -iTCP -sTCP:LISTEN`, both already shelled out to
// elsewhere in this binary; Windows has creation time from the process handle
// and listeners from GetExtendedTcpTable, which agents_windows.go already
// calls. Neither has a package database in the dpkg sense, so the third rule
// stays Linux-only on purpose.

import "time"

func deltaAgeReader() func(int) (time.Duration, bool) {
	return func(int) (time.Duration, bool) { return 0, false }
}

func deltaListeningPIDs() (map[int]bool, bool) { return nil, false }

func deltaPackagedFn() func([]string) map[string]string { return nil }
