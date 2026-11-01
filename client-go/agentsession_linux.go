//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func osProcCwd(pid int) string {
	d, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/cwd")
	if err != nil {
		return ""
	}
	return d
}

func osProcCmdArgs(pid int) []string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil
	}
	return splitNul(raw)
}

// osProcStarted is the process's start: boot time (/proc/stat btime) plus its
// start in clock ticks (procIdentity), at the USER_HZ of 100 Linux reports.
func osProcStarted(pid int) (time.Time, bool) {
	id, _, ok := procIdentity(pid)
	if !ok {
		return time.Time{}, false
	}
	ticks, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			boot, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			return time.Unix(boot, 0).Add(time.Duration(ticks) * 10 * time.Millisecond), true
		}
	}
	return time.Time{}, false
}
