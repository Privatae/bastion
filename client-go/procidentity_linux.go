//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// osProcIdentity reads /proc/<pid>/stat: field 22 (starttime, in clock ticks
// since boot) is the identity — a reused pid has a later one — and field 3
// (state) says whether the process is already stopped ('T', or 't' when
// stopped by a tracer). Parsed after the LAST ')' so a name containing spaces
// or parentheses cannot shift the fields.
func osProcIdentity(pid int) (id string, stopped bool, ok bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", false, false
	}
	s := string(raw)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 > len(s) {
		return "", false, false
	}
	f := strings.Fields(s[i+2:])
	if len(f) < 20 {
		return "", false, false
	}
	return f[19], f[0] == "T" || f[0] == "t", true
}
