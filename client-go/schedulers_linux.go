//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Linux scheduler inventory: the system crontab and cron.d (five fields, a
// user, a command), every user's crontab under the spool (Debian and RHEL
// layouts), and systemd timers with the ExecStart of the unit they activate.
// User-level systemd timers (`systemctl --user`) are per login session and
// are not read from a root service; that gap is stated, not papered over.

const maxCronFiles = 500

func platformSchedulers() ([]schedEntry, []string, bool) {
	all := []schedEntry{}
	kinds := []string{}
	cronRead := false
	readSystem := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		cronRead = true
		all = append(all, parseCrontab(string(data), path, "", true)...)
	}
	readSystem("/etc/crontab")
	if ents, err := os.ReadDir("/etc/cron.d"); err == nil {
		for i, e := range ents {
			if i >= maxCronFiles || e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			readSystem(filepath.Join("/etc/cron.d", e.Name()))
		}
	}
	for _, spool := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		ents, err := os.ReadDir(spool)
		if err != nil {
			continue
		}
		for i, e := range ents {
			if i >= maxCronFiles || e.IsDir() {
				continue
			}
			p := filepath.Join(spool, e.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			cronRead = true
			all = append(all, parseCrontab(string(data), p, e.Name(), false)...)
		}
	}
	if cronRead {
		kinds = append(kinds, "cron")
	}
	timers := systemdTimerUnits()
	if len(timers) > 0 {
		kinds = append(kinds, "systemd-timer")
	}
	for unit, timer := range timers {
		out, err := runTimed("systemctl", "show", unit, "-p", "ExecStart", "--value")
		if err != nil {
			continue
		}
		cmd := parseExecStart(string(out))
		if cmd == "" {
			continue
		}
		all = append(all, schedEntry{Kind: "systemd-timer", Name: timer, Command: truncate(cmd, 200), Schedule: unit})
	}
	return all, kinds, true
}
