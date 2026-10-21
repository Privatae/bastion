//go:build darwin

package main

import (
	"strconv"
	"strings"
)

// macOS facts for the origin walk: one `ps` sweep with pid, ppid, tty and
// `comm`. "??" is no terminal.
//
// `comm` on macOS is argv[0] — usually a full path, because launchd and dyld
// exec with one, but chosen by the launcher all the same (Apple's ps maps the
// comm keyword to just_command, adv_cmds ps/keyword.c:101, which skips the
// kernel's saved exec_path to reach argv[0]). This file once said it was the
// kernel's path. Good enough to match the launchd inventory
// below; never an identity — procExe (agents_darwin.go) is that.
// No unit: launchd's label for a pid is a per-pid `launchctl procinfo`,
// too costly for a beat; interval jobs are recognised instead by matching
// the executable against the launchd inventory (originExtra.ScheduledExes).

func parsePSFacts(out string) map[int]procFacts {
	m := map[int]procFacts{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || pid <= 0 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		exe := strings.Join(f[3:], " ")
		pf := procFacts{PID: pid, PPID: ppid, Comm: binBase(exe), Exe: exe}
		if f[2] != "??" && f[2] != "-" {
			pf.Interactive, pf.Detail = true, "tty "+f[2]
		}
		m[pid] = pf
	}
	return m
}

func procFactsReader() func(int) (procFacts, bool) {
	var facts map[int]procFacts
	return func(pid int) (procFacts, bool) {
		if facts == nil {
			facts = map[int]procFacts{}
			if out, err := runTimed("ps", "-axo", "pid=,ppid=,tty=,comm="); err == nil {
				facts = parsePSFacts(string(out))
			}
		}
		f, ok := facts[pid]
		return f, ok
	}
}

func originExtras() originExtra {
	exes := map[string]string{}
	entries, _ := scanSchedulers()
	for _, e := range entries {
		if e.Kind != "launchd" || e.Schedule == "" {
			continue
		}
		if argv := strings.Fields(e.Command); len(argv) > 0 {
			exes[strings.ToLower(argv[0])] = e.Name
		}
	}
	return originExtra{ScheduledExes: exes}
}
