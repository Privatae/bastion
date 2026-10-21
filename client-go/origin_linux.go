//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Linux facts for the origin walk, all from /proc: comm, ppid and tty_nr
// from /proc/<pid>/stat, the cgroup's leaf unit from /proc/<pid>/cgroup, the
// executable from /proc/<pid>/exe. Read per pid on demand and memoised for
// one scan by the closure procFactsReader returns.

// parseProcStatFacts reads comm, ppid and tty_nr out of a stat line. The
// comm is parenthesised and may hold spaces; fields are counted from the
// LAST ')': state(0) ppid(1) pgrp(2) session(3) tty_nr(4).
func parseProcStatFacts(stat string) (comm string, ppid int, tty int, ok bool) {
	i := strings.LastIndex(stat, ")")
	j := strings.Index(stat, "(")
	if i < 0 || j < 0 || j > i {
		return "", 0, 0, false
	}
	comm = stat[j+1 : i]
	f := strings.Fields(stat[i+1:])
	if len(f) < 5 {
		return comm, 0, 0, false
	}
	ppid, _ = strconv.Atoi(f[1])
	tty, _ = strconv.Atoi(f[4])
	return comm, ppid, tty, true
}

// cgroupUnit returns the systemd unit a cgroup path ends in (a .service or a
// user@N.service child), or "" for a login session scope and everything
// else. "0::/system.slice/cron.service" -> "cron.service".
func cgroupUnit(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		// v2: "0::/path"; v1: "N:controllers:/path" — the path is after the last ':'
		k := strings.LastIndex(line, ":")
		if k < 0 {
			continue
		}
		path := line[k+1:]
		leaf := path[strings.LastIndex(path, "/")+1:]
		if strings.HasSuffix(leaf, ".service") {
			return leaf
		}
	}
	return ""
}

func procFactsReader() func(int) (procFacts, bool) {
	memo := map[int]procFacts{}
	miss := map[int]bool{}
	return func(pid int) (procFacts, bool) {
		if f, ok := memo[pid]; ok {
			return f, true
		}
		if miss[pid] {
			return procFacts{}, false
		}
		p := "/proc/" + strconv.Itoa(pid)
		stat, err := os.ReadFile(p + "/stat")
		if err != nil {
			miss[pid] = true
			return procFacts{}, false
		}
		comm, ppid, tty, ok := parseProcStatFacts(string(stat))
		if !ok {
			miss[pid] = true
			return procFacts{}, false
		}
		f := procFacts{PID: pid, PPID: ppid, Comm: binBase(comm), Interactive: tty != 0}
		if tty != 0 {
			f.Detail = "tty " + ttyName(tty)
		}
		if cg, err := os.ReadFile(p + "/cgroup"); err == nil {
			f.Unit = cgroupUnit(string(cg))
		}
		if exe, err := os.Readlink(p + "/exe"); err == nil {
			f.Exe = strings.TrimSuffix(exe, " (deleted)")
			if f.Comm == "" {
				f.Comm = binBase(f.Exe)
			}
		}
		memo[pid] = f
		return f, true
	}
}

// ttyName renders a tty_nr the way `ps` does for the common cases: pts/N and
// ttyN. Anything else is shown as the raw number — a fact, not a guess.
func ttyName(n int) string {
	major, minor := (n>>8)&0xfff, (n&0xff)|((n>>12)&0xfff00)
	switch major {
	case 136, 137, 138, 139, 140, 141, 142, 143:
		return "pts/" + strconv.Itoa((major-136)*256+minor)
	case 4:
		return "tty" + strconv.Itoa(minor)
	}
	return strconv.Itoa(n)
}

// systemd timers, read once per scan window and shared with the scheduler
// inventory. `systemctl` absent (a non-systemd box) yields an empty map.
var timerCache = struct {
	sync.Mutex
	at time.Time
	m  map[string]string
}{}

func systemdTimerUnits() map[string]string {
	timerCache.Lock()
	defer timerCache.Unlock()
	if timerCache.m != nil && time.Since(timerCache.at) < schedCacheFor {
		return timerCache.m
	}
	m := map[string]string{}
	if out, err := runTimed("systemctl", "list-timers", "--all", "--no-legend", "--plain"); err == nil {
		m = parseSystemdTimers(string(out))
	}
	timerCache.at, timerCache.m = time.Now(), m
	return m
}

func originExtras() originExtra {
	return originExtra{TimerUnits: systemdTimerUnits()}
}
