//go:build linux

package main

import "testing"

func TestParseProcStatFactsAndCgroup(t *testing.T) {
	stat := "9002 (python3) S 9001 9002 9002 0 -1 4194560 1200 0 0 0 5 1 0 0 20 0 1 0 12345 100000 300 18446744073709551615"
	comm, ppid, tty, ok := parseProcStatFacts(stat)
	if !ok || comm != "python3" || ppid != 9001 || tty != 0 {
		t.Errorf("parseProcStatFacts = %q %d %d %v", comm, ppid, tty, ok)
	}
	// comm with a space and a paren, tty set (pts/0 = 34816)
	stat = "2002 (my (odd) name) S 2001 2002 2002 34816 2002 4194304 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1 1"
	comm, ppid, tty, ok = parseProcStatFacts(stat)
	if !ok || comm != "my (odd) name" || ppid != 2001 || tty != 34816 {
		t.Errorf("parseProcStatFacts(odd) = %q %d %d %v", comm, ppid, tty, ok)
	}
	if ttyName(34816) != "pts/0" || ttyName(34817) != "pts/1" || ttyName(1025) != "tty1" {
		t.Errorf("ttyName: %s %s %s", ttyName(34816), ttyName(34817), ttyName(1025))
	}
	if u := cgroupUnit("0::/system.slice/cron.service\n"); u != "cron.service" {
		t.Errorf("cgroupUnit(system) = %q", u)
	}
	if u := cgroupUnit("0::/user.slice/user-1000.slice/session-3.scope\n"); u != "" {
		t.Errorf("cgroupUnit(session scope) = %q, want empty", u)
	}
	if u := cgroupUnit("0::/user.slice/user-1000.slice/user@1000.service/app.slice/agent.service\n"); u != "agent.service" {
		t.Errorf("cgroupUnit(user unit) = %q", u)
	}
	if u := cgroupUnit("12:pids:/system.slice/atd.service\n1:name=systemd:/system.slice/atd.service\n"); u != "atd.service" {
		t.Errorf("cgroupUnit(v1) = %q", u)
	}
}
