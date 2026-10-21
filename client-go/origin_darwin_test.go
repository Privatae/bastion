//go:build darwin

package main

import "testing"

func TestParsePSFacts(t *testing.T) {
	out := "    1     0 ??       /sbin/launchd\n  420     1 ??       /usr/local/bin/python3\n 2002  2001 ttys003  /usr/local/bin/claude\n"
	m := parsePSFacts(out)
	if f := m[420]; f.PPID != 1 || f.Interactive || f.Comm != "python3" || f.Exe != "/usr/local/bin/python3" {
		t.Errorf("parsePSFacts(420) = %+v", f)
	}
	if f := m[2002]; !f.Interactive || f.Detail != "tty ttys003" || f.Comm != "claude" {
		t.Errorf("parsePSFacts(2002) = %+v", f)
	}
}
