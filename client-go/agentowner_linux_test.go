//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The Linux reader end to end over an invented machine: a /proc with two
// processes and an /etc and /run that say who they belong to. Nothing here is
// read from the box the test runs on.
func TestLinuxOwnerFactsReaderOverAFixtureMachine(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/passwd", "root:x:0:0::/root:/bin/sh\npat:x:1001:1001::/home/pat:/bin/bash\n"+
		"kim:x:1002:1002::/home/kim:/bin/bash\nsvcdemo:x:120:120::/nonexistent:/usr/sbin/nologin\n")
	write("etc/group", "root:x:0:\nsudo:x:27:pat\npat:x:1001:\nkim:x:1002:\n")
	write("etc/sudoers", "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n")
	write("etc/nsswitch.conf", "passwd: files\n")
	write("run/systemd/users/1001", "UID=1001\nSTATE=active\n")
	write("proc/400/status", "Name:\tdemo\nUid:\t1001\t1001\t1001\t1001\nGroups:\t27 1001\n")
	write("proc/401/status", "Name:\tdemo\nUid:\t1002\t1002\t1002\t1002\nGroups:\t1002\n")
	write("proc/402/status", "Name:\tdemo\nUid:\t120\t120\t120\t120\nGroups:\t\n")
	write("proc/403/status", "Name:\tdemo\nUid:\t1002\t0\t1002\t1002\nGroups:\t1002\n")

	oldID, oldProc := identityRoot, procRoot
	identityRoot, procRoot = root, filepath.Join(root, "proc")
	t.Cleanup(func() { identityRoot, procRoot = oldID, oldProc })

	read := ownerFactsReader()
	for _, c := range []struct {
		pid  int
		user string
		want ownerFacts
	}{
		{400, "pat", ownerFacts{ownerClassLocal, ownerYes, ownerYes}},
		{401, "kim", ownerFacts{ownerClassLocal, ownerNo, ownerNo}},
		{402, "svcdemo", ownerFacts{ownerClassService, ownerNo, ownerNo}},
		// Effective root under kim's account: administrator, class unchanged.
		{403, "kim", ownerFacts{ownerClassLocal, ownerYes, ownerNo}},
		// A pid with no status file: everything unknown, nothing guessed.
		{404, "ghost", unknownOwner},
	} {
		if got := read(c.pid, c.user); got != c.want {
			t.Errorf("pid %d (%s): got %+v, want %+v", c.pid, c.user, got, c.want)
		}
	}
}

// Every observation scanAgents returns carries the owner facts: the wiring,
// not only the classifier. The one process is this test itself, so the facts
// come from the real /proc and are only checked for being filled in.
func TestScanAgentsCarriesOwnerFacts(t *testing.T) {
	prev := scanProcessesFn
	t.Cleanup(func() { scanProcessesFn = prev })
	self := os.Getpid()
	scanProcessesFn = func() (map[int]agentObs, error) {
		return map[int]agentObs{self: {PID: self, User: procUser(self), Signature: "claude-code",
			Cmdline: "claude", raw: "claude"}}, nil
	}
	got, err := scanAgents()
	if err != nil || len(got) == 0 {
		t.Fatalf("scan: %d observations, %v", len(got), err)
	}
	// The network signal may add this box's own model clients; every
	// observation, however it was caught, must carry the facts.
	for _, a := range got {
		if a.OwnerClass == "" || a.OwnerAdmin == "" || a.OwnerInteractive == "" {
			t.Fatalf("owner facts missing from pid %d", a.PID)
		}
	}
}
