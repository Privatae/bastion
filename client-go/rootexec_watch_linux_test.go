//go:build linux

package main

// The connection watch against the real kernel: nftables, the command's
// cgroup, a real /bin/sh through the handler. It needs root, nft and ip, and
// it never runs in this machine's own network namespace: the test re-runs
// itself in a new one (CLONE_NEWNET), with a dummy interface as its way out,
// so the tables it makes and the packets it sends are seen by no firewall but
// its own. A machine without those skips it; CI's container is one.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const watchNetnsEnv = "PRIVATAE_TEST_ROOTEXEC_WATCH_NETNS"

func TestRootExecWatchKernel(t *testing.T) {
	if os.Getenv(watchNetnsEnv) != "1" {
		if os.Geteuid() != 0 {
			t.Skip("needs root: nftables and a cgroup of its own")
		}
		for _, b := range []string{"nft", "ip"} {
			if _, err := exec.LookPath(b); err != nil {
				if _, err := os.Stat("/usr/sbin/" + b); err != nil {
					t.Skipf("needs %s", b)
				}
			}
		}
		own, err := rootExecOwnCgroup()
		if err != nil || syscall.Access(filepath.Join(cgroupRoot, own), 2 /* W_OK */) != nil {
			t.Skip("needs a writable cgroup v2 folder of its own")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestRootExecWatchKernel$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), watchNetnsEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
		out, err := cmd.CombinedOutput()
		t.Logf("in a private network namespace:\n%s", out)
		if err != nil {
			t.Fatalf("the namespaced run failed: %v", err)
		}
		if strings.Contains(string(out), "--- SKIP") || !strings.Contains(string(out), "--- PASS: TestRootExecWatchKernel/") {
			t.Fatal("the namespaced run did not run its cases")
		}
		return
	}
	watchNetnsSetup(t)
	rootExecWatchStart, rootExecWatchStop = rootExecWatchStartKernel, rootExecWatchStopKernel
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	connect := func(args ...string) string {
		return "'" + bin + "' " + rootExecConnectSubcommand + " " + strings.Join(args, " ")
	}

	// MUTATION: return no connections from rootExecWatchStopKernel.
	// RESULT: red — the outside destinations are not reported.
	t.Run("outside", func(t *testing.T) {
		env := rootExecBox(t, true)
		j := runKernelCommand(t, env, "exec-k-out", connect("tcp:192.0.2.7:443", "udp:[fd99::7]:53"), 30)
		u := untrustedOf(t, j)
		if !u["192.0.2.7 tcp 443"] || !u["fd99::7 udp 53"] || len(u) != 2 {
			t.Fatalf("both outside destinations, nothing else: %v (J=%v)", u, j)
		}
		row := auditRow(t, env, "exec-k-out")
		if n, _ := row["untrusted_connections"].(float64); n != 2 {
			t.Fatalf("audit stop row: %v", row)
		}
		watchNothingLeft(t)
	})

	// MUTATION: drop the loopback test from rootExecIsOwn, or the list lookup.
	// RESULT: red — 127.0.0.1 or the platform's address is reported.
	t.Run("loopback and own only", func(t *testing.T) {
		env := rootExecBox(t, true)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		writeOwnHosts(t, `{"hosts": ["192.0.2.0/24", "fd99::/64"]}`)
		j := runKernelCommand(t, env, "exec-k-own",
			connect("tcp:"+ln.Addr().String(), "tcp:192.0.2.8:443", "udp:[fd99::8]:53", "udp:10.9.9.1:53"), 30)
		if _, ok := j["untrusted_connections"]; ok {
			t.Fatalf("loopback, this machine's own address and the platform's hosts are not outside: %v", j["untrusted_connections"])
		}
		cs, _ := auditRow(t, env, "exec-k-own")["connections"].([]any)
		seen := map[string]bool{}
		for _, c := range cs {
			m, _ := c.(map[string]any)
			seen[fmt.Sprintf("%v %v", m["addr"], m["own"])] = true
		}
		if !seen["192.0.2.8 true"] || !seen["fd99::8 true"] {
			t.Fatalf("the platform connections are still recorded, marked own: %v", cs)
		}
		watchNothingLeft(t)
	})

	// MUTATION: keep the plain `oifname "lo" return` rule (no relay ports).
	// RESULT: red — the connection to the loopback relay is never recorded.
	t.Run("a loopback relay", func(t *testing.T) {
		env := rootExecBox(t, true)
		relay, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer relay.Close()
		plain, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer plain.Close()
		port := relay.Addr().(*net.TCPAddr).Port
		writeOwnHosts(t, fmt.Sprintf(`{"hosts": [], "loopback_relays": [%d]}`, port))
		j := runKernelCommand(t, env, "exec-k-relay",
			connect("tcp:"+relay.Addr().String(), "tcp:"+plain.Addr().String(), "udp:127.0.0.53:53"), 30)
		u := untrustedOf(t, j)
		if !u[fmt.Sprintf("127.0.0.1 tcp %d", port)] || len(u) != 1 {
			t.Fatalf("only the relay is outside, not other loopback or the resolver: %v (J=%v)", u, j)
		}
		watchNothingLeft(t)
	})

	// MUTATION: start the shell without the watch's cgroup (cgroupFD -1).
	// RESULT: red — nothing the command does is seen.
	t.Run("a child process", func(t *testing.T) {
		env := rootExecBox(t, true)
		j := runKernelCommand(t, env, "exec-k-child",
			"("+connect("fork", "tcp:203.0.113.5:80")+") & wait; "+connect("fork", "udp:198.51.100.6:123"), 30)
		u := untrustedOf(t, j)
		if !u["203.0.113.5 tcp 80"] || !u["198.51.100.6 udp 123"] {
			t.Fatalf("a grandchild's connections are the command's: %v", u)
		}
		watchNothingLeft(t)
	})

	// MUTATION: skip rootExecWatchCleanup's cgroup removal on the deadline path.
	// RESULT: red — the cgroup outlives the command.
	t.Run("forced kill", func(t *testing.T) {
		env := rootExecBox(t, true)
		j := runKernelCommand(t, env, "exec-k-kill",
			connect("tcp:192.0.2.9:443")+"; (trap '' TERM; exec sleep 37) & sleep 37", 1)
		if j["timed_out"] != true {
			t.Fatalf("the deadline must have stopped it: %v", j)
		}
		if u := untrustedOf(t, j); !u["192.0.2.9 tcp 443"] {
			t.Fatalf("what it reached before the kill is reported: %v", u)
		}
		watchNothingLeft(t)
	})

	// A bastion that died mid-command leaves its table (systemd removes the
	// cgroup with the unit; here the test leaves both). The next sweep
	// removes them, and a process still in the cgroup moves to its parent.
	t.Run("left by a crash", func(t *testing.T) {
		w := rootExecWatchStartKernel("exec-k-crash")
		if w.Err != "" {
			t.Fatalf("watch: %s", w.Err)
		}
		sl := exec.Command("/bin/sleep", "30")
		sl.SysProcAttr = &syscall.SysProcAttr{}
		rootExecIntoCgroup(sl.SysProcAttr, w.CgroupFD())
		if err := sl.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sl.Process.Kill(); _ = sl.Wait() }()
		_ = syscall.Close(w.fd)
		// the process that made it is gone: it holds nothing any more
		rootExecWatching.Lock()
		delete(rootExecWatching.ids, w.ID)
		rootExecWatching.Unlock()
		if left := watchLeftovers(t); len(left) != 2 {
			t.Fatalf("the abandoned watch must still be there before the sweep: %v", left)
		}
		rootExecWatchSweep()
		watchNothingLeft(t)
		cg, _ := os.ReadFile("/proc/" + strconv.Itoa(sl.Process.Pid) + "/cgroup")
		if strings.Contains(string(cg), rootExecWatchCgroupPrefix) {
			t.Fatalf("the process left in it must have moved out: %s", cg)
		}
	})
}

// watchNetnsSetup gives the namespace loopback and one dummy interface that
// every other address routes to, so a connection leaves as a packet and goes
// nowhere.
func watchNetnsSetup(t *testing.T) {
	t.Helper()
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "d0", "type", "dummy"},
		{"addr", "add", "10.9.9.1/24", "dev", "d0"},
		{"-6", "addr", "add", "fd99::1/64", "dev", "d0", "nodad"},
		{"link", "set", "d0", "up"},
		{"route", "add", "default", "dev", "d0"},
		{"-6", "route", "add", "default", "dev", "d0"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
}

func runKernelCommand(t *testing.T, env sessionEnv, sid, command string, deadline int) map[string]any {
	t.Helper()
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, sid, command, deadline, 0)
	got := readUntil(t, ws, 'X', 20*time.Second)
	var j map[string]any
	if err := json.Unmarshal(got['J'], &j); err != nil {
		t.Fatalf("J: %v (X=%q E=%q)", err, got['X'], got['E'])
	}
	return j
}

func untrustedOf(t *testing.T, j map[string]any) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	cs, _ := j["untrusted_connections"].([]any)
	for _, c := range cs {
		m, _ := c.(map[string]any)
		if m["addr"] == "*" {
			t.Fatalf("the watch did not run: %v", m["note"])
		}
		out[fmt.Sprintf("%v %v %v", m["addr"], m["proto"], m["port"])] = true
	}
	return out
}

// watchLeftovers lists every watch table and command cgroup that exists.
func watchLeftovers(t *testing.T) []string {
	t.Helper()
	var left []string
	out, err := exec.Command("nft", "list", "tables").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list tables: %v %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, rootExecWatchTablePrefix) {
			left = append(left, line)
		}
	}
	own, _ := rootExecOwnCgroup()
	ents, _ := os.ReadDir(filepath.Join(cgroupRoot, own))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), rootExecWatchCgroupPrefix) {
			left = append(left, e.Name())
		}
	}
	return left
}

func watchNothingLeft(t *testing.T) {
	t.Helper()
	if left := watchLeftovers(t); len(left) > 0 {
		t.Fatalf("the watch left kernel objects behind: %v", left)
	}
}

// The cgroup kill without a kernel: cgroup.kill gets "1" when the kernel has
// it; on an older kernel each pid cgroup.procs lists gets SIGKILL, never pid 0
// or 1, and the list is read again until it is empty.
func TestRootExecWatchKillKernelCgroup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rootExecWatchKillKernel(&rootExecWatch{fd: -1, dir: dir})
	if b, _ := os.ReadFile(filepath.Join(dir, "cgroup.kill")); string(b) != "1" {
		t.Fatalf("cgroup.kill must get 1, got %q", b)
	}

	dir = t.TempDir()
	procs := filepath.Join(dir, "cgroup.procs")
	if err := os.WriteFile(procs, []byte("4242\n1\n0\n4343\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var sent []int
	oldKill := rootExecKillPid
	rootExecKillPid = func(pid int) error {
		sent = append(sent, pid)
		if len(sent) >= 2 {
			_ = os.WriteFile(procs, nil, 0o600) // the kernel empties the cgroup
		}
		return nil
	}
	t.Cleanup(func() { rootExecKillPid = oldKill })
	rootExecWatchKillKernel(&rootExecWatch{fd: -1, dir: dir})
	if fmt.Sprint(sent) != "[4242 4343]" {
		t.Fatalf("SIGKILL to each listed pid but 0 and 1, until the list is empty: %v", sent)
	}
	if _, err := os.Stat(filepath.Join(dir, "cgroup.kill")); !os.IsNotExist(err) {
		t.Fatal("cgroup.kill must never be created where the kernel has none")
	}
	rootExecWatchKillKernel(&rootExecWatch{fd: -1})
	rootExecWatchKillKernel(nil)
}
