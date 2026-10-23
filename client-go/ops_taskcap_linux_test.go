package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// opTaskCapRun runs one dry run of the op fixture with the given run body
// (@ROOT@ in it is the op's effects folder), at the given privilege, and
// returns its report and its report's JSON (what the host receives). A
// timeLimit above 0 replaces the fixture's.
func opTaskCapRun(t *testing.T, privilege, body string, timeLimit int) (*opReport, string, error) {
	t.Helper()
	n := time.Now().UnixNano()
	root := filepath.Join(opTestRoot, fmt.Sprintf("tc%d", n))
	opDir := filepath.Join(opTestRoot, fmt.Sprintf("tcop%d", n))
	for _, p := range []string{root, opDir} {
		p := p
		t.Cleanup(func() { _ = os.RemoveAll(p) })
	}
	_ = os.MkdirAll(root, 0o777)
	_ = os.Chmod(root, 0o777)
	_ = os.MkdirAll(opDir, 0o755)
	for _, f := range opFixture(root, strings.ReplaceAll(body, "@ROOT@", root)) {
		raw, _ := base64.StdEncoding.DecodeString(f.B64)
		_ = os.WriteFile(filepath.Join(opDir, f.Path), raw, os.FileMode(f.Mode))
	}
	man := strings.Replace(fmt.Sprintf(opTestManifest, root), "privilege: root", "privilege: "+privilege, 1)
	if timeLimit > 0 {
		man = strings.Replace(man, "time_limit: 30", fmt.Sprintf("time_limit: %d", timeLimit), 1)
	}
	m, err := parseOpManifest([]byte(man))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := opRunSandboxed(opDir, m, opModeDryRun, `{"name":"x","count":1,"kind":"a"}`)
	if rep == nil {
		return nil, "", err
	}
	t.Cleanup(rep.cleanup)
	raw, _ := json.Marshal(rep)
	return rep, string(raw), err
}

// opFakeSystemdRun puts a stand-in for systemd-run first on PATH. With a
// cgroup it does what `systemd-run --scope -p TasksMax=N` does for the
// process it runs: a cgroup of its own whose pids.max is N, then the command.
// The cgroup is a fresh one at the top of the hierarchy, removed after the
// test; no unit is started. Without one it fails the way systemd-run does
// with no bus to reach. It records the arguments it was given.
func opFakeSystemdRun(t *testing.T, cgroup string) (argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	body := "echo 'Failed to connect to bus: No such file or directory' >&2; exit 1\n"
	if cgroup != "" {
		body = `max=
while [ $# -gt 0 ]; do
	case "$1" in
	--) shift; break ;;
	-p) shift; case "$1" in TasksMax=*) max=${1#TasksMax=} ;; esac ;;
	esac
	shift
done
mkdir -p ` + cgroup + `
[ -z "$max" ] || echo "$max" > ` + cgroup + `/pids.max
echo $$ > ` + cgroup + `/cgroup.procs
exec "$@"
`
		t.Cleanup(func() {
			// The cgroup empties once the sandbox's pid 1 is gone, which takes
			// every task the op left behind with it.
			for i := 0; i < 100; i++ {
				if err := os.Remove(cgroup); err == nil || os.IsNotExist(err) {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Errorf("the test cgroup %s did not empty", cgroup)
		})
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\n" + body
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return argsFile
}

// A root op's tasks are capped as a user op's are. RLIMIT_NPROC does not
// hold root (the kernel exempts it), so a root op runs in a scope of its own
// whose pids.max counts every task in it, root's included: a loop starting
// 100 background tasks is stopped at the cap, and the report says a cap held.
func TestARootOpIsStoppedAtItsTaskCap(t *testing.T) {
	requireSandbox(t)
	if ctl, err := os.ReadFile("/sys/fs/cgroup/cgroup.subtree_control"); err != nil || !strings.Contains(" "+string(ctl), " pids") {
		t.Skip("no pids controller at the top of the unified cgroup hierarchy here")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("the bastion asks for a scope only where systemd is init")
	}
	cgroup := fmt.Sprintf("/sys/fs/cgroup/privatae-optest-%d", os.Getpid())
	argsFile := opFakeSystemdRun(t, cgroup)

	rep, js, err := opTaskCapRun(t, "root", `i=0; while [ $i -lt 100 ]; do echo "STARTING=$i"; sleep 5 & i=$((i+1)); done; echo DONE; true`, 0)
	if rep == nil {
		t.Fatalf("the op did not run: %v", err)
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "fork") || strings.Contains(rep.Output, "DONE") {
		t.Fatalf("a root op started 100 background tasks with nothing stopping it: %v, %q", err, rep.Output)
	}
	last := ""
	for _, line := range strings.Split(rep.Output, "\n") {
		if strings.HasPrefix(line, "STARTING=") {
			last = strings.TrimPrefix(line, "STARTING=")
		}
	}
	if n, _ := strconv.Atoi(last); n < 50 {
		t.Errorf("the cap stopped the op after %s of its own tasks: the sandbox's own processes take too much of it", last)
	}
	t.Logf("the root op's fork loop was stopped at task %s", last)
	if !strings.Contains(js, `"tasks_capped":true`) || strings.Contains(js, `"tasks_note"`) {
		t.Errorf("the report does not say the cap held: %s", js)
	}

	raw, _ := os.ReadFile(argsFile)
	args := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{"--scope", "--slice=" + opActionSlice, "-p\nTasksMax="}
	for _, w := range want {
		if !strings.Contains(string(raw), w) {
			t.Errorf("systemd-run was not given %q: %q", w, args)
		}
	}
	unit := ""
	for _, a := range args {
		if strings.HasPrefix(a, "--unit=") {
			unit = strings.TrimPrefix(a, "--unit=")
		}
	}
	if !strings.HasPrefix(unit, opScopeUnitPrefix) || strings.HasPrefix(unit, opActionUnitPrefix) {
		t.Errorf("the scope's unit is %q: it must be a files op's, never one the action ops' sweep takes for its own", unit)
	}

	// A root op that starts a few tasks finishes as before.
	rep, js, err = opTaskCapRun(t, "root", `for i in 1 2 3 4 5; do sleep 0.1 & done; wait; echo RAN-AS=$(id -u); true`, 0)
	if err != nil {
		t.Fatalf("a root op starting five tasks: %v", err)
	}
	if !strings.Contains(rep.Output, "RAN-AS=0") || !strings.Contains(js, `"tasks_capped":true`) {
		t.Errorf("a capped root op: %q %s", rep.Output, js)
	}

	// The time limit still ends a run in its scope, with everything it
	// started (the cgroup must empty for the cleanup to remove it).
	rep, _, err = opTaskCapRun(t, "root", `sleep 30 & sleep 30; true`, 1)
	if err == nil || rep == nil || !rep.TimedOut {
		t.Fatalf("a root op past its time limit in its scope: %v", err)
	}
}

// opTaskCapRoom runs a root op's fork loop in its scope and returns how many
// tasks the op held when its next fork was refused.
func opTaskCapRoom(t *testing.T) int {
	t.Helper()
	rep, _, err := opTaskCapRun(t, "root", `i=0; while [ $i -lt 150 ]; do echo "STARTING=$i"; sleep 5 & i=$((i+1)); done; echo DONE; true`, 0)
	if rep == nil || err == nil || strings.Contains(rep.Output, "DONE") {
		t.Fatalf("the fork loop was not stopped by the scope's cap: %v", err)
	}
	last := -1
	for _, line := range strings.Split(rep.Output, "\n") {
		if v, ok := strings.CutPrefix(line, "STARTING="); ok {
			last, _ = strconv.Atoi(v)
		}
	}
	// STARTING=n is printed before the fork of task n: the shell and n tasks
	// were running when that fork was refused.
	return last + 1
}

// A root op has the same room under its scope's cap on a machine of any
// size. The two bastion processes in the scope are Go programs, and the Go
// runtime starts threads by the CPUs it may use: left to that, with the
// runtime set for 64 CPUs they held 44 of the scope's 96 tasks, leaving the
// op fewer than a user op's 64, and set for 256 the sandbox's pid 1 could not
// start at all. Here the bastion's CPUs are narrowed to one, then given back:
// the op must have as much room either way.
func TestARootOpsTaskRoomDoesNotShrinkWithTheMachinesCPUs(t *testing.T) {
	requireSandbox(t)
	if ctl, err := os.ReadFile("/sys/fs/cgroup/cgroup.subtree_control"); err != nil || !strings.Contains(" "+string(ctl), " pids") {
		t.Skip("no pids controller at the top of the unified cgroup hierarchy here")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("the bastion asks for a scope only where systemd is init")
	}
	var all unix.CPUSet
	if err := unix.SchedGetaffinity(0, &all); err != nil || all.Count() < 4 {
		t.Skip("needs at least 4 CPUs to show a difference")
	}
	opFakeSystemdRun(t, fmt.Sprintf("/sys/fs/cgroup/privatae-optest-cpus-%d", os.Getpid()))

	// The sandbox is started from this goroutine's thread (opRunSandboxCmd
	// holds it), and every process under it takes that thread's CPUs.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() { _ = unix.SchedSetaffinity(0, &all) }()
	var one unix.CPUSet
	for c := 0; ; c++ {
		if all.IsSet(c) {
			one.Set(c)
			break
		}
	}
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		t.Fatal(err)
	}
	narrow := opTaskCapRoom(t)
	if err := unix.SchedSetaffinity(0, &all); err != nil {
		t.Fatal(err)
	}
	wide := opTaskCapRoom(t)
	t.Logf("a root op held %d tasks with 1 CPU and %d with %d CPUs", narrow, wide, all.Count())
	if narrow < opSandboxTasksMax || wide < opSandboxTasksMax {
		t.Errorf("a root op held fewer tasks than a user op's %d: %d with 1 CPU, %d with %d", opSandboxTasksMax, narrow, wide, all.Count())
	}
	if wide < narrow-3 {
		t.Errorf("a root op's room shrank from %d tasks to %d with %d CPUs: the bastion's own processes in its scope took it", narrow, wide, all.Count())
	}
}

// Where no scope can be made, a root op runs as before and its report says
// its tasks were not capped, and why; it never claims a cap. A user op's
// tasks are held by RLIMIT_NPROC with no scope at all.
func TestARootOpWithNoScopeSaysItsTasksWereNotCapped(t *testing.T) {
	requireSandbox(t)
	body := `echo RAN-AS=$(id -u); true`

	// systemd-run is there and fails: the op still runs, once.
	opFakeSystemdRun(t, "")
	rep, js, err := opTaskCapRun(t, "root", `echo RUN >> @ROOT@/runs; echo "RUNS=$(wc -l < @ROOT@/runs)"; `+body, 0)
	if err != nil {
		t.Fatalf("a root op where systemd-run fails: %v", err)
	}
	if !strings.Contains(rep.Output, "RAN-AS=0") || !strings.Contains(rep.Output, "RUNS=1") {
		t.Errorf("the op did not run as root, once: %q", rep.Output)
	}
	if strings.Contains(js, `"tasks_capped":true`) || !strings.Contains(js, `"tasks_note":"`) || !strings.Contains(js, "not capped") || !strings.Contains(js, "Failed to connect to bus") {
		t.Errorf("the report must say the root op's tasks were not capped and why: %s", js)
	}

	// No systemd-run at all.
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	_, js, err = opTaskCapRun(t, "root", body, 0)
	if err != nil {
		t.Fatalf("a root op with no systemd-run: %v", err)
	}
	if strings.Contains(js, `"tasks_capped":true`) || !strings.Contains(js, "not capped") || !strings.Contains(js, "systemd-run is not installed") {
		t.Errorf("the report must say the root op's tasks were not capped and why: %s", js)
	}

	// A user op needs no scope: its cap is the rlimit, and the report says so.
	if _, _, err := opUnprivilegedIdentity(); err == nil {
		_, js, err = opTaskCapRun(t, "user", body, 0)
		if err != nil {
			t.Fatalf("a user op: %v", err)
		}
		if !strings.Contains(js, `"tasks_capped":true`) || strings.Contains(js, `"tasks_note"`) {
			t.Errorf("a user op's report: %s", js)
		}
	}
}

// An action op's program needs no scope of its own: it runs as a uid that no
// other run, account or subordinate range has (opNextUID), so RLIMIT_NPROC
// counts its own tasks only, and its unit's TasksMax holds every task in the
// unit, root's included. systemd-run is a stand-in that records what it was
// given and the spec it was handed; no unit starts.
func TestAnActionOpsTasksAreItsOwnAndItsUnitIsCapped(t *testing.T) {
	// The run mounts its own tmpfs before it reaches systemd-run, which takes
	// what the sandbox takes: root that may mount and make namespaces.
	requireSandbox(t)
	dir := t.TempDir()
	rec := filepath.Join(dir, "rec")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + rec + "\nfor a; do last=$a; done\ncat \"$last\" >> " + rec + "\necho >> " + rec + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	m, err := parseOpManifest([]byte(opActionManifest))
	if err != nil {
		t.Fatal(err)
	}
	opDir := t.TempDir()
	uids := map[uint32]bool{}
	for i := 0; i < 2; i++ {
		_ = os.Remove(rec)
		if _, _, err := opRunActionProgram(opDir, m, opModeDryRun, `{}`, nil, fmt.Sprintf("tc%d", i)); err != nil {
			t.Fatalf("the stand-in unit: %v", err)
		}
		raw, err := os.ReadFile(rec)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "-p\nTasksMax=512\n") || !strings.Contains(string(raw), "--slice="+opActionSlice+"\n") {
			t.Errorf("the action op's unit is not held to a task cap: %q", raw)
		}
		var spec opActionSpec
		js := string(raw)[strings.Index(string(raw), "{"):]
		if err := json.Unmarshal([]byte(strings.TrimSpace(js)), &spec); err != nil {
			t.Fatalf("the spec the unit was handed: %v %q", err, js)
		}
		if spec.UID < opUIDBase || spec.GID != spec.UID || uids[spec.UID] {
			t.Errorf("run %d's program runs as uid %d: not a fresh one of the ops' range", i, spec.UID)
		}
		uids[spec.UID] = true
	}
}
