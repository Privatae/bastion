//go:build linux

package main

// ops_taskcap_linux.go — a root op's tasks are capped by a cgroup.
//
// A files op's tasks are capped at opSandboxTasksMax by RLIMIT_NPROC, and the
// kernel never applies that limit to root: a task whose real user is root,
// or that holds CAP_SYS_RESOURCE or CAP_SYS_ADMIN, forks past it. A user op
// runs as an unprivileged user and the limit holds. A root op's runaway fork
// was held by nothing but its time limit.
//
// A cgroup's pids.max counts every task in the cgroup, root's included. So a
// root op runs in a scope of its own, in the ops' slice, with TasksMax set,
// started by systemd-run as an action op's unit is. The scope's process is
// this binary as `__op-sandbox-scope <spec>`: it reads its own cgroup's
// pids.max, writes what it read beside the spec, and only then starts the
// sandbox's pid 1 exactly as the bastion does without a scope. The report
// says the tasks were capped only when that value is the cap.
//
// Where no scope can be made (no systemd, no pids controller, systemd-run
// failing), the op runs as before, and its report says its tasks were not
// capped and why. A scope that could not start ran nothing: the value is
// written before the sandbox starts, so with no value the op never ran.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	// opSandboxTasksMax is the most tasks a files op's sandbox holds at once,
	// threads included: RLIMIT_NPROC for a user op, pids.max for a root op.
	opSandboxTasksMax = 64
	// opSandboxScopeTasks is the scope's TasksMax: the op's own cap plus room
	// for the two bastion processes that start it inside the scope (this
	// binary, twice, each with its runtime's threads; 8 tasks between them
	// where measured, held there by opSandboxHelperEnv), so a root op may
	// start at least as many tasks as a user op.
	opSandboxScopeTasks = opSandboxTasksMax + 32
	// opSandboxHelperEnv is in the environment of both bastion processes that
	// start the sandbox. The Go runtime starts threads by the CPUs it may use,
	// and in a scope each one counts against the cap: measured, the two held
	// 16 tasks with 12 CPUs, 44 with the runtime set for 64, and set for 256
	// the sandbox's pid 1 could not start a thread and the op never ran. With
	// one, they hold 8 on a machine of any size. Neither process does more
	// than start its child and wait for it. The op never sees this: pid 1
	// sets the op's environment itself.
	opSandboxHelperEnv       = "GOMAXPROCS=1"
	opSandboxScopeSubcommand = "__op-sandbox-scope"
	// opScopeTasksFile, beside the spec on the run's tmpfs, holds the
	// pids.max the scope's process read in its own cgroup.
	opScopeTasksFile = "scope_pids_max"
)

// opTasksScopeWhyNot says why this machine cannot hold an op's tasks in a
// scope of their own, "" when it can.
func opTasksScopeWhyNot() string {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return "systemd-run is not installed"
	}
	if st, err := os.Stat("/run/systemd/system"); err != nil || !st.IsDir() {
		return "systemd is not this machine's init"
	}
	raw, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return "this machine does not run the unified cgroup hierarchy"
	}
	for _, c := range strings.Fields(string(raw)) {
		if c == "pids" {
			return ""
		}
	}
	return "the kernel offers no pids cgroup controller"
}

// opTasksScopeArgs is the systemd-run command line for a root op's run.
func opTasksScopeArgs(unit, self, specPath string) []string {
	return []string{"--scope", "--quiet", "--collect", "--unit=" + unit, "--slice=" + opActionSlice,
		"-p", "TasksMax=" + strconv.Itoa(opSandboxScopeTasks),
		"--", self, opSandboxScopeSubcommand, specPath}
}

// opScopeUnit names the scope of the run whose tmpfs is run.
func opScopeUnit(run string) string {
	return opScopeUnitPrefix + strings.TrimPrefix(filepath.Base(run), "run-")
}

// opKillScope kills every task in a files op's scope through the kernel.
func opKillScope(unit string) {
	_ = os.WriteFile(filepath.Join("/sys/fs/cgroup", opActionSlice, unit+".scope", "cgroup.kill"), []byte("1"), 0o600)
}

// opSweepScopes kills what a files op's scope still holds when the bastion
// died under it.
func opSweepScopes() {
	entries, _ := os.ReadDir(filepath.Join("/sys/fs/cgroup", opActionSlice))
	for _, e := range entries {
		if n := e.Name(); e.IsDir() && strings.HasPrefix(n, opScopeUnitPrefix) && strings.HasSuffix(n, ".scope") {
			opKillScope(strings.TrimSuffix(n, ".scope"))
		}
	}
}

// opSandboxCmd is the command that starts the sandbox: the sandbox's pid 1
// directly, or systemd-run making the scope it runs in.
func opSandboxCmd(ctx context.Context, self, specPath, unit string) *exec.Cmd {
	if unit == "" {
		cmd := exec.CommandContext(ctx, self, opSandboxSubcommand, specPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
			Setpgid:    true,
		}
		return cmd
	}
	cmd := exec.CommandContext(ctx, "systemd-run", opTasksScopeArgs(unit, self, specPath)...)
	// The scope is outside the bastion's own cgroup, so a bastion stopped or
	// restarted does not take it down: the scope's process dies with the
	// bastion instead (systemd-run execs it, which keeps the signal), and the
	// sandbox's pid 1 dies with that process.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	return cmd
}

// opRunSandboxCmd runs cmd on a thread held for the whole run: a parent-
// death signal is sent when the thread that started the child exits.
func opRunSandboxCmd(cmd *exec.Cmd) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return cmd.Run()
}

// opScopeTasks reads what the scope's process found its cgroup's pids.max to
// be: ok is false when the scope's process never ran.
func opScopeTasks(run string) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(run, opScopeTasksFile))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(raw)), true
}

// opOwnPidsMax reads pids.max of the cgroup this process is in.
func opOwnPidsMax() string {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "unreadable: " + err.Error()
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			v, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+p), "pids.max"))
			if err != nil {
				return "unreadable: " + err.Error()
			}
			return strings.TrimSpace(string(v))
		}
	}
	return "unreadable: no unified cgroup"
}

// opSandboxScopeMain is the scope's process: it records its cgroup's
// pids.max, then starts the sandbox's pid 1 and returns its exit.
func opSandboxScopeMain(specPath string) int {
	if err := os.WriteFile(filepath.Join(filepath.Dir(specPath), opScopeTasksFile), []byte(opOwnPidsMax()), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: cannot record the scope's task cap:", err)
		return 125
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		return 125
	}
	cmd := exec.Command(self, opSandboxSubcommand, specPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Pdeathsig:  syscall.SIGKILL,
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", opSandboxHelperEnv}
	return opExitOf(cmd.Run())
}

// opTasksNotCapped is the report's note for a root op whose tasks no cgroup
// held.
func opTasksNotCapped(why string) string {
	return "this root op's tasks were not capped: " + why
}

// opLastLine is the last line s holds, "" for none.
func opLastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
