//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// macOS enumeration for the observe plane.
//
// Both enumerators shell out, exactly as the Linux side already does for `ss`:
// `ps` for processes and `lsof` for established connections. Both ship with
// every macOS install, and their output is stable and parseable — the parsers
// below are pure functions, unit-tested from any OS with captured fixtures,
// which is the only way this code gets tested at all in a Linux CI.
//
// Not used FOR ARGV AND THE ENVIRONMENT: sysctl KERN_PROCARGS2. It would give
// both in one syscall, but that use needs the whole layout — including the '='
// heuristic Apple's own ps calls a guess — and on a SIP-hardened machine the
// environment half is refused for exactly the processes worth reading. A
// shell-out that works everywhere beats a syscall that works sometimes, for a
// signal explicitly documented as soft.
//
// It IS used for one thing, and the exception is narrow on purpose: procExe
// reads the single null-terminated string the kernel writes at the front of
// that blob, which is the executable path and the only value here a process
// cannot choose for itself. `ps` cannot answer that question at all — it skips
// that string by design — so there was no shell-out to prefer. See procExe.

const (
	agentScanSupported = true
	agentScanKind      = "ps+lsof"
)

// psCache holds the whole `ps` sweep from the current scan so the per-pid
// lookups the shared code makes for a connection-only process cost nothing
// extra. Refreshed by scanProcesses, which always runs first in scanAgents.
var psCache = struct {
	sync.Mutex
	user   map[int]string
	args   map[int]string
	parent map[int]int
}{user: map[int]string{}, args: map[int]string{}, parent: map[int]int{}}

// psSweep runs the one `ps` this plane needs and parses it. ppid rides in the
// same call so the parent map costs no second process spawn.
func psSweep() (map[int]string, map[int][]string, map[int]int, error) {
	data, err := exec.Command("ps", "-axo", "pid=,ppid=,user=,args=").Output()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ps sweep: %w", err)
	}
	users, argvs, parents := parsePSOutput(string(data))
	if len(users) == 0 {
		// ps lists at least itself; nothing parsed is output this code could
		// not read, not an empty machine.
		return nil, nil, nil, errors.New("ps sweep: no processes parsed")
	}
	return users, argvs, parents, nil
}

// scanProcesses: an error is a sweep that did not happen, never an empty box;
// the heartbeat withholds `agents` for it.
func scanProcesses() (map[int]agentObs, error) {
	out := map[int]agentObs{}
	users, argvs, parents, err := psSweep()
	if err != nil {
		return nil, err
	}
	self := os.Getpid()

	psCache.Lock()
	psCache.user = users
	psCache.parent = parents
	psCache.args = map[int]string{}
	for pid, argv := range argvs {
		psCache.args[pid] = strings.Join(argv, " ")
	}
	psCache.Unlock()

	for pid, argv := range argvs {
		if pid == self {
			continue
		}
		sig, auto, ok := matchSignature(argv)
		if !ok {
			continue
		}
		full := strings.Join(argv, " ")
		out[pid] = agentObs{PID: pid, User: users[pid], Signature: sig,
			Cmdline: truncate(full, 200), Exe: procExe(pid),
			DelegationToken: procEnvToken(pid), raw: full, automation: auto}
	}
	return out, nil
}

// procParent answers from the sweep scanProcesses just took.
func procParent(pid int) int {
	psCache.Lock()
	defer psCache.Unlock()
	return psCache.parent[pid]
}

// processParents takes a FRESH sweep: contain must walk the tree as it is
// now, not as it was when the heartbeat was built.
func processParents() map[int]int {
	_, _, parents, err := psSweep()
	ok := err == nil
	if !ok {
		return map[int]int{}
	}
	return parents
}

func scanConnections() []connObs {
	// -n/-P: no DNS or service-name lookups (fast, and never blocks a beat on
	// a slow resolver). -Fpn: machine-readable pid + name fields only.
	data, err := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-Fpn").Output()
	if err != nil && len(data) == 0 {
		// lsof exits non-zero when some file is unreadable while still printing
		// the rest; only a truly empty result is a failure.
		return []connObs{}
	}
	return parseLsofOutput(string(data), os.Getpid())
}

func procUser(pid int) string {
	psCache.Lock()
	defer psCache.Unlock()
	return psCache.user[pid]
}

func procCmdline(pid int) string {
	psCache.Lock()
	c := psCache.args[pid]
	psCache.Unlock()
	if c != "" {
		return truncate(c, 200)
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "args=").Output()
	if err != nil {
		return ""
	}
	return truncate(strings.TrimSpace(string(out)), 200)
}

// procExe is the KERNEL's record of which file this process runs, read out of
// KERN_PROCARGS2 and decoded by parseProcargs2ExePath (agents_parse.go).
//
// NOT `ps -o comm=`, and that correction is the point of this function.
//
// Three comments in this tree said comm was the executable path from the
// kernel — origin_darwin.go's header, origin.go's procFacts.Exe, and
// sanction.go's list of what each platform supplies. It is argv[0]. Apple's ps
// maps the `comm` keyword to just_command (adv_cmds ps/keyword.c:101), which
// calls getproclline (ps/print.c:115), and getproclline's own comment is
// "/* Skip the saved exec_path. */" immediately before it starts copying at
// argv[0]. So `ps -o comm=` on macOS is a string the launcher chose, which is
// precisely what a sanction must stop being keyed on. All three comments now
// say what it is, and each records what it used to claim, so the next person
// does not re-derive the wrong answer from a plausible-sounding man page.
//
// WHY THE SYSCTL THIS FILE'S HEADER REJECTED. The header rejects
// KERN_PROCARGS2 for argv AND THE ENVIRONMENT: that use needs the whole
// layout, including the '=' heuristic ps itself calls a guess, and the env half
// is what SIP withholds. This reads ONE null-terminated string at a fixed
// offset — the prefix the kernel writes before anything else. It also adds no
// failure mode the file did not already have: `ps -axo args=` IS this sysctl
// (getproclline again), so every process whose command line the sweep above
// could read is one this can read, and every process it could not is one where
// ps already printed "(comm)" in parentheses instead of a command.
//
// Refused (another user's process without root — xnu bsd/kern/kern_sysctl.c
// sysctl_procargsx checks uid against the caller's) yields "", the same
// conservative outcome as procEnvToken below.
//
// The whole blob is read, never a bounded window: when the buffer is smaller
// than the argument area the kernel copies out its TAIL, not its head
// (sysctl_procargsx, the `buflen < argslen` branch), so a cheap short read
// would return the end of the environment and this would parse rubbish. The
// cost is bounded by what ps already pays for every process on the box.
func procExe(pid int) string {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return ""
	}
	return parseProcargs2ExePath(buf)
}

// procEnvToken reads the host-issued delegation tag (PRIVATAE_AGENT_TOKEN) via
// `ps -E`, which appends the environment to the command.
//
// Best-effort by nature: macOS only discloses another process's environment to
// the same user (and SIP withholds it for protected binaries regardless), so
// this is often empty. That is the SAME conservative outcome as Linux when
// /proc/PID/environ is unreadable — an agent with no readable tag reads as
// unrequested, which surfaces it to the user rather than hiding it.
func procEnvToken(pid int) string {
	out, err := exec.Command("ps", "-Eww", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return ""
	}
	for _, name := range agentTokenEnvNames {
		if tok := parseEnvTokenSpaced(string(out), name); tok != "" {
			return tok
		}
	}
	return ""
}
