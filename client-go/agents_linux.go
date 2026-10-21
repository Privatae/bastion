//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// Linux enumeration for the observe plane: /proc for processes and their
// environment, `ss` for established connections (it does the inode->pid
// mapping we would otherwise have to rebuild by hand).
//
// This is the original implementation, moved out of agents.go unchanged in
// behaviour when the plane grew macOS and Windows siblings.

const (
	agentScanSupported = true
	agentScanKind      = "proc+ss"
)

// scanProcesses walks /proc and returns the agent processes (process signal),
// keyed by pid. An error is a walk that did not happen — not an empty box —
// and the heartbeat withholds `agents` for it rather than send a list nothing
// measured.
//
// procRoot is "/proc"; a test points it at a directory that is not there to
// prove this enumerator's own failure path returns an error, not an empty map.
var procRoot = "/proc"

func scanProcesses() (map[int]agentObs, error) {
	out := map[int]agentObs{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", procRoot, err)
	}
	self := os.Getpid()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue
		}
		argv := splitNul(raw)
		sig, auto, ok := matchSignature(argv)
		if !ok {
			continue
		}
		full := strings.Join(argv, " ")
		out[pid] = agentObs{PID: pid, User: procUser(pid), Signature: sig,
			Cmdline: truncate(full, 200), Exe: procExe(pid),
			DelegationToken: procEnvToken(pid), raw: full, automation: auto}
	}
	return out, nil
}

// scanMCPProcesses is the process list mcpconfig.go correlates declared tool
// servers against: every process, with its parent and command line, from one
// /proc walk. The want set only matters on Windows, where reading a command
// line costs a handle per process. An error is a walk that did not happen,
// and then no running state is guessed.
func scanMCPProcesses(want map[string]bool) ([]mcpProc, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", procRoot, err)
	}
	self := os.Getpid()
	var out []mcpProc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self || !e.IsDir() {
			continue
		}
		p := mcpProc{PID: pid}
		if raw, err := os.ReadFile(procRoot + "/" + e.Name() + "/stat"); err == nil {
			p.PPID = parseProcStatPPID(string(raw))
		}
		if raw, err := os.ReadFile(procRoot + "/" + e.Name() + "/cmdline"); err == nil {
			p.Argv = splitNul(raw)
		}
		out = append(out, p)
	}
	return out, nil
}

// procParent reads one process's parent pid from /proc/<pid>/stat.
func procParent(pid int) int {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	return parseProcStatPPID(string(raw))
}

// processParents is the whole pid -> parent map, one /proc walk. Contain uses
// it to take an agent's descendants along with it.
func processParents() map[int]int {
	out := map[int]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pp := procParent(pid); pp > 0 {
			out[pid] = pp
		}
	}
	return out
}

// scanConnections returns established outbound TCP with the owning pid, via `ss`
// (it does the inode->pid mapping). Best-effort: if ss is absent it returns
// empty and the process signal still stands.
func scanConnections() []connObs {
	data, err := exec.Command("ss", "-tnpH", "state", "established").Output()
	if err != nil {
		return []connObs{}
	}
	return parseSSOutput(string(data), os.Getpid())
}

func procUser(pid int) string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if u, err := user.LookupId(f[1]); err == nil {
					return u.Username
				}
				return f[1]
			}
		}
	}
	return ""
}

// ownerFactsReader answers, per process, the three facts about its owner that
// agentowner.go decides on. The machine-wide tables (/etc/passwd, /etc/group,
// login.defs, nsswitch.conf, the sudo rules, who is logged in) are read once
// per scan, on first use, and every process looks itself up in them.
//
// The uid and groups come from /proc/<pid>/status, so they are what the
// PROCESS holds, the same source procUser names it from.
func ownerFactsReader() func(pid int, user string) ownerFacts {
	var (
		loaded      bool
		groupNames  map[int]string
		groupsOK    bool
		passwd      map[int]bool
		passwdOK    bool
		sysMax      int
		directory   bool
		sudoers     map[string]bool
		sudoKnown   bool
		sessions    map[string]bool
		sessionsOK  bool
		logindUsers = identityPath("/run/systemd/users")
	)
	load := func() {
		loaded = true
		if b, err := os.ReadFile(identityPath("/etc/group")); err == nil {
			groupNames, groupsOK = parseGroupNames(string(b)), true
		}
		if b, err := os.ReadFile(identityPath("/etc/passwd")); err == nil {
			passwd, passwdOK = parsePasswdUIDs(string(b)), true
		}
		sysMax = linuxSystemUIDMax
		if b, err := os.ReadFile(identityPath("/etc/login.defs")); err == nil {
			sysMax = parseLoginDefsSysMax(string(b))
		}
		if b, err := os.ReadFile(identityPath("/etc/nsswitch.conf")); err == nil {
			directory = nsswitchHasDirectory(string(b))
		}
		var partial string
		sudoers, partial = sudoPrincipals()
		sudoKnown = partial == ""
		// Who has a session: logind's own record when it runs, else utmp.
		// Neither readable leaves the answer unknown rather than "nobody".
		if _, err := os.Stat(logindUsers); err != nil {
			if b, err := os.ReadFile(identityPath("/var/run/utmp")); err == nil {
				sessions, sessionsOK = parseUtmpUsers(b), true
			}
		}
	}
	return func(pid int, user string) ownerFacts {
		if !loaded {
			load()
		}
		raw, err := os.ReadFile(procRoot + "/" + strconv.Itoa(pid) + "/status")
		if err != nil {
			return unknownOwner
		}
		realUID, effUID, gids, ok := parseStatusIDs(string(raw))
		if !ok {
			return unknownOwner
		}
		o := unixOwner{UID: realUID, Name: user, LocalRecord: ownerUnknown, DirectorySource: directory,
			SystemUIDMax: sysMax, AdminGroups: linuxAdminGroups, SudoApplies: true,
			SudoNamed: sudoers[user], SudoKnown: sudoKnown}
		if passwdOK {
			o.LocalRecord = yesNo(passwd[realUID])
		}
		if groupsOK {
			o.GroupsKnown = true
			for _, g := range gids {
				if n, ok := groupNames[g]; ok {
					o.Groups = append(o.Groups, n)
				}
			}
		}
		switch {
		case sessionsOK:
			o.Sessions, o.SessionsKnown = sessions, true
		default:
			b, err := os.ReadFile(logindUsers + "/" + strconv.Itoa(realUID))
			switch {
			case err == nil:
				if live, ok := parseLogindUserState(string(b)); ok {
					o.Sessions, o.SessionsKnown = map[string]bool{user: live}, true
				}
			case os.IsNotExist(err):
				// logind keeps a file for every user it tracks; none means
				// this account has no session and no lingering services.
				if _, derr := os.Stat(logindUsers); derr == nil {
					o.Sessions, o.SessionsKnown = map[string]bool{}, true
				}
			}
		}
		f := classifyUnixOwner(o)
		if effUID == 0 {
			// A process running with effective uid 0 holds root whatever
			// account started it: that is the administrator answer that
			// matters, while the class stays the account's own.
			f.Admin = ownerYes
		}
		return f
	}
}

func procCmdline(pid int) string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	return truncate(strings.Join(splitNul(raw), " "), 200)
}

// procExe is the KERNEL's record of which file this process runs:
// /proc/<pid>/exe, a link the kernel maintains from the vnode and the process
// cannot rewrite. The strongest of the three platforms — it is RESOLVED, so a
// symlinked launcher reports its target (measured here: a `#!/bin/bash` script
// reported /usr/bin/bash, not the /bin/bash its own argv[0] said).
//
// Unreadable yields "" — another user's process without the capability, a
// hardened kernel — the same conservative outcome as procEnvToken above, and
// sanction.go refuses to mark an observation with no path rather than falling
// back to the command line.
func procExe(pid int) string {
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return sanitizeExePath(exe)
}

// procEnvToken reads the host-issued delegation tag (PRIVATAE_AGENT_TOKEN, or
// its older name; see agentTokenEnvNames) from an agent's env, if set.
// Unreadable (another user's process, hardened kernel) yields "" — the same
// conservative outcome as an agent that genuinely carries no tag.
func procEnvToken(pid int) string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return ""
	}
	for _, name := range agentTokenEnvNames {
		if tok := parseEnvToken(raw, name); tok != "" {
			return tok
		}
	}
	return ""
}
