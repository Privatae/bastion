package main

import (
	"strconv"
	"strings"
)

// ORIGIN — the first phase of the agent-detection plane. Every observed
// process now says HOW IT WAS STARTED, walked from the parent map the plane
// already builds, and carries the typed evidence that produced every field.
//
// The name tables answer "which product is this". They cannot answer the
// question the headlines are about: an agent that has been running for months
// with nobody at the keyboard. That shape is "model traffic, a scheduler
// ancestor, no terminal" — and it needs no new table to see, only lineage.
//
//	interactive  a controlling terminal (Linux/macOS) or a logged-in session
//	             (Windows): a person is plausibly present.
//	remote       an ssh / mosh / screen-sharing ancestor: a person, elsewhere.
//	scheduler    cron, at, a systemd timer, a launchd interval job, the
//	             Windows Task Scheduler: it fired on a clock.
//	service      a daemon with no session: systemd unit, launchd daemon,
//	             a Windows service or session 0.
//	agent        started by a process that is itself an observed agent.
//	unknown      the box could not read enough to say. Never guessed.
//
// Nearest ancestor wins: a shell under sshd is remote even though it has a
// tty; an agent forked by an agent is `agent` even if the root was cron. The
// walk is over facts each platform supplies (procFacts); every rule with a
// decision in it lives here, under test, exactly like agents_parse.go.

const (
	originInteractive = "interactive"
	originRemote      = "remote"
	originScheduler   = "scheduler"
	originService     = "service"
	originAgent       = "agent"
	originUnknown     = "unknown"
)

// Evidence tiers mirror the local-inference tiers in agents.go: verified is
// read from this box's own state or an OS-flagged fact; known is a published
// default distinctive enough to stand alone; ambiguous annotates and never
// promotes.
const (
	tierVerified  = "verified"
	tierKnown     = "known"
	tierAmbiguous = "ambiguous"
)

// evidence is one typed reason on the wire. The host renders the list on the
// card; a reader sees exactly why a process is what it is.
type evidence struct {
	Signal string `json:"signal"`
	Tier   string `json:"tier"`
	Value  string `json:"value,omitempty"`
}

// procFacts is what a platform can say about one process without judgement.
// Comm is the executable's basename (binBase'd). Interactive is a controlling
// tty on Linux/macOS or a non-zero session on Windows. Unit is the systemd
// unit / launchd label / Windows service the process belongs to, when known.
type procFacts struct {
	PID         int
	PPID        int
	Comm        string
	Interactive bool
	Unit        string
	// Exe is the executable path AS THE PLATFORM'S ORIGIN SOURCE REPORTS IT,
	// and the three are not the same grade of fact: Linux reads the kernel's
	// link (readlink /proc/pid/exe, origin_linux.go:84), Windows takes
	// Toolhelp32's basename with no directory (origin_windows.go:50), and macOS
	// takes `ps -o comm=`, WHICH IS argv[0] — Apple's ps maps comm to
	// just_command (adv_cmds ps/keyword.c:101 → ps/print.c getproclline, whose
	// own comment skips the saved exec_path). This field was once described as
	// "macOS comm is a full path from the kernel"; it is usually a full path and
	// it is not from the kernel.
	//
	// So it is fit for what it is used for here — matching the launchd
	// scheduler inventory, where a wrong answer costs an origin label — and NOT
	// fit to be an identity. agentObs.Exe (agents.go) is the identity-grade
	// value, populated per platform by procExe.
	Exe string
	// Detail is what made Interactive true ("pts/3", "session 1"), for the
	// evidence line. Empty when not interactive.
	Detail string
}

// Ancestor executables that decide an origin outright. Basenames, compared
// after binBase(), so `crond`, `/usr/sbin/crond` and `cron.exe` all read once.
var (
	schedulerComms = map[string]bool{
		"cron": true, "crond": true, "anacron": true, "fcron": true,
		"atd": true, "at": true,
	}
	remoteComms = map[string]bool{
		"sshd": true, "sshd-session": true, "dropbear": true,
		"mosh-server": true, "screensharingd": true, "x11vnc": true, "vncserver": true,
		"tmate": true,
	}
	// Init-class parents: a process directly under one of these with no
	// session is a service. Linux systemd is pid 1; launchd is pid 1; on
	// Windows services.exe (and wininit.exe above it) play the part.
	initComms = map[string]bool{
		"systemd": true, "init": true, "launchd": true,
		"services": true, "wininit": true,
	}
)

// maxOriginHops bounds the ancestor walk. Real trees are shallow; a chain
// this long is a corrupt parent map and the walk stops rather than loops.
const maxOriginHops = 32

// originExtra lets a platform add signals the shared walk cannot see: the pid
// of the Windows Task Scheduler's svchost, a systemd unit known to be
// timer-activated. Both are answered from facts collected once per scan.
type originExtra struct {
	// SchedulerPIDs: processes that ARE the scheduler on this box even though
	// their basename is generic (svchost.exe hosting Schedule).
	SchedulerPIDs map[int]bool
	// TimerUnits: systemd .service units a .timer activates (unit -> timer).
	TimerUnits map[string]string
	// ScheduledExes: executables the scheduler inventory would start on a
	// clock (exe path -> job name). launchd is the parent of everything on
	// macOS, so an interval job is told apart from a daemon only this way.
	ScheduledExes map[string]string
}

// classifyOrigin walks from pid to the root and returns the origin plus the
// evidence that decided it. facts answers for any pid it can read; observed
// is the set of pids the same scan classified as agents (kind agent or
// automation), so a child of one reads as `agent`.
func classifyOrigin(pid int, facts func(int) (procFacts, bool), observed map[int]bool, extra originExtra) (string, []evidence) {
	self, ok := facts(pid)
	if !ok {
		return originUnknown, []evidence{{Signal: "origin", Tier: tierAmbiguous, Value: "process facts unreadable"}}
	}
	// The process's own unit can settle "scheduler" before any walk: a
	// systemd service that a timer activates fired on a clock, whatever its
	// parent chain looks like (systemd is the parent of everything).
	if self.Unit != "" {
		if timer, ok := extra.TimerUnits[self.Unit]; ok {
			return originScheduler, []evidence{{Signal: "systemd-timer", Tier: tierVerified, Value: timer + " → " + self.Unit}}
		}
	}
	seen := map[int]bool{pid: true}
	cur := self
	for hops := 0; hops < maxOriginHops; hops++ {
		pp := cur.PPID
		if pp <= 0 || seen[pp] {
			break
		}
		seen[pp] = true
		if observed[pp] {
			return originAgent, []evidence{{Signal: "parent-agent", Tier: tierVerified, Value: "pid " + strconv.Itoa(pp)}}
		}
		if extra.SchedulerPIDs[pp] {
			return originScheduler, []evidence{{Signal: "task-scheduler", Tier: tierVerified, Value: "pid " + strconv.Itoa(pp)}}
		}
		pf, ok := facts(pp)
		if !ok {
			break // unreadable ancestor: decide from what we hold
		}
		if schedulerComms[pf.Comm] {
			return originScheduler, []evidence{{Signal: "scheduler-parent", Tier: tierVerified, Value: pf.Comm + " pid " + strconv.Itoa(pp)}}
		}
		if remoteComms[pf.Comm] {
			return originRemote, []evidence{{Signal: "remote-parent", Tier: tierVerified, Value: pf.Comm + " pid " + strconv.Itoa(pp)}}
		}
		if initComms[pf.Comm] || pp == 1 {
			// Directly under init with no session of its own: a service. With
			// a session it is an interactive login that init spawned (a
			// display manager's shell, a launchd user agent with a tty), and
			// the interactive rule below answers.
			if !self.Interactive {
				// launchd is the parent of everything on macOS, so an interval
				// job is told from a daemon only by its executable matching the
				// inventory. Tiered `known`: one interpreter can serve two jobs.
				if job, ok := scheduledJobFor(self, extra); ok {
					return originScheduler, []evidence{{Signal: "scheduled-job", Tier: tierKnown, Value: job}}
				}
				ev := evidence{Signal: "service-parent", Tier: tierVerified, Value: pf.Comm + " pid " + strconv.Itoa(pp)}
				if self.Unit != "" {
					ev.Value = self.Unit
				}
				return originService, []evidence{ev}
			}
			break
		}
		cur = pf
	}
	if self.Interactive {
		return originInteractive, []evidence{{Signal: "session", Tier: tierVerified, Value: self.Detail}}
	}
	if job, ok := scheduledJobFor(self, extra); ok {
		return originScheduler, []evidence{{Signal: "scheduled-job", Tier: tierKnown, Value: job}}
	}
	if self.Unit != "" {
		return originService, []evidence{{Signal: "unit", Tier: tierVerified, Value: self.Unit}}
	}
	return originUnknown, []evidence{{Signal: "origin", Tier: tierAmbiguous, Value: "no session, no unit, no known ancestor"}}
}

// signatureEvidence is the evidence line for the signal that put a process
// in the report in the first place. A name-table hit is `known`: distinctive,
// but a name is something a process chooses.
func signatureEvidence(a agentObs) evidence {
	switch a.Kind {
	case kindClient:
		return evidence{Signal: "model-traffic", Tier: tierVerified, Value: joinMax(a.LLMEndpoints, 3)}
	case kindApp:
		return evidence{Signal: "app-signature", Tier: tierKnown, Value: a.Signature}
	case kindAutomation:
		return evidence{Signal: "automation-signature", Tier: tierKnown, Value: a.Signature}
	}
	return evidence{Signal: "agent-signature", Tier: tierKnown, Value: a.Signature}
}

// endpointEvidence adds one line per classified endpoint. A cloud host or a
// verified/known local port is verified traffic; a "?"-suffixed ambiguous
// port stays ambiguous, exactly as classifyConn labelled it.
func endpointEvidence(eps []string) []evidence {
	out := make([]evidence, 0, len(eps))
	for _, e := range eps {
		tier := tierVerified
		if len(e) >= 2 && e[len(e)-2:] == "?)" {
			tier = tierAmbiguous
		}
		out = append(out, evidence{Signal: "model-endpoint", Tier: tier, Value: e})
	}
	return out
}

func joinMax(s []string, n int) string {
	if len(s) == 0 {
		return ""
	}
	out := ""
	for i, v := range s {
		if i == n {
			out += ", …"
			break
		}
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

// scheduledJobFor: the inventory job whose executable this non-interactive
// process runs, if any. Consulted only once the ancestor walk has found no
// stronger answer (an observed parent agent, a scheduler or remote ancestor).
func scheduledJobFor(f procFacts, extra originExtra) (string, bool) {
	if f.Exe == "" || f.Interactive {
		return "", false
	}
	job, ok := extra.ScheduledExes[strings.ToLower(f.Exe)]
	return job, ok
}
