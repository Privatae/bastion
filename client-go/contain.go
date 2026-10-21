package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Containment. The host directs the bastion to TERMINATE a detected agent via a heartbeat
// "contain" directive ([pids]); the bastion kills each pid that is currently a detected agent on
// this host, and REFUSES any pid that isn't — the host can only contain agents it observed, never
// an arbitrary process. Host-directed (the directive rides the authenticated mTLS heartbeat from
// the user's OWN host); the user containing activity on the user's own server. This is the surgical
// containment; revoking the bastion is the broad "cut the whole server's mesh reach" kill.
//
// Two refinements:
//
//   - Contain takes the agent's PROCESS TREE. An agent that spawned a shell, a
//     build, or a sub-agent left those running when only its own pid died —
//     the work it was doing carried on without it. The tree is frozen, re-walked
//     until it stops growing, and then killed (killtree.go), so a child forked
//     during the kill is caught too. The tree guard (containfinding.go
//     containGuard) spares init, this bastion, its own local agent, anything it
//     started, apps, and accounting entries — each with everything beneath it.
//   - An APP is refused. The Claude desktop app, an IDE, a browser: software
//     the user is running, observed because it talks to a model. The host
//     refuses to queue those too; this is the box's own line, held even if a
//     host asks.

// observedAgents is the scan the guard consults. A var so a test can stub it —
// the guard's whole job is a decision, and the decision must be testable
// without a live process tree underneath it.
// It returns the walk's error as well: a walk that FAILED is not an empty
// machine, and every consumer says so in its own place — the guard kills
// nothing and prints why, the sanction and policy pages banner it, the
// census records it instead of a clean pass.
var observedAgents = scanAgents

// processTree is the pid -> parent map contain walks; stubbed the same way.
var processTree = processParents

// killProcess is the one side effect, injectable so the decision can be
// tested without terminating anything.
var killProcess = func(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// pairing is the host whose heartbeat carried the directive. Killing a process
// is box-wide, not per-pairing: on an anchored machine only the anchor host may
// direct it (anchor.go anchorOnly). Every pairing still receives
// the agents list on its heartbeat (agents.go); a member host can see, but
// cannot terminate processes on someone else's machine — including an agent
// its own user started there, which is the stated cost: the anchor user is
// the one who kills on that box.
func maybeContain(pairing, dcnDir string, heartbeatResponse []byte) {
	var hb struct {
		Contain []int `json:"contain"`
	}
	if json.Unmarshal(heartbeatResponse, &hb) != nil || len(hb.Contain) == 0 {
		return
	}
	// directiveGate (writes.go): anchor-only, the local switch, then on an
	// anchored box an approval PER PID — `approvals["contain:<pid>"]`, bound
	// to that one pid. Per pid rather than per beat because orders are placed
	// one at a time and each carries its own approval; a beat naming two pids
	// is two acts. A pid without its approval is refused and reported; the
	// others proceed.
	// ONE scan for the whole directive (it walks every process and every
	// connection), taken BEFORE the gate so a remembered approval is checked
	// against the signature the pid wears NOW — a reused pid is a new act.
	observed := observedAgentMap()
	approved := hb.Contain[:0]
	refused := ""
	for _, p := range hb.Contain {
		pid := strconv.Itoa(p)
		sig := ""
		if a, ok := observed[p]; ok {
			sig = a.Signature
		}
		why := directiveGateFor(pairing, dcnDir, directiveContain, []string{pid},
			directiveApproval(heartbeatResponse, directiveContain+":"+pid), sig)
		if why != "" {
			fmt.Printf("contain pid %s: %s\n", pid, why)
			refused = why
			continue
		}
		approved = append(approved, p)
	}
	if refused != "" {
		// A containment the host believes it ordered and this box did not carry
		// out is the single worst thing to leave in a local log.
		recordDirectiveRefusal("contain", refused)
	} else {
		clearDirectiveRefusal("contain")
	}
	hb.Contain = approved
	if len(hb.Contain) == 0 {
		return
	}
	self := os.Getpid()
	// THE SAME TREE GUARD AS A FINDING STOP (containGuard): an agent's tree can
	// hold an accounting entry, an app, or something this bastion started, and
	// those are spared with everything beneath them. The accounting's pids come
	// from a fresh comparison when this box can make one; when it cannot (not
	// root, no accounting) the rest of the guard still holds.
	view, _ := processFindings()
	_, _, guard := containGuard(observed, view.protected)
	for _, pid := range hb.Contain {
		if pid <= 1 || pid == self {
			continue // never kill init or ourselves
		}
		a, ok := observed[pid]
		if !ok {
			continue // never a process we did not observe
		}
		if a.Kind == kindApp {
			fmt.Printf("contain: refused pid %d — %s is an app the user is running, not an agent\n", pid, a.Signature)
			// Recorded as well as printed. The host TRIED to close software the
			// user was sitting in front of, and this box said no on their behalf
			// — a line they should be able to read without having been watching
			// a console at the moment it scrolled past.
			recordLocalEvent(eventContain, hostPhrase(pairing)+" asked this machine to stop "+
				a.Signature+" (pid "+strconv.Itoa(pid)+"). It refused: that is an app you are "+
				"running, not an agent.")
			continue
		}
		// The tree is frozen and re-walked until it stops growing, then killed
		// (killtree.go), pruned at every protected process BENEATH the agent
		// (containGuard). The agent itself is not put through the guard: it
		// already passed the agent checks above, and an agent whose own
		// fingerprint is in the accounting (one running as a service, say)
		// would otherwise be spared in silence — killTree returns 0 for a
		// spared root and a zero kill is not recorded (review of #100).
		root := pid
		killed := killTree(pid, func(p int) bool {
			if p == root {
				return spareFromContain(p)
			}
			return guard(p)
		})
		if killed > 0 {
			fmt.Printf("contain: terminated agent pid %d and %d child process(es) (host-directed)\n", pid, killed-1)
			// The Printf stays — under systemd it is journald, which is a real
			// console that really does exist. What it is not is a record: it
			// scrolls, and on Windows after a self-update it has nowhere to go
			// at all (relaunch_windows.go:47). events.go keeps it.
			recordLocalEvent(eventContain, containSentence(pairing, a.Signature, pid, killed-1))
		}
		// killed == 0 is deliberately NOT recorded. killProcess is FindProcess +
		// Kill (above), so zero kills is overwhelmingly the benign race — the
		// agent exited between observedAgentMap() and the signal — and a
		// "could not stop your agent" line for a process that had already gone
		// would be a false alarm on the one surface that must never cry wolf.
	}
}

// hostPhrase names the host that directed this. An empty pairing is the
// unanchored LOCAL box with no pairing identity, which anchorOnly lets through
// (anchor.go:496-509, via unanchoredNetworkedRefusal). It must never render as
// "Your host  stopped", with the hole where the name goes.
func hostPhrase(pairing string) string {
	if pairing == "" {
		return "Your host"
	}
	return "Your host " + pairing
}

// containSentence writes the containment the way the page says it: no pids
// without a name beside them, and no "1 child process(es)". The wording lives
// here rather than in events.go because this is the only place that still holds
// the host, the signature and the count together.
func containSentence(pairing, signature string, pid, children int) string {
	s := hostPhrase(pairing) + " stopped " + signature + " (pid " + strconv.Itoa(pid) +
		") running on this machine"
	switch {
	case children == 0:
	case children == 1:
		s += ", and 1 other process it had started"
	default:
		s += ", and " + strconv.Itoa(children) + " other processes it had started"
	}
	return s + "."
}

// observedAgentMap is the snapshot the bastion would report on this beat,
// keyed by pid — the guard asks the SAME question the heartbeat answers,
// rather than re-deriving a narrower one. Two bugs fell out of that alignment:
// a /proc-only guard was inert on Windows and macOS, and a
// signature-only guard could never contain an observed "llm-client". A
// platform with no enumerator returns an empty map and contains nothing: a
// box that cannot see must not kill on belief.
func observedAgentMap() map[int]agentObs {
	out := map[int]agentObs{}
	agents, err := observedAgents()
	if err != nil {
		// Nothing observed, so nothing is killed: a box that cannot see must
		// not kill on belief. The host holds the order for a beat that can.
		fmt.Printf("contain: the process walk failed (%v) — nothing observed, nothing stopped\n", err)
		return out
	}
	for _, a := range agents {
		out[a.PID] = a
	}
	return out
}
