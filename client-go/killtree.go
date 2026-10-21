package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Killing a process TREE, not a pid and a snapshot of its children.
//
// The first version took one parent map, then killed the root and every
// descendant in it. Two things escaped that: a child forked between the
// snapshot and the signal (the agent was still running while its tree was being
// read), and anything a victim forked while its own parent was being killed. An
// agent that notices it is being stopped has exactly that window.
//
// So the tree is FROZEN first, then killed. Freezing (SIGSTOP on unix) is the
// part that closes the window: a stopped process cannot fork. Each round walks
// the tree again, freezes whatever it has not seen, and the walk repeats until a
// round finds nothing new — every process that could still create another one
// is stopped by then. Only then is anything killed, so no victim is ever
// reparented to init while still running (the kill order no longer matters).
//
// This is the stop-then-kill approach every supervisor without a cgroup
// uses; cgroup.kill would be stronger on Linux, but it needs the tree to have
// been STARTED inside a cgroup this process owns, and the bastion is stopping
// software it did not start. No maintained Go library does a cross-platform
// "kill this existing tree until it is gone" (checked 2026-09-23: gopsutil walks
// and signals but has no tree kill; the small tree-kill packages have no users),
// so it is written here over the process walk this package already has.
//
// Windows has no SIGSTOP. There the rounds kill as they go, which still
// catches a child forked during the kill on the next walk, because Windows keeps
// the parent pid of an orphan (processParents validates it against creation
// time so a recycled pid is never read as a parent).
//
// WHAT THIS STILL CANNOT REACH, named rather than implied: a process that left
// the tree BEFORE the order arrived (a daemon that double-forked and was
// reparented to init) has no parent link to follow. It is not lost, it is a
// separate thing: it shows up in the delta as its own proc_new finding, and
// containFindings (containfinding.go) can stop it by its fingerprint.
//
// THE PROCESSES ABOVE THE ROOT ARE NOT IN THE TREE, BUT THE FREEZE CAN STILL
// REACH THEM. sudo and su stop THEMSELVES when the child they are waiting on
// is stopped (that is how job control keeps working through them), and stay
// stopped until something continues them; under a terminal the stop is relayed
// a hop further, from sudo's monitor process to sudo itself and on to the
// terminal wrapper. Our SIGSTOP on the agent does exactly that to such a chain,
// and the kill that follows never wakes it: the agent dies, its parent is still
// stopped, so it never collects the exit — the agent lingers as a zombie under
// a parent that hangs for ever, and anything asking whether that pid is gone is
// told it is not. Measured on an agent started as `sudo -u <user> <agent>`:
// sudo `T`, agent `Z`, until someone sent sudo SIGCONT by hand. A plain shell
// does not relay a stop; it is read and left alone.
//
// So the root's ancestors are read BEFORE the first freeze, and after the kill
// every one that was running then and is stopped now, under the same identity,
// is resumed (thawRelayingAncestors). One somebody stopped on purpose, or a
// number that has changed hands, is left alone. They ride in the frozen-set
// journal too, from the first freeze on, so a bastion that dies between the
// freeze and the thaw continues them on its next start. Where a process's state
// cannot be read (procidentity
// for that platform answers "unknown"), no ancestor is recorded and the thaw
// does nothing.

// killTreeMaxRounds bounds the walk. A tree that is still growing after this
// many frozen rounds is being grown by something outside it; the kill proceeds
// with what was found rather than looping for ever.
const killTreeMaxRounds = 8

// stopProcess and resumeProcess are the freeze. Side effects, injectable for the
// same reason killProcess is (contain.go): the decision must be testable
// without signalling anything. TestMain replaces both with no-ops so no test
// that stubs only killProcess can stop a real process.
var (
	stopProcess   = osStopProcess
	resumeProcess = osResumeProcess
)

// procIdentity is what makes a pid mean one process: its start time as the
// kernel records it, and whether it is already stopped. ok=false where the
// platform cannot say (then nothing is compared and the kill proceeds as it
// did before identities existed). Injectable like the signals.
var procIdentity = osProcIdentity

// killTree freezes and then kills root and every descendant of it.
//
// `spare` PRUNES: a spared process is not signalled AND nothing beneath it is
// walked. The tree kill used to test only the root, so stopping a finding
// took everything under it — a replaced sshd took every ssh session with it,
// accounting entries included, which is exactly what the guards on the root
// exist to refuse (review of #100). Killing a parent does not kill its
// children, so a spared subtree simply survives, re-parented.
//
// A PID IS NOT A PROCESS. Each pid's identity is read before it is stopped and
// again after: a different process under the same number (the original exited
// and the number was reused) is resumed at once and left alone. It is read
// once more before the kill, so a process that died while frozen cannot hand
// its number to a stranger that is then killed. A process that was ALREADY
// stopped when we found it is killed with the tree but never resumed by us —
// someone else stopped it, deliberately.
//
// The frozen set is written down before the kill (killTreeJournal) and removed
// after, so a bastion that dies between freeze and kill thaws what it froze on
// its next start (recoverFrozenTrees) instead of leaving it stopped for ever.
//
// It returns how many processes the kill reached, the root included.
func killTree(root int, spare func(int) bool) int { return killTreeExpect(root, spare, "") }

// killTreeExpect is killTree for a root whose identity was read when it was
// chosen (the finding walk): if the pid no longer carries that identity, the
// number has changed hands since and nothing is signalled. That closes the gap
// between choosing the root and the first read inside the kill (review of #100).
func killTreeExpect(root int, spare func(int) bool, rootID string) int {
	if spare(root) {
		return 0
	}
	if rootID != "" {
		if id, _, ok := procIdentity(root); ok && id != rootID {
			return 0
		}
	}
	type frozenProc struct {
		id         string
		wasStopped bool
	}
	seen := map[int]bool{}
	order := []int{}
	frozen := map[int]frozenProc{}
	journal := []frozenEntry{}
	killed := 0
	// The root's ANCESTORS, read BEFORE anything is frozen: whether each was
	// already stopped then is what decides, after the kill, whether a stop we
	// caused is undone (thawRelayingAncestors). Read on the first walk only —
	// the root's ancestry does not change while the root is alive. They go into
	// the journal WITH THE FIRST FREEZE, not before it: a relayed stop cannot
	// begin until our SIGSTOP lands, and a journal holding a running process we
	// never signalled would let a restart continue a stop the user made
	// themselves in the meantime. So a bastion that dies between the freeze and
	// the thaw continues them on its next start like anything else it stopped,
	// and one that dies before the first freeze has nothing to continue.
	var ancestors []relayingAncestor
	ancestorsJournalled := false
	for round := 0; round < killTreeMaxRounds; round++ {
		parents := processTree()
		if round == 0 && freezeSupported {
			ancestors = readRelayingAncestors(parents, root)
		}
		grew := false
		for _, pid := range append([]int{root}, descendantsPruned(parents, root, spare)...) {
			if seen[pid] || spare(pid) {
				continue
			}
			seen[pid] = true
			grew = true
			id0, stopped0, known := procIdentity(pid)
			if !freezeSupported {
				// No freeze on this platform: kill as found, and let the next
				// walk pick up anything forked in the meantime.
				if known {
					if id, _, ok := procIdentity(pid); ok && id != id0 {
						continue
					}
				}
				if killProcess(pid) == nil {
					killed++
				}
				continue
			}
			if stopProcess(pid) != nil {
				continue
			}
			if known {
				if id1, _, ok := procIdentity(pid); !ok || id1 != id0 {
					// Stopped a stranger: the number changed hands between the
					// read and the signal. Undo at once, and never kill it.
					_ = resumeProcess(pid)
					continue
				}
			}
			order = append(order, pid)
			frozen[pid] = frozenProc{id: id0, wasStopped: stopped0}
			if !stopped0 {
				// Journalled AS it is frozen, not after every round: a bastion
				// that dies mid-freeze still leaves a record of what it stopped.
				// The ancestors ride in the first such write (see above).
				if !ancestorsJournalled {
					for _, a := range ancestors {
						journal = append(journal, frozenEntry{PID: a.pid, ID: a.id})
					}
					ancestorsJournalled = true
				}
				journal = append(journal, frozenEntry{PID: pid, ID: id0})
				killTreeJournalWrite(journal)
			}
		}
		if !grew {
			break
		}
	}
	if !freezeSupported {
		return killed
	}
	for _, pid := range order {
		f := frozen[pid]
		if f.id != "" {
			if id, _, ok := procIdentity(pid); ok && id != f.id {
				continue // gone while frozen; the number is someone else's now
			}
		}
		if killProcess(pid) == nil {
			killed++
		} else if !f.wasStopped {
			// A process we stopped and then could not kill must not be left
			// stopped: that would be a hang this box caused, reported as nothing.
			_ = resumeProcess(pid)
		}
	}
	thawRelayingAncestors(ancestors)
	killTreeJournalWrite(nil)
	return killed
}

// relayingAncestor is a process above the root that was RUNNING when the kill
// began, with the identity it had then. Only those can have been stopped by
// our freeze; an ancestor already stopped at the start is someone else's
// decision and is not recorded.
type relayingAncestor struct {
	pid int
	id  string
}

// ancestorThawDepth bounds the walk upward. The stop is relayed one hop at a
// time (sudo's monitor to sudo, sudo to the terminal wrapper); a few hops
// cover every launch shape seen, and init is never reached.
const ancestorThawDepth = 8

// readRelayingAncestors walks from the root's parent upward through the parent
// map, nearest first, and records each running ancestor whose identity can be
// read. It stops at init, at this bastion, at an unknown pid, at an ancestor
// that is already stopped (nothing above it can be relaying OUR stop through a
// process that was not running), and at a cycle.
func readRelayingAncestors(parents map[int]int, root int) []relayingAncestor {
	out := []relayingAncestor{}
	seen := map[int]bool{root: true}
	pid := parents[root]
	for hop := 0; hop < ancestorThawDepth; hop++ {
		if pid <= 1 || pid == os.Getpid() || seen[pid] {
			return out
		}
		seen[pid] = true
		id, stopped, ok := procIdentity(pid)
		if !ok || id == "" || stopped {
			return out
		}
		out = append(out, relayingAncestor{pid: pid, id: id})
		pid = parents[pid]
	}
	return out
}

// ancestorThawChecks and ancestorThawWait bound how long the kill waits for an
// ancestor to show the stop it relays. Each relays on its child's stop
// NOTIFICATION, which can land a moment after our signal and a hop later for
// each level, so one read straight after the kill can miss it. An ancestor that
// never follows (almost every root has a running parent) costs each tree kill
// (checks − 1) × wait, a quarter of a second; a containment of several pids
// pays it once per pid, on a heartbeat measured in tens of seconds. The wait is
// a variable so the tests do not sleep.
const ancestorThawChecks = 6

var ancestorThawWait = func() { time.Sleep(50 * time.Millisecond) }

// thawRelayingAncestors resumes every recorded ancestor that is stopped now,
// under the identity it had before the first freeze (the header names the
// mechanism). A number that has changed hands belongs to a stranger and is
// dropped. Rounds end as soon as nothing is left to watch.
func thawRelayingAncestors(ancestors []relayingAncestor) {
	pending := append([]relayingAncestor(nil), ancestors...)
	for i := 0; i < ancestorThawChecks && len(pending) > 0; i++ {
		if i > 0 {
			ancestorThawWait()
		}
		still := pending[:0]
		for _, a := range pending {
			id, stopped, ok := procIdentity(a.pid)
			if !ok || id != a.id {
				continue
			}
			if stopped {
				_ = resumeProcess(a.pid)
				continue
			}
			still = append(still, a)
		}
		pending = still
	}
}

// descendantsPruned is descendantsOf that does not walk below a spared pid.
func descendantsPruned(parents map[int]int, root int, spare func(int) bool) []int {
	children := map[int][]int{}
	for pid, pp := range parents {
		if pp > 0 && pid != pp {
			children[pp] = append(children[pp], pid)
		}
	}
	seen := map[int]bool{root: true}
	out := []int{}
	queue := []int{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[cur] {
			if seen[c] {
				continue
			}
			seen[c] = true
			if spare(c) {
				continue // neither it nor anything beneath it
			}
			out = append(out, c)
			queue = append(queue, c)
		}
	}
	return out
}

// spareFromContain is the set no containment may touch: init, this bastion, and
// the local agent it launched itself.
func spareFromContain(pid int) bool {
	return pid <= 1 || pid == os.Getpid() || faIsOwnChild(pid)
}

// ── the frozen-set journal ───────────────────────────────────────────────────

type frozenEntry struct {
	PID int    `json:"pid"`
	ID  string `json:"id"`
}

func killTreeJournalPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "killtree-frozen.json"), nil
}

// killTreeJournalWrite records the processes this box has frozen and not yet
// killed; nil removes the record. Best-effort: failing to write it must not
// stop a kill the host ordered.
var killTreeJournalWrite = func(entries []frozenEntry) {
	p, err := killTreeJournalPath()
	if err != nil {
		return
	}
	if len(entries) == 0 {
		_ = os.Remove(p)
		return
	}
	if b, err := json.Marshal(entries); err == nil {
		_ = atomicWrite(p, b) // temp + rename: a crash mid-write never leaves half a record
	}
}

// recoverFrozenTrees thaws anything a previous run froze and did not get to
// kill (it died mid-kill: a crash, an OOM, a self-update restart). Only a pid
// whose identity still matches AND that is still stopped is resumed, so a
// number reused since is never touched. Called once at daemon start.
func recoverFrozenTrees() {
	p, err := killTreeJournalPath()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var entries []frozenEntry
	if json.Unmarshal(raw, &entries) == nil {
		for _, e := range entries {
			if id, stopped, ok := procIdentity(e.PID); ok && id == e.ID && stopped {
				_ = resumeProcess(e.PID)
			}
		}
	}
	_ = os.Remove(p)
}
