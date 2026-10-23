package main

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// killTreeRig stubs the three side effects and the walk, and records the
// order of every signal, so a test can assert "nothing was killed until
// everything was frozen" rather than only the final set.
type killTreeRig struct {
	walks   []map[int]int // one map per processTree() call; the last repeats
	calls   int
	log     []sig
	failKil map[int]bool
}

type sig struct {
	kind string
	pid  int
}

func (r *killTreeRig) install(t *testing.T) {
	t.Helper()
	prevTree, prevKill, prevStop, prevResume := processTree, killProcess, stopProcess, resumeProcess
	t.Cleanup(func() {
		processTree, killProcess, stopProcess, resumeProcess = prevTree, prevKill, prevStop, prevResume
	})
	processTree = func() map[int]int {
		i := r.calls
		if i >= len(r.walks) {
			i = len(r.walks) - 1
		}
		r.calls++
		return r.walks[i]
	}
	stopProcess = func(pid int) error { r.log = append(r.log, sig{"stop", pid}); return nil }
	resumeProcess = func(pid int) error { r.log = append(r.log, sig{"resume", pid}); return nil }
	killProcess = func(pid int) error {
		r.log = append(r.log, sig{"kill", pid})
		if r.failKil[pid] {
			return os.ErrPermission
		}
		return nil
	}
}

func (r *killTreeRig) signalled(kind string) []int {
	out := []int{}
	for _, e := range r.log {
		if e.kind == kind {
			out = append(out, e.pid)
		}
	}
	sort.Ints(out)
	return out
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// THE CHILD FORKED DURING THE KILL. The one-snapshot version read the tree once,
// so a process the agent started after that read survived. Here the second walk
// shows a grandchild the first did not; it must be frozen and killed.
//
// MUTATION: make killTree walk once (break after round 0).
// RESULT: red — 205 is never signalled.
func TestKillTreeCatchesAChildForkedDuringTheKill(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze order is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{
		{202: 201},
		{202: 201, 205: 202},
	}}
	r.install(t)
	got := killTree(201, spareFromContain)
	if got != 3 {
		t.Fatalf("killTree reached %d, want 3 (the root, its child, and the late grandchild)", got)
	}
	if want := []int{201, 202, 205}; !sameInts(r.signalled("kill"), want) {
		t.Fatalf("killed %v, want %v", r.signalled("kill"), want)
	}
}

// NOTHING IS KILLED UNTIL EVERYTHING IS FROZEN. Killing a parent while its child
// still runs reparents the child to init, where no parent link finds it again.
//
// MUTATION: kill inside the walk loop instead of after it.
// RESULT: red — a kill appears before the last stop.
func TestKillTreeFreezesEverythingBeforeKillingAnything(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze order is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{202: 201, 203: 202}, {202: 201, 203: 202, 204: 203}}}
	r.install(t)
	killTree(201, spareFromContain)
	lastStop, firstKill := -1, len(r.log)
	for i, e := range r.log {
		if e.kind == "stop" {
			lastStop = i
		}
		if e.kind == "kill" && i < firstKill {
			firstKill = i
		}
	}
	if lastStop < 0 || firstKill < lastStop {
		t.Fatalf("a kill was sent before the tree was fully frozen: %v", r.log)
	}
}

// The spare set holds inside the tree too: init, this bastion, and its own
// local agent are never frozen or killed even when a corrupt map names them as
// descendants; a spared ROOT reaches nothing.
//
// MUTATION: drop the spare(pid) check inside the walk.
// RESULT: red — self or 1 is signalled.
func TestKillTreeNeverTouchesTheSpareSet(t *testing.T) {
	self := os.Getpid()
	r := &killTreeRig{walks: []map[int]int{{202: 201, self: 201, 1: 201, 206: 201}}}
	r.install(t)
	faTrackPID(206)
	defer faUntrackPID(206)
	killTree(201, spareFromContain)
	for _, kind := range []string{"stop", "kill"} {
		for _, pid := range r.signalled(kind) {
			if pid == self || pid == 1 || pid == 206 {
				t.Fatalf("%s sent to spared pid %d: %v", kind, pid, r.log)
			}
		}
	}
	if n := killTree(1, spareFromContain); n != 0 {
		t.Fatalf("a spared root must reach nothing, reached %d", n)
	}
}

// A PROCESS WE STOPPED AND COULD NOT KILL IS RESUMED. Leaving it stopped would
// be a hang this box caused and reported as nothing.
//
// MUTATION: remove the resumeProcess call.
// RESULT: red — 202 is never resumed.
func TestKillTreeResumesWhatItCouldNotKill(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{202: 201}}, failKil: map[int]bool{202: true}}
	r.install(t)
	if got := killTree(201, spareFromContain); got != 1 {
		t.Fatalf("reached %d, want 1 (202's kill failed)", got)
	}
	if !sameInts(r.signalled("resume"), []int{202}) {
		t.Fatalf("the unkillable frozen process was not resumed: %v", r.log)
	}
}

// A TREE THAT NEVER STOPS GROWING DOES NOT HANG THE BOX. Each walk invents a new
// child; the rounds are bounded and the kill proceeds with what was found.
//
// MUTATION: make the loop unbounded (for {}).
// RESULT: the test never returns (go test -timeout catches it).
func TestKillTreeIsBoundedAgainstAnEndlesslyGrowingTree(t *testing.T) {
	calls := 0
	prevTree, prevKill := processTree, killProcess
	t.Cleanup(func() { processTree, killProcess = prevTree, prevKill })
	processTree = func() map[int]int {
		calls++
		m := map[int]int{}
		for i := 0; i < calls; i++ {
			m[300+i] = 201
		}
		return m
	}
	killProcess = func(int) error { return nil }
	killTree(201, spareFromContain)
	if calls > killTreeMaxRounds {
		t.Fatalf("walked %d times, the bound is %d", calls, killTreeMaxRounds)
	}
}

// identityRig drives procIdentity from a script: pid -> successive answers.
func identityRig(t *testing.T, script map[int][]string, stopped map[int]bool) {
	t.Helper()
	prev := procIdentity
	t.Cleanup(func() { procIdentity = prev })
	calls := map[int]int{}
	procIdentity = func(pid int) (string, bool, bool) {
		seq, ok := script[pid]
		if !ok {
			return "", false, false
		}
		i := calls[pid]
		if i >= len(seq) {
			i = len(seq) - 1
		}
		calls[pid]++
		return seq[i], stopped[pid], true
	}
}

// A PID IS NOT A PROCESS. 202's number changes hands between
// the read and the stop: the stranger is resumed and never killed. 203 dies
// while frozen and its number is reused before the kill: not killed, and not
// resumed either (the frozen process is gone; the new one was never stopped).
//
// MUTATION: drop the post-stop identity check.  RESULT: red — 202 is killed.
// MUTATION: drop the pre-kill identity check.   RESULT: red — 203 is killed.
func TestKillTreeNeverSignalsAStrangerUnderARecycledPid(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{202: 201, 203: 201}}}
	r.install(t)
	identityRig(t, map[int][]string{
		201: {"t1"},
		202: {"t2", "t2-new"},    // read, then after the stop: a different process
		203: {"t3", "t3", "t3x"}, // read, after stop, then at the kill: reused
	}, nil)
	killTree(201, spareFromContain)
	kills := r.signalled("kill")
	for _, pid := range kills {
		if pid == 202 || pid == 203 {
			t.Fatalf("killed a recycled pid %d: %v", pid, r.log)
		}
	}
	if !sameInts(r.signalled("resume"), []int{202}) {
		t.Fatalf("the stranger stopped by mistake must be resumed, and only it: %v", r.log)
	}
}

// A PROCESS SOMEONE ELSE HAD STOPPED is killed with the tree but never resumed
// by us when the kill fails: its stopped state was not
// ours to undo.
//
// MUTATION: resume on kill failure regardless of wasStopped.  RESULT: red.
func TestKillTreeNeverResumesAProcessItDidNotStop(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{202: 201}}, failKil: map[int]bool{202: true}}
	r.install(t)
	identityRig(t, map[int][]string{201: {"t1"}, 202: {"t2"}}, map[int]bool{202: true})
	killTree(201, spareFromContain)
	if len(r.signalled("resume")) != 0 {
		t.Fatalf("resumed a process somebody else had stopped: %v", r.log)
	}
}

// THE FROZEN SET IS WRITTEN DOWN BEFORE THE KILL AND CLEARED AFTER, and a
// process someone else had stopped is not in it (it is not ours to thaw).
//
// MUTATION: skip the journal write.  RESULT: red.
func TestKillTreeJournalsWhatItFreezes(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{202: 201, 203: 201}}}
	r.install(t)
	identityRig(t, map[int][]string{201: {"t1"}, 202: {"t2"}, 203: {"t3"}}, map[int]bool{203: true})
	prev := killTreeJournalWrite
	t.Cleanup(func() { killTreeJournalWrite = prev })
	var writes [][]frozenEntry
	killTreeJournalWrite = func(e []frozenEntry) { writes = append(writes, e) }
	killTree(201, spareFromContain)
	if len(writes) < 2 || len(writes[len(writes)-1]) != 0 {
		t.Fatalf("want the journal written during the freeze and cleared after: %v", writes)
	}
	got := map[int]string{}
	for _, e := range writes[len(writes)-2] {
		got[e.PID] = e.ID
	}
	if len(got) != 2 || got[201] != "t1" || got[202] != "t2" {
		t.Fatalf("journal = %v, want 201 and 202 with their identities (203 was already stopped)", writes[len(writes)-2])
	}
}

// RECOVERY THAWS ONLY WHAT IT FROZE: a journalled pid whose identity still
// matches and that is still stopped is resumed; a reused number or a process
// no longer stopped is left alone; the journal is removed.
//
// MUTATION: resume without the identity check.  RESULT: red — 302 is resumed.
func TestRecoverFrozenTreesThawsOnlyWhatItFroze(t *testing.T) {
	r := &killTreeRig{walks: []map[int]int{{}}}
	r.install(t)
	stopped := map[int]bool{301: true, 302: true, 303: false}
	identityRig(t, map[int][]string{301: {"a"}, 302: {"b-reused"}, 303: {"c"}}, stopped)
	p, err := killTreeJournalPath()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal([]frozenEntry{{PID: 301, ID: "a"}, {PID: 302, ID: "b"}, {PID: 303, ID: "c"}})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	recoverFrozenTrees()
	if !sameInts(r.signalled("resume"), []int{301}) {
		t.Fatalf("resumed %v, want only 301", r.signalled("resume"))
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("the journal was not removed after recovery")
	}
}

// THE FROZEN SET IS JOURNALLED AS IT IS FROZEN: a bastion that
// dies during the freeze rounds still leaves a record of what it stopped.
//
// MUTATION: write the journal only after the freeze rounds.  RESULT: red — the
// first write already holds every frozen pid, and none is ever written alone.
func TestKillTreeJournalsEachFreezeAsItHappens(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{202: 201}, {202: 201, 203: 202}}}
	r.install(t)
	identityRig(t, map[int][]string{201: {"t1"}, 202: {"t2"}, 203: {"t3"}}, nil)
	prev := killTreeJournalWrite
	t.Cleanup(func() { killTreeJournalWrite = prev })
	var sizes []int
	killTreeJournalWrite = func(e []frozenEntry) { sizes = append(sizes, len(e)) }
	killTree(201, spareFromContain)
	want := []int{1, 2, 3, 0}
	if !sameInts(sizes, want) {
		t.Fatalf("journal writes %v, want one per freeze then a clear %v", sizes, want)
	}
}

// ancestorRig drives procIdentity for a chain of ancestors whose STOPPED state
// changes over successive reads (sudo is running when the kill begins and
// stopped once its child is frozen). `stopped[pid]` is that pid's stopped
// answers in order; the last repeats. `others` are the tree's own pids, always
// running with a fixed identity. The thaw wait is a no-op.
func ancestorRig(t *testing.T, ids map[int]string, stopped map[int][]bool, others map[int]string) {
	t.Helper()
	prev := procIdentity
	prevWait := ancestorThawWait
	t.Cleanup(func() { procIdentity, ancestorThawWait = prev, prevWait })
	ancestorThawWait = func() {}
	calls := map[int]int{}
	procIdentity = func(pid int) (string, bool, bool) {
		if id, ok := ids[pid]; ok {
			seq := stopped[pid]
			i := calls[pid]
			if i >= len(seq) {
				i = len(seq) - 1
			}
			calls[pid]++
			return id, i >= 0 && seq[i], true
		}
		if id, ok := others[pid]; ok {
			return id, false, true
		}
		return "", false, false
	}
}

// THE PARENT THAT STOPPED WITH ITS CHILD IS RESUMED. 200 is running when the
// kill begins; it stops itself once its child 201 is frozen (a relaying parent);
// after the kill it must be continued, or 201 stays a zombie under a parent that
// hangs for ever. The resume comes AFTER every kill — a parent continued early
// would continue its frozen child with it — and the parent is never frozen or
// killed itself.
//
// MUTATION: drop the thawRelayingAncestors call.  RESULT: red — 200 is never resumed.
// MUTATION: thaw before the kill loop.  RESULT: red — the resume precedes a kill.
func TestKillTreeThawsAParentThatStoppedWithItsChild(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{201: 200, 202: 201}}}
	r.install(t)
	ancestorRig(t, map[int]string{200: "sudo"}, map[int][]bool{200: {false, true}},
		map[int]string{201: "t1", 202: "t2"})
	if got := killTree(201, spareFromContain); got != 2 {
		t.Fatalf("reached %d, want 2", got)
	}
	if !sameInts(r.signalled("resume"), []int{200}) {
		t.Fatalf("the parent our freeze stopped was not resumed: %v", r.log)
	}
	if !sameInts(r.signalled("stop"), []int{201, 202}) || !sameInts(r.signalled("kill"), []int{201, 202}) {
		t.Fatalf("the parent must never be frozen or killed, only thawed: %v", r.log)
	}
	lastKill, resumeAt := -1, -1
	for i, e := range r.log {
		if e.kind == "kill" {
			lastKill = i
		}
		if e.kind == "resume" && e.pid == 200 {
			resumeAt = i
		}
	}
	if resumeAt < lastKill {
		t.Fatalf("the parent was resumed before the tree was dead: %v", r.log)
	}
}

// UNDER A TERMINAL THE STOP IS RELAYED A HOP FURTHER. The agent's direct parent
// (sudo's monitor, 200) never stops; the grandparent (sudo itself, 199) and the
// terminal wrapper above it (198) do. Both are resumed; 200 is left alone.
//
// MUTATION: read only the direct parent.  RESULT: red — 199 and 198 stay stopped.
func TestKillTreeThawsTheAncestorsAStopIsRelayedThrough(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{201: 200, 200: 199, 199: 198, 198: 1}}}
	r.install(t)
	ancestorRig(t, map[int]string{200: "monitor", 199: "sudo", 198: "script"},
		map[int][]bool{200: {false}, 199: {false, true}, 198: {false, false, true}},
		map[int]string{201: "t1"})
	killTree(201, spareFromContain)
	if !sameInts(r.signalled("resume"), []int{198, 199}) {
		t.Fatalf("the relaying ancestors were not both resumed (and nothing else): %v", r.log)
	}
	if !sameInts(r.signalled("stop"), []int{201}) || !sameInts(r.signalled("kill"), []int{201}) {
		t.Fatalf("only the root is frozen and killed: %v", r.log)
	}
}

// A PARENT THAT WAS ALREADY STOPPED IS NOT OURS TO THAW — and nothing above it
// can be relaying OUR stop, so the walk ends there. 200 is stopped before the
// first freeze (somebody did that on purpose) and stays untouched. 199 above it
// is running at the walk and stopped by the time of the thaw; it is not
// recorded, because a stop cannot have passed through a process that was not
// running, so it is not resumed either.
//
// MUTATION: drop the stopped check in readRelayingAncestors.  RESULT: red — 200 is resumed.
// MUTATION: skip past a stopped ancestor instead of ending the walk.  RESULT: red — 199 is resumed.
func TestKillTreeLeavesAParentSomebodyElseStopped(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{201: 200, 200: 199}}}
	r.install(t)
	ancestorRig(t, map[int]string{200: "sudo", 199: "sh"}, map[int][]bool{200: {true}, 199: {false, true}},
		map[int]string{201: "t1"})
	killTree(201, spareFromContain)
	if len(r.signalled("resume")) != 0 {
		t.Fatalf("resumed a process our freeze did not stop: %v", r.log)
	}
}

// A PARENT WHOSE NUMBER CHANGED HANDS IS A STRANGER. 200 exits during the kill
// and a stopped process now holds its number; it is not resumed.
//
// MUTATION: drop the identity comparison in thawRelayingAncestors.  RESULT: red.
func TestKillTreeNeverThawsAStrangerUnderTheParentsPid(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{201: 200}}}
	r.install(t)
	prev := procIdentity
	prevWait := ancestorThawWait
	t.Cleanup(func() { procIdentity, ancestorThawWait = prev, prevWait })
	ancestorThawWait = func() {}
	calls := 0
	procIdentity = func(pid int) (string, bool, bool) {
		switch pid {
		case 200:
			calls++
			if calls == 1 {
				return "sudo", false, true
			}
			return "stranger", true, true
		case 201:
			return "t1", false, true
		}
		return "", false, false
	}
	killTree(201, spareFromContain)
	if len(r.signalled("resume")) != 0 {
		t.Fatalf("resumed a stranger under the parent's old number: %v", r.log)
	}
}

// A PARENT THAT NEVER FOLLOWS COSTS A BOUNDED WAIT AND NO SIGNAL. A plain
// shell does not stop with its child; the kill reads it a bounded number of
// times, waits between reads and not after the last, and leaves it alone.
//
// MUTATION: make the wait loop unbounded.  RESULT: the test never returns.
// MUTATION: wait after the last read too.  RESULT: red — one wait too many.
func TestKillTreeLeavesARunningParentAlone(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{201: 200}}}
	r.install(t)
	ancestorRig(t, map[int]string{200: "sh"}, map[int][]bool{200: {false}}, map[int]string{201: "t1"})
	waits := 0
	prevWait := ancestorThawWait
	t.Cleanup(func() { ancestorThawWait = prevWait })
	ancestorThawWait = func() { waits++ }
	killTree(201, spareFromContain)
	if len(r.signalled("resume")) != 0 {
		t.Fatalf("signalled a parent that was never stopped: %v", r.log)
	}
	if waits != ancestorThawChecks-1 {
		t.Fatalf("waited %d times, want exactly %d (between reads, never after the last)", waits, ancestorThawChecks-1)
	}
}

// THE ANCESTORS RIDE IN THE JOURNAL WITH THE FIRST FREEZE. A bastion that dies
// between the freeze and the thaw must continue the relaying parent on its next
// start, so the parent is written down in the same write as the first process
// frozen — and not one moment earlier: before our SIGSTOP lands nothing can be
// relaying it, and a journal holding a process we never signalled would let a
// restart continue a stop the user made themselves. recoverFrozenTrees then
// thaws it only when it is stopped under the same identity, like any entry.
//
// MUTATION: leave the ancestors out of the journal.  RESULT: red — no write holds 200.
// MUTATION: write the ancestors before the first freeze.  RESULT: red — a write
// precedes the first stop.
func TestKillTreeJournalsTheRelayingParent(t *testing.T) {
	if !freezeSupported {
		t.Skip("the freeze is a unix property")
	}
	r := &killTreeRig{walks: []map[int]int{{201: 200}}}
	r.install(t)
	ancestorRig(t, map[int]string{200: "sudo"}, map[int][]bool{200: {false}}, map[int]string{201: "t1"})
	prev := killTreeJournalWrite
	t.Cleanup(func() { killTreeJournalWrite = prev })
	var writes [][]frozenEntry
	stopsSeen := 0
	stopsAtWrite := []int{}
	prevStop := stopProcess
	stopProcess = func(pid int) error { stopsSeen++; return prevStop(pid) }
	killTreeJournalWrite = func(e []frozenEntry) {
		writes = append(writes, append([]frozenEntry(nil), e...))
		stopsAtWrite = append(stopsAtWrite, stopsSeen)
	}
	killTree(201, spareFromContain)
	if len(writes) != 2 || len(writes[0]) != 2 {
		t.Fatalf("want one write holding the parent and the root, then a clear: %v", writes)
	}
	if writes[0][0].PID != 200 || writes[0][0].ID != "sudo" || writes[0][1].PID != 201 {
		t.Fatalf("the first write must hold the parent then the frozen root: %v", writes[0])
	}
	if stopsAtWrite[0] != 1 {
		t.Fatalf("the first write must follow the first freeze, not precede it (stops seen: %d)", stopsAtWrite[0])
	}
	if len(writes[1]) != 0 {
		t.Fatalf("the journal must be cleared after the kill: %v", writes)
	}
}
