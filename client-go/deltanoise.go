package main

// deltanoise.go — the deterministic noise filter, on the box, before
// anything travels.
//
// A detection plane is judged by its second week, not its first. Every rule
// here exists because something ordinary would otherwise be reported as a
// finding, and a list with ordinary things in it is a list nobody opens.
//
// Two dispositions, and the difference between them is the whole design:
//
//	FILTERED  taken out of the findings entirely, with the reason kept on the
//	          event so the operator can read what was removed. Only for things
//	          this bastion itself caused, or that were never really there.
//	DEMOTED   still a finding, at tier `known`, which moves it down the level table
//	          (a known-tier proc_new is a notice, not a warn). For things that
//	          have an ordinary explanation but are still true.
//
// A rule earns a disposition by how much it EXPLAINS, and one of the four here
// explains almost nothing once measured, so it sets neither — see rule 4.
//
// The default when a rule CANNOT BE EVALUATED on this platform is to report.
// A filter that fails closed would turn "this build cannot read process ages"
// into silence, and silence is indistinguishable from a quiet machine.

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// deltaShortLived is the short-lived threshold: a process younger than this that holds no
// listening socket and talks to no model is counted rather than reported. The
// design proposes 5 seconds and it is the right order of magnitude — it is the
// lifetime of a shell command, not of anything installed.
const deltaShortLived = 5 * time.Second

// deltaHoldKey is what the ceiling counts against. For a process it is the
// fingerprint, which is stable across restarts by design — that is what lets a
// respawner accumulate and escape.
//
// A LISTENER'S FINGERPRINT CONTAINS ITS BIND POINT, so a holder that takes a
// FRESH ephemeral port each time never accumulates anything: measured, twelve
// passes reopening the same port produced two findings and twelve passes taking
// a new one produced ZERO, indefinitely. The ceiling
// existed and could not fire. Keying a listener on its protocol and HOLDER
// instead makes the pattern — "this program keeps opening ephemeral loopback
// ports" — the thing that accumulates, which is the pattern worth reporting.
//
// The bound on being wrong: two unrelated programs with the same name would
// share a key and escape together. Both would then be reported, which is the
// safe direction.
// deltaListenerHoldPrefix begins every listener hold key, which is how the hold
// list tells a listener hold from a process one without storing the class.
const deltaListenerHoldPrefix = "listener-holder\x00"

func deltaHoldKey(ev deltaEvent) string {
	if ev.Kind != deltaListenerNew {
		return ev.FP
	}
	proto, _ := listenerProtoPort(ev.Entry.Unit)
	return deltaListenerHoldPrefix + proto + "\x00" + ev.Entry.ArgvShape
}

// deltaHoldMax bounds how long one fingerprint may be held back by the rule
// above. Five minutes is five passes at the heartbeat's cadence — long enough
// that a service restarting once or twice is still filtered, short enough that
// something respawning continuously is a finding while it is still happening.
const deltaHoldMax = 5 * time.Minute

// The filter reasons, as they appear on the event.
const (
	deltaFilterBastion    = "started by this bastion"
	deltaFilterShortLived = "gone before it was old enough to report"
)

// deltaNoise is everything the filter needs to know about the live machine that
// the two lists being compared do not carry.
type deltaNoise struct {
	// Self is this process. Everything below it in the tree is ours.
	Self    int
	Parents map[int]int
	// BaselinePIDs are the pids of accounted PROCESS entries, so a process
	// parented by one of them is a child of something normal. Never a
	// listener's holder: a listener's identity is only its bind point and the
	// holder's chosen name (deltaNoiseFor).
	BaselinePIDs map[int]bool
	// Age answers how long a pid has been running. The bool is false where the
	// platform cannot say, and that is not the same as zero.
	Age func(pid int) (time.Duration, bool)
	// Listening is the set of pids holding a listening socket, and Sockets says
	// whether the set could be read at all. An unreadable set means the
	// short-lived rule cannot check its own exemption, so it does not fire.
	Listening map[int]bool
	Sockets   bool
	// Packaged answers, for the executables asked about, which ones the
	// platform's package database owns AND still matches. Nil where there is no
	// package database to ask.
	Packaged func(paths []string) map[string]string
}

// deltaFilter applies the noise rules to one pass of events. It returns the findings and
// the events it took out, both in the order they arrived.
func deltaFilter(events []deltaEvent, n deltaNoise, st *deltaState, now time.Time) (findings, filtered []deltaEvent) {
	packaged := n.lookupPackaged(events)
	seenHeld := map[string]bool{}
	for _, ev := range events {
		switch ev.Kind {
		case deltaProcGone, deltaSchedGone, deltaBinaryChanged:
			// An absence has no process to explain away, and the bastion's own
			// binary is never noise.
			findings = append(findings, ev)
			continue
		}
		// 1. Anything this bastion started. A harness run, a lab job, a session
		//    PTY, the local agent: the bastion knows it launched them because
		//    they are below it in the process tree, and a program reporting its
		//    own work as an intrusion is the fastest way to be ignored.
		//
		//    IT DOES NOT NAME WHICH OP STARTED IT. The design tags a bastion-started
		//    process with its op id; this says only "ours", read off the process
		//    tree. The tree is the more robust signal — it needs no bookkeeping
		//    and cannot go stale — but a filtered row that cannot say whether it
		//    was a harness run, a lab job or a session shell is one an operator
		//    has to take on trust. The op id needs a registry the bastion does
		//    not keep; it belongs with the findings store the host can read.
		if len(ev.PIDs) > 0 && n.allOurs(ev.PIDs) {
			ev.Filtered = deltaFilterBastion
			ev.Evidence = append(ev.Evidence, evidence{Signal: "bastion-child", Tier: tierVerified,
				Value: "every process behind this entry is below this bastion in the tree " +
					"(which op started it is not recorded)"})
			filtered = append(filtered, ev)
			continue
		}
		// 2. Short-lived. Held rather than dropped: if it is still here next
		//    pass it was not short-lived after all and becomes a finding then.
		//
		//    AND THE HOLD HAS A CEILING, because without one a respawner is
		//    held for ever. Something that keeps starting fresh copies of
		//    itself — a crash-looping unit, a beacon relaunched every few
		//    seconds — is young at EVERY pass, so it was re-held at every pass
		//    and, being seen each time, never settled into the short-lived
		//    count either: ten passes, no finding and a storm counter reading
		//    zero. A thing that has been "about to go
		//    away" for deltaHoldMax is not short-lived work, it is a pattern,
		//    and the pattern is the finding.
		if hold, why := n.shortLived(ev); hold {
			if since, held := st.heldSince(deltaHoldKey(ev)); held && now.Sub(since) >= deltaHoldMax {
				ev.Evidence = append(ev.Evidence, evidence{Signal: "respawning", Tier: tierVerified,
					Value: "seen as a new short-lived process at every pass for " +
						now.Sub(since).Round(time.Minute).String()})
				st.release(deltaHoldKey(ev))
				findings = append(findings, ev)
				continue
			}
			st.hold(deltaHoldKey(ev), now)
			seenHeld[deltaHoldKey(ev)] = true
			ev.Filtered = why
			ev.Evidence = append(ev.Evidence, evidence{Signal: "short-lived", Tier: tierVerified, Value: why})
			filtered = append(filtered, ev)
			continue
		}
		// RELEASED UNDER THE KEY IT WAS HELD UNDER. This said ev.FP while the
		// hold above it used deltaHoldKey, and for a process those are the same
		// string so nothing showed — but a listener's differ, so its hold entry
		// was never released by name and was swept by settleHeld instead, which
		// counts it as something that came and went. Measured: a listener still
		// open and being reported as a finding in the same breath also bumped
		// the storm counter, on a running total that no report resets and that
		// rides the heartbeat as short_lived. The noise filter's
		// storm signal was measuring something other than what it says.
		st.release(deltaHoldKey(ev))
		// 3. Package-managed. The distribution's own database says this is the
		//    file that package ships, byte for byte. Demoted, never removed:
		//    /usr/bin/python3 is packaged and is also how half the agents on
		//    earth are started, which is exactly why this sets a tier instead
		//    of dropping the row.
		if pkg, ok := packaged[ev.Entry.Exe]; ok {
			ev.Tier = tierKnown
			ev.Evidence = append(ev.Evidence, evidence{Signal: "package-managed", Tier: tierVerified,
				Value: "shipped by " + pkg + " and unmodified"})
		}
		// 4. Child of a baseline entry — RECORDED AND NEVER ACTED ON, because
		//    the version of this rule that can be built today is worse than no
		//    rule, and that is a measurement rather than an opinion.
		//
		//    The design folds a new process into its parent when the parent is a
		//    baseline entry AND the child's exe is in "that entry's declared
		//    children set (built during baseline from what the service actually
		//    spawned over the scan window)". There is no such set: the
		//    accounting is one instantaneous scan (baseline.go collectBaseline),
		//    with no window and no record of what anything spawned.
		//
		//    Dropping the children-set half leaves "the parent was running at
		//    baseline time", which on a real machine is nearly everything.
		//    MEASURED on a live machine: a brand-new root-owned
		//    binary at /tmp/brandnewthing and a swapped binary at a known post
		//    were BOTH lowered to `notice` — batched into a daily summary,
		//    waking nobody — because each had been started from a shell that
		//    existed when the accounting was taken. That is the filter hiding
		//    the two findings this plane exists to produce.
		//
		//    So the fact travels as evidence, at the tier that "annotates and
		//    never promotes" (origin.go:44-45), and the level is left alone.
		//    The fold comes back with the children set, which belongs to a
		//    baseline taken over a window rather than in an instant.
		if len(ev.PIDs) > 0 && n.allChildrenOfBaseline(ev.PIDs) {
			ev.Evidence = append(ev.Evidence, evidence{Signal: "child-of-baseline", Tier: tierAmbiguous,
				Value: "started by something the accounting already holds — context, not an explanation"})
		}
		findings = append(findings, ev)
	}
	// Everything still held that did not turn up this pass came and went
	// between two scans. That is the count the design wants riding the beat.
	st.settleHeld(seenHeld)
	return findings, filtered
}

// allOurs reports whether every pid behind an entry descends from this bastion.
// EVERY, not any: a binary the bastion happens to run and the user also runs
// independently is still the user's process, and dropping the entry because one
// of its pids is ours would hide it.
func (n deltaNoise) allOurs(pids []int) bool {
	if n.Self <= 0 {
		return false
	}
	for _, pid := range pids {
		if !n.descendsFromSelf(pid) {
			return false
		}
	}
	return true
}

// descendsFromSelf walks up the parent map. Bounded like the origin walk
// (origin.go maxOriginHops) so a corrupt map terminates instead of looping.
func (n deltaNoise) descendsFromSelf(pid int) bool {
	cur := pid
	for hop := 0; hop < maxOriginHops; hop++ {
		if cur == n.Self {
			return true
		}
		next, ok := n.Parents[cur]
		if !ok || next <= 0 || next == cur {
			return false
		}
		cur = next
	}
	return false
}

func (n deltaNoise) allChildrenOfBaseline(pids []int) bool {
	if len(n.BaselinePIDs) == 0 {
		return false
	}
	for _, pid := range pids {
		parent, ok := n.Parents[pid]
		if !ok || !n.BaselinePIDs[parent] {
			return false
		}
	}
	return true
}

// shortLived decides whether to hold an entry back for one pass.
//
// The two exemptions are the design's and they are not optional: something that opened
// a listening socket or reached a model endpoint in its first five seconds is
// the most interesting thing on the box, not the least. Where the socket table
// could not be read, the rule does not fire at all — an exemption that cannot
// be checked is not an exemption.
func (n deltaNoise) shortLived(ev deltaEvent) (bool, string) {
	// A LOOPBACK LISTENER ON AN EPHEMERAL PORT IS THE SAME EVENT TWICE, and on
	// the machine class this plane actually runs on — a person's own computer —
	// it is most of what the listener class would say.
	//
	// Measured while adding the class: a `go test` run on this box produced two
	// `listener_new` warns on tcp/127.0.0.1:41579 and :44945, held by a test
	// binary that had already been reported as a proc_new. The kernel's
	// ephemeral range here is 32768-60999 (/proc/sys/net/ipv4/ip_local_port_range),
	// which is where a language server, a browser, a debugger and every test
	// harness bind. Reporting each one is how a plane gets ignored.
	//
	// NARROW ON PURPOSE, and each condition is load-bearing:
	//   loopback         nothing off this machine can reach it
	//   ephemeral range  the kernel's own "this is not a service" range
	//   young holder     it has not survived even one pass
	// A backdoor on 4444, anything on a routable address, and anything a
	// long-running process holds are all untouched. And this HOLDS BACK ONE
	// PASS, exactly like the first-miss rule for an absence — it never
	// suppresses: a port still there on the next pass is reported.
	if ev.Kind == deltaListenerNew {
		if why, held := n.ephemeralLoopbackListener(ev); held {
			return true, why
		}
		return false, ""
	}
	if ev.Kind != deltaProcNew && ev.Kind != deltaProcChanged {
		return false, ""
	}
	if len(ev.Entry.Endpoints) > 0 || n.Age == nil || len(ev.PIDs) == 0 {
		return false, ""
	}
	if !n.Sockets {
		return false, ""
	}
	oldest := time.Duration(0)
	for _, pid := range ev.PIDs {
		if n.Listening[pid] {
			return false, ""
		}
		age, ok := n.Age(pid)
		if !ok {
			// One unreadable age is enough to report: the platform cannot tell
			// us this is young, so it is not treated as young.
			return false, ""
		}
		if age > oldest {
			oldest = age
		}
	}
	if oldest >= deltaShortLived {
		return false, ""
	}
	return true, deltaFilterShortLived
}

// lookupPackaged asks the platform's package database about every executable in
// this pass's events, in ONE query. Doing it per event would read the whole
// package corpus once per finding; doing it eagerly for every process on the
// box would read it on every pass, findings or not. This reads it only when
// there is something to weigh, which in steady state is never.
func (n deltaNoise) lookupPackaged(events []deltaEvent) map[string]string {
	if n.Packaged == nil {
		return nil
	}
	seen := map[string]bool{}
	paths := []string{}
	for _, ev := range events {
		p := strings.TrimSpace(ev.Entry.Exe)
		if p == "" || seen[p] || ev.Entry.ExeDigest == "" {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		return nil
	}
	sort.Strings(paths)
	return n.Packaged(paths)
}

// ephemeralLoopbackListener is the listener half of shortLived. See its comment
// for why all three conditions have to hold.
func (n deltaNoise) ephemeralLoopbackListener(ev deltaEvent) (string, bool) {
	if listenerIsExposed(ev.Entry) {
		return "", false
	}
	port := listenerPortNum(ev.Entry)
	if port < readEphemeralFloor() {
		return "", false
	}
	// ONE PASS, AND THE SENTENCE SAYS ONE PASS. This tested deltaShortLived (5s)
	// while a pass is deltaRefreshEvery (60s), so the words an operator reads —
	// "younger than one pass" — described something the code did not do, and the
	// case the rule was added for was suppressed only when a pass happened to
	// land in the holder's first five seconds: about one sighting in twelve.
	// A `go test` run is thirty seconds old when the
	// pass sees it, so the noise this exists to stop came through anyway.
	//
	// The process half keeps deltaShortLived because it means something
	// different there: "gone before it was old enough to report". Here the
	// question is "has it survived a pass yet", and that is the pass interval.
	//
	// An unreadable age is NOT young — the same call the process half makes, for
	// the same reason: a rule that fires where the platform cannot answer is a
	// rule that fires on the wrong machines.
	if n.Age == nil || len(ev.PIDs) == 0 {
		return "", false
	}
	for _, pid := range ev.PIDs {
		age, ok := n.Age(pid)
		if !ok || age >= deltaRefreshEvery {
			return "", false
		}
	}
	return "a loopback port in the kernel's ephemeral range, held by a process " +
		"younger than one pass — held back until it survives one", true
}

// ephemeralPortFloor is the bottom of THIS kernel's ephemeral range, read from
// net.ipv4.ip_local_port_range and not compiled in.
//
// THE DIRECTION OF BEING WRONG IS NOT SYMMETRIC, which is why it is read. A box
// that WIDENS its range (a lower floor than the stock 32768) would, against a
// hardcoded floor, have its genuinely-ephemeral ports reported — noisy, but
// nothing is hidden. A box that NARROWS it (say 49152-60999) is the dangerous
// one: ports 32768-49151 are ordinary service ports on that machine, and a
// hardcoded floor would hold a real listener back on them. Reading the kernel's
// own answer removes the second case entirely.
//
// Falls back to the stock floor when the file cannot be read, and a sysctl this
// box will not show us is not a reason to suppress MORE — the fallback is the
// stock value, which is the conservative end of the range in practice.
// ephemeralRangePath is a var so a test can point it at a fixture. Without that
// the floor test compared the value against THIS box's sysctl — which is the
// stock 32768, identical to the fallback, so hardcoding the floor left the whole
// suite green. A guard that cannot fail on the machine
// it runs on is not a guard. Same remedy as sshdConfigPath.
var ephemeralRangePath = "/proc/sys/net/ipv4/ip_local_port_range"

func readEphemeralFloor() int {
	b, err := os.ReadFile(ephemeralRangePath)
	if err != nil {
		return 32768
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 32768
	}
	n, err := strconv.Atoi(f[0])
	if err != nil || n <= 0 || n > 65535 {
		return 32768
	}
	return n
}

// READ AT THE POINT OF USE, not cached in a package var, and the reason is that
// the var could not be tested. A test pointing ephemeralRangePath at a fixture
// could not change a value computed once at program start, so the whole floor
// could be hardcoded with the suite green — measured once, and then again by
// the sweep that was supposed to prove the fix.
//
// The cost is one small read of a proc file, and only for a listener_new event
// that already passed the loopback test. That is a handful of reads on a pass
// that has findings at all, and zero on a quiet one.
