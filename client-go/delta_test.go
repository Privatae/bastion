package main

// The delta has exactly one job — say what changed — and there are two ways to
// fail at it that no single test can cover, because a fix for either is the
// cause of the other:
//
//	MISSES IT    the swapped binary reads as unrelated new-and-gone rows, the
//	             new cron line reads as nothing at all, and the product does not
//	             do the thing it says on the box.
//	CRIES WOLF   a service restart, an apt upgrade, the bastion's own harness
//	             run, or a shell command that lived a second each land in the
//	             findings, and by the second week nobody opens the list.
//
// Every test below is one of those two, named for the behaviour rather than the
// function, so a mutation that breaks the behaviour fails a test whose name
// says what was lost.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── helpers ─────────────────────────────────────────────────────────────────

func procEntry(digest, user, unit, shape string) baselineEntry {
	return baselineEntry{
		FP:        baselineFP("process", digest, user, unit, shape),
		Kind:      "process",
		ExeDigest: digest, Exe: "/usr/bin/thing", User: user, Unit: unit, ArgvShape: shape,
	}
}

func schedBaseEntry(user, unit, shape string) baselineEntry {
	return baselineEntry{
		FP:   baselineFP("scheduler", "", user, unit, shape),
		Kind: "scheduler", User: user, Unit: unit, ArgvShape: shape,
	}
}

func liveOf(e baselineEntry, pids ...int) deltaLiveEntry {
	return deltaLiveEntry{Entry: e, PIDs: pids}
}

func eventsOfKind(evs []deltaEvent, kind string) []deltaEvent {
	out := []deltaEvent{}
	for _, e := range evs {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func freshState(t *testing.T) *deltaState {
	t.Helper()
	return &deltaState{Version: deltaStateVersion, Baseline: "b"}
}

// ── missing it ──────────────────────────────────────────────────────────────

// THE CENTRAL CLAIM OF THE WHOLE PLANE. A binary replaced at a post the
// accounting already knows about must be ONE event that says so, carrying both
// digests. Reported as a `proc_new` plus a `proc_gone` it is two rows nobody
// connects, and the design's own `proc_changed` — "same fingerprint, new exe
// digest" — cannot fire at all, because the digest is inside the fingerprint.
func TestASwappedBinaryAtAKnownPostIsOneChangedEventNotTwoHalves(t *testing.T) {
	was := procEntry("aaaaaaaaaaaa", "root", "web.service", "node server.js")
	now := procEntry("bbbbbbbbbbbb", "root", "web.service", "node server.js")
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(now, 41)})
	changed := eventsOfKind(evs, deltaProcChanged)
	if len(changed) != 1 {
		t.Fatalf("a replaced binary produced %d proc_changed events, want 1:\n%+v", len(changed), evs)
	}
	if changed[0].Reason != deltaReasonExeDigest {
		t.Errorf("reason = %q, want %q", changed[0].Reason, deltaReasonExeDigest)
	}
	if changed[0].Was == nil || changed[0].Was.ExeDigest != "aaaaaaaaaaaa" {
		t.Error("the event does not carry what was there before, so a reader cannot " +
			"see what the binary was replaced FROM")
	}
	if n := len(eventsOfKind(evs, deltaProcNew)); n != 0 {
		t.Errorf("%d proc_new events as well — the swap was reported twice, as two "+
			"unrelated halves of one sentence", n)
	}
	if n := len(eventsOfKind(evs, deltaProcGone)); n != 0 {
		t.Errorf("%d proc_gone events as well — same defect from the other side", n)
	}
}

// A program that was never there, in a place nothing was, is NEW. This is the
// other side of the slot rule: it must not be swallowed as a change to
// something else.
func TestAProgramInAPlaceNothingWasReadsAsNew(t *testing.T) {
	was := procEntry("aaaa", "root", "web.service", "node server.js")
	now := procEntry("cccc", "user", "interactive", "/tmp/<tmp> --x")
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(was, 1), liveOf(now, 99)})
	if n := len(eventsOfKind(evs, deltaProcNew)); n != 1 {
		t.Fatalf("got %d proc_new, want 1:\n%+v", n, evs)
	}
	if n := len(eventsOfKind(evs, deltaProcChanged)); n != 0 {
		t.Errorf("the unrelated program was reported as a change to a known one (%d events)", n)
	}
}

// A PROCESS THE ACCOUNTING ALREADY HOLDS THAT HAS STARTED TALKING TO A MODEL.
// Endpoints are deliberately not fingerprinted (baseline.go), so this entry's
// fingerprint is unchanged and this is the only place the fact can be caught.
func TestAKnownProgramThatStartsTalkingToAModelIsReported(t *testing.T) {
	was := procEntry("aaaa", "user", "interactive", "python3 x.py")
	now := was
	now.Endpoints = []string{"api.anthropic.com"}
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(now, 7)})
	changed := eventsOfKind(evs, deltaProcChanged)
	if len(changed) != 1 || changed[0].Reason != deltaReasonEndpoint {
		t.Fatalf("a known process that began talking to a model produced %+v", evs)
	}
	if len(changed[0].Added) != 1 || changed[0].Added[0] != "api.anthropic.com" {
		t.Errorf("the event does not name the endpoint that is new: %+v", changed[0].Added)
	}
	if got := deltaLevel(changed[0]); got != deltaHigh {
		t.Errorf("level = %q, want high — a model endpoint is high", got)
	}
}

// The same endpoints in a different order are not a finding. A scan returns
// connections in whatever order the kernel had them.
func TestTheSameEndpointsInAnotherOrderAreNotAFinding(t *testing.T) {
	was := procEntry("aaaa", "user", "interactive", "python3 x.py")
	was.Endpoints = []string{"api.anthropic.com", "api.openai.com"}
	now := was
	now.Endpoints = []string{"API.OpenAI.com", "api.anthropic.com"}
	if evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(now, 7)}); len(evs) != 0 {
		t.Errorf("re-ordered endpoints produced %d events: %+v", len(evs), evs)
	}
}

// A STANDING JOB IS ITS OWN SLOT. Editing what an existing crontab line runs is
// the persistence move, and it must read as a change to that job — not as an
// unrelated job appearing while another vanishes.
func TestAnEditedCronLineIsAChangeToThatJob(t *testing.T) {
	was := schedBaseEntry("root", "cron:/etc/crontab:4", "/usr/bin/backup.sh")
	now := schedBaseEntry("root", "cron:/etc/crontab:4", "curl <hex> | sh")
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(now)})
	changed := eventsOfKind(evs, deltaSchedChanged)
	if len(changed) != 1 || changed[0].Reason != deltaReasonCommand {
		t.Fatalf("an edited cron line produced %+v", evs)
	}
	if n := len(eventsOfKind(evs, deltaSchedNew)) + len(eventsOfKind(evs, deltaSchedGone)); n != 0 {
		t.Errorf("it was ALSO reported as %d new/gone events — one edit, two rows", n)
	}
}

// A brand new standing job that would run a recognised agent is the persistence
// form of "a new process with an agent signature", which the level table puts at high.
func TestANewScheduledJobRunningAnAgentIsHigh(t *testing.T) {
	plain := deltaEvent{Kind: deltaSchedNew, Entry: schedBaseEntry("root", "cron:x:1", "/usr/bin/backup.sh")}
	agent := deltaEvent{Kind: deltaSchedNew}
	agent.Entry = schedBaseEntry("root", "cron:x:2", "claude -p go")
	agent.Entry.Signature = "claude-code"
	if got := deltaLevel(plain); got != deltaWarn {
		t.Errorf("an ordinary new job is %q, want warn", got)
	}
	if got := deltaLevel(agent); got != deltaHigh {
		t.Errorf("a new job that would start an agent is %q, want high", got)
	}
}

// ── crying wolf ─────────────────────────────────────────────────────────────

// AN UNREADABLE EXECUTABLE IS NOT A SWAPPED ONE. Both produce "the digests
// differ", and one of them is a security finding while the other is this
// process not being able to look. Getting this wrong fills the list with
// alarms every time a scan runs with fewer rights than the accounting did.
func TestLosingSightOfABinaryIsNotReportedAsASwap(t *testing.T) {
	was := procEntry("aaaaaaaaaaaa", "root", "web.service", "node server.js")
	now := procEntry("", "root", "web.service", "node server.js")
	now.DigestNote = "could not be read by this account"
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(now, 3)})
	changed := eventsOfKind(evs, deltaProcChanged)
	if len(changed) != 1 {
		t.Fatalf("got %+v", evs)
	}
	if changed[0].Reason != deltaReasonUnreadable {
		t.Fatalf("reason = %q, want %q — this is a visibility change, not a machine change",
			changed[0].Reason, deltaReasonUnreadable)
	}
	if got := deltaLevel(changed[0]); got != deltaNotice {
		t.Errorf("level = %q, want notice", got)
	}
}

// A packaged binary is ordinary; a packaged binary talking to a model is not.
// The tier must lower the first and never the second — a noise filter that can
// hide the finding is worse than no filter.
func TestTheTierLowersAnOrdinaryNewProgramAndNeverOneTalkingToAModel(t *testing.T) {
	plain := deltaEvent{Kind: deltaProcNew, Entry: procEntry("aaaa", "root", "svc", "thing")}
	if got := deltaLevel(plain); got != deltaWarn {
		t.Errorf("an unexplained new program is %q, want warn", got)
	}
	plain.Tier = tierKnown
	if got := deltaLevel(plain); got != deltaNotice {
		t.Errorf("an explained new program is %q, want notice", got)
	}
	talking := plain
	talking.Entry.Endpoints = []string{"api.anthropic.com"}
	if got := deltaLevel(talking); got != deltaHigh {
		t.Fatalf("a KNOWN-tier program talking to a model is %q, want high. The package "+
			"database shipping /usr/bin/python3 says nothing about what it is doing.", got)
	}
	signed := plain
	signed.Entry.Signature = "claude-code"
	if got := deltaLevel(signed); got != deltaHigh {
		t.Fatalf("a KNOWN-tier program with an agent signature is %q, want high", got)
	}
}

// THE BASTION'S OWN UPDATE MUST NOT BE A CRITICAL. Every machine on this fleet
// takes published updates; a critical that fires on each one is a critical
// nobody reads by the third. A digest that moved WITHOUT the version is the
// swap, and stays critical.
func TestABastionUpdateIsHighAndASilentSwapIsCritical(t *testing.T) {
	upd := deltaBinaryEvent("aaaa", "0.27.0", "bbbb", "0.28.0")
	if upd == nil || upd.Level != deltaHigh {
		t.Fatalf("a bastion self-update levelled %+v, want high", upd)
	}
	swap := deltaBinaryEvent("aaaa", "0.27.0", "bbbb", "0.27.0")
	if swap == nil || swap.Level != deltaCritical {
		t.Fatalf("a binary replaced under the SAME version levelled %+v, want critical", swap)
	}
	if same := deltaBinaryEvent("aaaa", "0.27.0", "aaaa", "0.27.0"); same != nil {
		t.Error("an unchanged binary produced an event")
	}
	if blind := deltaBinaryEvent("", "", "aaaa", "0.27.0"); blind != nil {
		t.Error("a baseline that recorded no digest produced a change event — there is " +
			"nothing to compare, and an absent record is not a difference")
	}
}

// AND THE CRITICAL RUNG SURVIVES THE FIRST LEGITIMATE UPDATE. Compared against
// the ACCOUNTING's version — which nothing retakes when the bastion updates
// itself — every machine on an auto-updating fleet is permanently "newer than
// its baseline", so every later digest change reads as another update and comes
// out high. The rung was disarmed by the very event its own justification was
// written around.
func TestASwapAfterALegitimateUpdateIsStillCritical(t *testing.T) {
	// The accounting was taken at 0.27.0/aaaa. The fleet updates.
	upd := deltaBinaryEvent("aaaa", "0.27.0", "bbbb", "0.28.0")
	if upd == nil || upd.Level != deltaHigh {
		t.Fatalf("the update levelled %+v, want high", upd)
	}
	// Days later, still 0.28.0, and the binary moves again. Compared against
	// what the LAST PASS saw, this is the swap.
	swap := deltaBinaryEvent("bbbb", "0.28.0", "cccc", "0.28.0")
	if swap == nil || swap.Level != deltaCritical {
		t.Fatalf("a binary replaced under an unchanged version, after an earlier update, "+
			"levelled %+v — want critical. Comparing against the accounting's frozen "+
			"version is what switches this rung off for good.", swap)
	}
}

// AN ABSENCE IS NOT A FINDING ON THE STRENGTH OF ONE SCAN. A service restart,
// an upgrade that stops and starts a unit, a reboot: each makes the accounting
// briefly wrong, and reporting on the first miss reports all three.
func TestAnAbsenceIsOnlyReportedOnceItHasOutlastedARestart(t *testing.T) {
	gone := deltaEvent{Kind: deltaProcGone, FP: "fp1"}
	st := freshState(t)
	t0 := time.Now()
	if out := deltaApplyGrace([]deltaEvent{gone}, st, t0); len(out) != 0 {
		t.Fatalf("the FIRST miss was reported: %+v", out)
	}
	if out := deltaApplyGrace([]deltaEvent{gone}, st, t0.Add(deltaGoneGrace-time.Minute)); len(out) != 0 {
		t.Fatalf("an absence inside the grace was reported: %+v", out)
	}
	out := deltaApplyGrace([]deltaEvent{gone}, st, t0.Add(deltaGoneGrace+time.Minute))
	if len(out) != 1 {
		t.Fatalf("an absence past the grace was NOT reported: %+v", out)
	}
	if out[0].FirstSeen == "" {
		t.Error("the reported absence does not say when it started")
	}
}

// A service that bounces must not accumulate. Without clearing the clock when
// it comes back, the SECOND bounce is measured from the first and reports gone
// immediately — for ever after.
func TestAServiceThatComesBackResetsItsClock(t *testing.T) {
	gone := deltaEvent{Kind: deltaProcGone, FP: "fp1"}
	st := freshState(t)
	t0 := time.Now()
	deltaApplyGrace([]deltaEvent{gone}, st, t0)
	deltaApplyGrace(nil, st, t0.Add(time.Minute)) // it is back: no gone event this pass
	if out := deltaApplyGrace([]deltaEvent{gone}, st, t0.Add(deltaGoneGrace+time.Minute)); len(out) != 0 {
		t.Fatalf("after coming back and going again it reported immediately, timed from "+
			"the FIRST disappearance: %+v", out)
	}
}

// A baseline entry whose post is now filled by something else is already
// reported as the change at that post. Reporting it gone as well makes one
// event into two halves of the same sentence — the exact defect the slot key
// exists to remove.
func TestAReplacedEntryIsNotAlsoReportedGone(t *testing.T) {
	was := procEntry("aaaa", "root", "web.service", "node server.js")
	now := procEntry("bbbb", "root", "web.service", "node server.js")
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(now, 5)})
	if n := len(eventsOfKind(evs, deltaProcGone)); n != 0 {
		t.Errorf("%d gone events beside the change: %+v", n, evs)
	}
}

// ── the noise filter ────────────────────────────────────────────────────────

// A PROGRAM REPORTING ITS OWN WORK AS AN INTRUSION IS IGNORED BY WEEK TWO. The
// bastion runs harnesses, labs and session shells; all of them are below it in
// the process tree and none of them is a finding.
func TestWhatThisBastionItselfStartedIsNotAFinding(t *testing.T) {
	ev := deltaEvent{Kind: deltaProcNew, FP: "fp1", PIDs: []int{300},
		Entry: procEntry("aaaa", "root", "svc", "harness run")}
	n := deltaNoise{Self: 100, Parents: map[int]int{300: 200, 200: 100}, Sockets: true}
	findings, filtered := deltaFilter([]deltaEvent{ev}, n, freshState(t), time.Now())
	if len(findings) != 0 || len(filtered) != 1 {
		t.Fatalf("a grandchild of this bastion was reported: findings=%+v", findings)
	}
	if filtered[0].Filtered != deltaFilterBastion {
		t.Errorf("filtered for %q, want %q", filtered[0].Filtered, deltaFilterBastion)
	}
	// And a process that merely SHARES a fingerprint with one of ours is still
	// the user's: `every`, not `any`.
	ev.PIDs = []int{300, 999}
	findings, _ = deltaFilter([]deltaEvent{ev}, n, freshState(t), time.Now())
	if len(findings) != 1 {
		t.Error("an entry with a process that is NOT ours was filtered anyway — a " +
			"binary the bastion runs and the user also runs is still the user's")
	}
}

// Short-lived work is counted, not reported — and only once it has proved it
// was short-lived by being gone next time.
func TestSomethingThatCameAndWentIsCountedNotReported(t *testing.T) {
	st := freshState(t)
	young := deltaEvent{Kind: deltaProcNew, FP: "fp1", PIDs: []int{7},
		Entry: procEntry("aaaa", "user", "interactive", "ls")}
	n := deltaNoise{Self: 1, Parents: map[int]int{7: 2}, Sockets: true,
		Age: func(int) (time.Duration, bool) { return time.Second, true }}
	findings, filtered := deltaFilter([]deltaEvent{young}, n, st, time.Now())
	if len(findings) != 0 || len(filtered) != 1 {
		t.Fatalf("a one-second-old process was reported: %+v", findings)
	}
	if st.ShortLived != 0 {
		t.Error("it was counted while still running — it has not proved anything yet")
	}
	// Next pass: it is gone.
	if _, _ = deltaFilter(nil, n, st, time.Now()); st.ShortLived != 1 {
		t.Errorf("short-lived count = %d, want 1 — the storm counter never moved", st.ShortLived)
	}
	// And one that is still there next pass is a finding after all.
	st2 := freshState(t)
	deltaFilter([]deltaEvent{young}, n, st2, time.Now())
	n.Age = func(int) (time.Duration, bool) { return time.Hour, true }
	findings, _ = deltaFilter([]deltaEvent{young}, n, st2, time.Now())
	if len(findings) != 1 {
		t.Error("a process that survived was still being held back")
	}
	if st2.ShortLived != 0 {
		t.Error("something that survived was counted as short-lived")
	}
}

// The short-lived rule's exemptions are not optional: whatever opened a listening socket or
// reached a model endpoint in its first seconds is the most interesting thing
// on the box, not the least. And where the socket table could not be read at
// all, the rule does not fire — an exemption that cannot be checked is not one.
func TestTheShortLivedRuleNeverSwallowsAListenerOrAModelEndpoint(t *testing.T) {
	base := deltaNoise{Self: 1, Parents: map[int]int{7: 2}, Sockets: true,
		Age: func(int) (time.Duration, bool) { return time.Second, true }}
	young := deltaEvent{Kind: deltaProcNew, FP: "fp1", PIDs: []int{7},
		Entry: procEntry("aaaa", "user", "interactive", "x")}

	talking := young
	talking.Entry.Endpoints = []string{"api.anthropic.com"}
	if f, _ := deltaFilter([]deltaEvent{talking}, base, freshState(t), time.Now()); len(f) != 1 {
		t.Error("a process talking to a model was filtered for being young")
	}
	listening := base
	listening.Listening = map[int]bool{7: true}
	if f, _ := deltaFilter([]deltaEvent{young}, listening, freshState(t), time.Now()); len(f) != 1 {
		t.Error("a process holding a listening socket was filtered for being young")
	}
	blind := base
	blind.Sockets = false
	if f, _ := deltaFilter([]deltaEvent{young}, blind, freshState(t), time.Now()); len(f) != 1 {
		t.Error("the rule fired on a box that could not read its socket table, so it " +
			"could not know whether the exemption applied")
	}
	ageless := base
	ageless.Age = func(int) (time.Duration, bool) { return 0, false }
	if f, _ := deltaFilter([]deltaEvent{young}, ageless, freshState(t), time.Now()); len(f) != 1 {
		t.Error("the rule fired where the platform cannot read a process age — an " +
			"unknown age was treated as a young one")
	}
}

// BEING STARTED BY SOMETHING IN THE ACCOUNTING CHANGES NOTHING ABOUT A FINDING,
// and this is the test for a rule that was BUILT, MEASURED AND THEN TAKEN OUT.
//
// Measured on a live machine: with the parent rule lowering the
// tier, a brand-new root-owned binary at /tmp/brandnewthing and a swapped
// binary at a known post both came out as `notice` — because each had been
// started from a shell that was running when the accounting was taken. On a
// real machine nearly everything is a child of something that was already
// running, so the design's rule minus its declared-children set is not a noise
// filter, it is a way to lose the two findings that matter most.
func TestBeingStartedByAKnownProcessDoesNotLowerAFinding(t *testing.T) {
	ev := deltaEvent{Kind: deltaProcNew, FP: "fp1", PIDs: []int{300},
		Entry: procEntry("aaaa", "root", "web.service", "sh -c curl")}
	n := deltaNoise{Self: 1, Parents: map[int]int{300: 200}, BaselinePIDs: map[int]bool{200: true},
		Sockets: true}
	findings, filtered := deltaFilter([]deltaEvent{ev}, n, freshState(t), time.Now())
	if len(findings) != 1 {
		t.Fatalf("a child of a baseline process was REMOVED from the findings (%d filtered). "+
			"Without the declared children set that is the attack being hidden.", len(filtered))
	}
	if findings[0].Tier == tierKnown {
		t.Fatal("a new program was lowered to `known` for having been started by a " +
			"process that was already running. Every interactive program on a machine " +
			"is a child of a shell that was already running.")
	}
	if got := deltaLevel(findings[0]); got != deltaWarn {
		t.Errorf("level = %q, want warn — nothing here explains the program away", got)
	}
	// The fact still travels, because it is real context for whoever reads it.
	var said bool
	for _, e := range findings[0].Evidence {
		if e.Signal == "child-of-baseline" {
			said = true
			if e.Tier != tierAmbiguous {
				t.Errorf("the evidence line is tier %q; a signal that explains nothing "+
					"must annotate and never promote", e.Tier)
			}
		}
	}
	if !said {
		t.Error("the parentage was dropped entirely — it is context a reader wants even " +
			"though it changes no level")
	}
}

// The package database lowers a row and names the package that shipped it.
func TestAPackagedBinaryIsLoweredAndSaysWhichPackage(t *testing.T) {
	ev := deltaEvent{Kind: deltaProcNew, FP: "fp1", PIDs: []int{300},
		Entry: procEntry("aaaa", "root", "svc", "thing")}
	n := deltaNoise{Self: 1, Parents: map[int]int{300: 2}, Sockets: true,
		Packaged: func(paths []string) map[string]string {
			return map[string]string{paths[0]: "coreutils"}
		}}
	findings, _ := deltaFilter([]deltaEvent{ev}, n, freshState(t), time.Now())
	if len(findings) != 1 || findings[0].Tier != tierKnown {
		t.Fatalf("a packaged binary was not lowered: %+v", findings)
	}
	var said bool
	for _, e := range findings[0].Evidence {
		if strings.Contains(e.Value, "coreutils") {
			said = true
		}
	}
	if !said {
		t.Error("the evidence does not name the package, so the reader cannot check it")
	}
}

// Absences and the bastion's own binary have no process to explain away, and
// must never be filtered as if they did.
func TestAnAbsenceIsNeverFilteredAsNoise(t *testing.T) {
	evs := []deltaEvent{
		{Kind: deltaProcGone, FP: "a"},
		{Kind: deltaBinaryChanged, FP: "b", Level: deltaCritical},
	}
	n := deltaNoise{Self: 1, Parents: map[int]int{}, Sockets: true}
	findings, filtered := deltaFilter(evs, n, freshState(t), time.Now())
	if len(findings) != 2 || len(filtered) != 0 {
		t.Fatalf("findings=%d filtered=%d, want 2 and 0", len(findings), len(filtered))
	}
}

// ── the bookkeeping ─────────────────────────────────────────────────────────

// RETAKING THE ACCOUNTING REDEFINES NORMAL, so every clock kept against the old
// one is timing something that is no longer being compared.
func TestRetakingTheAccountingThrowsAwayTheOldClocks(t *testing.T) {
	isolateConfigDir(t)
	st := &deltaState{Version: deltaStateVersion, Baseline: "digest-one"}
	st.setMissingSince("fp1", time.Now().Add(-time.Hour))
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	if again := deltaStateLoad("digest-one"); len(again.MissingSince) != 1 {
		t.Fatalf("the state did not survive a save/load: %+v", again)
	}
	after := deltaStateLoad("digest-two")
	if len(after.MissingSince) != 0 {
		t.Error("a clock from the OLD accounting was carried into the new one — a " +
			"process missing from a baseline nobody is comparing against any more " +
			"would report gone the moment the new one was taken")
	}
}

// The state file is the bastion's own, and nothing else's business.
func TestTheDeltaStateIsWrittenPrivate(t *testing.T) {
	dir := isolateConfigDir(t)
	st := &deltaState{Version: deltaStateVersion, Baseline: "d", dirty: true}
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "delta-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
}

// A corrupt bookkeeping file costs one pass of memory, never the feature.
func TestACorruptStateFileDoesNotStopTheDelta(t *testing.T) {
	dir := isolateConfigDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "delta-state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := deltaStateLoad("d")
	if st == nil || st.Version != deltaStateVersion {
		t.Fatalf("a truncated bookkeeping file stopped the plane: %+v", st)
	}
}

// ── the wiring ──────────────────────────────────────────────────────────────

// A BOX WITH NO ACCOUNTING MUST NOT READ AS A BOX WITH NOTHING TO REPORT.
// Zero findings and "nobody ever said what normal is here" are opposite facts
// and they render identically unless the state travels with the counts.
func TestABoxWithNoAccountingSaysSoRatherThanReportingZero(t *testing.T) {
	isolateConfigDir(t)
	if !processIsRoot() {
		t.Skip("the pass refuses without machine authority, which is its own test")
	}
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	if r.Baseline != deltaBaselineNone {
		t.Fatalf("baseline = %q, want %q", r.Baseline, deltaBaselineNone)
	}
	s := r.summary()
	if s.Baseline != deltaBaselineNone {
		t.Errorf("the summary that rides the beat says %q", s.Baseline)
	}
	if len(r.Findings) != 0 {
		t.Errorf("it reported %d findings against an accounting that does not exist", len(r.Findings))
	}
}

// AN ACCOUNTING TAKEN UNDER OTHER FINGERPRINT RULES REPORTS THE WHOLE MACHINE.
// baselineVersion is bumped exactly so old entries cannot match new ones, which
// makes the first pass after such a bump 188 findings that are all one fact
// about a software upgrade. One sentence asking for a retake is the answer.
func TestAnAccountingFromOlderRulesIsNotComparedAtAll(t *testing.T) {
	dir := isolateConfigDir(t)
	if !processIsRoot() {
		t.Skip("the pass refuses without machine authority, which is its own test")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := baselineFile{Version: "privatae-baseline-v0", TakenAt: "2026-01-01T00:00:00Z",
		Coverage: "processes=all,schedulers=all",
		Entries:  []baselineEntry{procEntry("aaaa", "root", "svc", "thing")}}
	if err := baselineSave(old); err != nil {
		t.Fatal(err)
	}
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	if r.Baseline != deltaBaselineStale {
		t.Fatalf("baseline = %q, want %q", r.Baseline, deltaBaselineStale)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("it reported %d findings against an accounting it cannot compare with", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "taken again") {
		t.Errorf("the notes do not say what to do about it: %v", r.Notes)
	}
}

// The delta refuses to run without machine authority rather than producing a
// page of false findings from a view of the box the accounting never had.
func TestWithoutMachineAuthorityThePassSaysSoInsteadOfGuessing(t *testing.T) {
	if processIsRoot() {
		t.Skip("this test is about the unprivileged path; run the suite as a user for it")
	}
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	if r.Baseline != deltaBaselineNoAuth {
		t.Fatalf("baseline = %q, want %q", r.Baseline, deltaBaselineNoAuth)
	}
}

// THE SUMMARY REACHES THE HOST. A detection plane whose result never leaves the
// box is a detection plane nobody has. This holds the wiring — that
// buildHeartbeatBody actually carries what deltaPayload publishes — rather than
// only that the two functions exist.
func TestTheFindingsSummaryRidesTheHeartbeat(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	deltaMu.Lock()
	deltaLast = &deltaSummary{Baseline: deltaBaselineOK, High: 2, Critical: 1,
		NewSince: "2026-09-14T22:00:00Z"}
	deltaMu.Unlock()
	t.Cleanup(func() {
		deltaMu.Lock()
		deltaLast = nil
		deltaMu.Unlock()
	})
	body := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	for _, want := range []string{`"findings"`, `"critical":1`, `"high":2`, `"baseline":"ok"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("the heartbeat does not carry %s:\n%s", want, body)
		}
	}
}

// Before the first pass completes there is no key at all, the way posture does
// it — an absent field is a host that keeps what it had, and a zeroed one is a
// host told this machine is clean.
func TestNoSummaryTravelsBeforeTheFirstPass(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	deltaMu.Lock()
	deltaLast = nil
	deltaMu.Unlock()
	if body := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil); strings.Contains(body, `"findings"`) {
		t.Fatalf("a findings key travelled before anything had been measured:\n%s", body)
	}
}

// ── /proc's byte layout ─────────────────────────────────────────────────────

// The comm field is parenthesised and may contain spaces AND parens, which is
// why the fields are counted from the last ')'. A process named ") (" is legal
// and is how a naive split gets the wrong number.
func TestTheProcessStartTimeIsReadFromTheRightField(t *testing.T) {
	// pid comm state ppid ... starttime is field 22.
	fields := []string{"2", "1", "1", "0", "0", "0", "0", "0", "0", "0",
		"0", "0", "0", "0", "0", "0", "0", "0", "914623"}
	line := "1234 (weird ) name) S " + strings.Join(fields, " ") + " 0 0 0"
	got, ok := parseProcStatStartTicks(line)
	if !ok || got != 914623 {
		t.Fatalf("start ticks = %d (%v), want 914623 — a wrong field here makes every "+
			"process read as the wrong age", got, ok)
	}
	if _, ok := parseProcStatStartTicks("garbage with no paren"); ok {
		t.Error("a line with no comm field read as a valid start time")
	}
	if _, ok := parseProcStatStartTicks("1 (x) S 0 0"); ok {
		t.Error("a truncated line read as a valid start time")
	}
}

// ── what a second look found ────────────────────────────────────────────────

// A SECOND PROGRAM BESIDE THE FIRST IS NOT A REPLACEMENT OF IT. The slot rule
// fired on "the slot is known" alone, so a venv or pyenv interpreter starting
// the same script beside the system one — same user, same unit, same masked
// argv — came out as proc_changed at high, carrying `was:` a process that was
// still running. A doorbell that rings for a benign event is what the noise
// filter exists to prevent, and the sentence it rang with was not true.
func TestASecondProgramBesideTheOriginalIsNewNotAReplacement(t *testing.T) {
	was := procEntry("aaaa", "root", "web.service", "python3 x.py")
	second := procEntry("bbbb", "root", "web.service", "python3 x.py")
	// Both running: the original is still there.
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(was, 1), liveOf(second, 2)})
	if n := len(eventsOfKind(evs, deltaProcChanged)); n != 0 {
		t.Fatalf("%d proc_changed while the original was still running: %+v", n, evs)
	}
	if n := len(eventsOfKind(evs, deltaProcNew)); n != 1 {
		t.Fatalf("got %d proc_new, want 1: %+v", n, evs)
	}
	// And when the original HAS gone, it is a replacement again.
	evs = deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(second, 2)})
	if n := len(eventsOfKind(evs, deltaProcChanged)); n != 1 {
		t.Fatalf("with the original gone this must be one proc_changed, got %+v", evs)
	}
}

// THE OTHER HALF OF THE SAME RULE: an entry that leaves must still be reported
// gone when something ELSE happens to share its slot. Suppressing on "is
// anything standing here" lost the departure entirely.
func TestOneOfTwoEntriesSharingASlotLeavingIsStillReported(t *testing.T) {
	a := procEntry("aaaa", "root", "web.service", "python3 x.py")
	b := procEntry("bbbb", "root", "web.service", "python3 x.py")
	// b stays, a goes. They share a slot; a's absence is its own fact.
	evs := deltaCompare([]baselineEntry{a, b}, []deltaLiveEntry{liveOf(b, 2)})
	gone := eventsOfKind(evs, deltaProcGone)
	if len(gone) != 1 || gone[0].FP != a.FP {
		t.Fatalf("the entry that left was not reported gone: %+v", evs)
	}
}

// THE PACKAGE DATABASE EXPLAINS THE BINARY, NEVER THE ENDPOINT. apt upgrades
// node, the service that runs it restarts, and it now talks to api.openai.com:
// the proc_changed branch demoted on the tier alone and landed that at notice,
// while the identical situation as a proc_new came out high. Two branches
// asking the same question about the same machine have to answer the same
// way.
func TestAPackagedReplacementTalkingToAModelIsStillHigh(t *testing.T) {
	was := procEntry("aaaa", "root", "web.service", "node server.js")
	now := procEntry("bbbb", "root", "web.service", "node server.js")
	now.Endpoints = []string{"api.openai.com"}
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(now, 9)})
	changed := eventsOfKind(evs, deltaProcChanged)
	if len(changed) != 1 {
		t.Fatalf("got %+v", evs)
	}
	// The event has to CARRY the endpoint, or no tier could see it.
	if len(changed[0].Added) != 1 || changed[0].Added[0] != "api.openai.com" {
		t.Fatalf("the replacement event does not name the model endpoint it gained: %+v",
			changed[0].Added)
	}
	ev := changed[0]
	ev.Tier = tierKnown // the distribution shipped the new binary
	if got := deltaLevel(ev); got != deltaHigh {
		t.Fatalf("a PACKAGED replacement that also began talking to a model levelled %q, "+
			"want high. The package database explains the binary; it says nothing about "+
			"what the program is doing.", got)
	}
}

// THE TWO SIDES OF THE COMPARISON AGGREGATE THE SAME WAY. The accounting kept
// the first pid's endpoints and the delta's live side unioned them, so four
// workers of one service with only the fourth talking to a model recorded no
// endpoint at baseline and then reported proc_changed[llm_endpoint] at high on
// an unchanged machine, every pass until the accounting was retaken.
func TestTheAccountingUnionsEndpointsTheWayTheDeltaDoes(t *testing.T) {
	obs := []agentObs{
		{PID: 1, User: "root", Cmdline: "worker --port 3001", Origin: "service"},
		{PID: 2, User: "root", Cmdline: "worker --port 3002", Origin: "service",
			LLMEndpoints: []string{"api.openai.com"}},
	}
	entries, _ := baselineFromObservations(obs, func(string) (string, string) { return "d", "" })
	if len(entries) != 1 {
		t.Fatalf("two workers of one service made %d entries", len(entries))
	}
	if len(entries[0].Endpoints) != 1 || entries[0].Endpoints[0] != "api.openai.com" {
		t.Fatalf("the accounting recorded %v — the endpoint belonged to the SECOND pid and "+
			"was dropped, so the next delta reports it as newly appeared on an "+
			"unchanged machine", entries[0].Endpoints)
	}
	// Which is exactly what the live side would build from the same input.
	live, _, _ := deltaCollectLiveFrom(obs, func(string) (string, string) { return "d", "" })
	if len(live) != 1 || len(live[0].Entry.Endpoints) != 1 {
		t.Fatalf("the live side built %+v", live)
	}
	if evs := deltaCompare(entries, live); len(evs) != 0 {
		t.Fatalf("the same machine compared against itself produced %d events: %+v", len(evs), evs)
	}
}

// THE MODEL ENDPOINT REACHES THE WALK AT ALL. The unfiltered /proc walk carries
// pid, user, argv, exe, unit and parent and no endpoints; only the observe
// plane resolves those. So on Linux — the one platform WITH the full walk —
// both sides of every comparison held an empty list and the two rules that rest
// on it could never fire.
func TestTheWalkCarriesTheModelEndpointsItIsJudgedOn(t *testing.T) {
	obs := []agentObs{{PID: 41, User: "user", Cmdline: "python3 agent.py"}}
	got := baselineAttachEndpoints(obs, map[int][]string{41: {"api.anthropic.com"}})
	if len(got[0].LLMEndpoints) != 1 {
		t.Fatal("the join dropped the endpoint, so every level that depends on one is dead")
	}
	// And on this machine, for real: whatever the observe plane can see, the
	// walk the delta is built from must also see.
	seen := map[int][]string{}
	agentsNow, err := scanAgents()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range agentsNow {
		if len(a.LLMEndpoints) > 0 {
			seen[a.PID] = a.LLMEndpoints
		}
	}
	if len(seen) == 0 {
		t.Skip("nothing on this box is talking to a model right now")
	}
	walked, complete, err := baselineWalk()
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Skip("this platform has no unfiltered walk, so there is nothing to enrich")
	}
	found := 0
	for _, a := range walked {
		if _, ok := seen[a.PID]; ok && len(a.LLMEndpoints) > 0 {
			found++
		}
	}
	if found == 0 {
		t.Fatalf("the observe plane sees %d processes talking to a model and the walk the "+
			"delta compares carries none of them", len(seen))
	}
}

// THE DAEMON READS ITS BINARY FROM DISK. selfDigest() is a sync.Once frozen at
// process start (enforcing.go:35-38), so a long-running daemon compared its own
// startup digest for ever and could never observe its binary being replaced —
// the one process in a position to notice, unable to.
func TestTheBastionBinaryIsReadFromDiskAndNotFromAFrozenDigest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "privatae-bastion")
	if err := os.WriteFile(p, []byte("version one"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := deltaSelfPath
	deltaSelfPath = p
	t.Cleanup(func() { deltaSelfPath = old })

	dc := &digestCache{}
	before := deltaSelfOnDisk(dc)
	if before == "" {
		t.Fatal("the binary was not digested at all")
	}
	// Replaced the way replaceSelf does it: the old one moved aside, a new one
	// written at the same path (update.go:160-169).
	if err := os.Rename(p, p+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("version two"), 0o755); err != nil {
		t.Fatal(err)
	}
	after := deltaSelfOnDisk(dc)
	if after == before {
		t.Fatal("the bastion read the same digest after its binary was replaced under it. " +
			"A frozen digest, or one taken from /proc/self/exe — which follows the inode " +
			"to the file that was moved ASIDE — both read like this.")
	}
}

// ONE PASS PER BOX, NOT ONE PER PAIRING. run.go starts a refresher beside every
// heartbeat, so a box serving three hosts ran three full passes a minute and
// three read-modify-writers of one state file — and whether a 40-second process
// was counted or reported depended on how many hosts the box served.
func TestASecondRefresherDoesNotRunItsOwnPass(t *testing.T) {
	deltaMu.Lock()
	oldLast, oldAt, oldRan := deltaLast, deltaAt, deltaRan
	deltaLast, deltaAt, deltaRan = &deltaSummary{Baseline: "sentinel"}, time.Now(), true
	deltaMu.Unlock()
	t.Cleanup(func() {
		deltaMu.Lock()
		deltaLast, deltaAt, deltaRan = oldLast, oldAt, oldRan
		deltaMu.Unlock()
	})
	refreshDelta()
	deltaMu.Lock()
	got := deltaLast.Baseline
	deltaMu.Unlock()
	if got != "sentinel" {
		t.Fatalf("the second refresher ran its own pass (published %q). N pairings would "+
			"mean N passes a minute over one state file.", got)
	}
}

// SOMETHING THAT IS ALWAYS YOUNG IS A PATTERN, NOT SHORT-LIVED WORK. A
// respawner — a crash-looping unit, a beacon relaunched every few seconds — was
// young at every pass, so it was re-held at every pass and, being seen each
// time, never settled into the short-lived count either: no finding, and a
// storm counter reading zero.
func TestARespawnerStopsBeingHeldAndBecomesAFinding(t *testing.T) {
	st := freshState(t)
	ev := deltaEvent{Kind: deltaProcNew, FP: "fp1", PIDs: []int{7},
		Entry: procEntry("aaaa", "user", "interactive", "beacon")}
	n := deltaNoise{Self: 1, Parents: map[int]int{7: 2}, Sockets: true,
		Age: func(int) (time.Duration, bool) { return time.Second, true }}

	start := time.Now()
	for i := 0; i < 4; i++ {
		findings, _ := deltaFilter([]deltaEvent{ev}, n, st, start.Add(time.Duration(i)*time.Minute))
		if len(findings) != 0 {
			t.Fatalf("pass %d reported it before the hold ceiling", i)
		}
	}
	findings, _ := deltaFilter([]deltaEvent{ev}, n, st, start.Add(deltaHoldMax+time.Minute))
	if len(findings) != 1 {
		t.Fatal("a process that has been 'about to go away' for longer than the ceiling " +
			"is still being held. It is never counted either, because it is seen every pass.")
	}
	var said bool
	for _, e := range findings[0].Evidence {
		if e.Signal == "respawning" {
			said = true
		}
	}
	if !said {
		t.Error("the finding does not say WHY it arrived late — that it kept coming back")
	}
}

// THE WIRING OF THE BASTION-BINARY RUNG, DRIVEN THROUGH A REAL PASS.
//
// The two unit tests above hold deltaSelfOnDisk and deltaBinaryEvent in
// isolation, and a mutation that pointed deltaPass back at selfDigest() — or
// back at the accounting's frozen version — passed both of them. That is the
// defect shape this whole plane keeps being caught by: the claim asserted at a
// layer nothing wires to. So this drives the pass itself, three times, and
// watches the rung move.
func TestThePassReadsTheBinaryFromDiskAndRemembersWhatItSaw(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)

	fixture := filepath.Join(t.TempDir(), "privatae-bastion")
	writeBinary := func(body string) string {
		t.Helper()
		if _, err := os.Stat(fixture); err == nil {
			// Replaced the way replaceSelf does it (update.go:160-169).
			if err := os.Rename(fixture, fixture+".old"); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(fixture, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		d, _ := baselineExeDigest(fixture)
		return d
	}
	oldPath, oldVersion := deltaSelfPath, clientVersion
	deltaSelfPath = fixture
	t.Cleanup(func() { deltaSelfPath, clientVersion = oldPath, oldVersion })

	// An accounting taken by 0.27.0, with that binary on disk.
	clientVersion = "0.27.0"
	first := writeBinary("version one")
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	base.BastionDigest, base.BastionVersion = first, "0.27.0"
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}

	binaryEvent := func(r deltaReport) *deltaEvent {
		for i := range r.Findings {
			if r.Findings[i].Kind == deltaBinaryChanged {
				return &r.Findings[i]
			}
		}
		return nil
	}

	dc := &digestCache{}
	if ev := binaryEvent(deltaPass(dc, time.Now(), deltaRoleDaemon)); ev != nil {
		t.Fatalf("an unchanged binary produced %+v", ev)
	}

	// The fleet update: new binary, new version.
	writeBinary("version two")
	clientVersion = "0.28.0"
	ev := binaryEvent(deltaPass(dc, time.Now(), deltaRoleDaemon))
	if ev == nil {
		t.Fatal("the bastion's binary was replaced on disk and the pass did not notice. " +
			"selfDigest() is frozen at process start, so a pass that asks IT can never see this.")
	}
	if ev.Level != deltaHigh {
		t.Fatalf("the update levelled %q, want high", ev.Level)
	}

	// And now the swap: new binary, SAME version, after that update.
	writeBinary("version three")
	ev = binaryEvent(deltaPass(dc, time.Now(), deltaRoleDaemon))
	if ev == nil {
		t.Fatal("the second replacement was not noticed at all")
	}
	if ev.Level != deltaCritical {
		t.Fatalf("a binary replaced under an unchanged version, after an earlier update, "+
			"levelled %q — want critical. Compared against the ACCOUNTING's version this "+
			"reads as one more update for ever, because nothing retakes the accounting "+
			"when the bastion updates itself.", ev.Level)
	}

	// A FOURTH PASS, WHICH IS WHERE THE DEFECT LIVED. Advancing the remembered
	// pair after reporting a swap makes the swapped binary the new normal, so
	// the critical appears for exactly one beat — into a summary the host does
	// not store — and an operator running observe:delta an hour later is told
	// the machine is clean. A finding this severe is pinned until a human
	// resolves it, which here means retaking the accounting.
	ev = binaryEvent(deltaPass(dc, time.Now(), deltaRoleDaemon))
	if ev == nil {
		t.Fatal("the swap was reported once and then absorbed. The pass that reports it " +
			"must not record the swapped binary as what the machine last saw.")
	}
	if ev.Level != deltaCritical {
		t.Fatalf("the repeat levelled %q, want critical", ev.Level)
	}

	// And the UPDATE is not repeated, which is the other half of the same rule:
	// a legitimate new version becomes the new normal exactly once.
	writeBinary("version four")
	clientVersion = "0.29.0"
	if ev = binaryEvent(deltaPass(dc, time.Now(), deltaRoleDaemon)); ev == nil || ev.Level != deltaHigh {
		t.Fatalf("the second update levelled %+v, want high", ev)
	}
	if ev = binaryEvent(deltaPass(dc, time.Now(), deltaRoleDaemon)); ev != nil {
		t.Fatalf("the update was reported again on the next pass: %+v", ev)
	}
}

// THE SEED FROM THE ACCOUNTING IS WHAT COVERS THE FIRST PASS — on a fresh
// install, after a retake, after a corrupt state file. Nothing held it: deleting
// the seed left the whole suite green, and without it
// the first pass is blind to a swap that happened before it ran.
func TestTheFirstPassComparesAgainstTheAccounting(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)
	fixture := filepath.Join(t.TempDir(), "privatae-bastion")
	if err := os.WriteFile(fixture, []byte("the one that is here now"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath, oldVersion := deltaSelfPath, clientVersion
	deltaSelfPath, clientVersion = fixture, "0.27.0"
	t.Cleanup(func() { deltaSelfPath, clientVersion = oldPath, oldVersion })

	// The accounting recorded a DIFFERENT binary under this same version — the
	// swap happened before this process ever ran a pass.
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	base.BastionDigest, base.BastionVersion = "a-different-binary-entirely", "0.27.0"
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleDaemon)
	found := false
	for _, ev := range r.Findings {
		if ev.Kind == deltaBinaryChanged {
			found = true
			if ev.Level != deltaCritical {
				t.Errorf("levelled %q, want critical", ev.Level)
			}
		}
	}
	if !found {
		t.Fatal("with no prior pass to compare against, the accounting's record is the " +
			"only thing that can catch this, and it was not consulted")
	}
}

// AN OPERATOR'S OWN COMMAND MUST NOT POISON THE DAEMON'S BOOKKEEPING. Running
// observe:delta from a copy of the binary somewhere else would otherwise record
// THAT copy as what the machine last saw, and the daemon's next pass reports a
// swap that never happened.
func TestAnOperatorPassDoesNotRewriteWhatTheMachineLastSaw(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)
	fixture := filepath.Join(t.TempDir(), "some-other-copy")
	if err := os.WriteFile(fixture, []byte("a developer's build"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath, oldVersion := deltaSelfPath, clientVersion
	deltaSelfPath, clientVersion = fixture, "0.27.0"
	t.Cleanup(func() { deltaSelfPath, clientVersion = oldPath, oldVersion })

	// The accounting records THIS copy, so the pass finds nothing to report —
	// which is precisely the case where a daemon pass advances the remembered
	// pair. If the role is ignored, this is where the operator's copy gets
	// written down as what the machine last saw.
	mine, _ := baselineExeDigest(fixture)
	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	base.BastionDigest, base.BastionVersion = mine, "0.27.0"
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	// THE KEY THE STATE IS FILED UNDER IS THE SAVED FILE'S DIGEST, not the one
	// on the struct that was handed to baselineSave — that function digests its
	// own copy. Reading it back is the difference between this test checking
	// something and this test always passing.
	saved, _, err := baselineLoad()
	if err != nil {
		t.Fatal(err)
	}
	if st := deltaStateLoad(saved.Digest); st.BastionDigest != "" {
		t.Fatalf("the fixture state was not empty to begin with: %q", st.BastionDigest)
	}
	deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	if st := deltaStateLoad(saved.Digest); st.BastionDigest != "" {
		t.Fatalf("an operator pass wrote %q into the shared state as what the machine "+
			"last saw. Run from a copy of the binary somewhere else, that is a swap the "+
			"daemon reports on its next pass and nobody made.", st.BastionDigest)
	}
	// And the daemon in the same position DOES advance — otherwise this test
	// would pass against a pass that never writes anything at all.
	deltaPass(&digestCache{}, time.Now(), deltaRoleDaemon)
	if st := deltaStateLoad(saved.Digest); st.BastionDigest != mine {
		t.Fatalf("the daemon's pass recorded %q, want the binary it actually has", st.BastionDigest)
	}
}

// A v1 ACCOUNTING CANNOT BE COMPARED, because its entries mean something
// different: on Linux it holds no model endpoints for anything, while a walk
// now does. The fingerprints still match, so nothing else would have caught it
// — every known process talking to a model would report proc_changed
// [llm_endpoint] at high until somebody retook it.
func TestTheAccountingVersionMovedWithItsMeaning(t *testing.T) {
	dir := isolateConfigDir(t)
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	if baselineVersion == "privatae-baseline-v1" {
		t.Fatal("the endpoint join changed what an entry MEANS without moving the version, " +
			"so a baseline taken before it compares as a page of model-endpoint findings")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := baselineFile{Version: "privatae-baseline-v1", TakenAt: "2026-09-14T23:51:04Z",
		Coverage: "processes=all,schedulers=all",
		Entries:  []baselineEntry{procEntry("aaaa", "root", "svc", "python3 x.py")}}
	if err := baselineSave(old); err != nil {
		t.Fatal(err)
	}
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	if r.Baseline != deltaBaselineStale {
		t.Fatalf("a v1 accounting read as %q, want %q", r.Baseline, deltaBaselineStale)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("it produced %d findings against an accounting it cannot compare with", len(r.Findings))
	}
}

// TWO BASELINE ENTRIES AT ONE SLOT, AND ONE OF THEM UPGRADES. Keeping only the
// first entry per slot made the answer depend on which of them sorted first:
// the upgraded one either read as a replacement or as an unrelated new program
// with the untrue line "neither this program nor anything in its place was in
// the accounting", while its predecessor was separately reported gone. A hash
// order was choosing between two different sentences.
func TestAnUpgradeAtASharedSlotIsAReplacementWhicheverWaySorted(t *testing.T) {
	a := procEntry("aaaa", "root", "web.service", "python3 x.py") // system python
	b := procEntry("bbbb", "root", "web.service", "python3 x.py") // a second one
	upgraded := procEntry("cccc", "root", "web.service", "python3 x.py")

	for _, order := range [][]baselineEntry{{a, b}, {b, a}} {
		// a is still running; b has been upgraded to `upgraded`.
		evs := deltaCompare(order, []deltaLiveEntry{liveOf(a, 1), liveOf(upgraded, 2)})
		changed := eventsOfKind(evs, deltaProcChanged)
		if len(changed) != 1 {
			t.Fatalf("order %v: got %+v", []string{order[0].ExeDigest, order[1].ExeDigest}, evs)
		}
		if changed[0].Was == nil || changed[0].Was.FP != b.FP {
			t.Errorf("the replacement names the wrong predecessor: %+v", changed[0].Was)
		}
		if n := len(eventsOfKind(evs, deltaProcNew)); n != 0 {
			t.Errorf("order %v: %d proc_new as well", []string{order[0].ExeDigest, order[1].ExeDigest}, n)
		}
		if n := len(eventsOfKind(evs, deltaProcGone)); n != 0 {
			t.Errorf("order %v: %d proc_gone as well", []string{order[0].ExeDigest, order[1].ExeDigest}, n)
		}
	}
}

// A BINARY REPLACED AND THEN UNLINKED IS THE MOST DELIBERATE VERSION OF THIS,
// and it digested as empty — the exe path reads " (deleted)", which is stripped,
// and the stat then fails — so it came out as a visibility notice. The
// unreadable shortcut now sits BELOW the endpoint check.
func TestAReplacedBinaryThatWasUnlinkedIsNotJustAVisibilityNotice(t *testing.T) {
	was := procEntry("aaaa", "root", "web.service", "node server.js")
	gone := procEntry("", "root", "web.service", "node server.js")
	gone.DigestNote = "could not be read by this account"
	gone.Endpoints = []string{"api.openai.com"}
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(gone, 3)})
	changed := eventsOfKind(evs, deltaProcChanged)
	if len(changed) != 1 {
		t.Fatalf("got %+v", evs)
	}
	if got := deltaLevel(changed[0]); got != deltaHigh {
		t.Fatalf("a binary replaced at a known post, unlinked, and talking to a model "+
			"levelled %q — want high. An unreadable digest is a visibility change only "+
			"when there is nothing else on the event.", got)
	}
	// With nothing else on it, it is still a notice.
	plain := changed[0]
	plain.Added, plain.Entry.Endpoints, plain.Entry.Signature = nil, nil, ""
	if got := deltaLevel(plain); got != deltaNotice {
		t.Errorf("an unreadable digest with nothing else on it levelled %q, want notice", got)
	}
}

// A PACKAGED UPGRADE OF A SERVICE THAT ALREADY TALKED TO A MODEL IS AN APT
// UPGRADE. Levelling on "has endpoints" rather than "gained endpoints" made
// every one of those high, which is the noise the tier exists to remove.
func TestAPackagedUpgradeOfAModelTalkingServiceIsNotHighOnItsOwn(t *testing.T) {
	was := procEntry("aaaa", "root", "web.service", "node server.js")
	was.Endpoints = []string{"api.openai.com"}
	now := procEntry("bbbb", "root", "web.service", "node server.js")
	now.Endpoints = []string{"api.openai.com"} // the same one, still
	evs := deltaCompare([]baselineEntry{was}, []deltaLiveEntry{liveOf(now, 4)})
	changed := eventsOfKind(evs, deltaProcChanged)
	if len(changed) != 1 {
		t.Fatalf("got %+v", evs)
	}
	ev := changed[0]
	if len(ev.Added) != 0 {
		t.Fatalf("an unchanged endpoint list was reported as added: %v", ev.Added)
	}
	ev.Tier = tierKnown // the distribution shipped the new binary
	if got := deltaLevel(ev); got != deltaNotice {
		t.Errorf("a packaged upgrade of a service whose model endpoint did not change "+
			"levelled %q, want notice", got)
	}
	// Unpackaged, the same replacement is still high.
	ev.Tier = ""
	if got := deltaLevel(ev); got != deltaHigh {
		t.Errorf("an unexplained replacement levelled %q, want high", got)
	}
}

// THE REFRESHERS ARRIVE TOGETHER, because run.go starts every pairing in one
// loop and each calls refreshDelta immediately. A freshness check alone lets
// all of them past — none has finished yet — so a three-host box ran three
// concurrent walks of the machine and three writers of one state file.
func TestRefreshersThatStartTogetherRunOnePass(t *testing.T) {
	// Isolated because the mutation this test exists to kill makes it run a REAL
	// pass — which would write this machine's own delta-state.json, as root,
	// from a test. A test that only misbehaves when
	// it is doing its job is still a test that misbehaves.
	isolateConfigDir(t)
	deltaMu.Lock()
	oldLast, oldAt, oldRan, oldRunning := deltaLast, deltaAt, deltaRan, deltaRunning
	deltaLast, deltaAt, deltaRan, deltaRunning = nil, time.Time{}, false, true
	deltaMu.Unlock()
	t.Cleanup(func() {
		deltaMu.Lock()
		deltaLast, deltaAt, deltaRan, deltaRunning = oldLast, oldAt, oldRan, oldRunning
		deltaMu.Unlock()
	})
	// A pass is in flight. Every other refresher must return at once rather
	// than starting its own — the freshness check cannot help, because nothing
	// has been published yet.
	done := make(chan struct{})
	go func() { refreshDelta(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a second refresher started its own pass while one was already running")
	}
	deltaMu.Lock()
	published := deltaLast
	deltaMu.Unlock()
	if published != nil {
		t.Fatal("the second refresher published a result of its own")
	}
}

// A v1 ACCOUNTING HAS NOT BEEN EDITED, and both places that report on a
// baseline's integrity said it had. baselineDigestOf prefixes with the CURRENT
// version constant, so every file taken under older rules recomputes to a
// different digest — which after the v2 bump would have read as tampering on
// every machine holding one, in the one place a person goes to check exactly
// that.
func TestAnAccountingFromOlderRulesIsNotCalledTamperedWith(t *testing.T) {
	old := &baselineFile{Version: "privatae-baseline-v1", TakenAt: "2026-09-14T23:51:04Z"}
	note := baselineIntegrityNote(old, false)
	if note == "" {
		t.Fatal("a v1 accounting produced no note at all")
	}
	if strings.Contains(note, "has been changed since it was taken") {
		t.Errorf("the note accuses somebody of editing it: %q", note)
	}
	if !strings.Contains(note, "NOT evidence") {
		t.Errorf("the note does not rule out tampering, which is the whole reason it "+
			"exists — a person reading it still has to wonder: %q", note)
	}
	if !strings.Contains(note, "taken again") {
		t.Errorf("the note does not say what to do about it: %q", note)
	}
	// A file under the CURRENT rules whose digest does not match HAS been
	// edited, and must still say so — that is the whole point of the digest.
	cur := &baselineFile{Version: baselineVersion, TakenAt: "2026-09-15T00:00:00Z"}
	if note := baselineIntegrityNote(cur, false); !strings.Contains(note, "changed since it was taken") {
		t.Errorf("a tampered file under the current rules reads %q", note)
	}
	if note := baselineIntegrityNote(cur, true); note != "" {
		t.Errorf("an intact file produced a warning: %q", note)
	}
}

// A BASTION THAT CANNOT READ ITS OWN BINARY MUST NOT READ LIKE ONE THAT
// CHECKED. An empty digest produces no event, and silence is indistinguishable
// from "checked, unchanged" — the same quiet-versus-blind rule this plane
// applies to the accounting.
func TestABastionThatCannotReadItsOwnBinarySaysSo(t *testing.T) {
	if !processIsRoot() {
		t.Skip("a pass needs machine authority, which is its own test")
	}
	isolateConfigDir(t)
	oldPath := deltaSelfPath
	deltaSelfPath = filepath.Join(t.TempDir(), "not-here")
	t.Cleanup(func() { deltaSelfPath = oldPath })

	base, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	base.BastionDigest, base.BastionVersion = "something-was-recorded", "0.27.0"
	if err := baselineSave(base); err != nil {
		t.Fatal(err)
	}
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleDaemon)
	for _, ev := range r.Findings {
		if ev.Kind == deltaBinaryChanged {
			t.Fatalf("an unreadable binary produced a change event: %+v", ev)
		}
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "could not read its own binary") {
		t.Fatalf("the pass reported nothing about its own binary and said nothing about "+
			"why. That reads exactly like 'checked, unchanged': %v", r.Notes)
	}
}

// AND BOTH COMMANDS THAT REPORT ON IT ACTUALLY USE THAT SENTENCE. The note
// being right is worth nothing if the two places a person reads it compose
// their own — which is how the pair drifted apart in the first place. Rewriting
// either one to print its own wording leaves this red.
func TestBothBaselineCommandsSayTheRulesMovedRatherThanTampering(t *testing.T) {
	isolateConfigDir(t)
	writeV1Accounting(t)

	// `observe:baseline:show` prints it.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	showErr := cmdObserveBaselineShow()
	os.Stdout = stdout
	_ = w.Close()
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	if showErr != nil {
		t.Fatal(showErr)
	}
	shown := buf.String()
	if strings.Contains(shown, "has been changed since it was taken") {
		t.Errorf("observe:baseline:show tells the person their accounting was tampered "+
			"with when the version constant is what moved:\n%s", shown)
	}
	if !strings.Contains(shown, "taken again") {
		t.Errorf("observe:baseline:show does not say what to do:\n%s", shown)
	}

	// `observe:baseline` without --force refuses, and names the same state.
	if !processIsRoot() {
		return // the take path needs machine authority; the show half stands alone
	}
	takeErr := cmdObserveBaseline(false)
	if takeErr == nil {
		t.Fatal("taking a second accounting without --force was allowed")
	}
	if strings.Contains(takeErr.Error(), "has been changed since it was taken") {
		t.Errorf("observe:baseline accuses somebody of editing it: %v", takeErr)
	}
	if !strings.Contains(takeErr.Error(), "taken again") {
		t.Errorf("observe:baseline does not say the rules moved: %v", takeErr)
	}
}

// AND IT DOES NOT CRASH ON THE FILE IT EXISTS TO INSPECT. `observe:baseline:show`
// truncated every digest to twelve characters, which a real sha256 always
// survives and a hand-edited or truncated file does not — so the one command
// for looking at an accounting you suspect has been tampered with panicked on
// exactly that accounting. Found by the test above, written for something else.
func TestShowingATruncatedAccountingDoesNotCrash(t *testing.T) {
	isolateConfigDir(t)
	f := baselineFile{Version: baselineVersion, TakenAt: "2026-09-15T00:00:00Z",
		Coverage: "processes=all,schedulers=all", Entries: []baselineEntry{
			procEntry("aa", "root", "svc", "short"),
			procEntry("", "root", "svc", "none"),
			procEntry(strings.Repeat("f", 64), "root", "svc", "full"),
		}}
	if err := baselineSave(f); err != nil {
		t.Fatal(err)
	}
	if err := cmdObserveBaselineShow(); err != nil {
		t.Fatalf("showing an accounting with a short digest failed: %v", err)
	}
}

// writeV1Accounting writes an accounting the way a v1 BINARY would have: its
// digest computed under the v1 constant, so it is intact by its own rules and
// mismatched by ours. baselineSave cannot make this fixture — it re-digests
// under the current constant, which produces a file no v1 bastion ever wrote
// and which reads as perfectly intact.
func writeV1Accounting(t *testing.T) {
	t.Helper()
	const v1 = "privatae-baseline-v1"
	f := baselineFile{Version: v1, TakenAt: "2026-09-14T23:51:04Z",
		Coverage: "processes=all,schedulers=all",
		Entries:  []baselineEntry{procEntry("aaaa", "root", "svc", "thing")}}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte(v1+"\x00"), b...))
	f.Digest = hex.EncodeToString(sum[:])
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p, err := baselinePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	// It must be intact under ITS OWN rules and mismatched under ours, or this
	// fixture is not the situation being tested.
	got, ok, err := baselineLoad()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the v1 fixture reads as digest-intact under v2, so nothing below is " +
			"exercising the note at all")
	}
	if got.Version != v1 {
		t.Fatalf("fixture version is %q", got.Version)
	}
}
