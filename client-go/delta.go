package main

// delta.go — what is running on this machine that the accounting does not
// know about.
//
// The rule this file implements: new processes after the baseline get flagged,
// run through a noise filter, and presented as indexed context for a host that
// applies alert thresholds, automated escalations and a kill path.
//
// The baseline (baseline.go) answers "what is normal here". This answers
// the only question that follows from it — "what is not" — and it is worth
// being precise about what that costs to get wrong in each direction. Miss a
// real change and the product does not do the one thing it claims. Report an
// ordinary one and the person stops reading the list, which costs the same
// thing one step later and is harder to notice.
//
// NO MODEL ANYWHERE IN THIS PATH. Every rule here is
// deterministic over typed evidence; the host reads the result and never
// produces it.
//
// ── THE FINGERPRINT IS NOT ENOUGH ON ITS OWN, and the design says why without
// saying how. The design asks for `proc_changed` on "same fingerprint, new exe
// digest" — but the exe digest is INSIDE the fingerprint (baseline.go:123-127),
// so a new digest is by construction a new fingerprint and that event could
// never fire. Compared on the fingerprint alone, a swapped binary appears as
// one `proc_new` and one `proc_gone` an hour apart, correlated by nobody.
//
// So there are two keys, and the second one is what makes "changed" a thing
// that can be said:
//
//	FINGERPRINT  exe digest + user + unit + argv shape. Identity: is this the
//	             exact thing that was here before?
//	SLOT         the same, MINUS the digest. Position: is something else now
//	             running where that thing was?
//
// A live entry whose fingerprint is known is known. One whose fingerprint is
// new but whose SLOT is in the baseline is the binary at a known post having
// been replaced — `proc_changed`, and the event carries both digests so the
// reader sees what it was. One whose slot is new too is `proc_new`.
//
// A SCHEDULER'S SLOT IS NOT THE SAME SHAPE, deliberately. Its identity is the
// job — the crontab line, the timer unit — and its command is what that job
// would run, so the slot is the job and the command sits outside it. That is
// what makes "someone edited an existing cron entry to run something else" a
// `scheduler_changed` rather than an unrelated new-and-gone pair. On a process
// the argv shape is part of the slot, because a program that grew a flag is
// not the same program (baseline.go:32-34).

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// The typed events. The design's vocabulary, restricted to the classes the
// baseline actually holds. Which classes those are is decided per pass by
// deltaComparableClasses below, not fixed at compile time.
const (
	deltaProcNew       = "proc_new"
	deltaProcChanged   = "proc_changed"
	deltaProcGone      = "proc_gone"
	deltaSchedNew      = "scheduler_new"
	deltaSchedChanged  = "scheduler_changed"
	deltaSchedGone     = "scheduler_gone"
	deltaBinaryChanged = "binary_digest_changed"
	// The two classes added after processes and standing jobs. The accounting now holds
	// listeners and identities, so these can fire — see baseline_listeners.go
	// and baseline_identity.go for what each slot and fingerprint is made of.
	deltaListenerNew     = "listener_new"
	deltaListenerChanged = "listener_changed"
	deltaListenerGone    = "listener_gone"
	deltaIdentityNew     = "identity_new"
	deltaIdentityGone    = "identity_gone"
	// The two identity changes the design names separately, because "this account
	// gained sudo" and "a key was added to this account" are different
	// sentences and a person acts on them differently. Both are a _changed on
	// an identity slot; the REASON is what splits them.
	deltaIdentityChanged = "identity_changed"
)

// Why an identity `_changed` fired. deltaIdentityChanged carries one of these,
// and the design's `sudoers_changed` / `authkeys_changed` are these reasons rather
// than separate kinds — the slot is the account either way, and splitting the
// kind would have made "the account gained sudo AND a key" two unrelated
// findings about one account.
const (
	deltaReasonSudoers  = "sudoers_changed"
	deltaReasonAuthKeys = "authkeys_changed"
	deltaReasonShell    = "shell_changed"
	deltaReasonUID      = "uid_changed"
)

// Why a `_changed` fired. The reason is not decoration: "the binary at this
// post was replaced" and "this box can no longer read that binary" produce the
// same digest comparison and are not remotely the same event.
const (
	deltaReasonExeDigest  = "exe_digest"
	deltaReasonEndpoint   = "llm_endpoint"
	deltaReasonCommand    = "command"
	deltaReasonUnreadable = "digest_unreadable"
)

// The levels. Thresholds themselves are meant to be admin-signed policy
// set from a week of measured fleet deltas; what is here is the design's
// proposed default table, in code, and deltaPolicyIsNotSigned says so.
const (
	deltaNotice   = "notice"
	deltaWarn     = "warn"
	deltaHigh     = "high"
	deltaCritical = "critical"
)

// THE SIGNED-POLICY HALF IS NOT BUILT, AND THIS SAYS SO RATHER THAN IMPLYING
// IT IS. The design makes thresholds a record the admin signs and syncs
// (detect_policy_sync, TOFU-pinned like a grant), so a machine's operator — not
// its software — decides what is worth waking someone for. What is here is the
// default table below, compiled in. Nothing reads a policy file yet and nothing
// escalates: this plane reports, and the quarantine and kill rungs are the
// next piece.
const deltaPolicyIsNotSigned = "levels are the design's proposed defaults, compiled in — not admin-signed policy"

// WHAT deltaNotYetCompared USED TO SAY, and why it is now computed per pass.
//
// The design's list is processes, standing jobs, LISTENERS, IDENTITIES (users
// with a shell, sudoers, authorized-key counts) and the bastion's own state. The
// first version shipped processes and standing jobs; baselineEntry.Kind documented
// `listener` from the start and nothing ever wrote one, so this file carried a
// FIXED sentence admitting that `listener_new`, `identity_new`,
// `sudoers_changed` and `authkeys_changed` could not fire.
//
// Both classes now exist, so the sentence stopped being true of every box
// and started being true of SOME — the machine with no `ss`, the pass that
// cannot read another account's keys, the accounting taken before either class
// existed. A constant cannot say that. deltaComparableClasses below decides it
// per pass, from what the accounting covers and what this pass could read, and
// names the classes it had to leave out.

// THE TWO READERS AS VARS, so a test can hand this plane a machine it is not
// running on. Same pattern and same reason as deltaSockets and deltaPackagedFn:
// the states that matter here — an accounting taken where `ss` was missing, a
// pass that can no longer read another account's keys — cannot be produced by
// running the real reader on the box the test runs on.
//
// CALLED ONCE PER PASS. deltaCollectLive reads them and reports what it saw in
// a deltaSight; nothing else may call them during a pass.
var (
	deltaListenerReader = listenerScan
	deltaIdentityReader = identityScan
)

// notInBaselineWords is the "nothing like this was accounted for" sentence, in
// the vocabulary of the class. It said "neither this program nor anything in
// its place" for every class, which calls an account and a port a program.
func notInBaselineWords(kind string) string {
	switch kind {
	case "identity":
		return "this account was not in the accounting, and neither was any account in its place"
	case "listener":
		return "nothing was listening at this address and port when the accounting was taken"
	}
	return "neither this program nor anything in its place was in the accounting"
}

// deltaIsGone is the absence event of any class. A list rather than a pair,
// for the reason the kind selectors became a switch: a fifth class must not be
// silently left out of the grace.
func deltaIsGone(kind string) bool {
	switch kind {
	case deltaProcGone, deltaSchedGone, deltaListenerGone, deltaIdentityGone:
		return true
	}
	return false
}

// deltaClasses is every class this plane compares, and the coverage key that
// says whether a baseline holds it.
var deltaClasses = []struct{ Kind, CoverageKey string }{
	{"process", "processes"},
	{"scheduler", "schedulers"},
	{"listener", "listeners"},
	{"identity", "identities"},
}

// deltaComparableClasses drops the classes only one side measured, and says so.
//
// The rule is symmetric and deliberately strict: a class is compared when the
// ACCOUNTING covers it AND this pass produced entries for it or could have. A
// class present on one side only is not a finding about the machine, it is a
// fact about what was readable, and the whole discipline of this plane is not
// confusing those two.
//
// NOTE THE ASYMMETRY THAT IS NOT A BUG: "the live side produced no entries" is
// indistinguishable from "this class is genuinely empty now" without asking the
// reader, which is why the live side is asked (liveSaw) rather than inferred
// from the entry count. A machine that really has no listeners left reports
// them all gone, correctly; a machine that could not read its socket table
// reports nothing about listeners at all.
//
// It also returns the entry kinds it left out, so everything downstream that
// reads "absent from this pass" as a fact about the machine (the grace clocks,
// the hold list, the prune, the machine store's closes) can tell "not there"
// from "not looked at" for that class.
func deltaComparableClasses(base *baselineFile, live []deltaLiveEntry, sight deltaSight, notes []string) ([]baselineEntry, []deltaLiveEntry, []string, []string) {
	// WHAT THE PASS THAT BUILT `live` SAW — not a second read. See deltaSight.
	liveSaw := map[string]bool{
		"listener": sight.Listeners,
		"identity": sight.Identities,
	}
	// The two classes that predate this guard are compared exactly as before:
	// their readers have no supported/unsupported answer, and the coverage line
	// already carries `recognised-only` where they saw a subset.
	liveSaw["process"], liveSaw["scheduler"] = true, true

	skip := map[string]string{}
	for _, c := range deltaClasses {
		inBase := baselineHasClass(base.Coverage, c.CoverageKey)
		switch {
		case inBase && liveSaw[c.Kind]:
			// Both sides looked. Compare.
		case !inBase && !liveSaw[c.Kind]:
			skip[c.Kind] = "neither the accounting nor this pass can see " + c.CoverageKey
		case !inBase:
			skip[c.Kind] = c.CoverageKey + " are not in the accounting, so this delta cannot report them — take it again to start"
		default:
			skip[c.Kind] = c.CoverageKey + " are in the accounting but could not be read on this pass, so they are not compared"
		}
	}
	if len(skip) == 0 {
		return base.Entries, live, notes, nil
	}
	// One note per distinct reason, sorted, so the sentence is stable across
	// passes and a person is not reading a different ordering every beat.
	seen := map[string]bool{}
	var reasons []string
	for _, c := range deltaClasses {
		if r, ok := skip[c.Kind]; ok && !seen[r] {
			seen[r] = true
			reasons = append(reasons, r)
		}
	}
	notes = append(notes, reasons...)
	var skipped []string
	for _, c := range deltaClasses {
		if _, ok := skip[c.Kind]; ok {
			skipped = append(skipped, c.Kind)
		}
	}

	keptBase := make([]baselineEntry, 0, len(base.Entries))
	for _, e := range base.Entries {
		if _, dropped := skip[e.Kind]; !dropped {
			keptBase = append(keptBase, e)
		}
	}
	keptLive := make([]deltaLiveEntry, 0, len(live))
	for _, l := range live {
		if _, dropped := skip[l.Entry.Kind]; !dropped {
			keptLive = append(keptLive, l)
		}
	}
	return keptBase, keptLive, notes, skipped
}

// deltaLiveEntry is one entry of the live scan with the pids that produced it.
// The baseline keeps no pid on purpose (baseline.go:36-38) — it churns every
// restart — but the noise filter and the kill path both need to know WHICH
// processes an entry is, so the association is carried here and not in the file.
type deltaLiveEntry struct {
	Entry baselineEntry
	PIDs  []int
}

// deltaEvent is one typed difference between the accounting and now.
type deltaEvent struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`
	Level  string `json:"level"`
	// Tier is what the noise filter made of it: `new` (nothing explains it) or
	// `known` (something deterministic does — it is packaged, or its parent is
	// in the baseline). It is the same vocabulary the observe plane's evidence
	// lines use, and it is what moves a finding down the level table.
	Tier  string         `json:"tier"`
	FP    string         `json:"fp"`
	Entry baselineEntry  `json:"entry"`
	Was   *baselineEntry `json:"was,omitempty"`
	PIDs  []int          `json:"pids,omitempty"`
	// Added carries the model endpoints that are new since the accounting, for
	// the one reason that has a list to show.
	Added []string `json:"added,omitempty"`
	// FirstSeen is when THIS BOX first noticed this finding, which is not when
	// the process started and is not when the delta ran. It is what makes
	// "new since" mean something across beats.
	FirstSeen string     `json:"first_seen,omitempty"`
	Evidence  []evidence `json:"evidence,omitempty"`
	// Filtered is the noise filter's reason for taking this out of the
	// findings. Present means it is NOT a finding; the event is kept so the
	// operator can read what was filtered and why, which is the only way a
	// filter that is wrong ever gets found.
	Filtered string `json:"filtered,omitempty"`
}

// baselineSlot is the POSITION key — what the fingerprint is minus the thing
// that identifies the program itself. See the file header for why there are two
// keys and what each one answers.
func baselineSlot(e baselineEntry) string {
	if e.Kind == "listener" {
		// THE BIND POINT IS THE SLOT, and the program holding it is deliberately
		// NOT in here. That is what lets "something else is answering on 443
		// now" be one `listener_changed` instead of an unrelated gone/new pair
		// a person has to correlate by eye. baseline_listeners.go argues it.
		return "listener\x00" + e.Unit
	}
	if e.Kind == "identity" {
		// The ACCOUNT is the slot. Its shell, its sudo rights and its key count
		// are what may change about it, so they belong in the fingerprint and
		// not in here — otherwise granting an existing user sudo would read as
		// a brand-new account appearing, which is a different and much louder
		// claim than the true one.
		return "identity\x00" + e.Unit
	}
	if e.Kind == "scheduler" {
		// The job IS the slot: this crontab line, this timer unit. What it runs
		// is the payload, so changing the command is a change to a known job
		// rather than a new one appearing.
		return "scheduler\x00" + e.User + "\x00" + e.Unit
	}
	return e.Kind + "\x00" + e.User + "\x00" + e.Unit + "\x00" + e.ArgvShape
}

// deltaCompare is the whole comparison, and it is pure: two lists in, typed
// events out, no clock and no disk. Grace, first-seen and the noise filter are
// applied to its output by the caller, each in its own place, so that each one
// can be tested for what it does rather than through everything else.
//
// `proc_gone` events come out of here as CANDIDATES — the grace in
// deltaApplyGrace decides whether an absence is a finding.
func deltaCompare(base []baselineEntry, live []deltaLiveEntry) []deltaEvent {
	byFP := make(map[string]baselineEntry, len(base))
	bySlot := make(map[string][]baselineEntry, len(base))
	for _, e := range base {
		byFP[e.FP] = e
		// EVERY ENTRY AT A SLOT, NOT THE FIRST ONE.
		//
		// Several baseline entries can share a slot — the system python and a
		// uv-installed one running the same script in one session scope have
		// the same user, unit and masked argv, and differ only in their digest.
		// Keeping just the first made the answer depend on which of them sorted
		// first: with A kept, an upgraded B came out as `proc_new` at warn
		// carrying the line "neither this program nor anything in its place was
		// in the accounting" — which is false — and B was separately reported
		// gone; with B kept it came out as a replacement. One of those is
		// right and a hash order was choosing.
		//
		// WHAT REMAINS ORDER-DEPENDENT, named rather than implied: when TWO
		// unknown entries arrive at a slot that holds two, which of them is
		// paired with which departure follows the walk order — lexical pid
		// order from os.ReadDir("/proc"). With one departure and two arrivals
		// that decides which gets `proc_changed` (high) and which gets
		// `proc_new` (warn). An instantaneous scan does not contain the answer:
		// nothing on the box says which new process replaced the old one. Both
		// sentences are true of the machine; only the pairing is a guess, and
		// it is a stable one for a fixed set of pids.
		bySlot[e.Slot()] = append(bySlot[e.Slot()], e)
	}
	out := []deltaEvent{}
	liveFP := make(map[string]bool, len(live))
	for _, l := range live {
		liveFP[l.Entry.FP] = true
	}
	// The baseline entries a `_changed` event has already accounted for. Only
	// those may have their absence suppressed below — see the loop over `base`.
	replaced := map[string]bool{}
	for _, l := range live {
		e := l.Entry
		if was, known := byFP[e.FP]; known {
			// The same thing that was here before. One question is still open:
			// the design's "new model endpoint" on a process the accounting already
			// holds — the fingerprint deliberately excludes endpoints
			// (baseline.go:74-77), so a known program that has STARTED talking
			// to a model keeps its fingerprint and must be caught here or not
			// at all.
			if added := addedEndpoints(was.Endpoints, e.Endpoints); len(added) > 0 {
				ev := deltaEvent{Kind: changedKindFor(e.Kind), Reason: deltaReasonEndpoint,
					FP: e.FP, Entry: e, Was: &was, PIDs: l.PIDs, Added: added}
				ev.Evidence = append(ev.Evidence, evidence{Signal: "llm-endpoint-new",
					Tier: tierVerified, Value: strings.Join(added, ", ")})
				out = append(out, ev)
			}
			continue
		}
		// SOMETHING ELSE AT A KNOWN POST IS ONLY A REPLACEMENT IF THE ORIGINAL
		// IS GONE. This fired on "the slot is known" alone, so a second
		// interpreter starting the same script beside the first — a venv or a
		// pyenv build, same user, same unit, same masked argv — was reported as
		// `proc_changed` at high, carrying `was:` a process that was still
		// running. A doorbell that rings for a benign event is the cost the
		// whole noise filter exists to avoid, and the sentence it rang with was
		// not true.
		if was, slotKnown := departedAtSlot(bySlot[e.Slot()], liveFP, replaced); slotKnown {
			replaced[was.FP] = true
			out = append(out, changedAtSlot(e, was, l.PIDs))
			continue
		}
		ev := deltaEvent{Kind: newKindFor(e.Kind), FP: e.FP, Entry: e, PIDs: l.PIDs}
		// A LISTENER THAT MOVED ADDRESS IS NOT A LISTENER THAT APPEARED, and
		// the first cut graded it as one. The address is in the
		// slot on purpose — loopback and the wildcard are different facts — but
		// that made every address change a fresh high, repeating on every pass
		// because nothing retakes the accounting. Measured on one box: 15 of 54
		// listeners are pinned to a specific address, including a DHCP lease,
		// so a laptop joining a different network stood in that state
		// permanently.
		//
		// The same program on the same proto and port at a DIFFERENT address is
		// a re-addressing. Still reported, still a new bind point, but the
		// reason says what happened and the level follows it — and
		// loopback-to-routable is excluded, because that is the exposure change
		// this class exists to catch and it must keep its high.
		if e.Kind == "listener" {
			if from, moved := listenerMovedFrom(e, base, liveFP, replaced); moved {
				ev.Reason = deltaReasonAddressMoved
				ev.Was = &from
				// CLAIM THE DEPARTURE, so this is ONE event. Without it the
				// same re-addressing came out as a `listener_gone` at the old
				// address AND a `listener_new` at the new one — the
				// correlate-by-eye shape the slot design exists to avoid, and
				// the thing this branch was added to stop. Same mechanism changedAtSlot uses.
				replaced[from.FP] = true
				ev.Evidence = append(ev.Evidence, evidence{Signal: "listener-readdressed", Tier: tierVerified,
					Value: from.Unit + " → " + e.Unit + ", same program (" + e.ArgvShape + ")"})
				out = append(out, ev)
				continue
			}
		}
		ev.Evidence = append(ev.Evidence, evidence{Signal: "not-in-baseline", Tier: tierVerified,
			Value: notInBaselineWords(e.Kind)})
		out = append(out, ev)
	}
	for _, b := range base {
		if liveFP[b.FP] {
			continue
		}
		// An entry a `_changed` event already accounted for is not ALSO gone —
		// that would turn one event into two halves of the same sentence.
		//
		// Keyed on the entry that was actually replaced, not on "is anything
		// standing in this slot". The looser version suppressed the departure of
		// a baseline entry that merely SHARED a slot with a surviving one:
		// two entries at one post, one leaves, and its absence went
		// unreported because the other was still there.
		if replaced[b.FP] {
			continue
		}
		ev := deltaEvent{Kind: goneKindFor(b.Kind), FP: b.FP, Entry: b}
		ev.Evidence = append(ev.Evidence, evidence{Signal: "absent-from-scan", Tier: tierVerified,
			Value: "in the accounting, not running now"})
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].FP < out[j].FP
	})
	return out
}

// deltaReasonAddressMoved marks a listener whose bind ADDRESS changed while its
// protocol, port and holder did not.
const deltaReasonAddressMoved = "listener_readdressed"

// listenerMovedFrom finds a baseline listener with the same protocol, port and
// holder at a different address, which is no longer listening. Returns it and
// whether the move is one that keeps its grade — a bind that was on loopback
// and is now routable is NOT a re-addressing for this purpose, it is the
// exposure change the class exists to report.
func listenerMovedFrom(e baselineEntry, base []baselineEntry, liveFP, claimed map[string]bool) (baselineEntry, bool) {
	proto, port := listenerProtoPort(e.Unit)
	for _, b := range base {
		// NOT ALREADY CLAIMED by another move, or two new binds could both
		// point at one departure and the second would suppress an absence that
		// nothing accounted for.
		if b.Kind != "listener" || liveFP[b.FP] || claimed[b.FP] || b.ArgvShape != e.ArgvShape {
			continue
		}
		bp, bport := listenerProtoPort(b.Unit)
		if bp != proto || bport != port || b.Unit == e.Unit {
			continue
		}
		if listenerExposureGrew(b, e) {
			// AN EXPOSURE INCREASE IS NOT A RE-ADDRESSING, and the first cut
			// only caught half of them. loopback -> routable was excluded;
			// 10.0.0.5:9000 -> 0.0.0.0:9000 was not, and binding every
			// interface instead of one is the same argument the class exists
			// for.
			continue
		}
		return b, true
	}
	return baselineEntry{}, false
}

// listenerExposureGrew is true when a bind moved to an address that more
// things can reach: off loopback, or from one interface to all of them.
func listenerExposureGrew(was, now baselineEntry) bool {
	if !listenerIsExposed(was) && listenerIsExposed(now) {
		return true
	}
	return !listenerIsWildcard(was) && listenerIsWildcard(now)
}

// listenerIsWildcard is a bind to every interface rather than a named one.
func listenerIsWildcard(e baselineEntry) bool {
	addr := listenerAddr(e)
	return addr == "0.0.0.0" || addr == "::" || addr == "*"
}

// listenerAddr is the address half of a bind point.
func listenerAddr(e baselineEntry) string {
	addr := e.Unit
	if i := strings.Index(addr, "/"); i >= 0 {
		addr = addr[i+1:]
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = addr[:i]
	}
	return strings.Trim(addr, "[]")
}

// listenerPortNum is the port of a bind point, or 0 when it cannot be read.
func listenerPortNum(e baselineEntry) int {
	_, port := listenerProtoPort(e.Unit)
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}

// listenerProtoPort splits a bind point into its protocol and port, which are
// the parts a re-addressing keeps.
func listenerProtoPort(unit string) (string, string) {
	proto, rest, _ := strings.Cut(unit, "/")
	port := rest
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		port = rest[i+1:]
	}
	return proto, port
}

// Slot is baselineSlot as a method, so an entry and its position travel
// together and no call site has to remember which fields make one.
func (e baselineEntry) Slot() string { return baselineSlot(e) }

// departedAtSlot picks which of the entries at a slot this live one replaced:
// the first that is no longer running and has not already been claimed by
// another replacement. None gone means nothing was replaced — whatever is here
// arrived BESIDE what was already there, and is new.
func departedAtSlot(at []baselineEntry, liveFP, claimed map[string]bool) (baselineEntry, bool) {
	for _, e := range at {
		if !liveFP[e.FP] && !claimed[e.FP] {
			return e, true
		}
	}
	return baselineEntry{}, false
}

// changedAtSlot builds the event for "something else is running where that
// was", and separates the two ways the digests can differ.
func changedAtSlot(now, was baselineEntry, pids []int) deltaEvent {
	ev := deltaEvent{Kind: changedKindFor(now.Kind), FP: now.FP, Entry: now, Was: &was, PIDs: pids}
	// THE ENDPOINTS TOO, and they were missing here. This reported only the
	// digest, so a replaced binary that ALSO began talking to a model carried no
	// evidence line for the model at any tier — the one fact on the event most
	// likely to matter.
	if added := addedEndpoints(was.Endpoints, now.Endpoints); len(added) > 0 {
		ev.Added = added
		ev.Evidence = append(ev.Evidence, evidence{Signal: "llm-endpoint-new", Tier: tierVerified,
			Value: strings.Join(added, ", ")})
	}
	switch {
	case now.Kind == "identity":
		// WHICH PROPERTY MOVED, because "this account gained sudo" and "a key
		// was added" are different sentences that a person acts on differently,
		// and the design names them separately for that reason. Ordered by how much
		// the answer matters: privilege first, then the key set, then the shell.
		ev.Reason, ev.Evidence = identityChangeReason(was, now), append(ev.Evidence,
			evidence{Signal: "identity-changed", Tier: tierVerified,
				Value: identityChangeWords(was, now)})
	case now.Kind == "listener":
		// The bind point is the slot, so a _changed here means one thing and
		// needs no case analysis: something else is holding a port that was
		// already open.
		ev.Reason = deltaReasonCommand
		ev.Evidence = append(ev.Evidence, evidence{Signal: "listener-holder-changed", Tier: tierVerified,
			Value: was.ArgvShape + " → " + now.ArgvShape + " on " + now.Unit})
	case now.Kind == "scheduler":
		// No digest on either side (a scheduled job has no executable until it
		// fires, baseline.go:310-311), so the difference is the command.
		ev.Reason = deltaReasonCommand
		ev.Evidence = append(ev.Evidence, evidence{Signal: "scheduled-command-changed", Tier: tierVerified,
			Value: was.ArgvShape + " → " + now.ArgvShape})
	case now.ExeDigest == "" || was.ExeDigest == "":
		// THE FALSE ALARM THIS EXISTS TO STOP. An entry whose executable could
		// not be read digests as empty (baseline.go:175-199), so "root took the
		// baseline, the delta ran as somebody else" and "the binary was swapped"
		// produce the identical comparison. They are not the same event and
		// this one is not a security finding.
		ev.Reason = deltaReasonUnreadable
		note := now.DigestNote
		if note == "" {
			note = was.DigestNote
		}
		ev.Evidence = append(ev.Evidence, evidence{Signal: "digest-unreadable", Tier: tierAmbiguous,
			Value: note})
	default:
		ev.Reason = deltaReasonExeDigest
		ev.Evidence = append(ev.Evidence, evidence{Signal: "exe-digest-changed", Tier: tierVerified,
			Value: shortDigest(was.ExeDigest) + " → " + shortDigest(now.ExeDigest)})
	}
	return ev
}

// THE THREE SELECTORS ARE A TABLE, NOT A CHAIN OF ifs, since the class count
// went from two to four. A switch with an explicit default is what makes
// a fifth class fail loudly here instead of being silently reported as a
// process — which is what the old `if scheduler { } return proc` shape would
// have done to every listener and identity had these not been added.
func newKindFor(kind string) string {
	switch kind {
	case "scheduler":
		return deltaSchedNew
	case "listener":
		return deltaListenerNew
	case "identity":
		return deltaIdentityNew
	}
	return deltaProcNew
}

func changedKindFor(kind string) string {
	switch kind {
	case "scheduler":
		return deltaSchedChanged
	case "listener":
		return deltaListenerChanged
	case "identity":
		return deltaIdentityChanged
	}
	return deltaProcChanged
}

func goneKindFor(kind string) string {
	switch kind {
	case "scheduler":
		return deltaSchedGone
	case "listener":
		return deltaListenerGone
	case "identity":
		return deltaIdentityGone
	}
	return deltaProcGone
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	if d == "" {
		return "(none)"
	}
	return d
}

// addedEndpoints returns the endpoints in `now` that the accounting did not
// hold. Order-independent and case-folded: an endpoint list is a set, and
// reporting "it talks to api.anthropic.com" because the scan returned the same
// two hosts in the other order would be a finding about sorting.
func addedEndpoints(was, now []string) []string {
	if len(now) == 0 {
		return nil
	}
	had := make(map[string]bool, len(was))
	for _, e := range was {
		had[strings.ToLower(strings.TrimSpace(e))] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, e := range now {
		k := strings.ToLower(strings.TrimSpace(e))
		if k == "" || had[k] || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// ── the levels ──────────────────────────────────────────────────────────────

// deltaLevel is the level table, applied to one event after the noise filter
// has set its tier.
//
// THE ONE PLACE THIS DEPARTS FROM THE TABLE IS binary_digest_changed, and the
// reason is that the fleet updates itself. The design lists it flat as `critical`,
// alongside anchor_changed and exec_outside_plan — sound, because a swapped
// bastion binary is how you turn the watching off. But every machine on this
// fleet takes published updates, and a `critical` that fires on every
// legitimate update is a `critical` nobody reads by the third one. So the
// version decides which it is: a digest that moved WITH the version is the
// update that was asked for and is reported at `high` — the person is still
// entitled to know the thing watching their machine was replaced — while a
// digest that moved while the version stood still is the swap, and stays
// `critical`.
func deltaLevel(ev deltaEvent) string {
	switch ev.Kind {
	case deltaBinaryChanged:
		if ev.Reason == deltaReasonVersionAlso {
			return deltaHigh
		}
		return deltaCritical
	case deltaProcGone, deltaSchedGone:
		return deltaNotice
	case deltaProcChanged:
		// HIGH BEATS EVERYTHING BELOW IT, and it did not. The proc_new branch
		// has had this ordering from the start; this one demoted on the tier
		// alone, so "apt upgraded node, and the service it runs now talks to
		// api.openai.com" came out as a notice — the package database
		// explaining the BINARY was allowed to explain away the ENDPOINT.
		//
		// IT IS ALSO ABOVE THE UNREADABLE SHORTCUT, which was the same defect
		// one line further down: a binary replaced at a
		// known post and then UNLINKED digests as empty — sanitizeExePath
		// strips " (deleted)" and the stat then fails — so a replacement that
		// also talks to a model came out as a visibility notice.
		//
		// NARROWER THAN IT FIRST READ, and the difference is worth being exact
		// about: what this rescues is "unreadable AND
		// something else on the event". An unlinked replacement with nothing
		// else on it is still a notice, deliberately — a process whose exe this
		// box cannot read is the ordinary case for a container, and levelling
		// every one of those up would fill the list on exactly the machines
		// that run the most of them.
		//
		// NEW endpoints, not merely HAVING them: a packaged upgrade of a
		// service that was already talking to a model is an apt upgrade, and
		// levelling every one of those high is the noise the tier exists to
		// remove. The `proc_new` branch reads Endpoints because for a program
		// that was not here before, every endpoint it holds is new.
		if len(ev.Added) > 0 || ev.Entry.Signature != "" {
			return deltaHigh
		}
		if ev.Reason == deltaReasonUnreadable {
			// A visibility change, not a machine change.
			return deltaNotice
		}
		if ev.Tier == tierKnown {
			// The replacement is accounted for — the distribution's own package
			// database says this is the file that package ships. An upgrade.
			return deltaNotice
		}
		return deltaHigh
	case deltaSchedChanged:
		if ev.Entry.Signature != "" {
			return deltaHigh
		}
		return deltaWarn
	case deltaSchedNew:
		// scheduler_new is warn. A standing job that would run a
		// RECOGNISED agent is the persistence form of "proc_new with an agent
		// signature", which the same table puts at high.
		if ev.Entry.Signature != "" {
			return deltaHigh
		}
		return deltaWarn
	case deltaListenerGone:
		// A port that stopped answering is a service that stopped, which is an
		// availability fact and not a security one. Notice, like proc_gone.
		return deltaNotice
	case deltaListenerNew:
		if ev.Reason == deltaReasonAddressMoved {
			// The same program on the same port at a different address, and not
			// loopback-to-routable (listenerMovedFrom excludes that). A DHCP
			// lease, a new interface, a container restart. Reported, not paged.
			return deltaWarn
		}
		// A PORT NOTHING WAS ON BEFORE IS THE CLASSIC FINDING, and it is high
		// rather than warn when it faces the network. The address is in the
		// slot precisely so this distinction can be made: a new loopback
		// listener is a developer running something, a new listener on a
		// routable address is a way in that did not exist when the accounting
		// was taken.
		if listenerIsExposed(ev.Entry) {
			return deltaHigh
		}
		return deltaWarn
	case deltaListenerChanged:
		// A DIFFERENT PROGRAM ANSWERING ON A PORT THAT WAS ALREADY OPEN is the
		// more alarming of the two and is high wherever it binds — including
		// loopback, because the slot was already normal here and what changed
		// is WHO holds it. That is the shape of a service being replaced.
		return deltaHigh
	case deltaIdentityGone:
		// An account that stopped existing. Notice: removing a way in is not
		// the direction this plane is watching, and an administrator deleting a
		// user should not page anyone.
		return deltaNotice
	case deltaIdentityNew:
		// A NEW ACCOUNT WITH A LOGIN SHELL IS A NEW WAY ONTO THE MACHINE.
		//
		// CRITICAL when it is uid 0, or arrives already holding sudo or keys.
		// A second uid-0 account is not an account, it is a root login under
		// another name, and it was once levelled below "a key was added". The rest is the same argument: arriving
		// armed is not how a colleague is added, it is how persistence is
		// installed in one step.
		keys, keysKnown := ev.Entry.identityKeys()
		sudo, sudoKnown := ev.Entry.identitySudo()
		if identityField(ev.Entry, "uid") == "0" || (sudoKnown && sudo) || (keysKnown && keys > 0) {
			return deltaCritical
		}
		// UNKNOWN IS NOT "NO". If either property could not be read, this box
		// cannot rule out that the account arrived armed — so it does not get
		// the service-account demotion below, and it does not drop under high.
		// The keys half was conservative by construction; the sudo half read
		// `?` as false and let an armed account on a box with unreadable
		// sudoers grade WARN if it took a service uid, which an attacker picks
		// freely.
		if !sudoKnown || !keysKnown {
			return deltaHigh
		}
		// A SERVICE ACCOUNT FROM A PACKAGE INSTALL IS NOT A WAY IN, and paging
		// for `apt install postgresql` is how a plane gets ignored. Service
		// accounts conventionally take a uid below the login threshold, and
		// this one holds neither sudo nor a key — so it is reported, at the
		// rung that does not wake anyone. The noise filter cannot do this: it
		// exempts every non-process kind (deltanoise.go).
		//
		// The threshold is the conventional one and it is a CONVENTION, not a
		// guarantee — an installer is free to use a high uid, and then this is
		// a warn the person reads. That is the right direction to be wrong in.
		if uid, err := strconv.Atoi(identityField(ev.Entry, "uid")); err == nil && uid < 1000 && uid > 0 {
			return deltaWarn
		}
		return deltaHigh
	case deltaIdentityChanged:
		switch ev.Reason {
		case deltaReasonUnreadable:
			// ONE SIDE DID NOT LOOK. A visibility change, not a machine change
			// — the same call this table makes for a process whose executable
			// could not be digested, and the reason `?` is in the fingerprint
			// at all.
			return deltaNotice
		case deltaReasonSudoers:
			// Privilege moved. This is the one identity change that is always
			// worth waking someone for.
			return deltaCritical
		case deltaReasonUID:
			// A uid change TO ZERO is the same fact as a second root account,
			// and it was a warn. Anything else is an administrative act worth
			// reading and not worth paging.
			if identityField(ev.Entry, "uid") == "0" {
				return deltaCritical
			}
			return deltaWarn
		case deltaReasonAuthKeys:
			// A key set that is not what it was.
			return deltaHigh
		case deltaReasonShell:
			// NARROWER THAN IT FIRST READ, and the first version's own
			// justification described a case that cannot occur:
			// identityScan drops non-login shells, so both sides always hold
			// one and "an account that gained a shell it did not have" is
			// unreachable here. What IS reachable is chsh between two login
			// shells, which is an ordinary thing a person does.
			return deltaWarn
		}
		return deltaWarn
	case deltaProcNew:
		// High beats the tier, and that order is the point: a packaged
		// interpreter talking to a model endpoint is still a process talking to
		// a model endpoint, and demoting it because apt shipped the binary
		// would be the noise filter hiding the finding.
		if len(ev.Entry.Endpoints) > 0 || ev.Entry.Signature != "" {
			return deltaHigh
		}
		if ev.Tier == tierKnown {
			return deltaNotice
		}
		return deltaWarn
	}
	return deltaNotice
}

// deltaReasonVersionAlso marks the bastion-binary change that came with a
// version change — the self-update, not the swap. See deltaLevel.
const deltaReasonVersionAlso = "version_changed_too"

// deltaBinaryEvent compares the bastion's own binary against the LAST ONE THIS
// PLANE SAW, which is not the same as the one the accounting recorded.
//
// IT WAS COMPARED AGAINST THE BASELINE'S, AND THAT DISARMS THE CRITICAL RUNG
// WITHIN DAYS. Nothing retakes the accounting when the
// bastion updates itself, so on an auto-updating fleet the standing state is
// "the version moved since the baseline" — and from that moment every later
// digest change reads as another update and comes out `high`. The rung meant to
// catch a binary swapped under an unchanged version was switched off by the
// first legitimate update, which is precisely the event its own justification
// was built around.
//
// So the comparison is against what the last pass saw, carried in the delta's
// own state and seeded from the accounting. A digest that moves WITH the
// version is the update. A digest that moves while the version stands still is
// the swap, however many updates came before it.
//
// Empty digests are NOT a finding: the digest is empty when the executable
// cannot be read, and a baseline taken by a build that could not read itself
// holds none either.
func deltaBinaryEvent(wasDigest, wasVersion, nowDigest, nowVersion string) *deltaEvent {
	if wasDigest == "" || nowDigest == "" || wasDigest == nowDigest {
		return nil
	}
	ev := deltaEvent{Kind: deltaBinaryChanged, Tier: tierVerified, FP: nowDigest,
		Entry: baselineEntry{Kind: "bastion", Signature: "privatae-bastion",
			ExeDigest: nowDigest}}
	ev.Evidence = append(ev.Evidence, evidence{Signal: "bastion-digest-changed", Tier: tierVerified,
		Value: shortDigest(wasDigest) + " → " + shortDigest(nowDigest)})
	// THE VERSION IS ON THE EVENT EITHER WAY, because it is the fact that
	// decides high from critical and the reader has to be able to check the
	// call. Unchanged is the more alarming of the two and would otherwise be
	// the one with nothing written on it.
	if nowVersion != "" && wasVersion != "" && nowVersion != wasVersion {
		ev.Reason = deltaReasonVersionAlso
		ev.Evidence = append(ev.Evidence, evidence{Signal: "bastion-version-changed", Tier: tierVerified,
			Value: wasVersion + " → " + nowVersion})
	} else {
		ev.Evidence = append(ev.Evidence, evidence{Signal: "bastion-version-unchanged", Tier: tierVerified,
			Value: "still " + nowVersion + " — a new binary under the same version is not an update"})
	}
	ev.Level = deltaLevel(ev)
	return &ev
}

// ── the grace on an absence ─────────────────────────────────────────────────

// deltaGoneGrace is how long something has to be missing before its absence is
// reported, and it is set against the things that legitimately make a process
// disappear for a moment rather than picked for roundness: a service restart is
// seconds, a package upgrade that stops and starts a unit is under a minute, a
// reboot is a few minutes end to end. Ten minutes — ten consecutive misses at
// the heartbeat's cadence — is past all three.
//
// The cost of the choice is a `proc_gone` notice arriving up to ten minutes
// late, which is what a `notice` is for: the level table batches it into the
// daily summary and wakes nobody. It is one of the numbers the admin's signed
// policy is meant to set from a week of measured fleet deltas.
const deltaGoneGrace = 10 * time.Minute

// deltaApplyGrace decides which absences have lasted long enough to report, and
// updates the state that remembers when each one started. Returns the events
// that survive.
func deltaApplyGrace(events []deltaEvent, st *deltaState, now time.Time) []deltaEvent {
	missing := map[string]bool{}
	out := make([]deltaEvent, 0, len(events))
	for _, ev := range events {
		// EVERY `_gone`, NOT TWO OF THE FOUR. This listed proc and scheduler
		// only, so a `systemctl restart` landing inside a pass reported the
		// port gone IMMEDIATELY while the process behind it got ten minutes.
		// An absence seen once is not a finding for any class
		// — that is what the grace is, and it does not depend on what kind of
		// thing went absent.
		if !deltaIsGone(ev.Kind) {
			out = append(out, ev)
			continue
		}
		missing[ev.FP] = true
		since, ok := st.missingSince(ev.FP)
		if !ok {
			st.setMissingSince(ev.FP, now)
			continue // first miss: nothing is reported on the strength of one scan
		}
		if now.Sub(since) < deltaGoneGrace {
			continue
		}
		ev.FirstSeen = since.UTC().Format(time.RFC3339)
		out = append(out, ev)
	}
	// Anything that came back stops being missing. Without this a service that
	// bounces once an hour accumulates a start time from its FIRST bounce and
	// reports gone for ever after.
	st.keepMissing(missing)
	return out
}
