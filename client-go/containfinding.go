package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Containing a FINDING, not only an agent.
//
// contain.go stops a pid only if the agent plane recognises it — a known agent
// binary, an interpreter running one, or a process talking to a model. The
// delta (delta.go) sees far more than that: every process whose fingerprint is
// not in the machine's accounting. Before this file, a program the delta
// reported as proc_new could be seen from the host and could not be stopped
// from it: its pid was never in the agent map, so contain refused it.
//
// The rule: a pid may be contained only if it is a finding (new-tier or
// changed) and not a baseline entry. The host names the finding by its
// FINGERPRINT, never by a pid. The fingerprint is the entry's identity (exe digest + user + unit +
// masked argv, baseline.go), so this box resolves it to the pids running under
// it NOW, from a fresh walk, at the moment of the order. A pid the host saw an
// hour ago and that now belongs to something else cannot be the target, because
// the host never sent a pid.
//
// Each order carries the host's own ORDER ID and the result echoes it. Results
// stay on the beat for containResultKeep, so without the id a second order for
// the same fingerprint (the program was stopped, restarted, and stopped again)
// would be answered by the first order's result and never delivered.
//
// What may be stopped this way:
//   - a PROCESS entry (a scheduled job has no process until it fires; it is
//     not killed, it is removed, which is the exec:plan rung, not this one);
//   - reported as proc_new or proc_changed by a comparison run at the time of
//     the order, against an accounting whose digest still verifies;
//   - whose fingerprint is not in the accounting — a baseline entry is never a
//     target here, however it is asked for;
//   - and not an app the user is running, not this bastion, not anything this
//     bastion started, not init.
//
// Nothing here runs by itself. It acts only on a directive from the anchor
// host, which queues it only under a signed management grant listing `contain`.
// Automatic termination is still not built
// (deltaPolicyIsNotSigned).

// The outcomes the box reports back. The host clears its order on any of them
// and writes it to the management audit; only containKilled means the program
// was stopped.
const (
	containKilled      = "killed"         // every pid under the fingerprint was reached
	containNotFinding  = "not_a_finding"  // nothing running under this fingerprint is a finding now
	containInBaseline  = "in_baseline"    // the fingerprint is in the accounting: never a target here
	containRefusedApp  = "refused_app"    // it is an app the user is running
	containRefusedOurs = "refused_ours"   // this bastion started it
	containNoAuthority = "no_authority"   // this bastion does not administer the machine
	containNoAccount   = "no_accounting"  // no usable accounting to compare against
	containWalkFailed  = "walk_failed"    // the process walk failed; nothing was compared
	containNotAnchor   = "refused_anchor" // only the anchor host may direct a kill on this box
	containKillFailed  = "kill_failed"    // it was a finding and the signal did not reach it
)

// containResultKeep is how long a result stays on the beat. Longer than the
// host's delivery TTL for a contain order (one hour) so an
// order the host is still holding always finds its answer.
const containResultKeep = 2 * time.Hour

type containResult struct {
	ID      int64  `json:"id"`
	FP      string `json:"fp"`
	Outcome string `json:"outcome"`
	// Stopped is how many processes the kill reached, children included.
	Stopped int    `json:"stopped"`
	At      string `json:"at"`
	at      time.Time
	pairing string
}

var (
	containResultsMu sync.Mutex
	containResults   = map[string]containResult{}
	containNow       = time.Now
)

// Results are kept PER PAIRING. A box can serve several hosts; a member host
// that orders a kill is refused (only the anchor may direct one), and that
// refusal must not arrive on the anchor's beat as the answer to the anchor's own
// order for the same fingerprint.
func recordContainResult(pairing string, o findingOrder, outcome string, stopped int) {
	now := containNow()
	containResultsMu.Lock()
	defer containResultsMu.Unlock()
	containResultsLoadLocked()
	containResults[pairing+"\x00"+strconv.FormatInt(o.ID, 10)] = containResult{ID: o.ID, FP: o.FP,
		Outcome: outcome, Stopped: stopped, At: now.UTC().Format(time.RFC3339), at: now, pairing: pairing}
	containResultsSaveLocked()
}

// ── results survive a restart ────────────────────────────────────────────────
// "Carried out once" held only while this process lived: a bastion that
// restarted after a kill and before the beat carried the answer (a self-update,
// a crash) would receive the order again, run it again, and report
// not_a_finding — or kill a restarted copy. So every result
// is written to the config dir as it is recorded and read back on first use.

var containResultsLoaded bool

type containResultDisk struct {
	Pairing string `json:"pairing"`
	ID      int64  `json:"id"`
	FP      string `json:"fp"`
	Outcome string `json:"outcome"`
	Stopped int    `json:"stopped"`
	At      string `json:"at"`
}

func containResultsPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "contain-results.json"), nil
}

func containResultsLoadLocked() {
	if containResultsLoaded {
		return
	}
	containResultsLoaded = true
	p, err := containResultsPath()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var disk []containResultDisk
	if json.Unmarshal(raw, &disk) != nil {
		return // a corrupt record forgets answers; it never invents one
	}
	for _, d := range disk {
		at, err := time.Parse(time.RFC3339, d.At)
		if err != nil {
			continue
		}
		containResults[d.Pairing+"\x00"+strconv.FormatInt(d.ID, 10)] = containResult{ID: d.ID, FP: d.FP,
			Outcome: d.Outcome, Stopped: d.Stopped, At: d.At, at: at, pairing: d.Pairing}
	}
}

func containResultsSaveLocked() {
	p, err := containResultsPath()
	if err != nil {
		return
	}
	disk := make([]containResultDisk, 0, len(containResults))
	for _, r := range containResults {
		disk = append(disk, containResultDisk{Pairing: r.pairing, ID: r.ID, FP: r.FP,
			Outcome: r.Outcome, Stopped: r.Stopped, At: r.At})
	}
	if b, err := json.Marshal(disk); err == nil {
		// Atomic: a crash mid-write must not corrupt the record and make the
		// box forget answers it gave.
		_ = atomicWrite(p, b)
	}
}

func unansweredOrders(pairing string, orders []findingOrder) []findingOrder {
	containResultsMu.Lock()
	defer containResultsMu.Unlock()
	containResultsLoadLocked()
	out := orders[:0:0]
	for _, o := range orders {
		if _, done := containResults[pairing+"\x00"+strconv.FormatInt(o.ID, 10)]; !done {
			out = append(out, o)
		}
	}
	return out
}

// findingOrder is one entry of the directive: the host's order id and the
// fingerprint it names.
type findingOrder struct {
	ID int64  `json:"id"`
	FP string `json:"fp"`
}

// containResultsReport is what rides the beat: every result younger than
// containResultKeep, oldest first. Always a list (possibly empty) so the host
// can tell "nothing to report" from a box that predates this key (absent).
func containResultsReport(pairing string) []containResult {
	now := containNow()
	containResultsMu.Lock()
	defer containResultsMu.Unlock()
	containResultsLoadLocked()
	out := []containResult{}
	for key, r := range containResults {
		if now.Sub(r.at) > containResultKeep {
			delete(containResults, key)
			continue
		}
		if r.pairing == pairing {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].at.Equal(out[j].at) {
			return out[i].at.Before(out[j].at)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// findingView is what one fresh comparison says about this machine, as the
// guard needs it.
type findingView struct {
	// findings: containable fingerprint -> the pids running under it now.
	findings map[string][]int
	// inBaseline: every fingerprint the accounting holds, so a refusal can say
	// why.
	inBaseline map[string]bool
	// protected: live pids whose OWN entry is in the accounting. The tree kill
	// spares them and everything beneath them (killTree's spare prunes), so
	// stopping a finding can never take an accounting entry with it.
	protected map[int]bool
	// identity: each finding pid's identity read straight after the walk. The
	// kill checks it before touching the root, so a pid reused between the walk
	// and the kill is never signalled.
	identity map[int]string
}

// processFindings is the comparison the guard trusts. A var so tests can drive
// the decision without a machine underneath it.
var processFindings = liveProcessFindings

// The machine under liveProcessFindings, as seams, so each refusal it makes is
// tested with the real function rather than by replacing it.
var (
	containIsRoot       = processIsRoot
	containBaselineLoad = baselineLoad
	containCollectLive  = func() ([]deltaLiveEntry, error) {
		// The live set now holds listener and identity entries too. They are
		// never a target and never protect a pid: processFindingsFrom reads
		// only process entries for both.
		live, _, _, _, err := deltaCollectLive(deltaCache.digest)
		return live, err
	}
	// containFilter is the SAME noise filter the delta pass applies, run over
	// this comparison with the box's own state (read, never saved): a finding
	// here is exactly what the box would report, so the host can only ever
	// order what it was shown.
	containFilter = func(events []deltaEvent, base *baselineFile, live []deltaLiveEntry) []deltaEvent {
		st := deltaStateLoad(base.Digest)
		findings, _ := deltaFilter(events, deltaNoiseFor(events, base, live), st, time.Now())
		return findings
	}
)

// liveProcessFindings runs the comparison fresh. The outcome string is empty
// when the comparison happened; otherwise it is the reason nothing can be
// contained on this pass.
func liveProcessFindings() (findingView, string) {
	if !containIsRoot() {
		return findingView{}, containNoAuthority
	}
	base, digestOK, err := containBaselineLoad()
	if err != nil || base == nil || base.Version != baselineVersion || !digestOK {
		// An accounting that is missing, from other rules, or edited since it
		// was taken cannot define what is foreign here — and "not in the
		// accounting" is the only licence this path has to kill.
		return findingView{}, containNoAccount
	}
	live, walkErr := containCollectLive()
	if walkErr != nil {
		return findingView{}, containWalkFailed
	}
	events := containFilter(deltaCompare(base.Entries, live), base, live)
	v := processFindingsFrom(base.Entries, live, events)
	v.identity = map[int]string{}
	for _, pids := range v.findings {
		for _, pid := range pids {
			if id, _, ok := procIdentity(pid); ok {
				v.identity[pid] = id
			}
		}
	}
	return v, ""
}

// processFindingsFrom is the rule, separate from the machine so it can be
// tested against the real comparison. Containable:
//   - a PROCESS entry (a listener or scheduler kind is never a kill target);
//   - proc_new at the NEW tier; a package-managed binary
//     (tier known) is a finding to read, not one this rung may stop;
//   - proc_changed for a real change — never `digest_unreadable`, which the
//     comparison itself says is not a security finding (delta.go);
//   - and whose fingerprint the accounting does not hold (a known program
//     that began talking to a model is proc_changed under its OWN fingerprint:
//     a finding, and still a baseline entry).
func processFindingsFrom(base []baselineEntry, live []deltaLiveEntry, events []deltaEvent) findingView {
	v := findingView{findings: map[string][]int{}, inBaseline: make(map[string]bool, len(base)),
		protected: map[int]bool{}}
	for _, e := range base {
		v.inBaseline[e.FP] = true
	}
	// ONLY AN ACCOUNTED PROCESS PROTECTS A PID. The live set also holds
	// listener entries, and a listener's identity is its bind point and the
	// holder's NAME, which the holder chooses: a replaced sshd restarted on :22
	// under the name `sshd` matches the accounted listener exactly. Letting that
	// protect its pid made the one finding this rung exists for uncontainable.
	for _, l := range live {
		if l.Entry.Kind == "process" && v.inBaseline[l.Entry.FP] {
			for _, pid := range l.PIDs {
				v.protected[pid] = true
			}
		}
	}
	for _, ev := range events {
		switch {
		case ev.Kind == deltaProcNew && ev.Tier == tierKnown:
			continue
		case ev.Kind == deltaProcChanged && ev.Reason == deltaReasonUnreadable:
			continue
		case ev.Kind != deltaProcNew && ev.Kind != deltaProcChanged:
			continue
		}
		if ev.Entry.Kind != "process" || v.inBaseline[ev.FP] || len(ev.PIDs) == 0 {
			continue
		}
		v.findings[ev.FP] = append(v.findings[ev.FP], ev.PIDs...)
	}
	return v
}

// maybeContainFindings acts on the heartbeat's "contain_findings" directive:
// a list of {id, fp} orders. Every one gets a result, including the refusals, so
// the host never has to infer from silence whether an order was carried out.
func maybeContainFindings(pairing, dcnDir string, heartbeatResponse []byte) {
	var hb struct {
		ContainFindings []findingOrder `json:"contain_findings"`
	}
	if json.Unmarshal(heartbeatResponse, &hb) != nil || len(hb.ContainFindings) == 0 {
		return
	}
	// AN ORDER IS CARRIED OUT ONCE. The host resends a pending order on every
	// beat until it reads the result, and a beat can cross the result in
	// flight. Running it again would find the program already gone and
	// overwrite "killed" with "not_a_finding" — the user would read that their
	// order did nothing.
	hb.ContainFindings = unansweredOrders(pairing, hb.ContainFindings)
	if len(hb.ContainFindings) == 0 {
		return
	}
	// directiveGate (writes.go): anchor-only, the local switch, then on an
	// anchored box an approval PER ORDER — `approvals["contain_finding:<id>"]`,
	// bound to "finding:<fp>", the same argument the host's contain op takes,
	// so the person approves the words they were shown. An order without its
	// approval is answered as refused (containNotAnchor carries the reason to
	// the host) rather than left unanswered.
	approved := hb.ContainFindings[:0]
	for _, o := range hb.ContainFindings {
		key := "contain_finding:" + strconv.FormatInt(o.ID, 10)
		why := directiveGate(pairing, dcnDir, directiveContain, []string{"finding:" + o.FP},
			directiveApproval(heartbeatResponse, key))
		if why != "" {
			fmt.Printf("contain finding %s: %s\n", o.FP, why)
			recordDirectiveRefusal("contain", why)
			recordContainResult(pairing, o, containNotAnchor, 0)
			continue
		}
		approved = append(approved, o)
	}
	hb.ContainFindings = approved
	if len(hb.ContainFindings) == 0 {
		return
	}
	view, outcome := processFindings()
	if outcome != "" {
		for _, o := range hb.ContainFindings {
			recordContainResult(pairing, o, outcome, 0)
		}
		return
	}
	// Built once per directive: the agent map (to refuse apps) and the parent
	// map (to refuse what this bastion started).
	observed := observedAgentMap()
	ours, ancestors, protected := containGuard(observed, view.protected)
	for _, o := range hb.ContainFindings {
		if o.FP == "" || o.ID <= 0 {
			continue
		}
		fp := o.FP
		if view.inBaseline[fp] {
			recordContainResult(pairing, o, containInBaseline, 0)
			continue
		}
		pids := view.findings[fp]
		if len(pids) == 0 {
			recordContainResult(pairing, o, containNotFinding, 0)
			continue
		}
		refused := ""
		for _, pid := range pids {
			if a, ok := observed[pid]; ok && a.Kind == kindApp {
				refused = containRefusedApp
				break
			}
			if ours.descendsFromSelf(pid) || spareFromContain(pid) || ancestors[pid] {
				refused = containRefusedOurs
				break
			}
		}
		if refused != "" {
			recordContainResult(pairing, o, refused, 0)
			continue
		}
		stopped := 0
		for _, pid := range pids {
			stopped += killTreeExpect(pid, protected, view.identity[pid])
		}
		if stopped == 0 {
			// Zero reached on a fingerprint that WAS a finding a moment ago is
			// usually the benign race (it exited between the walk and the
			// signal), but it is reported as what it is: nothing was stopped.
			recordContainResult(pairing, o, containKillFailed, 0)
			continue
		}
		recordContainResult(pairing, o, containKilled, stopped)
		fmt.Printf("contain: stopped finding %s (%d process(es), host-directed)\n", shortDigest(fp), stopped)
		recordLocalEvent(eventContain, findingContainSentence(pairing, fp, stopped))
	}
}

// containGuard is the tree guard both kill paths use: the SAME guards on every
// process in the tree, not only the ones an order names — an accounting entry
// (accountingPIDs), an app the user is running, anything this bastion started,
// init, the bastion. killTree does not signal a protected process or walk
// beneath it: without that, stopping a replaced sshd would take every ssh
// session with it. It also returns the bastion's ANCESTORS — its launch
// chain — which the finding path refuses by name: if any process in
// a tree were an ancestor of the bastion, the tree's root would be one too, so
// the named check always fires first and a tree-level check could never be
// reached.
func containGuard(observed map[int]agentObs, accountingPIDs map[int]bool) (deltaNoise, map[int]bool, func(int) bool) {
	ours := deltaNoise{Self: os.Getpid(), Parents: processTree()}
	ancestors := map[int]bool{}
	for cur, hops := ours.Parents[ours.Self], 0; cur > 1 && hops < 64; cur, hops = ours.Parents[cur], hops+1 {
		ancestors[cur] = true
	}
	protected := func(pid int) bool {
		if spareFromContain(pid) || accountingPIDs[pid] || ours.descendsFromSelf(pid) {
			return true
		}
		a, ok := observed[pid]
		return ok && a.Kind == kindApp
	}
	return ours, ancestors, protected
}

func findingContainSentence(pairing, fp string, stopped int) string {
	s := hostPhrase(pairing) + " stopped a program that was not in this machine's accounting (" +
		shortDigest(fp) + ")"
	switch {
	case stopped == 1:
	case stopped == 2:
		s += ", and 1 other process it had started"
	default:
		s += fmt.Sprintf(", and %d other processes it had started", stopped-1)
	}
	return s + "."
}
