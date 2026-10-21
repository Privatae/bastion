package main

// policy.go — THE DRY-RUN POLICY: what this machine WOULD stop, with no
// authority to stop anything.
//
// NO BUILD TAG, on purpose, exactly like agents_parse.go and sanction.go: every
// judgement here decides whether somebody's work survives an automatic policy
// later, so it has to be exercised by the one `go test` people actually run,
// from any platform.
//
// ── WHY THIS EXISTS, AND WHY IT CANNOT ACT ──────────────────────────────────
//
// The conflict, stated plainly: the pitch says the product "identifies rogue
// AI and automatically stops it", and the code does not — `maybeContain` runs
// off the heartbeat response (contain.go:56, run.go:575), so the HOST decides
// and this box carries it out. The work is ordered, and this unit is step 3 of
// that order:
//
//	3. Dry-run policy. The rule engine, reporting what it WOULD contain, with
//	   no authority to act. This is what earns the claim.
//	4. Autonomous containment, opt-in, only after (3) has run long enough on
//	   real machines to show its false-positive rate.
//
// So the one thing this file must never grow is a side effect. The reason is
// the sentence the whole unit is built around: "A missed rogue agent is a
// bad day. A false positive that kills the user's own long-running job is the
// thing they tell other people about." policy_test.go parses this file and
// uipolicy.go and fails if either one so much as NAMES killProcess (contain.go:41)
// or maybeContain (contain.go:56). That test is the unit, more than the rule is.
//
// ── THE RULE, AND WHERE IT DEPARTS FROM THE SKETCH ──────────────────────────
//
// The original sketch: "an `agent`-kind process, with model traffic, carrying no
// delegation tag, whose origin is not `interactive`". Each term below is
// derived from what agentObs (agents.go:165-192) actually carries, and two of
// them came out different from the sketch:
//
//	SKETCH                        BUILT                         WHY
//	carrying no delegation tag →  not SANCTIONED                the tag is one of
//	                                                            TWO mechanisms;
//	                                                            reading the tag
//	                                                            direct would skip
//	                                                            the local mark and
//	                                                            re-implement the
//	                                                            shape check.
//	origin is not `interactive` → origin is one of scheduler,   "not interactive"
//	                              service, agent                includes `remote`
//	                                                            (a person over ssh)
//	                                                            and `unknown` (no
//	                                                            answer at all).
//
// The second correction is the load-bearing one. origin.go:19 defines `remote`
// as "an ssh / mosh / screen-sharing ancestor: a person, elsewhere" — killing
// an agent a person started over ssh is the same false positive as killing one
// they started at the console, and a deny-list ("not interactive") quietly
// swept it in. origin.go:25 defines `unknown` as "the box could not read enough
// to say. Never guessed." — a deny-list read that absence of knowledge as
// grounds to stop something. Both are fixed by making the term an ALLOW-LIST of
// the origins where nobody is at a keyboard.
//
// ── EVERY TERM, AND WHY IT IS IN ────────────────────────────────────────────
//
// KIND == agent (policyKindTerm). The outermost gate, and it returns before any
// other term is even evaluated, so that nothing — not an unreadable registry,
// not a missing origin — can move an app off "leave alone":
//
//	app         NEVER a candidate. contain.go:84-86 refuses to terminate one
//	            however the host asks, and agents.go:170-176 records what it
//	            cost to learn: one Windows box reported the Claude DESKTOP app
//	            as nine "claude-code" agents (eight of them Chromium helpers)
//	            and the host offered nine kill buttons. An alert that cries wolf
//	            teaches the user to dismiss alerts, which is the one failure
//	            this feature cannot survive.
//	automation  NOT a candidate, and it needs no term of its own. An automation
//	            is inventory — a browser driver, an input injector, an RPA
//	            runtime with no model of its own (agents.go:61-65). The moment
//	            STRONG model traffic joins it the plane relabels it `agent`
//	            before this file ever sees it (agents_parse.go:421-426), so the
//	            interesting case arrives already inside the term above. Adding
//	            `automation` here would flag every chromedriver and every
//	            playwright run on a developer's machine for nothing.
//	client      NOT a candidate in v1, and this is a judgement call worth
//	            stating rather than burying. A `client` is any process the
//	            signature tables MISSED that holds a strong inference endpoint
//	            (agents_parse.go:480-483) — on a real machine that is curl, a
//	            notebook kernel, a python script, an IDE plugin. It also rests
//	            on ONE signal, where the plane's whole design is two correlated
//	            ones (the README, "Observe"). It is still evaluated, still
//	            listed, and still carries its reasons, so the census shows what
//	            a wider rule WOULD have caught before anybody widens it.
//
// MODEL TRAFFIC (policyTrafficTerm). The second, independent signal. A
// signature is `known` tier at best because "a name is something a process
// chooses" (origin.go:194-196); traffic to a model is the corroboration. The
// term reads the endpoint list through endpointEvidence (origin.go:211-221)
// rather than re-deciding what counts, so the tier rule lives in exactly one
// place: a "?"-suffixed endpoint is an AMBIGUOUS port — one that collides with
// ordinary web development (agents.go:146-151) — and the plane's standing rule
// is that those annotate and never promote (agents.go:130-133). This rule obeys
// it: an ambiguous endpoint alone is not enough to be a candidate.
//
//	REJECTED: reading a.Evidence for a "model-endpoint" line. Evidence is
//	assembled by scanAgents (agents.go:269-273) and is absent on an observation
//	built anywhere else, so a policy keyed on it would silently answer "no
//	traffic" for every caller that is not the live plane.
//
// ORIGIN ∈ {scheduler, service, agent} (policyOriginTerm). "Nobody was at the
// keyboard", stated positively. origin.go:14-15 is the reason the field exists
// at all: the shape the headlines are about is "an agent that has been running
// for months with nobody at the keyboard", and that needs no new table to see.
//
// NOT SANCTIONED (policySanctionTerm). The seam, agentSanction (sanction.go:535).
//
//	REJECTED: reading a.DelegationToken here. It would re-implement
//	looksLikeHostTag (sanction.go:251), skip the local mark entirely — which is
//	the half a person can actually use (sanction.go:32-37) — and put a value the
//	page must never render (uisanction_test.go:331-351) into a second file.
//	This unit compares the REASON CONSTANT and never parses the sentence.
//
// REJECTED AS A TERM: User. It is already inside the identity a mark is
// recorded against (sanction.go:274-292), so it is load-bearing here through
// the sanction term. Adding it again — "only root", "only this user" — would be
// a guess about which accounts matter on a machine this unit has never seen.
//
// ── THE ANSWER IS NOT A BOOLEAN ─────────────────────────────────────────────
//
// agents.go:183-188: the plane "never emits a bare verdict — it emits typed
// evidence with tiers so the host shows WHY". A verdict nobody can audit is a
// verdict nobody should trust, and this one is the input to a feature that
// terminates processes. So every observation gets every term, with its tier and
// a sentence, and THREE possible decisions rather than two:
//
//	would-stop    every term this machine could read points at stopping.
//	leave-alone   a term this machine could read says no. Decisive.
//	cannot-judge  no term says no, and a term the policy NEEDS could not be
//	              read. This is not "nothing to judge" — it is "I cannot".
//
// cannot-judge is reserved for a term that could not be READ, never for one
// that was read and came back empty. The two places the plane itself admits it
// could not read are the only two that reach it: an origin of `unknown`
// (origin.go:25, 190) and a sanction registry that would not load
// (sanction.go:517-525). "No model traffic in this scan" is an ANSWER — the
// connection table was read and this process held nothing — so it is a
// decisive leave-alone, tiered ambiguous because a scan is a snapshot.
//
// ── THE ONE THAT WILL BE GOT WRONG: sanctionWhyUnreadable ───────────────────
//
// agentSanction returns (TRUE, sanctionWhyUnreadable) when it cannot read the
// registry, and sanction.go:517-534 argues that direction at length: a corrupt
// registry that read as "nothing is marked" would hand a policy engine a
// machine where every process looks unvouched-for. But that true is NOT a
// vouch, it is an absence of knowledge, and a policy that treats it as "fine"
// goes blind in silence — which is the failure this whole feature exists to
// prevent. So policySanctionTerm tests the CONSTANT BY NAME, before it looks at
// the bool, and returns "unknown" rather than "leave alone". A verdict built on
// it is cannot-judge, and the page says so in those words.
//
// ── THE CENSUS: WHY THE VERDICT IS ALSO WRITTEN DOWN ────────────────────────
//
// The false-positive rate is the thing step 4 waits on, so this unit has
// to be able to answer, after a week on a real machine: what would this have
// killed, and would that have been wrong? A page that renders the current scan
// answers neither. So every census tick folds the would-stop set into a ledger
// on disk, keyed by the SANCTION FINGERPRINT (sanction.go:302-306) — the
// identity chosen precisely because it survives a restart at a new pid — and
// the page then asks, of each past candidate, what became of it. One that a
// person has SINCE MARKED AS THEIRS is a false positive this rule has been
// measured making. That number is the metric, and it is nameable row by row.
//
// WRITING. A new candidate is written immediately; otherwise the ledger is
// rewritten at most once every policyLedgerFlush, which also refreshes
// last_scan. The first tick writes even with nothing to record, and both halves
// of that matter for the same reason agents.go:594-598 gives about the
// second-bastion scan: "A scan that stops completing keeps publishing its last
// answer, and if that answer is [] the host would read 'clean' for ever with
// nothing to say otherwise." Without the first write, a machine that has never
// run the census is indistinguishable from one that ran it for a week and found
// nothing; without last_scan, a census that died three days ago still reads as
// an all-clear.
//
// READS CREATE NOTHING — policyLedgerPath is built on configDirPath()
// (config.go:129), never configDir() (config.go:137), which is MkdirAll-on-read.
// ui_approvals_flow_test.go:53-84 exists because a page that asked a question created
// a directory, twice, and sanction.go:160-167 holds the same line for the same
// reason. The WRITE path creates the directory, through atomicWrite's own
// MkdirAll(0700) at ctx.go:135.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ── the decisions ───────────────────────────────────────────────────────────

// The decision constants. A caller COMPARES these; it never parses them, the
// same contract sanction.go:196-200 sets for its reasons.
const (
	policyWouldStop   = "would-stop"
	policyLeaveAlone  = "leave-alone"
	policyCannotJudge = "cannot-judge"
)

// The terms, named so the page, the reasons and the tests share one vocabulary.
const (
	policyTermKind     = "kind"
	policyTermTraffic  = "model-traffic"
	policyTermOrigin   = "origin"
	policyTermSanction = "sanction"
)

// Which way a term points. Three values, not a bool, for the same reason the
// decision has three: a term the machine could not read is a different fact
// from a term that came back no.
const (
	policyPointsStop    = "stop"
	policyPointsLeave   = "leave"
	policyPointsUnknown = "unknown"
)

// policyReason is one term's answer: which way it points, how well this machine
// knows it, and a sentence a person can read. Shaped on `evidence`
// (origin.go:53) and using the SAME tier constants, because the page renders
// them beside the plane's own evidence and two tier vocabularies on one screen
// would be two things to learn.
type policyReason struct {
	Term   string `json:"term"`
	Points string `json:"points"`
	Tier   string `json:"tier"`
	Detail string `json:"detail"`
}

// policyVerdict is what this rule says about ONE observation.
//
// It embeds sanctionIdentity (sanction.go:274) rather than copying its fields:
// that is the identity a mark is recorded against, so a verdict and a mark
// cannot drift into describing different things, and describe() (sanction.go:310)
// already writes the sentence the page and the ledger both need.
type policyVerdict struct {
	ID string `json:"id"`
	sanctionIdentity
	PID       int            `json:"pid"`
	Origin    string         `json:"origin,omitempty"`
	Cmdline   string         `json:"cmdline,omitempty"`
	Endpoints []string       `json:"endpoints,omitempty"`
	Decision  string         `json:"decision"`
	Reasons   []policyReason `json:"reasons"`
}

// policyRuleLines is the rule in the words the page shows. It lives here, beside
// the terms it describes, so that changing a term and forgetting the sentence is
// one file's mistake rather than two. policy_test.go asserts every term constant
// reaches the rendered page.
func policyRuleLines() []policyReason {
	return []policyReason{
		{Term: policyTermKind, Tier: tierKnown,
			Detail: "it is an agent — not an app you are running, not a browser driver " +
				"with no model behind it, and not an unknown process caught by one signal alone"},
		{Term: policyTermTraffic, Tier: tierVerified,
			Detail: "it is talking to a model, at an address or a port distinctive enough " +
				"to stand on its own"},
		{Term: policyTermOrigin, Tier: tierKnown,
			Detail: "it was started by a clock, by the system, or by another agent — " +
				"nobody was at the keyboard"},
		{Term: policyTermSanction, Tier: tierKnown,
			Detail: "nothing has vouched for it: no host delegation tag, and nobody at " +
				"this machine has marked it as yours"},
	}
}

// ── the rule ────────────────────────────────────────────────────────────────

// policyEvaluate is the rule, for one observation.
//
// THE KIND GATE RETURNS EARLY, and that is a structural choice rather than an
// optimisation: it means no other term — not an unreadable registry, not a
// missing origin — can move an app off leave-alone. contain.go:84-86 refuses to
// terminate an app however the host asks; this rule cannot even propose one.
func policyEvaluate(a agentObs) policyVerdict {
	id := sanctionIdentityOf(a)
	v := policyVerdict{
		ID:               id.fingerprint(),
		sanctionIdentity: id,
		PID:              a.PID,
		Origin:           a.Origin,
		Cmdline:          a.Cmdline,
		Endpoints:        a.LLMEndpoints,
	}
	kind := policyKindTerm(a)
	v.Reasons = []policyReason{kind}
	if kind.Points != policyPointsStop {
		v.Decision = policyLeaveAlone
		return v
	}
	v.Reasons = append(v.Reasons,
		policyTrafficTerm(a), policyOriginTerm(a), policySanctionTerm(a))
	v.Decision = policyDecide(v.Reasons)
	return v
}

// policyDecide folds the terms into one answer. A term that says NO is decisive
// — whatever else could not be read could not have changed the outcome, so the
// answer is a confident leave-alone rather than a shrug. Only when every
// readable term points at stopping does an unreadable one matter, and then it
// matters completely.
func policyDecide(rs []policyReason) string {
	unknown := false
	for _, r := range rs {
		switch r.Points {
		case policyPointsLeave:
			return policyLeaveAlone
		case policyPointsUnknown:
			unknown = true
		}
	}
	if unknown {
		return policyCannotJudge
	}
	return policyWouldStop
}

// policyKindTerm: WHAT the process is (agents.go:168-176).
func policyKindTerm(a agentObs) policyReason {
	r := policyReason{Term: policyTermKind, Tier: tierKnown}
	switch a.Kind {
	case kindAgent:
		r.Points, r.Detail = policyPointsStop, "an agent: software that acts on its own."
	case kindApp:
		r.Points = policyPointsLeave
		r.Detail = "software you are running that happens to talk to a model. This machine " +
			"refuses to close an app however your host asks, so a rule that proposed one " +
			"would be proposing something that cannot happen."
	case kindAutomation:
		r.Points = policyPointsLeave
		r.Detail = "an automation — it drives the machine but has no model of its own. If a " +
			"model joins it, this machine relabels it an agent and it lands back in this rule."
	case kindClient:
		r.Points = policyPointsLeave
		r.Detail = "an unknown process caught by its network traffic alone. One signal is not " +
			"enough to propose stopping something; it is listed here so you can see what a " +
			"wider rule would have caught."
	default:
		// The plane gives every observation a kind (agents_parse.go:242-252), so
		// this is reachable only from a stub or from a kind added upstream that
		// this rule has not been taught. Not a candidate is the safe direction.
		r.Points, r.Tier = policyPointsLeave, tierAmbiguous
		r.Detail = "this machine did not classify it as an agent."
	}
	return r
}

// policyTrafficTerm: the second, independent signal.
func policyTrafficTerm(a agentObs) policyReason {
	r := policyReason{Term: policyTermTraffic}
	// endpointEvidence (origin.go:211-221) is the tier rule itself: a
	// "?"-suffixed label is an ambiguous port. Calling it keeps that judgement
	// in one place instead of re-deciding it here.
	ev := endpointEvidence(a.LLMEndpoints)
	for _, e := range ev {
		if e.Tier != tierAmbiguous {
			r.Points, r.Tier = policyPointsStop, tierVerified
			r.Detail = "talking to " + joinMax(a.LLMEndpoints, 3) + "."
			return r
		}
	}
	r.Points, r.Tier = policyPointsLeave, tierAmbiguous
	if len(ev) > 0 {
		r.Detail = "the only model traffic seen (" + joinMax(a.LLMEndpoints, 3) + ") is on a " +
			"port that ordinary web development also uses, so it corroborates and never " +
			"promotes. If a model really does serve there, tell this machine (OLLAMA_ADDR " +
			"or PRIVATAE_LLM_ADDR) and the port becomes evidence."
		return r
	}
	r.Detail = "no connection to a model when this machine last looked. That is one scan, " +
		"not a guarantee."
	return r
}

// policyOriginTerm: how it was started (origin.go:8-30). An ALLOW-LIST — see
// the header for why "not interactive" was the wrong shape.
func policyOriginTerm(a agentObs) policyReason {
	r := policyReason{Term: policyTermOrigin, Tier: tierKnown}
	switch a.Origin {
	case originScheduler:
		r.Points, r.Detail = policyPointsStop, "it fired on a clock: cron, a timer, or a scheduled task."
	case originService:
		r.Points, r.Detail = policyPointsStop, "it runs as a service, with no session behind it."
	case originAgent:
		r.Points, r.Detail = policyPointsStop, "another agent on this machine started it."
	case originInteractive:
		r.Points = policyPointsLeave
		r.Detail = "it was started from a terminal or a desktop session on this machine — " +
			"a person is plausibly sitting there."
	case originRemote:
		r.Points = policyPointsLeave
		r.Detail = "it was started over ssh or a shared screen — a person, elsewhere. Stopping " +
			"it would take someone's work away exactly as stopping one at this keyboard would."
	case originUnknown, "":
		r.Points, r.Tier = policyPointsUnknown, tierAmbiguous
		r.Detail = "this machine could not establish how it was started. That is not a " +
			"clearance and it is not grounds to stop anything."
	default:
		r.Points, r.Tier = policyPointsUnknown, tierAmbiguous
		r.Detail = "this machine reported an origin this rule has not been taught (" +
			a.Origin + "), so it cannot say whether a person is behind it."
	}
	// Tiered `known` even for an answer the plane called `verified`. classifyOrigin
	// returns verified for a session or a scheduler parent and known for an
	// inventory match (origin.go:169, 182), and this unit cannot tell which
	// answered without re-walking the tree. Reporting the weaker of the two can
	// never overstate what is known.
	return r
}

// policySanctionTerm: the seam (sanction.go:535).
//
// THE CONSTANT IS TESTED BY NAME, BEFORE THE BOOL, and it has to be: an
// unreadable registry comes back (true, sanctionWhyUnreadable), so a term
// written as `if sanctioned` reads a machine that lost its own records as a
// machine where everything is vouched for, and says nothing. See the header.
func policySanctionTerm(a agentObs) policyReason {
	sanctioned, why := agentSanction(a)
	r := policyReason{Term: policyTermSanction, Tier: tierKnown, Detail: why}
	switch {
	// TWO CONSTANTS MEAN "COULD NOT READ", AND NEITHER MEANS "UNWANTED".
	//
	// sanctionWhyUnreadable was here from the start. sanctionWhyNoExe arrived
	// later, with the change that moved a mark off the forgeable argv[0] onto
	// the kernel's executable path — and it returns FALSE, because nothing has
	// vouched for the process. Left in the default branch it scored
	// policyPointsStop, so every observation whose executable path this box
	// cannot read became a PROPOSED KILL. That is not a rare case: it is every
	// process on a build with no enumerator, and on Windows every process whose
	// handle cannot be opened. sanction.go says in as many words that it means
	// UNIDENTIFIED, not unwanted (sanction.go:150).
	//
	// Caught at integration, because neither unit could see it. The policy was
	// written against six constants; the seventh was added afterwards, in another
	// change whose brief was not to alter the seam — and it did not alter it.
	// It ADDED to it, correctly, and the consumer had no way to know. A seam is
	// not safe just because its signature held.
	case why == sanctionWhyUnreadable, why == sanctionWhyNoExe:
		r.Points, r.Tier = policyPointsUnknown, tierAmbiguous
	case sanctioned:
		r.Points = policyPointsLeave
	default:
		r.Points = policyPointsStop
	}
	return r
}

// policyVerdicts is the rule over everything this machine can see right now.
//
// observedAgents (contain.go:34) rather than scanAgents directly, for the
// reason uisanction.go:130-133 gives: it is the same var the thing that KILLS
// consults, so the dry run and the real containment can never be answering
// different questions — and it is the seam every test in this package stubs.
//
// The error is the walk failing: no verdicts, and the caller must not read
// that as "nothing would have been stopped". The error wins over anything
// that came back beside it (the list is not returned with it) — the same rule
// the kill guard and the agents page hold.
func policyVerdicts() ([]policyVerdict, error) {
	seen, err := observedAgents()
	if err != nil {
		return nil, err
	}
	out := make([]policyVerdict, 0, len(seen))
	for _, a := range seen {
		out = append(out, policyEvaluate(a))
	}
	return out, nil
}

// policyWouldStopCount is the headline number: how many of the observations in
// this set the rule would stop, and how many it could not judge at all.
func policyWouldStopCount(vs []policyVerdict) (stop, cannotJudge int) {
	for _, v := range vs {
		switch v.Decision {
		case policyWouldStop:
			stop++
		case policyCannotJudge:
			cannotJudge++
		}
	}
	return stop, cannotJudge
}

// ── the census ──────────────────────────────────────────────────────────────

// policyCandidate is one program this rule would have stopped, and when.
//
// It embeds sanctionIdentity for the same reason policyVerdict does, and here
// there is a second: the ledger outlives the process, so the only thing that can
// name a row a week later is an identity built to survive a restart
// (sanction.go:38-78). Everything prefixed Last is what the program looked like
// the last time it was seen — carried so a person reviewing this can recognise
// it, never matched on.
type policyCandidate struct {
	ID string `json:"id"`
	sanctionIdentity
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	LastPID       int       `json:"last_pid,omitempty"`
	LastOrigin    string    `json:"last_origin,omitempty"`
	LastCmdline   string    `json:"last_cmdline,omitempty"`
	LastEndpoints []string  `json:"last_endpoints,omitempty"`
}

// policyLedger is the census on disk.
//
// Since answers "how long has this been measured", LastScan answers "is it
// still being measured", and the difference between them is the whole reason
// both exist — see the header.
type policyLedger struct {
	Since      time.Time                  `json:"since"`
	LastScan   time.Time                  `json:"last_scan"`
	Dropped    int                        `json:"dropped,omitempty"`
	Candidates map[string]policyCandidate `json:"candidates"`
}

const (
	// policyCensusEvery — WHY 60 SECONDS. It is the cadence this box ALREADY
	// samples this exact data at: every heartbeat calls scanAgents()
	// (agents.go:479) and the beat is a 60-second ticker (run.go:596). So the
	// census adds one more scan per minute to a box that already runs one per
	// minute per pairing — not a new cost class, and the same resolution the
	// host's own agent list has. The limit is honest and stated on the page:
	// anything that lives and dies inside a minute is invisible to a sampler,
	// exactly as it is invisible to the heartbeat.
	policyCensusEvery = 60 * time.Second
	// policyCensusFirst keeps the first scan clear of daemon startup, the same
	// reason update.go:251-257 gives for its own first check.
	policyCensusFirst = 20 * time.Second
	// policyLedgerFlush — how stale last_seen and last_scan are allowed to get.
	// A NEW candidate is written the moment it appears; this governs only the
	// clock. Five minutes is 288 writes a day of a file measured in kilobytes,
	// against a stopped-census window nobody would notice. The page states the
	// granularity rather than implying a precision the file does not have.
	policyLedgerFlush = 5 * time.Minute
	// policyLedgerMax bounds the file. A machine with more than this many
	// DISTINCT unvouched-for automated identities has a different problem than
	// this page can help with, and the alternative — an unbounded file fed by
	// anything that launches itself from a fresh temp path each run — is a disk
	// the user did not agree to spend. The oldest go first and the count of what
	// went is kept, so the page can say the census is trimming rather than
	// quietly becoming a lie.
	policyLedgerMax = 500
)

// policyNow is the clock seam, as sanction.go:353 and directive_refusal.go:35
// do it: a test pins the timestamp rather than sleeping.
var policyNow = time.Now

// policyMu serialises the ledger's read-modify-write.
var policyMu sync.Mutex

// The last census failure, kept so the PAGE can say the record is not being
// written — the shape directive_refusal.go:30-36 uses, and for its reason: a
// failure that only ever reached a console is a failure nobody standing at the
// machine can see. A census that cannot write and says nothing would render as
// "nothing would have been stopped", which is the most reassuring sentence this
// program could print about a machine it has stopped watching.
var (
	policyErrMu sync.Mutex
	policyErr   string
	policyErrAt time.Time
)

func recordPolicyCensusError(err error) {
	policyErrMu.Lock()
	defer policyErrMu.Unlock()
	if err == nil {
		policyErr, policyErrAt = "", time.Time{}
		return
	}
	policyErr, policyErrAt = err.Error(), policyNow().UTC()
}

func policyCensusError() (string, time.Time) {
	policyErrMu.Lock()
	defer policyErrMu.Unlock()
	return policyErr, policyErrAt
}

// policyLedgerPath is the census's home. configDirPath(), NOT configDir():
// resolving a path must not create a directory. See the header.
func policyLedgerPath() (string, error) {
	d, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "policy-dryrun.json"), nil
}

// loadPolicyLedger reads the census.
//
// A MISSING FILE IS AN EMPTY LEDGER AND NOT AN ERROR — but the caller can still
// tell "never run" from "ran and found nothing", because a ledger that has ever
// run has a Since. A CORRUPT FILE IS AN ERROR, the same line loadSanctions
// draws at sanction.go:373-379: "I could not read it" and "there is nothing in
// it" have to stay different answers, and here the second one is the all-clear.
//
// A corrupt file therefore STOPS the census until somebody removes it, because
// policyRecord will not write over a read it could not make. That direction is
// chosen rather than fallen into: this file is the record of what a rule would
// have taken away from a person, and overwriting it because it did not parse
// destroys the evidence instead of the problem. The page says so, where the
// person is, rather than leaving it to a log.
func loadPolicyLedger() (policyLedger, error) {
	l := policyLedger{Candidates: map[string]policyCandidate{}}
	p, err := policyLedgerPath()
	if err != nil {
		return l, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return l, err
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return policyLedger{Candidates: map[string]policyCandidate{}}, err
	}
	if l.Candidates == nil {
		l.Candidates = map[string]policyCandidate{}
	}
	return l, nil
}

// savePolicyLedgerLocked writes the census. Caller holds policyMu.
func savePolicyLedgerLocked(l policyLedger) error {
	p, err := policyLedgerPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b) // ctx.go:133-160 — temp file, 0600, fsync, rename
}

// policyTrim drops the oldest candidates once the ledger is over its cap, and
// counts what went. Oldest by LAST seen rather than first: something that has
// been a candidate for months and still is has more to say about this rule than
// something last seen in March.
func policyTrim(l *policyLedger) {
	if len(l.Candidates) <= policyLedgerMax {
		return
	}
	ids := make([]string, 0, len(l.Candidates))
	for id := range l.Candidates {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := l.Candidates[ids[i]], l.Candidates[ids[j]]
		if a.LastSeen.Equal(b.LastSeen) {
			return a.ID < b.ID // a stable trim, not a random one
		}
		return a.LastSeen.Before(b.LastSeen)
	})
	for _, id := range ids[:len(ids)-policyLedgerMax] {
		delete(l.Candidates, id)
		l.Dropped++
	}
}

// policyRecord folds one scan's would-stop set into the census.
//
// It records ONLY would-stop. A cannot-judge is not a candidate — the rule did
// not reach a verdict — and writing one into a list headed "what this would
// have stopped" would put a machine's blind spot in a column of accusations.
// The page carries the cannot-judge count separately, where it reads as the
// alarm it is.
func policyRecord(vs []policyVerdict) error {
	now := policyNow().UTC()
	policyMu.Lock()
	defer policyMu.Unlock()
	l, err := loadPolicyLedger()
	if err != nil {
		return err
	}
	changed := l.Since.IsZero() // the first scan writes, even with nothing to say
	if changed {
		l.Since = now
	}
	for _, v := range vs {
		if v.Decision != policyWouldStop {
			continue
		}
		c, ok := l.Candidates[v.ID]
		if !ok {
			// A program this rule has never proposed stopping before. Written
			// immediately, not at the next flush: it is the event the census
			// exists to catch, and a crash in the next five minutes must not
			// lose it.
			c = policyCandidate{ID: v.ID, FirstSeen: now}
			changed = true
		}
		c.sanctionIdentity = v.sanctionIdentity
		c.LastSeen = now
		c.LastPID, c.LastOrigin, c.LastCmdline = v.PID, v.Origin, v.Cmdline
		c.LastEndpoints = v.Endpoints
		l.Candidates[v.ID] = c
	}
	if now.Sub(l.LastScan) >= policyLedgerFlush {
		changed = true
	}
	if !changed {
		// Nothing new, and the clock is fresh enough. The LastSeen bumps above
		// are dropped rather than kept in memory — a cached copy of a file
		// something else may write is the shape sanction.go:169-178 rejects, and
		// the cost is a last_seen accurate to policyLedgerFlush, which the page
		// says out loud.
		return nil
	}
	l.LastScan = now
	policyTrim(&l)
	return savePolicyLedgerLocked(l)
}

// policyCensusTick is one pass: evaluate, record, remember any failure.
//
// A failed walk is RECORDED as the census failure, not written as a clean pass:
// policyRecord over no verdicts would have cleared the stored error and the
// page would then read "nothing would have been stopped" about a machine the
// census could not see.
func policyCensusTick() {
	verdicts, err := policyVerdicts()
	if err != nil {
		recordPolicyCensusError(fmt.Errorf("the process walk failed, so this pass judged nothing: %w", err))
		return
	}
	recordPolicyCensusError(policyRecord(verdicts))
}

// runPolicyCensus keeps the census going for as long as the daemon runs. Shaped
// on runUpdateAvailabilityPoll (update.go:265-280), started beside it from
// startUIServer (ui.go).
//
// IT MUST NOT BE DRIVEN BY THE PAGE. Rendering is a read, and a read that writes
// to disk is the defect ui_approvals_flow_test.go:9-15 was written about; worse, a
// census that only accumulates while somebody has a browser open would answer
// "nothing would have been stopped" for every machine nobody was watching, which
// is every machine this measurement is for.
func runPolicyCensus(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(policyCensusFirst):
	}
	for {
		policyCensusTick()
		select {
		case <-ctx.Done():
			return
		case <-time.After(policyCensusEvery):
		}
	}
}
