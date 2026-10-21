package main

// The dry-run policy (policy.go): the rule, the census it writes, and the one
// property the whole unit exists to have — that it cannot stop anything.
//
// NOT tagged !windows, for the same reason sanction_test.go is not: this rule
// decides whether a Windows user's own editor would survive an automatic policy,
// so it has to be proven on that build too.
//
// Every test below was MUTATION-CHECKED — the code it covers was broken, the
// test confirmed red, and the code was restored. The mutation is named in each
// comment so the next person can re-run it rather than take this on trust.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// policyTestBox isolates the config dir and stubs the observe plane.
//
// It uses sanctionTestBox (sanction_test.go:30), which CREATES NOTHING and
// fails if the config dir already exists: whether asking this rule a question
// creates a directory is one of the claims below, and a fixture that supplies
// the thing under test can only ever pass (ui_approvals_flow_test.go:9-15).
func policyTestBox(t *testing.T, seen ...agentObs) string {
	t.Helper()
	cfg := sanctionTestBox(t)
	prev := observedAgents
	t.Cleanup(func() {
		observedAgents = prev
		policyNow = time.Now
		recordPolicyCensusError(nil)
	})
	observedAgents = func() ([]agentObs, error) { return seen, nil }
	recordPolicyCensusError(nil)
	return cfg
}

// policyCandidateObs is an observation that meets every term of the rule: an
// agent, talking to a model at a distinctive address, started by the system,
// with nothing vouching for it.
//
// Exe IS REQUIRED and was added at integration. These fixtures were written
// before the change that moved a mark off the forgeable argv[0] onto the
// kernel's executable path, so they carried none — and agentSanction answers
// sanctionWhyNoExe for an observation with no path, which the policy scores
// cannot-judge rather than would-stop. Every verdict test here was passing for
// the wrong reason: the fixture was unidentifiable, and under the old six-reason
// seam that happened to land on the same answer as "nothing vouched for it".
// A rule test needs a process the machine can actually identify.
func policyCandidateObs(sig, cmd string, pid int) agentObs {
	return agentObs{
		PID: pid, Kind: kindAgent, Signature: sig, Cmdline: cmd, User: "user",
		Exe:    "/usr/local/bin/" + sig,
		Origin: originService, LLMEndpoints: []string{"api.anthropic.com"},
	}
}

// reasonFor pulls one term's answer out of a verdict.
func reasonFor(t *testing.T, v policyVerdict, term string) policyReason {
	t.Helper()
	for _, r := range v.Reasons {
		if r.Term == term {
			return r
		}
	}
	t.Fatalf("the verdict carries no %q term: %+v", term, v.Reasons)
	return policyReason{}
}

// ── the trap: a registry this machine could not read ────────────────────────

// agentSanction returns (TRUE, sanctionWhyUnreadable) when the registry will not
// load (sanction.go:539-541), and that true is not a vouch — it is an absence of
// knowledge. A policy that reads it as "fine" goes blind in silence, which is
// the failure this whole feature exists to prevent. The constant has to be
// tested BY NAME, before the bool.
//
// MUTATION: delete the `why == sanctionWhyUnreadable` case from
// policySanctionTerm, leaving `case sanctioned: leave`.
// RESULT: red — "a corrupt registry read as: leave-alone". Every candidate on
// the machine silently stopped being one, and the page would have said so.
func TestARegistryThisMachineCannotReadIsNeverAClearance(t *testing.T) {
	cfg := policyTestBox(t)
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"),
		[]byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	v := policyEvaluate(policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))
	if v.Decision != policyCannotJudge {
		t.Fatalf("a corrupt registry read as: %s. It must be %s — the rule is missing a "+
			"term it needs, which is a different fact from having nothing to judge.",
			v.Decision, policyCannotJudge)
	}
	r := reasonFor(t, v, policyTermSanction)
	if r.Points != policyPointsUnknown {
		t.Errorf("the sanction term points %q, want %q", r.Points, policyPointsUnknown)
	}
	if r.Detail != sanctionWhyUnreadable {
		t.Errorf("the term does not carry the reason the seam gave: %q", r.Detail)
	}
	if r.Tier != tierAmbiguous {
		t.Errorf("an unreadable record is tiered %q — it is not knowledge", r.Tier)
	}
}

// The same corrupt registry, on an app. The kind gate is the outermost term for
// exactly this: contain.go:84-86 refuses to terminate an app however the host
// asks, so nothing this rule cannot read may move one off leave-alone.
//
// MUTATION: return policyPointsStop for kindApp in policyKindTerm.
// RESULT: red — the Claude desktop app became a candidate, which is the nine
// kill buttons agents.go:170-176 was written about.
func TestAnAppIsNeverACandidateWhateverElseIsUnreadable(t *testing.T) {
	cfg := policyTestBox(t)
	app := policyCandidateObs("claude-desktop", "/Applications/Claude.app/Contents/MacOS/claude", 51)
	app.Kind = kindApp

	if v := policyEvaluate(app); v.Decision != policyLeaveAlone {
		t.Fatalf("an app meeting every other term = %s, want %s", v.Decision, policyLeaveAlone)
	}
	// And with nothing else readable either.
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	app.Origin = originUnknown
	v := policyEvaluate(app)
	if v.Decision != policyLeaveAlone {
		t.Fatalf("an app on a machine that could read neither its marks nor its origins = %s, "+
			"want %s — this rule must not even be able to propose an app", v.Decision, policyLeaveAlone)
	}
	if len(v.Reasons) != 1 || v.Reasons[0].Term != policyTermKind {
		t.Errorf("the app's verdict should rest on the kind term alone: %+v", v.Reasons)
	}
}

// ── automation: inventory until a model joins it ────────────────────────────

// An automation drives the machine with no model of its own (agents.go:61-65)
// and is never an alert. This rule needs no term for it, because the plane
// itself relabels one `agent` the moment STRONG model traffic joins it
// (agents_parse.go:421-426) — so the promotion is driven here through
// mergeConnections rather than asserted, and the rule is run on both sides of it.
//
// MUTATION: point kindAutomation at policyPointsStop in policyKindTerm.
// RESULT: red — "the kind term points stop". The first version of this test
// asserted only that a chromedriver with no endpoints is left alone, which the
// TRAFFIC term already guaranteed, so the mutation ran green: it was proving
// something other than what it claimed. It now asserts on the kind term
// directly, and hands the gate the shape it must refuse even if something
// upstream produces one.
func TestAnAutomationIsACandidateOnlyOnceModelTrafficPromotesIt(t *testing.T) {
	policyTestBox(t)
	driver := agentObs{PID: 77, Kind: kindAutomation, Signature: "chromedriver",
		Cmdline: "/usr/bin/chromedriver --port=9515", User: "user",
		Exe: "/usr/bin/chromedriver", Origin: originService}

	if r := policyKindTerm(driver); r.Points != policyPointsLeave {
		t.Fatalf("the kind term points %q for an automation, want %q (%q)",
			r.Points, policyPointsLeave, r.Detail)
	}
	if v := policyEvaluate(driver); v.Decision != policyLeaveAlone {
		t.Fatalf("an automation with no model behind it = %s, want %s", v.Decision, policyLeaveAlone)
	}
	// The gate holds even when every other term points at stopping. That shape
	// cannot come out of the live plane — mergeConnections would have promoted
	// it — which is the point: the kind gate is what this rule relies on, not
	// what the plane happens to hand it.
	loud := driver
	loud.LLMEndpoints = []string{"api.anthropic.com"}
	v := policyEvaluate(loud)
	if v.Decision != policyLeaveAlone {
		t.Fatalf("an automation meeting every other term = %s, want %s", v.Decision, policyLeaveAlone)
	}
	if len(v.Reasons) != 1 || v.Reasons[0].Term != policyTermKind {
		t.Errorf("the automation's verdict should rest on the kind term alone: %+v", v.Reasons)
	}

	// The plane's own promotion: a strong local endpoint on the same pid.
	byPid := map[int]agentObs{77: driver}
	mergeConnections(byPid,
		[]connObs{{PID: 77, RemoteIP: "127.0.0.1", RemotePort: 11434}},
		map[string]string{}, map[int]string{11434: "ollama"}, map[int]string{},
		// mergeConnections took three loose strings until a later change gave
		// it procDetail, so the kernel's executable path could travel with the
		// user and cmdline instead of being squeezed into a fourth return. A
		// driver promoted by model traffic carries no exe here on purpose: the
		// policy must treat "no path" as UNIDENTIFIED, never as unwanted.
		func(int) procDetail { return procDetail{User: "user", Cmdline: driver.Cmdline} },
		func(int) int { return 1 })
	promoted := byPid[77]
	if promoted.Kind != kindAgent {
		t.Fatalf("fixture is broken: mergeConnections left the kind %q — the claim this "+
			"rule rests on is that model traffic promotes an automation", promoted.Kind)
	}
	if v := policyEvaluate(promoted); v.Decision != policyWouldStop {
		t.Fatalf("the promoted automation = %s, want %s: %+v", v.Decision, policyWouldStop, v.Reasons)
	}
}

// ── origin: an allow-list, because "not interactive" swept up two others ────

// The original sketch of the rule was "whose origin is not `interactive`".
// That deny-list includes `remote` — origin.go:19, "an ssh /
// mosh / screen-sharing ancestor: a person, elsewhere" — and killing an agent
// somebody started over ssh is the same false positive as killing one they
// started at this keyboard.
//
// MUTATION: move originRemote into the policyPointsStop arm of policyOriginTerm.
// RESULT: red — "an agent started over ssh = would-stop".
func TestAPersonAtAKeyboardIsNeverACandidateWhereverTheKeyboardIs(t *testing.T) {
	policyTestBox(t)
	for _, c := range []struct {
		origin string
		want   string
	}{
		{originInteractive, policyLeaveAlone},
		{originRemote, policyLeaveAlone},
		{originScheduler, policyWouldStop},
		{originService, policyWouldStop},
		{originAgent, policyWouldStop},
	} {
		a := policyCandidateObs("aider", "/usr/local/bin/aider", 4243)
		a.Origin = c.origin
		if v := policyEvaluate(a); v.Decision != c.want {
			t.Errorf("origin %s = %s, want %s (%q)", c.origin, v.Decision, c.want,
				reasonFor(t, v, policyTermOrigin).Detail)
		}
	}
}

// origin.go:25 defines `unknown` as "the box could not read enough to say. Never
// guessed." A deny-list read that absence as grounds to stop something.
//
// MUTATION: make the originUnknown branch return policyPointsLeave.
// RESULT: red — a process whose lineage could not be read was quietly cleared,
// and the page counted it among the ones the rule leaves alone.
func TestAnOriginThisMachineCouldNotReadIsNotAClearanceEither(t *testing.T) {
	policyTestBox(t)
	for _, origin := range []string{originUnknown, "", "something-new"} {
		a := policyCandidateObs("goose", "/usr/local/bin/goose", 4244)
		a.Origin = origin
		v := policyEvaluate(a)
		if v.Decision != policyCannotJudge {
			t.Errorf("origin %q = %s, want %s", origin, v.Decision, policyCannotJudge)
		}
		if r := reasonFor(t, v, policyTermOrigin); r.Tier != tierAmbiguous {
			t.Errorf("origin %q is tiered %q — an answer this machine does not have "+
				"is never knowledge", origin, r.Tier)
		}
	}
	// And an unknown origin is NOT decisive on its own: something that is not
	// talking to a model is left alone with confidence, whatever its lineage.
	quiet := policyCandidateObs("goose", "/usr/local/bin/goose", 4245)
	quiet.Origin, quiet.LLMEndpoints = originUnknown, nil
	if v := policyEvaluate(quiet); v.Decision != policyLeaveAlone {
		t.Errorf("an unreadable origin on something with no model traffic = %s, want %s — "+
			"a term that says no is decisive and the missing one could not have changed it",
			v.Decision, policyLeaveAlone)
	}
}

// ── model traffic: the second signal, and what counts as one ────────────────

// An ambiguous port is one that collides with ordinary web development
// (agents.go:146-151), and the plane's standing rule is that those annotate and
// never promote (agents.go:130-133). This rule obeys it, or every developer with
// something on :8080 becomes a candidate.
//
// MUTATION: in policyTrafficTerm, take the first endpoint as strong regardless
// of its tier (drop the `e.Tier != tierAmbiguous` guard).
// RESULT: red — an agent whose only traffic was to :8080 became a candidate.
func TestAnAmbiguousPortCorroboratesAndNeverPromotes(t *testing.T) {
	policyTestBox(t)
	for _, c := range []struct {
		eps  []string
		want string
	}{
		{[]string{"api.anthropic.com"}, policyWouldStop},
		{[]string{"local:11434 (ollama)"}, policyWouldStop},
		{[]string{"local:8080 (llama.cpp/localai?)"}, policyLeaveAlone},
		{[]string{"local:8080 (llama.cpp/localai?)", "local:11434 (ollama)"}, policyWouldStop},
		{nil, policyLeaveAlone},
	} {
		a := policyCandidateObs("cline", "/usr/local/bin/cline", 4246)
		a.LLMEndpoints = c.eps
		v := policyEvaluate(a)
		if v.Decision != c.want {
			t.Errorf("endpoints %v = %s, want %s (%q)", c.eps, v.Decision, c.want,
				reasonFor(t, v, policyTermTraffic).Detail)
		}
	}
	// No traffic is an ANSWER — the connection table was read — so it is a
	// decisive leave-alone rather than a shrug, tiered ambiguous because one
	// scan is a snapshot.
	quiet := policyCandidateObs("cline", "/usr/local/bin/cline", 4247)
	quiet.LLMEndpoints = nil
	r := reasonFor(t, policyEvaluate(quiet), policyTermTraffic)
	if r.Points != policyPointsLeave || r.Tier != tierAmbiguous {
		t.Errorf("no traffic gave points %q tier %q, want %q / %q",
			r.Points, r.Tier, policyPointsLeave, tierAmbiguous)
	}
}

// A tag is one of TWO mechanisms and this rule never reads it directly — it
// compares the reason constant agentSanction returns (sanction.go:196-207), so
// a local mark counts exactly as much as a host tag does.
//
// MUTATION: in policySanctionTerm, ignore `sanctioned` and point at stop
// whenever the reason is not sanctionWhyLocal.
// RESULT: red — a host-tagged agent stayed a candidate.
func TestEitherMechanismTakesSomethingOutOfTheCandidateSet(t *testing.T) {
	policyTestBox(t)
	tagged := policyCandidateObs("claude-code", "/usr/local/bin/claude", 4248)
	tagged.DelegationToken = "del_4jk-Lm9QzR_tUv2wXy7Bc1" // the shape the host mints
	if v := policyEvaluate(tagged); v.Decision != policyLeaveAlone {
		t.Errorf("a host-tagged agent = %s, want %s", v.Decision, policyLeaveAlone)
	}

	marked := policyCandidateObs("aider", "/usr/local/bin/aider", 4249)
	if v := policyEvaluate(marked); v.Decision != policyWouldStop {
		t.Fatalf("fixture is broken: %s before anything was marked", v.Decision)
	}
	if _, err := addSanction(marked, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	if v := policyEvaluate(marked); v.Decision != policyLeaveAlone {
		t.Errorf("a locally marked agent = %s, want %s", v.Decision, policyLeaveAlone)
	}
	// A tag that is not shaped like one the host mints is not a vouch — setting
	// one environment variable would otherwise be the whole evasion.
	bad := policyCandidateObs("goose", "/usr/local/bin/goose", 4250)
	bad.DelegationToken = "yes"
	if v := policyEvaluate(bad); v.Decision != policyWouldStop {
		t.Errorf("PRIVATAE_AGENT_TOKEN=yes = %s, want %s", v.Decision, policyWouldStop)
	}
}

// ── the answer is not a boolean ─────────────────────────────────────────────

// agents.go:183-188: the plane "never emits a bare verdict — it emits typed
// evidence with tiers so the host shows WHY". A verdict nobody can audit is a
// verdict nobody should trust, and this one feeds a feature that kills things.
//
// MUTATION: drop the three trailing terms from policyEvaluate (keep the kind
// term and decide from it alone).
// RESULT: red — "the verdict carries no model-traffic term".
func TestEveryVerdictCarriesEveryTermItWasDecidedOn(t *testing.T) {
	policyTestBox(t)
	v := policyEvaluate(policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))

	want := []string{policyTermKind, policyTermTraffic, policyTermOrigin, policyTermSanction}
	if len(v.Reasons) != len(want) {
		t.Fatalf("a candidate's verdict rests on %d terms, want %d: %+v",
			len(v.Reasons), len(want), v.Reasons)
	}
	for i, term := range want {
		r := v.Reasons[i]
		if r.Term != term {
			t.Errorf("term %d is %q, want %q", i, r.Term, term)
		}
		if r.Detail == "" {
			t.Errorf("%s carries no sentence — a reason a person cannot read is a "+
				"reason that gets ignored", term)
		}
		switch r.Tier {
		case tierVerified, tierKnown, tierAmbiguous:
		default:
			t.Errorf("%s is tiered %q, which is not one of the plane's three", term, r.Tier)
		}
		if r.Points != policyPointsStop {
			t.Errorf("%s points %q on an observation that meets every term", term, r.Points)
		}
	}
	// The identity a mark is recorded against travels with the verdict, so the
	// census and the sanction page can name the same thing (sanction.go:274-292).
	if v.ID != sanctionIdentityOf(policyCandidateObs("claude-code", "/usr/local/bin/claude", 9999)).fingerprint() {
		t.Error("the verdict's id is not the sanction fingerprint, so it does not survive a restart")
	}
}

// ── the census ──────────────────────────────────────────────────────────────

// What would have been stopped has to be nameable a week later, which means on
// disk, keyed by an identity that survives a restart at a new pid.
//
// MUTATION: remove the `if v.Decision != policyWouldStop { continue }` guard
// from policyRecord.
// RESULT: red — the desktop app the rule leaves alone was written into a list
// headed "what this would have stopped".
func TestTheCensusNamesOnlyWhatWouldHaveBeenStopped(t *testing.T) {
	cfg := policyTestBox(t)
	candidate := policyCandidateObs("claude-code", "/usr/local/bin/claude --resume abc", 4242)
	app := policyCandidateObs("claude-desktop", "/Applications/Claude.app/Contents/MacOS/claude", 51)
	app.Kind = kindApp
	observedAgents = func() ([]agentObs, error) { return []agentObs{candidate, app}, nil }

	policyCensusTick()

	// Read back from the bytes, the way a fresh process would.
	b, err := os.ReadFile(filepath.Join(cfg, "policy-dryrun.json"))
	if err != nil {
		t.Fatalf("the census is not on disk: %v — it would not survive a restart", err)
	}
	var l policyLedger
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatalf("the census on disk does not parse: %v", err)
	}
	if len(l.Candidates) != 1 {
		t.Fatalf("the census holds %d entries, want 1: %+v", len(l.Candidates), l.Candidates)
	}
	c, ok := l.Candidates[sanctionIdentityOf(candidate).fingerprint()]
	if !ok {
		t.Fatalf("the census does not hold the candidate under its sanction fingerprint: %+v", l.Candidates)
	}
	// This was argv[0] once; the census now names the KERNEL's path,
	// which is the whole point — a census that names what a process CALLED
	// itself records the forgery rather than the file.
	if c.Signature != "claude-code" || c.Exe != "/usr/local/bin/claude-code" || c.User != "user" {
		t.Errorf("the census cannot name what it would have stopped: %+v", c.sanctionIdentity)
	}
	if c.LastCmdline != candidate.Cmdline || c.LastPID != 4242 || c.LastOrigin != originService {
		t.Errorf("the census does not carry enough to recognise it: %+v", c)
	}
	if c.FirstSeen.IsZero() || c.LastSeen.IsZero() || l.Since.IsZero() || l.LastScan.IsZero() {
		t.Errorf("the census carries no clock: %+v", l)
	}
}

// A machine that has taken this measurement and found nothing is not the same
// machine as one that has never taken it. agents.go:594-598 records the same
// trap for the second-bastion scan: an answer of [] from a scan that stopped
// reads as "clean" for ever with nothing to say otherwise.
//
// MUTATION: initialise `changed` to false in policyRecord, so a scan with
// nothing to record writes nothing.
// RESULT: red — no file, and the page could not tell a clean machine from one
// that had never looked.
func TestTheCensusRecordsThatItLookedEvenWithNothingToRecord(t *testing.T) {
	cfg := policyTestBox(t, agentObs{PID: 51, Kind: kindApp, Signature: "claude-desktop",
		Exe:     "/Applications/Claude.app/Contents/MacOS/Claude",
		Cmdline: "/Applications/Claude.app/Contents/MacOS/claude", User: "user",
		Origin: originInteractive})

	policyCensusTick()

	l, err := loadPolicyLedger()
	if err != nil {
		t.Fatal(err)
	}
	if l.Since.IsZero() {
		t.Fatalf("a scan that found nothing left no record that it ran: %s",
			filepath.Join(cfg, "policy-dryrun.json"))
	}
	if len(l.Candidates) != 0 {
		t.Errorf("the census invented %d candidates", len(l.Candidates))
	}
	if msg, _ := policyCensusError(); msg != "" {
		t.Errorf("the tick recorded an error: %s", msg)
	}
}

// The first sighting is the audit fact; the last one is how long this would have
// gone on for. Between flushes the clock is deliberately not rewritten — the
// cost of that is a last_seen accurate to policyLedgerFlush, which the page says
// out loud rather than implying a precision the file does not have.
//
// MUTATION: set c.FirstSeen = now unconditionally in policyRecord.
// RESULT: red — "the first sighting moved", and a candidate that had been one
// for three days looked like it had appeared this minute.
func TestTheCensusKeepsTheFirstSightingAndMovesTheLast(t *testing.T) {
	policyTestBox(t, policyCandidateObs("aider", "/usr/local/bin/aider", 4243))
	first := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	policyNow = func() time.Time { return first }
	policyCensusTick()

	// Inside the flush window: the file is not rewritten.
	policyNow = func() time.Time { return first.Add(policyLedgerFlush / 2) }
	policyCensusTick()
	l, err := loadPolicyLedger()
	if err != nil {
		t.Fatal(err)
	}
	if !l.LastScan.Equal(first) {
		t.Errorf("the census rewrote itself inside the flush window (last_scan %s)", l.LastScan)
	}

	// Past it: the clock moves, the first sighting does not.
	later := first.Add(policyLedgerFlush + time.Minute)
	policyNow = func() time.Time { return later }
	policyCensusTick()
	l, err = loadPolicyLedger()
	if err != nil {
		t.Fatal(err)
	}
	c := l.Candidates[sanctionIdentityOf(policyCandidateObs("aider", "/usr/local/bin/aider", 0)).fingerprint()]
	if !c.FirstSeen.Equal(first) {
		t.Errorf("the first sighting moved to %s, want %s", c.FirstSeen, first)
	}
	if !c.LastSeen.Equal(later) {
		t.Errorf("the last sighting is %s, want %s", c.LastSeen, later)
	}
	if !l.Since.Equal(first) {
		t.Errorf("the census window start moved to %s", l.Since)
	}
}

// The file is bounded. Anything that launches itself from a fresh temp path each
// run would otherwise grow it without limit, on a disk the user did not agree to
// spend — and a census that quietly became a lie about its own completeness is
// the thing this page cannot be.
//
// MUTATION: remove the policyTrim call from policyRecord.
// RESULT: red — the ledger kept growing past its cap and Dropped stayed 0.
func TestTheCensusIsBoundedAndDropsTheOldestFirst(t *testing.T) {
	cfg := policyTestBox(t, policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	// A ledger already at its cap, oldest first.
	l := policyLedger{Since: base, LastScan: base, Candidates: map[string]policyCandidate{}}
	for i := range policyLedgerMax {
		id := "filler-" + strconv.Itoa(i)
		l.Candidates[id] = policyCandidate{ID: id, FirstSeen: base,
			LastSeen: base.Add(time.Duration(i) * time.Minute)}
	}
	oldest := ""
	for id, c := range l.Candidates {
		if oldest == "" || c.LastSeen.Before(l.Candidates[oldest].LastSeen) {
			oldest = id
		}
	}
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(l, "", "  ")
	if err := os.WriteFile(filepath.Join(cfg, "policy-dryrun.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	policyNow = func() time.Time { return base.Add(24 * time.Hour) }
	policyCensusTick()

	got, err := loadPolicyLedger()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Candidates) != policyLedgerMax {
		t.Fatalf("the census holds %d entries, want its cap of %d", len(got.Candidates), policyLedgerMax)
	}
	if _, still := got.Candidates[oldest]; still {
		t.Errorf("the oldest entry survived the trim")
	}
	if got.Dropped != 1 {
		t.Errorf("dropped = %d, want 1 — a census that trims silently is a census that "+
			"lies about its own completeness", got.Dropped)
	}
	if _, ok := got.Candidates[sanctionIdentityOf(policyCandidateObs("claude-code", "/usr/local/bin/claude", 0)).fingerprint()]; !ok {
		t.Error("the new candidate was trimmed instead of the old ones")
	}
}

// Asking what would be stopped must CREATE NOTHING. This rule is called in a
// loop over every observation, and ui_approvals_flow_test.go:53-84 exists because a
// page that asked a question created a directory — twice. sanction.go:160-167
// holds the same line at the seam this reads.
//
// MUTATION: build policyLedgerPath on configDir() instead of configDirPath().
// RESULT: red — reading the page created the config directory.
func TestAskingWhatWouldBeStoppedCreatesNothing(t *testing.T) {
	cfg := policyTestBox(t, policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))

	if vs, err := policyVerdicts(); err != nil || len(vs) != 1 {
		t.Fatalf("fixture is broken: %d verdicts", len(vs))
	}
	if _, err := loadPolicyLedger(); err != nil {
		t.Fatal(err)
	}
	_ = collectPolicyView()

	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatalf("asking what would be stopped created %s. configDirPath() "+
			"(config.go:129) resolves a path; configDir() (config.go:137) is "+
			"MkdirAll-on-read, and nothing on a read path may be the second one.", cfg)
	}
}

// ── the point of the unit: it cannot stop anything ──────────────────────────

// Acting is step 4, and shipping it before step 3 is how this product would
// acquire a reputation for killing people's work. The dry run earns the claim
// only if it genuinely cannot act, so this
// checks both halves: the source of the unit never NAMES the one side effect in
// contain.go, and driving everything it has with that side effect stubbed kills
// nothing.
//
// MUTATION: add `killProcess(1)` to policyCensusTick.
// RESULT: red twice — "policy.go:… names killProcess" and "this unit terminated
// [1]".
func TestNothingInThisUnitCanReachContainment(t *testing.T) {
	// ── the source half ──
	files := []string{"policy.go", "uipolicy.go"}
	// Named rather than globbed, and asserted to exist, so a rename cannot make
	// this check pass vacuously (buildtags_test.go:65-67 makes the same point).
	forbidden := map[string]string{
		"killProcess":  "the one side effect in contain.go:41",
		"maybeContain": "the host-directed containment path, contain.go:56",
	}
	forbiddenSel := map[string]string{
		"Kill":   "a process signal",
		"Signal": "a process signal",
	}
	forbiddenImport := map[string]string{
		`"os/exec"`: "starting a program",
		`"syscall"`: "signalling one",
	}
	for _, name := range files {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("%s is not here (%v) — this check would pass vacuously", name, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, imp := range f.Imports {
			if why, bad := forbiddenImport[imp.Path.Value]; bad {
				t.Errorf("%s imports %s (%s). This unit reports what a rule WOULD stop; "+
					"it may not be able to stop anything.", name, imp.Path.Value, why)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if why, bad := forbiddenSel[node.Sel.Name]; bad {
					t.Errorf("%s:%d reaches .%s (%s)", name,
						fset.Position(node.Pos()).Line, node.Sel.Name, why)
				}
			case *ast.Ident:
				if why, bad := forbidden[node.Name]; bad {
					t.Errorf("%s:%d names %s — %s. Step 3 is a rehearsal and step 4 is a "+
						"separate decision.",
						name, fset.Position(node.Pos()).Line, node.Name, why)
				}
			}
			return true
		})
	}

	// ── the behavioural half ──
	policyTestBox(t, policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))
	prevKill := killProcess
	t.Cleanup(func() { killProcess = prevKill })
	var killed []int
	killProcess = func(pid int) error { killed = append(killed, pid); return nil }

	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	policyCensusTick()
	for _, path := range []string{"/policy", "/fragments/policy"} {
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
		}
	}
	if len(killed) != 0 {
		t.Fatalf("this unit terminated %v — a dry run that can act is not a dry run", killed)
	}
}
