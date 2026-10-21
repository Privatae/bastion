package main

// The page that shows what the dry-run rule would stop (uipolicy.go), driven
// end to end through the real mux.
//
// NOT tagged !windows, for the same reason ui_test.go is not: this page is for
// the machine where the bastion has no console, which is the Windows desktop.
//
// Every test below was MUTATION-CHECKED — the code or the template it covers was
// broken, the test confirmed red, and it was restored. The mutation is named in
// each comment.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func policyGet(t *testing.T, h http.Handler, path, cookie string) string {
	t.Helper()
	r := uiReq(http.MethodGet, path)
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
	}
	return w.Body.String()
}

// writeLedger puts a census on disk without running one, for the cases that are
// about a record made days ago.
func writeLedger(t *testing.T, cfg string, l policyLedger) {
	t.Helper()
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "policy-dryrun.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ── the headline ────────────────────────────────────────────────────────────

// The page's subject is what the rule would take away, so that is what it leads
// with. "N automated programs are running" is the agents page's question and is
// already answered one page over.
//
// MUTATION: render `{{.Observed}}` where the template says `{{.WouldStop}}`.
// RESULT: red — the page announced 3 of 3 on a machine where the rule proposed
// stopping one thing.
func TestThePolicyPageLeadsWithWhatWouldBeStopped(t *testing.T) {
	candidate := policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242)
	mine := policyCandidateObs("aider", "/usr/local/bin/aider", 4243)
	mine.Origin = originInteractive
	app := policyCandidateObs("claude-desktop", "/Applications/Claude.app/Contents/MacOS/claude", 51)
	app.Kind = kindApp
	policyTestBox(t, candidate, mine, app)

	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	body := policyGet(t, h, "/policy", cookie)
	if !strings.Contains(body, "1 of 3 would be stopped by this rule.") {
		t.Fatalf("the page does not lead with what would be stopped: %s", firstLines(body))
	}
	if !strings.Contains(body, "/usr/local/bin/claude") {
		t.Error("the page does not name the one it would stop")
	}

	// Vouch for it, and the headline has to move.
	if _, err := addSanction(candidate, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	body = policyGet(t, h, "/fragments/policy", cookie)
	if !strings.Contains(body, "Nothing running here would be stopped by this rule.") {
		t.Errorf("the headline did not move after a mark: %s", firstLines(body))
	}
}

// A verdict this machine could not reach is counted apart and said out loud. It
// is the state a person has to do something about, and folding it into "left
// alone" is how a blind spot becomes an all-clear.
//
// MUTATION: drop the `{{if .CannotJudge}}` block from policy.html.
// RESULT: red — a machine that could not read a single origin reported one
// number, and it was the reassuring one.
func TestWhatCannotBeJudgedIsCountedApart(t *testing.T) {
	blind := policyCandidateObs("goose", "/usr/local/bin/goose", 4244)
	blind.Origin = originUnknown
	policyTestBox(t, blind)

	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))
	if !strings.Contains(body, "1 of 1 cannot be judged at all.") {
		t.Fatalf("the page does not count what it could not judge: %s", firstLines(body))
	}
	if !strings.Contains(body, "cannot judge") {
		t.Error("the row does not carry the verdict in words")
	}
}

// ── the misleading directions this page must not take ───────────────────────

// A read that FAILED is not a machine with nothing on it (ui_approvals_flow_test.go:
// 113-151). Every verdict needs the registry, so a registry that will not load
// means no count on this page means anything.
//
// MUTATION: drop the `{{if not .RegistryError}}` guard around the count block.
// RESULT: red — "0 of 1 would be stopped by this rule" about a machine whose
// record of what is vouched for it had just failed to read.
func TestAnUnreadableRegistryIsAnAlarmAndNeverACountHere(t *testing.T) {
	cfg := policyTestBox(t, policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))
	// A census with something in it, so BOTH counts on this page are reachable
	// before the registry is broken — otherwise the second half of this test
	// would be asserting about a block that never renders.
	policyCensusTick()
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"),
		[]byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))
	if !strings.Contains(body, "cannot read its own record") {
		t.Fatalf("the page did not say the record is unreadable: %s", firstLines(body))
	}
	if strings.Contains(body, "would be stopped by this rule.") {
		t.Error("the page counted candidates on a machine whose record of marks it could not read")
	}
	// The census count comes out of the same record, so it cannot be printed
	// either. Found by review rather than by a test going red: "Vouched for
	// since: 0" is the same reassuring sentence in the second half of the page.
	//
	// MUTATION: render the ordinary census headline regardless of RegistryError.
	// RESULT: red — "Vouched for since: 0" about a machine that could not read
	// what had been vouched for.
	if strings.Contains(body, "Vouched for since:") {
		t.Error("the census counted mistakes out of a record it could not read")
	}
	if !strings.Contains(body, "How many were mistakes is not known.") {
		t.Errorf("the census does not say the count is out of reach: %s", firstLines(body))
	}
	if !strings.Contains(body, "/usr/local/bin/claude") {
		t.Error("the past candidates stopped being listed at all — they are still " +
			"what would have been stopped; it is what became of them that is unknown")
	}
	if !strings.Contains(body, "It is not reporting that there is nothing to judge.") {
		t.Error("the page does not distinguish 'I cannot judge' from 'there is nothing to judge'")
	}
	if !strings.Contains(body, "cannot judge") {
		t.Error("the row does not say its verdict is out of reach")
	}
}

// A build with no enumerator must say so rather than render an empty list.
// agentScanSupported is a compile-time constant (agents_other.go:13), so the
// branch is driven through the template directly — which is where the sentence
// either exists or does not.
//
// MUTATION: delete the `{{if .Blind}}` block from policy.html.
// RESULT: red — a machine that cannot list its own processes rendered as one
// with nothing to stop.
func TestABlindBuildNeverRendersAsAQuietMachineHere(t *testing.T) {
	policyTestBox(t)
	u := uiTestServer(t)
	w := httptest.NewRecorder()
	u.renderPolicy(w, "policy", uiPolicyView{Version: clientVersion, Blind: true})
	body := w.Body.String()
	if !strings.Contains(body, "cannot watch itself") {
		t.Fatalf("a build with no enumerator does not say so: %s", firstLines(body))
	}
	for _, banned := range []string{"would be stopped by this rule.",
		"Nothing automated is running on this machine."} {
		if strings.Contains(body, banned) {
			t.Errorf("a blind machine printed %q — README's whole quiet-versus-blind "+
				"distinction is that these are different states", banned)
		}
	}
}

// ── this page cannot stop anything ──────────────────────────────────────────

// The unit is the dry run (step 3 of the design) and acting (step 4) is a
// separate decision. A page with a Stop button on it would have made that
// decision on everybody's behalf.
//
// MUTATION: add a `<form hx-post="/policy/stop">…<button>Stop</button></form>`
// to the row block in policy.html.
// RESULT: red — three times: the form, the button and the post target.
func TestThePolicyPageOffersNoControlAtAll(t *testing.T) {
	policyTestBox(t, policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	body := policyGet(t, h, "/policy", cookie)

	for _, banned := range []string{"hx-post", "<form", "<button"} {
		if strings.Contains(body, banned) {
			t.Errorf("the page carries %q. This unit reports; whether it may ever act is "+
				"step 4, and a control here would settle that quietly.", banned)
		}
	}
	if !strings.Contains(body, "This page cannot stop anything.") {
		t.Error("the page does not say out loud that it stops nothing")
	}
	// And the unit answers nothing but reads: a POST to either route is refused
	// by the method check, so no mutating route can be reached by accident.
	for _, path := range []string{"/policy", "/fragments/policy"} {
		w := uiPost(t, h, path, url.Values{"id": {"anything"}}, cookie)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, w.Code)
		}
	}
}

// ── the metric: what would this have killed, and would that have been wrong ──

// The false-positive rate is what step 4 waits on, and a count is not enough:
// the candidates have to be nameable and reviewable. A program this rule
// proposed stopping which somebody has SINCE vouched for is one it would have
// taken away by mistake, and that is the number.
//
// MUTATION: drop the `marks[c.ID].ID != ""` arm from uiPolicyPastRow.
// RESULT: red — a program marked as the user's after the fact was filed under
// "not running right now", and the false-positive count stayed at zero.
func TestACandidateVouchedForAfterwardsIsCountedAsAFalsePositive(t *testing.T) {
	candidate := policyCandidateObs("aider", "/usr/local/bin/aider --watch", 4243)
	other := policyCandidateObs("goose", "/usr/local/bin/goose", 4244)
	policyTestBox(t, candidate, other)

	policyCensusTick() // both proposed

	// The person looks at the page, recognises one of them, and marks it.
	if _, err := addSanction(candidate, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	// …and it later exits, so the only thing left to check is the record.
	observedAgents = func() ([]agentObs, error) { return []agentObs{other}, nil }

	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))
	if !strings.Contains(body, "2 would have been stopped. Vouched for since: 1.") {
		t.Fatalf("the page does not count the false positive: %s", firstLines(body))
	}
	if !strings.Contains(body, "would have taken away") {
		t.Error("the page does not say what that number means")
	}
	for _, want := range []string{"aider", "/usr/local/bin/aider --watch", "vouched for since"} {
		if !strings.Contains(body, want) {
			t.Errorf("the false positive is not nameable on the page (missing %q)", want)
		}
	}
	if !strings.Contains(body, "still a candidate") {
		t.Error("the page does not say which of the past candidates is still one now")
	}

	v := collectPolicyView()
	if v.PastTotal != 2 || v.PastVouched != 1 || v.PastStill != 1 {
		t.Errorf("total %d, vouched %d, still %d — want 2 / 1 / 1",
			v.PastTotal, v.PastVouched, v.PastStill)
	}
}

// The same measurement for something that is still running when it gets
// vouched for: the row has to say which term changed its mind, or a person
// reviewing this cannot tell a false positive from an agent that simply stopped
// talking to a model.
//
// MUTATION: in uiPolicyPastRow, set Vouched=true for any leave-alone term
// rather than only the sanction one.
// RESULT: red — an agent that had merely gone quiet was counted as a program
// the rule would have killed by mistake.
func TestOnlyAVouchCountsAsAMistakeNotAChangeOfBehaviour(t *testing.T) {
	quiet := policyCandidateObs("goose", "/usr/local/bin/goose", 4244)
	policyTestBox(t, quiet)
	policyCensusTick()

	// It stops talking to a model. Still running, no longer a candidate — and
	// the rule was not wrong about it.
	quiet.LLMEndpoints = nil
	observedAgents = func() ([]agentObs, error) { return []agentObs{quiet}, nil }

	v := collectPolicyView()
	if v.PastTotal != 1 {
		t.Fatalf("the census holds %d entries, want 1", v.PastTotal)
	}
	if v.PastVouched != 0 {
		t.Errorf("vouched = %d, want 0 — nothing vouched for it; it went quiet", v.PastVouched)
	}
	if v.Past[0].Because == "" {
		t.Error("the row does not say why it is no longer a candidate")
	}
	if !strings.Contains(v.Past[0].Status, "no longer proposes it") {
		t.Errorf("status = %q", v.Past[0].Status)
	}
}

// ── the census can be quiet, absent, or dead, and those differ ──────────────

// A machine that has never taken this measurement must not render as one that
// took it and found nothing. That is this page's version of the quiet-versus-
// blind distinction.
//
// MUTATION: replace `{{if not .CensusRan}}` with `{{if false}}` in policy.html.
// RESULT: red — a machine that had never run the census printed "Nothing has
// been proposed for stopping in that time", about no time at all.
func TestACensusThatHasNeverRunIsNotAnAllClear(t *testing.T) {
	policyTestBox(t, policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	body := policyGet(t, h, "/policy", cookie)
	if !strings.Contains(body, "has not taken this measurement yet") {
		t.Fatalf("the page does not say the census has never run: %s", firstLines(body))
	}
	if strings.Contains(body, "Nothing has been proposed for stopping") {
		t.Error("a machine that never looked printed the sentence for a machine that did")
	}

	// One tick, and the page is entitled to the other sentence.
	policyCensusTick()
	body = policyGet(t, h, "/fragments/policy", cookie)
	if strings.Contains(body, "has not taken this measurement yet") {
		t.Error("the page still says the census has never run after a scan")
	}
	if !strings.Contains(body, "Measured since") {
		t.Errorf("the page does not say since when: %s", firstLines(body))
	}
}

// A census that stopped keeps answering with its last result, and that answer
// reads as an all-clear for ever. agents.go:594-598 records the same trap and
// the same fix for the second-bastion scan.
//
// MUTATION: delete the CensusStale assignment in collectPolicyView.
// RESULT: red — a record last written days ago rendered as current.
//
// The second half is the check that would have proved the first one wrong, and
// it is the one that found a real defect. The census writes its clock only every
// policyLedgerFlush, so on a healthy machine last_scan is routinely a flush
// interval old; a threshold counted in SCANS rather than flushes puts "this
// measurement has stopped" on a machine that is measuring it correctly. That was
// the first version of uiPolicyStaleAfter. Nothing went red — the alarm test
// passed either way — and writing the half that would fail is what caught it.
//
// MUTATION: set uiPolicyStaleAfter back to 3 * policyCensusEvery.
// RESULT: red — a census flushed five minutes ago reported itself dead.
func TestACensusThatStoppedSaysSo(t *testing.T) {
	cfg := policyTestBox(t)
	old := time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	writeLedger(t, cfg, policyLedger{Since: old.Add(-48 * time.Hour), LastScan: old,
		Candidates: map[string]policyCandidate{}})
	t.Cleanup(func() { setUINow(nil) })

	// The session is minted under the SAME pinned clock it is spent under —
	// uiNow is the token store's clock too (uiauth.go:77, 174), so a cookie
	// minted at today's time and read three days later is expired, and the page
	// would answer 401 for a reason that has nothing to do with this test.
	at := func(when time.Time) string {
		setUINow(func() time.Time { return when })
		u := uiTestServer(t)
		return policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))
	}

	// Healthy: one flush interval since the clock was written, which is the
	// ordinary state of a machine doing this properly.
	if body := at(old.Add(policyLedgerFlush)); strings.Contains(body, "This measurement has stopped.") {
		t.Fatalf("a census flushed %s ago reported itself stopped — the threshold has to be "+
			"counted in flushes, not scans", policyLedgerFlush)
	}

	// Dead: three days.
	body := at(old.Add(72 * time.Hour))
	if !strings.Contains(body, "This measurement has stopped.") {
		t.Fatalf("a census last written three days ago rendered as current: %s", firstLines(body))
	}
	if !strings.Contains(body, "Last looked") {
		t.Error("the page does not say when it last looked")
	}
}

// A census file that will not parse is not a machine that has never measured
// anything. These were one branch of the template until this file was reviewed:
// an unparseable record rendered "This machine has not taken this measurement
// yet", which is the most reassuring sentence on the page about the one state
// that needs a person. ui_approvals_flow_test.go:113-151 is the same lesson on /given.
//
// MUTATION: replace `{{if .CensusUnreadable}}` with `{{if false}}` in policy.html.
// RESULT: red — the unreadable record rendered as a machine that never looked.
func TestAnUnreadableCensusIsNotReportedAsNeverMeasured(t *testing.T) {
	cfg := policyTestBox(t)
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "policy-dryrun.json"),
		[]byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))
	if strings.Contains(body, "has not taken this measurement yet") {
		t.Fatalf("a record this machine could not read rendered as one it never wrote: %s",
			firstLines(body))
	}
	if !strings.Contains(body, "could not read that record") {
		t.Errorf("the page does not say the record is unreadable: %s", firstLines(body))
	}
	if !strings.Contains(body, "not being written") {
		t.Error("the page does not raise it as an alarm at the top")
	}
}

// ── the rule has to be readable by whoever reviews it ───────────────────────

// A person asked "would this have been wrong?" cannot answer it against a rule
// they would have to read the source to find. So the page states the rule — and
// the rule it states has to be the one the evaluator runs, term for term.
//
// The terms are taken from a REAL VERDICT rather than from a list in this file,
// so the check cannot drift in either direction: a term the evaluator uses and
// the page never mentions is red, and so is a term deleted from the page.
//
// MUTATION: remove the origin line from policyRuleLines.
// RESULT: red — "the page does not describe the origin term, which the rule just
// used". The first version of this test looped over policyRuleLines() itself, so
// deleting a line deleted its own assertion and the mutation ran green — the
// shape ui_approvals_flow_test.go:9-15 names: a test whose fixture supplies the thing
// under test can only ever pass.
func TestThePageShowsTheRuleItActuallyRuns(t *testing.T) {
	policyTestBox(t)
	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))

	shown := map[string]string{}
	for _, line := range policyRuleLines() {
		shown[line.Term] = line.Detail
	}
	// A verdict that ran every term there is.
	used := policyEvaluate(policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242))
	if len(used.Reasons) == 0 {
		t.Fatal("fixture is broken: the verdict used no terms")
	}
	for _, r := range used.Reasons {
		detail, ok := shown[r.Term]
		if !ok {
			t.Errorf("the page does not describe the %s term, which the rule just used", r.Term)
			continue
		}
		if !strings.Contains(body, detail) {
			t.Errorf("the page does not state the %s term: %q", r.Term, detail)
		}
	}
	if len(shown) != len(used.Reasons) {
		t.Errorf("the page describes %d terms and the rule runs %d", len(shown), len(used.Reasons))
	}
}

// ── the page's front door ───────────────────────────────────────────────────

// The four headers renderWith sets (ui.go:437-442) are duplicated in
// renderPolicy because renderWith is typed to uiStatus. uisanction.go:251-255
// makes the same duplication safe with this comparison; so does this.
//
// MUTATION: drop the Content-Security-Policy line from renderPolicy.
// RESULT: red — the policy page was served without a CSP, and its own stylesheet
// rules about inline styles stopped being enforced by anything.
func TestThePolicyPageCarriesTheSameHeadersAsTheStatusPage(t *testing.T) {
	policyTestBox(t)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	get := func(path string) *httptest.ResponseRecorder {
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	status, policy := get("/fragments/status"), get("/policy")
	for _, k := range []string{"Content-Type", "Cache-Control",
		"Content-Security-Policy", "X-Content-Type-Options"} {
		if got, want := policy.Header().Get(k), status.Header().Get(k); got != want {
			t.Errorf("%s: policy page %q, status page %q", k, got, want)
		}
	}
}

// The page has to be reachable from the one page a person actually opens.
// page.html's own comment records that three units added a link each and none
// knew about the others; this is the fourth.
//
// MUTATION: remove the /policy link from page.html.
// RESULT: red — the page existed and nothing led to it.
func TestThePolicyPageIsLinkedFromTheMainPage(t *testing.T) {
	policyTestBox(t)
	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/", uiSignedIn(t, u))
	if !strings.Contains(body, `href="/policy"`) {
		t.Fatal("nothing on the main page leads to the policy page")
	}
}

// The stylesheet is served from the binary like every other asset, and the page
// is unreadable without it. The asset route is an allow-list (ui.go serveAsset),
// so a new sheet that is not added to it 404s in a way nothing else notices.
//
// MUTATION: remove "policy.css" from the serveAsset switch.
// RESULT: red — the page rendered and every card lost its shape.
func TestThePolicyStylesheetIsServedFromTheBinary(t *testing.T) {
	policyTestBox(t)
	h := uiTestServer(t).handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, uiReq(http.MethodGet, "/assets/policy.css"))
	if w.Code != http.StatusOK {
		t.Fatalf("/assets/policy.css = %d — the page links it and would render unstyled", w.Code)
	}
	if !strings.Contains(w.Body.String(), ".terms") {
		t.Error("the stylesheet does not look like itself — the embed may be empty")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("the stylesheet is served without nosniff")
	}
}
