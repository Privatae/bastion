package main

// The page where a person says which automated programs are theirs
// (uisanction.go), driven end to end through the real mux.
//
// NOT tagged !windows, for the same reason ui_test.go is not: this page is for
// the machine where the bastion has no console, which is the Windows desktop.
//
// Every test below was MUTATION-CHECKED — the code it covers was broken, the
// test confirmed red, and the code was restored. The mutation is named in each
// comment.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// agentsTestBox isolates the config dir and stubs the observe plane.
//
// observedAgents is the var contain.go:34 declares so a decision can be tested
// without a live process tree underneath it; the same seam every other test in
// this package uses (agents_kind_test.go:318, events_test.go:39).
func agentsTestBox(t *testing.T, seen ...agentObs) {
	t.Helper()
	uiTestConfigDir(t)
	prev := observedAgents
	t.Cleanup(func() { observedAgents = prev })
	observedAgents = func() ([]agentObs, error) { return seen, nil }
}

func agentsGet(t *testing.T, h http.Handler, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	r := uiReq(http.MethodGet, path)
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
	}
	return w
}

// anObservedAgent is an HONEST observation, exactly as obs() (sanction_test.go)
// is: the kernel's path and the path its own argv[0] claims agree. Anything
// that can be marked as yours must have one, so a fixture without it would only
// ever exercise the refusal.
func anObservedAgent(sig, cmd string, pid int) agentObs {
	return agentObs{PID: pid, Kind: kindAgent, Signature: sig, Cmdline: cmd,
		User: "user", Origin: originInteractive, Exe: argv0(cmd),
		Evidence: []evidence{{Signal: "agent-signature", Tier: tierKnown, Value: sig}}}
}

// ── the headline the whole product claim rests on ───────────────────────────

// "Separate the good guys from the bad by identifying the good." The page has
// to make the set nobody has vouched for countable, above everything else.
//
// MUTATION: render `{{.Observed}}` where the template says `{{.Unsanctioned}}`.
// RESULT: red — the page announced 3 of 3 after one had been marked.
func TestThePageLeadsWithHowManyAreNotMarkedAsYours(t *testing.T) {
	mine := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	agentsTestBox(t, mine,
		anObservedAgent("aider", "/usr/local/bin/aider", 4243),
		anObservedAgent("goose", "/usr/local/bin/goose", 4244))
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	body := agentsGet(t, h, "/agents", cookie).Body.String()
	if !strings.Contains(body, "3 of 3 are not marked as yours") {
		t.Fatalf("the page does not lead with the unsanctioned count: %s", firstLines(body))
	}

	if _, err := addSanction(mine, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	body = agentsGet(t, h, "/fragments/agents", cookie).Body.String()
	if !strings.Contains(body, "2 of 3 are not marked as yours") {
		t.Errorf("the count did not move after a mark: %s", firstLines(body))
	}
}

// A sanctioned entry must still be LISTED. A control that makes things
// disappear is a control an attacker wants the user to use.
//
// MUTATION: `continue` past sanctioned observations in collectAgentsView.
// RESULT: red — the marked agent vanished from the page.
func TestAMarkedProgramIsStillListed(t *testing.T) {
	mine := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	agentsTestBox(t, mine)
	if _, err := addSanction(mine, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	u := uiTestServer(t)
	body := agentsGet(t, u.handler(), "/agents", uiSignedIn(t, u)).Body.String()

	for _, want := range []string{"claude-code", "/usr/local/bin/claude", ">yours<",
		"All 1 are accounted for"} {
		if !strings.Contains(body, want) {
			t.Errorf("a marked program is not on the page (missing %q)", want)
		}
	}
	if !strings.Contains(body, sanctionWhyLocal) {
		t.Error("the page does not say WHY it counts as marked")
	}
}

// ── marking and unmarking ───────────────────────────────────────────────────

// MUTATION: make agentsMark return before addSanction.
// RESULT: red — the click recorded nothing.
func TestMarkingAndUnmarkingThroughThePage(t *testing.T) {
	mine := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	agentsTestBox(t, mine)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	id := sanctionIdentityOf(mine).fingerprint()

	w := uiPost(t, h, "/agents/mark", url.Values{"id": {id}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("mark = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Marked as yours") {
		t.Errorf("the page did not confirm the mark: %s", firstLines(w.Body.String()))
	}
	if sanctioned, why := agentSanction(mine); !sanctioned || why != sanctionWhyLocal {
		t.Fatalf("after the click the predicate says %v / %q", sanctioned, why)
	}
	// The fragment that came back is the CURRENT state, not the one rendered
	// before the click — the rule renderWith states at ui.go:424-427.
	if !strings.Contains(w.Body.String(), ">yours<") {
		t.Error("the fragment returned by the click still shows the old state")
	}

	w = uiPost(t, h, "/agents/unmark", url.Values{"id": {id}}, cookie)
	if !strings.Contains(w.Body.String(), "Unmarked") {
		t.Errorf("the page did not confirm the withdrawal: %s", firstLines(w.Body.String()))
	}
	if sanctioned, _ := agentSanction(mine); sanctioned {
		t.Fatal("the mark survived being withdrawn")
	}
}

// A person can only vouch for something this machine can SEE. The posted id is
// looked up among what is running rather than trusted, so a mark can never be
// pre-planted for an identity that has not run yet — the same care
// approvalTarget (ui.go:442-448) takes with a posted host name.
//
// MUTATION: in agentsMark, build the record from the posted id instead of
// scanning (add a sanction for a synthesised identity).
// RESULT: red — a mark was written for something that was never observed.
func TestSomethingThisMachineCannotSeeCannotBeMarked(t *testing.T) {
	agentsTestBox(t, anObservedAgent("claude-code", "/usr/local/bin/claude", 4242))
	u := uiTestServer(t)
	cookie := uiSignedIn(t, u)

	ghost := sanctionIdentityOf(obs("not-running", "/tmp/evil", "user")).fingerprint()
	w := uiPost(t, u.handler(), "/agents/mark", url.Values{"id": {ghost}}, cookie)
	if !strings.Contains(w.Body.String(), "not running on this machine") {
		t.Errorf("marking an unobserved identity was not refused: %s", firstLines(w.Body.String()))
	}
	recs, err := sanctionRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("a mark was written for something the machine never observed: %+v", recs)
	}

	// A form that named NOTHING is a different fact from one that named
	// something since exited, and saying the second about the first is a lie
	// about the machine. Added after a mutation run showed this branch had no
	// test on it at all.
	w = uiPost(t, u.handler(), "/agents/mark", url.Values{}, cookie)
	if !strings.Contains(w.Body.String(), "carried no program") {
		t.Errorf("a form naming nothing was reported as a program that had exited: %s",
			firstLines(w.Body.String()))
	}
}

// ── this page cannot stop anything ──────────────────────────────────────────

// Containment is host-directed (run.go:575) and whether the local UI may act is
// an open product decision. Marking something as yours is not the same act as
// terminating it, and this page must not be able to reach the one side effect
// in contain.go.
//
// MUTATION: call killProcess(a.PID) inside agentsMark.
// RESULT: red — "this page terminated pid 4242".
func TestNothingOnThisPageCanTerminateAnything(t *testing.T) {
	mine := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	agentsTestBox(t, mine)
	prevKill := killProcess
	t.Cleanup(func() { killProcess = prevKill })
	var killed []int
	killProcess = func(pid int) error { killed = append(killed, pid); return nil }

	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	id := sanctionIdentityOf(mine).fingerprint()

	body := agentsGet(t, h, "/agents", cookie).Body.String()
	uiPost(t, h, "/agents/mark", url.Values{"id": {id}}, cookie)
	uiPost(t, h, "/agents/unmark", url.Values{"id": {id}}, cookie)
	if len(killed) != 0 {
		t.Fatalf("this page terminated %v — containment is host-directed and marking "+
			"something as yours is a different act from taking it away", killed)
	}

	// And it offers no control that could grow into one: the only things the
	// page posts to are the two routes this unit owns.
	for _, frag := range strings.Split(body, `hx-post="`)[1:] {
		target := frag[:strings.IndexByte(frag, '"')]
		if target != "/agents/mark" && target != "/agents/unmark" {
			t.Errorf("the page posts to %q — this unit owns marking, nothing else", target)
		}
	}
	if !strings.Contains(body, "This page does not stop anything") {
		t.Error("the page does not say out loud that it stops nothing")
	}
}

// ── the misleading directions this page must not take ───────────────────────

// A read that FAILED is not a machine with nothing on it — ui_approvals_flow_test.go:
// 113-151, the same lesson that bit /given. A registry this machine cannot read
// must not produce a reassuring count, and must not draw a tick.
//
// MUTATION: drop the `{{if not .ReadError}}` guard around the count block.
// RESULT: red — the page printed "0 of 1 are not marked as yours" about a
// machine whose record of marks it had just failed to read.
func TestAnUnreadableRegistryIsAnAlarmAndNeverACount(t *testing.T) {
	agentsTestBox(t, anObservedAgent("claude-code", "/usr/local/bin/claude", 4242))
	d, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "sanctions.json"),
		[]byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	u := uiTestServer(t)
	body := agentsGet(t, u.handler(), "/agents", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(body, "cannot read its own record") {
		t.Errorf("the page did not say the registry is unreadable: %s", firstLines(body))
	}
	if strings.Contains(body, "are not marked as yours") ||
		strings.Contains(body, "are accounted for") {
		t.Error("the page counted marks on a machine whose record of them it could not read")
	}
	if strings.Contains(body, ">yours<") {
		t.Error("the page drew a tick for a verdict it could not reach")
	}
	if !strings.Contains(body, ">unknown<") {
		t.Error("the row does not say its verdict is unknown")
	}
}

// A build with no enumerator must say so rather than render an empty list.
// agentScanSupported is a compile-time constant (agents_other.go:13), so the
// branch is driven through the template directly — which is where the sentence
// either exists or does not.
//
// MUTATION: delete the `{{if .Blind}}` block from agents.html.
// RESULT: red — a blind machine rendered as a clean one.
func TestABlindBuildNeverRendersAsAQuietMachine(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	rec := httptest.NewRecorder()
	u.renderAgents(rec, "agents", uiAgentsView{Version: clientVersion, Blind: true})
	body := rec.Body.String()
	if !strings.Contains(body, "cannot watch itself") {
		t.Fatalf("a build with no enumerator does not say so: %s", firstLines(body))
	}
	if strings.Contains(body, "Nothing automated is running on this machine") {
		t.Error("a blind machine printed the reassuring sentence — README's whole " +
			"quiet-versus-blind distinction is that these are different states")
	}
}

// A mark whose program is not running right now has to be listed, with the only
// button that removes it. Without it, a record for something long uninstalled
// vouches for an identity nobody can see and nobody can withdraw.
//
// MUTATION: skip the dormant loop in collectAgentsView.
// RESULT: red — the mark was invisible and unreachable.
func TestAMarkWithNothingRunningBehindItIsListedWithAWayToRemoveIt(t *testing.T) {
	gone := anObservedAgent("aider", "/usr/local/bin/aider", 4243)
	agentsTestBox(t, gone)
	if _, err := addSanction(gone, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	// It stops running.
	observedAgents = func() ([]agentObs, error) { return nil, nil }

	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	body := agentsGet(t, h, "/agents", cookie).Body.String()

	if !strings.Contains(body, "Marked as yours, but not running right now") {
		t.Fatalf("a dormant mark is not on the page: %s", firstLines(body))
	}
	if !strings.Contains(body, "aider") {
		t.Error("the dormant entry does not name what was marked")
	}
	id := sanctionIdentityOf(gone).fingerprint()
	if !strings.Contains(body, `value="`+id+`"`) {
		t.Error("the dormant entry carries no id, so it cannot be withdrawn")
	}
	// And the button works with nothing observed at all.
	uiPost(t, h, "/agents/unmark", url.Values{"id": {id}}, cookie)
	recs, err := sanctionRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("a dormant mark could not be withdrawn: %+v", recs)
	}
}

// ── the exe identity, on the page ───────────────────────────────────────────

// The page shows the FILE a mark would be recorded against, next to the command
// line and never instead of it. A person being asked to vouch for a program is
// entitled to see the thing that is actually being recorded — and the two
// differing is precisely the case worth noticing.
//
// MUTATION: delete the `{{if .Exe}}<dt>File</dt>...` row from agents.html.
// RESULT: red — the page asked the user to vouch while showing only the name
// the program chose for itself.
func TestThePageShowsTheFileAMarkIsRecordedAgainst(t *testing.T) {
	forger := anObservedAgent("claude-code", "/usr/local/bin/claude --resume abc", 4242)
	forger.Exe = "/tmp/.hidden/x" // what the kernel says, and not what it claims
	agentsTestBox(t, forger)

	u := uiTestServer(t)
	body := agentsGet(t, u.handler(), "/agents", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(body, "/tmp/.hidden/x") {
		t.Errorf("the page does not show the file the kernel reports: %s", firstLines(body))
	}
	if !strings.Contains(body, "/usr/local/bin/claude --resume abc") {
		t.Error("the page dropped the command line — both facts are shown, not one")
	}
}

// An observation this machine could not identify gets NO mark button, because
// there is nothing to record: addSanction would refuse it (sanction.go). A
// control that can only fail is worse than no control — it tells the user the
// machine is withholding something it could do.
//
// MUTATION: render the mark form on `{{else}}` again, ignoring `.ID`.
// RESULT: red — the page offered "This one is mine" on a row whose click could
// only come back as an error.
func TestAProgramThisMachineCannotIdentifyCannotBeMarkedFromThePage(t *testing.T) {
	blind := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	blind.Exe = "" // another user's process, a refused handle, a build with none
	agentsTestBox(t, blind)

	u := uiTestServer(t)
	body := agentsGet(t, u.handler(), "/agents", uiSignedIn(t, u)).Body.String()

	if strings.Contains(body, "This one is mine") {
		t.Errorf("the page offered a mark it would have refused: %s", firstLines(body))
	}
	if !strings.Contains(body, "could not read which file") {
		t.Error("the page does not say why the program cannot be marked")
	}
	// It is still LISTED and still counted as not vouched for: unmarkable is not
	// invisible, and the whole page is built around the set nobody has vouched
	// for.
	if !strings.Contains(body, "1 of 1 are not marked as yours") {
		t.Error("an unidentifiable program dropped out of the count")
	}
	if !strings.Contains(body, "claude-code") {
		t.Error("an unidentifiable program dropped off the page entirely")
	}
}

// A mark written before the identity moved to the kernel's path vouches for
// nothing — and the page says so, in its own section, with the button that
// removes it. Silently dropping the user's record of their own decision is the
// alternative, and a security page that changes what your marks mean without
// telling you is the shape of thing this file exists to prevent.
//
// MUTATION: put the stale check AFTER the `seen[r.ID]` filter in
// collectAgentsView.
// RESULT: red — the second record below vanished from the page altogether.
//
// The first version of this test used only the v1 record and the mutation came
// back GREEN, which meant it was testing nothing: a v1 key is never in `seen`
// (no live observation can produce it), so the record reached the expired list
// either way. The rewrite adds the record that makes the ordering load-bearing
// — one whose key DOES match a live observation while carrying no path, which a
// hand-edited or truncated registry produces — and with the filters in the
// wrong order the user is never told their mark stopped counting at all.
// Silence is the worst of the three outcomes here, which is why this is the
// case worth pinning.
func TestAnExpiredMarkSaysItNoLongerCountsAndCanBeRemoved(t *testing.T) {
	live := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	agentsTestBox(t, live)
	d, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	// Written as bytes, exactly as a v1 machine or a damaged file would hold
	// them. Both programs are RUNNING, which is the case that separates
	// "expired" from "dormant".
	v1ID := v1Fingerprint(kindAgent, "claude-code", "/usr/local/bin/claude", "user")
	collidedID := sanctionIdentityOf(live).fingerprint()
	registry := `{
	  "` + v1ID + `": {
	    "id": "` + v1ID + `", "kind": "agent",
	    "signature": "claude-code", "argv0": "/usr/local/bin/claude",
	    "user": "user", "at": "2026-09-01T10:00:00Z", "by": "local-ui"},
	  "` + collidedID + `": {
	    "id": "` + collidedID + `", "kind": "agent",
	    "signature": "aider", "exe": "",
	    "user": "user", "at": "2026-09-02T10:00:00Z", "by": "local-ui"}}`
	if err := os.WriteFile(filepath.Join(d, "sanctions.json"), []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}

	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	body := agentsGet(t, h, "/agents", cookie).Body.String()

	if !strings.Contains(body, "Marks that no longer count") {
		t.Fatalf("an expired mark is not on the page: %s", firstLines(body))
	}
	if !strings.Contains(body, "no longer counts") {
		t.Error("the expired entry does not say that it has stopped vouching")
	}
	if !strings.Contains(body, "recorded against the name a program gave for itself") {
		t.Error("the page does not say WHY the old mark stopped counting")
	}
	if strings.Contains(body, "Marked as yours, but not running right now") {
		t.Error("an expired mark was filed under the dormant heading, which claims " +
			"it still vouches for something")
	}
	// The record whose key matches something running: it has no path, so it
	// vouches for nothing, and it must still be SHOWN. A mark that stops
	// counting and says nothing is the failure this section exists to prevent.
	if !strings.Contains(body, "aider") {
		t.Errorf("an expired mark under a live program's key was dropped from the "+
			"page entirely — the user is never told it stopped counting: %s", firstLines(body))
	}
	// The live program it was written for is still unvouched-for...
	if !strings.Contains(body, "1 of 1 are not marked as yours") {
		t.Errorf("an argv[0] mark still vouched for the running program: %s", firstLines(body))
	}
	// ...and each old record can be removed by the only button on it.
	for _, id := range []string{v1ID, collidedID} {
		if !strings.Contains(body, `value="`+id+`"`) {
			t.Errorf("the expired entry %s carries no id, so it cannot be removed", id)
		}
		uiPost(t, h, "/agents/unmark", url.Values{"id": {id}}, cookie)
	}
	recs, err := sanctionRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("an expired mark could not be removed: %+v", recs)
	}
}

// The delegation tag is a shared secret, soft key or not. agents.go:270-272
// reports only "present" to the host and this page must not do more.
//
// MUTATION: add `{{.Cmdline}}`-style rendering of the token to the row.
// RESULT: red — the tag value appeared in the page body.
func TestTheDelegationTagValueNeverReachesThePage(t *testing.T) {
	const secret = "del_ThisIsTheHostsSecretTag"
	tagged := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	tagged.DelegationToken = secret
	tagged.Evidence = append(tagged.Evidence,
		evidence{Signal: "delegation-tag", Tier: tierKnown, Value: "present"})
	agentsTestBox(t, tagged)

	u := uiTestServer(t)
	body := agentsGet(t, u.handler(), "/agents", uiSignedIn(t, u)).Body.String()
	if strings.Contains(body, secret) {
		t.Fatal("the delegation tag's VALUE was rendered — the host is only ever told " +
			"that one is present (agents.go:270-272)")
	}
	if !strings.Contains(body, "delegation-tag") {
		t.Error("the page does not say the process carries a host tag at all")
	}
	if !strings.Contains(body, sanctionWhyHostTag) {
		t.Error("the page does not say the host is what vouched for this one")
	}
}

// The four headers renderWith sets (ui.go:429-434) are duplicated in
// renderAgents because renderWith is typed to uiStatus. uigiven.go:513-518 makes
// the same duplication safe with this comparison; so does this.
//
// MUTATION: drop the Content-Security-Policy line from renderAgents.
// RESULT: red — the agents page was served without a CSP.
func TestTheAgentsPageCarriesTheSameHeadersAsTheStatusPage(t *testing.T) {
	agentsTestBox(t)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	status := agentsGet(t, h, "/fragments/status", cookie)
	agents := agentsGet(t, h, "/agents", cookie)
	for _, k := range []string{"Content-Type", "Cache-Control",
		"Content-Security-Policy", "X-Content-Type-Options"} {
		if got, want := agents.Header().Get(k), status.Header().Get(k); got != want {
			t.Errorf("%s: agents page %q, status page %q", k, got, want)
		}
	}
}

// The mutating routes are POST. A GET that changed state would be reachable from
// any page with an <img src>, which is the defect signOut carried (ui.go:557-563).
//
// MUTATION: drop the method check from agentsMark.
// RESULT: red — a GET recorded a mark.
func TestTheMarkingRoutesArePostOnly(t *testing.T) {
	mine := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	agentsTestBox(t, mine)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	id := sanctionIdentityOf(mine).fingerprint()

	for _, path := range []string{"/agents/mark?id=" + id, "/agents/unmark?id=" + id} {
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", path, w.Code)
		}
	}
	if sanctioned, _ := agentSanction(mine); sanctioned {
		t.Fatal("a GET recorded a mark")
	}

	// And a cross-site POST is refused by the Origin check, like every other
	// state change on this server.
	r := httptest.NewRequest(http.MethodPost, "/agents/mark",
		strings.NewReader("id="+id))
	r.Host = "127.0.0.1:" + uiTestPort
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST /agents/mark = %d, want 403", w.Code)
	}
	if sanctioned, _ := agentSanction(mine); sanctioned {
		t.Fatal("a cross-site POST recorded a mark")
	}
}

// The page has to be reachable from the one page a person actually opens.
// page.html's own comment records that two units added a link each and neither
// knew about the other; this is the third.
//
// MUTATION: remove the /agents link from page.html.
// RESULT: red — the page existed and nothing led to it.
func TestTheAgentsPageIsLinkedFromTheMainPage(t *testing.T) {
	agentsTestBox(t)
	u := uiTestServer(t)
	body := agentsGet(t, u.handler(), "/", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(body, `href="/agents"`) {
		t.Fatal("nothing on the main page leads to the agents page")
	}
}

func firstLines(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
