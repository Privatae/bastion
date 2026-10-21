package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE PAGES, RENDERED. walkfail_test.go proves the view models carry the
// failure; these prove the templates do not draw the tick under the banner.
// Both summaries were gated on Blind and the registry error only, so a walk
// failure with a working enumerator rendered the red banner AND "This machine
// looked; it did not find anything" beneath it.

func walkFailedBox(t *testing.T) {
	t.Helper()
	uiTestConfigDir(t)
	prev := observedAgents
	t.Cleanup(func() { observedAgents = prev })
	observedAgents = func() ([]agentObs, error) { return nil, errors.New("read /proc: permission denied") }
}

func TestTheAgentsPageDoesNotSayItLookedWhenTheWalkFailed(t *testing.T) {
	walkFailedBox(t)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	for _, path := range []string{"/agents", "/fragments/agents"} {
		w := httptest.NewRecorder()
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", cookie)
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d — both routes exist (uisanction.go) and a renamed one must fail here, not pass silently", path, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "could not read its processes") || !strings.Contains(body, "permission denied") {
			t.Fatalf("%s: the failed walk is not bannered: %s", path, firstLines(body))
		}
		if strings.Contains(body, "This machine looked") || strings.Contains(body, "Nothing automated is running") {
			t.Fatalf("%s: the page drew the tick under the walk banner: %s", path, firstLines(body))
		}
	}
}

func TestThePolicyPageDoesNotSayItLookedWhenTheWalkFailed(t *testing.T) {
	walkFailedBox(t)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	body := policyGet(t, h, "/policy", cookie)
	if !strings.Contains(body, "could not read its processes") {
		t.Fatalf("the failed walk is not bannered: %s", firstLines(body))
	}
	for _, tick := range []string{"Nothing automated is running", "would be stopped by this rule", "Nothing running here would be stopped"} {
		if strings.Contains(body, tick) {
			t.Fatalf("the policy page drew the tick %q under the walk banner: %s", tick, firstLines(body))
		}
	}
}

func TestMarkingDuringAFailedWalkNamesTheWalk(t *testing.T) {
	walkFailedBox(t)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	r := httptest.NewRequest(http.MethodPost, "/agents/mark", strings.NewReader("id=deadbeef"))
	r.Host = "127.0.0.1:" + uiTestPort
	r.Header.Set("Origin", "http://127.0.0.1:"+uiTestPort)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code == http.StatusSeeOther || w.Code == http.StatusFound {
		// The flash rides the redirected page.
		body = agentsGet(t, h, w.Header().Get("Location"), cookie).Body.String()
	}
	if !strings.Contains(body, "could not read its processes") {
		t.Fatalf("the mark did not name the failed walk (status %d): %s", w.Code, firstLines(body))
	}
	if strings.Contains(body, "not running on this machine any more") {
		t.Fatalf("the mark blamed the wrong cause: %s", firstLines(body))
	}
}

// THE ROWS THAT NAME A PROGRAM. The summary tick was gated in round two; these
// two lists said "not running right now" about a NAMED program on a render
// where nothing looked — one row below the banner. Both take the same shape
// their unreadable-registry guard already has.

func TestThePolicyPastRowsCannotSayNotRunningWhenTheWalkFailed(t *testing.T) {
	cfg := policyTestBox(t)
	obs := policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242)
	id := sanctionIdentityOf(obs)
	now := time.Now()
	writeLedger(t, cfg, policyLedger{Since: now.Add(-time.Hour), LastScan: now,
		Candidates: map[string]policyCandidate{id.fingerprint(): {
			ID: id.fingerprint(), sanctionIdentity: id, FirstSeen: now.Add(-time.Hour), LastSeen: now}}})
	observedAgents = func() ([]agentObs, error) { return nil, errors.New("read /proc: permission denied") }
	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))
	if strings.Contains(body, policyPastNotSeen) {
		t.Fatalf("a failed walk called a candidate %q: %s", policyPastNotSeen, firstLines(body))
	}
	if !strings.Contains(body, policyPastUnwalked) {
		t.Fatalf("the past row does not say the walk failed: %s", firstLines(body))
	}
	if strings.Contains(body, "Still a candidate right now: 0") {
		t.Fatalf("a failed walk counted zero candidates still running: %s", firstLines(body))
	}
}

func TestTheAgentsPageDoesNotListMarksAsNotRunningWhenTheWalkFailed(t *testing.T) {
	mine := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	agentsTestBox(t, mine)
	if _, err := addSanction(mine, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	observedAgents = func() ([]agentObs, error) { return nil, errors.New("read /proc: permission denied") }
	u := uiTestServer(t)
	h := u.handler()
	body := agentsGet(t, h, "/agents", uiSignedIn(t, u)).Body.String()
	if strings.Contains(body, "Marked as yours, but not running right now") || strings.Contains(body, "/usr/local/bin/claude") {
		t.Fatalf("a failed walk listed a marked program as not running: %s", firstLines(body))
	}
	if !strings.Contains(body, "could not read its processes") {
		t.Fatalf("the banner is missing: %s", firstLines(body))
	}
}

// THE CENSUS BLOCK, one line above the rows. "Vouched for since" is read from
// the registry and stays real on a failed walk; "still a candidate right now"
// is read from the walk and is not known. The first version of the row switch
// let the walk take the vouch with it — the count the whole page waits on
// went to 0 and the box turned green.
func TestTheCensusBlockKeepsTheVouchAndWithholdsStillOnAFailedWalk(t *testing.T) {
	cfg := policyTestBox(t)
	obs := policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242)
	id := sanctionIdentityOf(obs)
	now := time.Now()
	// Two candidates: one the user vouched for, one nobody did — the second is
	// the row that must wear no "nothing behind it" edge on a failed walk.
	other := policyCandidateObs("aider", "/usr/local/bin/aider", 4243)
	oid := sanctionIdentityOf(other)
	writeLedger(t, cfg, policyLedger{Since: now.Add(-time.Hour), LastScan: now,
		Candidates: map[string]policyCandidate{
			id.fingerprint():  {ID: id.fingerprint(), sanctionIdentity: id, FirstSeen: now.Add(-time.Hour), LastSeen: now},
			oid.fingerprint(): {ID: oid.fingerprint(), sanctionIdentity: oid, FirstSeen: now.Add(-time.Hour), LastSeen: now},
		}})
	if _, err := addSanction(obs, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	observedAgents = func() ([]agentObs, error) { return nil, errors.New("read /proc: permission denied") }
	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))
	if !strings.Contains(body, "Vouched for since: 1") {
		t.Fatalf("a failed walk zeroed the vouched count: %s", firstLines(body))
	}
	if strings.Contains(body, "Still a candidate right now: 0") {
		t.Fatalf("a failed walk counted zero candidates still running: %s", firstLines(body))
	}
	if !strings.Contains(body, "Still a candidate right now: not known") {
		t.Fatalf("the census block does not say the count is unknown: %s", firstLines(body))
	}
	if !strings.Contains(body, `class="state warn"`) || strings.Contains(body, `class="state ok"`) {
		t.Fatalf("a vouched candidate on a failed walk must keep the box amber, never green: %s", firstLines(body))
	}
	if strings.Contains(body, `past dormant`) {
		t.Fatalf("a row nothing looked for wore the 'nothing behind it' edge: %s", firstLines(body))
	}
}

// A mark that no longer counts is a fact about the record, not the walk: it is
// still said on a failed walk. Only the dormant half (which needs `seen`) is
// withheld.
func TestAnExpiredMarkIsStillSaidOnAFailedWalk(t *testing.T) {
	live := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	agentsTestBox(t, live)
	d, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	v1ID := v1Fingerprint(kindAgent, "claude-code", "/usr/local/bin/claude", "user")
	registry := `{"` + v1ID + `": {"id": "` + v1ID + `", "kind": "agent",
	    "signature": "claude-code", "argv0": "/usr/local/bin/claude",
	    "user": "user", "at": "2026-09-01T10:00:00Z", "by": "local-ui"}}`
	if err := os.WriteFile(filepath.Join(d, "sanctions.json"), []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}
	observedAgents = func() ([]agentObs, error) { return nil, errors.New("read /proc: permission denied") }
	u := uiTestServer(t)
	body := agentsGet(t, u.handler(), "/agents", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(body, "Marks that no longer count") {
		t.Fatalf("a failed walk silenced a mark that no longer counts: %s", firstLines(body))
	}
	if strings.Contains(body, "Marked as yours, but not running right now") {
		t.Fatalf("a failed walk listed a mark as not running: %s", firstLines(body))
	}
}

// A running candidate the registry cannot judge is unknowable too, and wears
// no "nothing behind it" edge — the live-verdict arm, pre-existing before
// this PR, set the status without the flag.
func TestARunningCandidateTheRegistryCannotJudgeWearsNoDormantEdge(t *testing.T) {
	obs := policyCandidateObs("claude-code", "/usr/local/bin/claude", 4242)
	cfg := policyTestBox(t, obs)
	id := sanctionIdentityOf(obs)
	now := time.Now()
	writeLedger(t, cfg, policyLedger{Since: now.Add(-time.Hour), LastScan: now,
		Candidates: map[string]policyCandidate{id.fingerprint(): {
			ID: id.fingerprint(), sanctionIdentity: id, FirstSeen: now.Add(-time.Hour), LastSeen: now}}})
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := uiTestServer(t)
	body := policyGet(t, u.handler(), "/policy", uiSignedIn(t, u))
	if !strings.Contains(body, policyPastUnknowable) {
		t.Fatalf("an unreadable registry did not make the running row unknowable: %s", firstLines(body))
	}
	if strings.Contains(body, "past dormant") {
		t.Fatalf("a running-but-unjudgeable row wore the dormant edge: %s", firstLines(body))
	}
}
