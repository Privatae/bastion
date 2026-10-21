package main

// The page saying the three things the machine already knew: what a host did
// here, what this box refused to do, and whether a newer version exists.
//
// Driven through the real handler rather than collectUIStatus, because the
// defect in every case was that the value existed and never reached a screen —
// so the assertion has to be made on what a browser would receive.

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func uiFragment(t *testing.T, u *uiServer) string {
	t.Helper()
	tok, err := u.sessions.mint()
	if err != nil {
		t.Fatal(err)
	}
	r := uiReq(http.MethodGet, "/fragments/status")
	r.Header.Set("Cookie", uiCookieName+"="+tok)
	w := httptest.NewRecorder()
	u.handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/fragments/status = %d: %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// contain.go killed the user's programs on a host's word and kept nothing at
// all, so the machine rendered exactly like one nothing had happened to.
func TestThePageSaysWhatTheHostDidHere(t *testing.T) {
	uiTestPairing(t, "member.host.privatae.ai")
	freshLocalEvents(t)
	u := uiTestServer(t)

	// Nothing has happened: the section is absent, not empty-with-a-heading.
	if body := uiFragment(t, u); strings.Contains(body, "What your host has done") {
		t.Error("a machine nothing has happened to must not carry the heading")
	}

	localEventNow = time.Now
	recordLocalEvent(eventContain, "Your host member.host.privatae.ai stopped claude-code "+
		"(pid 101) running on this machine, and 2 other processes it had started.")

	body := uiFragment(t, u)
	for _, want := range []string{
		`<h3 class="urgent">What your host has done on this machine</h3>`,
		`<div class="event recent">`,
		"stopped claude-code (pid 101)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page must carry %q:\n%s", want, body)
		}
	}
	// Above the state block, which is the one piece of placement that matters:
	// the state is still true in a minute and this is not.
	if strings.Index(body, "What your host has done") > strings.Index(body, `<div class="state`) {
		t.Error("a containment must sit above the state block, not below it")
	}

	// SEVEN DAYS LATER. It stops shouting and it is still there — an event is
	// never hidden, or the page would quietly forget the worst thing on it.
	freshLocalEvents(t)
	localEventNow = func() time.Time { return time.Now().Add(-30 * 24 * time.Hour) }
	recordLocalEvent(eventContain, "Your host stopped claude-code (pid 101) running on this machine.")
	body = uiFragment(t, u)
	if !strings.Contains(body, "stopped claude-code (pid 101)") {
		t.Error("an old event must still be readable")
	}
	if strings.Contains(body, `<div class="event recent">`) {
		t.Error("a month-old containment must not still be a red block")
	}
	if strings.Contains(body, `<h3 class="urgent">What your host has done`) {
		t.Error("...nor an urgent heading")
	}
}

// directive_refusal.go carried a refusal to the HOST on every enforcing report
// and gave the person at the machine a fmt.Printf into a console that, after a
// self-update, is gone.
func TestThePageSaysWhatThisMachineRefused(t *testing.T) {
	uiTestPairing(t, "member.host.privatae.ai")
	resetDirectiveRefusal(t)
	u := uiTestServer(t)

	if body := uiFragment(t, u); strings.Contains(body, "refused something your host asked for") {
		t.Error("a box that has refused nothing must say nothing")
	}

	recordDirectiveRefusal("contain",
		"refused: contain — this machine is networked but NOT ANCHORED, so it serves no host.")
	body := uiFragment(t, u)
	for _, want := range []string{
		"This machine refused something your host asked for",
		"<strong>contain</strong>",       // WHAT
		"networked but NOT ANCHORED",     // WHY — the only clue the operator gets
		"told this on its next check-in", // and that the host is not left waiting
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal must carry %q:\n%s", want, body)
		}
	}

	// Resolved refusals stop being shown, or the page is confidently wrong for
	// ever — which is worse than silent (directive_refusal.go:47).
	clearDirectiveRefusal("contain")
	if body := uiFragment(t, u); strings.Contains(body, "refused something your host asked for") {
		t.Error("a cleared refusal must leave the page")
	}
}

// hxPost finds every action the fragment can trigger. The page is allowed to
// answer a prompt this machine is holding; it is not allowed to originate
// anything (ui.go's header).
var hxPost = regexp.MustCompile(`hx-post="([^"]*)"`)

func TestTheUpdateBannerSaysWhoActsAndOffersNoButton(t *testing.T) {
	uiTestPairing(t, "member.host.privatae.ai")
	freshVersionState(t)
	clientVersion = "0.24.3"
	u := uiTestServer(t)

	if body := uiFragment(t, u); strings.Contains(body, "has been published") {
		t.Error("a machine that has not checked must not claim anything is available")
	}

	recordLatestPublished("0.24.4")
	body := uiFragment(t, u)
	for _, want := range []string{
		`<span class="tag warn">0.24.4 available</span>`, // beside the version it is about
		"will not install it on its own",                 // who does NOT act
		"your host directs updates",                      // who does
		"<strong>Network</strong>",                       // and where: app.js:1394
		"<strong>Bastions</strong>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the update banner must carry %q:\n%s", want, body)
		}
	}

	// THE LINE. Every action on this page must be one that answers a prompt
	// this machine is already holding. An Update button here would make the
	// local UI originate a request to the host, which is the one thing ui.go's
	// header says it must never do — and it is exactly the kind of convenience
	// that gets added next to a banner like this.
	for _, m := range hxPost.FindAllStringSubmatch(body, -1) {
		switch m[1] {
		case "/approve", "/deny":
		default:
			t.Errorf("the fragment can trigger %q — the UI never originates a request "+
				"to the host (ui.go's header)", m[1])
		}
	}
	if strings.Contains(body, "/update") {
		t.Error("the page references an update action")
	}

	// Already current: the banner goes, including the tag beside the version.
	recordLatestPublished("0.24.3")
	// recordLatestPublished only ever moves forward in the file, so drive the
	// equal case through the stored value directly.
	latestMu.Lock()
	latestPublished = "0.24.3"
	latestMu.Unlock()
	if body := uiFragment(t, u); strings.Contains(body, "available</span>") ||
		strings.Contains(body, "has been published") {
		t.Error("a machine on the published version must show no banner")
	}
}

// The page's CSP is `default-src 'self'` with no 'unsafe-inline' (ui.go
// renderWith), which covers style-src — so an inline style attribute is
// silently dropped by the browser and the markup lies about what it renders.
// It has already happened once: app.css:169-173 carries the fix.
func TestTheFragmentCarriesNoInlineStyle(t *testing.T) {
	uiTestPairing(t, "member.host.privatae.ai")
	freshLocalEvents(t)
	freshVersionState(t)
	clientVersion = "0.24.3"
	recordLatestPublished("0.24.4")
	recordLocalEvent(eventContain, "Your host stopped claude-code (pid 101) running on this machine.")
	resetDirectiveRefusal(t)
	recordDirectiveRefusal("contain", "refused: contain — this machine is networked but NOT ANCHORED")

	body := uiFragment(t, uiTestServer(t))
	if strings.Contains(body, "style=") {
		t.Errorf("an inline style is blocked by this page's own CSP:\n%s", body)
	}
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Errorf("the page must load nothing from anywhere but this machine:\n%s", body)
	}
}

// resetDirectiveRefusal empties the refusal slot for a test that asserts on it.
// The slot is package state written by several lanes; a test elsewhere that
// exercised one of them leaves its refusal behind, and clearing by kind would
// miss any kind added later.
func resetDirectiveRefusal(t *testing.T) {
	t.Helper()
	clear := func() {
		directiveMu.Lock()
		lastRefusalWhat, lastRefusalWhy, lastRefusalAt = "", "", time.Time{}
		directiveMu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}
