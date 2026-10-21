package main

// The user-run context surface (contextui.go, uicontext.go).
//
// The property this file exists for is the FIRST test: a process a normal
// person started must not serve the machine-admin console, even to the person
// who started it. Everything else here is about the surface being honest — it
// asks, it never grants, and it says which of the two it did.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const contextTestPort = "7861"

// contextTestServer builds the context surface over a home directory the test owns.
func contextTestServer(t *testing.T, home string) (*uiServer, string) {
	t.Helper()
	u, err := newUIServer(contextTestPort, "test-secret-aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("newUIServer: %v", err)
	}
	u.contextUI = true
	u.contextHome = home
	tok, err := u.sessions.mint()
	if err != nil {
		t.Fatal(err)
	}
	return u, uiCookieName + "=" + tok
}

func contextReq(t *testing.T, u *uiServer, method, path, cookie string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if method == http.MethodPost {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://127.0.0.1:"+contextTestPort)
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host = "127.0.0.1:" + contextTestPort
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	u.handler().ServeHTTP(w, r)
	return w
}

// ── the property the surface exists for ─────────────────────────────────────

// A CONTEXT PROCESS SERVES NO MACHINE-ADMIN ROUTE. Not "refuses with 403" —
// DOES NOT MOUNT. The person who started this process may well also be the
// machine's administrator, and that is beside the point: this surface is not
// where that authority is exercised, and a route that exists is a route that
// gets linked to, bookmarked and eventually relied on.
func TestTheContextSurfaceServesNoMachineAdminRoute(t *testing.T) {
	uiTestConfigDir(t)
	u, cookie := contextTestServer(t, t.TempDir())

	// Every route the admin console mounts. Named individually rather than
	// derived, because the list is the assertion: if one of these ever starts
	// answering here, that is the finding.
	for _, path := range []string{
		"/fragments/status", "/given", "/fragments/given", "/approve", "/deny",
		"/setup", "/setup/pair", "/setup/stepup/start", "/setup/stepup/qr",
		"/setup/stepup/key", "/setup/stepup/confirm", "/setup/folder/check",
		"/setup/folder/propose", "/setup/anchor/choose", "/setup/owner/name",
		"/diskmap", "/fragments/diskmap", "/diskmap/scan", "/diskmap/stop",
		"/agents", "/fragments/agents", "/agents/mark", "/agents/unmark",
		"/policy", "/fragments/policy",
	} {
		w := contextReq(t, u, http.MethodGet, path, cookie, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d on the context surface. This process runs as an "+
				"ordinary person; the pairing list, the anchor, the marks and the policy "+
				"are the machine's own console and belong to whoever administers it.",
				path, w.Code)
		}
	}
	// And the check is not passing because everything 404s.
	if w := contextReq(t, u, http.MethodGet, "/", cookie, nil); w.Code != http.StatusOK {
		t.Fatalf("/ = %d — the context page itself does not serve, so the assertions "+
			"above proved nothing", w.Code)
	}
}

// The same list from the other side: the ADMIN console must not grow the files
// routes either. Two surfaces, and the separation has to hold both ways or the
// next person to add a route picks whichever mux they happened to open.
func TestTheAdminConsoleServesNoContextRoute(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	cookie := uiSignedIn(t, u)
	for _, path := range []string{"/fragments/context", "/context/scan", "/context/stop", "/context/ask"} {
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		u.handler().ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d on the admin console, want 404", path, w.Code)
		}
	}
}

// THE STYLESHEET THE PAGE LINKS IS A STYLESHEET THE SERVER HAS. The rename to
// context.* proved the negative case: the page linked /assets/files.css while
// the embedded file was already context.css, and the suite stayed green because
// nothing asked for the href the page actually carries. A page whose
// stylesheet 404s renders unstyled and says nothing.
// So ask for whatever the page links, rather than asserting a name.
func TestTheContextPageStylesheetActuallyServes(t *testing.T) {
	uiTestConfigDir(t)
	u, cookie := contextTestServer(t, t.TempDir())

	w := contextReq(t, u, http.MethodGet, "/", cookie, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("/ = %d — the context page itself does not serve", w.Code)
	}
	hrefs := regexp.MustCompile(`<link[^>]+href="(/assets/[^"]+)"`).FindAllStringSubmatch(w.Body.String(), -1)
	if len(hrefs) == 0 {
		t.Fatal("the context page links no stylesheet at all — this check would pass for ever")
	}
	for _, m := range hrefs {
		if got := contextReq(t, u, http.MethodGet, m[1], cookie, nil).Code; got != http.StatusOK {
			t.Errorf("the page links %s but the server answers %d for it", m[1], got)
		}
	}
}

// ── it asks; it never grants ────────────────────────────────────────────────

// The word on the button and the words around it have to say that pressing it
// shares nothing. This is the one place on either surface where a person could
// believe they had just handed over a folder when they had not, or the reverse.
func TestTheAskSaysNothingIsSharedByPressingIt(t *testing.T) {
	home := t.TempDir()
	sub := filepath.Join(home, "Contracts")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "lease.pdf"), make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	uiTestConfigDir(t)
	dmTestInstall(t, dmScanTree(t, home))
	u, cookie := contextTestServer(t, home)

	body := contextReq(t, u, http.MethodGet, "/?p="+url.QueryEscape(sub), cookie, nil).Body.String()
	if !strings.Contains(body, "/context/ask") {
		t.Fatalf("there is no way to ask for a folder from inside one: %q", dmSnip(body, "ask"))
	}
	for _, want := range []string{
		"does not share anything",
		"has to approve it",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the ask does not say %q. A button that reads as "+
				"\"share\" when nothing is shared is the worst sentence on this page.", want)
		}
	}
}

// A FOLDER OUTSIDE YOUR OWN IS REFUSED AT THE POINT OF ASKING. The kernel is
// the real control — this process cannot read what it cannot read — but a
// request that travels to a host, waits for a person to approve it and only
// then fails is a bad way to learn that.
func TestAskingForAFolderOutsideYourOwnIsRefused(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir() // a sibling: real, readable, and not theirs
	uiTestConfigDir(t)
	dmTestInstall(t, nil)
	u, cookie := contextTestServer(t, home)

	w := contextReq(t, u, http.MethodPost, "/context/ask", cookie, url.Values{
		"path": {outside}, "name": {"not mine"},
	})
	body := w.Body.String()
	if !strings.Contains(body, "outside") {
		t.Errorf("a folder outside the person's own directory was not refused: %q",
			dmSnip(body, "flash"))
	}
	// And it names where that authority does live, rather than just saying no.
	if !strings.Contains(body, "privatae-bastion ui") {
		t.Errorf("the refusal does not say who can share a machine-wide folder: %q",
			dmSnip(body, "flash"))
	}
	if len(u.contextAsked()) != 0 {
		t.Error("a refused ask was recorded as an ask")
	}
}

// The home directory ITSELF is askable — the boundary is "outside", not
// "below". A person who wants to index their whole home directory is doing the
// ordinary thing, not an edge case.
func TestYourOwnHomeDirectoryIsAskable(t *testing.T) {
	home := t.TempDir()
	docs := filepath.Join(home, "Documents")
	// The folder has to EXIST: a path you cannot open is not one you can hand
	// over, and the check says so. The first version of this test skipped the
	// mkdir and read that refusal as a containment failure.
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	uiTestConfigDir(t)
	dmTestInstall(t, nil)
	u, _ := contextTestServer(t, home)
	if why := u.contextRefuseOutsideHome(home); why != "" {
		t.Errorf("the person's own home directory was refused: %s", why)
	}
	if why := u.contextRefuseOutsideHome(docs); why != "" {
		t.Errorf("a folder inside the person's home was refused: %s", why)
	}
	// And a folder inside your home that does not exist is still refused, here,
	// rather than travelling to a host to fail there.
	if why := u.contextRefuseOutsideHome(filepath.Join(home, "no-such-folder")); why == "" {
		t.Error("a folder that does not exist was accepted")
	}
}

// A PREFIX IS NOT A PARENT. "/home/user-backup" starts with "/home/user" and
// is a different person's directory.
func TestAPathThatMerelySharesAPrefixIsNotYours(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "user")
	sneak := filepath.Join(base, "user-backup")
	for _, d := range []string{home, sneak} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	uiTestConfigDir(t)
	u, _ := contextTestServer(t, home)
	if why := u.contextRefuseOutsideHome(sneak); why == "" {
		t.Errorf("%q was accepted as being inside %q — string prefixes are not path "+
			"containment, and the difference is another person's files", sneak, home)
	}
}

// ── the map is the person's own ─────────────────────────────────────────────

// There is NO whole-machine option on this surface, and that is not a hidden
// button: the scope does not exist here. A user-run process could not read
// other people's files anyway, so offering it would promise something false.
func TestTheContextSurfaceOffersNoWholeMachineMap(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, nil)
	u, cookie := contextTestServer(t, t.TempDir())
	body := contextReq(t, u, http.MethodGet, "/", cookie, nil).Body.String()

	if strings.Contains(body, `value="machine"`) {
		t.Error("the context surface offers a whole-machine map. This process runs as one " +
			"person and cannot read another's files; the button would produce a map full " +
			"of refusals and tell them something false about what this is.")
	}
	if !strings.Contains(body, "/context/scan") {
		t.Fatal("there is no way to count anything at all, so the assertion above " +
			"passed for the wrong reason")
	}
}

// And the walk it starts is the home scope, whatever anybody posts.
func TestTheContextScanIsAlwaysTheHomeScope(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		<-release
		return &dmResult{TakenAt: uiNow()}
	}
	u, cookie := contextTestServer(t, t.TempDir())

	// A hand-written form asking for the machine. The route takes no scope at
	// all, so this must change nothing.
	contextReq(t, u, http.MethodPost, "/context/scan", cookie, url.Values{"scope": {"machine"}})
	s.mu.Lock()
	got := s.scope
	s.mu.Unlock()
	if got != dmScopeHome {
		t.Errorf("a posted scope=machine started a %q walk. This route reads no scope "+
			"from the request precisely so that it cannot be widened by one.", got)
	}
}

// ── the reads are reads ─────────────────────────────────────────────────────

func TestEveryContextReadIsGETOnlyAndEveryWriteIsPOSTOnly(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, nil)
	u, cookie := contextTestServer(t, t.TempDir())

	for _, path := range []string{"/", "/fragments/context"} {
		if w := contextReq(t, u, http.MethodPost, path, cookie, url.Values{}); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, w.Code)
		}
	}
	for _, path := range []string{"/context/scan", "/context/stop", "/context/ask"} {
		if w := contextReq(t, u, http.MethodGet, path, cookie, nil); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405 — it changes something", path, w.Code)
		}
	}
}

// The same three defences the admin console has. A cross-site POST must not
// start a walk of somebody's home directory or hand a folder to a host.
func TestTheContextSurfaceTakesTheOriginAndHostChecks(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	started := 0
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		started++
		return &dmResult{}
	}
	u, cookie := contextTestServer(t, t.TempDir())

	for _, route := range []string{"/context/scan", "/context/ask"} {
		r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(""))
		r.Host = "127.0.0.1:" + contextTestPort
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		u.handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403", route, w.Code)
		}

		// And a rebound host, which is the one SameSite cannot see.
		r = httptest.NewRequest(http.MethodPost, route, strings.NewReader(""))
		r.Host = "evil.example:" + contextTestPort
		r.Header.Set("Origin", "http://127.0.0.1:"+contextTestPort)
		r.Header.Set("Cookie", cookie)
		w = httptest.NewRecorder()
		u.handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("rebound-host POST %s = %d, want 403", route, w.Code)
		}
	}
	if started != 0 {
		t.Fatalf("%d walks were started by refused requests", started)
	}
}

// Signed out, this page says nothing about anybody's files — including the
// name of the directory it would have shown.
func TestSignedOutTheContextPageNamesNothing(t *testing.T) {
	home := filepath.Join(t.TempDir(), "very-particular-directory-name")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	uiTestConfigDir(t)
	dmTestInstall(t, nil)
	u, _ := contextTestServer(t, home)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "127.0.0.1:" + contextTestPort
	w := httptest.NewRecorder()
	u.handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/ without a session = %d, want 401", w.Code)
	}
	if strings.Contains(w.Body.String(), "very-particular-directory-name") {
		t.Errorf("the refusal named the directory: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "privatae-bastion context") {
		t.Errorf("the refusal does not say how to get in: %q", w.Body.String())
	}
}

// ── two refusal-wording findings ────────────────────────────────────────────

// A REFUSAL THAT NAMES THE WRONG COMMAND sends somebody to a page they cannot
// open, which is worse than no instruction. The verb switch reached root() and
// not guarded(), so three refusal bodies on this surface still said `ui`: the
// guarded-route 401, the expired-ticket 403, and the rebinding refusal that
// lives in uiRequestAllowed and knew nothing about surfaces at all.
//
// Every refusal a person can actually hit, on both surfaces, checked together —
// a per-route test would have missed the two that are not routes.
func TestEveryRefusalNamesTheVerbThatOpensThisSurface(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, nil)

	for _, c := range []struct {
		surface string
		want    string
		wrong   string
	}{
		{"context", "privatae-bastion context", "privatae-bastion ui"},
		{"admin", "privatae-bastion ui", "privatae-bastion context"},
	} {
		t.Run(c.surface, func(t *testing.T) {
			var u *uiServer
			var port, guardedPath string
			if c.surface == "context" {
				u, _ = contextTestServer(t, t.TempDir())
				port, guardedPath = contextTestPort, "/fragments/context"
			} else {
				u = uiTestServer(t)
				port, guardedPath = uiTestPort, "/fragments/status"
			}
			h := u.handler()

			bodies := map[string]string{}

			// 1. A guarded route with no session.
			r := httptest.NewRequest(http.MethodGet, guardedPath, nil)
			r.Host = "127.0.0.1:" + port
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s with no session = %d, want 401", guardedPath, w.Code)
			}
			bodies["the guarded-route 401"] = w.Body.String()

			// 2. A ticket that has already been used.
			tok, err := u.tickets.mint()
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				r = httptest.NewRequest(http.MethodGet, "/?k="+tok, nil)
				r.Host = "127.0.0.1:" + port
				w = httptest.NewRecorder()
				h.ServeHTTP(w, r)
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("a re-used ticket = %d, want 403", w.Code)
			}
			bodies["the spent-ticket 403"] = w.Body.String()

			// 3. A rebound host — the refusal that lives in uiRequestAllowed.
			r = httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = "evil.example:" + port
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("a rebound host = %d, want 403", w.Code)
			}
			bodies["the rebinding 403"] = w.Body.String()

			for what, body := range bodies {
				if !strings.Contains(body, c.want) {
					t.Errorf("%s does not name %q: %q", what, c.want, strings.TrimSpace(body))
				}
				if strings.Contains(body, c.wrong) {
					t.Errorf("%s tells the person to run %q, which does not open this "+
						"surface: %q", what, c.wrong, strings.TrimSpace(body))
				}
			}
		})
	}
}

// renderContext duplicates the four headers renderWith and renderDiskMap set, and
// its comment claimed a comparison test made that duplication safe. It did not:
// the comparison existed for the DISKMAP renderer only, so dropping the CSP
// line from renderContext turned nothing red. A comment
// that names a safety net which does not cover it is worse than no comment,
// because the next person reads it and believes the duplication is held.
func TestTheContextPagesCarryTheSameHeadersAsTheAdminPages(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, nil)

	admin := uiTestServer(t)
	adminCookie := uiSignedIn(t, admin)
	r := uiReq(http.MethodGet, "/")
	r.Header.Set("Cookie", adminCookie)
	w := httptest.NewRecorder()
	admin.handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("the admin page = %d, so there is nothing to compare against", w.Code)
	}
	want := w.Header()

	u, cookie := contextTestServer(t, t.TempDir())
	for _, path := range []string{"/", "/fragments/context"} {
		got := contextReq(t, u, http.MethodGet, path, cookie, nil)
		if got.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, got.Code)
		}
		for _, k := range []string{"Content-Type", "Cache-Control",
			"Content-Security-Policy", "X-Content-Type-Options"} {
			if got.Header().Get(k) != want.Get(k) {
				t.Errorf("%s %s: files %q, admin %q", path, k,
					got.Header().Get(k), want.Get(k))
			}
		}
	}
	if want.Get("Content-Security-Policy") == "" {
		t.Fatal("neither surface sends a CSP, so this comparison proved nothing")
	}
}

// ── a fixture with an expiry date on it ─────────────────────────────────────

// NO FIXTURE MAY ENCODE "NOW" AS A LITERAL.
//
// Three fixtures stamped a pending request with a literal `At:` date, and
// stepup.go:569 drops any request older than stepupRequestTTL (24h,
// stepup.go:62). So those tests passed for one day after the date was typed and
// then failed on every machine for ever. Measured 32 hours past the stamp: six
// approvals tests red with nothing whatsoever wrong in the code they were
// testing.
//
// That is the worst failure shape a suite can have: it accuses working code,
// and it arrives on a day nobody changed anything. The scan below is over the
// FIELD THAT IS AGE-CHECKED, not over dates in general — an EnrolledAt or a
// FirstSeen in the past is a legitimate fixture and this must not fight it.
func TestNoFixtureHardcodesAMomentInTime(t *testing.T) {
	names, err := packageTestFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 20 {
		t.Fatalf("only %d _test.go files found — the scan has stopped finding them, "+
			"which makes this check a green light that proves nothing", len(names))
	}
	// `At:` followed by a literal RFC3339 date. That field is the one compared
	// against stepupRequestTTL.
	bad := regexp.MustCompile(`\bAt:\s*"(\d{4})-\d{2}-\d{2}T`)
	found := 0
	for _, name := range names {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			// A COMMENT IS NOT A FIXTURE. A comment may spell out the literal
			// this bans while explaining it, and a guard that fails on its own
			// explanation teaches the next person to delete the explanation.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if m := bad.FindStringSubmatch(line); m != nil {
				found++
				t.Errorf("%s:%d stamps a request with a literal date:\n    %s\n"+
					"stepup.go:569 drops requests older than stepupRequestTTL, so this "+
					"fixture stops working 24 hours after the date in it and takes "+
					"working code down with it. Use uiTestRecently().",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
	if found == 0 {
		// The scan must be capable of finding something, or it is decoration.
		// Assembled rather than written out, so the probe cannot trip the very
		// scan it is checking.
		probe := "At:" + `    "2026-` + `09-13T09:00:00Z",`
		if !bad.MatchString(probe) {
			t.Fatal("the pattern no longer matches the shape it was written for, so a " +
				"clean run proves nothing")
		}
	}
}

// ── what the page is NAMED for ──────────────────────────────────────────────

// A PAGE CALLED "YOUR CONTEXT" HAS TO SHOW YOUR CONTEXT. It showed a file
// browser and a list of requests, which answers every question except the one
// in its title.
func TestTheContextPageShowsWhatIsAlreadyContext(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, nil)
	// Reuse the fixtures the given page's own tests use, so this exercises the
	// same record shape the admin console reads rather than a parallel one.
	const host = "h1.host.privatae.ai"
	dcn := givenPairing(t, host, pairingActive)
	givenStoreGrants(t, dcn, map[string]map[string]any{
		"1": {"root": "/home/user/Contracts", "mask": []any{"read", "index"},
			"sweep": "nightly", "ttl_days": float64(30)},
	})
	u, cookie := contextTestServer(t, t.TempDir())
	body := contextReq(t, u, http.MethodGet, "/", cookie, nil).Body.String()

	if !strings.Contains(body, "What is context now") {
		t.Error("the page has no section for context that already exists")
	}
	if !strings.Contains(body, "/home/user/Contracts") {
		t.Errorf("a folder that IS context is not on the page named for it: %q",
			dmSnip(body, "context now"))
	}
	if !strings.Contains(body, host) {
		t.Error("the page does not say WHICH host holds that folder")
	}
}

// And when this process cannot read the records, it says so rather than
// rendering an empty table — "you have no context" is a different claim from
// "this window cannot see".
func TestAnUnreadableStoreIsSaidRatherThanShownAsNothing(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, nil)
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pd, "broken.host.privatae.ai.json"),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPairings(); err == nil {
		t.Skip("loadPairings tolerates this; the fixture needs updating")
	}
	u, cookie := contextTestServer(t, t.TempDir())
	body := contextReq(t, u, http.MethodGet, "/", cookie, nil).Body.String()
	if !strings.Contains(body, "cannot be read") {
		t.Errorf("an unreadable pairing store rendered as nothing at all: %q",
			dmSnip(body, "context now"))
	}
}

// ── the asks outlive the window ─────────────────────────────────────────────

// A request waiting on somebody else is a thing YOU DID. Closing the page used
// to erase the only evidence you had done it.
func TestAsksSurviveTheWindowClosing(t *testing.T) {
	uiTestConfigDir(t)
	first, _ := contextTestServer(t, t.TempDir())
	first.contextRecord(uiContextAsk{
		Path: "/home/user/Contracts", Name: "Contracts",
		Host: "h1.host.privatae.ai", At: "14 Sep 2026, 20:10", Sent: true,
	})
	if len(first.contextAsked()) != 1 {
		t.Fatal("the ask was not recorded at all")
	}

	// A NEW server object is the window being closed and reopened.
	second, cookie := contextTestServer(t, t.TempDir())
	if got := len(second.contextAsked()); got != 0 {
		t.Fatalf("a fresh server started with %d asks before loading", got)
	}
	second.contextLoadAsks()
	got := second.contextAsked()
	if len(got) != 1 {
		t.Fatalf("after reopening, %d asks — the record of what this person asked for "+
			"is gone, and they cannot see that they already asked", len(got))
	}
	if got[0].Path != "/home/user/Contracts" {
		t.Errorf("the reloaded ask is %+v", got[0])
	}
	body := contextReq(t, second, http.MethodGet, "/", cookie, nil).Body.String()
	if !strings.Contains(body, "/home/user/Contracts") {
		t.Error("the reloaded ask does not reach the page")
	}
}

// The file names folders a person asked to share; it is written private.
func TestTheAskHistoryIsWrittenPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not carry the same meaning here")
	}
	uiTestConfigDir(t)
	u, _ := contextTestServer(t, t.TempDir())
	u.contextRecord(uiContextAsk{Path: "/home/user/Private", At: "now"})
	p, err := contextAsksPath()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("no history was written: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("context-asks.json is %o, want 600 — it names folders this person "+
			"asked to share", got)
	}
}
