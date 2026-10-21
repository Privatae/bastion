package main

// The local UI's front door, driven end to end.
//
// Not tagged !windows, for the same reason uiauth_test.go is not: Windows is the
// platform this UI exists for, so the flow has to be proven there.
//
// The handler is driven directly rather than through httptest.NewServer, because
// the thing under test includes the Host header, and a real client would make
// that agree with the listener by construction — which is precisely the check
// that must NOT pass by construction.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const uiTestPort = "7877"

func uiTestServer(t *testing.T) *uiServer {
	t.Helper()
	srv, err := newUIServer(uiTestPort, "test-secret-aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("newUIServer: %v — a template that does not parse takes the whole UI down", err)
	}
	return srv
}

// uiTestPairing writes one pairing into an isolated config dir, so the page has
// something real to render.
func uiTestPairing(t *testing.T, host string) {
	t.Helper()
	uiTestConfigDir(t)
	d, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(&Config{
		HostName:        host,
		ListenAddr:      "127.0.0.1:59999", // nothing listens: "not answering"
		BastionTunnelIP: "fd00:9::a:1",
		State:           pairingActive,
		FirstSeen:       "2026-09-01T00:00:00Z",
	})
	if err := os.WriteFile(filepath.Join(d, host+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func uiReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "127.0.0.1:" + uiTestPort
	return r
}

// ── the whole flow, in order ────────────────────────────────────────────────

func TestTheFrontDoorFlow(t *testing.T) {
	uiTestPairing(t, "member.host.privatae.ai")
	u := uiTestServer(t)
	h := u.handler()

	// 1. Nothing is visible without a session.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, uiReq(http.MethodGet, "/"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/ without a session = %d, want 401 — the page lists every host "+
			"this machine serves", w.Code)
	}

	// 2. The CLI trades the secret for a ticket.
	r := uiReq(http.MethodPost, "/auth/ticket")
	r.Header.Set("Authorization", "Bearer "+u.secret)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/auth/ticket = %d, want 200: %s", w.Code, w.Body.String())
	}
	var out struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Ticket == "" {
		t.Fatalf("no ticket in %s", w.Body.String())
	}

	// 3. The browser opens ?k=<ticket> and is given a session.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, uiReq(http.MethodGet, "/?k="+out.Ticket))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("?k= = %d, want 303: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Fatalf("redirect to %q — the ticket must be stripped out of the address bar", loc)
	}
	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, uiCookieName+"=") {
		t.Fatalf("no session cookie was set: %q", cookie)
	}

	// 4. The page renders, and renders THIS machine.
	r = uiReq(http.MethodGet, "/")
	r.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/ with a session = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"member.host.privatae.ai", // the pairing
		"not answering",           // its liveness, probed not assumed
		"NOT RUNNING",             // the headline
		`hx-get="/fragments/status"`,
		"/assets/htmx.min.js",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not contain %q", want)
		}
	}

	// 5. The htmx poll target renders the same fragment, and only the fragment.
	r = uiReq(http.MethodGet, "/fragments/status")
	r.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/fragments/status = %d: %s", w.Code, w.Body.String())
	}
	frag := w.Body.String()
	if !strings.Contains(frag, "member.host.privatae.ai") {
		t.Error("the fragment does not carry the pairing")
	}
	if strings.Contains(frag, "<!doctype html") || strings.Contains(frag, "<script") {
		t.Error("the fragment is a whole page — htmx would nest a document inside the body")
	}

	// 6. A ticket is not a season pass.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, uiReq(http.MethodGet, "/?k="+out.Ticket))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a replayed ticket = %d, want 403 — it sits in browser history", w.Code)
	}
}

func TestTicketMintingNeedsTheSecret(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	h := u.handler()

	for _, offered := range []string{"", "Bearer ", "Bearer wrong", "Basic " + u.secret} {
		r := uiReq(http.MethodPost, "/auth/ticket")
		if offered != "" {
			r.Header.Set("Authorization", offered)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q = %d, want 401", offered, w.Code)
		}
	}
	// GET is refused even WITH the secret: a ticket mint must not be reachable
	// by navigation, or a crafted link would spend one.
	r := uiReq(http.MethodGet, "/auth/ticket")
	r.Header.Set("Authorization", "Bearer "+u.secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /auth/ticket = %d, want 405", w.Code)
	}
}

// Sign-out is a STATE CHANGE, so it takes the Origin check like every other one.
// It was a GET at first, and uiRequestAllowed exempts reads from
// the Origin check — correctly, a read is safe — which left any page able to
// sign the user out with an <img src>. Effect was small and nothing links to it;
// the name for it is well known enough to be worth one line.
func TestSignOutIsPostOnly(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	h := u.handler()
	tok, _ := u.sessions.mint()
	cookie := uiCookieName + "=" + tok

	r := uiReq(http.MethodGet, "/signout")
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /signout = %d, want 405", w.Code)
	}
	if !u.sessions.valid(tok) {
		t.Fatal("a GET signed the session out — that is the CSRF logout")
	}

	// Cross-site POST: the Origin check is what it now takes.
	r = httptest.NewRequest(http.MethodPost, "/signout", nil)
	r.Host = "127.0.0.1:" + uiTestPort
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST /signout = %d, want 403", w.Code)
	}
	if !u.sessions.valid(tok) {
		t.Fatal("a cross-site POST signed the session out")
	}

	// Our own page still works.
	r = httptest.NewRequest(http.MethodPost, "/signout", nil)
	r.Host = "127.0.0.1:" + uiTestPort
	r.Header.Set("Origin", "http://127.0.0.1:"+uiTestPort)
	r.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("same-origin POST /signout = %d, want 303", w.Code)
	}
	if u.sessions.valid(tok) {
		t.Fatal("sign out did not drop the session")
	}
}

// ── rebinding, at the server rather than the predicate ──────────────────────

func TestEveryRouteRefusesARebindingHost(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	h := u.handler()

	// A valid session, so the ONLY thing standing between the page and the
	// caller is the Host check.
	tok, _ := u.sessions.mint()

	for _, path := range []string{"/", "/fragments/status", "/assets/app.css",
		"/assets/htmx.min.js", "/auth/ticket", "/signout",
		// What this machine has given away (uigiven.go): the pairing list, the
		// caps each host holds and the paths of the folders shared from here.
		"/given", "/fragments/given", "/assets/given.css",
		// The approvals popup (uidevice.go): what the hosts are waiting on, and
		// the three routes that sign or refuse with the device key.
		"/approvals", "/fragments/approvals", "/fragments/approvals-news",
		"/device/approve", "/device/deny", "/device/approve-shown",
		// Phase 3 (uisetup.go). Every one of them goes through u.guarded, which
		// runs uiRequestAllowed before it looks at a cookie or a method — the
		// ordering signOut got wrong.
		"/setup", "/setup/pair", "/setup/stepup/start", "/setup/stepup/qr",
		"/setup/stepup/key", "/setup/stepup/confirm", "/setup/folder/check",
		"/setup/folder/propose", "/setup/anchor/choose", "/setup/owner/name",
		"/assets/setup.css",
		// The disk map (uidiskmap.go). Its page carries the name of every
		// large file on this machine, which is the most detailed thing about a
		// person that anything in this binary renders.
		"/diskmap", "/fragments/diskmap", "/diskmap/scan", "/diskmap/stop",
		"/assets/diskmap.css",
		// The automated programs seen here and the marks on them (uisanction.go).
		// The two mutating routes are in this list for the same reason the rest
		// are: guarded runs uiRequestAllowed before it looks at a cookie or a
		// method, so a rebound host is refused before the route admits it exists.
		"/agents", "/fragments/agents", "/agents/mark", "/agents/unmark",
		"/assets/agents.css",
		// The dry-run policy (uipolicy.go). Both routes are reads, and a read
		// is exactly what a rebinding page would want here: this one names
		// every automated program on the machine and adds the machine's own
		// opinion of which it would stop.
		"/policy", "/fragments/policy", "/assets/policy.css"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "evil.example:" + uiTestPort // resolves to 127.0.0.1, is not 127.0.0.1
		r.Header.Set("Cookie", uiCookieName+"="+tok)
		r.Header.Set("Authorization", "Bearer "+u.secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s from a rebound host = %d, want 403 (body %q)",
				path, w.Code, strings.TrimSpace(w.Body.String()))
		}
	}
}

// ── assets ──────────────────────────────────────────────────────────────────

func TestAssetsAreServedFromTheBinaryAndNothingElseIs(t *testing.T) {
	uiTestConfigDir(t)
	h := uiTestServer(t).handler()

	for path, sniff := range map[string]string{
		"/assets/htmx.min.js": "htmx",
		"/assets/app.css":     "--bg",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, uiReq(http.MethodGet, path))
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), sniff) {
			t.Errorf("%s does not look like itself (no %q) — the embed may be empty", path, sniff)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s is served without nosniff", path)
		}
	}

	// The asset route reads from an embedded FS by name, so it must serve only
	// the two names it knows.
	for _, path := range []string{
		"/assets/page.html", // a template, not an asset
		"/assets/../ui.go",  // traversal
		"/assets/ui.secret", // the credential, if the root were ever the config dir
		"/assets/",          // the directory
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, uiReq(http.MethodGet, path))
		if w.Code == http.StatusOK {
			t.Errorf("%s was served (%d) — the asset route must be an allow-list",
				path, w.Code)
		}
	}
}

// ── the unauthenticated surface ─────────────────────────────────────────────

func TestNothingAboutTheMachineLeaksWithoutASession(t *testing.T) {
	uiTestPairing(t, "secret-host.privatae.ai")
	h := uiTestServer(t).handler()

	// The given and setup pages both list every pairing, and the setup routes
	// answer questions about this machine's folders and its anchor. None of them
	// may say a word before a session exists.
	for _, path := range []string{"/", "/fragments/status", "/given", "/fragments/given",
		// The approvals popup names the machines your hosts want to act on and
		// what they want to do there.
		"/approvals", "/fragments/approvals", "/fragments/approvals-news",
		"/device/approve", "/device/deny", "/device/approve-shown",
		"/setup", "/setup/pair", "/setup/stepup/start", "/setup/stepup/qr",
		"/setup/stepup/key", "/setup/stepup/confirm", "/setup/folder/check",
		"/setup/folder/propose", "/setup/anchor/choose", "/setup/owner/name",
		// The disk map is the sharpest case on this list. A pairing name says
		// which host; a file listing says what a person works on, banks with
		// and is ill with, by name, and the map's own page prints the paths it
		// could not read as well as the ones it could.
		"/diskmap", "/fragments/diskmap", "/diskmap/scan", "/diskmap/stop",
		// The agents page names every automated program running here, its user
		// and its command line — as much about this machine as the pairing list.
		"/agents", "/fragments/agents", "/agents/mark", "/agents/unmark",
		// The policy page names the same programs and adds this machine's own
		// opinion of which of them it would stop.
		"/policy", "/fragments/policy"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, uiReq(http.MethodGet, path))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "secret-host.privatae.ai") {
			t.Errorf("%s leaked a host name in its REFUSAL: %q", path, w.Body.String())
		}
	}
}
