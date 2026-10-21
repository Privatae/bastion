package main

// The SET IT UP page, driven through the real handler.
//
// Not tagged !windows, for the reason ui_test.go gives: Windows is the platform
// this UI exists for. The two platform-shaped things here — the claim-anchor
// line and the claim-owner line — take the platform as an argument so a Linux
// builder can check the Windows string, which is the hole restartHintFor was
// rewritten to close (privilege.go:88).

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"rsc.io/qr"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// uiSetupPairingInState starts a fresh isolated config dir holding ONE pairing
// in a named state, and returns the DCN dir it points at.
//
// Split from uiSetupAddPairing because uiTestConfigDir points XDG_CONFIG_HOME at
// a NEW t.TempDir() on every call (uiauth_test.go:18) — so calling it twice does
// not give a machine with two pairings, it gives two machines with one each, and
// a test written that way silently checks the single-host path.
func uiSetupPairingInState(t *testing.T, host, state string) string {
	t.Helper()
	uiTestConfigDir(t)
	return uiSetupAddPairing(t, host, state)
}

// uiSetupAddPairing adds a pairing to the config dir already in force.
func uiSetupAddPairing(t *testing.T, host, state string) string {
	t.Helper()
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pd, 0o700); err != nil {
		t.Fatal(err)
	}
	dcn := filepath.Join(t.TempDir(), "dcn")
	if err := os.MkdirAll(dcn, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(&Config{
		HostName:   host,
		ListenAddr: "127.0.0.1:59999", // nothing answers there
		State:      state,
		DCNDir:     dcn,
		FirstSeen:  "2026-09-01T00:00:00Z",
	})
	if err := os.WriteFile(filepath.Join(pd, host+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dcn
}

func uiSetupPairingWithDCN(t *testing.T, host string) string {
	t.Helper()
	return uiSetupPairingInState(t, host, pairingActive)
}

// uiSetupNetworked writes mode.json DIRECTLY, the way repinBox does
// (anchor_test.go:1006) — setBoxMode needs machine authority, and this is
// setting up state, not driving the gate.
func uiSetupNetworked(t *testing.T) error {
	t.Helper()
	p, err := modePath()
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		return err
	}
	if boxMode() != modeNetworked {
		t.Fatalf("box must read networked, got %s", boxMode())
	}
	return nil
}

func uiSetupAnchorPath(t *testing.T) string {
	t.Helper()
	p, err := anchorPath()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func runtimeGOOSForTest() string { return runtime.GOOS }

// uiSetupNoMachineMarker points the machine marker at a path that does not
// exist, so the singleton guard reads "absent ⇒ today's behaviour"
// (singleton.go:362) instead of the real marker this builder carries.
//
// Not singleton_test.go's withMarkerAt, which is identical and behind
// `//go:build !windows` — and this file has to compile for Windows, because
// Windows is the platform the whole UI exists for.
func uiSetupNoMachineMarker(t *testing.T) {
	t.Helper()
	old := markerPathOverride
	markerPathOverride = filepath.Join(t.TempDir(), "no-such-marker.json")
	t.Cleanup(func() { markerPathOverride = old })
}

// qrTerminalPNGForTest is what the QR route must produce for a given payload.
func qrTerminalPNGForTest(uri string) ([]byte, error) {
	c, err := qr.Encode(uri, qr.M)
	if err != nil {
		return nil, err
	}
	return c.PNG(), nil
}

// uiSetupTestBox gives the setup page a machine to render: an isolated config
// dir and its own mux, so the test can reach the enrolments held in memory.
func uiSetupTestBox(t *testing.T) (*uiServer, *uiSetup, http.Handler, string) {
	t.Helper()
	u := uiTestServer(t)
	mux := http.NewServeMux()
	s := u.setupRoutes(mux)
	return u, s, mux, uiSignedIn(t, u)
}

func uiSetupGet(t *testing.T, h http.Handler, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	r := uiReq(http.MethodGet, path)
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// ── the page ────────────────────────────────────────────────────────────────

func TestTheSetupPageRendersEveryPanelItPromises(t *testing.T) {
	uiTestPairing(t, "member.host.privatae.ai")
	_, _, h, cookie := uiSetupTestBox(t)

	w := uiSetupGet(t, h, "/setup", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("/setup = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"member.host.privatae.ai",                     // the machine it is describing
		`hx-post="/setup/pair"`,                       // 1. pair
		`hx-post="/setup/stepup/start"`,               // 2. a second factor
		`hx-post="/setup/folder/check"`,               // 3. the live path check
		`hx-post="/setup/anchor/choose"`,              // 4. the anchor picker
		`hx-post="/setup/owner/name"`,                 // 5. the owner name
		`name="host" value="member.host.privatae.ai"`, // the anchor choice is a real pairing
		"/assets/setup.css",
		"This page will not do it", // the root-gated promise, said out loud
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the setup page is missing %q", want)
		}
	}
	// No inline styles and no template.HTML anywhere: the page's own CSP has no
	// 'unsafe-inline' in it, so a style attribute would be silently dropped —
	// the failure app.css:149 records.
	if strings.Contains(body, "style=") {
		t.Error("the page carries an inline style, which its own CSP blocks")
	}
}

// The setup page and the status page must be held to the same headers. They are
// rendered by two functions (uisetup.go's render, ui.go's renderWith) because
// their view models differ, and two functions drift.
func TestTheSetupPageIsHeldToTheSameHeadersAsTheStatusPage(t *testing.T) {
	uiTestPairing(t, "member.host.privatae.ai")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	status := uiSetupGet(t, h, "/", cookie)
	setup := uiSetupGet(t, h, "/setup", cookie)
	if status.Code != http.StatusOK || setup.Code != http.StatusOK {
		t.Fatalf("/ = %d, /setup = %d", status.Code, setup.Code)
	}
	for _, hdr := range []string{"Content-Security-Policy", "Cache-Control",
		"X-Content-Type-Options", "Content-Type"} {
		if got, want := setup.Header().Get(hdr), status.Header().Get(hdr); got != want {
			t.Errorf("/setup %s = %q, / = %q — the two render paths have drifted", hdr, got, want)
		}
	}
}

// A pending host is offerable as the anchor — claim-anchor flips it active
// because the anchor never waits on itself (anchor.go:931) — so it appears in
// the picker, and its state appears WITH it. A choice whose consequence is
// invisible at the moment of choosing is the thing this page exists to fix.
func TestAPendingHostIsOfferedTheAnchorWithItsStateVisible(t *testing.T) {
	const host = "waiting.host.privatae.ai"
	const live = "serving.host.privatae.ai"
	uiSetupPairingInState(t, host, pairingPending)
	// A live pairing beside it, so the panels that DO render a host list render
	// one — otherwise they collapse to their empty state and the assertions
	// below about what is missing from them would hold for the wrong reason.
	uiSetupAddPairing(t, live, pairingActive)
	_, _, h, cookie := uiSetupTestBox(t)

	body := uiSetupGet(t, h, "/setup", cookie).Body.String()
	radio := `<input type="radio" name="host" value="` + host + `">`
	i := strings.Index(body, radio)
	if i < 0 {
		t.Fatalf("a pending host is not offered the anchor at all: %q", body)
	}
	// Inside the same label, not merely somewhere on the page.
	label := body[i:]
	if end := strings.Index(label, "</label>"); end > 0 {
		label = label[:end]
	}
	if !strings.Contains(label, "waiting for approval") {
		t.Errorf("the pending state is not shown beside the choice: %q", label)
	}
	// But nothing that would CREATE state for it is offered: a pending pairing
	// gets no directory on this machine until the anchor approves it
	// (run.go:311), and both the folder target and the factor host are dropdowns
	// that would.
	if strings.Contains(body, `<option value="`+host+`"`) {
		t.Error("a pending host is offered as a folder or factor target — nothing may be " +
			"created for it here until the anchor approves the pairing")
	}
	// The live one IS offered, so the check above is about the pending host and
	// not about a panel that rendered nothing.
	if !strings.Contains(body, `<option value="`+live+`"`) {
		t.Fatal("the active host is not offered either — the panels rendered empty and the " +
			"assertion above proved nothing")
	}
}

// The same rule at the handler, because a select is a suggestion and a POST is
// not: cfg.dcnDir() is MkdirAll-on-read (config.go:115), so enrolling for a
// pending host would create the state dir run.go guards.
func TestAFactorIsNotEnrolledForAPairingWithNoLanes(t *testing.T) {
	const host = "waiting.host.privatae.ai"
	dcn := uiSetupPairingInState(t, host, pairingPending)
	if err := os.RemoveAll(dcn); err != nil { // it must be the HANDLER that does not create it
		t.Fatal(err)
	}
	_, s, h, cookie := uiSetupTestBox(t)

	w := uiPost(t, h, "/setup/stepup/start", url.Values{"host": {host}}, cookie)
	if !strings.Contains(w.Body.String(), "is pending on this machine") {
		t.Errorf("a pending host was not refused: %q", w.Body.String())
	}
	if _, e := s.enrols.forHost(host); e != nil {
		t.Fatal("a secret was minted for a pairing with no lanes")
	}
	if _, err := os.Stat(dcn); !os.IsNotExist(err) {
		t.Fatal("the page created a state directory for a host the anchor has not approved")
	}
}

// The same rule on the STATUS page, which is where this was found: it polls
// every three seconds and asked every pairing — including pending ones — for
// its approvals, and asking creates the directory. Covers a fix in ui.go's
// pendingApprovals rather than anything on the setup page; it lives here
// because this is the file whose test surfaced it.
func TestTheStatusPageDoesNotCreateStateForAPendingPairing(t *testing.T) {
	const host = "waiting.host.privatae.ai"
	dcn := uiSetupPairingInState(t, host, pairingPending)
	if err := os.RemoveAll(dcn); err != nil {
		t.Fatal(err)
	}
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	for i := 0; i < 3; i++ { // it is a poll, so the leak compounds
		if w := uiSetupGet(t, h, "/fragments/status", cookie); w.Code != http.StatusOK {
			t.Fatalf("/fragments/status = %d", w.Code)
		}
	}
	if _, err := os.Stat(dcn); !os.IsNotExist(err) {
		t.Fatal("rendering the status page created a state directory for a host the " +
			"anchor has not approved")
	}
}

// Every template the handlers name must exist, or a browser gets an empty body
// and a line in a log nobody is reading.
func TestEverySetupTemplateExists(t *testing.T) {
	u := uiTestServer(t)
	for _, name := range uiSetupTemplates() {
		if u.tpl.Lookup(name) == nil {
			t.Errorf("template %q is not in the parsed set", name)
		}
	}
}

// ── 1. pairing ──────────────────────────────────────────────────────────────

func TestPlanPairChangeFollowsWhatTheDaemonIsActuallyServing(t *testing.T) {
	active := func(h string) *Config { return &Config{HostName: h, State: pairingActive} }
	pending := func(h string) *Config { return &Config{HostName: h, State: pairingPending} }

	cases := []struct {
		name      string
		before    []string
		after     []*Config
		cfg       *Config
		wantStop  []string
		wantStart string
		wantIn    string
	}{
		{
			name:   "a brand new host starts, nothing stops",
			before: []string{"one.example"}, cfg: active("two.example"),
			after:     []*Config{active("one.example"), active("two.example")},
			wantStop:  nil,
			wantStart: "two.example",
			wantIn:    "Paired with two.example.",
		},
		{
			name:   "a pending pairing starts NOTHING and says so",
			before: []string{"one.example"}, cfg: pending("two.example"),
			after:     []*Config{active("one.example"), pending("two.example")},
			wantStop:  nil,
			wantStart: "",
			wantIn:    "PENDING",
		},
		{
			// The lane still running holds the credentials this redeem just
			// rotated out, so it must go before the new one comes up.
			name:   "a --replace stops the lane holding the old credentials",
			before: []string{"one.example"}, cfg: active("one.example"),
			after:     []*Config{active("one.example")},
			wantStop:  []string{"one.example"},
			wantStart: "one.example",
		},
		{
			// pair.go:370 removes the superseded file; the goroutine serving the
			// old name is still up and would collide on the inherited port.
			name:   "a --replace that renames stops the old name too",
			before: []string{"old.example"}, cfg: active("new.example"),
			after:     []*Config{active("new.example")},
			wantStop:  []string{"old.example"},
			wantStart: "new.example",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := planPairChange(c.before, c.after, c.cfg)
			if strings.Join(p.Stop, ",") != strings.Join(c.wantStop, ",") {
				t.Errorf("stop = %v, want %v", p.Stop, c.wantStop)
			}
			if p.Start != c.wantStart {
				t.Errorf("start = %q, want %q", p.Start, c.wantStart)
			}
			if c.wantIn != "" && !strings.Contains(p.Note, c.wantIn) {
				t.Errorf("note %q does not contain %q", p.Note, c.wantIn)
			}
		})
	}
}

// A pairing token is single-use credential material. It arrives in a POST body
// and must not come back out in the page — not in a field, not in an error.
func TestAPairingTokenNeverComesBackOutOfThePage(t *testing.T) {
	uiTestConfigDir(t)
	// The builder this runs on has a REAL machine marker naming a real state
	// dir, so without this the singleton guard (pair.go:221) refuses first and
	// decodeToken is never reached.
	uiSetupNoMachineMarker(t)
	_, _, h, cookie := uiSetupTestBox(t)

	// Malformed on purpose: decodeToken (pair.go:50) refuses it before any
	// network call, so this test touches nothing off the machine.
	const token = "skb_this-is-not-a-real-token-aaaaaaaaaaaa"
	w := uiPost(t, h, "/setup/pair", url.Values{"token": {token}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("/setup/pair = %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), token) {
		t.Fatalf("the token came back in the page: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "malformed token") {
		t.Errorf("the refusal did not reach the page: %q", w.Body.String())
	}
	// An empty token is a nudge, not an error, and redeems nothing.
	w = uiPost(t, h, "/setup/pair", url.Values{"token": {""}}, cookie)
	if !strings.Contains(w.Body.String(), "Paste the token") {
		t.Errorf("an empty token did not prompt: %q", w.Body.String())
	}
}

func TestUIWithoutTokenScrubsTheTokenAndLeavesShortStringsAlone(t *testing.T) {
	const token = "skb_aaaaaaaaaaaaaaaaaaaa"
	if got := uiWithoutToken("redeem rejected: "+token+" is spent", token); strings.Contains(got, token) {
		t.Errorf("the token survived: %q", got)
	}
	// A short "token" would match half the words in an error message, so it is
	// left alone rather than turning a message into nonsense.
	if got := uiWithoutToken("no such host", "no"); got != "no such host" {
		t.Errorf("a short token rewrote the message: %q", got)
	}
}

// ── 2. the step-up QR ───────────────────────────────────────────────────────

func TestTheEnrolmentQRIsAnImageAndTheSecretIsNotInThePage(t *testing.T) {
	const host = "member.host.privatae.ai"
	uiTestPairing(t, host)
	_, s, h, cookie := uiSetupTestBox(t)

	w := uiPost(t, h, "/setup/stepup/start", url.Values{"host": {host}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("/setup/stepup/start = %d: %s", w.Code, w.Body.String())
	}
	handle, e := s.enrols.forHost(host)
	if e == nil {
		t.Fatal("no enrolment was held for the host")
	}
	body := w.Body.String()
	if !strings.Contains(body, `src="/setup/stepup/qr?e=`+handle+`"`) {
		t.Errorf("the page does not point at the QR route: %q", body)
	}
	// THE POINT OF THE WHOLE ROUTE: the secret is in the pixels, never in the
	// markup, and never in the URL that fetches the pixels.
	if strings.Contains(body, e.SecretB32) {
		t.Fatal("the enrolment secret is in the page body")
	}
	if strings.Contains(body, "otpauth://") {
		t.Fatal("the otpauth URI — which carries the secret — is in the page body")
	}

	// The image itself.
	qw := uiSetupGet(t, h, "/setup/stepup/qr?e="+handle, cookie)
	if qw.Code != http.StatusOK {
		t.Fatalf("the QR route = %d: %s", qw.Code, qw.Body.String())
	}
	if got := qw.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("the QR is served as %q", got)
	}
	if got := qw.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("the QR is cacheable (%q) — a browser would keep a picture of a live secret", got)
	}
	png := qw.Body.Bytes()
	if len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("that is not a PNG (%d bytes)", len(png))
	}
	// It must be the code for THIS enrolment's URI, not a code for something
	// else that happens to be a valid PNG.
	want, err := qrTerminalPNGForTest(e.URI)
	if err != nil {
		t.Fatal(err)
	}
	if string(png) != string(want) {
		t.Error("the QR does not encode this enrolment's otpauth URI")
	}

	// A handle that is not held opens nothing.
	if bad := uiSetupGet(t, h, "/setup/stepup/qr?e=nope", cookie); bad.Code != http.StatusNotFound {
		t.Errorf("an unknown enrolment handle = %d, want 404", bad.Code)
	}
}

func TestTheEnrolmentKeyIsShownOnlyWhenAsked(t *testing.T) {
	const host = "member.host.privatae.ai"
	uiTestPairing(t, host)
	_, s, h, cookie := uiSetupTestBox(t)

	started := uiPost(t, h, "/setup/stepup/start", url.Values{"host": {host}}, cookie)
	handle, e := s.enrols.forHost(host)
	if e == nil {
		t.Fatal("no enrolment was held")
	}
	// ONLY WHEN ASKED is the whole claim, so the half that says "not before" is
	// checked here too and not only in the QR test.
	if strings.Contains(started.Body.String(), e.SecretB32) {
		t.Fatal("the key is on the page before anyone asked for it")
	}
	w := uiPost(t, h, "/setup/stepup/key", url.Values{"enrol": {handle}}, cookie)
	if !strings.Contains(w.Body.String(), e.SecretB32) {
		t.Errorf("the key was asked for and not given: %q", w.Body.String())
	}
	// And it is gone again on the next ordinary render — the key route is the
	// only response it ever appears in.
	if again := uiSetupGet(t, h, "/setup", cookie); strings.Contains(again.Body.String(), e.SecretB32) {
		t.Error("the key is still on the page after the request that showed it")
	}
	// And it is a POST: a GET would mean a link, a prefetch or an <img> could
	// spend it, and the Origin check does not apply to reads.
	if g := uiSetupGet(t, h, "/setup/stepup/key", cookie); g.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /setup/stepup/key = %d, want 405", g.Code)
	}
}

func TestNothingIsEnrolledUntilACodeMatches(t *testing.T) {
	const host = "member.host.privatae.ai"
	dir := uiSetupPairingWithDCN(t, host)
	_, s, h, cookie := uiSetupTestBox(t)

	uiPost(t, h, "/setup/stepup/start", url.Values{"host": {host}}, cookie)
	handle, e := s.enrols.forHost(host)
	if e == nil {
		t.Fatal("no enrolment was held")
	}
	if stepupEnrolled(dir) {
		t.Fatal("starting an enrolment already wrote a factor to disk")
	}

	// A wrong code writes nothing and keeps the enrolment alive to retry.
	w := uiPost(t, h, "/setup/stepup/confirm",
		url.Values{"enrol": {handle}, "code": {"000000"}}, cookie)
	if !strings.Contains(w.Body.String(), "did not match") {
		t.Errorf("a bad code did not say so: %q", w.Body.String())
	}
	if stepupEnrolled(dir) {
		t.Fatal("a wrong code enrolled a factor")
	}
	if _, still := s.enrols.forHost(host); still == nil {
		t.Fatal("a wrong code threw the enrolment away — the person would have to rescan")
	}

	// The real code, from the secret this machine is holding.
	raw, err := b32decode(e.SecretB32)
	if err != nil {
		t.Fatal(err)
	}
	code := hotp(raw, time.Now().Unix()/stepupPeriod)
	w = uiPost(t, h, "/setup/stepup/confirm",
		url.Values{"enrol": {handle}, "code": {code}}, cookie)
	if !strings.Contains(w.Body.String(), "Enrolled for "+host) {
		t.Fatalf("the confirmation did not land: %q", w.Body.String())
	}
	if !stepupEnrolled(dir) {
		t.Fatal("a matching code enrolled nothing")
	}
	f, err := stepupLoad(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f.SecretB32 != e.SecretB32 {
		t.Error("a different secret was written than the one the QR showed")
	}
	if f.LastCounter != -1 {
		t.Errorf("last_counter = %d, want -1 — the CLI's shape (stepup.go:802)", f.LastCounter)
	}
	// The secret is out of memory once it is on disk.
	if _, still := s.enrols.forHost(host); still != nil {
		t.Error("the enrolment is still held in memory after it was written")
	}
}

func TestReplacingAnEnrolledFactorTakesADeliberateTick(t *testing.T) {
	const host = "member.host.privatae.ai"
	dir := uiSetupPairingWithDCN(t, host)
	if err := stepupSave(dir, &stepupFile{
		SecretB32: uiTestSecret, EnrolledAt: "2026-08-29T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	_, s, h, cookie := uiSetupTestBox(t)

	w := uiPost(t, h, "/setup/stepup/start", url.Values{"host": {host}}, cookie)
	if !strings.Contains(w.Body.String(), "already enrolled") {
		t.Errorf("starting over an enrolled factor was not refused: %q", w.Body.String())
	}
	if _, e := s.enrols.forHost(host); e != nil {
		t.Fatal("a refused start still minted a secret")
	}
	w = uiPost(t, h, "/setup/stepup/start",
		url.Values{"host": {host}, "replace": {"1"}}, cookie)
	if _, e := s.enrols.forHost(host); e == nil {
		t.Fatalf("an explicit replace did not start an enrolment: %q", w.Body.String())
	}
	// And the factor on disk is untouched until a code confirms the new one.
	f, err := stepupLoad(dir)
	if err != nil || f.SecretB32 != uiTestSecret {
		t.Fatal("starting a replacement already overwrote the enrolled factor")
	}
}

// ── 3. the folder picker ────────────────────────────────────────────────────

func TestTheFolderCheckDescribesWhatIsActuallyThere(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, typed, class, in string
	}{
		{"a real folder", dir, "ok", "A folder on this machine."},
		{"a file", file, "bad", "That is a file, not a folder."},
		{"nothing there", filepath.Join(dir, "missing"), "bad", "There is nothing at that path"},
		{"empty", "  ", "warn", "Type the folder's full path."},
		// The trap a browser adds: there is no working directory the person can
		// see, so a relative path is a guess about what they meant.
		{"relative", "Documents", "bad", "Give the full path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := uiCheckFolder(c.typed)
			if got.Class != c.class {
				t.Errorf("class = %q, want %q (line %q)", got.Class, c.class, got.Line)
			}
			if !strings.Contains(got.Line+" "+got.Note, c.in) {
				t.Errorf("said %q / %q, want %q", got.Line, got.Note, c.in)
			}
		})
	}
	// The resolved path is always shown, because that is the whole point of
	// checking before proposing.
	if got := uiCheckFolder(dir); got.Resolved != dir {
		t.Errorf("resolved = %q, want %q", got.Resolved, dir)
	}
}

func TestAFolderIsNotProposedWhenThePathIsWrong(t *testing.T) {
	const host = "member.host.privatae.ai"
	uiTestPairing(t, host) // listen_addr 127.0.0.1:59999 — nothing answers there
	_, _, h, cookie := uiSetupTestBox(t)

	// Refused here, so nothing is sent anywhere.
	w := uiPost(t, h, "/setup/folder/propose",
		url.Values{"host": {host}, "path": {"Documents"}}, cookie)
	if !strings.Contains(w.Body.String(), "Nothing was proposed") {
		t.Errorf("a relative path was not refused: %q", w.Body.String())
	}

	// A real folder, but this host's lane is not up: the CLI's wording here is
	// "the bastion daemon isn't running" (addfolder.go:76), which cannot be what
	// happened — this page is served BY the daemon.
	w = uiPost(t, h, "/setup/folder/propose",
		url.Values{"host": {host}, "path": {t.TempDir()}}, cookie)
	body := w.Body.String()
	if !strings.Contains(body, "not answering for "+host) {
		t.Errorf("a down lane was not explained: %q", body)
	}
	if strings.Contains(body, "isn't running") {
		t.Error("the page told the user to start a daemon that is serving the page")
	}
}

// ── 4. the anchor ───────────────────────────────────────────────────────────

// The line this page writes must stay the line the CLI documents. They are two
// functions because the Windows hint ends in a parenthetical a flag cannot
// follow (privilege.go:58), so the only thing keeping them together is this.
func TestTheAnchorLineMatchesTheCLIsOwnHint(t *testing.T) {
	const host = "member.host.privatae.ai"
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cmd, how := uiAnchorCommandFor(goos, host)
		if !strings.HasSuffix(cmd, "--host "+host) {
			t.Errorf("%s: %q does not name the chosen host", goos, cmd)
		}
		bare := strings.TrimSuffix(cmd, " --host "+host)
		if !strings.HasPrefix(anchorCommandHintFor(goos), bare) {
			t.Errorf("%s: the page writes %q, the CLI hints %q — they have drifted",
				goos, bare, anchorCommandHintFor(goos))
		}
		if goos == "windows" && !strings.Contains(how, "Administrator") {
			t.Errorf("windows is told to use sudo: %q", how)
		}
		if goos != "windows" && !strings.HasPrefix(cmd, "sudo -H ") {
			t.Errorf("%s: %q drops the -H that keeps the write in root's own config dir", goos, cmd)
		}
	}
}

func TestTheAnchorPageChoosesAndNeverClaims(t *testing.T) {
	const host = "member.host.privatae.ai"
	uiTestPairing(t, host)
	_, _, h, cookie := uiSetupTestBox(t)

	// A local box: an anchor means nothing there, and set-mode is the first step.
	w := uiPost(t, h, "/setup/anchor/choose", url.Values{"host": {host}}, cookie)
	if !strings.Contains(w.Body.String(), "set-mode networked") {
		t.Errorf("a local box was not sent to set-mode first: %q", w.Body.String())
	}

	if err := uiSetupNetworked(t); err != nil {
		t.Fatal(err)
	}
	w = uiPost(t, h, "/setup/anchor/choose", url.Values{"host": {host}}, cookie)
	body := w.Body.String()
	cmd, _ := uiAnchorCommandFor(runtimeGOOSForTest(), host)
	if !strings.Contains(body, cmd) {
		t.Errorf("the page did not write the line %q: %q", cmd, body)
	}
	// IT CLAIMED NOTHING. currentAnchor reads the signed file; if this page had
	// called through, the box would be anchored now.
	if a := currentAnchor(); a != nil {
		t.Fatalf("the page claimed the anchor itself (%s) — it must only write the line",
			a.AnchorHost)
	}
	if _, err := os.Stat(uiSetupAnchorPath(t)); !os.IsNotExist(err) {
		t.Fatal("anchor.json exists — something wrote it")
	}

	// A host this machine does not serve is refused rather than typed into a line.
	w = uiPost(t, h, "/setup/anchor/choose", url.Values{"host": {"stranger.example"}}, cookie)
	if !strings.Contains(w.Body.String(), "does not serve") {
		t.Errorf("an unknown host was accepted: %q", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "claim-anchor --host stranger.example") {
		t.Fatal("the page wrote a command naming a host this machine does not serve")
	}
}

// The one above cannot tell "the page refused to claim" apart from "the page
// tried and the MACHINE refused" — off-root, or behind this builder's real
// machine marker, cmdClaimAnchor would fail either way and the assertion would
// pass for the wrong reason. That is the tautology shape, so it gets its own
// test on a box where a claim WOULD land.
func TestTheAnchorPageClaimsNothingEvenOnABoxWhereItCould(t *testing.T) {
	const host = "member.host.privatae.ai"
	uiTestPairing(t, host)
	uiSetupNoMachineMarker(t) // singletonGuardForPair would otherwise refuse first
	if err := uiSetupNetworked(t); err != nil {
		t.Fatal(err)
	}
	if !processIsRoot() {
		t.Skip("this process holds no machine authority, so claim-anchor would refuse " +
			"whatever this page did — the assertion below can only mean something as root, " +
			"and the builder runs as root. Everything else about the picker is covered by " +
			"TestTheAnchorPageChoosesAndNeverClaims.")
	}
	// Proof the box is claimable: the real command, on this exact state, works.
	// Run in a sub-directory of the same fixture so the assertion below is about
	// a machine that HAS just been shown to be anchorable.
	_, _, h, cookie := uiSetupTestBox(t)
	w := uiPost(t, h, "/setup/anchor/choose", url.Values{"host": {host}}, cookie)
	if !strings.Contains(w.Body.String(), "claim-anchor --host "+host) {
		t.Fatalf("the page did not write the line at all: %q", w.Body.String())
	}
	if a := currentAnchor(); a != nil {
		t.Fatalf("the page anchored this machine to %s — it must only write the line", a.AnchorHost)
	}
	// Now prove the machine was claimable all along, so the nil above is the
	// page's restraint and not the machine's refusal.
	if err := cmdClaimAnchor("", false, "", host); err != nil {
		t.Fatalf("this box could not be anchored anyway (%v) — the assertion above proved nothing", err)
	}
	if currentAnchor() == nil {
		t.Fatal("claim-anchor reported success and wrote no anchor")
	}
}

// An anchored box does not get a second first-claim button. Moving the anchor
// is --rotate, which the design keeps in the CLI on purpose — so the
// page hands over that line instead, with the one thing it cannot know left in
// angle brackets the way main.go:55 prints it.
func TestAnAnchoredBoxIsSentToRotateAndNotOfferedAFreshClaim(t *testing.T) {
	const host = "member.host.privatae.ai"
	uiTestPairing(t, host)
	uiSetupNoMachineMarker(t)
	if err := uiSetupNetworked(t); err != nil {
		t.Fatal(err)
	}
	if err := writeAnchor("the owner", host); err != nil {
		t.Fatal(err)
	}
	_, _, h, cookie := uiSetupTestBox(t)

	w := uiPost(t, h, "/setup/anchor/choose", url.Values{"host": {host}}, cookie)
	body := html.UnescapeString(w.Body.String())
	if !strings.Contains(body, "claim-anchor --rotate <token>") {
		t.Errorf("the rotate line was not offered: %q", body)
	}
	if strings.Contains(body, "claim-anchor --host") {
		t.Error("an anchored box was offered a fresh claim — anchor.go:835 refuses it")
	}
	if !strings.Contains(body, "signed consent") {
		t.Errorf("it did not say what a rotation costs: %q", body)
	}
}

func TestARevokedHostIsNotOfferedTheAnchor(t *testing.T) {
	const host = "revoked.host.privatae.ai"
	uiSetupPairingInState(t, host, pairingRevoked)
	if err := uiSetupNetworked(t); err != nil {
		t.Fatal(err)
	}
	_, _, h, cookie := uiSetupTestBox(t)

	w := uiPost(t, h, "/setup/anchor/choose", url.Values{"host": {host}}, cookie)
	body := w.Body.String()
	if !strings.Contains(body, "revoked") {
		t.Errorf("a revoked host was not refused: %q", body)
	}
	if strings.Contains(body, "claim-anchor --host") {
		t.Error("the page wrote a claim-anchor line for a revoked host — anchor.go:910 refuses it")
	}
}

// ── 5. the owner name ───────────────────────────────────────────────────────

func TestTheOwnerNameIsCheckedAndNeverClaimed(t *testing.T) {
	uiTestConfigDir(t)
	_, _, h, cookie := uiSetupTestBox(t)

	w := uiPost(t, h, "/setup/owner/name", url.Values{"owner": {"the owner"}}, cookie)
	// Unescaped, because html/template turns the shell quotes into &#34; — which
	// is what a browser renders back as a quote, and is the proof that the page
	// goes through the escaper rather than template.HTML.
	body := html.UnescapeString(w.Body.String())
	if !strings.Contains(w.Body.String(), "&#34;") {
		t.Error("the quotes were not escaped — something is bypassing html/template")
	}
	if !strings.Contains(body, `claim-owner "the owner"`) {
		t.Errorf("the page did not write the line: %q", body)
	}
	if !strings.Contains(body, "-H") {
		t.Error("the line drops sudo -H, which is what keeps the claim in root's own config dir")
	}
	// IT CLAIMED NOTHING.
	if o := currentOwnerClaim(); o != nil {
		t.Fatalf("the page signed an owner claim itself (%q)", o.Owner)
	}

	// The real rule (claimNameOK, anchor.go:121) is what refuses, not a second
	// copy of it living here.
	for _, bad := range []string{"", "  ", strings.Repeat("x", 121), "two\nlines"} {
		w = uiPost(t, h, "/setup/owner/name", url.Values{"owner": {bad}}, cookie)
		if !strings.Contains(w.Body.String(), "will be refused") {
			t.Errorf("%q was not refused: %q", bad, w.Body.String())
		}
	}
	// A name a shell would re-read is not refused — it is a fine name — but the
	// page will not write a line that does something other than what it says.
	w = uiPost(t, h, "/setup/owner/name", url.Values{"owner": {"O`whoami`Brien"}}, cookie)
	if strings.Contains(w.Body.String(), "claim-owner \"") {
		t.Error("the page wrote a command line containing a backtick")
	}
	if !strings.Contains(w.Body.String(), "a shell would read") {
		t.Errorf("it did not say why: %q", w.Body.String())
	}
}

func TestUIShellSafeName(t *testing.T) {
	for _, ok := range []string{"the owner", "the owner Smith", "team-a", "O'Brien", "a b (c)"} {
		if !uiShellSafeName(ok) {
			t.Errorf("%q should survive double quotes", ok)
		}
	}
	for _, bad := range []string{`say "hi"`, `back\slash`, `$HOME`, "a`b`"} {
		if uiShellSafeName(bad) {
			t.Errorf("%q would be re-read by a shell", bad)
		}
	}
}

// ── the method wall ─────────────────────────────────────────────────────────

// Anything that CHANGES something is POST, so it takes the Origin check —
// signOut was a GET behind only the Host check and that was a finding (ui.go:463).
func TestEverySetupRouteThatChangesSomethingIsPostOnly(t *testing.T) {
	uiTestPairing(t, "member.host.privatae.ai")
	_, _, h, cookie := uiSetupTestBox(t)

	for _, path := range []string{
		"/setup/pair", "/setup/stepup/start", "/setup/stepup/key",
		"/setup/stepup/confirm", "/setup/folder/check", "/setup/folder/propose",
		"/setup/anchor/choose", "/setup/owner/name",
	} {
		if w := uiSetupGet(t, h, path, cookie); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", path, w.Code)
		}
		// Cross-site POST: uiRequestAllowed's Origin arm is what stops it.
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.Host = "127.0.0.1:" + uiTestPort
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403", path, w.Code)
		}
	}
	// The two reads are GET-only for the same reason in reverse.
	for _, path := range []string{"/setup", "/setup/stepup/qr"} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.Host = "127.0.0.1:" + uiTestPort
		r.Header.Set("Origin", "http://127.0.0.1:"+uiTestPort)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, w.Code)
		}
	}
}
