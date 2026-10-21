package main

// The approvals popup, end to end against the real device code: the ask is filed
// the way a host files it (deviceNewRequest), answered through the page's own
// routes, and checked in the store the host reads back from (device_status).

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uiTestDevice makes this (isolated) machine an approval device and returns a
// function that files one ask for `op` on box-7, as a host would.
func uiTestDevice(t *testing.T) func(op string) string {
	t.Helper()
	uiTestConfigDir(t)
	if _, err := deviceInit(); err != nil {
		t.Fatal(err)
	}
	return func(op string) string {
		t.Helper()
		id, err := deviceNewRequest(map[string]any{"kind": "mgmt_op", "op": op, "server": "box-7", "args": []any{}})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
}

func uiGet(t *testing.T, h http.Handler, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	r := uiReq(http.MethodGet, path)
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func deviceState(t *testing.T, id string) deviceRequest {
	t.Helper()
	deviceMu.Lock()
	defer deviceMu.Unlock()
	return deviceRequestsLoad()[id]
}

func TestTheApprovalsPopupShowsADeviceAskAndApprovesIt(t *testing.T) {
	file := uiTestDevice(t)
	id := file("ctx_del")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	// The full page and its fragment both carry the ask, in the device's words.
	for _, path := range []string{"/approvals", "/fragments/approvals"} {
		w := uiGet(t, h, path, cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, w.Code)
		}
		body := w.Body.String()
		for _, want := range []string{"Waiting for your approval", "box-7", id[:8],
			`hx-post="/device/approve"`, `hx-post="/device/deny"`, `value="` + id + `"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s is missing %q", path, want)
			}
		}
		// One ask: no "approve all" — a single card has its own button.
		if strings.Contains(body, "/device/approve-shown") {
			t.Errorf("%s offers approve-all for a single ask", path)
		}
	}

	w := uiPost(t, h, "/device/approve", url.Values{"id": {id}}, cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Approved") {
		t.Fatalf("approve = %d %q", w.Code, w.Body.String())
	}
	r := deviceState(t, id)
	if r.State != "approved" || r.Approval == "" {
		t.Fatalf("the ask is %q with approval %q — the host has nothing to collect", r.State, r.Approval)
	}
	// It is a real device approval: signed by THIS device's key over the purpose
	// the device derived when the ask was filed — not something the page made up.
	var a deviceApproval
	if err := json.Unmarshal([]byte(r.Approval), &a); err != nil {
		t.Fatal(err)
	}
	key, _ := deviceKeyLoad()
	pub, _ := base64.StdEncoding.DecodeString(key.Pub)
	sig, _ := base64.StdEncoding.DecodeString(a.Sig)
	if a.Purpose != r.Purpose || a.Key != key.Pub || a.Uses != 1 ||
		!ed25519.Verify(ed25519.PublicKey(pub), a.canonical(), sig) {
		t.Fatalf("the approval is not this device's signature over the ask's purpose: %+v", a)
	}
	if strings.Contains(w.Body.String(), `value="`+id+`"`) {
		t.Error("the answered ask is still on screen")
	}
	// Answered twice is refused, not signed twice.
	w = uiPost(t, h, "/device/approve", url.Values{"id": {id}}, cookie)
	if !strings.Contains(w.Body.String(), "Not approved") {
		t.Errorf("a second approve of the same ask was not refused: %q", w.Body.String())
	}
}

func TestDenyingInThePopupIsFinalForTheDay(t *testing.T) {
	file := uiTestDevice(t)
	id := file("ctx_del")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	w := uiPost(t, h, "/device/deny", url.Values{"id": {id}}, cookie)
	if !strings.Contains(w.Body.String(), "Denied") {
		t.Fatalf("deny = %q", w.Body.String())
	}
	if got := deviceState(t, id).State; got != "denied" {
		t.Fatalf("the ask is %q after deny", got)
	}
	// The same ask cannot be filed again — the rule the host's card reads as a
	// final no (the device's refusal words).
	if _, err := deviceNewRequest(map[string]any{"kind": "mgmt_op", "op": "ctx_del", "server": "box-7", "args": []any{}}); err == nil ||
		!strings.HasPrefix(err.Error(), "you refused this on your device") {
		t.Fatalf("a denied ask was re-filed: %v", err)
	}
}

// "Approve all" signs the asks the page DREW and nothing that arrived since —
// `device-approve all`'s rule, held on the page.
func TestApproveAllSignsOnlyWhatThePageShowed(t *testing.T) {
	file := uiTestDevice(t)
	a := file("ctx_del")
	b := file("harness:run")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	body := uiGet(t, h, "/fragments/approvals", cookie).Body.String()
	if !strings.Contains(body, `hx-post="/device/approve-shown"`) || !strings.Contains(body, "Approve all 2 shown") {
		t.Fatalf("two asks, and no approve-all: %q", body)
	}
	late := file("model:drop") // filed after the page was drawn

	w := uiPost(t, h, "/device/approve-shown", url.Values{"id": {a, b}}, cookie)
	out := w.Body.String()
	if !strings.Contains(out, "Approved 2") || !strings.Contains(out, "1 arrived after you looked") {
		t.Fatalf("approve-shown said %q", out)
	}
	for _, id := range []string{a, b} {
		if got := deviceState(t, id).State; got != "approved" {
			t.Fatalf("a shown ask is %q", got)
		}
	}
	if got := deviceState(t, late).State; got != "pending" {
		t.Fatalf("an ask filed after the page was drawn was %q — approve-all signed what nobody read", got)
	}
	// It is still on screen to be read.
	if !strings.Contains(out, `value="`+late+`"`) {
		t.Error("the late ask is not shown for the person to read")
	}
}

func TestApproveAllSignsNothingItWasNotHanded(t *testing.T) {
	file := uiTestDevice(t)
	a := file("ctx_del")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	// No ids: nothing.
	w := uiPost(t, h, "/device/approve-shown", url.Values{}, cookie)
	if !strings.Contains(w.Body.String(), "Nothing was shown") || deviceState(t, a).State != "pending" {
		t.Fatalf("an empty approve-all acted: %q", w.Body.String())
	}
	// An id that is not an ask here: nothing, and the real ask untouched.
	w = uiPost(t, h, "/device/approve-shown", url.Values{"id": {"not-an-ask"}}, cookie)
	if deviceState(t, a).State != "pending" {
		t.Fatalf("an unrelated id approved a real ask: %q", w.Body.String())
	}
}

func TestTheApprovalsRoutesAreGuarded(t *testing.T) {
	file := uiTestDevice(t)
	id := file("ctx_del")
	u := uiTestServer(t)
	h := u.handler()

	// No session: the page says nothing about the machine or the ask.
	for _, path := range []string{"/approvals", "/fragments/approvals", "/fragments/approvals-news"} {
		w := uiGet(t, h, path, "")
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "box-7") {
			t.Errorf("GET %s without a session = %d %q", path, w.Code, w.Body.String())
		}
	}
	cookie := uiSignedIn(t, u)
	// A POST from another origin is refused before it reaches the device.
	for _, path := range []string{"/device/approve", "/device/deny", "/device/approve-shown"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"id": {id}}.Encode()))
		r.Host = "127.0.0.1:" + uiTestPort
		r.Header.Set("Origin", "http://evil.example")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s from another origin = %d", path, w.Code)
		}
		// GET changes nothing either.
		if w := uiGet(t, h, path+"?id="+id, cookie); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", path, w.Code)
		}
	}
	if got := deviceState(t, id).State; got != "pending" {
		t.Fatalf("a refused request moved the ask to %q", got)
	}
}

// The ticket link from the tray lands on the approvals page — and a ticket can
// land on nothing else we did not name, so the link is no open redirect.
func TestATicketLandsOnlyOnANamedPage(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	h := u.handler()
	for to, want := range map[string]string{
		"/approvals":           "/approvals",
		"":                     "/",
		"/given":               "/",
		"https://evil.example": "/",
		"//evil.example":       "/",
		"/approvals/../given":  "/",
	} {
		tk, err := u.tickets.mint()
		if err != nil {
			t.Fatal(err)
		}
		path := "/?k=" + tk
		if to != "" {
			path += "&to=" + url.QueryEscape(to)
		}
		w := uiGet(t, h, path, "")
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("to=%q landed %d %q, want %q", to, w.Code, w.Header().Get("Location"), want)
		}
	}
}

// A machine that is not the approval device shows no asks, even with a request
// file lying about — the device lane only answers where the key is.
func TestOnlyTheApprovalDeviceShowsAsks(t *testing.T) {
	uiTestConfigDir(t)
	p, err := deviceRequestsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	stray := map[string]deviceRequest{"deadbeefdeadbeef": {Purpose: "mgmt_op|ctx_del|box-7|x",
		Words: "delete things", Server: "box-7", At: uiTestRecently(), State: "pending"}}
	raw, _ := json.Marshal(stray)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := pendingDeviceApprovals(); len(got) != 0 {
		t.Fatalf("a machine with no device key listed %d asks", len(got))
	}
	u := uiTestServer(t)
	body := uiGet(t, u.handler(), "/fragments/approvals", uiSignedIn(t, u)).Body.String()
	if strings.Contains(body, "delete things") || !strings.Contains(body, "not your approval device") {
		t.Fatalf("the popup on a non-device machine said %q", body)
	}
}

// The front page tells the person asks are waiting and links to the popup.
func TestTheFrontPageLinksToWaitingAsks(t *testing.T) {
	file := uiTestDevice(t)
	file("ctx_del")
	u := uiTestServer(t)
	body := uiGet(t, u.handler(), "/fragments/status", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(body, `href="/approvals"`) || !strings.Contains(body, "waiting for your approval") {
		t.Fatalf("the front page does not point at the waiting ask: %q", body)
	}
}

// A step-up request on this machine is answered in the popup too, and the answer
// comes back into the popup rather than swapping the front page into it.
func TestAStepUpRequestIsAnsweredInThePopup(t *testing.T) {
	const host = "member.host.privatae.ai"
	dcn, id := uiTestApprovalBox(t, host)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	body := uiGet(t, h, "/fragments/approvals", cookie).Body.String()
	for _, want := range []string{"Waiting for your code on this machine", host, `hx-target="#approvals"`,
		`name="view" value="approvals"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the popup's step-up card is missing %q", want)
		}
	}
	w := uiPost(t, h, "/approve", url.Values{"host": {host}, "id": {id}, "code": {uiCurrentCode(t)},
		"view": {"approvals"}}, cookie)
	out := w.Body.String()
	if !strings.Contains(out, "Approved") || strings.Contains(out, `class="state`) {
		t.Fatalf("the popup's approve came back as %q", out)
	}
	if got := requestsLoad(dcn)[id].State; got != "approved" {
		t.Fatalf("request state %q", got)
	}
	// The front page's own card still answers into the front page.
	if b := uiGet(t, h, "/fragments/status", cookie).Body.String(); strings.Contains(b, `name="view"`) {
		t.Error("the front page's cards post as the popup")
	}
}

// The tray and the notification count both kinds, in the device's words, and a
// device ask can never be mistaken for a step-up id.
func TestTheTrayCountsDeviceAsks(t *testing.T) {
	file := uiTestDevice(t)
	id := file("ctx_del")
	s := collectUIStatus()
	pending := approvalsForNotice(s)
	if len(pending) != 1 || pending[0].ID != uiDeviceNoticeID+id || len(pending[0].Lines) == 0 {
		t.Fatalf("the notifier's list is %+v", pending)
	}
	n := approvalNoticeFor(pending)
	if !strings.Contains(n.Body, pending[0].Lines[0]) {
		t.Errorf("the notification does not say what is asked: %q", n.Body)
	}
	for n, want := range map[int]string{0: "No approvals waiting", 1: "1 approval waiting — open…",
		23: "23 approvals waiting — open…"} {
		if got := trayApprovalsLine(n); got != want {
			t.Errorf("trayApprovalsLine(%d) = %q, want %q", n, got, want)
		}
	}
}

// THE LIST STAYS STILL. Only the news line polls: a timer that redrew the list
// would move cards under the cursor and put a just-arrived ask into "approve
// all" before anyone read it.
func TestTheApprovalsListDoesNotRedrawItself(t *testing.T) {
	file := uiTestDevice(t)
	file("ctx_del")
	file("harness:run")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	for _, path := range []string{"/approvals", "/fragments/approvals"} {
		body := uiGet(t, h, path, cookie).Body.String()
		if n := strings.Count(body, "hx-trigger="); n != 1 {
			t.Fatalf("%s has %d timers, want exactly one (the news line)", path, n)
		}
		i := strings.Index(body, `id="approvals-news"`)
		if i < 0 {
			t.Fatalf("%s has no news line", path)
		}
		j := strings.Index(body, "hx-trigger=")
		k := strings.Index(body[i:], ">")
		if j < i || j > i+k {
			t.Fatalf("%s: the one timer is not on the news line", path)
		}
		if strings.Contains(body[:strings.Index(body, "<div id=\"approvals-news\"")+1], `hx-trigger="every`) {
			t.Fatalf("%s: something above the news line polls", path)
		}
	}
}

// The news line compares against EVERY id the list drew — device asks and this
// machine's own step-up requests — through the form its hx-include names. If
// either drifted, it would announce asks that are already on screen.
func TestTheNewsLineIsFedEveryDrawnID(t *testing.T) {
	const host = "member.host.privatae.ai"
	_, stepID := uiTestApprovalBox(t, host)
	if _, err := deviceInit(); err != nil {
		t.Fatal(err)
	}
	devID, err := deviceNewRequest(map[string]any{"kind": "mgmt_op", "op": "ctx_del", "server": "box-7", "args": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	u := uiTestServer(t)
	body := uiGet(t, u.handler(), "/fragments/approvals", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(body, `hx-include="#approvals-shown"`) || !strings.Contains(body, `<form id="approvals-shown"`) {
		t.Fatal("the news line's hx-include does not name the form of drawn ids")
	}
	form := body[strings.Index(body, `<form id="approvals-shown"`):]
	form = form[:strings.Index(form, "</form>")]
	for _, id := range []string{devID, stepID} {
		if !strings.Contains(form, `name="shown" value="`+id+`"`) {
			t.Errorf("the drawn-ids form is missing %s", id)
		}
	}
	// And with exactly those ids, the news line has nothing to say.
	q := url.Values{"shown": {devID, stepID}}
	if news := uiGet(t, u.handler(), "/fragments/approvals-news?"+q.Encode(), uiSignedIn(t, u)).Body.String(); strings.Contains(news, "arrived") {
		t.Fatalf("the news line announced what is already drawn: %q", news)
	}
}

// The news line says what changed since the list was drawn — and it never
// carries a control that signs anything.
func TestTheNewsLineSaysWhatChangedAndSignsNothing(t *testing.T) {
	file := uiTestDevice(t)
	a := file("ctx_del")
	b := file("harness:run")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	news := func(shown ...string) string {
		q := url.Values{"shown": shown}
		return uiGet(t, h, "/fragments/approvals-news?"+q.Encode(), cookie).Body.String()
	}
	if body := news(a, b); strings.Contains(body, "arrived") || strings.Contains(body, "Show them") {
		t.Fatalf("nothing changed and the news line spoke: %q", body)
	}
	c := file("model:drop")
	body := news(a, b)
	if !strings.Contains(body, "1 new request arrived") || !strings.Contains(body, `hx-get="/fragments/approvals"`) {
		t.Fatalf("a new ask was not announced: %q", body)
	}
	if strings.Contains(body, "/device/approve") || strings.Contains(body, c) {
		t.Fatalf("the news line carries the new ask or a control that signs: %q", body)
	}
	// Nor may it redraw the list from the poll by a side door.
	if strings.Contains(body, "hx-swap-oob") {
		t.Fatalf("the news line swaps content out of band: %q", body)
	}
	if err := deviceDeny(a); err != nil {
		t.Fatal(err)
	}
	if body := news(a, b, c); !strings.Contains(body, "1 was answered elsewhere or lapsed") {
		t.Fatalf("an ask answered at the console was not noticed: %q", body)
	}
}

// An ask answered at the console between the list and the click is skipped,
// and the rest of what was shown is still approved.
func TestApproveAllSkipsAnAskAnsweredElsewhere(t *testing.T) {
	file := uiTestDevice(t)
	a := file("ctx_del")
	b := file("harness:run")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	if err := deviceDeny(a); err != nil { // at the console, after the page drew both
		t.Fatal(err)
	}
	w := uiPost(t, h, "/device/approve-shown", url.Values{"id": {a, b}}, cookie)
	out := w.Body.String()
	if deviceState(t, b).State != "approved" {
		t.Fatalf("the still-pending shown ask was not approved: %q", out)
	}
	if deviceState(t, a).State != "denied" {
		t.Fatal("the console's deny was overwritten")
	}
	if !strings.Contains(out, "Approved 1") {
		t.Fatalf("approve-all said %q", out)
	}
	// The ask denied at the console was never in the pending list the loop walks,
	// so it is neither signed nor counted as a failure.
	if strings.Contains(out, "stopped") {
		t.Fatalf("approve-all stopped on an ask answered elsewhere: %q", out)
	}
}

// The race itself: an ask still pending when the list is read, answered at the
// console before its turn to be signed. It is skipped and counted; the next one
// is still signed.
func TestApproveAllSkipsAnAskAnsweredMidLoop(t *testing.T) {
	file := uiTestDevice(t)
	a := file("ctx_del")
	b := file("harness:run")
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)
	real := approveShownOne
	t.Cleanup(func() { approveShownOne = real })
	approveShownOne = func(id string) (string, error) {
		if id == a {
			if err := deviceDeny(a); err != nil { // the console answers first
				t.Fatal(err)
			}
		}
		return real(id)
	}
	out := uiPost(t, h, "/device/approve-shown", url.Values{"id": {a, b}}, cookie).Body.String()
	if deviceState(t, a).State != "denied" || deviceState(t, b).State != "approved" {
		t.Fatalf("a=%q b=%q after the mid-loop deny: %q", deviceState(t, a).State, deviceState(t, b).State, out)
	}
	if !strings.Contains(out, "Approved 1") || !strings.Contains(out, "1 had already been answered elsewhere") ||
		strings.Contains(out, "stopped") {
		t.Fatalf("approve-all said %q", out)
	}
}
