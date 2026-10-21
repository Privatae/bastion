package main

// Approving from the page, end to end with a real TOTP code.
//
// This is the flow the whole UI was justified by: a host asks for something, the
// request sits in a file, and until now the only way to answer was to know to
// type `privatae-bastion approvals` at a terminal that on Windows may not exist.
// So it is worth testing against the real step-up code path rather than a stub —
// the thing that must be true is that the SAME verification the CLI performs is
// what stands between the host's request and its approval.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// base32 of "0123456789012345", the same fixture stepup_test.go uses.
const uiTestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// uiTestApprovalBox writes a pairing that is enrolled for step-up and has one
// pending request, and returns its DCN dir and the request id.
// uiTestRecently is a timestamp for a request that is WAITING RIGHT NOW.
//
// It exists because three fixtures hardcoded a literal timestamp and
// stepup.go:569 drops any request older than stepupRequestTTL (24h,
// stepup.go:62). Those tests therefore passed for exactly one day after
// somebody typed the date in, and then failed on every machine for ever —
// measured 32 hours after the stamp, with six approvals tests red and nothing
// in the code wrong.
//
// A fixture that encodes "now" as a literal is a test with an expiry date on
// it. TestNoFixtureHardcodesAMomentInTime keeps it from coming back.
func uiTestRecently() string {
	return time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
}

func uiTestApprovalBox(t *testing.T, host string) (dcn, id string) {
	t.Helper()
	uiTestConfigDir(t)
	dcn = filepath.Join(t.TempDir(), "dcn")
	if err := os.MkdirAll(dcn, 0o700); err != nil {
		t.Fatal(err)
	}
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pd, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"host_name":"` + host + `","listen_addr":"127.0.0.1:59999",` +
		`"state":"active","dcn_dir":` + jsonQuote(dcn) + `}`
	if err := os.WriteFile(filepath.Join(pd, host+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stepupSave(dcn, &stepupFile{
		SecretB32: uiTestSecret, EnrolledAt: "2026-08-29T00:00:00Z", LastCounter: -1,
	}); err != nil {
		t.Fatal(err)
	}
	id = "abcdef0123456789"
	if err := requestsSave(dcn, map[string]stepupRequest{
		id: {
			Purpose: "dcn_store_grant|Documents|read",
			Details: map[string]any{
				"kind": "dcn_store_grant", "root": "~/Documents",
				"mask": []any{"read", "index"}, "excludes": []any{".ssh", ".env"},
				"sweep": "nightly", "ttl_days": float64(30),
				"display_name": "Documents",
			},
			At:    uiTestRecently(),
			State: "pending",
		},
	}); err != nil {
		t.Fatal(err)
	}
	return dcn, id
}

func jsonQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func uiCurrentCode(t *testing.T) string {
	t.Helper()
	raw, err := b32decode(uiTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	return hotp(raw, time.Now().Unix()/stepupPeriod)
}

func uiPost(t *testing.T, h http.Handler, path string, form url.Values, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Host = "127.0.0.1:" + uiTestPort
	r.Header.Set("Origin", "http://127.0.0.1:"+uiTestPort)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func uiSignedIn(t *testing.T, u *uiServer) string {
	t.Helper()
	tok, err := u.sessions.mint()
	if err != nil {
		t.Fatal(err)
	}
	return uiCookieName + "=" + tok
}

func TestAPendingRequestIsShownAndCanBeApproved(t *testing.T) {
	const host = "member.host.privatae.ai"
	dcn, id := uiTestApprovalBox(t, host)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	// 1. It is on the page, above everything else, in the box's own words.
	r := uiReq(http.MethodGet, "/fragments/status")
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := w.Body.String()
	for _, want := range []string{"Waiting for you", host, id[:8], `hx-post="/approve"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the fragment is missing %q", want)
		}
	}
	if i, j := strings.Index(body, "Waiting for you"), strings.Index(body, `class="state`); i < 0 || j < 0 || i > j {
		t.Error("the approval is not above the running-state block — it is the only " +
			"thing on this page that is waiting on the person")
	}
	// The FULL id must be what the form posts; the short one is for reading.
	if !strings.Contains(body, `value="`+id+`"`) {
		t.Error("the form does not carry the full request id")
	}

	// 2. A wrong code changes nothing.
	w = uiPost(t, h, "/approve", url.Values{
		"host": {host}, "id": {id}, "code": {"000000"}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("approve with a bad code = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Not approved") {
		t.Errorf("a refused code did not say so: %q", w.Body.String())
	}
	if got := requestsLoad(dcn)[id].State; got != "pending" {
		t.Fatalf("a bad code moved the request to %q", got)
	}

	// 3. An empty code is a nudge, not an error, and still changes nothing.
	w = uiPost(t, h, "/approve", url.Values{"host": {host}, "id": {id}, "code": {""}}, cookie)
	if !strings.Contains(w.Body.String(), "Enter the code") {
		t.Errorf("an empty code did not prompt: %q", w.Body.String())
	}
	if got := requestsLoad(dcn)[id].State; got != "pending" {
		t.Fatalf("an empty code moved the request to %q", got)
	}

	// 4. The real code approves it.
	w = uiPost(t, h, "/approve", url.Values{
		"host": {host}, "id": {id}, "code": {uiCurrentCode(t)}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("approve = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Approved") {
		t.Errorf("approval was not confirmed on screen: %q", w.Body.String())
	}
	if got := requestsLoad(dcn)[id].State; got != "approved" {
		t.Fatalf("request state is %q, want approved", got)
	}
	if requestsLoad(dcn)[id].Approval == "" {
		t.Error("no approval token was issued — the host has nothing to present")
	}
	// The card must be GONE from the response, not still sitting there: the
	// handler re-reads state rather than patching a remembered list.
	if strings.Contains(w.Body.String(), "Waiting for you") {
		t.Error("the answered request is still on screen")
	}
}

// A host that is NEWER than this bastion can ask for something this version has
// never heard of. describeRequest then returns "(unknown request)" — which the
// CLI prints and moves on from. On a page, that would be a green Approve button
// next to text that says nothing, for a request that came from the far side of
// a tunnel. Caught by looking at the rendered page rather than the code.
func TestAnUndescribableRequestDoesNotGetAPlainApprove(t *testing.T) {
	const host = "member.host.privatae.ai"
	dcn, id := uiTestApprovalBox(t, host)
	// Overwrite with a kind from a future version.
	if err := requestsSave(dcn, map[string]stepupRequest{
		id: {
			Purpose: "something_new|x",
			Details: map[string]any{"kind": "something_this_version_never_heard_of"},
			At:      uiTestRecently(), State: "pending",
		},
	}); err != nil {
		t.Fatal(err)
	}
	u := uiTestServer(t)
	cookie := uiSignedIn(t, u)
	r := uiReq(http.MethodGet, "/fragments/status")
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	u.handler().ServeHTTP(w, r)
	body := w.Body.String()

	if !strings.Contains(body, "cannot tell you what is being asked for") {
		t.Error("the page does not say that it cannot describe the request")
	}
	if !strings.Contains(body, `class="approval unreadable"`) {
		t.Error("the card is not marked unreadable, so it looks like any other")
	}
	// The primary (green) button must be Deny, not Approve.
	deny, approve := strings.Index(body, `class="go" type="submit">Deny`),
		strings.Index(body, `class="go" type="submit">Approve`)
	if deny < 0 {
		t.Error("Deny is not the primary action on an undescribable request")
	}
	if approve >= 0 {
		t.Error("Approve is still the primary action beside text that says nothing")
	}

	// It must still be POSSIBLE to approve — this is a warning, not a wall. A
	// machine that cannot be told "yes" would strand a fleet mid-upgrade.
	w = uiPost(t, u.handler(), "/approve", url.Values{
		"host": {host}, "id": {id}, "code": {uiCurrentCode(t)}}, cookie)
	if got := requestsLoad(dcn)[id].State; got != "approved" {
		t.Fatalf("an informed approval was blocked: state %q", got)
	}
}

func TestDenyingNeedsNoCode(t *testing.T) {
	const host = "member.host.privatae.ai"
	dcn, id := uiTestApprovalBox(t, host)
	u := uiTestServer(t)
	cookie := uiSignedIn(t, u)

	// Refusing is always the safe direction, and demanding a second factor to
	// say NO would train people to reach for Approve instead.
	w := uiPost(t, u.handler(), "/deny", url.Values{"host": {host}, "id": {id}}, cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Denied") {
		t.Fatalf("deny = %d: %s", w.Code, w.Body.String())
	}
	if got := requestsLoad(dcn)[id].State; got != "denied" {
		t.Fatalf("request state is %q, want denied", got)
	}
}

func TestApprovingSomethingThisMachineDoesNotServe(t *testing.T) {
	const host = "member.host.privatae.ai"
	dcn, id := uiTestApprovalBox(t, host)
	u := uiTestServer(t)
	cookie := uiSignedIn(t, u)

	// The posted host is looked UP among this machine's pairings, never joined
	// onto a path. A handler that builds a directory out of a posted string is
	// how a local UI becomes a file-system reach.
	for _, bad := range []string{"someone-else.privatae.ai", "../../etc", ""} {
		w := uiPost(t, u.handler(), "/approve", url.Values{
			"host": {bad}, "id": {id}, "code": {uiCurrentCode(t)}}, cookie)
		if !strings.Contains(w.Body.String(), "does not serve") {
			t.Errorf("host %q was not refused: %q", bad, w.Body.String())
		}
	}
	if got := requestsLoad(dcn)[id].State; got != "pending" {
		t.Fatalf("the real request was touched: %q", got)
	}
}

func TestApprovalRoutesNeedASessionAndAnOrigin(t *testing.T) {
	const host = "member.host.privatae.ai"
	dcn, id := uiTestApprovalBox(t, host)
	u := uiTestServer(t)
	h := u.handler()
	code := uiCurrentCode(t)
	form := url.Values{"host": {host}, "id": {id}, "code": {code}}

	// No session.
	w := uiPost(t, h, "/approve", form, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("approve with no session = %d, want 401", w.Code)
	}

	// A session, but posted from another site: SameSite would normally stop the
	// cookie ever arriving, and this is the check for when it does not.
	cookie := uiSignedIn(t, u)
	r := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	r.Host = "127.0.0.1:" + uiTestPort
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site approve = %d, want 403", w.Code)
	}

	if got := requestsLoad(dcn)[id].State; got != "pending" {
		t.Fatalf("an unauthorised request was approved: %q", got)
	}
}
