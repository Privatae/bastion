package main

// The tray beside a system service: when it starts (trayFor), what its logon
// entry runs (trayRunValue), and what its page does (uitray.go) with the pipe
// replaced by a recording fake. Every value here is invented.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func httpRec(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestTheTrayStartsPerPersonBesideAServiceAndNeverInIt(t *testing.T) {
	cases := []struct {
		goos               string
		asService, service bool
		cmd                string
		want               trayKind
		why                string
	}{
		{"windows", true, true, "run", trayNone, "the service runs in session 0: no desktop to put an icon on"},
		{"windows", false, true, "tray", trayPipe, "beside the service, each person's logon starts their own icon"},
		{"windows", true, true, "tray", trayNone, "the service itself never runs the tray verb's icon"},
		{"windows", false, true, "run", trayNone, "a second bastion beside the service gets no second icon"},
		{"windows", false, false, "run", trayInProcess, "a bastion run as the person keeps its own icon, as before"},
		{"windows", false, false, "tray", trayNone, "no service: the daemon's own icon is the tray"},
		{"linux", false, true, "tray", trayNone, "only Windows has a tray"},
		{"darwin", false, false, "run", trayNone, "only Windows has a tray"},
	}
	for _, c := range cases {
		if got := trayFor(c.goos, c.asService, c.service, c.cmd); got != c.want {
			t.Errorf("%s as-service=%v service=%v %s: got %d, want %d — %s",
				c.goos, c.asService, c.service, c.cmd, got, c.want, c.why)
		}
	}
	// The logon entry runs the service's own program, quoted for the space in
	// Program Files, with the tray verb.
	if got := trayRunValue(`C:\Program Files\Privatae\privatae-bastion.exe`); got != `"C:\Program Files\Privatae\privatae-bastion.exe" tray` {
		t.Fatalf("logon entry: %s", got)
	}
}

// fakePipe answers like the service would and records what the page sent.
type fakePipe struct {
	sent []pipeRequest
	list pipeResponse
}

func (f *fakePipe) call(req pipeRequest) (pipeResponse, error) {
	f.sent = append(f.sent, req)
	switch req.Op {
	case "list":
		return f.list, nil
	case "approve":
		return pipeResponse{OK: true, Message: "Approved. " + req.Host + " picks this up."}, nil
	case "deny":
		return pipeResponse{OK: true, Message: "Denied."}, nil
	}
	return pipeResponse{Error: "unknown"}, nil
}

func trayTestServer(t *testing.T, f *fakePipe) (*uiServer, string) {
	t.Helper()
	u := uiTestServer(t)
	u.trayPipe = true
	u.pipe = f.call
	return u, uiSignedIn(t, u)
}

func TestTheTrayPageServesNoAdminRoute(t *testing.T) {
	uiTestConfigDir(t)
	f := &fakePipe{list: pipeResponse{OK: true, State: "RUNNING", StateClass: "ok"}}
	u, cookie := trayTestServer(t, f)
	h := u.handler()
	for _, path := range []string{
		"/fragments/status", "/given", "/fragments/given", "/given/switch",
		"/setup", "/setup/pair", "/setup/stepup/start", "/setup/stepup/qr", "/setup/stepup/key",
		"/diskmap", "/agents", "/policy", "/device/approve", "/device/deny", "/device/approve-shown",
		"/fragments/context", "/context/scan",
	} {
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", cookie)
		w := httpRec(h, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d on the tray's page; it runs as the person and must not mount the machine's console", path, w.Code)
		}
	}
	r := uiReq(http.MethodGet, "/approvals")
	r.Header.Set("Cookie", cookie)
	if w := httpRec(h, r); w.Code != http.StatusOK {
		t.Fatalf("/approvals = %d: the page itself does not serve, so the checks above proved nothing", w.Code)
	}
}

func TestTheTrayPageSendsTheCodeForTheRequestItShowed(t *testing.T) {
	uiTestConfigDir(t)
	digest := purposeDigest("dcn_store_grant|desk-7|/srv/example-a|read,search|.ssh|hourly|false|ttl:0")
	f := &fakePipe{list: pipeResponse{OK: true, State: "RUNNING", StateClass: "ok", Approvals: []pipeApproval{{
		ID: "a1b2c3d4e5f60718293a4b5c6d7e8f90", Short: "a1b2c3d4", Host: "tray.host.example", At: uiTestRecently(),
		Lines: []string{"Your host asks to reach the folder  /srv/example-a  on desk-7"}, Purpose: digest,
	}}}}
	u, cookie := trayTestServer(t, f)
	h := u.handler()

	r := uiReq(http.MethodGet, "/approvals")
	r.Header.Set("Cookie", cookie)
	w := httpRec(h, r)
	body := w.Body.String()
	if !strings.Contains(body, "/srv/example-a") || !strings.Contains(body, `name="purpose" value="`+digest+`"`) {
		t.Fatalf("the card must show the service's words and carry the purpose it describes:\n%s", body)
	}
	if strings.Contains(body, `href="/">This machine`) {
		t.Fatal("the tray's page links to a console it does not serve")
	}

	// No code: nothing is sent.
	n := len(f.sent)
	uiPost(t, h, "/approve", url.Values{"host": {"tray.host.example"}, "id": {"a1b2c3d4e5f60718293a4b5c6d7e8f90"},
		"purpose": {digest}, "code": {" "}}, cookie)
	for _, s := range f.sent[n:] {
		if s.Op == "approve" {
			t.Fatal("an empty code was sent to the service")
		}
	}
	// A code: sent with the id and the purpose shown, and the answer drawn.
	w = uiPost(t, h, "/approve", url.Values{"host": {"tray.host.example"}, "id": {"a1b2c3d4e5f60718293a4b5c6d7e8f90"},
		"purpose": {digest}, "code": {"123456"}}, cookie)
	var got *pipeRequest
	for i := range f.sent {
		if f.sent[i].Op == "approve" {
			got = &f.sent[i]
		}
	}
	if got == nil || got.ID != "a1b2c3d4e5f60718293a4b5c6d7e8f90" || got.Purpose != digest || got.Code != "123456" || got.Host != "tray.host.example" {
		t.Fatalf("the page must send exactly the request it showed: %+v", got)
	}
	if !strings.Contains(w.Body.String(), "Approved.") {
		t.Fatalf("the service's answer must be shown: %s", w.Body.String())
	}
}

func TestTheTrayPageSaysWhenTheServiceCannotBeReached(t *testing.T) {
	s := trayPipeStatus(func(pipeRequest) (pipeResponse, error) {
		return pipeResponse{}, errTestNoService
	})
	if s.TrayError == "" || s.StateClass != "bad" || trayStateLineFrom(s) != "Cannot reach the bastion service" {
		t.Fatalf("an unreachable service must be said, not shown as nothing waiting: %+v", s)
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTestNoService = testErr("the bastion service is not running")
