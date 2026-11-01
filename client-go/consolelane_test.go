package main

import (
	"context"
	"net/http"
	"net/url"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

// laneOwner records uid as the machine's owner account, as the installer's
// root step does, with machine authority faked and the account looked up as
// an invented one.
func laneOwner(t *testing.T, uid uint32) {
	t.Helper()
	prevAuth, prevLookup, prevState := machineAuthorityHeld, lookupOwnerAccount, ownerServiceState
	t.Cleanup(func() { machineAuthorityHeld, lookupOwnerAccount, ownerServiceState = prevAuth, prevLookup, prevState })
	machineAuthorityHeld = func() bool { return true }
	ownerServiceState = func() string { return "" }
	lookupOwnerAccount = func(who string) (*user.User, error) {
		return &user.User{Uid: strconv.FormatUint(uint64(uid), 10), Username: "sam"}, nil
	}
	if err := cmdOwnerAccount("sam", false); err != nil {
		t.Fatal(err)
	}
}

// laneSignedIn redeems a ticket minted for the owner's lane, the way the
// browser does, and returns the session cookie it sets.
func laneSignedIn(t *testing.T, u *uiServer, uid uint32) string {
	t.Helper()
	u.addr = "127.0.0.1:" + uiTestPort
	prev := consoleLaneServer.Load()
	consoleLaneServer.Store(u)
	t.Cleanup(func() { consoleLaneServer.Store(prev) })
	link, err := consoleLaneEntry(uid, "sam")
	if err != nil {
		t.Fatalf("the owner's lane refused its owner: %v", err)
	}
	p, _ := url.Parse(link)
	w := uiGet(t, u.handler(), "/?"+p.RawQuery, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("redeeming the lane's ticket = %d: %s", w.Code, firstLines(w.Body.String()))
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == uiCookieName {
			return uiCookieName + "=" + c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestTheLaneOpensOnlyForTheOwnersAccount(t *testing.T) {
	uiTestConfigDir(t)
	if why := consoleLaneRefusal(1000, "sam"); !strings.Contains(why, "approvals-owner --account sam") {
		t.Errorf("with no owner recorded the refusal does not say how to record one: %q", why)
	}
	laneOwner(t, 1000)
	if why := consoleLaneRefusal(1000, "sam"); why != "" {
		t.Errorf("the owner was refused: %q", why)
	}
	if why := consoleLaneRefusal(1001, "lee"); !strings.Contains(why, "only for its owner's account (sam)") {
		t.Errorf("another account was let in, or told the wrong thing: %q", why)
	}
	if _, err := consoleLaneEntry(1001, "lee"); err == nil {
		t.Error("a ticket was minted for an account that is not the owner's")
	}
}

func TestTheOwnerAccountIsNotQuietlyHandedToAnother(t *testing.T) {
	uiTestConfigDir(t)
	laneOwner(t, 1000)
	if err := cmdOwnerAccount("sam", false); err != nil {
		t.Errorf("the same account again: %v", err)
	}
	lookupOwnerAccount = func(string) (*user.User, error) { return &user.User{Uid: "1001", Username: "lee"}, nil }
	if err := cmdOwnerAccount("lee", false); err == nil || !strings.Contains(err.Error(), "stays so") {
		t.Errorf("another account took the console: %v", err)
	}
	prev := ownerConsole
	t.Cleanup(func() { ownerConsole = prev })
	ownerConsole = func() bool { return false }
	if err := cmdOwnerAccount("lee", true); err == nil || !strings.Contains(err.Error(), "only at a terminal") {
		t.Errorf("--replace was taken from a pipe: %v", err)
	}
	if uid, _, _, _ := ownerAccountLoad(); uid != 1000 {
		t.Fatalf("the owner changed to uid %d", uid)
	}
	lookupOwnerAccount = func(string) (*user.User, error) { return &user.User{Uid: "0", Username: "root"}, nil }
	ownerConsole = func() bool { return true }
	if err := cmdOwnerAccount("root", true); err == nil || !strings.Contains(err.Error(), "root administers") {
		t.Errorf("root was recorded as the owner's account: %v", err)
	}
}

// A limited session sees the console and does what takes the code or narrows
// reach. What widens reach with no code is the administrator's, and the page
// says so instead of offering it.
func TestALaneSessionIsRefusedWhatWidensReachWithNoCode(t *testing.T) {
	u, admin := settingsWorld(t, true)
	laneOwner(t, 1000)
	lane := laneSignedIn(t, u, 1000)
	h := u.handler()

	for _, p := range []string{"/", "/setup", "/approvals", "/activity", "/machine"} {
		if w := uiGet(t, h, p, lane); w.Code != http.StatusOK {
			t.Errorf("GET %s from the lane = %d", p, w.Code)
		}
	}
	for _, p := range []string{"/setup/pair", "/setup/stepup/start", "/setup/stepup/confirm", "/setup/stepup/key",
		"/setup/folder/propose", "/setup/anchor/choose", "/device/approve", "/device/approve-shown"} {
		w := uiPost(t, h, p, url.Values{"target": {"machine"}, "token": {"skb_x"}}, lane)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "sudo -H privatae-bastion ui") {
			t.Errorf("POST %s from the lane = %d %s", p, w.Code, firstLines(w.Body.String()))
		}
	}
	if w := uiGet(t, h, "/setup/stepup/qr?e=x", lane); w.Code != http.StatusForbidden {
		t.Errorf("the enrolment QR was served to the lane: %d", w.Code)
	}
	// The disk map, run as root, names files in every account's home. Its
	// stand-in is installed, so a POST that got through would walk nothing:
	// it blocks until the test ends.
	dm := dmTestInstall(t, nil)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	dm.scan = func(ctx context.Context, _ []string, _ int, _ func(dmProgress)) *dmResult {
		<-release
		return nil
	}
	for _, p := range []string{"/diskmap", "/fragments/diskmap"} {
		if w := uiGet(t, h, p, lane); w.Code != http.StatusForbidden {
			t.Errorf("GET %s from the lane = %d", p, w.Code)
		}
	}
	if w := uiPost(t, h, "/diskmap/scan", url.Values{}, lane); w.Code != http.StatusForbidden {
		t.Errorf("POST /diskmap/scan from the lane = %d", w.Code)
	}
	// Narrowing reach needs no code, from the lane too.
	uiPost(t, h, "/setup/host/disconnect", url.Values{"host": {"member.host.privatae.ai"}, "confirm": {"1"}}, lane)
	if cfgs, _ := loadPairings(); len(cfgs) != 0 {
		t.Error("the lane could not disconnect a Host")
	}
	// The same routes still work for the administrator's own session.
	if w := uiPost(t, h, "/setup/stepup/start", url.Values{"target": {"machine"}, "replace": {"1"}}, admin); w.Code != http.StatusOK {
		t.Errorf("the administrator was refused: %d %s", w.Code, firstLines(w.Body.String()))
	}
	body := uiGet(t, h, "/setup", lane).Body.String()
	if strings.Contains(body, `hx-post="/setup/pair"`) || strings.Contains(body, `hx-post="/setup/stepup/start"`) {
		t.Error("Settings offers the lane a form it would refuse")
	}
	if !strings.Contains(body, "sudo -H privatae-bastion stepup-enroll --machine --rotate") {
		t.Error("Settings does not tell the lane how the code is replaced")
	}
	if body := uiGet(t, h, "/setup", admin).Body.String(); !strings.Contains(body, `hx-post="/setup/pair"`) {
		t.Error("Settings lost the pairing form for the administrator")
	}
}

// The folder check stats whatever path is posted, as the daemon, which is root
// on a whole-machine install. The lane draws no folder form, so from the lane
// it could only be used to learn what exists where the person's account cannot
// look; it is the administrator's, like the proposal it serves.
func TestALaneSessionCannotProbePathsThroughTheFolderCheck(t *testing.T) {
	u, admin := settingsWorld(t, true)
	laneOwner(t, 1000)
	lane := laneSignedIn(t, u, 1000)
	h := u.handler()
	dir := t.TempDir()
	w := uiPost(t, h, "/setup/folder/check", url.Values{"path": {dir}}, lane)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "A folder on this machine") {
		t.Errorf("the lane's folder check = %d %s", w.Code, firstLines(w.Body.String()))
	}
	if w := uiPost(t, h, "/setup/folder/check", url.Values{"path": {dir}}, admin); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "A folder on this machine") {
		t.Errorf("the administrator's folder check = %d %s", w.Code, firstLines(w.Body.String()))
	}
}

// Through the lane the Host factor's seed is out of reach, so wrong codes
// typed for a Host's request are throttled there, and only there.
func TestALaneSessionsWrongHostCodesAreThrottled(t *testing.T) {
	const host = "member.host.privatae.ai"
	_, id := uiTestApprovalBox(t, host)
	u := uiTestServer(t)
	laneOwner(t, 1000)
	lane := laneSignedIn(t, u, 1000)
	h := u.handler()
	var last string
	for i := 0; i < pipeFreeFailures+1; i++ {
		last = uiPost(t, h, "/approve", url.Values{"host": {host}, "id": {id}, "code": {"000000"}}, lane).Body.String()
	}
	if !strings.Contains(last, "wait") && !strings.Contains(last, "again in") {
		t.Errorf("the lane typed %d wrong codes with no wait: %s", pipeFreeFailures+1, firstLines(last))
	}
	admin := uiSignedIn(t, u)
	body := uiPost(t, h, "/approve", url.Values{"host": {host}, "id": {id}, "code": {"000000"}}, admin).Body.String()
	if strings.Contains(body, "again in") {
		t.Errorf("the administrator's page is throttled too: %s", firstLines(body))
	}
}

// Links minted for the lane are capped, so an account asking in a loop cannot
// grow the root daemon's memory; one opened frees its place.
func TestTheLaneCapsTheLinksWaitingToBeOpened(t *testing.T) {
	u := uiTestServer(t)
	uiTestConfigDir(t)
	laneOwner(t, 1000)
	laneSignedIn(t, u, 1000) // sets the server for the lane; its link is used
	for i := 0; i < consoleLaneTicketsMax; i++ {
		if _, err := consoleLaneEntry(1000, "sam"); err != nil {
			t.Fatalf("link %d refused: %v", i+1, err)
		}
	}
	if _, err := consoleLaneEntry(1000, "sam"); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("link %d was minted: %v", consoleLaneTicketsMax+1, err)
	}
}
