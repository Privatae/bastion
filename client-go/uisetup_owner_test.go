package main

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// settingsWorld: the bastion runs for the whole machine, the owner's code is
// set up, and one Host is connected. The Host's name is invented.
func settingsWorld(t *testing.T, whole bool) (*uiServer, string) {
	t.Helper()
	uiTestPairing(t, "member.host.privatae.ai")
	d, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, d, machineTestSecret)
	prev := machineAuthorityHeld
	t.Cleanup(func() { machineAuthorityHeld = prev })
	machineAuthorityHeld = func() bool { return whole }
	u := uiTestServer(t)
	return u, uiSignedIn(t, u)
}

func TestSettingsSaysWhatThisComputerIsInPlainWords(t *testing.T) {
	u, cookie := settingsWorld(t, true)
	body := uiGet(t, u.handler(), "/setup", cookie).Body.String()
	for _, want := range []string{"Your own computer: one Host at most", "for the whole machine",
		"Connected Hosts", "member.host.privatae.ai", "Disconnect", "Set the owner name"} {
		if !strings.Contains(body, want) {
			t.Errorf("Settings does not say %q", want)
		}
	}
	for _, gone := range []string{"<dt>Mode</dt>", "<dt>Anchor</dt>"} {
		if strings.Contains(body, gone) {
			t.Errorf("Settings still says %q", gone)
		}
	}
}

func TestTheOwnerNameIsSetHereWithTheCode(t *testing.T) {
	u, cookie := settingsWorld(t, true)
	h := u.handler()
	w := uiPost(t, h, "/setup/owner/name", url.Values{"owner": {"Sam"}, "code": {codeFor(t, hostTestSecret)}}, cookie)
	if !strings.Contains(w.Body.String(), "code refused") {
		t.Errorf("a wrong code: %s", firstLines(w.Body.String()))
	}
	if o := currentOwnerClaim(); o != nil {
		t.Fatalf("a name was set with a wrong code: %q", o.Owner)
	}
	w = uiPost(t, h, "/setup/owner/name", url.Values{"owner": {"Sam"}, "code": {codeFor(t, machineTestSecret)}}, cookie)
	if o := currentOwnerClaim(); o == nil || o.Owner != "Sam" {
		t.Fatalf("the owner's code did not set the name: %s", firstLines(w.Body.String()))
	}
}

func TestDisconnectingAHostTakesATickNotACode(t *testing.T) {
	u, cookie := settingsWorld(t, true)
	h := u.handler()
	if w := uiPost(t, h, "/setup/host/disconnect", url.Values{"host": {"member.host.privatae.ai"}}, cookie); !strings.Contains(w.Body.String(), "Tick the box") {
		t.Errorf("no tick: %s", firstLines(w.Body.String()))
	}
	if cfgs, _ := loadPairings(); len(cfgs) != 1 {
		t.Fatal("disconnected without the tick")
	}
	uiPost(t, h, "/setup/host/disconnect", url.Values{"host": {"member.host.privatae.ai"}, "confirm": {"1"}}, cookie)
	if cfgs, _ := loadPairings(); len(cfgs) != 0 {
		t.Fatal("the Host is still connected")
	}
	if items := collectActivity(time.Now().Add(-time.Hour)); len(items) == 0 || !strings.Contains(items[0].What, "Host removed member.host.privatae.ai") {
		t.Errorf("Activity does not show the disconnect: %+v", items)
	}
}

func TestReleasingAHostFromQuarantineTakesTheCode(t *testing.T) {
	u, cookie := settingsWorld(t, true)
	f := quarantineLoad()
	if f.Pairing == nil {
		f.Pairing = map[string]*quarantineEntry{}
	}
	f.Pairing["member.host.privatae.ai"] = &quarantineEntry{Until: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := quarantineSave(f); err != nil {
		t.Fatal(err)
	}
	h := u.handler()
	if body := uiGet(t, h, "/setup", cookie).Body.String(); !strings.Contains(body, "Release from quarantine") {
		t.Fatal("a quarantined Host offers no release")
	}
	uiPost(t, h, "/setup/host/release", url.Values{"host": {"member.host.privatae.ai"}}, cookie)
	if quarantinedUntil("member.host.privatae.ai", time.Now()).IsZero() {
		t.Fatal("released with no code")
	}
	uiPost(t, h, "/setup/host/release", url.Values{"host": {"member.host.privatae.ai"}, "code": {codeFor(t, machineTestSecret)}}, cookie)
	if !quarantinedUntil("member.host.privatae.ai", time.Now()).IsZero() {
		t.Fatal("the owner's code did not release it")
	}
}

// In the person's own account the page does not offer acts it cannot do.
func TestAPerAccountBastionOffersNoAdministratorActs(t *testing.T) {
	u, cookie := settingsWorld(t, false)
	body := uiGet(t, u.handler(), "/setup", cookie).Body.String()
	if strings.Contains(body, `hx-post="/setup/host/disconnect"`) || strings.Contains(body, "Set the owner name") {
		t.Error("a per-account bastion offered an administrator's act")
	}
	if !strings.Contains(body, "agents running as you can stop it") {
		t.Error("the page does not say what a per-account install costs")
	}
}
