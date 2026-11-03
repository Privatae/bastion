//go:build !windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// anchoredWithPending is the S0 machine: anchored to a Host on this machine,
// with a remote Host that redeemed its code and waits.
func anchoredWithPending(t *testing.T) {
	t.Helper()
	localBox(t)
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", "")
	if err := writeAnchor("the owner", tLocal); err != nil {
		t.Fatal(err)
	}
	pd, _ := pairingsDir()
	b, _ := json.Marshal(Config{HostName: tRemote, Transport: transportTCP, LaneAddr: "10.0.2.2:28811", WGPrivateKey: "k",
		State: pairingPending, ListenAddr: "127.0.0.1:7879", Origin: pairingOriginCarried})
	if err := os.WriteFile(filepath.Join(pd, tRemote+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// `pair` on an anchored machine says the code was used, that the Host waits
// for the anchor to admit it, and that the anchor asks the person.
//
// MUTATION: restore the 0.62 text ("a new host waits until the anchor host
// approves it"). RESULT: red.
func TestPairOnAnAnchoredMachineSaysWhoAdmitsTheHost(t *testing.T) {
	anchoredWithPending(t)
	cfg, all := pairingNamed(t, tRemote)
	out := pairReportOf(cfg, all, false)
	for _, want := range []string{
		"Paired with " + tRemote + " — WAITING for " + tLocal + " to admit it.",
		"The code was used",
		tLocal + " asks you to approve " + tRemote,
		"served at once, with no restart",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("pair does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not answering") || strings.Contains(out, "privatae-bastion run") {
		t.Errorf("pair names a dead end:\n%s", out)
	}
}

// `pair` never tells the person to start a bastion that is running: the
// running one serves the new pairing by itself. With none running it names
// this machine's own start command.
//
// MUTATION: restore "Start (or restart) the bastion:\n  privatae-bastion run".
// RESULT: red.
func TestPairNeverSaysRunWhenABastionServesTheMachine(t *testing.T) {
	localBox(t)
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", "")
	cfg, all := pairingNamed(t, tLocal)
	prev := pairDaemonRunning
	t.Cleanup(func() { pairDaemonRunning = prev })
	pairDaemonRunning = func() bool { return true }
	out := pairReportOf(cfg, all, false)
	if strings.Contains(out, "privatae-bastion run") || !strings.Contains(out, "serves it within 15 seconds; nothing needs restarting") {
		t.Errorf("with a bastion running:\n%s", out)
	}
	pairDaemonRunning = func() bool { return false }
	out = pairReportOf(cfg, all, false)
	if !strings.Contains(out, "Start the bastion so it serves it:\n  "+runCommandHint()) {
		t.Errorf("with none running:\n%s", out)
	}
}

// `status` and `status --json` say a pending Host waits for the anchor to
// admit it, never that it is not answering, and the machine is RUNNING when
// every Host it may serve is served.
//
// MUTATION: count pending pairings as served in readStatus. RESULT: red
// (PARTLY RUNNING). Drop WaitingFor. RESULT: red.
func TestStatusSaysAPendingHostWaitsForTheAnchor(t *testing.T) {
	anchoredWithPending(t)
	s, err := readStatus(readOpts{})
	if err != nil {
		t.Fatal(err)
	}
	var pend *statusPairing
	for i := range s.Pairings {
		if s.Pairings[i].Host == tRemote {
			pend = &s.Pairings[i]
		}
	}
	if pend == nil || pend.WaitingFor != tLocal {
		t.Fatalf("status --json does not say who admits it: %+v", s.Pairings)
	}
	raw, _ := json.Marshal(s)
	if !strings.Contains(string(raw), `"waiting_for":"`+tLocal+`"`) {
		t.Errorf("the JSON lacks waiting_for: %s", raw)
	}
	// As the daemon reads it, with the anchor's own lane answering.
	s.Running = "yes"
	for i := range s.Pairings {
		if s.Pairings[i].Host == tLocal {
			s.Pairings[i].Answering = true
		}
	}
	var b strings.Builder
	printStatus(&b, s)
	out := b.String()
	if !strings.HasPrefix(out, "RUNNING — serving 1 host(s)") {
		t.Errorf("headline:\n%s", out)
	}
	if !strings.Contains(out, "Waiting for "+tLocal+" to admit it: "+tRemote) ||
		!strings.Contains(out, "(waiting for "+tLocal+" to admit it)") {
		t.Errorf("status does not say who admits it:\n%s", out)
	}
	if strings.Contains(out, "not answering") {
		t.Errorf("a pending Host reads as not answering:\n%s", out)
	}
}

// The console says the same, and the page shows it in place of "not answering".
//
// MUTATION: drop the WaitingFor branch in status.html. RESULT: red.
func TestTheConsoleSaysAPendingHostWaitsForTheAnchor(t *testing.T) {
	anchoredWithPending(t)
	s := collectUIStatus()
	if strings.Contains(s.StateNote, "not answering") || !strings.Contains(s.StateNote, "wait(s) for "+tLocal+" to admit them") {
		t.Errorf("state %q: %q", s.State, s.StateNote)
	}
	found := false
	for _, p := range s.Pairings {
		found = found || (p.Host == tRemote && p.WaitingFor == tLocal)
	}
	if !found {
		t.Errorf("pairings %+v", s.Pairings)
	}
	page, err := os.ReadFile(filepath.Join("uiassets", "status.html"))
	if err != nil {
		t.Fatal(err)
	}
	i, j := strings.Index(string(page), "{{if .WaitingFor}}<span class=\"tag warn\">not served until"), strings.Index(string(page), "not answering</span>")
	if i < 0 || j < 0 || i > j {
		t.Error("the page shows a pending Host as not answering")
	}
	if line := trayStateLine(s); !strings.Contains(line, "waiting for "+tLocal) {
		t.Errorf("tray: %q", line)
	}
}

// The anchor's heartbeat carries each pending pairing with what the anchor
// Host needs for the approval prompt: who admits it, how it would run, where
// its Host is, and how it came.
//
// MUTATION: drop the pending fields in pairingsReport. RESULT: red.
func TestTheAnchorsBeatCarriesWhatItNeedsToAskThePerson(t *testing.T) {
	anchoredWithPending(t)
	var e *pairingEntry
	for _, p := range pairingsReport() {
		if p.HostName == tRemote {
			p := p
			e = &p
		}
	}
	if e == nil || e.State != pairingPending || e.WaitingFor != tLocal || e.Transport != "tcp" || e.SameMachine ||
		e.Origin != pairingOriginCarried || e.Handle != handleOf(tRemote) {
		t.Fatalf("%+v", e)
	}
	for _, p := range pairingsReport() {
		if p.HostName == tLocal && (p.WaitingFor != "" || p.Origin != "") {
			t.Errorf("an active pairing carries the pending fields: %+v", p)
		}
	}
	// The unapproved list keeps its four fields.
	raw, _ := json.Marshal(unapprovedAttempts(time.Now().Add(time.Hour)))
	if strings.Contains(string(raw), "waiting_for") {
		t.Errorf("unapproved attempts grew fields: %s", raw)
	}
}

// The installer's last words come from what the service holds: what it serves
// and what waits, before the "no Host is needed" line it said whatever the
// service served.
//
// MUTATION: drop the status --json read. RESULT: red.
func TestTheInstallerSaysWhatTheServiceServesAndWhatWaits(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	read := strings.Index(s, "$st = (& $exe status --json 2>$null | Out-String) | ConvertFrom-Json")
	waits := strings.Index(s, "waits for $($p.waiting_for) to admit it")
	none := strings.Index(s, "no Host is needed.")
	if read < 0 || waits < 0 || none < 0 || !(read < waits && waits < none) {
		t.Error("the installer's end text does not come from what the service serves")
	}
	if !strings.Contains(s, "if ($served -or $waits) {") {
		t.Error("the 'no Host is needed' line is not kept for a service that serves none")
	}
}
