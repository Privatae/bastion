package main

// uisetup_owner.go — owner acts on Settings that used to end in "the line to
// run": naming the owner, disconnecting a Host, releasing one from
// quarantine. Each needs the machine's administrator, so each is offered only
// when the bastion runs for the whole machine (the console then runs as
// that administrator), and each that widens what a Host may do takes the
// owner's code: anything driving the person's browser can press a button.
// Disconnecting only takes reach away, so it takes a tick, not a code.
// Every act is written to pairing_audit.jsonl, so it shows in Activity.

import (
	"net/http"
	"strings"
)

// ownerCodeRefusal spends the owner's code on one act, or says why not.
func ownerCodeRefusal(code, purpose string) string {
	dir := existingMachineFactorDir()
	if !stepupEnrolled(dir) {
		return "Set up your code under Settings first."
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "Type the code from your authenticator."
	}
	approval, err := machineCodeSpend(dir, uiNow(), func() (string, error) {
		return stepupIssueApproval(dir, code, purpose)
	})
	if err != nil {
		return "Not done: " + err.Error() + "."
	}
	if err := stepupConsumeApproval(dir, approval, purpose); err != nil {
		return "Not done: " + err.Error() + "."
	}
	return ""
}

func (s *uiSetup) ownerNameHere(w http.ResponseWriter, name, code string) {
	if err := claimNameOK(name); err != nil {
		s.flash(w, "That name will be refused: "+err.Error()+".", "bad")
		return
	}
	if err := purposeBad([]string{name}, nil); err != nil {
		s.flash(w, "That name cannot be used: "+err.Error()+".", "bad")
		return
	}
	if why := ownerCodeRefusal(code, "local_owner|"+name); why != "" {
		s.flash(w, why, "warn")
		return
	}
	if _, err := writeOwnerClaim(name); err != nil {
		s.flash(w, "Not set: "+err.Error()+".", "bad")
		return
	}
	pairingAudit("claim_owner", name, "set by the owner at this machine's console")
	s.flash(w, "The owner name is now “"+name+"”. It shows on this machine's card on every Host it serves, "+
		"and grants nothing.", "ok")
}

func (s *uiSetup) hostDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	if r.FormValue("confirm") == "" {
		s.flash(w, "Tick the box to confirm disconnecting "+host+". Connecting it again needs a new token from it.", "warn")
		return
	}
	name, err := unpairHost(host)
	if err != nil {
		s.flash(w, "Not disconnected: "+err.Error()+".", "bad")
		return
	}
	pairingAudit("unpair", name, "disconnected by the owner at this machine's console")
	s.flash(w, name+" is disconnected: its tunnel and lanes are down. What it kept on this machine stays on disk.", "ok")
}

func (s *uiSetup) hostRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	if _, err := setupHost(host); err != nil {
		s.flash(w, err.Error(), "bad")
		return
	}
	if !machineAuthorityHeld() {
		s.flash(w, "Releasing a Host needs the machine's administrator; this bastion runs in your own account.", "warn")
		return
	}
	if why := ownerCodeRefusal(r.FormValue("code"), "local_release|"+host); why != "" {
		s.flash(w, why, "warn")
		return
	}
	quarantineClear(host)
	pairingAudit("quarantine_clear", host, "released by the owner at this machine's console")
	s.flash(w, host+" may ask this machine for changes again, each with your approval as before.", "ok")
}
