package main

// uitray.go — the tray's approvals window beside a system service.
//
// The person's tray (tray_pipe_windows.go) runs as them and cannot read the
// service's state, so it cannot mint a ticket for the admin page either: that
// needs ui.secret, which lives in the service's state. Its window is therefore
// its own small page, served by the tray process on loopback, drawn from the
// approvals pipe and answering through it. It is the same server and the same
// approval cards as the admin page's popup (approvals.html), with another
// route set, exactly as the context surface is (contextui.go).
//
// What this page can do is what the pipe can do: list, approve with a code,
// deny. No admin route is mounted here (TestTheTrayPageServesNoAdminRoute).
// The session is in memory and the ticket is minted in-process, as for the
// context surface, so there is no secret on disk.

import (
	"net/http"
	"strings"
	"time"
)

func (u *uiServer) trayRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/approvals", u.guarded(u.approvalsPage))
	mux.HandleFunc("/fragments/approvals", u.guarded(u.approvalsFragment))
	mux.HandleFunc("/fragments/approvals-news", u.guarded(u.approvalsNews))
	mux.HandleFunc("/approve", u.guarded(u.trayApprove))
	mux.HandleFunc("/deny", u.guarded(u.trayDeny))
	mux.HandleFunc("/", u.root)
}

// trayPipeStatus is the machine as the service tells it through the pipe:
// the state line and the pending step-up requests in the service's words.
func trayPipeStatus(call func(pipeRequest) (pipeResponse, error)) uiStatus {
	s := uiStatus{Version: clientVersion, CheckedAt: time.Now().Format("15:04:05"), TrayView: true}
	if call == nil {
		s.State, s.StateClass, s.TrayError = "CANNOT REACH THE BASTION SERVICE", "bad", "this tray has no way to reach the bastion service"
		return s
	}
	resp, err := call(pipeRequest{Op: "list"})
	switch {
	case err != nil:
		s.State, s.StateClass, s.TrayError = "CANNOT REACH THE BASTION SERVICE", "bad", err.Error()
		return s
	case !resp.OK:
		s.State, s.StateClass, s.TrayError = "REFUSED BY THE BASTION SERVICE", "bad", resp.Error
		return s
	}
	s.State, s.StateClass, s.StateNote = resp.State, resp.StateClass, resp.StateLine
	for _, a := range resp.Approvals {
		s.Approvals = append(s.Approvals, uiApproval{
			ID: a.ID, Short: a.Short, Host: a.Host, At: a.At, Lines: a.Lines,
			Unreadable: a.Unreadable, PurposeSHA256: a.Purpose,
		})
	}
	return s
}

// trayStateLineFrom is the tray menu's first line from a pipe-drawn status.
func trayStateLineFrom(s uiStatus) string {
	if s.TrayError != "" {
		return "Cannot reach the bastion service"
	}
	if s.StateNote != "" {
		return s.StateNote
	}
	return s.State
}

func (u *uiServer) trayAnswer(w http.ResponseWriter, req pipeRequest, verb string) {
	if u.pipe == nil {
		u.renderApprovals(w, "approvals", "Not "+verb+": this tray has no way to reach the bastion service.", "bad")
		return
	}
	resp, err := u.pipe(req)
	switch {
	case err != nil:
		u.renderApprovals(w, "approvals", "Not "+verb+": "+err.Error(), "bad")
	case !resp.OK:
		u.renderApprovals(w, "approvals", resp.Error, "bad")
	default:
		u.renderApprovals(w, "approvals", resp.Message, "ok")
	}
}

func (u *uiServer) trayApprove(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	req := pipeRequest{Op: "approve", Host: r.FormValue("host"), ID: r.FormValue("id"),
		Purpose: r.FormValue("purpose"), Code: strings.TrimSpace(r.FormValue("code"))}
	if req.Code == "" {
		u.renderApprovals(w, "approvals", "Enter the code from the authenticator enrolled on this machine.", "warn")
		return
	}
	u.trayAnswer(w, req, "approved")
}

func (u *uiServer) trayDeny(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	u.trayAnswer(w, pipeRequest{Op: "deny", Host: r.FormValue("host"), ID: r.FormValue("id"),
		Purpose: r.FormValue("purpose")}, "denied")
}
