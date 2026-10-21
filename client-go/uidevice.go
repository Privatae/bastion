package main

// uidevice.go — the approvals popup: what your hosts are waiting on you for,
// opened from the taskbar instead of a terminal.
//
// THE GAP IT CLOSES. On the machine that is the person's approval device
// (device.go), a host files an ask and it lands in device_requests.json. Until
// now the only way to read it was `device-approvals` and the only way to answer
// it was `device-approve` — commands typed at a console the person had to know
// to open. A fleet update is one ask per machine, so the person who asked for
// a fleet of approvals was handed a terminal. An approval surface you have to go
// looking for is a poll, not a prompt.
//
// WHAT IS HERE. The page (/approvals) and its fragment list, in plain words,
// every ask waiting on this device plus the step-up requests waiting on this
// machine itself — everything that is waiting on the person, in one place. Each
// device ask has Approve and Deny; several have "Approve all shown". The tray
// (tray_windows.go) and the notification (notify_windows.go) open this page
// directly, as a small app window where the system has one (uipopup_*.go), so a
// waiting approval is one click from the taskbar with no menu in between.
//
// WHAT IS NOT CHANGED. Signing is deviceApprove's, exactly as the console does
// it: the same key, the same purpose the device derived itself when the ask was
// filed, one use, an hour at most. The page adds a way to press the button; it
// adds no way to sign anything the console could not.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// uiDeviceApproval is one ask waiting on this approval device.
type uiDeviceApproval struct {
	ID     string // full id; the forms post this
	Short  string // the console's [xxxxxxxx]
	Server string // the machine the approval will run on — the purpose names it
	At     string
	Lines  []string // the device's own words (describeRequest), one per line
	// A ship plan (device_plan.go); NeedsCode: it runs root work, so it is
	// approved one at a time with the person's code, never by "all shown".
	Plan      bool
	NeedsCode bool
}

// uiDeviceNoticeID prefixes a device ask's id in the notifier's memory, so it
// can never collide with a step-up request id from a pairing.
const uiDeviceNoticeID = "device:"

// isApprovalDevice: this machine holds a device key (device-init ran here).
//
// It reads the PUBLIC half only. It runs on every tray tick and every page
// render, and there is no reason for either to hold the private key in memory;
// deviceSign is the one place that loads it, at the moment it signs.
func isApprovalDevice() bool {
	p, err := deviceKeyPath()
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	var pub struct {
		Pub string `json:"pub"`
	}
	return json.Unmarshal(raw, &pub) == nil && pub.Pub != ""
}

// pendingDeviceApprovals is every ask waiting on this device, oldest first —
// the same order and the same filter as `device-approvals` prints.
//
// A machine that is not a device returns nothing and never reads the file: the
// device lane answers only on a machine that holds the key, so a stray file
// elsewhere is not an ask anyone can answer.
func pendingDeviceApprovals() []uiDeviceApproval {
	if !isApprovalDevice() {
		return nil
	}
	deviceMu.Lock()
	m := deviceRequestsLoad()
	deviceMu.Unlock()
	var out []uiDeviceApproval
	for _, id := range sortedDeviceRequests(m) {
		r := m[id]
		if r.State != "pending" {
			continue
		}
		short := id
		if len(short) > 8 {
			short = short[:8]
		}
		var lines []string
		for _, l := range strings.Split(r.Words, "\n") {
			if strings.TrimSpace(l) != "" {
				lines = append(lines, l)
			}
		}
		out = append(out, uiDeviceApproval{
			ID: id, Short: short, Server: r.Server, At: uiWhen(r.At), Lines: lines,
			Plan: r.Plan, NeedsCode: r.NeedsCode,
		})
	}
	return out
}

// approvalsForNotice is the one pending list the notification and the tray
// count: the step-up requests on this machine's pairings and the asks waiting
// on this device. They answer different questions (a code here vs a tap here)
// but to the person they are the same thing — something is waiting on them —
// and the popup shows both.
func approvalsForNotice(s uiStatus) []uiApproval {
	out := append([]uiApproval(nil), s.Approvals...)
	for _, d := range s.DeviceApprovals {
		lines := d.Lines
		if len(lines) == 0 {
			lines = []string{"A host is asking your approval for " + d.Server + "."}
		}
		out = append(out, uiApproval{ID: uiDeviceNoticeID + d.ID, Short: d.Short, At: d.At, Lines: lines})
	}
	return out
}

// ── routes ──────────────────────────────────────────────────────────────────

func (u *uiServer) deviceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/approvals", u.guarded(u.approvalsPage))
	mux.HandleFunc("/fragments/approvals", u.guarded(u.approvalsFragment))
	mux.HandleFunc("/fragments/approvals-news", u.guarded(u.approvalsNews))
	mux.HandleFunc("/device/approve", u.guarded(u.deviceApproveOne))
	mux.HandleFunc("/device/deny", u.guarded(u.deviceDenyOne))
	mux.HandleFunc("/device/approve-shown", u.guarded(u.deviceApproveShown))
}

func (u *uiServer) approvalsPage(w http.ResponseWriter, r *http.Request) {
	u.renderApprovals(w, "approvals.html", "", "")
}

func (u *uiServer) approvalsFragment(w http.ResponseWriter, r *http.Request) {
	u.renderApprovals(w, "approvals", "", "")
}

// renderApprovals is renderWith for the popup: the same fresh read of the
// machine, marked so the shared step-up cards post back into THIS page.
func (u *uiServer) renderApprovals(w http.ResponseWriter, name, flash, class string) {
	u.renderStatus(w, name, flash, class, true)
}

func postOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (u *uiServer) deviceApproveOne(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	server := deviceAskServer(id)
	if _, err := deviceApproveWithCode(id, strings.TrimSpace(r.FormValue("code"))); err != nil {
		u.renderApprovals(w, "approvals", "Not approved: "+err.Error(), "bad")
		return
	}
	if deviceIsPlan(id) {
		u.renderApprovals(w, "approvals", "Approved. Each of "+server+
			" runs its own steps of it, once, within its time.", "ok")
		return
	}
	u.renderApprovals(w, "approvals", "Approved. It may run once on "+server+
		" — your host picks it up within a minute.", "ok")
}

func (u *uiServer) deviceDenyOne(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	server := deviceAskServer(id)
	if err := deviceDeny(id); err != nil {
		u.renderApprovals(w, "approvals", "Not denied: "+err.Error(), "bad")
		return
	}
	u.renderApprovals(w, "approvals", "Denied. Nothing runs on "+server+
		", and your host cannot ask for this again for a day.", "ok")
}

// deviceApproveShown signs every ask the page SHOWED — the ids it rendered into
// the form — that is still pending, and nothing else.
//
// This is `device-approve all`'s rule carried over: a host can file an ask at
// any moment, and "all" must never sign one that arrived after the person read
// the list. The page posts the ids it drew; an ask filed since is not among
// them, is left pending, and is named so the person looks again.
func (u *uiServer) deviceApproveShown(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		u.renderApprovals(w, "approvals", "Not approved: the form could not be read.", "bad")
		return
	}
	shown := map[string]bool{}
	for _, id := range r.PostForm["id"] {
		if id = strings.TrimSpace(id); id != "" {
			shown[id] = true
		}
	}
	if len(shown) == 0 {
		u.renderApprovals(w, "approvals", "Nothing was shown, so nothing was approved.", "warn")
		return
	}
	approved, later, gone, coded := 0, 0, 0, 0
	for _, a := range pendingDeviceApprovals() {
		if !shown[a.ID] {
			later++
			continue
		}
		if a.NeedsCode {
			// Root work is approved one at a time, with the code.
			coded++
			continue
		}
		if _, err := approveShownOne(a.ID); err != nil {
			// Answered at the console, or lapsed, between the list being read
			// and this signature: it is no longer anyone's to approve, and the
			// rest of what the person was shown still is. Anything else (the
			// key could not sign) is a real failure and stops here.
			if deviceStateOf(a.ID) != "pending" {
				gone++
				continue
			}
			u.renderApprovals(w, "approvals",
				fmt.Sprintf("Approved %d, then stopped: %v", approved, err), "bad")
			return
		}
		approved++
	}
	msg := fmt.Sprintf("Approved %d. Each may run once — your host picks them up within a minute.", approved)
	class := "ok"
	if approved == 0 {
		msg, class = "Nothing you were shown is still waiting.", "warn"
	}
	if gone > 0 {
		msg += fmt.Sprintf(" %d had already been answered elsewhere.", gone)
	}
	if later > 0 {
		msg += fmt.Sprintf(" %d arrived after you looked and were NOT approved — read them below.", later)
		class = "warn"
	}
	if coded > 0 {
		msg += fmt.Sprintf(" %d ship plan(s) run root work and wait for your code, one at a time.", coded)
		class = "warn"
	}
	u.renderApprovals(w, "approvals", msg, class)
}

// approveShownOne is deviceApprove, named so a test can put an answer from the
// console between the list being read and one ask being signed — the window
// the "answered elsewhere" branch exists for. Nothing else ever replaces it.
var approveShownOne = deviceApprove

// NoCodeApprovals is how many shown asks "approve all shown" signs: every
// one but a ship plan that runs root work, which needs the code.
func (s uiStatus) NoCodeApprovals() int {
	n := 0
	for _, a := range s.DeviceApprovals {
		if !a.NeedsCode {
			n++
		}
	}
	return n
}

// deviceIsPlan: the ask is a ship plan.
func deviceIsPlan(id string) bool {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	return deviceRequestsLoad()[id].Plan
}

// deviceStateOf reads one ask's state under the lock ("" when unknown).
func deviceStateOf(id string) string {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	return deviceRequestsLoad()[id].State
}

// ── the news poll ───────────────────────────────────────────────────────────

// approvalsNews is the ONLY thing on the approvals page that updates by itself.
//
// WHY THE LIST DOES NOT. A list that redraws on a timer redraws under the
// person: a card answered elsewhere shifts the next one's Approve under the
// cursor, a half-typed code is wiped, and — the one that matters — the "approve
// all" form is re-drawn with an ask that landed a second ago, so "all shown"
// would sign something nobody read. So the list is drawn only when the person
// acts (an answer, or "show them"), and this poll only SAYS that something
// changed. It is handed the ids the list was drawn with and compares.
func (u *uiServer) approvalsNews(w http.ResponseWriter, r *http.Request) {
	shown := map[string]bool{}
	for _, id := range r.URL.Query()["shown"] {
		shown[id] = true
	}
	s := u.status()
	now := map[string]bool{}
	for _, a := range s.DeviceApprovals {
		now[a.ID] = true
	}
	for _, a := range s.Approvals {
		now[a.ID] = true
	}
	arrived, left := 0, 0
	for id := range now {
		if !shown[id] {
			arrived++
		}
	}
	for id := range shown {
		if !now[id] {
			left++
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	data := struct{ Arrived, Left int }{arrived, left}
	if err := u.tpl.ExecuteTemplate(w, "approvals-news", data); err != nil {
		uilogf("render approvals-news: %v\n", err)
	}
}

// deviceAskServer names the machine an ask is for, for the outcome line. Read
// before the answer is recorded; "" when the id is unknown (the answer will say
// so).
func deviceAskServer(id string) string {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	if r, ok := deviceRequestsLoad()[id]; ok && r.Server != "" {
		return r.Server
	}
	return "that machine"
}

// openApprovalsPopup is what the tray's approvals line and a click on the
// approval notification do: open /approvals, signed in, as a small window.
//
// It goes through localUIEntryURLTo exactly as openLocalUI goes through
// localUIEntryURL — a one-use ticket minted against the running daemon — so it
// cannot hand out a link that does not authenticate, and the ticket's redirect
// lands on the page itself rather than on a menu.
// approvalsOpener is what a click on an approval notification opens: the
// daemon's own popup, or, in the tray beside a system service, the tray's page
// (tray_pipe_windows.go sets it before the notifier starts).
var approvalsOpener = openApprovalsPopup

func openApprovalsPopup(from string) {
	entry, _, err := localUIEntryURLTo(uiApprovalsPath)
	if err != nil {
		uilogf("%s: %v\n", from, err)
		return
	}
	if err := openPopupWindow(entry); err != nil {
		uilogf("%s: %v\n", from, err)
	}
}

// uiApprovalsPath is the one place a sign-in ticket may land other than "/".
// root() redirects only to paths in uiLandingPaths — a ticket link is handed to
// a browser, and an open redirect on it would be a phishing tool pointed at the
// person's own machine.
const uiApprovalsPath = "/approvals"

var uiLandingPaths = map[string]bool{uiApprovalsPath: true}

// uiLanding is where a redeemed ticket goes: the requested page if it is one we
// name, else the front page.
func uiLanding(to string) string {
	if uiLandingPaths[to] {
		return to
	}
	return "/"
}
