package main

// ui.go — the bastion's local UI: what this machine is doing, on this machine.
//
// WHY IT EXISTS. Flashing console windows, a terminal that vanished after a
// self-update, and nothing on the machine to look at: three separate defects
// were the same defect. The bastion is a program with no face, and what it
// needs is a UI local to the machine. It runs, holds credentials, serves a remote host,
// reads folders and can open a root shell — and on the machine it lives on it is
// a name in Task Manager. `status` had to be TYPED to learn anything, and after
// a self-update there is no console to type it in (relaunch_windows.go).
//
// The full capability catalogue is larger than this file, and what each part
// of it needs is set out in the local UI's design. This file is phase 1 of
// that: SEE IT.
//
// THE LINE THIS MUST NOT CROSS. The UI is a view of, and a gate on, THIS
// MACHINE. It never originates a request to the host. The bastion has no MCP
// ingress — removed deliberately, and run.go still says why:
// "nothing on this box drives the host." A local UI is the most natural place in
// the world to re-introduce that by accident, one convenience button at a time.
//
// STACK. Go + htmx, one binary. deploy/publish.sh builds all
// six targets in ONE alpine container with CGO_ENABLED=0, which is what makes
// the bastion a static binary with no runtime dependencies. htmx costs nothing
// against that: the script is embedded, the server renders fragments, and no npm
// or bundler enters a security binary's release. It is vendored in uiassets/ and
// never fetched from a CDN — a privacy product must not pull a script off the
// internet to show you your own machine, and on a locked-down box it would fail.

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// uilogf is the UI's own log line. NOT run.go's logf — that one is a closure
// inside runPairing and prefixes every line with the pairing's host name
// (run.go:298), which is exactly what a machine-wide server must not claim: the
// UI belongs to the box, not to any host it serves.
func uilogf(format string, a ...any) { fmt.Printf("[ui] "+format, a...) }

//go:embed uiassets/htmx.min.js uiassets/app.css uiassets/given.css uiassets/setup.css uiassets/diskmap.css uiassets/agents.css uiassets/policy.css uiassets/context.css
var uiStaticFS embed.FS

//go:embed uiassets/page.html uiassets/status.html uiassets/given.html uiassets/setup.html uiassets/diskmap.html uiassets/agents.html uiassets/policy.html uiassets/context.html uiassets/approvals.html
var uiTemplateFS embed.FS

// uiPortHigh is the port the UI prefers, and it is one BELOW the pairing range
// on purpose. nextListenAddr (config.go:563) allocates a control port per
// pairing counting UP from 7878, so 7877 is a port it can never reach, however
// many hosts this machine ends up serving. uiPortLow leaves room to move if
// something else on the box already holds it.
const (
	uiPortHigh = 7877
	uiPortLow  = 7862
)

// ── the data the page shows ─────────────────────────────────────────────────

type uiPairing struct {
	Host       string
	State      string
	ListenAddr string
	Listening  bool
	TunnelIP   string
	FirstSeen  string
	IsAnchor   bool
}

// uiApproval is one thing a host has asked this machine to allow, waiting for
// the person sitting at it.
type uiApproval struct {
	ID    string // full id; the form posts this, never the short form
	Short string // what a human reads, matching the CLI's [xxxxxxxx]
	Host  string
	At    string
	Lines []string // describeRequest, in the box's own words
	// Unreadable: this bastion does not know what it is being asked for, so it
	// cannot put it in words. See uiUnknownRequest.
	Unreadable bool
	// PurposeSHA256 is the sha256 of the purpose these lines describe. The
	// tray's lane (approvalpipe.go) carries it back with the code, so what is
	// approved is the request that was read.
	PurposeSHA256 string
}

// uiRefusal is a host-directed action this box would not carry out
// (directive_refusal.go). It already reaches the HOST on every enforcing
// report; the person standing at the machine got a fmt.Printf into a console
// that, after a self-update, does not exist.
type uiRefusal struct {
	What string
	Why  string
	At   string
}

// uiEvent is one thing that happened TO this machine (events.go), in local
// time. Recent drives the emphasis and nothing else — an event is never
// removed, it stops shouting. Without that, a containment from three months ago
// would still be a red block at the top of the page, which is the stale-alarm
// failure directive_refusal.go:27-29 already names.
type uiEvent struct {
	At     string
	Text   string
	Recent bool
}

// uiEventRecentFor is how long an event is emphasised. A week, because there is
// no dismiss button and none is wanted — the emphasis has to time out by
// itself, and seven days is the coarsest span over which "whoever uses this
// machine has had a chance to look at it" is true for someone who is not at it
// daily. It is a styling threshold, never a filter.
const uiEventRecentFor = 7 * 24 * time.Hour

// uiEventTime is date-and-time, not the state block's clock-only format: these
// are things that happened, and "14:32" with no day is unreadable on the one
// line of the page where the day is the point.
const uiEventTime = "2 Jan 2006, 15:04"

type uiStatus struct {
	Version        string
	State          string
	StateClass     string
	StateNote      string
	Mode           string
	ModeNote       string
	AnchorHost     string
	AnchorOwner    string
	AnchorRequired bool
	Owner          string
	NoConsoleNote  bool
	Pairings       []uiPairing
	Approvals      []uiApproval
	// DeviceApprovals: asks your hosts filed on THIS machine as your approval
	// device (uidevice.go). IsDevice says whether it is one at all.
	DeviceApprovals []uiDeviceApproval
	IsDevice        bool
	// ApprovalsView: this render is for the approvals popup, so the step-up
	// cards post back into it rather than into the front page.
	ApprovalsView bool
	// Refusal, Events and UpdateAvailable are the three things this box already
	// knew and told nobody who was here. See collectUIStatus.
	Refusal         *uiRefusal
	Events          []uiEvent
	EventsRecent    bool
	UpdateAvailable string
	CheckedAt       string
	// Flash is the outcome of the last approve/deny, carried into the fragment
	// that replaces the page. Empty on an ordinary poll.
	Flash      string
	FlashClass string
	// TrayView: drawn by the person's tray beside a system service
	// (uitray.go), which reads the machine through the approvals pipe.
	// TrayError says why that read failed.
	TrayView  bool
	TrayError string
}

// collectUIStatus reads the same sources cmdStatus does, so the page and the
// command can never disagree. It probes liveness per pairing exactly as status
// does — a plain TCP connect, identical on every platform.
func collectUIStatus() uiStatus {
	s := uiStatus{
		Version:   clientVersion,
		Mode:      boxMode(),
		CheckedAt: time.Now().Format("15:04:05"),
	}
	if s.Mode == modeNetworked {
		s.ModeNote = "several hosts may be served here; the anchor approves each one"
	} else {
		s.ModeNote = "one host, this user"
	}
	if a := currentAnchor(); a != nil {
		s.AnchorHost, s.AnchorOwner = a.AnchorHost, a.Owner
	} else if s.Mode == modeNetworked {
		// The gate in anchor.go: a networked box with no anchor serves nothing.
		// The user has to be told that in the place they are looking, not only
		// in the refusal text of an op they cannot see.
		s.AnchorRequired = true
	}
	if o := currentOwnerClaim(); o != nil {
		s.Owner = o.Owner
	}
	// The device lane is this machine's, not a pairing's: read it before the
	// pairings, so a machine whose pairing list cannot be read still shows the
	// asks waiting on it.
	s.IsDevice = isApprovalDevice()
	s.DeviceApprovals = pendingDeviceApprovals()

	// The three things this machine already knew and told nobody standing at it.
	// A containment printed to stdout and kept nothing (the Printf at
	// contain.go:106, which is all there was); a
	// refused directive went to the host on the enforcing report and no further
	// (directive_refusal.go:60); and the box never asked whether it was current,
	// because fetchManifest had exactly one caller and that caller runs only
	// when the host directs an update (update.go).
	s.UpdateAvailable = updateAvailable()
	if r := directiveRefusalReport(); r != nil {
		what, _ := r["what"].(string)
		why, _ := r["why"].(string)
		at, _ := r["at"].(string)
		s.Refusal = &uiRefusal{What: what, Why: why, At: uiWhen(at)}
	}
	for _, e := range localEventsNewestFirst() {
		recent := time.Since(e.At) < uiEventRecentFor
		s.EventsRecent = s.EventsRecent || recent
		s.Events = append(s.Events, uiEvent{
			At: e.At.Local().Format(uiEventTime), Text: e.Text, Recent: recent,
		})
	}

	cfgs, err := loadPairings()
	if err != nil {
		s.State, s.StateClass = "CANNOT READ THIS MACHINE'S STATE", "bad"
		s.StateNote = err.Error()
		return s
	}
	running := 0
	for _, c := range cfgs {
		p := uiPairing{
			Host: c.HostName,
			// As the setup page and `status` read it: a pairing whose file
			// cannot be served is "invalid" whatever its stored state says.
			State:      c.stateName(),
			ListenAddr: c.ListenAddr,
			Listening:  bastionListening(c.ListenAddr),
			TunnelIP:   c.BastionTunnelIP,
			FirstSeen:  c.FirstSeen,
			IsAnchor:   s.AnchorHost != "" && c.HostName == s.AnchorHost,
		}
		if p.Listening {
			running++
		}
		s.Pairings = append(s.Pairings, p)
		s.Approvals = append(s.Approvals, pendingApprovals(c)...)
	}

	switch {
	case len(cfgs) == 0:
		s.State, s.StateClass = "NOT PAIRED", "warn"
		s.StateNote = "No host is paired with this machine yet."
	case running == len(cfgs):
		s.State, s.StateClass = "RUNNING", "ok"
		s.StateNote = fmt.Sprintf("Serving %d host(s) from this machine.", len(cfgs))
		s.NoConsoleNote = runtime.GOOS == "windows"
	case running > 0:
		s.State, s.StateClass = "PARTLY RUNNING", "warn"
		s.StateNote = fmt.Sprintf("%d of %d hosts are being served; the rest are not answering.",
			running, len(cfgs))
	default:
		s.State, s.StateClass = "NOT RUNNING", "bad"
		s.StateNote = "Nothing is serving these pairings. Start it with `" + runCommandHint() + "`."
	}
	return s
}

// uiWhen renders a stored RFC3339 stamp in the local time of the person reading
// it. An unparseable stamp is shown AS IT IS rather than dropped: a timestamp
// this code cannot read is still evidence, and blanking it would make a refusal
// look like it had no time at all.
func uiWhen(rfc3339 string) string {
	if t, err := time.Parse(time.RFC3339, rfc3339); err == nil {
		return t.Local().Format(uiEventTime)
	}
	return rfc3339
}

// pendingApprovals is what one host is waiting on this machine to allow.
//
// Per PAIRING, because that is where the state lives: each host has its own DCN
// dir with its own enrolment and its own request file (stepup.go). The UI is
// machine-wide, so it asks every pairing and shows one list — which is the thing
// the CLI cannot do, since `approvals` takes a --host and answers for one.
func pendingApprovals(c *Config) []uiApproval {
	// A PENDING OR REVOKED PAIRING IS NOT ASKED, and not because it has nothing
	// to say: dcnDir() is MkdirAll-on-read (config.go:115), so asking created
	// the directory. runPairing guards every such call behind cfg.active()
	// because "the order of the code below can never leak a side effect for a
	// host the anchor has not approved" (run.go:311-318) — and rendering a page
	// was doing exactly that, for every pairing, every three seconds. A pairing
	// with no lanes can have no requests either way.
	if !c.active() {
		return nil
	}
	dir := c.dcnDir()
	if dir == "" || !stepupEnrolled(dir) {
		return nil
	}
	stepupMu.Lock()
	m := requestsLoad(dir)
	stepupMu.Unlock()
	var out []uiApproval
	for _, id := range sortedPending(m) {
		short := id
		if len(short) > 8 {
			short = short[:8]
		}
		desc := describeRequest(m[id])
		var lines []string
		for _, l := range strings.Split(desc, "\n") {
			if strings.TrimSpace(l) != "" {
				lines = append(lines, l)
			}
		}
		out = append(out, uiApproval{
			ID: id, Short: short, Host: c.HostName, At: m[id].At, Lines: lines,
			Unreadable:    desc == uiUnknownRequest,
			PurposeSHA256: purposeDigest(m[id].Purpose),
		})
	}
	return out
}

// uiUnknownRequest is what describeRequest returns when details["kind"] is not
// one of the five it knows how to put into words (stepup.go).
//
// IT MATTERS MORE IN A UI THAN AT A PROMPT. The CLI prints "(unknown request)"
// and then makes you type a six-digit code, which is at least a pause. A page
// with a green Approve button beside text that says nothing is an invitation to
// approve something unreadable, and the request came from the far side of a
// tunnel. So the card changes shape: Deny becomes the primary action, Approve
// is demoted, and the reason is said out loud.
//
// This is not a theoretical case. It is what a machine sees when its host is
// NEWER than it is and has learned to ask for something this version has never
// heard of — which is the ordinary state of a fleet mid-upgrade.
const uiUnknownRequest = "(unknown request)"

// ── the server ──────────────────────────────────────────────────────────────

type uiServer struct {
	port     string // "7877" — the guard compares Host and Origin against it
	secret   string
	tickets  *uiTokenStore
	sessions *uiTokenStore
	tpl      *template.Template

	// contextUI marks the USER-RUN surface (contextui.go). It selects a
	// different ROUTE SET — not a different permission check, and that
	// distinction is the whole design. This process runs as the person who
	// typed `privatae-bastion context`, so the files it can read are the ones
	// the kernel already lets them read; nothing here adjudicates that, and
	// nothing here could widen it.
	//
	// What the flag DOES do is refuse to mount the machine-admin routes, so a
	// user-run process cannot serve the pairing list, the anchor, the marks or
	// the policy even to the person who started it. Held mechanically by
	// TestTheContextSurfaceServesNoMachineAdminRoute.
	contextUI bool
	// contextHome is the one directory this surface covers, resolved once at
	// start-up from the invoking user's own environment.
	contextHome string
	// contextMu guards contextAsks, the in-memory list of what this person asked
	// for from this window (uicontext.go).
	contextMu   sync.Mutex
	contextAsks []uiContextAsk

	// trayPipe marks the TRAY's own page beside a system service (uitray.go):
	// another route set, run by the person's tray, that reads and answers the
	// service through the approvals pipe. pipe is that call; a variable so the
	// suite drives the page off Windows.
	trayPipe bool
	pipe     func(pipeRequest) (pipeResponse, error)
}

func newUIServer(port, secret string) (*uiServer, error) {
	tpl, err := template.ParseFS(uiTemplateFS,
		"uiassets/page.html", "uiassets/status.html", "uiassets/given.html",
		"uiassets/setup.html", "uiassets/diskmap.html", "uiassets/agents.html", "uiassets/policy.html",
		"uiassets/context.html", "uiassets/approvals.html")
	if err != nil {
		return nil, err
	}
	return &uiServer{
		port:     port,
		secret:   secret,
		tickets:  newUITokenStore(uiTicketTTL),
		sessions: newUITokenStore(uiSessionTTL),
		tpl:      tpl,
	}, nil
}

// verb is the command that opens this surface. ONE answer, used by every
// refusal on both surfaces: the first cut computed it inline in root() and the
// three refusals reachable through guarded() kept saying `ui` on a page only
// `files` can open.
func (u *uiServer) verb() string {
	if u.contextUI {
		return "context"
	}
	if u.trayPipe {
		return "tray"
	}
	return "ui"
}

// status is the machine as this surface shows it: read directly by the admin
// console, through the approvals pipe by the tray's page.
func (u *uiServer) status() uiStatus {
	if u.trayPipe {
		return trayPipeStatus(u.pipe)
	}
	return collectUIStatus()
}

func (u *uiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/", u.serveAsset)
	mux.HandleFunc("/auth/ticket", u.mintTicket)
	mux.HandleFunc("/signout", u.signOut)
	// THE CONTEXT SURFACE MOUNTS NOTHING ELSE. An early return rather than a
	// condition wrapped around each block below: a route added to this function
	// next year lands on the admin console by default, which is the safe
	// direction, and the alternative — remembering to exclude it — is the kind
	// of guard that holds until somebody is in a hurry.
	if u.contextUI {
		u.contextRoutes(mux)
		return mux
	}
	// THE TRAY'S PAGE MOUNTS ONLY ITS OWN, for the same reason.
	if u.trayPipe {
		u.trayRoutes(mux)
		return mux
	}
	mux.HandleFunc("/fragments/status", u.guarded(u.statusFragment))
	// What this machine has given away (uigiven.go): the caps ceiling per host
	// and the folders shared from here. Read-only, and guarded like every other
	// route — it is the most security-relevant page in the binary.
	mux.HandleFunc("/given", u.guarded(u.givenPage))
	// THE ONE MUTATING ROUTE ON THIS PAGE, and it can only ever remove reach
	// (localdeny.go). The console can switch a granted capability off: that is
	// local control the person at the machine needs.
	mux.HandleFunc("/given/switch", u.guarded(u.givenSwitch))
	mux.HandleFunc("/fragments/given", u.guarded(u.givenFragment))
	mux.HandleFunc("/approve", u.guarded(u.approve))
	mux.HandleFunc("/deny", u.guarded(u.deny))
	// The approvals popup (uidevice.go): everything waiting on the person, and
	// the approval device's Approve / Deny, reachable from the taskbar.
	u.deviceRoutes(mux)
	// Phase 3 (uisetup.go): pairing, the step-up QR, the folder picker, and the
	// two root-gated choices the page presents but does not perform.
	u.setupRoutes(mux)
	// The disk map (uidiskmap.go): a treemap of this machine's own storage,
	// read from names and sizes only. A FILE LISTING IS SENSITIVE — the names
	// alone say what a person works on — so these are guarded like everything
	// else, and are in both leak tests in ui_test.go.
	u.diskMapRoutes(mux)
	// The automated programs this machine can see, and which of them the person
	// here has said are theirs (uisanction.go). Deliberately no control that
	// stops anything — see that file's header.
	u.agentRoutes(mux)
	// The dry-run policy (uipolicy.go): what a rule WOULD stop, and what it
	// would have stopped over the past week. Two routes, both reads — there is
	// no mutating route in that unit at all, which is the point of it.
	u.policyRoutes(mux)
	mux.HandleFunc("/", u.root)
	return mux
}

// guarded wraps a handler that requires a signed-in session.
func (u *uiServer) guarded(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if why := uiRequestAllowed(r, u.port, u.verb()); why != "" {
			http.Error(w, why, http.StatusForbidden)
			return
		}
		if !u.sessions.valid(uiSessionFrom(r)) {
			http.Error(w, "not signed in — open this page from `privatae-bastion "+u.verb()+"`",
				http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// root serves the page, and is also where a ticket is redeemed.
func (u *uiServer) root(w http.ResponseWriter, r *http.Request) {
	if why := uiRequestAllowed(r, u.port, u.verb()); why != "" {
		http.Error(w, why, http.StatusForbidden)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// ?k=<ticket>: redeem it, set the session, and REDIRECT to a clean URL so
	// the ticket is not left in the address bar, the history or a screenshot.
	// It is one-use and dies in a minute anyway; this is the second lock.
	if k := r.URL.Query().Get("k"); k != "" {
		if !u.tickets.redeem(k) {
			http.Error(w, "that link has already been used or has expired — "+
				"run `privatae-bastion "+u.verb()+"` again", http.StatusForbidden)
			return
		}
		tok, err := u.sessions.mint()
		if err != nil {
			http.Error(w, "could not start a session", http.StatusInternalServerError)
			return
		}
		uiSetSessionCookie(w, tok)
		// A ticket may name where it lands (?to=), but only a page on the short
		// list in uidevice.go: the link goes through a browser, and an open
		// redirect on it would be a phishing tool pointed at this machine.
		http.Redirect(w, r, uiLanding(r.URL.Query().Get("to")), http.StatusSeeOther)
		return
	}
	if !u.sessions.valid(uiSessionFrom(r)) {
		http.Error(w, "not signed in — open this page from `privatae-bastion "+u.verb()+"`",
			http.StatusUnauthorized)
		return
	}
	if u.contextUI {
		// The context surface has no status page to land on, and `p` is how it
		// walks into a folder — so root IS the map.
		u.contextPage(w, r)
		return
	}
	if u.trayPipe {
		// The tray's page is the approvals window and nothing else.
		u.approvalsPage(w, r)
		return
	}
	u.render(w, "page.html")
}

func (u *uiServer) statusFragment(w http.ResponseWriter, r *http.Request) {
	u.render(w, "status")
}

func (u *uiServer) render(w http.ResponseWriter, name string) {
	u.renderWith(w, name, "", "")
}

// renderWith re-reads the machine's state and renders it, carrying an outcome
// line. The state is ALWAYS re-read rather than patched: after an approve the
// request is gone, and rendering a remembered list would leave the card the
// user just answered sitting on screen.
func (u *uiServer) renderWith(w http.ResponseWriter, name, flash, class string) {
	u.renderStatus(w, name, flash, class, false)
}

// renderStatus is the one render path: a fresh read of the machine, the outcome
// line, and whether the popup (not the front page) is what is being drawn.
func (u *uiServer) renderStatus(w http.ResponseWriter, name, flash, class string, approvalsView bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// This page renders only local state, but it costs nothing to say that
	// nothing may be loaded into it from anywhere else.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s := u.status()
	s.Flash, s.FlashClass = flash, class
	s.ApprovalsView = approvalsView
	if err := u.tpl.ExecuteTemplate(w, name, s); err != nil {
		uilogf("render %s: %v\n", name, err)
	}
}

// renderAnswer draws the outcome of a step-up approve or deny into whichever
// page the card was on: the popup posts view=approvals, the front page does not.
func (u *uiServer) renderAnswer(w http.ResponseWriter, r *http.Request, flash, class string) {
	if r.FormValue("view") == "approvals" {
		u.renderApprovals(w, "approvals", flash, class)
		return
	}
	u.renderWith(w, "status", flash, class)
}

// approvalTarget resolves the posted host+id to the pairing's DCN dir.
//
// The host is looked UP among this machine's pairings rather than trusted as a
// path component: the form is local and session-authed, but a handler that
// joins a posted string onto a directory is the shape of bug that turns a local
// UI into a file-system reach, and there is no reason to write it that way when
// the pairing list is right here.
func approvalTarget(host string) (*Config, error) {
	cfgs, err := loadPairings()
	if err != nil {
		return nil, err
	}
	for _, c := range cfgs {
		if c.HostName == host {
			// The same active() guard the reading paths take, and here it is a
			// correctness rule as well as a side-effect one: approving a request
			// for a pairing the anchor has not approved would answer on behalf
			// of a host that holds no lanes to act on the answer. Both callers
			// below reach cfg.dcnDir(), which is MkdirAll-on-read.
			if !c.active() {
				return nil, fmt.Errorf("this machine does not serve %q yet — that pairing is %s",
					host, c.stateName())
			}
			return c, nil
		}
	}
	return nil, fmt.Errorf("this machine does not serve %q", host)
}

// approve: the whole reason the UI exists. The host asked for something, the
// request has been sitting in a file, and until now the only way to answer was
// to know to type `privatae-bastion approvals` at a terminal that, on Windows,
// may not exist.
//
// NO ATTEMPT THROTTLE, deliberately. Step-up defends against a compromised
// HOST — the host never handles the code — and a host cannot reach this form at
// all: the UI is loopback-only and the bastion has no MCP ingress. The only
// caller who can reach it is a process running as this user, and that process
// can read the TOTP seed straight out of stepup.json (stepupFile.SecretB32) in
// the same directory. Guessing codes gains an attacker nothing over reading the
// file, so a lockout would cost a real user a locked account and cost an
// attacker nothing.
func (u *uiServer) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	host, id, code := r.FormValue("host"), r.FormValue("id"), strings.TrimSpace(r.FormValue("code"))
	cfg, err := approvalTarget(host)
	if err != nil {
		u.renderAnswer(w, r, err.Error(), "bad")
		return
	}
	if code == "" {
		u.renderAnswer(w, r, "Enter the code from the authenticator enrolled on this machine.", "warn")
		return
	}
	if _, err := stepupApproveRequest(cfg.dcnDir(), id, code); err != nil {
		u.renderAnswer(w, r, "Not approved: "+err.Error(), "bad")
		return
	}
	u.renderAnswer(w, r,
		"Approved. "+host+" picks this up on its next check-in, within a minute.", "ok")
}

func (u *uiServer) deny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	host, id := r.FormValue("host"), r.FormValue("id")
	cfg, err := approvalTarget(host)
	if err != nil {
		u.renderAnswer(w, r, err.Error(), "bad")
		return
	}
	// Denying needs no code: refusing is always the safe direction, and asking
	// for a second factor to say NO would train people to approve instead.
	if err := stepupDenyRequest(cfg.dcnDir(), id); err != nil {
		u.renderAnswer(w, r, "Not denied: "+err.Error(), "bad")
		return
	}
	u.renderAnswer(w, r, "Denied. "+host+" is told on its next check-in.", "ok")
}

// mintTicket is the ONE route authenticated by the long-lived secret rather than
// a cookie, and it is the CLI that calls it. It deliberately does NOT take the
// Origin check the cookie routes take: a bearer header cannot be attached by a
// page cross-origin without a preflight this mux never answers, so there is no
// CSRF to defend against here — while a Go client legitimately sends no Origin
// at all. The Host check still applies, because rebinding does not care what
// authenticates.
func (u *uiServer) mintTicket(w http.ResponseWriter, r *http.Request) {
	if !uiLoopbackHost(r.Host, u.port) {
		http.Error(w, "not reachable this way", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	offered := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !uiSecretMatches(offered, u.secret) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tok, err := u.tickets.mint()
	if err != nil {
		http.Error(w, "could not mint", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"ticket": tok})
}

// signOut is POST-only, which it was not at first. As a GET it
// took only the Host check — uiRequestAllowed exempts reads from the Origin
// check, correctly, because a read is safe — so any page could have signed the
// user out with an <img src>. Harmless in effect and unreachable today (nothing
// links here), but a logout that any site can trigger is a papercut with a
// well-known name, and the fix is one line. As a POST it takes the Origin check
// like every other state change.
func (u *uiServer) signOut(w http.ResponseWriter, r *http.Request) {
	// HOST CHECK FIRST, method second. Putting the method check on top read
	// fine and answered a rebound host with 405 instead of 403 — refused either
	// way, but it tells a caller the route exists and what it takes, and the
	// rebinding wall is supposed to be the OUTERMOST thing on every route.
	// Caught by TestEveryRouteRefusesARebindingHost, which walks all of them.
	if why := uiRequestAllowed(r, u.port, u.verb()); why != "" {
		http.Error(w, why, http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u.sessions.drop(uiSessionFrom(r))
	uiClearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (u *uiServer) serveAsset(w http.ResponseWriter, r *http.Request) {
	if !uiLoopbackHost(r.Host, u.port) {
		http.Error(w, "not reachable this way", http.StatusForbidden)
		return
	}
	// Assets are not secret and are needed before a session exists (the error
	// pages are plain text, but the page itself loads them on first paint).
	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	switch name {
	case "htmx.min.js", "app.css", "given.css", "setup.css", "diskmap.css", "agents.css",
		"policy.css", "context.css":
	default:
		http.NotFound(w, r)
		return
	}
	b, err := uiStaticFS.ReadFile("uiassets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Embedded in the binary, so it changes only when the binary does.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(b)
}

// ── lifecycle ───────────────────────────────────────────────────────────────

// uiAddrPath holds the address the UI actually bound, so `privatae-bastion ui`
// does not have to guess it after a fallback.
func uiAddrPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "ui.addr"), nil
}

// startUIServer binds the UI and serves until ctx is done. ONE per machine,
// started from cmdRun — not per pairing, because the UI shows the whole box.
//
// LOOPBACK IS THE POINT, not an oversight. This listener exposes the pairing
// list, the anchor, the machine owner and (phase 2) the approval prompts. It is
// the user's own machine talking to the user sitting at it. Binding anything
// wider would publish a person's control surface to their LAN, which is the
// exact inverse of what this product is. Nothing off-box ever reaches it: the
// host reaches this machine only through the lanes the bastion dials OUT.
func startUIServer(ctx context.Context) {
	// Claimed BEFORE the port work below, which has two early returns. The
	// record of what a host did to this machine must not depend on a free TCP
	// port — events.go's header has the rest — and the version check is the only
	// thing in the binary that can tell a user their machine is behind.
	openLocalEventLog()
	go runUpdateAvailabilityPoll(ctx)
	// The dry-run policy census (policy.go). Here beside the update poll rather
	// than inside the page, because a measurement of what a rule WOULD stop over
	// a week has to accumulate while nobody has a browser open — and because a
	// render that wrote to disk is the defect ui_approvals_flow_test.go:9-15 exists
	// for. It writes only when the set of candidates changes or its own clock
	// goes stale, so a machine with nothing to report costs nothing.
	//
	// ABOVE the port work below for the same reason the event log is: that code
	// has two early returns, and what this rule would have taken away from
	// somebody must not go unrecorded because a TCP port was busy.
	go runPolicyCensus(ctx)
	// The context socket (contextsock.go): how a LOCAL USER who is not this
	// daemon's owner asks for a folder to become context. Started here, beside
	// the other background lanes and above the port work, for the same reason
	// they are — that code has early returns, and a person's ability to ask
	// must not depend on a free TCP port.
	startContextSock(ctx.Done())
	secret, err := loadOrCreateUISecret()
	if err != nil {
		uilogf("not started (%v)\n", err)
		return
	}
	var ln net.Listener
	var port string
	for p := uiPortHigh; p >= uiPortLow; p-- {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln, port = l, fmt.Sprint(p)
			break
		}
	}
	if ln == nil {
		uilogf("no free port between %d and %d — the local UI is not available\n",
			uiPortLow, uiPortHigh)
		return
	}
	srv, err := newUIServer(port, secret)
	if err != nil {
		uilogf("not started (%v)\n", err)
		_ = ln.Close()
		return
	}
	addr := ln.Addr().String()
	if p, err := uiAddrPath(); err == nil {
		_ = os.WriteFile(p, []byte(addr), 0o600)
	}
	h := &http.Server{
		Handler:           srv.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.Shutdown(sh)
	}()
	go func() {
		uilogf("listening on http://%s — open it with `privatae-bastion ui`\n", addr)
		if err := h.Serve(ln); err != nil && err != http.ErrServerClosed {
			uilogf("%v\n", err)
		}
	}()
}

// ── the `ui` verb ───────────────────────────────────────────────────────────

// localUIEntryURL mints a one-use ticket against the RUNNING daemon and returns
// the URL that redeems it, plus the address it is on.
//
// The tray (tray_windows.go) goes through this same path even though it lives
// inside the daemon and could mint from the server object directly. One code
// path, exercised identically by the CLI and by the menu item, is worth more
// than saving a sub-millisecond round trip on loopback — and it means a tray
// that can open the UI proves the CLI can too.
func localUIEntryURL() (entry, addr string, err error) {
	return localUIEntryURLTo("")
}

// localUIEntryURLTo is localUIEntryURL landing on `to` after sign-in (one of
// uiLandingPaths; anything else lands on the front page).
func localUIEntryURLTo(to string) (entry, addr string, err error) {
	addr = "127.0.0.1:" + fmt.Sprint(uiPortHigh)
	if p, err := uiAddrPath(); err == nil {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			addr = strings.TrimSpace(string(b))
		}
	}
	if !bastionListening(addr) {
		return "", addr, fmt.Errorf("the bastion is not running on this machine, so "+
			"there is nothing to show.\n  Start it with `%s`, then run this again",
			runCommandHint())
	}
	secret, err := loadOrCreateUISecret()
	if err != nil {
		return "", addr, err
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/auth/ticket", nil)
	if err != nil {
		return "", addr, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", addr, fmt.Errorf("could not reach the local UI at %s: %w", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", addr, fmt.Errorf("the local UI refused this machine's own key (%s) — "+
			"if the bastion was reinstalled, restart it so it and this command agree",
			resp.Status)
	}
	var out struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Ticket == "" {
		return "", addr, fmt.Errorf("the local UI returned no ticket")
	}
	entry = "http://" + addr + "/?k=" + out.Ticket
	if to != "" {
		entry += "&to=" + url.QueryEscape(to)
	}
	return entry, addr, nil
}

// cmdUI opens the local UI in a browser. It does NOT start a server: the UI
// belongs to the running daemon, because that is the process that knows what is
// live.
func cmdUI() error {
	entry, addr, err := localUIEntryURL()
	if err != nil {
		return err
	}
	fmt.Printf("opening the local UI: http://%s\n", addr)
	if err := openBrowser(entry); err != nil {
		fmt.Printf("\ncould not open a browser (%v).\nPaste this into one, within a minute:\n\n  %s\n\n", err, entry)
	}
	return nil
}

// openBrowser hands a URL to whatever the desktop uses. hideConsole matters
// here for the same reason it matters everywhere else on Windows: started from
// a console-less daemon or a double-click, rundll32 would flash a window
// (console_windows.go).
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	hideConsole(cmd)
	return cmd.Start()
}
