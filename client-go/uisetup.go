package main

// uisetup.go — the local UI's SET IT UP page (phase 3 of the local UI).
//
// WHY IT EXISTS. Every capability on this page already has a CLI verb, and
// every one of them is painful or impossible for a person who does not live in
// a terminal. The QR code for a second factor is printed as block glyphs into a
// console window (stepup.go:786) that, after a self-update on Windows, does not
// exist. `claim-anchor` on a box serving three hosts refuses and prints the
// names to choose from (anchor.go:902) — a list with one choice is what that
// refusal is asking for. `add-folder` takes an absolute path typed blind
// (addfolder.go:57). These are the onboarding steps, in the order they happen,
// and they are where a person falls off.
//
// THE LINE THIS DOES NOT CROSS is ui.go's: the page reads local state and acts
// on THIS MACHINE. It never originates a request to the host. `add-folder` is
// the one outward-facing thing here and it stays inside the line for the reason
// the design gives: the draft rides the tunnel and is inert until the
// user approves it in their host (addfolder.go:132-137).
//
// ── WHY THE ANCHOR AND THE OWNER NAME ARE CHOOSERS, NOT DOERS ───────────────
//
// Both are gated by requireMachineAuthority (anchor.go:816, owner.go:83), which
// asks processIsRoot(): euid 0 on unix (session_unix.go:31), elevated and in
// Administrators on Windows (privilege_windows.go:47). That is a question about
// the PROCESS — and this page runs inside that process. startUIServer is called
// from cmdRun (run.go:131), and deploy/install.sh:154 writes the networked unit
// with no `User=` line, deliberately: "the service runs as root". So on the box
// where an anchor picker is needed at all — a networked one, serving several
// hosts — the gate would simply pass if this page called the function.
//
// So this is not "the page cannot". It is "the page must not", and the reason
// has to be written down or someone will helpfully add the button later:
//
//   - The credential behind this page is a 12-hour cookie in a BROWSER
//     (uiauth.go:66). The credential behind `sudo -H` is a password prompt
//     answered seconds ago at a terminal. Moving the machine's constitutional
//     act — who approves every future pairing here, for as long as the box
//     lives — from the second to the first lowers the bar that root is there to
//     hold, whatever the euid of the process happens to be.
//   - The design already draws this line for the anchor's siblings:
//     `claim-anchor --rotate` is CLI because it is rare, consequential, and
//     deserves the friction — show the state in the UI, keep the action in the
//     CLI. A first claim is the same act with no predecessor to consent.
//   - And on a networked box the person reading this page is already root. The
//     UI secret is 0600 in the daemon's own config dir (uiauth.go:127), and a
//     non-root `privatae-bastion ui` reads a DIFFERENT config dir, mints a
//     different secret and is refused by /auth/ticket. So the terminal this
//     page hands a command to is open in front of them.
//
// What the page does instead is the part that was actually missing: it shows
// the state, it makes the choice a click instead of a hostname to transcribe,
// it checks the choice against the same rules the command will apply, and it
// writes out the exact line with the chosen host already in it. No escalation
// path is invented here, and none should be.

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

// uiEnrolTTL bounds a step-up enrolment that has been started and not confirmed.
// For that long the new TOTP secret lives in this process's memory and nowhere
// else — not on disk, not in a URL, not in the page.
//
// Ten minutes, because the number is set by what the person is doing: fetching
// a phone, unlocking it, finding the authenticator, scanning, typing six
// digits. uiTicketTTL (uiauth.go:63) is 60 seconds because it only has to
// survive a browser launch; this one has to survive a human walking to a drawer.
const uiEnrolTTL = 10 * time.Minute

// ── pending enrolments ──────────────────────────────────────────────────────

// uiEnrol is one half-finished step-up enrolment.
//
// SecretB32 is a CREDENTIAL and is treated like one: it is rendered as PIXELS
// (the QR route), or as text only when the person explicitly asks for it, and
// it reaches disk only once a code proves the authenticator holds it. The CLI
// prints both the otpauth URI and the base32 key into a terminal's scrollback
// (stepup.go:792-794) for a reason it states — a QR is useless over a serial
// console — and that reason does not apply in a browser, so the default here is
// the stricter one.
type uiEnrol struct {
	Host      string
	SecretB32 string
	URI       string
	Expires   time.Time
}

type uiEnrolStore struct {
	mu sync.Mutex
	m  map[string]*uiEnrol // handle -> enrolment
}

func newUIEnrolStore() *uiEnrolStore { return &uiEnrolStore{m: map[string]*uiEnrol{}} }

// put replaces any enrolment already in flight FOR THE SAME HOST. Starting over
// is the ordinary way out of a scan that did not take, and leaving the previous
// secret sitting in memory would mean a code from the abandoned one still
// enrolled something.
func (s *uiEnrolStore) put(e *uiEnrol) (string, error) {
	h, err := genSecret(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	for k, v := range s.m {
		if v.Host == e.Host {
			delete(s.m, k)
		}
	}
	s.m[h] = e
	return h, nil
}

func (s *uiEnrolStore) get(handle string) *uiEnrol {
	if handle == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	return s.m[handle]
}

// forHost is what the page renders from: after any re-render the enrolment in
// flight has to be found again without the browser holding the handle.
func (s *uiEnrolStore) forHost(host string) (string, *uiEnrol) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	for h, e := range s.m {
		if e.Host == host {
			return h, e
		}
	}
	return "", nil
}

func (s *uiEnrolStore) drop(handle string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, handle)
}

func (s *uiEnrolStore) sweepLocked() {
	now := uiNow()
	for k, e := range s.m {
		if now.After(e.Expires) {
			delete(s.m, k)
		}
	}
}

// ── the server half ─────────────────────────────────────────────────────────

// uiSetup holds the state this page needs that the machine does not already
// have on disk: enrolments that have been started and not finished.
//
// It hangs off the mux rather than off uiServer so registering these routes is
// one line in ui.go's handler(), and so two servers in one test process cannot
// see each other's half-finished enrolments.
type uiSetup struct {
	u      *uiServer
	enrols *uiEnrolStore
}

// setupRoutes registers phase 3. Every route goes through u.guarded, which runs
// the Host check before anything else (uiauth.go:258) and the Origin check on
// anything that is not a read.
//
// The method check lives INSIDE each handler rather than in the mux pattern,
// and that is deliberate: Go's method patterns would answer a rebound host with
// 405 before uiRequestAllowed ever ran, and the rebinding wall is supposed to
// be the outermost thing on every route (ui.go:464, and the test that walks
// them all).
//
// It returns the state it registered, which ui.go ignores and the tests use:
// an enrolment in flight lives in memory by design, so a test that cannot reach
// it can only assert that the page does not show a secret — never that the
// right secret was the one enrolled.
func (u *uiServer) setupRoutes(mux *http.ServeMux) *uiSetup {
	s := &uiSetup{u: u, enrols: newUIEnrolStore()}
	mux.HandleFunc("/setup", u.guarded(s.page))
	mux.HandleFunc("/setup/pair", u.guarded(s.pair))
	mux.HandleFunc("/setup/stepup/start", u.guarded(s.stepupStart))
	mux.HandleFunc("/setup/stepup/qr", u.guarded(s.stepupQR))
	mux.HandleFunc("/setup/stepup/key", u.guarded(s.stepupKey))
	mux.HandleFunc("/setup/stepup/confirm", u.guarded(s.stepupConfirm))
	mux.HandleFunc("/setup/folder/check", u.guarded(s.folderCheck))
	mux.HandleFunc("/setup/folder/propose", u.guarded(s.folderPropose))
	mux.HandleFunc("/setup/anchor/choose", u.guarded(s.anchorChoose))
	mux.HandleFunc("/setup/owner/name", u.guarded(s.ownerName))
	return s
}

// ── what the page shows ─────────────────────────────────────────────────────

type uiSetupHost struct {
	Name     string
	State    string
	Active   bool
	IsAnchor bool
	Serving  bool // its loopback control port answers — add-folder goes there
	Stepup   bool // a second factor is enrolled for this pairing
}

// uiEnrolView is an enrolment in flight. The SECRET IS NOT IN IT: the handle
// addresses it server-side and the QR route turns it into pixels. Key is filled
// only by the one route the person has to press a button to reach.
type uiEnrolView struct {
	Handle string
	Host   string
	Key    string
}

// uiFolderCheck is one typed path resolved against the real filesystem, before
// anything is proposed to anyone.
type uiFolderCheck struct {
	Typed    string
	Resolved string
	Class    string // ok | warn | bad
	Line     string
	Note     string
}

// uiCommand is a line the person runs themselves, because this page will not.
type uiCommand struct {
	Command string
	How     string
	Why     string
	Class   string // ok | warn | bad — bad means "this cannot be run yet"
}

type uiSetupView struct {
	Version        string
	Mode           string
	Networked      bool
	Hosts          []uiSetupHost
	Servable       []uiSetupHost // active pairings: what a folder or a factor attaches to
	AnchorHost     string
	AnchorOwner    string
	AnchorRequired bool
	Owner          string

	// ReadError is why the pairing list could not be read — see uiGiven's copy
	// of this field. Returning the bare view here showed an empty setup page
	// for a machine whose records simply could not be read.
	ReadError string

	Flash      string
	FlashClass string

	Enrol *uiEnrolView
	Check *uiFolderCheck
	Cmd   *uiCommand
}

// collectSetupView re-reads the machine every time, for the same reason
// renderWith does (ui.go:336): after a pair or an enrolment the previous view
// is wrong, and a remembered one would leave the user looking at the state they
// just changed.
func (s *uiSetup) view() uiSetupView {
	v := uiSetupView{
		Version:   clientVersion,
		Mode:      boxMode(),
		Networked: boxMode() == modeNetworked,
	}
	if a := currentAnchor(); a != nil {
		v.AnchorHost, v.AnchorOwner = a.AnchorHost, a.Owner
	} else if v.Networked {
		// anchor.go:496 — a networked box with no anchor serves nothing at all.
		v.AnchorRequired = true
	}
	if o := currentOwnerClaim(); o != nil {
		v.Owner = o.Owner
	}
	cfgs, err := loadPairings()
	if err != nil {
		v.ReadError = err.Error()
		return v
	}
	for _, c := range cfgs {
		h := uiSetupHost{
			Name:     c.HostName,
			State:    c.stateName(),
			Active:   c.active(),
			IsAnchor: v.AnchorHost != "" && c.HostName == v.AnchorHost,
		}
		// dcnDir() is MkdirAll-on-read (config.go:115), so asking a PENDING
		// pairing whether it has a factor would create its state directory —
		// the side effect runPairing guards every one of these behind
		// cfg.active() to prevent (run.go:311). Rendering a page must not be
		// the thing that creates state for a host the anchor has not approved.
		if h.Active {
			h.Stepup = stepupEnrolled(c.dcnDir())
			h.Serving = bastionListening(c.ListenAddr)
		}
		v.Hosts = append(v.Hosts, h)
		if h.Active {
			v.Servable = append(v.Servable, h)
		}
	}
	return v
}

// render mirrors ui.go's renderWith headers exactly — no-store, the same CSP
// with no 'unsafe-inline', nosniff. It is a second function rather than a call
// into that one because the view model differs; TestTheSetupPageIsHeldToTheSame
// HeadersAsTheStatusPage is what stops the two drifting apart.
func (s *uiSetup) render(w http.ResponseWriter, name string, v uiSetupView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := s.u.tpl.ExecuteTemplate(w, name, v); err != nil {
		uilogf("render %s: %v\n", name, err)
	}
}

// flash re-reads the machine and renders the whole page body with an outcome.
func (s *uiSetup) flash(w http.ResponseWriter, msg, class string) {
	v := s.view()
	v.Flash, v.FlashClass = msg, class
	s.fill(&v)
	s.render(w, "setup", v)
}

// fill puts any enrolment in flight back into the view, so a re-render caused
// by something else does not lose the QR the person is looking at.
func (s *uiSetup) fill(v *uiSetupView) {
	for _, h := range v.Hosts {
		if handle, e := s.enrols.forHost(h.Name); e != nil {
			v.Enrol = &uiEnrolView{Handle: handle, Host: e.Host}
			return
		}
	}
}

func (s *uiSetup) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	v := s.view()
	s.fill(&v)
	s.render(w, "setup-page", v)
}

// setupHost resolves a posted host name against this machine's pairings. Looked
// UP rather than trusted, for the reason approvalTarget gives (ui.go:350): a
// handler that joins a posted string onto a directory is the shape of bug that
// turns a local UI into a filesystem reach, and the pairing list is right here.
func setupHost(host string) (*Config, error) {
	cfgs, err := loadPairings()
	if err != nil {
		return nil, err
	}
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("no host is paired with this machine yet")
	}
	host = strings.TrimSpace(host)
	if host == "" && len(cfgs) == 1 {
		return cfgs[0], nil
	}
	if host == "" {
		return nil, fmt.Errorf("this machine serves %d hosts — choose which one", len(cfgs))
	}
	for _, c := range cfgs {
		if c.HostName == host {
			return c, nil
		}
	}
	return nil, fmt.Errorf("this machine does not serve %q", host)
}

// ── 1. pair ─────────────────────────────────────────────────────────────────

// uiWithoutToken keeps a pairing token out of anything the page renders.
//
// Nothing in pairWithToken's error paths echoes the token today — decodeToken
// answers "malformed token" without quoting it (pair.go:53) and the redeem
// errors name the host. But the token is single-use CREDENTIAL material that
// arrived in this request, the error text comes from six functions and a remote
// host's JSON, and the cost of being sure is four lines.
func uiWithoutToken(msg, token string) string {
	if len(token) < 8 {
		return msg
	}
	return strings.ReplaceAll(msg, token, "the token")
}

// uiPairPlan is what the RUNNING daemon must do about a pairing that just
// changed. Decided separately from being done, so the decision can be tested
// without standing up a WireGuard device.
//
// THE SUBTLETY THIS EXISTS FOR. The UI server lives inside cmdRun (run.go:131),
// and cmdRun started one runPairing goroutine per pairing at boot
// (run.go:118). Pairing from this page changes that set underneath the running
// daemon, and the CLI's answer — "Start (or restart) the tunnels" (pair.go:200)
// — is not available to a page: there is no terminal, and restarting the daemon
// from inside itself to serve one new host would drop every other host's tunnel.
//
// superviseOnce (run.go:254) already reconciles disk against what is running,
// every 15 seconds, and that is the catch-up. This plan is the same three rules
// applied AT ONCE so the person is not left looking at a pairing that does
// nothing for a quarter of a minute with no explanation:
//
//   - a --replace rotated the credentials, so the lane still running for that
//     host holds dead ones and must be stopped before the new one starts;
//   - a --replace that lands a different host_name removes the old pairing file
//     (pair.go:370), so the lane running under the OLD name must stop too;
//   - a pairing written PENDING starts nothing, and says so, because that is
//     what anchoring means (pair.go:186).
type uiPairPlan struct {
	Stop  []string
	Start string // "" when the pairing is not active
	Note  string
	Class string
}

func planPairChange(before []string, after []*Config, cfg *Config) uiPairPlan {
	onDisk := map[string]bool{}
	for _, c := range after {
		onDisk[c.HostName] = true
	}
	p := uiPairPlan{}
	for _, h := range before {
		// Stop what is stale: a host whose file is gone (renamed away by a
		// --replace), and the re-paired host itself, whose running lane holds
		// the credentials this redeem has just rotated out.
		if !onDisk[h] || h == cfg.HostName {
			p.Stop = append(p.Stop, h)
		}
	}
	if !cfg.active() {
		p.Note = "Paired with " + cfg.HostName + " — PENDING. This machine is anchored, so a " +
			"new host waits until the anchor host approves it. Nothing is started for it yet: " +
			"no tunnel, no lanes. It shows as a pending pairing on the anchor host's Network app."
		p.Class = "warn"
		return p
	}
	p.Start = cfg.HostName
	p.Note = "Paired with " + cfg.HostName + "."
	p.Class = "ok"
	return p
}

// applyPairPlan carries the plan out against the running daemon and returns the
// outcome in the words the person gets. What it says depends on what actually
// happened, not on what was planned: supervisorStart answers false from a
// process that is not serving (run.go:174), and claiming a tunnel is open when
// it is not is the failure this whole function exists to avoid.
func applyPairPlan(p uiPairPlan, cfg *Config) (string, string) {
	for _, h := range p.Stop {
		stopPairing(h)
	}
	if p.Start == "" {
		return p.Note, p.Class
	}
	if supervisorStart(cfg) {
		return p.Note + " Its tunnel and lanes are open now — nothing to restart.", p.Class
	}
	return p.Note + " Its lanes open on this machine's next sweep, within 15 seconds.", p.Class
}

// pair redeems a token from the host's "Set up a bastion".
//
// The token arrives in a POST body and is never written back into the page, a
// log line or a URL: it is single-use credential material, and uiauth.go's
// whole front door exists because a secret in an address bar outlives the
// moment it was useful.
func (s *uiSetup) pair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	replace := r.FormValue("replace") != ""
	if token == "" {
		s.flash(w, "Paste the token from your host's “Set up a bastion”.", "warn")
		return
	}
	before, err := loadPairings()
	if err != nil {
		s.flash(w, "Cannot read this machine's pairings: "+err.Error(), "bad")
		return
	}
	cfg, all, err := pairWithToken(token, replace, false)
	if err != nil {
		s.flash(w, uiWithoutToken(err.Error(), token), "bad")
		return
	}
	note, class := applyPairPlan(planPairChange(hostNames(before), all, cfg), cfg)
	s.flash(w, note, class)
}

// ── 2. step-up enrolment, with a real QR ────────────────────────────────────

// stepupStart mints a secret and holds it in memory. Nothing reaches disk until
// a code proves the authenticator has it — the same order cmdStepupEnroll uses
// (stepup.go:799-803), so a scan that silently failed cannot leave the machine
// holding a factor nobody can produce a code for.
func (s *uiSetup) stepupStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := setupHost(r.FormValue("host"))
	if err != nil {
		s.flash(w, err.Error(), "bad")
		return
	}
	// A PENDING OR REVOKED PAIRING GETS NOTHING, INCLUDING A DIRECTORY.
	// cfg.dcnDir() is MkdirAll-on-read (config.go:115), and runPairing guards
	// every one of those behind cfg.active() precisely so "the order of the code
	// below can never leak a side effect for a host the anchor has not approved"
	// (run.go:311-318). Enrolling a factor for a pending host would create that
	// host's state dir from a page — and the factor could never be used anyway,
	// because it gates dcn ops and a pending pairing has no lanes to run them on.
	if !cfg.active() {
		s.flash(w, cfg.HostName+" is "+cfg.stateName()+" on this machine. Nothing is created for "+
			"it here until the anchor host approves the pairing — including a second factor, "+
			"which gates ops it cannot run yet.", "warn")
		return
	}
	dir := cfg.dcnDir()
	if dir == "" {
		s.flash(w, "Cannot open this pairing's state directory on this machine.", "bad")
		return
	}
	// Replacing an enrolled factor is --rotate (stepup.go:767), and it stops the
	// authenticator already enrolled here from working. So it takes a deliberate
	// tick, the same way the flag is deliberate.
	if stepupEnrolled(dir) && r.FormValue("replace") == "" {
		s.flash(w, "A second factor is already enrolled for "+cfg.HostName+" on this machine. "+
			"Tick “replace it” to enrol a new one — the authenticator enrolled now stops working.", "warn")
		return
	}
	var secret [20]byte
	if _, err := rand.Read(secret[:]); err != nil {
		s.flash(w, "Could not generate a secret on this machine: "+err.Error(), "bad")
		return
	}
	b32 := strings.TrimRight(base32.StdEncoding.EncodeToString(secret[:]), "=")
	hn, _ := os.Hostname()
	// Byte-identical to the URI the CLI builds (stepup.go:777-779) so the same
	// authenticator entry appears however it was enrolled.
	label := url.PathEscape("Privatae NAC:" + hn + " for " + cfg.HostName)
	uri := "otpauth://totp/" + label + "?secret=" + b32 + "&issuer=" + url.QueryEscape("Privatae NAC") +
		"&digits=6&period=30"
	handle, err := s.enrols.put(&uiEnrol{
		Host: cfg.HostName, SecretB32: b32, URI: uri, Expires: uiNow().Add(uiEnrolTTL),
	})
	if err != nil {
		s.flash(w, "Could not start an enrolment: "+err.Error(), "bad")
		return
	}
	v := s.view()
	v.Enrol = &uiEnrolView{Handle: handle, Host: cfg.HostName}
	v.Flash = "Scan the square with your authenticator app, then type a code from it below. " +
		"Nothing is enrolled on this machine until that code matches."
	v.FlashClass = "ok"
	s.render(w, "setup", v)
}

// stepupQR renders the enrolment as a PNG.
//
// A GET, because an <img> cannot be anything else. It carries the HANDLE, never
// the secret: an address bar, a history file and a referrer header are exactly
// the places uiauth.go refuses to put credentials, and a QR is a picture of one.
// The handle is 32 random bytes, dies with the enrolment, and the route still
// takes the session and the Host check like every other one. A GET is where the
// Origin check stops applying (uiauth.go:264) and it does not matter here:
// SameSite=Strict means no cookie is attached to a cross-site <img> at all, so
// the request arrives with no session and is refused — and a cross-origin image
// is unreadable to the page that loaded it either way.
//
// The image is also no-store: a browser that cached it would hand the next
// person at this machine a picture of a live secret.
func (s *uiSetup) stepupQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	e := s.enrols.get(r.URL.Query().Get("e"))
	if e == nil {
		http.Error(w, "that enrolment has expired — start it again", http.StatusNotFound)
		return
	}
	// qr.M is ~15% recovery, the level qrTerminal picked for the same payload
	// (stepup_qr.go:38). On a screen it buys tolerance for a phone held at an
	// angle; the cost is a slightly larger symbol, which a browser has room for.
	c, err := qr.Encode(e.URI, qr.M)
	if err != nil {
		http.Error(w, "could not render the code", http.StatusInternalServerError)
		return
	}
	// PNG() writes 4 modules of quiet zone on every side ((size+8)*scale) — the
	// margin scanners need to find the symbol, and the single most common reason
	// a hand-rolled QR does not scan (stepup_qr.go:22).
	png := c.PNG()
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(png)
}

// stepupKey shows the base32 key as text, and only when asked.
//
// It exists because an authenticator can be on THIS machine, where you cannot
// photograph your own screen — the one case the CLI's text fallback covers that
// a browser does not solve. Behind a button rather than in the page, so a
// secret is not in a screenshot, a screen share or a page left open; that is the
// same discipline uiauth.go applies to the ticket.
func (s *uiSetup) stepupKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	handle := r.FormValue("enrol")
	e := s.enrols.get(handle)
	if e == nil {
		s.render(w, "stepup-key", uiSetupView{})
		return
	}
	s.render(w, "stepup-key", uiSetupView{
		Enrol: &uiEnrolView{Handle: handle, Host: e.Host, Key: e.SecretB32},
	})
}

// stepupConfirm verifies a code against the secret held in memory and only then
// writes it. Same check and same file shape as the CLI (stepup.go:799-804) —
// stepupMatchedCounter and stepupSave, not a second implementation of either.
func (s *uiSetup) stepupConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	handle := r.FormValue("enrol")
	e := s.enrols.get(handle)
	if e == nil {
		s.flash(w, "That enrolment has expired — start it again. Nothing was enrolled.", "warn")
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		s.flash(w, "Type a code from the authenticator you just scanned with.", "warn")
		return
	}
	cfg, err := setupHost(e.Host)
	if err != nil {
		s.flash(w, err.Error(), "bad")
		return
	}
	// Re-checked here and not only at start: a pairing can be revoked by the
	// anchor between scanning the square and typing the code, and the write
	// below would create its state dir.
	if !cfg.active() {
		s.enrols.drop(handle)
		s.flash(w, cfg.HostName+" became "+cfg.stateName()+" while you were enrolling, so "+
			"nothing was written. Nothing is created for it here until the anchor host "+
			"approves the pairing.", "warn")
		return
	}
	dir := cfg.dcnDir()
	if dir == "" {
		s.flash(w, "Cannot open this pairing's state directory on this machine.", "bad")
		return
	}
	if stepupMatchedCounter(e.SecretB32, code, time.Now()) < 0 {
		s.flash(w, "That code did not match — nothing was enrolled. Check the app is showing a "+
			"code for “Privatae NAC”, and try the next one.", "bad")
		return
	}
	if err := stepupSave(dir, &stepupFile{
		SecretB32:   e.SecretB32,
		EnrolledAt:  time.Now().UTC().Format(time.RFC3339),
		LastCounter: -1,
	}); err != nil {
		s.flash(w, "Could not write the factor to this machine: "+err.Error(), "bad")
		return
	}
	s.enrols.drop(handle)
	s.flash(w, "Enrolled for "+cfg.HostName+". From now on that host can only reach a folder or "+
		"move files here after you approve the request ON THIS MACHINE — the approval appears on "+
		"the front page and your host never sees the code.", "ok")
}

// ── 3. the folder picker ────────────────────────────────────────────────────

// uiCheckFolder resolves a typed path exactly the way the daemon will
// (addfolder.go:122 — expandHome then filepath.Abs) and reports what is
// actually there. It is ADVISORY: the rule that decides is dcnProposeLocal's,
// and this must never be able to disagree with it about a path.
//
// filepath.IsAbs is the platform's own answer, and this runs on the machine
// whose filesystem it is describing, so the Windows question is asked by a
// Windows binary.
func uiCheckFolder(typed string) uiFolderCheck {
	c := uiFolderCheck{Typed: typed}
	typed = strings.TrimSpace(typed)
	if typed == "" {
		c.Class, c.Line = "warn", "Type the folder's full path."
		return c
	}
	expanded := expandHome(typed)
	abs, err := filepath.Abs(expanded)
	if err != nil {
		c.Class, c.Line = "bad", "That is not a path this machine can resolve."
		return c
	}
	c.Resolved = abs
	// A RELATIVE path is refused here and nowhere else, and the reason is the
	// browser. filepath.Abs resolves against the process's working directory,
	// and this process is a daemon: under systemd that is "/", so "Documents"
	// becomes "/Documents" and "etc" becomes "/etc" — which exists. The CLI has
	// the same behaviour and it is harmless there, because the working directory
	// is the shell the person is standing in. On a page there is no such thing to
	// reason about, so a relative path is a guess about what someone meant.
	if !filepath.IsAbs(expanded) {
		c.Class = "bad"
		c.Line = "Give the full path, starting at the top of the disk."
		c.Note = "Typed as it is, this machine reads it against the bastion's own working " +
			"directory and gets " + abs + " — which is almost certainly not the folder you mean."
		return c
	}
	info, err := os.Stat(abs)
	switch {
	case err != nil:
		c.Class, c.Line = "bad", "There is nothing at that path on this machine."
	case !info.IsDir():
		c.Class, c.Line = "bad", "That is a file, not a folder."
	default:
		c.Class, c.Line = "ok", "A folder on this machine."
		// Listing it is not part of the daemon's rule, so this is a note and
		// never a refusal. It is worth saying now because the alternative is
		// finding out weeks later, when the host asks for a file and cannot
		// have it.
		if f, err := os.Open(abs); err != nil {
			c.Class = "warn"
			c.Note = "The bastion cannot open it (" + err.Error() + "), so it would have nothing to index."
		} else {
			_, rerr := f.Readdirnames(1)
			_ = f.Close()
			if rerr != nil && rerr != io.EOF {
				c.Class = "warn"
				c.Note = "The bastion cannot list what is inside it (" + rerr.Error() + ")."
			}
		}
	}
	return c
}

func (s *uiSetup) folderCheck(w http.ResponseWriter, r *http.Request) {
	// POST for a read, on purpose: a folder path is the person's own business
	// and a GET would put it in a query string. It costs nothing — this route
	// changes nothing — and it means the Origin check applies here too.
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c := uiCheckFolder(r.FormValue("path"))
	s.render(w, "folder-check", uiSetupView{Check: &c})
}

// folderPropose posts the draft to the SAME loopback endpoint add-folder posts
// to (addfolder.go:66). Not a second call to dcnProposeLocal's internals and
// not a reimplementation of its checks: the daemon's own validation, its own
// bearer, its own upstream call. If the two ever disagree about a path it will
// be because someone changed one of them, and there is only one of them.
func (s *uiSetup) folderPropose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := setupHost(r.FormValue("host"))
	if err != nil {
		s.flash(w, err.Error(), "bad")
		return
	}
	path := strings.TrimSpace(r.FormValue("path"))
	if c := uiCheckFolder(path); c.Class == "bad" {
		line := c.Line
		if c.Note != "" {
			line += " " + c.Note
		}
		s.flash(w, "Nothing was proposed: "+line, "bad")
		return
	}
	if !cfg.active() {
		s.flash(w, cfg.HostName+" is "+cfg.stateName()+" on this machine, so it has no lanes open — "+
			"a folder cannot be proposed to it until the anchor host approves the pairing.", "bad")
		return
	}
	body, _ := json.Marshal(map[string]string{
		"root": path, "display_name": strings.TrimSpace(r.FormValue("name")),
	})
	req, err := http.NewRequest(http.MethodPost,
		"http://"+cfg.ListenAddr+"/dcn/propose", bytes.NewReader(body))
	if err != nil {
		s.flash(w, err.Error(), "bad")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.OperatorSecret)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		// The CLI's wording here is "the bastion daemon isn't running"
		// (addfolder.go:76), which cannot be what happened: this page is served
		// BY that daemon. What it means from here is that this host's own lane
		// is down.
		s.flash(w, "This machine is not answering for "+cfg.HostName+" on "+cfg.ListenAddr+
			", so nothing was proposed. Its tunnel and lanes are not up.", "bad")
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		s.flash(w, "Nothing was proposed: "+strings.TrimSpace(string(raw)), "bad")
		return
	}
	abs, _ := filepath.Abs(expandHome(path))
	s.flash(w, "Draft created for "+abs+". Your files stay on this machine — your host keeps only "+
		"the index. Nothing is granted yet: approve the draft on your host (Context Manager → "+
		"Storage → Your network) with your 6-digit code.", "ok")
}

// ── 4. the anchor picker ────────────────────────────────────────────────────

// uiAnchorCommandFor writes the claim-anchor line with the chosen host in it.
//
// TAKES THE PLATFORM AS AN ARGUMENT for the reason restartHintFor states
// (privilege.go:88): a platform branch nothing off-platform can reach is a
// platform branch nothing checks, and the only machine that could ever test the
// Windows string would be a Windows machine.
//
// It cannot simply append to anchorCommandHintFor (privilege.go:58) because the
// Windows form of that ends in a parenthetical saying where to run it, and a
// flag after that reads as part of the sentence. The two are pinned together by
// a test instead.
func uiAnchorCommandFor(goos, host string) (cmd, how string) {
	if goos == "windows" {
		return "privatae-bastion claim-anchor --host " + host,
			"Run it from an Administrator terminal (right-click → Run as administrator)."
	}
	return "sudo -H privatae-bastion claim-anchor --host " + host,
		"Run it in a terminal on this machine."
}

// anchorChoose turns "which host holds the anchor" into a click, checks the
// choice against the rules claim-anchor will apply, and writes out the line.
//
// It performs nothing. See this file's header for why, at length.
func (s *uiSetup) anchorChoose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	cmdView := func(c uiCommand) { s.render(w, "anchor-cmd", uiSetupView{Cmd: &c}) }
	cfg, err := setupHost(r.FormValue("host"))
	if err != nil {
		cmdView(uiCommand{Class: "bad", Why: err.Error()})
		return
	}
	// Every rule below is one claim-anchor enforces, checked here so the person
	// is not sent to a terminal to be refused. None of them is a new rule.
	if boxMode() != modeNetworked {
		// anchor.go:827. set-mode is root too (mode.go), so both lines are given
		// in the order they have to be run.
		cmdView(uiCommand{
			Class:   "bad",
			Command: setModeCommandHint(),
			How:     adminHowTo() + ", then claim the anchor.",
			Why: "This machine is in local mode, where it serves one host and needs no anchor. " +
				"An anchor only means something on a networked bastion.",
		})
		return
	}
	if prev := currentAnchor(); prev != nil {
		// anchor.go:835. Moving it is --rotate, which the design keeps in the
		// CLI on purpose: rare, consequential, and it deserves friction.
		// The line is written with <token> left in it, the way main.go:55 prints
		// it: a rotation names a host this box does not serve, so that host has
		// to issue the token and this page cannot know it.
		rotate := "sudo -H privatae-bastion claim-anchor --rotate <token>"
		how := "Run it in a terminal on this machine, with a token from the host taking the anchor."
		if runtime.GOOS == "windows" {
			rotate = "privatae-bastion claim-anchor --rotate <token>"
			how = "Run it from an Administrator terminal, with a token from the host taking the anchor."
		}
		cmdView(uiCommand{
			Class:   "warn",
			Command: rotate,
			How:     how,
			Why: "This machine is already anchored to " + prev.AnchorHost + ". Moving the anchor " +
				"to another host needs that anchor's signed consent, or 14 days of silence from it.",
		})
		return
	}
	if cfg.State == pairingRevoked {
		// anchor.go:910 — revoked is a decision, not a queue.
		cmdView(uiCommand{
			Class: "bad",
			Why: cfg.HostName + " is revoked on this machine. Claiming the anchor will not " +
				"reinstate it — re-pair that host first.",
		})
		return
	}
	cmd, how := uiAnchorCommandFor(runtime.GOOS, cfg.HostName)
	cmdView(uiCommand{
		Class:   "ok",
		Command: cmd,
		How:     how,
		Why: "From then on every host paired here waits, pending, until " + cfg.HostName +
			" approves it. The hosts already paired keep the lanes they have.",
	})
}

// ── 5. the owner name ───────────────────────────────────────────────────────

// uiShellSafeName reports whether a name survives being put in double quotes on
// a command line unchanged. A name that does not is not refused — it is a
// perfectly good owner name — but this page will not hand someone a line that
// does something other than what it says.
func uiShellSafeName(name string) bool { return !strings.ContainsAny(name, "\"\\$`") }

// ownerName validates the name with the same function the command uses and
// writes out the line. Root-gated like the anchor (owner.go:83), and not
// performed here for the same reasons.
func (s *uiSetup) ownerName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	cmdView := func(c uiCommand) { s.render(w, "owner-cmd", uiSetupView{Cmd: &c}) }
	name := strings.TrimSpace(r.FormValue("owner"))
	// claimNameOK (anchor.go:121) is the real rule: it is what stops a name
	// being read as more than one field of the signed input.
	if err := claimNameOK(name); err != nil {
		cmdView(uiCommand{Class: "bad", Why: "That name will be refused: " + err.Error() + "."})
		return
	}
	if !uiShellSafeName(name) {
		cmdView(uiCommand{Class: "warn", Why: "That name is fine, but it contains a character a " +
			"shell would read (a quote, a backslash, a $ or a backtick), so this page will not " +
			"write the line for you — type it with the name quoted the way your shell needs."})
		return
	}
	// `sudo -H`, not the bare `sudo` in main.go's usage text. -H is what keeps
	// HOME pointing at root's own config dir, and claim-owner WRITES there
	// (owner.go:49 → configDir): a sudo without it writes the claim into the
	// calling user's directory, which is the same hazard cmdRun warns about for
	// pair (run.go:73-77). adminHowTo (privilege.go:31) already says -H, and it
	// is what the refusal the person would otherwise see says.
	cmd := "sudo -H privatae-bastion claim-owner \"" + name + "\""
	how := "Run it in a terminal on this machine."
	if runtime.GOOS == "windows" {
		cmd = "privatae-bastion claim-owner \"" + name + "\""
		how = "Run it from an Administrator terminal (right-click → Run as administrator)."
	}
	cmdView(uiCommand{
		Class: "ok", Command: cmd, How: how,
		Why: "It travels on the next check-in to every host this machine serves and shows as the " +
			"owner on this machine's card. It grants nothing anywhere.",
	})
}

// uiSetupTemplates is the assertion that the page's templates exist, used by
// the tests so a rename of one of them fails loudly rather than rendering
// nothing into a browser.
func uiSetupTemplates() []string {
	return []string{"setup-page", "setup", "folder-check", "stepup-key", "anchor-cmd", "owner-cmd"}
}
