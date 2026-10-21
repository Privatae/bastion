package main

// uisanction.go — the page where a person says which of the automated things on
// their machine are theirs.
//
// WHY IT EXISTS. Without a way for a user to say THIS ONE IS MINE, a policy
// engine's first act is to kill the user's own editor.
// sanction.go is the record and the predicate; this is
// the only surface that can produce one, because the act being recorded is a
// person looking at a list and recognising something.
//
// ── THERE IS NO KILL BUTTON ON THIS PAGE, AND THAT IS A DECISION ────────────
//
// Containment is host-directed today: `maybeContain` runs off the heartbeat
// response (run.go:575), the host decides and the box carries it out. Whether
// the LOCAL UI may act is an open product question — the local UI's design
// keeps the same question open for turning a granted capability off,
// and uigiven.go's header says why a page must not be shaped like a settings
// screen with the switches missing.
//
// Beyond that: MARKING SOMETHING AS YOURS IS NOT THE SAME ACT AS TERMINATING
// SOMETHING. One is a person vouching, the other takes their work away. Putting
// both on one page would put a kill one mis-click from a vouch, and would settle
// a decision that is not this unit's to settle. So there is no Stop, no
// Terminate, and no disabled control hinting at one — and a test drives the
// whole page with killProcess stubbed to prove nothing here can reach it.
//
// ── THE PAGE MUST NOT BECOME A WAY TO HIDE ──────────────────────────────────
//
// A sanction is the user vouching for something, so the page is built around
// the set that has NOT been vouched for:
//
//   - The unsanctioned count is the headline, above everything else.
//   - A sanctioned entry is still LISTED. It moves down the page and loses its
//     emphasis; it never disappears. A control that makes things vanish is a
//     control an attacker wants the user to use.
//   - A mark whose program is not running right now is listed too, in its own
//     section, with the only button that removes it. Without that, a record for
//     something long uninstalled would sit on the machine for ever, vouching for
//     an identity nobody can see and nobody can withdraw.
//   - A mark that has EXPIRED — written before the identity moved to the
//     kernel's executable path (sanction.go, RECORDS WRITTEN BEFORE THIS) — is
//     listed in a third section that says plainly that it vouches for nothing
//     and why. The user's own record of a decision is not something this program
//     deletes on their behalf without saying so, and "your marks stopped
//     counting" is exactly the kind of change a security page must not make
//     silently.
//   - A build with no enumerator says so instead of showing an empty list.
//     the README section "Observe" calls this the quiet-versus-blind distinction and
//     agents_other.go:5-10 is the whole reason agentScanSupported exists; a page
//     that renders "0 unsanctioned" on a box that cannot look is the most
//     reassuring sentence this program could print about the least known machine.
//   - An unreadable registry is an alarm, never a tick. ui_approvals_flow_test.go:
//     113-151 is the same lesson on the same kind of page: a read that FAILED is
//     not a machine with nothing on it.
//
// ── NO SECOND FACTOR, AND THE REASON IS STRUCTURAL ──────────────────────────
//
// Approving a host's request needs a code (ui.go:484). Marking your own editor
// as yours does not, for two reasons. The step-up exists to defend against a
// compromised HOST and nothing here is host-facing. And there is no machine-wide
// second factor to ask for: step-up is enrolled PER PAIRING, in that pairing's
// own DCN dir (ui.go:264-277), while a sanction belongs to the box. ui.go:474-483
// already argues the same shape for the approval throttle — a control that only
// costs the real user is not a control.

import (
	"net/http"
	"sort"
	"strings"
)

// ── what the page shows ─────────────────────────────────────────────────────

// uiAgentRow is one observation, as a person reads it.
type uiAgentRow struct {
	// ID is the sanction fingerprint (sanction.go). It is what the form posts,
	// and it is deliberately NOT the pid: a pid posted back a second later may
	// belong to something else entirely.
	//
	// EMPTY when the observation has no kernel executable path, because then
	// there is no identity to post: addSanction would refuse it, and two
	// unreadable processes of the same kind and signature would share the same
	// fingerprint over an empty path. The template renders no button for an
	// empty ID, so the page cannot offer a control that could only fail.
	ID        string
	PID       int
	Kind      string
	Signature string
	User      string
	Origin    string
	Cmdline   string
	// Exe is the file the kernel says this process is running — what the mark is
	// actually recorded against. Shown beside the command line and never instead
	// of it: they are different facts, and the page that asks someone to vouch
	// for a program is the last place to conflate them.
	Exe       string
	Endpoints []string
	Evidence  []evidence

	Sanctioned bool
	Why        string
	// Marked: a LOCAL record covers this, so Unmark is the action. Derived from
	// the reason constant rather than by looking the record up again — asking
	// the predicate is what stops this page drifting away from the gate, the
	// same rule uigiven.go:36-41 sets for the caps matrix.
	Marked bool
	// Unknown: the registry could not be read, so Sanctioned is not a verdict.
	// The page must not draw a tick for this (sanction.go, agentSanction).
	Unknown bool
	// App: contain.go:85 refuses to terminate an app however it is asked, so
	// "not marked as yours" means something different here and the row says so.
	App bool
}

// uiDormantSanction is a mark that matches nothing running right now. The same
// shape serves the EXPIRED list below — a record, what it named, when and by
// whom — because that is all either section shows; what differs is the sentence
// above them, which is the template's job.
type uiDormantSanction struct {
	ID      string
	What    string
	Cmdline string
	At      string
	By      string
	ByUser  string
}

type uiAgentsView struct {
	Version   string
	CheckedAt string

	Rows         []uiAgentRow
	Observed     int
	Unsanctioned int
	Dormant      []uiDormantSanction
	// Expired: marks written before the identity moved to the kernel's
	// executable path (sanction.go, RECORDS WRITTEN BEFORE THIS). They vouch for
	// nothing and they are shown ANYWAY, because the alternative is this program
	// quietly discarding a decision the user made and never mentioning it.
	Expired []uiDormantSanction

	// Blind: this build has no enumerator for its platform, so the list below is
	// empty because nothing looked — not because nothing is running.
	Blind bool
	// ReadError is why the registry could not be read. Every row is then
	// Unknown, and the page says so instead of counting.
	ReadError string
	// WalkError is why the process walk failed for this render: the list is
	// empty because nothing looked — Blind for one pass, not for the platform.
	WalkError string

	Flash      string
	FlashClass string
}

// collectAgentsView asks the observe plane and the registry, once.
//
// observedAgents (contain.go:34) rather than scanAgents directly: it is the same
// var contain consults, so the page and the thing that kills can never be
// answering different questions — and it is the seam every test in this package
// already stubs.
//
// Re-read on every render, never cached, for the reason renderWith gives
// (ui.go:424-427): a stale copy of a security page is worse than no page,
// because it is the page the user trusted.
func collectAgentsView() uiAgentsView {
	v := uiAgentsView{
		Version:   clientVersion,
		CheckedAt: uiNow().Format("15:04:05"),
		Blind:     !agentScanSupported,
	}
	if _, err := loadSanctions(); err != nil {
		v.ReadError = err.Error()
	}

	seen := map[string]bool{}
	agents, err := observedAgents()
	if err != nil {
		// The error wins over anything beside it: a list that arrived with an
		// error is not believed, the same rule the kill guard holds.
		v.WalkError = err.Error()
		agents = nil
	}
	for _, a := range agents {
		sanctioned, why := agentSanction(a)
		id := sanctionIdentityOf(a)
		row := uiAgentRow{
			PID:        a.PID,
			Kind:       a.Kind,
			Signature:  a.Signature,
			User:       a.User,
			Origin:     a.Origin,
			Cmdline:    a.Cmdline,
			Exe:        a.Exe,
			Endpoints:  a.LLMEndpoints,
			Evidence:   a.Evidence,
			Sanctioned: sanctioned,
			Why:        why,
			Marked:     why == sanctionWhyLocal || why == sanctionWhyBoth,
			Unknown:    why == sanctionWhyUnreadable,
			App:        a.Kind == kindApp,
		}
		// No identity, no id to post. Asked of the identity rather than of the
		// reason string, so the page cannot offer a mark button in some future
		// state where the two disagree.
		if id.usable() {
			row.ID = id.fingerprint()
			seen[row.ID] = true
		}
		v.Rows = append(v.Rows, row)
		v.Observed++
		if !sanctioned {
			v.Unsanctioned++
		}
	}
	sortAgentRows(v.Rows)

	// Marks with nothing running behind them, and marks that no longer count at
	// all. Skipped entirely when the registry could not be read, because an
	// empty "you have marked nothing" list would be the reassuring half of the
	// same lie the ReadError banner exists to stop. A failed WALK withholds
	// only the dormant half — "not running right now" needs `seen` — while a
	// mark that no longer counts is a fact about the record and is still said:
	// silence about a control that changed meaning is the worse failure.
	if v.ReadError == "" {
		recs, err := sanctionRecords()
		if err != nil {
			v.ReadError = err.Error()
		}
		for _, r := range recs {
			entry := uiDormantSanction{
				ID: r.ID, What: r.describeMark(), Cmdline: r.Cmdline,
				At: r.At.Local().Format(uiEventTime), By: r.By, ByUser: r.ByUser,
			}
			// EXPIRED IS TESTED FIRST, before `seen`, and the order is load
			// bearing in two different ways — both measured by swapping it:
			//
			//	a record whose key matches something running  DISAPPEARS, because
			//	  `seen` swallows it and the user is never told their mark stopped
			//	  counting. (A hand-edited or truncated registry produces this.)
			//	a record whose key matches nothing            lands under "marked
			//	  as yours, but not running", which is the one sentence about it
			//	  that is no longer true.
			//
			// The first is the worse of the two: silence about a control that
			// changed meaning.
			if r.stale() {
				v.Expired = append(v.Expired, entry)
				continue
			}
			if seen[r.ID] || v.WalkError != "" {
				continue
			}
			v.Dormant = append(v.Dormant, entry)
		}
	}
	return v
}

// sortAgentRows puts the page's subject first: everything nobody has vouched
// for, then everything that has been.
//
// Within the unsanctioned set, an APP sinks below the rest — contain.go:85
// refuses to terminate one however the host asks, so it can never be the thing
// this whole feature exists to make safe to stop. It is still counted and still
// listed; it simply does not lead a list a person reads top-down.
//
// The remaining keys (kind, signature, pid) exist so the order is STABLE across
// a 10-second poll. A list that reshuffles under the cursor is a list nobody
// clicks the right row in.
func sortAgentRows(rows []uiAgentRow) {
	rank := func(r uiAgentRow) int {
		switch {
		case !r.Sanctioned && !r.App:
			return 0
		case !r.Sanctioned:
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if a, b := rank(rows[i]), rank(rows[j]); a != b {
			return a < b
		}
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		if rows[i].Signature != rows[j].Signature {
			return rows[i].Signature < rows[j].Signature
		}
		return rows[i].PID < rows[j].PID
	})
}

// ── the routes ──────────────────────────────────────────────────────────────

// agentRoutes registers this page. The shape copies setupRoutes
// (uisetup.go:199-212) exactly, including WHY the method check is inside each
// handler rather than in the mux pattern: Go's method patterns would answer a
// rebound host with 405 before uiRequestAllowed ever ran, and the rebinding wall
// has to be the outermost thing on every route.
func (u *uiServer) agentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/agents", u.guarded(u.agentsPage))
	mux.HandleFunc("/fragments/agents", u.guarded(u.agentsFragment))
	mux.HandleFunc("/agents/mark", u.guarded(u.agentsMark))
	mux.HandleFunc("/agents/unmark", u.guarded(u.agentsUnmark))
}

// renderAgents sets the SAME four headers renderWith does (ui.go:429-434) and
// not one fewer, for the reason uigiven.go:513-518 gives: renderWith is typed to
// uiStatus, widening it belongs to whoever owns that file, and the duplication
// is made safe by a test that compares the two responses header by header.
func (u *uiServer) renderAgents(w http.ResponseWriter, name string, v uiAgentsView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := u.tpl.ExecuteTemplate(w, name, v); err != nil {
		uilogf("render %s: %v\n", name, err)
	}
}

func (u *uiServer) agentsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderAgents(w, "agents-page", collectAgentsView())
}

func (u *uiServer) agentsFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderAgents(w, "agents", collectAgentsView())
}

// agentsFlash re-reads the machine and renders the fragment with an outcome
// line, exactly as renderWith does after an approve (ui.go:424-427). The state
// is always re-read: after a mark, the row the person clicked has changed sides.
func (u *uiServer) agentsFlash(w http.ResponseWriter, flash, class string) {
	v := collectAgentsView()
	v.Flash, v.FlashClass = flash, class
	u.renderAgents(w, "agents", v)
}

// agentsMark records one observation as the user's.
//
// THE POSTED ID IS LOOKED UP AMONG WHAT IS RUNNING, never trusted as an
// identity. approvalTarget (ui.go:442-448) takes the same care with a posted
// host name and says why: the form is local and session-authed, but a handler
// that builds state out of a posted string is the shape of bug that turns a
// local UI into something wider. Here it also buys a real property — a person
// can only vouch for something the plane can SEE — so a mark can never be
// pre-planted for an identity that has not run yet.
//
// The cost is one extra scan per click (24ms, measured; see sanction.go). A
// click is a human, and the alternative is trusting the browser about which
// program it is talking about.
func (u *uiServer) agentsMark(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		u.agentsFlash(w, "Nothing was marked: that form carried no program.", "bad")
		return
	}
	agents, err := observedAgents()
	if err != nil {
		// The right cause, not "not running any more": nothing was looked at.
		u.agentsFlash(w, "Nothing was marked: this machine could not read its processes "+
			"just now ("+err.Error()+"). Try again.", "bad")
		return
	}
	for _, a := range agents {
		if sanctionIdentityOf(a).fingerprint() != id {
			continue
		}
		rec, err := addSanction(a, sanctionByLocalUI)
		if err != nil {
			u.agentsFlash(w, "Not marked: "+err.Error(), "bad")
			return
		}
		u.agentsFlash(w, "Marked as yours: "+rec.sanctionIdentity.describe()+
			". It stays marked across restarts, including this program's own updates.", "ok")
		return
	}
	// Said as a fact about the machine rather than as an error about the form:
	// between the render and the click the process may simply have exited, which
	// is not the user doing anything wrong.
	u.agentsFlash(w, "Nothing was marked: that program is not running on this "+
		"machine any more. Only something this machine can see right now can be "+
		"marked as yours.", "warn")
}

// agentsUnmark withdraws a mark.
//
// BY ID ALONE, with no scan. A mark must be withdrawable for a program that is
// no longer running — see dropSanction — or the dormant list would be a list of
// records with no way to remove any of them.
func (u *uiServer) agentsUnmark(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	dropped, err := dropSanction(id)
	switch {
	case err != nil:
		u.agentsFlash(w, "Not unmarked: "+err.Error(), "bad")
	case !dropped:
		u.agentsFlash(w, "Nothing to unmark: this machine holds no mark for that program.", "warn")
	default:
		u.agentsFlash(w, "Unmarked. Nothing at this machine vouches for that program now.", "ok")
	}
}
