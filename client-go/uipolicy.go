package main

// uipolicy.go — the page that shows what the dry-run rule WOULD stop, and the
// record of what it would have stopped while nobody was looking.
//
// ── WHY THIS PAGE HAS NO BUTTONS AT ALL ─────────────────────────────────────
//
// The dry run is step 3 of the design and acting is step 4, and shipping
// them in the other order is how this product acquires a reputation for
// killing people's work. So this page renders, and that is the whole of it.
// There is no Stop, no
// Contain, no disabled control hinting at one, and — unlike the sanction page,
// which at least POSTs a mark (uisanction.go:240-245) — there is no mutating
// route in this file for anything to grow out of. policy_test.go drives the
// whole page with killProcess stubbed and then parses the source to prove the
// unit cannot so much as name it.
//
// The one action a person might want after reading this page is to say "that one
// is mine", and that already exists one page over. This page links there rather
// than growing its own copy: two surfaces that both write marks would be two
// places to get the identity wrong.
//
// ── THE THREE WAYS THIS PAGE COULD LIE, AND WHAT STOPS EACH ─────────────────
//
// A BLIND BUILD. agentScanSupported is false where no enumerator exists
// (agents_other.go:13). "Nothing would be stopped" from a machine that cannot
// list its own processes is the most reassuring sentence this program could
// print about the least known machine — the README, "Observe" calls it the
// quiet-versus-blind distinction and uisanction.go:41-45 holds the same line for
// the same reason.
//
// AN UNREADABLE REGISTRY. Every sanction term is then unknown, every agent-kind
// verdict is cannot-judge, and no count on this page means anything. It renders
// as an alarm and the counts are withheld — ui_approvals_flow_test.go:113-151 is this
// exact lesson on a neighbouring page.
//
// A CENSUS THAT STOPPED. The subtlest one, and the reason the ledger carries
// last_scan as well as since (policy.go). A record that stopped being written
// three days ago keeps answering "nothing since Tuesday", which reads as an
// all-clear; agents.go:594-598 records the same trap for the second-bastion scan
// and the same fix. When the census has never run at all, the page says THAT
// rather than "nothing would have been stopped".

import (
	"net/http"
	"sort"
	"strconv"
	"time"
)

// ── what the page shows ─────────────────────────────────────────────────────

// uiPolicyRow is one live observation and what the rule says about it. It
// embeds the verdict (policy.go) rather than copying it field by field: the
// verdict IS the product of this unit, and a page that re-typed it would be a
// second place for it to drift.
type uiPolicyRow struct {
	policyVerdict
	What  string // the identity in words — sanctionIdentity.describe()
	Word  string // the decision as a person reads it
	Class string // which of the three states the left edge carries
}

// The four things that can have become of a past candidate. A page that only
// said "it was a candidate once" would answer none of the question step 4 is
// waiting on.
const (
	policyPastStill      = "still a candidate right now"
	policyPastVouched    = "something has vouched for it since"
	policyPastRunning    = "running now, and this rule no longer proposes it"
	policyPastNotSeen    = "not running right now"
	policyPastUnknowable = "this machine cannot say — it could not read its own record of marks"
	policyPastUnwalked   = "this machine cannot say — it could not read its processes just now"
)

// uiPolicyPast is one row of the census: a program this rule would have stopped,
// what it looked like, and what became of it.
type uiPolicyPast struct {
	ID        string
	What      string
	Cmdline   string
	Origin    string
	Endpoints []string
	FirstSeen string
	LastSeen  string
	Status    string
	// Why it is no longer a candidate, in the words of the term that said so.
	// Empty while it still is one.
	Because string
	// Vouched: somebody has since said this is theirs. That makes it a false
	// positive this rule has been MEASURED making, which is the number step 4
	// is waiting on.
	Vouched bool
	// Unknowable: neither running nor not — the registry or the walk failed
	// for this render, and the row's edge must not read as "nothing behind it".
	Unknowable bool
	Still      bool
}

type uiPolicyView struct {
	Version   string
	CheckedAt string

	// The rule itself, in the words policy.go keeps beside the terms.
	Rule []policyReason

	Rows        []uiPolicyRow
	Observed    int
	WouldStop   int
	CannotJudge int

	// Blind: no enumerator on this platform, so the list is empty because
	// nothing looked.
	Blind bool
	// RegistryError: the sanction registry would not load. Every verdict below
	// is cannot-judge and no count is worth printing.
	RegistryError string
	// CensusError: the record of what would have been stopped is not being
	// written, and a page that stayed quiet about that would report a machine it
	// had stopped measuring as a machine with nothing to report.
	CensusError   string
	CensusErrorAt string
	// WalkError: the process walk failed for THIS render, so the rows below
	// are empty because nothing looked — the same reading Blind gets, for one
	// pass instead of for the platform.
	WalkError string
	// CensusUnreadable: the record could not be READ, which is a different state
	// from a write that failed. A failed write still leaves everything written
	// before it worth showing; a failed read leaves nothing that may be shown as
	// an absence. Kept apart so the second never renders as "never measured".
	CensusUnreadable bool

	// CensusRan is false when this machine has never taken a census — which is
	// a different fact from taking one and finding nothing, and must never be
	// rendered as the second.
	CensusRan   bool
	CensusSince string
	CensusLast  string
	// CensusStale: the last scan is older than it should be, so the rows below
	// are history rather than news.
	CensusStale bool

	Past         []uiPolicyPast
	PastTotal    int
	PastStill    int
	PastVouched  int
	PastDropped  int
	CensusWindow string
}

// uiPolicyStaleAfter is when a census stops being news.
//
// IT IS COUNTED IN FLUSHES, NOT IN SCANS, and that is the whole subtlety. The
// census scans every policyCensusEvery but only writes its clock every
// policyLedgerFlush (policy.go says why), so last_scan on a perfectly healthy
// machine is routinely a flush interval old. A threshold shorter than that
// would put "this measurement has stopped" on a machine that is measuring
// correctly, which is the cry-wolf failure every page in this UI is built to
// avoid. Three flushes: long enough that a slow box or a closed laptop lid is
// not an alarm, short enough that a daemon that died this morning is visible
// this afternoon.
const uiPolicyStaleAfter = 3 * policyLedgerFlush

// collectPolicyView asks the rule and the census, once.
//
// Re-read on every render and never cached, for the reason renderWith gives
// (ui.go:432-435): a stale copy of a security page is worse than no page,
// because it is the page the user trusted.
func collectPolicyView() uiPolicyView {
	now := uiNow()
	v := uiPolicyView{
		Version:   clientVersion,
		CheckedAt: now.Format("15:04:05"),
		Rule:      policyRuleLines(),
		Blind:     !agentScanSupported,
	}
	// Asked once here for the banner, exactly as collectAgentsView does
	// (uisanction.go:144-146). Each verdict below asks again through
	// agentSanction, which re-reads by design (sanction.go:169-178).
	marks, err := loadSanctions()
	if err != nil {
		v.RegistryError = err.Error()
	}
	if msg, at := policyCensusError(); msg != "" {
		v.CensusError, v.CensusErrorAt = msg, at.Local().Format(uiEventTime)
	}

	live := map[string]policyVerdict{}
	verdicts, err := policyVerdicts()
	if err != nil {
		v.WalkError = err.Error()
	}
	for _, verdict := range verdicts {
		live[verdict.ID] = verdict
		v.Rows = append(v.Rows, uiPolicyRow{
			policyVerdict: verdict,
			What:          verdict.sanctionIdentity.describe(),
			Word:          policyWord(verdict.Decision),
			Class:         policyClass(verdict.Decision),
		})
	}
	v.Observed = len(v.Rows)
	v.WouldStop, v.CannotJudge = policyWouldStopCount(policyRowVerdicts(v.Rows))
	sortPolicyRows(v.Rows)

	l, err := loadPolicyLedger()
	if err != nil {
		// The census file itself is unreadable. Same rule as the registry: say
		// so, and do not print a count — or an absence — derived from a read
		// that failed. In particular this must NOT fall through to "this machine
		// has never taken this measurement", which is the reassuring half of the
		// same lie (ui_approvals_flow_test.go:113-151).
		v.CensusUnreadable = true
		if v.CensusError == "" {
			v.CensusError, v.CensusErrorAt = err.Error(), v.CheckedAt
		}
		return v
	}
	v.CensusRan = !l.Since.IsZero()
	if !v.CensusRan {
		return v
	}
	v.CensusSince = l.Since.Local().Format(uiEventTime)
	v.CensusLast = l.LastScan.Local().Format(uiEventTime)
	v.CensusStale = now.Sub(l.LastScan) > uiPolicyStaleAfter
	v.CensusWindow = uiPolicyWindow(l.Since, now)
	v.PastDropped = l.Dropped
	for _, c := range l.Candidates {
		// A failed walk is as unknowable as an unreadable registry: `live` is
		// empty because nothing looked, and "not running right now" about a
		// named program would be the same lie one row down from the banner.
		// Each cause gets its own sentence, so the row says which.
		unknowable := ""
		switch {
		case v.RegistryError != "":
			unknowable = policyPastUnknowable
		case v.WalkError != "":
			unknowable = policyPastUnwalked
		}
		v.Past = append(v.Past, uiPolicyPastRow(c, live, marks, unknowable))
	}
	v.PastTotal = len(v.Past)
	for _, p := range v.Past {
		if p.Still {
			v.PastStill++
		}
		if p.Vouched {
			v.PastVouched++
		}
	}
	sortPolicyPast(v.Past)
	return v
}

// uiPolicyPastRow says what became of one past candidate.
//
// The order of the questions is the order of certainty. What this machine can
// SEE running now beats what it can infer from a record, and a mark it could
// not read is never reported as an absence of one.
//
// unknowable, when not empty, is the sentence for a row about which nothing
// can be said: the registry could not be read, or the walk did not happen.
func uiPolicyPastRow(c policyCandidate, live map[string]policyVerdict,
	marks map[string]sanctionRecord, unknowable string) uiPolicyPast {
	p := uiPolicyPast{
		ID:        c.ID,
		What:      c.sanctionIdentity.describe(),
		Cmdline:   c.LastCmdline,
		Origin:    c.LastOrigin,
		Endpoints: c.LastEndpoints,
		FirstSeen: c.FirstSeen.Local().Format(uiEventTime),
		LastSeen:  c.LastSeen.Local().Format(uiEventTime),
	}
	if verdict, running := live[c.ID]; running {
		switch verdict.Decision {
		case policyWouldStop:
			p.Status, p.Still = policyPastStill, true
		case policyCannotJudge:
			// Running, but the registry could not be read: unknowable, and the
			// row must not wear the "nothing behind it" edge.
			p.Status, p.Unknowable = policyPastUnknowable, true
		default:
			p.Status = policyPastRunning
			for _, r := range verdict.Reasons {
				if r.Points != policyPointsLeave {
					continue
				}
				p.Because = r.Detail
				// Something vouched for it: the rule was wrong about this one,
				// and that is the measurement this page exists to take. Any
				// other term (it stopped talking to a model, a person picked up
				// the session) is the rule being right and the world moving.
				p.Vouched = r.Term == policyTermSanction
				break
			}
		}
		return p
	}
	// Not running. The only thing this machine can still check is the LOCAL
	// mark: a host delegation tag is read out of a live process's environment
	// (sanction.go:23-30), so for something that has exited there is nothing to
	// read it from.
	// ORDER IS LOAD-BEARING. The registry being unreadable takes everything
	// with it — `marks` came from it. A failed WALK takes only "running" with
	// it: the mark is read from the registry, not from the process list, so a
	// vouched candidate stays vouched (the count the whole page is waiting on
	// must not zero because nothing looked — that turned the box green).
	switch {
	case unknowable == policyPastUnknowable:
		p.Status, p.Unknowable = unknowable, true
	case marks[c.ID].ID != "":
		p.Status, p.Vouched = policyPastVouched, true
	case unknowable != "":
		p.Status, p.Unknowable = unknowable, true
	default:
		p.Status = policyPastNotSeen
	}
	return p
}

// policyRowVerdicts unwraps the embedded verdicts so the count is taken by the
// same function the census counts with, rather than a second loop that could
// come to a different total.
func policyRowVerdicts(rows []uiPolicyRow) []policyVerdict {
	out := make([]policyVerdict, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.policyVerdict)
	}
	return out
}

// policyWord is the decision in the words the page uses. The constants are the
// seam; these are for reading.
func policyWord(decision string) string {
	switch decision {
	case policyWouldStop:
		return "would be stopped"
	case policyCannotJudge:
		return "cannot judge"
	default:
		return "left alone"
	}
}

// policyClass maps a decision onto the three states app.css already carries, so
// this page looks like the rest of the UI rather than like a new product.
//
// Amber for would-stop, never red. Red is reserved here for a verdict this
// machine could not reach, which is the state that needs a person — the same
// order agents.css:17-26 sets, and for the same reason: a page that shouts at
// ordinary state is a page that gets ignored the one time it matters.
func policyClass(decision string) string {
	switch decision {
	case policyWouldStop:
		return "warn"
	case policyCannotJudge:
		return "bad"
	default:
		return "ok"
	}
}

// uiPolicyWindow is how long the census has been running, in the words a person
// would use. Precision below a day is noise on a measurement whose unit is
// "long enough to trust".
func uiPolicyWindow(since, now time.Time) string {
	d := now.Sub(since)
	switch {
	case d < time.Hour:
		return "less than an hour"
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour"
		}
		return strconv.Itoa(h) + " hours"
	case d < 48*time.Hour:
		return "1 day"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + " days"
	}
}

// sortPolicyRows puts the page's subject first: what this rule would stop, then
// what it could not judge, then everything it leaves alone. The remaining keys
// exist so the order is STABLE across a poll — a list that reshuffles under the
// cursor is a list nobody can read down (uisanction.go:205-207).
func sortPolicyRows(rows []uiPolicyRow) {
	rank := func(r uiPolicyRow) int {
		switch r.Decision {
		case policyWouldStop:
			return 0
		case policyCannotJudge:
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

// sortPolicyPast puts what is still a candidate first — those are what step 4
// would take away today — then the rest, most recently seen first.
func sortPolicyPast(past []uiPolicyPast) {
	sort.SliceStable(past, func(i, j int) bool {
		if past[i].Still != past[j].Still {
			return past[i].Still
		}
		if past[i].LastSeen != past[j].LastSeen {
			return past[i].LastSeen > past[j].LastSeen
		}
		return past[i].ID < past[j].ID
	})
}

// ── the routes ──────────────────────────────────────────────────────────────

// policyRoutes registers this page. The shape copies agentRoutes
// (uisanction.go:240-245) exactly, including WHY the method check lives inside
// each handler rather than in the mux pattern: Go's method patterns would answer
// a rebound host with 405 before uiRequestAllowed ever ran, and the rebinding
// wall has to be the outermost thing on every route.
//
// BOTH ROUTES ARE READS. There is no third one, and that is the point of the
// unit rather than an omission.
func (u *uiServer) policyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/policy", u.guarded(u.policyPage))
	mux.HandleFunc("/fragments/policy", u.guarded(u.policyFragment))
}

// renderPolicy sets the SAME four headers renderWith does (ui.go:437-442) and
// not one fewer, for the reason uisanction.go:251-255 gives: renderWith is typed
// to uiStatus, widening it belongs to whoever owns that file, and the
// duplication is made safe by a test that compares the two responses header by
// header.
func (u *uiServer) renderPolicy(w http.ResponseWriter, name string, v uiPolicyView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := u.tpl.ExecuteTemplate(w, name, v); err != nil {
		uilogf("render %s: %v\n", name, err)
	}
}

func (u *uiServer) policyPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderPolicy(w, "policy-page", collectPolicyView())
}

func (u *uiServer) policyFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderPolicy(w, "policy", collectPolicyView())
}
