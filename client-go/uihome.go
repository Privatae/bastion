package main

// uihome.go — the console's home page: the agents on this machine and what
// each one is doing, and one page per agent.
//
// Plan: /srv/work/plans/HANDOFF-bastion-first-2026-10-30.md, Addendum 4, step 1.
// The home page is built from buildAgentViews (agentsession.go), the same
// data `privatae-bastion agents` prints, worded by the same agentLinesOf, so
// the console and the command line cannot describe an agent differently. Two
// facts that each had a page of their own sit on every row: whether the person
// has marked the program as theirs (sanction.go) and whether the dry-run rule
// would stop it (policy.go). Those pages stay, as the detail behind each fact.
//
// Nothing on these pages acts. Stopping an agent and marking it as yours come
// with the owner's code on the page (step 2).

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type uiHomeRow struct {
	PID            int
	Service        bool
	App            bool
	Head           string
	State          string
	Where          string
	RunningNow     string
	ToolServers    string
	WaitingForYou  bool
	PermissionsOff bool
	NotYours       bool
	WouldStop      bool
}

type uiHomeFamily struct {
	Heading string
	Rows    []uiHomeRow
}

type uiHomeView struct {
	Version   string
	CheckedAt string
	Blind     bool
	WalkError string
	// PerAccount: the daemon runs in a person's own account, so an agent
	// running as that person can stop it and read its code's secret
	// (ui.go approve). Said on every load, because it changes what every
	// approval on this console is worth.
	PerAccount bool
	// The first-run steps (step 7): shown until the owner's code is set up
	// and a baseline is recorded, the two things that make the rest work.
	CodeSet       bool
	BaselineSet   bool
	HostsPaired   bool
	Waiting       int
	Sessions      int
	Others        int // browser drivers and unknown model clients: running, not sessions
	WaitingForYou int
	NotYours      int
	WouldStop     int
	Families      []uiHomeFamily
}

// homeWaitingFn counts the requests /approvals shows; a var so the suite can
// say how many without a pairing.
var homeWaitingFn = func() int {
	s := collectUIStatus()
	return len(s.Approvals) + len(s.DeviceApprovals) + len(s.MachineAsks)
}

func collectHomeView(now time.Time) uiHomeView {
	v := uiHomeView{
		Version:    clientVersion,
		CheckedAt:  now.Format("15:04:05"),
		Blind:      !agentScanSupported,
		PerAccount: !machineAuthorityHeld(),
		Waiting:    homeWaitingFn(),
		CodeSet:    stepupEnrolled(existingMachineFactorDir()),
	}
	if _, _, err := baselineLoad(); err == nil {
		v.BaselineSet = true
	}
	if cfgs, err := loadPairings(); err == nil && len(cfgs) > 0 {
		v.HostsPaired = true
	}
	agents, err := observedAgents()
	if err != nil {
		v.WalkError = err.Error()
		return v
	}
	byPID := map[int]agentObs{}
	for _, a := range agents {
		byPID[a.PID] = a
	}
	views := buildAgentViews(agents, processTree())
	fams := map[string]*uiHomeFamily{}
	var order []string
	byFam := map[string][]agentView{}
	for _, av := range views {
		if _, ok := fams[av.Signature]; !ok {
			fams[av.Signature] = &uiHomeFamily{}
			order = append(order, av.Signature)
		}
		byFam[av.Signature] = append(byFam[av.Signature], av)
	}
	sort.Strings(order)
	for _, sig := range order {
		vs := byFam[sig]
		sort.SliceStable(vs, func(i, j int) bool {
			if a, b := viewRank(vs[i]), viewRank(vs[j]); a != b {
				return a < b
			}
			return vs[i].PID < vs[j].PID
		})
		f := fams[sig]
		f.Heading = familyHeading(familyLabel(sig), vs)
		for _, av := range vs {
			row := homeRow(av, byPID[av.PID], now)
			if !row.Service && !row.App && av.Kind != kindAgent {
				v.Others++
			}
			if !row.Service && !row.App && av.Kind == kindAgent {
				v.Sessions++
				if row.WaitingForYou {
					v.WaitingForYou++
				}
				if row.NotYours {
					v.NotYours++
				}
				if row.WouldStop {
					v.WouldStop++
				}
			}
			f.Rows = append(f.Rows, row)
		}
		v.Families = append(v.Families, *f)
	}
	return v
}

func homeRow(av agentView, a agentObs, now time.Time) uiHomeRow {
	r := uiHomeRow{PID: av.PID, Service: av.Role == "service", App: av.Kind == kindApp}
	if r.Service {
		r.Head = "Background service"
		r.State = "starts background sessions; not a session itself"
		return r
	}
	l := agentLinesOf(av, now)
	r.Head, r.State, r.Where = l.Head, l.State, l.Where
	r.RunningNow = strings.Join(av.RunningNow, "; ")
	r.ToolServers = strings.Join(av.ToolServers, ", ")
	if av.Self != nil {
		r.WaitingForYou = av.Self.WaitingFor != ""
		r.PermissionsOff = av.Self.PermissionMode == "bypassPermissions"
	}
	sanctioned, _ := agentSanction(a)
	r.NotYours = !sanctioned && !r.App
	r.WouldStop = policyEvaluate(a).Decision == policyWouldStop
	return r
}

// ── one agent ───────────────────────────────────────────────────────────────

type uiToolServer struct {
	Name     string   `json:"name"`
	Where    string   `json:"where"`
	Problems []string `json:"problems,omitempty"`
}

type uiAgentPage struct {
	Version     string
	Flash       string
	FlashClass  string
	OwnerCode   bool   // the owner's code is set up: Stop and the mark are offered
	Signature   string // posted back with Stop, so a pid that changed hands is refused
	MarkID      string // the sanction fingerprint the mark posts; "" when none can be made
	Found       bool
	PID         int
	Family      string
	Row         uiHomeRow
	Self        *agentSelf
	Kind        string
	Exe         string
	Cmdline     string
	Origin      string
	Endpoints   []string
	Evidence    []evidence
	Tools       []uiToolServer
	Sanctioned  bool
	SanctionWhy string
	Verdict     string
	VerdictCls  string
	Reasons     []policyReason
}

func collectAgentPage(pid int, now time.Time) uiAgentPage {
	p := uiAgentPage{Version: clientVersion, PID: pid, OwnerCode: stepupEnrolled(existingMachineFactorDir())}
	agents, err := observedAgents()
	if err != nil {
		return p
	}
	var a agentObs
	for _, x := range agents {
		if x.PID == pid {
			a, p.Found = x, true
			break
		}
	}
	if !p.Found {
		return p
	}
	views := buildAgentViews([]agentObs{a}, processTree())
	av := views[0]
	p.Family = familyLabel(a.Signature)
	p.Row = homeRow(av, a, now)
	p.Self = av.Self
	p.Kind, p.Exe, p.Cmdline, p.Origin = a.Kind, a.Exe, a.Cmdline, a.Origin
	p.Signature = a.Signature
	if id := sanctionIdentityOf(a); id.usable() {
		p.MarkID = id.fingerprint()
	}
	p.Endpoints, p.Evidence = a.LLMEndpoints, a.Evidence
	p.Sanctioned, p.SanctionWhy = agentSanction(a)
	pv := policyEvaluate(a)
	p.Verdict, p.VerdictCls, p.Reasons = policyWord(pv.Decision), policyClass(pv.Decision), pv.Reasons
	servers, _ := readMCPConfigs()
	p.Tools = toolServersFor(a.Signature, homeForUserFn(a.User), av.Folder, servers)
	return p
}

// toolServersFor is the tool servers this agent reads: its own client's
// settings files in its account's home, or inside the folder it works in.
func toolServersFor(signature, home, folder string, servers []mcpServerObs) []uiToolServer {
	var out []uiToolServer
	for _, s := range servers {
		if s.Client != signature || s.Path == "" {
			continue
		}
		if !pathUnder(s.Path, home) && !pathUnder(s.Path, folder) {
			continue
		}
		t := uiToolServer{Name: s.Name, Where: s.Path}
		if t.Name == "" {
			t.Name = s.PackageName
		}
		if s.SecretInPlaintext {
			t.Problems = append(t.Problems, "a key is written in plain text in "+s.Path)
		}
		if s.PackagePinned == "no" && s.PackageName != "" {
			t.Problems = append(t.Problems, "runs "+s.PackageName+
				" with no fixed version, so whatever is published next is what runs")
		}
		if s.RunningState == "running_not_declared" {
			t.Problems = append(t.Problems, "running, but not in any settings file this machine can read")
		}
		if s.Disabled {
			t.Problems = nil
			t.Name += " (turned off)"
		}
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].Problems) > len(out[j].Problems) })
	return out
}

func pathUnder(p, dir string) bool {
	if dir == "" || p == "" {
		return false
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// ── routes ──────────────────────────────────────────────────────────────────

func (u *uiServer) homeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/fragments/home", u.guarded(u.homeFragment))
	mux.HandleFunc("/agent", u.guarded(u.agentPage))
	// The two acts on an agent's page, each taking the owner's code.
	mux.HandleFunc("/agent/stop", u.guarded(u.agentStop))
	mux.HandleFunc("/agent/mark", u.guarded(u.agentMark))
	// This machine's sections (uimachine.go).
	u.machineRoutes(mux)
	// What happened here, newest first (activity.go).
	mux.HandleFunc("/activity", u.guarded(u.activityPage))
	// Answering what is asked of this machine itself, on Waiting for you.
	mux.HandleFunc("/approvals/machine/approve", u.guarded(u.machineApprove))
	mux.HandleFunc("/approvals/machine/deny", u.guarded(u.machineDeny))
	// The machine's state page, which was the home page until the agents
	// took that place.
	mux.HandleFunc("/machine", u.guarded(u.machinePage))
}

// renderView sets the same four headers every page here sets (renderStatus).
func (u *uiServer) renderView(w http.ResponseWriter, name string, v any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := u.tpl.ExecuteTemplate(w, name, v); err != nil {
		uilogf("render %s: %v\n", name, err)
	}
}

func (u *uiServer) homePage(w http.ResponseWriter, r *http.Request) {
	u.renderView(w, "home-page", collectHomeView(uiNow()))
}

func (u *uiServer) homeFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderView(w, "home", collectHomeView(uiNow()))
}

func (u *uiServer) agentPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	pid, err := strconv.Atoi(r.URL.Query().Get("pid"))
	if err != nil || pid <= 0 {
		http.Error(w, "which agent? open it from the Agents page", http.StatusBadRequest)
		return
	}
	u.renderView(w, "agent-page", collectAgentPage(pid, uiNow()))
}

func (u *uiServer) machinePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.render(w, "page.html")
}

// stopFromConsole stops one agent for the person at this console: the agent
// they were looking at (pid AND signature, so a number that changed hands
// since the page was drawn is refused), with their code, through the same
// approval and the same carry-out as `stop` (stop_local.go). The console runs
// in the daemon, so the stop is carried out here and now and recorded in the
// machine's activity, rather than waiting for the loop's next tick.
func stopFromConsole(pid int, signature, code string, now time.Time) (string, string) {
	observed := observedAgentMap()
	if why := stopRefusal(pid, observed); why != "" {
		return "Not stopped: " + why + ".", "warn"
	}
	if got := observed[pid].Signature; got != signature {
		return "Not stopped: pid " + strconv.Itoa(pid) + " is now " + got + ", not the " + signature +
			" this page showed. Open it again from the Agents page.", "warn"
	}
	dir := existingMachineFactorDir()
	if !stepupEnrolled(dir) {
		return "Not stopped: set up your code under Settings first. Stopping an agent takes it.", "warn"
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "Not stopped: type the code from your authenticator.", "warn"
	}
	purpose, err := purposeForLocalStop(pid, signature)
	if err != nil {
		return "Not stopped: " + err.Error() + ".", "bad"
	}
	approval, err := machineCodeSpend(dir, now, func() (string, error) {
		return stepupIssueApproval(dir, code, purpose)
	})
	if err != nil {
		return "Not stopped: " + err.Error() + ".", "bad"
	}
	localStopOnce(dir, now)
	r, ok := waitStopResult(dir, approval, 5*time.Second)
	if !ok {
		return "Approved, but the stop was not carried out. Look under Activity.", "warn"
	}
	if strings.HasPrefix(r.Outcome, "not stopped") {
		return r.Outcome, "warn"
	}
	return r.Outcome, "ok"
}

func (u *uiServer) agentStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	pid, err := strconv.Atoi(r.FormValue("pid"))
	if err != nil || pid <= 1 {
		http.Error(w, "which agent? open it from the Agents page", http.StatusBadRequest)
		return
	}
	now := uiNow()
	flash, class := stopFromConsole(pid, r.FormValue("signature"), r.FormValue("code"), now)
	p := collectAgentPage(pid, now)
	p.Flash, p.FlashClass = flash, class
	u.renderView(w, "agent-page", p)
}

func (u *uiServer) agentMark(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	pid, err := strconv.Atoi(r.FormValue("pid"))
	if err != nil || pid <= 1 {
		http.Error(w, "which agent? open it from the Agents page", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	flash, class := "Nothing was marked: that program is not running on this machine any more.", "warn"
	if agents, err := observedAgents(); err == nil {
		for _, a := range agents {
			if a.PID != pid || sanctionIdentityOf(a).fingerprint() != id {
				continue
			}
			if why := markCodeRefusal(id, r.FormValue("code")); why != "" {
				flash, class = why, "warn"
				break
			}
			if rec, err := addSanction(a, sanctionByLocalUI); err != nil {
				flash, class = "Not marked: "+err.Error(), "bad"
			} else {
				flash, class = "Marked as yours: "+rec.sanctionIdentity.describe()+".", "ok"
			}
			break
		}
	}
	p := collectAgentPage(pid, uiNow())
	p.Flash, p.FlashClass = flash, class
	u.renderView(w, "agent-page", p)
}

// ── what is asked of this machine ───────────────────────────────────────────

type uiMachineAsk struct {
	ID    string
	Short string
	Text  string
	At    string
}

// machineAsks is every pending request in the owner's factor, oldest first.
func machineAsks() []uiMachineAsk {
	dir := existingMachineFactorDir()
	if dir == "" {
		return nil
	}
	stepupMu.Lock()
	m := requestsLoad(dir)
	stepupMu.Unlock()
	var out []uiMachineAsk
	for _, id := range sortedPending(m) {
		short := id
		if len(short) > 8 {
			short = short[:8]
		}
		out = append(out, uiMachineAsk{ID: id, Short: short, Text: describeRequest(m[id]), At: m[id].At})
	}
	return out
}

// machineApprove answers one request asked of this machine with the owner's
// code, and carries out what it approved at once (a stop: localStopOnce), so
// the person sees what happened rather than a promise.
func (u *uiServer) machineApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	dir := existingMachineFactorDir()
	if !stepupEnrolled(dir) {
		u.renderApprovals(w, "approvals", "Set up your code under Settings first.", "warn")
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		u.renderApprovals(w, "approvals", "Type the code from your authenticator.", "warn")
		return
	}
	id := r.FormValue("id")
	approval, err := machineCodeSpend(dir, uiNow(), func() (string, error) {
		return stepupApproveRequest(dir, id, code)
	})
	if err != nil {
		u.renderApprovals(w, "approvals", "Not approved: "+err.Error()+".", "bad")
		return
	}
	localStopOnce(dir, uiNow())
	if res, ok := waitStopResult(dir, approval, 5*time.Second); ok {
		class := "ok"
		if strings.HasPrefix(res.Outcome, "not stopped") {
			class = "warn"
		}
		u.renderApprovals(w, "approvals", res.Outcome, class)
		return
	}
	u.renderApprovals(w, "approvals", "Approved.", "ok")
}

// machineDeny refuses one. No code: refusing is always the safe direction.
func (u *uiServer) machineDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	dir := existingMachineFactorDir()
	if dir == "" || stepupDenyRequest(dir, r.FormValue("id")) != nil {
		u.renderApprovals(w, "approvals", "That request is no longer waiting.", "warn")
		return
	}
	u.renderApprovals(w, "approvals", "Denied. Nothing was done.", "ok")
}

type uiActivityView struct {
	Version string
	Kind    string // the filter: "" (all), stop, approval, host, change
	Items   []activityItem
	Counts  map[string]int
}

func (u *uiServer) activityPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	all := collectActivity(uiNow().Add(-7 * 24 * time.Hour))
	v := uiActivityView{Version: clientVersion, Counts: map[string]int{}}
	switch k := r.URL.Query().Get("kind"); k {
	case "stop", "approval", "host", "change":
		v.Kind = k
	}
	for _, it := range all {
		v.Counts[it.Kind]++
		if v.Kind == "" || it.Kind == v.Kind {
			v.Items = append(v.Items, it)
		}
	}
	u.renderView(w, "activity-page", v)
}
