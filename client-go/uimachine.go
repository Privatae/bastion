package main

// uimachine.go — the sections of This machine (plan Addendum 4, step 4):
// scheduled jobs that start an agent, the MCP tool servers configured here
// and what is wrong with them, and what runs that the baseline does not
// hold. Each loads once when the page opens (hx-trigger="load"), apart from
// the machine's state above them, which refreshes every three seconds: these
// read files and walk processes, and none of them changes that fast.
//
// Recording a baseline takes the owner's code. It decides what counts as
// normal here, and everything in it stops being reported, so it is the act
// an agent clicking through a signed-in console would most want.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type uiSchedule struct {
	Agent    string `json:"agent"`
	Schedule string `json:"schedule"`
	Where    string `json:"where"`
	User     string `json:"user,omitempty"`
	Command  string `json:"command"`
}

func collectSchedules() ([]uiSchedule, bool) {
	entries, scan := scanSchedulers()
	var out []uiSchedule
	for _, e := range entries {
		args, _ := redactSecretArgs(strings.Fields(e.Command))
		out = append(out, uiSchedule{
			Agent: familyLabel(e.Signature), Schedule: cronWords(e.Schedule), Where: e.Kind + " " + e.Name,
			User: e.User, Command: cleanText(strings.Join(args, " "), 160),
		})
	}
	return out, scan.Supported
}

type uiToolGroup struct {
	Client  string         `json:"client"`
	Servers []uiToolServer `json:"servers"`
	Bad     int            `json:"with_problems"`
}

// toolProblems is one tool server's problems in plain words: the same
// sentences an agent's page uses (toolServersFor).
func toolProblems(s mcpServerObs) []string {
	if s.Disabled {
		return nil
	}
	var p []string
	if s.SecretInPlaintext {
		p = append(p, "a key is written in plain text in "+s.Path)
	}
	if s.PackagePinned == "no" && s.PackageName != "" {
		p = append(p, "runs "+s.PackageName+" with no fixed version, so whatever is published next is what runs")
	}
	if s.RunningState == "running_not_declared" {
		p = append(p, "running, but not in any settings file this machine can read")
	}
	return p
}

func collectToolGroups() []uiToolGroup {
	servers, _ := readMCPConfigs()
	by := map[string]*uiToolGroup{}
	var order []string
	for _, s := range servers {
		c := s.Client
		if c == "" {
			c = "not in any settings file"
		}
		g, ok := by[c]
		if !ok {
			g = &uiToolGroup{Client: familyLabel(c)}
			by[c] = g
			order = append(order, c)
		}
		name := s.Name
		if name == "" {
			name = s.PackageName
		}
		t := uiToolServer{Name: name, Where: s.Path, Problems: toolProblems(s)}
		if len(t.Problems) > 0 {
			g.Bad++
		}
		g.Servers = append(g.Servers, t)
	}
	sort.Strings(order)
	var out []uiToolGroup
	for _, c := range order {
		g := by[c]
		sort.SliceStable(g.Servers, func(i, j int) bool { return len(g.Servers[i].Problems) > len(g.Servers[j].Problems) })
		out = append(out, *g)
	}
	return out
}

// ── the baseline ────────────────────────────────────────────────────────────

type uiBaselineView struct {
	Flash      string
	FlashClass string
	Has        bool
	TakenAt    string
	Entries    int
	Note       string
	OwnerCode  bool
	Compared   bool
	ComparedAt string
	State      string
	Findings   []string
	WalkFailed string
}

// lastDelta keeps the last comparison for the page: a delta pass walks every
// process and digests their files, so it runs when asked, not on every load.
var lastDelta struct {
	sync.Mutex
	r  *deltaReport
	at time.Time
}

func collectBaselineView() uiBaselineView {
	v := uiBaselineView{OwnerCode: stepupEnrolled(existingMachineFactorDir())}
	if f, ok, err := baselineLoad(); err == nil {
		v.Has, v.TakenAt, v.Entries, v.Note = true, f.TakenAt, len(f.Entries), baselineIntegrityNote(f, ok)
	}
	lastDelta.Lock()
	r, at := lastDelta.r, lastDelta.at
	lastDelta.Unlock()
	if r != nil {
		v.Compared, v.ComparedAt, v.State, v.WalkFailed = true, at.Local().Format("15:04:05"), r.Baseline, r.WalkFailed
		for _, ev := range r.Findings {
			v.Findings = append(v.Findings, ev.Level+": "+deltaOneLine(ev))
		}
	}
	return v
}

func (u *uiServer) machineRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/fragments/machine/schedules", u.guarded(u.machineSchedules))
	mux.HandleFunc("/fragments/machine/tools", u.guarded(u.machineTools))
	mux.HandleFunc("/fragments/machine/baseline", u.guarded(u.machineBaseline))
	mux.HandleFunc("/machine/compare", u.guarded(u.machineCompare))
	mux.HandleFunc("/machine/baseline", u.guarded(u.machineRecordBaseline))
	mux.HandleFunc("/machine/report", u.guarded(u.machineReport))
}

// machineReport writes the report (report.go) and hands it to the browser as
// a file. A POST: writing it walks every process and compares the baseline.
func (u *uiServer) machineReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	now := uiNow()
	rep := buildReport(now, now.Add(-7*24*time.Hour))
	name := "bastion-report-" + now.Format("2006-01-02-1504") + ".md"
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	renderReportMarkdown(w, rep)
}

func (u *uiServer) machineSchedules(w http.ResponseWriter, r *http.Request) {
	s, ok := collectSchedules()
	u.renderView(w, "machine-schedules", map[string]any{"Items": s, "Supported": ok})
}

func (u *uiServer) machineTools(w http.ResponseWriter, r *http.Request) {
	u.renderView(w, "machine-tools", collectToolGroups())
}

func (u *uiServer) machineBaseline(w http.ResponseWriter, r *http.Request) {
	u.renderView(w, "machine-baseline", collectBaselineView())
}

func (u *uiServer) machineCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	rep := deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	lastDelta.Lock()
	lastDelta.r, lastDelta.at = &rep, time.Now()
	lastDelta.Unlock()
	u.renderView(w, "machine-baseline", collectBaselineView())
}

func (u *uiServer) machineRecordBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	flash, class := recordBaselineFromConsole(r.FormValue("code"))
	v := collectBaselineView()
	v.Flash, v.FlashClass = flash, class
	u.renderView(w, "machine-baseline", v)
}

// recordBaselineFromConsole takes the owner's code, then the same baseline
// `observe:baseline --force` takes (collectBaseline, baselineSave).
func recordBaselineFromConsole(code string) (string, string) {
	dir := existingMachineFactorDir()
	if !stepupEnrolled(dir) {
		return "Set up your code under Settings first. Recording a baseline takes it.", "warn"
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "Type the code from your authenticator.", "warn"
	}
	approval, err := machineCodeSpend(dir, uiNow(), func() (string, error) {
		return stepupIssueApproval(dir, code, "local_baseline")
	})
	if err != nil {
		return "Not recorded: " + err.Error() + ".", "bad"
	}
	if err := stepupConsumeApproval(dir, approval, "local_baseline"); err != nil {
		return "Not recorded: " + err.Error() + ".", "bad"
	}
	f, _, _, _, err := collectBaseline()
	if err != nil {
		return "Not recorded: " + err.Error() + ".", "bad"
	}
	if err := baselineSave(f); err != nil {
		return "Not recorded: " + err.Error() + ".", "bad"
	}
	dcnAudit(dir, "local_baseline", 0, "", "recorded: "+f.TakenAt)
	lastDelta.Lock()
	lastDelta.r = nil
	lastDelta.Unlock()
	return "Recorded. What runs here now is the baseline; anything new from here on is reported.", "ok"
}

// cronWords says the common cron schedules in words; anything else stays as
// written, which is what the file says.
func cronWords(spec string) string {
	f := strings.Fields(spec)
	if len(f) != 5 {
		return spec
	}
	min, hour, dom, mon, dow := f[0], f[1], f[2], f[3], f[4]
	num := func(s string) (int, bool) {
		n, err := strconv.Atoi(s)
		return n, err == nil
	}
	days := map[string]string{"0": "Sunday", "1": "Monday", "2": "Tuesday", "3": "Wednesday", "4": "Thursday",
		"5": "Friday", "6": "Saturday", "7": "Sunday"}
	m, mOK := num(min)
	h, hOK := num(hour)
	switch {
	case strings.HasPrefix(min, "*/") && hour == "*" && dom == "*" && mon == "*" && dow == "*":
		return "every " + strings.TrimPrefix(min, "*/") + " minutes"
	case min == "*" && hour == "*" && dom == "*" && mon == "*" && dow == "*":
		return "every minute"
	case mOK && hour == "*" && dom == "*" && mon == "*" && dow == "*":
		return fmt.Sprintf("every hour at :%02d", m)
	case mOK && hOK && dom == "*" && mon == "*" && dow == "*":
		return fmt.Sprintf("every day at %02d:%02d", h, m)
	case mOK && hOK && dom == "*" && mon == "*" && days[dow] != "":
		return fmt.Sprintf("every %s at %02d:%02d", days[dow], h, m)
	}
	return spec
}
