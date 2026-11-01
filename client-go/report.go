package main

// report.go — `privatae-bastion report [--since 7d] [--json] [--out FILE|-]`
// and the console's Write report: what this machine's bastion knows, as one
// Markdown file a person can read, keep, or hand to someone (plan Addendum 4,
// step 5; M0-T5). No model writes any of it: every sentence is built here
// from what the bastion already reads, the same builders the console uses.
//
// Sections: the agents running now; scheduled jobs that start an agent; MCP
// tool servers and their problems; what runs that the baseline does not
// hold; what happened in the window. A summary of the problems leads it.
//
// Left out on purpose: each session's last prompt (what a person typed into
// another session), and any secret: tool-server commands and scheduled
// commands are redacted before they get here.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type reportBaseline struct {
	Has      bool     `json:"has"`
	TakenAt  string   `json:"taken_at,omitempty"`
	Note     string   `json:"note,omitempty"`
	Compared bool     `json:"compared"`
	Why      string   `json:"why_not_compared,omitempty"`
	Findings []string `json:"findings,omitempty"`
}

type machineReport struct {
	Machine     string         `json:"machine"`
	Generated   time.Time      `json:"generated"`
	Since       time.Time      `json:"since"`
	Version     string         `json:"bastion_version"`
	Summary     []string       `json:"summary"`
	Agents      []reportAgent  `json:"agents"`
	Schedules   []uiSchedule   `json:"scheduled_agents"`
	SchedOK     bool           `json:"schedulers_read"`
	ToolServers []uiToolGroup  `json:"tool_servers"`
	Baseline    reportBaseline `json:"baseline"`
	Activity    []activityItem `json:"activity"`
}

// reportAgent is one agent in the report, with whether it is marked as
// yours. The mark is judged where the report is built, against the machine's
// own registry (sanction.go): a report read through the owner's lane
// (reads.go) is printed by an account that holds no registry, and judging it
// there listed every agent as not marked as yours under a summary that
// counted the machine's marks.
type reportAgent struct {
	agentView
	NotYours bool `json:"not_marked_yours,omitempty"`
}

func buildReport(now, since time.Time) machineReport {
	hn, _ := os.Hostname()
	r := machineReport{Machine: hn, Generated: now, Since: since, Version: clientVersion}
	if agents, err := observedAgents(); err == nil {
		for _, v := range buildAgentViews(agents, processTree()) {
			if v.Self != nil {
				v.Self.LastPrompt = ""
			}
			v.DelegationToken = "" // a shared secret for the Host, as readAgents leaves it out
			a := reportAgent{agentView: v}
			if v.Role != "service" && v.Kind != kindApp {
				ok, _ := agentSanction(v.agentObs)
				a.NotYours = !ok
			}
			r.Agents = append(r.Agents, a)
		}
	}
	r.Schedules, r.SchedOK = collectSchedules()
	r.ToolServers = collectToolGroups()
	if f, ok, err := baselineLoad(); err == nil {
		r.Baseline.Has, r.Baseline.TakenAt, r.Baseline.Note = true, f.TakenAt, baselineIntegrityNote(f, ok)
		if machineAuthorityHeld() {
			rep := deltaPass(&digestCache{}, now, deltaRoleOperator)
			if rep.WalkFailed != "" {
				r.Baseline.Why = "the process walk failed: " + rep.WalkFailed
			} else {
				r.Baseline.Compared = true
				for _, ev := range rep.Findings {
					r.Baseline.Findings = append(r.Baseline.Findings, ev.Level+": "+deltaOneLine(ev))
				}
			}
		} else {
			r.Baseline.Why = "comparing needs the machine's administrator; run the report with sudo"
		}
	}
	r.Activity = collectActivity(since)
	r.Summary = reportSummary(r)
	return r
}

// reportSummary is the problems first, in counts a person can act on.
func reportSummary(r machineReport) []string {
	var s []string
	sessions, notYours, promptsOff, waiting := 0, 0, 0, 0
	for _, a := range r.Agents {
		if a.Role == "service" || a.Kind != kindAgent {
			continue
		}
		sessions++
		if a.NotYours {
			notYours++
		}
		if a.Self != nil && a.Self.PermissionMode == "bypassPermissions" {
			promptsOff++
		}
		if a.Self != nil && a.Self.WaitingFor != "" {
			waiting++
		}
	}
	line := fmt.Sprintf("%s running", plural(sessions, "AI agent session", "AI agent sessions"))
	var extra []string
	if notYours > 0 {
		extra = append(extra, fmt.Sprintf("%d not marked as yours", notYours))
	}
	if promptsOff > 0 {
		extra = append(extra, fmt.Sprintf("%d with permission prompts off", promptsOff))
	}
	if waiting > 0 {
		extra = append(extra, fmt.Sprintf("%d waiting for a person", waiting))
	}
	if len(extra) > 0 {
		line += ": " + strings.Join(extra, ", ")
	}
	s = append(s, line+".")
	if len(r.Schedules) > 0 {
		s = append(s, plural(len(r.Schedules), "scheduled job starts", "scheduled jobs start")+" an AI agent with nobody at the keyboard.")
	}
	plain, unpinned := 0, 0
	for _, g := range r.ToolServers {
		for _, t := range g.Servers {
			for _, p := range t.Problems {
				switch {
				case strings.Contains(p, "plain text"):
					plain++
				case strings.Contains(p, "no fixed version"):
					unpinned++
				}
			}
		}
	}
	if plain > 0 {
		s = append(s, plural(plain, "MCP tool server has", "MCP tool servers have")+" a key written in plain text.")
	}
	if unpinned > 0 {
		s = append(s, plural(unpinned, "MCP tool server runs", "MCP tool servers run")+" a package with no fixed version.")
	}
	switch {
	case !r.Baseline.Has:
		s = append(s, "No baseline is recorded, so nothing new on this machine can be told apart from what was always there.")
	case r.Baseline.Compared && len(r.Baseline.Findings) > 0:
		s = append(s, plural(len(r.Baseline.Findings), "thing runs", "things run")+" that the baseline does not hold.")
	case r.Baseline.Compared:
		s = append(s, "Everything running is in the baseline.")
	}
	return s
}

func renderReportMarkdown(w io.Writer, r machineReport) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("# AI agents on %s\n\n", mdText(r.Machine))
	p("Written %s by privatae-bastion %s. Activity covers %s to now. No AI model wrote any of this report.\n\n",
		r.Generated.Format("2006-01-02 15:04 MST"), mdText(r.Version), r.Since.Format("2006-01-02 15:04"))
	p("## Summary\n\n")
	for _, l := range r.Summary {
		p("- %s\n", mdText(l))
	}
	p("\n## Agents running now\n\n")
	if len(r.Agents) == 0 {
		p("None.\n")
	}
	for _, a := range r.Agents {
		if a.Role == "service" {
			p("- **%s background service** (pid %d): starts background sessions; not a session itself.\n",
				mdText(familyLabel(a.Signature)), a.PID)
			continue
		}
		l := agentLinesOf(a.agentView, r.Generated)
		p("- **%s**: %s\n", mdText(familyLabel(a.Signature)), mdText(l.Head))
		if l.State != "" {
			p("  - %s\n", mdText(l.State))
		}
		if l.Where != "" {
			p("  - %s · pid %d\n", mdText(l.Where), a.PID)
		}
		if len(a.RunningNow) > 0 {
			p("  - running now: `%s`\n", mdCode(strings.Join(a.RunningNow, "; ")))
		}
		if len(a.ToolServers) > 0 {
			p("  - tool servers: %s\n", mdText(strings.Join(a.ToolServers, ", ")))
		}
		if len(a.LLMEndpoints) > 0 {
			p("  - talks to: %s\n", mdText(strings.Join(a.LLMEndpoints, ", ")))
		}
		if a.NotYours {
			p("  - not marked as yours\n")
		}
	}
	p("\nNames, titles and statuses are what each agent says about itself.\n")
	p("\n## Scheduled jobs that start an agent\n\n")
	switch {
	case !r.SchedOK:
		p("This platform's schedulers could not be read, so this section is empty because nothing looked.\n")
	case len(r.Schedules) == 0:
		p("None.\n")
	}
	for _, s := range r.Schedules {
		p("- **%s** %s, from %s", mdText(s.Agent), mdText(s.Schedule), mdText(s.Where))
		if s.User != "" {
			p(", as %s", mdText(s.User))
		}
		p(": `%s`\n", mdCode(s.Command))
	}
	p("\n## MCP tool servers\n\n")
	if len(r.ToolServers) == 0 {
		p("None configured in any settings file this bastion can read.\n")
	}
	for _, g := range r.ToolServers {
		p("- **%s**: %s\n", mdText(g.Client), plural(len(g.Servers), "tool server", "tool servers"))
		for _, t := range g.Servers {
			if len(t.Problems) == 0 {
				p("  - %s: no problems found\n", mdText(t.Name))
				continue
			}
			for _, pr := range t.Problems {
				p("  - %s: %s\n", mdText(t.Name), mdText(pr))
			}
		}
	}
	p("\n## Changes since the baseline\n\n")
	switch {
	case !r.Baseline.Has:
		p("No baseline is recorded. Record one on the console's This machine page, or with " +
			"`sudo -H privatae-bastion observe:baseline`.\n")
	default:
		p("Baseline recorded %s.", mdText(r.Baseline.TakenAt))
		if r.Baseline.Note != "" {
			p(" **%s**", mdText(r.Baseline.Note))
		}
		p("\n\n")
		if !r.Baseline.Compared {
			p("Not compared: %s.\n", mdText(r.Baseline.Why))
		} else if len(r.Baseline.Findings) == 0 {
			p("Nothing running is outside the baseline.\n")
		}
		for _, f := range r.Baseline.Findings {
			p("- %s\n", mdText(f))
		}
	}
	p("\n## Activity\n\n")
	if len(r.Activity) == 0 {
		p("Nothing happened in this period.\n")
	}
	for _, it := range r.Activity {
		who := ""
		if it.Who != "" {
			who = it.Who + " "
		}
		refused := ""
		if it.Refused {
			refused = " (refused)"
		}
		p("- %s: %s%s\n", it.At.Local().Format("Jan 2 15:04"), mdText(who+it.What), refused)
	}
}

// mdText keeps agent- and file-written text from becoming Markdown: no
// links, images, emphasis or HTML can be smuggled in through a session title.
func mdText(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
		"<", "&lt;", ">", "&gt;", "!", `\!`, "#", `\#`, "|", `\|`)
	return r.Replace(cleanText(s, 400))
}

func mdCode(s string) string { return strings.ReplaceAll(cleanText(s, 400), "`", "'") }

const reportUsage = "usage: privatae-bastion report [--since 7d] [--json] [--out FILE | --out -]"

// readReport is the report itself, built where the machine's state is.
func readReport(o readOpts) (machineReport, error) {
	since, err := o.since(7 * 24 * time.Hour)
	if err != nil {
		return machineReport{}, err
	}
	now := time.Now()
	return buildReport(now, now.Add(-since)), nil
}

func cmdReport(args []string) error {
	sinceFlag, asJSON, out := "", false, ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			asJSON = true
		case args[i] == "--since" && i+1 < len(args):
			if _, err := parseSince(args[i+1]); err != nil {
				return err
			}
			sinceFlag, i = args[i+1], i+1
		case args[i] == "--out" && i+1 < len(args):
			out, i = args[i+1], i+1
		default:
			return errors.New(reportUsage)
		}
	}
	r, err := readMachine("report", readOpts{Since: sinceFlag}, readReport)
	if err != nil {
		return laneRefusalError("report", err)
	}
	if out == "-" {
		// To standard output, for an agent that reads it rather than keeps it.
		if asJSON {
			return printJSON(os.Stdout, r)
		}
		renderReportMarkdown(os.Stdout, r)
		return nil
	}
	now := r.Generated.Local()
	if out == "" {
		d, err := configDir()
		if err != nil {
			return err
		}
		ext := ".md"
		if asJSON {
			ext = ".json"
		}
		out = filepath.Join(d, "reports", "report-"+now.Format("2006-01-02-150405")+ext)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(fh)
		enc.SetIndent("", "  ")
		err = enc.Encode(r)
	} else {
		renderReportMarkdown(fh, r)
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	fmt.Println("report written to", out)
	return nil
}
