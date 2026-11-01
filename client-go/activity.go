package main

// activity.go — what happened on this machine, newest first, in one list:
// the console's Activity page and `privatae-bastion activity [--since 7d]
// [--json]` (plan Addendum 4, step 3).
//
// It adds no record of its own. It reads the ones this bastion already keeps,
// each the authority for its own kind of fact:
//
//	events.json          stops, by the owner or a Host, and stops refused
//	machine-factor/      the owner's approvals and the stops they carried
//	  audit.jsonl          out or refused
//	<pairing>/audit.jsonl  what each Host did here (files, stores, op runs)
//	mgmt_audit.jsonl     each Host's management ops and the verdict
//	pairing_audit.jsonl  Hosts paired, granted, revoked
//	sanctions            programs marked as yours, and when
//	local-deny.json      capabilities switched off for a Host, and when
//
// Each file is read from its tail (activityTailMax), so a long-lived machine
// shows its recent past without reading years of log on every load.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	activityTailMax = 256 << 10
	activityLimit   = 300
)

type activityItem struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"` // stop, approval, host, change
	Who     string    `json:"who,omitempty"`
	What    string    `json:"what"`
	Refused bool      `json:"refused,omitempty"`
}

// askedBy is ", asked by <who>" for a row about an agent's ask, else "".
func askedBy(row map[string]any) string {
	if who := actStr(row, "who"); who != "" {
		return ", asked by " + who
	}
	return ""
}

func collectActivity(since time.Time) []activityItem {
	var out []activityItem
	add := func(it activityItem) {
		if !it.At.Before(since) && it.What != "" {
			out = append(out, it)
		}
	}
	// Stops, as the page and the Host were told them.
	if p, err := localEventPath(); err == nil {
		for _, e := range loadLocalEvents(p) {
			add(activityItem{At: e.At, Kind: "stop", What: e.Text,
				Refused: strings.Contains(e.Text, "refused") || strings.Contains(e.Text, "It refused")})
		}
	}
	// The owner's approvals, and stops that did not happen (one that did is
	// already an event above).
	if dir := existingMachineFactorDir(); dir != "" {
		for _, row := range activityRows(filepath.Join(dir, "audit.jsonl")) {
			op, decision := actStr(row, "op"), actStr(row, "decision")
			switch {
			case op == localStopKind && strings.HasPrefix(decision, "not stopped"):
				target := actStr(row, "path") // "<pid> <signature>", as localStopOnce writes it
				if pid, sig, ok := strings.Cut(target, " "); ok {
					target = sig + " (pid " + pid + ")"
				}
				add(activityItem{At: rowTime(row), Kind: "stop", Who: "You", What: "approved stopping " + target +
					", but it was not stopped: " + strings.TrimPrefix(decision, "not stopped: "), Refused: true})
			case op == "local_baseline":
				add(activityItem{At: rowTime(row), Kind: "change", Who: "You", What: "recorded a new baseline"})
			case op == "stepup_approve":
				add(activityItem{At: rowTime(row), Kind: "approval", Who: "You",
					What: "approved " + purposeWords(strings.TrimPrefix(decision, "approved: ")) + askedBy(row)})
			case op == "stepup_deny":
				add(activityItem{At: rowTime(row), Kind: "approval", Who: "You", Refused: true,
					What: "denied " + purposeWords(strings.TrimPrefix(decision, "denied: ")) + askedBy(row)})
			case op == localStopAskOp:
				// An agent asked (agentask.go). Who is the asker in the words
				// the owner read on the request.
				add(activityItem{At: rowTime(row), Kind: "approval", Who: actStr(row, "who"), What: decision})
			case op == askHoldOp:
				who, what := "This machine", "held asks from "+actStr(row, "path")+" ("+decision+")"
				if decision == "lifted by the owner" {
					who, what = "You", "lifted the hold on asks from "+actStr(row, "path")
				}
				add(activityItem{At: rowTime(row), Kind: "approval", Who: who, What: what, Refused: who != "You"})
			}
		}
	}
	// What each Host did here.
	if cfgs, err := loadPairings(); err == nil {
		for _, c := range cfgs {
			if !c.active() {
				continue // nothing is created for a pending pairing (run.go)
			}
			for _, row := range activityRows(filepath.Join(c.dcnDir(), "audit.jsonl")) {
				decision := actStr(row, "decision")
				what := opWords(actStr(row, "op"))
				if p := actStr(row, "path"); p != "" {
					what += " " + p
				}
				if decision != "" {
					what += " (" + decision + ")"
				}
				add(activityItem{At: rowTime(row), Kind: "host", Who: "Host " + c.HostName, What: what,
					Refused: strings.HasPrefix(decision, "refused") || strings.HasPrefix(decision, "denied")})
			}
		}
	}
	if p, err := mgmtAuditPath(); err == nil {
		for _, row := range activityRows(p) {
			verdict := actStr(row, "verdict")
			what := "ran " + actStr(row, "op")
			if verdict != "" {
				what += " (" + verdict
				if why := actStr(row, "why"); why != "" && verdict != "ok" {
					what += ": " + why
				}
				what += ")"
			}
			add(activityItem{At: rowTime(row), Kind: "host", Who: "Host " + actStr(row, "self"), What: what,
				Refused: verdict != "" && verdict != "ok" && verdict != "allowed"})
		}
	}
	if d, err := configDir(); err == nil {
		for _, row := range activityRows(filepath.Join(d, auditFilePairing)) {
			add(activityItem{At: rowTime(row), Kind: "change", Who: "This machine",
				What:    opWords(actStr(row, "op")) + " " + actStr(row, "subject") + ": " + actStr(row, "decision"),
				Refused: strings.HasPrefix(actStr(row, "decision"), "refused")})
		}
	}
	// The owner's own changes.
	if recs, err := sanctionRecords(); err == nil {
		for _, r := range recs {
			add(activityItem{At: r.At, Kind: "change", Who: "You", What: "marked " + r.describeMark() + " as yours"})
		}
	}
	localDenyMu.Lock()
	f, err := localDenyLoad()
	localDenyMu.Unlock()
	if err == nil {
		for key, at := range f.At {
			host, fam, _ := strings.Cut(key, "/")
			if t, err := time.Parse(time.RFC3339, at); err == nil {
				add(activityItem{At: t, Kind: "change", Who: "You", What: "switched " + fam + " off for " + host})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > activityLimit {
		out = out[:activityLimit]
	}
	return out
}

// activityRows is the JSON rows in the tail of a JSONL file.
func activityRows(path string) []map[string]any {
	var rows []map[string]any
	for _, line := range tailLines(path, activityTailMax) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			rows = append(rows, m)
		}
	}
	return rows
}

func actStr(m map[string]any, k string) string { s, _ := m[k].(string); return cleanText(s, 300) }

func rowTime(m map[string]any) time.Time {
	t, _ := time.Parse(time.RFC3339, actStr(m, "ts"))
	return t
}

// opWords names the ops a person meets most in words; anything else keeps its
// name, which is what the audit file and the Host both call it.
func opWords(op string) string {
	switch op {
	case "dcn_read", "read_range":
		return "read"
	case "dcn_list", "list":
		return "listed"
	case "dcn_stat", "stat":
		return "looked at"
	case "pair", "pairing_add":
		return "Host paired"
	case "pairing_grant", "pairing_grant_sync":
		return "Host granted"
	case "pairing_revoke", "unpair":
		return "Host removed"
	case "quarantine_clear":
		return "Host released from quarantine"
	case "claim_owner":
		return "owner name set to"
	case "stepup_approve":
		return "approved"
	}
	return op
}

// purposeWords says an approval's purpose the way the request said it.
func purposeWords(purpose string) string {
	if pid, sig, ok := parseLocalStopPurpose(purpose); ok {
		return fmt.Sprintf("stopping %s (pid %d)", sig, pid)
	}
	if kind, _, _ := strings.Cut(purpose, "|"); kind != "" {
		return "a request (" + kind + ")"
	}
	return "a request"
}

// ── the command ─────────────────────────────────────────────────────────────

const activityUsage = "usage: privatae-bastion activity [--since 7d] [--json]"

func cmdActivity(args []string) error {
	sinceFlag, asJSON := "", false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			asJSON = true
		case args[i] == "--since" && i+1 < len(args):
			if _, err := parseSince(args[i+1]); err != nil {
				return err
			}
			sinceFlag = args[i+1]
			i++
		default:
			return errors.New(activityUsage)
		}
	}
	v, err := readMachine("activity", readOpts{Since: sinceFlag}, readActivity)
	if err != nil {
		return laneRefusalError("activity", err)
	}
	if asJSON {
		return printJSON(os.Stdout, v)
	}
	printActivity(os.Stdout, v.Activity)
	return nil
}

// activityRead is `activity`: what happened here, newest first.
type activityRead struct {
	Activity []activityItem `json:"activity"`
}

func readActivity(o readOpts) (activityRead, error) {
	since, err := o.since(7 * 24 * time.Hour)
	if err != nil {
		return activityRead{}, err
	}
	items := collectActivity(time.Now().Add(-since))
	if items == nil {
		items = []activityItem{}
	}
	return activityRead{Activity: items}, nil
}

// parseSince takes Go durations and whole days: 90m, 12h, 7d.
func parseSince(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		if _, err := fmt.Sscanf(d, "%d", &n); err == nil && n > 0 && n <= 3650 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, nil
	}
	return 0, fmt.Errorf("--since %q: give a duration like 12h or 7d", s)
}

func printActivity(w io.Writer, items []activityItem) {
	if len(items) == 0 {
		fmt.Fprintln(w, "Nothing has happened on this machine in that time.")
		return
	}
	for _, it := range items {
		who := it.Who
		if who != "" {
			who += " "
		}
		mark := ""
		if it.Refused {
			mark = "  [refused]"
		}
		fmt.Fprintf(w, "%s  %s%s%s\n", it.At.Local().Format("Jan 2 15:04"), who, it.What, mark)
	}
}
