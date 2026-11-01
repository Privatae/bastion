package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// askFlowWorld is askWorld with each agent's origin set, so the audit's
// "started by" can be checked: the asking claude-code session was started at
// a terminal, the aider job by the scheduler.
func askFlowWorld(t *testing.T) string {
	t.Helper()
	uiTestConfigDir(t)
	stubStopWorld(t, []agentObs{
		{PID: 101, Kind: kindAgent, Signature: "aider", User: "u", Origin: "scheduler"},
		{PID: 102, Kind: kindAgent, Signature: "aider", User: "u", Origin: "scheduler"},
		{PID: 103, Kind: kindAgent, Signature: "aider", User: "u", Origin: "scheduler"},
		{PID: 104, Kind: kindAgent, Signature: "aider", User: "u", Origin: "scheduler"},
		{PID: 105, Kind: kindAgent, Signature: "aider", User: "u", Origin: "scheduler"},
		{PID: 106, Kind: kindAgent, Signature: "aider", User: "u", Origin: "scheduler"},
		{PID: 300, Kind: kindAgent, Signature: "claude-code", User: "u", Origin: "interactive"},
		{PID: 4532, Kind: kindApp, Signature: "claude-desktop", User: "u"},
	}, map[int]int{310: 300, 311: 310})
	prev := homeForUserFn
	t.Cleanup(func() { homeForUserFn = prev })
	homeForUserFn = func(string) string { return "" }
	d, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, d, machineTestSecret)
	return d
}

func fullRequestID(t *testing.T, d, prefix string) string {
	t.Helper()
	for id := range requestsLoad(d) {
		if strings.HasPrefix(id, prefix) {
			return id
		}
	}
	t.Fatalf("no request %s", prefix)
	return ""
}

// The M1 gate's loop: an agent asks, follows the ask, and learns what the
// owner decided and what happened. Before, it got an id and nothing after.
func TestAnAgentFollowsItsAskToTheOutcome(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if !r.OK {
		t.Fatalf("refused: %s", r.Why)
	}
	if s := askStatus(d, r.Request, "u", false); !s.OK || s.State != askWaiting {
		t.Fatalf("before the owner answers: %+v", s)
	}
	id := fullRequestID(t, d, r.Request)
	if _, err := stepupApproveRequest(d, id, codeFor(t, machineTestSecret)); err != nil {
		t.Fatal(err)
	}
	if s := askStatus(d, r.Request, "u", false); s.State != askApproved {
		t.Fatalf("approved, not yet carried out: %+v", s)
	}
	localStopOnce(d, time.Now())
	s := askStatus(d, r.Request, "u", false)
	if s.State != askStopped || !strings.Contains(s.Outcome, "stopped aider (pid 101)") {
		t.Fatalf("after the stop: %+v", s)
	}
	if got := askSentence(askViewOf(s, false)); !strings.Contains(got, "The bastion stopped aider") {
		t.Errorf("the agent reads %q", got)
	}
}

// Another account learns nothing about an ask, not even that it exists.
func TestAnotherAccountLearnsNothingOfAnAsk(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if !r.OK {
		t.Fatal(r.Why)
	}
	theirs := askStatus(d, r.Request, "other", false)
	never := askStatus(d, "ffffffff", "other", false)
	if theirs.OK || theirs.State != askUnknown || theirs.Text != "" {
		t.Fatalf("another account read %+v", theirs)
	}
	if strings.ReplaceAll(theirs.Why, r.Request, "X") != strings.ReplaceAll(never.Why, "ffffffff", "X") {
		t.Errorf("an existing id reads differently from one that never existed: %q vs %q", theirs.Why, never.Why)
	}
	if s := askStatus(d, r.Request, "", false); s.OK {
		t.Errorf("an unnamed asker read an ask: %+v", s)
	}
}

// A deny says so, blocks the same ask, and blocks it for a day from the
// deny, not from the ask.
func TestADeniedAskBlocksADayFromTheDeny(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	id := fullRequestID(t, d, r.Request)
	if err := stepupDenyRequest(d, id); err != nil {
		t.Fatal(err)
	}
	if s := askStatus(d, r.Request, "u", false); s.State != askDenied {
		t.Fatalf("after the deny: %+v", s)
	}
	again := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if again.OK || !strings.Contains(again.Why, "refused this same stop within the last 24 hours") {
		t.Fatalf("the same ask again: %+v", again)
	}

	// Asked 25 h ago, denied a minute ago: still blocked.
	m := requestsLoad(d)
	q := m[id]
	q.At = time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339)
	q.DeniedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	m[id] = q
	if err := requestsSave(d, m); err != nil {
		t.Fatal(err)
	}
	if _, ok := requestsLoad(d)[id]; !ok {
		t.Fatal("a deny a minute old stopped blocking because the ask was 25 h old")
	}
	q.DeniedAt = time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339)
	m[id] = q
	_ = requestsSave(d, m)
	if _, ok := requestsLoad(d)[id]; ok {
		t.Fatal("a deny 25 h old still blocks")
	}
}

// Five refused asks in ten minutes hold that account's asks; another account
// is not held; the owner lifts it.
func TestRefusedAsksHoldTheAccountThatAsked(t *testing.T) {
	d := askFlowWorld(t)
	for i := 0; i < quarantineStrikes; i++ {
		if r := fileAsk(agentAskRequest{Op: "stop", PID: 4532}, "u", 311); r.OK {
			t.Fatalf("an app was asked to stop: %+v", r)
		}
	}
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if r.OK || !strings.Contains(r.Why, "on hold until") {
		t.Fatalf("after five refusals: %+v", r)
	}
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "other", 0); !r.OK {
		t.Fatalf("another account was held: %s", r.Why)
	}
	if err := askQuarantineClear(d, "u"); err != nil {
		t.Fatal(err)
	}
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 102}, "u", 311); !r.OK {
		t.Fatalf("after the owner lifted it: %s", r.Why)
	}
}

// What the owner refuses counts too: five denies hold the account.
func TestOwnerDeniesCountTowardTheHold(t *testing.T) {
	d := askFlowWorld(t)
	for pid := 101; pid < 101+quarantineStrikes; pid++ {
		r := fileAsk(agentAskRequest{Op: "stop", PID: pid}, "u", 311)
		if !r.OK {
			t.Fatalf("ask %d: %s", pid, r.Why)
		}
		if err := stepupDenyRequest(d, fullRequestID(t, d, r.Request)); err != nil {
			t.Fatal(err)
		}
	}
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 106}, "u", 311); r.OK || !strings.Contains(r.Why, "on hold") {
		t.Fatalf("after five denies: %+v", r)
	}
	// What the machine itself lacks is not the asker's doing.
	if until := askHeldUntil(d, "nobody", time.Now()); !until.IsZero() {
		t.Fatal("an account that never asked is held")
	}
}

func auditRowsOf(t *testing.T, d, op string) []map[string]any {
	t.Helper()
	var out []map[string]any
	fh, err := os.Open(filepath.Join(d, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil && m["op"] == op {
			out = append(out, m)
		}
	}
	return out
}

// Every row about an agent's ask names the asking agent and the target, with
// how each was started: filed, approved, carried out.
func TestTheAuditNamesTheAskerAndTheTarget(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if _, err := stepupApproveRequest(d, fullRequestID(t, d, r.Request), codeFor(t, machineTestSecret)); err != nil {
		t.Fatal(err)
	}
	localStopOnce(d, time.Now())
	for _, op := range []string{localStopAskOp, "stepup_approve", localStopKind} {
		rows := auditRowsOf(t, d, op)
		if len(rows) != 1 {
			t.Fatalf("%s: %d rows", op, len(rows))
		}
		raw, _ := json.Marshal(rows[0])
		var row struct {
			Asker struct {
				Account string `json:"account"`
				PID     int    `json:"pid"`
				Agent   struct {
					Signature, Origin string
					PID               int
				} `json:"agent"`
			} `json:"asker"`
			Target struct {
				Signature, Origin string
				PID               int
			} `json:"target"`
		}
		_ = json.Unmarshal(raw, &row)
		a, g := row.Asker, row.Target
		if a.Account != "u" || a.PID != 311 || a.Agent.Signature != "claude-code" || a.Agent.PID != 300 ||
			a.Agent.Origin != "interactive" || g.Signature != "aider" || g.PID != 101 || g.Origin != "scheduler" {
			t.Errorf("%s row: %s", op, raw)
		}
	}
}

// The owner sees the ask and the deny in Activity.
func TestActivityShowsAsksAndDenies(t *testing.T) {
	d := askFlowWorld(t)
	r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if err := stepupDenyRequest(d, fullRequestID(t, d, r.Request)); err != nil {
		t.Fatal(err)
	}
	var asked, denied bool
	for _, it := range collectActivity(time.Time{}) {
		if strings.Contains(it.Who, "Claude Code (pid 300)") && strings.Contains(it.What, "asked to stop aider") {
			asked = true
		}
		if it.Who == "You" && strings.HasPrefix(it.What, "denied ") && strings.Contains(it.What, "asked by Claude Code") &&
			it.Refused {
			denied = true
		}
	}
	if !asked || !denied {
		t.Fatalf("asked %v denied %v in %+v", asked, denied, collectActivity(time.Time{}))
	}
}

// What an agent branches on: the exit status, and JSON it can parse.
func TestAskExitStatusesAndJSON(t *testing.T) {
	for _, c := range []struct {
		v      askView
		waited bool
		want   int // -1: no error
	}{
		{askView{State: askStopped}, true, -1},
		{askView{State: askWaiting, Request: "abcd1234"}, false, -1},
		{askView{State: askWaiting, Request: "abcd1234"}, true, askExitWaiting},
		{askView{State: askApproved}, true, askExitWaiting},
		{askView{State: askDenied}, true, 1},
		{askView{State: askNotStopped}, false, 1},
		{askView{State: askRefused, Why: "x"}, false, 1},
		{askView{State: askUnknown, Why: "x"}, false, 1},
	} {
		var buf bytes.Buffer
		err := printAsk(&buf, c.v, true, c.waited)
		var q quietExit
		got := -1
		if errors.As(err, &q) {
			got = q.code
		} else if err != nil {
			t.Fatalf("%+v: %v", c.v, err)
		}
		if got != c.want {
			t.Errorf("%s (waited %v): exit %d, want %d", c.v.State, c.waited, got, c.want)
		}
		var back askView
		if json.Unmarshal(buf.Bytes(), &back) != nil || back.State != c.v.State {
			t.Errorf("%s: --json printed %q", c.v.State, buf.String())
		}
	}
}

// Agents write the pid before the flags as often as after.
func TestAskFlagsTakeThePositionalAnywhere(t *testing.T) {
	for _, args := range [][]string{{"101", "--wait", "5m", "--json"}, {"--json", "101", "--wait=5m"},
		{"--wait", "5m", "--json", "101"}} {
		key, wait, asJSON, err := askFlags("stop", args)
		if err != nil || key != "101" || wait != 5*time.Minute || !asJSON {
			t.Errorf("%v: %q %v %v %v", args, key, wait, asJSON, err)
		}
	}
	for _, args := range [][]string{{}, {"101", "102"}, {"101", "--wait", "-1m"}, {"101", "--nope"}} {
		if _, _, _, err := askFlags("stop", args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}

// A Host's request is the Host's own words. One that names an account on
// this machine as its asker must not put that account in the owner's audit,
// and the owner denying it must not count toward that account's hold.
func TestAHostsRequestNeverStrikesALocalAccount(t *testing.T) {
	d := askFlowWorld(t)
	for i := 0; i < quarantineStrikes; i++ {
		gd := map[string]any{"kind": "dcn_store_grant", "server": "box1", "root": "/data/" + strconv.Itoa(i),
			"mask": []any{"read"}, "sweep": "hourly", "sensitive": false,
			"asked_by_account": "u", "asked_by": "You", "asker": map[string]any{"account": "u"}}
		gp, err := purposeFromDetails(gd)
		if err != nil {
			t.Fatal(err)
		}
		id, err := stepupNewRequest(d, gp, gd)
		if err != nil {
			t.Fatal(err)
		}
		if err := stepupDenyRequest(d, id); err != nil {
			t.Fatal(err)
		}
	}
	if until := askHeldUntil(d, "u", time.Now()); !until.IsZero() {
		t.Fatalf("denying a Host's requests held a local account until %s", until)
	}
	for _, row := range auditRowsOf(t, d, "stepup_deny") {
		if row["asker"] != nil || row["who"] != nil {
			t.Fatalf("a Host's request named a local asker in the audit: %v", row)
		}
	}
	// A critical action's own "target" is not an ask's target.
	if p := askPartiesOf(map[string]any{"kind": "critical_action", "target": "prod-db"}); p != nil {
		t.Fatalf("a Host's request carried ask parties: %v", p)
	}
	// At the Host's door: the fields only this machine writes are dropped.
	ls := map[string]any{"kind": localStopKind, "pid": "101", "signature": "aider", "asked_by_account": "u",
		"asker": map[string]any{}, "asked_by": "You", "target": map[string]any{}}
	hostAskDetails(ls)
	for _, k := range []string{"asked_by_account", "asker", "asked_by", "target"} {
		if _, ok := ls[k]; ok {
			t.Fatalf("a Host's local_stop kept %q: %v", k, ls)
		}
	}
	ca := map[string]any{"kind": "critical_action", "target": "prod-db", "asked_by_account": "u"}
	hostAskDetails(ca)
	if ca["target"] != "prod-db" || ca["asked_by_account"] != nil {
		t.Fatalf("a critical action keeps its target and loses the local asker: %v", ca)
	}
}

// The holds file is keyed by kernel account names, and a user with
// subordinate ids can present thousands. An account with nothing left to
// remember (not held, no recent refusal, no hold within the forgiving day)
// is dropped at the next write; the ones that still matter stay.
func TestTheHoldsFileForgetsAccountsWithNothingToRemember(t *testing.T) {
	d := askFlowWorld(t)
	now := time.Now()
	at := func(ago time.Duration) string { return now.Add(-ago).UTC().Format(time.RFC3339) }
	m := map[string]*quarantineEntry{
		"stale":        {Refusals: []string{at(time.Hour)}},
		"old-hold":     {Strikes: 1, LastHold: at(48 * time.Hour)},
		"held":         {Strikes: 1, Until: now.Add(time.Hour).UTC().Format(time.RFC3339), LastHold: at(-time.Hour)},
		"doubling":     {Strikes: 2, LastHold: at(2 * time.Hour)},
		"recent-refus": {Refusals: []string{at(time.Minute)}},
	}
	if err := askQuarantineSave(d, m); err != nil {
		t.Fatal(err)
	}
	askStrike(d, "new", now)
	got := askQuarantineLoad(d)
	for _, k := range []string{"stale", "old-hold"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s has nothing left to remember and was kept: %v", k, got)
		}
	}
	for _, k := range []string{"held", "doubling", "recent-refus", "new"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("%s still matters and was dropped: %v", k, got)
		}
	}
	if got["doubling"].Strikes != 2 {
		t.Fatalf("the doubling was lost: %+v", got["doubling"])
	}
}

// Two accounts asking for the same stop each get their own request, which
// each alone can follow: handing the second one the first's id told it that
// someone else had asked, and gave it an id it could not follow.
func TestTwoAccountsAskingTheSameStopEachGetTheirOwn(t *testing.T) {
	d := askFlowWorld(t)
	a := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	b := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "other", 0)
	if !a.OK || !b.OK {
		t.Fatalf("asks: %+v %+v", a, b)
	}
	if a.Request == b.Request {
		t.Fatalf("the second account was handed the first account's request %s", a.Request)
	}
	if s := askStatus(d, b.Request, "other", false); !s.OK || s.State != askWaiting {
		t.Fatalf("the second account cannot follow its own ask: %+v", s)
	}
	if again := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311); again.Request != a.Request {
		t.Errorf("the same account asking again got a new request %s, not %s", again.Request, a.Request)
	}
	// The owner's deny of that stop holds for everyone.
	if err := stepupDenyRequest(d, fullRequestID(t, d, a.Request)); err != nil {
		t.Fatal(err)
	}
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "third", 0); r.OK {
		t.Errorf("a stop the owner refused was filed again by another account: %+v", r)
	}
}

// An approved stop was acted on; if it could not be done, asking again is a
// new request, not the old approved one for the rest of the day.
func TestAStopThatFailedCanBeAskedAgain(t *testing.T) {
	d := askFlowWorld(t)
	first := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if _, err := stepupApproveRequest(d, fullRequestID(t, d, first.Request), codeFor(t, machineTestSecret)); err != nil {
		t.Fatal(err)
	}
	localStopOnce(d, time.Now().Add(localStopWindow+time.Minute)) // read too late: not stopped
	if s := askStatus(d, first.Request, "u", false); s.State != askNotStopped {
		t.Fatalf("the late stop: %+v", s)
	}
	again := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311)
	if !again.OK || again.Request == first.Request {
		t.Fatalf("asking again after a failed stop: %+v (first %s)", again, first.Request)
	}
	if s := askStatus(d, again.Request, "u", false); s.State != askWaiting {
		t.Errorf("the new ask: %+v", s)
	}
}

// An account at its limit that asks again for a stop it already has waiting
// gets that request back: it is not a sixth ask, and it is not a refusal to
// count toward a hold.
func TestAskingAgainAtTheLimitReturnsTheWaitingRequest(t *testing.T) {
	d := askFlowWorld(t)
	var first string
	for pid := 101; pid < 101+askMaxPendingPer; pid++ {
		r := fileAsk(agentAskRequest{Op: "stop", PID: pid}, "u", 311)
		if !r.OK {
			t.Fatalf("ask %d: %s", pid, r.Why)
		}
		if first == "" {
			first = r.Request
		}
	}
	for i := 0; i < quarantineStrikes; i++ {
		if r := fileAsk(agentAskRequest{Op: "stop", PID: 101}, "u", 311); !r.OK || r.Request != first {
			t.Fatalf("asking again for a waiting stop at the limit: %+v (want %s)", r, first)
		}
	}
	if until := askHeldUntil(d, "u", time.Now()); !until.IsZero() {
		t.Fatalf("repeating a waiting ask held the account until %v", until)
	}
	if r := fileAsk(agentAskRequest{Op: "stop", PID: 106}, "u", 311); r.OK || !strings.Contains(r.Why, "already have 5") {
		t.Errorf("a new sixth ask: %+v", r)
	}
}
