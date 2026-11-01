package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A read through the lane is answered for the machine's owner's account and
// nobody else's: another account would see every account's sessions.
func TestALaneReadIsAnsweredOnlyForTheOwnersAccount(t *testing.T) {
	uiTestConfigDir(t)
	if r := serveRead(1000, "sam", agentAskRequest{Op: "read", Read: "status"}); r.OK ||
		!strings.Contains(r.Why, "approvals-owner --account sam") {
		t.Errorf("with no owner recorded: %+v", r)
	}
	laneOwner(t, 1000)
	if r := serveRead(1000, "sam", agentAskRequest{Op: "read", Read: "status"}); !r.OK || len(r.View) == 0 {
		t.Errorf("the owner was refused: %+v", r)
	}
	if r := serveRead(1001, "lee", agentAskRequest{Op: "read", Read: "agents"}); r.OK || r.View != nil ||
		!strings.Contains(r.Why, "only for its owner's account (sam), not lee") {
		t.Errorf("another account: %+v", r)
	}
	if r := serveRead(1000, "sam", agentAskRequest{Op: "read", Read: "../ui.secret"}); r.OK ||
		!strings.Contains(r.Why, "no read called") {
		t.Errorf("a read that does not exist: %+v", r)
	}
	if r := serveRead(1000, "sam", agentAskRequest{Op: "read", Read: "activity", Since: "forever"}); r.OK {
		t.Errorf("a --since nobody can parse was answered: %+v", r)
	}
}

// Reads that walk every process or run the package manager run one at a
// time, and an agent polling one gets the last answer back for readReuse.
func TestAHeavyReadIsReusedNotRunAgain(t *testing.T) {
	runs := 0
	spec := machineRead{heavy: true, build: func(readOpts) (any, error) { runs++; return map[string]int{"run": runs}, nil }}
	now := time.Now()
	prev := readNow
	t.Cleanup(func() { readNow = prev })
	readNow = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if _, err := runMachineRead("test-heavy", spec, readOpts{}); err != nil {
			t.Fatal(err)
		}
	}
	if runs != 1 {
		t.Errorf("three reads inside the window ran the pass %d times", runs)
	}
	if _, err := runMachineRead("test-heavy", spec, readOpts{Since: "1d"}); err != nil || runs != 2 {
		t.Errorf("a read with other flags was handed the first one's answer (runs %d, %v)", runs, err)
	}
	now = now.Add(readReuse)
	b, err := runMachineRead("test-heavy", spec, readOpts{})
	if err != nil || runs != 3 || !strings.Contains(string(b), `"run":3`) {
		t.Errorf("past the window: runs %d, %s, %v", runs, b, err)
	}
	light := machineRead{build: func(readOpts) (any, error) { runs++; return runs, nil }}
	_, _ = runMachineRead("test-light", light, readOpts{})
	_, _ = runMachineRead("test-light", light, readOpts{})
	if runs != 5 {
		t.Errorf("a light read was cached: runs %d", runs)
	}
}

// Reads leave connections for stop asks: past readSlots, a read is turned
// away, not queued.
func TestReadsCannotTakeEveryConnection(t *testing.T) {
	uiTestConfigDir(t)
	laneOwner(t, 1000)
	if cap(readSlots) >= askSockInFlight {
		t.Fatalf("reads may hold %d of %d connections", cap(readSlots), askSockInFlight)
	}
	for i := 0; i < cap(readSlots); i++ {
		readSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < cap(readSlots); i++ {
			<-readSlots
		}
	})
	if r := serveRead(1000, "sam", agentAskRequest{Op: "read", Read: "status"}); r.OK || !strings.Contains(r.Why, "ask again") {
		t.Errorf("a read past the slots: %+v", r)
	}
}

// What crosses the lane is the value the words are printed from, so a read
// through the lane prints exactly what the administrator's own run prints.
func TestEveryReadPrintsTheSameAfterTheLane(t *testing.T) {
	homeTestWorld(t, true)
	agents, err := readAgents(readOpts{Prompts: true})
	if err != nil || len(agents.Agents) == 0 {
		t.Fatalf("agents: %+v %v", agents, err)
	}
	now := time.Now()
	printers := map[string]func(*bytes.Buffer, any){}
	values := map[string]any{}
	add := func(name string, v any, print func(*bytes.Buffer, any)) { values[name], printers[name] = v, print }

	add("agents", agents, func(w *bytes.Buffer, v any) { printAgents(w, v.(agentsRead).Agents, now) })
	add("status", statusRead{Version: "9.9.9", Running: "partly", Mode: "networked",
		Anchor: &statusAnchor{Host: "home", Owner: "Sam", Since: "2026-10-01"},
		Pairings: []statusPairing{
			{Host: "home", State: "active", Transport: "local", Lanes: "/run/x.sock", Runs: "/runs", Local: "127.0.0.1:7878", Answering: true},
			{Host: "vm", State: "active", Transport: "tcp", Lanes: "127.0.0.1:8811", Local: "127.0.0.1:7879"},
			{Host: "cloud", State: "active", Transport: "tunnel", BastionIP: "2001:db8::2", HostIP: "2001:db8::1", Endpoint: "e:51820", Local: "127.0.0.1:7880"},
			{Host: "bad", State: "invalid", Problem: "no key"},
		}}, func(w *bytes.Buffer, v any) { printStatus(w, v.(statusRead)) })
	add("schedules", schedulesRead{Read: true, Schedules: []uiSchedule{{Agent: "aider", Schedule: "every day at 09:00",
		Where: "cron /etc/cron.d/a", User: "sam", Command: "aider --yes"}}}, func(w *bytes.Buffer, v any) { printSchedules(w, v.(schedulesRead)) })
	add("tool-servers", toolServersRead{Clients: []uiToolGroup{{Client: "Claude Code", Bad: 1, Servers: []uiToolServer{
		{Name: "fs", Where: "/home/sam/.claude.json", Problems: []string{"a key is written in plain text"}}, {Name: "git", Where: "x"}}}}},
		func(w *bytes.Buffer, v any) { printToolServers(w, v.(toolServersRead)) })
	add("posture", postureRead{Supported: true, OS: "linux", AsAdmin: true, Checks: &hostPosture{Ufw: "active",
		Pubwall: "accept+tdrop", Ssh22: "unscoped", F2b: "inactive", Input: "ACCEPT", Sec: 3, Load: 0.5, Cpus: 4,
		Reboot: "yes", DiskPct: 41, Jrn: 12, Puv: "ok", Timeouts: []string{"sec"}}},
		func(w *bytes.Buffer, v any) { printPosture(w, v.(postureRead)) })
	add("activity", activityRead{Activity: []activityItem{{At: now.Add(-time.Hour), Kind: "stop", Who: "Sam", What: "stopped aider", Refused: true}}},
		func(w *bytes.Buffer, v any) { printActivity(w, v.(activityRead).Activity) })
	add("approvals", approvalsRead{For: "for this machine", CodeSetUp: true, Waiting: []approvalWaiting{
		{ID: "abcd1234", AskedAt: "2026-11-01T10:00:00Z", Purpose: "local_stop", Text: "Stop aider (pid 101)."}}},
		func(w *bytes.Buffer, v any) { printApprovals(w, v.(approvalsRead)) })
	add("baseline-diff", deltaReport{Baseline: "intact", BaselineTakenAt: "2026-10-01", Coverage: "all-processes",
		Scanned: 300, Elapsed: "1.2s", ShortLived: 2, ShortLivedTotal: 5, Notes: []string{"a note"},
		Findings: []deltaEvent{{Level: "high", Kind: "program_new", Entry: baselineEntry{Kind: "process", Signature: "aider",
			User: "sam", Unit: "cron.service"}, Evidence: []evidence{{Tier: "strong", Signal: "exe", Value: "/usr/bin/aider"}}}},
		Filtered: []deltaEvent{{Level: "info"}}},
		func(w *bytes.Buffer, v any) { _ = printDelta(w, v.(deltaReport)) })
	rep := buildReport(now, now.Add(-7*24*time.Hour))
	add("report", rep, func(w *bytes.Buffer, v any) { renderReportMarkdown(w, v.(machineReport)) })

	for name := range machineReads {
		if name == "baseline" {
			continue // TestBaselineShowPrintsTheSameAfterTheLane: it needs a file on disk
		}
		if _, ok := values[name]; !ok {
			t.Errorf("read %q has no case here", name)
		}
	}
	for name, v := range values {
		var before, after bytes.Buffer
		printers[name](&before, v)
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		back := zeroLike(v)
		if err := json.Unmarshal(b, back.ptr); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		printers[name](&after, back.get())
		if before.Len() == 0 {
			t.Errorf("%s printed nothing", name)
		}
		if before.String() != after.String() {
			t.Errorf("%s reads differently after the lane:\nbefore:\n%s\nafter:\n%s", name, before.String(), after.String())
		}
	}
}

func TestBaselineShowPrintsTheSameAfterTheLane(t *testing.T) {
	isolateConfigDir(t)
	writeV1Accounting(t)
	v, err := readBaseline(readOpts{})
	if err != nil || !v.Has {
		t.Fatalf("%+v %v", v, err)
	}
	var before, after bytes.Buffer
	if err := printBaseline(&before, v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	var back baselineRead
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if err := printBaseline(&after, back); err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() || !strings.Contains(before.String(), "entries") {
		t.Errorf("before:\n%s\nafter:\n%s", before.String(), after.String())
	}
}

// zeroLike is a fresh value of v's type to decode into.
type decoded struct {
	ptr any
	get func() any
}

func zeroLike(v any) decoded {
	switch v.(type) {
	case agentsRead:
		var x agentsRead
		return decoded{&x, func() any { return x }}
	case statusRead:
		var x statusRead
		return decoded{&x, func() any { return x }}
	case schedulesRead:
		var x schedulesRead
		return decoded{&x, func() any { return x }}
	case toolServersRead:
		var x toolServersRead
		return decoded{&x, func() any { return x }}
	case postureRead:
		var x postureRead
		return decoded{&x, func() any { return x }}
	case activityRead:
		var x activityRead
		return decoded{&x, func() any { return x }}
	case approvalsRead:
		var x approvalsRead
		return decoded{&x, func() any { return x }}
	case deltaReport:
		var x deltaReport
		return decoded{&x, func() any { return x }}
	case machineReport:
		var x machineReport
		return decoded{&x, func() any { return x }}
	}
	panic("no case")
}

// Read from an ordinary account, the firewall's tools refuse and their
// refusals read as "absent" or a stray word: those fields are not reported,
// and the words say who can read them.
func TestPostureReadWithoutTheAdministratorReportsNoFirewall(t *testing.T) {
	prevAuth, prevHave := machineAuthorityHeld, observeHave
	t.Cleanup(func() { machineAuthorityHeld, observeHave = prevAuth, prevHave })
	machineAuthorityHeld = func() bool { return false }
	observeHave = func(string) bool { return false }
	v, err := readPosture(readOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if !observeHostSupported {
		if v.Checks != nil {
			t.Errorf("checks off Linux: %+v", v.Checks)
		}
		return
	}
	p := v.Checks
	for _, f := range []string{p.Ufw, p.Pubwall, p.Input, p.Ssh22} {
		if f != postureNeedsAdmin {
			t.Errorf("a firewall field read without the administrator says %q: %+v", f, p)
		}
	}
	var b bytes.Buffer
	printPosture(&b, v)
	out := b.String()
	if !strings.Contains(out, "Firewall: not read; it takes the administrator") || strings.Contains(out, "ufw firewall:") {
		t.Errorf("printed:\n%s", out)
	}
}

func TestPostureSaysEachCheckInWords(t *testing.T) {
	lines := strings.Join(postureLines(hostPosture{Ufw: "inactive", Pubwall: "absent", Ssh22: "scoped", F2b: "active",
		Input: "DROP", Sec: 0, Load: -1, Cpus: 2, Reboot: "no", DiskPct: -1, Jrn: -1, Puv: "absent"}, true), "\n")
	for _, want := range []string{"ufw firewall: installed, off", "iptables INPUT: refuses by default (DROP)",
		"SSH (port 22): admitted only from listed addresses", "fail2ban: running", "Security updates: none waiting",
		"System log: could not be read"} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in:\n%s", want, lines)
		}
	}
	for _, not := range []string{"pubwall", "Disk", "Load", "restart", "upgrade"} {
		if strings.Contains(lines, not) {
			t.Errorf("%q printed for a check that said nothing:\n%s", not, lines)
		}
	}
}

func TestTheNewReadCommandsRefuseStrayFlags(t *testing.T) {
	for name, cmd := range map[string]func([]string) error{"schedules": cmdSchedules, "tool-servers": cmdToolServers,
		"posture": cmdPosture, "status": cmdStatus, "baseline": cmdBaseline} {
		if err := cmd([]string{"--jsno"}); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("%s --jsno: %v", name, err)
		}
	}
	if err := cmdBaseline([]string{"record", "--now"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("baseline record --now: %v", err)
	}
}

// Read through the lane, the report is built where the machine's marks are
// and printed by an account that holds none of them: which agents are not
// marked as yours travels with the report, so the list agrees with its own
// summary instead of with the reading account's empty registry.
func TestTheReportSaysWhatIsMarkedAsTheMachineSaysIt(t *testing.T) {
	uiTestConfigDir(t)
	mine := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	other := anObservedAgent("goose", "/usr/local/bin/goose", 4244)
	stubStopWorld(t, []agentObs{mine, other}, nil)
	prevHome := homeForUserFn
	t.Cleanup(func() { homeForUserFn = prevHome })
	homeForUserFn = func(string) string { return "" }
	if _, err := addSanction(mine, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b, err := json.Marshal(buildReport(now, now.Add(-time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	uiTestConfigDir(t) // the owner's own account: no registry of its own
	var back machineReport
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	var md bytes.Buffer
	renderReportMarkdown(&md, back)
	out := md.String()
	if !strings.Contains(out, "2 AI agent sessions running: 1 not marked as yours.") {
		t.Errorf("the summary:\n%s", out)
	}
	if n := strings.Count(out, "not marked as yours\n"); n != 1 {
		t.Errorf("%d agents listed as not marked as yours, where the machine marks one of two:\n%s", n, out)
	}
}

// The delegation tag is a shared secret read out of another process's
// environment, which the owner's account cannot read; the console only ever
// says one is present (TestTheDelegationTagValueNeverReachesThePage). A read
// through the lane says no more.
func TestNoReadCarriesADelegationTag(t *testing.T) {
	const secret = "del_ThisIsTheHostsSecretTag"
	uiTestConfigDir(t)
	tagged := anObservedAgent("claude-code", "/usr/local/bin/claude", 4242)
	tagged.DelegationToken = secret
	stubStopWorld(t, []agentObs{tagged}, nil)
	prevHome := homeForUserFn
	t.Cleanup(func() { homeForUserFn = prevHome })
	homeForUserFn = func(string) string { return "" }
	laneOwner(t, 1000)
	for _, read := range []string{"agents", "report"} {
		r := serveRead(1000, "sam", agentAskRequest{Op: "read", Read: read, Prompts: true})
		if !r.OK || !strings.Contains(string(r.View), "4242") {
			t.Fatalf("%s: %+v", read, r)
		}
		if strings.Contains(string(r.View), secret) {
			t.Errorf("%s through the lane carries the delegation tag's value", read)
		}
	}
	// Nor the administrator's own run, and not the report file either: it is
	// written to be handed to someone.
	if v, err := readAgents(readOpts{}); err != nil || len(v.Agents) != 1 || v.Agents[0].DelegationToken != "" {
		t.Errorf("readAgents for the administrator: %+v %v", v, err)
	}
	if r, err := readReport(readOpts{}); err != nil || len(r.Agents) != 1 || r.Agents[0].DelegationToken != "" {
		t.Errorf("readReport for the administrator: %+v %v", r, err)
	}
}

// The skill an agent reads names the key tool-servers --json puts each
// server's problems under; a key the JSON does not have reads as none.
func TestTheSkillNamesTheKeyToolServersPrints(t *testing.T) {
	skill, err := os.ReadFile(filepath.Join("..", "docs", "skills", "bastion.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("what is wrong with each \\(`([A-Za-z_]+)`\\)").FindSubmatch(skill)
	if m == nil {
		t.Fatal("the skill no longer names the key tool-servers --json prints problems under")
	}
	b, _ := json.Marshal(toolServersRead{Clients: []uiToolGroup{{Client: "c", Servers: []uiToolServer{
		{Name: "fs", Problems: []string{"a key is written in plain text"}}}}}})
	if !strings.Contains(string(b), `"`+string(m[1])+`":["a key`) {
		t.Errorf("the skill says %q; tool-servers --json prints %s", m[1], b)
	}
}
