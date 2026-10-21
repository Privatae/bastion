package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Origin. Each fixture is a process tree in the shape a real
// box produces; the facts function is what the platform files hand the
// shared walk, so every OS's rule is exercised from the Linux CI run.

func factsOf(m map[int]procFacts) func(int) (procFacts, bool) {
	return func(pid int) (procFacts, bool) {
		f, ok := m[pid]
		return f, ok
	}
}

func TestClassifyOrigin(t *testing.T) {
	cases := []struct {
		name     string
		tree     map[int]procFacts
		pid      int
		observed map[int]bool
		extra    originExtra
		want     string
		signal   string
	}{
		{
			// The headline shape: cron -> sh -> python agent, no tty.
			name: "cron job on linux",
			tree: map[int]procFacts{
				1:    {PID: 1, Comm: "systemd"},
				800:  {PID: 800, PPID: 1, Comm: "cron", Unit: "cron.service"},
				9001: {PID: 9001, PPID: 800, Comm: "sh"},
				9002: {PID: 9002, PPID: 9001, Comm: "python3"},
			},
			pid: 9002, want: originScheduler, signal: "scheduler-parent",
		},
		{
			name: "systemd timer-activated unit",
			tree: map[int]procFacts{
				1:    {PID: 1, Comm: "systemd"},
				4100: {PID: 4100, PPID: 1, Comm: "python3", Unit: "nightly-agent.service"},
			},
			pid:   4100,
			extra: originExtra{TimerUnits: map[string]string{"nightly-agent.service": "nightly-agent.timer"}},
			want:  originScheduler, signal: "systemd-timer",
		},
		{
			name: "interactive terminal",
			tree: map[int]procFacts{
				1:    {PID: 1, Comm: "systemd"},
				2000: {PID: 2000, PPID: 1, Comm: "gnome-terminal-", Interactive: true, Detail: "tty pts/0"},
				2001: {PID: 2001, PPID: 2000, Comm: "bash", Interactive: true, Detail: "tty pts/0"},
				2002: {PID: 2002, PPID: 2001, Comm: "claude", Interactive: true, Detail: "tty pts/0"},
			},
			pid: 2002, want: originInteractive, signal: "session",
		},
		{
			// A shell under sshd has a tty too; the sshd ancestor wins.
			name: "ssh session",
			tree: map[int]procFacts{
				1:    {PID: 1, Comm: "systemd"},
				700:  {PID: 700, PPID: 1, Comm: "sshd", Unit: "ssh.service"},
				7001: {PID: 7001, PPID: 700, Comm: "sshd-session"},
				7002: {PID: 7002, PPID: 7001, Comm: "bash", Interactive: true, Detail: "tty pts/2"},
				7003: {PID: 7003, PPID: 7002, Comm: "aider", Interactive: true, Detail: "tty pts/2"},
			},
			pid: 7003, want: originRemote, signal: "remote-parent",
		},
		{
			name: "sub-agent forked by an observed agent",
			tree: map[int]procFacts{
				1:    {PID: 1, Comm: "systemd"},
				3000: {PID: 3000, PPID: 1, Comm: "claude", Interactive: true, Detail: "tty pts/1"},
				3001: {PID: 3001, PPID: 3000, Comm: "bash", Interactive: true, Detail: "tty pts/1"},
				3002: {PID: 3002, PPID: 3001, Comm: "codex", Interactive: true, Detail: "tty pts/1"},
			},
			pid: 3002, observed: map[int]bool{3000: true},
			want: originAgent, signal: "parent-agent",
		},
		{
			name: "systemd service, no tty",
			tree: map[int]procFacts{
				1:    {PID: 1, Comm: "systemd"},
				5000: {PID: 5000, PPID: 1, Comm: "node", Unit: "openclaw.service"},
			},
			pid: 5000, want: originService, signal: "service-parent",
		},
		{
			// Windows: a task under the Schedule svchost, session 0.
			name: "windows scheduled task",
			tree: map[int]procFacts{
				4:    {PID: 4, Comm: "system"},
				600:  {PID: 600, PPID: 4, Comm: "wininit"},
				700:  {PID: 700, PPID: 600, Comm: "services"},
				1500: {PID: 1500, PPID: 700, Comm: "svchost"},
				8800: {PID: 8800, PPID: 1500, Comm: "node"},
			},
			pid:   8800,
			extra: originExtra{SchedulerPIDs: map[int]bool{1500: true}},
			want:  originScheduler, signal: "task-scheduler",
		},
		{
			// Windows: a service under services.exe with no scheduler pid known.
			name: "windows service session 0",
			tree: map[int]procFacts{
				700:  {PID: 700, PPID: 600, Comm: "services"},
				1501: {PID: 1501, PPID: 700, Comm: "svchost"},
				8801: {PID: 8801, PPID: 1501, Comm: "python"},
			},
			pid: 8801, want: originService, signal: "service-parent",
		},
		{
			name: "windows desktop session",
			tree: map[int]procFacts{
				900:  {PID: 900, PPID: 700, Comm: "explorer", Interactive: true, Detail: "session 1"},
				9100: {PID: 9100, PPID: 900, Comm: "windowsterminal", Interactive: true, Detail: "session 1"},
				9101: {PID: 9101, PPID: 9100, Comm: "node", Interactive: true, Detail: "session 1"},
			},
			pid: 9101, want: originInteractive, signal: "session",
		},
		{
			// macOS: launchd is everyone's parent; an interval job is told by
			// its executable matching the launchd inventory.
			name: "launchd interval job",
			tree: map[int]procFacts{
				1:   {PID: 1, Comm: "launchd"},
				420: {PID: 420, PPID: 1, Comm: "python3", Exe: "/usr/local/bin/python3"},
			},
			pid:   420,
			extra: originExtra{ScheduledExes: map[string]string{"/usr/local/bin/python3": "com.example.nightly"}},
			want:  originScheduler, signal: "scheduled-job",
		},
		{
			name: "launchd daemon with no schedule",
			tree: map[int]procFacts{
				1:   {PID: 1, Comm: "launchd"},
				421: {PID: 421, PPID: 1, Comm: "node", Exe: "/usr/local/bin/node"},
			},
			pid: 421, want: originService, signal: "service-parent",
		},
		{
			name: "unreadable process",
			tree: map[int]procFacts{},
			pid:  1, want: originUnknown, signal: "origin",
		},
		{
			// An unreadable ancestor mid-walk: decide from what we hold.
			name: "unreadable ancestor, no tty",
			tree: map[int]procFacts{
				6000: {PID: 6000, PPID: 5999, Comm: "python3"},
			},
			pid: 6000, want: originUnknown, signal: "origin",
		},
		{
			name: "parent map cycle terminates",
			tree: map[int]procFacts{
				10: {PID: 10, PPID: 11, Comm: "a"},
				11: {PID: 11, PPID: 10, Comm: "b"},
			},
			pid: 10, want: originUnknown, signal: "origin",
		},
	}
	for _, c := range cases {
		got, ev := classifyOrigin(c.pid, factsOf(c.tree), c.observed, c.extra)
		if got != c.want {
			t.Errorf("%s: origin = %q, want %q (evidence %v)", c.name, got, c.want, ev)
			continue
		}
		if len(ev) == 0 || ev[0].Signal != c.signal {
			t.Errorf("%s: evidence = %v, want first signal %q", c.name, ev, c.signal)
		}
		if len(ev) > 0 && ev[0].Tier == "" {
			t.Errorf("%s: evidence carries no tier", c.name)
		}
	}
}

// ── automation kind + promotion ─────────────────────────────────────────────

func TestMatchSignatureAutomation(t *testing.T) {
	cases := []struct {
		argv []string
		sig  string
		auto bool
		ok   bool
	}{
		{[]string{"claude"}, "claude-code", false, true},
		{[]string{"/usr/bin/xdotool", "type", "hello"}, "xdotool", true, true},
		{[]string{"chromedriver.exe", "--port=9515"}, "chromedriver", true, true},
		{[]string{"node", "/app/node_modules/playwright/cli.js", "test"}, "playwright", true, true},
		{[]string{"python3", "-m", "pytest", "tests/selenium_smoke.py"}, "selenium", true, true},
		{[]string{"bash", "-c", "echo playwright"}, "", false, false}, // not an interpreter
		{[]string{"node", "server.js"}, "", false, false},
		// an agent that also drives a browser is an agent first
		{[]string{"node", "/x/@anthropic-ai/claude-code/cli.js", "--playwright"}, "claude-code", false, true},
	}
	for _, c := range cases {
		sig, auto, ok := matchSignature(c.argv)
		if ok != c.ok || sig != c.sig || auto != c.auto {
			t.Errorf("matchSignature(%v) = (%q,%v,%v), want (%q,%v,%v)", c.argv, sig, auto, ok, c.sig, c.auto, c.ok)
		}
	}
}

func TestAutomationKindAndPromotion(t *testing.T) {
	byPid := map[int]agentObs{
		100: {PID: 100, Signature: "xdotool", Cmdline: "xdotool type hi", raw: "xdotool type hi", automation: true},
		200: {PID: 200, Signature: "playwright", Cmdline: "node playwright/cli.js", raw: "node playwright/cli.js", automation: true},
		300: {PID: 300, Signature: "claude-code", Cmdline: "claude", raw: "claude"},
	}
	parent := func(pid int) int { return 1 }
	classifyObservations(byPid, parent)
	if byPid[100].Kind != kindAutomation || byPid[200].Kind != kindAutomation || byPid[300].Kind != kindAgent {
		t.Fatalf("kinds after classify: %q %q %q", byPid[100].Kind, byPid[200].Kind, byPid[300].Kind)
	}
	// 200 talks to a model: promoted. 100 only hits an ambiguous port: stays automation.
	conns := []connObs{
		{PID: 200, RemoteIP: "1.2.3.4", RemotePort: 443},
		{PID: 100, RemoteIP: "127.0.0.1", RemotePort: 8080},
	}
	cloud := map[string]string{"1.2.3.4": "api.anthropic.com"}
	strong, weak := map[int]string{}, map[int]string{8080: "llama.cpp/localai"}
	info := func(pid int) procDetail { return procDetail{} }
	mergeConnections(byPid, conns, cloud, strong, weak, info, parent)
	if byPid[200].Kind != kindAgent {
		t.Errorf("playwright with model traffic should be an agent, got %q", byPid[200].Kind)
	}
	if byPid[100].Kind != kindAutomation || len(byPid[100].LLMEndpoints) != 1 {
		t.Errorf("xdotool on an ambiguous port should stay automation with the annotation, got %q %v", byPid[100].Kind, byPid[100].LLMEndpoints)
	}
	// evidence tiers follow the label
	ev := endpointEvidence(byPid[100].LLMEndpoints)
	if len(ev) != 1 || ev[0].Tier != tierAmbiguous {
		t.Errorf("ambiguous port evidence = %+v", ev)
	}
	ev = endpointEvidence(byPid[200].LLMEndpoints)
	if len(ev) != 1 || ev[0].Tier != tierVerified || ev[0].Value != "api.anthropic.com" {
		t.Errorf("cloud endpoint evidence = %+v", ev)
	}
}

func TestAgentObsWireShape(t *testing.T) {
	a := agentObs{PID: 1, Kind: kindAgent, Signature: "claude-code", Origin: originScheduler,
		Evidence: []evidence{{Signal: "scheduler-parent", Tier: tierVerified, Value: "cron pid 800"}}, automation: true}
	b, _ := json.Marshal(a)
	s := string(b)
	for _, want := range []string{`"origin":"scheduler"`, `"evidence":[{"signal":"scheduler-parent","tier":"verified","value":"cron pid 800"}]`} {
		if !strings.Contains(s, want) {
			t.Errorf("wire form lacks %s: %s", want, s)
		}
	}
	if strings.Contains(s, "automation") || strings.Contains(s, "raw") {
		t.Errorf("unexported fields leaked to the wire: %s", s)
	}
}
