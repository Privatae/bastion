package main

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// homeTestWorld: one Claude Code session waiting for the person, with
// permission prompts off and agent-written text that tries to be markup; its
// background service; and an app. Every name and title here is invented.
func homeTestWorld(t *testing.T, authority bool) {
	t.Helper()
	uiTestConfigDir(t)
	stubProcIdentity(t, "5551")
	home := fakeClaudeHome(t, 4242, "5551", `{"type":"ai-title","aiTitle":"<script>alert(1)</script> Rename invoices","sessionId":"x"}
{"type":"permission-mode","permissionMode":"bypassPermissions","sessionId":"x"}
{"type":"last-prompt","lastPrompt":"PRIVATE PROMPT TEXT","sessionId":"x"}
`)
	prevObs, prevTree, prevHome, prevAuth, prevWait := observedAgents, processTree, homeForUserFn, machineAuthorityHeld, homeWaitingFn
	prevUID := uidForUserFn
	t.Cleanup(func() {
		observedAgents, processTree, homeForUserFn, machineAuthorityHeld, homeWaitingFn = prevObs, prevTree, prevHome, prevAuth, prevWait
		uidForUserFn = prevUID
	})
	uidForUserFn = func(string) (int, bool) { return os.Getuid(), true }
	observedAgents = func() ([]agentObs, error) {
		return []agentObs{
			{PID: 4242, Kind: kindAgent, Signature: "claude-code", User: "u", Cmdline: "claude", Origin: originRemote},
			{PID: 4300, Kind: kindAgent, Signature: "claude-code", User: "u", Cmdline: "claude.exe daemon run --spawned"},
			{PID: 5000, Kind: kindApp, Signature: "claude-code", User: "u", Cmdline: "Claude"},
		}, nil
	}
	processTree = func() map[int]int { return nil }
	homeForUserFn = func(string) string { return home }
	machineAuthorityHeld = func() bool { return authority }
	homeWaitingFn = func() int { return 2 }
}

func TestTheHomePageCountsSessionsNotTheServiceOrApps(t *testing.T) {
	homeTestWorld(t, true)
	v := collectHomeView(time.Now())
	if v.Sessions != 1 || v.WaitingForYou != 1 || v.NotYours != 1 {
		t.Errorf("sessions %d, waiting %d, not yours %d; want 1, 1, 1", v.Sessions, v.WaitingForYou, v.NotYours)
	}
	if len(v.Families) != 1 || !strings.HasPrefix(v.Families[0].Heading, "Claude Code: 1 session (1 waiting for you)") {
		t.Fatalf("families %+v", v.Families)
	}
	rows := v.Families[0].Rows
	if !rows[0].WaitingForYou || !rows[0].PermissionsOff || rows[0].PID != 4242 {
		t.Errorf("the waiting session is not first, flagged: %+v", rows[0])
	}
	var service bool
	for _, r := range rows {
		service = service || (r.Service && r.PID == 4300)
	}
	if !service {
		t.Error("the background service is not shown as one")
	}
	if v.PerAccount || v.Waiting != 2 {
		t.Errorf("per-account %v, waiting %d", v.PerAccount, v.Waiting)
	}
}

// What an agent writes about itself is text on this page, never markup, and
// its last prompt is not on the home page at all.
func TestTheHomePageShowsAgentTextAsTextAndNoPrompts(t *testing.T) {
	homeTestWorld(t, true)
	u := uiTestServer(t)
	body := uiGet(t, u.handler(), "/", uiSignedIn(t, u)).Body.String()
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("an agent's title was rendered as markup")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt; Rename invoices") {
		t.Errorf("the title is not shown, escaped:\n%s", firstLines(body))
	}
	if strings.Contains(body, "PRIVATE PROMPT TEXT") {
		t.Error("a session's last prompt is on the home page")
	}
	for _, want := range []string{"waiting for you: permission prompt", "permission prompts off",
		"Background service", "2 requests are waiting for your approval", `href="/agent?pid=4242"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the home page does not say %q", want)
		}
	}
}

// A bastion in the person's own account says what that costs, on every load.
func TestTheHomePageSaysWhenTheBastionRunsInYourOwnAccount(t *testing.T) {
	homeTestWorld(t, false)
	u := uiTestServer(t)
	body := uiGet(t, u.handler(), "/fragments/home", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(body, "This bastion runs in your own account.") {
		t.Error("a per-account bastion did not say so")
	}
}

func TestAnAgentsPageShowsItsSessionAndItsLastPrompt(t *testing.T) {
	homeTestWorld(t, true)
	u := uiTestServer(t)
	w := uiGet(t, u.handler(), "/agent?pid=4242", uiSignedIn(t, u))
	if w.Code != http.StatusOK {
		t.Fatalf("/agent = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"shop-a1", "PRIVATE PROMPT TEXT", "Permission prompts are off",
		"what Claude Code says about this session", "The stopping rule"} {
		if !strings.Contains(body, want) {
			t.Errorf("the agent page does not say %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("an agent's title was rendered as markup on its page")
	}
	gone := uiGet(t, u.handler(), "/agent?pid=999", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(gone, "Not running") {
		t.Error("a pid that is no agent did not say so")
	}
}

func TestAnAgentsToolServersAreItsOwnClientsAndSayWhatIsWrong(t *testing.T) {
	servers := []mcpServerObs{
		{Client: "claude-code", Path: "/home/u/.claude.json", Name: "files", SecretInPlaintext: true,
			PackageName: "mcp-files", PackagePinned: "no"},
		{Client: "claude-code", Path: "/work/shop/.mcp.json", Name: "db", PackagePinned: "yes"},
		{Client: "cursor", Path: "/home/u/.cursor/mcp.json", Name: "other-client"},
		{Client: "claude-code", Path: "/home/someone-else/.claude.json", Name: "not-this-account"},
	}
	got := toolServersFor("claude-code", "/home/u", "/work/shop", servers)
	if len(got) != 2 || got[0].Name != "files" || got[1].Name != "db" {
		t.Fatalf("tool servers %+v", got)
	}
	if len(got[0].Problems) != 2 || !strings.Contains(got[0].Problems[0], "plain text") ||
		!strings.Contains(got[0].Problems[1], "no fixed version") {
		t.Errorf("problems %v", got[0].Problems)
	}
}

// The first run says what to do next, and stops saying it once the owner's
// code and a baseline are in place.
func TestTheHomePageWalksAFirstRunThroughCodeAndBaseline(t *testing.T) {
	homeTestWorld(t, true)
	u := uiTestServer(t)
	h, cookie := u.handler(), uiSignedIn(t, u)
	body := uiGet(t, h, "/fragments/home", cookie).Body.String()
	for _, want := range []string{"Getting started", "Set up your code", "Record a baseline", "connect a Host"} {
		if !strings.Contains(body, want) {
			t.Errorf("a first run does not say %q", want)
		}
	}
	d, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, d, machineTestSecret)
	if f, _ := recordBaselineFromConsole(codeFor(t, machineTestSecret)); !strings.HasPrefix(f, "Recorded") {
		t.Fatalf("baseline: %q", f)
	}
	if body := uiGet(t, h, "/fragments/home", cookie).Body.String(); strings.Contains(body, "Getting started") {
		t.Error("the first-run steps still show with the code and a baseline in place")
	}
}
