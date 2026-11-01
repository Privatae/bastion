package main

import (
	"net/http"
	"strings"
	"testing"
)

// Recording a baseline decides what counts as normal, so it takes the
// owner's code: none set up, none typed, or the wrong one, and nothing is
// written.
func TestRecordingABaselineTakesTheOwnersCode(t *testing.T) {
	uiTestConfigDir(t)
	if f, _ := recordBaselineFromConsole("123456"); !strings.Contains(f, "Set up your code") {
		t.Errorf("no code set up: %q", f)
	}
	d, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, d, machineTestSecret)
	if f, _ := recordBaselineFromConsole(""); !strings.Contains(f, "Type the code") {
		t.Errorf("no code typed: %q", f)
	}
	if f, _ := recordBaselineFromConsole(codeFor(t, hostTestSecret)); !strings.Contains(f, "code refused") {
		t.Errorf("a wrong code: %q", f)
	}
	if _, _, err := baselineLoad(); err == nil {
		t.Fatal("a baseline was written without the owner's code")
	}
	f, class := recordBaselineFromConsole(codeFor(t, machineTestSecret))
	if class != "ok" {
		t.Fatalf("the owner's code: %q", f)
	}
	if _, _, err := baselineLoad(); err != nil {
		t.Errorf("recorded, but no baseline to load: %v", err)
	}
}

func TestToolServerProblemsAreSaidInPlainWords(t *testing.T) {
	p := toolProblems(mcpServerObs{Path: "/h/.claude.json", SecretInPlaintext: true, PackageName: "mcp-x",
		PackagePinned: "no", RunningState: "running_not_declared"})
	if len(p) != 3 || !strings.Contains(p[0], "plain text in /h/.claude.json") ||
		!strings.Contains(p[1], "no fixed version") || !strings.Contains(p[2], "not in any settings file") {
		t.Errorf("problems %q", p)
	}
	if p := toolProblems(mcpServerObs{SecretInPlaintext: true, Disabled: true}); len(p) != 0 {
		t.Errorf("a turned-off server reported %q", p)
	}
}

func TestThisMachineLoadsItsSections(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	h, cookie := u.handler(), uiSignedIn(t, u)
	page := uiGet(t, h, "/machine", cookie).Body.String()
	for _, frag := range []string{"/fragments/machine/schedules", "/fragments/machine/tools", "/fragments/machine/baseline"} {
		if !strings.Contains(page, `hx-get="`+frag+`"`) {
			t.Errorf("This machine does not load %s", frag)
		}
		if w := uiGet(t, h, frag, cookie); w.Code != http.StatusOK {
			t.Errorf("%s = %d", frag, w.Code)
		}
	}
	if body := uiGet(t, h, "/fragments/machine/baseline", cookie).Body.String(); !strings.Contains(body, "No baseline yet") {
		t.Errorf("baseline section: %q", firstLines(body))
	}
}

func TestCommonCronSchedulesAreSaidInWords(t *testing.T) {
	for in, want := range map[string]string{
		"0 3 * * *":    "every day at 03:00",
		"*/15 * * * *": "every 15 minutes",
		"5 * * * *":    "every hour at :05",
		"30 9 * * 1":   "every Monday at 09:30",
		"0 3 1 * *":    "0 3 1 * *",
		"@daily":       "@daily",
	} {
		if got := cronWords(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}
