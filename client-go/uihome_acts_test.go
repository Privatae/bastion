package main

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// actsWorld: one agent with a child, the owner's code set up, nothing real
// signalled.
func actsWorld(t *testing.T) (dir string, killed *[]int) {
	t.Helper()
	uiTestConfigDir(t)
	killed = stubStopWorld(t, []agentObs{{PID: 101, Kind: kindAgent, Signature: "claude-code", User: "u"}},
		map[int]int{102: 101})
	prev := homeForUserFn
	t.Cleanup(func() { homeForUserFn = prev })
	homeForUserFn = func(string) string { return "" }
	d, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, d, machineTestSecret)
	return d, killed
}

func TestStopFromTheConsoleTakesTheCodeAndTheAgentItShowed(t *testing.T) {
	_, killed := actsWorld(t)
	now := time.Now()
	if f, _ := stopFromConsole(101, "claude-code", "", now); !strings.Contains(f, "type the code") {
		t.Errorf("no code: %q", f)
	}
	if f, _ := stopFromConsole(101, "aider", codeFor(t, machineTestSecret), now); !strings.Contains(f, "is now claude-code") {
		t.Errorf("a pid that changed hands: %q", f)
	}
	if f, _ := stopFromConsole(101, "claude-code", codeFor(t, hostTestSecret), now); !strings.Contains(f, "code refused") {
		t.Errorf("a wrong code: %q", f)
	}
	if len(*killed) != 0 {
		t.Fatalf("a refused stop signalled %v", *killed)
	}
	f, class := stopFromConsole(101, "claude-code", codeFor(t, machineTestSecret), now)
	if class != "ok" || !strings.HasPrefix(f, "You stopped claude-code (pid 101)") || len(*killed) != 2 {
		t.Errorf("stop: %q %s, killed %v", f, class, *killed)
	}
}

func TestStopFromTheConsoleNeedsTheCodeSetUp(t *testing.T) {
	uiTestConfigDir(t)
	killed := stubStopWorld(t, []agentObs{{PID: 101, Kind: kindAgent, Signature: "claude-code"}}, nil)
	if f, _ := stopFromConsole(101, "claude-code", "123456", time.Now()); !strings.Contains(f, "set up your code") {
		t.Errorf("no code set up: %q", f)
	}
	if len(*killed) != 0 {
		t.Fatal("stopped with no code set up")
	}
}

// A mark takes the owner's code; with none set up, nothing is marked.
func TestAMarkTakesTheCodeOnceItIsSetUp(t *testing.T) {
	uiTestConfigDir(t)
	if why := markCodeRefusal("fp1", "123456"); !strings.Contains(why, "set up your code") {
		t.Errorf("with no code set up a mark was made: %q", why)
	}
	d, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, d, machineTestSecret)
	if why := markCodeRefusal("fp1", ""); !strings.Contains(why, "type the code") {
		t.Errorf("no code: %q", why)
	}
	if why := markCodeRefusal("fp1", codeFor(t, hostTestSecret)); !strings.Contains(why, "code refused") {
		t.Errorf("a wrong code: %q", why)
	}
	if why := markCodeRefusal("fp1", codeFor(t, machineTestSecret)); why != "" {
		t.Errorf("the owner's code: %q", why)
	}
}

// A stop an agent asked for waits on Waiting for you in plain words, and the
// owner's code there carries it out.
func TestWaitingForYouAnswersWhatIsAskedOfTheMachine(t *testing.T) {
	d, killed := actsWorld(t)
	purpose, _ := purposeForLocalStop(101, "claude-code")
	id, err := stepupNewRequest(d, purpose, map[string]any{"kind": localStopKind, "pid": "101",
		"signature": "claude-code", "agent": "Claude Code", "session": "shop-a1",
		"asked_by": "Claude Code session notes-b2 (pid 300)"})
	if err != nil {
		t.Fatal(err)
	}
	u := uiTestServer(t)
	h, cookie := u.handler(), uiSignedIn(t, u)
	page := uiGet(t, h, "/approvals", cookie).Body.String()
	for _, want := range []string{"Asked of this machine", "Stop Claude Code session shop-a1 (pid 101)",
		"Asked from Claude Code session notes-b2 (pid 300)."} {
		if !strings.Contains(page, want) {
			t.Errorf("Waiting for you does not say %q", want)
		}
	}
	w := uiPost(t, h, "/approvals/machine/approve", url.Values{"id": {id}, "code": {codeFor(t, machineTestSecret)}}, cookie)
	if body := w.Body.String(); !strings.Contains(body, "You stopped claude-code (pid 101)") {
		t.Errorf("approve answered %q", firstLines(body))
	}
	if len(*killed) != 2 {
		t.Errorf("killed %v", *killed)
	}
}

func TestDenyingWhatIsAskedOfTheMachineTakesNoCodeAndDoesNothing(t *testing.T) {
	d, killed := actsWorld(t)
	purpose, _ := purposeForLocalStop(101, "claude-code")
	id, err := stepupNewRequest(d, purpose, map[string]any{"kind": localStopKind, "pid": "101", "signature": "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	u := uiTestServer(t)
	w := uiPost(t, u.handler(), "/approvals/machine/deny", url.Values{"id": {id}}, uiSignedIn(t, u))
	if !strings.Contains(w.Body.String(), "Denied. Nothing was done.") || len(*killed) != 0 {
		t.Errorf("deny: %q, killed %v", firstLines(w.Body.String()), *killed)
	}
	if r := requestsLoad(d)[id]; r.State == "pending" {
		t.Error("the request is still waiting")
	}
}

// The owner's code is set up from the Settings page with no Host at all:
// start, read the key, confirm with a code from it.
func TestTheOwnersCodeIsSetUpFromSettingsWithNoHost(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	h, cookie := u.handler(), uiSignedIn(t, u)
	start := uiPost(t, h, "/setup/stepup/start", url.Values{"target": {"machine"}}, cookie).Body.String()
	m := regexp.MustCompile(`name="enrol" value="([^"]+)"`).FindStringSubmatch(start)
	if m == nil || !strings.Contains(start, "Privatae bastion") {
		t.Fatalf("no enrolment started:\n%s", firstLines(start))
	}
	key := uiPost(t, h, "/setup/stepup/key", url.Values{"enrol": {m[1]}}, cookie).Body.String()
	k := regexp.MustCompile(`[A-Z2-7]{32}`).FindString(key)
	if k == "" {
		t.Fatalf("no key shown:\n%s", firstLines(key))
	}
	done := uiPost(t, h, "/setup/stepup/confirm", url.Values{"enrol": {m[1]}, "code": {codeFor(t, k)}}, cookie).Body.String()
	if !strings.Contains(done, "Your code is set up") {
		t.Errorf("confirm answered:\n%s", firstLines(done))
	}
	if !stepupEnrolled(existingMachineFactorDir()) {
		t.Error("the owner's code was not written")
	}
}
