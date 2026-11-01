package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// activityWorld writes the records the bastion keeps, one of each kind, at
// known times. Everything in them is invented.
func activityWorld(t *testing.T) {
	t.Helper()
	uiTestConfigDir(t)
	now := time.Now().UTC()
	p, err := localEventPath()
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := json.Marshal([]localEvent{
		{Kind: eventContain, At: now.Add(-3 * time.Hour), Text: "You stopped aider (pid 27) running on this machine."},
		{Kind: eventContain, At: now.Add(-10 * 24 * time.Hour), Text: "You stopped goose (pid 9) running on this machine."},
	})
	if err := os.WriteFile(p, ev, 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	dcnAudit(dir, "stepup_approve", 0, "", "approved: local_stop|27|aider")
	dcnAudit(dir, localStopKind, 0, "31 claude-code", "not stopped: pid 31 is now aider, not the claude-code that was approved")
	givenPairing(t, "h1.host.privatae.ai", pairingActive)
	if err := localDenySet("h1.host.privatae.ai", "dcn", true); err != nil {
		t.Fatal(err)
	}
}

func TestActivityGathersEveryRecordNewestFirstAndWithinTheWindow(t *testing.T) {
	activityWorld(t)
	items := collectActivity(time.Now().Add(-7 * 24 * time.Hour))
	var lines []string
	for _, it := range items {
		lines = append(lines, it.Who+" "+it.What)
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"You stopped aider (pid 27) running on this machine.",
		"You approved stopping aider (pid 27)",
		"You approved stopping claude-code (pid 31), but it was not stopped: pid 31 is now aider",
		"You switched dcn off for h1.host.privatae.ai",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("activity does not say %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "goose") {
		t.Error("a stop older than the window was listed")
	}
	for i := 1; i < len(items); i++ {
		if items[i].At.After(items[i-1].At) {
			t.Fatalf("not newest first: %v after %v", items[i].At, items[i-1].At)
		}
	}
}

func TestTheActivityPageFiltersByKind(t *testing.T) {
	activityWorld(t)
	u := uiTestServer(t)
	h, cookie := u.handler(), uiSignedIn(t, u)
	all := uiGet(t, h, "/activity", cookie).Body.String()
	if !strings.Contains(all, "You stopped aider") || !strings.Contains(all, "switched dcn off") {
		t.Errorf("the page:\n%s", firstLines(all))
	}
	stops := uiGet(t, h, "/activity?kind=stop", cookie).Body.String()
	if !strings.Contains(stops, "You stopped aider") || strings.Contains(stops, "switched dcn off") {
		t.Errorf("the stops filter let other kinds through")
	}
}

func TestSinceTakesDaysAndDurations(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "12h": 12 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := parseSince(in); err != nil || got != want {
			t.Errorf("%s = %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"0d", "-1h", "soon", "99999d"} {
		if _, err := parseSince(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
