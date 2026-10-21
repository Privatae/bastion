package main

// The local event record (events.go): a containment has to outlive the console
// it used to be printed into, and it has to stay out of a developer's live
// config dir while it does.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// freshLocalEvents isolates the package-level record for one test and puts it
// back afterwards. This is one process and one box's worth of state — the same
// reason TestARefusedDirectiveIsReportedToTheHost (anchor_test.go) establishes
// its own baseline rather than trusting the one it inherits — so a test that
// left the list, the path or the clock behind would be deciding a sibling's
// result instead of its own.
func freshLocalEvents(t *testing.T) {
	t.Helper()
	localEventMu.Lock()
	oldList, oldFile, oldNow := localEventList, localEventFile, localEventNow
	localEventList, localEventFile = nil, ""
	localEventMu.Unlock()
	t.Cleanup(func() {
		localEventMu.Lock()
		localEventList, localEventFile, localEventNow = oldList, oldFile, oldNow
		localEventMu.Unlock()
	})
}

// stubContain replaces the three seams contain.go injects, so nothing real is
// ever signalled (the same stubs TestMaybeContainKillsTreeAndRefusesApps uses).
func stubContain(t *testing.T) {
	t.Helper()
	prevObs, prevTree, prevKill := observedAgents, processTree, killProcess
	t.Cleanup(func() { observedAgents, processTree, killProcess = prevObs, prevTree, prevKill })
	observedAgents = func() ([]agentObs, error) {
		return []agentObs{
			{PID: 101, Kind: kindAgent, Signature: "claude-code"},
			{PID: 4532, Kind: kindApp, Signature: "claude-desktop"},
		}, nil
	}
	processTree = func() map[int]int { return map[int]int{102: 101, 103: 102} }
	killProcess = func(pid int) error { return nil }
}

// The whole point of the file: the box kills the user's programs on a host's
// word, and until now the ONLY trace was a line on stdout (contain.go:106) that
// a Windows self-update relaunch has nowhere to put (relaunch_windows.go:47).
func TestAContainmentIsRecordedAndSurvivesARestart(t *testing.T) {
	uiTestConfigDir(t)
	freshLocalEvents(t)
	stubContain(t)
	openLocalEventLog()

	at := time.Date(2026, 9, 13, 14, 2, 0, 0, time.UTC)
	localEventNow = func() time.Time { return at }

	maybeContain("member.host.privatae.ai", "", []byte(`{"contain":[101, 4532]}`))

	got := localEventsNewestFirst()
	if len(got) != 2 {
		t.Fatalf("want a record per pid the directive named, got %d: %+v", len(got), got)
	}
	// Newest first: the app refusal was processed second.
	if !strings.Contains(got[0].Text, "claude-desktop") || !strings.Contains(got[0].Text, "refused") {
		t.Errorf("the newest event must be the app refusal: %q", got[0].Text)
	}
	kill := got[1].Text
	for _, want := range []string{
		"member.host.privatae.ai", // WHICH host did it
		"claude-code",             // WHAT it stopped
		"pid 101",                 // and which process
		"2 other processes",       // the tree, which is the part a pid alone hides
	} {
		if !strings.Contains(kill, want) {
			t.Errorf("the containment record must name %q: %q", want, kill)
		}
	}
	if got[1].Kind != eventContain || !got[1].At.Equal(at) {
		t.Errorf("kind/time must be recorded from the seam: %+v", got[1])
	}

	// ON DISK, and readable. This is the half that makes it a record: the
	// process exits on purpose on every self-update (update.go:127).
	p, err := localEventPath()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("the record was never written: %v", err)
	}
	var onDisk []localEvent
	if err := json.Unmarshal(b, &onDisk); err != nil || len(onDisk) != 2 {
		t.Fatalf("the file must hold both events: %v %s", err, b)
	}

	// The restart: everything this process remembers is gone, and the box comes
	// back up and opens the log again.
	localEventMu.Lock()
	localEventList, localEventFile = nil, ""
	localEventMu.Unlock()
	openLocalEventLog()
	after := localEventsNewestFirst()
	if len(after) != 2 || !strings.Contains(after[1].Text, "claude-code") {
		t.Fatalf("a restart must not erase what the host did here: %+v", after)
	}
}

// The anti-pollution property, and the reason the daemon claims the path
// instead of the recorder resolving it. agents_kind_test.go:342 drives
// maybeContain with no config isolation at all; if recordLocalEvent called
// configDir() itself, running `go test` on a machine with a live bastion would
// forge "your host stopped an agent" into that user's own UI —
// freeagent_managed_test.go:61-68 is the same accident, measured.
func TestNothingIsWrittenUntilTheDaemonOpensTheLog(t *testing.T) {
	uiTestConfigDir(t)
	freshLocalEvents(t)

	recordLocalEvent(eventContain, "recorded before anything claimed a path")
	p, err := localEventPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("an unclaimed record must touch no disk (stat %s: %v)", p, err)
	}
	if len(localEventsNewestFirst()) != 1 {
		t.Fatal("...but it must still be in memory, or the page shows nothing")
	}

	// And when the daemon does open the log — the window between a pairing's
	// first beat and the UI starting (run.go:120-131) — the pending event is
	// merged in rather than dropped.
	openLocalEventLog()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("opening the log must flush what was already recorded: %v", err)
	}
	if !strings.Contains(string(b), "before anything claimed a path") {
		t.Fatalf("the pending event was lost on open: %s", b)
	}
	// Opening twice must not duplicate it.
	openLocalEventLog()
	if n := len(localEventsNewestFirst()); n != 1 {
		t.Fatalf("a second open duplicated the record (%d entries)", n)
	}
}

func TestTheRecordIsCappedNewestFirst(t *testing.T) {
	uiTestConfigDir(t)
	freshLocalEvents(t)
	openLocalEventLog()

	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < localEventCap+5; i++ {
		n := i
		localEventNow = func() time.Time { return base.Add(time.Duration(n) * time.Hour) }
		recordLocalEvent(eventContain, "event "+string(rune('a'+n)))
	}
	got := localEventsNewestFirst()
	if len(got) != localEventCap {
		t.Fatalf("the record must stay bounded: %d entries", len(got))
	}
	if got[0].Text != "event "+string(rune('a'+localEventCap+4)) {
		t.Errorf("newest first: got %q", got[0].Text)
	}
	// Recorded order and time order agree here, which is the normal case and
	// the one the page relies on; events.go says why recording order is the one
	// that wins when a clock disagrees.
	if !got[0].At.After(got[len(got)-1].At) {
		t.Errorf("newest recorded is not the latest in time: %v then %v", got[0].At, got[len(got)-1].At)
	}
	// The DROPPED ones are the oldest, not a random five.
	for _, ev := range got {
		if ev.Text == "event a" {
			t.Error("the cap must drop the oldest, and 'event a' was the first")
		}
	}
}

// A record that cannot be parsed must cost history, never the machine. A
// bastion that refused to run because its advisory event log is malformed would
// turn a cosmetic problem into an outage.
func TestACorruptRecordIsNotAnOutage(t *testing.T) {
	uiTestConfigDir(t)
	freshLocalEvents(t)
	p, err := localEventPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	openLocalEventLog()
	if n := len(localEventsNewestFirst()); n != 0 {
		t.Fatalf("a corrupt file must read as no history, got %d", n)
	}
	recordLocalEvent(eventContain, "after the corruption")
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "after the corruption") {
		t.Fatalf("the log must keep working once it is rewritten: %v %s", err, b)
	}
}

// The counted wording, because "1 child process(es)" is how a machine talks and
// this line is read by the person whose programs were just killed.
func TestTheContainmentSentenceCounts(t *testing.T) {
	cases := []struct {
		children int
		want     string
	}{
		{0, "claude-code (pid 101) running on this machine."},
		{1, "and 1 other process it had started."},
		{4, "and 4 other processes it had started."},
	}
	for _, c := range cases {
		got := containSentence("member.host.privatae.ai", "claude-code", 101, c.children)
		if !strings.HasSuffix(got, c.want) {
			t.Errorf("%d children: %q does not end %q", c.children, got, c.want)
		}
		if !strings.HasPrefix(got, "Your host member.host.privatae.ai ") {
			t.Errorf("the host that directed it must lead: %q", got)
		}
	}
	// No pairing identity (an unanchored local box, anchor.go:506 lets it
	// through) must not render a hole where the name goes.
	if got := containSentence("", "claude-code", 101, 0); !strings.HasPrefix(got, "Your host stopped ") {
		t.Errorf("an empty pairing must still read as a sentence: %q", got)
	}
}
