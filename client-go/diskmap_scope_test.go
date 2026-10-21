package main

// THE DEFAULT IS YOUR OWN FILES; a full drive map is a request.
//
// A map of the whole machine reaches into every account on it. On a shared box
// that is somebody else's private life drawn as rectangles, and it is a bigger
// act than a button labelled "Map" implies. So the default walk is the home
// directory of whoever this process runs as, the whole machine is asked for
// separately, and the page names what that will cover BEFORE it is pressed.
//
// The tests below are about which walk actually happens. Wording is asserted in
// exactly one place — the flash, where the words ARE the mechanism, because
// they are what tells the person which of the two they just started.

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dmScopeRecorder installs a state whose scan records the roots it was handed
// and never walks anything.
func dmScopeRecorder(t *testing.T) (*dmState, func() []string) {
	t.Helper()
	s := dmTestInstall(t, nil)
	done := make(chan []string, 8)
	s.roots = dmRootsFor // the REAL resolver: the scope must pick the roots
	s.scan = func(_ context.Context, roots []string, _ int, _ func(dmProgress)) *dmResult {
		done <- append([]string(nil), roots...)
		return &dmResult{TakenAt: uiNow()}
	}
	return s, func() []string {
		t.Helper()
		// The walk runs in a goroutine, so this has to WAIT for it. The first
		// version read the channel with a default branch and reported "no walk
		// was started" every time — a test that fails for its own reasons
		// teaches nothing about the code.
		select {
		case r := <-done:
			return r
		case <-time.After(2 * time.Second):
			t.Fatal("no walk was started at all")
			return nil
		}
	}
}

// Pressing the ordinary button walks the home directory and nothing else. This
// is the whole point: it fails if the default ever widens back to the volumes.
func TestTheDefaultMapIsYourFilesAndNotTheMachine(t *testing.T) {
	// AFTER the fixture, never before: uiTestConfigDir moves HOME to a temp
	// directory, so a home read first is not the home the walk will resolve.
	// Reading it in the wrong order is how this test first failed against
	// perfectly correct code.
	uiTestConfigDir(t)
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		t.Skip("this account has no home directory, so there is no default to check")
	}
	home = filepath.Clean(home)

	s, walked := dmScopeRecorder(t)
	if !s.dmStart(dmScopeHome) {
		t.Fatal("the scan did not start")
	}
	roots := walked()

	if len(roots) != 1 || roots[0] != home {
		t.Fatalf("the default walk covered %v, want exactly [%s]. A default that "+
			"reaches past the person's own files reads every account on this machine, "+
			"which is the thing this scope exists to stop.", roots, home)
	}
	// And the volumes really are wider, so the assertion above is not passing
	// because both scopes happen to be the same thing.
	machine, _ := dmMachineRoots()
	if len(machine) == 1 && machine[0] == home {
		t.Skip("on this box the machine scope IS the home directory, so the two " +
			"cannot be told apart here")
	}
	for _, m := range machine {
		if m == home {
			continue
		}
		for _, r := range roots {
			if r == m {
				t.Errorf("the default walk included %q, which belongs to the machine scope", m)
			}
		}
	}
}

// The whole machine is reachable — this is a scope, not a ban.
func TestTheWholeMachineIsStillReachableWhenAskedForByName(t *testing.T) {
	uiTestConfigDir(t)
	s, walked := dmScopeRecorder(t)
	if !s.dmStart(dmScopeMachine) {
		t.Fatal("the scan did not start")
	}
	want, _ := dmMachineRoots()
	got := walked()
	if len(got) != len(want) {
		t.Fatalf("the machine walk covered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the machine walk covered %v, want %v", got, want)
		}
	}
}

// A VALUE NOBODY RECOGNISES RESOLVES TO THE SMALLER WALK. The failure mode of a
// typo, a stale bookmark or a hand-written form must never be the one that
// reads other people's files.
func TestAnUnknownScopeIsTheSmallerWalk(t *testing.T) {
	for _, in := range []string{"", "  ", "everything", "MACHINE", "Machine", "all",
		"home", "machines", "machine,home", "*"} {
		if got := dmScopeOf(in); got != dmScopeHome {
			t.Errorf("dmScopeOf(%q) = %q, want %q — a value nobody recognises must fall "+
				"to the smaller walk", in, got, dmScopeHome)
		}
	}
	// Surrounding whitespace is normalised, the way every other form value in
	// this UI is. That can only ever turn the word into itself, never something
	// else into the word, so it widens nothing.
	for _, in := range []string{"machine", " machine", "machine ", "  machine  "} {
		if got := dmScopeOf(in); got != dmScopeMachine {
			t.Errorf("dmScopeOf(%q) = %q — the explicit request must still work", in, got)
		}
	}
}

// The same rule through the HTTP handler, which is where a real request arrives.
func TestTheScanRouteDefaultsToYourFilesAndTakesTheExplicitRequest(t *testing.T) {
	for _, c := range []struct {
		form url.Values
		want dmScope
		says string
	}{
		{url.Values{}, dmScopeHome, "Mapping your files"},
		{url.Values{"scope": {"home"}}, dmScopeHome, "Mapping your files"},
		{url.Values{"scope": {"nonsense"}}, dmScopeHome, "Mapping your files"},
		{url.Values{"scope": {"machine"}}, dmScopeMachine, "Mapping this whole machine"},
	} {
		t.Run(c.form.Encode(), func(t *testing.T) {
			uiTestConfigDir(t)
			s := dmTestInstall(t, nil)
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
				<-release
				return &dmResult{TakenAt: uiNow()}
			}
			u := uiTestServer(t)
			w := uiPost(t, u.handler(), "/diskmap/scan", c.form, uiSignedIn(t, u))

			s.mu.Lock()
			got := s.scope
			s.mu.Unlock()
			if got != c.want {
				t.Errorf("scope=%q started a %q walk, want %q", c.form.Get("scope"), got, c.want)
			}
			// The person has to be TOLD which one is running. These two walks
			// differ in what they read, and a progress view that says the same
			// thing for both is how somebody discovers afterwards that they
			// mapped a machine they meant to map a folder of.
			if !strings.Contains(w.Body.String(), c.says) {
				t.Errorf("the page does not say %q: %q", c.says, dmSnip(w.Body.String(), "MAPPING"))
			}
		})
	}
}

// A HELD MAP CARRIES ITS OWN SCOPE, stamped from what was asked for rather than
// from the walker. A map labelled "your files" that quietly held the whole
// machine would be the worst thing this page could say.
func TestAFinishedMapSaysWhichWalkMadeIt(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	// A walker that lies about its scope, because a stubbed or future walker is
	// exactly the case the stamping exists to survive.
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		return &dmResult{TakenAt: uiNow(), Scope: dmScopeHome}
	}
	if !s.dmStart(dmScopeMachine) {
		t.Fatal("the scan did not start")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		done := s.res != nil && !s.running
		s.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the scan never produced a map")
		}
		time.Sleep(2 * time.Millisecond)
	}
	s.mu.Lock()
	got := s.res.Scope
	s.mu.Unlock()
	if got != dmScopeMachine {
		t.Errorf("the finished map says it covers %q when the whole machine was asked "+
			"for. The scope is stamped by dmStart precisely so the walker cannot "+
			"mislabel it.", got)
	}
}

// The whole-machine offer NAMES what it would walk before it is pressed. A
// single click has to say what it covers, or it is blind.
func TestTheWholeMachineOfferSaysWhatItWouldCover(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	s.roots = dmRootsFor
	u := uiTestServer(t)
	body := dmRender(t, u, uiSignedIn(t, u), "")

	if !strings.Contains(body, `value="machine"`) {
		t.Fatal("there is no way to ask for the whole machine at all — the scope is a " +
			"request, not a ban")
	}
	machine, _ := dmMachineRoots()
	if len(machine) == 0 {
		t.Skip("this box reports no volume roots, so there is nothing to name")
	}
	for _, m := range machine {
		// THE LIST ITEM, not the bare path. On a unix box the only volume root
		// is "/", which is a substring of nearly every line of HTML on the
		// page — so `strings.Contains(body, m)` passed with the whole listing
		// deleted. Measured: the mutation applied, every render of
		// .MachineRoots was gone, and the test still went green.
		if !strings.Contains(body, "<li>"+m+"</li>") {
			t.Errorf("the whole-machine offer does not name %q in its list. It walks "+
				"other people's folders, so what it covers is said before it is pressed "+
				"and not after.", m)
		}
	}
}
