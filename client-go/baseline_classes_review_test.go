//go:build linux

package main

// Each defect found in the listener and identity classes, pinned. Each test name is the false
// sentence the machine used to be able to produce.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// `ss` installed and exiting non-zero produced Supported=true with an empty
// table, and 54 of 54 listeners reported gone on a machine where every one was
// up — with no note.
func TestAFailedSocketReadIsBlindNotEmpty(t *testing.T) {
	// THE REAL listenerScan, through the real report shape. The first version
	// of this test reimplemented the branch inline and a mutation proved it
	// tested a copy: breaking listenerScan left the suite green.
	withSockets(t, socketsReport{Supported: true, Failed: "tcp: exit status 1"})
	if _, ok, why := listenerScan(); ok {
		t.Error("a failed ss reads as a readable table")
	} else if !strings.Contains(why, "could not be read") {
		t.Errorf("the reason %q does not say the box could not look", why)
	}
	// A half table is refused too, and for a reason listenerScan states: a
	// partial read must not become the definition of normal.
	withSockets(t, socketsReport{Supported: true, Partial: "udp: timeout",
		Sockets: []listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)}})
	if _, ok, _ := listenerScan(); ok {
		t.Error("half a socket table reads as a whole one")
	}
	// And a good read still works, or the two above pass on a broken reader.
	withSockets(t, socketsReport{Supported: true,
		Sockets: []listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)}})
	if got, ok, _ := listenerScan(); !ok || len(got) != 1 {
		t.Errorf("a clean socket table read as unusable: ok=%v n=%d", ok, len(got))
	}

	// THE SHORT-LIVED RULE'S EXEMPTION USES THE SAME TABLE, and an exemption
	// that cannot be checked is not an exemption.
	withSockets(t, socketsReport{Supported: true, Failed: "tcp: exit status 1"})
	if _, ok := deltaListeningPIDs(); ok {
		t.Error("deltaListeningPIDs accepted a failed socket table")
	}

	// And the guard then refuses to compare the class, in BOTH directions.
	known, _ := baselineFromListeners([]listenSocket{
		sock("tcp", "0.0.0.0", 22, "sshd", 1),
		sock("tcp", "0.0.0.0", 443, "nginx", 2),
	})
	base := &baselineFile{Coverage: baselineCoverage(true, true, true, true), Entries: known}
	keptBase, keptLive, notes, _ := deltaComparableClasses(base, nil, deltaSight{Identities: true}, nil)
	for _, e := range deltaCompare(keptBase, keptLive) {
		if e.Kind == deltaListenerGone {
			t.Fatal("a blind socket read still reports every listener gone")
		}
	}
	if !strings.Contains(strings.Join(notes, " "), "could not be read on this pass") {
		t.Errorf("notes do not say the class was unreadable: %v", notes)
	}
}

// The guard read the machine a SECOND time, so a reader that flipped
// between the two reads either invented findings or discarded real ones. The
// live entries and the comparability decision now come from one read.
func TestTheGuardUsesTheReadThatBuiltTheLiveEntries(t *testing.T) {
	base := &baselineFile{
		Coverage: baselineCoverage(true, true, true, true),
		Entries:  []baselineEntry{},
	}
	// The pass SAW listeners and found a backdoor. Under the old shape a
	// second read that failed would have thrown this away.
	found, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 4444, "nc", 9)})
	keptBase, keptLive, _, _ := deltaComparableClasses(base, liveList(found),
		deltaSight{Listeners: true, Identities: true}, nil)
	evs := deltaCompare(keptBase, keptLive)
	if len(evs) != 1 || evs[0].Kind != deltaListenerNew {
		t.Fatalf("an observed backdoor was discarded: %v", kindsOf(evs))
	}
	// And a pass that did NOT see the class does not compare it, whatever a
	// later read would have said.
	_, keptLive2, _, _ := deltaComparableClasses(base, liveList(found), deltaSight{Identities: true}, nil)
	for _, l := range keptLive2 {
		if l.Entry.Kind == "listener" {
			t.Fatal("a class the pass did not see was still compared")
		}
	}
}

// An unreadable key file fingerprinted identically to an account with no
// keys, so the person read "authorized keys 1 → 0" — keys were removed — about
// a box that never looked.
func TestUnreadableKeysAreNotReportedAsKeysRemoved(t *testing.T) {
	was := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash", AuthKeys: 1, KeyDigest: "d1"})}
	blind := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash", KeysUnread: "permission denied"})}

	if was[0].FP == blind[0].FP {
		t.Fatal("an unreadable key file fingerprints the same as no keys")
	}
	evs := deltaCompare(was, liveList(blind))
	if len(evs) != 1 || evs[0].Kind != deltaIdentityChanged {
		t.Fatalf("want one identity_changed, got %v", kindsOf(evs))
	}
	if evs[0].Reason != deltaReasonUnreadable {
		t.Errorf("reason = %q, want %q — a visibility change, not a machine change",
			evs[0].Reason, deltaReasonUnreadable)
	}
	if got := deltaLevel(evs[0]); got != deltaNotice {
		t.Errorf("a blind read levelled %q, want notice", got)
	}
	if w := identityChangeWords(was[0], blind[0]); !strings.Contains(w, "could not read") {
		t.Errorf("the sentence %q asserts something about the account anyway", w)
	}
	// AND THE SAME FOR SUDO. Unreadable sudo rules recorded sudo=false for
	// every account, so the next readable pass fired sudoers_changed at
	// CRITICAL for each one.
	sudoBlind := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash", AuthKeys: 1, KeyDigest: "d1", SudoUnknown: true})}
	evs = deltaCompare(was, liveList(sudoBlind))
	if len(evs) != 1 || deltaLevel(evs[0]) != deltaNotice {
		t.Fatalf("unreadable sudo rules produced %v at %v, want one notice",
			kindsOf(evs), deltaLevel(evs[0]))
	}
}

// `erin,dave ALL=(ALL:ALL) ALL` is ordinary sudoers. It recorded a
// principal literally named "erin,dave" and left both accounts sudo=false — a
// missed privilege grant, and a false critical when a name was added.
func TestACommaSeparatedUserListNamesEveryAccountInIt(t *testing.T) {
	out, groups := map[string]bool{}, map[string]bool{}
	sudoParse([]string{
		"erin,dave ALL=(ALL:ALL) ALL",
		"%wheel,%admin ALL=(ALL) NOPASSWD: ALL",
		"root ALL=(ALL:ALL) ALL",
		"Defaults env_reset",
		"# a comment",
	}, out, groups)

	for _, want := range []string{"erin", "dave", "root"} {
		if !out[want] {
			t.Errorf("%q is not recognised as holding sudo — a missed privilege grant", want)
		}
	}
	if out["erin,dave"] {
		t.Error("a literal \"erin,dave\" principal was recorded")
	}
	for _, want := range []string{"wheel", "admin"} {
		if !groups[want] {
			t.Errorf("group %q in a comma list was not expanded", want)
		}
	}
	if out["Defaults"] || out["#"] {
		t.Error("a Defaults or comment line produced a principal")
	}
}

// A second uid-0 account is not an account, it is a root login under
// another name — and it graded below "a key was added".
func TestASecondRootAccountIsCritical(t *testing.T) {
	newRoot := baselineEntryOfIdentity(identityObs{Name: "toor", UID: 0, Shell: "/bin/bash"})
	ev := deltaEvent{Kind: deltaIdentityNew, Entry: newRoot}
	if got := deltaLevel(ev); got != deltaCritical {
		t.Errorf("a new uid-0 account levelled %q, want critical", got)
	}
	was := baselineEntryOfIdentity(identityObs{Name: "erin", UID: 1000, Shell: "/bin/bash"})
	now := baselineEntryOfIdentity(identityObs{Name: "erin", UID: 0, Shell: "/bin/bash"})
	ch := deltaEvent{Kind: deltaIdentityChanged, Reason: identityChangeReason(was, now), Entry: now}
	if got := deltaLevel(ch); got != deltaCritical {
		t.Errorf("an account moved to uid 0 levelled %q, want critical", got)
	}
}

// `apt install postgresql` creates a service account with a login shell.
// At high, every package install pages someone, and a plane that pages for
// ordinary work gets ignored.
func TestAServiceAccountFromAPackageInstallDoesNotPage(t *testing.T) {
	svc := baselineEntryOfIdentity(identityObs{Name: "postgres", UID: 114, Shell: "/bin/bash"})
	if got := deltaLevel(deltaEvent{Kind: deltaIdentityNew, Entry: svc}); got != deltaWarn {
		t.Errorf("a new service account levelled %q, want warn", got)
	}
	// But a service-uid account arriving WITH sudo or keys is still the
	// persistence move, and stays critical.
	armed := baselineEntryOfIdentity(identityObs{Name: "postgres", UID: 114, Shell: "/bin/bash", Sudo: true})
	if got := deltaLevel(deltaEvent{Kind: deltaIdentityNew, Entry: armed}); got != deltaCritical {
		t.Errorf("a service-uid account with sudo levelled %q, want critical", got)
	}
	// And a real person's account is unaffected.
	person := baselineEntryOfIdentity(identityObs{Name: "intern", UID: 1001, Shell: "/bin/bash"})
	if got := deltaLevel(deltaEvent{Kind: deltaIdentityNew, Entry: person}); got != deltaHigh {
		t.Errorf("a new login account levelled %q, want high", got)
	}
}

// 15 of 54 listeners on a real box are pinned to a specific address,
// including a DHCP lease. Every address change was a fresh high that repeated
// on every pass, because nothing retakes the accounting.
func TestAReAddressedListenerIsNotGradedAsANewOne(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "192.168.1.5", 8080, "app", 5)})
	now, _ := baselineFromListeners([]listenSocket{sock("tcp", "192.168.9.9", 8080, "app", 5)})

	evs := deltaCompare(was, liveList(now))
	var newEv *deltaEvent
	for i := range evs {
		if evs[i].Kind == deltaListenerNew {
			newEv = &evs[i]
		}
	}
	if newEv == nil {
		t.Fatal("a re-addressed listener produced no listener_new at all")
	}
	if newEv.Reason != deltaReasonAddressMoved {
		t.Errorf("reason = %q, want %q", newEv.Reason, deltaReasonAddressMoved)
	}
	if got := deltaLevel(*newEv); got != deltaWarn {
		t.Errorf("a DHCP re-address levelled %q, want warn", got)
	}

	// THE EXCLUSION THAT KEEPS THE CLASS WORTH HAVING: loopback to routable is
	// the exposure change this exists to catch and must stay high.
	wasLocal, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", 8080, "app", 5)})
	nowOpen, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 8080, "app", 5)})
	for _, e := range deltaCompare(wasLocal, liveList(nowOpen)) {
		if e.Kind != deltaListenerNew {
			continue
		}
		if e.Reason == deltaReasonAddressMoved {
			t.Error("loopback → routable was written off as a re-addressing")
		}
		if got := deltaLevel(e); got != deltaHigh {
			t.Errorf("a service opening itself to the network levelled %q, want high", got)
		}
	}
}

// A `systemctl restart` landing inside a pass reported the port gone
// immediately while the process behind it got ten minutes.
func TestEveryClassGetsTheGraceNotJustProcessesAndSchedulers(t *testing.T) {
	for _, kind := range []string{deltaProcGone, deltaSchedGone, deltaListenerGone, deltaIdentityGone} {
		if !deltaIsGone(kind) {
			t.Errorf("%s is not treated as an absence, so it bypasses the grace", kind)
		}
		st := freshState(t)
		ev := deltaEvent{Kind: kind, FP: "fp-" + kind}
		if out := deltaApplyGrace([]deltaEvent{ev}, st, time.Now()); len(out) != 0 {
			t.Errorf("%s was reported on the FIRST scan that missed it", kind)
		}
	}
}

// A box with AuthorizedKeysFile pointing elsewhere recorded "no keys" for
// everyone, silently — the class went narrow with no note.
func TestANonDefaultAuthorizedKeysLocationIsReadAndSaidOutLoud(t *testing.T) {
	home := t.TempDir()
	central := filepath.Join(home, "central")
	if err := os.MkdirAll(central, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(central, "erin"), []byte("ssh-ed25519 AAAAK x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, unread := authorizedKeysOf(home, "erin", "1000", []string{filepath.Join(central, "%u")})
	if unread != "" {
		t.Fatalf("a readable central key file reported unreadable: %s", unread)
	}
	if identityCountKeys(keys) != 1 {
		t.Errorf("central keys not read: %d", identityCountKeys(keys))
	}
	// The %u token and an absolute path both have to work, and a relative one
	// still resolves under the home.
	if got := authorizedKeysPath(".ssh/authorized_keys", "/home/erin", "erin", "1000"); got != "/home/erin/.ssh/authorized_keys" {
		t.Errorf("relative path resolved to %q", got)
	}
	if got := authorizedKeysPath("/etc/ssh/keys/%u", "/home/erin", "erin", "1000"); got != "/etc/ssh/keys/erin" {
		t.Errorf("%%u expanded to %q", got)
	}
}

// A home directory that is not there is a box that did not look — an unmounted
// /home, a network home not yet available — and reading it as "no keys" made
// every account report authkeys_changed the moment the mount appeared.
func TestAnAbsentHomeDirectoryIsBlindNotKeyless(t *testing.T) {
	_, unread := authorizedKeysOf("/definitely/not/here", "ghost", "1002",
		[]string{".ssh/authorized_keys", ".ssh/authorized_keys2"})
	if unread == "" {
		t.Fatal("an absent home directory read as an account with no keys")
	}
	// A home that IS there with no .ssh is genuinely none, and says nothing.
	if _, u := authorizedKeysOf(t.TempDir(), "erin", "1000",
		[]string{".ssh/authorized_keys", ".ssh/authorized_keys2"}); u != "" {
		t.Errorf("an account with no keys reported %q", u)
	}
}

// withSockets points BOTH socket readers at one report — listenerScan for the
// accounting and deltaListeningPIDs for the noise filter's exemption.
func withSockets(t *testing.T, r socketsReport) {
	t.Helper()
	oL, oD := listenerSockets, deltaSockets
	listenerSockets = func() socketsReport { return r }
	deltaSockets = func() socketsReport { return r }
	t.Cleanup(func() { listenerSockets, deltaSockets = oL, oD })
}

func withSshdConfig(t *testing.T, body string) {
	t.Helper()
	old := sshdConfigPath
	p := filepath.Join(t.TempDir(), "sshd_config")
	if body != "" {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sshdConfigPath = p
	t.Cleanup(func() { sshdConfigPath = old })
}

// The AuthorizedKeysFile override, through the parse. A path-expansion test
// alone exercised the EXPANSION but never the
// sshd_config parse, so a mutation that ignored the override entirely left the
// suite green — the class would silently narrow to the default pair.
func TestTheAuthorizedKeysLocationComesFromSshdConfig(t *testing.T) {
	withSshdConfig(t, "Port 22\n# a comment\nAuthorizedKeysFile /etc/ssh/keys/%u\n")
	paths, note := authorizedKeysPaths()
	if len(paths) != 1 || paths[0] != "/etc/ssh/keys/%u" {
		t.Fatalf("the override was ignored: %v", paths)
	}
	if note == "" {
		t.Error("a narrowed key lookup was not said out loud at all")
	}
	// AND THE NOTE CARRIES NO PATH. It reaches deltaSummary.Note, which rides
	// the heartbeat, so the first version of it put a line of the user's own
	// sshd configuration on the wire every pass.
	if strings.Contains(note, "/etc/ssh/keys/") || strings.Contains(note, "%u") {
		t.Errorf("the note carries the user's sshd configuration off their machine: %q", note)
	}

	// `none` means no account has keys to account for, which is a different
	// fact from "this box found none".
	withSshdConfig(t, "AuthorizedKeysFile none\n")
	if paths, note := authorizedKeysPaths(); len(paths) != 0 || !strings.Contains(note, "none") {
		t.Errorf("AuthorizedKeysFile none gave paths=%v note=%q", paths, note)
	}

	// No sshd on the box: the default pair is the right guess and needs no note.
	withSshdConfig(t, "")
	if paths, note := authorizedKeysPaths(); len(paths) != 2 || note != "" {
		t.Errorf("a box with no sshd_config gave paths=%v note=%q", paths, note)
	}

	// Silent by default: a stock config must not produce a note, or the note
	// stops meaning anything.
	withSshdConfig(t, "Port 22\nPermitRootLogin no\n")
	if paths, note := authorizedKeysPaths(); len(paths) != 2 || note != "" {
		t.Errorf("a stock sshd_config gave paths=%v note=%q", paths, note)
	}
}

// A NARROWED READ MUST SAY SO. identityScanReport.Partial was set by the reader and read NOWHERE,
// so a class that went narrow — sudo rules unopenable, keys read from somewhere
// this does not look — reported a confident answer over the gap. The entries it
// produced are real and still compared; what was missing was the sentence
// saying the answer covers less than it looks.
func TestAPartiallyReadIdentityClassSaysSoOnThePass(t *testing.T) {
	oI := deltaIdentityReader
	deltaIdentityReader = func() identityScanReport {
		return identityScanReport{Supported: true,
			Partial:  "sudo rules not readable: /etc/sudoers",
			Accounts: []identityObs{{Name: "erin", UID: 1000, Shell: "/bin/bash", SudoUnknown: true}}}
	}
	oL := deltaListenerReader
	deltaListenerReader = func() ([]listenSocket, bool, string) { return nil, false, "no ss" }
	t.Cleanup(func() { deltaIdentityReader, deltaListenerReader = oI, oL })

	_, _, _, sight, _ := deltaCollectLive(func(string) (string, string) { return "", "" })
	if !sight.Identities {
		t.Fatal("a partially-read class reported as blind — its real entries would be dropped")
	}
	if len(sight.Notes) != 1 || !strings.Contains(sight.Notes[0], "sudo rules not readable") {
		t.Fatalf("the reader's partial note did not reach the pass: %v", sight.Notes)
	}
}
