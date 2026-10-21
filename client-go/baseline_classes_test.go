package main

// Tests for the listener and identity classes. Each one pins a sentence the
// plane is supposed to be able to say, or a false finding it must not produce.

import (
	"strings"
	"testing"
)

func sock(proto, local string, port int, proc string, pid int) listenSocket {
	return listenSocket{Proto: proto, Local: local, Port: port, Process: proc, PID: pid}
}

func kindsOf(evs []deltaEvent) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

// liveList is the plural of delta_test.go's liveOf, which takes one entry.
func liveList(entries []baselineEntry) []deltaLiveEntry {
	out := make([]deltaLiveEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, deltaLiveEntry{Entry: e})
	}
	return out
}

// ── listeners ───────────────────────────────────────────────────────────────

// THE SENTENCE THE SLOT EXISTS FOR. A different program answering on a port
// that was already open is ONE event that says so — not a gone and a new that a
// person has to correlate by eye.
func TestADifferentProgramOnAKnownPortIsOneChangedNotAGoneAndANew(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 443, "nginx", 10)})
	now, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 443, "evil", 99)})

	evs := deltaCompare(was, liveList(now))
	if len(evs) != 1 || evs[0].Kind != deltaListenerChanged {
		t.Fatalf("want one listener_changed, got %v", kindsOf(evs))
	}
	if evs[0].Was == nil || evs[0].Was.ArgvShape != "nginx" {
		t.Error("the event does not carry what used to hold the port")
	}
	if got := deltaLevel(evs[0]); got != deltaHigh {
		t.Errorf("a service replaced at a known port levelled %q, want high", got)
	}
	// And the words name both sides and the port, because that is the finding.
	var words string
	for _, e := range evs[0].Evidence {
		if e.Signal == "listener-holder-changed" {
			words = e.Value
		}
	}
	for _, want := range []string{"nginx", "evil", "443"} {
		if !strings.Contains(words, want) {
			t.Errorf("evidence %q does not name %q", words, want)
		}
	}
}

// A port nothing was on before. The one the class is really for.
func TestAPortNothingWasOnBeforeIsListenerNewAndItsLevelFollowsTheAddress(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", 5432, "postgres", 3)})

	exposed, _ := baselineFromListeners([]listenSocket{
		sock("tcp", "127.0.0.1", 5432, "postgres", 3),
		sock("tcp", "0.0.0.0", 4444, "nc", 77),
	})
	evs := deltaCompare(was, liveList(exposed))
	if len(evs) != 1 || evs[0].Kind != deltaListenerNew {
		t.Fatalf("want one listener_new, got %v", kindsOf(evs))
	}
	if got := deltaLevel(evs[0]); got != deltaHigh {
		t.Errorf("a new listener on a routable address levelled %q, want high", got)
	}

	// THE SAME PORT ON LOOPBACK IS NOT THE SAME FINDING. A developer running
	// something locally must not page anyone, and the address is in the slot
	// precisely so this can be told apart.
	local, _ := baselineFromListeners([]listenSocket{
		sock("tcp", "127.0.0.1", 5432, "postgres", 3),
		sock("tcp", "127.0.0.1", 4444, "nc", 77),
	})
	evs = deltaCompare(was, liveList(local))
	if len(evs) != 1 || evs[0].Kind != deltaListenerNew {
		t.Fatalf("want one listener_new, got %v", kindsOf(evs))
	}
	if got := deltaLevel(evs[0]); got != deltaWarn {
		t.Errorf("a new loopback listener levelled %q, want warn", got)
	}
}

// THE SAME SERVICE MOVING FROM LOOPBACK TO THE WILDCARD IS THE FINDING, and
// the address being in the slot is what makes it visible at all. This is the
// judgement baseline_listeners.go's header argues for, so it is pinned.
func TestAServiceThatStartsBindingTheWildcardIsReported(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", 9000, "app", 5)})
	now, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 9000, "app", 5)})
	evs := deltaCompare(was, liveList(now))
	var sawNew bool
	for _, e := range evs {
		if e.Kind == deltaListenerNew && deltaLevel(e) == deltaHigh {
			sawNew = true
		}
	}
	if !sawNew {
		t.Fatalf("a service that opened itself to the network produced %v, with no high listener_new", kindsOf(evs))
	}
}

// Four workers accept()ing one bound port are one listener to a person.
func TestOneBindPointWithSeveralWorkersIsOneEntryCarryingEveryPID(t *testing.T) {
	entries, pids := baselineFromListeners([]listenSocket{
		sock("tcp", "0.0.0.0", 80, "nginx", 11),
		sock("tcp", "0.0.0.0", 80, "nginx", 12),
		sock("tcp", "0.0.0.0", 80, "nginx", 13),
	})
	if len(entries) != 1 {
		t.Fatalf("want one folded entry, got %d", len(entries))
	}
	if len(pids[0]) != 3 {
		t.Errorf("the folded entry carries %v, want all three worker pids", pids[0])
	}
}

// THE COLLISION THE MARKER EXISTS TO STOP. `ss` omits the process column for
// sockets this account may not read. Recording that as the empty string would
// make every unreadable socket ONE fingerprint, so the second and later ones
// would never be reported at all.
func TestTwoSocketsWithNoReadableOwnerStayDistinct(t *testing.T) {
	entries, _ := baselineFromListeners([]listenSocket{
		sock("tcp", "0.0.0.0", 8000, "", 0),
		sock("tcp", "0.0.0.0", 9999, "", 0),
	})
	if len(entries) != 2 {
		t.Fatalf("two unreadable sockets folded into %d entries — one of them can never be reported", len(entries))
	}
	if entries[0].FP == entries[1].FP {
		t.Error("two different bind points share a fingerprint")
	}
	if !strings.Contains(entries[0].ArgvShape, "unreadable") {
		t.Errorf("an unreadable owner reads as %q, which does not say the box could not look", entries[0].ArgvShape)
	}
}

// ── identities ──────────────────────────────────────────────────────────────

func idEntry(name string, sudo bool, keys int, digest, shell string) baselineEntry {
	return baselineEntryOfIdentity(identityObs{
		Name: name, UID: 1000, Shell: shell, Sudo: sudo, AuthKeys: keys, KeyDigest: digest,
	})
}

// A NEW ACCOUNT THAT ARRIVES ALREADY PRIVILEGED IS NOT HOW A COLLEAGUE IS
// ADDED. It is how persistence is installed, and the level says so.
func TestANewAccountIsHighAndCriticalWhenItArrivesArmed(t *testing.T) {
	base := []baselineEntry{idEntry("erin", false, 1, "d1", "/bin/bash")}

	plain := append([]baselineEntry{}, base...)
	plain = append(plain, idEntry("intern", false, 0, "", "/bin/bash"))
	evs := deltaCompare(base, liveList(plain))
	if len(evs) != 1 || evs[0].Kind != deltaIdentityNew {
		t.Fatalf("want one identity_new, got %v", kindsOf(evs))
	}
	if got := deltaLevel(evs[0]); got != deltaHigh {
		t.Errorf("a plain new account levelled %q, want high", got)
	}

	for _, armed := range []baselineEntry{
		idEntry("backdoor", true, 0, "", "/bin/bash"),  // sudo on arrival
		idEntry("backdoor", false, 2, "dx", "/bin/sh"), // keys on arrival
	} {
		live := append([]baselineEntry{}, base...)
		live = append(live, armed)
		evs := deltaCompare(base, liveList(live))
		if len(evs) != 1 {
			t.Fatalf("want one event, got %v", kindsOf(evs))
		}
		if got := deltaLevel(evs[0]); got != deltaCritical {
			t.Errorf("an account arriving with sudo or keys levelled %q, want critical", got)
		}
	}
}

// Granting sudo to an EXISTING account must read as a change to that account,
// never as a new one — the slot is the account for exactly this reason.
func TestGrantingSudoIsACriticalChangeToAKnownAccountNotANewOne(t *testing.T) {
	was := []baselineEntry{idEntry("erin", false, 1, "d1", "/bin/bash")}
	now := []baselineEntry{idEntry("erin", true, 1, "d1", "/bin/bash")}

	evs := deltaCompare(was, liveList(now))
	if len(evs) != 1 || evs[0].Kind != deltaIdentityChanged {
		t.Fatalf("want one identity_changed, got %v", kindsOf(evs))
	}
	if evs[0].Reason != deltaReasonSudoers {
		t.Errorf("reason = %q, want %q", evs[0].Reason, deltaReasonSudoers)
	}
	if got := deltaLevel(evs[0]); got != deltaCritical {
		t.Errorf("privilege moving levelled %q, want critical", got)
	}
	if w := identityChangeWords(was[0], now[0]); !strings.Contains(w, "sudo") {
		t.Errorf("the sentence %q does not mention sudo", w)
	}
}

// THE CASE A COUNT CANNOT SEE, and the only reason the digest is kept at all:
// one key swapped for another is the same number and a different machine.
func TestAKeySwappedAtTheSameCountIsStillReported(t *testing.T) {
	was := []baselineEntry{idEntry("erin", false, 1, "digest-of-old-key", "/bin/bash")}
	now := []baselineEntry{idEntry("erin", false, 1, "digest-of-new-key", "/bin/bash")}

	evs := deltaCompare(was, liveList(now))
	if len(evs) != 1 || evs[0].Kind != deltaIdentityChanged {
		t.Fatalf("a key swap at an unchanged count produced %v — it is invisible", kindsOf(evs))
	}
	if evs[0].Reason != deltaReasonAuthKeys {
		t.Errorf("reason = %q, want %q", evs[0].Reason, deltaReasonAuthKeys)
	}
	if got := deltaLevel(evs[0]); got != deltaHigh {
		t.Errorf("a swapped key levelled %q, want high", got)
	}
	if w := identityChangeWords(was[0], now[0]); !strings.Contains(w, "not the same keys") {
		t.Errorf("the sentence %q does not say the keys differ at the same count", w)
	}
}

// The digest must not churn on things that grant nothing, or the class becomes
// noise and people stop reading it.
func TestTheKeyDigestIgnoresOrderCommentsAndBlankLines(t *testing.T) {
	a := identityKeyDigest([]string{
		"ssh-ed25519 AAAAKEY1 erin@laptop",
		"ssh-rsa AAAAKEY2 erin@desktop",
	})
	reordered := identityKeyDigest([]string{
		"ssh-rsa AAAAKEY2 erin@desktop",
		"ssh-ed25519 AAAAKEY1 erin@laptop",
	})
	if a != reordered {
		t.Error("reordering authorized_keys changed the digest — every config-management rewrite would be a finding")
	}
	recommented := identityKeyDigest([]string{
		"ssh-ed25519 AAAAKEY1 a-new-comment",
		"# a comment line",
		"",
		"ssh-rsa AAAAKEY2 erin@desktop",
	})
	if a != recommented {
		t.Error("renaming a key's comment changed the digest")
	}
	if n := identityCountKeys([]string{"ssh-rsa AAAAK x", "# no", "", "  "}); n != 1 {
		t.Errorf("counted %d keys, want 1 — comments and blanks are not grants", n)
	}
	// A REAL CHANGE STILL MOVES IT, or none of the above is worth anything.
	if a == identityKeyDigest([]string{"ssh-ed25519 AAAAKEY1 x", "ssh-rsa AAAADIFFERENT y"}) {
		t.Error("a different key produced the same digest")
	}
}

// THE PRIVACY PROPERTY, pinned. The accounting holds the shape of an identity
// and never its content; baseline_identity.go's header states it and this is
// what would catch someone widening it.
func TestTheAccountingNeverHoldsKeyMaterial(t *testing.T) {
	const secret = "AAAAC3NzaC1lZDI1NTE5AAAAISECRETKEYBODY"
	keys := []string{"ssh-ed25519 " + secret + " erin@laptop"}
	e := baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash", Sudo: true,
		AuthKeys: identityCountKeys(keys), KeyDigest: identityKeyDigest(keys),
	})
	blob := e.FP + e.Kind + e.Unit + e.User + e.ArgvShape + e.Origin + e.DigestNote + e.Signature
	if strings.Contains(blob, secret) {
		t.Fatal("the key body is in the accounting")
	}
	n, nok := e.identityKeys()
	sudo, sok := e.identitySudo()
	if !nok || n != 1 || !sok || !sudo {
		t.Errorf("the shape did not survive the round trip: keys=%d known=%v sudo=%v known=%v",
			n, nok, sudo, sok)
	}
}

// A system account is not a way onto the machine, and fifty of them would bury
// the one that is.
func TestOnlyAccountsWithALoginShellAreAccounted(t *testing.T) {
	for _, s := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""} {
		if identityIsLoginShell(s) {
			t.Errorf("%q counted as a login shell", s)
		}
	}
	for _, s := range []string{"/bin/bash", "/bin/zsh", "/usr/bin/fish", "/opt/weird/shell"} {
		if !identityIsLoginShell(s) {
			t.Errorf("%q did not count as a login shell — an unusual shell is MORE interesting, not less", s)
		}
	}
}

// ── the class guard ─────────────────────────────────────────────────────────
//
// The two false-finding floods deltaComparableClasses exists to stop. Both are
// reachable on a real machine and neither is a fact about the machine — they
// are facts about what was readable, which is the distinction this whole plane
// is built on.

func withReaders(t *testing.T, listeners bool, identities bool) {
	t.Helper()
	oL, oI := deltaListenerReader, deltaIdentityReader
	deltaListenerReader = func() ([]listenSocket, bool, string) {
		if !listeners {
			return nil, false, "no ss on this box"
		}
		return []listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)}, true, ""
	}
	deltaIdentityReader = func() identityScanReport {
		if !identities {
			return identityScanReport{Reason: "cannot read the account database"}
		}
		return identityScanReport{Supported: true,
			Accounts: []identityObs{{Name: "erin", UID: 1000, Shell: "/bin/bash"}}}
	}
	t.Cleanup(func() { deltaListenerReader, deltaIdentityReader = oL, oI })
}

// FLOOD ONE: the accounting was taken before this box could see listeners.
// Every listener on it would compare against nothing and come out as new — on a
// machine where nothing changed at all.
func TestAListenerClassMissingFromTheAccountingIsNotReportedAsAllNew(t *testing.T) {
	base := &baselineFile{
		Coverage: baselineCoverage(true, true, false, true), // listeners=unsupported
		Entries:  []baselineEntry{procEntry("d", "root", "svc", "x")},
	}
	liveListeners, _ := baselineFromListeners([]listenSocket{
		sock("tcp", "0.0.0.0", 22, "sshd", 1),
		sock("tcp", "0.0.0.0", 443, "nginx", 2),
	})
	live := append(liveList(liveListeners), deltaLiveEntry{Entry: base.Entries[0]})

	keptBase, keptLive, notes, _ := deltaComparableClasses(base, live, deltaSight{Listeners: true, Identities: true}, nil)
	for _, e := range deltaCompare(keptBase, keptLive) {
		if strings.HasPrefix(e.Kind, "listener") {
			t.Fatalf("a listener event fired against an accounting that never saw listeners: %s", e.Kind)
		}
	}
	if !strings.Contains(strings.Join(notes, " "), "listeners are not in the accounting") {
		t.Errorf("the pass did not SAY it cannot report listeners; notes = %v", notes)
	}
}

// FLOOD TWO, and the worse of the two: the accounting HAS the class and this
// pass went blind. Every entry would come out `_gone` — "the listeners all
// stopped" reads as an incident rather than as a blindfold.
func TestAClassThisPassCannotReadIsNotReportedAsAllGone(t *testing.T) {
	known, _ := baselineFromListeners([]listenSocket{
		sock("tcp", "0.0.0.0", 22, "sshd", 1),
		sock("tcp", "0.0.0.0", 443, "nginx", 2),
	})
	base := &baselineFile{
		Coverage: baselineCoverage(true, true, true, true),
		Entries:  append(known, idEntry("erin", false, 1, "d1", "/bin/bash")),
	}
	// The live side saw neither class, which is exactly what a blind pass looks
	// like: no entries, and no way to tell that from "they are all gone".
	keptBase, keptLive, notes, _ := deltaComparableClasses(base, nil, deltaSight{}, nil)

	for _, e := range deltaCompare(keptBase, keptLive) {
		if strings.HasPrefix(e.Kind, "listener") || strings.HasPrefix(e.Kind, "identity") {
			t.Fatalf("a blind pass reported %s — that is a blindfold being read as an incident", e.Kind)
		}
	}
	joined := strings.Join(notes, " ")
	for _, want := range []string{"listeners are in the accounting", "identities are in the accounting"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the pass did not say which class it could not read; notes = %v", notes)
		}
	}
}

// AND WHEN BOTH SIDES CAN SEE, THE CLASS IS COMPARED NORMALLY — without this
// the two tests above would pass on a plane that had simply stopped working.
func TestAClassBothSidesCanSeeIsStillCompared(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)})
	base := &baselineFile{Coverage: baselineCoverage(true, true, true, true), Entries: was}
	now, _ := baselineFromListeners([]listenSocket{
		sock("tcp", "0.0.0.0", 22, "sshd", 1),
		sock("tcp", "0.0.0.0", 4444, "nc", 9),
	})
	keptBase, keptLive, notes, _ := deltaComparableClasses(base, liveList(now), deltaSight{Listeners: true, Identities: true}, nil)
	evs := deltaCompare(keptBase, keptLive)
	if len(evs) != 1 || evs[0].Kind != deltaListenerNew {
		t.Fatalf("want one listener_new when both sides can see, got %v (notes %v)", kindsOf(evs), notes)
	}
	if len(notes) != 0 {
		t.Errorf("a fully-sighted pass still carried a cannot-compare note: %v", notes)
	}
}

// A baseline taken before either class existed says nothing about them, and
// that is the ordinary upgrade path — every box in the fleet is in this state
// the first time it runs a bastion carrying these classes.
func TestAnAccountingFromBeforeTheseClassesAsksForARetakeRatherThanFlooding(t *testing.T) {
	base := &baselineFile{
		Coverage: "processes=all,schedulers=all", // what earlier versions wrote
		Entries:  []baselineEntry{procEntry("d", "root", "svc", "x")},
	}
	listeners, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 22, "sshd", 1)})
	live := append(liveList(listeners), deltaLiveEntry{Entry: base.Entries[0]})

	keptBase, keptLive, notes, _ := deltaComparableClasses(base, live, deltaSight{Listeners: true, Identities: true}, nil)
	if evs := deltaCompare(keptBase, keptLive); len(evs) != 0 {
		t.Fatalf("upgrading the bastion produced findings on an unchanged machine: %v", kindsOf(evs))
	}
	if !strings.Contains(strings.Join(notes, " "), "take it again") {
		t.Errorf("the note does not tell the operator what to do; notes = %v", notes)
	}
}

// THE SIGHT MUST COME FROM THE READERS, and until this test nothing checked
// that — the guard tests hand deltaComparableClasses a deltaSight directly, so
// a deltaCollectLive that always reported "I saw both" would have passed every
// one of them while reintroducing the exact flood the guard exists to stop.
func TestTheSightIsWhatTheReadersActuallySaid(t *testing.T) {
	for _, tc := range []struct{ listeners, identities bool }{
		{true, true}, {true, false}, {false, true}, {false, false},
	} {
		withReaders(t, tc.listeners, tc.identities)
		_, _, _, sight, _ := deltaCollectLive(func(string) (string, string) { return "", "" })
		if sight.Listeners != tc.listeners {
			t.Errorf("readers said listeners=%v, sight says %v", tc.listeners, sight.Listeners)
		}
		if sight.Identities != tc.identities {
			t.Errorf("readers said identities=%v, sight says %v", tc.identities, sight.Identities)
		}
	}
}

// AND A BLIND READER CONTRIBUTES NO ENTRIES, which is the other half: a sight
// of false with entries in the list would mean the guard dropped real
// observations, and a sight of true with none is the state that reports
// everything gone.
func TestABlindReaderContributesNoEntriesOfItsClass(t *testing.T) {
	withReaders(t, false, true)
	live, _, _, sight, _ := deltaCollectLive(func(string) (string, string) { return "", "" })
	if sight.Listeners {
		t.Fatal("a blind listener reader reported as sighted")
	}
	for _, l := range live {
		if l.Entry.Kind == "listener" {
			t.Fatal("a blind listener reader still produced listener entries")
		}
	}
}

// The identity fold, which nothing exercised until a coverage sweep noticed —
// baselineFromIdentities is what both sides call and only the single-entry
// constructor beneath it was being tested.
func TestADuplicateAccountLineProducesOneEntry(t *testing.T) {
	dup := identityObs{Name: "erin", UID: 1000, Shell: "/bin/bash"}
	out := baselineFromIdentities([]identityObs{dup, dup})
	if len(out) != 1 {
		t.Fatalf("a duplicated passwd line produced %d entries", len(out))
	}
	// Two DIFFERENT accounts still produce two, or the fold is eating them.
	out = baselineFromIdentities([]identityObs{dup, {Name: "dave", UID: 1001, Shell: "/bin/bash"}})
	if len(out) != 2 {
		t.Fatalf("two accounts folded into %d entries", len(out))
	}
}
