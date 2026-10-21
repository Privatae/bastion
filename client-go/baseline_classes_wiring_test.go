//go:build linux

package main

// TEN MUTATION SURVIVORS, and they were all one shape.
//
// Every test first written for these classes injected at a seam —
// listenerSockets, deltaListenerReader, deltaIdentityReader, a hand-built
// deltaEvent — that sits ABOVE the line the change actually touched. So the
// suite asserted the behaviour of values the test supplied and never ran the
// code under test. That included the failed-`ss` guard itself: nothing in the
// suite executed readSockets at all, so the exec-error check that guard exists
// for could be deleted with everything green.
//
// The rule, which is the part worth keeping: A TEST THAT SUPPLIES THE VALUE
// UNDER TEST CANNOT TEST THE CODE THAT PRODUCES IT. These inject one layer
// lower — observeExec for the socket reader, a fixture root for the account
// reader, and deltaCompare's own output instead of a constructed event.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── below the socket seam: readSockets itself ───────────────────────────────

func withSs(t *testing.T, out map[string]string, fail map[string]error) {
	t.Helper()
	oe, oh := observeExec, observeHave
	observeHave = func(string) bool { return true }
	observeExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "ss" || len(args) == 0 {
			return nil, nil
		}
		return []byte(out[args[0]]), fail[args[0]]
	}
	t.Cleanup(func() { observeExec, observeHave = oe, oh })
}

// `ss` runs and exits non-zero. textOf discards that error, so without
// the check in readSockets the caller gets Supported=true with an empty table —
// and an empty table is what the next accounting calls normal.
func TestReadSocketsReportsAFailedExecRatherThanAnEmptyTable(t *testing.T) {
	line := "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"

	// The tcp half fails. Note it returns OUTPUT TOO — exec.Cmd.Output gives
	// partial stdout alongside the error, so a truncated run reads as a
	// complete short table unless the error is what is checked.
	withSs(t, map[string]string{"-tlnpH": line}, map[string]error{"-tlnpH": os.ErrPermission})
	if r := readSockets(); r.Failed == "" {
		t.Errorf("a failed tcp read reported Failed=%q Partial=%q sockets=%d",
			r.Failed, r.Partial, len(r.Sockets))
	}

	// The udp half fails after a clean tcp half.
	withSs(t, map[string]string{"-tlnpH": line, "-ulnpH": ""},
		map[string]error{"-ulnpH": os.ErrPermission})
	if r := readSockets(); r.Failed == "" {
		t.Error("a failed udp read was not reported")
	}

	// A clean run still works, or the two above pass on a reader that always
	// claims failure.
	withSs(t, map[string]string{"-tlnpH": line, "-ulnpH": ""}, nil)
	r := readSockets()
	if r.Failed != "" || !r.Supported || len(r.Sockets) != 1 {
		t.Fatalf("a clean read gave Failed=%q supported=%v n=%d", r.Failed, r.Supported, len(r.Sockets))
	}
	// And the whole way up: listenerScan refuses each failure, accepts the good
	// one. This is the path the accounting and the delta both take.
	withSs(t, map[string]string{"-tlnpH": line}, map[string]error{"-tlnpH": os.ErrPermission})
	if _, ok, _ := listenerScan(); ok {
		t.Error("listenerScan accepted a failed socket read")
	}
}

// ── below the account seam: identityScan itself ─────────────────────────────

func withEtc(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := identityRoot
	identityRoot = root
	t.Cleanup(func() { identityRoot = old })
	return root
}

// identityScan is what sets SudoUnknown, and every test built the flag by
// hand — so the whole sudo-`?` path could be dead with the suite green.
func TestIdentityScanMarksSudoUnknownWhenTheRulesCannotBeRead(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nerin:x:1000:1000::/home/erin:/bin/bash\n" +
		"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"

	// No /etc/sudoers at all — ReadFile fails, so the rules are unreadable.
	withEtc(t, map[string]string{"etc/passwd": passwd})
	r := identityScan()
	if !r.Supported {
		t.Fatalf("a readable passwd reported unsupported: %s", r.Reason)
	}
	if r.Partial == "" {
		t.Error("unreadable sudo rules produced no partial note")
	}
	for _, a := range r.Accounts {
		if !a.SudoUnknown {
			t.Errorf("account %q recorded sudo as KNOWN while the rules were unreadable", a.Name)
		}
	}
	// Only login shells, which is the filter that keeps fifty system accounts
	// from burying the one that matters.
	if len(r.Accounts) != 2 {
		t.Errorf("got %d accounts, want 2 (nologin must be dropped)", len(r.Accounts))
	}

	// With rules present, sudo is KNOWN and the comma list resolves — the same
	// assertion as the unit test, but through the real reader this time.
	withEtc(t, map[string]string{
		"etc/passwd":  passwd,
		"etc/sudoers": "Defaults env_reset\nerin, root ALL=(ALL:ALL) ALL\n",
	})
	r = identityScan()
	for _, a := range r.Accounts {
		if a.SudoUnknown {
			t.Errorf("account %q still unknown with readable rules", a.Name)
		}
		if !a.Sudo {
			t.Errorf("account %q in a spaced User_List was not recognised", a.Name)
		}
	}
	if r.Partial != "" {
		t.Errorf("a fully readable scan carried a partial note: %q", r.Partial)
	}
}

// A truncated account database drops ENTRIES, not properties, so it must
// refuse the class rather than narrow it — otherwise the tail reports gone and
// an account created after the bad line is never seen at all.
func TestATruncatedAccountDatabaseRefusesTheClass(t *testing.T) {
	long := strings.Repeat("x", 80*1024)
	withEtc(t, map[string]string{
		"etc/passwd": "erin:x:1000:1000:" + long + ":/home/erin:/bin/bash\n" +
			"dave:x:1001:1001::/home/dave:/bin/bash\n",
		"etc/sudoers": "",
	})
	if r := identityScan(); r.Supported {
		t.Errorf("a truncated account database was compared as complete: %d accounts, reason %q",
			len(r.Accounts), r.Reason)
	}
}

// M35b/M36b. identityScan is what feeds the sshd_config paths into the key
// reader and what carries the narrowed-lookup note. Both were wired but neither
// wiring was asserted.
func TestIdentityScanReadsKeysWhereSshdSaysAndSaysWhenThatIsUnusual(t *testing.T) {
	root := withEtc(t, map[string]string{
		"etc/passwd":  "erin:x:1000:1000::/home/erin:/bin/bash\n",
		"etc/sudoers": "",
	})
	central := filepath.Join(root, "etc/ssh/keys")
	if err := os.MkdirAll(central, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(central, "erin"),
		[]byte("ssh-ed25519 AAAAKEYBODY erin@laptop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withSshdConfig(t, "AuthorizedKeysFile "+central+"/%u\n")

	r := identityScan()
	if len(r.Accounts) != 1 {
		t.Fatalf("got %d accounts", len(r.Accounts))
	}
	if r.Accounts[0].AuthKeys != 1 {
		t.Errorf("the central key store was not read: keys=%d unread=%q",
			r.Accounts[0].AuthKeys, r.Accounts[0].KeysUnread)
	}
	if !strings.Contains(r.Partial, "does not choose") {
		t.Errorf("the narrowed lookup did not reach the report: %q", r.Partial)
	}
	// No configuration text in the note, checked at the level that matters:
	// this string reaches the heartbeat.
	if strings.Contains(r.Partial, central) {
		t.Errorf("the note carries the user's sshd configuration: %q", r.Partial)
	}
}

// Include is the stock Debian 12 / Ubuntu 22.04 layout, and a Match block
// scopes what follows it to some users only.
func TestSshdConfigIncludeIsFollowedAndMatchIsNot(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sshd_config")
	if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config.d", "50-keys.conf"),
		[]byte("AuthorizedKeysFile /etc/ssh/global/%u\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("Include "+dir+"/sshd_config.d/*.conf\nPort 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := sshdConfigPath
	sshdConfigPath = main
	t.Cleanup(func() { sshdConfigPath = old })

	paths, note := authorizedKeysPaths()
	if len(paths) != 1 || paths[0] != "/etc/ssh/global/%u" {
		t.Fatalf("an Include drop-in was missed: %v", paths)
	}
	if note == "" {
		t.Error("a narrowed lookup from a drop-in was not said out loud")
	}

	// A Match-scoped override is NOT the global setting, and applying it to
	// every account would be wrong in the confident direction.
	if err := os.WriteFile(main,
		[]byte("Port 22\nMatch User backup\n    AuthorizedKeysFile /etc/ssh/backup/%u\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if paths, _ := authorizedKeysPaths(); len(paths) != 2 {
		t.Errorf("a Match-scoped override was applied globally: %v", paths)
	}
}

// ── above the seam, but taking the event from deltaCompare ──────────────────

// changedAtSlot decides which entry the event carries, and every level
// test built its deltaEvent by hand — so the event could carry the OLD entry
// and nothing would notice. Measured: `usermod -u 0 erin`
// graded warn instead of critical, because the event held the old uid.
func TestTheChangedEventCarriesTheNewStateNotTheOld(t *testing.T) {
	was := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash"})}
	now := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 0, Shell: "/bin/bash"})}

	evs := deltaCompare(was, liveList(now))
	if len(evs) != 1 {
		t.Fatalf("want one event, got %v", kindsOf(evs))
	}
	if got := identityField(evs[0].Entry, "uid"); got != "0" {
		t.Fatalf("the event carries uid %q — the OLD state", got)
	}
	// THROUGH deltaLevel, from the event deltaCompare actually built.
	if got := deltaLevel(evs[0]); got != deltaCritical {
		t.Errorf("an account moved to uid 0 levelled %q, want critical", got)
	}
	if evs[0].Was == nil || identityField(*evs[0].Was, "uid") != "1000" {
		t.Error("the event does not carry the previous state as `was`")
	}
}

// The regression the `?` fix introduced: a sudo grant on an account whose
// keys could not be read graded NOTICE, while the sentence beside it said "a
// sudo rule now names this account". Readable properties classify first.
func TestAReadablePropertyThatMovedBeatsAnUnreadableOne(t *testing.T) {
	was := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash", Sudo: false,
		KeysUnread: "permission denied"})}
	now := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash", Sudo: true,
		KeysUnread: "permission denied"})}

	evs := deltaCompare(was, liveList(now))
	if len(evs) != 1 {
		t.Fatalf("want one event, got %v", kindsOf(evs))
	}
	if evs[0].Reason != deltaReasonSudoers {
		t.Errorf("reason = %q, want %q — the readable property is the one that moved",
			evs[0].Reason, deltaReasonSudoers)
	}
	if got := deltaLevel(evs[0]); got != deltaCritical {
		t.Errorf("a sudo grant beside an unreadable key file levelled %q, want critical", got)
	}
	// And when NOTHING readable moved, it really is a visibility change.
	same := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash", Sudo: false, AuthKeys: 1, KeyDigest: "d"})}
	blind := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash", Sudo: false, KeysUnread: "denied"})}
	evs = deltaCompare(same, liveList(blind))
	if len(evs) != 1 || evs[0].Reason != deltaReasonUnreadable || deltaLevel(evs[0]) != deltaNotice {
		t.Errorf("a pure visibility change gave %v reason=%q level=%q",
			kindsOf(evs), evs[0].Reason, deltaLevel(evs[0]))
	}
}

// identitySudo mapped `?` to false and the level table read it
// directly, so an account arriving with sudo on a box with unreadable rules
// graded high — or WARN at a service uid, which an attacker picks freely.
func TestUnknownSudoDoesNotReadAsNoSudo(t *testing.T) {
	unknown := baselineEntryOfIdentity(identityObs{
		Name: "svc", UID: 114, Shell: "/bin/bash", SudoUnknown: true})
	if _, known := unknown.identitySudo(); known {
		t.Error("`?` reads as a known sudo answer")
	}
	if got := deltaLevel(deltaEvent{Kind: deltaIdentityNew, Entry: unknown}); got != deltaHigh {
		t.Errorf("a new account with unreadable sudo levelled %q — unknown must not "+
			"earn the service-account demotion", got)
	}
	// The same account with rules readable and no sudo IS the ordinary case.
	known := baselineEntryOfIdentity(identityObs{Name: "svc", UID: 114, Shell: "/bin/bash"})
	if got := deltaLevel(deltaEvent{Kind: deltaIdentityNew, Entry: known}); got != deltaWarn {
		t.Errorf("an ordinary service account levelled %q, want warn", got)
	}
}

// listenerMovedFrom must match on the HOLDER, or a different program
// taking a dead service's port at a new address gets the re-address demotion.
func TestADifferentProgramAtANewAddressIsNotARaAddressing(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "10.0.0.5", 8080, "app", 5)})
	now, _ := baselineFromListeners([]listenSocket{sock("tcp", "10.0.0.9", 8080, "evil", 9)})
	for _, e := range deltaCompare(was, liveList(now)) {
		if e.Kind == deltaListenerNew && e.Reason == deltaReasonAddressMoved {
			t.Fatal("a different program at a new address was written off as a re-addressing")
		}
	}
}

// Binding every interface instead of one is an exposure increase by the
// same argument loopback→routable is.
func TestMovingToTheWildcardIsNotARaAddressing(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "10.0.0.5", 9000, "app", 5)})
	now, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 9000, "app", 5)})
	var sawHigh bool
	for _, e := range deltaCompare(was, liveList(now)) {
		if e.Kind != deltaListenerNew {
			continue
		}
		if e.Reason == deltaReasonAddressMoved {
			t.Error("one interface → all interfaces was written off as a re-addressing")
		}
		if deltaLevel(e) == deltaHigh {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Error("a service that began binding every interface did not produce a high")
	}
}

// A re-addressing is ONE event. It used to be a gone at the old address
// and a new at the other — the correlate-by-eye shape the slot design exists
// to avoid, produced by the branch added to avoid it.
func TestARaAddressingIsOneEventNotAPair(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "192.168.1.5", 8080, "app", 5)})
	now, _ := baselineFromListeners([]listenSocket{sock("tcp", "192.168.9.9", 8080, "app", 5)})
	evs := deltaCompare(was, liveList(now))
	if len(evs) != 1 {
		t.Fatalf("a re-addressing produced %d events (%v) — it must be one", len(evs), kindsOf(evs))
	}
	if evs[0].Was == nil || evs[0].Was.Unit != "tcp/192.168.1.5:8080" {
		t.Error("the single event does not carry where the listener moved from")
	}
}

// The login-shell regrade, which nothing guarded before.
func TestChangingBetweenTwoLoginShellsIsOrdinary(t *testing.T) {
	was := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/bin/bash"})}
	now := []baselineEntry{baselineEntryOfIdentity(identityObs{
		Name: "erin", UID: 1000, Shell: "/usr/bin/zsh"})}
	evs := deltaCompare(was, liveList(now))
	if len(evs) != 1 || evs[0].Reason != deltaReasonShell {
		t.Fatalf("want one shell change, got %v", kindsOf(evs))
	}
	if got := deltaLevel(evs[0]); got != deltaWarn {
		t.Errorf("chsh between two login shells levelled %q, want warn", got)
	}
}

// The class-specific sentences, which a mutation could revert and
// leave identities printing their raw state blob as the subject.
func TestEachClassRendersItsOwnSentence(t *testing.T) {
	id := baselineEntryOfIdentity(identityObs{Name: "intern", UID: 1010, Shell: "/bin/bash", Sudo: true})
	line := deltaOneLine(deltaEvent{Kind: deltaIdentityNew, Entry: id})
	if strings.Contains(line, "keydigest=") || strings.Contains(line, "shell=/bin/bash;") {
		t.Errorf("an identity prints its raw fingerprinted state: %q", line)
	}
	if !strings.HasPrefix(line, "account intern") {
		t.Errorf("an identity does not read as an account: %q", line)
	}

	lis, _ := baselineFromListeners([]listenSocket{sock("tcp", "0.0.0.0", 4444, "nc", 7)})
	line = deltaOneLine(deltaEvent{Kind: deltaListenerNew, Entry: lis[0]})
	if !strings.HasPrefix(line, "listening on tcp/0.0.0.0:4444") || !strings.Contains(line, "nc") {
		t.Errorf("a listener does not read as a bind point: %q", line)
	}
}

// THE NOISE MEASURED ON A DEVELOPER'S MACHINE: a `go test` run
// produced two listener_new warns on ephemeral loopback ports, held by a test
// binary that had already been reported as a proc_new. Same event twice, and on
// a person's own computer that is most of what this class would ever say.
func TestAnEphemeralLoopbackListenerWaitsOnePass(t *testing.T) {
	young := func(int) (time.Duration, bool) { return time.Second, true }
	mk := func(addr string, port int) deltaEvent {
		e, _ := baselineFromListeners([]listenSocket{sock("tcp", addr, port, "go-test", 7)})
		return deltaEvent{Kind: deltaListenerNew, Entry: e[0], PIDs: []int{7}}
	}
	n := deltaNoise{Age: young}

	if _, held := n.ephemeralLoopbackListener(mk("127.0.0.1", 41579)); !held {
		t.Error("an ephemeral loopback port from a one-second-old process was reported immediately")
	}
	// EVERY CONDITION IS LOAD-BEARING — drop any one and it must report.
	if _, held := n.ephemeralLoopbackListener(mk("0.0.0.0", 41579)); held {
		t.Error("a ROUTABLE ephemeral port was held back")
	}
	if _, held := n.ephemeralLoopbackListener(mk("127.0.0.1", 4444)); held {
		t.Error("a loopback port BELOW the ephemeral range was held back — 4444 is the backdoor case")
	}
	old := deltaNoise{Age: func(int) (time.Duration, bool) { return time.Hour, true }}
	if _, held := old.ephemeralLoopbackListener(mk("127.0.0.1", 41579)); held {
		t.Error("a listener held by an HOUR-OLD process was held back")
	}
	// An age this platform cannot read is not a young one.
	blind := deltaNoise{Age: func(int) (time.Duration, bool) { return 0, false }}
	if _, held := blind.ephemeralLoopbackListener(mk("127.0.0.1", 41579)); held {
		t.Error("the rule fired where the process age could not be read")
	}
	// And it goes through shortLived, which is what the filter actually calls.
	if held, why := n.shortLived(mk("127.0.0.1", 41579)); !held || why == "" {
		t.Errorf("shortLived did not hold the ephemeral listener: held=%v why=%q", held, why)
	}
	if held, _ := n.shortLived(mk("0.0.0.0", 4444)); held {
		t.Error("shortLived held back a routable backdoor port")
	}
}

// THE HOLD HAS A CEILING, AND IT IS INHERITED RATHER THAN RE-IMPLEMENTED.
//
// A beacon that reopens a loopback ephemeral port every 50s is young at EVERY
// pass, so a hold without a ceiling hides it for ever — the exact defect
// deltanoise.go:110-119 documents for the process path ("ten passes, no finding
// and a storm counter reading zero"). The listener rule lives INSIDE
// shortLived, so deltaFilter's ceiling applies to it by construction. That is
// the kind of claim that is true until someone moves the rule, so it is pinned.
func TestARespawningEphemeralListenerEscapesTheHold(t *testing.T) {
	e, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", 41579, "beacon", 7)})
	ev := deltaEvent{Kind: deltaListenerNew, Entry: e[0], PIDs: []int{7}}
	n := deltaNoise{Age: func(int) (time.Duration, bool) { return time.Second, true }}

	// First pass: held, not reported.
	st := freshState(t)
	now := time.Now()
	f, filtered := deltaFilter([]deltaEvent{ev}, n, st, now)
	if len(f) != 0 || len(filtered) != 1 {
		t.Fatalf("first pass: findings=%d filtered=%d, want 0/1", len(f), len(filtered))
	}

	// Still young a pass later — still held.
	f, _ = deltaFilter([]deltaEvent{ev}, n, st, now.Add(time.Minute))
	if len(f) != 0 {
		t.Fatalf("a listener held for one minute already escaped: %d findings", len(f))
	}

	// PAST THE CEILING it becomes a finding, and the evidence says why.
	f, _ = deltaFilter([]deltaEvent{ev}, n, st, now.Add(deltaHoldMax+time.Second))
	if len(f) != 1 {
		t.Fatalf("a listener young at every pass for %v was still held — it is invisible forever",
			deltaHoldMax)
	}
	var said bool
	for _, x := range f[0].Evidence {
		if x.Signal == "respawning" {
			said = true
		}
	}
	if !said {
		t.Error("the escape carries no evidence explaining why it is now a finding")
	}
}

// THE FLOOR REACHES THE RULE, which is the claim that matters and the one the
// first two versions of this test did not make.
//
// v1 compared the value against this box's sysctl — 32768, identical to the
// fallback, so hardcoding it left the suite green. v2 tested readEphemeralFloor
// with a fixture but the RULE read a package var computed at program start, so
// hardcoding THAT left the suite green too. Both were guards that could not
// fail on the machine they ran on. This drives ephemeralLoopbackListener with a
// narrowed range and asserts the behaviour changes.
func TestTheEphemeralFloorReachesTheRule(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "range")
	old := ephemeralRangePath
	ephemeralRangePath = p
	t.Cleanup(func() { ephemeralRangePath = old })

	e, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", 40000, "thing", 7)})
	ev := deltaEvent{Kind: deltaListenerNew, Entry: e[0], PIDs: []int{7}}
	n := deltaNoise{Age: func(int) (time.Duration, bool) { return time.Second, true }}

	// Stock range: 40000 IS ephemeral, so a young loopback holder is held.
	if err := os.WriteFile(p, []byte("32768\t60999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, held := n.ephemeralLoopbackListener(ev); !held {
		t.Error("port 40000 was not treated as ephemeral under the stock range")
	}
	// NARROWED range: 40000 is an ordinary service port on that box and must be
	// reported. This is the case a hardcoded floor gets wrong.
	if err := os.WriteFile(p, []byte("49152\t60999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, held := n.ephemeralLoopbackListener(ev); held {
		t.Error("a real service port was held back because the floor ignored the kernel")
	}
}

// THE NOTE HAS TO REACH THE PASS, and nothing tested that it did — the
// first test stopped at deltaCollectLive and checked sight.Notes, which is the
// value the test supplied, one seam above the line that publishes it. A mutation
// deleting the publish left the suite green, which is exactly the shape this
// whole file exists for.
//
// This drives deltaPass itself and reads r.Notes, so the wiring is what is
// asserted rather than the fixture.
func TestThePassPublishesWhatTheReadersCouldNotSee(t *testing.T) {
	isolateConfigDir(t)
	if !processIsRoot() {
		t.Skip("the pass refuses without machine authority, which is its own test")
	}
	oI, oL := deltaIdentityReader, deltaListenerReader
	deltaIdentityReader = func() identityScanReport {
		return identityScanReport{Supported: true,
			Partial:  "sudo rules not readable: /etc/sudoers",
			Accounts: []identityObs{{Name: "erin", UID: 1000, Shell: "/bin/bash", SudoUnknown: true}}}
	}
	deltaListenerReader = func() ([]listenSocket, bool, string) { return nil, false, "no ss" }
	t.Cleanup(func() { deltaIdentityReader, deltaListenerReader = oI, oL })

	// An accounting that covers both classes, so the identity half is compared
	// (narrowed, not blind) and the listener half is the one that is refused.
	if err := baselineSave(baselineFile{
		Version:  baselineVersion,
		TakenAt:  stamp(time.Now()),
		Coverage: baselineCoverage(true, true, true, true),
		Entries:  []baselineEntry{baselineEntryOfIdentity(identityObs{Name: "erin", UID: 1000, Shell: "/bin/bash", SudoUnknown: true})},
	}); err != nil {
		t.Fatal(err)
	}

	r := deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	joined := strings.Join(r.Notes, " | ")
	if !strings.Contains(joined, "sudo rules not readable") {
		t.Errorf("the reader's narrowed-class note never reached the pass: %q", joined)
	}
	// And the blind class is named too, so "no listener findings" cannot be
	// read as "this machine has no listeners".
	if !strings.Contains(joined, "listeners") {
		t.Errorf("a refused class was not named on the pass: %q", joined)
	}
	// The summary is what rides the heartbeat, and it must carry the same words.
	if !strings.Contains(r.summary().Note, "sudo rules not readable") {
		t.Errorf("the note did not reach the summary: %q", r.summary().Note)
	}
}

// ── five more, each one the sentence or the guard that was hollow ─────────────

// The rule tested deltaShortLived (5s) while telling the operator "younger
// than one pass", and a pass is 60s. So the words were false AND the case it was
// added for — a `go test` run whose port is thirty seconds old when the pass
// lands — came through anyway, suppressed only about one sighting in twelve.
func TestTheListenerHoldIsOnePassNotFiveSeconds(t *testing.T) {
	e, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", 41579, "go-test", 7)})
	ev := deltaEvent{Kind: deltaListenerNew, Entry: e[0], PIDs: []int{7}}

	for _, age := range []time.Duration{time.Second, 9 * time.Second, 30 * time.Second} {
		n := deltaNoise{Age: func(int) (time.Duration, bool) { return age, true }}
		if _, held := n.ephemeralLoopbackListener(ev); !held {
			t.Errorf("a holder %v old was reported — the rule promises one pass (%v)",
				age, deltaRefreshEvery)
		}
	}
	// PAST one pass it has survived, so it reports. The hold never suppresses.
	n := deltaNoise{Age: func(int) (time.Duration, bool) { return deltaRefreshEvery + time.Second, true }}
	if _, held := n.ephemeralLoopbackListener(ev); held {
		t.Error("a holder older than one pass was still held back")
	}
}

// The ceiling is keyed on the event fingerprint, and a listener's
// fingerprint contains its BIND POINT — so a holder taking a fresh ephemeral
// port each pass never accumulated anything. Measured: twelve
// passes on the same port gave 2 findings, twelve on fresh ports gave ZERO,
// indefinitely. The ceiling existed and could not fire.
func TestAHolderThatChurnsPortsStillReachesTheCeiling(t *testing.T) {
	st := freshState(t)
	n := deltaNoise{Age: func(int) (time.Duration, bool) { return time.Second, true }}
	now := time.Now()

	mk := func(port int) deltaEvent {
		e, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", port, "beacon", 7)})
		return deltaEvent{Kind: deltaListenerNew, Entry: e[0], PIDs: []int{7}}
	}
	// A FRESH PORT EVERY PASS, which is what defeated the old key.
	var found int
	for i := 0; i < 12; i++ {
		f, _ := deltaFilter([]deltaEvent{mk(41000 + i)}, n, st, now.Add(time.Duration(i)*time.Minute))
		found += len(f)
	}
	if found == 0 {
		t.Fatal("a holder opening a new ephemeral port every pass was held forever — invisible")
	}
	// Two unrelated programs must not share the key and escape together.
	if a, b := deltaHoldKey(mk(41000)), deltaHoldKey(mk(42000)); a != b {
		t.Error("the same holder on two ports produced two keys — it will never accumulate")
	}
	e2, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", 41000, "other", 9)})
	if deltaHoldKey(mk(41000)) == deltaHoldKey(deltaEvent{Kind: deltaListenerNew, Entry: e2[0]}) {
		t.Error("two different holders share a hold key")
	}
}

// The floor test compared against THIS box's sysctl, which is the stock
// 32768 — identical to the fallback — so hardcoding the floor left the entire
// suite green. A guard that cannot fail on the machine it runs on is not a
// guard, which is the same lesson as every other item in this file.
func TestTheEphemeralFloorFollowsANonStockRange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "range")
	if err := os.WriteFile(p, []byte("49152\t60999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := ephemeralRangePath
	ephemeralRangePath = p
	t.Cleanup(func() { ephemeralRangePath = old })

	if got := readEphemeralFloor(); got != 49152 {
		t.Fatalf("a NARROWED range read as %d — ports 32768-49151 are ordinary "+
			"service ports on that box and would be held back", got)
	}
	// A widened range follows too, and garbage falls back to the stock floor
	// rather than to something that suppresses more.
	if err := os.WriteFile(p, []byte("10000 60999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readEphemeralFloor(); got != 10000 {
		t.Errorf("a widened range read as %d", got)
	}
	if err := os.WriteFile(p, []byte("not-a-number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readEphemeralFloor(); got != 32768 {
		t.Errorf("an unreadable range read as %d, want the stock floor", got)
	}
	ephemeralRangePath = filepath.Join(dir, "absent")
	if got := readEphemeralFloor(); got != 32768 {
		t.Errorf("a missing sysctl read as %d, want the stock floor", got)
	}
}

// One departure excuses exactly ONE arrival. Without the claimed guard a
// second new bind would point at the same departure and suppress an absence
// nothing accounted for.
func TestOneDepartureExcusesOnlyOneReAddressing(t *testing.T) {
	was, _ := baselineFromListeners([]listenSocket{sock("tcp", "10.0.0.5", 8080, "app", 5)})
	now, _ := baselineFromListeners([]listenSocket{
		sock("tcp", "10.0.0.9", 8080, "app", 5),
		sock("tcp", "10.0.0.10", 8080, "app", 6),
	})
	var readdressed, plain int
	for _, e := range deltaCompare(was, liveList(now)) {
		if e.Kind != deltaListenerNew {
			continue
		}
		if e.Reason == deltaReasonAddressMoved {
			readdressed++
		} else {
			plain++
		}
	}
	if readdressed != 1 || plain != 1 {
		t.Fatalf("one departure excused %d arrivals (and %d were genuinely new) — want 1 and 1",
			readdressed, plain)
	}
}

// `%h` was substituted before `%%` was collapsed, so `%%h/.ssh/ak`
// expanded to `/home/erin/%/home/erin/.ssh/ak` — a path that does not exist,
// which reads as ENOENT, which reads as "this account has no keys". And `%U`
// was not a token at all.
func TestTheSshdTokensExpandInTheRightOrder(t *testing.T) {
	for _, c := range []struct{ pattern, want string }{
		{"%h/.ssh/ak", "/home/erin/.ssh/ak"},
		{"/etc/ssh/keys/%u", "/etc/ssh/keys/erin"},
		{"/etc/ssh/keys/%U", "/etc/ssh/keys/1000"},
		{"%%h/.ssh/ak", "/home/erin/%h/.ssh/ak"},
		{"/etc/%%/%u", "/etc/%/erin"},
		// THE CASES THAT DISCRIMINATE THE ORDER, and the first version had none
		// — so a mutation swapping %% back after the other tokens left the suite
		// green. `%%h` gives the same answer either way; `%%u` does not,
		// because collapse-last reads the `%u` at index 1 and yields `%erin`
		// where sshd means the literal `%u`.
		{"%%u", "/home/erin/%u"},
		{"/etc/ssh/%%u/keys", "/etc/ssh/%u/keys"},
	} {
		if got := authorizedKeysPath(c.pattern, "/home/erin", "erin", "1000"); got != c.want {
			t.Errorf("%q expanded to %q, want %q", c.pattern, got, c.want)
		}
	}
}

// THE STORM COUNTER MEASURED SOMETHING OTHER THAN WHAT IT SAYS.
//
// The hold was taken under deltaHoldKey and released under ev.FP. For a process
// those are the same string, so nothing showed; for a listener they differ, so
// the hold entry was never released by name and settleHeld swept it as
// something that came and went. A listener STILL OPEN and being reported as a
// finding in the same breath also bumped ShortLived — a running total no report
// resets, which rides the heartbeat as short_lived and so drifts upward
// permanently on a developer's machine.
//
// The process half is the control: both classes must behave identically here,
// because nothing about "did this come and go" depends on what kind of thing it
// is.
func TestAThingStillPresentIsNotCountedAsHavingComeAndGone(t *testing.T) {
	lis, _ := baselineFromListeners([]listenSocket{sock("tcp", "127.0.0.1", 41579, "svc", 7)})
	cases := []struct {
		what string
		ev   deltaEvent
	}{
		{"listener", deltaEvent{Kind: deltaListenerNew, Entry: lis[0], PIDs: []int{7}}},
		{"process", deltaEvent{Kind: deltaProcNew, FP: "fp-proc",
			Entry: procEntry("d", "root", "unit", "shape"), PIDs: []int{7}}},
	}
	for _, c := range cases {
		st := freshState(t)
		now := time.Now()
		// Sockets true and this pid not listening: the process rule refuses to
		// fire where it cannot check its own exemption, which is its own test.
		young := deltaNoise{Self: 1, Sockets: true, Listening: map[int]bool{},
			Age: func(int) (time.Duration, bool) { return time.Second, true }}
		// Pass 1: young, so held.
		if f, _ := deltaFilter([]deltaEvent{c.ev}, young, st, now); len(f) != 0 {
			t.Fatalf("%s: reported on the first pass", c.what)
		}
		// Pass 2: it survived, so it is a finding — and it did NOT come and go.
		old := deltaNoise{Self: 1, Sockets: true, Listening: map[int]bool{},
			Age: func(int) (time.Duration, bool) { return time.Hour, true }}
		f, _ := deltaFilter([]deltaEvent{c.ev}, old, st, now.Add(deltaRefreshEvery))
		if len(f) != 1 {
			t.Fatalf("%s: a survivor was not reported: %d findings", c.what, len(f))
		}
		if st.settledThisPass != 0 || st.ShortLived != 0 {
			t.Errorf("%s: still present and reported, yet counted as having come and gone "+
				"(settledThisPass=%d ShortLived=%d)", c.what, st.settledThisPass, st.ShortLived)
		}
	}
}
