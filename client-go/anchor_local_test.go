//go:build !windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tLocal  = "home.cseries.localhost"
	tLocal2 = "second.cseries.localhost"
	tRemote = "remote.host.privatae.ai"
)

// localBox is a networked box with machine authority in a temp config dir.
func localBox(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	prev := machineAuthorityHeld
	machineAuthorityHeld = func() bool { return true }
	t.Cleanup(func() { machineAuthorityHeld = prev })
	withPolicy(t, nil)
	if err := setBoxMode(modeNetworked); err != nil {
		t.Fatal(err)
	}
}

func withPolicy(t *testing.T, p *anchorPolicy) {
	t.Helper()
	prev := readAnchorPolicy
	readAnchorPolicy = func() *anchorPolicy {
		if p == nil {
			return nil
		}
		c := *p
		return &c
	}
	t.Cleanup(func() { readAnchorPolicy = prev })
}

// writeTCPPairing is a Host reached on a lane port, as pair_tcp.go writes it.
func writeTCPPairing(t *testing.T, host, lane, state string) {
	t.Helper()
	pd, _ := pairingsDir()
	// Its control port is one nothing listens on, whatever runs on the machine
	// running the suite (a bastion of its own answers on 7878).
	b, _ := json.Marshal(Config{HostName: host, Transport: transportTCP, LaneAddr: lane, WGPrivateKey: "k", State: state,
		ListenAddr: "127.0.0.1:1"})
	if err := os.WriteFile(filepath.Join(pd, host+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pairingNamed(t *testing.T, host string) (*Config, []*Config) {
	t.Helper()
	all, err := loadPairings()
	if err != nil {
		t.Fatal(err)
	}
	c := pairingFor(all, host)
	if c == nil {
		t.Fatalf("%s not paired", host)
	}
	return c, all
}

func auditLines(t *testing.T) string {
	t.Helper()
	d, _ := configDir()
	b, _ := os.ReadFile(filepath.Join(d, "pairing_audit.jsonl"))
	return string(b)
}

// What "on this machine" is: a unix socket, or a lane port on loopback. A LAN
// address, the relay's tunnel, and a Host's own name are not.
//
// MUTATION: return true for every tcp pairing in sameMachineHost. RESULT: red.
func TestSameMachineIsASocketOrALoopbackLane(t *testing.T) {
	for _, c := range []struct {
		cfg  Config
		want bool
	}{
		{Config{Transport: transportUnix, LaneSocket: "/run/h/lane.sock"}, true},
		{Config{Transport: transportTCP, LaneAddr: "127.0.0.1:8811"}, true},
		{Config{Transport: transportTCP, LaneAddr: "127.3.4.5:8811"}, true},
		{Config{Transport: transportTCP, LaneAddr: "[::1]:8811"}, true},
		{Config{Transport: transportTCP, LaneAddr: "localhost:8811"}, true},
		{Config{Transport: transportTCP, LaneAddr: "10.0.2.2:28811"}, false},
		{Config{Transport: transportTCP, LaneAddr: "192.168.1.20:8811"}, false},
		{Config{Transport: transportTCP, LaneAddr: "home.cseries.localhost:8811"}, false},
		{Config{HostName: "x.cseries.localhost", BastionTunnelIP: "fd12:3456::a:1"}, false},
	} {
		if got := sameMachineHost(&c.cfg); got != c.want {
			t.Errorf("%+v: same machine = %v, want %v", c.cfg, got, c.want)
		}
	}
}

// The S0 order the other way round: the machine was anchored to a remote Host,
// then a Host on this machine is paired with machine authority. It takes the
// anchor; the remote one becomes an ordinary pairing waiting for it, is told
// on its beat, and the audit says so.
//
// MUTATION: drop the sameMachineHost case from anchorAfterPair. RESULT: red.
// Leave the replaced anchor active in takeAnchor. RESULT: red.
func TestAHostOnThisMachineTakesTheAnchorFromARemoteOne(t *testing.T) {
	localBox(t)
	writePairing(t, tRemote)
	if err := writeAnchor("the owner", tRemote); err != nil {
		t.Fatal(err)
	}
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", pairingPending)
	cfg, all := pairingNamed(t, tLocal)
	took, err := anchorAfterPair(cfg, all)
	if err != nil || !took.Taken || took.Replaced != tRemote {
		t.Fatalf("a Host on this machine must take the anchor: %+v %v", took, err)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != tLocal || a.Owner != "the owner" {
		t.Fatalf("anchor = %+v", a)
	}
	if got := loadState(t, tLocal); got != pairingActive {
		t.Errorf("the new anchor waits on itself: %q", got)
	}
	if got := loadState(t, tRemote); got != pairingPending {
		t.Errorf("the replaced anchor is %q, want pending", got)
	}
	a := auditLines(t)
	if !strings.Contains(a, `"op":"anchor_take"`) || !strings.Contains(a, "it replaced "+tRemote) ||
		!strings.Contains(a, "waits for "+tLocal+" to admit it") {
		t.Errorf("the audit does not record it:\n%s", a)
	}
	note := anchorReplacedNote(tRemote)
	if note == nil || note["by"] != tLocal || note["why"] != anchorWhyLocal {
		t.Fatalf("the replaced anchor's beat is not told: %v", note)
	}
	if e := pairingEnforcing(tRemote); e["anchor_replaced"] == nil || e["waiting_for"] != tLocal {
		t.Errorf("the enforcing report of the replaced anchor: %v", e)
	}
	if anchorReplacedNote(tLocal) != nil {
		t.Error("the new anchor is told it was replaced")
	}
	var former *pairingEntry
	for _, e := range pairingsReport() {
		if e.HostName == tRemote {
			e := e
			former = &e
		}
	}
	if former == nil || former.Origin != pairingOriginFormerAnchor || former.WaitingFor != tLocal || former.Transport != "tunnel" || former.SameMachine {
		t.Errorf("the anchor's report of the former anchor: %+v", former)
	}
}

// A networked box with no anchor and a remote Host already serving: the Host on
// this machine takes the anchor, and the remote one waits for it.
func TestAHostOnThisMachineAnchorsABoxThatAlreadyServesARemoteHost(t *testing.T) {
	localBox(t)
	writePairing(t, tRemote)
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", "")
	cfg, all := pairingNamed(t, tLocal)
	took, err := anchorAfterPair(cfg, all)
	if err != nil || !took.Taken || took.Replaced != "" || strings.Join(took.Waiting, ",") != tRemote {
		t.Fatalf("%+v %v", took, err)
	}
	if got := loadState(t, tRemote); got != pairingPending {
		t.Errorf("the remote Host holds no grant from the new anchor and must wait: %q", got)
	}
}

// Never "whichever paired first": a remote Host never takes the anchor from a
// Host on this machine, and a second Host on this machine does not either.
//
// MUTATION: drop the "a Host on this machine already holds it" return.
// RESULT: red.
func TestTheAnchorOnThisMachineIsNotReplaced(t *testing.T) {
	for _, newcomer := range []struct{ host, lane string }{{tRemote, "10.0.2.2:28811"}, {tLocal2, "127.0.0.1:9811"}} {
		t.Run(newcomer.host, func(t *testing.T) {
			localBox(t)
			writeTCPPairing(t, tLocal, "127.0.0.1:8811", "")
			if err := writeAnchor("the owner", tLocal); err != nil {
				t.Fatal(err)
			}
			writeTCPPairing(t, newcomer.host, newcomer.lane, pairingPending)
			cfg, all := pairingNamed(t, newcomer.host)
			if took, err := anchorAfterPair(cfg, all); took.Taken || err != nil {
				t.Fatalf("%s took the anchor: %+v %v", newcomer.host, took, err)
			}
			if a := currentAnchor(); a == nil || a.AnchorHost != tLocal {
				t.Fatalf("anchor moved: %+v", a)
			}
			if got := loadState(t, newcomer.host); got != pairingPending {
				t.Errorf("state %q", got)
			}
		})
	}
}

// Without machine authority, or on a local machine, nothing is anchored.
func TestTakingTheAnchorNeedsANetworkedMachineAndItsAuthority(t *testing.T) {
	localBox(t)
	writePairing(t, tRemote)
	if err := writeAnchor("the owner", tRemote); err != nil {
		t.Fatal(err)
	}
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", pairingPending)
	machineAuthorityHeld = func() bool { return false }
	cfg, all := pairingNamed(t, tLocal)
	if took, _ := anchorAfterPair(cfg, all); took.Taken {
		t.Fatal("anchored without machine authority")
	}
	machineAuthorityHeld = func() bool { return true }
	localBox(t)
	if err := setBoxMode(modeLocal); err != nil {
		t.Fatal(err)
	}
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", "")
	cfg, all = pairingNamed(t, tLocal)
	if took, _ := anchorAfterPair(cfg, all); took.Taken || currentAnchor() != nil {
		t.Fatal("anchored a local machine")
	}
}

// An organisation's policy wins over the Host on this machine: the Host it
// names takes the anchor, from a Host on this machine too; any other Host
// waits for it; and claim-anchor for any other Host is refused in words that
// say an organisation manages the machine.
//
// MUTATION: check sameMachineHost before the policy in anchorAfterPair.
// RESULT: red. Drop the policy refusal in claimAnchorByRule. RESULT: red.
func TestAnOrganisationsPolicyNamesTheHostInCharge(t *testing.T) {
	localBox(t)
	withPolicy(t, &anchorPolicy{Host: tRemote, Source: "HKLM\\SOFTWARE\\Policies\\Privatae\\Bastion AnchorHost"})

	// Unanchored: the Host on this machine waits for the one the policy names.
	if _, state, err := pairPrecheckState(false, handleOf(tLocal)); err != nil || state != pairingPending {
		t.Fatalf("a Host the policy does not name must wait: %q %v", state, err)
	}
	if _, state, _ := pairPrecheckState(false, handleOf(tRemote)); state != "" {
		t.Fatalf("the Host the policy names waits for nobody: %q", state)
	}
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", pairingPending)
	cfg, all := pairingNamed(t, tLocal)
	if took, _ := anchorAfterPair(cfg, all); took.Taken {
		t.Fatal("the Host on this machine took the anchor against the organisation's policy")
	}
	if got := admitter(); got != tRemote {
		t.Errorf("a pending pairing waits for %q, want the policy's Host", got)
	}
	err := cmdClaimAnchor("", false, "", tLocal)
	if err == nil || !strings.Contains(err.Error(), "an organisation manages this machine") ||
		!strings.Contains(err.Error(), "names "+tRemote) {
		t.Fatalf("claim-anchor for another Host: %v", err)
	}
	if err := cmdClaimAnchor("", false, "", ""); err == nil || !strings.Contains(err.Error(), "not paired with this machine yet") {
		t.Fatalf("claim-anchor before the policy's Host is paired: %v", err)
	}

	// The policy's Host is paired: it takes the anchor, the other one waits.
	writePairingState(t, tRemote, "")
	cfg, all = pairingNamed(t, tRemote)
	took, err := anchorAfterPair(cfg, all)
	if err != nil || !took.Taken {
		t.Fatalf("the policy's Host must take the anchor: %+v %v", took, err)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != tRemote {
		t.Fatalf("anchor = %+v", a)
	}
	if !strings.Contains(auditLines(t), "an organisation's policy") {
		t.Errorf("the audit does not name the policy: %s", auditLines(t))
	}
	if err := cmdClaimAnchor("", true, "", tLocal); err == nil || !strings.Contains(err.Error(), "an organisation manages this machine") {
		t.Fatalf("claim-anchor --rotate to another Host: %v", err)
	}
}

// A policy deployed after a Host on this machine took the anchor: claim-anchor
// with no argument hands it to the Host the policy names, without --rotate.
func TestClaimAnchorFollowsAPolicyDeployedLater(t *testing.T) {
	localBox(t)
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", "")
	if err := writeAnchor("the owner", tLocal); err != nil {
		t.Fatal(err)
	}
	writePairingState(t, tRemote, pairingPending)
	withPolicy(t, &anchorPolicy{Host: handleOf(tRemote), Source: "/etc/privatae-bastion/policy.json anchor_host"})
	if err := cmdClaimAnchor("", false, "", ""); err != nil {
		t.Fatal(err)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != tRemote {
		t.Fatalf("anchor = %+v", a)
	}
	if got := loadState(t, tLocal); got != pairingPending {
		t.Errorf("the Host on this machine is %q, want waiting for the policy's Host", got)
	}
}

// claim-anchor with no argument on a box that serves a remote Host and a Host
// on this machine picks the one on this machine; naming the remote one is
// refused while a Host on this machine is paired.
//
// MUTATION: return false at the top of claimAnchorByRule's same-machine part.
// RESULT: red (the old "say which one" refusal).
func TestClaimAnchorPicksTheHostOnThisMachine(t *testing.T) {
	localBox(t)
	writePairing(t, tRemote)
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", "")
	if err := cmdClaimAnchor("", false, "", tRemote); err == nil || !strings.Contains(err.Error(), "runs on this machine and is the Host in charge") {
		t.Fatalf("naming the remote Host: %v", err)
	}
	if err := cmdClaimAnchor("", false, "", ""); err != nil {
		t.Fatal(err)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != tLocal {
		t.Fatalf("anchor = %+v", a)
	}
	if got := loadState(t, tRemote); got != pairingPending {
		t.Errorf("the remote Host is %q", got)
	}
}

// The replaced anchor's running beat is beaten once more before its lanes stop.
//
// MUTATION: drop the tellReplacedAnchor call in superviseOnce, or the
// tellReplacedAnchorsBeforeStop body. RESULT: red.
func TestTheReplacedAnchorIsToldOnALastBeat(t *testing.T) {
	localBox(t)
	writePairing(t, tRemote)
	if err := writeAnchor("the owner", tRemote); err != nil {
		t.Fatal(err)
	}
	writeTCPPairing(t, tLocal, "127.0.0.1:8811", pairingPending)
	remote, _ := pairingNamed(t, tRemote)
	cfg, all := pairingNamed(t, tLocal)
	if took, err := anchorAfterPair(cfg, all); err != nil || !took.Taken {
		t.Fatal(took, err)
	}
	var told any
	beat := func() { told = pairingEnforcing(tRemote)["anchor_replaced"] }
	_, unregister := registerRunBeat(tRemote, beat)
	defer unregister()
	done := make(chan struct{})
	close(done)
	supervisor.Lock()
	supervisor.runs = map[string]*pairingRun{tRemote: {cancel: func() {}, done: done, cfg: remote}}
	supervisor.Unlock()
	t.Cleanup(func() { supervisor.Lock(); supervisor.runs = nil; supervisor.Unlock() })
	// The daemon stopping first (an installer's Restart-Service right after
	// `pair`) tells it as well.
	tellReplacedAnchorsBeforeStop()
	if told == nil {
		t.Fatal("the daemon stopped without a last beat to the replaced anchor")
	}
	told = nil
	superviseOnce()
	if told == nil {
		t.Fatal("the replaced anchor was stopped without a last beat that says so")
	}
	// Admitted again, it is no longer told.
	clearAnchorReplacedFor(tRemote)
	if anchorReplacedNote(tRemote) != nil {
		t.Error("an admitted former anchor still hears it was replaced")
	}
}

// One pairing's fatal error stops that pairing alone: nothing reaches the
// daemon's fatal channel, the failure is recorded for status, and it is tried
// again after a pause.
//
// MUTATION: send the error to supervisor.errc again. RESULT: red.
func TestOnePairingsFatalErrorStopsOnlyThatPairing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	freshLocalEvents(t)
	// A Host over TCP whose CA does not read: runUnixPairing fails at once.
	bad := &Config{HostName: "broken.example.test", Transport: transportTCP, LaneAddr: "127.0.0.1:1", Bearer: "b",
		CACert: "not a certificate", ListenAddr: "127.0.0.1:0"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 4)
	supervisor.Lock()
	prevCtx, prevErrc, prevRuns := supervisor.ctx, supervisor.errc, supervisor.runs
	supervisor.ctx, supervisor.errc, supervisor.runs = ctx, errc, nil
	supervisor.Unlock()
	t.Cleanup(func() {
		supervisor.Lock()
		supervisor.ctx, supervisor.errc, supervisor.runs = prevCtx, prevErrc, prevRuns
		supervisor.Unlock()
		pairingRecovered(bad.HostName)
	})
	if !startPairing(bad) {
		t.Fatal("not started")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := loadPairingFailures()[bad.HostName]; ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-errc:
		t.Fatalf("one pairing's error went to the whole daemon: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	f, ok := loadPairingFailures()[bad.HostName]
	if !ok || f.Error == "" || f.Tries != 1 {
		t.Fatalf("the failure is not recorded: %+v", f)
	}
	if pairingRetryDue(bad.HostName) {
		t.Error("tried again with no pause")
	}
	if retryPause(1) != supervisePeriod || retryPause(3) != 4*supervisePeriod || retryPause(40) != retryMaxPause {
		t.Errorf("pauses %v %v %v", retryPause(1), retryPause(3), retryPause(40))
	}
	found := false
	for _, e := range localEventsNewestFirst() {
		found = found || strings.Contains(e.Text, "The other Hosts go on being served")
	}
	if !found {
		t.Error("the machine's events do not say so")
	}
}

// The Windows service manager's stop is logged as its own, not the tray's.
// The service handler cannot run here, so its source is read.
//
// MUTATION: call requestShutdown() in sysservice_windows.go. RESULT: red.
func TestTheServiceManagersStopIsNotLoggedAsTheTrays(t *testing.T) {
	src, err := os.ReadFile("sysservice_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "requestShutdownFor(shutdownFromService)") || strings.Contains(string(src), "requestShutdown()") {
		t.Error("the service's stop does not name the service manager")
	}
	run, _ := os.ReadFile("run.go")
	if !strings.Contains(string(run), `"\nstopping — " + shutdownWhy`) {
		t.Error("cmdRun does not log who asked it to stop")
	}
	if strings.Contains(shutdownFromService, "tray") {
		t.Error(shutdownFromService)
	}
}

// Over a network logon (ssh) the service cannot be queried for its process id;
// the ask pipe is then checked by its owner, SYSTEM, instead of refused.
//
// MUTATION: drop the ERROR_ACCESS_DENIED branch. RESULT: red.
func TestTheAskPipeIsCheckedByItsOwnerWhenTheServiceCannotBeQueried(t *testing.T) {
	src, err := os.ReadFile("approvalpipe_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "func pipeServerIsService(")
	if i < 0 {
		t.Fatal("no pipeServerIsService")
	}
	body := s[i : i+strings.Index(s[i:], "\n}\n")]
	if !strings.Contains(body, "errors.Is(err, windows.ERROR_ACCESS_DENIED)") || !strings.Contains(body, "return pipeOwnedBySystem(h)") {
		t.Error("a network logon is still refused")
	}
	if !strings.Contains(s, "!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)") {
		t.Error("the owner check does not require LocalSystem or the Administrators group")
	}
}

// The last beat to a replaced anchor (lastBeat, from superviseOnce's
// goroutine) never runs beside the run's own beat or path failover: both write
// cfg.Endpoints and the WG device, and before lastBeat a run's beats all came
// from its one loop.
func TestTheLastBeatNeverRunsBesideTheRunsOwnBeat(t *testing.T) {
	const host = "serial-beat.host.privatae.ai"
	var mu sync.Mutex
	in, most := 0, 0
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	beat := func() {
		mu.Lock()
		in++
		if in > most {
			most = in
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		in--
		mu.Unlock()
	}
	rb, unregister := registerRunBeat(host, beat)
	defer unregister()
	old := lastBeatWait
	lastBeatWait = 200 * time.Millisecond
	t.Cleanup(func() { lastBeatWait = old })

	loopDone := make(chan struct{})
	go func() { defer close(loopDone); rb.run() }() // the run's own beat, in flight
	<-entered
	failoverRan := make(chan struct{})
	go func() { rb.do(func() {}); close(failoverRan) }() // the tick's failover waits too
	if !lastBeat(host) {
		t.Fatal("lastBeat found no beat for a running pairing")
	}
	select {
	case <-entered:
		t.Fatal("the last beat ran beside the run's own beat")
	default:
	}
	select {
	case <-failoverRan:
		t.Fatal("path failover ran beside a beat")
	default:
	}
	close(release)
	<-loopDone
	<-failoverRan
	mu.Lock()
	defer mu.Unlock()
	if most != 1 {
		t.Fatalf("%d beats ran at once, want 1", most)
	}
}
