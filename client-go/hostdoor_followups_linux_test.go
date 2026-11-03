//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// windowBox is a pairing box whose `pair --open` runs with machine authority
// (held) and no organisation's policy, in the given mode.
func windowBox(t *testing.T, networked, held bool) {
	t.Helper()
	pairingBox(t)
	prev := machineAuthorityHeld
	machineAuthorityHeld = func() bool { return true }
	t.Cleanup(func() { machineAuthorityHeld = prev })
	withPolicy(t, nil)
	if networked {
		if err := setBoxMode(modeNetworked); err != nil {
			t.Fatal(err)
		}
	}
	machineAuthorityHeld = func() bool { return held }
}

// pairThroughWindow opens a window on a free port, pairs h's Host through it,
// and waits for `pair --open` to finish. h is made for that port.
func pairThroughWindow(t *testing.T, ca *testCA, handle, name string) (windowDoneReq, string) {
	t.Helper()
	addr := freeDoorAddr(t)
	code, out, res := openWindowFor(t, addr)
	h := newStandinHost(t, ca, handle, name, addr)
	done, err := h.pair(formatWindowCode(code))
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, pairingAuditText(t))
	}
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("pair --open: %v\n%s", err, out.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("pair --open never ended")
	}
	return done, out.String()
}

// 1. A server paired through `pair --open`, by someone with machine
// authority, on a machine nobody is in charge of, has that Host in charge:
// the anchor, the existing mechanism. A local machine is made networked for
// it (an anchor is a networked machine's). The rules before it still win: a
// Host on this machine, an organisation's policy naming another Host. Nobody
// without machine authority puts anyone in charge, and a local machine that
// already serves a Host the person said yes to keeps serving it.
//
// MUTATION: windowCommit calls anchorAfterPair instead of anchorAfterWindow.
// RESULT: red (local, and networked beside another pairing: no anchor).
// MUTATION: drop the sameMachineHost check in anchorAfterWindow. RESULT: red.
// MUTATION: drop the local-mode active check. RESULT: red.
// MUTATION: anchorAfterWindow ignores openerAuthority. RESULT: red.
func TestAServerPairedThroughTheWindowHasThatHostInCharge(t *testing.T) {
	const name = "home201721e4.cseries.localhost"
	t.Run("local machine, nobody in charge: networked, anchored, active", func(t *testing.T) {
		windowBox(t, false, true)
		done, out := pairThroughWindow(t, newTestCA(t, "home CA"), "home", name)
		if done.State != pairingActive {
			t.Fatalf("done: %+v", done)
		}
		if a := currentAnchor(); a == nil || a.AnchorHost != name {
			t.Fatalf("anchor = %+v, want %s", a, name)
		}
		if boxMode() != modeNetworked {
			t.Fatalf("mode %s: a machine with an anchor is networked", boxMode())
		}
		if !strings.Contains(out, name+" is now the Host in charge of this machine") || !strings.Contains(out, "pair --open") {
			t.Fatalf("the person is not told who is in charge:\n%s", out)
		}
		if a := pairingAuditText(t); !strings.Contains(a, `"op":"anchor_take"`) {
			t.Fatalf("no anchor_take in the audit:\n%s", a)
		}
	})
	t.Run("networked, unanchored, another pairing already there: anchored, the other waits", func(t *testing.T) {
		windowBox(t, true, true)
		writePairing(t, tRemote)
		_, _ = pairThroughWindow(t, newTestCA(t, "home CA"), "home", name)
		if a := currentAnchor(); a == nil || a.AnchorHost != name {
			t.Fatalf("anchor = %+v, want %s", a, name)
		}
		if got := loadState(t, name); got != pairingActive {
			t.Fatalf("the anchor never waits on itself: %q", got)
		}
		if got := loadState(t, tRemote); got != pairingPending {
			t.Fatalf("the other Host is %q, want pending (waiting for %s)", got, name)
		}
	})
	t.Run("a Host on this machine is paired: it stays the one in charge", func(t *testing.T) {
		windowBox(t, true, true)
		writeTCPPairing(t, tLocal2, "127.0.0.1:8811", pairingPending)
		_, _ = pairThroughWindow(t, newTestCA(t, "home CA"), "home", name)
		if a := currentAnchor(); a != nil {
			t.Fatalf("a Host on this machine lost the machine to the window's Host: anchor %+v", a)
		}
	})
	t.Run("an organisation's policy names another Host: it waits for that one", func(t *testing.T) {
		windowBox(t, true, true)
		withPolicy(t, &anchorPolicy{Host: "corp.host.privatae.ai", Source: "test policy"})
		done, _ := pairThroughWindow(t, newTestCA(t, "home CA"), "home", name)
		if a := currentAnchor(); a != nil {
			t.Fatalf("anchor %+v against the policy", a)
		}
		if done.State != pairingPending || done.AdmittedBy != "corp.host.privatae.ai" {
			t.Fatalf("done: %+v, want pending for the Host the policy names", done)
		}
	})
	t.Run("an organisation's policy names this Host: in charge, on a local machine too", func(t *testing.T) {
		windowBox(t, false, true)
		withPolicy(t, &anchorPolicy{Host: name, Source: "test policy"})
		writeTCPPairing(t, tLocal2, "127.0.0.1:8811", pairingRevoked)
		_, _ = pairThroughWindow(t, newTestCA(t, "home CA"), "home", name)
		if a := currentAnchor(); a == nil || a.AnchorHost != name {
			t.Fatalf("anchor = %+v, want %s (the policy names it)", a, name)
		}
	})
	t.Run("no machine authority: nobody is put in charge, the mode is left", func(t *testing.T) {
		windowBox(t, false, false)
		_, _ = pairThroughWindow(t, newTestCA(t, "home CA"), "home", name)
		if a := currentAnchor(); a != nil || boxMode() != modeLocal {
			t.Fatalf("without authority: anchor %+v, mode %s", a, boxMode())
		}
	})
	t.Run("opened without machine authority, committed by a door that has it: nobody in charge", func(t *testing.T) {
		windowBox(t, false, true)
		cfg := Config{HostName: name, State: ""}
		if took, err := anchorAfterWindow(&cfg, []*Config{&cfg}, false); took.Taken || err != nil || currentAnchor() != nil {
			t.Fatalf("a window opened without authority put %s in charge: %+v %v", name, took, err)
		}
	})
	t.Run("a local machine already serving another Host: it keeps serving it", func(t *testing.T) {
		windowBox(t, false, true)
		writePairing(t, tRemote)
		_, _ = pairThroughWindow(t, newTestCA(t, "home CA"), "home", name)
		if a := currentAnchor(); a != nil || boxMode() != modeLocal {
			t.Fatalf("anchor %+v, mode %s: the Host already served here would wait", a, boxMode())
		}
		if got := loadState(t, tRemote); got == pairingPending {
			t.Fatal("the Host already served here was left waiting")
		}
	})
}

// 2. The same Host pairing the same server again, through a fresh window,
// replaces its pairing: no `unpair` first. The same CA is the same Host,
// whatever handle it gives (a C-Series Host's handle is "home" while its name
// carries an id). Its state, the anchor and its grants are kept, and the old
// credentials are gone.
//
// MUTATION: drop the doorPairingWithCA lookup in windowCommit. RESULT: red,
// "this Host is already paired with this server as ...".
func TestTheSameHostPairingAgainReplacesItsPairing(t *testing.T) {
	const name = "home201721e4.cseries.localhost"
	windowBox(t, true, true)
	ca := newTestCA(t, "home CA")
	_, _ = pairThroughWindow(t, ca, "home", name)
	if a := currentAnchor(); a == nil || a.AnchorHost != name {
		t.Fatalf("first pairing: anchor %+v", a)
	}
	before, _ := pairingNamed(t, name)
	gp, err := pairingGrantPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gp, []byte(`{"kept":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	done, out := pairThroughWindow(t, ca, "home", name)
	if done.State != pairingActive || done.HostName != name {
		t.Fatalf("pairing again: %+v\n%s", done, out)
	}
	after, all := pairingNamed(t, name)
	if len(all) != 1 {
		t.Fatalf("%d pairings after pairing again, want the one", len(all))
	}
	if after.OperatorCert == before.OperatorCert || after.OperatorKey == before.OperatorKey || after.WGPrivateKey == before.WGPrivateKey {
		t.Fatal("the old credentials were kept")
	}
	if after.ListenAddr != before.ListenAddr || after.FirstSeen != before.FirstSeen || after.State != before.State {
		t.Fatalf("the pairing was not kept in place: %+v -> %+v", before, after)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != name {
		t.Fatalf("the anchor was not kept: %+v", a)
	}
	if b, err := os.ReadFile(gp); err != nil || string(b) != `{"kept":true}` {
		t.Fatalf("the grant was not kept: %q %v", b, err)
	}

	// Another Host (another CA) with the same handle is never this one.
	done, err = func() (windowDoneReq, error) {
		addr := freeDoorAddr(t)
		code, _, res := openWindowFor(t, addr)
		h := newStandinHost(t, newTestCA(t, "another CA"), "home", name, addr)
		d, err := h.pair(formatWindowCode(code))
		<-res
		return d, err
	}()
	if err != nil || done.State != "refused" || !strings.Contains(done.Error, "different Host") {
		t.Fatalf("another Host of the same name: %+v %v", done, err)
	}
	if c, _ := pairingNamed(t, name); c.Bearer != after.Bearer {
		t.Fatal("another Host's pairing replaced this one's")
	}
}

// The same Host paired again under a new name (same CA) stays in charge under
// that name: the anchor follows it, its pinned key kept.
//
// MUTATION: drop carryAnchorToNewName from windowCommit. RESULT: red.
func TestTheAnchorFollowsItsHostToANewName(t *testing.T) {
	windowBox(t, true, true)
	ca := newTestCA(t, "home CA")
	_, _ = pairThroughWindow(t, ca, "home", "home1.cseries.localhost")
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := pinAnchorVerifyKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	f, _ := loadAnchorFile()
	pin := f.VerifyPubkey
	_, _ = pairThroughWindow(t, ca, "home", "home2.cseries.localhost")
	all, _ := loadPairings()
	if len(all) != 1 || all[0].HostName != "home2.cseries.localhost" {
		t.Fatalf("pairings: %v", hostNames(all))
	}
	f, _ = loadAnchorFile()
	if a := currentAnchor(); a == nil || a.AnchorHost != "home2.cseries.localhost" || f.VerifyPubkey != pin || pin == "" {
		t.Fatalf("anchor %+v (pin kept: %v)", a, f != nil && f.VerifyPubkey == pin)
	}
}

// The anchor moves only with machine authority, as every other anchor write
// (claim-anchor --repin's wall): a process without it leaves anchor.json as
// it is.
//
// MUTATION: drop the machineAuthorityHeld check in carryAnchorToNewName.
// RESULT: red, the anchor names the new name.
func TestTheAnchorMovesToANewNameOnlyWithMachineAuthority(t *testing.T) {
	windowBox(t, true, true)
	ca := newTestCA(t, "home CA")
	_, _ = pairThroughWindow(t, ca, "home", "home1.cseries.localhost")
	if a := currentAnchor(); a == nil || a.AnchorHost != "home1.cseries.localhost" {
		t.Fatalf("first pairing: anchor %+v", a)
	}
	machineAuthorityHeld = func() bool { return false }
	_, _ = pairThroughWindow(t, ca, "home", "home2.cseries.localhost")
	if a := currentAnchor(); a == nil || a.AnchorHost != "home1.cseries.localhost" {
		t.Fatalf("without machine authority the anchor was rewritten: %+v", a)
	}
}

// 3. Right after `unpair` the running bastion still holds the door's port
// until it sees the pairing gone (a supervision period). `pair --open` waits
// for it to let go instead of failing "address already in use".
//
// MUTATION: drop the awaitDoorReleased call in cmdPairOpen. RESULT: red.
func TestPairOpenWaitsForTheRunningBastionToLetGoOfThePort(t *testing.T) {
	pairingBox(t)
	prevRunning, prevWait := pairDaemonRunning, doorReleaseWait
	pairDaemonRunning = func() bool { return true }
	doorReleaseWait = 10 * time.Second
	t.Cleanup(func() { pairDaemonRunning, doorReleaseWait = prevRunning, prevWait })
	addr := freeDoorAddr(t)
	held, err := listenDoor(addr) // the running bastion's door, its pairing just removed
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(1500*time.Millisecond, func() { _ = held.Close() })
	code, out, res := openWindowFor(t, addr)
	if !strings.Contains(out.String(), "waiting for it to let go") {
		t.Fatalf("the person is not told why it waits:\n%s", out.String())
	}
	h := newStandinHost(t, newTestCA(t, "home CA"), "home", "home.cseries.localhost", addr)
	if done, err := h.pair(formatWindowCode(code)); err != nil || done.State != pairingActive {
		t.Fatalf("pair after the port was let go: %+v %v", done, err)
	}
	if err := <-res; err != nil {
		t.Fatalf("pair --open: %v\n%s", err, out.String())
	}

	// Another program that never lets go: it still fails, after the wait, and
	// says what to do.
	doorReleaseWait = 300 * time.Millisecond
	addr2 := freeDoorAddr(t)
	other, err := net.Listen("tcp", addr2)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	err = cmdPairOpen(addr2, &syncBuf{})
	if err == nil || !strings.Contains(err.Error(), "choose another with --port") {
		t.Fatalf("a port another program holds: %v", err)
	}
	if !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("not refused for the address in use: %v", err)
	}
}
