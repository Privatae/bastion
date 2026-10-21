//go:build !windows

// Uses setupBox / writePairingState / signTerms / grantTerms / driveOp from
// anchor_test.go, the session helpers from session_test.go and the service
// runtime stub from service_test.go, all unix-only.

package main

// The README's security model, driven through the code that enforces it:
// the tunnel forwards' accept path, the session lane's handler, the
// machine-authority gates and the management lane's allowlisted op. The
// tunnel here is an in-memory network stack and every upstream a loopback
// listener the test owns; nothing reaches the live machine's network, its
// services or its processes.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ── inside the tunnel ───────────────────────────────────────────────────────

// upstreamCounter is a listener standing in for the service a forward
// splices to. A connection arriving at it is the proof that the forward let
// a tunnel connection through.
type upstreamCounter struct {
	ln  net.Listener
	got chan struct{}
}

func newUpstream(t *testing.T, network, addr string) *upstreamCounter {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s here: %v", network, addr, err)
	}
	u := &upstreamCounter{ln: ln, got: make(chan struct{}, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.got <- struct{}{}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return u
}

// reached reports whether a connection arrived within d.
func (u *upstreamCounter) reached(d time.Duration) bool {
	select {
	case <-u.got:
		return true
	case <-time.After(d):
		return false
	}
}

// tunnelDial connects to port on the in-memory stack, retrying while the
// forward under test is still coming up. The connection is closed at once:
// the accept is what the forward's wall acts on.
func tunnelDial(t *testing.T, tnet *netstack.Net, gw netip.Addr, port int) {
	t.Helper()
	addr := net.JoinHostPort(gw.String(), fmt.Sprint(port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := tnet.DialContext(ctx, "tcp", addr)
		cancel()
		if err == nil {
			// Hold it open briefly so an allowed splice has a live peer.
			time.Sleep(50 * time.Millisecond)
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing listens on %s in the tunnel: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func grantMemberCaps(t *testing.T, priv ed25519.PrivateKey, caps ...string) {
	t.Helper()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, caps, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant %v: %d %s", caps, code, errOut)
	}
}

// Inside the tunnel, only gated listeners: each inference forward, driven
// through its real accept loop on a tunnel stack, passes a connection to its
// upstream only while the pairing holds the `inference` family, re-read on
// every accept.
func TestEachInferenceForwardAdmitsOnlyThePairingThatHoldsInference(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	grantMemberCaps(t, priv, "observe")

	ollama := newUpstream(t, "tcp", "127.0.0.1:0")
	llm := newUpstream(t, "tcp", "127.0.0.1:0")
	pii := newUpstream(t, "tcp", "127.0.0.1:0")
	t.Setenv("OLLAMA_ADDR", ollama.ln.Addr().String())
	t.Setenv("PRIVATAE_LLM_ADDR", llm.ln.Addr().String())
	t.Setenv("PRIVATAE_PII_ADDR", pii.ln.Addr().String())

	gw := netip.MustParseAddr("2001:db8::a:1")
	_, tnet, err := netstack.CreateNetTUN([]netip.Addr{gw}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go serveOllamaForward(ctx, tMember, tnet, gw)
	go serveLLMForward(ctx, tMember, tnet, gw)
	go servePIIForward(ctx, tMember, tnet, gw)

	lanes := []struct {
		name string
		port int
		up   *upstreamCounter
	}{{"ollama", 11434, ollama}, {"llm", llmForwardPort, llm}, {"pii", piiForwardPort, pii}}

	for _, l := range lanes {
		tunnelDial(t, tnet, gw, l.port)
		if l.up.reached(300 * time.Millisecond) {
			t.Errorf("%s forward: a pairing without the inference family reached the upstream", l.name)
		}
	}
	grantMemberCaps(t, priv, "observe", "inference")
	for _, l := range lanes {
		tunnelDial(t, tnet, gw, l.port)
		if !l.up.reached(3 * time.Second) {
			t.Errorf("%s forward: a pairing granted inference must reach the upstream, with no restart", l.name)
		}
	}
}

// A service slot port admits a connection only when BOTH walls pass: the
// pairing holds the `services` family, and a reach grant for that server
// names that host. Driven through serveServiceForwards' accept loop; the
// server's socket counts what gets through.
func TestTheServiceSlotAdmitsOnlyWithTheFamilyAndAReachGrant(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the slot forward pins the server's socket through /proc and is linux-only")
	}
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	grantMemberCaps(t, priv, "observe")

	f := stubServiceRuntime(t, "docker")
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	f.running["privatae-svc-forge"] = true
	rec, err := loadServiceRecord("forge")
	if err != nil {
		t.Fatal(err)
	}
	// The data dir's path is longer than a unix socket address may be, so the
	// server's socket is bound at a short path and moved into place: the
	// forward reaches it by inode through /proc (service_sock_linux.go), which
	// is exactly the path it takes on a real machine.
	data, _ := serviceDataDir("forge")
	short, err := os.MkdirTemp("", "svc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	server := newUpstream(t, "unix", filepath.Join(short, "s"))
	if err := os.Rename(filepath.Join(short, "s"), filepath.Join(data, "gitea.sock")); err != nil {
		t.Skipf("cannot move the socket into the data dir here: %v", err)
	}

	// The reach grant, signed and on disk the way service_grant_sync leaves it.
	dir := t.TempDir()
	_, rpriv, _ := ed25519.GenerateKey(nil)
	tc, sig := signedTerms(t, rpriv, reachTermsFor(tMember, "forge", 30))
	withReach := &dcnGrantFile{VerifyPubkey: base64.StdEncoding.EncodeToString(rpriv.Public().(ed25519.PublicKey)),
		Stores: map[string]dcnGrantRec{}, Reach: map[string]dcnGrantRec{"1": {TermsCanonical: tc, Signature: sig}}}
	noReach := &dcnGrantFile{VerifyPubkey: withReach.VerifyPubkey, Stores: map[string]dcnGrantRec{}, Reach: map[string]dcnGrantRec{}}
	if err := dcnSaveFile(dir, withReach); err != nil {
		t.Fatal(err)
	}

	gw := netip.MustParseAddr("2001:db8::a:1")
	_, tnet, err := netstack.CreateNetTUN([]netip.Addr{gw}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go serveServiceForwards(ctx, tMember, dir, tnet, gw)

	// A reach grant, but no services family: refused.
	tunnelDial(t, tnet, gw, rec.TunnelPort)
	if server.reached(300 * time.Millisecond) {
		t.Fatal("a pairing without the services family reached the server, reach grant or not")
	}
	// The family, but no reach grant for this server: refused.
	grantMemberCaps(t, priv, "observe", "services")
	if err := dcnSaveFile(dir, noReach); err != nil {
		t.Fatal(err)
	}
	tunnelDial(t, tnet, gw, rec.TunnelPort)
	if server.reached(300 * time.Millisecond) {
		t.Fatal("a pairing with no reach grant for this server reached it")
	}
	// Both: the connection goes through to the server's socket.
	if err := dcnSaveFile(dir, withReach); err != nil {
		t.Fatal(err)
	}
	tunnelDial(t, tnet, gw, rec.TunnelPort)
	if !server.reached(3 * time.Second) {
		t.Fatal("with the family and a reach grant the connection must reach the server")
	}
}

// ── the session lane, through handleSessionConn ────────────────────────────

// openSession opens one session through the handler and returns what came
// back: the fake shell echoes "Iping" as O "ping" when the session opened. It
// returns only after the handler has finished, so nothing the session writes
// (its transcript, its audit line) lands after the test's dirs are removed.
func openSession(t *testing.T, env sessionEnv, self string, spec sessionSpec) map[byte][]byte {
	t.Helper()
	done := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, first, err := c.ReadMessage()
		if err != nil {
			return
		}
		handleSessionConn(c, first, self, env)
	}))
	defer srv.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sendSpec(t, ws, spec)
	_ = ws.WriteMessage(websocket.BinaryMessage, []byte("Iping"))
	_ = ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := map[byte][]byte{}
	for {
		_, data, err := ws.ReadMessage()
		if err != nil || len(data) == 0 {
			break
		}
		got[data[0]] = append(got[data[0]], data[1:]...)
		if data[0] == 'X' || (data[0] == 'O' && strings.Contains(string(got['O']), "ping")) {
			break
		}
	}
	// The host hanging up ends an open session; wait for the handler to
	// write its last line and return.
	_ = ws.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the session handler did not finish after the host hung up")
	}
	return got
}

func opened(got map[byte][]byte) bool { return strings.Contains(string(got['O']), "ping") }

func refusedWith(got map[byte][]byte, words string) bool {
	return string(got['X']) == "126" && len(got['O']) == 0 && strings.Contains(string(got['E']), words)
}

// withSessionRoot makes the daemon read as root, or not, for the session
// lane's root wall only.
func withSessionRoot(t *testing.T, root bool) {
	t.Helper()
	old := sessionDaemonIsRoot
	sessionDaemonIsRoot = func() bool { return root }
	t.Cleanup(func() { sessionDaemonIsRoot = old })
}

// consoleApproval issues a one-use approval on this machine for purpose,
// with the factor enrolled here (the code a person types at the console).
func consoleApproval(t *testing.T, dcn, purpose string) string {
	t.Helper()
	raw, _ := b32decode(tSecret)
	code := hotp(raw, time.Now().Unix()/stepupPeriod)
	id, err := stepupIssueApproval(dcn, code, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A terminal: on an anchored machine a host other than the anchor needs the
// `session` family in its pairing grant. The handler refuses it before any
// approval is looked at, and the approval it carried is still good after.
func TestAMemberWithoutTheSessionFamilyGetsNoTerminal(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	grantMemberCaps(t, priv, "observe")
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	env.HostName = tMember
	withFake(t)
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	approval, err := deviceSign(mgmtOpPurpose(sessionOpOpen, env.Server, []string{"sess-member-1"}), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got := openSession(t, env, tMember, sessionSpec{Op: sessionOpOpen, SessionID: "sess-member-1", Approval: approval})
	if !refusedWith(got, "family 'session', not in this pairing's caps") {
		t.Fatalf("a member without the session family must be refused by the family wall: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
	if _, err := os.Stat(filepath.Join(env.CtxRoot, "sessions", "sess-member-1.log")); err == nil {
		t.Fatal("a refused terminal must leave no transcript")
	}
	grantMemberCaps(t, priv, "observe", "session")
	if got := openSession(t, env, tMember, sessionSpec{Op: sessionOpOpen, SessionID: "sess-member-1", Approval: approval}); !opened(got) {
		t.Fatalf("with the family granted the same approval must open the terminal: X=%q E=%q", got['X'], got['E'])
	}
}

// On an anchored machine each terminal needs an approval bound to that one
// session and used once.
func TestAnAnchoredTerminalApprovalOpensOneSessionOnce(t *testing.T) {
	setupBox(t)
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	env.HostName = tAnchor
	withFake(t)
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	approval, err := deviceSign(mgmtOpPurpose(sessionOpOpen, env.Server, []string{"sess-bound-A"}), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := openSession(t, env, tAnchor, sessionSpec{Op: sessionOpOpen, SessionID: "sess-bound-B", Approval: approval}); !refusedWith(got, "purpose mismatch") {
		t.Fatalf("an approval for one session must not open another: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
	if got := openSession(t, env, tAnchor, sessionSpec{Op: sessionOpOpen, SessionID: "sess-bound-A", Approval: approval}); !opened(got) {
		t.Fatalf("the approval must open the session it names: X=%q E=%q", got['X'], got['E'])
	}
	if got := openSession(t, env, tAnchor, sessionSpec{Op: sessionOpOpen, SessionID: "sess-bound-A", Approval: approval}); !refusedWith(got, "already used") {
		t.Fatalf("a spent approval must not open the session a second time: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
}

// A root terminal needs the bastion to run as root. Everything else in
// order — the factor enrolled here and a code entered for this session — a
// daemon that is not root refuses, and spends nothing: the same approval
// opens the session once the daemon is root.
func TestARootTerminalNeedsTheBastionToRunAsRoot(t *testing.T) {
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen, sessionOpRoot}, nil)
	enrollFactor(t, env.DcnDir)
	withFake(t)
	p, _ := purposeForSessionRoot(env.Server, "sess-root-euid")
	approval := consoleApproval(t, env.DcnDir, p)

	withSessionRoot(t, false)
	got := openSession(t, env, "", sessionSpec{Op: sessionOpRoot, SessionID: "sess-root-euid", Approval: approval})
	if !refusedWith(got, "needs the bastion to run as root") {
		t.Fatalf("a root terminal on a daemon that is not root must be refused for that reason: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
	withSessionRoot(t, true)
	if got := openSession(t, env, "", sessionSpec{Op: sessionOpRoot, SessionID: "sess-root-euid", Approval: approval}); !opened(got) {
		t.Fatalf("the same approval must open the root terminal on a root daemon: X=%q E=%q", got['X'], got['E'])
	}
}

// An approval device cannot approve a root terminal, with or without a
// factor enrolled here: root is approved with a code entered on this machine.
func TestADeviceCannotApproveARootTerminal(t *testing.T) {
	withSessionRoot(t, true)
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen, sessionOpRoot}, nil)
	withFake(t)
	uiTestConfigDir(t)
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	p, _ := purposeForSessionRoot(env.Server, "sess-root-dev1")
	dev, err := deviceSign(p, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := openSession(t, env, "", sessionSpec{Op: sessionOpRoot, SessionID: "sess-root-dev1", Approval: dev}); !refusedWith(got, "second factor enrolled on this machine") {
		t.Fatalf("with only a device pinned, root must be refused: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
	enrollFactor(t, env.DcnDir)
	if got := openSession(t, env, "", sessionSpec{Op: sessionOpRoot, SessionID: "sess-root-dev1", Approval: dev}); !refusedWith(got, "not from a device") {
		t.Fatalf("with a factor enrolled, a device approval must still not open root: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
}

// A root approval opens the one session it was entered for, once.
func TestARootApprovalOpensOneSessionOnce(t *testing.T) {
	withSessionRoot(t, true)
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen, sessionOpRoot}, nil)
	enrollFactor(t, env.DcnDir)
	withFake(t)
	p, _ := purposeForSessionRoot(env.Server, "sess-root-one")
	approval := consoleApproval(t, env.DcnDir, p)
	if got := openSession(t, env, "", sessionSpec{Op: sessionOpRoot, SessionID: "sess-root-two", Approval: approval}); !refusedWith(got, "purpose mismatch") {
		t.Fatalf("a root approval must not open another session: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
	if got := openSession(t, env, "", sessionSpec{Op: sessionOpRoot, SessionID: "sess-root-one", Approval: approval}); !opened(got) {
		t.Fatalf("the root approval must open its own session: X=%q E=%q", got['X'], got['E'])
	}
	if got := openSession(t, env, "", sessionSpec{Op: sessionOpRoot, SessionID: "sess-root-one", Approval: approval}); !refusedWith(got, "already used") {
		t.Fatalf("a spent root approval must not open anything again: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
}

// Grants are verified here: the key a session frame offers is pinned by the
// handler the first time, and a later frame offering another key is refused
// with the pin kept.
func TestTheSessionHandlerPinsTheOfferedKey(t *testing.T) {
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	env.DcnDir = t.TempDir() // no key pinned yet
	withFake(t)
	pub1, _, _ := ed25519.GenerateKey(nil)
	k1 := base64.StdEncoding.EncodeToString(pub1)
	if got := openSession(t, env, "", sessionSpec{Op: sessionOpOpen, SessionID: "sess-pin-one", VerifyPubkey: k1}); !opened(got) {
		t.Fatalf("the first key offered must open and pin: X=%q E=%q", got['X'], got['E'])
	}
	if f, err := dcnLoadFile(env.DcnDir); err != nil || f.VerifyPubkey != k1 {
		t.Fatalf("the handler must pin the offered key: %v %+v", err, f)
	}
	pub2, _, _ := ed25519.GenerateKey(nil)
	k2 := base64.StdEncoding.EncodeToString(pub2)
	if got := openSession(t, env, "", sessionSpec{Op: sessionOpOpen, SessionID: "sess-pin-two", VerifyPubkey: k2}); !refusedWith(got, "mismatch") {
		t.Fatalf("a different key must be refused: X=%q E=%q O=%q", got['X'], got['E'], got['O'])
	}
	if f, _ := dcnLoadFile(env.DcnDir); f.VerifyPubkey != k1 {
		t.Fatalf("a refused key must not replace the pin: %q", f.VerifyPubkey)
	}
}

// ── root only where there is no one else to ask ────────────────────────────

func withMachineAuthority(t *testing.T, held bool) {
	t.Helper()
	old := machineAuthorityHeld
	machineAuthorityHeld = func() bool { return held }
	t.Cleanup(func() { machineAuthorityHeld = old })
}

// Claiming ownership or the anchor, and turning a box networked, are
// refused without machine authority and write nothing; with it, each gets
// past that wall. Both halves run whatever euid the suite runs under.
func TestMachineWideFactsNeedMachineAuthority(t *testing.T) {
	freshBox := func(t *testing.T) {
		t.Helper()
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	}
	t.Run("claim-owner", func(t *testing.T) {
		freshBox(t)
		withMachineAuthority(t, false)
		if err := cmdClaimOwner("Acme IT"); err == nil || !strings.Contains(err.Error(), "machine authority") {
			t.Fatalf("claim-owner without machine authority must be refused: %v", err)
		}
		if currentOwnerClaim() != nil {
			t.Fatal("a refused claim-owner wrote a claim")
		}
		withMachineAuthority(t, true)
		if err := cmdClaimOwner("Acme IT"); err != nil {
			t.Fatalf("claim-owner with machine authority: %v", err)
		}
		if c := currentOwnerClaim(); c == nil || c.Owner != "Acme IT" {
			t.Fatalf("the claim was not written: %+v", c)
		}
	})
	t.Run("set-mode networked", func(t *testing.T) {
		freshBox(t)
		withMachineAuthority(t, false)
		if err := setBoxMode(modeNetworked); err == nil || !strings.Contains(err.Error(), "machine authority") {
			t.Fatalf("set-mode networked without machine authority must be refused: %v", err)
		}
		if boxMode() != modeLocal {
			t.Fatal("a refused set-mode changed the mode")
		}
		withMachineAuthority(t, true)
		if err := setBoxMode(modeNetworked); err != nil || boxMode() != modeNetworked {
			t.Fatalf("set-mode networked with machine authority: %v, mode %s", err, boxMode())
		}
	})
	t.Run("claim-anchor", func(t *testing.T) {
		freshBox(t)
		withMachineAuthority(t, true)
		if err := setBoxMode(modeNetworked); err != nil {
			t.Fatal(err)
		}
		writePairingState(t, tMember, pairingPending)
		withMachineAuthority(t, false)
		if err := cmdClaimAnchor("", false, "Acme IT", ""); err == nil || !strings.Contains(err.Error(), "machine authority") {
			t.Fatalf("claim-anchor without machine authority must be refused: %v", err)
		}
		if currentAnchor() != nil || currentOwnerClaim() != nil {
			t.Fatal("a refused claim-anchor wrote an anchor or an owner claim")
		}
		if err := cmdRepinAnchor(); err == nil || !strings.Contains(err.Error(), "machine authority") {
			t.Fatalf("claim-anchor --repin without machine authority must be refused: %v", err)
		}
		withMachineAuthority(t, true)
		if err := cmdClaimAnchor("", false, "Acme IT", ""); err != nil {
			t.Fatalf("claim-anchor with machine authority: %v", err)
		}
		if a := currentAnchor(); a == nil || a.AnchorHost != tMember {
			t.Fatalf("the anchor was not written: %+v", a)
		}
		// --repin with machine authority gets past that wall and completes: on
		// this box it re-pins the anchor to the pairing that already holds it.
		if err := cmdRepinAnchor(); err != nil {
			t.Fatalf("claim-anchor --repin with machine authority: %v", err)
		}
		if a := currentAnchor(); a == nil || a.AnchorHost != tMember {
			t.Fatalf("--repin moved the anchor: %+v", a)
		}
	})
}

// ── fixed argv ──────────────────────────────────────────────────────────────

// The allowlisted op ignores what the caller sends: the program it runs is
// given no argument, whatever the job carries. The program is a stand-in on
// a PATH the test owns, which writes down the argv it was given.
func TestTheAllowlistedOpIgnoresTheCallersArguments(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	bin := t.TempDir()
	record := filepath.Join(t.TempDir(), "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$#\" \"$@\" > '" + record + "'\necho up 1 day\n"
	if err := os.WriteFile(filepath.Join(bin, "uptime"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	hostile := []string{"-p", "; touch /tmp/owned", "$(id)", "--help"}
	out, errOut, code := driveOp(t, tMember, "uptime", hostile)
	if code != 0 || !strings.Contains(out, "up 1 day") {
		t.Fatalf("uptime did not run the stand-in: %d %q %q", code, out, errOut)
	}
	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "0" {
		t.Fatalf("the allowlisted op passed arguments to its program: %q", got)
	}
}

// ── scoped tunnel, at pairing and at start ─────────────────────────────────

// A pairing response whose host_tunnel_ip is not one host's address is
// refused, and no pairing is saved; the same response with a bare address
// pairs. The redeem is served on loopback in place of the platform's ingress.
func TestAPairingResponseWithAWideTunnelAddressSavesNothing(t *testing.T) {
	cfgHome := uiTestConfigDir(t)
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	hostIP := ""
	redeem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"operator_crt": "CERT", "ca_crt": "CA", "bearer": "b", "endpoint": "203.0.113.7:51820",
			"endpoint_pubkey": testWGKey(t), "bastion_tunnel_ip": "2001:db8::a:1",
			"host_tunnel_ip": hostIP, "host_name": "acme.host.privatae.ai",
		})
	}))
	defer redeem.Close()
	old := redeemURLBase
	redeemURLBase = redeem.URL
	t.Cleanup(func() { redeemURLBase = old })
	token := "skb_" + base64.RawURLEncoding.EncodeToString([]byte("acme.secret"))

	for _, bad := range []string{"2001:db8::e:3/64", "::/0", "2001:db8::e:3/128", "::"} {
		hostIP = bad
		if _, _, err := pairWithToken(token, false, false); err == nil || !strings.Contains(err.Error(), "not a single host address") {
			t.Fatalf("%q: the pairing must be refused for its tunnel address, got %v", bad, err)
		}
		// Nothing at all: not a pairing, not a grant file, not a key. The
		// walk covers what loadPairings would skip.
		_ = filepath.Walk(cfgHome, func(path string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				t.Errorf("%q: a refused pairing left a file behind: %s", bad, path)
			}
			return nil
		})
	}
	hostIP = "2001:db8::e:3"
	cfg, _, err := pairWithToken(token, false, false)
	if err != nil {
		t.Fatalf("a bare address must pair: %v", err)
	}
	if cfg.HostTunnelIP != "2001:db8::e:3" {
		t.Fatalf("saved %q", cfg.HostTunnelIP)
	}
}

// A pairing file that already holds a wide address (written by an older
// build, or by hand) brings no tunnel up: runPairing refuses before the
// device is raised.
func TestRunPairingRefusesAWideTunnelAddress(t *testing.T) {
	uiTestConfigDir(t)
	for _, bad := range []string{"2001:db8::e:3/64", "::/0"} {
		cfg := &Config{HostName: "acme.host.privatae.ai", WGPrivateKey: testWGKey(t), EndpointPubKey: testWGKey(t),
			Endpoint: "203.0.113.7:51820", BastionTunnelIP: "2001:db8::a:1", HostTunnelIP: bad}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := runPairing(ctx, cfg)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "not a single host address") {
			t.Fatalf("%q: runPairing must refuse the tunnel address, got %v", bad, err)
		}
	}
}
