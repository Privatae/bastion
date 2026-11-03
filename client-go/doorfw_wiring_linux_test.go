//go:build linux

package main

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fwFake is a firewall the bastion manages, kept in memory.
type fwFake struct {
	mu    sync.Mutex
	rules map[string]bool
	adds  int
}

func (f *fwFake) id() string   { return "ufw" }
func (f *fwFake) name() string { return "ufw" }
func (f *fwFake) has(port string) (bool, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules[port], false, nil
}
func (f *fwFake) add(port string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[port] = true
	f.adds++
	return nil
}
func (f *fwFake) remove(port, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.rules[port] {
		return errors.New("no such rule")
	}
	delete(f.rules, port)
	return nil
}
func (f *fwFake) manual(port string) string { return "allow " + port }
func (f *fwFake) open(port string) bool     { ok, _, _ := f.has(port); return ok }

func fwFakeWorld(t *testing.T) *fwFake {
	t.Helper()
	f := &fwFake{rules: map[string]bool{}}
	prevFor, prevBy := doorFirewallFor, doorFirewallByID
	t.Cleanup(func() { doorFirewallFor, doorFirewallByID = prevFor, prevBy })
	doorFirewallFor = func(string) (doorFirewall, string) { return f, "" }
	doorFirewallByID = func(string) doorFirewall { return f }
	return f
}

// The window's own door opens the way in while the window is open, and a
// window that ends with nothing paired takes it away again.
func TestAPairingWindowOpensTheFirewallAndClosingItRemovesTheRule(t *testing.T) {
	pairingBox(t)
	f := fwFakeWorld(t)
	addr := freeDoorAddr(t)
	port := doorPort(addr)
	_, out, res := openWindowFor(t, addr)
	if !f.open(port) || !strings.Contains(out.String(), "added its own rule in ufw") {
		t.Fatalf("the window is open and the firewall is not: %v\n%s", f.rules, out.String())
	}
	w := loadOpenWindow()
	removeWindow(w.ID) // closed at the terminal, as Ctrl-C does
	select {
	case <-res:
	case <-time.After(5 * time.Second):
		t.Fatal("pair --open did not end")
	}
	if f.open(port) {
		t.Fatal("the rule outlived a window that paired nothing")
	}
	a := pairingAuditText(t)
	if !strings.Contains(a, `"door_firewall_opened"`) || !strings.Contains(a, `"door_firewall_closed"`) {
		t.Fatalf("the audit:\n%s", a)
	}
	// MUTATION: pair --open does not release. RESULT: red, the rule outlived the window.
}

// A pairing made through the window keeps the rule; the daemon's door keeps
// it while it serves the pairing and when the bastion stops (the pairing has
// not gone); unpairing removes it.
func TestThePairingsDoorKeepsTheRuleUntilThePairingGoes(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	// Opened without machine authority, so the Host is not put in charge
	// (anchorAfterWindow) and `unpair` below may remove it: which Host is in
	// charge is TestAServerPairedThroughTheWindowHasThatHostInCharge's.
	prevAuth := machineAuthorityHeld
	machineAuthorityHeld = func() bool { return false }
	t.Cleanup(func() { machineAuthorityHeld = prevAuth })
	f := fwFakeWorld(t)
	addr := freeDoorAddr(t)
	port := doorPort(addr)
	code, _, res := openWindowFor(t, addr)
	ca := newTestCA(t, "home host CA")
	h := newStandinHost(t, ca, "home", "home.cseries.localhost", addr)
	if done, err := h.pair(formatWindowCode(code)); err != nil || done.State != pairingActive {
		t.Fatalf("pair: %+v %v", done, err)
	}
	if err := <-res; err != nil {
		t.Fatal(err)
	}
	if !f.open(port) {
		t.Fatal("the window's end removed the rule its active pairing needs")
	}
	cfgs, _ := loadPairings()
	cfg := pairingFor(cfgs, "home")
	// Its local control on a free port: the machine running the suite may
	// have its own bastion on the default one.
	cfg.ListenAddr = freeDoorAddr(t)
	stop := runPairingBG(t, cfg)
	doorWaitFor(t, 5*time.Second, "the door to bind", func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	})
	if err := stop(); err != nil && !errors.Is(err, errPairingNotActive) {
		t.Fatal(err)
	}
	if !f.open(port) {
		t.Fatal("the bastion stopping removed the rule of a pairing that is still there")
	}
	if f.adds != 1 {
		t.Fatalf("%d adds", f.adds)
	}
	if err := cmdUnpair("home"); err != nil {
		t.Fatal(err)
	}
	if f.open(port) {
		t.Fatal("the rule outlived the last pairing")
	}
	// MUTATION: cmdUnpair does not release. RESULT: red, the rule outlived the last pairing.
	// MUTATION: doorPortWanted ignores pairings. RESULT: red, the window's end removed the rule.
}

// The daemon's door alone: bound, it opens the way in; its last pairing
// stopped and gone, the rule goes with it.
func TestTheDaemonsDoorRemovesTheRuleWhenItsLastPairingGoes(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	f := fwFakeWorld(t)
	ca := newTestCA(t, "home host CA")
	addr := freeDoorAddr(t)
	cfg := hostDialsPairingFor(t, ca, "home.cseries.localhost", addr) // never saved: gone once it stops
	stop := runPairingBG(t, cfg)
	doorWaitFor(t, 5*time.Second, "the rule", func() bool { return f.open(doorPort(addr)) })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	doorWaitFor(t, 5*time.Second, "the rule to go", func() bool { return !f.open(doorPort(addr)) })
	// MUTATION: the door's release does not call doorFirewallRelease. RESULT: red, timed out waiting for the rule to go.
	// MUTATION: bindLoop does not ensure. RESULT: red, timed out waiting for the rule.
}

// fwHung is a firewall whose commands hang until let go.
type fwHung struct {
	*fwFake
	gate chan struct{}
}

func (f *fwHung) has(port string) (bool, bool, error) { <-f.gate; return f.fwFake.has(port) }

// A firewall command that hangs never holds the daemon's door shut: the door
// serves while the bastion waits on the firewall.
func TestTheDoorServesWhileTheFirewallHangs(t *testing.T) {
	pairingBox(t)
	laneTestProcess(t)
	f := &fwHung{fwFake: &fwFake{rules: map[string]bool{}}, gate: make(chan struct{})}
	prevFor, prevBy := doorFirewallFor, doorFirewallByID
	t.Cleanup(func() { doorFirewallFor, doorFirewallByID = prevFor, prevBy })
	doorFirewallFor = func(string) (doorFirewall, string) { return f, "" }
	doorFirewallByID = func(string) doorFirewall { return f }
	var once sync.Once
	release := func() { once.Do(func() { close(f.gate) }) }
	t.Cleanup(release)
	ca := newTestCA(t, "home host CA")
	addr := freeDoorAddr(t)
	cfg := hostDialsPairingFor(t, ca, "home.cseries.localhost", addr)
	stop := runPairingBG(t, cfg)
	doorWaitFor(t, 5*time.Second, "the door to answer a handshake", func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return false
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		err = tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: tcpServerName}).Handshake()
		var ne net.Error
		return err == nil || !(errors.As(err, &ne) && ne.Timeout())
	})
	release()
	doorWaitFor(t, 5*time.Second, "the rule", func() bool { return f.open(doorPort(addr)) })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	// MUTATION: bindLoop ensures before it serves. RESULT: red, timed out waiting for the door to answer a handshake.
}
