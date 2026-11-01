package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
)

// serveConsoleAt runs a console with `secret` on a fresh loopback port and
// records that port in this account's ui.addr, as a running daemon does.
func serveConsoleAt(t *testing.T, secret string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u, err := newUIServer(fmt.Sprint(ln.Addr().(*net.TCPAddr).Port), secret)
	if err != nil {
		t.Fatal(err)
	}
	h := &http.Server{Handler: u.handler()}
	go func() { _ = h.Serve(ln) }()
	t.Cleanup(func() { _ = h.Close() })
	p, err := uiAddrPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(ln.Addr().String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// With no Host, `status` decides "running" from the console. A console that
// answers on the recorded port but belongs to another account's bastion (the
// system service beside a person's own, say) is not this one running.
func TestStatusWithNoHostCountsOnlyThisAccountsOwnConsole(t *testing.T) {
	uiTestConfigDir(t)
	if _, err := loadOrCreateUISecret(); err != nil {
		t.Fatal(err)
	}
	serveConsoleAt(t, "another-accounts-secret-aaaaaaaaaaaaaaaaaaaa")
	if uiDaemonListening() {
		t.Fatal("another account's console on the recorded port read as this bastion running")
	}
}

func TestStatusWithNoHostSeesItsOwnRunningConsole(t *testing.T) {
	uiTestConfigDir(t)
	secret, err := loadOrCreateUISecret()
	if err != nil {
		t.Fatal(err)
	}
	serveConsoleAt(t, secret)
	if !uiDaemonListening() {
		t.Fatal("this account's own console, up and answering, did not read as running")
	}
}

func TestStatusWithNoHostAndNoDaemonIsNotRunning(t *testing.T) {
	uiTestConfigDir(t)
	if uiDaemonListening() {
		t.Fatal("nothing recorded and nothing listening read as running")
	}
}
