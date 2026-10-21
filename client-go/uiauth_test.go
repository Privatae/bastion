package main

// Deliberately NOT tagged !windows. Windows is the platform this UI exists for,
// so its front door has to be proven there — which means not borrowing
// withConfigDir (freeagent_managed_test.go, behind //go:build !windows) and
// isolating the config dir locally instead.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func uiTestConfigDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", d) // os.UserConfigDir on linux
	t.Setenv("HOME", d)            // darwin
	t.Setenv("AppData", d)         // windows
	return d
}

// ── the Host guard: DNS rebinding ───────────────────────────────────────────

func TestUIRefusesARebindingHost(t *testing.T) {
	// The attack: a page served from evil.example whose hostname is re-resolved
	// to 127.0.0.1. Every same-origin protection the browser has agrees the page
	// is talking to itself, because by its own rules it is. The Host header is
	// the only place the attacker's name still appears.
	cases := []struct {
		host string
		ok   bool
		why  string
	}{
		{"127.0.0.1:7877", true, "the real thing"},
		{"localhost:7877", true, "what a browser sends when you type localhost"},
		{"[::1]:7877", true, "loopback over v6"},
		{"localhost.:7877", true, "the fully-qualified spelling of the same name"},
		{"evil.example.:7877", false, "a trailing dot does not make a stranger local"},
		{"localhost..:7877", false, "only the ROOT dot is stripped"},
		{"evil.example:7877", false, "REBINDING — resolves to loopback, is not loopback"},
		{"bastion.internal:7877", false, "a friendly-looking name is still not loopback"},
		{"127.0.0.1:7878", false, "a pairing's control port, not ours"},
		{"127.0.0.1", false, "no port: a browser only omits it for :80"},
		{"", false, "absent"},
	}
	for _, c := range cases {
		got := uiLoopbackHost(c.host, "7877")
		if got != c.ok {
			t.Errorf("uiLoopbackHost(%q) = %v, want %v — %s", c.host, got, c.ok, c.why)
		}
	}
}

func TestUIGuardRefusesRebindingOnEveryMethod(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := httptest.NewRequest(method, "/", nil)
		r.Host = "evil.example:7877"
		r.Header.Set("Origin", "http://evil.example:7877") // self-consistent, and still not us
		if why := uiRequestAllowed(r, "7877", "ui"); why == "" {
			t.Errorf("%s from a rebound host was allowed — a read is not safe either, "+
				"the page would get the pairing list and the anchor", method)
		}
	}
}

// ── the Origin guard: CSRF ──────────────────────────────────────────────────

func TestUIGuardOnMutatingRequests(t *testing.T) {
	cases := []struct {
		name, method, origin string
		allowed              bool
	}{
		{"a read needs no Origin", http.MethodGet, "", true},
		{"a write from our own page", http.MethodPost, "http://127.0.0.1:7877", true},
		{"a write from localhost spelling", http.MethodPost, "http://localhost:7877", true},
		{"a write from another site", http.MethodPost, "https://evil.example", false},
		{"a write from a sandboxed frame", http.MethodPost, "null", false},
		{"a write with no Origin at all", http.MethodPost, "", false},
		{"a write from another local port", http.MethodPost, "http://127.0.0.1:7878", false},
		{"https to our own port is still not our page", http.MethodPost, "https://127.0.0.1:7877", false},
		{"DELETE is a write too", http.MethodDelete, "https://evil.example", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "/x", nil)
		r.Host = "127.0.0.1:7877"
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		why := uiRequestAllowed(r, "7877", "ui")
		if (why == "") != c.allowed {
			t.Errorf("%s: allowed=%v, want %v (reason %q)", c.name, why == "", c.allowed, why)
		}
	}
}

// ── tickets ─────────────────────────────────────────────────────────────────

func TestATicketWorksExactlyOnce(t *testing.T) {
	s := newUITokenStore(uiTicketTTL)
	tok, err := s.mint()
	if err != nil {
		t.Fatal(err)
	}
	if !s.redeem(tok) {
		t.Fatal("a fresh ticket did not redeem")
	}
	if s.redeem(tok) {
		t.Fatal("the SAME ticket redeemed twice — it travels in a URL, so a " +
			"replayable one is a credential sitting in browser history")
	}
	if s.redeem("not-a-ticket") || s.redeem("") {
		t.Fatal("a made-up ticket redeemed")
	}
}

func TestATicketExpires(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	setUINow(func() time.Time { return base })
	defer setUINow(nil)

	s := newUITokenStore(uiTicketTTL)
	tok, err := s.mint()
	if err != nil {
		t.Fatal(err)
	}
	setUINow(func() time.Time { return base.Add(uiTicketTTL - time.Second) })
	if !s.redeem(tok) {
		t.Fatal("a ticket died before its TTL")
	}

	// Back to base before minting, or this ticket's TTL runs from the advanced
	// clock and the check below lands well inside it.
	setUINow(func() time.Time { return base })
	tok2, _ := s.mint()
	setUINow(func() time.Time { return base.Add(uiTicketTTL + 2*time.Second) })
	if s.redeem(tok2) {
		t.Fatal("an expired ticket still redeemed")
	}
}

// ── sessions ────────────────────────────────────────────────────────────────

func TestASessionIsReusableUntilItExpires(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	setUINow(func() time.Time { return base })
	defer setUINow(nil)

	s := newUITokenStore(uiSessionTTL)
	tok, _ := s.mint()
	for i := 0; i < 3; i++ {
		if !s.valid(tok) {
			t.Fatalf("session rejected on use %d — unlike a ticket it is presented "+
				"on every request", i+1)
		}
	}
	setUINow(func() time.Time { return base.Add(uiSessionTTL + time.Minute) })
	if s.valid(tok) {
		t.Fatal("an expired session was accepted")
	}
}

func TestSignOutDropsTheSession(t *testing.T) {
	s := newUITokenStore(uiSessionTTL)
	tok, _ := s.mint()
	s.drop(tok)
	if s.valid(tok) {
		t.Fatal("a dropped session still validated — sign out must mean it")
	}
}

// ── the secret file ─────────────────────────────────────────────────────────

func TestTheUISecretIsStableAndPrivate(t *testing.T) {
	uiTestConfigDir(t)

	first, err := loadOrCreateUISecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 32 {
		t.Fatalf("secret is %d chars — too short to be a credential", len(first))
	}
	again, err := loadOrCreateUISecret()
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatal("the secret changed on the second read — every open browser session " +
			"would be signed out, and `ui` would mint against a secret the daemon no " +
			"longer holds")
	}

	p, err := uiSecretPath()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return // POSIX modes do not describe Windows ACLs; %AppData% is per-user
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("ui.secret is %o, want 600", fi.Mode().Perm())
	}

	// A file that already exists with loose permissions must be REPAIRED, not
	// accepted. os.WriteFile applies its mode only when it creates the file, so
	// a secret written once under a bad umask would stay world-readable for ever
	// and nothing would ever mention it.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateUISecret(); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("a world-readable ui.secret was left at %o — every user on this "+
			"machine could open the UI", fi.Mode().Perm())
	}
}

func TestUISecretComparison(t *testing.T) {
	if !uiSecretMatches("abc", "abc") {
		t.Fatal("equal secrets did not match")
	}
	if uiSecretMatches("abc", "abd") || uiSecretMatches("", "abc") ||
		uiSecretMatches("abc", "") || uiSecretMatches("", "") {
		t.Fatal("a mismatch matched — note the empty/empty case: an unset secret " +
			"must never be satisfied by sending nothing")
	}
}

// ── the cookie ──────────────────────────────────────────────────────────────

func TestTheSessionCookieCarriesItsDefences(t *testing.T) {
	w := httptest.NewRecorder()
	uiSetSessionCookie(w, "tok-1")
	raw := w.Header().Get("Set-Cookie")

	for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(raw, want) {
			t.Errorf("Set-Cookie is missing %s: %s", want, raw)
		}
	}
	// Secure would mean the cookie is never STORED over plain http, so the
	// login would appear to work and every later request would be anonymous.
	if strings.Contains(raw, "Secure") {
		t.Errorf("Secure is set on a cookie served over http on loopback — the "+
			"browser will silently drop it: %s", raw)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", "privatae_ui_session=tok-1")
	if got := uiSessionFrom(r); got != "tok-1" {
		t.Fatalf("uiSessionFrom = %q", got)
	}
	if got := uiSessionFrom(httptest.NewRequest(http.MethodGet, "/", nil)); got != "" {
		t.Fatalf("a request with no cookie produced %q", got)
	}
}
