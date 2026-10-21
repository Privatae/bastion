package main

// uiauth.go — the local UI's front door.
//
// WHY THIS IS NOT THE BEARER THE REST OF THE LOOPBACK PORT USES. The two
// existing local routes authenticate with `Bearer <OperatorSecret>`
// (addfolder.go:110, gitlane.go:132) and that is right for them, because their
// callers are the CLI: a Go process that can read the pairing file and set a
// header. A browser cannot. A top-level navigation carries no Authorization
// header and there is no way to add one, so the very first request of a UI built
// that way would 401 and there would be nothing to log into with.
//
// So the browser is let in by URL once, and by cookie afterwards:
//
//	privatae-bastion ui          reads ui.secret (0600, this user only)
//	  → POST /auth/ticket        with the secret, over loopback
//	  ← a ONE-USE ticket, 60s
//	  → opens http://127.0.0.1:7877/?k=<ticket>
//	  ← Set-Cookie (HttpOnly, SameSite=Strict) + 303 to /
//
// The long-lived secret never appears in a URL, a browser history or a shell
// history. The thing that does appear is dead after one use and after a minute,
// which is what makes it safe to put somewhere as leaky as an address bar.
//
// WHAT A COOKIE COSTS, AND WHAT PAYS FOR IT. A bearer header has one nice
// property a cookie does not: the browser never attaches it on its own, so a
// page you happen to visit cannot make an authenticated request to 127.0.0.1 no
// matter what it does. A cookie IS attached automatically, so it brings that
// risk back and it has to be bought off deliberately:
//
//   - SameSite=Strict — the browser will not attach this cookie to a request
//     initiated from any other site. That is the primary defence, and on every
//     browser this product supports it is sufficient on its own.
//   - An Origin check on every mutating request — the belt to that brace, for
//     anything that predates or misimplements SameSite.
//   - A Host check on EVERY request — this one is not about CSRF at all. It
//     stops DNS rebinding, where a page at evil.example re-resolves its own
//     hostname to 127.0.0.1 and then talks to us as same-origin. Its requests
//     arrive with `Host: evil.example`, and nothing else in the stack notices.
//
// All three are required. Any one alone leaves a hole the other two cover.

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// A ticket exists only to carry the user from the command line into the
	// browser, and it travels in a URL the whole way. One minute is long enough
	// for a cold browser start on a slow machine and far too short to be worth
	// scraping out of a history file.
	uiTicketTTL = 60 * time.Second
	// A session is a working day. Not sliding-forever: a UI that never asks
	// again is a UI whose cookie is as good as the secret.
	uiSessionTTL = 12 * time.Hour
	uiCookieName = "privatae_ui_session"
)

// uiNow is the clock seam — the expiry tests pin it rather than sleeping. It
// is read from timer goroutines (the disk map's drop timer) that can outlive
// the test that armed them, so the seam is swapped atomically rather than by
// assignment: a test pinning the clock while such a timer fires is a plain
// read of one pointer or the other, never a torn one.
var uiClock atomic.Pointer[func() time.Time]

func uiNow() time.Time {
	if f := uiClock.Load(); f != nil {
		return (*f)()
	}
	return time.Now()
}

// setUINow pins the clock seam; nil restores the real clock.
func setUINow(f func() time.Time) {
	if f == nil {
		uiClock.Store(nil)
		return
	}
	uiClock.Store(&f)
}

// ── the long-lived secret ───────────────────────────────────────────────────

func uiSecretPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "ui.secret"), nil
}

// loadOrCreateUISecret returns this machine's UI secret, generating it on first
// use. It is deliberately MACHINE-wide rather than per-pairing: the UI shows the
// whole box (every pairing, the mode, the anchor), so binding its key to one
// pairing would mean the UI died when that pairing was removed.
//
// 0600, and re-chmodded on every read rather than only at creation. os.WriteFile
// applies its mode only when it CREATES the file, so a secret written once under
// a loose umask, or restored from a backup that flattened permissions, would
// keep those permissions for ever and nothing would ever say so.
func loadOrCreateUISecret() (string, error) {
	p, err := uiSecretPath()
	if err != nil {
		return "", err
	}
	if b, err := os.ReadFile(p); err == nil {
		if s := string(bytes.TrimSpace(b)); len(s) >= 32 {
			_ = os.Chmod(p, 0o600)
			return s, nil
		}
	}
	s, err := genSecret(32)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("cannot write the UI secret: %w", err)
	}
	if _, err := f.WriteString(s); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	_ = os.Chmod(p, 0o600)
	return s, nil
}

// uiSecretMatches compares in constant time. The window is narrow — an attacker
// must already be able to reach loopback — but this is a fixed secret compared
// on every ticket request, which is exactly the shape a timing oracle likes.
func uiSecretMatches(offered, want string) bool {
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(offered), []byte(want)) == 1
}

// ── tickets and sessions ────────────────────────────────────────────────────

// uiTokenStore holds unexpired tokens. Tickets are redeemed (one use);
// sessions are checked (many uses, until they expire).
type uiTokenStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]time.Time // token -> expiry
}

func newUITokenStore(ttl time.Duration) *uiTokenStore {
	return &uiTokenStore{ttl: ttl, m: map[string]time.Time{}}
}

func (s *uiTokenStore) mint() (string, error) {
	tok, err := genSecret(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.m[tok] = uiNow().Add(s.ttl)
	return tok, nil
}

// redeem CONSUMES the token: true at most once, ever. This is what makes a
// ticket safe to put in a URL — by the time that URL is anywhere durable, the
// value in it no longer opens anything.
func (s *uiTokenStore) redeem(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	exp, ok := s.m[tok]
	if !ok || uiNow().After(exp) {
		return false
	}
	delete(s.m, tok)
	return true
}

// valid does NOT consume — a session cookie is presented on every request.
func (s *uiTokenStore) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	exp, ok := s.m[tok]
	return ok && !uiNow().After(exp)
}

func (s *uiTokenStore) drop(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tok)
}

func (s *uiTokenStore) sweepLocked() {
	now := uiNow()
	for k, exp := range s.m {
		if now.After(exp) {
			delete(s.m, k)
		}
	}
}

// ── the request guard ───────────────────────────────────────────────────────

// uiLoopbackHost reports whether a Host/Origin authority names this machine's
// loopback interface. Anything else — a hostname that merely RESOLVES to
// 127.0.0.1 included, which is the whole point — is not us.
func uiLoopbackHost(authority, wantPort string) bool {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		// No port at all: a browser only omits it for :80, which we never are.
		return false
	}
	if port != wantPort {
		return false
	}
	// A single trailing dot is the fully-qualified spelling of the same name —
	// `http://localhost.:7877/` is a real thing a browser will send, and it was
	// refused at first (safe direction, usability edge). Stripping it
	// widens nothing: `evil.example.` becomes `evil.example`, which is still not
	// loopback and still refused. Only the ROOT dot is stripped, so `localhost..`
	// stays wrong.
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// uiRequestAllowed is the gate every UI handler passes through before it looks
// at a cookie. It returns the refusal reason, or "" to proceed.
// verb is which command opens THIS surface — "ui" for the machine's own
// console, "context" for a person's own files (contextui.go). It is a parameter
// rather than a constant because a refusal that names the wrong command sends
// somebody to a page they cannot open, which is a worse failure than no
// instruction at all.
func uiRequestAllowed(r *http.Request, wantPort, verb string) string {
	// 1. DNS rebinding. The attacker's page holds its own origin and re-points
	//    its hostname at loopback; SameSite and Origin both read as same-site
	//    because from the browser's point of view they are. The Host header is
	//    the one place the real name survives.
	if !uiLoopbackHost(r.Host, wantPort) {
		return "this address is not how the local UI is reached — open it from " +
			"`privatae-bastion " + verb + "`"
	}
	// 2. CSRF. Reads are safe to serve on a cookie alone; anything that CHANGES
	//    something must prove it came from our own page.
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return ""
	}
	o := r.Header.Get("Origin")
	if o == "" {
		// Browsers send Origin on every POST. Its absence is a non-browser
		// client, which should be using the CLI and the bearer instead.
		return "this request carried no Origin and was refused"
	}
	u, err := url.Parse(o)
	if err != nil || u.Scheme != "http" || !uiLoopbackHost(u.Host, wantPort) {
		return "this request came from " + o + " and was refused"
	}
	return ""
}

// uiSetSessionCookie installs the session.
//
// Secure is deliberately FALSE and that is not an oversight: the UI is plain
// http on 127.0.0.1, and a Secure cookie would simply never be stored, so the
// login would appear to succeed and every following request would be anonymous.
// Loopback traffic does not leave the machine, and a local process that could
// read it could read the secret file instead.
func uiSetSessionCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     uiCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(uiSessionTTL / time.Second),
	})
}

func uiClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: uiCookieName, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

func uiSessionFrom(r *http.Request) string {
	c, err := r.Cookie(uiCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
