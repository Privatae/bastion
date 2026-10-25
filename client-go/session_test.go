//go:build !windows

// Tagged !windows. These tests were ALREADY unix-only — they use
// helpers that live behind `//go:build !windows` (sessionShellsPath,
// withConfigDir, withMarkerAt, setupBox) — so this file has never compiled for
// Windows and `GOOS=windows go vet ./...` has been red on it since it was
// written. The tag removes no coverage; it states a dependency that was already
// there so vet can run clean on that target, which is what makes a REAL Windows
// regression visible instead of being lost in a failure everyone scrolls past.
// Windows-safe coverage of the machine-authority gate lives in privilege_test.go.

package main

// Session lane walls, testable without a live relay: the wire framing round-trip
// (with a fake pty, and with a real one running /bin/cat on Linux), the grant
// refusal shape (exit 126 like an ungranted mgmt op), resize, the idle timer, the
// transcript, and root refused without a step-up approval.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeProc is a sessionProc that echoes input back as output, records resizes and
// ends when killed (or when its input pipe closes).
type fakeProc struct {
	pr, pw   *os.File
	mu       sync.Mutex
	resizes  []sessionResize
	killed   bool
	done     chan struct{}
	waitOnce sync.Once
}

func newFakeProc() *fakeProc {
	pr, pw, _ := os.Pipe()
	return &fakeProc{pr: pr, pw: pw, done: make(chan struct{})}
}

func (f *fakeProc) Read(b []byte) (int, error)  { return f.pr.Read(b) }
func (f *fakeProc) Write(b []byte) (int, error) { return f.pw.Write(b) }
func (f *fakeProc) Resize(c, r int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resizes = append(f.resizes, sessionResize{Cols: c, Rows: r})
	return nil
}
func (f *fakeProc) Wait() int {
	f.waitOnce.Do(func() { <-f.done })
	return 0
}
func (f *fakeProc) Kill() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.killed {
		return
	}
	f.killed = true
	_ = f.pw.Close()
	_ = f.pr.Close()
	close(f.done)
}
func (f *fakeProc) User() string  { return "fake" }
func (f *fakeProc) Shell() string { return "/bin/fake" }

// sessionTestEnv writes a pinned entity key + one signed grant and returns the env
// plus a signer for more grants.
func sessionTestEnv(t *testing.T, ops, deny []string) (sessionEnv, string, string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	dcn := filepath.Join(dir, "dcn")
	ctx := filepath.Join(dir, "ctx")
	_ = os.MkdirAll(dcn, 0o700)
	_ = os.MkdirAll(ctx, 0o700)
	if err := dcnSaveFile(dcn, &dcnGrantFile{VerifyPubkey: base64.StdEncoding.EncodeToString(pub),
		Stores: map[string]dcnGrantRec{}}); err != nil {
		t.Fatal(err)
	}
	terms, _ := json.Marshal(map[string]any{"entity": 9001, "server": "box1", "ops": ops, "deny": deny,
		"intent": nil, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	env := sessionEnv{CtxRoot: ctx, DcnDir: dcn, HostName: "h.example", Server: "box1"}
	return env, base64.StdEncoding.EncodeToString(terms), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, terms))
}

// sessionDial stands up the box side (handleSessionConn on an upgraded socket) and
// returns the host side, already connected.
func sessionDial(t *testing.T, env sessionEnv) *websocket.Conn {
	t.Helper()
	return sessionDialAs(t, env, "")
}

// sessionDialAs is sessionDial with this box's own name given to the handler
// (what an anchored box passes: its hostname, for the per-session approval's
// purpose).
func sessionDialAs(t *testing.T, env sessionEnv, self string) *websocket.Conn {
	t.Helper()
	up := websocket.Upgrader{}
	done := make(chan struct{})
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
	t.Cleanup(srv.Close)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Cleanups run last-registered first: the host hangs up, then the handler
	// is waited for, so nothing the session writes (its transcript, its audit
	// line) lands after the test's dirs are removed.
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the session handler did not finish after the host hung up")
		}
	})
	t.Cleanup(func() { _ = ws.Close() })
	return ws
}

func sendSpec(t *testing.T, ws *websocket.Conn, spec sessionSpec) {
	t.Helper()
	b, _ := json.Marshal(spec)
	if err := ws.WriteMessage(websocket.BinaryMessage, append([]byte{'S'}, b...)); err != nil {
		t.Fatal(err)
	}
}

// readUntil collects frames until one with tag `until` arrives (or timeout); returns
// every frame seen keyed by tag, concatenated.
func readUntil(t *testing.T, ws *websocket.Conn, until byte, d time.Duration) map[byte][]byte {
	t.Helper()
	got := map[byte][]byte{}
	_ = ws.SetReadDeadline(time.Now().Add(d))
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("read (waiting for %c): %v — got so far %q", until, err, got)
		}
		if len(data) == 0 {
			continue
		}
		got[data[0]] = append(got[data[0]], data[1:]...)
		if data[0] == until {
			return got
		}
	}
}

func withFake(t *testing.T) *fakeProc {
	t.Helper()
	fp := newFakeProc()
	old := sessionSpawn
	sessionSpawn = func(op, shell string, cols, rows int) (sessionProc, error) {
		fp.Resize(cols, rows) // record the initial window like the real spawner applies it
		return fp, nil
	}
	t.Cleanup(func() { sessionSpawn = old; fp.Kill() })
	return fp
}

func TestSessionFramingResizeAndTranscript(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	fp := withFake(t)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, Cols: 100, Rows: 30, GrantB64: terms, SigB64: sig, SessionID: "sess-0001"})

	// I -> pty; the fake echoes it as O.
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte("Ihello\n")); err != nil {
		t.Fatal(err)
	}
	got := readUntil(t, ws, 'O', 3*time.Second)
	if string(got['O']) != "hello\n" {
		t.Fatalf("O frame: %q", got['O'])
	}
	// R -> resize.
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte(`R{"cols":132,"rows":43}`)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		fp.mu.Lock()
		n := len(fp.resizes)
		fp.mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fp.mu.Lock()
	rz := append([]sessionResize(nil), fp.resizes...)
	fp.mu.Unlock()
	if len(rz) != 2 || rz[0] != (sessionResize{100, 30}) || rz[1] != (sessionResize{132, 43}) {
		t.Fatalf("resizes: %+v", rz)
	}
	// Shell exits (pty EOF) -> X with its code.
	fp.Kill()
	got = readUntil(t, ws, 'X', 3*time.Second)
	if string(got['X']) != "0" {
		t.Fatalf("X frame: %q", got['X'])
	}
	// Transcript: 0600, start + output + stop lines.
	p := filepath.Join(env.CtxRoot, "sessions", "sess-0001.log")
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("transcript missing: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("transcript mode %o, want 0600", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(p)
	s := string(raw)
	for _, want := range []string{"== session sess-0001 op=session:open user=fake", "hello\n", "== session sess-0001 stop=", "exit=0 reason=exit"} {
		if !strings.Contains(s, want) {
			t.Fatalf("transcript lacks %q:\n%s", want, s)
		}
	}
	// Audit: start + stop rows in the pairing's audit.jsonl.
	araw, _ := os.ReadFile(filepath.Join(env.DcnDir, "audit.jsonl"))
	if !strings.Contains(string(araw), `"event":"start"`) || !strings.Contains(string(araw), `"event":"stop"`) {
		t.Fatalf("audit lacks start/stop:\n%s", araw)
	}
}

func TestSessionRefusedWithoutGrantIs126(t *testing.T) {
	cases := []struct {
		name      string
		ops, deny []string
		mangle    func(*sessionSpec)
		want      string
	}{
		{"op not granted", []string{"uptime"}, nil, nil, "not in your grant"},
		{"op denied", []string{sessionOpOpen}, []string{sessionOpOpen}, nil, "denied by your grant"},
		{"deny all", []string{sessionOpOpen}, []string{"*"}, nil, "denied by your grant"},
		{"bad signature", []string{sessionOpOpen}, nil, func(s *sessionSpec) { s.SigB64 = base64.StdEncoding.EncodeToString(make([]byte, 64)) }, "does not verify"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, terms, sig := sessionTestEnv(t, c.ops, c.deny)
			withFake(t)
			ws := sessionDial(t, env)
			spec := sessionSpec{Op: sessionOpOpen, GrantB64: terms, SigB64: sig, SessionID: "sess-refuse"}
			if c.mangle != nil {
				c.mangle(&spec)
			}
			sendSpec(t, ws, spec)
			got := readUntil(t, ws, 'X', 3*time.Second)
			if string(got['X']) != "126" || !strings.Contains(string(got['E']), c.want) {
				t.Fatalf("want X 126 + E ~%q, got X=%q E=%q", c.want, got['X'], got['E'])
			}
			if _, err := os.Stat(filepath.Join(env.CtxRoot, "sessions", "sess-refuse.log")); err == nil {
				t.Fatal("a refused session must not leave a transcript")
			}
			araw, _ := os.ReadFile(filepath.Join(env.DcnDir, "audit.jsonl"))
			if !strings.Contains(string(araw), `"event":"refused"`) {
				t.Fatalf("refusal not audited:\n%s", araw)
			}
		})
	}
}

// 0.39.0 (rung 8): a terminal is the person's
// own act and no longer needs the host's signed management grant. On a local
// box the pairing's caps are the authorization; a frame with no grant opens.
// A grant that IS presented is still verified (the refusals above), and the
// key the frame offers is still pinned — the same pin, by the same rules.
func TestSessionOpensWithoutAGrantOnALocalBox(t *testing.T) {
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	fp := withFake(t)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, SessionID: "sess-nogrant"})
	// The fake shell echoes keyboard bytes as output: an O frame back means
	// the session OPENED — with no grant in the frame at all.
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte("Ihello\n")); err != nil {
		t.Fatal(err)
	}
	got := readUntil(t, ws, 'O', 3*time.Second)
	if string(got['O']) != "hello\n" {
		t.Fatalf("a shell with no grant presented must open on a local box: O=%q E=%q X=%q", got['O'], got['E'], got['X'])
	}
	fp.Kill()
	readUntil(t, ws, 'X', 3*time.Second)
	araw, _ := os.ReadFile(filepath.Join(env.DcnDir, "audit.jsonl"))
	if !strings.Contains(string(araw), `"event":"start"`) {
		t.Fatalf("the session must be audited like any other:\n%s", araw)
	}
	// A key offered without a grant is still pinned, and a second key refused.
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(nil)
	key := base64.StdEncoding.EncodeToString(pub)
	if why := sessionPinOfferedKey(dir, "", key); why != "" {
		t.Fatalf("first offer must pin: %s", why)
	}
	f, _ := dcnLoadFile(dir)
	if f.VerifyPubkey != key {
		t.Fatalf("the offered key must be pinned: %q", f.VerifyPubkey)
	}
	pub2, _, _ := ed25519.GenerateKey(nil)
	if why := sessionPinOfferedKey(dir, "", base64.StdEncoding.EncodeToString(pub2)); why == "" ||
		!strings.Contains(why, "mismatch") {
		t.Fatalf("a second key must be refused, not re-pinned: %q", why)
	}
	if sessionPinOfferedKey(dir, "", "") != "" {
		t.Fatal("no key offered: nothing to pin, nothing to refuse")
	}
}

// On an ANCHORED box the grant was never the wall for session:open — the
// per-session approval is (boxConsume, bound to this session id). With the
// grant no longer demanded (0.39.0), that approval is the ONLY wall left on
// the box, so it is driven here through the handler itself: a frame with no
// grant and no approval is refused 126 by boxConsume's own words, opens no
// shell and leaves no transcript.
func TestSessionOnAnAnchoredBoxTheApprovalIsTheWall(t *testing.T) {
	setupBox(t)
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	env.HostName = tAnchor
	withFake(t)
	ws := sessionDialAs(t, env, tAnchor)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, SessionID: "sess-anchored-1"})
	got := readUntil(t, ws, 'X', 3*time.Second)
	if string(got['X']) != "126" || len(got['O']) != 0 {
		t.Fatalf("an anchored box must refuse a grant-less session:open with no approval: X=%q O=%q E=%q", got['X'], got['O'], got['E'])
	}
	if !strings.Contains(string(got['E']), "session:open needs your approval") {
		t.Fatalf("the refusal must be the per-session approval's, not a grant's: E=%q", got['E'])
	}
	if _, err := os.Stat(filepath.Join(env.CtxRoot, "sessions", "sess-anchored-1.log")); err == nil {
		t.Fatal("a refused session must not leave a transcript")
	}
	araw, _ := os.ReadFile(filepath.Join(env.DcnDir, "audit.jsonl"))
	if !strings.Contains(string(araw), `"event":"refused"`) {
		t.Fatalf("refusal not audited:\n%s", araw)
	}
	// The same box WITH a factor enrolled: the wall is still the approval —
	// a frame that carries none is refused by consumeApproval's own words,
	// not waved through because the box could take one.
	if err := stepupSave(env.DcnDir, &stepupFile{SecretB32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		EnrolledAt: "2026-09-25T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	ws2 := sessionDialAs(t, env, tAnchor)
	sendSpec(t, ws2, sessionSpec{Op: sessionOpOpen, SessionID: "sess-anchored-2"})
	got = readUntil(t, ws2, 'X', 3*time.Second)
	if string(got['X']) != "126" || len(got['O']) != 0 || !strings.Contains(string(got['E']), "none was given") {
		t.Fatalf("with a factor enrolled and no approval in the frame the session must still be refused: X=%q O=%q E=%q",
			got['X'], got['O'], got['E'])
	}
	if _, err := os.Stat(filepath.Join(env.CtxRoot, "sessions", "sess-anchored-2.log")); err == nil {
		t.Fatal("a refused session must not leave a transcript")
	}
}

func TestSessionServerMismatchRefused(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	env.Server = "other-box"
	if _, err := sessionVerifyGrant(env.DcnDir, env.HostName, env.Server, sessionOpOpen, terms, sig, ""); err == nil {
		t.Fatal("a grant for box1 must not open a session on other-box")
	}
}

func TestSessionIdleTimeoutKills(t *testing.T) {
	oldT, oldC := sessionIdleTimeout, sessionIdleCheck
	sessionIdleTimeout, sessionIdleCheck = 50*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { sessionIdleTimeout, sessionIdleCheck = oldT, oldC })
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	fp := withFake(t)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, GrantB64: terms, SigB64: sig, SessionID: "sess-idle"})
	got := readUntil(t, ws, 'X', 5*time.Second)
	if string(got['X']) != "124" || !strings.Contains(string(got['E']), "idle") {
		t.Fatalf("want X 124 + E idle, got X=%q E=%q", got['X'], got['E'])
	}
	fp.mu.Lock()
	killed := fp.killed
	fp.mu.Unlock()
	if !killed {
		t.Fatal("idle timeout must kill the shell")
	}
}

func TestSessionHostCloseKills(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	fp := withFake(t)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, GrantB64: terms, SigB64: sig, SessionID: "sess-close"})
	_ = ws.WriteMessage(websocket.BinaryMessage, []byte("Ix"))
	readUntil(t, ws, 'O', 3*time.Second)
	_ = ws.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		fp.mu.Lock()
		k := fp.killed
		fp.mu.Unlock()
		if k {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("closing the socket must kill the shell")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSessionRootRefusedWithoutStepup(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen, sessionOpRoot}, nil)
	withFake(t)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpRoot, GrantB64: terms, SigB64: sig, SessionID: "sess-root"})
	got := readUntil(t, ws, 'X', 3*time.Second)
	if string(got['X']) != "126" || !strings.Contains(string(got['E']), "session:root") {
		t.Fatalf("want X 126 + E about session:root, got X=%q E=%q", got['X'], got['E'])
	}
	// When the daemon IS root, the refusal must be the step-up one (no factor enrolled
	// / no approval), never a spawn: the audit says refused, and no transcript exists.
	if _, err := os.Stat(filepath.Join(env.CtxRoot, "sessions", "sess-root.log")); err == nil {
		t.Fatal("root refused must not leave a transcript")
	}
}

func TestSessionRootApprovalBindsToSession(t *testing.T) {
	// The purpose the user approves names the server AND the session id, so an
	// approval for one root shell cannot open another.
	p1, err := purposeForSessionRoot("box1", "sess-a")
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := purposeForSessionRoot("box1", "sess-b")
	if p1 == p2 {
		t.Fatal("purposes for different sessions must differ")
	}
	if got, err := purposeFromDetails(map[string]any{"kind": "session_root", "server": "box1", "session_id": "sess-a"}); err != nil || got != p1 {
		t.Fatalf("purposeFromDetails: %q %v", got, err)
	}
	if _, err := purposeForSessionRoot("box1", "a|b"); err == nil {
		t.Fatal("reserved character must be refused")
	}
}

func TestSessionBadSpecIsExit1(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	withFake(t)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, GrantB64: terms, SigB64: sig, SessionID: "../../etc"})
	got := readUntil(t, ws, 'X', 3*time.Second)
	if string(got['X']) != "1" {
		t.Fatalf("bad session_id must be exit 1, got %q", got['X'])
	}
}

func TestSessionShellListedAndPasswd(t *testing.T) {
	dir := t.TempDir()
	shells := filepath.Join(dir, "shells")
	_ = os.WriteFile(shells, []byte("# list\n/bin/sh\n/bin/bash\n"), 0o644)
	if !sessionShellListed(shells, "/bin/bash") || sessionShellListed(shells, "/bin/cat") || sessionShellListed(shells, "bash") {
		t.Fatal("shell allowlist wrong")
	}
	passwd := filepath.Join(dir, "passwd")
	_ = os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"), 0o644)
	if sessionShellFromPasswd(passwd, "root") != "/bin/bash" || sessionShellFromPasswd(passwd, "nobody") != "/usr/sbin/nologin" || sessionShellFromPasswd(passwd, "x") != "" {
		t.Fatal("passwd shell parse wrong")
	}
}

// TestSessionRealPtyCat runs the real spawner with /bin/cat standing in as the shell
// (allowed through a fixture /etc/shells): input must come back through a real pty,
// with a real process group, and closing the socket must reap it.
func TestSessionRealPtyCat(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real pty test is linux-only")
	}
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("no /bin/cat")
	}
	shells := filepath.Join(t.TempDir(), "shells")
	_ = os.WriteFile(shells, []byte("/bin/cat\n"), 0o644)
	oldShells := sessionShellsPath
	sessionShellsPath = shells
	t.Cleanup(func() { sessionShellsPath = oldShells })

	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, Shell: "/bin/cat", Cols: 80, Rows: 24, GrantB64: terms, SigB64: sig, SessionID: "sess-real-cat"})
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte("Iping\r")); err != nil {
		t.Fatal(err)
	}
	// A pty echoes the typed line and cat writes it back: "ping" appears at least once.
	deadline := time.Now().Add(5 * time.Second)
	var seen []byte
	_ = ws.SetReadDeadline(deadline)
	for !strings.Contains(string(seen), "ping") {
		_, data, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v (seen %q)", err, seen)
		}
		if len(data) > 0 && data[0] == 'E' {
			t.Fatalf("E frame: %s", data[1:])
		}
		if len(data) > 0 && data[0] == 'O' {
			seen = append(seen, data[1:]...)
		}
	}
	// Ctrl-D ends cat -> X with cat's exit.
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte{'I', 4}); err != nil {
		t.Fatal(err)
	}
	got := readUntil(t, ws, 'X', 5*time.Second)
	if string(got['X']) != "0" {
		t.Fatalf("cat exit: %q (E=%q)", got['X'], got['E'])
	}
	raw, err := os.ReadFile(filepath.Join(env.CtxRoot, "sessions", "sess-real-cat.log"))
	if err != nil || !strings.Contains(string(raw), "ping") || !strings.Contains(string(raw), "reason=exit") {
		t.Fatalf("transcript: %v\n%s", err, raw)
	}
}

// TestSessionSpawnFailureLeavesNoTranscript: a spawn that fails must leave no
// O_EXCL file behind, so the same session id (and a root approval bound to it) can
// be retried.
func TestSessionSpawnFailureLeavesNoTranscript(t *testing.T) {
	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	old := sessionSpawn
	sessionSpawn = func(op, shell string, cols, rows int) (sessionProc, error) {
		return nil, errBoom
	}
	t.Cleanup(func() { sessionSpawn = old })
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, GrantB64: terms, SigB64: sig, SessionID: "sess-nospawn"})
	got := readUntil(t, ws, 'X', 3*time.Second)
	if string(got['X']) != "1" || !strings.Contains(string(got['E']), "boom") {
		t.Fatalf("X=%q E=%q", got['X'], got['E'])
	}
	if _, err := os.Stat(filepath.Join(env.CtxRoot, "sessions", "sess-nospawn.log")); err == nil {
		t.Fatal("failed spawn must not leave a transcript")
	}
	// And the id is retryable: a second attempt with a working spawner succeeds.
	fp := withFake(t)
	ws2 := sessionDial(t, env)
	sendSpec(t, ws2, sessionSpec{Op: sessionOpOpen, GrantB64: terms, SigB64: sig, SessionID: "sess-nospawn"})
	_ = ws2.WriteMessage(websocket.BinaryMessage, []byte("Iok"))
	readUntil(t, ws2, 'O', 3*time.Second)
	fp.Kill()
	if got := readUntil(t, ws2, 'X', 3*time.Second); string(got['X']) != "0" {
		t.Fatalf("retry after failed spawn: X=%q E=%q", got['X'], got['E'])
	}
}

var errBoom = errBoomT{}

type errBoomT struct{}

func (errBoomT) Error() string { return "boom: no shell today" }

// TestSessionWorkerLaneRouting: a session worker refuses an H frame with a plain
// line + X 1; a harness worker refuses an S frame the same way.
func TestSessionWorkerLaneRouting(t *testing.T) {
	env, _, _ := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	up := websocket.Upgrader{}
	serve := func(handler func(*websocket.Conn)) *websocket.Conn {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			handler(c)
		}))
		t.Cleanup(srv.Close)
		ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ws.Close() })
		return ws
	}
	ws := serve(func(c *websocket.Conn) { handleSessionWorkerConn(c, "", env) })
	_ = ws.WriteMessage(websocket.BinaryMessage, []byte(`H{"harness_id":"x","mode":"echo"}`))
	got := readUntil(t, ws, 'X', 3*time.Second)
	if string(got['X']) != "1" || !strings.Contains(string(got['E']), "session worker") {
		t.Fatalf("session worker given H: X=%q E=%q", got['X'], got['E'])
	}
	ws = serve(func(c *websocket.Conn) { handleHarnessConn(c, "", "") })
	_ = ws.WriteMessage(websocket.BinaryMessage, []byte(`S{"op":"session:open","session_id":"sess-wrong-lane"}`))
	got = readUntil(t, ws, 'X', 3*time.Second)
	if string(got['X']) != "1" || !strings.Contains(string(got['E']), "harness worker") {
		t.Fatalf("harness worker given S: X=%q E=%q", got['X'], got['E'])
	}
}

// TestSessionRefusesTerminalServers: tmux/screen are servers that outlive the
// session's kill, so they are never the session shell even when /etc/shells lists them.
func TestSessionRefusesTerminalServers(t *testing.T) {
	shells := filepath.Join(t.TempDir(), "shells")
	_ = os.WriteFile(shells, []byte("/usr/bin/tmux\n/usr/bin/screen\n/bin/sh\n"), 0o644)
	old := sessionShellsPath
	sessionShellsPath = shells
	t.Cleanup(func() { sessionShellsPath = old })
	for _, sh := range []string{"/usr/bin/tmux", "/usr/bin/screen"} {
		if _, err := sessionResolveIdentity(sessionOpOpen, sh); err == nil || !strings.Contains(err.Error(), "terminal server") {
			t.Fatalf("%s must be refused as a session shell, got %v", sh, err)
		}
	}
	if !sessionShellIsServer("/opt/homebrew/bin/tmux") || sessionShellIsServer("/bin/zsh") {
		t.Fatal("sessionShellIsServer wrong")
	}
}

// TestSessionUnprivilegedHasNoRootGroups: when the daemon is root the spawned
// shell must carry exactly the session user's gid — no inherited supplementary
// groups, and never group 0. Runs the real spawner with /bin/sh and reads `id -G`.
func TestSessionUnprivilegedHasNoRootGroups(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs linux + root")
	}
	shells := filepath.Join(t.TempDir(), "shells")
	_ = os.WriteFile(shells, []byte("/bin/sh\n"), 0o644)
	old := sessionShellsPath
	sessionShellsPath = shells
	t.Cleanup(func() { sessionShellsPath = old })

	env, terms, sig := sessionTestEnv(t, []string{sessionOpOpen}, nil)
	ws := sessionDial(t, env)
	sendSpec(t, ws, sessionSpec{Op: sessionOpOpen, Shell: "/bin/sh", GrantB64: terms, SigB64: sig, SessionID: "sess-groups"})
	first := readUntil(t, ws, 'O', 10*time.Second) // the prompt: the shell is up and reading
	if len(first['E']) > 0 {
		t.Fatalf("E: %s", first['E'])
	}
	_ = ws.WriteMessage(websocket.BinaryMessage, []byte("Iecho GROUPS=$(id -G); echo UID=$(id -u); exit\r"))
	got := readUntil(t, ws, 'X', 10*time.Second)
	out := string(first['O']) + string(got['O'])
	line := ""
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "GROUPS=") && !strings.Contains(l, "$(") {
			line = strings.TrimPrefix(l, "GROUPS=")
		}
	}
	if line == "" {
		t.Fatalf("no GROUPS line in output:\n%s", out)
	}
	groups := strings.Fields(line)
	if len(groups) != 1 {
		t.Fatalf("shell carries supplementary groups %v (want exactly the session gid)", groups)
	}
	if groups[0] == "0" {
		t.Fatalf("shell is in group 0: %v", groups)
	}
	if strings.Contains(out, "UID=0") {
		t.Fatalf("shell runs as uid 0:\n%s", out)
	}
}

// A TERMINAL MUST NOT REQUIRE A FOLDER GRANT FIRST.
//
// Until 0.24.1 the box's pinned host key was written by exactly one thing — a
// DCN store sync — so "let the host open a terminal here" was inseparable from
// "give the host a folder here". Two different permissions, welded together by
// where the key happened to live. Measured across one deployment: 19 of 20
// online machines held zero DCN grants, so no terminal could open on any of
// them, and the refusal read "sync a grant first", which sounds like advice and
// is actually a coupling.
//
// The session frame now carries the host's own verify key and the box TOFU-pins
// it — the same shape, the same lane and the same mismatch rule as the DCN pin.
func TestSessionPinsTheHostKeyWithoutAStoreGrant(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	key := base64.StdEncoding.EncodeToString(pub)
	hn, _ := os.Hostname()

	// A signed grant the host would send for session:open on this machine.
	terms, sig := func() (string, string) {
		b, _ := json.Marshal(map[string]any{
			"server": hn, "ops": []string{sessionOpOpen},
			"expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		return base64.StdEncoding.EncodeToString(b),
			base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
	}()

	// BEFORE: no key pinned and none offered — the old behaviour, unchanged.
	if _, err := sessionVerifyGrant(dir, "", hn, sessionOpOpen, terms, sig, ""); err == nil ||
		!contains(err.Error(), "no entity key pinned") {
		t.Fatalf("a box with no pin and no offer must still refuse: %v", err)
	}
	f, _ := dcnLoadFile(dir)
	if f.VerifyPubkey != "" {
		t.Fatal("a refused verify must not have pinned anything")
	}

	// THE FIX: the host offers its key, the box pins it, the grant verifies —
	// with no store grant anywhere.
	if _, err := sessionVerifyGrant(dir, "", hn, sessionOpOpen, terms, sig, key); err != nil {
		t.Fatalf("a terminal must open with no DCN store grant: %v", err)
	}
	f, _ = dcnLoadFile(dir)
	if f.VerifyPubkey != key {
		t.Fatalf("the host key must be pinned: %q", f.VerifyPubkey)
	}
	if len(f.Stores) != 0 {
		t.Fatalf("pinning must NOT invent a store grant: %v", f.Stores)
	}

	// AND IT IS A PIN, NOT A HANDOFF. A second, different key is refused —
	// otherwise anything that could reach the lane could re-home the box.
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	b2, _ := json.Marshal(map[string]any{
		"server": hn, "ops": []string{sessionOpOpen},
		"expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	t2 := base64.StdEncoding.EncodeToString(b2)
	s2 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv2, b2))
	if _, err := sessionVerifyGrant(dir, "", hn, sessionOpOpen, t2, s2,
		base64.StdEncoding.EncodeToString(pub2)); err == nil || !contains(err.Error(), "mismatch") {
		t.Fatalf("a different key must be refused, not re-pinned: %v", err)
	}
	f, _ = dcnLoadFile(dir)
	if f.VerifyPubkey != key {
		t.Fatalf("a refused re-pin must leave the original key: %q", f.VerifyPubkey)
	}

	// A malformed offer is refused and pins nothing.
	dir2 := t.TempDir()
	if _, err := sessionVerifyGrant(dir2, "", hn, sessionOpOpen, terms, sig, "not-base64!!"); err == nil ||
		!contains(err.Error(), "malformed") {
		t.Fatalf("a malformed key must be refused: %v", err)
	}
	f2, _ := dcnLoadFile(dir2)
	if f2.VerifyPubkey != "" {
		t.Fatalf("a malformed offer must pin nothing: %q", f2.VerifyPubkey)
	}
}
