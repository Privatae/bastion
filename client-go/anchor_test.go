//go:build !windows

// Tagged !windows. These tests were ALREADY unix-only — they use
// helpers that live behind `//go:build !windows` (sessionShellsPath,
// withConfigDir, withMarkerAt, setupBox) — so this file has never compiled for
// Windows and `GOOS=windows go vet ./...` has been red on it since it was
// written. The tag removes no coverage; it states a dependency that was already
// there so vet can run clean on that target, which is what makes a REAL Windows
// regression visible instead of being lost in a failure everyone scrolls past.
// Windows-safe coverage of the machine-authority gate lives in privilege_test.go.
//
// IF YOU USE setupBox, driveOp, writePairingState, signTerms, grantTerms OR
// tMember/tAnchor IN A NEW TEST FILE, that file needs `//go:build !windows` on
// line 1 as well. buildtags_test.go checks this and prints the exact fix — it
// exists because the mistake was made twice in quick succession, both times by someone
// who had run `GOOS=windows go build ./...`, which does NOT compile test files
// and reports green. `GOOS=windows go vet ./...` is the command that sees it.

package main

// Anchoring gates: the walls this box enforces on its
// own, with no host in the loop. Each test is one way a pairing could gain
// lanes it was not granted, or one way a lost anchor could brick the box.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const (
	tAnchor = "anchor.host.privatae.ai"
	tMember = "member.host.privatae.ai"
)

// setupBox: a networked, anchored box in a temp config dir with a pinned
// anchor verify key. Returns the anchor host's signing key (what the anchor
// host's entity_sign key would be).
func setupBox(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := modePath()
	_ = os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600)
	writePairing(t, tAnchor)
	if err := writeAnchor("Acme IT", tAnchor); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := pinAnchorVerifyKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	return priv
}

func writePairingState(t testing.TB, host, state string) {
	t.Helper()
	pd, _ := pairingsDir()
	b, _ := json.Marshal(Config{HostName: host, WGPrivateKey: "k", BastionTunnelIP: "fd00:9::a:1", State: state})
	if err := os.WriteFile(filepath.Join(pd, host+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadState(t *testing.T, host string) string {
	t.Helper()
	cfgs, err := loadPairings()
	if err != nil {
		t.Fatal(err)
	}
	c := pairingFor(cfgs, host)
	if c == nil {
		t.Fatalf("%s not paired", host)
	}
	return c.stateName()
}

// signTerms signs canonical terms (sorted keys, no whitespace — what Go's
// json.Marshal of a map produces) and returns the two b64 args the ops take.
func signTerms(t *testing.T, priv ed25519.PrivateKey, terms map[string]any) (string, string) {
	t.Helper()
	canonical, err := json.Marshal(terms)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(canonical),
		base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))
}

func grantTerms(subject string, caps []string, expires string) map[string]any {
	hn, _ := os.Hostname()
	return map[string]any{"anchor": tAnchor, "caps": caps, "expires": expires,
		"issued_at": time.Now().UTC().Format(time.RFC3339), "kind": "pairing_grant",
		"server": hn, "subject": subject, "subject_handle": handleOf(subject)}
}

// driveOp runs one job through the real mgmt frame path as pairing `self`.
func driveOp(t *testing.T, self, op string, args []string) (string, string, int) {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConnFor(ws, self, "", "", "")
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// A write on an anchored box carries the person's approval (writes.go);
	// testApproval (hostops_test.go) signs one from a test device so a test
	// about something else is not refused at the gate. The gate's own tests
	// drive raw jobs and never go through here.
	job, _ := json.Marshal(mgmtJob{Op: op, Args: args, Approval: testApproval(t, op, args)})
	if err := c.WriteMessage(websocket.BinaryMessage, append([]byte("C"), job...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errOut string
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch data[0] {
		case 'O':
			out += string(data[1:])
		case 'R':
			errOut += string(data[1:])
		case 'X':
			var code int
			fmt.Sscanf(string(data[1:]), "%d", &code)
			return out, errOut, code
		}
	}
}

// ── mode ───────────────────────────────────────────────────────────────────

// LOCAL mode is the whole protection for a single-user machine: one host, and
// a second token is refused before the redeem so it is not burned. --replace
// of the one host still works (a rotation is not a second host).
func TestLocalModeRefusesSecondPairing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if boxMode() != modeLocal {
		t.Fatalf("a box with no mode file must be LOCAL, got %s", boxMode())
	}
	writePairing(t, tAnchor)
	cfgs, _ := loadPairings()

	_, _, err := pairPrecheck(cfgs, "other", false, false)
	if err == nil || !contains(err.Error(), "local mode") {
		t.Fatalf("local mode must refuse a second pairing with a plain message, got %v", err)
	}
	if _, _, err := pairPrecheck(cfgs, "anchor", true, false); err != nil {
		t.Fatalf("--replace of the one host must still be allowed in local mode: %v", err)
	}
	if _, st, err := pairPrecheck(nil, "first", false, false); err != nil || st != "" {
		t.Fatalf("the first pairing on a local box is active: state %q err %v", st, err)
	}
}

// Networked + anchored: every pairing after the anchor is written PENDING.
func TestAnchoredBoxWritesNewPairingsPending(t *testing.T) {
	setupBox(t)
	cfgs, _ := loadPairings()
	_, st, err := pairPrecheck(cfgs, "member", false, false)
	if err != nil || st != pairingPending {
		t.Fatalf("a pairing after the anchor must be pending: state %q err %v", st, err)
	}
	// claim-anchor's own redeem is never pending (forceActive)
	_, st, err = pairPrecheck(nil, "anchor", false, true)
	if err != nil || st != pairingActive {
		t.Fatalf("the anchor's own redeem must be active: state %q err %v", st, err)
	}
	// --replace keeps the current state: a credential rotation is not an approval
	writePairingState(t, tMember, pairingPending)
	cfgs, _ = loadPairings()
	_, st, err = pairPrecheck(cfgs, "member", true, false)
	if err != nil || st != pairingPending {
		t.Fatalf("--replace must keep a pending pairing pending: state %q err %v", st, err)
	}
}

func TestSetModeNetworkedNeedsRoot(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if os.Geteuid() == 0 {
		if err := setBoxMode(modeNetworked); err != nil || boxMode() != modeNetworked {
			t.Fatalf("root must be able to set networked: %v", err)
		}
		return
	}
	if err := setBoxMode(modeNetworked); err == nil {
		t.Fatal("networked mode must need root")
	}
	if boxMode() != modeLocal {
		t.Fatal("a refused set-mode must not have written anything")
	}
}

// ── a pending pairing is a file ───────────────────────────────────────────

// The guard above everything in runPairing: a pending pairing returns before
// a device, a listener, a lane or even a directory exists. The dirs are the
// observable half — contextRoot()/dcnDir() create on read, so if runPairing
// had reached them the temp config dir would show context/ and dcn/.
func TestPendingPairingStartsNothing(t *testing.T) {
	setupBox(t)
	cd, _ := configDir()
	cfg := &Config{HostName: tMember, State: pairingPending, BastionTunnelIP: "fd00:9::a:2",
		ContextRoot: filepath.Join(cd, "context", tMember), DCNDir: filepath.Join(cd, "dcn", tMember),
		ListenAddr: "127.0.0.1:0"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := runPairing(ctx, cfg); err != errPairingNotActive {
		t.Fatalf("runPairing on a pending pairing must return errPairingNotActive, got %v", err)
	}
	for _, d := range []string{cfg.ContextRoot, cfg.DCNDir} {
		if _, err := os.Stat(d); err == nil {
			t.Errorf("a pending pairing created %s — it must create nothing", d)
		}
	}
	if startPairing(cfg) {
		t.Fatal("startPairing must refuse a pending pairing")
	}
	cfg.State = pairingRevoked
	if err := runPairing(ctx, cfg); err != errPairingNotActive {
		t.Fatalf("a revoked pairing must not start either, got %v", err)
	}
}

// ── grant verify ───────────────────────────────────────────────────────────

func TestPairingGrantSyncWalls(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	hn, _ := os.Hostname()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	// good: pending -> active, grant persisted, caps reported
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe", "dcn"}, future))
	out, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig})
	if code != 0 {
		t.Fatalf("a good grant must be accepted: exit %d, %s", code, errOut)
	}
	if loadState(t, tMember) != pairingActive {
		t.Fatal("grant_sync must flip the pairing active")
	}
	if !contains(out, `"caps":["dcn","observe"]`) {
		t.Fatalf("result must carry the caps: %s", out)
	}
	if caps, ok := pairingCaps(tMember); !ok || len(caps) != 2 {
		t.Fatalf("the persisted grant must verify and carry caps: %v %v", caps, ok)
	}

	// bad key: a grant from anyone but the pinned anchor host
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	writePairingState(t, "x.host.privatae.ai", pairingPending)
	terms, sig = signTerms(t, otherPriv, grantTerms("x.host.privatae.ai", []string{"observe"}, future))
	if _, errOut, code = driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 126 || !contains(errOut, "signature") {
		t.Fatalf("a grant under another key must be refused (126): %d %s", code, errOut)
	}
	if loadState(t, "x.host.privatae.ai") != pairingPending {
		t.Fatal("a refused grant must leave the pairing pending")
	}

	// wrong server: signed for another machine
	wrong := grantTerms("x.host.privatae.ai", []string{"observe"}, future)
	wrong["server"] = hn + "-not"
	terms, sig = signTerms(t, priv, wrong)
	if _, errOut, code = driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 126 || !contains(errOut, "server") {
		t.Fatalf("a grant for another server must be refused: %d %s", code, errOut)
	}

	// wrong anchor: names a different anchor host
	wrong = grantTerms("x.host.privatae.ai", []string{"observe"}, future)
	wrong["anchor"] = "someone-else.host.privatae.ai"
	terms, sig = signTerms(t, priv, wrong)
	if _, errOut, code = driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 126 || !contains(errOut, "anchor") {
		t.Fatalf("a grant naming another anchor must be refused: %d %s", code, errOut)
	}

	// expired
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	terms, sig = signTerms(t, priv, grantTerms("x.host.privatae.ai", []string{"observe"}, past))
	if _, errOut, code = driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 126 || !contains(errOut, "expired") {
		t.Fatalf("an expired grant must be refused: %d %s", code, errOut)
	}

	// not pending: an unknown subject, and a revoked one
	terms, sig = signTerms(t, priv, grantTerms("ghost.host.privatae.ai", []string{"observe"}, future))
	if _, errOut, code = driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 126 || !contains(errOut, "not paired") {
		t.Fatalf("a grant for an unpaired subject must be refused: %d %s", code, errOut)
	}
	writePairingState(t, "gone.host.privatae.ai", pairingRevoked)
	terms, sig = signTerms(t, priv, grantTerms("gone.host.privatae.ai", []string{"observe"}, future))
	if _, errOut, code = driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 126 || !contains(errOut, "revoked") {
		t.Fatalf("a grant for a revoked subject must be refused: %d %s", code, errOut)
	}

	// the anchor itself holds no grant
	terms, sig = signTerms(t, priv, grantTerms(tAnchor, []string{"observe"}, future))
	if _, _, code = driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 126 {
		t.Fatalf("a grant for the anchor itself must be refused: %d", code)
	}
}

// pairing_* ops answer ONLY on the anchor pairing's connection. A member — or
// an anonymous caller — asking is refused before any handler runs.
func TestPairingOpsRefusedOffTheAnchorConnection(t *testing.T) {
	setupBox(t)
	writePairingState(t, tMember, pairingActive)
	for _, self := range []string{tMember, ""} {
		if _, errOut, code := driveOp(t, self, "pairing_list", nil); code != 126 || !contains(errOut, "anchor") {
			t.Fatalf("pairing_list from %q must be refused: %d %s", self, code, errOut)
		}
	}
	out, _, code := driveOp(t, tAnchor, "pairing_list", nil)
	if code != 0 || !contains(out, tMember) || !contains(out, `"anchor_host":"`+tAnchor+`"`) {
		t.Fatalf("pairing_list from the anchor must list pairings + anchor: %d %s", code, out)
	}
}

// ── drop ───────────────────────────────────────────────────────────────────

// A revoke marks the pairing revoked, keeps the file, and cancels the running
// pairing's context at once. The supervisor is driven with a stand-in run so
// the test observes the cancel without a real tunnel.
func TestPairingGrantDropTearsDown(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingActive)
	hn, _ := os.Hostname()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	supervisor.Lock()
	supervisor.runs = map[string]*pairingRun{tMember: {cancel: cancel, done: done}}
	supervisor.Unlock()
	t.Cleanup(func() {
		supervisor.Lock()
		supervisor.runs = nil
		supervisor.Unlock()
	})
	go func() { <-ctx.Done(); close(done) }()

	terms, sig := signTerms(t, priv, map[string]any{"anchor": tAnchor, "issued_at": time.Now().UTC().Format(time.RFC3339),
		"kind": "pairing_revoke", "server": hn, "subject": tMember})
	// subject arg must match the signed subject
	if _, _, code := driveOp(t, tAnchor, "pairing_grant_drop", []string{"other.host.privatae.ai", terms, sig}); code != 126 {
		t.Fatalf("a revoke whose arg names another subject must be refused: %d", code)
	}
	if ctx.Err() != nil {
		t.Fatal("a refused revoke must not have torn anything down")
	}
	if _, err := addBackupShare(tMember, t.TempDir(), t.TempDir(), "old host"); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := driveOp(t, tAnchor, "pairing_grant_drop", []string{tMember, terms, sig})
	if code != 0 {
		t.Fatalf("a good revoke must be accepted: %d %s", code, errOut)
	}
	if len(sharesFor(tMember)) != 0 || !contains(out, `"backup_shares_dropped":true`) {
		t.Fatalf("a revoked pairing kept the backup folders shared with it: %s", out)
	}
	if ctx.Err() == nil {
		t.Fatal("drop must cancel the pairing's context immediately")
	}
	if !contains(out, `"stopped":true`) {
		t.Fatalf("drop must report it stopped the running pairing: %s", out)
	}
	if loadState(t, tMember) != pairingRevoked {
		t.Fatal("drop must mark the pairing revoked")
	}
	pd, _ := pairingsDir()
	if _, err := os.Stat(filepath.Join(pd, tMember+".json")); err != nil {
		t.Fatal("drop must keep the pairing file")
	}
	if _, ok := pairingCaps(tMember); ok {
		t.Fatal("a revoked pairing must hold no caps")
	}
	// the anchor cannot revoke itself
	terms, sig = signTerms(t, priv, map[string]any{"anchor": tAnchor, "issued_at": time.Now().UTC().Format(time.RFC3339),
		"kind": "pairing_revoke", "server": hn, "subject": tAnchor})
	if _, _, code := driveOp(t, tAnchor, "pairing_grant_drop", []string{tAnchor, terms, sig}); code != 126 {
		t.Fatalf("the anchor revoking itself must be refused: %d", code)
	}
}

// ── caps ceiling ───────────────────────────────────────────────────────────

func TestCapsRefusal(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}

	// observe family passes the ceiling and reaches the handler (uptime runs)
	if _, errOut, code := driveOp(t, tMember, "uptime", nil); code == 126 {
		t.Fatalf("an op inside caps must not be refused by the ceiling: %s", errOut)
	}
	// dcn family is outside the ceiling → refused before the handler
	if _, errOut, code := driveOp(t, tMember, "dcn_list", []string{"1", "{}"}); code != 126 || !contains(errOut, "caps") {
		t.Fatalf("an op outside caps must be refused with the caps quoted: %d %s", code, errOut)
	}
	if _, errOut, code := driveOp(t, tMember, "ctx_get", []string{"k"}); code != 126 || !contains(errOut, "caps") {
		t.Fatalf("ctx_* is the dcn family and must be refused: %d %s", code, errOut)
	}
	// stepup_* IS caps-gated, on the family of the thing being
	// approved rather than on a family of its own (stepupOpFamily). With no DCN
	// root configured there is no request store to read a kind from, so this one
	// reaches the handler and is refused for the unconfigured root — a different
	// reason, and the distinction is the point. The gating itself is covered by
	// TestStepupIsGatedOnTheApprovedFamily.
	if _, errOut, _ := driveOp(t, tMember, "stepup_status", []string{"x"}); contains(errOut, "caps") {
		t.Fatalf("stepup_status with no request store must reach the handler: %s", errOut)
	}
	// the anchor pairing is unconstrained
	if _, errOut, code := driveOp(t, tAnchor, "dcn_list", []string{"1", "{}"}); code == 126 && contains(errOut, "caps") {
		t.Fatalf("the anchor pairing must not be caps-gated: %s", errOut)
	}
	// a pairing with no grant on an anchored box is default-deny
	writePairingState(t, "nogrant.host.privatae.ai", pairingActive)
	if why := capsAllow("nogrant.host.privatae.ai", "uptime"); why == "" {
		t.Fatal("a pairing holding no grant must be refused every op")
	}
	// the enforcing report states the ceiling
	rep := pairingEnforcing(tMember)
	if caps, _ := rep["pairing_caps"].([]string); len(caps) != 1 || caps[0] != "observe" {
		t.Fatalf("enforcing must report pairing_caps: %+v", rep)
	}
	if rep["pairing_state"] != pairingActive {
		t.Fatalf("enforcing must report pairing_state: %+v", rep)
	}
	// tampering the grant file authorises nothing: widen the caps inside the
	// canonical bytes and leave the signature — it no longer verifies
	g, err := loadPairingGrant(tMember)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := base64.StdEncoding.DecodeString(g.TermsCanonical)
	g.TermsCanonical = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(canonical), `"observe"`, `"session"`, 1)))
	if err := savePairingGrant(tMember, g); err != nil {
		t.Fatal(err)
	}
	if _, ok := pairingCaps(tMember); ok {
		t.Fatal("a hand-edited grant file must not verify")
	}
	if why := capsAllow(tMember, "uptime"); why == "" {
		t.Fatal("a pairing whose grant no longer verifies must be refused every op")
	}
}

func TestOpFamilies(t *testing.T) {
	for op, want := range map[string]string{
		"observe:sockets": "observe", "computer:windows": "observe", "uptime": "observe",
		"session:open": "session", "dcn_list": "dcn", "ctx_put": "dcn", "backup_fetch": "dcn",
		// ctx_extract runs a PROGRAM, so its family is the one thing standing
		// between a member pairing and an extractor on this machine. opFamily
		// returns "" for a name it does not know and capsAllow then allows —
		// so this row is the guard against a rename opening that door.
		"ctx_extract": "dcn",
		"harness:run": "harness", "mode:lab": "harness", "egress": "egress",
		// Neither of these is grantable, and that is what they are for.
		// capsAllowIn default-denies an op in no family, so leaving either
		// unclassified would refuse it everywhere; classifying them into
		// families absent from allCaps refuses only the pairings that should
		// never reach them. stepup_* has its real ceiling resolved per request
		// (stepupOpFamily); pairing_* is refused by the anchor rule first.
		"stepup_request": capsFamilyStepup, "pairing_list": capsFamilyAnchor,
	} {
		if got := opFamily(op); got != want {
			t.Errorf("opFamily(%q) = %q, want %q", op, got, want)
		}
	}
}

// ── rotation ───────────────────────────────────────────────────────────────

func TestAnchorRotationPaths(t *testing.T) {
	priv := setupBox(t)
	prev := currentAnchor()
	hn, _ := os.Hostname()
	now := time.Now()

	// fresh anchor, no consent: refused
	if _, err := rotationPermitted(prev, "next", now); err == nil {
		t.Fatal("rotation without consent from a live anchor must be refused")
	}
	// silence path: 15 days after the last successful beat, root alone may rotate
	recordPairingOK(tAnchor)
	if _, err := rotationPermitted(prev, "next", now.Add(15*24*time.Hour)); err != nil {
		t.Fatalf("14 days of silence must permit rotation: %v", err)
	}
	if _, err := rotationPermitted(prev, "next", now.Add(13*24*time.Hour)); err == nil {
		t.Fatal("13 days of silence must NOT permit rotation")
	}

	// consent path: the anchor's signed word, delivered by the op, names the next anchor
	terms, sig := signTerms(t, priv, map[string]any{"anchor": tAnchor, "issued_at": now.UTC().Format(time.RFC3339),
		"kind": "anchor_consent", "server": hn, "subject": "next.host.privatae.ai"})
	if _, errOut, code := driveOp(t, tMember, "pairing_anchor_consent", []string{terms, sig}); code != 126 {
		t.Fatalf("consent from a non-anchor connection must be refused: %d %s", code, errOut)
	}
	if _, errOut, code := driveOp(t, tAnchor, "pairing_anchor_consent", []string{terms, sig}); code != 0 {
		t.Fatalf("consent from the anchor must be stored: %d %s", code, errOut)
	}
	c, err := rotationPermitted(prev, "next", now)
	if err != nil || c == nil || c.Subject != "next.host.privatae.ai" {
		t.Fatalf("a stored consent naming the token's host must permit rotation: %v %+v", err, c)
	}
	if _, err := rotationPermitted(prev, "someone-else", now); err == nil {
		t.Fatal("consent naming another host must not permit rotation to this one")
	}
	if _, err := rotationPermitted(prev, "next", now.Add(31*24*time.Hour)); err == nil {
		t.Fatal("a consent older than 30 days must not be usable")
	}
	// a consent signed by anyone else is refused at the op
	_, other, _ := ed25519.GenerateKey(nil)
	terms, sig = signTerms(t, other, map[string]any{"anchor": tAnchor, "issued_at": now.UTC().Format(time.RFC3339),
		"kind": "anchor_consent", "server": hn, "subject": "next.host.privatae.ai"})
	if _, _, code := driveOp(t, tAnchor, "pairing_anchor_consent", []string{terms, sig}); code != 126 {
		t.Fatalf("a consent under another key must be refused: %d", code)
	}
}

// claim-anchor's own walls that need no network: root, mode, already anchored.
func TestClaimAnchorWalls(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// cmdClaimAnchor runs singletonGuardForPair BEFORE the mode check, and
	// deliberately so (anchor.go:729-736: both later calls would MkdirAll a
	// forked config dir first). XDG_CONFIG_HOME does not reach the machine
	// marker — that path is machine-scoped (/var/lib/privatae/bastion) — so
	// without this the guard reads the REAL marker of whatever bastion is
	// installed here, refuses with "another bastion owns this machine", and
	// the mode assertion below never runs. Only bites as root on a box that
	// HAS a bastion, which is why it passes on a clean builder and fails on
	// any machine that already runs one.
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	token := "skb_" + base64.RawURLEncoding.EncodeToString([]byte("next.secret"))
	if os.Geteuid() != 0 {
		if err := cmdClaimAnchor(token, false, "", ""); err == nil || !contains(err.Error(), "machine authority") {
			t.Fatalf("claim-anchor must need machine authority: %v", err)
		}
		return
	}
	// root: local mode refuses
	if err := cmdClaimAnchor(token, false, "", ""); err == nil || !contains(err.Error(), "networked") {
		t.Fatalf("claim-anchor in local mode must be refused: %v", err)
	}
	_ = setBoxMode(modeNetworked)
	writePairing(t, tAnchor)
	_ = writeAnchor("Acme", tAnchor)
	if err := cmdClaimAnchor(token, false, "", ""); err == nil || !contains(err.Error(), "already anchored") {
		t.Fatalf("a second claim-anchor without --rotate must be refused: %v", err)
	}
	if err := cmdClaimAnchor(token, true, "", ""); err == nil || !contains(err.Error(), "consent") {
		t.Fatalf("--rotate on a live anchor without consent must be refused: %v", err)
	}
}

// The no-token path: anchoring a box you have ALREADY paired.
//
// This is the flow the product actually asks for — pair, set-mode networked,
// claim-anchor — and until 0.23.0 the third step demanded a second pairing
// token, minted from the same "Set up a bastion" button, redeemed against a
// machine that was already paired. Nothing surfaced that, and on a box with one
// pairing the token proved nothing the pairing had not already proved.
func TestClaimAnchorWithNoToken(t *testing.T) {
	// Each phase gets its OWN box: a fresh config dir AND a fresh machine marker.
	// They travel together — the marker records which state dir owns the machine,
	// so moving XDG_CONFIG_HOME while leaving the marker behind makes the
	// singleton guard refuse the new dir as a second bastion (which is exactly
	// what it is for).
	freshBox := func(t *testing.T, networked bool) {
		t.Helper()
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
		if networked {
			if err := setBoxMode(modeNetworked); err != nil {
				t.Fatal(err)
			}
		}
	}

	if os.Geteuid() != 0 {
		freshBox(t, false)
		if err := cmdClaimAnchor("", false, "", ""); err == nil || !contains(err.Error(), "machine authority") {
			t.Fatalf("claim-anchor must need machine authority whether or not a token is given: %v", err)
		}
		t.Skip("the rest needs root: without machine authority claim-anchor stops at the refusal checked above")
	}

	t.Run("local mode refuses — the token is not what gates this", func(t *testing.T) {
		freshBox(t, false)
		if err := cmdClaimAnchor("", false, "", ""); err == nil || !contains(err.Error(), "networked") {
			t.Fatalf("no-token claim-anchor in local mode must be refused: %v", err)
		}
	})

	t.Run("no pairing at all — refused, and told how to get one", func(t *testing.T) {
		freshBox(t, true)
		if err := cmdClaimAnchor("", false, "", ""); err == nil || !contains(err.Error(), "no pairing yet") {
			t.Fatalf("an unpaired box must refuse and say to pair first: %v", err)
		}
	})

	t.Run("--rotate still needs a token: it names a different host", func(t *testing.T) {
		freshBox(t, true)
		writePairing(t, tAnchor)
		if err := writeAnchor("Acme", tAnchor); err != nil {
			t.Fatal(err)
		}
		if err := cmdClaimAnchor("", true, "", ""); err == nil || !contains(err.Error(), "--rotate needs a token") {
			t.Fatalf("--rotate with no token must be refused: %v", err)
		}
	})

	t.Run("one pairing, no token — anchors to it", func(t *testing.T) {
		freshBox(t, true)
		writePairingState(t, tMember, pairingPending)
		if err := cmdClaimAnchor("", false, "Acme IT", ""); err != nil {
			t.Fatalf("a box with one pairing must anchor with no token: %v", err)
		}
		a := currentAnchor()
		if a == nil || a.AnchorHost != tMember {
			t.Fatalf("the sole pairing must become the anchor: %+v", a)
		}
		if a.Owner != "Acme IT" {
			t.Fatalf("--owner must still be honoured on the no-token path: %+v", a)
		}
		// "the anchor never waits on itself" — the same rule the forceActive
		// redeem applies, and why a pending sole pairing is not left pending.
		if got := loadState(t, tMember); got != pairingActive {
			t.Fatalf("anchoring must flip the sole pairing active, got %q", got)
		}
		// and the owner claim is re-signed, exactly as the token path does
		if oc := currentOwnerClaim(); oc == nil || oc.Owner != "Acme IT" {
			t.Fatalf("claim-anchor must write the owner claim: %+v", oc)
		}
	})

	t.Run("already anchored to that host — success, and nothing changes", func(t *testing.T) {
		// `pair` anchors a networked box by itself, and an installer that runs
		// claim-anchor afterwards must find that done, not an error.
		freshBox(t, true)
		writePairing(t, tMember)
		if err := writeAnchor("Acme", tMember); err != nil {
			t.Fatal(err)
		}
		if err := cmdClaimAnchor("", false, "", ""); err != nil {
			t.Fatalf("claim-anchor on a box already anchored to its host must succeed: %v", err)
		}
		if err := cmdClaimAnchor("", false, "", tMember); err != nil {
			t.Fatalf("naming the anchor host itself must succeed: %v", err)
		}
		if err := cmdClaimAnchor("", false, "", handleOf(tMember)); err != nil {
			t.Fatalf("naming the anchor host by its handle (as --host accepts) must succeed: %v", err)
		}
		if a := currentAnchor(); a == nil || a.AnchorHost != tMember || a.Owner != "Acme" {
			t.Fatalf("the anchor must be untouched: %+v", a)
		}
	})

	t.Run("anchored to a host whose pairing is pending or revoked — not reported done", func(t *testing.T) {
		// A success here would tell an installer the anchor holds while its
		// host has no active lanes on this box.
		for _, st := range []string{pairingPending, pairingRevoked} {
			freshBox(t, true)
			writePairingState(t, tMember, st)
			if err := writeAnchor("Acme", tMember); err != nil {
				t.Fatal(err)
			}
			if err := cmdClaimAnchor("", false, "", ""); err == nil {
				t.Fatalf("anchor pairing %s: claim-anchor must not report the anchor done", st)
			}
			if got := loadState(t, tMember); got != st {
				t.Fatalf("anchor pairing %s: state changed to %q", st, got)
			}
		}
	})

	t.Run("already anchored — another host is still refused without --rotate", func(t *testing.T) {
		freshBox(t, true)
		writePairing(t, tMember)
		writePairing(t, tAnchor)
		if err := writeAnchor("Acme", tMember); err != nil {
			t.Fatal(err)
		}
		if err := cmdClaimAnchor("", false, "", tAnchor); err == nil || !contains(err.Error(), "already anchored") {
			t.Fatalf("naming a different host must not move the anchor without --rotate: %v", err)
		}
		if a := currentAnchor(); a == nil || a.AnchorHost != tMember {
			t.Fatalf("the anchor must be untouched: %+v", a)
		}
	})

	t.Run("a REVOKED sole pairing is not reinstated", func(t *testing.T) {
		// cfg.active() is false for pending AND revoked, so a bare !active() flip
		// would quietly undo a revocation. pair.go holds the same line for a
		// re-pair: pending again, never straight back to active.
		freshBox(t, true)
		writePairingState(t, tMember, pairingRevoked)
		err := cmdClaimAnchor("", false, "", "")
		if err == nil || !contains(err.Error(), "REVOKED") {
			t.Fatalf("a revoked sole pairing must be refused, not reinstated: %v", err)
		}
		if got := loadState(t, tMember); got != pairingRevoked {
			t.Fatalf("the refusal must leave it revoked, got %q", got)
		}
		if currentAnchor() != nil {
			t.Fatal("a refused claim must leave the box unanchored")
		}
	})

	t.Run("a bad --owner refuses BEFORE touching the pairing", func(t *testing.T) {
		// The flip is the only state this path writes, so it must be the last
		// thing that happens: a refusal after it leaves a half-applied command.
		freshBox(t, true)
		writePairingState(t, tMember, pairingPending)
		err := cmdClaimAnchor("", false, strings.Repeat("x", 400), "") // claimNameOK caps at 120
		if err == nil || !contains(err.Error(), "owner") {
			t.Fatalf("a bad --owner must be refused: %v", err)
		}
		if got := loadState(t, tMember); got != pairingPending {
			t.Fatalf("a refused claim must not have flipped the pairing, got %q", got)
		}
		if currentAnchor() != nil {
			t.Fatal("a refused claim must leave the box unanchored")
		}
	})

	// THE SHARED MACHINE — the case networked mode exists for, and the one that
	// failed on the first real box: a real desktop serves three hosts, so the
	// first cut of the no-token path refused it and sent the user back for a token.
	t.Run("several pairings: --host names the anchor, no token", func(t *testing.T) {
		freshBox(t, true)
		writePairing(t, tAnchor)
		writePairing(t, tMember)
		writePairing(t, "third.host.privatae.ai")
		if err := cmdClaimAnchor("", false, "", tMember); err != nil {
			t.Fatalf("--host must anchor a multi-pairing box with no token: %v", err)
		}
		a := currentAnchor()
		if a == nil || a.AnchorHost != tMember {
			t.Fatalf("--host must pick THAT host: %+v", a)
		}
		// The others keep the lanes they already had — anchoring governs what
		// happens NEXT, it does not retroactively suspend existing pairings.
		for _, h := range []string{tAnchor, "third.host.privatae.ai"} {
			if got := loadState(t, h); got != pairingActive {
				t.Fatalf("%s must keep its lanes, got %q", h, got)
			}
		}
	})

	t.Run("--host accepts the bare handle, not just the full name", func(t *testing.T) {
		// The error prints full names; Circles shows handles. Whichever the user
		// copied has to work, or the instruction is only half true.
		freshBox(t, true)
		writePairing(t, tAnchor)
		writePairing(t, tMember)
		if err := cmdClaimAnchor("", false, "", handleOf(tMember)); err != nil {
			t.Fatalf("--host must accept the handle alone: %v", err)
		}
		if a := currentAnchor(); a == nil || a.AnchorHost != tMember {
			t.Fatalf("the handle must resolve to that pairing: %+v", a)
		}
	})

	t.Run("--host naming a host this box does not serve is refused", func(t *testing.T) {
		freshBox(t, true)
		writePairing(t, tAnchor)
		writePairing(t, tMember)
		err := cmdClaimAnchor("", false, "", "nobody.host.privatae.ai")
		if err == nil || !contains(err.Error(), "not one of this box's pairings") {
			t.Fatalf("--host must only choose among EXISTING pairings: %v", err)
		}
		if currentAnchor() != nil {
			t.Fatal("a refused claim must leave the box unanchored")
		}
	})

	t.Run("--host with a token is refused rather than silently ignored", func(t *testing.T) {
		// Both answer "which host". Picking one would discard the other, and
		// discarding the token would BURN it — it is single-use and redeemable.
		freshBox(t, true)
		writePairing(t, tMember)
		tok := "skb_" + base64.RawURLEncoding.EncodeToString([]byte("next.secret"))
		err := cmdClaimAnchor(tok, false, "", tMember)
		if err == nil || !contains(err.Error(), "pass one") {
			t.Fatalf("--host plus a token must be refused: %v", err)
		}
	})

	t.Run("two pairings, no token — refused, and told how to choose", func(t *testing.T) {
		freshBox(t, true)
		writePairing(t, tAnchor)
		writePairing(t, tMember)
		err := cmdClaimAnchor("", false, "", "")
		if err == nil || !contains(err.Error(), "--host") {
			t.Fatalf("two pairings with no token must be refused WITH the way out: %v", err)
		}
		// the refusal must NAME them, or the user cannot act on it
		if !contains(err.Error(), tAnchor) || !contains(err.Error(), tMember) {
			t.Fatalf("the ambiguity refusal must name both hosts: %v", err)
		}
		if currentAnchor() != nil {
			t.Fatal("a refused claim must leave the box unanchored")
		}
	})
}

// ── the anchor claim itself ────────────────────────────────────────────────

func TestAnchorClaimIsSignedByTheBoxKeyAndTamperIsAbsent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if currentAnchor() != nil {
		t.Fatal("an unanchored box reports no anchor")
	}
	if err := writeAnchor("Acme IT", tAnchor); err != nil {
		t.Fatal(err)
	}
	a := currentAnchor()
	if a == nil || a.AnchorHost != tAnchor || a.AnchorHandle != "anchor" || a.Owner != "Acme IT" {
		t.Fatalf("anchor did not round-trip: %+v", a)
	}
	// same key as the owner claim: one box, one key
	if _, err := writeOwnerClaim("Acme IT"); err != nil {
		t.Fatal(err)
	}
	if oc := currentOwnerClaim(); oc == nil || oc.PublicKey != a.PublicKey {
		t.Fatal("anchor and owner claims must share the box key")
	}
	// hand-edit the anchor host: the signature covers it, so the claim vanishes
	p, _ := anchorPath()
	raw, _ := os.ReadFile(p)
	_ = os.WriteFile(p, []byte(strings.Replace(string(raw), tAnchor, "evil.host.privatae.ai", 1)), 0o600)
	if currentAnchor() != nil {
		t.Fatal("a tampered anchor must read as no anchor")
	}
}

// The verify key is pinned TOFU from the anchor pairing's DCN pin when the
// anchor file has none, and a different key is refused once one is held.
func TestAnchorVerifyKeyPinsFromDCNAndRefusesRepin(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writePairing(t, tAnchor)
	_ = writeAnchor("Acme", tAnchor)
	if anchorVerifyKey() != "" {
		t.Fatal("a fresh anchor has no verify key")
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	pinned := base64.StdEncoding.EncodeToString(pub)
	cfgs, _ := loadPairings()
	ac := pairingFor(cfgs, tAnchor)
	if err := dcnSaveFile(ac.dcnDir(), &dcnGrantFile{VerifyPubkey: pinned, Stores: map[string]dcnGrantRec{}}); err != nil {
		t.Fatal(err)
	}
	if anchorVerifyKey() != pinned {
		t.Fatal("the anchor verify key must be pinned from the anchor pairing's DCN pin")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if err := pinAnchorVerifyKey(base64.StdEncoding.EncodeToString(other)); err == nil {
		t.Fatal("a different key must not re-pin")
	}
	if err := pinAnchorVerifyKey(pinned); err != nil {
		t.Fatalf("re-pinning the same key is a no-op: %v", err)
	}
}

// ── heartbeat ──────────────────────────────────────────────────────────────

func TestHeartbeatCarriesModeAnchorPairingsAndAttempts(t *testing.T) {
	// local, unanchored: mode rides, nothing else
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	body := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if !contains(body, `"mode":"local"`) {
		t.Fatalf("mode must ride every heartbeat:\n%s", body)
	}
	for _, k := range []string{`"anchor"`, `"pairings"`} {
		if contains(body, k) {
			t.Fatalf("an unanchored box must not carry %s:\n%s", k, body)
		}
	}
	// enumerated and none: an explicit [] (the host COALESCEs an absent key)
	if !contains(body, `"unapproved_pairing_attempts":[]`) {
		t.Fatalf("an enumerated-but-empty attempt set must travel as []:\n%s", body)
	}

	// anchored, with a pending member
	setupBox(t)
	writePairingState(t, tMember, pairingPending)
	var got struct {
		Mode   string `json:"mode"`
		Anchor *struct {
			Owner        string `json:"owner"`
			AnchorHost   string `json:"anchor_host"`
			AnchorHandle string `json:"anchor_handle"`
			ClaimedAt    string `json:"claimed_at"`
			PublicKey    string `json:"public_key"`
			Signature    string `json:"signature"`
			VerifyPubkey string `json:"verify_pubkey"`
		} `json:"anchor"`
		Pairings []pairingEntry `json:"pairings"`
		Attempts []peerAnnounce `json:"unapproved_pairing_attempts"`
	}
	// the anchor's own beat: full list including itself and the pending member
	body = buildHeartbeatBody(tAnchor, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != modeNetworked {
		t.Fatalf("mode = %q", got.Mode)
	}
	if got.Anchor == nil || got.Anchor.AnchorHost != tAnchor || got.Anchor.Signature == "" || got.Anchor.PublicKey == "" {
		t.Fatalf("anchor must ride with all six fields: %+v", got.Anchor)
	}
	if got.Anchor.VerifyPubkey != "" {
		t.Fatal("the pinned verify key must stay on the box")
	}
	if len(got.Pairings) != 2 {
		t.Fatalf("the anchor's beat must list every pairing including itself: %+v", got.Pairings)
	}
	states := map[string]string{}
	for _, p := range got.Pairings {
		states[p.HostName] = p.State
		if p.Since == "" || p.Handle == "" {
			t.Errorf("pairing entry incomplete: %+v", p)
		}
	}
	if states[tAnchor] != pairingActive || states[tMember] != pairingPending {
		t.Fatalf("states wrong: %v", states)
	}
	// a fresh pending pairing is not yet an unapproved attempt (10 min grace) —
	// and "none" is an explicit [], never an absent key
	if got.Attempts == nil || len(got.Attempts) != 0 || !contains(body, `"unapproved_pairing_attempts":[]`) {
		t.Fatalf("a pairing pending for seconds is not an attempt yet, and none must travel as []: %+v", got.Attempts)
	}

	// a member's beat: anchor yes, pairings list no
	got.Pairings, got.Anchor = nil, nil
	body = buildHeartbeatBody(tMember, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	_ = json.Unmarshal([]byte(body), &got)
	if got.Anchor == nil {
		t.Fatal("the anchor claim rides every pairing's beat")
	}
	if got.Pairings != nil {
		t.Fatal("the pairings list is for the anchor host only")
	}

	// age the pending file past 10 minutes: every beat reports the attempt
	pd, _ := pairingsDir()
	old := time.Now().Add(-11 * time.Minute)
	_ = os.Chtimes(filepath.Join(pd, tMember+".json"), old, old)
	got.Attempts = nil
	body = buildHeartbeatBody(tMember, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	_ = json.Unmarshal([]byte(body), &got)
	if len(got.Attempts) != 1 || got.Attempts[0].HostName != tMember || got.Attempts[0].Since == "" {
		t.Fatalf("a pairing pending past 10 minutes must be reported on every beat: %+v", got.Attempts)
	}
	// approve it: the next beat must RETRACT with [], or the host keeps X forever
	writePairingState(t, tMember, pairingActive)
	body = buildHeartbeatBody(tAnchor, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if !contains(body, `"unapproved_pairing_attempts":[]`) {
		t.Fatalf("after approval the attempt list must travel as [] so the host can clear it:\n%s", body)
	}
	// the one case that is genuinely absent: the pairings cannot be enumerated
	if os.Geteuid() != 0 {
		pd, _ := pairingsDir()
		if err := os.Chmod(pd, 0o000); err == nil {
			t.Cleanup(func() { _ = os.Chmod(pd, 0o700) })
			if unapprovedAttempts(time.Now()) != nil {
				t.Fatal("an unreadable pairings dir must yield nil (key absent), never []")
			}
		}
	}
}

// The enforcing report a running pairing sends gains its state and caps.
func TestEnforcingReportCarriesPairingCaps(t *testing.T) {
	setupBox(t)
	rep := buildEnforcingReport("", nil)
	for k, v := range pairingEnforcing(tAnchor) {
		rep[k] = v
	}
	raw := buildHeartbeatBody(tAnchor, "box", "linux", "test", "pk", "fp", "", "", false, nil, rep, nil)
	var body struct {
		Enforcing struct {
			State    string   `json:"pairing_state"`
			Caps     []string `json:"pairing_caps"`
			IsAnchor bool     `json:"is_anchor"`
			MgmtOps  []string `json:"mgmt_ops"`
		} `json:"enforcing"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	if body.Enforcing.State != pairingActive || !body.Enforcing.IsAnchor || len(body.Enforcing.Caps) != len(allCaps) {
		t.Fatalf("the anchor's enforcing report must say active, is_anchor, every cap: %+v", body.Enforcing)
	}
	has := false
	for _, op := range body.Enforcing.MgmtOps {
		has = has || op == "pairing_grant_sync"
	}
	if !has {
		t.Fatal("the op vocabulary must include the pairing ops")
	}
}

// loadPairings must never read a grant file as a pairing.
func TestGrantFileIsNotAPairing(t *testing.T) {
	setupBox(t)
	if err := savePairingGrant(tMember, &pairingGrantFile{TermsCanonical: "x", Signature: "y"}); err != nil {
		t.Fatal(err)
	}
	cfgs, err := loadPairings()
	if err != nil {
		t.Fatalf("a grant file broke loadPairings: %v", err)
	}
	if len(cfgs) != 1 || cfgs[0].HostName != tAnchor {
		t.Fatalf("the grant file must be skipped: %v", hostNames(cfgs))
	}
}

// ── claim-anchor --repin ────────────────────────────────────────────────────
// A host's own name can change under the box (a Host address move does
// exactly that). `pair --replace` updates the pairing but never anchor.json, and
// --rotate refuses a same-handle claim outright, so without --repin an
// anchored box names its anchor by a name that no longer exists and rejects
// every signed record naming the real one.

// Writes mode.json DIRECTLY rather than calling setBoxMode, which requires
// machine authority — the same reason setupBox does. These four tests were
// failing for every non-root run and nobody saw it, because the only machine
// that runs them is a builder running as root and there is no CI here.
// needsMachineAuthority marks a test that drives a command REQUIRING machine
// authority (not merely setting up state that does). Off-root the command
// correctly refuses, so the test cannot assert its success path.
//
// An explicit, reasoned skip — not the silent one it replaced, where the
// whole networked half of a gate test vanished off-root and the run still
// reported green. Here the skip names what is not covered and why, and the
// builder runs as root so the path IS exercised on every real run.
func needsMachineAuthority(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("drives a command that requires machine authority; the refusal path is covered by TestRepinRefusesWhenNotAnchored")
	}
}

func repinBox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p, err := modePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if boxMode() != modeNetworked {
		t.Fatalf("box must read networked, got %s", boxMode())
	}
	return dir
}

func TestRepinRefusesWhenNotAnchored(t *testing.T) {
	repinBox(t)
	if err := cmdRepinAnchor(); err == nil {
		t.Fatal("re-pinned an unanchored box")
	}
}

func TestRepinRefusesWhenTheAnchorHasNoPairingHere(t *testing.T) {
	needsMachineAuthority(t)
	repinBox(t)
	if err := writeAnchor("the owner", "acme.host.privatae.ai"); err != nil {
		t.Fatalf("writeAnchor: %v", err)
	}
	err := cmdRepinAnchor()
	if err == nil {
		t.Fatal("re-pinned with no pairing for the anchor's handle")
	}
	if !strings.Contains(err.Error(), "re-pair it first") {
		t.Fatalf("want the re-pair-first hint, got %v", err)
	}
}

func TestRepinIsANoOpWhenTheNameHasNotChanged(t *testing.T) {
	needsMachineAuthority(t)
	repinBox(t)
	if err := writeAnchor("the owner", "acme.host.privatae.ai"); err != nil {
		t.Fatalf("writeAnchor: %v", err)
	}
	c := &Config{HostName: "acme.host.privatae.ai", ListenAddr: "127.0.0.1:7878"}
	if err := c.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := cmdRepinAnchor(); err != nil {
		t.Fatalf("no-op re-pin should succeed, got %v", err)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != "acme.host.privatae.ai" {
		t.Fatalf("anchor changed on a no-op: %+v", a)
	}
}

func TestRepinMovesTheAnchorToTheNewNameAndKeepsThePin(t *testing.T) {
	needsMachineAuthority(t)
	repinBox(t)
	if err := writeAnchor("the owner", "acme.host.privatae.ai"); err != nil {
		t.Fatalf("writeAnchor: %v", err)
	}
	// Pin a verify key, as a live box would have after its first grant sync.
	f, err := loadAnchorFile()
	if err != nil {
		t.Fatalf("loadAnchorFile: %v", err)
	}
	f.VerifyPubkey = "PINNED-KEY-B64"
	if err := saveAnchorFile(f); err != nil {
		t.Fatalf("saveAnchorFile: %v", err)
	}
	// The re-pair has already happened: the pairing now carries the NEW name.
	c := &Config{HostName: "acme.host.privatae.ai", ListenAddr: "127.0.0.1:7878"}
	if err := c.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := cmdRepinAnchor(); err != nil {
		t.Fatalf("repin: %v", err)
	}

	a := currentAnchor()
	if a == nil {
		t.Fatal("anchor did not verify after re-pin")
	}
	if a.AnchorHost != "acme.host.privatae.ai" {
		t.Fatalf("anchor_host = %q, want the new name", a.AnchorHost)
	}
	if a.AnchorHandle != "acme" {
		t.Fatalf("anchor_handle = %q, want acme", a.AnchorHandle)
	}
	if a.Owner != "the owner" {
		t.Fatalf("owner = %q, want the owner preserved", a.Owner)
	}
	// The pin is the whole difference from a rotation: same host, so the key it
	// pinned is still the right key and dropping it would re-open TOFU.
	after, err := loadAnchorFile()
	if err != nil {
		t.Fatalf("loadAnchorFile after: %v", err)
	}
	if after.VerifyPubkey != "PINNED-KEY-B64" {
		t.Fatalf("verify pin = %q, want it carried across", after.VerifyPubkey)
	}
}

// ── inference family + anchor-only directives ───────────────────────────────

// The three inbound forwards (ollama, llm, pii) were the one lane every pairing
// got regardless of its ceiling. They are now the `inference` family: a member
// outside it is refused at accept, and its heartbeat stops advertising them.
func TestInferenceLaneIsCapsGated(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	// observe only: the forwards refuse, the anchor is unconstrained
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	if why := capsAllow(tMember, "inference"); why == "" || !contains(why, "inference") {
		t.Fatalf("a member outside the inference family must be refused the forwards, got %q", why)
	}
	if why := capsAllow(tAnchor, "inference"); why != "" {
		t.Fatalf("the anchor pairing must reach the forwards: %s", why)
	}
	refuse := inferenceRefuser(tMember, "ollama")
	a, b := net.Pipe()
	defer b.Close()
	if !refuse(a) {
		t.Fatal("the refuser must close a member connection outside the family")
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("the refused connection must be closed")
	}

	// the heartbeat for that member withholds embed / llm-openai / pii even
	// with an OpenAI-compatible server declared and answering
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"qwen"}]}`))
	}))
	defer srv.Close()
	t.Setenv("PRIVATAE_LLM_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("PRIVATAE_PII_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("OLLAMA_ADDR", "127.0.0.1:1")
	var hb struct {
		Caps    []string `json:"capabilities"`
		LLMPort int      `json:"llm_port"`
		PiiPort *int     `json:"pii_port"`
	}
	body := buildHeartbeatBody(tMember, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if err := json.Unmarshal([]byte(body), &hb); err != nil {
		t.Fatal(err)
	}
	for _, c := range hb.Caps {
		if c == "embed" || c == "llm-openai" || c == "pii" {
			t.Fatalf("a member outside the inference family must not advertise %s: %v", c, hb.Caps)
		}
	}
	if hb.LLMPort != 0 || hb.PiiPort != nil {
		t.Fatalf("no forward ports for a member outside the family: llm_port=%d pii_port=%v", hb.LLMPort, hb.PiiPort)
	}
	// the anchor's heartbeat still advertises the declared server
	body = buildHeartbeatBody(tAnchor, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if !contains(body, `"llm-openai"`) || !contains(body, `"pii"`) {
		t.Fatalf("the anchor pairing must keep advertising its inference lanes:\n%s", body)
	}

	// re-signed with inference: the same member now passes, with no restart
	terms, sig = signTerms(t, priv, grantTerms(tMember, []string{"observe", "inference"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("re-grant: %d %s", code, errOut)
	}
	if why := capsAllow(tMember, "inference"); why != "" {
		t.Fatalf("a member granted inference must reach the forwards: %s", why)
	}
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	if refuse(c) {
		t.Fatal("the same refuser must follow the re-signed grant without a restart")
	}
	// the enforcing report names the family; the anchor's ceiling is EVERY
	// family. Counted against allCaps rather than a literal: adding a family is
	// a deliberate change to make, but it should not fail an unrelated test
	// about the inference lane — which is exactly what the literal 6 did when
	// "models" was added.
	rep := pairingEnforcing(tMember)
	if caps, _ := rep["pairing_caps"].([]string); len(caps) != 2 || caps[1] != "inference" {
		t.Fatalf("enforcing must report the inference cap: %+v", rep)
	}
	if caps, _ := pairingEnforcing(tAnchor)["pairing_caps"].([]string); len(caps) != len(allCaps) {
		t.Fatalf("the anchor's ceiling is every family (%v): %v", allCaps, caps)
	}
}

// Update, contain and mirror change the whole machine, not one pairing's
// lanes. On an anchored box only the anchor host directs them.
func TestBoxWideDirectivesAreAnchorOnly(t *testing.T) {
	// unanchored: nothing gated (the common case)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if why := anchorOnly(tMember, "self-update"); why != "" {
		t.Fatalf("an unanchored box gates nothing: %s", why)
	}
	if why := anchorOnly("", "self-update"); why != "" {
		t.Fatalf("an unanchored box gates nothing, even with no identity: %s", why)
	}

	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, allCaps, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	// even a member holding EVERY family is not the anchor
	if why := anchorOnly(tMember, "self-update"); why == "" || !contains(why, tAnchor) {
		t.Fatalf("a member pairing must be refused a box-wide directive and told who may: %q", why)
	}
	if why := anchorOnly("", "contain"); why == "" {
		t.Fatal("no identity on an anchored box is default-deny")
	}
	if why := anchorOnly(tAnchor, "mirror placement"); why != "" {
		t.Fatalf("the anchor must not be refused: %s", why)
	}

	// contain: a member's directive kills nothing, the anchor's reaches the guard
	prevObserved := observedAgents
	observedAgents = func() ([]agentObs, error) {
		return []agentObs{{PID: 4242, Kind: kindAgent, Signature: "test-agent"}}, nil
	}
	processTree = func() map[int]int { return map[int]int{} }
	killed := []int{}
	killProcess = func(pid int) error { killed = append(killed, pid); return nil }
	t.Cleanup(func() { observedAgents = prevObserved; processTree = processParents })
	maybeContain(tMember, "", testDirective(t, directiveContain+":4242", []string{"4242"}, `{"contain":[4242]}`))
	if len(killed) != 0 {
		t.Fatalf("a member host must not terminate processes on an anchored box: %v", killed)
	}
	// The anchor's directive on the anchor's word alone is refused too now
	// (writes.go directiveGate) — it reaches the guard with the person's
	// approval bound to these pids.
	maybeContain(tAnchor, "", []byte(`{"contain":[4242]}`))
	if len(killed) != 0 {
		t.Fatalf("the anchor's directive without an approval must not reach the guard: %v", killed)
	}
	maybeContain(tAnchor, "", testDirective(t, directiveContain+":4242", []string{"4242"}, `{"contain":[4242]}`))
	if len(killed) != 1 || killed[0] != 4242 {
		t.Fatalf("the anchor host's approved directive must reach the guard: %v", killed)
	}

	// self-update: a member's directive never fetches the manifest; the
	// anchor's does (and finds a version it did not ask for, so no swap).
	// The target is older than the version this box runs, so the anchor's
	// directive needs an approval (a newer one would not:
	// claims_update_forward_test.go).
	freshVersionState(t)
	clientVersion = "100.0.0"
	fetches := 0
	man := httptest.NewServer(signedStub(releaseKindBastion, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		_, _ = w.Write([]byte(`{"version":"0.0.0-test","binaries":{}}`))
	})))
	defer man.Close()
	oldURL := manifestURL
	manifestURL = man.URL + "/version.json"
	t.Cleanup(func() { manifestURL = oldURL })
	maybeSelfUpdate(tMember, "", testDirective(t, directiveSelfUpdate, []string{"99.0.0"}, `{"update":{"version":"99.0.0"}}`))
	if fetches != 0 {
		t.Fatal("a member's update directive must be refused before any fetch")
	}
	maybeSelfUpdate(tAnchor, "", []byte(`{"update":{"version":"99.0.0"}}`))
	if fetches != 0 {
		t.Fatal("the anchor's update directive without an approval must be refused before any fetch")
	}
	maybeSelfUpdate(tAnchor, "", testDirective(t, directiveSelfUpdate, []string{"99.0.0"}, `{"update":{"version":"99.0.0"}}`))
	if fetches != 1 {
		t.Fatalf("the anchor's approved directive must reach the manifest fetch, got %d fetches", fetches)
	}

	// mirror: a member's enable is reported as failed with the reason, and no
	// manager starts
	cfg := &Config{HostName: tMember}
	maybeMirror([]byte(`{"mirror":{"enabled":true,"db_image":{"known":true,"tag":"x"}}}`), cfg, "", nil, nil)
	rep := currentMirrorReport(tMember)
	if rep == nil || rep.State != "failed" || !contains(rep.Error, "anchor") {
		t.Fatalf("a member's mirror placement must be reported refused: %+v", rep)
	}
	mirrorMu.Lock()
	_, running := mirrorManagers[tMember]
	mirrorMu.Unlock()
	if running {
		t.Fatal("no mirror manager may start for a member's directive")
	}
	// the host's disable clears the refusal, so the beat does not carry
	// "failed" forever
	maybeMirror([]byte(`{"mirror":{"enabled":false,"reason":"not_configured_here"}}`), cfg, "", nil, nil)
	if rep := currentMirrorReport(tMember); rep != nil { // absent reads as nil: no field on the beat
		t.Fatalf("a disable after a refused placement must clear the report: %+v", rep)
	}
}

// A networked box with no anchor serves NOTHING — on every lane, not just the
// management frame.
//
// The first cut of this put the predicate only in handleMgmtConnFor and closed
// about a fifth of what its own commit message claimed: harness:run, session:
// open, egress, the inference forwards, self-update, contain, mirror placement
// and context-prep all stayed open, because each of them gates through
// capsAllow or anchorOnly and BOTH returned allow when unanchored. So this
// drives those two functions directly — they are what every lane consults.
//
// Sets mode.json DIRECTLY rather than via setBoxMode, which needs root: the
// first version skipped the whole networked half off-root and reported green
// with the gate unexercised, and there is no CI here to catch that.
func TestNetworkedUnanchoredBoxServesNothing(t *testing.T) {
	networkedBox := func(t *testing.T) {
		t.Helper()
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		p, err := modePath()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if boxMode() != modeNetworked {
			t.Fatalf("box must read networked, got %s", boxMode())
		}
	}

	// LOCAL is untouched — it cannot be anchored at all, so gating it would take
	// every local bastion dark for a state it can never reach (and most
	// bastions are local). This half needs no root either way.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if boxMode() != modeLocal {
		t.Fatalf("a box with no mode file must be local, got %s", boxMode())
	}
	for _, op := range []string{"uptime", "dcn_list", "harness:run", "session:open", "egress"} {
		if why := capsAllow(tMember, op); why != "" {
			t.Fatalf("a LOCAL bastion must keep %s: %s", op, why)
		}
	}
	for _, what := range []string{"self-update", "contain", "mirror placement"} {
		if why := anchorOnly(tMember, what); why != "" {
			t.Fatalf("a LOCAL bastion must keep %s: %s", what, why)
		}
	}

	// NETWORKED + unanchored: EVERY lane refuses, each naming the way out.
	// These are the real gate calls each lane makes, not op names invented here:
	//   harness.go capsAllow(self,"harness:run") · session.go capsAllow(self,"session:open")
	//   egress.go  capsAllow(self,"egress")      · run.go/agents.go capsAllow(self,"inference")
	//   update.go  anchorOnly(self,"self-update")· contain.go anchorOnly(self,"contain")
	//   mirror.go  anchorOnly(self,"mirror placement")
	networkedBox(t)
	for _, op := range []string{"uptime", "dcn_list", "ctx_get", "harness:run", "session:open", "egress", "inference"} {
		why := capsAllow(tMember, op)
		if why == "" {
			t.Fatalf("capsAllow must refuse %q on a networked unanchored box", op)
		}
		if !contains(why, "NOT ANCHORED") || !contains(why, "claim-anchor") {
			t.Fatalf("the %q refusal must say why and name the fix: %s", op, why)
		}
	}
	for _, what := range []string{"self-update", "contain", "mirror placement"} {
		why := anchorOnly(tMember, what)
		if why == "" {
			t.Fatalf("anchorOnly must refuse %q on a networked unanchored box", what)
		}
		if !contains(why, "claim-anchor") {
			t.Fatalf("the %q refusal must name the fix: %s", what, why)
		}
	}
	// An op in NO family must not slip through: capsAllow returns "" for an
	// unknown family on an anchored box, so the unanchored refusal has to come
	// first or "not in any family" would read as "allowed".
	if why := capsAllow(tMember, "some_op_in_no_family"); why == "" {
		t.Fatal("an op in no family must still be refused on a networked unanchored box")
	}

	// And the mgmt frame itself, end to end through the real lane.
	for _, op := range []string{"uptime", "dcn_list", "pairing_grant_sync"} {
		_, errOut, code := driveOp(t, tMember, op, nil)
		if code != 126 || !contains(errOut, "NOT ANCHORED") {
			t.Fatalf("mgmt op %q must be refused as unanchored: %d %s", op, code, errOut)
		}
	}

	// Once anchored the lanes answer again under the normal caps rules: the
	// anchor host is unconstrained, a member with no grant is default-denied.
	if err := writeAnchor("Acme IT", tMember); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"uptime", "harness:run", "egress"} {
		if why := capsAllow(tMember, op); why != "" {
			t.Fatalf("the anchor host must be served %s again: %s", op, why)
		}
	}
	if why := capsAllow("stranger.host.privatae.ai", "harness:run"); !contains(why, "no verified pairing grant") {
		t.Fatalf("a member with no grant must be default-denied, not unanchored-refused: %q", why)
	}
	// And the MGMT FRAME itself, after anchoring — the direct call site, which
	// this test drove only while unanchored. A review nit: its anchored half went
	// through capsAllow/anchorOnly and left the frame's own path covered only by
	// pre-existing tests, so the one call site that does NOT delegate was the one
	// this test never re-checked. That is exactly where the predicate bug lived.
	if _, errOut, code := driveOp(t, tMember, "uptime", nil); code == 126 && contains(errOut, "NOT ANCHORED") {
		t.Fatalf("the mgmt frame must answer an anchored box again: %s", errOut)
	}
}

// TWO SAFETY PROPERTIES of refusing everything on a networked unanchored box.
// Both were open questions that argument could not settle, so they
// are answered here by driving the code.
//
//  1. A BOX CANNOT BE STRANDED. currentAnchor() returns nil for a MISSING file
//     and equally for a corrupt or tampered one, so a disk fault or a bad write
//     flips a working networked box into refusing every lane. That is the right
//     direction to fail, but only if it is recoverable: re-anchoring must work
//     from the box itself, with no lane and no host involved.
//
//  2. IT STAYS VISIBLE. The refusal is worth nothing if the machine simply goes
//     quiet — an absent box and a refusing box would look identical from the
//     host, which is the failure shape whose only symptom is absence. The
//     heartbeat is a separate lane (an HTTP POST) and must keep reporting, so
//     the host can see mode=networked with no anchor and say why.
func TestUnanchoredNetworkedBoxIsRecoverableAndStillVisible(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, err := modePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writePairing(t, tAnchor)
	if err := writeAnchor("Acme IT", tAnchor); err != nil {
		t.Fatal(err)
	}
	if capsAllow(tAnchor, "uptime") != "" {
		t.Fatal("a healthy anchored box must serve its anchor host")
	}

	// Corrupt the anchor the way a bad write would — the signature covers the
	// host name, so an edited file reads as NO anchor (anchorVerified).
	ap, err := anchorPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ap, []byte(strings.Replace(string(raw), tAnchor, "evil.host.privatae.ai", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if currentAnchor() != nil {
		t.Fatal("a tampered anchor must read as no anchor")
	}
	if why := capsAllow(tAnchor, "uptime"); !contains(why, "NOT ANCHORED") {
		t.Fatalf("a corrupt anchor must close the lanes, not leave them open: %q", why)
	}

	// PROPERTY 2: the heartbeat still goes out, and still says what it is.
	// buildHeartbeatBody takes no lane and consults no gate for mode — an
	// unanchored networked box reports mode=networked and no anchor, which is
	// exactly what the host needs to explain the refusal to the user.
	body := buildHeartbeatBody(tAnchor, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if !contains(body, `"mode":"networked"`) {
		t.Fatalf("an unanchored networked box must still report its mode:\n%s", body)
	}
	if contains(body, `"anchor"`) {
		t.Fatalf("a box with no verified anchor must not claim one:\n%s", body)
	}

	// PROPERTY 1: re-anchoring works from the box, with no lane and no host.
	// currentAnchor() is nil, so claim-anchor does NOT hit "already anchored" —
	// the corrupt file cannot wedge the box permanently.
	if os.Geteuid() != 0 {
		t.Log("recovery half needs machine authority; the refusal path above is covered")
		return
	}
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	if err := cmdClaimAnchor("", false, "Acme IT", tAnchor); err != nil {
		t.Fatalf("a box with a corrupt anchor must be re-anchorable in place: %v", err)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != tAnchor {
		t.Fatalf("re-anchor did not take: %+v", a)
	}
	if why := capsAllow(tAnchor, "uptime"); why != "" {
		t.Fatalf("the lanes must come back after re-anchoring: %s", why)
	}
}

// THE ANCHOR CANNOT BE CLEARED BY ANYTHING REACHABLE FROM OUTSIDE THE MACHINE.
//
// This became a security invariant in 0.24.0 rather than a curiosity. Before it,
// an unanchored networked box served everything; now it serves nothing — so any
// inbound path that could clear an anchor would be a remote denial of service
// against the whole machine, and a very quiet one.
//
// Audited every writer of anchor.json: writeAnchor (cmdClaimAnchor, root CLI),
// writeAnchorPreservingPin (cmdRepinAnchor, root CLI), and two saveAnchorFile
// calls that only ADD a verify key to an anchor already loaded AND verified.
// os.Remove is never pointed at the anchor path — the one removal in this file
// is the single-use rotation CONSENT file, which is a different thing.
//
// So the only ways to become unanchored are root at the machine or disk
// corruption, both of which need the access that also fixes it.
func TestNothingInboundCanClearTheAnchor(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, err := modePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// pinAnchorVerifyKey is the one anchor-file writer an inbound op reaches
	// (the anchor's mgmt lane TOFUs its key). On an UNANCHORED box it must
	// refuse outright — it must never be able to manufacture an anchor either.
	pub, _, _ := ed25519.GenerateKey(nil)
	key := base64.StdEncoding.EncodeToString(pub)
	if err := pinAnchorVerifyKey(key); err == nil {
		t.Fatal("pinning a verify key on an unanchored box must be refused, not create one")
	}
	if currentAnchor() != nil {
		t.Fatal("a refused pin must not have written an anchor")
	}

	// On an anchored box it may pin, but must leave the CLAIM untouched.
	writePairing(t, tAnchor)
	if err := writeAnchor("Acme IT", tAnchor); err != nil {
		t.Fatal(err)
	}
	before := currentAnchor()
	if before == nil {
		t.Fatal("setup: box should be anchored")
	}
	if err := pinAnchorVerifyKey(key); err != nil {
		t.Fatalf("pinning on an anchored box should work: %v", err)
	}
	after := currentAnchor()
	if after == nil {
		t.Fatal("pinning a verify key must NEVER clear the anchor")
	}
	if after.AnchorHost != before.AnchorHost || after.Owner != before.Owner {
		t.Fatalf("pinning must not change who the anchor is: %+v -> %+v", before, after)
	}
	// And a second, different key is refused rather than silently re-homing it.
	pub2, _, _ := ed25519.GenerateKey(nil)
	if err := pinAnchorVerifyKey(base64.StdEncoding.EncodeToString(pub2)); err == nil {
		t.Fatal("a different verify key must be refused once one is held")
	}
	if currentAnchor() == nil {
		t.Fatal("a refused re-pin must not have cleared the anchor")
	}
}

// `mode` rides EVERY heartbeat, whatever the box's state.
//
// The host side leans on this: it treats a beat CARRYING mode as
// authoritative about its anchor too, so absent-anchor means unanchored rather
// than "too old to know". If mode were ever conditional, a box could have its
// anchor wrongly cleared on the host. agents.go sets it unconditionally; this
// pins that so the coupling is stated on the side that depends on it.
func TestModeRidesEveryHeartbeat(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"local unanchored", `"mode":"local"`},
		{"networked unanchored", `"mode":"networked"`},
		{"networked anchored", `"mode":"networked"`},
	} {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		if tc.name != "local unanchored" {
			p, err := modePath()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if tc.name == "networked anchored" {
			writePairing(t, tAnchor)
			if err := writeAnchor("Acme IT", tAnchor); err != nil {
				t.Fatal(err)
			}
		}
		body := buildHeartbeatBody(tAnchor, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
		if !contains(body, tc.want) {
			t.Fatalf("%s: mode must ride the beat (%s):\n%s", tc.name, tc.want, body)
		}
	}
}

// EVERY OP IN THE VOCABULARY IS IN A CAPS FAMILY, OR IS DELIBERATELY EXCEPTED.
//
// The hole found reviewing 0.24.0, and it is about the NEXT op, not any
// op that exists today. capsAllow returns "" — allow — when opFamily(op) is ""
// (anchor.go), so on an ANCHORED box an op whose name matches no family prefix
// is served to any pairing holding any grant at all, whatever its caps say. The
// unanchored-networked case is covered because handleMgmtConnFor refuses before
// capsAllow is reached; the anchored case is not covered by anything.
//
// TestOpFamilies pins thirteen ops by hand, so it can only ever check the ops
// somebody remembered to add to it. This walks the REAL vocabulary — the same
// list the enforcing report publishes to the host — so an op added to
// handlerOps, p8AllowedOps or sessionOps has to be classified or explicitly
// excepted, and cannot arrive quietly exempt from the ceiling.
//
// The exceptions are narrow and each has a reason:
//
//	stepup_*  — the approval flow itself. Caps-gating it would mean needing an
//	            approval to ask for an approval (TestCapsRefusal pins this).
//	pairing_* — answered only on the anchor host's pairing, refused for
//	            everyone else before capsAllow is consulted (mgmt.go).
func TestEveryMgmtOpIsClassifiedOrExcepted(t *testing.T) {
	// The exception list is now EMPTY: every op on this lane carries a family,
	// because capsAllowIn default-denies one that does not, and
	// TestEveryOpOnTheMgmtLaneHasAFamily is the stronger form of this check.
	// Kept as a seam rather than deleted — the next op that genuinely needs no
	// family goes here with its reason, and the vacuity check below makes sure
	// an empty list still proves something.
	excepted := func(op string) bool { return false }
	vocab := mgmtOpVocabulary()
	if len(vocab) == 0 {
		t.Fatal("the op vocabulary is empty — this test would assert nothing")
	}
	var unclassified []string
	for _, op := range vocab {
		if opFamily(op) == "" && !excepted(op) {
			unclassified = append(unclassified, op)
		}
	}
	if len(unclassified) > 0 {
		t.Fatalf("these ops are in no caps family and are not on the exception list, so on an\n"+
			"ANCHORED box capsAllow serves them to any pairing holding any grant:\n    %s\n"+
			"Give each one a family in opFamily, or add it to the exception list here with\n"+
			"the reason it needs none.", strings.Join(unclassified, "\n    "))
	}
	// The exception list must not rot into a blanket: prove it still refuses
	// something. A bare unknown op has no family and is not excepted, so if this
	// stopped failing the check above would be vacuous.
	if opFamily("some_future_op") != "" || excepted("some_future_op") {
		t.Fatal("the classification check has gone vacuous — an unknown op must be neither")
	}
}

// A REFUSED DIRECTIVE REACHES THE HOST, not just this box's log.
//
// This was first set aside as needing a new heartbeat field and host-side
// handling. It does not: the enforcing report already rides every beat and is
// REPLACED each beat host-side, so a field there is live by construction.
// Setting it aside was the wrong call — the whole point of this change is that
// a refusal is LOUD, and self-update and contain were refusing into a log on
// the far side of the tunnel.
func TestARefusedDirectiveIsReportedToTheHost(t *testing.T) {
	// The recorder is package-level state — one process, one box — so a sibling
	// test that drives any refusal leaves one behind. Start from an empty slot.
	resetDirectiveRefusal(t)

	// Nothing refused yet: the field is ABSENT, never "refused: none".
	if r := directiveRefusalReport(); r != nil {
		t.Fatalf("a box that has refused nothing must report nothing: %v", r)
	}
	rep := buildEnforcingReport("", nil)
	if _, ok := rep["last_directive_refusal"]; ok {
		t.Fatal("the enforcing report must omit the field when there is nothing to say")
	}

	// A refusal shows up, carrying WHAT and WHY — the why is the operator's
	// only clue, so an empty one would make the field decorative.
	recordDirectiveRefusal("self-update", "refused: this machine is networked but NOT ANCHORED")
	rep = buildEnforcingReport("", nil)
	got, ok := rep["last_directive_refusal"].(map[string]any)
	if !ok {
		t.Fatalf("the refusal must reach the enforcing report: %v", rep["last_directive_refusal"])
	}
	if got["what"] != "self-update" {
		t.Fatalf("the report must name the directive: %v", got)
	}
	if w, _ := got["why"].(string); !contains(w, "NOT ANCHORED") {
		t.Fatalf("the report must carry the reason: %v", got)
	}
	if at, _ := got["at"].(string); at == "" {
		t.Fatalf("the report must carry when, or the host cannot tell stale from live: %v", got)
	}

	// A LATER SUCCESS CLEARS IT. Without this the host shows a machine refusing
	// something it now does, for ever — which is worse than silence, because it
	// is confidently wrong rather than merely missing.
	clearDirectiveRefusal("self-update")
	if r := directiveRefusalReport(); r != nil {
		t.Fatalf("a resolved refusal must stop being reported: %v", r)
	}

	// Clearing a DIFFERENT directive must not wipe a live one — otherwise a
	// successful contain would hide a still-refused update.
	recordDirectiveRefusal("self-update", "still refused")
	clearDirectiveRefusal("contain")
	if r := directiveRefusalReport(); r == nil || r["what"] != "self-update" {
		t.Fatalf("clearing one directive must not clear another: %v", r)
	}
}
