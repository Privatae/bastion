//go:build !windows

// Uses setupBox / tAnchor / tMember from anchor_test.go (unix-only).

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// driveDirOp runs one management job through the real lane as pairing `self`,
// with a real grant directory (driveOp passes none, so dcn-dir ops refuse there).
func driveDirOp(t *testing.T, self, dir, op string, args []string) (string, string, int) {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConnFor(ws, self, "", dir, "")
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	job, _ := json.Marshal(mgmtJob{Op: op, Args: args})
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
			code := 0
			for _, ch := range string(data[1:]) {
				code = code*10 + int(ch-'0')
			}
			return out, errOut, code
		}
	}
}

func signedTerms(t *testing.T, priv ed25519.PrivateKey, terms map[string]any) (string, string) {
	t.Helper()
	raw, err := json.Marshal(terms) // sorted keys, no whitespace — the host's canonical form
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
}

func reachPayload(t *testing.T, priv ed25519.PrivateKey, id int64, terms map[string]any) string {
	t.Helper()
	tc, sig := signedTerms(t, priv, terms)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	b, _ := json.Marshal(map[string]any{"grant_id": id, "terms_canonical": tc, "signature": sig, "verify_pubkey": pub})
	return base64.StdEncoding.EncodeToString(b)
}

func reachTermsFor(subject, slot string, days int) map[string]any {
	hn, _ := os.Hostname()
	return map[string]any{"kind": reachKind, "server": hn, "slot": slot, "subject": subject,
		"ttl_days": days, "expires": time.Now().Add(time.Duration(days-1) * 24 * time.Hour).UTC().Format(time.RFC3339)}
}

// The approval the person's device gives for exactly these terms.
func approveReach(t *testing.T, terms map[string]any) {
	t.Helper()
	p, err := purposeForReach(&reachTerms{Server: terms["server"].(string), Slot: terms["slot"].(string),
		Subject: terms["subject"].(string), TTLDays: terms["ttl_days"].(int)})
	if err != nil {
		t.Fatal(err)
	}
	a, err := deviceSign(p, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	terms["approval"] = a
}

// A store grant and a reach grant are both records the entity key signs; neither
// may be offered as the other. (Before this, dcnVerifyRec parsed `kind` and
// never compared it.)
func TestSignedKindsCannotStandInForEachOther(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	store := map[string]any{"kind": "dcn_store_grant", "class": "machine", "server": "b", "root": "/d",
		"mask": []string{"read"}, "expires": exp, "slot": "forge", "subject": "h"}
	reach := reachTermsFor("h.example", "forge", 30)
	tcS, sigS := signedTerms(t, priv, store)
	tcR, sigR := signedTerms(t, priv, reach)
	if _, err := reachVerifyRec(pub, dcnGrantRec{TermsCanonical: tcS, Signature: sigS}); err == nil {
		t.Fatal("a store grant must not verify as a reach grant")
	}
	if _, err := dcnVerifyRec(pub, dcnGrantRec{TermsCanonical: tcR, Signature: sigR}); err == nil {
		t.Fatal("a reach grant must not verify as a store grant")
	}
	if _, err := reachVerifyRec(pub, dcnGrantRec{TermsCanonical: tcR, Signature: sigR}); err != nil {
		t.Fatalf("a reach grant verifies as itself: %v", err)
	}
	if _, err := dcnVerifyRec(pub, dcnGrantRec{TermsCanonical: tcS, Signature: sigS}); err != nil {
		t.Fatalf("a store grant verifies as itself: %v", err)
	}
}

// The purpose the host builds for the person's approval must be this string
// (nac_stepup.purpose_for_reach_terms pins the same one).
func TestReachPurposeMatchesTheHost(t *testing.T) {
	got, err := purposeForReach(&reachTerms{Server: "box1", Slot: "forge", Subject: "h.example", TTLDays: 30})
	if err != nil || got != "service_reach_grant|box1|forge|h.example|ttl:30" {
		t.Fatalf("purpose drifted: %q %v", got, err)
	}
	if _, err := purposeForReach(&reachTerms{Server: "b", Slot: "f", Subject: "a|b", TTLDays: 1}); err == nil {
		t.Fatal("a reserved character in a purpose field must be refused")
	}
	if p, _ := purposeFromDetails(map[string]any{"kind": reachKind, "server": "box1", "slot": "forge",
		"subject": "h.example", "ttl_days": float64(30)}); p != got {
		t.Fatalf("the details the person reads must build the same purpose: %q", p)
	}
	if stepupKindFamily(reachKind) != "services" {
		t.Fatal("a reach approval is gated on the services family")
	}
}

// On an anchored box: a reach grant installs only with the person's approval,
// only for the host that sends it, only for this machine; it then lets exactly
// that host reach exactly that server; revoke and expiry take it away.
func TestReachGrantSyncAndTheForwardWall(t *testing.T) {
	priv := setupBox(t)
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	dir := t.TempDir()

	// No approval: refused on an anchored box.
	bare := reachTermsFor(tAnchor, "forge", 30)
	if _, errOut, code := driveDirOp(t, tAnchor, dir, "service_grant_sync",
		[]string{reachPayload(t, priv, 1, bare)}); code != 126 {
		t.Fatalf("an unapproved reach grant must be refused: %d %s", code, errOut)
	}

	// For ANOTHER host, sent by this one: refused even when approved.
	other := reachTermsFor(tMember, "forge", 30)
	approveReach(t, other)
	if _, errOut, code := driveDirOp(t, tAnchor, dir, "service_grant_sync",
		[]string{reachPayload(t, priv, 2, other)}); code != 126 || !strings.Contains(errOut, "not the host that sent it") {
		t.Fatalf("a host must not install reach for another host: %d %s", code, errOut)
	}

	// For another machine: refused.
	elsewhere := reachTermsFor(tAnchor, "forge", 30)
	elsewhere["server"] = "some-other-box"
	approveReach(t, elsewhere)
	if _, errOut, code := driveDirOp(t, tAnchor, dir, "service_grant_sync",
		[]string{reachPayload(t, priv, 3, elsewhere)}); code != 126 {
		t.Fatalf("a grant for another machine must be refused: %d %s", code, errOut)
	}

	// The real one.
	good := reachTermsFor(tAnchor, "forge", 30)
	approveReach(t, good)
	if out, errOut, code := driveDirOp(t, tAnchor, dir, "service_grant_sync",
		[]string{reachPayload(t, priv, 4, good)}); code != 0 {
		t.Fatalf("an approved reach grant for this host installs: %d %s %s", code, out, errOut)
	}
	if why := serviceReachAllowed(dir, tAnchor, "forge"); why != "" {
		t.Fatalf("the granted host reaches the granted server: %s", why)
	}
	if why := serviceReachAllowed(dir, tAnchor, "other-server"); why == "" {
		t.Fatal("a grant for one server does not open another")
	}
	if why := serviceReachAllowed(dir, tMember, "forge"); why == "" {
		t.Fatal("a grant for one host does not let another in")
	}

	// The same approval cannot install a second, different grant.
	again := reachTermsFor(tAnchor, "forge", 29)
	again["approval"] = good["approval"]
	if _, _, code := driveDirOp(t, tAnchor, dir, "service_grant_sync",
		[]string{reachPayload(t, priv, 5, again)}); code == 0 {
		t.Fatal("an approval installs one grant once")
	}

	// Revoke.
	if _, errOut, code := driveDirOp(t, tAnchor, dir, "service_grant_drop", []string{"4"}); code != 0 {
		t.Fatalf("drop: %d %s", code, errOut)
	}
	if why := serviceReachAllowed(dir, tAnchor, "forge"); why == "" {
		t.Fatal("a revoked grant reaches nothing")
	}
}

// A grant that expired, or whose bytes were changed on disk, lets nobody in.
func TestReachGrantExpiryAndTamper(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	hn, _ := os.Hostname()
	put := func(terms map[string]any, tamper bool) {
		tc, sig := signedTerms(t, priv, terms)
		if tamper {
			raw, _ := base64.StdEncoding.DecodeString(tc)
			raw = []byte(strings.Replace(string(raw), `"forge"`, `"forgf"`, 1))
			tc = base64.StdEncoding.EncodeToString(raw)
		}
		f := &dcnGrantFile{VerifyPubkey: pub, Stores: map[string]dcnGrantRec{},
			Reach: map[string]dcnGrantRec{"1": {TermsCanonical: tc, Signature: sig}}}
		if err := dcnSaveFile(dir, f); err != nil {
			t.Fatal(err)
		}
	}
	live := map[string]any{"kind": reachKind, "server": hn, "slot": "forge", "subject": "h",
		"ttl_days": 30, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	put(live, false)
	if why := serviceReachAllowed(dir, "h", "forge"); why != "" {
		t.Fatalf("a live grant lets its host in: %s", why)
	}
	expired := map[string]any{"kind": reachKind, "server": hn, "slot": "forge", "subject": "h",
		"ttl_days": 30, "expires": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}
	put(expired, false)
	if why := serviceReachAllowed(dir, "h", "forge"); why == "" {
		t.Fatal("an expired grant lets nobody in")
	}
	put(live, true)
	if why := serviceReachAllowed(dir, "h", "forgf"); why == "" {
		t.Fatal("a record whose signed bytes were changed lets nobody in")
	}
	delete(live, "expires")
	put(live, false)
	if why := serviceReachAllowed(dir, "h", "forge"); why == "" {
		t.Fatal("an open-ended grant is refused")
	}
}

// The heartbeat reconcile: a held grant absent from TWO consecutive replies is a
// revoke this box missed and is dropped; an absent field means no instruction.
func TestReachReconcile(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	tc, sig := signedTerms(t, priv, reachTermsFor("h", "forge", 30))
	f := &dcnGrantFile{VerifyPubkey: pub, Stores: map[string]dcnGrantRec{},
		Reach: map[string]dcnGrantRec{"7": {TermsCanonical: tc, Signature: sig}}}
	if err := dcnSaveFile(dir, f); err != nil {
		t.Fatal(err)
	}
	if d := maybeReconcileReach([]byte(`{"ok":true}`), dir); len(d) != 0 {
		t.Fatal("no service_grants field is no instruction")
	}
	listed := []byte(`{"service_grants":{"grants":[{"grant_id":7,"signature":"x"}]}}`)
	empty := []byte(`{"service_grants":{"grants":[]}}`)
	if d := maybeReconcileReach(empty, dir); len(d) != 0 {
		t.Fatal("one missed reply could be timing: kept")
	}
	if d := maybeReconcileReach(listed, dir); len(d) != 0 {
		t.Fatal("listed again: kept, and the count resets")
	}
	maybeReconcileReach(empty, dir)
	if d := maybeReconcileReach(empty, dir); len(d) != 1 || d[0] != 7 {
		t.Fatalf("two missed replies in a row: dropped, got %v", d)
	}
	if got := heldReachGrants(dir); len(got) != 0 {
		t.Fatalf("nothing held after the drop: %v", got)
	}
}

// The enforcing report names the pairing, so the host signs the subject the box enforces.
func TestEnforcingNamesThePairingHost(t *testing.T) {
	setupBox(t)
	if got, _ := pairingEnforcing(tAnchor)["pairing_host"].(string); got != tAnchor {
		t.Fatalf("pairing_host must be the pairing's own host name, got %q", got)
	}
}

// Stopping a server drops every reach grant for it, in every pairing's file, so
// the next server built under that name inherits no one's reach.
func TestStoppingAServerDropsItsReachGrants(t *testing.T) {
	setupBox(t)
	stubServiceRuntime(t, "docker")
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	cfgs, _ := loadPairings()
	var dir string
	for _, c := range cfgs {
		if c.HostName == tAnchor {
			dir = c.dcnDir()
		}
	}
	if dir == "" {
		t.Fatal("anchor pairing has no dir")
	}
	tcF, sigF := signedTerms(t, priv, reachTermsFor(tAnchor, "forge", 30))
	tcW, sigW := signedTerms(t, priv, reachTermsFor(tAnchor, "wiki", 30))
	f := &dcnGrantFile{VerifyPubkey: pub, Stores: map[string]dcnGrantRec{}, Reach: map[string]dcnGrantRec{
		"1": {TermsCanonical: tcF, Signature: sigF}, "2": {TermsCanonical: tcW, Signature: sigW}}}
	if err := dcnSaveFile(dir, f); err != nil {
		t.Fatal(err)
	}
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	b, code := runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge"})
	if code != 0 || decodeRes(t, b)["reach_grants_dropped"] != float64(1) {
		t.Fatalf("down must drop the one grant for forge: %s", b)
	}
	if why := serviceReachAllowed(dir, tAnchor, "forge"); why == "" {
		t.Fatal("the stopped server's grant is gone")
	}
	if why := serviceReachAllowed(dir, tAnchor, "wiki"); why != "" {
		t.Fatalf("another server's grant stays: %s", why)
	}
	if got := droppedReachGrants(dir); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the dropped grant is reported so its host revokes it, got %v", got)
	}
}

// The approval device files a reach grant ask (its purpose names the machine).
func TestTheDeviceTakesAReachAsk(t *testing.T) {
	setupBox(t)
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	hn, _ := os.Hostname()
	id, err := deviceNewRequest(map[string]any{"kind": reachKind, "server": hn, "slot": "forge",
		"subject": tAnchor, "ttl_days": float64(30)})
	if err != nil || id == "" {
		t.Fatalf("a reach ask must be filed on the device: %q %v", id, err)
	}
}

// A record of another kind that happens to list a session op never opens a
// terminal: a management grant carries no kind, every other signed record does.
func TestAKindedRecordNeverOpensATerminal(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	dir := t.TempDir()
	if err := dcnSaveFile(dir, &dcnGrantFile{VerifyPubkey: pub, Stores: map[string]dcnGrantRec{}}); err != nil {
		t.Fatal(err)
	}
	hn, _ := os.Hostname()
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	mgmt := map[string]any{"server": hn, "ops": []string{sessionOpOpen}, "expires": exp}
	tc, sig := signedTerms(t, priv, mgmt)
	if _, err := sessionVerifyGrant(dir, "", hn, sessionOpOpen, tc, sig, ""); err != nil {
		t.Fatalf("a management grant listing the op opens it: %v", err)
	}
	for _, kind := range []string{reachKind, "dcn_store_grant", "dcn_move_plan"} {
		rec := map[string]any{"kind": kind, "server": hn, "ops": []string{sessionOpOpen}, "expires": exp}
		tc, sig := signedTerms(t, priv, rec)
		if _, err := sessionVerifyGrant(dir, "", hn, sessionOpOpen, tc, sig, ""); err == nil {
			t.Fatalf("a %s must never open a terminal", kind)
		}
	}
}
