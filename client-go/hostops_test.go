//go:build !windows

package main

// hostops_test.go — the write gate on an anchored box (writes.go, device.go,
// quarantine.go): every change needs an approval this box verified, reads
// never do, a local box is untouched, and the mutations the design names —
// unsigned / expired / uses-exhausted / wrong-key / no-nonce / replayed /
// wrong-purpose approvals — are each refused.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// testApproval signs a device approval for one run of a write on an anchored
// test box, from a device key it creates and pins in the test's config dir.
// "" when the gate does not apply (local box, a read, an op with its own
// approval), so drivers can pass it unconditionally.
func testApproval(t *testing.T, op string, args []string) string {
	t.Helper()
	if currentAnchor() == nil || !opWrites(op) || ownApproval(op) {
		return ""
	}
	pub, err := deviceInit()
	if err != nil {
		t.Fatalf("device-init: %v", err)
	}
	if err := pinDeviceKey(pub); err != nil {
		t.Fatalf("pin-device: %v", err)
	}
	hn, _ := os.Hostname()
	a, err := deviceSign(mgmtOpPurpose(op, hn, args), time.Minute)
	if err != nil {
		t.Fatalf("device-sign: %v", err)
	}
	return a
}

// testDirective attaches the person's approval for one heartbeat directive.
// `key` is the approvals map key ("self-update", "contain:<pid>", "mirror");
// the purpose is bound to the directive name before any ":".
func testDirective(t *testing.T, key string, args []string, body string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	what, _, _ := strings.Cut(key, ":")
	if a := testApproval(t, what, args); a != "" {
		m["approvals"] = map[string]string{key: a}
	}
	out, _ := json.Marshal(m)
	return out
}

// driveJob sends a job AS IS — no approval is added — with a configured
// context root, so the reply is the gate's and not "context store not
// configured".
func driveJob(t *testing.T, self string, job mgmtJob, ctxRoot, dcnDir string) (string, string, int) {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConnFor(ws, self, ctxRoot, dcnDir, "")
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	raw, _ := json.Marshal(job)
	if err := c.WriteMessage(websocket.BinaryMessage, append([]byte("C"), raw...)); err != nil {
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

// putJob is the gated write the gate tests drive: ctx_extract with an
// argument its handler will refuse (an unknown tool), so a run that passes
// the gate answers with the HANDLER's exit (1) — the gate's refusals are 126.
// (ctx_put is standing work under the configured store and is not gated.)
func putJob(approval string) mgmtJob {
	return mgmtJob{Op: "ctx_extract", Args: []string{`{"tool":"no-such-tool","mime":"text/plain","b64":"aGk="}`},
		Approval: approval}
}

const putOp = "ctx_extract"

// Every op this box answers is a read or a write, and the read set is exactly
// the one the design names. A new op lands as a write until someone says
// otherwise.
func TestEveryOpIsReadOrWrite(t *testing.T) {
	reads := map[string]bool{}
	for _, op := range []string{"uptime", mgmtAuditFetchOp, "dcn_list", "dcn_stat", "dcn_read_range",
		"dcn_search", "dcn_catalog", "ctx_get", "backup_list", "model:list", "pairing_list", "stepup_request",
		"stepup_status", "device_request", "device_status", "op_list", "op_run_status", "op_plan_status"} {
		reads[op] = true
	}
	for _, op := range mgmtOpVocabulary() {
		isRead := reads[op] || strings.HasPrefix(op, "observe:") || strings.HasPrefix(op, "computer:")
		if opWrites(op) == isRead {
			t.Errorf("%s: opWrites=%v, the design says read=%v", op, opWrites(op), isRead)
		}
	}
	for _, op := range []string{"harness:run", "session:open", "contain", "self-update", "mirror", "backup_fetch",
		"op_sync", "op_dry_run", "op_apply", "op_grant_run", "brand_new_op"} {
		if !opWrites(op) {
			t.Errorf("%s must be a write", op)
		}
	}
	// egress and inference USE the machine and change nothing on it.
	for _, op := range []string{"egress", "inference"} {
		if opWrites(op) {
			t.Errorf("%s uses this machine and changes nothing on it — not gated per run", op)
		}
	}
	for _, op := range []string{"dcn_grant_drop", "pairing_grant_drop"} {
		if !opTightens(op) || !ownApproval(op) {
			t.Errorf("%s only removes reach and is never held back", op)
		}
	}
	for _, op := range []string{"dcn_grant_sync", "dcn_plan_apply", "model:pull", "pairing_grant_sync", "backup_fetch", "ctx_put", "ctx_del"} {
		if !ownApproval(op) {
			t.Errorf("%s carries its own approval and must not be gated twice", op)
		}
	}
	if ownApproval("ctx_extract") || ownApproval("model:drop") {
		t.Error("ctx_extract / model:drop carry no approval of their own")
	}
	for _, op := range []string{"backup_fetch", "ctx_put", "ctx_del"} {
		if !ownApproval(op) {
			t.Errorf("%s is standing work under a store the person configured at the machine", op)
		}
	}
}

// A local box gates nothing: the pairing is the authorization there.
func TestALocalBoxRunsAWriteOnThePairingAlone(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writePairing(t, tAnchor)
	if _, errOut, code := driveJob(t, tAnchor, putJob(""), t.TempDir(), ""); code == 126 {
		t.Fatalf("a local box must run a write with no approval (the handler answers, not the gate): %d %s", code, errOut)
	}
}

// On an anchored box: a read answers; a write with no approval is refused and
// names the fix; a write with a device approval runs exactly once.
func TestAnAnchoredBoxRefusesAWriteWithoutApprovalAndRunsItOnceWithOne(t *testing.T) {
	setupBox(t)
	ctx := t.TempDir()
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "pairing_list"}, ctx, ""); code != 0 {
		t.Fatalf("a read must answer on the anchor's word: %d %s", code, errOut)
	}
	_, errOut, code := driveJob(t, tAnchor, putJob(""), ctx, "")
	if code != 126 || !strings.Contains(errOut, "holds no way to take one") || !strings.Contains(errOut, "pin-device") {
		t.Fatalf("no factor, no device: the refusal must name the fix: %d %q", code, errOut)
	}
	if !quarantinedUntil(tAnchor, time.Now()).IsZero() {
		t.Fatal("'no way to approve' is the box's own state and must not count as a strike")
	}
	if refusalCounts(putOp, "refused: op 'zzz' not permitted on this host") || refusalCounts("uptime", "refused: x") {
		t.Fatal("an unknown op or a read never counts")
	}
	if !refusalCounts(putOp, "refused: op 'ctx_extract' changes this machine and approval expired") {
		t.Fatal("a bad approval on a known write counts")
	}
	// Device pinned, no approval given.
	pub, _ := deviceInit()
	if err := pinDeviceKey(pub); err != nil {
		t.Fatal(err)
	}
	if !devicePinned() || !secondFactorAvailable("") {
		t.Fatal("the pin must count as a second factor")
	}
	_, errOut, code = driveJob(t, tAnchor, putJob(""), ctx, "")
	if code != 126 || !strings.Contains(errOut, "none was given") {
		t.Fatalf("a write with no approval is refused: %d %q", code, errOut)
	}
	// Approved: runs once.
	hn, _ := os.Hostname()
	approval, err := deviceSign(mgmtOpPurpose(putOp, hn, putJob("").Args), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := driveJob(t, tAnchor, putJob(approval), ctx, ""); code == 126 {
		t.Fatalf("an approved write must reach the handler: %d %s", code, errOut)
	}
	// Replay: the nonce is burned.
	if _, errOut, code := driveJob(t, tAnchor, putJob(approval), ctx, ""); code != 126 || !strings.Contains(errOut, "already used") {
		t.Fatalf("a replayed approval must be refused: %d %q", code, errOut)
	}
	// The audit line names how it was approved and binds the args.
	recs := readMgmtAudit(t)
	var ran map[string]any
	for _, r := range recs {
		if r["verdict"] == auditAllowed && r["op"] == putOp {
			ran = r
		}
	}
	if ran == nil || !strings.HasPrefix(fmt.Sprint(ran["approval"]), "device:") || ran["args_sha256"] != argsDigest(putJob("").Args) {
		t.Fatalf("the allowed line must name the approval spent and the args digest: %v", ran)
	}
}

// The mutation suite: each broken approval is refused for its own reason.
func TestEveryBrokenDeviceApprovalIsRefused(t *testing.T) {
	setupBox(t)
	ctx := t.TempDir()
	pub, _ := deviceInit()
	if err := pinDeviceKey(pub); err != nil {
		t.Fatal(err)
	}
	hn, _ := os.Hostname()
	purpose := mgmtOpPurpose(putOp, hn, putJob("").Args)
	good, _ := deviceSign(purpose, time.Minute)
	var a deviceApproval
	_ = json.Unmarshal([]byte(good), &a)
	mutate := func(f func(x *deviceApproval)) string {
		x := a
		f(&x)
		raw, _ := json.Marshal(&x)
		return string(raw)
	}
	cases := []struct{ name, approval, want string }{
		{"wrong purpose (other args)", mutate(func(x *deviceApproval) { x.Purpose = mgmtOpPurpose(putOp, hn, []string{"other"}) }), "signature does not verify"},
		{"tampered signature", mutate(func(x *deviceApproval) { x.Sig = base64.StdEncoding.EncodeToString(make([]byte, 64)) }), "signature does not verify"},
		{"expired", mutate(func(x *deviceApproval) { x.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) }), "signature does not verify"},
		{"two uses", mutate(func(x *deviceApproval) { x.Uses = 2 }), "signature does not verify"},
		{"no nonce", mutate(func(x *deviceApproval) { x.Nonce = "" }), "signature does not verify"},
		{"other version", mutate(func(x *deviceApproval) { x.V = 2 }), "not one this box reads"},
		{"unreadable", `{"sig": not json`, "not readable"},
		{"not an approval at all", "{not json", "none was given"},
		{"console id that does not exist", "deadbeef", "none was given"},
	}
	// Every refused write here is a strike (quarantine.go); the hold is lifted
	// between cases so each case meets the gate and not the hold.
	for _, c := range cases {
		_, errOut, code := driveJob(t, tAnchor, putJob(c.approval), ctx, "")
		if code != 126 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: want refusal containing %q, got %d %q", c.name, c.want, code, errOut)
		}
		quarantineClear(tAnchor)
	}
	// Properly RE-SIGNED mutations: the signature is fine, the content is not.
	resign := func(f func(x *deviceApproval)) string {
		x := a
		f(&x)
		f2, _ := deviceKeyLoad()
		priv, _ := base64.StdEncoding.DecodeString(f2.Priv)
		x.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(priv), x.canonical()))
		raw, _ := json.Marshal(&x)
		return string(raw)
	}
	resigned := []struct{ name, approval, want string }{
		{"wrong purpose", resign(func(x *deviceApproval) { x.Purpose = mgmtOpPurpose(putOp, hn, []string{"other"}) }), "purpose mismatch"},
		{"expired", resign(func(x *deviceApproval) { x.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) }), "expired"},
		{"too long-lived", resign(func(x *deviceApproval) { x.Expires = time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339) }), "longer than"},
		{"two uses", resign(func(x *deviceApproval) { x.Uses = 2 }), "one run"},
		{"short nonce", resign(func(x *deviceApproval) { x.Nonce = "abc" }), "nonce too short"},
	}
	for _, c := range resigned {
		_, errOut, code := driveJob(t, tAnchor, putJob(c.approval), ctx, "")
		if code != 126 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: want refusal containing %q, got %d %q", c.name, c.want, code, errOut)
		}
		quarantineClear(tAnchor)
	}
	// And the good one still runs after all of that: no mutation spent it.
	if _, errOut, code := driveJob(t, tAnchor, putJob(good), ctx, ""); code == 126 {
		t.Fatalf("the untouched approval must still run: %d %s", code, errOut)
	}
}

// A device the box never pinned signs nothing that runs here, and unpinning
// withdraws a device.
func TestAnUnpinnedDeviceIsRefusedAndUnpinWithdrawsOne(t *testing.T) {
	// Device A on its own machine.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	pubA, _ := deviceInit()
	hn, _ := os.Hostname()
	fromA, _ := deviceSign(mgmtOpPurpose(putOp, hn, putJob("").Args), time.Minute)
	// The anchored box, with device B pinned.
	setupBox(t)
	ctx := t.TempDir()
	pubB, _ := deviceInit()
	if err := pinDeviceKey(pubB); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := driveJob(t, tAnchor, putJob(fromA), ctx, ""); code != 126 || !strings.Contains(errOut, "not pinned") {
		t.Fatalf("an unpinned device's approval must be refused: %d %q", code, errOut)
	}
	if err := pinDeviceKey(pubA); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := driveJob(t, tAnchor, putJob(fromA), ctx, ""); code == 126 {
		t.Fatalf("once pinned, A's approval runs: %d %s", code, errOut)
	}
	if err := unpinDeviceKey(pubA); err != nil {
		t.Fatal(err)
	}
	if err := unpinDeviceKey(pubB); err != nil {
		t.Fatal(err)
	}
	if devicePinned() {
		t.Fatal("no device is pinned now")
	}
	if err := unpinDeviceKey(pubB); err == nil {
		t.Fatal("unpinning a key that is not pinned must say so")
	}
	if err := pinDeviceKey("not-a-key"); err == nil {
		t.Fatal("a malformed key must be refused")
	}
}

// The console path: a factor enrolled here, a mgmt_op request the host files,
// the person approves with their code, and the approval runs the op once.
func TestAConsoleApprovalRunsAWriteOnce(t *testing.T) {
	setupBox(t)
	ctx, dcn := t.TempDir(), t.TempDir()
	enrollFactor(t, dcn)
	hn, _ := os.Hostname()
	args := putJob("").Args
	details := map[string]any{"kind": "mgmt_op", "op": putOp, "server": hn,
		"args": []any{args[0]}, "note": "save the meeting notes"}
	purpose, err := purposeFromDetails(details)
	if err != nil {
		t.Fatal(err)
	}
	if purpose != mgmtOpPurpose(putOp, hn, args) {
		t.Fatalf("the purpose must be derived from the details: %s", purpose)
	}
	if stepupDetailsFamily(details) != "dcn" {
		t.Fatalf("a mgmt_op ask is gated on the op's family: %s", stepupDetailsFamily(details))
	}
	if stepupDetailsFamily(map[string]any{"kind": "mgmt_op", "op": "contain", "server": hn}) != capsFamilyAnchor {
		t.Fatal("a directive's approval is the anchor's alone")
	}
	elsewhere := map[string]any{"kind": "mgmt_op", "op": "ctx_put", "server": "elsewhere", "args": []any{"a"}}
	ep, _ := purposeFromDetails(elsewhere)
	if _, err := stepupNewRequest(dcn, ep, elsewhere); err == nil || !strings.Contains(err.Error(), "elsewhere") {
		t.Fatalf("a request for another machine must be refused at THIS box's ask: %v", err)
	}
	// The host files the ask on the mgmt lane.
	detailsRaw, _ := json.Marshal(details)
	detailsB64 := base64.StdEncoding.EncodeToString(detailsRaw)
	out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "stepup_request", Args: []string{purpose, detailsB64}}, ctx, dcn)
	if code != 0 {
		t.Fatalf("stepup_request: %d %s", code, errOut)
	}
	var reply struct{ Request string }
	_ = json.Unmarshal([]byte(out), &reply)
	if words := describeRequest(stepupRequest{Details: details}); !strings.Contains(words, putOp) ||
		!strings.Contains(words, "on "+hn) || !strings.Contains(words, "arg 1: "+args[0]) || strings.Contains(words, "meeting notes") {
		t.Fatalf("the console shows the op, the machine and every argument — never the pod's note: %q", words)
	}
	if long := argWords(strings.Repeat("x", 3000)); !strings.Contains(long, "3000 bytes in all") {
		t.Fatalf("a long argument is named by its length and digest: %q", long[len(long)-60:])
	}
	raw, _ := b32decode(tSecret)
	approval, err := stepupApproveRequest(dcn, reply.Request, hotp(raw, time.Now().Unix()/stepupPeriod))
	if err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := driveJob(t, tAnchor, putJob(approval), ctx, dcn); code == 126 {
		t.Fatalf("the console approval must run the op: %d %s", code, errOut)
	}
	if _, errOut, code := driveJob(t, tAnchor, putJob(approval), ctx, dcn); code != 126 || !strings.Contains(errOut, "already used") {
		t.Fatalf("single use: %d %q", code, errOut)
	}
	// The console path hands a missed tap back on a re-file, once. The first
	// request above was approved directly (never read through stepup_status),
	// so it is still undelivered: a re-file returns IT, approved.
	same, err := stepupNewRequest(dcn, purpose, details)
	if err != nil || same != reply.Request {
		t.Fatalf("an approved, undelivered ask is the same request: %s %v", same, err)
	}
	if _, ok := stepupHandOut(dcn, reply.Request); !ok {
		t.Fatal("handed out once")
	}
	id2, err := stepupNewRequest(dcn, purpose, details)
	if err != nil || id2 == reply.Request {
		t.Fatalf("after delivery the same ask is a new request: %s %v", id2, err)
	}
	if _, err := stepupApproveRequest(dcn, id2, hotp(raw, time.Now().Unix()/stepupPeriod+1)); err != nil {
		t.Fatal(err)
	}
	out2, _, code := driveJob(t, tAnchor, mgmtJob{Op: "stepup_request", Args: []string{purpose, detailsB64}}, ctx, dcn)
	if code != 0 || !strings.Contains(out2, `"approved"`) || !strings.Contains(out2, id2) {
		t.Fatalf("a re-filed approved ask is answered approved with its id: %d %s", code, out2)
	}
	st, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "stepup_status", Args: []string{id2}}, ctx, dcn)
	if !strings.Contains(st, `"delivered"`) {
		t.Fatalf("handed out once: %s", st)
	}
}

// Five refused writes inside ten minutes close a pairing's write lanes; reads
// stay open; the console lifts it.
func TestRepeatedRefusedWritesQuarantineThePairing(t *testing.T) {
	setupBox(t)
	ctx := t.TempDir()
	// A device is pinned, so every refusal below is the host's fault (no
	// approval given), the kind that counts.
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	for i := 0; i < quarantineStrikes; i++ {
		if _, errOut, code := driveJob(t, tAnchor, putJob(""), ctx, ""); code != 126 || strings.Contains(errOut, "quarantined") {
			t.Fatalf("refusal %d must be the gate's, not a hold yet: %d %q", i+1, code, errOut)
		}
	}
	if _, errOut, code := driveJob(t, tAnchor, putJob(""), ctx, ""); code != 126 || !strings.Contains(errOut, "quarantined") {
		t.Fatalf("the sixth write must meet the hold: %d %q", code, errOut)
	}
	// Even a GOOD approval is refused during the hold, and not spent — and a
	// revoke is never held back.
	hn, _ := os.Hostname()
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "dcn_grant_drop", Args: []string{"7"}}, ctx, t.TempDir()); code == 126 && strings.Contains(errOut, "quarantined") {
		t.Fatalf("a tighten must pass a hold: %d %q", code, errOut)
	}
	approval, _ := deviceSign(mgmtOpPurpose(putOp, hn, putJob("").Args), time.Minute)
	if _, errOut, code := driveJob(t, tAnchor, putJob(approval), ctx, ""); code != 126 || !strings.Contains(errOut, "quarantined") {
		t.Fatalf("a held pairing's approved write is still refused: %d %q", code, errOut)
	}
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "pairing_list"}, ctx, ""); code != 0 {
		t.Fatalf("reads stay open under a hold: %d %s", code, errOut)
	}
	rep := buildEnforcingReport("", nil)
	if rep["write_gate"] != true || rep["device"] != true {
		t.Fatalf("the report must say the gate is on and a device is pinned: %v", rep)
	}
	held, _ := rep["quarantined"].([]string)
	if len(held) != 1 || held[0] != tAnchor {
		t.Fatalf("the report must name the held pairing: %v", rep["quarantined"])
	}
	if ring, _ := rep["refusals"].([]refusalRecord); len(ring) < quarantineStrikes {
		t.Fatalf("the report must carry the refusal ring: %v", rep["refusals"])
	}
	quarantineClear(tAnchor)
	if _, errOut, code := driveJob(t, tAnchor, putJob(approval), ctx, ""); code == 126 {
		t.Fatalf("after the console lifts the hold, the approval (never spent) runs: %d %s", code, errOut)
	}
	// A second hold doubles.
	for i := 0; i < quarantineStrikes; i++ {
		driveJob(t, tAnchor, putJob(""), ctx, "")
	}
	until := quarantinedUntil(tAnchor, time.Now())
	if until.IsZero() {
		t.Fatal("second hold")
	}
	quarantineClear(tAnchor) // forgiven: strikes reset
	for i := 0; i < quarantineStrikes; i++ {
		driveJob(t, tAnchor, putJob(""), ctx, "")
	}
	if u := quarantinedUntil(tAnchor, time.Now()); u.IsZero() || u.Sub(time.Now()) > quarantineBase+time.Minute {
		t.Fatalf("a cleared hold is forgiven — the next one is the base length again: %v", u)
	}
	// Strikes double when the hold lapses on its own.
	f := quarantineLoad()
	f.Pairing[tAnchor].Until = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	_ = quarantineSave(f)
	for i := 0; i < quarantineStrikes; i++ {
		driveJob(t, tAnchor, putJob(""), ctx, "")
	}
	if u := quarantinedUntil(tAnchor, time.Now()); u.IsZero() || u.Sub(time.Now()) < 2*quarantineBase-time.Minute {
		t.Fatalf("a repeat hold doubles: %v", u)
	}
}

// The person at the machine switches the directives off, and the anchor's
// approved directive is refused anyway.
// The args digest is what the pod derives too: a fixed vector, framed
// "<len>:<bytes>\n" per argument, never JSON.
func TestArgsDigestIsTheFramedSHA256(t *testing.T) {
	if got := argsDigest(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("no args: %s", got)
	}
	// sha256 of "1:a\n3:b<c\n" — the host pins the same vector on its side.
	if got := argsDigest([]string{"a", "b<c"}); got != "922c052b1872b6644665fa394e99c19aa26037ee0b81b5c4bc22ed4fd34ddd0b" {
		t.Fatalf("fixed vector: %s", got)
	}
	if argsDigest([]string{"a\nb"}) == argsDigest([]string{"a", "b"}) {
		t.Fatal("the length prefix must keep one argument apart from two")
	}
}

// A directive the box already approved is not re-asked on the next beat, and
// a mirror placement stands until the host disables it.
func TestARepeatedDirectiveRunsOnTheApprovalAlreadyGiven(t *testing.T) {
	setupBox(t)
	// Both targets below are older than the version this box runs, so each
	// needs an approval (a newer one would not: claims_update_forward_test.go).
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
	maybeSelfUpdate(tAnchor, "", testDirective(t, directiveSelfUpdate, []string{"99.0.0"}, `{"update":{"version":"99.0.0"}}`))
	maybeSelfUpdate(tAnchor, "", []byte(`{"update":{"version":"99.0.0"}}`)) // the next beat, no approval carried
	if fetches != 2 {
		t.Fatalf("the same directive inside the window runs on the approval already given: %d", fetches)
	}
	maybeSelfUpdate(tAnchor, "", []byte(`{"update":{"version":"98.0.0"}}`))
	if fetches != 2 {
		t.Fatal("a different target is a different act")
	}
	if directiveApproved(directiveSelfUpdate, argsDigest([]string{"99.0.0"}), "", time.Now().Add(directiveRepeatWindow+time.Second)) {
		t.Fatal("the window lapses")
	}
	rememberDirective(directiveMirror, "d1", "", true, time.Now())
	if !directiveApproved(directiveMirror, "d1", "", time.Now().Add(365*24*time.Hour)) {
		t.Fatal("a mirror placement stands")
	}
	forgetDirective(directiveMirror)
	if directiveApproved(directiveMirror, "d1", "", time.Now()) {
		t.Fatal("disabled: forgotten")
	}
}

func TestTheLocalSwitchCoversTheDirectives(t *testing.T) {
	setupBox(t)
	// Both targets below are older than the version this box runs, so each
	// needs an approval (a newer one would not: claims_update_forward_test.go).
	freshVersionState(t)
	clientVersion = "100.0.0"
	if err := localDenySet(tAnchor, localFamilyDirectives, true); err != nil {
		t.Fatalf("directives must be switchable: %v", err)
	}
	if err := localDenySet(tAnchor, "no-such-family", true); err == nil {
		t.Fatal("an unknown family is still refused")
	}
	fetches := 0
	man := httptest.NewServer(signedStub(releaseKindBastion, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		_, _ = w.Write([]byte(`{"version":"0.0.0-test","binaries":{}}`))
	})))
	defer man.Close()
	oldURL := manifestURL
	manifestURL = man.URL + "/version.json"
	t.Cleanup(func() { manifestURL = oldURL })
	maybeSelfUpdate(tAnchor, "", testDirective(t, directiveSelfUpdate, []string{"99.0.0"}, `{"update":{"version":"99.0.0"}}`))
	if fetches != 0 {
		t.Fatal("switched off here: even an approved self-update must not fetch")
	}
	if r := directiveRefusalReport(); r == nil || !strings.Contains(fmt.Sprint(r), "switched off") {
		t.Fatalf("the host is told why: %v", r)
	}
	if err := localDenySet(tAnchor, localFamilyDirectives, false); err != nil {
		t.Fatal(err)
	}
	maybeSelfUpdate(tAnchor, "", testDirective(t, directiveSelfUpdate, []string{"99.0.0"}, `{"update":{"version":"99.0.0"}}`))
	if fetches != 1 {
		t.Fatal("switched back on: the approved directive proceeds")
	}
	// The approval is bound to the target: one for 99.0.0 does not roll 98.0.0.
	body := testDirective(t, directiveSelfUpdate, []string{"99.0.0"}, `{"update":{"version":"98.0.0"}}`)
	maybeSelfUpdate(tAnchor, "", body)
	if fetches != 1 {
		t.Fatal("an approval for another version must not fetch")
	}
}

// No open-ended terms: a DCN store grant or a session grant with no expiry
// does not verify.
func TestOpenEndedTermsAreRefused(t *testing.T) {
	priv := setupBox(t) // the anchor's key, pinned at anchoring
	pubB64 := anchorVerifyKey()
	hn, _ := os.Hostname()
	terms := map[string]any{"kind": "dcn_store_grant", "class": "machine", "server": hn, "root": "/srv/x",
		"mask": []string{"read"}, "expires": ""}
	sign := func() dcnGrantRec {
		canonical, _ := json.Marshal(terms)
		return dcnGrantRec{TermsCanonical: base64.StdEncoding.EncodeToString(canonical),
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))}
	}
	if _, err := dcnVerifyRec(pubB64, sign()); err == nil || !strings.Contains(err.Error(), "no expiry") {
		t.Fatalf("an open-ended store grant must be refused: %v", err)
	}
	terms["expires"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if _, err := dcnVerifyRec(pubB64, sign()); err != nil {
		t.Fatalf("the same grant with an expiry verifies: %v", err)
	}
	// The session lane's grant, same rule.
	dir := t.TempDir()
	st := map[string]any{"entity": 9001, "server": hn, "ops": []string{sessionOpOpen}, "deny": []string{}, "expires": ""}
	canonical, _ := json.Marshal(st)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))
	if _, err := sessionVerifyGrant(dir, tAnchor, hn, sessionOpOpen, base64.StdEncoding.EncodeToString(canonical), sig, ""); err == nil ||
		!strings.Contains(err.Error(), "no expiry") {
		t.Fatalf("an open-ended session grant must be refused: %v", err)
	}
}

// On an anchored box the key a grant is verified under comes from anchoring,
// never from what the host offers on the lane.
func TestAnAnchoredBoxNeverPinsAnOfferedKey(t *testing.T) {
	priv := setupBox(t)
	want := anchorVerifyKey()
	other := base64.StdEncoding.EncodeToString(make([]byte, 32))
	f := &dcnGrantFile{Stores: map[string]dcnGrantRec{}}
	// The anchor pairing: pinned from anchor.json, an offer that differs is refused.
	if pinned, why := pinVerifyKey(f, tAnchor, other); why == "" || pinned {
		t.Fatalf("an offered key that is not the anchor's must be refused: %q", why)
	}
	f = &dcnGrantFile{Stores: map[string]dcnGrantRec{}}
	if pinned, why := pinVerifyKey(f, tAnchor, ""); why != "" || !pinned || f.VerifyPubkey != want {
		t.Fatalf("the anchor's key is pinned from anchoring: %v %q %s", pinned, why, f.VerifyPubkey)
	}
	// A member with no verify_key in its grant and nothing pinned keeps
	// first-use pinning (the anchor host holds no other host's key yet); the
	// anchor's own offer above was never taken.
	writePairingState(t, tMember, pairingActive)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, allCaps, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	f = &dcnGrantFile{Stores: map[string]dcnGrantRec{}}
	if pinned, why := pinVerifyKey(f, tMember, other); why != "" || !pinned || f.VerifyPubkey != other {
		t.Fatalf("a member with no key from anchoring pins its first offer: %v %q", pinned, why)
	}
	f = &dcnGrantFile{Stores: map[string]dcnGrantRec{}}
	if _, why := pinVerifyKey(f, tMember, ""); why == "" {
		t.Fatal("a member with no key from anchoring and no offer is default-deny")
	}
	// The same member, re-granted WITH verify_key: pinned from the grant.
	memberKey := base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	gt := grantTerms(tMember, allCaps, future)
	gt["verify_key"] = memberKey
	terms, sig = signTerms(t, priv, gt)
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("re-grant: %d %s", code, errOut)
	}
	f = &dcnGrantFile{Stores: map[string]dcnGrantRec{}}
	if pinned, why := pinVerifyKey(f, tMember, memberKey); why != "" || !pinned || f.VerifyPubkey != memberKey {
		t.Fatalf("a member's key is pinned from the anchor-signed grant: %v %q", pinned, why)
	}
	if _, why := pinVerifyKey(f, tMember, other); why == "" {
		t.Fatal("an offer that disagrees with the grant's key is refused")
	}
	// A local box keeps TOFU.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f = &dcnGrantFile{Stores: map[string]dcnGrantRec{}}
	if pinned, why := pinVerifyKey(f, tAnchor, other); why != "" || !pinned || f.VerifyPubkey != other {
		t.Fatalf("a local box pins the first offer: %v %q", pinned, why)
	}
}

// The device derives the purpose it signs and the words it shows from the
// same details; root is never signed there; only the person's own host may
// use the device lane.
func TestTheDeviceSignsOnlyWhatItDerivedItself(t *testing.T) {
	setupBox(t) // the device is an anchored box too, anchored to tAnchor
	if _, err := deviceInit(); err != nil {
		t.Fatal(err)
	}
	hn, _ := os.Hostname()
	details := map[string]any{"kind": "mgmt_op", "op": "ctx_put", "server": "box-7",
		"args": []any{"notes/a.txt", "aGk="}, "note": "save the notes"}
	raw, _ := json.Marshal(details)
	b64 := base64.StdEncoding.EncodeToString(raw)
	// A member pairing cannot file an ask on the person's device.
	if _, errOut, code := driveJob(t, tMember, mgmtJob{Op: "device_request", Args: []string{b64}}, "", ""); code != 126 || !strings.Contains(errOut, "anchor") {
		t.Fatalf("a member must be refused the device lane: %d %q", code, errOut)
	}
	out, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "device_request", Args: []string{b64}}, "", "")
	if code != 0 {
		t.Fatalf("device_request: %d %s", code, errOut)
	}
	var reply struct{ ID string }
	_ = json.Unmarshal([]byte(out), &reply)
	deviceMu.Lock()
	r := deviceRequestsLoad()[reply.ID]
	deviceMu.Unlock()
	if r.Purpose != mgmtOpPurpose("ctx_put", "box-7", []string{"notes/a.txt", "aGk="}) {
		t.Fatalf("the device must derive the purpose from the details: %s", r.Purpose)
	}
	if !strings.Contains(r.Words, "ctx_put") || !strings.Contains(r.Words, "on box-7") ||
		!strings.Contains(r.Words, "notes/a.txt") || strings.Contains(r.Words, "save the notes") {
		t.Fatalf("the words name the machine and every argument, and never the pod's free text: %q", r.Words)
	}
	if r.Server != "box-7" {
		t.Fatalf("the request's machine is the details' machine: %q", r.Server)
	}
	// A kind whose purpose names no machine is not signed here.
	pull := map[string]any{"kind": "model_pull", "model": "m", "role": "embed", "max_bytes": float64(1), "replaces": ""}
	praw, _ := json.Marshal(pull)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "device_request", Args: []string{base64.StdEncoding.EncodeToString(praw)}}, "", ""); code != 126 || !strings.Contains(errOut, "console") {
		t.Fatalf("a model_pull ask names no machine and is refused on the device: %d %q", code, errOut)
	}
	// The same ask again is the same request.
	out2, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "device_request", Args: []string{b64}}, "", "")
	if !strings.Contains(out2, reply.ID) || strings.Contains(out2, "approval") {
		t.Fatalf("a repeat of a pending ask returns the same id and no approval: %s", out2)
	}
	// Status before the tap: pending, no approval.
	st, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "device_status", Args: []string{reply.ID}}, "", "")
	if !strings.Contains(st, `"pending"`) || strings.Contains(st, "approval") {
		t.Fatalf("pending, and no approval leaks: %s", st)
	}
	if _, err := deviceApprove(reply.ID); err != nil {
		t.Fatal(err)
	}
	st, _, _ = driveJob(t, tAnchor, mgmtJob{Op: "device_status", Args: []string{reply.ID}}, "", "")
	var stv struct{ State, Approval string }
	_ = json.Unmarshal([]byte(st), &stv)
	if stv.State != "approved" || !isDeviceApproval(stv.Approval) {
		t.Fatalf("approved, with the signed approval: %s", st)
	}
	// device_status handed the approval out once; a second read says delivered,
	// and the same ask filed again is a NEW request (a new act), never the
	// spent approval handed back.
	st2, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "device_status", Args: []string{reply.ID}}, "", "")
	if !strings.Contains(st2, `"delivered"`) || strings.Contains(st2, "approval") {
		t.Fatalf("a second status read repeats nothing: %s", st2)
	}
	again, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "device_request", Args: []string{b64}}, "", "")
	var av struct{ ID, State, Approval string }
	_ = json.Unmarshal([]byte(again), &av)
	if av.ID == reply.ID || av.State != "pending" || av.Approval != "" {
		t.Fatalf("after delivery the same ask is a new request: %s", again)
	}
	// The tap the pod MISSED: approve, then re-file without a status read —
	// the approval is handed back on the file, once.
	if _, err := deviceApprove(av.ID); err != nil {
		t.Fatal(err)
	}
	again2, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "device_request", Args: []string{b64}}, "", "")
	var av2 struct{ ID, State, Approval string }
	_ = json.Unmarshal([]byte(again2), &av2)
	if av2.ID != av.ID || av2.State != "approved" || !isDeviceApproval(av2.Approval) {
		t.Fatalf("a re-filed approved ask is handed back once: %s", again2)
	}
	again3, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "device_request", Args: []string{b64}}, "", "")
	if strings.Contains(again3, av.ID) {
		t.Fatalf("and not twice: %s", again3)
	}
	// The approval verifies on the governed box (this one, playing box-7's part).
	_ = pinDeviceKey(mustPub(t))
	if _, err := verifyDeviceApproval(stv.Approval, r.Purpose, time.Now()); err != nil {
		t.Fatalf("the signed approval must verify under the pinned key: %v", err)
	}
	// Root is never signed on a device.
	rootDetails := map[string]any{"kind": "session_root", "server": hn, "session_id": "sess-0001"}
	rraw, _ := json.Marshal(rootDetails)
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "device_request",
		Args: []string{base64.StdEncoding.EncodeToString(rraw)}}, "", ""); code != 126 || !strings.Contains(errOut, "code") {
		t.Fatalf("a root ask must be refused on the device: %d %q", code, errOut)
	}
	// Deny: not asked again.
	details2 := map[string]any{"kind": "mgmt_op", "op": "ctx_del", "server": "box-7", "args": []any{"x"}}
	raw2, _ := json.Marshal(details2)
	out3, _, _ := driveJob(t, tAnchor, mgmtJob{Op: "device_request", Args: []string{base64.StdEncoding.EncodeToString(raw2)}}, "", "")
	_ = json.Unmarshal([]byte(out3), &reply)
	if err := deviceDeny(reply.ID); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "device_request", Args: []string{base64.StdEncoding.EncodeToString(raw2)}}, "", ""); code != 126 || !strings.Contains(errOut, "refused this") {
		t.Fatalf("a denied ask is not asked again: %d %q", code, errOut)
	}
}

func mustPub(t *testing.T) string {
	t.Helper()
	f, err := deviceKeyLoad()
	if err != nil {
		t.Fatal(err)
	}
	return f.Pub
}

// An approval is spent when accepted — two workers handed the same one
// cannot both run — and root never opens on a device tap.
func TestAnApprovalIsSpentWhenAcceptedNotAfterTheRun(t *testing.T) {
	setupBox(t)
	dcn := t.TempDir()
	enrollFactor(t, dcn)
	hn, _ := os.Hostname()
	purpose := mgmtOpPurpose(putOp, hn, putJob("").Args)
	raw, _ := b32decode(tSecret)
	id, err := stepupIssueApproval(dcn, hotp(raw, time.Now().Unix()/stepupPeriod), purpose)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumeApproval(dcn, id, purpose); err != nil {
		t.Fatal(err)
	}
	if _, err := consumeApproval(dcn, id, purpose); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("the second spend must fail: %v", err)
	}
	if err := approvalOK(dcn, id, purpose); err == nil {
		t.Fatal("a spent approval no longer checks out")
	}
	// A device approval, likewise, and its identity is what the audit records.
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	dev, _ := deviceSign(purpose, time.Minute)
	got, err := consumeApproval(dcn, dev, purpose)
	if err != nil || !strings.HasPrefix(got, "device:") {
		t.Fatalf("device approval spent once: %q %v", got, err)
	}
	if _, err := consumeApproval(dcn, dev, purpose); err == nil {
		t.Fatal("a device approval cannot be spent twice")
	}
}

// The harness lane is gated on an anchored box: no approval, no container.
func TestTheHarnessLaneSpendsAnApprovalOnAnAnchoredBox(t *testing.T) {
	setupBox(t)
	drive := func(spec harnessSpec) (string, int) {
		up := websocket.Upgrader{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer ws.Close()
			handleHarnessConn(ws, tAnchor, "")
		}))
		defer srv.Close()
		c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		raw, _ := json.Marshal(spec)
		_ = c.WriteMessage(websocket.BinaryMessage, append([]byte("H"), raw...))
		var out string
		for {
			_, data, err := c.ReadMessage()
			if err != nil {
				t.Fatal(err)
			}
			switch data[0] {
			case 'J':
				out = string(data[1:])
			case 'X':
				var code int
				fmt.Sscanf(string(data[1:]), "%d", &code)
				return out, code
			}
		}
	}
	spec := harnessSpec{HarnessID: "h1", Mode: "echo", Prompt: "ping"}
	if out, code := drive(spec); code != 126 || !strings.Contains(out, "needs your approval") {
		t.Fatalf("the anchor's harness job without an approval must be refused: %d %s", code, out)
	}
	spec.Approval = testApproval(t, "harness:run", harnessArgs(spec))
	if out, code := drive(spec); code != 0 || !strings.Contains(out, `"echo":"ping"`) {
		t.Fatalf("with the approval it runs: %d %s", code, out)
	}
	if out, code := drive(spec); code != 126 || !strings.Contains(out, "already used") {
		t.Fatalf("the same approval does not run a second job: %d %s", code, out)
	}
	other := spec
	other.Image = "someone-elses-image"
	if out, code := drive(other); code != 126 {
		t.Fatalf("an approval for one image does not run another: %d %s", code, out)
	}
}

// `device-approve all` signs only the asks the person was shown.
func TestDeviceApproveAllSignsOnlyWhatWasShown(t *testing.T) {
	setupBox(t)
	if _, err := deviceInit(); err != nil {
		t.Fatal(err)
	}
	file := func(op string) string {
		d := map[string]any{"kind": "mgmt_op", "op": op, "server": "box-7", "args": []any{}}
		id, err := deviceNewRequest(d)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := file("ctx_del")
	if err := cmdDeviceApprove("all"); err == nil {
		t.Fatal("nothing shown yet: all must refuse")
	}
	if err := cmdDeviceApprovals(); err != nil {
		t.Fatal(err)
	}
	b := file("harness:run") // filed AFTER the person looked
	if err := cmdDeviceApprove("all"); err != nil {
		t.Fatal(err)
	}
	deviceMu.Lock()
	m := deviceRequestsLoad()
	deviceMu.Unlock()
	if m[a].State != "approved" || m[b].State != "pending" {
		t.Fatalf("shown %s must be approved, unseen %s must stay pending: %s / %s", a[:8], b[:8], m[a].State, m[b].State)
	}
	if err := cmdDeviceApprove("all"); err == nil {
		t.Fatal("the snapshot is spent: all must refuse again until the list is re-read")
	}
}

// The harness approval binds everything the run acts on, and the clone URL
// must name the approved repository.
func TestHarnessApprovalBindsTheWholeRunAndTheRepoName(t *testing.T) {
	setupBox(t)
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	hn, _ := os.Hostname()
	spec := harnessSpec{HarnessID: "h1", Mode: "git", Image: "img", Repo: "git.example/owner/site", Branch: "main",
		Prompt: "fix the header", RepoURL: "https://u:tok@git.example/owner/site.git"}
	sign := func(sp harnessSpec) string {
		a, _ := deviceSign(mgmtOpPurpose("harness:run", hn, harnessArgs(sp)), time.Minute)
		return a
	}
	spec.Approval = sign(spec)
	if why := harnessGate(tAnchor, "", spec); why != "" {
		t.Fatalf("a matching run passes: %s", why)
	}
	other := spec
	other.Approval = sign(spec)
	other.RepoURL = "https://u:tok@git.example/someone/else.git"
	if why := harnessGate(tAnchor, "", other); !strings.Contains(why, "not the one the approval names") {
		t.Fatalf("a clone URL naming another repo is refused: %q", why)
	}
	changed := spec
	changed.Approval = sign(spec)
	changed.Prompt = "rm -rf everything"
	if why := harnessGate(tAnchor, "", changed); why == "" {
		t.Fatal("a changed prompt is a different act")
	}
	elsewhere := spec
	elsewhere.Approval = sign(spec)
	elsewhere.RepoURL = "https://u:tok@evil.example/owner/site.git"
	if why := harnessGate(tAnchor, "", elsewhere); !strings.Contains(why, "not the one the approval names") {
		t.Fatalf("the same path on another forge is another repository: %q", why)
	}
	if repoNameOf("https://u:t@H.example/owner/name.git") != "h.example/owner/name" || repoNameOf("nonsense") != "" {
		t.Fatal("repoNameOf")
	}
	// A blank repository on both sides, or a local path as the URL, is refused.
	blank := harnessSpec{HarnessID: "h2", Mode: "git", Image: "img", RepoURL: "/srv/app/.git"}
	blank.Approval = sign(blank)
	if why := harnessGate(tAnchor, "", blank); !strings.Contains(why, "not the one the approval names") {
		t.Fatalf("a git run with no repository named is refused: %q", why)
	}
	local := spec
	local.Approval = sign(spec)
	local.RepoURL = "file:///srv/app"
	if why := harnessGate(tAnchor, "", local); why == "" {
		t.Fatal("a file: URL is not the approved forge repository")
	}
	if clean("a\u009bb\x1bc") != "a b c" {
		t.Fatalf("C0 and C1 controls are blanked: %q", clean("a\u009bb\x1bc"))
	}
}

// On an anchored box the egress lane refuses anything inward.
func TestAnchoredEgressRefusesLoopbackAndPrivateDestinations(t *testing.T) {
	setupBox(t)
	ctx := context.Background()
	for _, d := range []string{"127.0.0.1:11434", "localhost:80", "10.0.0.5:443", "192.168.1.1:80",
		"172.16.4.4:22", "[::1]:80", "[fd12:3456::e:3]:8443", "[fe80::1]:80", "100.64.0.1:80", "169.254.169.254:80"} {
		if why := egressInternalRefusal(ctx, d); why == "" {
			t.Errorf("%s must be refused on an anchored box", d)
		}
	}
	for _, d := range []string{"8.8.8.8:53", "[2606:4700::1111]:443"} {
		if why := egressInternalRefusal(ctx, d); why != "" {
			t.Errorf("%s is the public internet: %s", d, why)
		}
	}
	// The address vetted is the address dialled, never the name again.
	if addr, why := egressVettedAddr(ctx, "8.8.8.8:53"); why != "" || addr != "8.8.8.8:53" {
		t.Fatalf("vetted literal: %q %q", addr, why)
	}
	if addr, why := egressVettedAddr(ctx, "localhost:80"); why == "" || addr != "" {
		t.Fatalf("a refused name yields no address: %q %q", addr, why)
	}
	// A local box refuses this machine too, and keeps its LAN
	// (egress_local_test.go has the rest).
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubOwnAddrs(t, loopbackOnly, localRange())
	if why := egressInternalRefusal(ctx, "127.0.0.1:11434"); why == "" {
		t.Fatal("a local box must refuse its own ollama on the egress lane")
	}
	if addr, why := egressVettedAddr(ctx, "192.168.1.1:80"); why != "" || addr != "192.168.1.1:80" {
		t.Fatalf("a local box keeps its LAN: %q %q", addr, why)
	}
}

// A contain approval is remembered with the agent's signature: a reused pid
// is a new act.
func TestARememberedContainDoesNotKillAReusedPid(t *testing.T) {
	setupBox(t)
	if directiveApproved(directiveContain, argsDigest([]string{"4242"}), "sig-A", time.Now()) {
		t.Fatal("nothing remembered yet")
	}
	rememberDirective(directiveContain, argsDigest([]string{"4242"}), "sig-A", false, time.Now())
	if !directiveApproved(directiveContain, argsDigest([]string{"4242"}), "sig-A", time.Now()) {
		t.Fatal("the same agent under the same pid is the remembered act")
	}
	if directiveApproved(directiveContain, argsDigest([]string{"4242"}), "sig-B", time.Now()) {
		t.Fatal("another program under that pid is not")
	}
}

// The standing context lane cannot touch this box's own record.
func TestTheContextLaneCannotTouchTheSessionRecord(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writePairing(t, tAnchor)
	ctx := t.TempDir()
	for _, p := range []string{"sessions/sess-0001.log", "/sessions/x.log", "Sessions/x.log", "sessions", "Sessions",
		"./sessions/x.log", "notes/../sessions/x.log", "a/b/../../sessions/x.log"} {
		job := mgmtJob{Op: "ctx_put", Args: []string{p, "aGk="}}
		if _, errOut, code := driveJob(t, tAnchor, job, ctx, ""); code == 0 || !strings.Contains(errOut, "path rejected") {
			t.Fatalf("ctx_put %q must be refused: %d %q", p, code, errOut)
		}
		if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "ctx_del", Args: []string{p}}, ctx, ""); code == 0 || !strings.Contains(errOut, "path rejected") {
			t.Fatalf("ctx_del %q must be refused: %d %q", p, code, errOut)
		}
	}
	if _, errOut, code := driveJob(t, tAnchor, mgmtJob{Op: "ctx_put", Args: []string{"notes/sessions.txt", "aGk="}}, ctx, ""); code != 0 {
		t.Fatalf("an ordinary blob path is fine: %d %s", code, errOut)
	}
}

// The extract approval binds the tool, the mime and the host's name for the
// document — never the bytes, never the pull ticket.
func TestTheExtractApprovalBindsStableFields(t *testing.T) {
	a := approvalArgs("ctx_extract", []string{`{"tool":"pdf-text","mime":"application/pdf","doc":"ctx:42","ticket":"t-1","b64":"aGk="}`})
	if len(a) != 4 || a[0] != "pdf-text" || a[1] != "application/pdf" || a[2] != "ctx:42" || len(a[3]) != 64 {
		t.Fatalf("stable fields, and the inline bytes' digest: %v", a)
	}
	other := approvalArgs("ctx_extract", []string{`{"tool":"pdf-text","mime":"application/pdf","doc":"ctx:42","b64":"b3RoZXI="}`})
	if other[3] == a[3] {
		t.Fatal("another document under the same label is another act")
	}
	b := approvalArgs("ctx_extract", []string{`{"tool":"pdf-text","mime":"application/pdf","ticket":"t-9"}`})
	if len(b) != 4 || b[2] != "ticket:t-9" || b[3] != "" {
		t.Fatalf("pull path with no doc name: the ticket, no bytes: %v", b)
	}
	if got := approvalArgs("ctx_put", []string{"x", "y"}); len(got) != 2 {
		t.Fatalf("other ops bind their args as sent: %v", got)
	}
	// And the purpose for two calls that differ only in the ticket is the same.
	p1 := mgmtOpPurpose("ctx_extract", "box", []string{`{"tool":"t","mime":"m","doc":"ctx:1","ticket":"a"}`})
	p2 := mgmtOpPurpose("ctx_extract", "box", []string{`{"tool":"t","mime":"m","doc":"ctx:1","ticket":"b"}`})
	if p1 != p2 {
		t.Fatal("a re-minted ticket must not change the purpose")
	}
}
