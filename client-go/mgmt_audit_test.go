//go:build !windows

// Uses setupBox / driveOp / writePairingState / signTerms / grantTerms /
// tAnchor / tMember from anchor_test.go, which are unix-only — hence the tag
// above. buildtags_test.go enforces it.

package main

// The command lane's accounting (mgmt_audit.go).
//
// The gate that matters is not "does mgmtAudit write a file" — it is "does an
// op that crossed the real frame path leave the right verdict behind". So every
// test here goes through driveOp, the same websocket round trip the host uses,
// and reads what landed on disk afterwards.

import (
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

// driveRawMgmt is driveOp for a frame that is not a valid job — the one case
// driveOp cannot express, because it marshals a well-formed mgmtJob.
func driveRawMgmt(t *testing.T, self string, frame []byte) (string, string, int) {
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
	if err := c.WriteMessage(websocket.BinaryMessage, frame); err != nil {
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

// readMgmtAudit returns the parsed records in <configDir>/mgmt_audit.jsonl.
func readMgmtAudit(t *testing.T) []map[string]any {
	t.Helper()
	p, err := mgmtAuditPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("the audit file must exist once an op has been served: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("every line must be one JSON record, got %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// truncateMgmtAudit clears what the setup ops wrote, so a test counts only the
// ops it drove itself. Granting a pairing is a management op like any other and
// is audited too, which is correct and would otherwise make every count here
// one about the fixture rather than about the thing under test.
func truncateMgmtAudit(t *testing.T) {
	t.Helper()
	p, err := mgmtAuditPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// One allowed op and one refused op leave two lines with the right verdicts —
// the gate that matters. The refused one is refused by the CAPS ceiling,
// which is the refusal the whole feature exists to make visible: a host asking
// its own machine for a family it was told it does not hold.
func TestMgmtAuditRecordsAllowedAndRefused(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	// The member holds "observe" and nothing else.
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	truncateMgmtAudit(t)

	// Allowed: uptime is family "observe", which this pairing holds.
	if _, errOut, code := driveOp(t, tMember, "uptime", nil); code != 0 {
		t.Fatalf("uptime must be served to an observe pairing: %d %s", code, errOut)
	}
	// Refused: dcn_list is family "dcn", which it does not.
	if _, errOut, code := driveOp(t, tMember, "dcn_list", nil); code != 126 {
		t.Fatalf("dcn_list must be refused to an observe-only pairing: %d %s", code, errOut)
	}

	recs := readMgmtAudit(t)
	if len(recs) != 2 {
		t.Fatalf("two ops must leave exactly two lines, got %d: %v", len(recs), recs)
	}

	allowed, refused := recs[0], recs[1]
	if allowed["op"] != "uptime" || allowed["verdict"] != auditAllowed {
		t.Fatalf("the first line must be uptime/allowed: %v", allowed)
	}
	if allowed["family"] != "observe" {
		t.Fatalf("uptime is family observe: %v", allowed)
	}
	if allowed["why"] != "" {
		t.Fatalf("an allowed op has no refusal string: %v", allowed)
	}
	if allowed["exit"] != float64(0) {
		t.Fatalf("uptime exited 0 on the wire, so the line must say 0: %v", allowed)
	}
	if refused["op"] != "dcn_list" || refused["verdict"] != auditRefused {
		t.Fatalf("the second line must be dcn_list/refused: %v", refused)
	}
	if refused["exit"] != float64(126) {
		t.Fatalf("a refusal exits 126: %v", refused)
	}
	why, _ := refused["why"].(string)
	if !strings.Contains(why, "dcn") || !strings.Contains(why, "caps") {
		t.Fatalf("the refusal must record WHICH ceiling refused it, got %q", why)
	}

	// Both lines name the pairing, never a key, and both carry the signature of
	// the grant that was consulted plus the binary they were decided by.
	for _, r := range recs {
		if r["self"] != tMember {
			t.Fatalf("self must be the pairing id: %v", r)
		}
		if s, _ := r["grant_sig"].(string); s == "" {
			t.Fatalf("a member pairing's line must carry the grant signature: %v", r)
		}
		if d, _ := r["binary_sha256"].(string); d == "" {
			t.Fatalf("binary_sha256 must be present: %v", r)
		}
		if ts, err := time.Parse(time.RFC3339, r["ts"].(string)); err != nil || ts.IsZero() {
			t.Fatalf("ts must be RFC3339 UTC: %v", r)
		}
	}
}

// The heartbeat summary is what the host reacts to without pulling anything.
func TestMgmtAuditReportCountsTheRefusal(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	truncateMgmtAudit(t)

	// A box that has answered nothing says nothing — a missing record must not
	// report the same confident zero as a quiet machine.
	if r := mgmtAuditReport(); r != nil {
		t.Fatalf("no file must mean no audit block, got %v", r)
	}
	if _, ok := buildEnforcingReport("", nil)["audit"]; ok {
		t.Fatal("the enforcing report must omit audit until there is something to say")
	}

	driveOp(t, tMember, "uptime", nil)
	driveOp(t, tMember, "dcn_list", nil)

	rep := mgmtAuditReport()
	if rep == nil {
		t.Fatal("two served ops must produce a report")
	}
	if rep["lines"] != 2 {
		t.Fatalf("lines must count every record, not just refusals: %v", rep)
	}
	if rep["refused_last_hour"] != 1 {
		t.Fatalf("one of the two was refused: %v", rep)
	}
	last, ok := rep["last_refusal"].(map[string]any)
	if !ok || last["op"] != "dcn_list" {
		t.Fatalf("last_refusal must name the op: %v", rep)
	}
	if w, _ := last["why"].(string); w == "" {
		t.Fatalf("last_refusal must carry why: %v", rep)
	}

	// And it rides the enforcing report, which is the only way the host sees it.
	er := buildEnforcingReport("", nil)
	got, ok := er["audit"].(map[string]any)
	if !ok {
		t.Fatalf("the enforcing report must carry audit: %v", er)
	}
	if got["refused_last_hour"] != 1 {
		t.Fatalf("the enforcing report's copy must agree: %v", got)
	}
}

// audit_fetch is in the op table (so the enforcing report advertises it), is
// classified (so capsAllow cannot fail open on it), and is answered for the
// anchor but refused for a member on an anchored box — the file names every
// pairing, so a member reading it is a cross-pairing read.
func TestAuditFetchIsAnchorDirectedAndCapped(t *testing.T) {
	priv := setupBox(t)
	if _, ok := handlerOps[mgmtAuditFetchOp]; !ok {
		t.Fatal("audit_fetch must be in handlerOps, or the enforcing report never advertises it")
	}
	if opFamily(mgmtAuditFetchOp) != "observe" {
		t.Fatalf("audit_fetch must have a family or capsAllow fails open on it, got %q",
			opFamily(mgmtAuditFetchOp))
	}
	found := false
	for _, op := range mgmtOpVocabulary() {
		found = found || op == mgmtAuditFetchOp
	}
	if !found {
		t.Fatal("audit_fetch must appear in the advertised vocabulary")
	}

	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	// Grant the member the very family audit_fetch belongs to: the point is that
	// the caps ceiling is NOT what keeps it out, the anchor gate is.
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	if _, errOut, code := driveOp(t, tMember, mgmtAuditFetchOp, nil); code != 126 ||
		!strings.Contains(errOut, "anchor") {
		t.Fatalf("a member must be refused audit_fetch on an anchored box: %d %s", code, errOut)
	}

	out, errOut, code := driveOp(t, tAnchor, mgmtAuditFetchOp, nil)
	if code != 0 {
		t.Fatalf("the anchor must be served: %d %s", code, errOut)
	}
	var res struct {
		Bytes     int64  `json:"bytes"`
		Truncated bool   `json:"truncated"`
		Text      string `json:"text"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("the reply must be JSON: %v (%q)", err, out)
	}
	if res.Bytes == 0 || res.Text == "" {
		t.Fatalf("by now the file holds the grant and the refusal: %+v", res)
	}
	if !strings.Contains(res.Text, "pairing_grant_sync") ||
		!strings.Contains(res.Text, mgmtAuditFetchOp) {
		t.Fatalf("the fetched text must be the audit lines: %q", res.Text)
	}

	// The cap is a ceiling the caller can only ask BELOW, and a truncated read
	// starts on a record boundary — a fetch that begins mid-line hands the
	// consumer a first line it cannot parse.
	out, errOut, code = driveOp(t, tAnchor, mgmtAuditFetchOp, []string{`{"max_bytes":200}`})
	if code != 0 {
		t.Fatalf("a capped fetch must still be served: %d %s", code, errOut)
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatalf("200 bytes cannot hold this file, so the reply must say truncated: %+v", res)
	}
	if len(res.Text) > 200 {
		t.Fatalf("the returned text must respect the cap: %d bytes", len(res.Text))
	}
	for _, line := range strings.Split(strings.TrimRight(res.Text, "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("a truncated fetch must start on a record boundary, got %q", line)
		}
	}
}

// The exit code on an allowed line is the one that went over the wire, not one
// re-derived at the call site. A handler that runs and FAILS is still allowed —
// the verdict is about the wall, and conflating "refused" with "errored" would
// make every bad argument look like a permission event on the host's posture.
func TestMgmtAuditAllowedCarriesTheHandlerExit(t *testing.T) {
	setupBox(t)
	truncateMgmtAudit(t)

	// dcn_list from the ANCHOR pairing: unconstrained by caps, so it reaches the
	// handler table — and refused there for an unconfigured root, which is a
	// refusal and not a handler exit.
	if _, _, code := driveOp(t, tAnchor, "dcn_list", nil); code != 126 {
		t.Fatalf("an unconfigured dcn root refuses like an unpermitted op: %d", code)
	}
	recs := readMgmtAudit(t)
	if len(recs) != 1 || recs[0]["verdict"] != auditRefused {
		t.Fatalf("the unconfigured-root exit must be audited as refused: %v", recs)
	}
	if w, _ := recs[0]["why"].(string); !strings.Contains(w, "not configured") {
		t.Fatalf("it must record WHY: %v", recs[0])
	}
	// The anchor's own line carries no grant signature: it is unconstrained by
	// construction, so no grant was consulted and there is none to name.
	if s, _ := recs[0]["grant_sig"].(string); s != "" {
		t.Fatalf("the anchor pairing consults no grant: %v", recs[0])
	}

	// An op with no family and no handler: refused as not permitted.
	truncateMgmtAudit(t)
	if _, _, code := driveOp(t, tAnchor, "no_such_op", nil); code != 126 {
		t.Fatalf("an unknown op must be refused: %d", code)
	}
	recs = readMgmtAudit(t)
	if len(recs) != 1 || recs[0]["verdict"] != auditRefused {
		t.Fatalf("the not-permitted exit must be audited: %v", recs)
	}
	if w, _ := recs[0]["why"].(string); !strings.Contains(w, "not permitted") {
		t.Fatalf("it must record WHY: %v", recs[0])
	}

	// A frame that does not parse is audited with an empty op — this box does
	// not know what it was asked for, and saying so is the record.
	truncateMgmtAudit(t)
	if _, _, code := driveRawMgmt(t, tAnchor, []byte("C{not json")); code != 126 {
		t.Fatalf("a bad job must be refused: %d", code)
	}
	recs = readMgmtAudit(t)
	if len(recs) != 1 || recs[0]["op"] != "" || recs[0]["verdict"] != auditRefused {
		t.Fatalf("a bad job must be audited with an empty op: %v", recs)
	}
}

// A networked box with no anchor answers nothing — and the refusal is recorded.
// This is the exit an allowed-or-refused sketch of the lane misses, and it is the one that
// fires on a machine that was networked and then lost its anchor: without a
// line here, a box refusing every op looks identical to a box nobody asked.
func TestMgmtAuditRecordsTheUnanchoredRefusal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := modePath()
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if currentAnchor() != nil {
		t.Fatal("this box must have no anchor for the test to mean anything")
	}
	if _, errOut, code := driveOp(t, tMember, "uptime", nil); code != 126 ||
		!strings.Contains(errOut, "NOT ANCHORED") {
		t.Fatalf("a networked unanchored box refuses everything: %d %s", code, errOut)
	}
	recs := readMgmtAudit(t)
	if len(recs) != 1 || recs[0]["verdict"] != auditRefused || recs[0]["op"] != "uptime" {
		t.Fatalf("the unanchored refusal must be audited: %v", recs)
	}
	if s, _ := recs[0]["grant_sig"].(string); s != "" {
		t.Fatalf("no anchor means no grant was consulted: %v", recs[0])
	}
}

// A POISON LINE MUST NOT BLIND THE SIGNAL.
//
// The attack this closes: a member pairing sends one job with a 70 KiB op name.
// It is refused correctly — and the refusal is written with that op in it,
// twice, because the refusal string embeds the op as well. If the summary
// reader stopped at an over-long line, every heartbeat from then on would
// report only the lines BEFORE the poison, permanently, with no error and a
// block that still looks like a real answer. The count that would prompt anyone
// to pull the file is exactly the count that is frozen.
//
// Two halves, and both matter: the reader must step over a line that is already
// too long, and mgmtAudit must not write one in the first place.
func TestMgmtAuditPoisonLineDoesNotStopTheCount(t *testing.T) {
	setupBox(t)
	truncateMgmtAudit(t)
	p, err := mgmtAuditPath()
	if err != nil {
		t.Fatal(err)
	}

	write := func(line string) {
		t.Helper()
		fh, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()
		if _, err := fh.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	rec := func(op, verdict string) string {
		b, _ := json.Marshal(map[string]any{
			"ts": time.Now().UTC().Format(time.RFC3339), "self": tMember, "op": op,
			"family": "observe", "verdict": verdict, "why": "", "exit": 0,
		})
		return string(b)
	}

	write(rec("before_1", auditAllowed))
	write(rec("before_2", auditAllowed))
	write(strings.Repeat("x", 70*1024)) // the poison: longer than the read buffer
	write(rec("after_1", auditAllowed))
	write(rec("after_2", auditRefused))

	rep := mgmtAuditReport()
	if rep == nil {
		t.Fatal("the report must survive a poison line")
	}
	if rep["lines"] != 5 {
		t.Fatalf("every line must be counted, including the ones AFTER the poison "+
			"and the poison itself: %v", rep)
	}
	if rep["unreadable"] != 1 {
		t.Fatalf("the poison line must be reported as unreadable: %v", rep)
	}
	// The refusal AFTER the poison is the one that would have been lost.
	if rep["refused_last_hour"] != 1 {
		t.Fatalf("a refusal after the poison must still be counted: %v", rep)
	}
	last, ok := rep["last_refusal"].(map[string]any)
	if !ok || last["op"] != "after_2" {
		t.Fatalf("last_refusal must be the one past the poison: %v", rep)
	}
}

// The other half: an op this long never reaches the file, because mgmtAudit
// bounds the two caller-influenced fields before it marshals them.
func TestMgmtAuditClampsTheOpAndTheReason(t *testing.T) {
	setupBox(t)
	truncateMgmtAudit(t)

	huge := strings.Repeat("A", 70*1024)
	mgmtAudit(tMember, huge, "observe", auditRefused, "refused: op '"+huge+"' not permitted", 126, nil, "")

	recs := readMgmtAudit(t)
	if len(recs) != 1 {
		t.Fatalf("one call, one line: %v", len(recs))
	}
	op, _ := recs[0]["op"].(string)
	why, _ := recs[0]["why"].(string)
	if len(op) > mgmtAuditOpMax+64 {
		t.Fatalf("op must be clamped, got %d bytes", len(op))
	}
	if len(why) > mgmtAuditWhyMax+64 {
		t.Fatalf("why must be clamped, got %d bytes", len(why))
	}
	// Silent truncation in an audit record is its own small lie — a reader has
	// to be able to tell a short value from a clipped one.
	if !strings.Contains(op, "truncated") || !strings.Contains(op, "71680") {
		t.Fatalf("the clamp must mark itself and carry the original length: %q", op)
	}
	if !strings.Contains(why, "truncated") {
		t.Fatalf("the reason must be marked when clamped: %q", why)
	}
	// And the line is short enough that the reader never has to skip it.
	if rep := mgmtAuditReport(); rep == nil || rep["lines"] != 1 || rep["unreadable"] != nil {
		t.Fatalf("a clamped line must be fully readable: %v", rep)
	}

	// A legitimate value is never touched: the longest real refusal on this lane
	// is the unanchored one, and it must survive whole.
	real := unanchoredNetworkedRefusal("op 'pairing_anchor_consent'")
	if real == "" {
		real = "refused: op 'pairing_anchor_consent' is answered only on the anchor host's pairing"
	}
	if got := auditClamp(real, mgmtAuditWhyMax); got != real {
		t.Fatalf("a real refusal string must never be clamped (%d bytes): %q", len(real), got)
	}
	for op := range handlerOps {
		if got := auditClamp(op, mgmtAuditOpMax); got != op {
			t.Fatalf("a real op name must never be clamped: %q", op)
		}
	}
}

// The frame itself is bounded, and the bound clears the largest job this lane
// legitimately carries.
func TestMgmtFrameLimitClearsTheLargestRealJob(t *testing.T) {
	// ctx_extract's inline path is the biggest thing that rides this frame.
	b64 := (ctxExtractMaxBytes + 2) / 3 * 4
	if mgmtFrameMaxBytes <= b64 {
		t.Fatalf("the frame limit %d must clear a base64'd ctxExtractMaxBytes document "+
			"(%d bytes) or the inline extract path breaks", mgmtFrameMaxBytes, b64)
	}
	// And it must actually be a bound, not a number so large it is decorative.
	if mgmtFrameMaxBytes > 4*b64 {
		t.Fatalf("the frame limit %d is far above the largest real job (%d) — it is "+
			"not bounding anything", mgmtFrameMaxBytes, b64)
	}
}

// The file rolls rather than growing without end, and the roll keeps both
// halves valid JSONL rather than chopping a record in two.
func TestMgmtAuditRolls(t *testing.T) {
	setupBox(t)
	truncateMgmtAudit(t)
	p, err := mgmtAuditPath()
	if err != nil {
		t.Fatal(err)
	}
	// One byte under the roll point, written as whole records.
	fh, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := json.Marshal(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339),
		"self": tMember, "op": "filler", "verdict": auditAllowed, "exit": 0})
	for n := 0; n < mgmtAuditMaxBytes; n += len(line) + 1 {
		if _, err := fh.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	fh.Close()

	mgmtAudit(tMember, "uptime", "observe", auditAllowed, "", 0, nil, "")

	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatalf("the file must roll aside once it passes the cap: %v", err)
	}
	st, err := os.Stat(p)
	if err == nil && st.Size() > 0 {
		t.Fatalf("the live file must start again empty after a roll, got %d bytes", st.Size())
	}
	// Both halves are still whole records.
	prev, err := os.ReadFile(p + ".1")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimRight(string(prev), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("the rolled file must stay valid JSONL: %v", err)
		}
	}
}

// THE RECORDED FAMILY IS THE ONE THE OP WAS JUDGED ON.
//
// stepup_* is gated on the family of the thing being approved (stepupOpFamily),
// not on the "stepup" floor its name resolves to. The account is seeded from
// the name, so without setMgmtAccountFamily the line would say family "stepup"
// while the refusal string printed beside it named "dcn" — a record that
// contradicts its own reason is worse than no record, because it is the one an
// investigator would believe.
func TestMgmtAuditRecordsTheResolvedFamily(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	truncateMgmtAudit(t)

	details, _ := json.Marshal(map[string]any{"kind": "session_root"})
	args := []string{"p", base64.StdEncoding.EncodeToString(details)}
	if _, errOut, code := driveOp(t, tMember, "stepup_request", args); code != 126 ||
		!strings.Contains(errOut, "caps") {
		t.Fatalf("an observe-only pairing must be refused a session_root step-up: %d %s", code, errOut)
	}
	recs := readMgmtAudit(t)
	if len(recs) != 1 {
		t.Fatalf("one op, one line: %v", recs)
	}
	if recs[0]["family"] != "session" {
		t.Fatalf("the line must record the family the op was JUDGED on (session), "+
			"not opFamily's %q floor: %v", capsFamilyStepup, recs[0])
	}
	why, _ := recs[0]["why"].(string)
	if !strings.Contains(why, "session") {
		t.Fatalf("and it must agree with the reason beside it: %q", why)
	}
}
