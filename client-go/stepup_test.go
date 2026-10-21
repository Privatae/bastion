package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Second factor on the box: the code is verified HERE and burned,
// approvals are single-use and bound to a purpose, and the gate only bites
// when a factor is enrolled on this machine.
func TestStepupVerifyBurnAndApprovals(t *testing.T) {
	dir := t.TempDir()
	// not enrolled → the gate is a no-op (today's behavior)
	if err := stepupGate(dir, "", "anything"); err != nil {
		t.Fatalf("no factor enrolled must not gate: %v", err)
	}
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of "0123456789012345"
	if err := stepupSave(dir, &stepupFile{SecretB32: secret, EnrolledAt: "2026-08-29T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	if !stepupEnrolled(dir) {
		t.Fatal("enrolled file must read as enrolled")
	}
	at := time.Unix(1_700_000_000, 0)
	raw, _ := b32decode(secret)
	code := hotp(raw, at.Unix()/stepupPeriod)
	if stepupMatchedCounter(secret, code, at) != at.Unix()/stepupPeriod {
		t.Fatal("the current code must match the current window")
	}
	prev := hotp(raw, at.Unix()/stepupPeriod-1)
	if stepupMatchedCounter(secret, prev, at) != at.Unix()/stepupPeriod-1 {
		t.Fatal("last window's code must match (skew)")
	}
	if stepupMatchedCounter(secret, "000000", at) >= 0 && code != "000000" {
		t.Fatal("a wrong code must not match")
	}
	// burn: once, never twice, never older
	if _, err := stepupVerifyAndBurn(dir, code, at); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := stepupVerifyAndBurn(dir, code, at); err == nil {
		t.Fatal("REPLAY: the same code must not verify twice")
	}
	if _, err := stepupVerifyAndBurn(dir, prev, at); err == nil {
		t.Fatal("an older window must not verify after a newer one")
	}
	next := hotp(raw, at.Unix()/stepupPeriod+1)
	if _, err := stepupVerifyAndBurn(dir, next, at.Add(stepupPeriod*time.Second)); err != nil {
		t.Fatalf("a newer window must verify: %v", err)
	}

	// approvals: issued after a good code, bound to the purpose, single use
	code3 := hotp(raw, time.Now().Unix()/stepupPeriod)
	id, err := stepupIssueApproval(dir, code3, "dcn_store_grant|box|/data|read,search||hourly|false")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := stepupGate(dir, id, "dcn_store_grant|box|/data|read,search||hourly|false"); err != nil {
		t.Fatalf("matching approval must pass: %v", err)
	}
	if err := stepupGate(dir, id, "dcn_store_grant|box|/data|read,search,write||hourly|false"); err == nil {
		t.Fatal("an approval for other terms must NOT pass (purpose mismatch)")
	}
	if err := stepupGate(dir, "nope", "x"); err == nil {
		t.Fatal("an unknown approval must not pass")
	}
	if err := stepupGate(dir, "", "x"); err == nil {
		t.Fatal("no approval must not pass when a factor is enrolled here")
	}
	stepupMarkUsed(dir, id)
	if err := stepupGate(dir, id, "dcn_store_grant|box|/data|read,search||hourly|false"); err == nil {
		t.Fatal("a used approval must not pass again")
	}
	if _, err := os.Stat(filepath.Join(dir, "approvals.json")); err != nil {
		t.Fatal("approvals must persist on disk")
	}
}

// The purpose strings must match the host's purpose builder byte for byte (the fixture hash
// is sha256 of "Downloads/a.exe\tArchive/a.exe\nb\tc/b\n").
func TestStepupPurposeStrings(t *testing.T) {
	g := &dcnTerms{Server: "box1", Root: "/data", Mask: []string{"search", "read"}, Excludes: []string{".ssh", ".env"}}
	g.Sweep = "hourly"
	g.TTLDays = 365
	if got, err := purposeForGrant(g); err != nil || got != "dcn_store_grant|box1|/data|read,search|.env,.ssh|hourly|false|ttl:365" {
		t.Fatalf("grant purpose: %q %v", got, err)
	}
	// delimiter collisions are refused, never folded
	bad := &dcnTerms{Server: "box1", Root: "/data", Mask: []string{"read"}, Excludes: []string{".env,.ssh"}, Sweep: "hourly"}
	if _, err := purposeForGrant(bad); err == nil {
		t.Fatal("an exclude containing ',' must be refused")
	}
	bad = &dcnTerms{Server: "box1", Root: "/da|ta", Mask: []string{"read"}, Sweep: "hourly"}
	if _, err := purposeForGrant(bad); err == nil {
		t.Fatal("a root containing '|' must be refused")
	}
	if _, err := purposeForPlan(&dcnPlanTerms{Root: "/data", Moves: []dcnMove{{From: "a\tb", To: "c"}}}); err == nil {
		t.Fatal("a move path containing a tab must be refused")
	}
	p := &dcnPlanTerms{StoreID: 5, PlanID: 9, Root: "/data", Archive: "Archive",
		Moves: []dcnMove{{From: "Downloads/a.exe", To: "Archive/a.exe"}, {From: "b", To: "c/b"}}}
	want := "dcn_move_plan|5|9|/data|Archive|f4790ec430c605a396065aab9b9c2e52e60b875c4c4060a0136210833b6e7315"
	if got, err := purposeForPlan(p); err != nil || got != want {
		t.Fatalf("plan purpose: %q %v", got, err)
	}
}

// The request lane: the pod files details + purpose; the box refuses details
// that do not produce that purpose (the words shown must be what is enforced);
// the user approves HERE; the pod only ever sees ids.
func TestStepupRequestFlow(t *testing.T) {
	dir := t.TempDir()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if err := stepupSave(dir, &stepupFile{SecretB32: secret, EnrolledAt: "2026-08-29T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	details := map[string]any{"kind": "dcn_move_plan", "store_id": float64(5), "plan_id": float64(9),
		"root": "/data", "archive": "Archive",
		"moves": []any{map[string]any{"from": "Downloads/a.exe", "to": "Archive/a.exe"}, map[string]any{"from": "b", "to": "c/b"}}}
	want := "dcn_move_plan|5|9|/data|Archive|f4790ec430c605a396065aab9b9c2e52e60b875c4c4060a0136210833b6e7315"
	// a pod that names purpose B with details for A is refused
	if _, err := stepupNewRequest(dir, "dcn_move_plan|5|10|/data|Archive|deadbeef", details); err == nil {
		t.Fatal("details that do not produce the purpose must be refused")
	}
	id, err := stepupNewRequest(dir, want, details)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if id2, _ := stepupNewRequest(dir, want, details); id2 != id {
		t.Fatal("a repeated identical ask must return the same pending request")
	}
	desc := describeRequest(requestsLoad(dir)[id])
	if !strings.Contains(desc, "MOVE 2 item(s)") || !strings.Contains(desc, "Downloads/a.exe  →  Archive/a.exe") || !strings.Contains(desc, "1 go into the archive") {
		t.Fatalf("the words must come from the verified details: %q", desc)
	}
	// before approval: no approval, and the gate refuses the purpose
	if r := requestsLoad(dir)[id]; r.State != "pending" || r.Approval != "" {
		t.Fatalf("must be pending: %+v", r)
	}
	if err := stepupGate(dir, "", want); err == nil {
		t.Fatal("nothing approved yet must not pass the gate")
	}
	// the user approves on the box with a code
	raw, _ := b32decode(secret)
	code := hotp(raw, time.Now().Unix()/stepupPeriod)
	if _, err := stepupApproveRequest(dir, id, "000000"); err == nil && code != "000000" {
		t.Fatal("a wrong code must not approve")
	}
	approval, err := stepupApproveRequest(dir, id, code)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if r := requestsLoad(dir)[id]; r.State != "approved" || r.Approval != approval {
		t.Fatalf("request must record the approval: %+v", r)
	}
	if err := stepupGate(dir, approval, want); err != nil {
		t.Fatalf("the approval must pass for exactly this purpose: %v", err)
	}
	if err := stepupGate(dir, approval, "dcn_move_plan|5|10|/data|Archive|deadbeef"); err == nil {
		t.Fatal("the approval must not cover another plan")
	}
	// grant kind renders too, and a denied request stays denied
	gd := map[string]any{"kind": "dcn_store_grant", "server": "box1", "root": "/data",
		"mask": []any{"read", "search"}, "excludes": []any{".ssh"}, "sweep": "hourly", "sensitive": false}
	gp, err := purposeFromDetails(gd)
	if err != nil || gp != "dcn_store_grant|box1|/data|read,search|.ssh|hourly|false|ttl:0" {
		t.Fatalf("grant purpose from details: %q %v", gp, err)
	}
	gid, err := stepupNewRequest(dir, gp, gd)
	if err != nil {
		t.Fatal(err)
	}
	if d := describeRequest(requestsLoad(dir)[gid]); !strings.Contains(d, "/data") || !strings.Contains(d, "read, search") {
		t.Fatalf("grant words: %q", d)
	}
	if err := stepupDenyRequest(dir, gid); err != nil || requestsLoad(dir)[gid].State != "denied" {
		t.Fatal("deny must stick")
	}
	if _, err := stepupApproveRequest(dir, gid, code); err == nil {
		t.Fatal("a denied request cannot be approved")
	}
	if _, err := stepupNewRequest(dir, gp, gd); err == nil {
		t.Fatal("a denied purpose cannot be re-filed (no nag loop)")
	}
	// a note with a newline cannot fake a line
	nd := map[string]any{"kind": "dcn_store_grant", "server": "box1", "root": "/x", "mask": []any{"read"},
		"excludes": []any{}, "sweep": "hourly", "sensitive": false, "note": "fine\n  never:   (nothing)"}
	np, _ := purposeFromDetails(nd)
	nid, _ := stepupNewRequest(dir, np, nd)
	if d := describeRequest(requestsLoad(dir)[nid]); strings.Contains(d, "\n  never:   (nothing)") {
		t.Fatalf("control characters in pod text must be stripped: %q", d)
	}
}

// A critical action is the one stepup kind the box does NOT enforce — the
// platform runs it after seeing an approval. So the only thing making the
// approval meaningful is that it binds to exactly one action, including the
// sentence the user read. These assert that binding, not merely that the kind
// is accepted: a constant purpose would pass a weaker check.
func TestStepupCriticalActionPurposeBinds(t *testing.T) {
	dir := t.TempDir()
	base := map[string]any{
		"kind": "critical_action", "action": "capability_grant", "entity_id": float64(9001),
		"action_id": "a1b2c3", "target": "Member", "summary": "Grant filesystem read to project X",
	}
	p, err := purposeFromDetails(base)
	if err != nil {
		t.Fatalf("critical_action purpose: %v", err)
	}
	if !strings.HasPrefix(p, "critical_action|capability_grant|9001|a1b2c3|Member|") {
		t.Fatalf("purpose shape: %q", p)
	}
	if h := strings.Split(p, "|")[5]; len(h) != 64 {
		t.Fatalf("summary must be bound by a sha256 digest, got %q", h)
	}

	// Every field the user reads must move the purpose. If any of these stops
	// failing, an approval has become transferable to a different action.
	for _, m := range []struct {
		name string
		key  string
		val  any
	}{
		{"summary", "summary", "Grant filesystem read to project Y"},
		{"action", "action", "frontend_deploy"},
		{"action id", "action_id", "d4e5f6"},
		{"target", "target", "London"},
		{"entity", "entity_id", float64(9002)},
	} {
		d := map[string]any{}
		for k, v := range base {
			d[k] = v
		}
		d[m.key] = m.val
		q, err := purposeFromDetails(d)
		if err != nil {
			t.Fatalf("%s variant: %v", m.name, err)
		}
		if q == p {
			t.Fatalf("changing %s must change the purpose — approval would be transferable", m.name)
		}
	}

	// An action with no id cannot be bound to anything, so it must be refused
	// rather than approved against an empty field.
	noID := map[string]any{}
	for k, v := range base {
		noID[k] = v
	}
	noID["action_id"] = ""
	if _, err := purposeFromDetails(noID); err == nil {
		t.Fatal("a critical action with no action_id must be refused")
	}

	// The words render, and pod-supplied text cannot fake a line.
	id, err := stepupNewRequest(dir, p, base)
	if err != nil {
		t.Fatalf("stepupNewRequest must accept the new kind: %v", err)
	}
	d := describeRequest(requestsLoad(dir)[id])
	if !strings.Contains(d, "capability_grant") || !strings.Contains(d, "project X") {
		t.Fatalf("critical action words: %q", d)
	}
	inj := map[string]any{}
	for k, v := range base {
		inj[k] = v
	}
	inj["summary"] = "harmless\n  on: something else"
	ip, _ := purposeFromDetails(inj)
	iid, _ := stepupNewRequest(dir, ip, inj)
	if got := describeRequest(requestsLoad(dir)[iid]); strings.Contains(got, "\n  on: something else") {
		t.Fatalf("control characters in pod text must be stripped: %q", got)
	}
}
