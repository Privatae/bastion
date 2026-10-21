package main

// The tray's lane to a system service (approvalpipe.go), driven through
// pipeServe: who may use it, what it lists, and that a code approves exactly
// the one request that was shown, once, and not by guessing.
//
// Every value here is invented.

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	pipeTestHost   = "tray.host.example"
	pipeTestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of "0123456789012345"
	pipeTestUser   = "S-1-5-21-1111111111-2222222222-3333333333-1001"
)

// thePerson is a client that may use the lane: the person signed in to an
// active session, connecting from it.
var thePerson = pipeClient{PID: 4242, UserSID: pipeTestUser, UserName: `EXAMPLE\pat`,
	SessionID: 1, SessionUserSID: pipeTestUser, SessionActive: true}

// pipeBox is one paired Host with a factor enrolled and two pending requests,
// A and B, in an isolated config dir.
func pipeBox(t *testing.T) (dir, idA, purposeA, idB, purposeB string) {
	t.Helper()
	uiTestConfigDir(t)
	writePairing(t, pipeTestHost)
	cfgs, err := loadPairings()
	if err != nil || len(cfgs) != 1 {
		t.Fatalf("pairing: %v %d", err, len(cfgs))
	}
	dir = cfgs[0].dcnDir()
	if err := stepupSave(dir, &stepupFile{SecretB32: pipeTestSecret, EnrolledAt: "2026-10-19T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	// The person owns this machine's approvals, as the installer records it.
	writeApprovalsOwner(t, pipeTestUser)
	ask := func(root string) (string, string) {
		d := map[string]any{"kind": "dcn_store_grant", "server": "desk-7", "root": root,
			"mask": []any{"read", "search"}, "excludes": []any{".ssh"}, "sweep": "hourly", "sensitive": false}
		p, err := purposeFromDetails(d)
		if err != nil {
			t.Fatal(err)
		}
		id, err := stepupNewRequest(dir, p, d)
		if err != nil {
			t.Fatal(err)
		}
		return id, p
	}
	idA, purposeA = ask("/srv/example-a")
	idB, purposeB = ask("/srv/example-b")
	return
}

// writeApprovalsOwner records sid as the owner of this machine's approvals,
// the file `approvals-owner` writes.
func writeApprovalsOwner(t *testing.T, sid string) {
	t.Helper()
	p, err := approvalsOwnerPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(approvalsOwnerRecord{SID: sid, SetAt: "2026-10-19T00:00:00Z"})
	if err := atomicWrite(p, raw); err != nil {
		t.Fatal(err)
	}
}

// anotherPerson is someone else with an account on the machine, signed in to
// an active session of their own: everything pipeClientRefusal asks, and not
// the owner.
var anotherPerson = pipeClient{PID: 5151, UserSID: "S-1-5-21-1111111111-2222222222-3333333333-1002", UserName: `EXAMPLE\sam`,
	SessionID: 2, SessionUserSID: "S-1-5-21-1111111111-2222222222-3333333333-1002", SessionActive: true}

func TestThePipeServesOnlyTheAccountThatOwnsTheApprovals(t *testing.T) {
	dir, idA, purposeA, _, _ := pipeBox(t)
	now := time.Now()
	if why := pipeClientRefusal(anotherPerson); why != "" {
		t.Fatalf("the fixture must pass the session rules: %s", why)
	}
	refusedOwner := func(resp pipeResponse, what string) {
		t.Helper()
		if resp.OK || !strings.Contains(resp.Error, "belong to another account") {
			t.Fatalf("%s by another account must be refused: %+v", what, resp)
		}
	}
	refusedOwner(pipeServe(pipeRequest{Op: "list"}, anotherPerson, now), "list")
	code := pipeCodeNow()
	refusedOwner(pipeServe(pipeRequest{Op: "approve", Host: pipeTestHost, ID: idA, Purpose: purposeDigest(purposeA), Code: code}, anotherPerson, now), "approve")
	refusedOwner(pipeServe(pipeRequest{Op: "deny", Host: pipeTestHost, ID: idA, Purpose: purposeDigest(purposeA)}, anotherPerson, now), "deny")
	if r := stateOf(t, dir, idA); r.State != "pending" {
		t.Fatalf("a refused account changed the request: %s", r.State)
	}
	// Refused before any code was looked at: the owner's code still works.
	if resp := pipeServe(pipeRequest{Op: "approve", Host: pipeTestHost, ID: idA, Purpose: purposeDigest(purposeA), Code: code}, thePerson, now); !resp.OK {
		t.Fatalf("the owner's approve: %+v", resp)
	}

	// No owner recorded, or a record that cannot be read: nobody is served.
	p, _ := approvalsOwnerPath()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if resp := pipeServe(pipeRequest{Op: "list"}, thePerson, now); resp.OK || !strings.Contains(resp.Error, "no account is recorded") {
		t.Fatalf("with no owner recorded the lane serves nobody: %+v", resp)
	}
	if err := os.WriteFile(p, []byte(`{"sid": 7`), 0o600); err != nil {
		t.Fatal(err)
	}
	if resp := pipeServe(pipeRequest{Op: "list"}, thePerson, now); resp.OK {
		t.Fatalf("an unreadable owner record must serve nobody: %+v", resp)
	}
}

func pipeCodeNow() string {
	raw, _ := b32decode(pipeTestSecret)
	return hotp(raw, time.Now().Unix()/stepupPeriod)
}

func stateOf(t *testing.T, dir, id string) stepupRequest {
	t.Helper()
	r, ok := requestsLoad(dir)[id]
	if !ok {
		t.Fatalf("request %s is gone", id)
	}
	return r
}

// ── who may connect ─────────────────────────────────────────────────────────

func TestThePipeServesOnlyThePersonSignedInToTheirOwnSession(t *testing.T) {
	if why := pipeClientRefusal(thePerson); why != "" {
		t.Fatalf("the person at the screen was refused: %s", why)
	}
	other := "S-1-5-21-1111111111-2222222222-3333333333-1002"
	cases := map[string]pipeClient{
		"unknown account":                 {PID: 1, SessionID: 1, SessionUserSID: pipeTestUser, SessionActive: true},
		"session 0":                       {PID: 1, UserSID: pipeTestUser, SessionID: 0, SessionUserSID: pipeTestUser, SessionActive: true},
		"SYSTEM in a session":             {PID: 1, UserSID: "S-1-5-18", SessionID: 1, SessionUserSID: pipeTestUser, SessionActive: true},
		"a service account":               {PID: 1, UserSID: "S-1-5-80-123-456", SessionID: 1, SessionUserSID: pipeTestUser, SessionActive: true},
		"another account, run as":         {PID: 1, UserSID: other, SessionID: 1, SessionUserSID: pipeTestUser, SessionActive: true},
		"nobody signed in to its session": {PID: 1, UserSID: pipeTestUser, SessionID: 2, SessionActive: true},
		"a disconnected session":          {PID: 1, UserSID: pipeTestUser, SessionID: 1, SessionUserSID: pipeTestUser, SessionActive: false},
	}
	for name, c := range cases {
		if pipeClientRefusal(c) == "" {
			t.Errorf("%s: accepted, and must be refused", name)
		}
	}

	// And a refused client gets nothing at all: no list, no approval, even
	// with the right code for a real request.
	dir, idA, purposeA, _, _ := pipeBox(t)
	intruder := cases["another account, run as"]
	if resp := pipeServe(pipeRequest{Op: "list"}, intruder, time.Now()); resp.OK || len(resp.Approvals) != 0 {
		t.Fatalf("a refused client was shown the list: %+v", resp)
	}
	resp := pipeServe(pipeRequest{Op: "approve", Host: pipeTestHost, ID: idA, Purpose: purposeDigest(purposeA), Code: pipeCodeNow()},
		intruder, time.Now())
	if resp.OK || stateOf(t, dir, idA).State != "pending" {
		t.Fatalf("a refused client approved a request: %+v", resp)
	}
	if f, _ := stepupLoad(dir); f.LastCounter != -1 {
		t.Fatal("a refused client's code was checked and burned")
	}
}

// ── what it lists ───────────────────────────────────────────────────────────

func TestThePipeListsWhatIsPendingInTheConsolesWordsAndNoSecret(t *testing.T) {
	dir, idA, purposeA, idB, _ := pipeBox(t)
	resp := pipeServe(pipeRequest{Op: "list"}, thePerson, time.Now())
	if !resp.OK || len(resp.Approvals) != 2 {
		t.Fatalf("list: %+v", resp)
	}
	byID := map[string]pipeApproval{}
	for _, a := range resp.Approvals {
		byID[a.ID] = a
	}
	a, ok := byID[idA]
	if !ok || byID[idB].ID == "" {
		t.Fatalf("both pending requests must be listed: %+v", resp.Approvals)
	}
	// The same words `privatae-bastion approvals` prints.
	want := describeRequest(requestsLoad(dir)[idA])
	if strings.Join(a.Lines, "\n") != strings.TrimSpace(want) {
		t.Fatalf("the tray's words are not the console's:\n%q\n%q", a.Lines, want)
	}
	if a.Purpose != purposeDigest(purposeA) || a.Host != pipeTestHost {
		t.Fatalf("the card must name its Host and carry its purpose's digest: %+v", a)
	}
	raw, _ := json.Marshal(resp)
	if strings.Contains(string(raw), pipeTestSecret) {
		t.Fatal("the TOTP secret crossed the pipe")
	}
	// An approval id is what the Host spends; it never crosses either.
	if _, err := stepupApproveRequest(dir, idB, pipeCodeNow()); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(pipeServe(pipeRequest{Op: "list"}, thePerson, time.Now()))
	if appr := requestsLoad(dir)[idB].Approval; appr == "" || strings.Contains(string(raw), appr) {
		t.Fatalf("an approval id crossed the pipe, or none was issued (%q)", appr)
	}
}

// ── a code approves exactly what was shown ──────────────────────────────────

func TestThePipeApprovesOneRequestWithACodeBoundToItsPurpose(t *testing.T) {
	dir, idA, purposeA, idB, purposeB := pipeBox(t)
	now := time.Now()
	approve := func(id, purposeSHA, code string) pipeResponse {
		return pipeServe(pipeRequest{Op: "approve", Host: pipeTestHost, ID: id, Purpose: purposeSHA, Code: code}, thePerson, now)
	}

	if r := approve(idA, purposeDigest(purposeA), ""); r.OK || !strings.Contains(r.Error, "code") {
		t.Fatalf("no code must not approve: %+v", r)
	}
	if r := approve(idA, purposeDigest(purposeA), "000000"); r.OK && pipeCodeNow() != "000000" {
		t.Fatalf("a wrong code approved: %+v", r)
	}
	// A valid code, posted for A with the purpose B's card showed: refused,
	// and the code is not spent by it.
	r := approve(idA, purposeDigest(purposeB), pipeCodeNow())
	if r.OK || !strings.Contains(r.Error, "not the one shown") {
		t.Fatalf("a code bound to another request's purpose must be refused: %+v", r)
	}
	if r := approve(idA, "", pipeCodeNow()); r.OK {
		t.Fatalf("a code with no purpose must be refused: %+v", r)
	}
	if stateOf(t, dir, idA).State != "pending" {
		t.Fatal("A was approved by a mismatched submission")
	}
	if f, _ := stepupLoad(dir); f.LastCounter != -1 {
		t.Fatal("a refused submission spent the code")
	}

	// The right card: approved, once.
	if r := approve(idA, purposeDigest(purposeA), pipeCodeNow()); !r.OK {
		t.Fatalf("the right code for the request shown must approve it: %+v", r)
	}
	a := stateOf(t, dir, idA)
	if a.State != "approved" || a.Approval == "" {
		t.Fatalf("A must be approved: %+v", a)
	}
	if stateOf(t, dir, idB).State != "pending" {
		t.Fatal("approving A touched B")
	}
	// The approval binds A's purpose and nothing else.
	if err := stepupCheckApproval(dir, a.Approval, purposeB); err == nil {
		t.Fatal("A's approval passed for B's purpose")
	}
	if err := stepupConsumeApproval(dir, a.Approval, purposeA); err != nil {
		t.Fatalf("A's approval must pass for A's purpose: %v", err)
	}
	// And the code is spent: the same code cannot approve B.
	if r := approve(idB, purposeDigest(purposeB), pipeCodeNow()); r.OK {
		t.Fatal("one code approved two requests")
	}
}

func TestThePipeDeniesOnlyTheRequestShown(t *testing.T) {
	dir, idA, purposeA, _, purposeB := pipeBox(t)
	deny := func(purposeSHA string) pipeResponse {
		return pipeServe(pipeRequest{Op: "deny", Host: pipeTestHost, ID: idA, Purpose: purposeSHA}, thePerson, time.Now())
	}
	if r := deny(purposeDigest(purposeB)); r.OK || stateOf(t, dir, idA).State != "pending" {
		t.Fatalf("a deny for another card's purpose must be refused: %+v", r)
	}
	if r := deny(purposeDigest(purposeA)); !r.OK || stateOf(t, dir, idA).State != "denied" {
		t.Fatalf("deny: %+v", r)
	}
}

// ── no guessing ─────────────────────────────────────────────────────────────

func TestThePipeThrottlesWrongCodesAndLocksUntilAnotherLaneApproves(t *testing.T) {
	dir, idA, purposeA, idB, purposeB := pipeBox(t)
	wrong := "000000"
	if pipeCodeNow() == wrong {
		wrong = "000001"
	}
	t0 := time.Now()
	try := func(code string, at time.Time) pipeResponse {
		return pipeServe(pipeRequest{Op: "approve", Host: pipeTestHost, ID: idA, Purpose: purposeDigest(purposeA), Code: code}, thePerson, at)
	}
	for i := 0; i < pipeFreeFailures; i++ {
		if r := try(wrong, t0); r.OK || strings.Contains(r.Error, "try again") {
			t.Fatalf("attempt %d: the first %d wrong codes are not throttled: %+v", i+1, pipeFreeFailures, r)
		}
	}
	// Now even the RIGHT code is not looked at until pipeSlowEvery has passed.
	if r := try(pipeCodeNow(), t0.Add(time.Second)); r.OK || !strings.Contains(r.Error, "try again") {
		t.Fatalf("after %d wrong codes the next attempt must wait: %+v", pipeFreeFailures, r)
	}
	if stateOf(t, dir, idA).State != "pending" {
		t.Fatal("a throttled attempt approved")
	}
	if r := try(wrong, t0.Add(pipeSlowEvery+time.Second)); r.OK || strings.Contains(r.Error, "try again") {
		t.Fatalf("after the wait one attempt is taken: %+v", r)
	}

	// At pipeLockAfter the lane takes no code at all, whatever the wait...
	raw, _ := json.Marshal(pipeThrottleFile{Failures: pipeLockAfter, Last: t0.UTC().Format(time.RFC3339)})
	if err := os.WriteFile(pipeThrottlePath(dir), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := try(pipeCodeNow(), t0.Add(24*time.Hour)); r.OK || !strings.Contains(r.Error, "Administrator terminal") {
		t.Fatalf("a locked lane must refuse and say where to approve instead: %+v", r)
	}
	// ...until a code is accepted on another lane (here, what `approve` at an
	// Administrator terminal calls), which re-opens it.
	if _, err := stepupApproveRequest(dir, idB, pipeCodeNow()); err != nil {
		t.Fatal(err)
	}
	if f := pipeThrottleLoad(dir); f.Failures != 0 {
		t.Fatalf("an accepted code on another lane must reset the count, got %d", f.Failures)
	}
	_ = purposeB
}

// ── the pipe's own permissions ──────────────────────────────────────────────

// TestTheApprovalPipeTakesLocalInteractiveClientsOnly reads the pipe's ACL and
// its creation flags. Interactive users may read and write, and may NOT create
// an instance of the pipe (FILE_APPEND_DATA, 0x4, is FILE_CREATE_PIPE_INSTANCE
// on a pipe): that right would let a client stand up its own end of the name.
// Remote clients are refused by the pipe itself. A Windows-only file, so this
// reads it rather than runs it.
func TestTheApprovalPipeTakesLocalInteractiveClientsOnly(t *testing.T) {
	m := regexp.MustCompile(`\(A;;(0x[0-9a-fA-F]+);;;IU\)`).FindStringSubmatch(approvalPipeSDDL)
	if m == nil {
		t.Fatalf("no interactive-users entry in %s", approvalPipeSDDL)
	}
	mask, err := strconv.ParseUint(m[1], 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	if mask&0x4 != 0 {
		t.Fatalf("interactive users may create pipe instances (mask %#x)", mask)
	}
	if mask&0x3 != 0x3 || mask&0x100000 == 0 {
		t.Fatalf("interactive users cannot read, write and wait on the pipe (mask %#x)", mask)
	}
	if strings.Count(approvalPipeSDDL, "(A;") != 3 || !strings.HasPrefix(approvalPipeSDDL, "D:P") {
		t.Fatalf("the pipe's DACL must be protected and hold exactly SYSTEM, Administrators and interactive users: %s", approvalPipeSDDL)
	}
	src, err := os.ReadFile("approvalpipe_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PIPE_REJECT_REMOTE_CLIENTS", "FILE_FLAG_FIRST_PIPE_INSTANCE", "SECURITY_IDENTIFICATION",
		"GetNamedPipeClientProcessId", "pipeServerIsService(c.h)"} {
		if !strings.Contains(string(src), want) {
			t.Errorf("approvalpipe_windows.go no longer uses %s", want)
		}
	}
}
