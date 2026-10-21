package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The move-plan lane: signed plan, sandboxed moves, dry-run then
// apply with rollback and verify, archive-only — no delete, no overwrite.
func TestDcnPlanCheckApplyVerify(t *testing.T) {
	root := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk("Downloads/setup.exe", "xxxxxxxx")
	mk("Downloads/photo.jpg", "img")
	mk("Documents/notes.txt", "n")
	mk("keep/.env", "secret")
	if err := os.MkdirAll(filepath.Join(root, "Existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	size8 := int64(8)
	excludes := []string{".env*"}

	// dry run finds every kind of problem and touches nothing
	bad := []dcnMove{
		{From: "Downloads/setup.exe", To: "Existing"},            // target exists
		{From: "../outside", To: "Archive/x"},                    // escape
		{From: "keep/.env", To: "Archive/env"},                   // excluded
		{From: "nope.txt", To: "Archive/nope.txt"},               // missing source
		{From: "Documents", To: "Documents/inner"},               // into itself
		{From: "Downloads/photo.jpg", To: "Downloads/photo.jpg"}, // same
	}
	pr := dcnCheckPlan(root, excludes, bad)
	if len(pr) != len(bad) {
		t.Fatalf("every bad move must be a problem: %+v", pr)
	}
	if _, err := os.Stat(filepath.Join(root, "Downloads", "setup.exe")); err != nil {
		t.Fatal("dry run must not touch files")
	}

	// a good plan: reorganize + archive
	good := &dcnPlanTerms{Kind: "dcn_move_plan", StoreID: 1, PlanID: 77, Root: root, Archive: "Archive",
		Moves: []dcnMove{
			{From: "Downloads/setup.exe", To: "Archive/installers/setup.exe", SizeBytes: &size8},
			{From: "Downloads/photo.jpg", To: "Pictures/photo.jpg"},
			{From: "Documents/notes.txt", To: "Documents/Notes/notes.txt"},
		}}
	if pr := dcnCheckPlan(root, excludes, good.Moves); len(pr) != 0 {
		t.Fatalf("good plan must pass the check: %+v", pr)
	}
	rep := dcnApplyPlan(root, excludes, good)
	if rep["state"] != "ok" || rep["applied"] != 3 || rep["verified"] != 3 {
		t.Fatalf("apply+verify: %+v", rep)
	}
	for _, p := range []string{"Archive/installers/setup.exe", "Pictures/photo.jpg", "Documents/Notes/notes.txt"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
			t.Fatalf("%s must exist after apply", p)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "Downloads", "setup.exe")); err == nil {
		t.Fatal("source must be gone after a move")
	}
	if _, err := os.Stat(filepath.Join(root, "keep", ".env")); err != nil {
		t.Fatal("untouched files stay untouched")
	}

	// a plan that fails mid-way rolls back what it did
	mk("A/one.txt", "1")
	mk("A/two.txt", "2")
	if err := os.MkdirAll(filepath.Join(root, "B", "two.txt"), 0o755); err != nil { // a DIR where a file wants to go
		t.Fatal(err)
	}
	// pre-check catches the collision (target exists) → refused, nothing moved
	rb := &dcnPlanTerms{Kind: "dcn_move_plan", StoreID: 1, PlanID: 78, Root: root,
		Moves: []dcnMove{{From: "A/one.txt", To: "B/one.txt"}, {From: "A/two.txt", To: "B/two.txt"}}}
	rep = dcnApplyPlan(root, excludes, rb)
	if rep["state"] != "refused" {
		t.Fatalf("a colliding plan must be refused whole: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(root, "A", "one.txt")); err != nil {
		t.Fatal("a refused plan must change nothing")
	}

	// signature wall: a plan must be signed by the pinned key and parse as a plan
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	terms := map[string]any{"kind": "dcn_move_plan", "store_id": 1, "plan_id": 79, "server": "box", "root": root,
		"archive": "Archive", "moves": []map[string]any{{"from": "a", "to": "b"}},
		"expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	rec := signedRec(t, priv, terms)
	if p, err := dcnVerifyPlan(pubB64, rec.TermsCanonical, rec.Signature); err != nil || p.PlanID != 79 {
		t.Fatalf("a signed plan must verify: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := dcnVerifyPlan(base64.StdEncoding.EncodeToString(other), rec.TermsCanonical, rec.Signature); err == nil {
		t.Fatal("a plan signed by another key must not verify")
	}
	terms["kind"] = "dcn_store_grant"
	rec2 := signedRec(t, priv, terms)
	if _, err := dcnVerifyPlan(pubB64, rec2.TermsCanonical, rec2.Signature); err == nil {
		t.Fatal("a store grant must not pass as a plan")
	}

	// the vocabulary carries the op, and there is still no delete
	ops := mgmtOpVocabulary()
	hasPlan := false
	for _, o := range ops {
		if o == "dcn_plan_apply" {
			hasPlan = true
		}
		if o == "dcn_delete" || o == "dcn_remove" || o == "stepup_verify" {
			t.Fatal("no delete op may exist")
		}
	}
	if !hasPlan {
		t.Fatal("dcn_plan_apply must be in the reported vocabulary")
	}
	_ = json.Marshal
}

// Walls the first cut missed: paths that clean to the same target are one target;
// a stale size refuses BEFORE anything moves; a failure mid-plan really rolls
// back; a plan needs an expiry; the report never leaves the root.
func TestDcnPlanReviewWalls(t *testing.T) {
	root := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk("one.txt", "ONE")
	mk("two.txt", "TWO")

	// two targets that normalize to the same file — the second must be a problem
	pr := dcnCheckPlan(root, nil, []dcnMove{
		{From: "one.txt", To: "Archive/x.txt"}, {From: "two.txt", To: "./Archive//x.txt"}})
	if len(pr) != 1 || pr[0].Index != 1 {
		t.Fatalf("normalized duplicate target must be refused: %+v", pr)
	}
	pr = dcnCheckPlan(root, nil, []dcnMove{
		{From: "one.txt", To: "Archive/x.txt"}, {From: "two.txt", To: "archive/X.TXT"}})
	if len(pr) != 1 {
		t.Fatalf("case-folded duplicate target must be refused: %+v", pr)
	}
	// the apply path refuses the whole plan and touches nothing
	rep := dcnApplyPlan(root, nil, &dcnPlanTerms{PlanID: 1, Moves: []dcnMove{
		{From: "one.txt", To: "Archive/x.txt"}, {From: "two.txt", To: "./Archive//x.txt"}}})
	if rep["state"] != "refused" {
		t.Fatalf("apply must refuse a colliding plan: %+v", rep)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "one.txt")); string(b) != "ONE" {
		t.Fatal("nothing may move when a plan is refused")
	}

	// size in the plan ≠ size on disk → refused before moving
	wrong := int64(99)
	pr = dcnCheckPlan(root, nil, []dcnMove{{From: "one.txt", To: "Archive/one.txt", SizeBytes: &wrong}})
	if len(pr) != 1 || !strings.Contains(pr[0].Why, "size") {
		t.Fatalf("a stale catalog size must refuse before the move: %+v", pr)
	}

	// a real mid-plan failure rolls the first move back. Move 2's target
	// parent is a FILE ("blocker"), so MkdirAll fails after move 1 succeeded.
	mk("blocker", "i am a file")
	rep = dcnApplyPlan(root, nil, &dcnPlanTerms{PlanID: 2, Moves: []dcnMove{
		{From: "one.txt", To: "Moved/one.txt"}, {From: "two.txt", To: "blocker/two.txt"}}})
	if rep["state"] != "failed" || rep["failed_at"] != 1 || rep["rolled_back"] != 1 {
		t.Fatalf("mid-plan failure must roll back: %+v", rep)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "one.txt")); string(b) != "ONE" {
		t.Fatal("rolled-back source must be back in place with its content")
	}
	if _, err := os.Stat(filepath.Join(root, "Moved", "one.txt")); err == nil {
		t.Fatal("rolled-back target must be gone")
	}

	// a plan without an expiry never verifies
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	terms := map[string]any{"kind": "dcn_move_plan", "store_id": 1, "plan_id": 3, "root": root,
		"archive": "Archive", "moves": []map[string]any{{"from": "a", "to": "b"}}}
	rec := signedRec(t, priv, terms)
	if _, err := dcnVerifyPlan(pubB64, rec.TermsCanonical, rec.Signature); err == nil {
		t.Fatal("a plan with no expiry must not verify")
	}

	// a symlinked .agent pointing outside the root → no report file written
	outside := t.TempDir()
	root2 := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root2, ".agent")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if p := dcnReportPath(root2, 7); p != "" {
		t.Fatalf("report path must not resolve outside the root: %q", p)
	}
	if p := dcnReportPath(root, 7); p == "" || !strings.HasPrefix(p, root) {
		t.Fatalf("report path inside the root must resolve: %q", p)
	}
}
