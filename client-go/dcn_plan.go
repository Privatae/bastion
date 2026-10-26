package main

// Move plans: the ONE write lane on a machine store, and it
// is archive-only. The host reads the local agent's catalog, proposes a plan of
// `move` operations inside the granted root (a new structure; "remove" means
// move into an archive folder), the USER approves it with their step-up code,
// the host signs it, and this box executes it:
//
//	dry_run → every move checked against the sandbox (nothing touched)
//	apply   → the same check, then renames in order — each one re-checked the
//	          instant before it runs (target still absent, parent still inside
//	          the root); a failure rolls the completed renames back; then a
//	          verify pass (every target present, every source gone, sizes as
//	          declared) and a report.
//
// What cannot happen here, by construction:
//   - no delete: there is no remove call on any user path in this file. The
//     only filesystem mutations are os.Rename inside the root and MkdirAll for
//     a target's parent inside the root.
//   - no overwrite: a target that exists is a problem, never replaced — checked
//     on normalized, case-folded paths at plan time AND immediately before each
//     rename (rename(2) replaces silently; this lane never lets it).
//   - no escape: from/to both resolve through the same sandbox as every read
//     (cleanRel + symlink wall), and excludes still apply. The report file is
//     written only if its own path resolves inside the root.
//   - no unsigned, no eternal plan: verified against the pinned entity key,
//     must carry an expiry, must name this store's root and this box, and the
//     store grant must still be held here. An applied plan is not re-applied.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const dcnPlanMaxMoves = 5000

type dcnMove struct {
	From      string `json:"from"`
	To        string `json:"to"`
	SizeBytes *int64 `json:"size_bytes,omitempty"` // declared by the host from the catalog; checked before AND after the move
}

type dcnPlanTerms struct {
	Kind    string    `json:"kind"`
	StoreID int64     `json:"store_id"`
	PlanID  int64     `json:"plan_id"`
	Server  string    `json:"server"`
	Root    string    `json:"root"`
	Archive string    `json:"archive"`
	Moves   []dcnMove `json:"moves"`
	Expires string    `json:"expires"`
	// Approval this box issued after seeing the user's code (stepup.go). Required
	// to APPLY when a second factor is enrolled here; ignored otherwise.
	Approval string `json:"approval,omitempty"`
}

type dcnPlanProblem struct {
	Index int    `json:"index"`
	From  string `json:"from"`
	To    string `json:"to"`
	Why   string `json:"why"`
}

// dcnVerifyPlan checks the plan's signature against the pinned key and parses
// its terms from the EXACT signed bytes — the same discipline as dcnVerifyRec.
func dcnVerifyPlan(pinnedKeyB64, termsB64, sigB64 string) (*dcnPlanTerms, error) {
	rec := dcnGrantRec{TermsCanonical: termsB64, Signature: sigB64}
	if _, err := verifySignedUnexpired(pinnedKeyB64, rec); err != nil {
		// Signature + a stated, future expiry — the wall every signed record
		// shares (service_reach.go). Its KIND is checked just below; dcnVerifyRec
		// is not used here, because it now refuses anything but a store grant.
		return nil, err
	}
	canonical, _ := base64.StdEncoding.DecodeString(termsB64)
	var p dcnPlanTerms
	if err := json.Unmarshal(canonical, &p); err != nil {
		return nil, fmt.Errorf("signed plan unparsable")
	}
	if p.Kind != "dcn_move_plan" {
		return nil, fmt.Errorf("not a move plan")
	}
	if strings.TrimSpace(p.Expires) == "" {
		return nil, fmt.Errorf("plan carries no expiry (a plan is executed, never held)")
	}
	if len(p.Moves) == 0 || len(p.Moves) > dcnPlanMaxMoves {
		return nil, fmt.Errorf("plan must carry 1..%d moves", dcnPlanMaxMoves)
	}
	return &p, nil
}

// pathKey is the identity two plan paths are compared by: the cleaned absolute
// path, case-folded — so "Archive/x", "./Archive//x" and "archive/X" collide
// (case-insensitive filesystems make the last two the same file).
func pathKey(abs string) string {
	return strings.ToLower(filepath.Clean(abs))
}

// dcnCheckPlan is the dry run: every move is validated against the sandbox and
// the current filesystem, nothing is touched. Returns the problems found.
func dcnCheckPlan(root string, excludes []string, moves []dcnMove) []dcnPlanProblem {
	var problems []dcnPlanProblem
	bad := func(i int, m dcnMove, why string) {
		problems = append(problems, dcnPlanProblem{Index: i, From: m.From, To: m.To, Why: why})
	}
	seenTo := map[string]int{}
	seenFrom := map[string]int{}
	for i, m := range moves {
		if strings.TrimSpace(m.From) == "" || strings.TrimSpace(m.To) == "" {
			bad(i, m, "from and to are required")
			continue
		}
		src, ok := dcnResolvePath(root, m.From)
		if !ok {
			bad(i, m, "source escapes the store root")
			continue
		}
		dst, ok := cleanRel(root, m.To)
		if !ok {
			bad(i, m, "target escapes the store root")
			continue
		}
		if pathKey(src) == pathKey(dst) {
			bad(i, m, "from and to are the same path")
			continue
		}
		if j, dup := seenTo[pathKey(dst)]; dup {
			bad(i, m, fmt.Sprintf("target already used by move %d", j))
			continue
		}
		if j, dup := seenFrom[pathKey(src)]; dup {
			bad(i, m, fmt.Sprintf("source already moved by move %d", j))
			continue
		}
		seenTo[pathKey(dst)], seenFrom[pathKey(src)] = i, i
		if dcnExcludedAsSent(excludes, root, m.From) {
			bad(i, m, "source is excluded by the grant")
			continue
		}
		info, err := os.Lstat(src)
		if err != nil {
			bad(i, m, "source does not exist")
			continue
		}
		if m.SizeBytes != nil && !info.IsDir() && info.Size() != *m.SizeBytes {
			bad(i, m, fmt.Sprintf("size is %d, the plan says %d (the file changed since it was catalogued)", info.Size(), *m.SizeBytes))
			continue
		}
		if dcnExcludedAsSent(excludes, root, m.To) {
			bad(i, m, "target is excluded by the grant")
			continue
		}
		// The target's deepest existing ancestor must resolve inside the root
		// (a symlinked parent pointing outside would carry the file out).
		if _, ok := dcnResolvePath(root, m.To); !ok {
			bad(i, m, "target's parent escapes the store root")
			continue
		}
		if _, err := os.Lstat(dst); err == nil {
			bad(i, m, "target already exists (a plan never overwrites)")
			continue
		}
		// Moving a directory into itself.
		if strings.HasPrefix(pathKey(dst), pathKey(src)+string(os.PathSeparator)) {
			bad(i, m, "target is inside the source")
			continue
		}
	}
	return problems
}

// dcnReportPath is where the box keeps a plan's report — <root>/.agent/plans/<id>.json,
// the machine's own record next to the local agent's outputs — but only if that
// path resolves inside the root (a symlinked .agent could otherwise carry the
// write out). "" = do not write; the report still goes back over the lane.
func dcnReportPath(root string, planID int64) string {
	rel := filepath.Join(".agent", "plans", strconv.FormatInt(planID, 10)+".json")
	p, ok := dcnResolvePath(root, rel)
	if !ok {
		return ""
	}
	return p
}

// dcnApplyPlan is dcnApplyPlanIn on root opened where it leads now (the op
// handler opens the PINNED folder instead, dcn_store.go).
func dcnApplyPlan(root string, excludes []string, plan *dcnPlanTerms) map[string]any {
	real, err := dcnRealRoot(root)
	if err != nil {
		return map[string]any{"state": "refused", "mode": "apply", "plan_id": plan.PlanID,
			"reason": "the store's folder cannot be opened: " + err.Error()}
	}
	r, err := dcnOpenRootAt(real)
	if err != nil {
		return map[string]any{"state": "refused", "mode": "apply", "plan_id": plan.PlanID, "reason": err.Error()}
	}
	defer r.Close()
	return dcnApplyPlanIn(r, root, excludes, plan)
}

// dcnApplyPlanIn runs the plan: check, rename in order (each re-checked just
// before it runs; rolling back on the first failure), verify, report. Every
// path it touches has passed dcnCheckPlan, and every change is made through
// r, the store's handle, so a folder that becomes a link to somewhere else
// between the check and the rename is refused rather than followed.
func dcnApplyPlanIn(r *os.Root, root string, excludes []string, plan *dcnPlanTerms) map[string]any {
	problems := dcnCheckPlan(root, excludes, plan.Moves)
	if len(problems) > 0 {
		return map[string]any{"state": "refused", "mode": "apply", "plan_id": plan.PlanID,
			"reason":   fmt.Sprintf("%d move(s) failed the pre-check; nothing was changed", len(problems)),
			"problems": problems}
	}
	type done struct{ src, dst, from string }
	var applied []done
	// rollback undoes the completed renames in reverse; returns what is back
	// and what is NOT (so the user knows exactly what is still displaced).
	rollback := func() (back, stuck []string) {
		for i := len(applied) - 1; i >= 0; i-- {
			if _, err := r.Lstat(applied[i].src); err == nil {
				stuck = append(stuck, applied[i].from) // something now sits at the source; never replace it
				continue
			}
			if err := r.Rename(applied[i].dst, applied[i].src); err == nil {
				back = append(back, applied[i].from)
			} else {
				stuck = append(stuck, applied[i].from)
			}
		}
		return back, stuck
	}
	fail := func(i int, m dcnMove, why string) map[string]any {
		back, stuck := rollback()
		rep := map[string]any{"state": "failed", "mode": "apply", "plan_id": plan.PlanID,
			"failed_at": i, "from": m.From, "to": m.To, "reason": why,
			"applied": len(applied), "rolled_back": len(back)}
		if len(stuck) > 0 {
			rep["not_rolled_back"] = stuck
		}
		return rep
	}
	for i, m := range plan.Moves {
		srcAbs, _ := dcnResolvePath(root, m.From)
		dstAbs, _ := cleanRel(root, m.To)
		src, serr := dcnRel(root, srcAbs)
		dst, derr := dcnRel(root, dstAbs)
		if serr != nil || derr != nil {
			return fail(i, m, "path escapes the store root")
		}
		if d := filepath.Dir(dst); d != "." {
			if err := r.MkdirAll(d, 0o755); err != nil {
				return fail(i, m, "could not create the target folder: "+err.Error())
			}
		}
		// Re-check the instant before the rename: the world may have changed since
		// the pre-check (a file appeared at the target; a parent became a symlink).
		// rename(2) would replace silently — this lane never lets it.
		if _, ok := dcnResolvePath(root, m.To); !ok {
			return fail(i, m, "target's parent no longer resolves inside the store root")
		}
		if _, err := r.Lstat(dst); err == nil {
			return fail(i, m, "target appeared since the check (a plan never overwrites)")
		}
		if err := r.Rename(src, dst); err != nil {
			why := err.Error()
			if errors.Is(err, syscall.EXDEV) {
				why = "target is on a different filesystem than the source (a plan only renames; it never copies and removes)"
			}
			return fail(i, m, why)
		}
		applied = append(applied, done{src, dst, m.From})
	}
	// Verify pass: every target present, every source gone, declared sizes hold.
	var mismatches []dcnPlanProblem
	for i, m := range plan.Moves {
		srcAbs, _ := dcnResolvePath(root, m.From)
		dstAbs, _ := cleanRel(root, m.To)
		src, _ := dcnRel(root, srcAbs)
		dst, _ := dcnRel(root, dstAbs)
		info, err := r.Lstat(dst)
		if err != nil {
			mismatches = append(mismatches, dcnPlanProblem{i, m.From, m.To, "target missing after move"})
			continue
		}
		if _, err := r.Lstat(src); err == nil {
			mismatches = append(mismatches, dcnPlanProblem{i, m.From, m.To, "source still present after move"})
		}
		if m.SizeBytes != nil && !info.IsDir() && info.Size() != *m.SizeBytes {
			mismatches = append(mismatches, dcnPlanProblem{i, m.From, m.To,
				fmt.Sprintf("size %d, plan declared %d", info.Size(), *m.SizeBytes)})
		}
	}
	rep := map[string]any{"state": "ok", "mode": "apply", "plan_id": plan.PlanID,
		"applied": len(applied), "verified": len(applied) - len(mismatches),
		"archive": plan.Archive, "at": time.Now().UTC().Format(time.RFC3339)}
	if len(mismatches) > 0 {
		rep["state"] = "failed"
		rep["reason"] = fmt.Sprintf("%d move(s) did not verify", len(mismatches))
		rep["mismatches"] = mismatches
	}
	return rep
}

// handleDcnPlanApply — op dcn_plan_apply <store_id> <payload_b64>, payload =
// {"terms_canonical","signature","mode":"dry_run"|"apply"}.
func handleDcnPlanApply(ws *websocket.Conn, dir string, args []string) {
	if len(args) < 2 {
		sendMgmt(ws, 'R', []byte("dcn_plan_apply: need <store_id> <payload_b64>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	storeID, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil {
		sendMgmt(ws, 'R', []byte("dcn_plan_apply: bad store_id\n"))
		sendMgmtExit(ws, 1)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args[1]))
	if err != nil {
		sendMgmt(ws, 'R', []byte("bad base64\n"))
		sendMgmtExit(ws, 1)
		return
	}
	var payload struct {
		TermsCanonical string `json:"terms_canonical"`
		Signature      string `json:"signature"`
		Mode           string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		sendMgmt(ws, 'R', []byte("bad payload json\n"))
		sendMgmtExit(ws, 1)
		return
	}
	mode := strings.TrimSpace(payload.Mode)
	if mode != "dry_run" && mode != "apply" {
		sendMgmt(ws, 'R', []byte("mode must be dry_run or apply\n"))
		sendMgmtExit(ws, 1)
		return
	}
	op := "plan_" + mode
	// The store grant must be held here (any mask — the plan is its own signed,
	// user-approved authorization; the grant supplies root + excludes).
	grantsMu.Lock()
	f, err := dcnLoadFile(dir)
	grantsMu.Unlock()
	if err != nil || f.VerifyPubkey == "" {
		dcnRefuse(ws, dir, op, storeID, "", "no grant synced to this box (default-deny)")
		return
	}
	rec, ok := f.Stores[strconv.FormatInt(storeID, 10)]
	if !ok {
		dcnRefuse(ws, dir, op, storeID, "", "no grant for this store on this box (default-deny)")
		return
	}
	terms, err := dcnVerifyRec(f.VerifyPubkey, rec)
	if err != nil {
		dcnRefuse(ws, dir, op, storeID, "", "grant refused: "+err.Error())
		return
	}
	if terms.Class != "machine" || terms.Root == "" {
		dcnRefuse(ws, dir, op, storeID, "", "grant is not a machine store")
		return
	}
	plan, err := dcnVerifyPlan(f.VerifyPubkey, payload.TermsCanonical, payload.Signature)
	if err != nil {
		dcnRefuse(ws, dir, op, storeID, "", "plan refused: "+err.Error())
		return
	}
	if plan.StoreID != storeID || plan.Root != terms.Root {
		dcnRefuse(ws, dir, op, storeID, "", "plan is for a different store or root")
		return
	}
	if hn, _ := os.Hostname(); hn != "" && plan.Server != "" && plan.Server != hn {
		dcnRefuse(ws, dir, op, storeID, "", fmt.Sprintf("plan is for server '%s', this box is '%s'", plan.Server, hn))
		return
	}
	planKey := strconv.FormatInt(plan.PlanID, 10)
	if mode == "dry_run" {
		problems := dcnCheckPlan(terms.Root, terms.Excludes, plan.Moves)
		res := map[string]any{"state": "ok", "mode": "dry_run", "plan_id": plan.PlanID,
			"checked": len(plan.Moves), "ready": len(problems) == 0}
		if len(problems) > 0 {
			res["problems"] = problems
		}
		dcnResult(ws, dir, op, storeID, planKey, res)
		return
	}
	// apply — once. A report on disk from a successful run means the files have
	// already moved; running the same plan again could only fail or surprise, so
	// a retry (a lost reply, a host re-run) gets the earlier report back BEFORE
	// any gate can turn it into a refusal. (The signed expiry is the guard that
	// does not depend on a file the user can remove.)
	store, err := dcnOpenStore(dir, storeID, terms)
	if err != nil {
		dcnRefuse(ws, dir, op, storeID, planKey, err.Error())
		return
	}
	defer store.Close()
	repPath := dcnReportPath(terms.Root, plan.PlanID)
	repRel := ""
	if repPath != "" {
		repRel, _ = dcnRel(terms.Root, repPath)
	}
	if repRel != "" {
		if prev, err := store.ReadFile(repRel); err == nil {
			var old map[string]any
			if json.Unmarshal(prev, &old) == nil && old["state"] == "ok" {
				old["note"] = "already applied on this machine; this is the earlier report"
				dcnResult(ws, dir, op, storeID, planKey, old)
				return
			}
		}
	}
	// Second factor on THIS box (stepup.go): applying a plan changes files here,
	// so when a factor is enrolled here the plan must carry an approval this
	// machine issued after the user confirmed exactly these moves HERE.
	// Checked, not burned, until success.
	if approvalRequired(dir) {
		purpose, perr := purposeForPlan(plan)
		if perr != nil {
			dcnRefuse(ws, dir, op, storeID, planKey, "plan refused: "+perr.Error())
			return
		}
		if err := boxApproval(dir, plan.Approval, purpose); err != nil {
			dcnRefuse(ws, dir, op, storeID, planKey, err.Error())
			return
		}
	}
	rep := dcnApplyPlanIn(store, terms.Root, terms.Excludes, plan)
	if rep["state"] == "ok" && plan.Approval != "" {
		markApprovalUsed(dir, plan.Approval) // single use: the files have moved
	}
	if repRel != "" {
		if raw, err := json.MarshalIndent(rep, "", "  "); err == nil {
			_ = dcnRootAtomicWrite(store, repRel, raw) // the machine's own record; best-effort
		}
	}
	dcnResult(ws, dir, op, storeID, planKey, rep)
}
