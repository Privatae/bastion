//go:build linux

package main

// ops_plan_linux.go — a machine running its lines of a signed ship plan
// (ops_plan.go), and undoing one.
//
//	op_plan_line <plan_b64> <n> [receipts_b64] [sealed credential ...]
//	op_plan_undo <plan_b64> <n> <failed_receipt_b64>
//
// A line runs as an action op's apply (ops_verbs_linux.go) with the plan as
// its approval: no change list is bound (the digest a build produces cannot
// be known when the person approves), and the verbs' own rules still hold —
// a tree only forward, an image only from a receipt of this plan and only
// forward from what this machine rolled, unless the line adopts the live
// image. Every run, success or not, ends in a line receipt signed with this
// machine's key: a failed one is what a machine needs to undo an earlier line.
//
// A line's attempts run one at a time, each only after the one before it
// failed, and never after one passed: the machine keeps one record per line
// (planRunRecord), written before an attempt starts and before each of its
// verbs runs, and that record — not the pod — says which attempt is next.
//
// An undo takes a line back to the state THIS machine recorded before the
// line's FIRST attempt, and nothing else: the tree to its old commit, the
// image to its old reference, each unit the line restarted restarted again.
// It needs a failed check of a LATER line of the same plan on that line's
// last allowed attempt, or the failure of this line's own latest attempt when
// none of its attempts passed — a receipt signed by the key the plan names
// for that line's machine — and it is spent once.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const planRunsDirName = "plan_runs"

// A line's state on this machine. Only a failed line runs again; passed and
// undone are final.
const (
	planStateRunning = "running"
	planStatePassed  = "passed"
	planStateFailed  = "failed"
	planStateUndone  = "undone"
)

// planKeepAfterExpiry: how long a line's record and receipts outlive their
// plan, for op_plan_status (an expired plan runs and undoes nothing).
const planKeepAfterExpiry = 7 * 24 * time.Hour

// planRunRecord is what this machine keeps of a line: which attempt is the
// latest and how it ended, and every verb any attempt ran, for its undo.
type planRunRecord struct {
	Plan    string `json:"plan"`
	N       int    `json:"n"`
	At      string `json:"at"`
	Expires string `json:"expires"`
	Attempt int    `json:"attempt"` // the latest attempt started here
	State   string `json:"state"`
	// The bastion process running the attempt (planProcAt): an attempt whose
	// process is gone was stopped by a restart, and is settled as failed.
	Proc string `json:"proc,omitempty"`
	// The receipt an attempt stopped by a restart is settled with.
	Receipt lineReceipt `json:"receipt"`
	// Every verb any attempt ran, in the order first run, each with the state
	// it was in before the line's first attempt touched it and the state the
	// latest attempt was to leave it in.
	Verbs []opVerbLine `json:"verbs"`
	Froms []string     `json:"froms"`
	Tos   []string     `json:"tos"`
}

// planLineMu orders the reads and writes of the line records.
var planLineMu sync.Mutex

// planProc names this bastion process: the boot, the pid, and its start
// time, so a pid reused later, or after a reboot, is another name. The pid is
// the one /proc shows (read from /proc/self), so the name and the check that
// the process is alive read the same /proc even in another pid namespace.
var planProc, _ = planProcAt("self")

// planProcRoot is /proc (a test points it elsewhere).
var planProcRoot = "/proc"

// planProcAt names a process as planProc does. Only a process that is not
// there returns an error errors.Is(os.ErrNotExist); any other failure to read
// is not an answer.
func planProcAt(which string) (string, error) {
	boot, err := os.ReadFile(filepath.Join(planProcRoot, "sys/kernel/random/boot_id"))
	if err != nil {
		return "", fmt.Errorf("the boot id does not read: %v", err)
	}
	stat, err := os.ReadFile(filepath.Join(planProcRoot, which, "stat"))
	if err != nil {
		return "", err
	}
	// The pid, then the command in parentheses (which may hold anything),
	// then the fields after it: the start time is field 22, the 20th after.
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	j := strings.IndexByte(s, ' ')
	f := []string{}
	if i >= 0 {
		f = strings.Fields(s[i+1:])
	}
	if i < 0 || j < 0 || j > i || len(f) < 20 {
		return "", errors.New("the process's stat does not read")
	}
	return strings.TrimSpace(string(boot)) + ":" + s[:j] + ":" + f[19], nil
}

// planProcGone: the process an attempt was running in is known to be gone —
// not there, or another process under its pid. A /proc that cannot be read
// is not known, and never settles an attempt.
func planProcGone(id string) bool {
	parts := strings.Split(id, ":")
	if len(parts) != 3 {
		return true // not a name planProcAt makes: no process runs under it
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return true
	}
	now, err := planProcAt(parts[1])
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	return err == nil && now != id
}

func planRunPath(nonce string, n int) (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(d, planRunsDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if !printableASCII(nonce) || strings.ContainsAny(nonce, "/\\.") {
		return "", errors.New("a plan nonce that cannot name a file")
	}
	return filepath.Join(dir, nonce+"-"+strconv.Itoa(n)+".json"), nil
}

// planDecodeArgs reads the plan envelope and the line number.
func planDecodeArgs(args []string) (*shipPlan, string, int, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args[0]))
	if err != nil {
		return nil, "", 0, errors.New("the plan does not decode")
	}
	var env shipPlanEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, "", 0, errors.New("the plan is not an envelope")
	}
	p, sha, err := planOpen(env)
	if err != nil {
		return nil, "", 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(args[1]))
	if err != nil {
		return nil, "", 0, errors.New("the line is not a number")
	}
	return p, sha, n, nil
}

func planDecodeReceipts(b64 string) ([]opSignedReceipt, error) {
	if strings.TrimSpace(b64) == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, errors.New("the receipts do not decode")
	}
	var out []opSignedReceipt
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.New("the receipts are not a list")
	}
	return out, nil
}

func handlePlanLine(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 2 {
		opFail(ws, "op_plan_line: need <plan_b64> <n> [receipts_b64] [sealed credential ...]")
		return
	}
	recB64 := ""
	if len(args) > 2 {
		recB64 = args[2]
	}
	var creds []string
	if len(args) > 3 {
		creds = args[3:]
	}
	out, err := planRunLine(dir, args[0], args[1], recB64, creds)
	if err != nil {
		opFail(ws, "op_plan_line refused: "+err.Error())
		return
	}
	b, _ := json.Marshal(out)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// planRunLine checks a line and runs it. A refusal before the run returns an
// error (nothing ran, nothing is spent unless the spend itself was reached);
// a run that ran returns its signed receipt, successful or not.
func planRunLine(dir, planB64, nArg, recB64 string, credBlobs []string) (map[string]any, error) {
	p, sha, n, err := planDecodeArgs([]string{planB64, nArg})
	if err != nil {
		return nil, err
	}
	l, err := planLineFor(p, n)
	if err != nil {
		return nil, err
	}
	receipts, err := planDecodeReceipts(recB64)
	if err != nil {
		return nil, err
	}
	params, steps, err := planInputs(p, sha, l, receipts)
	if err != nil {
		return nil, err
	}
	m, err := opLoad(dir, l.OpSHA256)
	if err != nil {
		return nil, fmt.Errorf("this machine does not hold the op %s@%s (op_sync it first): %v", l.Op, truncate(l.OpSHA256, 12), err)
	}
	if err := planLineMatchesOp(l, m, params); err != nil {
		return nil, err
	}
	if _, err := opOpenCreds(credBlobs, m, p.Nonce, false); err != nil {
		return nil, err
	}
	if !m.verbsOnly() {
		if ok, why := opActionCheck(); !ok {
			return nil, errors.New("this machine cannot run an action op: " + why)
		}
	}
	if err := planRecordVersion(p.Pipeline, p.Version); err != nil {
		return nil, fmt.Errorf("could not record the plan's version: %v", err)
	}
	hn, _ := os.Hostname()
	lr := lineReceipt{Plan: p.Nonce, PlanSHA256: sha, Pipeline: p.Pipeline, Commit: p.Commit, N: n, Step: l.Step,
		Machine: hn, OpSHA256: l.OpSHA256, ParamsSHA256: planParamsSHA(params)}
	// One attempt at a time, the next only after the last failed, and spent
	// before it runs, as an approval is.
	attempt, err := planBeginAttempt(p, l, lr)
	if err != nil {
		return nil, err
	}
	lr.Attempt = attempt
	id, _ := newID()
	t := &opTerms{Kind: opKindRun, Op: m.Name, Version: m.Version, SHA256: l.OpSHA256, Privilege: m.Privilege,
		Params: params, Nonce: p.Nonce, Uses: 1}
	pc := &opPlanCtx{Commit: p.Commit, AdoptLive: l.AdoptLive, Steps: steps,
		beforeVerb: func(v opVerbLine, from, to string) error { return planRecordVerb(p.Nonce, n, attempt, v, from, to) }}
	rep, runErr := opRunAction(opStoreDir(dir, l.OpSHA256), m, t, opModeApply, id, credBlobs, pc)
	lr.At, lr.OK = time.Now().UTC().Format(time.RFC3339), runErr == nil
	if runErr != nil {
		lr.Error = truncate(runErr.Error(), 500)
	}
	if rep != nil {
		lr.VerifyError, lr.Verbs, lr.Checks = rep.VerifyError, rep.Verbs, rep.Checks
		for _, s := range rep.Receipts {
			if r, err := opVerifyReceipt(s); err == nil {
				lr.Images = append(lr.Images, opResultImage{Image: r.Image, Digest: r.Digest, Source: r.Source, Commit: r.Commit})
			}
		}
	}
	signed, err := lineReceiptSign(lr)
	if err != nil {
		// Ended as failed with no receipt: nothing can retry or undo it on
		// the strength of a receipt that does not exist.
		_ = planEndAttempt(p.Nonce, n, attempt, false)
		return nil, fmt.Errorf("the line ran and its receipt could not be signed: %v", err)
	}
	// The receipt is kept before the attempt is ended, so a record that says
	// an attempt ended always has its receipt beside it. A record that could
	// not be ended stays running: nothing runs or undoes the line after it
	// until this bastion restarts and settles it from the kept receipt.
	keepErr := planKeepReceipt(p.Nonce, n, signed)
	endErr := planEndAttempt(p.Nonce, n, attempt, !lr.failed())
	out := map[string]any{"receipt": signed, "ok": lr.OK, "error": lr.Error, "verify_error": lr.VerifyError}
	if keepErr != nil || endErr != nil {
		out["keep_error"] = fmt.Sprint(errors.Join(keepErr, endErr))
	}
	if rep != nil {
		out["report"] = rep
	}
	dcnAudit(dir, "op_plan_line", 0, p.Pipeline+"#"+strconv.Itoa(n)+" "+l.Op, fmt.Sprintf("ok=%v attempt=%d plan=%s", lr.OK, attempt, truncate(p.Nonce, 12)))
	return out, nil
}

func planParamsSHA(params string) string {
	sum := sha256.Sum256([]byte(params))
	return hex.EncodeToString(sum[:])
}

// ── the line record ─────────────────────────────────────────────────────────

// planLoadRun reads a line's record: nil when the line never started here.
func planLoadRun(nonce string, n int) (*planRunRecord, error) {
	path, err := planRunPath(nonce, n)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not read this machine's record of line %d: %v", n, err)
	}
	var rec planRunRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Plan != nonce || rec.N != n {
		return nil, fmt.Errorf("this machine's record of line %d does not read", n)
	}
	return &rec, nil
}

func planSaveRun(rec *planRunRecord) error {
	path, err := planRunPath(rec.Plan, rec.N)
	if err != nil {
		return err
	}
	rec.At = time.Now().UTC().Format(time.RFC3339)
	raw, _ := json.MarshalIndent(rec, "", "  ")
	return atomicWrite(path, raw)
}

// planBeginAttempt starts the line's next attempt: the first, or the one
// after an attempt that FAILED here. It refuses while an attempt is running,
// once one passed, and once the line was undone, and records the attempt as
// running before anything of it runs; a record it cannot write refuses.
func planBeginAttempt(p *shipPlan, l *shipPlanLine, tmpl lineReceipt) (int, error) {
	planLineMu.Lock()
	defer planLineMu.Unlock()
	if planProc == "" {
		return 0, errors.New("this machine cannot name its own process, so it cannot keep a line's attempts apart")
	}
	rec, err := planLoadRun(p.Nonce, l.N)
	if err != nil {
		return 0, err
	}
	next := 1
	if rec != nil {
		if rec.State == planStateRunning && planProcGone(rec.Proc) {
			if err := planSettleLocked(rec); err != nil {
				return 0, err
			}
		}
		switch rec.State {
		case planStateRunning:
			return 0, fmt.Errorf("attempt %d of line %d is running here; the next waits for its receipt", rec.Attempt, l.N)
		case planStatePassed:
			return 0, fmt.Errorf("line %d of this plan already succeeded here; it is not run again", l.N)
		case planStateUndone:
			return 0, fmt.Errorf("line %d of this plan was undone here; it is not run again", l.N)
		case planStateFailed:
			next = rec.Attempt + 1
		default:
			return 0, fmt.Errorf("this machine's record of line %d does not read", l.N)
		}
	} else {
		rec = &planRunRecord{Plan: p.Nonce, N: l.N, Expires: p.Expires}
	}
	k, err := planSpendAttempt(p, l)
	if err != nil {
		return 0, err
	}
	if k != next {
		return 0, fmt.Errorf("line %d: its record here says attempt %d is next and its spent attempts say %d; refused rather than run out of order", l.N, next, k)
	}
	tmpl.Attempt = k
	rec.Attempt, rec.State, rec.Proc, rec.Receipt = k, planStateRunning, planProc, tmpl
	if err := planSaveRun(rec); err != nil {
		return 0, fmt.Errorf("could not record attempt %d of line %d before it runs (%v); refused rather than run unrecorded", k, l.N, err)
	}
	return k, nil
}

// planRecordVerb adds a verb the running attempt is about to run to the
// line's record. A verb an earlier attempt already ran keeps the state it
// started in before the first attempt, so an undo goes back to before the
// line, not to where a failed attempt left it.
func planRecordVerb(nonce string, n, attempt int, v opVerbLine, from, to string) error {
	planLineMu.Lock()
	defer planLineMu.Unlock()
	rec, err := planLoadRun(nonce, n)
	if err != nil {
		return err
	}
	if rec == nil || rec.Attempt != attempt || rec.State != planStateRunning || rec.Proc != planProc {
		return fmt.Errorf("the record of line %d is not this attempt's", n)
	}
	for i, had := range rec.Verbs {
		if had.Verb == v.Verb && had.target() == v.target() {
			// Where an earlier attempt left it, or where it was before: a
			// target in neither state was moved by something else between
			// the attempts, and an undo to before the first attempt would
			// take that change back too. Refused before it runs.
			if from != rec.Froms[i] && from != rec.Tos[i] {
				return fmt.Errorf("it is at %s, which is neither where it was before this line's first attempt nor where that attempt was taking it: something else moved it since, and it is left alone", truncate(from, 90))
			}
			rec.Verbs[i], rec.Tos[i] = v, to
			return planSaveRun(rec)
		}
	}
	rec.Verbs, rec.Froms, rec.Tos = append(rec.Verbs, v), append(rec.Froms, from), append(rec.Tos, to)
	return planSaveRun(rec)
}

// planEndAttempt records how the running attempt ended.
func planEndAttempt(nonce string, n, attempt int, passed bool) error {
	planLineMu.Lock()
	defer planLineMu.Unlock()
	rec, err := planLoadRun(nonce, n)
	if err != nil {
		return err
	}
	if rec == nil || rec.Attempt != attempt || rec.State != planStateRunning || rec.Proc != planProc {
		return fmt.Errorf("the record of line %d is not this attempt's", n)
	}
	rec.State, rec.Proc = planStateFailed, ""
	if passed {
		rec.State = planStatePassed
	}
	return planSaveRun(rec)
}

// planSettleLocked ends an attempt whose bastion process is gone (the op
// unit went with it, opStartupSweep). If its receipt was kept, that is how it
// ended; if not, it failed, and a receipt saying so is signed and kept, so
// the pod can read it (op_plan_status) and retry or undo on it.
func planSettleLocked(rec *planRunRecord) error {
	if r := planKeptReceipt(rec.Plan, rec.N, rec.Attempt); r != nil {
		rec.State = planStateFailed
		if !r.failed() {
			rec.State = planStatePassed
		}
	} else {
		lr := rec.Receipt
		lr.Attempt, lr.OK, lr.At = rec.Attempt, false, time.Now().UTC().Format(time.RFC3339)
		lr.Error = fmt.Sprintf("attempt %d stopped when the bastion running it did", rec.Attempt)
		signed, err := lineReceiptSign(lr)
		if err != nil {
			return fmt.Errorf("could not sign the receipt of line %d's stopped attempt: %v", rec.N, err)
		}
		if err := planKeepReceipt(rec.Plan, rec.N, signed); err != nil {
			return fmt.Errorf("could not keep the receipt of line %d's stopped attempt: %v", rec.N, err)
		}
		rec.State = planStateFailed
	}
	rec.Proc = ""
	return planSaveRun(rec)
}

// planSettleStopped runs at startup (opStartupSweep, after the op units are
// gone): every attempt the last process died in is settled, and a line whose
// plan expired more than planKeepAfterExpiry ago is let go with its receipts.
func planSettleStopped() {
	d, err := configDir()
	if err != nil {
		return
	}
	dir := filepath.Join(d, planRunsDirName)
	entries, _ := os.ReadDir(dir)
	planLineMu.Lock()
	defer planLineMu.Unlock()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".receipts.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var rec planRunRecord
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		if exp, err := time.Parse(time.RFC3339, rec.Expires); err == nil && time.Since(exp) > planKeepAfterExpiry {
			_ = os.Remove(filepath.Join(dir, name))
			_ = os.Remove(filepath.Join(dir, strings.TrimSuffix(name, ".json")+".receipts.json"))
			continue
		}
		if rec.State == planStateRunning && planProcGone(rec.Proc) {
			if err := planSettleLocked(&rec); err != nil {
				fmt.Fprintf(os.Stderr, "privatae-bastion: ship plan %s line %d: %v\n", truncate(rec.Plan, 12), rec.N, err)
			}
		}
	}
}

func handlePlanUndo(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 3 {
		opFail(ws, "op_plan_undo: need <plan_b64> <n> <failed_receipt_b64>")
		return
	}
	out, err := planUndoLine(args[0], args[1], args[2])
	if err != nil {
		opFail(ws, "op_plan_undo refused: "+err.Error())
		return
	}
	b, _ := json.Marshal(out)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// planUndoLine takes line n back to what this machine recorded before it ran.
func planUndoLine(planB64, nArg, failedB64 string) (map[string]any, error) {
	p, sha, n, err := planDecodeArgs([]string{planB64, nArg})
	if err != nil {
		return nil, err
	}
	l, err := planLineFor(p, n)
	if err != nil {
		return nil, err
	}
	if !l.Undo {
		return nil, fmt.Errorf("line %d is not one the plan lets be undone", n)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(failedB64))
	if err != nil {
		return nil, errors.New("the failed receipt does not decode")
	}
	var s opSignedReceipt
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errors.New("the failed receipt is not a receipt")
	}
	fr, err := lineReceiptVerify(s, p, sha)
	if err != nil {
		return nil, err
	}
	// What may start an undo: a later line whose CHECK failed (its apply ran,
	// its verify or log check did not pass — the machines' own verdict, not
	// something a pod can cause by handing a bad credential) on the last
	// attempt the plan allows it, so no retry of it can still pass; or the
	// line's own failure, which takes back only what that line itself did.
	later := fr.N > n && fr.OK && fr.VerifyError != ""
	own := fr.N == n && fr.failed()
	if fr.Undo || !(later || own) {
		return nil, fmt.Errorf("an undo of line %d needs a signed receipt of a LATER line of this plan whose check failed, or of line %d's own failure", n, n)
	}
	if later {
		if last := planLineAttempts(p, fr.N); fr.Attempt != last {
			return nil, fmt.Errorf("line %d's check failed on attempt %d of the %d the plan allows it; only its last attempt's failure undoes an earlier line, since a retry may still pass", fr.N, fr.Attempt, last)
		}
	}
	planLineMu.Lock()
	rec, err := planLoadRun(p.Nonce, n)
	if err == nil && rec == nil {
		err = fmt.Errorf("this machine has no record of running line %d, so there is nothing of it to undo", n)
	}
	if err == nil && rec.State == planStateRunning && planProcGone(rec.Proc) {
		err = planSettleLocked(rec)
	}
	if err == nil {
		err = planUndoAllowed(rec, fr, later)
	}
	if err == nil {
		err = planSpend(p, strconv.Itoa(n)+":undo")
	}
	if err == nil {
		// Undone before the undo runs, so no attempt of the line starts
		// under it; an undo that cannot be recorded does not run.
		prev := rec.State
		rec.State = planStateUndone
		if err = planSaveRun(rec); err != nil {
			rec.State = prev
			err = fmt.Errorf("could not record the undo of line %d before it runs (%v); refused", n, err)
		}
	}
	planLineMu.Unlock()
	if err != nil {
		return nil, err
	}
	hn, _ := os.Hostname()
	ur := lineReceipt{Plan: p.Nonce, PlanSHA256: sha, Pipeline: p.Pipeline, Commit: p.Commit, N: n, Step: l.Step,
		Machine: hn, OpSHA256: l.OpSHA256, At: time.Now().UTC().Format(time.RFC3339), Undo: true, OK: true}
	ctx := context.Background()
	// The state first, newest first (the tree, the image back where they
	// were), and only then each unit the line restarted, in its order, so it
	// starts again on what was put back — never on the failed code.
	order := []int{}
	for i := len(rec.Verbs) - 1; i >= 0; i-- {
		if !strings.HasPrefix(rec.Verbs[i].Verb, "unit.") {
			order = append(order, i)
		}
	}
	for i := range rec.Verbs {
		if strings.HasPrefix(rec.Verbs[i].Verb, "unit.") {
			order = append(order, i)
		}
	}
	for _, i := range order {
		v := rec.Verbs[i]
		note, err := planUndoVerb(ctx, v, rec.Froms[i], rec.Tos[i])
		ur.Verbs = append(ur.Verbs, opVerbResult{Verb: v.Verb, Target: v.target(), OK: err == nil, Note: note})
		if err != nil {
			ur.OK, ur.Error = false, truncate(v.Verb+" "+v.target()+": "+err.Error(), 500)
			break
		}
	}
	signed, err := lineReceiptSign(ur)
	if err != nil {
		return nil, fmt.Errorf("the undo ran and its receipt could not be signed: %v", err)
	}
	out := map[string]any{"receipt": signed, "ok": ur.OK, "error": ur.Error}
	if err := planKeepReceipt(p.Nonce, n, signed); err != nil {
		out["keep_error"] = err.Error()
	}
	return out, nil
}

// planLineAttempts is how many times the plan lets line n run.
func planLineAttempts(p *shipPlan, n int) int {
	for i := range p.Lines {
		if p.Lines[i].N == n && p.Lines[i].Attempts > 1 {
			return p.Lines[i].Attempts
		}
	}
	return 1
}

// planUndoAllowed checks the receipt against what this machine recorded of
// the line: a later line's failure undoes a line that passed here; the
// line's own failure must be its LATEST attempt's, and none may have passed.
func planUndoAllowed(rec *planRunRecord, fr *lineReceipt, later bool) error {
	switch rec.State {
	case planStateRunning:
		return fmt.Errorf("attempt %d of line %d is running here; an undo waits for its receipt", rec.Attempt, rec.N)
	case planStateUndone:
		return fmt.Errorf("line %d of this plan was undone here already", rec.N)
	}
	if later {
		if rec.State != planStatePassed {
			return fmt.Errorf("line %d did not pass here, so no later line ran on it", rec.N)
		}
		return nil
	}
	if rec.State == planStatePassed {
		return fmt.Errorf("an attempt of line %d passed here; an earlier attempt's failure does not undo it", rec.N)
	}
	if fr.Attempt != rec.Attempt {
		return fmt.Errorf("that receipt is of attempt %d of line %d, and its latest attempt here is %d: only the latest attempt's failure undoes the line", fr.Attempt, rec.N, rec.Attempt)
	}
	return nil
}

// planUndoVerb takes one verb back from `to` to `from`, and only from `to`:
// a tree or image that moved since the line ran is someone else's change, and
// is left alone.
func planUndoVerb(ctx context.Context, v opVerbLine, from, to string) (string, error) {
	switch v.Verb {
	case "tree.checkout":
		defer opLockTarget(v)()
		path := v.Args["path"]
		head, branch, err := opTreeState(v)
		if err != nil {
			return "", err
		}
		if head == from {
			return "already at " + truncate(from, 12), nil
		}
		if head != to {
			return "", fmt.Errorf("the tree is at %s, not the %s the line left it at: it moved since, and is left alone", truncate(head, 12), truncate(to, 12))
		}
		if err := opTreeWriteDirs(path, head, from); err != nil {
			return "", err
		}
		// Never over a file the machine keeps: a path the move back writes
		// that is there now, untracked and ignored, stops it (reset --keep,
		// unlike merge, has no --no-overwrite-ignore).
		// The names are matched as they are, never as patterns.
		names, err := opTreeGitStdout(path, "diff", "--name-only", "--no-renames", "-z", head, from)
		if err != nil {
			return "", errors.New("could not read which files moving back writes: " + err.Error())
		}
		var paths []string
		for _, n := range strings.Split(names, "\x00") {
			if n != "" {
				paths = append(paths, n)
			}
		}
		if len(paths) > 0 {
			kept, err := opTreeGitStdout(path, append([]string{"--literal-pathspecs", "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--"}, paths...)...)
			if err != nil {
				return "", errors.New("could not read which files the tree keeps: " + err.Error())
			}
			if strings.Trim(kept, "\x00") != "" {
				return "", fmt.Errorf("moving back would overwrite %s, a file this machine keeps and git ignores", strings.SplitN(strings.Trim(kept, "\x00"), "\x00", 2)[0])
			}
		}
		// Read again right before the move back: reset --keep moves the
		// branch from wherever it is, and a commit something else made
		// since the first read is left alone.
		opTreeBeforeMove(path)
		if now, err := opTreeGit(path, nil, "rev-parse", "HEAD"); err != nil {
			return "", errors.New("could not read the tree's commit: " + truncate(now, 300))
		} else if err := opMovedSince(now, head); err != nil {
			return "", err
		}
		var out string
		if branch != "" {
			// Back on the branch it was on, keeping any local work: reset --keep
			// refuses when a local change is in the way.
			out, err = opTreeGit(path, nil, "reset", "--keep", "--quiet", from)
		} else {
			out, err = opTreeGit(path, nil, "checkout", "--no-overwrite-ignore", "--quiet", "--detach", from)
		}
		if err != nil {
			return "", errors.New("could not move the tree back: " + truncate(out, 300))
		}
		return truncate(to, 12) + " → " + truncate(from, 12) + " (undone)", nil
	case "k8s.set_image":
		defer opLockTarget(v)()
		a := v.Args
		live, err := opLiveImage(ctx, v)
		if err != nil {
			return "", err
		}
		if live == from {
			return "already " + truncate(from, 90), nil
		}
		if live != to {
			return "", fmt.Errorf("the container runs %s, not the %s the line set: it moved since, and is left alone", truncate(live, 90), truncate(to, 90))
		}
		// Read again right before the write, as a roll does.
		if now, err := opLiveImage(ctx, v); err != nil {
			return "", err
		} else if err := opMovedSince(now, live); err != nil {
			return "", err
		}
		wl := a["kind"] + "/" + a["name"]
		if out, err := opKubectl(ctx, "-n", a["namespace"], "set", "image", wl, a["container"]+"="+from); err != nil {
			return "", errors.New("set image failed: " + truncate(out, 300))
		}
		if out, err := opKubectl(ctx, "-n", a["namespace"], "rollout", "status", wl, "--timeout=5m"); err != nil {
			return "", errors.New("the rollout did not finish: " + truncate(out, 300))
		}
		return truncate(to, 60) + " → " + truncate(from, 60) + " (undone), rolled out", nil
	case "unit.reload", "unit.restart":
		// The unit is started again on what the other verbs just put back.
		return opUnitDo(ctx, v)
	}
	return "", fmt.Errorf("%s cannot be undone", v.Verb)
}

// ── what a line left: its receipts, for a pod that lost the answer ─────────

func planReceiptsPath(nonce string, n int) (string, error) {
	p, err := planRunPath(nonce, n)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(p, ".json") + ".receipts.json", nil
}

// planKeepReceipt keeps every receipt a line (and its undo) signed, in order.
func planKeepReceipt(nonce string, n int, s opSignedReceipt) error {
	path, err := planReceiptsPath(nonce, n)
	if err != nil {
		return err
	}
	planMu.Lock()
	defer planMu.Unlock()
	var all []opSignedReceipt
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &all); err != nil {
			return fmt.Errorf("the kept receipts of line %d do not read", n)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	all = append(all, s)
	raw, _ = json.MarshalIndent(all, "", "  ")
	return atomicWrite(path, raw)
}

// op_plan_status <plan nonce> <n>: the receipts line n of that plan signed
// here, in order — a read, for a pod whose answer to op_plan_line was lost
// (a restart mid-run). Nothing is spent by asking.
func handlePlanStatus(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 2 {
		opFail(ws, "op_plan_status: need <plan nonce> <n>")
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(args[1]))
	if err != nil {
		opFail(ws, "op_plan_status: the line is not a number")
		return
	}
	path, err := planReceiptsPath(strings.TrimSpace(args[0]), n)
	if err != nil {
		opFail(ws, "op_plan_status: "+err.Error())
		return
	}
	var all []opSignedReceipt
	planMu.Lock()
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &all)
	}
	planMu.Unlock()
	if all == nil {
		all = []opSignedReceipt{}
	}
	b, _ := json.Marshal(map[string]any{"receipts": all})
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// planKeptReceipt is the kept receipt of attempt k of line n, or nil.
func planKeptReceipt(nonce string, n, k int) *lineReceipt {
	path, err := planReceiptsPath(nonce, n)
	if err != nil {
		return nil
	}
	planMu.Lock()
	raw, err := os.ReadFile(path)
	planMu.Unlock()
	if err != nil {
		return nil
	}
	var all []opSignedReceipt
	if json.Unmarshal(raw, &all) != nil {
		return nil
	}
	for _, sr := range all {
		body, err := base64.StdEncoding.DecodeString(sr.Payload)
		if err != nil {
			continue
		}
		var r lineReceipt
		if json.Unmarshal(body, &r) == nil && r.Plan == nonce && r.N == n && !r.Undo && r.Attempt == k {
			return &r
		}
	}
	return nil
}
