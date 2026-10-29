package main

// writes.go — which ops READ this machine and which ones CHANGE it, and the
// gate every change on an anchored box runs.
//
// Host-authored ops, the box's side: the anchor host keeps
// unconstrained READ of the machine it governs, and every op that writes or
// executes here runs only with a live approval THIS box verified — given from
// the person's own device or at this console — bounded by expiry and uses.
// Before this the anchor pairing passed the whole ceiling (capsAllowIn), and
// on a fleet of machines anchored to one host, that host's word was the only
// check on every write.
//
// The read set is enumerated; everything else writes. A new op is a write until
// someone says otherwise, because the failure that matters is a write that was
// never classified slipping through as a read.
//
// LOCAL (unanchored) boxes gate nothing here: the pairing is the authorization
// on a person's own machine, as it always was. A factor enrolled there still
// bites where it did before (stepupGate).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// opWrites reports whether `op` changes this machine — writes a file, runs a
// program, moves data in, swaps the binary, kills a process — as opposed to
// reading it.
func opWrites(op string) bool {
	if strings.HasPrefix(op, "observe:") || strings.HasPrefix(op, "computer:") {
		return false
	}
	switch op {
	case "uptime", mgmtAuditFetchOp,
		"dcn_list", "dcn_stat", "dcn_read_range", "dcn_search", "dcn_catalog",
		// backup_list creates nothing: backupRootReady (backupstate.go) makes
		// the backup folder only for an op this function calls a write.
		"ctx_get", "backup_list",
		"model:list",
		"pairing_list",
		"stepup_request", "stepup_status",
		"device_request", "device_status",
		"op_list", "op_run_status", "op_plan_status":
		return false
	// egress and inference USE this machine — its connection, its loaded
	// models — and change nothing on it: no file, no process, no binary.
	// That holds only because neither can be turned inward: on an anchored
	// box the egress lane refuses loopback, link-local and private
	// destinations (egress.go egressInternalRefusal), so it reaches the
	// public internet and nothing on this machine or its network; and the
	// store-mutating half of the ollama forward is refused for every pairing
	// (inferencefilter.go). Neither takes a per-run approval.
	case "egress", "inference":
		return false
	}
	return true
}

// opTightens reports whether a WRITE only REMOVES reach — a revoke pushed to
// the box. Never held back: not by the quarantine, not for want of an
// approval. A lost device must not keep a revoked grant alive.
func opTightens(op string) bool {
	return op == "dcn_grant_drop" || op == "pairing_grant_drop" || op == "service_grant_drop" ||
		op == "coder_grant_drop" || op == "op_grant_drop"
}

// ownApproval reports whether a WRITE op already carries its own proof of the
// person's approval, verified elsewhere on this box, so the generic per-run
// approval below would be a second ask for the same act:
//   - dcn_grant_sync / dcn_plan_apply carry terms.Approval (dcn.go, dcn_plan.go),
//     and so does service_grant_sync (service_reach.go)
//   - model:pull carries req.Approval (modelswap.go)
//   - pairing_* records are signed by the pinned anchor key (anchor.go): the
//     person's own governance of who may pair, not a Host's reach.
//   - dcn_grant_drop and pairing_grant_drop only REMOVE reach; a tighten has
//     never needed an approval on this box and gating one would let a lost
//     device keep a revoked grant alive.
//   - backup_fetch, ctx_put and ctx_del are STANDING WORK under a store the
//     person configured AT THIS MACHINE (Config.BackupRoot / ContextRoot):
//     the backup ship runs unattended every night, and the Host's context
//     store writes blobs into its sandboxed root as it works. Deterministic
//     standing work takes no approval. The root the person set
//     here is their standing approval; the op cannot leave it (cleanRel).
//     ctx_extract is NOT among them — it EXECUTES an extractor over a
//     document, and is approved per run.
//   - backup_push is the same standing work in the other direction: it
//     sends a backup file from that root (ciphertext the host wrote) to a
//     signed upload URL, and changes nothing here.
//   - backup_reseal files a request and changes nothing here; the act it
//     asks for runs only when the person approves it at this machine with
//     `backup approve` (backupreseal.go), on every box, anchored or not.
//   - op_sync / op_dry_run / op_apply / op_grant_run carry SIGNED TERMS
//     (ops.go): an op_apply spends the person's approval inside its terms; a
//     grant is installed under one at sync; a dry run and a grant run are
//     the sandbox and the held grant doing what the person already approved.
//     op_plan_line / op_plan_undo carry the plan the person's device signed
//     (ops_plan.go), and spend its line.
func ownApproval(op string) bool {
	switch op {
	case "dcn_grant_sync", "dcn_plan_apply", "model:pull", "service_grant_sync", "coder_grant_sync",
		"backup_fetch", "backup_push", "backup_reseal", "ctx_put", "ctx_del",
		"op_sync", "op_dry_run", "op_apply", "op_grant_run", "op_plan_line", "op_plan_undo":
		return true
	}
	return opTightens(op) || strings.HasPrefix(op, "pairing_")
}

// argsDigest is the args as the approval binds them: the sha256 of every
// argument framed as "<byte length>:<bytes>\n", in order. NOT a JSON encoding
// — Go's json.Marshal HTML-escapes <, > and & and escapes U+2028/9 where
// Python's json.dumps does neither, and the pod derives this same digest
// (stepup.go's doctrine: never JSON canonicalization across two languages).
// The length prefix keeps "a","b" apart from "a\nb". An approval for one
// argument list cannot run with another.
func argsDigest(args []string) string {
	h := sha256.New()
	for _, a := range args {
		h.Write([]byte(strconv.Itoa(len(a)) + ":"))
		h.Write([]byte(a))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// mgmtOpPurpose is what the person approves for one run of a write op: this
// op, on this machine, with exactly these arguments. A plain |-joined string,
// derived the same way on both sides (stepup.go's doctrine: never JSON
// canonicalization across two languages).
func mgmtOpPurpose(op, server string, args []string) string {
	return "mgmt_op|" + op + "|" + server + "|" + argsDigest(approvalArgs(op, args))
}

// approvalArgs is what the approval for one op BINDS — the arguments as sent,
// except where an argument carries something that cannot be bound: the
// ctx_extract job carries either the document's bytes (inline) or a
// single-use pull ticket minted per call, and a card that showed either
// would show nothing the person can read and bind nothing stable across a
// re-ask. For it the approval binds [tool, mime, doc, bytes] — `doc` is the
// host's stable name for the document (the pod sends "ctx:<id>"), and `bytes`
// is the sha256 of the inline document when it rides the frame, so a label
// cannot be approved for one document and used for another. On the PULL
// path the bytes are not in hand and `bytes` is "": the approval binds the
// label alone there, and the label is the pod's word. The pull carries no
// digest by design (the document never left the user's own stores, so
// nothing this side has hashed it; the host's extract route says
// why) — the box checks the declared size, not the content. That is the
// one place a label can be approved for one document and pulled for
// another, and it is written here rather than papered over. The pod
// derives the same (nac_approval.approval_args).
func approvalArgs(op string, args []string) []string {
	if op != "ctx_extract" || len(args) != 1 {
		return args
	}
	var job struct {
		Tool, Mime, Doc, B64, Ticket string
	}
	if json.Unmarshal([]byte(args[0]), &job) != nil {
		return args
	}
	bytesDigest := ""
	if job.B64 != "" {
		sum := sha256.Sum256([]byte(job.B64))
		bytesDigest = hex.EncodeToString(sum[:])
	}
	doc := job.Doc
	if doc == "" {
		doc = "ticket:" + job.Ticket
	}
	return []string{job.Tool, job.Mime, doc, bytesDigest}
}

// writeGate is the one decision for a management job on this box. Returns
// (approval identity, refusal): a non-empty identity means an approval was
// verified AND SPENT (consumeApproval) for this run; a non-empty refusal is
// sent as-is.
//
// Order matters and each step is deny-only or pass-through:
//  1. an unanchored box gates nothing here (see the file header);
//  2. a read is never gated — the anchor keeps unconstrained read;
//  3. a tighten (a revoke) is never held back, by anything;
//  4. a quarantined pairing's other writes are refused before anything is
//     checked, so a pairing being held cannot spend approvals or probe;
//  5. an op carrying its own approval is checked where that approval lives;
//  6. everything else spends an approval for exactly this op/machine/args.
func writeGate(self, dcnDir string, job mgmtJob) (string, string) {
	if currentAnchor() == nil || !opWrites(job.Op) || opTightens(job.Op) {
		return "", ""
	}
	if until := quarantinedUntil(self, time.Now()); !until.IsZero() {
		return "", quarantineRefusal(until)
	}
	if ownApproval(job.Op) {
		return "", ""
	}
	hn, _ := os.Hostname()
	id, err := boxConsume(dcnDir, job.Approval, mgmtOpPurpose(job.Op, hn, job.Args))
	if err != nil {
		return "", "refused: op '" + job.Op + "' changes this machine and " + err.Error()
	}
	return id, ""
}

// ── the box-wide directives on the heartbeat ────────────────────────────────

// The three host-directed actions that ride the heartbeat rather than the
// management lane (update.go, contain.go, mirror.go). Each is a write on the
// machine and takes the same approval a management write does, carried on
// the heartbeat response beside the directive:
//
//	{"update": {...}, "approvals": {"self-update": "<approval>"}}
//
// The purpose binds the directive's own arguments (the target version; the
// pids; the slot and image), so an approval for one roll cannot fund another.
// One exception (0.44.0): a self-update to a NEWER version needs no approval,
// because the release signature is the approval for it (maybeSelfUpdate).
const (
	directiveSelfUpdate = "self-update"
	directiveContain    = "contain"
	directiveMirror     = "mirror"
	// localFamilyDirectives is the switchable family the person at the machine
	// turns the three off with (localdeny.go). Not a caps family — no grant can
	// name it — so it lives beside allCaps rather than in it.
	localFamilyDirectives = "directives"
)

func isDirectiveOp(op string) bool {
	return op == directiveSelfUpdate || op == directiveContain || op == directiveMirror
}

// directiveApproval reads the approval the host attached for one directive.
func directiveApproval(heartbeatResponse []byte, what string) string {
	var hb struct {
		Approvals map[string]string `json:"approvals"`
	}
	if json.Unmarshal(heartbeatResponse, &hb) != nil {
		return ""
	}
	return hb.Approvals[what]
}

// directiveGate is anchorOnly, then the local switch, then the write gate,
// for one directive. Returns the refusal, or "" to proceed.
//
// A directive is REPEATED: the host sends it on every beat until the box
// reports the result, and for a mirror for as long as the mirror stands. The
// approval is burned the first time the directive passes, and the act it
// covered is remembered (directiveLedger) so the same directive on the next
// beat — the same what and the same args — proceeds without a second tap:
// the person approved THIS act, and the host re-sending it is not a new one.
// contain and self-update are remembered for directiveRepeatWindow (a kill
// the box could not confirm on the first beat, a swap whose manifest fetch
// failed); a mirror placement is remembered until it is disabled or changes.
func directiveGate(self, dcnDir, what string, args []string, approval string) string {
	return directiveGateFor(self, dcnDir, what, args, approval, "")
}

// directiveGateFor is directiveGate with a FINGERPRINT of the thing the
// directive acts on, remembered beside the act: a contain remembers the
// signature the agent wore when the person approved it, so a pid handed to
// a new process inside the repeat window is a new act, not the remembered
// one. "" for a directive whose arguments already name the thing (a version,
// a finding's fingerprint, a mirror image).
func directiveGateFor(self, dcnDir, what string, args []string, approval, fingerprint string) string {
	if why := directiveWalls(self, what); why != "" {
		return why
	}
	if currentAnchor() == nil {
		return ""
	}
	digest := argsDigest(args)
	if directiveApproved(what, digest, fingerprint, time.Now()) {
		return ""
	}
	hn, _ := os.Hostname()
	if _, err := boxConsume(dcnDir, approval, mgmtOpPurpose(what, hn, args)); err != nil {
		return "refused: " + what + " changes this machine and " + err.Error()
	}
	standing := what == directiveMirror
	rememberDirective(what, digest, fingerprint, standing, time.Now())
	return ""
}

// directiveWalls is what every directive passes, with an approval or without
// one: anchorOnly (which also refuses on a networked box that is not
// anchored), then the person's local switch. Returns the refusal, or "".
func directiveWalls(self, what string) string {
	if why := anchorOnly(self, what); why != "" {
		return why
	}
	if localDenied(self, localFamilyDirectives) {
		return localDenyRefusal(localFamilyDirectives)
	}
	return ""
}

// ── the directive ledger ─────────────────────────────────────────────────────

const (
	directiveRepeatWindow = 10 * time.Minute
	directiveLedgerFile   = "directive_approvals.json"
)

var directiveLedgerMu sync.Mutex

// directiveLedger: "<what>|<args digest>|<fingerprint>" -> RFC3339 expiry,
// or "" for a standing placement (a mirror), which forgetDirective clears.
type directiveLedger map[string]string

func ledgerKey(what, digest, fingerprint string) string {
	return what + "|" + digest + "|" + fingerprint
}

func directiveLedgerPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, directiveLedgerFile), nil
}

func directiveLedgerLoad() directiveLedger {
	out := directiveLedger{}
	p, err := directiveLedgerPath()
	if err != nil {
		return out
	}
	if raw, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func directiveLedgerSave(l directiveLedger) {
	p, err := directiveLedgerPath()
	if err != nil {
		return
	}
	raw, _ := json.MarshalIndent(l, "", "  ")
	_ = atomicWrite(p, raw)
}

func directiveApproved(what, digest, fingerprint string, now time.Time) bool {
	directiveLedgerMu.Lock()
	defer directiveLedgerMu.Unlock()
	exp, ok := directiveLedgerLoad()[ledgerKey(what, digest, fingerprint)]
	if !ok {
		return false
	}
	if exp == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, exp)
	return err == nil && t.After(now)
}

func rememberDirective(what, digest, fingerprint string, standing bool, now time.Time) {
	directiveLedgerMu.Lock()
	defer directiveLedgerMu.Unlock()
	l := directiveLedgerLoad()
	// One standing entry per kind: a new mirror placement replaces the old.
	for k, exp := range l {
		if strings.HasPrefix(k, what+"|") && (exp == "" || standing) {
			delete(l, k)
			continue
		}
		if t, err := time.Parse(time.RFC3339, exp); err == nil && !t.After(now) {
			delete(l, k)
		}
	}
	if standing {
		l[ledgerKey(what, digest, fingerprint)] = ""
	} else {
		l[ledgerKey(what, digest, fingerprint)] = now.Add(directiveRepeatWindow).UTC().Format(time.RFC3339)
	}
	directiveLedgerSave(l)
}

// forgetDirective drops every remembered act of one kind — a mirror the
// host disabled needs a fresh approval to come back.
func forgetDirective(what string) {
	directiveLedgerMu.Lock()
	defer directiveLedgerMu.Unlock()
	l := directiveLedgerLoad()
	for k := range l {
		if strings.HasPrefix(k, what+"|") {
			delete(l, k)
		}
	}
	directiveLedgerSave(l)
}
