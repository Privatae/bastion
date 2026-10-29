package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const mgmtWorkerCount = 2
const mgmtCmdTimeout = 25 * time.Second

// mgmtFrameMaxBytes is the ceiling on ONE management frame — see the
// SetReadLimit call in handleMgmtConnFor for how the number was derived.
const mgmtFrameMaxBytes = 12 << 20

// p8AllowedOps is the bastion's AUTHORITATIVE allowlist (today: one read-only op). The pod sends
// an op id; the bastion maps it to argv HERE and refuses anything not in this map — so even a
// compromised pod can't make this host run an ungranted command. Signed-grant verification
// sits on top of this; growing the set means validating per-op args.
var p8AllowedOps = map[string][]string{
	"uptime": {"uptime"},
}

type mgmtJob struct {
	Op   string   `json:"op"`
	Args []string `json:"args"`
	// Approval is the person's approval for THIS run of a write op on an
	// anchored box (writes.go / device.go): a device-signed approval or a
	// box-issued approval id, bound to mgmtOpPurpose(op, hostname, args).
	// Ignored for reads and for ops that carry their own approval.
	Approval string `json:"approval,omitempty"`
}

// The no-exec handler families and the root each one is sandboxed to.
type opRoot int

const (
	rootCtx    opRoot = iota // context-store blobs (Config.contextRoot)
	rootBackup               // backup_fetch destination (Config.backupRoot)
	rootDcn                  // per-pairing DCN state: pinned key, grants, audit, stepup
	rootNone                 // computer:* observe ops read the OS, not a configured root
)

type opHandler struct {
	root         opRoot
	unconfigured string
	fn           func(ws *websocket.Conn, root string, args []string)
}

// handlerOps is THE table of dedicated handlers — the switch in handleMgmtConn and
// the enforcing report's vocabulary (enforcing.go) both read it, so a new op cannot
// be answered without being reported, or reported without being answered.
//   - ctx_*: context-store blobs under the sandboxed context root (no exec).
//   - ctx_extract (contextextract.go): the ONE ctx_ op that does exec —
//     it runs a local extractor (pdftotext today) over one document and returns
//     TEXT, so a user's PDF becomes searchable without its bytes ever leaving
//     their machine. Not the p8 exec lane: the tool must be named in
//     contextprep.go's table AND still answer its probe, the argv is built here
//     from a fixed template, and the caller's only inputs are a tool NAME and a
//     body. It shares rootCtx because the scratch file belongs in the pairing's
//     own sandbox and is removed before the reply.
//   - model:* (modelswap.go): the one lane that CHANGES what is on this
//     machine's model store — pull a model onto it, drop one this host placed.
//     Its own caps family ("models"), never folded into "inference": using a
//     loaded model and deciding what gets downloaded onto someone's disk are
//     different permissions. A drop is refused for any model missing from this
//     pairing's ledger, so a model the user pulled themselves cannot be removed
//     through this lane at all.
//   - backup_fetch: PULL a backup artifact from a short-lived signed URL
//     onto this machine; its own root because the user may want a NAS mount.
//   - dcn_*: the box is its own wall — a synced, signature-verified store
//     grant gates every op (root sandbox + excludes + mask). Read vocabulary plus
//     the ONE write lane, dcn_plan_apply (a signed, user-approved MOVE plan;
//     archive-only). dcn_grant_drop pushes a revoke. There is no delete.
//   - stepup_request / stepup_status: the pod files what it wants the user to
//     confirm; the user confirms ON THIS MACHINE with the factor enrolled here
//     (privatae-bastion approvals / approve); the pod polls for the approval id the
//     grant/plan terms must carry (stepup.go). The pod never handles the code.
//   - computer:* (computer.go / computer_tree.go): the OBSERVE
//     rung of governed computer use — installed apps with their ways in, the
//     open windows, and one app's accessibility tree (computer:tree, args
//     [pid, max_nodes?]). Read-only; no injection lives here. Like every op they
//     need a signed grant on the pod side, where a deny beats an allow.
//   - observe:* (observe_ops.go): read-only ROOT ops for the networked
//     bastion — host posture (the same fields the host's own probe reports), listening
//     sockets, firewall text, failed units and timers, disk, kernel log, the
//     cluster (control planes only, via a read-only kubeconfig placed at
//     install), and a tcp/tls/http probe from this box. Fixed argvs only; the
//     one caller value (observe:net's host[:port]) is charset-checked and goes
//     to net.Dial, never to a program. Same grant rule as every other op.
//   - observe:alerts / observe:metrics / observe:logs (observe_pull.go):
//     the PULL half of that family — HTTP reads of the Alertmanager, Prometheus
//     and Loki named by the admin in /etc/privatae-bastion/observe-endpoints.json
//     (observe_endpoints.go), which are private-network addresses only. Nothing
//     is exec'd, so the discipline here is a fixed QUERY TABLE instead of a
//     fixed argv: the host sends a NAME, the box owns the PromQL and the LogQL,
//     and an unknown name is refused with the known ones listed.
//   - observe:folders / observe:journal / observe:logins / observe:cert
//     (observe_reads.go): the questions a host otherwise handed the person as
//     a command — the largest folders under a path, one unit's recent journal,
//     sshd's failed and accepted logins, the certificate a local port serves.
//     Their caller values are a path, a unit name, a number and a port with a
//     server name, each checked against a written grammar before use. The
//     one caller string that reaches a program is the unit name, and only
//     once this machine's own unit list names it; a window reaches journalctl
//     only as a number this box parsed and wrote back out.
var handlerOps = map[string]opHandler{
	"computer:inventory": {rootNone, "", handleComputerInventory},
	"computer:windows":   {rootNone, "", handleComputerWindows},
	"computer:tree":      {rootNone, "", handleComputerTree},
	"observe:host":       {rootNone, "", handleObserveHost},
	"observe:sockets":    {rootNone, "", handleObserveSockets},
	"observe:firewall":   {rootNone, "", handleObserveFirewall},
	"observe:units":      {rootNone, "", handleObserveUnits},
	"observe:disk":       {rootNone, "", handleObserveDisk},
	"observe:kernel":     {rootNone, "", handleObserveKernel},
	"observe:k8s":        {rootNone, "", handleObserveK8s},
	"observe:net":        {rootNone, "", handleObserveNet},
	"observe:alerts":     {rootNone, "", handleObserveAlerts},
	"observe:metrics":    {rootNone, "", handleObserveMetrics},
	"observe:logs":       {rootNone, "", handleObserveLogs},
	"observe:folders":    {rootNone, "", handleObserveFolders},
	"observe:journal":    {rootNone, "", handleObserveJournal},
	"observe:logins":     {rootNone, "", handleObserveLogins},
	"observe:cert":       {rootNone, "", handleObserveCert},
	"ctx_put":            {rootCtx, "context store not configured", handleCtxPut},
	"ctx_get":            {rootCtx, "context store not configured", handleCtxGet},
	"ctx_del":            {rootCtx, "context store not configured", handleCtxDel},
	"ctx_extract":        {rootCtx, "context store not configured", handleCtxExtract},
	"backup_fetch":       {rootBackup, "backup destination not configured", handleBackupFetch},
	// backup_push (backuppush.go): send a backup file held here to a signed
	// upload URL, the way back for a backup kept only on this machine.
	"backup_push": {rootBackup, "backup destination not configured", handleBackupPush},
	// backup_list (backuplist.go): the backups held here for this host, in its
	// own folder and in folders the person shared with it, with digests.
	"backup_list": {rootBackup, "backup destination not configured", handleBackupList},
	// backup_reseal (backupreseal.go): the host asks for one backup's key,
	// sealed to it; the person decides on this machine. rootDcn: the requests
	// are the pairing's own state, so one host never reads another's.
	"backup_reseal":  {rootDcn, "dcn store not configured", handleBackupReseal},
	"dcn_grant_sync": {rootDcn, "dcn store not configured", handleDcnGrantSync},
	"dcn_grant_drop": {rootDcn, "dcn store not configured", handleDcnGrantDrop},
	// Reach grants for the service slot (service_reach.go): the same grant file
	// and pinned key as the store grants above, so the same pairing dir.
	"service_grant_sync": {rootDcn, "dcn store not configured", handleServiceGrantSync},
	"service_grant_drop": {rootDcn, "dcn store not configured", handleServiceGrantDrop},
	"dcn_list":           {rootDcn, "dcn store not configured", handleDcnList},
	"dcn_stat":           {rootDcn, "dcn store not configured", handleDcnStat},
	"dcn_read_range":     {rootDcn, "dcn store not configured", handleDcnReadRange},
	"dcn_search":         {rootDcn, "dcn store not configured", handleDcnSearch},
	"dcn_catalog":        {rootDcn, "dcn store not configured", handleDcnCatalog},
	"dcn_plan_apply":     {rootDcn, "dcn store not configured", handleDcnPlanApply},
	"stepup_request":     {rootDcn, "dcn store not configured", handleStepupRequest},
	"stepup_status":      {rootDcn, "dcn store not configured", handleStepupStatus},
	// device_* (device.go): the pod files an ask on the person's OWN bastion
	// (the approval device) and reads back the signed answer. rootNone: the
	// device's requests are box-level (one person, one device), not a
	// per-pairing root.
	"device_request": {rootNone, "", handleDeviceRequest},
	"device_status":  {rootNone, "", handleDeviceStatus},
	// op_* (ops.go / ops_exec_linux.go): an op the host wrote, held under
	// signed terms and run in a sandbox. rootDcn: the op store and ops.json
	// sit beside the pairing's grants, and the terms verify under its key.
	// op_grant_drop <grant|all> (ops_bounds.go) takes a held grant back: a
	// tighten (writes.go opTightens), so no quarantine or approval holds it.
	"op_sync":       {rootDcn, "dcn store not configured", handleOpSync},
	"op_dry_run":    {rootDcn, "dcn store not configured", handleOpDryRun},
	"op_apply":      {rootDcn, "dcn store not configured", handleOpApply},
	"op_grant_run":  {rootDcn, "dcn store not configured", handleOpGrantRun},
	"op_grant_drop": {rootDcn, "dcn store not configured", handleOpGrantDrop},
	"op_list":       {rootDcn, "dcn store not configured", handleOpList},
	"op_run_status": {rootDcn, "dcn store not configured", handleOpRunStatus},
	// op_plan_* (ops_plan.go): a line of a ship plan the person's device
	// signed, and its undo.
	"op_plan_line":   {rootDcn, "dcn store not configured", handlePlanLine},
	"op_plan_undo":   {rootDcn, "dcn store not configured", handlePlanUndo},
	"op_plan_status": {rootDcn, "dcn store not configured", handlePlanStatus},
	// model:* (modelswap.go): change WHICH models are on this machine.
	// rootDcn for the same reason stepup_* uses it — it is the PAIRING's own
	// state directory, and the ownership ledger that decides what this host may
	// drop has to be per-pairing or one host could remove what another placed.
	"model:list": {rootDcn, "per-pairing state not configured", handleModelList},
	"model:pull": {rootDcn, "per-pairing state not configured", handleModelPull},
	"model:drop": {rootDcn, "per-pairing state not configured", handleModelDrop},
	// pairing_* (anchor.go / pairing_ops.go): the ANCHOR host's
	// lane for approving, revoking and listing the other pairings on this box,
	// for consenting to a rotation, and for redeeming a pairing token
	// another host asked it to redeem here. rootNone: they read box-level state
	// beside the pairings, not a per-pairing root. Answered only on the anchor
	// pairing's own mgmt connection — handleMgmtConnFor refuses them from any
	// other pairing before the handler runs, which is the whole reason
	// pairing_redeem carries this prefix instead of a name of its own.
	"pairing_grant_sync":     {rootNone, "", handlePairingGrantSync},
	"pairing_grant_drop":     {rootNone, "", handlePairingGrantDrop},
	"pairing_list":           {rootNone, "", handlePairingList},
	"pairing_anchor_consent": {rootNone, "", handlePairingAnchorConsent},
	"pairing_redeem":         {rootNone, "", handlePairingRedeem},
	// audit_fetch (mgmt_audit.go): read the box-level record of
	// what has been ASKED of this machine on this lane. rootNone for the same
	// reason pairing_* uses it — the file sits beside the pairings, not inside
	// one. Anchor-directed: the gate is below in handleMgmtConnFor, because the
	// file names every pairing and a handler is given no identity to filter on.
	mgmtAuditFetchOp: {rootNone, "", handleAuditFetch},
	// Standing coder grants (coder_grant.go): the same grant file and pinned
	// key as the reach grants above, so the same pairing dir.
	"coder_grant_sync": {rootDcn, "dcn store not configured", handleCoderGrantSync},
	"coder_grant_drop": {rootDcn, "dcn store not configured", handleCoderGrantDrop},
}

// ── accounting on this lane (mgmt_audit.go) ────────────────────────────────
//
// The line for a job is written where the job ENDS, which is sendMgmtExit —
// the single funnel every exit on this lane already passes through — and never
// at the call sites alone. Two things forced that, and both are properties of
// the code rather than preferences:
//
//   - A handler in handlerOps writes its own X frame and returns nothing, and
//     there are twenty-odd of them. An allowed line must carry the code the box
//     actually sent, so anything other than reading it off the funnel means the
//     audit and the wire can disagree, which is the one thing an audit may not
//     do. A second return value on every handler would say the same thing in
//     twenty more places and drift in one of them.
//   - A new exit added to this lane cannot then be forgotten. It is the same
//     argument handlerOps itself makes one comment up: one table, so an op
//     cannot be answered without being reported.
//
// The refusal sites still name themselves, through refuseMgmt, because the
// REASON is theirs and nothing downstream can reconstruct it. refuseMgmt writes
// the line before it sends a single frame — a refusal is the half of this file
// somebody will go looking for, and a crash between deciding and writing would
// lose exactly that one.
//
// One connection serves exactly one job (handleMgmtConnFor) on one goroutine,
// so the account below is touched by that goroutine only and needs no lock; the
// map is shared across the worker pool and does.
type mgmtAccount struct {
	self string
	op   string // "" when the frame did not parse: the box does not know
	// args is what the host passed, so the observe shelf can record WHAT was
	// asked beside the result. Seven ops read a caller value — observe:net
	// (host[:port]), observe:metrics (a name), observe:logs (a name and an
	// optional window), observe:folders (a path and a depth), observe:journal
	// (a unit and a window), observe:logins (hours) and observe:cert (a port
	// and a server name); the rest ignore theirs. The shelf records args only
	// for those seven, bounded (machinestore.go observeArgsRecorded): the first
	// version recorded whatever the host sent for every op, unbounded, and
	// this comment — which said only one op took a value — made that look safe.
	args []string
	// fam is the family the op is JUDGED on, which is not always the one its
	// name resolves to: a step-up is gated on the family of the thing being
	// approved (stepupOpFamily), so opFamily's "stepup" floor would put a
	// family in the record that contradicts the refusal string printed beside
	// it. Seeded from the name and overwritten once the gate resolves it.
	fam string
	// approval identifies the approval a gated write spent — "device:<nonce>"
	// or "console:<id>" — for the audit line; "" for reads and ungated ops.
	approval string
	written  bool
}

var mgmtAccounts sync.Map // *websocket.Conn -> *mgmtAccount

func beginMgmtAccount(ws *websocket.Conn, self, op string, args []string) {
	mgmtAccounts.Store(ws, &mgmtAccount{self: self, op: op, args: args, fam: opFamily(op)})
}

// mgmtAccountOf is the record for this connection, or nil. Read by the observe
// shelf to learn which op produced a result and which host asked, without the
// observe handlers having to be told either.
func mgmtAccountOf(ws *websocket.Conn) *mgmtAccount {
	if v, ok := mgmtAccounts.Load(ws); ok {
		return v.(*mgmtAccount)
	}
	return nil
}

// setMgmtAccountFamily records the family this job was actually judged on, for
// the one lane whose family is not a property of its op name.
func setMgmtAccountFamily(ws *websocket.Conn, fam string) {
	if v, ok := mgmtAccounts.Load(ws); ok {
		v.(*mgmtAccount).fam = fam
	}
}

// setMgmtAccountApproval records which approval a gated write spent.
func setMgmtAccountApproval(ws *websocket.Conn, id string) {
	if v, ok := mgmtAccounts.Load(ws); ok {
		v.(*mgmtAccount).approval = id
	}
}

// finishMgmtAccount writes this job's one line, once. A second call is a no-op,
// which is what makes refuseMgmt's early write and sendMgmtExit's default
// compose instead of double-counting.
func finishMgmtAccount(ws *websocket.Conn, verdict, why string, exit int) {
	v, ok := mgmtAccounts.Load(ws)
	if !ok {
		return
	}
	a := v.(*mgmtAccount)
	if a.written {
		return
	}
	a.written = true
	mgmtAudit(a.self, a.op, a.fam, verdict, why, exit, a.args, a.approval)
}

// refuseMgmt accounts for a refusal and then sends it: stderr + 126, the shape
// every refusal on this lane has always had.
func refuseMgmt(ws *websocket.Conn, why string) {
	// The box's own notice of abuse (quarantine.go): every refusal goes on the
	// ring; a refused WRITE from a named pairing counts toward closing that
	// pairing's write lanes. Before the audit line so the two cannot disagree
	// about what was refused.
	if a := mgmtAccountOf(ws); a != nil && a.op != "" {
		noteRefusal(a.self, a.op, why, refusalCounts(a.op, why), time.Now())
	}
	finishMgmtAccount(ws, auditRefused, why, 126)
	sendMgmt(ws, 'R', []byte(why+"\n"))
	sendMgmtExit(ws, 126)
}

// runMgmtWorkers opens a pool of worker WebSockets to the host's /bastion-mgmt lane and serves one
// command job per worker, reconnecting after each. Mirrors runEgressWorkers: the host can't reach
// the bastion's tunnel IP, so the bastion dials out to the host and parks until a job arrives.
//
// pctx is the PAIRING's context (run.go): a pairing the anchor revokes has its
// context cancelled, and the workers must stop re-dialing rather than spin on a
// closed tunnel for the life of the process. self is the pairing's host name —
// the identity the pairing_* ops are gated on.
func runMgmtWorkers(pctx context.Context, self string, wsURL string, tlsCfg *tls.Config,
	dialHost func(ctx context.Context) (net.Conn, error), bearer, ctxRoot, dcnDir, backupRoot string, n int) {
	dialer := &websocket.Dialer{
		NetDialContext:   func(ctx context.Context, network, addr string) (net.Conn, error) { return dialHost(ctx) },
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 20 * time.Second,
	}
	for i := 0; i < n; i++ {
		go func() {
			for pctx.Err() == nil {
				ctx, cancel := context.WithTimeout(pctx, 25*time.Second)
				ws, _, err := dialer.DialContext(ctx, wsURL, http.Header{})
				cancel()
				if err != nil {
					sleepCtx(pctx, 3*time.Second)
					continue
				}
				if err := ws.WriteMessage(websocket.TextMessage, []byte("BEARER "+bearer)); err != nil {
					_ = ws.Close()
					sleepCtx(pctx, time.Second)
					continue
				}
				stopKA := armWSKeepalive(ws) // ping/read-deadline: a dead tunnel unblocks the park
				// A revoke while parked: closing the socket is what unblocks the read.
				unpark := context.AfterFunc(pctx, func() { _ = ws.Close() })
				handleMgmtConnFor(ws, self, ctxRoot, dcnDir, backupRoot) // blocks until a job, serves it, then returns
				unpark()
				stopKA()
				_ = ws.Close()
			}
		}()
	}
}

// sleepCtx sleeps d or until ctx is done, whichever is first.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// handleMgmtConn serves ONE management job: read the C frame, resolve the op against the local
// allowlist (the authoritative wall), run it, and stream O/R + a terminal X(exit). A refusal is
// reported as stderr + exit 126. It NEVER runs anything outside p8AllowedOps.
func handleMgmtConn(ws *websocket.Conn, ctxRoot, dcnDir, backupRoot string) {
	handleMgmtConnFor(ws, "", ctxRoot, dcnDir, backupRoot)
}

// handleMgmtConnFor is handleMgmtConn with the pairing's identity. self=="" is
// an anonymous caller (tests, legacy call sites): it can never be the anchor, so
// pairing_* ops are refused, and on an anchored box the caps gate treats it as
// a pairing with no grant (default-deny) — never as the unconstrained anchor.
func handleMgmtConnFor(ws *websocket.Conn, self, ctxRoot, dcnDir, backupRoot string) {
	// The account is per-connection and the connection is about to be closed by
	// the caller; drop the entry so a long-lived process does not accumulate one
	// per job it has ever served.
	defer mgmtAccounts.Delete(ws)

	// BOUND THE FRAME. gorilla enforces a read limit only when one is set, and
	// before this line nothing in this program set one anywhere — so a job frame
	// was whatever size the sender chose, read whole into memory, with its op
	// name and arguments carried on into whatever the handler did with them.
	//
	// The number is the largest job this lane legitimately carries, derived and
	// not guessed. That is ctx_extract's INLINE path: a document riding the
	// management frame, capped at ctxExtractMaxBytes = 8 MiB of raw bytes
	// (contextextract.go:57), which is 11,184,812 bytes once base64'd, plus a
	// JSON wrapper of a few hundred. 12 MiB clears that with room and sits above
	// every other declared ceiling on this lane. contextextract.go's own comment
	// has always said the inline path is "capped at ctxExtractMaxBytes by the
	// frame" — this is the line that finally makes that true; the pull path
	// (contextpull.go, 64 MiB) does not come through here and is unaffected.
	ws.SetReadLimit(mgmtFrameMaxBytes)

	mt, data, err := ws.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || len(data) == 0 || data[0] != 'C' {
		// No job was ever stated, so there is nothing to account for. This is a
		// dropped tunnel or a worker being unparked by a revoke, not a request.
		return
	}
	var job mgmtJob
	if err := json.Unmarshal(data[1:], &job); err != nil {
		// Accounted with an EMPTY op, because the frame did not parse and this
		// box genuinely does not know what it was asked for. Recording it anyway
		// is the point: "something on the management lane sent this machine a
		// frame it could not read" is exactly the kind of thing that leaves no
		// trace otherwise, and it is the first thing a tampered or mismatched
		// host would produce.
		beginMgmtAccount(ws, self, "", nil)
		refuseMgmt(ws, "bad job")
		return
	}
	beginMgmtAccount(ws, self, job.Op, job.Args)
	// A NETWORKED BOX WITH NO ANCHOR ANSWERS NOTHING — see
	// unanchoredNetworkedRefusal (anchor.go) for the whole reasoning. Kept here
	// as well as inside capsAllow because the caps gate below only runs on an
	// ANCHORED box, and an unanchored networked one has no anchor to gate
	// against — so without this the whole ceiling would be skipped rather than
	// applied. One predicate, two call sites. (The reason used to be
	// different and narrower: capsAllow let an op through when opFamily(op) was
	// "", so "in no family" had to be refused here or it read as "allowed".
	// capsAllowIn default-denies that case now, at every call site.)
	if why := unanchoredNetworkedRefusal("op '" + job.Op + "'"); why != "" {
		refuseMgmt(ws, why)
		return
	}
	// Anchor-only ops (anchor.go): the pairing that IS the anchor host is the
	// only one that may approve, revoke or list pairings, or consent to a
	// rotation. Everyone else is refused here, before any handler runs.
	if strings.HasPrefix(job.Op, "pairing_") {
		if a := currentAnchor(); a == nil || self == "" || a.AnchorHost != self {
			refuseMgmt(ws, "refused: op '"+job.Op+"' is answered only on the anchor host's pairing")
			return
		}
	}
	// audit_fetch is ANCHOR-DIRECTED, through the existing predicate rather than
	// the pairing_* rule above (mgmt_audit.go).
	//
	// The file it serves is box-level: it names every pairing that has asked
	// this machine for anything. On an ANCHORED box that makes an ungated fetch
	// a cross-pairing read — one member host learning which ops another member
	// was refused — so only the anchor, whose user is the admin of this machine,
	// may take it. On a LOCAL box there is exactly one host and nothing to leak
	// between, and anchorOnly (anchor.go:512-524) already draws that line in one
	// place: it falls through to unanchoredNetworkedRefusal, which is empty on a
	// local box and a refusal on a networked one. The pairing_* rule above
	// cannot be reused for this, because it refuses outright when the box has no
	// anchor, and that would put the record of a single-user machine out of
	// reach of the only host paired to it.
	if job.Op == mgmtAuditFetchOp {
		if why := anchorOnly(self, "op '"+job.Op+"'"); why != "" {
			refuseMgmt(ws, why)
			return
		}
	}
	// Caps ceiling (anchor.go): on an anchored box a member pairing may only be
	// asked for op families its pairing grant names. Deny beats allow, and an op
	// in NO family is denied too — see capsAllowIn.
	//
	// ASKED ON EVERY BOX, NOT ONLY AN ANCHORED ONE. This was `if a != nil`, so
	// a local bastion never consulted the ceiling at all — and once the machine
	// admin's own off switch moved inside capsAllow, that made the switch a
	// no-op on exactly the machines it was built for.
	// capsAllow returns "" for an unanchored local box unless something is
	// switched off, so asking it always costs one map lookup and can only ever
	// refuse.
	gateSelf := self
	if gateSelf == "" && currentAnchor() != nil {
		// Anonymous on an ANCHORED box: not the anchor, holds no grant, so it
		// is default-denied below. The substitution stays anchored-only — on an
		// unanchored box it would replace the pairing's own name with a
		// placeholder the per-host deny list could never match.
		gateSelf = "-"
	}
	// stepup_* is gated on the family of the thing being APPROVED, resolved from
	// the request itself (stepupOpFamily, stepup.go), because a step-up is the
	// approval step of another capability rather than one of its own. Every
	// other op's family is a property of its name. The resolved family is what
	// the local off switch is consulted with too, so switching a family off here
	// also stops the host raising an approval prompt for it.
	fam := opFamily(job.Op)
	if strings.HasPrefix(job.Op, "stepup_") {
		fam = stepupOpFamily(job.Op, dcnDir, job.Args)
		// The accounting line records the family the op was actually judged on,
		// not the "stepup" floor its name resolves to — the refusal string names
		// the resolved one, and a record that disagreed with the reason beside
		// it would be worse than no record.
		setMgmtAccountFamily(ws, fam)
	}
	if why := capsAllowIn(gateSelf, job.Op, fam); why != "" {
		refuseMgmt(ws, why)
		return

	}
	// Dedicated no-exec handlers (one table — handlerOps — so the enforcing report's
	// op vocabulary can never drift from what this switch answers). Each family has
	// its own root; an unconfigured root refuses like an unpermitted op.
	h, handled := handlerOps[job.Op]
	argv, allowlisted := p8AllowedOps[job.Op]
	if !handled && !allowlisted {
		refuseMgmt(ws, "refused: op '"+job.Op+"' not permitted on this host")
		return
	}
	root := ""
	if handled {
		switch h.root {
		case rootCtx:
			root = ctxRoot
		case rootBackup:
			root = backupRoot
			if root != "" {
				// A read (backup_list) finds the folder or not; only a
				// backup op that writes creates it (writes.go opWrites).
				if why := backupRootReady(self, root, opWrites(job.Op)); why != "" {
					refuseMgmt(ws, why)
					return
				}
			}
		case rootDcn:
			root = dcnDir
		case rootNone:
			root = "-" // nothing to configure; the handler ignores it
		}
		if root == "" {
			refuseMgmt(ws, h.unconfigured)
			return
		}
	}
	// THE WRITE GATE (writes.go, device.go). On an anchored box, an op that
	// CHANGES this machine runs only with a live approval this box verified —
	// from the person's device or this console — bound to this op, this
	// machine and exactly these arguments. The caps ceiling above says which
	// families a pairing may be asked for; this says that asking is not
	// running. It holds for the anchor pairing too: before this, the anchor
	// host's word was the only check on every write across a fleet anchored
	// to it (capsAllowIn passes the anchor above the family check).
	//
	// LAST, after the op is known and its root is configured: an unknown op
	// or an unconfigured root is refused for that reason and spends no
	// approval. The approval is SPENT here, before the handler runs
	// (consumeApproval) — a handler that then refuses on its own argument
	// check has cost the person a tap, and the host asks again; the other
	// order left a window in which a second worker could pass on the same
	// approval while a slow handler was still running.
	approvalID, why := writeGate(gateSelf, dcnDir, job)
	if why != "" {
		refuseMgmt(ws, why)
		return
	}
	if approvalID != "" {
		setMgmtAccountApproval(ws, approvalID)
	}
	if handled {
		// ALLOWED from here: the handler writes its own frames, and its exit is
		// accounted for inside sendMgmtExit. The verdict is about the WALL, not
		// the outcome — this op got past every gate above, and a handler that
		// then failed on a bad argument is a different event from one that was
		// never allowed to run, which is precisely the distinction the host's
		// posture engine acts on.
		h.fn(ws, root, job.Args)
		return
	}
	// Allowlisted ops take a FIXED argv (caller args ignored); an op that ever accepts args must validate them per op.
	ctx, cancel := context.WithTimeout(context.Background(), mgmtCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	hideConsole(cmd) // console_windows.go
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	if out.Len() > 0 {
		sendMgmt(ws, 'O', out.Bytes())
	}
	if errb.Len() > 0 {
		sendMgmt(ws, 'R', errb.Bytes())
	}
	code := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			sendMgmt(ws, 'R', []byte(runErr.Error()+"\n"))
			code = 1
		}
	}
	sendMgmtExit(ws, code)
}

func sendMgmt(ws *websocket.Conn, tag byte, payload []byte) {
	_ = ws.WriteMessage(websocket.BinaryMessage, append([]byte{tag}, payload...))
}

func sendMgmtExit(ws *websocket.Conn, code int) {
	// The job's accounting line, written BEFORE the terminal frame goes out so
	// the record exists by the time the host is told anything. "allowed" is the
	// default because a refusal has already written its own line with its reason
	// (refuseMgmt) and finishMgmtAccount writes only once.
	finishMgmtAccount(ws, auditAllowed, "", code)
	sendMgmt(ws, 'X', []byte(strconv.Itoa(code)))
}
