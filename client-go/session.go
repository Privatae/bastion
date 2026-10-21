package main

// The session lane: an interactive
// terminal that runs ON this machine and is streamed to the host over the SAME reverse
// WebSocket workers the harness lane uses. Nothing new on the network — no inbound
// port, no SSH server — the tunnel already exists and the box dialled it.
//
// Wire contract (one WebSocket = one session; every frame is a BINARY message whose
// first byte is the tag):
//
//	host -> box   'S' + JSON sessionSpec     first frame, opens the session
//	host -> box   'I' + bytes                keyboard input for the pty
//	host -> box   'R' + JSON {"cols":N,"rows":N}   terminal resize
//	box  -> host  'O' + bytes                pty output
//	box  -> host  'E' + text                 a plain-words error or notice (may precede X)
//	box  -> host  'X' + decimal exit code    the session is over; the socket closes after it
//
// One more op rides the same S frame: session:root:exec runs ONE command as root,
// with no terminal, under a standing grant the person gave at this machine
// (rootexec.go has its contract and its walls). It answers 'J' + JSON result, then X.
//
// Exit codes on X: the shell's own exit status when it ended by itself; 126 when the
// box REFUSED (no grant, denied by grant, root without step-up, caps) — the same shape
// an ungranted mgmt op returns, so the host reads both the same way; 1 for a bad spec
// or a box that cannot do this (Windows today); 124 when the box closed it on a timer
// (idle or hard cap), echoing the coreutils `timeout` convention.
//
// Gating: a session is a management op. The pod passes the user's SIGNED mgmt grant
// (the same record the host's management-op gate enforces) in the spec; the box re-verifies it against
// the entity key it pinned at first dcn_grant_sync and refuses unless the grant lists
// the op for this server and does not deny it. The box is its own wall: a pod that
// forges or widens a grant gets 126 here regardless of what it decided for itself.
//
// Privilege: session:open runs as an unprivileged user when the daemon is root
// (privatae-session if that account exists, else nobody); as the daemon's own user
// otherwise. session:root runs as root only when the daemon is root, the grant lists
// session:root, AND the user approved THIS session on this machine with the enrolled
// second factor (stepup.go). The pod never sees the code.
//
// Every session is written to <context root>/sessions/<session_id>.log (0600; output
// only — input echoes, passwords do not) and recorded in the pairing's audit.jsonl
// with start, stop, and exit. Closing the socket kills the shell's whole process group.

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// sessionWorkerCount is the session pool per pairing: four parked sockets, so four
// terminals can be open on one box at once without touching the harness workers.
const sessionWorkerCount = 4

// runSessionWorkers parks n workers on the host's /bastion-harness endpoint with the
// hello line `BEARER <bearer> lane=session`, so the host can hand S frames only to
// these and H frames only to the plain harness workers. Same reverse-dial shape as
// runHarnessWorkers: the host cannot reach the box, so the box parks here.
//
// pctx is the pairing's context: revoking a pairing must end its terminals and stop
// the re-dial, exactly as it does for the harness and mgmt lanes (run.go supervisor).
// self is the pairing this pool belongs to, for the caps gate on an anchored box.
func runSessionWorkers(pctx context.Context, self string, wsURL string, tlsCfg *tls.Config,
	dialHost func(ctx context.Context) (net.Conn, error), bearer string, n int, senv sessionEnv) {
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
				if err := ws.WriteMessage(websocket.TextMessage, []byte("BEARER "+bearer+" lane=session")); err != nil {
					_ = ws.Close()
					sleepCtx(pctx, time.Second)
					continue
				}
				stopKA := armWSKeepalive(ws)
				// A revoked pairing closes the socket under the session, which ends the
				// shell through the same path a host disconnect takes.
				unpark := context.AfterFunc(pctx, func() { _ = ws.Close() })
				handleSessionWorkerConn(ws, self, senv) // blocks for the life of one session
				unpark()
				stopKA()
				_ = ws.Close()
			}
		}()
	}
}

// handleSessionWorkerConn reads the first frame on a session worker: S opens a
// session; an H frame is refused with a plain line (harness jobs belong on the
// harness workers) so a host that routes wrongly learns it at once.
func handleSessionWorkerConn(ws *websocket.Conn, self string, senv sessionEnv) {
	mt, data, err := ws.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || len(data) == 0 {
		return
	}
	switch data[0] {
	case 'S':
		handleSessionConn(ws, data, self, senv)
	case 'H':
		sendSession(ws, 'E', []byte("this is a session worker (lane=session); harness jobs go to a harness worker\n"))
		sendSessionExit(ws, 1)
	}
}

const (
	sessionOpOpen = "session:open"
	sessionOpRoot = "session:root"
)

// sessionOps is what the enforcing report advertises for this lane (enforcing.go
// folds it into mgmt_ops) so a grant can name them. They are NOT in handlerOps: they
// ride the harness workers, not the C-frame mgmt lane.
var sessionOps = []string{sessionOpOpen, sessionOpRoot, sessionOpRootExec}

// Timers. Idle = no keyboard input from the host; a session someone is watching but
// not typing into still ends at 30 minutes, because an unattended root shell is the
// risk this exists to bound. Both are package vars so tests can shorten them.
var (
	sessionIdleTimeout = 30 * time.Minute
	sessionHardCap     = 8 * time.Hour
	sessionKillGrace   = 3 * time.Second
	sessionIdleCheck   = 15 * time.Second // how often the idle clock is looked at
)

// sessionSpec is the S-frame body.
type sessionSpec struct {
	Op        string `json:"op"`              // session:open | session:root
	Shell     string `json:"shell"`           // "" = the session user's login shell, else must be listed in /etc/shells
	Cols      int    `json:"cols"`            // initial window; 0 = 80
	Rows      int    `json:"rows"`            // initial window; 0 = 24
	GrantB64  string `json:"grant_terms_b64"` // the EXACT signed bytes of the user's mgmt grant
	SigB64    string `json:"grant_sig_b64"`   // b64 ed25519 signature over those bytes
	SessionID string `json:"session_id"`      // host-minted id; names the transcript + audit rows
	// The host's OWN entity signing key, so a box that has never synced a DCN
	// store grant can still pin it and verify the grant above. TOFU, first use
	// only — see sessionVerifyGrant. Absent on an older host; then the box falls
	// back to whatever a DCN sync pinned, which is exactly today's behaviour.
	VerifyPubkey string `json:"verify_pubkey"`
	Approval     string `json:"approval"` // session:root only: the step-up approval id issued on this box
	// session:root:exec only (rootexec.go): the command, and the host's asks
	// for its deadline and output size, each held to this box's ceiling.
	Command        string `json:"command,omitempty"`
	DeadlineS      int    `json:"deadline_s,omitempty"`
	MaxOutputBytes int    `json:"max_output_bytes,omitempty"`
}

type sessionResize struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// sessionEnv is what the worker hands the handler: where this pairing keeps its
// state, which host it serves, and what this machine is called in grants.
type sessionEnv struct {
	CtxRoot  string // transcripts live under <CtxRoot>/sessions
	DcnDir   string // pinned entity key + audit.jsonl + step-up state
	HostName string // the pairing (host) this worker serves — for the caps hook
	Server   string // this machine's hostname, the `server` a grant names
}

// sessionGrantTerms is parsed FROM the verified signed bytes only — the shape the
// host signs when it approves a mgmt grant: {entity, server, ops, deny, intent, expires}.
type sessionGrantTerms struct {
	Entity  int64    `json:"entity"`
	Server  string   `json:"server"`
	Ops     []string `json:"ops"`
	Deny    []string `json:"deny"`
	Expires string   `json:"expires"`
}

// sessionProc is a running shell behind a pty. The real one (session_unix.go) wraps
// creack/pty; tests substitute a fake through sessionSpawn.
type sessionProc interface {
	io.Reader // pty output
	io.Writer // pty input
	Resize(cols, rows int) error
	Wait() int // blocks until the shell exits; returns its exit code
	Kill()     // ends the whole process group; idempotent
	User() string
	Shell() string
}

// sessionSpawn is the platform spawner (session_unix.go / session_windows.go). A var
// so tests can stand in a fake process.
var sessionSpawn = spawnSessionProc

// sessionAllowedByCaps applies the pairing caps an anchor granted this host
// (anchor.go capsAllow, merged with the anchoring lane). It returns the box's own
// refusal words, or "" when the pairing may open a session here.
//
// Two walls, not one: this says whether the ANCHOR let this host have terminals on
// this machine at all, and sessionVerifyGrant below says whether the host's own user
// signed a grant listing the op. An unanchored LOCAL box has no anchor to ask, so
// capsAllow returns "" unless the person at the machine has switched `session`
// off on it (localdeny.go) — otherwise the signed grant is the only wall, the
// same shape the mgmt lane uses. An unanchored NETWORKED box is refused here outright from
// 0.24.0: capsAllow carries the gate, so session:open never reaches the grant
// check and session:root never reaches the step-up.
func sessionAllowedByCaps(pairingHostName string) string {
	return capsAllow(pairingHostName, sessionOpOpen)
}

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$`)

func sendSession(ws *websocket.Conn, tag byte, payload []byte) {
	_ = ws.WriteMessage(websocket.BinaryMessage, append([]byte{tag}, payload...))
}

func sendSessionExit(ws *websocket.Conn, code int) {
	sendSession(ws, 'X', []byte(strconv.Itoa(code)))
}

// sessionRefuse is the refusal shape: E + why, then X 126 — read by the host exactly
// like an ungranted mgmt op.
func sessionRefuse(ws *websocket.Conn, env sessionEnv, spec sessionSpec, why string) {
	sessionAudit(env.DcnDir, spec.Op, spec.SessionID, "", "refused", 126, why)
	sendSession(ws, 'E', []byte(why+"\n"))
	sendSessionExit(ws, 126)
}

// sessionAudit appends one row to the pairing's audit.jsonl — the same file every
// dcn/stepup decision lands in, with the fields a session needs (who it ran as, which
// event, the exit). Best-effort like dcnAudit: a refusal stands whether or not the
// line lands.
func sessionAudit(dir, op, sessionID, user, event string, exit int, detail string) {
	if dir == "" {
		return
	}
	rec, _ := json.Marshal(map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "op": op, "session_id": sessionID,
		"user": user, "event": event, "exit": exit, "decision": detail,
	})
	fh, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	_, _ = fh.Write(append(rec, '\n'))
}

// sessionPinOfferedKey is the pin half of sessionVerifyGrant on its own, for a
// session frame that carries no grant (0.39.0): the host's offered key is
// pinned under the same rules (pinVerifyKey — first use only on a local box,
// never over the anchoring pin on an anchored one), and a key that disagrees
// with the pinned one refuses the session. "" when there is nothing to pin
// or nothing to refuse.
func sessionPinOfferedKey(dcnDir, pairing, offeredKey string) string {
	if dcnDir == "" || strings.TrimSpace(offeredKey) == "" {
		return ""
	}
	f, err := dcnLoadFile(dcnDir)
	if err != nil {
		return "grant store unreadable"
	}
	pinned, why := pinVerifyKey(f, pairing, offeredKey)
	if why != "" {
		return why
	}
	if pinned {
		if e := dcnSaveFile(dcnDir, f); e != nil {
			return "could not pin the host key: " + e.Error()
		}
	}
	return ""
}

// sessionVerifyGrant re-verifies the pod-supplied grant against the entity key this
// box pinned, then applies the same decision rule the host applies: the
// server must match (or be '*'), a deny of the op or '*' beats everything, and the
// op must be listed. Returns the parsed terms on success, a plain-words reason on
// refusal. Since 0.39.0 it runs only for a frame that PRESENTS a grant
// (handleSessionConn); a frame without one goes through sessionPinOfferedKey.
func sessionVerifyGrant(dcnDir, pairing, server, op, termsB64, sigB64, offeredKey string) (*sessionGrantTerms, error) {
	if dcnDir == "" {
		return nil, fmt.Errorf("no grant state on this box (default-deny)")
	}
	f, err := dcnLoadFile(dcnDir)
	if err != nil {
		return nil, fmt.Errorf("grant store unreadable")
	}
	// TOFU-PIN THE HOST KEY FROM THE SESSION FRAME ITSELF.
	//
	// Until 0.24.3 the only writer of this field was a DCN store sync
	// (dcn.go), so a terminal required a FOLDER
	// GRANT on the machine first — two different permissions welded together by
	// where the key happened to live. Measured across one deployment: 19 of 20
	// online machines held zero DCN grants, so the host could not open a terminal
	// on any of them, and the refusal said "sync a grant first" — which reads as advice
	// and is really a coupling.
	//
	// The trust basis is identical to the DCN pin and this is deliberately the
	// same shape: the lane is mTLS + bearer to the host this box enrolled with,
	// the box only ever talks to that host, and a key that disagrees with one
	// already pinned is REFUSED rather than re-pinned. So this widens nothing —
	// it lets the same pin arrive by the lane that needs it.
	// On an ANCHORED box the key comes from anchoring, never from this offer —
	// pinVerifyKey (dcn.go) holds both rules in one place.
	pinned, why := pinVerifyKey(f, pairing, offeredKey)
	if why != "" {
		return nil, fmt.Errorf("%s", why)
	}
	if pinned {
		if e := dcnSaveFile(dcnDir, f); e != nil {
			return nil, fmt.Errorf("could not pin the host key: %v", e)
		}
	}
	if f.VerifyPubkey == "" {
		return nil, fmt.Errorf("no entity key pinned on this box yet (default-deny) — this host is too old to offer one; sync a grant first")
	}
	pub, err := base64.StdEncoding.DecodeString(f.VerifyPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad pinned verify key")
	}
	if termsB64 == "" || sigB64 == "" {
		return nil, fmt.Errorf("no signed grant presented (default-deny)")
	}
	canonical, err := base64.StdEncoding.DecodeString(termsB64)
	if err != nil {
		return nil, fmt.Errorf("bad grant encoding")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("bad grant signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sig) {
		return nil, fmt.Errorf("grant signature does not verify on this box")
	}
	var t sessionGrantTerms
	if err := json.Unmarshal(canonical, &t); err != nil {
		return nil, fmt.Errorf("signed grant unparsable")
	}
	// A MANAGEMENT grant carries no `kind` (the host has never signed one
	// with it), while every other record the entity key signs does — a store
	// grant, a move plan, a reach grant. So a record that declares ANY kind is
	// not a management grant and cannot open a terminal, whatever else it says.
	var kinded struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(canonical, &kinded) == nil && kinded.Kind != "" {
		return nil, fmt.Errorf("signed record is a %q, not a management grant", kinded.Kind)
	}
	// NO OPEN-ENDED TERMS (dcn.go dcnVerifyRec says why).
	exp, err := time.Parse(time.RFC3339, t.Expires)
	if err != nil {
		return nil, fmt.Errorf("grant states no expiry (open-ended terms are refused)")
	}
	if !exp.After(time.Now()) {
		return nil, fmt.Errorf("grant expired")
	}
	if t.Server != "*" && t.Server != server {
		return nil, fmt.Errorf("grant is for server '%s', this machine is '%s'", t.Server, server)
	}
	for _, d := range t.Deny {
		if d == "*" || d == op {
			return nil, fmt.Errorf("op '%s' is denied by your grant", op)
		}
	}
	for _, o := range t.Ops {
		if o == op {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("op '%s' is not in your grant for this server (default-deny)", op)
}

// purposeForSessionRoot is the step-up purpose a root session binds to: this server,
// this session id. One approval opens one root shell.
func purposeForSessionRoot(server, sessionID string) (string, error) {
	if err := purposeBad([]string{server, sessionID}, nil); err != nil {
		return "", err
	}
	if server == "" || sessionID == "" {
		return "", fmt.Errorf("a root session needs a server and a session id")
	}
	return "session_root|" + server + "|" + sessionID, nil
}

// sessionTranscriptPath is <ctxRoot>/sessions/<id>.log. The id is already shape-checked
// (sessionIDRe), so it cannot carry a separator; cleanRel is the second wall.
func sessionTranscriptPath(ctxRoot, sessionID string) (string, bool) {
	if ctxRoot == "" {
		return "", false
	}
	return cleanRel(ctxRoot, filepath.Join("sessions", sessionID+".log"))
}

// sessionOpenTranscript creates <ctxRoot>/sessions/<id>.log, 0600, refusing to reuse
// a name (O_EXCL): one session id, one transcript, ever.
func sessionOpenTranscript(tpath string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(tpath), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(tpath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
}

// sessionDaemonIsRoot is processIsRoot, held in a variable so a test can
// assert the root session's walls whatever euid the suite runs under. Nothing
// outside tests assigns it.
var sessionDaemonIsRoot = processIsRoot

// handleSessionConn serves ONE session on a harness worker socket. `first` is the
// whole S frame (tag included) the worker already read. Returns when the session is
// over and X has been sent; the worker closes the socket.
func handleSessionConn(ws *websocket.Conn, first []byte, self string, env sessionEnv) {
	var spec sessionSpec
	if len(first) < 2 || first[0] != 'S' || json.Unmarshal(first[1:], &spec) != nil {
		sendSession(ws, 'E', []byte("bad session spec\n"))
		sendSessionExit(ws, 1)
		return
	}
	if !sessionIDRe.MatchString(spec.SessionID) {
		if spec.Op == sessionOpRootExec {
			// A root command leaves a row whatever its outcome (rootexec.go);
			// the id is the host's text, so it goes in bounded.
			bad := spec
			if len(bad.SessionID) > 64 {
				bad.SessionID = bad.SessionID[:64]
			}
			bad.SessionID = strings.ToValidUTF8(bad.SessionID, "�")
			rootExecAuditFailed(env, bad, self, "bad_request", "bad session spec: session_id must be 8-64 chars of [A-Za-z0-9._-]")
		}
		sendSession(ws, 'E', []byte("bad session spec: session_id must be 8-64 chars of [A-Za-z0-9._-]\n"))
		sendSessionExit(ws, 1)
		return
	}
	if spec.Op == sessionOpRootExec {
		handleRootExec(ws, spec, self, env)
		return
	}
	if spec.Op != sessionOpOpen && spec.Op != sessionOpRoot {
		sessionRefuse(ws, env, spec, "refused: op '"+spec.Op+"' is not a session op")
		return
	}
	if why := sessionAllowedByCaps(self); why != "" {
		sessionRefuse(ws, env, spec, "refused: "+why)
		return
	}
	// THE HOST-SIGNED MANAGEMENT GRANT IS NO LONGER REQUIRED (0.39.0). A
	// terminal is the PERSON'S own act in their Terminal app, and the authority
	// for it is what this box checks below, not a standing grant the host
	// holds: root is approved here with
	// the code; session:open on an anchored box takes the person's approval
	// from their device or this console, bound to this one session; on a local
	// box the pairing's caps (above) are the authorization, as for every other
	// write on a person's own machine. A grant that IS presented is still
	// verified as before — an older host sends one, and a deny in it must
	// still refuse — and the key the frame offers is still pinned, because
	// that is how a box with no store grant learns the host key at all.
	if spec.GrantB64 != "" || spec.SigB64 != "" {
		if _, err := sessionVerifyGrant(env.DcnDir, env.HostName, env.Server, spec.Op, spec.GrantB64, spec.SigB64, spec.VerifyPubkey); err != nil {
			sessionRefuse(ws, env, spec, "refused: "+err.Error())
			return
		}
	} else if why := sessionPinOfferedKey(env.DcnDir, env.HostName, spec.VerifyPubkey); why != "" {
		sessionRefuse(ws, env, spec, "refused: "+why)
		return
	}
	// Root: the daemon must BE root, and the user must have approved this very session
	// on this machine. No enrolled factor = no root shell, ever; there is no "unenrolled
	// passes" here the way stepupGate allows for a grant sync.
	// THE APPROVAL IS SPENT HERE, before the shell exists (stepupConsumeApproval
	// / consumeApproval): four session workers can carry the same frame, and a
	// check here with a burn after the spawn let two of them open on one tap.
	spent := false
	if spec.Op == sessionOpRoot {
		if !sessionDaemonIsRoot() {
			sessionRefuse(ws, env, spec, "refused: session:root needs the bastion to run as root, and it does not")
			return
		}
		// ROOT IS APPROVED AT THE MACHINE WITH THE CODE, and only there. A
		// device tap opens a shell; it does not open root. The factor enrolled
		// here is required, as it always was — a device pinned on this box
		// does not stand in for it.
		if !stepupEnrolled(env.DcnDir) {
			sessionRefuse(ws, env, spec, "refused: session:root needs a second factor enrolled on this machine (privatae-bastion stepup-enroll) — root is approved here with the code, never from a device")
			return
		}
		p, err := purposeForSessionRoot(env.Server, spec.SessionID)
		if err != nil {
			sessionRefuse(ws, env, spec, "refused: "+err.Error())
			return
		}
		if isDeviceApproval(spec.Approval) {
			sessionRefuse(ws, env, spec, "refused: session:root is approved at this machine with the code, not from a device")
			return
		}
		if err := stepupConsumeApproval(env.DcnDir, spec.Approval, p); err != nil {
			sessionRefuse(ws, env, spec, "refused: session:root — "+err.Error())
			return
		}
		spent = true
	} else if currentAnchor() != nil {
		// session:open on an ANCHORED box is a shell on a fleet machine —
		// a write in every sense that matters (writes.go). It takes the same
		// per-run approval a management write does, bound to this session id,
		// so an approval opens exactly one shell. A local box keeps today's
		// rule: the signed grant above is the authorization there.
		p := mgmtOpPurpose(sessionOpOpen, env.Server, []string{spec.SessionID})
		if _, err := boxConsume(env.DcnDir, spec.Approval, p); err != nil {
			sessionRefuse(ws, env, spec, "refused: session:open "+err.Error())
			return
		}
		spent = true
	}
	_ = spent
	tpath, ok := sessionTranscriptPath(env.CtxRoot, spec.SessionID)
	if !ok {
		sessionRefuse(ws, env, spec, "refused: context store not configured, so the transcript has nowhere to go")
		return
	}
	cols, rows := spec.Cols, spec.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	// Spawn FIRST, transcript second: a failed spawn must leave nothing behind, or the
	// session id (and the root approval bound to it) could never be retried.
	proc, err := sessionSpawn(spec.Op, spec.Shell, cols, rows)
	if err != nil {
		sessionAudit(env.DcnDir, spec.Op, spec.SessionID, "", "failed", 1, err.Error())
		sendSession(ws, 'E', []byte(err.Error()+"\n"))
		sendSessionExit(ws, 1)
		return
	}
	tf, err := sessionOpenTranscript(tpath)
	if err != nil {
		proc.Kill()
		proc.Wait()
		sessionAudit(env.DcnDir, spec.Op, spec.SessionID, proc.User(), "failed", 1, "transcript: "+err.Error())
		sendSession(ws, 'E', []byte("transcript: "+err.Error()+"\n"))
		sendSessionExit(ws, 1)
		return
	}
	defer tf.Close()
	start := time.Now()
	sessionAudit(env.DcnDir, spec.Op, spec.SessionID, proc.User(), "start", 0, "shell="+proc.Shell())
	fmt.Fprintf(tf, "== session %s op=%s user=%s shell=%s start=%s\n",
		spec.SessionID, spec.Op, proc.User(), proc.Shell(), start.UTC().Format(time.RFC3339))
	fmt.Printf("session: %s %s user=%s shell=%s\n", spec.SessionID, spec.Op, proc.User(), proc.Shell())

	// One reader, one writer (gorilla). The read pump owns ws.ReadMessage: it feeds the
	// pty and resizes it, and notices the host going away. This loop is the ONLY
	// ws.WriteMessage caller. The pty pump only reads the pty.
	var lastInput atomic.Int64
	lastInput.Store(time.Now().UnixNano())
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage || len(data) == 0 {
				continue
			}
			switch data[0] {
			case 'I':
				lastInput.Store(time.Now().UnixNano())
				if len(data) > 1 {
					_, _ = proc.Write(data[1:])
				}
			case 'R':
				var rz sessionResize
				if json.Unmarshal(data[1:], &rz) == nil && rz.Cols > 0 && rz.Rows > 0 {
					_ = proc.Resize(rz.Cols, rz.Rows)
				}
			}
		}
	}()
	out := make(chan []byte, 64)
	go func() {
		defer close(out)
		buf := make([]byte, 32*1024)
		for {
			n, err := proc.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				out <- b
			}
			if err != nil {
				return
			}
		}
	}()

	idle := time.NewTicker(sessionIdleCheck)
	defer idle.Stop()
	hard := time.NewTimer(sessionHardCap)
	defer hard.Stop()
	reason, code := "", 0
	finish := func(r string, c int) { reason, code = r, c }
loop:
	for {
		select {
		case b, ok := <-out:
			if !ok { // pty closed: the shell exited on its own
				finish("exit", proc.Wait())
				break loop
			}
			_, _ = tf.Write(b)
			sendSession(ws, 'O', b)
		case <-closed:
			proc.Kill()
			finish("host closed", proc.Wait())
			break loop
		case <-idle.C:
			if time.Since(time.Unix(0, lastInput.Load())) >= sessionIdleTimeout {
				proc.Kill()
				proc.Wait()
				finish("idle "+sessionIdleTimeout.String(), 124)
				break loop
			}
		case <-hard.C:
			proc.Kill()
			proc.Wait()
			finish("hard cap "+sessionHardCap.String(), 124)
			break loop
		}
	}
	// Drain whatever the pty produced before it died so the transcript is whole; the
	// host may already be gone, in which case the writes just fail quietly.
	for b := range out {
		_, _ = tf.Write(b)
		sendSession(ws, 'O', b)
	}
	stop := time.Now()
	fmt.Fprintf(tf, "\n== session %s stop=%s exit=%d reason=%s duration=%s\n",
		spec.SessionID, stop.UTC().Format(time.RFC3339), code, reason, stop.Sub(start).Round(time.Second))
	sessionAudit(env.DcnDir, spec.Op, spec.SessionID, proc.User(), "stop", code, reason)
	fmt.Printf("session: %s done exit=%d reason=%s\n", spec.SessionID, code, reason)
	if reason != "exit" && reason != "host closed" {
		sendSession(ws, 'E', []byte("session closed by this machine: "+reason+"\n"))
	}
	sendSessionExit(ws, code)
}

// sessionShellFromPasswd returns the login shell /etc/passwd lists for name, or "".
// Read directly (not via os/user, which does not expose the shell) so the default
// shell is the user's own, the way a login would give them.
func sessionShellFromPasswd(passwdPath, name string) string {
	raw, err := os.ReadFile(passwdPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[0] == name {
			return strings.TrimSpace(f[6])
		}
	}
	return ""
}

// sessionShellIsServer names the /etc/shells entries that are terminal SERVERS, not
// shells: tmux and screen daemonize past the session's process group and would keep
// a root pty alive after the session's kill. Refused as the session shell.
func sessionShellIsServer(shell string) bool {
	switch filepath.Base(shell) {
	case "tmux", "screen", "byobu", "byobu-tmux", "byobu-screen":
		return true
	}
	return false
}

// sessionShellListed reports whether shell is an absolute path named in the shells
// file (/etc/shells). A caller-chosen shell is the one user-supplied string that
// reaches exec, so it must come from the box's own list, never from the wire alone.
func sessionShellListed(shellsPath, shell string) bool {
	if shell == "" || !filepath.IsAbs(shell) {
		return false
	}
	raw, err := os.ReadFile(shellsPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == shell {
			return true
		}
	}
	return false
}
