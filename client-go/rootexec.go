package main

// Root commands for the anchor host, under ONE standing grant the person
// approved at this machine with the code.
//
// The session lane (session.go) gives a person a root TERMINAL, one approval
// per shell. A host that runs a machine needs the other shape: one command at
// a time, no terminal, and no approval per command. So the authority behind it
// is decided once, here, by whoever administers the machine:
//
//	sudo -H privatae-bastion root-exec grant --host <anchor host> --for 30d
//
// shows what it grants, asks for the code from the authenticator enrolled here
// (the factor a root shell takes), and records one grant: this host, this
// machine, until the expiry chosen at that moment. `privatae-bastion root-exec`
// shows it and `root-exec revoke` takes it back. Nothing the host sends can
// create, widen or extend it: the grant is written only by that console
// command, and the frame below carries no authority of its own.
//
// Wire (one command per session worker; the S frame of session.go):
//
//	host -> box   'S' + JSON {"op":"session:root:exec", "session_id":"…",
//	                          "command":"…", "deadline_s":N, "max_output_bytes":N,
//	                          "verify_pubkey":"…"}
//	box  -> host  'J' + JSON rootExecResult      only when the command ran;
//	                                             untrusted_connections when it
//	                                             reached outside (rootexec_watch.go)
//	box  -> host  'E' + text                     a refusal or a notice
//	box  -> host  'X' + decimal exit code        last frame
//
// X is the command's own exit status when it ran, 124 when its deadline
// stopped it (J says timed_out), 126 when this box refused (no J) or stopped
// it mid-run because a wall no longer held (J says stopped, and why), and 1
// for a bad spec or a command that could not start. An older bastion answers
// the same frame with "op 'session:root:exec' is not a session op" and 126:
// it is refused, never run.
//
// The walls are looked at again every rootExecRecheck while the command runs:
// the grant revoked at the console or expired, `session` switched off here,
// the pairing quarantined or no longer the anchor each kill the group then.
//
// Every command is written whole to <context root>/sessions/<session_id>.log
// (0600) with its output, and recorded in the pairing's audit.jsonl at start
// and stop with the command, its sha256, the exit and the byte counts. Every
// other outcome gets one row too: a refusal, a bad command, a transcript that
// would not open, a command that would not start.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

const sessionOpRootExec = "session:root:exec"

// Bounds. The host asks for a deadline and an output size; the box holds
// each to its own ceiling. A command with no deadline is given the default,
// never none.
var (
	rootExecDefaultDeadline = 10 * time.Minute
	rootExecMaxDeadline     = 8 * time.Hour // the same bound a root terminal has (sessionHardCap)
	// After SIGTERM the group gets rootExecKillGrace, then SIGKILL. It is
	// shorter than rootExecOutputGrace (the command's WaitDelay), so a child
	// that ignored SIGTERM is killed before its open output is cut off.
	rootExecKillGrace   = 2 * time.Second
	rootExecOutputGrace = 3 * time.Second
	// How often the walls are looked at again while a command runs. A revoke
	// is a separate process writing the grant file, so this is how soon it
	// reaches a command already running.
	rootExecRecheck       = 2 * time.Second
	rootExecDefaultOutput = 256 << 10 // bytes kept per stream for the host
	rootExecMaxOutput     = 4 << 20
	rootExecMinOutput     = 1 << 10
	rootExecTranscriptMax = int64(64 << 20) // the local record keeps far more than the host sees
	rootExecMaxGrantTTL   = 365 * 24 * time.Hour
)

// rootExecCommandMax bounds the command text itself: a script, not a payload.
const rootExecCommandMax = 64 << 10

// rootExecResult is the J frame body.
type rootExecResult struct {
	SessionID       string `json:"session_id"`
	User            string `json:"user"`
	Exit            int    `json:"exit"`
	DurationMS      int64  `json:"duration_ms"`
	TimedOut        bool   `json:"timed_out"`
	DeadlineS       int    `json:"deadline_s"`
	MaxOutputBytes  int    `json:"max_output_bytes"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutBytes     int64  `json:"stdout_bytes"`
	StderrBytes     int64  `json:"stderr_bytes"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	// Stopped says why this machine ended the command before it ended by
	// itself: its deadline, or the wall that no longer held. Empty otherwise.
	Stopped string `json:"stopped,omitempty"`
	// UntrustedConnections are the destinations outside the platform's own
	// hosts that the command's process tree connected to (rootexec_watch.go),
	// at most rootExecUntrustedMax, the rest counted in the field after it.
	// Absent when there were none, so an older host reads the frame as before.
	// Non-empty means the output may carry outside text: the host treats it as
	// untrusted and ends root for the turn.
	UntrustedConnections     []rootExecConn `json:"untrusted_connections,omitempty"`
	UntrustedConnectionsMore int            `json:"untrusted_connections_more,omitempty"`
}

// ── the standing grant ──────────────────────────────────────────────────────

// rootExecGrant is the one record that lets a host run root commands here.
// It lives in that pairing's own state folder, so it names the host twice:
// by where it is kept and by Host, and both must agree with the pairing that
// asks.
type rootExecGrant struct {
	ID        string `json:"id"`
	Host      string `json:"host"`
	Server    string `json:"server"`
	GrantedAt string `json:"granted_at"`
	Expires   string `json:"expires"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

var rootExecMu sync.Mutex

func rootExecGrantPath(dir string) string { return filepath.Join(dir, "root_exec_grant.json") }

func rootExecGrantLoad(dir string) (*rootExecGrant, error) {
	raw, err := os.ReadFile(rootExecGrantPath(dir))
	if err != nil {
		return nil, err
	}
	var g rootExecGrant
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func rootExecGrantSave(dir string, g *rootExecGrant) error {
	raw, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(rootExecGrantPath(dir), raw)
}

// rootExecGrantHowTo is the one line that tells the person how to grant it.
func rootExecGrantHowTo(host string) string {
	return "the person at this machine grants it once: sudo -H privatae-bastion root-exec grant --host " +
		host + " --for <how long, e.g. 30d>"
}

// rootExecGrantCheck answers whether the pairing `self` may run a root command
// on this machine (`server`) now. "" = yes; otherwise the refusal in plain
// words.
func rootExecGrantCheck(dir, self, server string, now time.Time) string {
	if dir == "" {
		return "no grant state on this machine (default-deny)"
	}
	rootExecMu.Lock()
	g, err := rootExecGrantLoad(dir)
	rootExecMu.Unlock()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "no standing grant for root commands on this machine — " + rootExecGrantHowTo(self)
		}
		return "the root-command grant on this machine is unreadable (default-deny)"
	}
	if g.RevokedAt != "" {
		return "the root-command grant was revoked at this machine at " + g.RevokedAt + " — " + rootExecGrantHowTo(self)
	}
	if g.Host == "" || g.Host != self {
		return fmt.Sprintf("the root-command grant on this machine is for '%s', not '%s'", g.Host, self)
	}
	if g.Server == "" || g.Server != server {
		return fmt.Sprintf("the root-command grant is for machine '%s', this machine is '%s'", g.Server, server)
	}
	exp, err := time.Parse(time.RFC3339, g.Expires)
	if err != nil {
		return "the root-command grant states no expiry (open-ended terms are refused)"
	}
	if !exp.After(now) {
		return "the root-command grant expired at " + g.Expires + " — " + rootExecGrantHowTo(self)
	}
	return ""
}

// rootExecGrantWithCode is the console ceremony's core: the code from the
// factor enrolled here is verified and burned, then the grant is written.
// A grant already held is replaced, so a re-grant is how the expiry moves.
func rootExecGrantWithCode(dir, host, server, code string, ttl time.Duration, now time.Time) (*rootExecGrant, error) {
	if dir == "" {
		return nil, errors.New("cannot open this pairing's state folder")
	}
	if strings.TrimSpace(host) == "" || strings.TrimSpace(server) == "" {
		return nil, errors.New("a root-command grant needs a host and a machine")
	}
	if ttl <= 0 {
		return nil, errors.New("a root-command grant needs an expiry (--for, e.g. 30d)")
	}
	if ttl > rootExecMaxGrantTTL {
		return nil, fmt.Errorf("--for is at most %d days; grant again before it ends", int(rootExecMaxGrantTTL.Hours()/24))
	}
	if !stepupEnrolled(dir) {
		return nil, errors.New("no second factor enrolled on this machine for this host — run `privatae-bastion stepup-enroll` first; root is approved here with the code")
	}
	if _, err := stepupVerifyAndBurn(dir, code, now); err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	g := &rootExecGrant{ID: id, Host: host, Server: server,
		GrantedAt: now.UTC().Format(time.RFC3339), Expires: now.Add(ttl).UTC().Format(time.RFC3339)}
	rootExecMu.Lock()
	err = rootExecGrantSave(dir, g)
	rootExecMu.Unlock()
	if err != nil {
		return nil, err
	}
	dcnAudit(dir, "root_exec_grant", 0, "", "granted at this machine: host="+host+" server="+server+" until "+g.Expires)
	return g, nil
}

// rootExecRevoke takes the grant back. Like every console revoke it only
// removes reach, so it needs no code.
func rootExecRevoke(dir string, now time.Time) (*rootExecGrant, error) {
	rootExecMu.Lock()
	defer rootExecMu.Unlock()
	g, err := rootExecGrantLoad(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("no root-command grant is held on this machine for this host")
		}
		return nil, err
	}
	if g.RevokedAt != "" {
		return g, nil
	}
	g.RevokedAt = now.UTC().Format(time.RFC3339)
	if err := rootExecGrantSave(dir, g); err != nil {
		return nil, err
	}
	dcnAudit(dir, "root_exec_revoke", 0, "", "revoked at this machine: host="+g.Host)
	return g, nil
}

// parseGrantFor reads --for: Go durations (12h, 90m) plus whole days (30d).
func parseGrantFor(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("--for %q: say how long, e.g. 7d, 30d or 12h", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--for %q: say how long, e.g. 7d, 30d or 12h", s)
	}
	return d, nil
}

// ── the console ─────────────────────────────────────────────────────────────

// cmdRootExec: root-exec [--host <host>] | grant --for <d> | revoke
func cmdRootExec(args []string) error {
	host, rest := takeHostFlag(args)
	sub := ""
	if len(rest) > 0 {
		sub, rest = rest[0], rest[1:]
	}
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	if dir == "" {
		return errors.New("cannot open this pairing's state folder")
	}
	server, _ := os.Hostname()
	switch sub {
	case "", "status":
		rootExecMu.Lock()
		g, err := rootExecGrantLoad(dir)
		rootExecMu.Unlock()
		if err != nil {
			fmt.Println("no root-command grant is held on this machine for", cfg.HostName)
			return nil
		}
		state := "active"
		if g.RevokedAt != "" {
			state = "revoked at " + g.RevokedAt
		} else if why := rootExecGrantCheck(dir, cfg.HostName, server, time.Now()); why != "" {
			state = why
		}
		fmt.Printf("root commands for %s on %s: %s\n  granted %s, until %s\n", g.Host, g.Server, state, g.GrantedAt, g.Expires)
		fmt.Println("  every command: " + filepath.Join(cfg.contextRoot(), "sessions") + "/<id>.log and audit.jsonl")
		fmt.Println("  " + rootExecOwnHostsLine())
		fmt.Println("  take it back:  privatae-bastion root-exec revoke --host " + cfg.HostName)
		return nil
	case "revoke":
		g, err := rootExecRevoke(dir, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("revoked: %s can no longer run root commands on this machine (a command already running is stopped within %s)\n", g.Host, rootExecRecheck)
		return nil
	case "grant":
	default:
		return errors.New("usage: privatae-bastion root-exec [--host <host>] [grant --for <30d> | revoke]")
	}
	forS := ""
	for i := 0; i < len(rest); i++ {
		if rest[i] == "--for" && i+1 < len(rest) {
			forS = rest[i+1]
			i++
			continue
		}
		return fmt.Errorf("unexpected %q — usage: sudo -H privatae-bastion root-exec grant --host <host> --for <30d>", rest[i])
	}
	if err := requireMachineAuthority("root-exec grant"); err != nil {
		return err
	}
	if why := anchorOnly(cfg.HostName, "a root-command grant"); why != "" {
		return errors.New(why)
	}
	if forS == "" {
		return errors.New("say how long the grant lasts: --for 30d (or 7d, 12h); it ends then unless you grant it again")
	}
	ttl, err := parseGrantFor(forS)
	if err != nil {
		return err
	}
	if !stepupEnrolled(dir) {
		return errors.New("no second factor enrolled on this machine for " + cfg.HostName + " — run `privatae-bastion stepup-enroll --host " + cfg.HostName + "` first")
	}
	until := time.Now().Add(ttl).UTC().Format(time.RFC3339)
	fmt.Printf("This lets the host  %s  run commands AS ROOT on this machine (%s),\n", clean(cfg.HostName), clean(server))
	fmt.Println("one at a time, with no further approval from you, until " + until + ".")
	fmt.Println("  Every command is recorded here, whole, with its output.")
	fmt.Println("  Take it back at any time:  privatae-bastion root-exec revoke --host " + cfg.HostName)
	fmt.Println()
	fmt.Print("Grant it? Enter the code from your authenticator (or leave empty to cancel): ")
	code, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(code) == "" {
		fmt.Println("cancelled — nothing granted")
		return nil
	}
	g, err := rootExecGrantWithCode(dir, cfg.HostName, server, code, ttl, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("granted until %s. Revoke: privatae-bastion root-exec revoke --host %s\n", g.Expires, cfg.HostName)
	return nil
}

// ── output capture ──────────────────────────────────────────────────────────

// lockedLimitWriter is the transcript: both streams write to it, so it holds
// its own lock, and it stops at max with one line saying so.
type lockedLimitWriter struct {
	mu   sync.Mutex
	w    io.Writer
	left int64
	cut  bool
}

func (l *lockedLimitWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	if l.left <= 0 {
		if !l.cut {
			l.cut = true
			_, _ = io.WriteString(l.w, "\n[transcript cut here: the rest of the output was not recorded]\n")
		}
		return n, nil
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	_, _ = l.w.Write(p)
	l.left -= int64(len(p))
	return n, nil
}

// headTail keeps the first and the last half of `max` bytes of a stream and
// counts the whole: the start of an output says what ran, the end says how it
// ended, and the middle is what a cap can drop.
type headTail struct {
	mu    sync.Mutex
	max   int
	head  []byte
	tail  []byte
	total int64
	tee   io.Writer
}

func newHeadTail(max int, tee io.Writer) *headTail { return &headTail{max: max, tee: tee} }

func (h *headTail) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(p)
	h.total += int64(n)
	if h.tee != nil {
		_, _ = h.tee.Write(p)
	}
	hmax := h.max / 2
	if len(h.head) < hmax {
		k := hmax - len(h.head)
		if k > len(p) {
			k = len(p)
		}
		h.head = append(h.head, p[:k]...)
		p = p[k:]
	}
	if len(p) > 0 {
		tmax := h.max - hmax
		h.tail = append(h.tail, p...)
		if len(h.tail) > 2*tmax { // trimmed in batches, so a long stream is not copied per write
			h.tail = append([]byte(nil), h.tail[len(h.tail)-tmax:]...)
		}
	}
	return n, nil
}

// text is what the host is given, and whether anything was cut from it.
func (h *headTail) text() (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	tail := h.tail
	tmax := h.max - h.max/2
	if len(tail) > tmax {
		tail = tail[len(tail)-tmax:]
	}
	kept := int64(len(h.head) + len(tail))
	if kept >= h.total {
		return strings.ToValidUTF8(string(h.head)+string(tail), "�"), false
	}
	return strings.ToValidUTF8(string(h.head), "�") +
		fmt.Sprintf("\n[… %d bytes cut here: %d bytes in all, the first and last %d kept …]\n", h.total-kept, h.total, kept) +
		strings.ToValidUTF8(string(tail), "�"), true
}

// ── running one command ─────────────────────────────────────────────────────

// rootExecProc is a started command. The real one (rootexec_unix.go) is a
// /bin/sh -c in its own process group; tests substitute a fake.
type rootExecProc interface {
	Wait() int // blocks until the command and its output are done; its exit status
	Kill()     // ends the whole process group; idempotent
}

// rootExecStart is the platform starter, a var so tests can stand in a fake.
var rootExecStart = startRootExec

func rootExecAudit(dir string, rec map[string]any) {
	if dir == "" {
		return
	}
	rec["ts"] = time.Now().UTC().Format(time.RFC3339)
	rec["op"] = sessionOpRootExec
	raw, _ := json.Marshal(rec)
	auditToSystemLog(auditFilePairingD, auditPairingOfDir(dir), raw)
	fh, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	_, _ = fh.Write(append(raw, '\n'))
}

// rootExecAuditFailed is the row for an outcome that ends before the command
// starts and is not a wall's refusal: a bad command, a transcript that would
// not open. The command goes in whole up to rootExecCommandMax bytes (a bad
// one may be longer, or not text), with its size and the sha256 of all of it.
func rootExecAuditFailed(env sessionEnv, spec sessionSpec, self, event, why string) {
	cmd := spec.Command
	sum := sha256.Sum256([]byte(cmd))
	shown := cmd
	if len(shown) > rootExecCommandMax {
		shown = shown[:rootExecCommandMax]
	}
	rootExecAudit(env.DcnDir, map[string]any{"session_id": spec.SessionID, "host": self, "event": event,
		"exit": 1, "decision": why, "command": strings.ToValidUTF8(shown, "�"), "command_bytes": len(cmd),
		"command_sha256": hex.EncodeToString(sum[:])})
}

// rootExecWallsHold is the part of the walls that can change while a command
// runs, looked at again on every rootExecRecheck: the local switch and the
// pairing's ceiling, the anchor, the quarantine, and the standing grant
// (revoked at the console, or expired). "" while they all hold.
func rootExecWallsHold(self string, env sessionEnv, now time.Time) string {
	if why := capsAllow(self, sessionOpRootExec); why != "" {
		return why
	}
	if why := anchorOnly(self, "root commands"); why != "" {
		return why
	}
	if until := quarantinedUntil(self, now); !until.IsZero() {
		return quarantineRefusal(until)
	}
	return rootExecGrantCheck(env.DcnDir, self, env.Server, now)
}

func rootExecRefuse(ws *websocket.Conn, env sessionEnv, spec sessionSpec, self, why string, counts bool) {
	if !strings.HasPrefix(why, "refused") {
		why = "refused: " + why
	}
	sum := sha256.Sum256([]byte(spec.Command))
	rootExecAudit(env.DcnDir, map[string]any{"session_id": spec.SessionID, "host": self, "event": "refused",
		"exit": 126, "decision": why, "command": spec.Command, "command_sha256": hex.EncodeToString(sum[:])})
	if counts {
		// A refused root command is a refused write: it goes toward this
		// pairing's quarantine like any other (quarantine.go).
		noteRefusal(self, sessionOpRootExec, why, true, time.Now())
	}
	sendSession(ws, 'E', []byte(why+"\n"))
	sendSessionExit(ws, 126)
}

// rootExecBounds holds the host's asks to this box's ceilings.
func rootExecBounds(spec sessionSpec) (time.Duration, int) {
	deadline := rootExecDefaultDeadline
	if spec.DeadlineS > 0 {
		deadline = time.Duration(spec.DeadlineS) * time.Second
	}
	if deadline > rootExecMaxDeadline {
		deadline = rootExecMaxDeadline
	}
	out := rootExecDefaultOutput
	if spec.MaxOutputBytes > 0 {
		out = spec.MaxOutputBytes
	}
	if out > rootExecMaxOutput {
		out = rootExecMaxOutput
	}
	if out < rootExecMinOutput {
		out = rootExecMinOutput
	}
	return deadline, out
}

// handleRootExec serves one S frame with op session:root:exec. The session
// id and the op have been checked by handleSessionConn.
func handleRootExec(ws *websocket.Conn, spec sessionSpec, self string, env sessionEnv) {
	cmd := spec.Command
	if strings.TrimSpace(cmd) == "" || len(cmd) > rootExecCommandMax || !utf8.ValidString(cmd) || strings.ContainsRune(cmd, 0) {
		why := fmt.Sprintf("bad command: give 1 to %d bytes of text, no NUL", rootExecCommandMax)
		rootExecAuditFailed(env, spec, self, "bad_request", why)
		sendSession(ws, 'E', []byte(why+"\n"))
		sendSessionExit(ws, 1)
		return
	}
	// The walls, in order. Each refusal is audited with the command it refused.
	//  1. the pairing's ceiling on this machine, and the person's local switch
	//     ("session" off here stops root commands too);
	if why := capsAllow(self, sessionOpRootExec); why != "" {
		rootExecRefuse(ws, env, spec, self, why, false)
		return
	}
	//  2. the anchor host only — a member pairing never runs root commands;
	if why := anchorOnly(self, "root commands"); why != "" {
		rootExecRefuse(ws, env, spec, self, why, false)
		return
	}
	//  3. a pairing whose write lanes are held runs nothing;
	if until := quarantinedUntil(self, time.Now()); !until.IsZero() {
		rootExecRefuse(ws, env, spec, self, quarantineRefusal(until), false)
		return
	}
	//  4. a management grant the frame presents is verified as for a shell
	//     (a deny of this op in it refuses), and an offered key is pinned;
	if spec.GrantB64 != "" || spec.SigB64 != "" {
		if _, err := sessionVerifyGrant(env.DcnDir, env.HostName, env.Server, sessionOpRootExec, spec.GrantB64, spec.SigB64, spec.VerifyPubkey); err != nil {
			rootExecRefuse(ws, env, spec, self, err.Error(), true)
			return
		}
	} else if why := sessionPinOfferedKey(env.DcnDir, env.HostName, spec.VerifyPubkey); why != "" {
		rootExecRefuse(ws, env, spec, self, why, true)
		return
	}
	//  5. the daemon must be root to run anything as root;
	if !sessionDaemonIsRoot() {
		rootExecRefuse(ws, env, spec, self, "root commands need the bastion to run as root, and it does not", false)
		return
	}
	//  6. the standing grant the person gave at this machine, for this host
	//     and this machine, unexpired and not revoked.
	if why := rootExecGrantCheck(env.DcnDir, self, env.Server, time.Now()); why != "" {
		rootExecRefuse(ws, env, spec, self, why, false)
		return
	}
	tpath, ok := sessionTranscriptPath(env.CtxRoot, spec.SessionID)
	if !ok {
		rootExecRefuse(ws, env, spec, self, "context store not configured, so the transcript has nowhere to go", false)
		return
	}
	tf, err := sessionOpenTranscript(tpath)
	if err != nil {
		rootExecAuditFailed(env, spec, self, "failed", "transcript: "+err.Error())
		sendSession(ws, 'E', []byte("transcript: "+err.Error()+"\n"))
		sendSessionExit(ws, 1)
		return
	}
	defer tf.Close()

	deadline, maxOut := rootExecBounds(spec)
	sum := sha256.Sum256([]byte(cmd))
	sumHex := hex.EncodeToString(sum[:])
	start := time.Now()
	fmt.Fprintf(tf, "== root command %s host=%s user=root start=%s deadline=%s\n== command (%d bytes, sha256 %s):\n%s\n== output:\n",
		spec.SessionID, self, start.UTC().Format(time.RFC3339), deadline, len(cmd), sumHex, cmd)
	trans := &lockedLimitWriter{w: tf, left: rootExecTranscriptMax}
	stdout, stderr := newHeadTail(maxOut, trans), newHeadTail(maxOut, trans)
	rootExecAudit(env.DcnDir, map[string]any{"session_id": spec.SessionID, "host": self, "user": "root",
		"event": "start", "command": cmd, "command_sha256": sumHex, "deadline_s": int(deadline / time.Second)})
	fmt.Printf("root command: %s for %s (%d bytes, sha256 %s)\n", spec.SessionID, self, len(cmd), sumHex[:12])

	// Where the command connects is watched from its first instruction; the
	// watch is ended (and everything it made removed) on every path out.
	watch := rootExecWatchStart(spec.SessionID)
	watchDone := false
	stopWatch := func() ([]rootExecConn, string) {
		watchDone = true
		return rootExecWatchStop(watch)
	}
	defer func() {
		if !watchDone {
			_, _ = stopWatch()
		}
	}()
	proc, err := rootExecStart(cmd, stdout, stderr, watch.CgroupFD())
	if err != nil {
		fmt.Fprintf(tf, "\n== could not start: %v\n", err)
		rootExecAudit(env.DcnDir, map[string]any{"session_id": spec.SessionID, "host": self, "user": "root",
			"event": "failed", "exit": 1, "decision": err.Error(), "command_sha256": sumHex})
		sendSession(ws, 'E', []byte("could not start the command: "+err.Error()+"\n"))
		sendSessionExit(ws, 1)
		return
	}
	// The host going away ends the command: the read pump notices the socket
	// close. Nothing the host sends after S is read as input.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}()
	done := make(chan int, 1)
	go func() { done <- proc.Wait() }()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	// A grant is not only checked at the start: taken back at the console,
	// expired, switched off or quarantined while the command runs, it stops
	// the command within one interval.
	recheck := time.NewTicker(rootExecRecheck)
	defer recheck.Stop()
	code, reason, timedOut, stopped := 0, "exit", false, ""
run:
	for {
		select {
		case code = <-done:
			break run
		case <-timer.C:
			proc.Kill()
			<-done
			code, reason, timedOut = 124, "deadline "+deadline.String(), true
			stopped = "its deadline (" + deadline.String() + ")"
			break run
		case <-closed:
			proc.Kill()
			code = <-done
			reason = "host closed"
			break run
		case <-recheck.C:
			why := rootExecWallsHold(self, env, time.Now())
			if why == "" {
				continue
			}
			// The whole cgroup first, so a child that left the process group
			// (setsid, a double fork) does not run on as root after the grant
			// is gone; then the group, which reaches what left the cgroup.
			rootExecWatchKill(watch)
			proc.Kill()
			<-done
			stopped = strings.TrimPrefix(why, "refused: ")
			code, reason = 126, "stopped: "+stopped
			break run
		}
	}
	dur := time.Since(start)
	so, soCut := stdout.text()
	se, seCut := stderr.text()
	seen, unwatched := stopWatch()
	untrusted, more, conns := rootExecClassify(seen, unwatched, rootExecOwnSet(), rootExecLoopbackRelays())
	fmt.Fprintf(tf, "\n== connections: %s\n", rootExecConnsText(conns))
	fmt.Fprintf(tf, "== stop=%s exit=%d reason=%s duration=%s stdout_bytes=%d stderr_bytes=%d\n",
		time.Now().UTC().Format(time.RFC3339), code, reason, dur.Round(time.Millisecond), stdout.total, stderr.total)
	stopRow := map[string]any{"session_id": spec.SessionID, "host": self, "user": "root",
		"event": "stop", "exit": code, "decision": reason, "command_sha256": sumHex,
		"duration_ms": dur.Milliseconds(), "stdout_bytes": stdout.total, "stderr_bytes": stderr.total,
		"connections": conns, "untrusted_connections": len(untrusted) + more}
	if conns == nil {
		stopRow["connections"] = []rootExecConn{}
	}
	rootExecAudit(env.DcnDir, stopRow)
	fmt.Printf("root command: %s done exit=%d reason=%s\n", spec.SessionID, code, reason)
	if reason == "host closed" {
		return
	}
	res, _ := json.Marshal(rootExecResult{SessionID: spec.SessionID, User: "root", Exit: code,
		DurationMS: dur.Milliseconds(), TimedOut: timedOut, DeadlineS: int(deadline / time.Second),
		MaxOutputBytes: maxOut, Stdout: so, Stderr: se, StdoutBytes: stdout.total, StderrBytes: stderr.total,
		StdoutTruncated: soCut, StderrTruncated: seCut, Stopped: stopped,
		UntrustedConnections: untrusted, UntrustedConnectionsMore: more})
	sendSession(ws, 'J', res)
	if stopped != "" {
		sendSession(ws, 'E', []byte("command stopped by this machine: "+stopped+"\n"))
	}
	sendSessionExit(ws, code)
}
