package main

// approvalpipe.go — the signed-in person's lane to a bastion that runs as the
// machine's system service.
//
// THE PROBLEM. On Windows a networked bastion is a LocalSystem service
// (sysservice_windows.go), and its state, the TOTP secrets included, sits in
// LocalSystem's profile. The person at the machine works in their own,
// unelevated account. Before this lane the only places to answer a Host's
// request were an Administrator terminal and the admin page, both behind a UAC
// prompt, so every approval cost a prompt.
//
// THE LANE. The service serves a named pipe. The tray, running as the person
// (tray_pipe_windows.go), connects and can do exactly three things:
//
//   - list what is pending, in the operation's own words: describeRequest,
//     the same text `privatae-bastion approvals` prints;
//   - approve ONE request id with a code from the authenticator enrolled on
//     this machine, verified by the existing step-up check (stepupApproveRequest)
//     and bound to the purpose the tray showed (purpose_sha256);
//   - deny one request id, which needs no code, as on every other lane.
//
// WHAT NEVER CROSSES IT. The TOTP secret, ui.secret, an approval id, a device
// approval. The secret stays in the service's state; the tray sends a code and
// gets back "approved" or why not. Device approvals (uidevice.go) are not
// listed at all: they need no code, so offering them here would let any
// process running as the person approve them.
//
// WHO MAY CONNECT. The pipe's ACL admits interactive users only. The service
// then identifies the client from the pipe itself (GetNamedPipeClientProcessId
// and that process's token) and serves only a process running as the person
// signed in to that process's own session, in a session someone is in front of
// (pipeClientRefusal). A runas process of another account inside the session,
// a service, session 0 and a disconnected session are refused. Of those people,
// it serves only the account that owns this machine's approvals, recorded in
// the service's state by the installer (approvals_owner.go).
//
// WHY A THROTTLE HERE AND NOT ON THE ADMIN PAGE. The admin page's approve has
// no attempt limit because a process that can reach it can read the seed
// anyway (ui.go). Through this lane that is no longer true: a process running
// as the person cannot read the seed, so guessing codes is its only way in.
// pipeThrottle bounds that, the way NIST SP 800-63B 5.2.2 asks: free
// attempts, then one attempt per pipeSlowEvery, and none after
// pipeLockAfter consecutive failures until a code is accepted on another lane
// (an Administrator terminal or the admin page), which resets the count.
//
// The decisions are here, untagged, so the suite checks them on every
// platform. The Windows calls that gather the client's identity and move the
// bytes are in approvalpipe_windows.go.

import (
	"crypto/sha256"
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
)

const (
	// approvalPipeName is the pipe the service serves and the tray dials.
	approvalPipeName = `\\.\pipe\privatae-bastion-approvals`

	// approvalPipeSDDL: SYSTEM and Administrators full control; Interactive
	// users (IU) read, write and synchronize, and NOT FILE_CREATE_PIPE_INSTANCE.
	// 0x12019b is FILE_GENERIC_READ|FILE_GENERIC_WRITE (0x12019f) without
	// FILE_APPEND_DATA (0x4), which on a pipe is the right to create another
	// server instance of it: granting it would let a client stand up its own
	// end of this name and read the next code the tray sends. P protects the
	// DACL from inheritance.
	approvalPipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)"

	// pipeMaxRequest bounds one request. A list request is a few bytes and an
	// approve is under 300; anything larger is not ours.
	pipeMaxRequest = 16 << 10
	// pipeIOTimeout bounds every read and write on one connection, so a client
	// that connects and says nothing cannot hold an instance.
	pipeIOTimeout = 5 * time.Second
	// pipeMaxClients bounds the connections served at once.
	pipeMaxClients = 8

	// The throttle (see the header). Five free attempts covers mistyped codes
	// and a code typed as the window turned; after that one attempt per
	// pipeSlowEvery, so an attacker gets at most pipeLockAfter guesses (a
	// 3-in-a-million chance each with the drift window) before the lane closes.
	pipeFreeFailures = 5
	pipeSlowEvery    = 30 * time.Second
	pipeLockAfter    = 100
)

// pipeRequest is one request from the tray.
type pipeRequest struct {
	Op string `json:"op"` // list | approve | deny
	// Host and ID name the request; Purpose is the sha256 of the purpose the
	// tray was shown for that id, so what is approved is what was read.
	Host    string `json:"host,omitempty"`
	ID      string `json:"id,omitempty"`
	Purpose string `json:"purpose_sha256,omitempty"`
	Code    string `json:"code,omitempty"`
}

// pipeApproval is one pending request as the tray shows it.
type pipeApproval struct {
	ID         string   `json:"id"`
	Short      string   `json:"short"`
	Host       string   `json:"host"`
	At         string   `json:"at"`
	Lines      []string `json:"lines"`
	Unreadable bool     `json:"unreadable,omitempty"`
	Purpose    string   `json:"purpose_sha256"`
}

// pipeResponse is the service's one answer.
type pipeResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	// list only: the machine's state for the tray's icon and first line, and
	// what is waiting.
	State      string         `json:"state,omitempty"`
	StateClass string         `json:"state_class,omitempty"`
	StateLine  string         `json:"state_line,omitempty"`
	Approvals  []pipeApproval `json:"approvals,omitempty"`
}

// pipeClient is what the service learned about the process on the other end.
type pipeClient struct {
	PID       uint32
	UserSID   string // the client process token's user
	UserName  string // for the log line
	SessionID uint32 // the client process token's session
	// SessionUserSID is the user signed in to SessionID (WTSQueryUserToken),
	// "" when nobody is.
	SessionUserSID string
	SessionActive  bool // WTSActive: the session someone is in front of
	// NameTimedOut: the account directory did not answer for UserSID within
	// pipeSIDLane's budget, so UserName is empty and nobody can say whose
	// account approved. pipeApprove refuses; list and deny go on, by SID.
	NameTimedOut bool
}

// pipeSIDLane bounds the client's account-name lookup (sidnames.go). The tray
// waits 2*pipeIOTimeout for its answer, and the name is looked up before the
// request is read, so the lookup gets well under that: a directory that does
// not answer costs one connection 2 s, and holds at most one goroutine for
// the pipe however many connections come.
var pipeSIDLane = sidLane{slots: make(chan struct{}, 1), budget: 2 * time.Second}

// pipeClientName fills c.UserName from the account directory, or sets
// c.NameTimedOut when the directory did not answer in time. A SID with no
// account leaves UserName empty: the log shows the SID, as before.
func pipeClientName(c *pipeClient, dir *sidDirectory, lane sidLane) {
	acct, outcome := dir.resolve(c.UserSID, lane)
	switch outcome {
	case sidResolved:
		c.UserName = sidAccountLabel(acct)
	case sidTimedOut:
		c.NameTimedOut = true
	}
}

// purposeDigest is the sha256 of a purpose as the tray carries it back.
func purposeDigest(purpose string) string {
	s := sha256.Sum256([]byte(purpose))
	return hex.EncodeToString(s[:])
}

// winPersonSID reports whether a SID names a person's account: one issued by
// the machine or its domain (S-1-5-21-) or by Microsoft Entra ID (S-1-12-1-).
// SYSTEM, the service and virtual accounts and every group are not.
func winPersonSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
}

// pipeClientRefusal says why a connected process may not use the lane, or ""
// when it may: it must run as the person signed in to its own session, in a
// session someone is in front of.
func pipeClientRefusal(c pipeClient) string {
	switch {
	case c.UserSID == "":
		return "cannot tell which account connected"
	case c.SessionID == 0:
		return "the connecting process runs in session 0, where services run and nobody signs in"
	case !winPersonSID(c.UserSID):
		return "the connecting process runs as " + pipeWho(c) + ", one of the machine's own identities, not a person"
	case c.SessionUserSID == "":
		return "nobody is signed in to the session the connecting process runs in"
	case !strings.EqualFold(c.UserSID, c.SessionUserSID):
		return "the connecting process runs as " + pipeWho(c) + ", not as the person signed in to its session"
	case !c.SessionActive:
		return "the connecting process runs in a session nobody is in front of"
	}
	return ""
}

// pipeAccessRefusal is every rule on who may use the lane, for list, deny and
// approve alike: a person at their own active session (pipeClientRefusal),
// and the one account that owns this machine's approvals (approvals_owner.go).
func pipeAccessRefusal(c pipeClient) string {
	if why := pipeClientRefusal(c); why != "" {
		return why
	}
	return pipeOwnerRefusal(c, approvalsOwner())
}

func pipeWho(c pipeClient) string {
	if c.UserName != "" {
		return c.UserName + " (" + c.UserSID + ")"
	}
	return c.UserSID
}

// ── the throttle ────────────────────────────────────────────────────────────

type pipeThrottleFile struct {
	Failures int    `json:"failures"`
	Last     string `json:"last,omitempty"`
}

func pipeThrottlePath(dir string) string { return filepath.Join(dir, "pipe_code_failures.json") }

func pipeThrottleLoad(dir string) pipeThrottleFile {
	var f pipeThrottleFile
	if raw, err := os.ReadFile(pipeThrottlePath(dir)); err == nil {
		_ = json.Unmarshal(raw, &f)
	}
	return f
}

// pipeThrottleRefusal says why the lane takes no code for this pairing now, or
// "" when it does.
func pipeThrottleRefusal(f pipeThrottleFile, now time.Time) string {
	if f.Failures >= pipeLockAfter {
		return fmt.Sprintf("%d wrong codes in a row came through the tray, so it takes no more codes for this Host. "+
			"Approve once from an Administrator terminal (privatae-bastion approvals, then privatae-bastion approve <id>) "+
			"and the tray takes codes again", f.Failures)
	}
	if f.Failures < pipeFreeFailures {
		return ""
	}
	last, err := time.Parse(time.RFC3339, f.Last)
	if err != nil {
		return ""
	}
	if wait := pipeSlowEvery - now.Sub(last); wait > 0 {
		return fmt.Sprintf("%d wrong codes in a row; try again in %d seconds", f.Failures, int(wait.Seconds()+0.999))
	}
	return ""
}

// pipeThrottleFail records one wrong code. Under stepupMu, like every other
// write to a pairing's step-up state.
func pipeThrottleFail(dir string, now time.Time) {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	f := pipeThrottleLoad(dir)
	f.Failures++
	f.Last = now.UTC().Format(time.RFC3339)
	if raw, err := json.MarshalIndent(f, "", "  "); err == nil {
		_ = atomicWrite(pipeThrottlePath(dir), raw)
	}
}

// pipeThrottleReset clears the count. stepupApproveRequest calls it after any
// accepted code, on any lane, so an approval from an Administrator terminal
// re-opens a locked tray.
func pipeThrottleReset(dir string) {
	_ = os.Remove(pipeThrottlePath(dir))
}

// pipeCodeError reports whether an approve failed on the code itself (and so
// counts towards the throttle), rather than on the request or the store.
func pipeCodeError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return s == "code refused" || s == "code already used"
}

// ── serving one request ─────────────────────────────────────────────────────

// pipeServe answers one request from client c. It is the whole lane apart
// from moving bytes, so the suite runs it directly.
func pipeServe(req pipeRequest, c pipeClient, now time.Time) pipeResponse {
	if why := pipeAccessRefusal(c); why != "" {
		return pipeResponse{Error: "refused: " + why}
	}
	switch req.Op {
	case "list":
		return pipeList()
	case "approve":
		return pipeApprove(req, c, now)
	case "deny":
		return pipeDeny(req, c)
	}
	return pipeResponse{Error: "unknown request " + strconv.Quote(req.Op)}
}

// pipeList is the machine's state line and every pending step-up request, in
// the words describeRequest gives them (collectUIStatus reads them through
// pendingApprovals, which is what the admin page and its approvals popup show).
func pipeList() pipeResponse {
	s := collectUIStatus()
	out := pipeResponse{OK: true, State: s.State, StateClass: s.StateClass, StateLine: trayStateLine(s)}
	for _, a := range s.Approvals {
		out.Approvals = append(out.Approvals, pipeApproval{
			ID: a.ID, Short: a.Short, Host: a.Host, At: a.At, Lines: a.Lines,
			Unreadable: a.Unreadable, Purpose: a.PurposeSHA256,
		})
	}
	return out
}

// pipeTarget resolves a request named by host and id to its pairing's step-up
// state, refusing unless the request is pending and its purpose is the one the
// tray showed.
func pipeTarget(req pipeRequest) (dir string, r stepupRequest, err error) {
	if strings.TrimSpace(req.Host) == "" || strings.TrimSpace(req.ID) == "" {
		return "", r, errors.New("which request? the tray sends a Host and a request id")
	}
	cfg, err := approvalTarget(req.Host)
	if err != nil {
		return "", r, err
	}
	dir = cfg.dcnDir()
	if dir == "" || !stepupEnrolled(dir) {
		return "", r, fmt.Errorf("no second factor is enrolled on this machine for %s", cfg.HostName)
	}
	stepupMu.Lock()
	r, ok := requestsLoad(dir)[req.ID]
	stepupMu.Unlock()
	if !ok || r.State != "pending" {
		return "", r, errors.New("that request is no longer waiting (answered elsewhere, or lapsed)")
	}
	// BOUND TO WHAT WAS SHOWN. An id names one request, and a request's purpose
	// never changes; the check makes that a property of this lane rather than
	// of how ids are made, so a tray drawing one card and posting another's id
	// approves nothing.
	if req.Purpose == "" || req.Purpose != purposeDigest(r.Purpose) {
		return "", r, errors.New("that request is not the one shown; nothing was approved — reopen the list")
	}
	return dir, r, nil
}

// pipeApproveMu makes the throttle's check, the attempt and the count one step:
// without it, pipeMaxClients connections could each pass the check before any
// of their failures was recorded.
var pipeApproveMu sync.Mutex

func pipeApprove(req pipeRequest, c pipeClient, now time.Time) pipeResponse {
	// FAILS CLOSED ON A SLOW DIRECTORY. The rules above decide by SID, but an
	// approval's audit line names the account that gave it, and when the
	// directory could not say whose account this is, nothing is approved.
	// Before the throttle and the code, so this counts as no wrong code.
	if c.NameTimedOut {
		return pipeResponse{Error: "not approved: this machine's account directory did not answer for " + c.UserSID +
			" in time; try again in a minute, or approve from an Administrator terminal"}
	}
	pipeApproveMu.Lock()
	defer pipeApproveMu.Unlock()
	code := strings.TrimSpace(req.Code)
	if code == "" {
		return pipeResponse{Error: "enter the code from the authenticator enrolled on this machine"}
	}
	dir, _, err := pipeTarget(req)
	if err != nil {
		return pipeResponse{Error: err.Error()}
	}
	stepupMu.Lock()
	thr := pipeThrottleLoad(dir)
	stepupMu.Unlock()
	if why := pipeThrottleRefusal(thr, now); why != "" {
		return pipeResponse{Error: why}
	}
	if _, err := stepupApproveRequest(dir, req.ID, code); err != nil {
		if pipeCodeError(err) {
			pipeThrottleFail(dir, now)
			dcnAudit(dir, "stepup_approve_tray", 0, "", "refused for "+pipeWho(c)+": "+err.Error())
		}
		return pipeResponse{Error: "not approved: " + err.Error()}
	}
	dcnAudit(dir, "stepup_approve_tray", 0, "", "approved by "+pipeWho(c))
	return pipeResponse{OK: true, Message: "Approved. " + req.Host + " picks this up on its next check-in, within a minute."}
}

func pipeDeny(req pipeRequest, c pipeClient) pipeResponse {
	dir, _, err := pipeTarget(req)
	if err != nil {
		return pipeResponse{Error: err.Error()}
	}
	// No code, as on every other lane: refusing is the safe direction.
	if err := stepupDenyRequest(dir, req.ID); err != nil {
		return pipeResponse{Error: "not denied: " + err.Error()}
	}
	dcnAudit(dir, "stepup_deny_tray", 0, "", "denied by "+pipeWho(c))
	return pipeResponse{OK: true, Message: "Denied. " + req.Host + " is told on its next check-in."}
}

// ── the accept loop ─────────────────────────────────────────────────────────

// errPipeStopped: a wait ended because the service is stopping.
var errPipeStopped = errors.New("stopped")

// pipeInstances is the pipe as pipeAcceptLoop sees it. approvalPipeServer
// (approvalpipe_windows.go) is the real one; the suite drives a fake, so the
// loop's one invariant is checked off Windows.
type pipeInstances[T any] interface {
	// create opens a new server instance of the pipe's name.
	create() (T, error)
	// connect waits for a client on t: nil once one is connected,
	// errPipeStopped when the service stopped first.
	connect(t T) error
	// release closes t.
	release(t T)
}

// pipeAcceptLoop serves the pipe until stop is closed, handing each connected
// instance to serve on its own goroutine, at most maxClients at once.
//
// NO GAP IN THE NAME. From the first create until stop, one of our instances
// is always open: a pipe's name exists only while an instance of it is, and in
// a gap any process could create the name and be the server the tray dials
// next. So a replacement is always created BEFORE the instance it replaces is
// released, after a connect that worked and after one that failed (a client
// that connects and closes at once fails the connect, and can do that on
// purpose, as often as it likes).
//
// ready, when not nil, is called once the first instance exists: from then on
// the service holds the name.
func pipeAcceptLoop[T any](p pipeInstances[T], stop <-chan struct{}, maxClients int, retry time.Duration,
	logf func(string, ...any), ready func(), serve func(T)) error {
	slots := make(chan struct{}, maxClients)
	next, err := p.create()
	if err != nil {
		return err
	}
	if ready != nil {
		ready()
	}
	for {
		c := next
		select {
		case slots <- struct{}{}:
		case <-stop:
			p.release(c)
			return nil
		}
		if err := p.connect(c); err != nil {
			<-slots
			if errors.Is(err, errPipeStopped) {
				p.release(c)
				return nil
			}
			// One failed connect is that client's. Its replacement is created
			// while it is still open, and only then is it closed: no gap.
			fresh, cerr := p.create()
			p.release(c)
			if cerr != nil {
				return cerr
			}
			next = fresh
			continue
		}
		// The next instance first, while this one is still open: no gap.
		for {
			if next, err = p.create(); err == nil {
				break
			}
			logf("approvals pipe: %v; retrying\n", err)
			select {
			case <-stop:
				p.release(c)
				return nil
			case <-time.After(retry):
			}
		}
		go func(c T) {
			defer func() { <-slots }()
			defer p.release(c)
			serve(c)
		}(c)
	}
}

// pipeRetryFirst and pipeRetryMax bound the wait between attempts to serve
// the pipe after one failed.
const (
	pipeRetryFirst = time.Second
	pipeRetryMax   = time.Minute
)

// pipeServeRetrying runs serve until stop (serve returns nil), starting it
// again whenever it fails. serve calls ready once it holds the pipe's name.
// wait sleeps, and reports false when the service stopped meanwhile.
//
// THE NAME TAKEN AT START. A process that creates the pipe's name before the
// service does (at boot, or in the five seconds of a restart) makes the
// service's first create fail, because that create insists on the name being
// new (FILE_FLAG_FIRST_PIPE_INSTANCE): the service never serves under a name it
// did not create. Rather than leaving the tray off until the next restart, the
// service tries again, waiting pipeRetryFirst and doubling to pipeRetryMax,
// and starts the wait again once it holds the name. The log says so once per
// series of failed attempts and once when serving again, not once per try.
func pipeServeRetrying(serve func(ready func()) error, wait func(time.Duration) bool, logf func(string, ...any)) {
	backoff := pipeRetryFirst
	failing := false
	for {
		err := serve(func() {
			if failing {
				logf("approvals pipe: serving again\n")
				failing = false
			}
			backoff = pipeRetryFirst
		})
		if err == nil {
			return
		}
		if !failing {
			logf("approvals pipe: %v. Approvals are answered from an Administrator terminal meanwhile; "+
				"retrying, waiting up to %s between attempts.\n", err, pipeRetryMax)
			failing = true
		}
		if !wait(backoff) {
			return
		}
		if backoff *= 2; backoff > pipeRetryMax {
			backoff = pipeRetryMax
		}
	}
}

// pipeDecode reads one request, refusing anything that is not one JSON object
// within pipeMaxRequest.
func pipeDecode(raw []byte) (pipeRequest, error) {
	var req pipeRequest
	if len(raw) > pipeMaxRequest {
		return req, errors.New("request too large")
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, errors.New("not a request")
	}
	return req, nil
}
