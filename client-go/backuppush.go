package main

// backuppush.go — backup_push: send a backup this machine holds to a
// short-lived signed upload URL the host hands over.
//
// This is the way back for a backup that exists only here: a host being
// restored cannot reach this machine's disk, so it asks for the one backup
// file it needs to be put where it can fetch it. The file is ciphertext a
// host wrote (only a registered key, or a one-backup key resealed with the
// person's approval, opens it), so this is standing work under the backup
// folder the person configured here, like backup_fetch.
//
// What it refuses, each for the same reason as backup_fetch:
//   - any file that is not named like a backup (<stamp>.tar.zst.age or
//     <stamp>.key.age), not directly inside this pairing's backup folder or a
//     folder the person shared with it (backuplist.go), reached through a link
//     that leaves that folder, or itself a link;
//   - a file whose sha256 is not the one the host named — the host must say
//     which bytes it wants, and gets exactly those;
//   - any URL that is not https or resolves to this machine or its network
//     (validateBackupURL), checked again at the address actually dialled.
//
// HEADERS. The upload URL comes with the headers its signature covers
// (`headers`, as the platform's backup.put_url returns them). The platform
// signs exactly one: If-None-Match: *, so the storage refuses to write over an
// object that is there; without it the storage answers 403. That header, with
// that value, is the only one a host may hand over (the name in any case);
// every other name, and any other value, is refused at start, so the host
// cannot put anything else on this machine's request. No headers at all is
// refused too: the platform always hands the header over, so a start without
// it comes from a broken or tampered host.
//
// `start` answers at once: the file is hashed and checked in the background
// job, before anything is sent, because reading gigabytes does not fit in one
// dispatch. The host polls `status`, which answers only for jobs this pairing
// started. No reply or job error quotes the signed URL's query.
//
// A DEAD MOUNT. A job whose file stops answering fails at backupPushFileStall,
// but the read it was in cannot be stopped: it keeps a goroutine, an OS thread
// and the open file until the mount answers or goes away. Pushes and the
// background hashing keep their reads in one record (backupReads,
// backupstate.go): a start in a folder with a read of either that has not
// returned is refused with a sentence until it does, and the whole bastion
// keeps at most backupReadsMax reads of both.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// backupPushReq is the host's ask, in the same shape as backup_fetch's: one
// JSON argument, {"op":"start",...} or {"op":"status","job_id":...}. `path`
// is relative to the backup folder.
type backupPushReq struct {
	Op     string `json:"op"` // start | status
	JobID  string `json:"job_id"`
	Path   string `json:"path"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	// Headers the upload URL was signed with, sent on the PUT as given.
	Headers map[string]string `json:"headers"`
}

// backupPushAllowedHeaders is every header a host may hand over with an
// upload URL, with the one value each may have: what the platform's
// backup.put_url signs into the URL. A change there is a change here.
var backupPushAllowedHeaders = map[string]string{"If-None-Match": "*"}

// backupPushHeaders checks the headers a host hands over with an upload URL
// against backupPushAllowedHeaders and returns them ready to send.
func backupPushHeaders(in map[string]string) (http.Header, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("no headers came with the upload address; the platform signs " +
			"If-None-Match: * into every one and hands it over, so the host that asked is broken or not the platform's")
	}
	h := http.Header{}
	for k, v := range in {
		ck := http.CanonicalHeaderKey(k)
		want, ok := backupPushAllowedHeaders[ck]
		if !ok {
			return nil, fmt.Errorf("header %q is not one an upload address is signed with (only If-None-Match: *)", clip(k, 64))
		}
		if v != want {
			return nil, fmt.Errorf("header %s must be %q, not %q", ck, want, clip(v, 64))
		}
		h.Set(ck, v)
	}
	return h, nil
}

// clip is s cut to at most n bytes, for quoting what a host sent.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type backupPushJob struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
	State    string `json:"state"` // pending | done | failed
	Error    string `json:"error,omitempty"`
	Started  string `json:"started_at"`
	Finished string `json:"finished_at,omitempty"`
	root     string
	done     time.Time
	headers  http.Header // sent on the PUT (backupPushHeaders)
}

// A finished push is forgotten after this long; the host reads the outcome
// within a poll or two.
const backupPushKeep = 24 * time.Hour

var backupPushJobs = map[string]*backupPushJob{}

// backupPushFileStall bounds one operation on the file being pushed (a stat,
// the open, one read). A backup folder on a network mount that stopped
// answering can leave a read that never returns; past the bound the job fails
// with a sentence and its upload is stopped, instead of staying pending. It
// bounds a stall, not a big file: reads that keep returning never trip it, and
// neither does a slow upload (no file read is in flight while the network
// takes the bytes).
//
// backupPushRead is one read of the file being pushed; a test replaces it with
// one that never returns. Both are read under backupPushHookMu.
var (
	backupPushHookMu    sync.Mutex
	backupPushFileStall = 2 * time.Minute
	backupPushRead      = func(f *os.File, p []byte) (int, error) { return f.Read(p) }
)

// ── one file operation per folder at a time ────────────────────────────────
//
// Every operation of a push on its file (a stat, the open, a read) holds its
// folder's push slot in backupReads (backupstate.go) while it runs, and counts
// toward backupReadsMax. Operations are short, so pushes from one folder, or
// from many, barely wait on each other. An operation that never returns keeps
// its slot until it does: a push behind it waits no longer than its bound and
// then fails with a sentence naming what it waited on, without an operation
// of its own, so a dead mount holds one stuck push read however often a push
// is started there. The slot is freed when the operation returns.

// pushStallBound is backupPushFileStall, read under backupPushHookMu.
func pushStallBound() time.Duration {
	backupPushHookMu.Lock()
	defer backupPushHookMu.Unlock()
	return backupPushFileStall
}

// pushSlotWait is a push that waited past its bound for a slot to read its
// file; the error is the sentence the job fails with.
type pushSlotWait struct{ why string }

func (e *pushSlotWait) Error() string { return e.why }

// pushSlotTake takes dir's push slot for one operation on rel, a file in dir.
// It waits while dir's push slot is held, while dir's hashing read is stuck,
// or while backupReadsMax reads are in flight; for at most pushBound, then it
// returns a *pushSlotWait saying which; and not past ctx.
func pushSlotTake(ctx context.Context, dir, rel string, pushBound, hashBound time.Duration) error {
	timer := time.NewTimer(pushBound)
	defer timer.Stop()
	late := false
	for {
		backupReadMu.Lock()
		now := time.Now()
		r := backupReads[dir]
		_, stuck := folderStuckLocked(dir, now, pushBound, hashBound)
		here := r != nil && !r.push.IsZero()
		inFlight := readsInFlightLocked()
		if !here && !stuck && inFlight < backupReadsMax {
			if r == nil {
				r = &folderReads{}
				backupReads[dir] = r
			}
			r.push = now
			backupReadMu.Unlock()
			return nil
		}
		if late {
			why, ok := folderStuckLocked(dir, now, pushBound, hashBound)
			backupReadMu.Unlock()
			if !ok && here {
				why = "an earlier push"
			}
			msg := fmt.Sprintf("this push waited more than %s for a turn to read its file: ", pushBound)
			if why != "" {
				msg += folderRefusal(rel, why)
			} else {
				msg += capRefusal(inFlight)
			}
			return &pushSlotWait{msg}
		}
		freed := backupReadFreed
		backupReadMu.Unlock()
		select {
		case <-freed:
		case <-timer.C:
			late = true
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func folderRefusal(rel, what string) string {
	return fmt.Sprintf("the folder of %s has not answered %s (a network mount that stopped?); "+
		"nothing more is sent from that folder until it answers", rel, what)
}

func capRefusal(n int) string {
	return fmt.Sprintf("%d reads of backup folders have not returned (network mounts that stopped?); "+
		"no push starts on this machine until one does", n)
}

// pushSlotRefusal is why a push of rel, a file in dir, may not start now, or
// "" when it may: a read of dir (a push's or the hashing job's) has been in
// flight past its bound, or backupReadsMax reads have.
func pushSlotRefusal(dir, rel string, pushBound, hashBound time.Duration) string {
	now := time.Now()
	backupReadMu.Lock()
	defer backupReadMu.Unlock()
	if what, stuck := folderStuckLocked(dir, now, pushBound, hashBound); stuck {
		return folderRefusal(rel, what)
	}
	if n := stuckReadsLocked(now, pushBound, hashBound); n >= backupReadsMax {
		return capRefusal(n)
	}
	return ""
}

// fileWatch records since when an operation on the pushed file has been in
// flight (zero when none is). The wait for its folder's slot before it is not
// an operation on the file, and is bounded on its own (pushSlotTake).
type fileWatch struct {
	mu        sync.Mutex
	since     time.Time
	ctx       context.Context
	job       *backupPushJob
	dir       string
	pushBound time.Duration
	hashBound time.Duration
}

// do runs f holding the folder's slot. It returns an error, without running
// f, when the job ended while it waited for the slot, or when the wait
// outlasted its bound; then the job fails with the sentence of why.
func (w *fileWatch) do(f func()) error {
	if err := pushSlotTake(w.ctx, w.dir, w.job.Path, w.pushBound, w.hashBound); err != nil {
		var late *pushSlotWait
		if errors.As(err, &late) {
			finishPush(w.job, "failed", late.why)
		}
		return err
	}
	defer backupReadFree(w.dir, false)
	w.mu.Lock()
	w.since = time.Now()
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.since = time.Time{}
		w.mu.Unlock()
	}()
	f()
	return nil
}

func (w *fileWatch) stuckFor(now time.Time) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.since.IsZero() {
		return 0
	}
	return now.Sub(w.since)
}

// watchedFile reads the pushed file under the watch.
type watchedFile struct {
	f    *os.File
	w    *fileWatch
	read func(*os.File, []byte) (int, error)
}

func (r watchedFile) Read(p []byte) (n int, err error) {
	if e := r.w.do(func() { n, err = r.read(r.f, p) }); e != nil {
		return 0, e
	}
	return n, err
}

func handleBackupPush(ws *websocket.Conn, root string, args []string) {
	if len(args) < 1 {
		backupFail(ws, "backup_push: need a JSON argument")
		return
	}
	var req backupPushReq
	if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
		backupFail(ws, "backup_push: argument is not JSON: "+err.Error())
		return
	}
	switch req.Op {
	case "status":
		backupJobsMu.Lock()
		j, ok := backupPushJobs[req.JobID]
		var snap backupPushJob
		if ok {
			snap = *j
		}
		backupJobsMu.Unlock()
		// Another pairing's job reads exactly as a job this bastion never had.
		if !ok || snap.root != root {
			backupOK(ws, map[string]string{"job_id": req.JobID, "state": "unknown"})
			return
		}
		out := map[string]string{"job_id": snap.ID, "state": snap.State}
		if snap.Error != "" {
			out["error"] = snap.Error
		}
		backupOK(ws, out)
	case "start", "":
		backupPushStart(ws, root, req)
	default:
		backupFail(ws, "backup_push: unknown op "+req.Op)
	}
}

func backupPushStart(ws *websocket.Conn, root string, req backupPushReq) {
	abs, why := backupResolveFile(mgmtSelf(ws), root, req.Path)
	if why != "" {
		backupFail(ws, "backup_push: "+why)
		return
	}
	if _, err := hex.DecodeString(req.SHA256); err != nil || len(req.SHA256) != 64 {
		backupFail(ws, "backup_push: sha256 must be 64 hex characters")
		return
	}
	if err := validateBackupURL(req.URL); err != nil {
		backupFail(ws, "backup_push: "+err.Error())
		return
	}
	headers, err := backupPushHeaders(req.Headers)
	if err != nil {
		backupFail(ws, "backup_push: "+err.Error())
		return
	}
	if why := pushSlotRefusal(filepath.Dir(abs), req.Path, pushStallBound(), hashBound()); why != "" {
		backupFail(ws, "backup_push: "+why)
		return
	}
	now := time.Now()
	job := &backupPushJob{ID: newBackupJobID("bp"), Path: req.Path, SHA256: strings.ToLower(req.SHA256),
		State: "pending", Started: now.UTC().Format(time.RFC3339), root: root, headers: headers}
	backupJobsMu.Lock()
	for id, j := range backupPushJobs {
		if !j.done.IsZero() && now.Sub(j.done) > backupPushKeep {
			delete(backupPushJobs, id)
		}
	}
	backupPushJobs[job.ID] = job
	backupJobsMu.Unlock()
	go runBackupPush(job, req.URL, abs)
	backupOK(ws, map[string]string{"job_id": job.ID, "state": "pending"})
}

// finishPush records the outcome of a push job. The first outcome stands:
// a read that returns after the job was failed for not returning changes
// nothing.
func finishPush(job *backupPushJob, state, msg string) {
	backupJobsMu.Lock()
	defer backupJobsMu.Unlock()
	if job.State != "pending" {
		return
	}
	job.State, job.Error = state, redactURLs(msg)
	job.done = time.Now()
	job.Finished = job.done.UTC().Format(time.RFC3339)
}

// runBackupPush runs the push and watches its file: when an operation on the
// file has not returned within backupPushFileStall, the job fails and the
// upload is stopped. A stuck operation cannot be stopped; it keeps its
// folder's slot until it returns by itself. A wait for the slot is not an
// operation on the file; it fails the job on its own bound (fileWatch.do).
func runBackupPush(job *backupPushJob, rawURL, abs string) {
	ctx, cancel := context.WithTimeout(context.Background(), backupFetchTimeout)
	defer cancel()
	backupPushHookMu.Lock()
	bound, read := backupPushFileStall, backupPushRead
	backupPushHookMu.Unlock()
	w := &fileWatch{ctx: ctx, job: job, dir: filepath.Dir(abs), pushBound: bound, hashBound: hashBound()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pushFile(ctx, job, rawURL, abs, w, read)
	}()
	every := bound / 4
	if every < 10*time.Millisecond {
		every = 10 * time.Millisecond
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-tick.C:
			if w.stuckFor(now) > bound {
				finishPush(job, "failed", fmt.Sprintf("the backup folder stopped answering: an operation on the file "+
					"did not return within %s (a network mount that stopped?); the upload was stopped", bound))
				return
			}
		}
	}
}

func pushFile(ctx context.Context, job *backupPushJob, rawURL, abs string, w *fileWatch,
	read func(*os.File, []byte) (int, error)) {
	finish := func(state, msg string) { finishPush(job, state, msg) }
	var before os.FileInfo
	var err error
	if e := w.do(func() { before, err = os.Lstat(abs) }); e != nil {
		finish("failed", e.Error())
		return
	}
	if err != nil || !before.Mode().IsRegular() {
		finish("failed", "no backup file at that path")
		return
	}
	var f *os.File
	if e := w.do(func() { f, err = os.Open(abs) }); e != nil {
		finish("failed", e.Error())
		return
	}
	if err != nil {
		finish("failed", err.Error())
		return
	}
	defer f.Close()
	// What was opened is what was checked: a link put in its place between
	// the check and the open is a different file, and is refused.
	var fi os.FileInfo
	if e := w.do(func() { fi, err = f.Stat() }); e != nil {
		finish("failed", e.Error())
		return
	}
	if err != nil || !os.SameFile(before, fi) {
		finish("failed", "the file changed while it was being opened")
		return
	}
	backupJobsMu.Lock()
	job.Bytes = fi.Size()
	backupJobsMu.Unlock()
	file := watchedFile{f, w, read}
	// The digest the host named, checked before anything is sent: from the
	// cache when this exact file (size and modification time) was hashed
	// already, else read once here.
	sum := cachedHash(abs, fi)
	if sum == "" {
		h := sha256.New()
		if _, err := io.Copy(h, file); err != nil {
			finish("failed", err.Error())
			return
		}
		sum = hex.EncodeToString(h.Sum(nil))
		noteHash(abs, fi, sum)
		if e := w.do(func() { _, err = f.Seek(0, io.SeekStart) }); e != nil {
			err = e
		}
		if err != nil {
			finish("failed", err.Error())
			return
		}
	}
	if sum != job.SHA256 {
		finish("failed", "the file at that path is not the one named (sha256 differs)")
		return
	}
	// The bytes sent are hashed again as they go. If the file changed after
	// the check, the job says so rather than done.
	h := sha256.New()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, io.TeeReader(io.LimitReader(file, fi.Size()), h))
	if err != nil {
		finish("failed", err.Error())
		return
	}
	for k, vs := range job.headers {
		req.Header[k] = append([]string(nil), vs...)
	}
	req.ContentLength = fi.Size()
	dialer := &net.Dialer{Timeout: 30 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || !backupDialAllowed(ip) {
			return fmt.Errorf("refused: %s is on this machine or this network — a backup destination must be a public address", host)
		}
		return nil
	}}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	transport.Proxy = nil
	client := &http.Client{Transport: transport,
		// A signed upload URL does not redirect; following one would send the
		// backup somewhere the host did not name.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		finish("failed", err.Error())
		return
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed {
		finish("failed", "the destination already holds an object there (HTTP 412); nothing was replaced")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		finish("failed", fmt.Sprintf("the destination answered HTTP %d", resp.StatusCode))
		return
	}
	if hex.EncodeToString(h.Sum(nil)) != job.SHA256 {
		finish("failed", "the file changed while it was being sent; what arrived is not the backup named")
		return
	}
	finish("done", "")
}
