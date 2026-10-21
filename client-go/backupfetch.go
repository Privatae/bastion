package main

// backup_fetch — the bastion PULLS a backup artifact onto the user's own machine.
//
// WHY PULL AND NOT PUSH, measured rather than assumed. The obvious route was
// ctx_put: it already writes a blob under a sandboxed root and it is already
// granted. It cannot carry a backup. The whole management job is ONE WebSocket
// frame (`C` + JSON of {op,args}, the host's mgmt worker)
// and the payload rides inside args[1] as base64, so nothing streams and the
// bytes are buffered whole on both sides. Measured (ctxcap_measure_test.go):
// the frame crosses the host's 16 MiB WebSocket frame ceiling — its live
// limit, since nothing overrides the server default — at just under 12 MiB of
// plaintext. A 13 GiB export (a real entity's tree) is 1,110 sequential
// dispatches, each one job per
// worker connection, against a 30 s host-side dispatch timeout. Chunking that
// would be a file-transfer protocol written on top of a command channel.
//
// So the host sends a short-lived signed URL and a digest, and this machine
// fetches it over its OWN internet connection, streaming to disk with constant
// memory. The artifact is already encrypted, to keys the platform does not hold,
// before it leaves the host, so the URL is not a
// secret worth much and the bytes are not readable in flight by anyone.
//
// ASYNC, because the host cannot wait. The host's management dispatch has a
// 30 s timeout; a multi-gigabyte download does not finish inside that. `start`
// validates, spawns, and returns a job id immediately; `status` reports
// progress. Each call is its own short dispatch. (The 25 s mgmtCmdTimeout in
// mgmt.go does NOT apply here — it wraps only the p8 shell exec path.)
//
// WHAT THIS REFUSES, and why each one is here rather than assumed safe:
//   * a non-HTTPS URL — the digest would still catch tampering, but there is no
//     reason to fetch a backup in the clear;
//   * a URL that resolves to this machine or to a private/link-local address —
//     the host chooses this URL, and this process sits INSIDE the user's
//     network. Without the check, "fetch my backup" is a request the host can
//     point at the user's router. The egress lane can already reach the LAN,
//     but it is separately granted and separately audited; this op has no
//     legitimate need, so it does not get the reach.
//   * a body larger than the declared max — a hostile or buggy host must not be
//     able to fill the user's disk;
//   * a digest or length that does not match what arrived — verified BEFORE the
//     file is put in place, so a truncated download never appears as a backup.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// A backup fetch is long by nature; this bounds a stall, not a big file.
	backupFetchTimeout = 6 * time.Hour
	// Nothing to do with the artifact size — this is the read buffer.
	backupFetchChunk = 1 << 20
	// Refuse anything the caller has not sized. Also the ceiling when the
	// declared size is absurd: 512 GiB is far past any entity and still leaves
	// the check meaningful.
	backupFetchMaxBytes = 512 << 30
)

type backupJob struct {
	ID       string `json:"id"`
	RPath    string `json:"rpath"`
	Want     int64  `json:"want_bytes"`
	SHA256   string `json:"sha256"`
	Got      int64  `json:"got_bytes"`
	State    string `json:"state"` // running | done | failed
	Error    string `json:"error,omitempty"`
	Started  string `json:"started_at"`
	Finished string `json:"finished_at,omitempty"`
	Path     string `json:"path,omitempty"`
	// Pruned is how many older backup files the arrival of this one retired
	// from its folder (backupretention.go).
	Pruned int `json:"pruned,omitempty"`
	// root is the pairing's backup folder: a status call from another
	// pairing reads this job as unknown, and a backup file that lands at its
	// top is recorded as an arrival there.
	root    string
	arrival bool
}

var (
	backupJobsMu sync.Mutex
	backupJobs   = map[string]*backupJob{}
)

// backupRootPath is backupRoot without creating it: the folder this pairing's
// backups WOULD go to, for comparing pairings without touching the disk.
func (c *Config) backupRootPath() string {
	if c.BackupRoot != "" {
		return c.BackupRoot
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "privatae-bastion", "backups", c.HostName)
}

// backupRoot returns the directory this bastion writes fetched backups into.
//
// Defaults to backups/<host_name> under the bastion's config dir, mirroring
// contextRoot() exactly — per host, because one daemon serves many and their
// artifacts must not mix. A user who wants them on a NAS sets `backup_root` in
// this pairing's config to the mount point; it is deliberately a local choice,
// because a destination the HOST could pick is not a sandbox.
//
// "" on any failure to resolve or create it, and the mgmt lane then refuses the
// op the same way it refuses ctx_* with no context store.
func (c *Config) backupRoot() string {
	root := c.backupRootPath()
	if root == "" {
		return ""
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return ""
	}
	return root
}

type backupFetchReq struct {
	Op       string `json:"op"`     // start | status
	JobID    string `json:"job_id"` // status
	URL      string `json:"url"`    // start
	RPath    string `json:"rpath"`  // start — relative, sandboxed under backupRoot
	SHA256   string `json:"sha256"` // start — of the artifact as served
	Size     int64  `json:"size"`   // start — expected bytes
	MaxBytes int64  `json:"max_bytes"`
}

// handleBackupFetch serves both ops on the single `backup_fetch` job name, so
// the host-side allowlist grants one op rather than two.
func handleBackupFetch(ws *websocket.Conn, root string, args []string) {
	if len(args) < 1 {
		backupFail(ws, "backup_fetch: need a JSON argument")
		return
	}
	var req backupFetchReq
	if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
		backupFail(ws, "backup_fetch: argument is not JSON: "+err.Error())
		return
	}
	switch req.Op {
	case "status":
		backupStatus(ws, root, req.JobID)
	case "start", "":
		backupStart(ws, root, req)
	default:
		backupFail(ws, "backup_fetch: unknown op "+req.Op)
	}
}

// backupFail refuses with msg, with any signed URL's query taken out: a URL
// the host sent can end up quoted in an error, and its signature does not
// belong in a reply or a log.
func backupFail(ws *websocket.Conn, msg string) {
	sendMgmt(ws, 'R', []byte(redactURLs(msg)+"\n"))
	sendMgmtExit(ws, 1)
}

func backupOK(ws *websocket.Conn, v any) {
	b, _ := json.Marshal(v)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

func backupStatus(ws *websocket.Conn, root, id string) {
	backupJobsMu.Lock()
	j, ok := backupJobs[id]
	var snap backupJob
	if ok {
		snap = *j
	}
	backupJobsMu.Unlock()
	// Another pairing's job reads exactly as a job this bastion never had.
	if !ok || snap.root != root {
		// A restart loses in-flight jobs. Say "unknown", not "failed": the host
		// re-starts the fetch, which is idempotent on (rpath, sha256).
		backupOK(ws, map[string]string{"state": "unknown", "id": id})
		return
	}
	backupOK(ws, snap)
}

func backupStart(ws *websocket.Conn, root string, req backupFetchReq) {
	abs, arrival, why := backupFetchDest(root, req.RPath)
	if why != "" {
		backupFail(ws, "backup_fetch: "+why)
		return
	}
	if len(req.SHA256) != 64 {
		backupFail(ws, "backup_fetch: sha256 must be 64 hex characters")
		return
	}
	if _, err := hex.DecodeString(req.SHA256); err != nil {
		backupFail(ws, "backup_fetch: sha256 is not hex")
		return
	}

	// IDEMPOTENT, AND CHECKED BEFORE THE URL. If the artifact is already here
	// and already correct, say done without fetching it again — a retry after a
	// bastion restart, or a host that lost our reply, must not re-download
	// gigabytes.
	//
	// The order matters and was wrong first time round (caught by
	// TestBackupFetchIsIdempotent): validating the URL first meant a retry whose
	// signed URL had since EXPIRED — or that arrived while DNS was down —
	// re-failed even though the correct bytes were already sitting on disk. The
	// local check is free and needs no network; do it first.
	//
	// The digest comes from what this bastion already knows about the file
	// (the record of what it fetched, the hash cache) and is read from disk
	// only for a file small enough to hash well inside one dispatch; a large
	// file with no known digest is fetched again.
	if sum, n, err := knownOrQuickHash(root, abs); err == nil && sum == strings.ToLower(req.SHA256) &&
		(req.Size == 0 || n == req.Size) {
		backupOK(ws, backupJob{ID: "already-present", RPath: req.RPath, State: "done",
			Got: n, Want: n, SHA256: sum, Path: abs,
			Finished: time.Now().UTC().Format(time.RFC3339)})
		return
	}

	if err := validateBackupURL(req.URL); err != nil {
		backupFail(ws, "backup_fetch: "+err.Error())
		return
	}
	max := req.MaxBytes
	if max <= 0 {
		max = req.Size
	}
	if max <= 0 || max > backupFetchMaxBytes {
		backupFail(ws, fmt.Sprintf(
			"backup_fetch: size/max_bytes must be between 1 and %d", int64(backupFetchMaxBytes)))
		return
	}

	id := newBackupJobID("bf")
	job := &backupJob{ID: id, RPath: req.RPath, Want: req.Size, SHA256: strings.ToLower(req.SHA256),
		State: "running", Started: time.Now().UTC().Format(time.RFC3339), root: root, arrival: arrival}
	backupJobsMu.Lock()
	backupJobs[id] = job
	backupJobsMu.Unlock()

	go runBackupFetch(job, req.URL, abs, max)
	backupOK(ws, map[string]string{"id": id, "state": "running"})
}

func runBackupFetch(job *backupJob, rawURL, abs string, max int64) {
	finish := func(state, errMsg, path string) {
		backupJobsMu.Lock()
		job.State, job.Error, job.Path = state, redactURLs(errMsg), path
		job.Finished = time.Now().UTC().Format(time.RFC3339)
		backupJobsMu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), backupFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		finish("failed", err.Error(), "")
		return
	}
	// Re-check every redirect hop: a signed URL that 302s to a private address
	// would otherwise walk straight past the check done at start().
	// THE ADDRESS DIALLED IS THE ADDRESS CHECKED. validateBackupURL resolves
	// the name for the check and the transport would resolve it again for the
	// dial — a rebinding name answers public to the first and private to the
	// second. The dialer's Control hook sees the address actually connected
	// to and refuses one that is not public (the same fix egress got).
	dialer := &net.Dialer{Timeout: 30 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || !backupDialAllowed(ip) {
			return fmt.Errorf("refused: %s is on this machine or this network — a backup source must be a public address", host)
		}
		return nil
	}}
	// The default transport, cloned, with only the dial replaced — its TLS
	// settings (and whatever the tests put in them) stay as they were.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	// NO PROXY. Through an environment proxy the hook would vet the proxy's
	// address and the proxy would resolve the target itself, outside it; the
	// backup source is fetched directly or not at all.
	transport.Proxy = nil
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return validateBackupURL(r.URL.String())
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		finish("failed", err.Error(), "")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The status code is the diagnosis the user needs: 403 on a signed URL
		// means it expired, which is a different problem from a 404.
		finish("failed", fmt.Sprintf("source returned HTTP %d", resp.StatusCode), "")
		return
	}

	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		finish("failed", err.Error(), "")
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".backup-*.part")
	if err != nil {
		finish("failed", err.Error(), "")
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		finish("failed", err.Error(), "")
		return
	}

	h := sha256.New()
	buf := make([]byte, backupFetchChunk)
	var total int64
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > max {
				_ = tmp.Close()
				finish("failed", fmt.Sprintf(
					"source is larger than the declared %d bytes — stopped", max), "")
				return
			}
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				_ = tmp.Close()
				finish("failed", werr.Error(), "")
				return
			}
			h.Write(buf[:n])
			backupJobsMu.Lock()
			job.Got = total
			backupJobsMu.Unlock()
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = tmp.Close()
			finish("failed", rerr.Error(), "")
			return
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		finish("failed", err.Error(), "")
		return
	}
	if err := tmp.Close(); err != nil {
		finish("failed", err.Error(), "")
		return
	}

	// VERIFY BEFORE PUBLISHING. A truncated or substituted download must never
	// end up sitting at the destination path looking like a backup.
	got := hex.EncodeToString(h.Sum(nil))
	if got != job.SHA256 {
		finish("failed", fmt.Sprintf("sha256 mismatch: got %s, expected %s", got, job.SHA256), "")
		return
	}
	if job.Want > 0 && total != job.Want {
		finish("failed", fmt.Sprintf("size mismatch: got %d bytes, expected %d", total, job.Want), "")
		return
	}
	if err := os.Rename(tmpName, abs); err != nil {
		finish("failed", err.Error(), "")
		return
	}
	// Record the arrival, then thin the folder now that a new backup is
	// safely in it (backupretention.go). A failure of either is not a failed
	// fetch: the backup arrived.
	if job.arrival {
		if err := recordArrival(job.root, filepath.Base(abs), got, time.Now()); err == nil {
			if removed, err := pruneBackupRoot(job.root, filepath.Base(abs)); err == nil && len(removed) > 0 {
				backupJobsMu.Lock()
				job.Pruned = len(removed)
				backupJobsMu.Unlock()
			}
		}
	}
	finish("done", "", abs)
}

// validateBackupURL is the SSRF wall. The host picks this URL and this process
// runs inside the user's network, so "https and not pointed at your own LAN" is
// the minimum. Every resolved address must be public — a name that resolves to
// one public and one private address is refused, because which one gets dialled
// is not ours to predict.
func validateBackupURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("url is not parseable: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("url must be https (got %q)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url has no host")
	}
	ips, err := backupLookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%s resolves to nothing", host)
	}
	for _, ip := range ips {
		if !backupAddrAllowed(ip) {
			return fmt.Errorf(
				"%s resolves to %s, which is on this machine or this network — "+
					"a backup source must be a public address", host, ip)
		}
	}
	return nil
}

// backupLookupIP is net.LookupIP; a test answers for a name without DNS.
var backupLookupIP = net.LookupIP

// backupDialAllowed is the dial-time wall (backupAddrAllowed). A package var
// only so the fetch tests, which serve the artifact from a loopback test
// server, can let loopback through at the dial while keeping the wall on
// everything else in the same binary.
var backupDialAllowed = backupAddrAllowed

// backupAddrAllowed is the wall both backup lanes apply, to every address a
// name resolves to and again to the address dialled: a public address that is
// not this machine. A public address can still be this machine (one on its
// NIC, or a range a `local` route delivers here; ownaddr.go), and a service on
// 0.0.0.0 answers there. When the machine cannot tell, it refuses.
func backupAddrAllowed(ip net.IP) bool {
	if !isPublicIP(ip) {
		return false
	}
	own, err := ownDestination([]net.IP{ip})
	return err == nil && !own
}

// isPublicIP classifies the address alone; whether it is this machine is
// backupAddrAllowed's question. It is the coder lane's classifier
// (coderInternalIP, coder_egress.go), so the backup lanes refuse what a coder
// run's proxy refuses: loopback, private, link-local, multicast, unspecified,
// CGNAT, ULA, 0.0.0.0/8, 198.18.0.0/15 and 240.0.0.0/4, site-local fec0::/10,
// IPv4-compatible ::/96 and IPv4-translated ::ffff:0:0/96, the 64:ff9b::/32
// NAT64 space beyond the well-known prefix, and a NAT64 64:ff9b::/96, 6to4
// 2002::/16 or IPv4-mapped address whose IPv4 address is any of those.
func isPublicIP(ip net.IP) bool {
	return !coderInternalIP(ip)
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// quickHashMax is the largest file start hashes inside a dispatch: about a
// second or two of reading on ordinary disks, well inside the host's 30 s.
const quickHashMax = 512 << 20

// knownOrQuickHash is the digest of the file at abs from what this bastion
// already knows (the hash cache, the arrivals record), or read from disk when
// it is small; a large file with no known digest is an error.
func knownOrQuickHash(root, abs string) (string, int64, error) {
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, fmt.Errorf("not a file")
	}
	if sum := cachedHash(abs, fi); sum != "" {
		return sum, fi.Size(), nil
	}
	if filepath.Dir(abs) == filepath.Clean(root) {
		backupStateMu.Lock()
		a, err := arrivalsLoadLocked(root)
		backupStateMu.Unlock()
		if err == nil {
			if rec, ok := a.Files[filepath.Base(abs)]; ok && stillTheArrival(fi, rec) {
				return rec.SHA256, fi.Size(), nil
			}
		}
	}
	if fi.Size() > quickHashMax {
		return "", 0, fmt.Errorf("digest not known")
	}
	sum, n, err := hashFile(abs)
	if err == nil {
		noteHash(abs, fi, sum)
	}
	return sum, n, err
}

// backupFetchDest is where a fetch of rpath lands. A backup file
// (<stamp>.tar.zst.age, <stamp>.key.age) lands at the top of this pairing's
// own backup folder, whatever folder the host named: that is the one place
// thinning looks (backupretention.go) and the one place backup_list reads,
// so the host cannot scatter backups where they are never thinned. Anything
// else lands where the host named, inside the folder (cleanRel).
func backupFetchDest(root, rpath string) (string, bool, string) {
	abs, ok := cleanRel(root, rpath)
	if !ok {
		return "", false, "path rejected"
	}
	if base := filepath.Base(abs); backupFileRe.MatchString(base) {
		return filepath.Join(root, base), true, ""
	}
	return abs, false, ""
}
