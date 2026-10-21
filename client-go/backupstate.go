package main

// backupstate.go — what this bastion knows about the backups in a pairing's
// backup folder, kept where the host cannot write.
//
// Three records, all in the bastion's own state directory and never inside a
// backup folder: backup_fetch writes files into the backup folder on a host's
// say-so, so anything kept there could be rewritten by the host it describes.
//
//   - ARRIVALS: every backup file this bastion fetched into a folder, with its
//     sha256, size, modification time and the moment it arrived. Thinning
//     (backupretention.go) considers only these files, and only while each is
//     still the file that arrived (same size and modification time). A file
//     the person put in the folder, or one that was there before this
//     version, is never counted and never removed.
//   - HASHES: a cache of sha256 by (path, size, modification time), so a host
//     can be told the digest of a backup it did not fetch here (a replacement
//     host restoring the backups of the one it replaces) without a listing
//     reading gigabytes inside a 30-second dispatch. A miss starts ONE
//     background hashing job; the host lists again until the digest appears.
//   - SHARES: folders the person, at this machine, let one pairing's host read
//     through backup_list and backup_push — how a replacement host reaches the
//     copies its lost predecessor kept here. Kept by pairing, not by folder.
//     Only the person adds one (`privatae-bastion backup share`); no
//     management op writes this record; unpairing or revoking a pairing
//     takes its shares back.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// backupStateDir is overridable only so tests can point it somewhere else.
var backupStateDir = func() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "backup-state")
	return p, os.MkdirAll(p, 0o700)
}

// backupStateMu serialises every read-modify-write of the arrivals and share
// records in this process: fetch jobs finish on their own goroutines.
var backupStateMu sync.Mutex

func backupRootKey(root string) string {
	abs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		abs = filepath.Clean(root)
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:16]
}

// newBackupJobID is a random job id. Ids are not guessable, and a status call
// answers only for the pairing that started the job (the job's root).
func newBackupJobID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// redactURLs strips the query and fragment from every URL in a message, so an
// error that quotes a signed URL does not hand its signature to whoever reads
// the job's status or the host's logs.
var urlInTextRe = regexp.MustCompile(`((?:https?)://[^\s?#"']*)[?#][^\s"']*`)

func redactURLs(s string) string {
	return urlInTextRe.ReplaceAllString(s, "$1?(signature removed)")
}

// ── arrivals ───────────────────────────────────────────────────────────────

type backupArrival struct {
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	ModNs   int64  `json:"mtime_ns"`
	Arrived string `json:"arrived_at"`
}

type backupArrivals struct {
	Root  string                   `json:"root"`
	Files map[string]backupArrival `json:"files"`
}

func arrivalsPath(root string) (string, error) {
	d, err := backupStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "arrivals-"+backupRootKey(root)+".json"), nil
}

// arrivalsLoadLocked reads the record; the caller holds backupStateMu.
func arrivalsLoadLocked(root string) (*backupArrivals, error) {
	a := &backupArrivals{Root: root, Files: map[string]backupArrival{}}
	p, err := arrivalsPath(root)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, a); err != nil {
		return nil, fmt.Errorf("the record of fetched backups is unreadable: %w", err)
	}
	if a.Files == nil {
		a.Files = map[string]backupArrival{}
	}
	return a, nil
}

func arrivalsSaveLocked(root string, a *backupArrivals) error {
	p, err := arrivalsPath(root)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, raw)
}

// recordArrival notes that this bastion put the backup file `name` into the
// top of `root`, with digest sha.
func recordArrival(root, name, sha string, at time.Time) error {
	fi, err := os.Lstat(filepath.Join(root, name))
	if err != nil {
		return err
	}
	backupStateMu.Lock()
	defer backupStateMu.Unlock()
	a, err := arrivalsLoadLocked(root)
	if err != nil {
		return err
	}
	a.Files[name] = backupArrival{SHA256: sha, Size: fi.Size(), ModNs: fi.ModTime().UnixNano(),
		Arrived: at.UTC().Format(time.RFC3339Nano)}
	noteHash(filepath.Join(root, name), fi, sha)
	return arrivalsSaveLocked(root, a)
}

// stillTheArrival reports whether the file at path is the one recorded.
func stillTheArrival(fi os.FileInfo, a backupArrival) bool {
	return fi.Mode().IsRegular() && fi.Size() == a.Size && fi.ModTime().UnixNano() == a.ModNs
}

// ── hashes ─────────────────────────────────────────────────────────────────

type hashEntry struct {
	size, modNs int64
	sha         string
}

var (
	hashMu      sync.Mutex
	hashCache   = map[string]hashEntry{}
	hashQueue   = map[string]bool{}
	hashRunning bool
	// hashFileFn is hashFileWatched; a test replaces it to hold the worker.
	hashFileFn = hashFileWatched
	// hashRead is one read of a file the job hashes (under hashMu); a test
	// replaces it with a slow one.
	hashRead = func(f *os.File, p []byte) (int, error) { return f.Read(p) }
	// hashJobTimeout (under hashMu) bounds two things. It is how long the job
	// waits for one file: a file on a network mount that stopped answering
	// may never return from a read, and one such file would otherwise stop
	// the digests of every folder. Past the bound the job goes on to the next
	// file; the read goes on by itself and its digest is kept if it ever
	// returns. It is also how long the reading of a file may go without one
	// of its reads returning before its folder counts as stuck (backupReads).
	// A large backup on a slow disk can take far longer than the bound to
	// read, but its reads keep returning, so it never counts as stuck.
	hashJobTimeout = 2 * time.Minute
)

const hashCacheMax = 20000

func noteHash(abs string, fi os.FileInfo, sha string) {
	hashMu.Lock()
	defer hashMu.Unlock()
	if len(hashCache) >= hashCacheMax {
		hashCache = map[string]hashEntry{}
	}
	hashCache[abs] = hashEntry{size: fi.Size(), modNs: fi.ModTime().UnixNano(), sha: sha}
}

// cachedHash is the digest of the file at abs if it is known for exactly
// this size and modification time, else "".
func cachedHash(abs string, fi os.FileInfo) string {
	hashMu.Lock()
	defer hashMu.Unlock()
	e, ok := hashCache[abs]
	if !ok || e.size != fi.Size() || e.modNs != fi.ModTime().UnixNano() {
		return ""
	}
	return e.sha
}

// hashBound is hashJobTimeout, read under hashMu.
func hashBound() time.Duration {
	hashMu.Lock()
	defer hashMu.Unlock()
	return hashJobTimeout
}

// requestHash queues abs for the one background hashing job, starting it if
// it is not running. Never blocks on the file. A file in a folder with a read
// that has not returned (the hashing job's or a push's, backupReads) is not
// queued; a later listing asks again.
func requestHash(abs string) {
	pushBound := pushStallBound()
	hashMu.Lock()
	defer hashMu.Unlock()
	if _, stuck := folderStuck(filepath.Dir(abs), time.Now(), pushBound, hashJobTimeout); stuck {
		return
	}
	hashQueue[abs] = true
	if hashRunning {
		return
	}
	hashRunning = true
	go hashWorker()
}

func hashWorker() {
	for {
		pushBound := pushStallBound()
		hashMu.Lock()
		var next string
		for p := range hashQueue {
			next = p
			break
		}
		if next == "" {
			hashRunning = false
			hashMu.Unlock()
			return
		}
		delete(hashQueue, next)
		dir := filepath.Dir(next)
		bound := hashJobTimeout
		// Not read now: a folder with a read that has not returned, or a
		// bastion at backupReadsMax. A later listing asks again.
		if !hashReadTake(dir, pushBound, bound) {
			hashMu.Unlock()
			continue
		}
		hashMu.Unlock()

		// The read keeps its slot until it returns, however long after the
		// job stopped waiting for it, and its watch ends before the slot is
		// freed.
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer backupReadFree(dir, true)
			stop, watched := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(watched)
				watchHashRead(dir, filepath.Base(next), bound, stop)
			}()
			hashOne(next)
			close(stop)
			<-watched
		}()
		timer := time.NewTimer(bound)
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// watchHashRead says in the log when the job's read of name, in dir, has
// taken longer than bound while its reads keep returning, and when it has gone
// without an answer for more than bound; each once. It ends when stop is
// closed.
func watchHashRead(dir, name string, bound time.Duration, stop <-chan struct{}) {
	start := time.Now()
	slow := false
	for {
		now := time.Now()
		quiet := hashReadQuiet(dir, now)
		if quiet > bound {
			opMaskLog("backup folder %s: reading %s for its digest has not answered for more than %s (a network "+
				"mount that stopped?); nothing more is read from that folder until it returns\n", dir, name, bound)
			return
		}
		wait := bound - quiet
		if took := now.Sub(start); !slow && took > bound {
			slow = true
			opMaskLog("backup folder %s: reading %s for its digest is taking more than %s (a large file or a slow "+
				"disk); the job goes on to other folders and reads nothing more from that folder until it is done\n",
				dir, name, bound)
		} else if !slow && bound-took < wait {
			wait = bound - took
		}
		timer := time.NewTimer(wait + time.Millisecond)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// hashOne reads the file at p and keeps its digest if the file did not
// change while it was read.
func hashOne(p string) {
	// A file listed again while it was being read is queued again; by then
	// its digest is known, and it is not read twice.
	before, err := os.Lstat(p)
	if err != nil || !before.Mode().IsRegular() || cachedHash(p, before) != "" {
		return
	}
	hashReadProgress(filepath.Dir(p))
	sum, _, err := hashFileFn(p)
	if err != nil {
		return
	}
	after, err := os.Lstat(p)
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return
	}
	noteHash(p, after, sum)
}

// hashFileWatched is hashFile for the hashing job: each operation on the file
// that returns (the open, every read) is noted as progress on its folder's
// hashing read, so a file read slowly but steadily never counts as stuck.
func hashFileWatched(path string) (string, int64, error) {
	hashMu.Lock()
	read := hashRead
	hashMu.Unlock()
	dir := filepath.Dir(path)
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	hashReadProgress(dir)
	h := sha256.New()
	n, err := io.Copy(h, progressReader{f: f, dir: dir, read: read})
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// progressReader reads f, noting progress on dir's hashing read each time a
// read returns.
type progressReader struct {
	f    *os.File
	dir  string
	read func(*os.File, []byte) (int, error)
}

func (r progressReader) Read(p []byte) (int, error) {
	n, err := r.read(r.f, p)
	hashReadProgress(r.dir)
	return n, err
}

// ── reads of backup folders in flight ────────────────────────────────────
//
// A read of a file in a backup folder that never returns (a network mount
// that stopped answering) cannot be stopped: it keeps a goroutine, an OS
// thread and, for a push, the open file until the mount answers. Two things
// read backup folders, a push (backuppush.go) and the hashing job above, and
// both keep their reads in flight here, by folder, so each sees the other's:
//
//   - a push holds its folder's one push slot for each operation on its file
//     (a stat, the open, a read), and the hashing job holds its folder's one
//     hash slot for the file it reads;
//   - neither starts a read in a folder with a read of either kind that has
//     gone without an answer past its bound (backupPushFileStall for one
//     operation of a push; hashJobTimeout since the hashing job's last read
//     of its file returned, so a large file on a slow disk that keeps
//     answering never counts), so a dead folder holds at most one push read
//     and one hashing read;
//   - at most backupReadsMax reads, of both kinds together, are in flight on
//     the bastion at once.
//
// A slot is freed when its read returns.

// folderReads is, for each kind of read of one folder, since when it has gone
// without an answer; zero when none is in flight. For a push, since its
// operation on the file started; for the hashing job, since it took the slot
// or since the last operation on its file returned (hashReadProgress).
type folderReads struct {
	push, hash time.Time
}

var (
	backupReadMu sync.Mutex
	// backupReads holds the folders with a read in flight.
	backupReads = map[string]*folderReads{}
	// backupReadFreed is closed, and replaced, whenever a read returns.
	backupReadFreed = make(chan struct{})
	// backupReadsMax bounds the reads one bastion keeps in flight (a
	// goroutine, a thread and a descriptor each for one that never returns):
	// far below the process's thread and descriptor limits, and above the
	// folders that ever go dead at once. A test lowers it.
	backupReadsMax = 8
)

// readsInFlightLocked is the number of reads in flight; the caller holds
// backupReadMu.
func readsInFlightLocked() int {
	n := 0
	for _, r := range backupReads {
		if !r.push.IsZero() {
			n++
		}
		if !r.hash.IsZero() {
			n++
		}
	}
	return n
}

// stuckReadsLocked is the number of reads in flight past their bound; the
// caller holds backupReadMu.
func stuckReadsLocked(now time.Time, pushBound, hashBound time.Duration) int {
	n := 0
	for _, r := range backupReads {
		if !r.push.IsZero() && now.Sub(r.push) > pushBound {
			n++
		}
		if !r.hash.IsZero() && now.Sub(r.hash) > hashBound {
			n++
		}
	}
	return n
}

// folderStuckLocked says which read of dir has been in flight past its bound,
// as a phrase for a sentence, and false when none has; the caller holds
// backupReadMu.
func folderStuckLocked(dir string, now time.Time, pushBound, hashBound time.Duration) (string, bool) {
	r := backupReads[dir]
	switch {
	case r == nil:
		return "", false
	case !r.push.IsZero() && now.Sub(r.push) > pushBound:
		return fmt.Sprintf("an earlier push for more than %s", pushBound), true
	case !r.hash.IsZero() && now.Sub(r.hash) > hashBound:
		return fmt.Sprintf("the reading of a backup for its digest for more than %s", hashBound), true
	}
	return "", false
}

func folderStuck(dir string, now time.Time, pushBound, hashBound time.Duration) (string, bool) {
	backupReadMu.Lock()
	defer backupReadMu.Unlock()
	return folderStuckLocked(dir, now, pushBound, hashBound)
}

// hashReadTake takes dir's hash slot for the hashing job, or reports false
// when it may not read there now: a read of dir is stuck, the job's earlier
// read there has not returned, or backupReadsMax reads are in flight.
func hashReadTake(dir string, pushBound, hashBound time.Duration) bool {
	backupReadMu.Lock()
	defer backupReadMu.Unlock()
	now := time.Now()
	if _, stuck := folderStuckLocked(dir, now, pushBound, hashBound); stuck {
		return false
	}
	r := backupReads[dir]
	if (r != nil && !r.hash.IsZero()) || readsInFlightLocked() >= backupReadsMax {
		return false
	}
	if r == nil {
		r = &folderReads{}
		backupReads[dir] = r
	}
	r.hash = now
	return true
}

// hashReadProgress notes that an operation of the hashing job's read of dir
// returned, so the read counts as stuck only after hashJobTimeout without
// another. Only the job's own read, which holds dir's hash slot until it
// returns, calls it.
func hashReadProgress(dir string) {
	backupReadMu.Lock()
	defer backupReadMu.Unlock()
	if r := backupReads[dir]; r != nil && !r.hash.IsZero() {
		r.hash = time.Now()
	}
}

// hashReadQuiet is how long the hashing job's read of dir has gone without an
// answer at now; zero when none is in flight.
func hashReadQuiet(dir string, now time.Time) time.Duration {
	backupReadMu.Lock()
	defer backupReadMu.Unlock()
	if r := backupReads[dir]; r != nil && !r.hash.IsZero() {
		return now.Sub(r.hash)
	}
	return 0
}

// backupReadFree frees dir's hash slot (hash) or its push slot, when the read
// holding it returned.
func backupReadFree(dir string, hash bool) {
	backupReadMu.Lock()
	defer backupReadMu.Unlock()
	if r := backupReads[dir]; r != nil {
		if hash {
			r.hash = time.Time{}
		} else {
			r.push = time.Time{}
		}
		if r.push.IsZero() && r.hash.IsZero() {
			delete(backupReads, dir)
		}
	}
	close(backupReadFreed)
	backupReadFreed = make(chan struct{})
}

// ── one folder per host, and none over the bastion's own state ────────────

// resolvedPath is p made absolute with every link in its existing part
// resolved, so two spellings of one folder compare equal. Unbounded: for
// this bastion's own local folders; a host's backup folder, which may be a
// network mount, goes through backupFolderResolve instead.
func resolvedPath(p string) string {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		abs = filepath.Clean(p)
	}
	return opResolveFn(abs)
}

// pathInside reports whether child is strictly inside parent.
func pathInside(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// bastionStateOverlap is a refusal when folder is, or contains, this
// bastion's own state (its config folder, its backup keys, its backup
// records), or sits inside the config folder anywhere but under its
// backups/ folder: a host that can write, list or send files there could
// reach the pairings, the DCN state, the keys, or the record that decides
// what thinning removes.
func bastionStateOverlap(folder string) string {
	return bastionStateOverlapResolved(folder, resolvedPath(folder))
}

// bastionStateOverlapResolved is bastionStateOverlap for a folder already
// resolved to r (the bastion's own folders are local and resolved here).
func bastionStateOverlapResolved(folder, r string) string {
	if conf, err := configDirPath(); err == nil && conf != "" {
		rc := resolvedPath(conf)
		if pathInside(r, rc) && !pathInside(r, filepath.Join(rc, "backups")) {
			return fmt.Sprintf("the backup folder %s is inside this bastion's configuration folder (%s) but not under "+
				"its backups folder; set backup_root to a folder of its own", folder, conf)
		}
	}
	// A folder inside the keys or the records is inside the configuration
	// folder and outside backups/, so it was refused above.
	type prot struct {
		name string
		path func() (string, error)
	}
	for _, p := range []prot{
		{"this bastion's configuration folder", configDirPath},
		{"this bastion's backup keys", backupKeysDir},
		{"this bastion's backup records", backupStateDir},
	} {
		pp, err := p.path()
		if err != nil || pp == "" {
			continue
		}
		rp := resolvedPath(pp)
		if r == rp || pathInside(rp, r) {
			return fmt.Sprintf("the backup folder %s overlaps %s (%s); set backup_root to a folder of its own", folder, p.name, pp)
		}
	}
	return ""
}

// backupRootProblem is a refusal when the backup folder of the pairing self
// is not one this bastion can keep apart: it overlaps the bastion's own
// state, or it is, contains or sits inside another pairing's backup folder —
// two hosts would then list, send and thin each other's backups, and a folder
// shared with one would reach both. Checked on every backup op, against the
// pairings on disk now.
//
// Every backup folder is resolved with a bound (backupFolderResolve), since
// any of them can be a network mount that stopped answering. This pairing's
// own folder not answering refuses its backup ops with a sentence saying
// so. Another pairing's folder not answering blocks nothing: it is compared
// as written and as it last resolved.
func backupRootProblem(self, root string) string {
	r, ok, _ := backupFolderResolve(root)
	if !ok {
		return fmt.Sprintf("refused: this host's backup folder %s does not answer (a network mount that stopped?); "+
			"its backup ops wait until it does", root)
	}
	if why := bastionStateOverlapResolved(root, r); why != "" {
		return "refused: " + why
	}
	cfgs, err := loadPairings()
	if err != nil {
		return "refused: the pairings on this machine are unreadable, so this host's backup folder cannot be checked: " + err.Error()
	}
	for _, c := range cfgs {
		if c.HostName == self {
			continue
		}
		op := c.backupRootPath()
		if op == "" {
			continue
		}
		var forms []string
		if o, ok, last := backupFolderResolve(op); ok {
			forms = []string{o}
		} else {
			abs, _ := filepath.Abs(filepath.Clean(op))
			forms = []string{abs}
			if last != "" {
				forms = append(forms, last)
			}
		}
		for _, o := range forms {
			if o == r || pathInside(o, r) || pathInside(r, o) {
				return fmt.Sprintf("refused: this host's backup folder %s is, contains or sits inside the backup folder of %s (%s). "+
					"Give each host a backup_root of its own on this machine", root, c.HostName, op)
			}
		}
	}
	return ""
}

// backupMkdirFn is os.MkdirAll; a test replaces it with one that fails or
// blocks.
var backupMkdirFn = os.MkdirAll

// backupRootReady is the check every backup op runs before its handler: the
// folder is this host's own (backupRootProblem), and, for an op that writes
// (create), it exists, created here on first use rather than when the daemon
// starts. A read (backup_list) creates nothing: a folder not made yet lists
// empty. Both steps are bounded, so a backup folder on a network mount that
// stopped answering refuses that host's backup ops with a sentence and holds
// up nothing else: not the daemon's start, not the rest of this host's lane,
// not another host.
func backupRootReady(self, root string, create bool) string {
	if why := backupRootProblem(self, root); why != "" {
		return why
	}
	if !create {
		return ""
	}
	if err := opProbe("mkdir:"+root, func() error { return backupMkdirFn(root, 0o700) }); err != nil {
		if errors.Is(err, errProbeBusy) || errors.Is(err, errProbeTimeout) {
			return fmt.Sprintf("refused: this host's backup folder %s does not answer (a network mount that stopped?); "+
				"its backup ops wait until it does", root)
		}
		return fmt.Sprintf("refused: this host's backup folder %s cannot be created: %v", root, err)
	}
	return ""
}

// ── shares ─────────────────────────────────────────────────────────────────

type backupShare struct {
	Slug  string `json:"slug"`
	Dir   string `json:"dir"`
	From  string `json:"from"`
	Added string `json:"added_at"`
}

// shares by the reading pairing's host name: a share is given to a pairing,
// not to a folder, so it cannot reach another pairing that happens to use
// the same folder, and it goes when that pairing is unpaired or revoked.
type backupSharesFile map[string][]backupShare

var shareSlugRe = regexp.MustCompile(`[^a-z0-9.-]+`)

func sharesPath() (string, error) {
	d, err := backupStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "shares.json"), nil
}

func sharesLoadLocked() (backupSharesFile, error) {
	m := backupSharesFile{}
	p, err := sharesPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("the record of shared backup folders is unreadable: %w", err)
	}
	return m, nil
}

func sharesSaveLocked(m backupSharesFile) error {
	p, err := sharesPath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, raw)
}

// sharesFor is the folders the pairing `reader` may read. An anonymous
// caller ("") has none.
func sharesFor(reader string) []backupShare {
	if reader == "" {
		return nil
	}
	backupStateMu.Lock()
	defer backupStateMu.Unlock()
	m, err := sharesLoadLocked()
	if err != nil {
		return nil
	}
	out := append([]backupShare(nil), m[reader]...)
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

// addBackupShare lets the pairing `reader`, whose own backup folder is
// readerRoot, read the folder dir. from names it for the person and becomes
// the folder's name in listings (shared/<slug>).
func addBackupShare(reader, readerRoot, dir, from string) (*backupShare, error) {
	if reader == "" {
		return nil, errors.New("say which host to share with")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", dir)
	}
	if resolvedPath(abs) == resolvedPath(readerRoot) {
		return nil, errors.New("that is already this host's own backup folder")
	}
	if why := bastionStateOverlap(abs); why != "" {
		return nil, errors.New(why)
	}
	slug := strings.Trim(shareSlugRe.ReplaceAllString(strings.ToLower(from), "-"), "-.")
	if len(slug) > 40 {
		slug = slug[:40]
	}
	if slug == "" {
		slug = "folder"
	}
	backupStateMu.Lock()
	defer backupStateMu.Unlock()
	m, err := sharesLoadLocked()
	if err != nil {
		return nil, err
	}
	taken := map[string]bool{}
	for _, s := range m[reader] {
		if s.Dir == abs {
			return nil, fmt.Errorf("that folder is already shared with this host as shared/%s", s.Slug)
		}
		taken[s.Slug] = true
	}
	base := slug
	for i := 2; taken[slug]; i++ {
		slug = fmt.Sprintf("%s-%d", base, i)
	}
	s := backupShare{Slug: slug, Dir: abs, From: from, Added: time.Now().UTC().Format(time.RFC3339)}
	m[reader] = append(m[reader], s)
	if err := sharesSaveLocked(m); err != nil {
		return nil, err
	}
	return &s, nil
}

func dropBackupShare(reader, slug string) error {
	backupStateMu.Lock()
	defer backupStateMu.Unlock()
	m, err := sharesLoadLocked()
	if err != nil {
		return err
	}
	var keep []backupShare
	found := false
	for _, s := range m[reader] {
		if s.Slug == slug {
			found = true
			continue
		}
		keep = append(keep, s)
	}
	if !found {
		return fmt.Errorf("no folder is shared with this host as shared/%s", slug)
	}
	if len(keep) == 0 {
		delete(m, reader)
	} else {
		m[reader] = keep
	}
	return sharesSaveLocked(m)
}

// dropSharesOf takes back every folder shared with the pairing reader: called
// when it is unpaired or revoked, so a later pairing under the same name does
// not inherit them.
func dropSharesOf(reader string) error {
	backupStateMu.Lock()
	defer backupStateMu.Unlock()
	m, err := sharesLoadLocked()
	if err != nil {
		return err
	}
	if _, ok := m[reader]; !ok {
		return nil
	}
	delete(m, reader)
	return sharesSaveLocked(m)
}
