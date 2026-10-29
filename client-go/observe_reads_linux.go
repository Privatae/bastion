//go:build linux

package main

// Linux drivers for observe:folders, observe:journal, observe:logins and
// observe:cert (observe_reads.go holds their grammar and parsers). The
// programs are the ones observe_ops_linux.go keeps to — journalctl, systemctl
// and ss, read-only forms only — and every exec shares one op budget.
//
// No elevation of its own. The networked install runs the bastion as root
// (deploy/install.sh writes no User=), which is how observe:host already reads
// nft and iptables, and so how these read the journal and every folder. A
// bastion run as a user reads what that user can: a folder it cannot open is
// named in skipped, and a journal it cannot read wholly is said so outright
// (journalAccess), because journalctl does not fail for such a user — it shows
// only the user's own lines, an empty answer that would read as a quiet machine.

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// journalAccess is the default observeJournalAccess. root reads everything;
// any other account can read the system journal only when it may open the
// system journal file itself (the systemd-journal or adm group), which is
// exactly what journalctl will be able to do.
func journalAccess() string {
	if os.Geteuid() == 0 {
		return ""
	}
	raw, err := os.ReadFile("/etc/machine-id")
	mid := strings.TrimSpace(string(raw))
	if err == nil && machineIDRe.MatchString(mid) {
		for _, dir := range []string{"/var/log/journal/", "/run/log/journal/"} {
			if f, err := os.Open(dir + mid + "/system.journal"); err == nil {
				_ = f.Close()
				return ""
			}
		}
	}
	return "the bastion runs as an account that cannot read the system journal; " +
		"run it as root (the networked install does) or add that account to the systemd-journal group"
}

var machineIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ── observe:folders ──────────────────────────────────────────────────────────

const (
	// folderReadBatch is how many names one directory read takes: a folder of
	// a million files is read in pieces, not into memory at once.
	folderReadBatch = 512
	// folderLinkCap bounds the set of hard-linked files already counted.
	// Past it each further link is counted (sizes may read high) and the
	// answer says so.
	folderLinkCap = 1 << 20
	// folderStuckMax bounds the walks left inside a read that has not
	// returned. Each holds an OS thread for as long as that read hangs (a hard
	// network mount: until it comes back), and a Host asking again and again
	// about a path on one would otherwise pile them up until the bastion
	// could start no more. Past it the op answers at once, sizing nothing.
	folderStuckMax = 4
)

// folderStuckGrace is how long past the op budget the answer waits for a walk
// that is inside one read, before answering without it. folderSizer is the
// walk. Both are variables so a test can stand in a walk that never returns.
var (
	folderStuckGrace = 2 * time.Second
	folderSizer      = sizeFolders
	// folderWalksStuck counts the walks readFolders answered without that have not
	// returned since.
	folderWalksStuck atomic.Int32
)

// folderBeforeOpen is called with each folder's path between its stat and its
// open: a seam so a test can swap the folder in that gap. nil outside tests.
var folderBeforeOpen func(string)

// reasonChanged is the skip reason for a folder that is no longer the one the
// walk stat'd when it comes to open it: swapped for a link, or reached
// through a folder above it that was.
const reasonChanged = "changed while it was read, not counted"

type folderWalk struct {
	ctx      context.Context
	root     string
	depth    int
	dev      uint64
	mounts   map[string]bool
	linked   map[uint64]struct{}
	linkFull bool
	top      folderTop
	sized    int
	skips    folderSkips
	cut      bool
}

func (w *folderWalk) expired() bool {
	if !w.cut && w.ctx.Err() != nil {
		w.cut = true
	}
	return w.cut
}

// skip records what could not be sized against the folder that holds it,
// folded to the asked depth. A file is never named: its folder is.
func (w *folderWalk) skip(dir, reason string) {
	w.skips.add(folderAt(w.root, dir, w.depth), reason)
}

func folderSkipReason(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == syscall.EACCES || errno == syscall.EPERM {
			return "permission denied"
		}
		return errno.Error()
	}
	return "could not be read"
}

// firstLink says whether a file with more than one link is being seen for
// the first time, so its blocks are counted once, as du counts them.
func (w *folderWalk) firstLink(ino uint64) bool {
	if _, seen := w.linked[ino]; seen {
		return false
	}
	if len(w.linked) >= folderLinkCap {
		w.linkFull = true
		return true
	}
	w.linked[ino] = struct{}{}
	return true
}

// openFolder opens p only when it is still the folder st describes. Between
// the stat and the open, p, or a folder above it, can be swapped for a link
// by whoever owns the folder above; O_NOFOLLOW refuses a link at p itself,
// and the device and inode of what opened refuse one above it. Without this
// a link put there in that gap would lead the walk elsewhere, onto another
// filesystem or into /proc, under p's name.
func openFolder(p string, st *syscall.Stat_t) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return nil, errFolderChanged
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	got, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || got.Dev != st.Dev || got.Ino != st.Ino {
		_ = f.Close()
		return nil, errFolderChanged
	}
	return f, nil
}

var errFolderChanged = errors.New(reasonChanged)

// dir sizes one folder and everything under it on the same filesystem, and
// returns the bytes. st is the folder's own stat, taken when its parent was
// read: its blocks are counted, and the folder opened must still be the one
// it describes (openFolder). Names are read in batches and stat'd as read;
// subfolders are walked after the folder is closed, so the walk holds one
// open folder at a time however deep it goes.
func (w *folderWalk) dir(p string, level int, st *syscall.Stat_t) int64 {
	total := int64(st.Blocks) * 512
	if w.expired() {
		return total
	}
	if folderBeforeOpen != nil {
		folderBeforeOpen(p)
	}
	f, err := openFolder(p, st)
	if err != nil {
		if errors.Is(err, errFolderChanged) {
			w.skip(p, reasonChanged)
		} else {
			w.skip(p, folderSkipReason(err))
		}
		return total
	}
	var subdirs []string
	var subSt []syscall.Stat_t
	for !w.expired() {
		ents, rerr := f.ReadDir(folderReadBatch)
		for _, e := range ents {
			child := childPath(p, e.Name())
			if w.mounts[child] {
				w.skip(child, reasonOtherFS)
				continue
			}
			var st syscall.Stat_t
			if err := syscall.Lstat(child, &st); err != nil {
				// Gone between the read and the stat is churn, not a gap.
				if !errors.Is(err, syscall.ENOENT) {
					w.skip(p, folderSkipReason(err))
				}
				continue
			}
			size := int64(st.Blocks) * 512
			if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
				// The mount table is read once at the start; a mount made
				// since is caught here by its device instead.
				if uint64(st.Dev) != w.dev {
					w.skip(child, reasonOtherFS)
					continue
				}
				subdirs = append(subdirs, child)
				subSt = append(subSt, st)
				continue
			}
			if uint64(st.Nlink) > 1 && !w.firstLink(uint64(st.Ino)) {
				continue
			}
			total += size
		}
		if rerr != nil {
			if rerr != io.EOF {
				w.skip(p, folderSkipReason(rerr))
			}
			break
		}
	}
	_ = f.Close()
	for i, c := range subdirs {
		if w.expired() {
			break
		}
		total += w.dir(c, level+1, &subSt[i])
	}
	if level >= 1 && level <= w.depth {
		w.sized++
		w.top.offer(folderSize{Path: p, Bytes: total, Depth: level})
	}
	return total
}

// readFolders sizes the folders under asked. The error is a refusal: a path
// that is not a folder here, or whose links lead into a kernel tree.
//
// All of it, the path's resolution included, runs on its own goroutine, so
// the answer goes out at the op budget even when one call never returns: a
// stat of a dead network mount named as the path, or a disk erroring slowly
// under it. That goroutine owns everything it touches; on the stuck path this
// function reads nothing of it and answers without it. Such a walk is counted
// until it returns, and past folderStuckMax of them no walk starts.
func readFolders(asked string, depth int) (foldersReport, error) {
	stuck := func(partial, note string) foldersReport {
		return foldersReport{Supported: true, Path: asked, Depth: depth, Folders: []folderSize{},
			Skipped: []folderSkip{}, Partial: partial, Note: note}
	}
	if folderWalksStuck.Load() >= folderStuckMax {
		return stuck("earlier reads on this machine have not returned",
			"nothing was sized: "+strconv.Itoa(folderStuckMax)+" earlier walks are still inside a read that "+
				"has not returned (a network mount that stopped answering, most often); try again once it answers"), nil
	}
	ctx, cancel := opBudget()
	defer cancel()
	type result struct {
		rep foldersReport
		err error
	}
	// 0 running, 1 returned, 2 answered without: whichever side moves it
	// from 0 first decides whether the walk holds a place in folderWalksStuck.
	var state atomic.Int32
	done := make(chan result, 1)
	go func() {
		rep, err := folderSizer(ctx, asked, depth)
		done <- result{rep, err}
		if !state.CompareAndSwap(0, 1) {
			folderWalksStuck.Add(-1)
		}
	}()
	select {
	case r := <-done:
		return r.rep, r.err
	case <-ctx.Done():
		select {
		case r := <-done:
			return r.rep, r.err
		case <-time.After(folderStuckGrace):
			if !state.CompareAndSwap(0, 2) {
				r := <-done
				return r.rep, r.err
			}
			folderWalksStuck.Add(1)
			return stuck("a read under this path did not return inside the op budget",
				"nothing was sized; ask about a folder further down, or try again"), nil
		}
	}
}

func sizeFolders(ctx context.Context, asked string, depth int) (foldersReport, error) {
	resolved, err := filepath.EvalSymlinks(asked)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return foldersReport{}, errors.New("there is no folder at that path on this machine")
		}
		return foldersReport{}, errors.New("that path cannot be read: " + folderSkipReason(err))
	}
	if err := folderPathAllowed(resolved); err != nil {
		return foldersReport{}, err
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(resolved, &st); err != nil {
		return foldersReport{}, errors.New("that path cannot be read: " + folderSkipReason(err))
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return foldersReport{}, errors.New("that path is not a folder")
	}
	rep := foldersReport{Supported: true, Path: asked, Depth: depth}
	if resolved != asked {
		rep.Resolved = resolved
	}
	mounts := map[string]bool{}
	if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		mounts = parseMountPoints(string(b))
	}
	w := &folderWalk{ctx: ctx, root: resolved, depth: depth, dev: uint64(st.Dev), mounts: mounts,
		linked: map[uint64]struct{}{}}
	rep.TotalBytes = w.dir(resolved, 0, &st)
	rep.Folders = w.top.sorted()
	rep.Sized = w.sized
	rep.Skipped = w.skips.list()
	rep.SkippedTotal = w.skips.total
	rep.Complete = !w.cut
	if w.cut {
		rep.Partial = "timeout"
		rep.Note = "the walk ran out of time: every size is at least what is shown, and a folder it never reached is missing"
	}
	if w.linkFull {
		rep.Note = strings.TrimSpace(rep.Note + " More than " + strconv.Itoa(folderLinkCap) +
			" hard-linked files: past that each link was counted, so sizes may read high.")
	}
	return rep, nil
}

// ── observe:journal ──────────────────────────────────────────────────────────

// readJournal reads one unit's recent journal. The unit has passed
// normalizeUnitName; the error is a refusal when this machine has no such
// unit, and every other gap is a reported reason.
func readJournal(unit string, minutes int) (journalReport, error) {
	rep := journalReport{Source: "journal", Unit: unit, Minutes: minutes}
	if !observeHave("journalctl") {
		rep.Reason = "journalctl not installed"
		return rep, nil
	}
	if !observeHave("systemctl") {
		rep.Reason = "systemctl not installed, so this machine cannot say which units it has"
		return rep, nil
	}
	if why := observeJournalAccess(); why != "" {
		rep.Reason = why
		return rep, nil
	}
	ctx, cancel := opBudget()
	defer cancel()
	// list-units is observe:units' read with --all for --failed: every unit
	// systemd has loaded. A failed run is not an empty list here either —
	// it would refuse every unit as unknown — so its error is checked.
	listed, lerr := observeExec(ctx, "systemctl", "list-units", "--all", "--no-legend", "--plain")
	if ctx.Err() != nil {
		rep.Reason = "systemctl list-units: timeout"
		return rep, nil
	}
	if lerr != nil && len(listed) == 0 {
		rep.Reason = "systemctl list-units: " + lerr.Error()
		return rep, nil
	}
	// The same for list-unit-files: without it an installed unit that is not
	// loaded right now would be refused as one this machine does not have.
	files, ferr := observeExec(ctx, "systemctl", "list-unit-files", "--no-legend", "--plain")
	if ctx.Err() != nil {
		rep.Reason = "systemctl list-unit-files: timeout"
		return rep, nil
	}
	if ferr != nil && len(files) == 0 {
		rep.Reason = "systemctl list-unit-files: " + ferr.Error()
		return rep, nil
	}
	loaded, installed := parseUnitList(string(listed)), parseUnitFiles(string(files))
	if !unitKnown(unit, loaded, installed) {
		return journalReport{}, errUnknownUnit(unit, loaded, installed)
	}
	// Bound to their flags with '=', so neither can be read as a flag of its
	// own whatever it held. --lines is observeLogLineLimit, the line limit
	// observe:logs asks Loki for: the newest 5000 lines in the window.
	unitArg := "--unit=" + unit
	sinceArg := "--since=-" + strconv.Itoa(minutes) + "min"
	out, err := observeExec(ctx, "journalctl", unitArg, sinceArg, "-o", "short-iso", "--no-pager", "-q", "--lines=5000")
	if ctx.Err() != nil {
		rep.Partial = "journalctl: timeout"
	} else if err != nil && len(out) == 0 {
		rep.Reason = "journalctl: " + err.Error()
		return rep, nil
	}
	rep.Supported = true
	rep.Log, rep.Truncated = capLines(string(out), observeLogLineLimit, observeTextCap)
	if strings.TrimSpace(rep.Log) != "" {
		rep.Lines = strings.Count(strings.TrimRight(rep.Log, "\n"), "\n") + 1
	} else {
		rep.Log = ""
		rep.Note = "no lines from " + unit + " in the last " + strconv.Itoa(minutes) + " minutes"
	}
	return rep, nil
}

// ── observe:logins ───────────────────────────────────────────────────────────

// readLogins counts sshd's logins over the window. sshd is matched two ways,
// either one enough ("+" is journalctl's OR): by program — sshd, and the
// sshd-session and sshd-auth processes newer OpenSSH splits it into — and by
// unit, ssh.service on Debian and Ubuntu, sshd.service elsewhere. --lines is
// loginsLineCap.
//
// Each match also needs _UID=0. Any account can run a program named sshd and
// log under _COMM=sshd, and one whose shell stays in ssh.service's cgroup (no
// pam_systemd) logs under that unit; either could add failures or accepted
// logins, or bury the real ones under 50,000 lines. _UID is journald's own,
// from the sender's credentials, and every message parsed here is written by
// sshd's root monitor (OpenSSH sends its unprivileged child's lines through
// it). A sshd run by an ordinary account is not read.
func readLogins(hours int) loginsReport {
	rep := loginsReport{Source: "journal", Hours: hours, FailedTotal: -1, AcceptedTotal: -1,
		FailedBySource: []loginSource{}, FailedByUser: []loginUser{}, Accepted: []acceptedLogin{}}
	if !observeHave("journalctl") {
		rep.Reason = "journalctl not installed"
		return rep
	}
	if why := observeJournalAccess(); why != "" {
		rep.Reason = why
		return rep
	}
	ctx, cancel := opBudget()
	defer cancel()
	sinceArg := "--since=-" + strconv.Itoa(hours) + "h"
	out, err := observeExec(ctx, "journalctl", sinceArg, "-o", "short-iso", "--no-pager", "-q", "--lines=50000",
		"_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth", "_UID=0",
		"+", "_SYSTEMD_UNIT=ssh.service", "_SYSTEMD_UNIT=sshd.service", "_UID=0")
	late := ctx.Err() != nil
	if !late && err != nil && len(out) == 0 {
		rep.Reason = "journalctl: " + err.Error()
		return rep
	}
	t := parseSSHLogins(string(out))
	rep.Supported = true
	t.fill(&rep)
	rep.Truncated = t.entries >= loginsLineCap
	if late {
		rep.Partial = "journalctl: timeout"
	}
	if t.entries == 0 {
		rep.Note = "no sshd entries in the journal in the last " + strconv.Itoa(hours) + " hours"
	}
	return rep
}

// ── observe:cert ─────────────────────────────────────────────────────────────

// readCert reads the certificate this machine's listener on port serves. The
// listener table is observe:sockets' own read (ss -tlnpH); the error is a
// refusal when nothing listens on the port.
func readCert(port int, name string) (certReport, error) {
	rep := certReport{Port: port, ServerName: name, Listening: []string{}, Tried: []string{},
		CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if !observeHave("ss") {
		rep.Reason = "ss not installed, so this machine cannot say which ports it listens on"
		return rep, nil
	}
	ctx, cancel := opBudget()
	defer cancel()
	out, err := observeExec(ctx, "ss", "-tlnpH")
	// A failed ss is not an empty table (readSockets says why): here an empty
	// table would refuse every port as not listening.
	if ctx.Err() != nil {
		rep.Reason = "ss: timeout"
		return rep, nil
	}
	if err != nil {
		rep.Reason = "ss: " + err.Error()
		return rep, nil
	}
	targets, listening := certTargets(parseSS("tcp", string(out)), port, observeOwnAddrs())
	if len(listening) == 0 {
		return certReport{}, errors.New("nothing on this machine listens on tcp port " + strconv.Itoa(port))
	}
	rep.Supported = true
	rep.Listening = listening
	dialCert(ctx, &rep, targets, name)
	return rep, nil
}
