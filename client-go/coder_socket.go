package main

// coder_socket.go — how a Host on THIS machine reaches a coder run.
//
// A pairing with transport "unix" (pair_unix.go) has no tunnel, so a run it
// owns is served as <runs_dir>/<run_id>.sock in place of a tunnel port
// (coder_forward.go). The walls are the forward's. The socket exists only in
// the owning pairing's runs directory and only while the run is up. Every
// accepted connection is checked again: mode:coder still allowed, the run
// still this pairing's, not past its deadline, not stopped by the watchdog.
// The splice pins the run's control.sock inode and checks that the far end is
// the engine's uid (spliceUnix). The run's control cap is enforced by the run
// itself. The file is 0660, group privatae-host when that group exists (the
// Host's container is given that group), else root, and the log says why.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// coderSocketGroup is the group the Host's container is given at install.
const coderSocketGroup = "privatae-host"

type coderRunSock struct {
	owner string
	path  string // what the Host is told: <runs_dir>/<run_id>.sock
	file  string // the same file by its real path, which is what is removed
	ln    net.Listener
}

var (
	coderSockMu       sync.Mutex
	coderSocks        = map[string]*coderRunSock{} // run_id -> its live socket
	coderSockDirs     = map[string]string{}        // pairing -> its runs dir, while its lanes run here
	coderSockLanes    = map[string]coderLane{}     // pairing -> its lane: who may connect (coderPeerRefusal)
	coderSockLastNote string

	// The seams: how the group is found and how the socket is handed to it.
	coderLookupGroup = func(name string) (int, error) {
		g, err := user.LookupGroup(name)
		if err != nil {
			return -1, err
		}
		return strconv.Atoi(g.Gid)
	}
	// Lchown: a link is never followed (coderPrepareRunsDir is the wall).
	coderSockChown = os.Lchown
)

// coderSocketRefusal is the per-connection wall: "" to splice, else why not.
func coderSocketRefusal(self string, rec *coderRecord, now time.Time) string {
	if why := capsAllow(self, coderGateOp); why != "" {
		return why
	}
	if rec == nil {
		return "no such run"
	}
	if rec.Owner != self {
		return "the run belongs to another host"
	}
	if rec.StoppedBy != "" {
		return "the run was stopped to protect this machine"
	}
	if dl, err := time.Parse(time.RFC3339, rec.Deadline); err != nil || now.After(dl) {
		return "the run is past its deadline"
	}
	return ""
}

// coderSocketGroupID is the group a run socket is given, and when it is root
// because the group does not exist, the reason.
func coderSocketGroupID() (int, string) {
	gid, err := coderLookupGroup(coderSocketGroup)
	if err != nil || gid < 0 {
		return 0, "group " + coderSocketGroup + " does not exist on this machine, so run sockets are root:root 0660 " +
			"and only root reaches them (create the group and give it to the Host's container)"
	}
	return gid, ""
}

// coderPrepareRunsDir makes sure dir is a directory only root can change,
// and returns its real path (its parent's links resolved), which every file
// operation on a run socket then uses. It creates dir itself (0750, root and
// the socket group) but never its parent: the shared directory is the Host
// install's.
//
// WHY. A run socket is chmod-ed and chown-ed by its path, and both follow a
// symlink. The Host names runs_dir and can write the shared directory, so a
// runs directory it could change would let it swap a fresh socket for a link
// to any file on this machine between bind and chmod, and that file would
// become 0660 and the Host group's. So dir must be a real directory owned by
// root that nobody else may write, and every directory above it must be
// root's and either writable by nobody else or sticky (the shared directory
// is 1770), so nobody else can move dir and put their own in its place.
func coderPrepareRunsDir(dir string) (string, error) {
	if !cleanAbsSocketPath(dir) {
		return "", fmt.Errorf("runs directory %q is not an absolute, clean path", dir)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(dir))
	if err != nil {
		return "", fmt.Errorf("runs directory %s: %w (the Host's install creates %s)", dir, err, filepath.Dir(dir))
	}
	for d := parent; ; d = filepath.Dir(d) {
		if why := coderDirRefusal(d, true); why != "" {
			return "", fmt.Errorf("runs directory %s: %s, so someone else could put another directory in its place; "+
				"refusing to put run sockets there", dir, why)
		}
		if d == filepath.Dir(d) {
			break
		}
	}
	rdir := filepath.Join(parent, filepath.Base(dir))
	if _, err := os.Lstat(rdir); os.IsNotExist(err) {
		if err := os.Mkdir(rdir, 0o750); err != nil {
			return "", fmt.Errorf("runs directory %s: %w", dir, err)
		}
		gid, _ := coderSocketGroupID()
		_ = os.Chmod(rdir, 0o750)
		_ = coderSockChown(rdir, 0, gid)
	}
	if why := coderDirRefusal(rdir, false); why != "" {
		return "", fmt.Errorf("runs directory %s: %s; refusing to put run sockets there", dir, why)
	}
	return rdir, nil
}

// coderDirRefusal is "" when only root (or this bastion's own user) can
// change what is in d: a real directory (Lstat, a link is never followed)
// owned by one of them and writable by nobody else, or, when stickyOK, sticky.
func coderDirRefusal(d string, stickyOK bool) string {
	fi, err := os.Lstat(d)
	if err != nil {
		return err.Error()
	}
	if !fi.IsDir() {
		return d + " is not a directory (a link is never followed)"
	}
	if uid, ok := coderFileOwner(fi); !ok || (uid != 0 && uid != os.Geteuid()) {
		return d + " is not root's"
	}
	if fi.Mode().Perm()&0o022 != 0 && (!stickyOK || fi.Mode()&os.ModeSticky == 0) {
		return d + " is writable by others"
	}
	return ""
}

// coderOpenRunSocket opens run runID's socket in pairing self's runs
// directory, or returns the one already open. ("", nil) when self has no runs
// directory in this daemon: a platform pairing, which uses a tunnel port.
func coderOpenRunSocket(self, runID string) (string, error) {
	coderSockMu.Lock()
	defer coderSockMu.Unlock()
	if s, ok := coderSocks[runID]; ok {
		if s.owner == self {
			return s.path, nil
		}
		return "", errors.New("that run's socket belongs to another host")
	}
	dir, ok := coderSockDirs[self]
	if !ok {
		return "", nil
	}
	if !coderRunIDRe.MatchString(runID) {
		return "", errors.New("bad run_id")
	}
	// Read again here, under coderSockMu: the reconcile loop opens from a
	// snapshot, and a run-down (which removes the record before it closes
	// the socket) or the watchdog's stop may have come between.
	if rec, err := loadCoderRecord(runID); err != nil || rec.Owner != self || rec.StoppedBy != "" {
		return "", errors.New("no run " + runID + " of this host is up")
	}
	rdir, err := coderPrepareRunsDir(dir)
	if err != nil {
		return "", err
	}
	name := runID + ".sock"
	p := filepath.Join(dir, name)
	f := filepath.Join(rdir, name)
	_ = os.Remove(f) // one a previous daemon left; nobody listens on it
	ln, err := coderListenUnix(rdir, name)
	if err != nil {
		return "", err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		// Bound through /proc/self/fd, so an unlink on close would name a
		// directory fd that is long closed. coderCloseRunSocket removes f.
		ul.SetUnlinkOnClose(false)
	}
	gid, note := coderSocketGroupID()
	if err := os.Chmod(f, 0o660); err != nil {
		_ = ln.Close()
		_ = os.Remove(f)
		return "", err
	}
	if err := coderSockChown(f, 0, gid); err != nil {
		_ = ln.Close()
		_ = os.Remove(f)
		return "", err
	}
	if note != coderSockLastNote {
		if note != "" {
			fmt.Printf("[%s] coder sockets: %s\n", self, note)
		}
		coderSockLastNote = note
	}
	coderSocks[runID] = &coderRunSock{owner: self, path: p, file: f, ln: ln}
	go coderServeRunSocket(self, runID, ln)
	return p, nil
}

// coderServeRunSocket accepts on one run's socket and splices each connection
// that passes the wall to the run's control.sock.
func coderServeRunSocket(self, runID string, ln net.Listener) {
	lastWhy := ""
	for {
		in, err := ln.Accept()
		if err != nil {
			return
		}
		rec, _ := loadCoderRecord(runID)
		why := coderSocketRefusal(self, rec, coderNow())
		if why == "" {
			why = coderPeerRefusal(self, in)
		}
		if why != "" {
			_ = in.Close()
			if why != lastWhy {
				fmt.Printf("[%s] coder socket %s: %s\n", self, runID, why)
				lastWhy = why
			}
			continue
		}
		R, err := coderRunDir(runID)
		if err != nil {
			_ = in.Close()
			continue
		}
		go spliceUnix(in, filepath.Join(R, "ctl", coderControlSock), rec.UID)
	}
}

// coderCloseRunSocket stops serving one run's socket and removes the file.
// Called at run-down (coderTeardown), by the watchdog's stop, and when the
// record goes or its pairing's lanes stop. A no-op when none is open here.
func coderCloseRunSocket(runID string) {
	coderSockMu.Lock()
	s, ok := coderSocks[runID]
	delete(coderSocks, runID)
	coderSockMu.Unlock()
	if !ok {
		return
	}
	_ = s.ln.Close()
	_ = os.Remove(s.file)
}

// startCoderSockets registers pairing self's runs directory, so a run-up for
// it opens the run's socket at once, and keeps one socket per run self owns:
// re-read from the records every serviceForwardPoll, which brings sockets back
// after a daemon restart and takes away those whose record went (a `coders
// drop` in another process). When ctx ends every socket of self is closed.
func startCoderSockets(ctx context.Context, self, runsDir string) {
	coderSockMu.Lock()
	coderSockDirs[self] = runsDir
	coderSockMu.Unlock()
	go func() {
		defer func() {
			coderSockMu.Lock()
			if coderSockDirs[self] == runsDir {
				delete(coderSockDirs, self)
			}
			var mine []string
			for id, s := range coderSocks {
				if s.owner == self {
					mine = append(mine, id)
				}
			}
			coderSockMu.Unlock()
			for _, id := range mine {
				coderCloseRunSocket(id)
			}
		}()
		coderReconcileSockets(self)
		t := time.NewTicker(serviceForwardPoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				coderReconcileSockets(self)
			}
		}
	}()
}

// coderReconcileSockets makes pairing self's open sockets match its records:
// one per run it owns that the watchdog has not stopped.
func coderReconcileSockets(self string) {
	want := map[string]bool{}
	for _, r := range loadCoderRecords() {
		if r.Owner == self && r.StoppedBy == "" {
			want[r.RunID] = true
		}
	}
	coderSockMu.Lock()
	var drop []string
	for id, s := range coderSocks {
		if s.owner == self && !want[id] {
			drop = append(drop, id)
		}
	}
	coderSockMu.Unlock()
	for _, id := range drop {
		coderCloseRunSocket(id)
	}
	for id := range want {
		_, _ = coderOpenRunSocket(self, id) // a failure is retried next poll
	}
}

// coderLane is pairing's lane as a run socket checks it: the lane socket's
// path, and the dial and mutual TLS its lanes use (unixLaneDialer), so the
// check can make the process on that path prove it is the pairing's Host.
type coderLane struct {
	path string
	dial func(ctx context.Context) (net.Conn, error)
	tls  *tls.Config
}

// setCoderSockLane records the lane of pairing self: a run socket serves only
// a process of the uid that serves it (coderPeerRefusal). An empty
// laneSocket forgets it, and then nothing is served.
func setCoderSockLane(self, laneSocket string, dial func(ctx context.Context) (net.Conn, error), laneTLS *tls.Config) {
	coderSockMu.Lock()
	defer coderSockMu.Unlock()
	if laneSocket == "" {
		delete(coderSockLanes, self)
		return
	}
	coderSockLanes[self] = coderLane{path: laneSocket, dial: dial, tls: laneTLS}
}
