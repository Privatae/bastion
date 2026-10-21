package main

// Second-bastion DETECTION — the second-bastion finding on the heartbeat.
//
// The singleton (singleton.go) refuses a second bastion going FORWARD: a `pair`
// whose state directory disagrees with the machine marker is turned away. That
// leaves two holes it cannot close by itself, and this file is what sees them:
//
//   1. Installs that PREDATE the marker. Every pairing made before the singleton
//      shipped is already on disk, and refusing new ones does nothing about the
//      ones already there. On existing installs this is the only case that exists.
//   2. Anything that got around the refusal — a build with the guard removed, a
//      state directory restored from a backup, a marker deleted and rewritten.
//
// The rule: the anchor host is alerted when a new bastion is installed on
// the machine. So the daemon LOOKS, and what it finds rides the
// heartbeat to every host the box serves.
//
// WHAT THIS CAN AND CANNOT SEE, stated here because the host's wording depends
// on it and a detection feature that overstates its reach is worse than none:
//
//   - It reads home directories out of /etc/passwd and looks for the default
//     config location under each. A user who sets XDG_CONFIG_HOME somewhere
//     else keeps their state dir somewhere this scan does not look.
//   - /etc/passwd ONLY. Users that exist through NSS alone — LDAP, SSSD, an AD
//     join — are never enumerated, so on a directory-joined machine this sees
//     the local accounts and nothing else. That is the common enterprise case
//     and it is a real hole, not a corner: getent would close it and is not
//     what this does today.
//   - A bastion RUNNING from a non-default directory is invisible to a scan of
//     default paths. The answer to the non-cooperating case is process
//     observation plus the observe signature table; this is
//     the filesystem half only, and it carries no posture degrade.
//   - So a finding is EVIDENCE, and an empty result is NOT PROOF of absence.
//     The heartbeat key is therefore omitted entirely on a box that could not
//     look (non-root, or not Linux), rather than reported as "none" — the same
//     watching/blind/unknown distinction the agent scanner already draws. A host
//     must never read "no second bastion" from a box that never looked.
//
// Root is required because the whole point is reading OTHER users' directories;
// a non-root scan would find nothing and report a clean machine, which is the
// exact lie this is here to prevent.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// passwdPath is the user list. Read-only, and only the name/uid/home fields are
// ever taken off a line.
const passwdPath = "/etc/passwd"

// otherBastionKind ranks a finding by how far along it is. The anchor needs the
// difference: a binary someone downloaded is not the same event as a state
// directory already serving a host nobody approved.
const (
	// obPaired — a state directory holding at least one pairing. This machine is
	// serving a host the anchor does not know about. The finding that degrades
	// posture.
	obPaired = "paired"
	// obState — a state directory with no pairings yet. Installed and initialised,
	// not yet attached to any host.
	obState = "state"
	// obBinary — a bastion binary in a user's own bin directory with no state
	// directory beside it. Nothing is running; somebody is part-way.
	obBinary = "binary"
)

// otherBastion is one bastion installation on this machine that is not the one
// sending this heartbeat. Paths and usernames only — never file contents, and
// never anything out of the other bastion's pairing files, which hold another
// host's credentials and are none of this host's business.
type otherBastion struct {
	Kind       string `json:"kind"`
	User       string `json:"user"`
	UID        int    `json:"uid"`
	StateDir   string `json:"state_dir,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Pairings   int    `json:"pairings"`
	LastChange string `json:"last_change,omitempty"`
}

// passwdUser is one line of /etc/passwd, narrowed to what the scan uses.
type passwdUser struct {
	Name string
	UID  int
	Home string
}

// readPasswdUsers parses /etc/passwd. A malformed line is skipped rather than
// failing the scan: one bad line in a file this scan does not own must not blind
// the machine.
func readPasswdUsers(path string) ([]passwdUser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []passwdUser
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 6 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		home := strings.TrimSpace(parts[5])
		if home == "" || home == "/" || home == "/nonexistent" || home == "/dev/null" {
			continue
		}
		// Several system accounts share one home (/var/run/foo and friends). Scan
		// each directory once; the first account named for it is the one reported.
		if seen[home] {
			continue
		}
		seen[home] = true
		out = append(out, passwdUser{Name: parts[0], UID: uid, Home: home})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ownStateDirs are the directories that must never be reported as somebody
// else's bastion: what the marker names AND this process's own config dir.
//
// Both, not either. The marker is not repointed once written (singleton.go
// maybeWriteMarker), so a root daemon whose own dir stops matching the marker —
// XDG_CONFIG_HOME set in root's environment, a config directory renamed — would
// otherwise skip the dir the marker names and report ITSELF as a second bastion
// "serving Hosts you never approved", to its own hosts. An alert about the
// reader's own bastion is worse than no alert: it is a red finding that cannot
// be acted on and that teaches the user to ignore the next one.
//
// A read error on either is not fatal; the other still excludes.
func ownStateDirs() []string {
	var out []string
	if m, err := readMarker(); err == nil && m != nil && strings.TrimSpace(m.StateDir) != "" {
		out = append(out, strings.TrimRight(m.StateDir, "/"))
	}
	if d, err := configDirPath(); err == nil {
		out = append(out, strings.TrimRight(d, "/"))
	}
	return out
}

// isOwnDir reports whether `dir` is one of ours. String comparison (sameDir),
// which is exactly why the symlink check in statRealDir has to exist: a link is
// a different string pointing at the same inode.
func isOwnDir(dir string, mine []string) bool {
	for _, m := range mine {
		if m != "" && sameDir(dir, m) {
			return true
		}
	}
	return false
}

// statRealDir stats a path WITHOUT following symlinks, and returns it only when
// it is a real directory.
//
// os.Stat follows links, and the ownership exclusion is a string compare, so a
// link cannot be seen through. Measured in a temp tree: an unprivileged user who
// runs
//
//	ln -s /root/.config/<state dir> ~/.config/<state dir>
//
// makes Stat report a directory and makes countPairings return ROOT's pairing
// count — which reaches the anchor's inbox as "eve is running a second bastion
// and it is serving 2 Hosts of its own. Your machine is answering to a host you
// never approved." One command, from any local account, forging a red security
// alert that is indistinguishable from a real one. Lstat is what tells them
// apart.
//
// A symlink here is not reported at all rather than reported as a lesser
// finding: the thing it points at is either ours (already excluded) or a real
// directory under some user's home, which this scan finds on its own pass.
func statRealDir(path string) (os.FileInfo, bool) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, false
	}
	return fi, true
}

// countPairings reports how many pairing files a state directory holds. A
// directory it cannot read counts zero — the DIRECTORY's existence is the
// finding, and the count only sharpens it.
//
// Lstat'd for the same reason as the state dir itself: `pairings` being a link
// to root's own is the same forgery one level down.
func countPairings(stateDir string) int {
	dir := filepath.Join(stateDir, "pairings")
	if _, ok := statRealDir(dir); !ok {
		return 0
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// bastionBinaryNames are the binary names an installation can carry. A single
// entry today; kept as a list so the scan below stays a loop when a second
// name ever exists.
var bastionBinaryNames = []string{"privatae-bastion"}

// scanOtherBastions walks the machine's users and returns every bastion
// installation that is not ours.
//
// nil means WE DID NOT LOOK and the caller must omit the heartbeat key. An empty
// (non-nil) slice means we looked and found none, which is a real state that has
// to travel so the host can clear a finding that has been dealt with — the same
// nil-vs-empty contract peers.go and unapprovedAttempts already use, for the
// same reason.
func scanOtherBastions() []otherBastion {
	if !singletonSupported() || !processIsRoot() {
		return nil
	}
	return scanOtherBastionsIn(passwdPath, ownStateDirs())
}

// scanOtherBastionsIn is the scan itself, with the two machine-scoped inputs
// passed in. Split out so the tests can exercise it against a temp tree: this
// binary's tests run as root on Linux, so a test calling scanOtherBastions()
// would read the REAL /etc/passwd and the real home directories of the machine
// it runs on. Two earlier test passes in this repo wrote to live state; the
// shape that prevents it is passing the paths rather than reaching for them.
func scanOtherBastionsIn(passwdFile string, mine []string) []otherBastion {
	users, err := readPasswdUsers(passwdFile)
	if err != nil {
		// Could not enumerate users ⇒ could not look. Say nothing.
		return nil
	}
	out := make([]otherBastion, 0)
	for _, u := range users {
		stateDir := filepath.Join(u.Home, ".config", "privatae-bastion")
		if isOwnDir(stateDir, mine) {
			continue
		}
		if st, ok := statRealDir(stateDir); ok {
			n := countPairings(stateDir)
			kind := obState
			if n > 0 {
				kind = obPaired
			}
			out = append(out, otherBastion{
				Kind: kind, User: u.Name, UID: u.UID, StateDir: stateDir,
				Pairings: n, LastChange: st.ModTime().UTC().Format(time.RFC3339),
			})
			continue
		}
		// No state directory. A binary on its own is the early warning.
		// Lstat again: a link named privatae-bastion proves nothing about what
		// it points at, and the finding is "this user has one", not "a path
		// resolves somewhere".
		for _, name := range bastionBinaryNames {
			bin := filepath.Join(u.Home, ".local", "bin", name)
			st, err := os.Lstat(bin)
			if err != nil || st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				continue
			}
			out = append(out, otherBastion{
				Kind: obBinary, User: u.Name, UID: u.UID, BinaryPath: bin,
				LastChange: st.ModTime().UTC().Format(time.RFC3339),
			})
			break
		}
	}
	// Most serious first, then by user, so the host reads the worst finding at the
	// top and the order does not churn between beats over a map iteration.
	rank := map[string]int{obPaired: 0, obState: 1, obBinary: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Kind] != rank[out[j].Kind] {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		return out[i].User < out[j].User
	})
	return out
}

// ── the heartbeat's cached view ────────────────────────────────────────────
//
// The scan stats a handful of paths per user, so it is far cheaper than the apt
// simulation posturePayload guards against — but it is still filesystem work on
// a box that may have a large passwd, and the heartbeat may never wait on disk:
// a late beat is what flips this box stale on the host and can trigger quarantine
// (observe_ops.go:787-795 sets out the same budget). So the beat publishes the
// last completed scan and a background ticker refreshes it, exactly as posture
// does.

const otherBastionRefreshEvery = 5 * time.Minute

var (
	otherBastionMu   sync.Mutex
	otherBastionLast []otherBastion
	otherBastionRan  bool
	otherBastionAt   time.Time
)

// otherBastionsPayload is what buildHeartbeatBody folds in: the last completed
// scan, or nil before the first one finishes (and forever on a box that cannot
// look). nil ⇒ the caller omits the key.
func otherBastionsPayload() []otherBastion {
	otherBastionMu.Lock()
	defer otherBastionMu.Unlock()
	if !otherBastionRan {
		return nil
	}
	return otherBastionLast
}

// otherBastionsScannedAt is WHEN the published answer was produced, sent beside
// it on every beat.
//
// Without it the list has no age, and a scan that stops completing publishes its
// last answer for ever — including a `[]`, which the platform and the UI both
// read as "looked, and the machine is clean". A frozen all-clear is the failure
// this whole feature is built to avoid, so the freshness has to travel with the
// finding and the reader has to be able to age it out. Empty before the first
// scan completes; the caller omits the key then, exactly as it omits the list.
func otherBastionsScannedAt() string {
	otherBastionMu.Lock()
	defer otherBastionMu.Unlock()
	if !otherBastionRan || otherBastionAt.IsZero() {
		return ""
	}
	return otherBastionAt.UTC().Format(time.RFC3339)
}

// refreshOtherBastions runs the scan once and publishes it.
//
// One refresher is started per PAIRING (run.go starts it beside the heartbeat,
// and a box serving three hosts runs three heartbeats), so this skips a scan that
// another goroutine has just done. A plain sync.Once would be wrong: the
// refreshers are tied to their pairing's context, so the first one to be
// cancelled would take the scan down for the whole box.
func refreshOtherBastions() {
	otherBastionMu.Lock()
	fresh := otherBastionRan && time.Since(otherBastionAt) < otherBastionRefreshEvery/2
	otherBastionMu.Unlock()
	if fresh {
		return
	}
	found := scanOtherBastions()
	otherBastionMu.Lock()
	defer otherBastionMu.Unlock()
	if found == nil {
		// Could not look. Leave any previous answer alone rather than retracting
		// it — a transient read failure must not clear a real finding.
		return
	}
	otherBastionLast = found
	otherBastionRan = true
	otherBastionAt = time.Now()
}

// runOtherBastionRefresh is started by the heartbeat goroutine and lives as long
// as it does: one scan now, then one per window.
func runOtherBastionRefresh(ctx context.Context) {
	refreshOtherBastions()
	t := time.NewTicker(otherBastionRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refreshOtherBastions()
		}
	}
}

// describeOtherBastion is the one-line form used in the daemon's own log, so an
// operator reading journalctl sees the same finding the host was sent.
func describeOtherBastion(o otherBastion) string {
	switch o.Kind {
	case obPaired:
		return fmt.Sprintf("a second bastion under user %s serves %d host(s) of its own (%s)",
			o.User, o.Pairings, o.StateDir)
	case obState:
		return fmt.Sprintf("a second bastion under user %s is set up but not paired (%s)", o.User, o.StateDir)
	default:
		return fmt.Sprintf("user %s has a bastion binary installed (%s)", o.User, o.BinaryPath)
	}
}
