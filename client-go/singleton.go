package main

// ONE BASTION PER MACHINE.
//
// The gap this closes is not "the installer has no check". It is that NOTHING in
// this binary was machine-scoped: mode, anchor, owner and pairings all live under
// one OS user's config dir, so the anchor governed a DIRECTORY, not a machine. A
// second OS user installs non-root into $HOME/.local/bin, gets their own
// configDir(), pairs their own host, and the anchor never learns of it. They never
// need root, because they never need networked mode — local mode serves exactly one
// host, which is all they want. peers.go cannot see it: it reports peers read from
// the pairings its OWN daemon loaded, so a bastion under another user is
// structurally unseeable.
//
// Two instruments, and the difference between them is the honest part:
//
//   - a MARKER that makes the cooperating case refuse, with a message saying what
//     to do instead. A non-root user cannot be stopped from running a binary, and a
//     binary that honours a marker can be swapped for an older one or run with
//     HOME=/tmp/x. A marker binds only a COOPERATING binary. Nothing here claims to
//     prevent a determined local user from running their own copy.
//   - an exclusion LOCK that makes two daemons impossible rather than merely
//     unlucky.
//
// The non-cooperating case is a different instrument that already exists: the
// anchored bastion runs as root and walks /proc with per-process UID
// (agents_linux.go), so a second bastion is VISIBLE even when it cannot be refused.
//
// On the lock, and why it is a lock: there is ALREADY an accidental singleton and
// it is the worst kind. nextListenAddr allocates from 127.0.0.1:7878 upward
// consulting only the pairings handed to it (config.go), which are this user's — so
// user B's first pairing also gets 7878. runPairing pushes ListenAndServe into errc
// and cmdRun returns on the first errc, so the process exits; under Restart=always
// the loser crash-loops forever and the winner is decided by boot order. This
// replaces an accidental singleton that fails as a bind error with a deliberate one
// that says why.
//
// SCOPE, stated explicitly: step 1 is LINUX-ROOT ONLY.
// Nothing writes the marker on a non-root install, and the lock is root-owned by
// design. On macOS and Windows there is no marker or machine lock — for two
// non-root users on one Linux box there is none either. Where those platforms
// run the bastion as a system service, sysservice.go refuses `pair` and `run`
// from an account that does not administer the machine, which covers the
// cooperating case the marker covers here. markerPath knows their paths for
// when the work reaches them; it does not claim they are covered.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// machineMarker is the machine-scoped record. Root-owned and WORLD-READABLE on
// purpose: a non-root `pair` has to be able to read it, or the second-user refusal
// — the case the marker exists for — never fires.
type machineMarker struct {
	BoxPublicKey string `json:"box_public_key,omitempty"`
	Mode         string `json:"mode"`
	AnchorHandle string `json:"anchor_handle,omitempty"`
	StateDir     string `json:"state_dir"`
	BinaryPath   string `json:"binary_path,omitempty"`
	WrittenAt    string `json:"written_at"`
}

// markerDir / markerName: the machine-scoped location, named for the PRODUCT
// rather than the binary.
//
// That is not cosmetic. The binary name and the config directory name are
// allowed to change independently of each other over the life of an install;
// a marker keyed on either would split an installed base in two the day one of
// them moved. The product name is the one thing that stays.
//
// WHY THIS IS NOT /etc/privatae/bastion.json, which was the first choice.
//
// /etc/privatae is a SECRETS directory on the boxes that have one, and such a
// directory is normally 0750 rather than 0755. The marker must be WORLD-READABLE
// under a TRAVERSABLE directory or a non-root `pair` cannot read it and the
// second-user refusal never fires — so putting it there forces one of two bad
// outcomes: chmod a hardened secrets directory to 0755 as a side effect of a
// bastion write (which the first draft did, silently), or leave it 0750 and have
// the guard fail open on exactly those boxes, because ReadFile returns EACCES,
// which is not IsNotExist, and a guard that treated unreadable as absent would
// let that pairing through.
//
// Neither is acceptable, so the marker lives in a directory the bastion CREATES
// AND OWNS. /var/lib/privatae is already the bastion's root-install base
// (faStateBase, freeagent_drop.go). The rule that matters — name it for the
// PRODUCT, not the binary — still holds.
//
// The marker stores the state directory as an absolute path. A marker whose
// directory no longer exists protects nothing: there is no second bastion at
// that path to collide with, only a record of one that was moved or removed.
// Such a marker is treated as absent by both the rewrite rule and the pairing
// guard, so a machine whose state directory was renamed or deleted can pair
// again instead of refusing forever with advice that cannot be followed. Only
// a directory that is positively gone counts; one this user merely cannot
// traverse into is still somebody's bastion and still refuses.
const (
	markerDirLinux  = "/var/lib/privatae/bastion"
	markerDirDarwin = "/Library/Application Support/privatae/bastion"
	markerName      = "machine.json"
)

// markerPathOverride / runtimeDirOverride relocate the two machine-scoped paths
// for tests. Same shape as faStateBaseOverride in freeagent_drop.go. Nothing
// outside a test may set them.
var markerPathOverride, runtimeDirOverride string

func markerPath() string {
	if markerPathOverride != "" {
		return markerPathOverride
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(markerDirDarwin, markerName)
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "privatae", "bastion", markerName)
	default:
		return filepath.Join(markerDirLinux, markerName)
	}
}

// singletonSupported reports whether this platform has the machine-scoped half at
// all. Step 1 is Linux only (see the scope note above).
func singletonSupported() bool { return runtime.GOOS == "linux" }

// readMarker returns the machine marker, or nil when there is none. A missing
// marker is not an error: marker absent ⇒ exactly today's behaviour, which is what
// makes this safe to roll onto live installs.
func readMarker() (*machineMarker, error) {
	raw, err := os.ReadFile(markerPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var m machineMarker
	if err := json.Unmarshal(raw, &m); err != nil {
		// A corrupt marker must not brick pairing. Report it; the call sites treat
		// it as absent. Refusing on unparseable bytes would be a self-inflicted
		// outage with no upside.
		return nil, fmt.Errorf("machine marker at %s is unreadable: %w", markerPath(), err)
	}
	if strings.TrimSpace(m.StateDir) == "" {
		return nil, nil
	}
	return &m, nil
}

// writeMarker writes the marker with EXPLICIT 0755 dir / 0644 file.
//
// It deliberately does NOT use atomicWrite: that helper makes the dir 0700 and the
// file 0600 (ctx.go), which a non-root `pair` could not read — and then the
// second-user refusal, the entire point, would never fire. Same temp+rename shape,
// different modes, and an explicit Chmod because the process umask would otherwise
// decide.
func writeMarker(m *machineMarker) error {
	if err := refuseRealMachineWrite(markerPathOverride, "machine marker"); err != nil {
		fmt.Printf("singleton: %v\n", err)
		return nil
	}
	path := markerPath()
	dir := filepath.Dir(path)
	// Create the directory if it is ours to create; NEVER chmod one that already
	// exists. The first draft chmod'd unconditionally, which where this resolved
	// into a hardened directory would have loosened it as a side effect of a
	// bastion write.
	//
	// faMkdirAllMode, not MkdirAll: MkdirAll applies the process UMASK to every
	// ANCESTOR it creates, and only the leaf was being fixed. /var/lib/privatae
	// was absent on 19 of 20 boxes measured, so the first marker write creates it
	// almost everywhere — and under umask 027 or 077 (a `sudo -H set-mode` from a
	// hardened shell; sudo passes the umask through) that parent lands 0750 or
	// 0700. A non-root `pair` then cannot traverse to the marker, ReadFile
	// returns EACCES, and the guard would fail open on exactly the locked-down
	// boxes this location was chosen for. faMkdirAllMode records the ancestors it
	// creates and sets each to 0755 explicitly; it was written for this same
	// parent, for this same reason (freeagent_drop.go).
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		if err := faMkdirAllMode(dir, 0o755); err != nil {
			return err
		}
	} else if statErr != nil {
		return statErr
	} else if fi, lerr := os.Lstat(dir); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		// Symmetry with the lock's check: a symlinked marker dir means the marker
		// is not where we think it is.
		return fmt.Errorf("%s is a symlink — refusing to write the machine marker through it", dir)
	}
	m.WrittenAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".bastion-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once renamed away
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

// warnIfMarkerUnreachable says so, loudly, when a non-root process could not
// traverse to the marker. Without this the failure is silent in the worst
// direction: singletonGuardForPair treats an unreadable marker as absent and
// ALLOWS the pairing, so a locked-down ancestor turns the singleton off on the
// machines that are most hardened, with nothing in any log.
func warnIfMarkerUnreachable(path string) {
	for d := filepath.Dir(path); d != "/" && d != "."; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return
		}
		if fi.Mode().Perm()&0o001 == 0 {
			fmt.Printf("singleton: WARNING %s is %v — a non-root `pair` cannot reach the machine marker, "+
				"so the second-bastion refusal will NOT fire on this box\n", d, fi.Mode().Perm())
			return
		}
	}
}

// maybeWriteMarker records this process's state dir as the machine's canonical one.
// Called on root `run`, on `set-mode networked`, and on `claim-anchor`. Idempotent.
//
// The REWRITE IS CONDITIONAL, and that condition is load-bearing. An unconditional
// rewrite plus the lock means whichever root daemon wins after a primary dies can
// repoint the canonical state dir at its own: a run from a forked dir
// (XDG_CONFIG_HOME, or HOME in sudo's env_keep) that acquires the lock first would
// flip the marker, and the unit's restart seconds later would find ITSELF the
// standby. Without any rewrite at all, a future config-dir rename would refuse
// every pair on the fleet until someone hand-fixed it — so: rewrite when the marker
// names this same dir, or when there is no marker, and never otherwise.
func maybeWriteMarker() string {
	if !singletonSupported() {
		return "not supported on this platform"
	}
	if !processIsRoot() {
		return "not root"
	}
	// (the test guard now lives in writeMarker itself — see refuseRealMachineWrite)
	// Historical note, because it was a real incident on a real box:
	// the first run of this suite as root wrote /etc/privatae/bastion.json naming
	// a t.TempDir() that no longer exists — which would have made this box refuse
	// every future `pair`, pointing at a directory nobody can reach. The test that
	// did it only called setBoxMode; it never mentioned the marker, and it never
	// will. Relying on each test to remember an override is how that happens, so
	// the binary refuses instead: under `go test`, write only where a test has
	// explicitly pointed the marker.

	mine, err := configDirPath()
	if err != nil {
		return "no config dir"
	}
	existing, err := readMarker()
	if err != nil {
		fmt.Printf("singleton: %v — not rewriting it\n", err)
		return "unreadable marker"
	}
	if !markerShouldBeWritten(existing, mine) {
		// Another state dir owns this machine. Say so once; do not fight over it.
		fmt.Printf("singleton: this machine's bastion state is %s, not %s — leaving the marker alone\n",
			existing.StateDir, mine)
		return "another state dir owns this machine"
	}
	m := &machineMarker{StateDir: mine, Mode: boxMode()}
	if exe, e := os.Executable(); e == nil {
		m.BinaryPath = exe
	}
	if a := currentAnchor(); a != nil {
		m.AnchorHandle = a.AnchorHandle
		m.BoxPublicKey = a.PublicKey
	}
	// Check reachability on EVERY pass, not only when we write. An ancestor
	// chmod'd strict after the first write would otherwise never be reported —
	// it would just fail closed at `pair` with nothing in the journal.
	warnIfMarkerUnreachable(markerPath())

	// Only write when something actually changed. A machine that is crash-looping
	// unpaired runs this every two seconds; an unconditional write is a
	// CreateTemp + fsync + rename each pass for no change.
	if existing != nil && sameDir(existing.StateDir, m.StateDir) && existing.Mode == m.Mode &&
		existing.AnchorHandle == m.AnchorHandle && existing.BinaryPath == m.BinaryPath {
		return "unchanged"
	}
	if err := writeMarker(m); err != nil {
		fmt.Printf("singleton: could not write %s: %v\n", markerPath(), err)
		return "write failed"
	}
	if _, err := os.Stat(markerPath()); err != nil {
		return "refused" // the test guard declined; writeMarker returns nil softly
	}
	return "written"
}

// markerShouldBeWritten is the conditional-rewrite rule, extracted because it is
// the load-bearing one: write when there is NO marker, or when the marker already
// names this same state dir — never when it names another. Extracted so the rule
// is testable on its own rather than only reachable as root through maybeWriteMarker.
func markerShouldBeWritten(existing *machineMarker, mine string) bool {
	return existing == nil || sameDir(existing.StateDir, mine) || markerStateDirGone(existing)
}

// markerStateDirGone reports a marker whose state directory is positively
// absent. Permission errors are not absence: a directory this user cannot look
// into is still a bastion that the guard exists to protect.
func markerStateDirGone(m *machineMarker) bool {
	if m == nil || m.StateDir == "" {
		return false
	}
	_, err := os.Stat(m.StateDir)
	return err != nil && os.IsNotExist(err)
}

// refuseRealMachineWrite stops a TEST from claiming the real machine.
//
// A test must never write the machine marker or take the machine lock at their
// real paths. This is not hypothetical: the first run of this suite as root wrote
// a real marker on the build box naming a t.TempDir() that no longer existed,
// which would have made that machine refuse every future `pair`, pointing at a
// directory nobody can reach. The test responsible only called setBoxMode; it
// never mentioned the marker, and a future one will not either.
//
// It guards the two WRITE paths rather than the one caller, because a test that
// calls writeMarker or acquireSingletonLock directly would otherwise slip past.
// Reads are harmless and are not guarded.
func refuseRealMachineWrite(override, what string) error {
	if testing.Testing() && override == "" {
		return fmt.Errorf("refusing to write the real %s from a test — point it at a temp path first", what)
	}
	return nil
}

// sameDir compares two state-dir paths the way the filesystem would.
func sameDir(a, b string) bool {
	return filepath.Clean(strings.TrimSpace(a)) == filepath.Clean(strings.TrimSpace(b))
}

// errForkedState is returned when this process's state dir is not the machine's.
var errForkedState = errors.New("another bastion owns this machine")

// singletonGuardForPair refuses a pairing that would fork this machine's bastion
// state into a second directory.
//
// It is called at the TOP of pairWithToken, before loadPairings, and the ordering
// is the whole point: loadPairings -> pairingsDir -> MkdirAll CREATES the forked
// directory, so a check placed after it has already done the damage it exists to
// prevent. It uses configDirPath (no MkdirAll) for the same reason.
//
// Marker absent ⇒ nil ⇒ exactly today's behaviour.
func singletonGuardForPair() error {
	if !singletonSupported() {
		return nil
	}
	m, err := readMarker()
	if err != nil {
		return singletonGuardForPairFromReadError(err)
	}
	if m == nil {
		return nil
	}
	return singletonGuardAgainst(m)
}

// singletonGuardForPairFromReadError is the "we could not read the marker" half,
// split out so the EACCES-refuses / corrupt-allows decision is testable without
// dropping privileges inside the test process.
func singletonGuardForPairFromReadError(err error) error {
	// UNREADABLE IS NOT ABSENT. "Marker absent ⇒ today's behaviour" means
	// ENOENT, and readMarker already maps that to (nil, nil). Anything else —
	// EACCES from a locked-down ancestor, a truncated file — means we cannot
	// tell, and this directory is created only by the bastion, so something here
	// owns the machine. Allowing was the first draft's behaviour and it failed
	// open on precisely the hardened boxes.
	if os.IsPermission(err) || errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w.\n"+
			"  this machine has a bastion marker at %s that this user cannot read (%v).\n"+
			"  A machine runs one bastion: pair as that bastion's user, or with `sudo -H`",
			errForkedState, markerPath(), err)
	}
	// A CORRUPT file is different: refusing every pairing because one file got
	// truncated would be a self-inflicted outage with no upside.
	fmt.Printf("singleton: %v — allowing this pairing\n", err)
	return nil
}

// singletonGuardAgainst compares a marker we DID read against this process.
func singletonGuardAgainst(m *machineMarker) error {
	mine, err := configDirPath()
	if err != nil {
		return nil
	}
	if sameDir(m.StateDir, mine) || markerStateDirGone(m) {
		return nil
	}
	// Both dirs in the message on purpose: a legitimate `sudo -H pair` refused
	// because root's profile carries an XDG_CONFIG_HOME needs to see WHY, and
	// "already paired" would send the reader hunting in the wrong place.
	return fmt.Errorf(
		"%w.\n"+
			"  this machine's bastion keeps its state in: %s\n"+
			"  this command would write a SECOND one in:  %s\n"+
			"\n"+
			"A machine runs one bastion. If you are the owner, run this as that\n"+
			"bastion's user (or with `sudo -H`) so it pairs into the existing one.\n"+
			"If someone else owns the bastion here, this machine cannot serve your\n"+
			"host yet — say so to whoever runs it.",
		errForkedState, m.StateDir, mine)
}

// ── exclusion: the deliberate singleton ─────────────────────────────────────

// runtimeDir holds the lock. Root-owned 0755 so only root can create or remove
// anything in it, which is why the lock cannot be squatted.
const runtimeDir = "/run/privatae"

func runtimeDirPath() string {
	if runtimeDirOverride != "" {
		return runtimeDirOverride
	}
	return runtimeDir
}

func lockPath() string { return filepath.Join(runtimeDirPath(), "bastion.lock") }

// singletonLock is a held exclusion lock. Closing the file releases it; the kernel
// does that on death too, including SIGKILL and OOM, so there is nothing to clean up
// and no stale state to reason about.
type singletonLock struct{ f *os.File }

func (l *singletonLock) release() {
	if l != nil && l.f != nil {
		_ = l.f.Close()
	}
}

// acquireSingletonLock takes THE machine-wide exclusion lock for the daemon.
//
// 0600 AND ROOT-OWNED, and that is not tidiness: flock(2) needs no write access —
// LOCK_EX can be taken through an O_RDONLY fd. At the marker's 0644 any local uid
// could take this lock and hold the root daemon out, which is precisely the squat
// this design rejected abstract sockets for. A `nobody` process holding it across a
// restart would leave the unit active and blocked forever with nothing in the log.
//
// The file is NEVER unlinked. Unlink-and-recreate lets two daemons hold LOCK_EX on
// two different inodes at one path; /run/privatae being root 0755 means only root
// can do it, so the invariant is cheap — and writing it down is what stops a future
// "clean up stale files" change from reintroducing the race the lock replaced.
//
// Blocking vs non-blocking: blocking is right under systemd (the unit is
// Type=simple with no TimeoutStartSec, so a blocked start is not killed, and
// LOCK_NB-then-exit would be the two-second crash-loop this exists to end). It is
// wrong for a human: a manual `sudo -H privatae-bastion run` would become an
// invisible standby, `systemctl stop` would then not stop the bastion, and
// `systemctl restart` would swap the roles permanently. So: non-blocking with
// "already running" when stdin is a terminal, blocking when it is not.
func acquireSingletonLock() (*singletonLock, error) {
	if !singletonSupported() || !processIsRoot() {
		return nil, nil // no singleton on this platform/user in step 1
	}
	if err := refuseRealMachineWrite(runtimeDirOverride, "machine lock"); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(runtimeDirPath(), 0o755); err != nil {
		return nil, fmt.Errorf("singleton: cannot create %s: %w", runtimeDirPath(), err)
	}
	// Only root can create anything in /run, so this is belt-and-braces — but a
	// symlink or a non-root owner there would mean the lock is not the lock, and
	// the check is one syscall.
	if fi, err := os.Lstat(runtimeDirPath()); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("singleton: %s is a symlink — refusing to lock through it", runtimeDirPath())
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("singleton: %s is not a directory", runtimeDirPath())
		}
		if uid, ok := ownerUID(fi); ok && uid != 0 {
			return nil, fmt.Errorf("singleton: %s is owned by uid %d, not root — refusing to lock in it", runtimeDirPath(), uid)
		}
	}
	_ = os.Chmod(runtimeDirPath(), 0o755)
	f, err := os.OpenFile(lockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("singleton: cannot open %s: %w", lockPath(), err)
	}
	if err := os.Chmod(lockPath(), 0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("singleton: cannot secure %s: %w", lockPath(), err)
	}
	if stdinIsTerminal() {
		if err := flockFileNB(f); err != nil {
			holder := lockHolder(f)
			_ = f.Close()
			return nil, fmt.Errorf("a bastion is already running on this machine%s.\n"+
				"  Stop it first (`systemctl stop privatae-bastion`), or leave it running —\n"+
				"  one machine runs one bastion, and it already serves every pairing here", holder)
		}
	} else {
		fmt.Printf("singleton: taking the machine lock at %s (waits if another bastion holds it)\n", lockPath())
		if err := flockFile(f); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("singleton: cannot lock %s: %w", lockPath(), err)
		}
	}
	// Record who holds it. Truncate-and-write, never unlink.
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
		_ = f.Sync()
	}
	return &singletonLock{f: f}, nil
}

// lockHolder reads the pid recorded by the daemon that holds the lock, for the
// message. Best-effort: an empty or unreadable file just means a less specific
// sentence, never a failure.
func lockHolder(f *os.File) string {
	buf := make([]byte, 32)
	n, _ := f.ReadAt(buf, 0)
	pid := strings.TrimSpace(string(buf[:n]))
	if pid == "" {
		return ""
	}
	if _, err := strconv.Atoi(pid); err != nil {
		return ""
	}
	return " (pid " + pid + ")"
}
