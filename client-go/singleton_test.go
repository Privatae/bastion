//go:build !windows

// Tagged !windows. These tests were ALREADY unix-only — they use
// helpers that live behind `//go:build !windows` (sessionShellsPath,
// withConfigDir, withMarkerAt, setupBox) — so this file has never compiled for
// Windows and `GOOS=windows go vet ./...` has been red on it since it was
// written. The tag removes no coverage; it states a dependency that was already
// there so vet can run clean on that target, which is what makes a REAL Windows
// regression visible instead of being lost in a failure everyone scrolls past.
// Windows-safe coverage of the machine-authority gate lives in privilege_test.go.

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// withMarkerAt points the machine marker at a temp path for the duration of a test.
func withMarkerAt(t *testing.T, path string) {
	t.Helper()
	old := markerPathOverride
	markerPathOverride = path
	t.Cleanup(func() { markerPathOverride = old })
}

// writeMarkerNaming puts a marker on disk that claims `stateDir` owns the machine.
func writeMarkerNaming(t *testing.T, path, stateDir string) {
	t.Helper()
	withMarkerAt(t, path)
	if err := writeMarker(&machineMarker{StateDir: stateDir, Mode: modeLocal}); err != nil {
		t.Fatalf("writeMarker: %v", err)
	}
}

func TestSingletonGuardAllowsWhenThereIsNoMarker(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	withMarkerAt(t, filepath.Join(t.TempDir(), "absent", "bastion.json"))
	// Marker absent ⇒ exactly today's behaviour. This is what makes the change
	// safe to roll onto live installs: nothing changes until a root run writes one.
	if err := singletonGuardForPair(); err != nil {
		t.Fatalf("no marker must not refuse a pairing: %v", err)
	}
}

func TestSingletonGuardRefusesASecondStateDirAndNamesBoth(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	dir := withConfigDir(t) // this process's state dir is now under a temp HOME
	mine, err := configDirPath()
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "..", "someone-else", "privatae-bastion")
	if err := os.MkdirAll(other, 0o700); err != nil { // a real second bastion, present on disk
		t.Fatal(err)
	}
	writeMarkerNaming(t, filepath.Join(t.TempDir(), "bastion.json"), other)

	err = singletonGuardForPair()
	if err == nil {
		t.Fatal("a marker naming another state dir must refuse the pairing")
	}
	// Both dirs in the message: a legitimate `sudo -H pair` refused because of a
	// stray XDG_CONFIG_HOME has to be able to see WHY. "already paired" would send
	// the reader hunting in the wrong place.
	if !strings.Contains(err.Error(), filepath.Clean(other)) || !strings.Contains(err.Error(), mine) {
		t.Fatalf("the refusal must name BOTH directories, got: %v", err)
	}
}

func TestSingletonGuardAllowsItsOwnStateDir(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	withConfigDir(t)
	mine, err := configDirPath()
	if err != nil {
		t.Fatal(err)
	}
	writeMarkerNaming(t, filepath.Join(t.TempDir(), "bastion.json"), mine)
	if err := singletonGuardForPair(); err != nil {
		t.Fatalf("the machine's own bastion must still be able to pair: %v", err)
	}
}

// The ordering property, and the reason the guard is the FIRST statement in
// pairWithToken: asking "which state dir would I use" must not bring that
// directory into existence. configDir() -> MkdirAll is the damage, so a guard
// that called it would have already forked the state it refuses.
func TestSingletonGuardDoesNotCreateTheForkedStateDir(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HOME", home)
	mine, err := configDirPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mine); !os.IsNotExist(err) {
		t.Fatalf("precondition: %s should not exist yet (%v)", mine, err)
	}
	elsewhere := filepath.Join(home, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil { // present on disk: a real other bastion
		t.Fatal(err)
	}
	writeMarkerNaming(t, filepath.Join(t.TempDir(), "bastion.json"), elsewhere)

	if err := singletonGuardForPair(); err == nil {
		t.Fatal("expected a refusal")
	}
	if _, err := os.Stat(mine); !os.IsNotExist(err) {
		t.Fatalf("the guard CREATED the forked state dir %s — that is the damage it exists to prevent", mine)
	}
	// And prove the trap is real: the call the guard must not make does create it.
	if _, err := configDir(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mine); err != nil {
		t.Fatalf("configDir() is supposed to create the dir; the test's premise is wrong: %v", err)
	}
}

// The marker must be readable by a NON-root `pair`, or the second-user refusal —
// the whole point — never fires. atomicWrite would make it 0600 under a 0700 dir.
func TestMarkerIsWorldReadableUnderATraversableDir(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	path := filepath.Join(t.TempDir(), "machine", "bastion.json")
	writeMarkerNaming(t, path, "/some/state/dir")

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("marker must be 0644 so a non-root pair can read it, got %v", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o755 {
		t.Fatalf("marker dir must be 0755 traversable, got %v", di.Mode().Perm())
	}
	// It must also round-trip.
	m, err := readMarker()
	if err != nil || m == nil || m.StateDir != "/some/state/dir" {
		t.Fatalf("round-trip failed: %+v %v", m, err)
	}
}

func TestCorruptMarkerDoesNotBrickPairing(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	path := filepath.Join(t.TempDir(), "bastion.json")
	withMarkerAt(t, path)
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readMarker(); err == nil {
		t.Fatal("a corrupt marker should be reported as an error by readMarker")
	}
	// ...but the guard must ALLOW. Refusing every pairing on this machine because
	// one file got truncated would be a self-inflicted outage with no upside.
	if err := singletonGuardForPair(); err != nil {
		t.Fatalf("a corrupt marker must not refuse pairing: %v", err)
	}
	// An empty state dir is "no marker", not "a marker that owns nothing".
	if err := os.WriteFile(path, []byte(`{"state_dir":"  "}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := readMarker()
	if err != nil || m != nil {
		t.Fatalf("a marker with no state dir must read as absent, got %+v %v", m, err)
	}
}

// The conditional rewrite. An UNCONDITIONAL rewrite plus the lock lets whichever
// root daemon wins after a primary dies repoint the canonical state dir at its
// own — a run from a forked dir that takes the lock first would flip the marker,
// and the unit's restart seconds later would find itself the standby.
func TestMarkerRewriteIsConditional(t *testing.T) {
	mine := "/root/.config/privatae-bastion"
	if !markerShouldBeWritten(nil, mine) {
		t.Fatal("no marker yet: must write one, or a config-dir rename would refuse every pair on the fleet")
	}
	if !markerShouldBeWritten(&machineMarker{StateDir: mine}, mine) {
		t.Fatal("a marker naming this same dir must be refreshed")
	}
	if !markerShouldBeWritten(&machineMarker{StateDir: mine + "/"}, mine) {
		t.Fatal("trailing-slash differences are the same directory")
	}
	// A marker naming a directory that no longer exists protects nothing and
	// must not block this machine from pairing again.
	gone := filepath.Join(t.TempDir(), "moved-away")
	if !markerShouldBeWritten(&machineMarker{StateDir: gone}, mine) {
		t.Fatal("a marker whose state directory is gone must be rewritten")
	}
	if err := singletonGuardAgainst(&machineMarker{StateDir: gone}); err != nil {
		t.Fatalf("a marker whose state directory is gone must not refuse pair: %v", err)
	}
	other := filepath.Join(t.TempDir(), "other", "privatae-bastion")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if markerShouldBeWritten(&machineMarker{StateDir: other}, mine) {
		t.Fatal("a marker naming ANOTHER dir must never be overwritten — that is the repoint attack")
	}
}

// The lock is the deliberate singleton. It must actually exclude, and it must be
// unopenable by a non-root uid: flock needs no write access, so at 0644 any local
// user could take LOCK_EX through a read-only fd and hold the root daemon out.
func TestSingletonLockExcludesAndIsPrivate(t *testing.T) {
	if !singletonSupported() || !processIsRoot() {
		t.Skip("the lock is root-only on Linux in step 1")
	}
	dir := t.TempDir()
	old := runtimeDirOverride
	runtimeDirOverride = filepath.Join(dir, "run")
	t.Cleanup(func() { runtimeDirOverride = old })

	lock, err := acquireSingletonLock()
	if err != nil {
		t.Fatalf("first acquire must succeed: %v", err)
	}
	if lock == nil {
		t.Fatal("expected a held lock")
	}

	fi, err := os.Stat(lockPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock must be 0600 — at 0644 any local uid can take it through an O_RDONLY fd, got %v", fi.Mode().Perm())
	}

	// A second holder is refused while the first holds it.
	f2, err := os.OpenFile(lockPath(), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	if err := flockFileNB(f2); err == nil {
		t.Fatal("two daemons took the machine lock at once — it excludes nothing")
	}

	// Released on close, and the file is NEVER unlinked (unlink-and-recreate lets
	// two daemons hold LOCK_EX on two different inodes at one path).
	lock.release()
	if _, err := os.Stat(lockPath()); err != nil {
		t.Fatalf("the lock file must survive release, got %v", err)
	}
	if err := flockFileNB(f2); err != nil {
		t.Fatalf("after release the lock must be available: %v", err)
	}
}

func TestSingletonLockRecordsItsHolder(t *testing.T) {
	if !singletonSupported() || !processIsRoot() {
		t.Skip("the lock is root-only on Linux in step 1")
	}
	dir := t.TempDir()
	old := runtimeDirOverride
	runtimeDirOverride = filepath.Join(dir, "run")
	t.Cleanup(func() { runtimeDirOverride = old })

	lock, err := acquireSingletonLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
	raw, err := os.ReadFile(lockPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		t.Fatal("the holder's pid must be recorded, or the 'already running' message cannot name it")
	}
}

// The marker carries what a reader needs to act: which state dir owns the machine,
// the mode, and where the binary lives.
func TestMarkerCarriesTheMachineFacts(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	path := filepath.Join(t.TempDir(), "bastion.json")
	withMarkerAt(t, path)
	// The binary path as it is on a real install (verified on a real machine).
	if err := writeMarker(&machineMarker{
		StateDir:   "/root/.config/privatae-bastion",
		Mode:       modeNetworked,
		BinaryPath: filepath.Join("/usr/local/bin", "privatae-bastion"),
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"mode", "state_dir", "binary_path", "written_at"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("marker is missing %q: %s", k, raw)
		}
	}
}

// The protection for the protection. The first run of this suite as root wrote a
// real marker on the build box naming a t.TempDir() that no longer existed, which
// would have made that machine refuse every future pair. The test responsible only
// called setBoxMode; it never mentioned the marker, and a future one won't either.
//
// It asserts the REASON rather than the absence of a file: once a real marker
// exists on the box running the suite, "no marker appeared" passes even with the
// guard removed, because maybeWriteMarker would take the another-state-dir branch
// instead.
func TestATestCannotClaimTheRealMachine(t *testing.T) {
	if !singletonSupported() || !processIsRoot() {
		t.Skip("the marker is root-only on Linux in step 1")
	}
	// The rule itself, tested directly and safely: a write with no override set
	// is refused. This can never touch the machine.
	if err := refuseRealMachineWrite("", "machine marker"); err == nil {
		t.Fatal("a test with no override must be refused the real machine marker")
	}
	if err := refuseRealMachineWrite("/tmp/somewhere", "machine marker"); err != nil {
		t.Fatalf("a test that DID point it at a temp path must be allowed: %v", err)
	}

	// And the wiring: writeMarker must consult it before touching anything.
	// NON-DESTRUCTIVE BY CONSTRUCTION — if the guard is ever removed this would
	// create a real marker, so it removes what it created before failing. Measured
	// the hard way: a mutation run with the guard stripped wrote
	// /var/lib/privatae/bastion/machine.json on the build box and broke an
	// unrelated anchor test in the same run.
	old := markerPathOverride
	markerPathOverride = ""
	t.Cleanup(func() { markerPathOverride = old })
	existedBefore := false
	if _, err := os.Stat(markerPath()); err == nil {
		existedBefore = true
	}
	if err := writeMarker(&machineMarker{StateDir: "/tmp/whatever"}); err != nil {
		t.Fatalf("writeMarker must refuse softly, not error: %v", err)
	}
	if _, err := os.Stat(markerPath()); err == nil && !existedBefore {
		_ = os.Remove(markerPath()) // clean up before failing
		t.Fatalf("writeMarker is not consulting the test guard — it created %s", markerPath())
	}

	// The guard covers the lock too, not just the marker.
	oldRT := runtimeDirOverride
	runtimeDirOverride = ""
	t.Cleanup(func() { runtimeDirOverride = oldRT })
	if _, err := acquireSingletonLock(); err == nil {
		t.Fatal("a test just took the REAL machine lock")
	}
}

// The positive path. A no-op maybeWriteMarker passed the entire suite.
func TestMaybeWriteMarkerWritesTheMachinesOwnStateDir(t *testing.T) {
	if !singletonSupported() || !processIsRoot() {
		t.Skip("the marker is root-only on Linux in step 1")
	}
	withConfigDir(t)
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	mine, err := configDirPath()
	if err != nil {
		t.Fatal(err)
	}
	if got := maybeWriteMarker(); got != "written" {
		t.Fatalf("first root run must write the marker, got %q", got)
	}
	m, err := readMarker()
	if err != nil || m == nil {
		t.Fatalf("marker should exist: %+v %v", m, err)
	}
	if m.StateDir != mine {
		t.Fatalf("marker must name this process's state dir: got %q want %q", m.StateDir, mine)
	}
	// Idempotent: nothing changed, so nothing is rewritten. A crash-looping
	// unpaired box runs this every two seconds.
	if got := maybeWriteMarker(); got != "unchanged" {
		t.Fatalf("second call must be a no-op, got %q", got)
	}
	// And it refuses to take a machine another state dir already owns — one
	// that is present on disk. A marker naming a directory that is gone is
	// stale and is rewritten (covered in TestMarkerRewriteIsConditional).
	foreign := filepath.Join(t.TempDir(), "someone-else", "privatae-bastion")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(&machineMarker{StateDir: foreign}); err != nil {
		t.Fatal(err)
	}
	if got := maybeWriteMarker(); got != "another state dir owns this machine" {
		t.Fatalf("must not repoint a foreign marker, got %q", got)
	}
}

// The guard's POSITION in pairWithToken. Moving it below loadPairings passed
// the whole suite; nothing pinned the ordering through the real call path.
func TestPairWithTokenRefusesBeforeItTouchesAnything(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HOME", home)
	mine, err := configDirPath()
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(home, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil { // present on disk: a real other bastion
		t.Fatal(err)
	}
	writeMarkerNaming(t, filepath.Join(t.TempDir(), "machine.json"), elsewhere)

	// A deliberately invalid token: if the guard is late, decodeToken or the
	// redeem fails FIRST and the test would pass for the wrong reason. errors.Is
	// pins which refusal happened.
	_, _, err = pairWithToken("not-a-real-token", false, false)
	if !errors.Is(err, errForkedState) {
		t.Fatalf("pair must refuse with errForkedState before anything else, got %v", err)
	}
	if _, statErr := os.Stat(mine); !os.IsNotExist(statErr) {
		t.Fatalf("pairWithToken created %s before refusing", mine)
	}
}

// The branch selector. os.ModeCharDevice is TRUE for /dev/null, and every
// installed daemon has stdin on /dev/null, so the first draft took the fail-fast
// branch in the only deployment shape that exists and the blocking standby was
// unreachable.
func TestStdinIsTerminalIsFalseForDevNull(t *testing.T) {
	if !singletonSupported() {
		t.Skip("Linux-only in step 1")
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	realStdin := os.Stdin
	os.Stdin = devnull
	t.Cleanup(func() { os.Stdin = realStdin })

	if stdinIsTerminal() {
		t.Fatal("/dev/null must NOT read as a terminal — that is how the service " +
			"took the fail-fast branch and crash-looped instead of waiting")
	}
}

// The marker must never change the mode of a directory it did not create.
//
// The first draft chmod'd its parent to 0755 on every write. Measured on real
// installs: /etc/privatae — which holds secrets — is 0750 on most boxes, with
// a dedicated owning group on some. Loosening a hardened directory as a side effect of a bastion
// write is not something a marker gets to do, so the marker moved to a directory
// the bastion creates and owns, and this pins the second half of that fix.
func TestWriteMarkerNeverChmodsAnExistingDirectory(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	dir := filepath.Join(t.TempDir(), "hardened")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil { // defeat umask
		t.Fatal(err)
	}
	withMarkerAt(t, filepath.Join(dir, "machine.json"))
	if err := writeMarker(&machineMarker{StateDir: "/root/.config/privatae-bastion"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o750 {
		t.Fatalf("writeMarker changed an existing directory from 0750 to %v — on the fleet that directory holds secrets", fi.Mode().Perm())
	}
	// And when it DOES create the directory, it makes it traversable, or a
	// non-root pair cannot reach the marker and the refusal never fires.
	fresh := filepath.Join(t.TempDir(), "made-by-us")
	withMarkerAt(t, filepath.Join(fresh, "machine.json"))
	if err := writeMarker(&machineMarker{StateDir: "/root/.config/privatae-bastion"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(fresh); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("a directory the bastion creates must be 0755 traversable, got %v %v", fi.Mode().Perm(), err)
	}
}

// MkdirAll applies the process UMASK to every ANCESTOR it creates, and only
// the leaf was being fixed. /var/lib/privatae was absent on 19 of 20 boxes measured,
// so the first marker write creates it almost everywhere; under umask 027 or 077
// that parent lands 0750 or 0700, a non-root `pair` cannot traverse to the
// marker, and the guard would fail open on exactly the hardened boxes this
// location was chosen for.
func TestMarkerAncestorsAreTraversableUnderAnyUmask(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	for _, um := range []int{0o022, 0o027, 0o077} {
		root := t.TempDir()
		parent := filepath.Join(root, "privatae")
		dir := filepath.Join(parent, "bastion")
		withMarkerAt(t, filepath.Join(dir, "machine.json"))

		old := syscall.Umask(um)
		err := writeMarker(&machineMarker{StateDir: "/root/.config/privatae-bastion"})
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %#o: %v", um, err)
		}
		for _, d := range []string{parent, dir} {
			fi, err := os.Stat(d)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm()&0o001 == 0 {
				t.Fatalf("umask %#o: %s is %v — a non-root pair cannot traverse to the marker, so the guard fails OPEN",
					um, d, fi.Mode().Perm())
			}
		}
	}
}

// An UNREADABLE marker is not an ABSENT one. "Marker absent ⇒ today's
// behaviour" means ENOENT. EACCES from a locked-down ancestor means we cannot
// tell — and this directory is created only by the bastion, so something here
// owns the machine. The first draft allowed, which failed open on precisely the
// hardened boxes.
func TestUnreadableMarkerRefusesWhileCorruptOneAllows(t *testing.T) {
	if !singletonSupported() {
		t.Skip("singleton is Linux-only in step 1")
	}
	// Asserted on the MAPPING, not on a real unreadable file: root bypasses DAC,
	// so a chmod 0000 directory proves nothing inside this process. (The real
	// wiring was driven from a probe with the capability bounding set cleared —
	// readable-other-dir refuses, unreadable refuses, absent allows, corrupt
	// allows — which is the end-to-end witness this unit test cannot be.)
	if err := singletonGuardForPairFromReadError(os.ErrPermission); err == nil {
		t.Fatal("an unreadable marker must REFUSE — allowing is the fail-open the fleet measurement found")
	} else if !errors.Is(err, errForkedState) {
		t.Fatalf("the refusal must wrap errForkedState, got %v", err)
	} else if !strings.Contains(err.Error(), markerPath()) {
		t.Fatalf("the refusal must name the marker path, got %v", err)
	}
	// A truncated file is not a locked one: refusing every pairing on the machine
	// over one corrupt file would be a self-inflicted outage with no upside.
	if err := singletonGuardForPairFromReadError(errors.New("unexpected EOF")); err != nil {
		t.Fatalf("a corrupt marker must still allow: %v", err)
	}
}
