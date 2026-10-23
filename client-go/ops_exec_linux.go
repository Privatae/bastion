//go:build linux

package main

// ops_exec_linux.go — the executor: an op runs inside a throwaway sandbox and
// what it changed is read off the sandbox's upper layer.
// The person approves what they saw, so what
// lands must be what they saw — apply is the same run, committed.
//
// The sandbox is this binary re-exec'd as `privatae-bastion __op-sandbox
// <spec>` in new mount / pid / net / ipc / uts namespaces (a root daemon; the
// networked service is one). Inside, the child:
//
//	mounts an overlay whose lower is the real "/" and whose upper and work
//	  dirs sit on a tmpfs the parent mounted (opUpperMaxBytes), so a runaway
//	  op fills memory it was given, never the disk. An overlay does not look
//	  through the mounts inside its lower, so every other disk filesystem
//	  the machine has mounted (a /home or /srv on its own disk) gets an
//	  overlay of its own, on the same tmpfs, at the same place — the op sees
//	  the machine as it is, and each change is read off the layer it hit.
//	  An effect on a mount the sandbox cannot carry (a network share, a
//	  virtual filesystem) refuses the run before it starts;
//	masks /proc (a fresh one for the new pid namespace, with /proc/sys and
//	  the other machine-wide knobs read-only), /sys, /dev (null, zero,
//	  urandom, random only), /run, /tmp and /var/tmp with fresh tmpfs —
//	  scratch an op writes there is not a change to the machine and is not
//	  diffed;
//	bind-mounts the op directory read-only at opSandboxMount;
//	pivots into the overlay, sets rlimits, drops every capability that could
//	  reach past the filesystem (modules, clock, raw I/O, device nodes, ...),
//	  forbids new privileges, drops to the session user for privilege user,
//	  and runs `<interpreter> /opt/bastion-op/run --mode <m>` with the
//	  params on stdin, a scrubbed environment and no network.
//
// The parent kills the child at the time limit (pid 1 of the namespace, so
// everything under it goes), caps the output, then walks the upper dirs:
// created / modified (with a text diff) / removed (a whiteout), and refuses
// anything that is not a plain file or directory change — a symlink, a
// hardlink, an opaque directory (a replaced tree), a special file. Every
// change must sit inside the op's declared effects (ops.go
// opEffectsViolation); a run that touched anything else is refused before
// anyone is asked to approve it.
//
// Commit (apply) is the upper dir landed on the real filesystem, file by
// file, in the order created directories, files, removals.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const opSandboxSubcommand = "__op-sandbox"

// opSandboxSpec is what the parent hands the child, as a JSON file on the
// run's tmpfs (the child reads nothing else).
type opSandboxSpec struct {
	OpDir       string `json:"op_dir"`
	Interpreter string `json:"interpreter"` // the resolved program
	Mode        string `json:"mode"`
	Root        string `json:"root"` // <run>/root, the overlay's mount point
	Upper       string `json:"upper"`
	Work        string `json:"work"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	AsUser      bool   `json:"as_user"`
	TimeLimit   int    `json:"time_limit"`
	// Mounts: the other disk filesystems, each with its own upper/work.
	Mounts []opSandboxMountSpec `json:"mounts"`
	// Masks: this machine's own record (ops.go opOffLimits), each covered
	// inside the sandbox with an empty read-only tmpfs.
	Masks []string `json:"masks"`
	// Visible: everything the op may see (ops_view.go opViewVisible). The
	// rest is covered with EmptyDir or EmptyFile, both read-only.
	Visible   []string `json:"visible"`
	EmptyDir  string   `json:"empty_dir"`
	EmptyFile string   `json:"empty_file"`
}

type opSandboxMountSpec struct {
	Host  string `json:"host"` // the mount point on the machine
	Upper string `json:"upper"`
	Work  string `json:"work"`
}

// opCarriedFSTypes are the filesystems an overlay can sit on and that hold
// the machine's own files. Anything else mounted (proc, sysfs, tmpfs,
// cgroups, a network share, a fuse, and the case-insensitive ones — vfat
// on an EFI partition — which overlay refuses as a lower) is not carried
// into the sandbox: the virtual ones are masked, and an effect on the rest
// refuses the run.
var opCarriedFSTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "f2fs": true,
	"zfs": true, "jfs": true,
}

// opMaskedDirs are masked with fresh tmpfs inside the sandbox; a mount
// under one of them is never carried.
var opMaskedDirs = []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"}

type opHostMount struct {
	Point  string
	FSType string
}

// opHostMounts reads the machine's mount table (the visible mount at each
// point — the last listed wins), sorted by path.
func opHostMounts() ([]opHostMount, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	byPoint := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 5 || sep+1 >= len(f) {
			continue
		}
		point := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\").Replace(f[4])
		byPoint[point] = f[sep+1]
	}
	out := make([]opHostMount, 0, len(byPoint))
	for p, t := range byPoint {
		out = append(out, opHostMount{Point: p, FSType: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Point < out[j].Point })
	return out, nil
}

// opMountsUnder lists the machine's mount points strictly below a path.
func opMountsUnder(p string) []string {
	mounts, err := opHostMounts()
	if err != nil {
		return []string{"(unreadable mount table)"}
	}
	clean := filepath.Clean(p)
	var out []string
	for _, m := range mounts {
		if m.Point != "/" && strings.HasPrefix(m.Point, clean+"/") {
			out = append(out, m.Point)
		}
	}
	return out
}

func underAny(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// opMountOf names the mount a path lives on: the longest mount point that
// prefixes it.
func opMountOf(mounts []opHostMount, p string) opHostMount {
	best := opHostMount{Point: "/", FSType: ""}
	for _, m := range mounts {
		if (p == m.Point || strings.HasPrefix(p, strings.TrimSuffix(m.Point, "/")+"/")) && len(m.Point) >= len(best.Point) {
			best = m
		}
	}
	return best
}

// opEffectPrefix is the fixed part of an effect: the path up to its first
// glob character, so the mount it lives on can be named.
func opEffectPrefix(e string) string {
	if i := strings.IndexAny(e, "*?["); i >= 0 {
		return filepath.Dir(e[:i])
	}
	return filepath.Clean(strings.TrimSuffix(e, "/"))
}

type opChange struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"` // created | modified | removed | created_dir | removed_dir | symlink | hardlink | opaque | special
	Size   int64  `json:"size,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Digest string `json:"sha256,omitempty"`
	Diff   string `json:"diff,omitempty"` // text files ≤ opDiffMaxBytes: a line diff
	Note   string `json:"note,omitempty"`

	src string // where the change sits in the upper layer, for the commit
	// from: a verb line's raw starting state (a commit, an image), kept for
	// a plan line's undo (ops_plan_linux.go).
	from string
}

type opReport struct {
	Mode     string     `json:"mode"`
	Exit     int        `json:"exit"`
	TimedOut bool       `json:"timed_out,omitempty"`
	Seconds  float64    `json:"seconds"`
	Output   string     `json:"output"` // stdout+stderr, capped
	Changes  []opChange `json:"changes"`
	// ChangesSHA256 names the change list: sha256 over "kind\x00path\x00mode\x00sha256\n"
	// per change, in path order. An op_run apply is bound to it (ops.go opTerms.Changes).
	ChangesSHA256 string   `json:"changes_sha256"`
	Committed     []string `json:"committed,omitempty"`
	// An action op's apply (ops_verbs_linux.go): each verb as it ran, each
	// check after it, and the receipts for what its program pushed.
	Verbs       []opVerbResult    `json:"verbs,omitempty"`
	Checks      []opVerbResult    `json:"checks,omitempty"`
	Receipts    []opSignedReceipt `json:"receipts,omitempty"`
	VerifyError string            `json:"verify_error,omitempty"`

	run     string // the run's tmpfs (the uppers live on it) until cleanup()
	cleanup func()
}

func opChangesDigest(changes []opChange) string {
	h := sha256.New()
	for _, c := range changes {
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\n", c.Kind, c.Path, c.Mode, c.Digest)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ── availability ────────────────────────────────────────────────────────────

var (
	opSandboxOnce   sync.Once
	opSandboxOK     bool
	opSandboxReason string
)

// opSandboxAvailable: root, overlay in the kernel, and a namespace this
// process may create. Probed once; the beat reports it.
func opSandboxAvailable() (bool, string) {
	opSandboxOnce.Do(func() {
		if !processIsRoot() {
			opSandboxReason = "the bastion is not root (a networked, anchored machine runs it as root)"
			return
		}
		raw, err := os.ReadFile("/proc/filesystems")
		if err != nil || !strings.Contains(string(raw), "\toverlay\n") {
			opSandboxReason = "the kernel offers no overlay filesystem"
			return
		}
		self, err := os.Executable()
		if err != nil {
			opSandboxReason = "cannot find this binary to re-exec: " + err.Error()
			return
		}
		cmd := exec.Command(self, opSandboxSubcommand, "--probe")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS}
		if out, err := cmd.CombinedOutput(); err != nil {
			opSandboxReason = "cannot create the sandbox namespaces: " + strings.TrimSpace(string(out)) + " " + err.Error()
			return
		}
		opSandboxOK = true
	})
	return opSandboxOK, opSandboxReason
}

// ── the parent side ─────────────────────────────────────────────────────────

func opRunsRoot() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "op-sandbox")
	return p, os.MkdirAll(p, 0o700)
}

// opRunSandboxed runs one mode of the op and reads what it changed. The
// report keeps the run's tmpfs mounted (for a commit) until cleanup() is
// called; callers always call it.
func opRunSandboxed(opDir string, m *opManifest, mode, params string) (*opReport, error) {
	mounts, err := opHostMounts()
	if err != nil {
		return nil, fmt.Errorf("cannot read the machine's mounts: %v", err)
	}
	var carried []opHostMount
	for _, mt := range mounts {
		if mt.Point == "/" || !opCarriedFSTypes[mt.FSType] || underAny(mt.Point, opMaskedDirs) {
			continue
		}
		carried = append(carried, mt)
	}
	// Every effect must live on "/" or a carried mount: an effect on a
	// network share or a virtual filesystem is one the sandbox cannot show
	// truthfully, so the run refuses instead of running blind.
	// Each declared path resolved ONCE: that is what is judged here (mounts,
	// credential stores) and what the sandbox is handed, so a link that moves
	// between this check and the view cannot slip past it.
	var declared []string
	for _, d := range append(append([]string{}, m.Effects.Files...), m.Reads...) {
		forms := opDeclaredForms(d)
		if err := opUncarriedDeclared(mounts, d, forms); err != nil {
			return nil, err
		}
		// A declared path may have come to resolve onto a credential store
		// since the op was accepted (a link moved): judged again, every run.
		if sens, err := opSensitiveMatchForms(forms); err != nil {
			return nil, err
		} else if sens != "" {
			return nil, opSensitiveRefusal(d, sens)
		}
		declared = append(declared, forms...)
	}
	offs, err := opMaskSet()
	if err != nil {
		return nil, err
	}
	root, err := opRunsRoot()
	if err != nil {
		return nil, err
	}
	run, err := os.MkdirTemp(root, "run-")
	if err != nil {
		return nil, err
	}
	rep := &opReport{Mode: mode, Changes: []opChange{}}
	mounted := false
	rep.cleanup = func() {
		if mounted {
			_ = unix.Unmount(run, unix.MNT_DETACH)
		}
		_ = os.RemoveAll(run)
	}
	if err := unix.Mount("tmpfs", run, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV,
		fmt.Sprintf("size=%d,mode=0700", opUpperMaxBytes)); err != nil {
		rep.cleanup()
		return nil, fmt.Errorf("cannot mount the run's tmpfs: %v", err)
	}
	mounted = true
	spec := opSandboxSpec{OpDir: opDir, Interpreter: opInterpreters[m.Interpreter], Mode: mode,
		Root: filepath.Join(run, "root"), Upper: filepath.Join(run, "upper"), Work: filepath.Join(run, "work"),
		TimeLimit: m.TimeLimit, Masks: offs, Visible: opViewVisible(declared),
		EmptyDir: filepath.Join(run, "empty-dir"), EmptyFile: filepath.Join(run, "empty-file")}
	dirs := []string{spec.Root, spec.Upper, spec.Work}
	for i, mt := range carried {
		ms := opSandboxMountSpec{Host: mt.Point,
			Upper: filepath.Join(run, fmt.Sprintf("mnt%d-upper", i)), Work: filepath.Join(run, fmt.Sprintf("mnt%d-work", i))}
		spec.Mounts = append(spec.Mounts, ms)
		dirs = append(dirs, ms.Upper, ms.Work)
	}
	for _, d := range dirs {
		if err := os.Mkdir(d, 0o700); err != nil {
			rep.cleanup()
			return nil, err
		}
	}
	// What a covered path shows: an empty folder, an empty file.
	if err := os.Mkdir(spec.EmptyDir, 0o555); err != nil {
		rep.cleanup()
		return nil, err
	}
	if err := os.WriteFile(spec.EmptyFile, nil, 0o444); err != nil {
		rep.cleanup()
		return nil, err
	}
	// An overlay's root takes its attributes from the UPPER dir, so each
	// upper must look like the directory it overlays or a user-privilege op
	// could not even traverse "/".
	if err := opMatchDir(spec.Upper, "/"); err != nil {
		rep.cleanup()
		return nil, err
	}
	for _, ms := range spec.Mounts {
		if err := opMatchDir(ms.Upper, ms.Host); err != nil {
			rep.cleanup()
			return nil, err
		}
	}
	if m.Privilege == "user" {
		uid, gid, err := opUnprivilegedIdentity()
		if err != nil {
			rep.cleanup()
			return nil, err
		}
		spec.UID, spec.GID, spec.AsUser = uid, gid, true
		// The upper must be writable by that user where the op may write:
		// overlay copies up on write with the lower's ownership, so a user-
		// privilege op can only change files that user could change anyway.
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(run, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0o600); err != nil {
		rep.cleanup()
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		rep.cleanup()
		return nil, err
	}
	// The sandbox lives at most time_limit seconds, setup included: the
	// child is pid 1 of its namespace, so killing it takes everything under
	// it. (RLIMIT_CPU inside is the CPU-time cap beside this wall-clock one.)
	limit := time.Duration(m.TimeLimit) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, opSandboxSubcommand, specPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Setpgid:    true,
	}
	cmd.Stdin = strings.NewReader(params)
	out := &cappedBuffer{max: opOutputMaxBytes}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.WaitDelay = 2 * time.Second // the pipes close when the namespace is gone; never wait past that
	start := time.Now()
	runErr := cmd.Run()
	rep.Seconds = time.Since(start).Seconds()
	rep.Output = out.String()
	if ctx.Err() == context.DeadlineExceeded {
		rep.TimedOut = true
		rep.Exit = 124
		return rep, fmt.Errorf("the op did not finish inside its time limit (%ds)", m.TimeLimit)
	}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			rep.Exit = ee.ExitCode()
		} else {
			return rep, fmt.Errorf("the sandbox could not start: %v", runErr)
		}
	}
	rep.run = run
	changes, err := opUpperChanges(spec.Upper, "/")
	if err != nil {
		return rep, fmt.Errorf("could not read what the run changed: %v", err)
	}
	for _, ms := range spec.Mounts {
		more, err := opUpperChanges(ms.Upper, ms.Host)
		if err != nil {
			return rep, fmt.Errorf("could not read what the run changed under %s: %v", ms.Host, err)
		}
		changes = append(changes, more...)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	rep.Changes = changes
	rep.ChangesSHA256 = opChangesDigest(changes)
	if rep.Exit == 125 || rep.Exit == 126 {
		// The child's own failure (setup, spec, starting the interpreter),
		// never the op's: say what it said.
		lines := strings.Split(strings.TrimSpace(rep.Output), "\n")
		return rep, fmt.Errorf("the sandbox could not run the op: %s", lines[len(lines)-1])
	}
	if rep.Exit != 0 && mode != opModeVerify {
		lines := strings.Split(strings.TrimSpace(rep.Output), "\n")
		return rep, fmt.Errorf("the op exited %d in %s mode: %s", rep.Exit, mode, lines[len(lines)-1])
	}
	return rep, nil
}

// opUncarriedDeclared refuses a declared path (an effect or a read), as
// written or as it resolves, on a mount the sandbox does not carry (a network
// share, a virtual filesystem): an effect there cannot be shown truthfully,
// and a read there would show an empty folder and a dry run that looks right.
// Refused before the run, never run blind.
func opUncarriedDeclared(mounts []opHostMount, declared string, forms []string) error {
	for _, f := range forms {
		mt := opMountOf(mounts, opEffectPrefix(f))
		if mt.Point != "/" && !opCarriedFSTypes[mt.FSType] {
			return fmt.Errorf("%s is on a %s mount at %s, which the sandbox does not carry", declared, mt.FSType, mt.Point)
		}
	}
	return nil
}

// opMatchDir gives dir the mode and owner of like.
func opMatchDir(dir, like string) error {
	st, err := os.Stat(like)
	if err != nil {
		return err
	}
	if err := os.Chmod(dir, st.Mode().Perm()); err != nil {
		return err
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return os.Lchown(dir, int(s.Uid), int(s.Gid))
	}
	return nil
}

// opUnprivilegedIdentityHook, when set, is the identity a user-privilege op
// runs as. Only tests set it.
var opUnprivilegedIdentityHook func() (uint32, uint32, error)

// opUnprivilegedIdentity is the session lane's user (session_unix.go): the
// dedicated account if it exists, else nobody.
func opUnprivilegedIdentity() (uint32, uint32, error) {
	if opUnprivilegedIdentityHook != nil {
		return opUnprivilegedIdentityHook()
	}
	var u *user.User
	var err error
	for _, name := range sessionUnprivUsers {
		if u, err = user.Lookup(name); err == nil {
			break
		}
	}
	if err != nil {
		if u, err = user.Lookup("nobody"); err != nil {
			return 0, 0, fmt.Errorf("no unprivileged account to run the op as (create a '%s' system user)", sessionUnprivUsers[0])
		}
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("account %s has a non-numeric uid/gid", u.Username)
	}
	return uint32(uid), uint32(gid), nil
}

type cappedBuffer struct {
	buf bytes.Buffer
	max int
	cut bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.max - c.buf.Len()
	if room <= 0 {
		c.cut = true
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.cut = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) String() string {
	if c.cut {
		return c.buf.String() + "\n…[output capped]"
	}
	return c.buf.String()
}

// ── reading the upper layer ─────────────────────────────────────────────────

// opUpperChanges walks one overlay's upper dir and names every change as the
// real path it would land on: hostRoot is the path the overlay sits at on
// the machine ("/" for the root overlay, the mount point for the others),
// and the walker compares against what is there now. Tests pass a fixture
// root.
func opUpperChanges(upper, hostRoot string) ([]opChange, error) {
	var out []opChange
	err := filepath.Walk(upper, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if p == upper {
			return nil
		}
		rel, _ := filepath.Rel(upper, p)
		real := filepath.ToSlash(filepath.Join(hostRoot, rel))
		if real == opSandboxMount {
			// The op's own read-only mount point, created inside the overlay.
			return filepath.SkipDir
		}
		lower := real
		lowerInfo, lowerErr := os.Lstat(lower)
		mode := info.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			out = append(out, opChange{Path: real, Kind: "symlink", src: p})
			return nil
		case mode&os.ModeCharDevice != 0:
			// A whiteout: character device 0/0 marks a lower entry removed.
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Rdev == 0 {
				if lowerErr == nil && lowerInfo.IsDir() {
					// The card says how much a removed folder holds: the
					// whiteout covers the folder and everything under it.
					n, capped := opCountEntries(lower)
					note := fmt.Sprintf("a folder with %d entries under it", n)
					if capped {
						note = fmt.Sprintf("a folder with more than %d entries under it", n)
					}
					out = append(out, opChange{Path: real, Kind: "removed_dir", src: p, Note: note})
				} else {
					out = append(out, opChange{Path: real, Kind: "removed", src: p})
				}
				return nil
			}
			out = append(out, opChange{Path: real, Kind: "special"})
			return nil
		case mode.IsDir():
			if opaque, _ := opXattrOpaque(p); opaque {
				out = append(out, opChange{Path: real, Kind: "opaque"})
				return filepath.SkipDir
			}
			if lowerErr != nil {
				out = append(out, opChange{Path: real, Kind: "created_dir", Mode: fmt.Sprintf("%04o", mode.Perm()), src: p})
			}
			return nil
		case mode.IsRegular():
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
				out = append(out, opChange{Path: real, Kind: "hardlink"})
				return nil
			}
			c := opChange{Path: real, Size: info.Size(), Mode: fmt.Sprintf("%04o", mode.Perm()), src: p}
			after, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(after)
			c.Digest = hex.EncodeToString(sum[:])
			if lowerErr != nil {
				c.Kind = "created"
				if isText(after) && len(after) <= opDiffMaxBytes {
					c.Diff = opLineDiff(nil, after)
				}
			} else {
				c.Kind = "modified"
				before, _ := os.ReadFile(lower)
				if bytes.Equal(before, after) && lowerInfo.Mode().Perm() == mode.Perm() {
					return nil // copied up and written back unchanged: not a change
				}
				if isText(before) && isText(after) && len(before)+len(after) <= 2*opDiffMaxBytes {
					c.Diff = opLineDiff(before, after)
				} else {
					c.Note = fmt.Sprintf("binary or large: %d → %d bytes", len(before), len(after))
				}
			}
			out = append(out, c)
			return nil
		default:
			out = append(out, opChange{Path: real, Kind: "special"})
			return nil
		}
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// opCountEntries counts what a folder holds, stopping at opCountMax so a
// huge tree does not stall the report.
const opCountMax = 10000

func opCountEntries(dir string) (int, bool) {
	n := 0
	stop := errors.New("enough")
	err := filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err != nil || p == dir {
			return nil
		}
		n++
		if n >= opCountMax {
			return stop
		}
		return nil
	})
	return n, err == stop
}

func opXattrOpaque(dir string) (bool, error) {
	buf := make([]byte, 8)
	n, err := unix.Getxattr(dir, "trusted.overlay.opaque", buf)
	if err != nil {
		return false, nil // no xattr, or not supported: not opaque
	}
	return n > 0 && buf[0] == 'y', nil
}

func isText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if !utf8.Valid(b) {
		return false
	}
	return !bytes.ContainsRune(b, 0)
}

// opLineDiff is a plain line diff (LCS), bounded: the card shows what changed
// in a text file the person is being asked about, not a patch tool's output.
func opLineDiff(before, after []byte) string {
	a := strings.Split(strings.TrimSuffix(string(before), "\n"), "\n")
	b := strings.Split(strings.TrimSuffix(string(after), "\n"), "\n")
	if len(before) == 0 {
		a = nil
	}
	if len(after) == 0 {
		b = nil
	}
	const maxLines = 2000
	if len(a) > maxLines || len(b) > maxLines {
		return fmt.Sprintf("(%d → %d lines; too long to show line by line)", len(a), len(b))
	}
	// LCS table.
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var sb strings.Builder
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			sb.WriteString("- " + a[i] + "\n")
			i++
		default:
			sb.WriteString("+ " + b[j] + "\n")
			j++
		}
		if sb.Len() > opDiffMaxBytes {
			sb.WriteString("…[diff capped]\n")
			return sb.String()
		}
	}
	for ; i < n; i++ {
		sb.WriteString("- " + a[i] + "\n")
	}
	for ; j < m; j++ {
		sb.WriteString("+ " + b[j] + "\n")
	}
	return sb.String()
}

// ── commit ──────────────────────────────────────────────────────────────────

// opCommitUpper lands the run's upper dir on the real filesystem: created
// directories first, then files (written beside and renamed in), then
// removals (files, then folders deepest first) — each path re-checked to be
// a plain file/dir at the moment it lands. Returns the paths landed, in
// order, so a failure part-way is named.
func opCommitUpper(rep *opReport) ([]string, error) {
	if rep == nil || rep.run == "" {
		return nil, errors.New("nothing to commit")
	}
	var done []string
	kinds := map[string]int{"created_dir": 0, "created": 1, "modified": 1, "removed": 2, "removed_dir": 3}
	changes := append([]opChange(nil), rep.Changes...)
	sort.SliceStable(changes, func(i, j int) bool {
		if kinds[changes[i].Kind] != kinds[changes[j].Kind] {
			return kinds[changes[i].Kind] < kinds[changes[j].Kind]
		}
		if changes[i].Kind == "removed" || changes[i].Kind == "removed_dir" {
			return changes[i].Path > changes[j].Path // deepest first
		}
		return changes[i].Path < changes[j].Path
	})
	for _, c := range changes {
		src := c.src
		if src == "" {
			return done, fmt.Errorf("%s: no layer to commit it from", c.Path)
		}
		switch c.Kind {
		case "created_dir":
			perm, _ := strconv.ParseUint(c.Mode, 8, 32)
			if err := os.MkdirAll(c.Path, os.FileMode(perm)); err != nil {
				return done, err
			}
			if st, err := os.Stat(src); err == nil {
				if s, ok := st.Sys().(*syscall.Stat_t); ok {
					_ = os.Lchown(c.Path, int(s.Uid), int(s.Gid))
				}
			}
		case "created", "modified":
			raw, err := os.ReadFile(src)
			if err != nil {
				return done, err
			}
			perm, _ := strconv.ParseUint(c.Mode, 8, 32)
			if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
				return done, err
			}
			tmp := c.Path + ".privatae-op-tmp"
			if err := os.WriteFile(tmp, raw, os.FileMode(perm)); err != nil {
				return done, err
			}
			_ = os.Chmod(tmp, os.FileMode(perm))
			if st, err := os.Stat(src); err == nil {
				if s, ok := st.Sys().(*syscall.Stat_t); ok {
					_ = os.Lchown(tmp, int(s.Uid), int(s.Gid))
				}
			}
			if err := os.Rename(tmp, c.Path); err != nil {
				_ = os.Remove(tmp)
				return done, err
			}
		case "removed":
			if st, err := os.Lstat(c.Path); err == nil && !st.Mode().IsRegular() {
				return done, fmt.Errorf("%s is not a plain file any more; not removed", c.Path)
			}
			if err := os.Remove(c.Path); err != nil && !os.IsNotExist(err) {
				return done, err
			}
		case "removed_dir":
			// The whiteout covers the folder and everything under it — what
			// the card said. A folder that became a link since is not followed,
			// and one that holds a mount now is not entered.
			if st, err := os.Lstat(c.Path); err == nil && !st.IsDir() {
				return done, fmt.Errorf("%s is not a folder any more; not removed", c.Path)
			}
			if under := opMountsUnder(c.Path); len(under) > 0 {
				return done, fmt.Errorf("%s holds a mount at %s now; not removed", c.Path, under[0])
			}
			if err := os.RemoveAll(c.Path); err != nil {
				return done, err
			}
		default:
			return done, fmt.Errorf("a %s at %s cannot be committed", c.Kind, c.Path)
		}
		done = append(done, c.Kind+" "+c.Path)
	}
	return done, nil
}

// ── the child: pid 1 of the sandbox ─────────────────────────────────────────

// opSandboxChildMain is `privatae-bastion __op-sandbox <spec>`: set the
// sandbox up, run the op's interpreter as a grandchild, return its exit.
// `--probe` only proves the namespaces came up.
func opSandboxChildMain(arg string) int {
	if arg == "--probe" {
		return 0
	}
	raw, err := os.ReadFile(arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: no spec:", err)
		return 125
	}
	var spec opSandboxSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: bad spec:", err)
		return 125
	}
	if err := opSandboxSetup(&spec); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		return 125
	}
	// Rlimits are inherited by the grandchild: no fork bombs, no giant files,
	// a CPU cap beside the wall-clock one the parent enforces.
	_ = unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{Cur: 64, Max: 64})
	_ = unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: opUpperMaxBytes, Max: opUpperMaxBytes})
	_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 256, Max: 256})
	_ = unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: uint64(spec.TimeLimit), Max: uint64(spec.TimeLimit)})
	// The filesystem is the whole reach of an op. Every capability that
	// reaches past it leaves the bounding set here, so the interpreter — and
	// anything it runs — never holds it, root or not: no modules, no clock,
	// no raw I/O, no device nodes, no mounts, no reboot. No new privileges
	// means a setuid binary in the lower cannot hand any back.
	opDropCaps()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: no_new_privs:", err)
		return 125
	}
	newCmd := func(ownUserNS bool) *exec.Cmd {
		cmd := exec.Command(spec.Interpreter, opSandboxMount+"/run", "--mode", spec.Mode)
		cmd.Dir = "/"
		cmd.Env = []string{
			"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=/tmp",
			"TMPDIR=/tmp",
			"LANG=C.UTF-8",
			"PRIVATAE_OP_MODE=" + spec.Mode,
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if !spec.AsUser {
			cmd.Env = append(cmd.Env, "USER=root")
			return cmd
		}
		cmd.Env = append(cmd.Env, "USER=privatae-op")
		attr := &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: spec.UID, Gid: spec.GID, NoSetGroups: true}}
		if ownUserNS {
			// RLIMIT_NPROC counts every task of a user in its user namespace,
			// so in the machine's own one the cap above would count whatever
			// else runs as this user (nobody is shared with system daemons)
			// and refuse the op on a busy machine. In a user namespace of its
			// own the count is the op's tasks alone. The map is the identity:
			// the op is the same user and sees every file's real owner.
			attr.Cloneflags = syscall.CLONE_NEWUSER
			attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1<<31 - 1}}
			attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1<<31 - 1}}
		}
		cmd.SysProcAttr = attr
		return cmd
	}
	cmd := newCmd(true)
	err = cmd.Run()
	if spec.AsUser && err != nil && cmd.Process == nil {
		// No user namespace here (not built in, or turned off): run the op
		// as before, with the cap counting the user's other tasks too.
		cmd = newCmd(false)
		err = cmd.Run()
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "sandbox: cannot run the op:", err)
		return 126
	}
	return 0
}

// opKeptCaps is what a file-effects op may keep: owning, reading and
// writing files as root does. Everything else is dropped from the bounding
// set, which is what a root exec's permitted set is computed from.
var opKeptCaps = map[int]bool{
	unix.CAP_CHOWN: true, unix.CAP_DAC_OVERRIDE: true, unix.CAP_DAC_READ_SEARCH: true,
	unix.CAP_FOWNER: true, unix.CAP_FSETID: true, unix.CAP_KILL: true,
	unix.CAP_SETGID: true, unix.CAP_SETUID: true,
}

func opDropCaps() {
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		if opKeptCaps[c] {
			continue
		}
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0) // EINVAL past the kernel's last cap
	}
}

// opSandboxSetup builds the filesystem the op sees and pivots into it.
func opSandboxSetup(spec *opSandboxSpec) error {
	// Nothing done here may leak to the real mount table.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %v", err)
	}
	// nodev on every overlay: a device node the op makes or finds in a layer
	// opens nothing; nosuid: a setuid file in the lower grants nothing.
	const ovFlags = unix.MS_NODEV | unix.MS_NOSUID
	opts := "lowerdir=/,upperdir=" + spec.Upper + ",workdir=" + spec.Work
	if err := unix.Mount("overlay", spec.Root, "overlay", ovFlags, opts); err != nil {
		return fmt.Errorf("overlay: %v", err)
	}
	r := spec.Root
	// The machine's other disks, each its own overlay at the same place.
	// (The list is sorted by path, so a mount inside another comes after it.)
	for _, ms := range spec.Mounts {
		target := filepath.Join(r, ms.Host)
		if st, err := os.Stat(target); err != nil || !st.IsDir() {
			return fmt.Errorf("mount point %s is not a directory in the sandbox", ms.Host)
		}
		o := "lowerdir=" + ms.Host + ",upperdir=" + ms.Upper + ",workdir=" + ms.Work
		if err := unix.Mount("overlay", target, "overlay", ovFlags, o); err != nil {
			return fmt.Errorf("overlay for %s: %v", ms.Host, err)
		}
	}
	if err := opSandboxCommon(r, []string{"sys", "run", "tmp", "var/tmp"}, spec.Visible, spec.EmptyDir, spec.EmptyFile, spec.Masks); err != nil {
		return err
	}
	// The op itself, read-only, at a fixed place. (The mount point is created
	// inside the overlay and lands in the upper; the diff walker skips it.)
	mnt := filepath.Join(r, strings.TrimPrefix(opSandboxMount, "/"))
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return err
	}
	if err := unix.Mount(spec.OpDir, mnt, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("op mount: %v", err)
	}
	if err := unix.Mount("", mnt, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("op mount read-only: %v", err)
	}
	// Pivot: new root and old root the same directory, then detach the old.
	if err := os.Chdir(r); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %v", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %v", err)
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	_ = unix.Sethostname([]byte("op-sandbox"))
	return nil
}

// opSandboxCommon is what every op sandbox gets under its root r, whatever
// the root is (a files op's overlay, an action op's read-only machine): a
// fresh /proc with the kernel's knobs read-only, a fresh tmpfs on each of
// tmpDirs, a /dev of four devices, the closed view, and this machine's own
// record masked.
func opSandboxCommon(r string, tmpDirs, visible []string, emptyDir, emptyFile string, masks []string) error {
	// The masks: fresh, empty, never part of the diff.
	proc := filepath.Join(r, "proc")
	if err := unix.Mount("proc", proc, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("proc: %v", err)
	}
	// A fresh proc is still the machine's: /proc/sys and the other knobs
	// that reach the kernel are read-only, the ones that read it out are
	// hidden (the same set a container runtime masks).
	for _, sub := range []string{"sys", "sysrq-trigger", "irq", "bus", "fs"} {
		t := filepath.Join(proc, sub)
		if _, err := os.Lstat(t); err != nil {
			continue
		}
		if err := unix.Mount(t, t, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("proc/%s bind: %v", sub, err)
		}
		if err := unix.Mount("", t, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
			return fmt.Errorf("proc/%s read-only: %v", sub, err)
		}
	}
	for _, sub := range []string{"kcore", "keys", "timer_list", "sched_debug", "latency_stats", "timer_stats"} {
		t := filepath.Join(proc, sub)
		if _, err := os.Lstat(t); err != nil {
			continue
		}
		if err := unix.Mount("/dev/null", t, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("proc/%s mask: %v", sub, err)
		}
	}
	for _, d := range tmpDirs {
		target := filepath.Join(r, d)
		if err := os.MkdirAll(target, 0o1777); err != nil {
			return err
		}
		if err := unix.Mount("tmpfs", target, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=64m,mode=1777"); err != nil {
			return fmt.Errorf("%s: %v", d, err)
		}
	}
	dev := filepath.Join(r, "dev")
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID, "size=1m,mode=0755"); err != nil {
		return fmt.Errorf("dev: %v", err)
	}
	for _, n := range []struct {
		name string
		maj  uint32
		min  uint32
	}{{"null", 1, 3}, {"zero", 1, 5}, {"urandom", 1, 9}, {"random", 1, 8}} {
		if err := unix.Mknod(filepath.Join(dev, n.name), unix.S_IFCHR|0o666, int(unix.Mkdev(n.maj, n.min))); err != nil {
			return fmt.Errorf("dev/%s: %v", n.name, err)
		}
		// mknod takes the umask off the mode; a user-privilege op must be
		// able to write /dev/null like anyone.
		if err := os.Chmod(filepath.Join(dev, n.name), 0o666); err != nil {
			return fmt.Errorf("dev/%s: %v", n.name, err)
		}
	}
	// The closed view (ops_view.go): everything the op did not declare and
	// the base does not hold is covered. A cover that cannot be put in place
	// fails the setup, and the run with it.
	if err := opCloseView(r, visible, emptyDir, emptyFile); err != nil {
		return err
	}
	// This machine's own record: an empty read-only tmpfs over each folder
	// and an empty read-only file over each file, so an op can neither read
	// the keys nor write or remove the record — a mount point cannot be
	// removed, and a path that resolves here lands on the mask. A place that
	// does not exist here (or that the closed view already covered, so it is
	// not there to see) needs none; one that cannot be covered fails the run.
	for _, off := range masks {
		target := filepath.Join(r, off)
		st, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("mask %s: %v", off, err)
		}
		switch {
		case st.Mode()&os.ModeSymlink != 0:
			continue // listed again as it resolves (ops.go opOffLimits)
		case st.IsDir():
			if err := unix.Mount("tmpfs", target, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4k,mode=0700"); err != nil {
				return fmt.Errorf("mask %s: %v", off, err)
			}
			if err := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
				return fmt.Errorf("mask %s read-only: %v", off, err)
			}
		default:
			if err := opBindReadOnly(emptyFile, target); err != nil {
				return fmt.Errorf("mask %s: %v", off, err)
			}
		}
	}
	return nil
}

// opCloseView covers, under the sandbox root r, every path the visible list
// does not reach: a folder with an empty read-only folder, anything else with
// an empty read-only file. It walks only the folders on the way to a visible
// path, so its cost is the width of those folders, not the machine. A link is
// left as it is: where it points is judged where it lands.
func opCloseView(r string, visible []string, emptyDir, emptyFile string) error {
	segs := opViewSegments(visible)
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := os.ReadDir(filepath.Join(r, dir))
		if err != nil {
			return fmt.Errorf("closed view: %s: %v", dir, err)
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			target := filepath.Join(r, p)
			act := opViewDecide(p, segs)
			if act == opViewKeep {
				continue
			}
			st, err := os.Lstat(target)
			if err != nil {
				return fmt.Errorf("closed view: %s: %v", p, err)
			}
			if st.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if act == opViewDescend && st.IsDir() {
				if err := walk(p); err != nil {
					return err
				}
				continue
			}
			// Hidden, or a file where a visible path would need a folder.
			src := emptyFile
			if st.IsDir() {
				src = emptyDir
			}
			if err := opBindReadOnly(src, target); err != nil {
				return fmt.Errorf("closed view: cover %s: %v", p, err)
			}
		}
		return nil
	}
	return walk("/")
}

// opBindReadOnly mounts src over target, read-only, with nothing executable
// or special through it.
func opBindReadOnly(src, target string) error {
	if err := unix.Mount(src, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

var _ = io.EOF
