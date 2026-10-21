//go:build linux

package main

// ops_action_linux.go — an action op's program, run unprivileged (ops_action.go).
//
// The bastion starts it as a systemd transient unit, because the address
// allowlist is systemd's (IPAddressDeny=any plus, in an apply, IPAddressAllow=
// the addresses the op's destinations resolved to at run start, enforced by
// the kernel on the unit's cgroup; a dry run gets no address at all). The unit runs this binary as
// `__op-action <spec>`, which re-execs itself as `__op-action-child <spec>` in
// new mount, pid, ipc and uts namespaces. That child, pid 1 of its namespace:
//
//	binds the machine's "/" read-only (every mount under it too) at the run's
//	  root, then builds the same view a files op gets (opSandboxCommon): a
//	  fresh /proc, /sys, /run and /var/tmp, four devices, the closed view, the
//	  machine's record masked. /tmp is the run's work folder in apply, owned
//	  by the run's uid, and a fresh tmpfs in a dry run; /etc/hosts names only
//	  the destinations; the op's directory is at /run/bastion-op, read-only;
//	  the builder's socket is at /run/privatae-builder/ in apply when the op
//	  declares it;
//	pivots, drops every capability from the bounding set, sets no-new-privs,
//	  and restricts itself with Landlock: TCP connects only to the declared
//	  ports, no TCP bind, no abstract unix socket and no signal outside the
//	  sandbox;
//	runs `<interpreter> /run/bastion-op/run --mode <m>` as a fresh uid that no
//	  run had before, with the params on stdin and the credentials the op
//	  declared in its environment.
//
// The unit runs in its own slice (privatae_ops.slice) with no memory ceiling:
// ops_memory_linux.go stops it first when the machine runs short. A unit is
// stopped by writing its cgroup's cgroup.kill, which needs no bus.
//
// When pid 1 exits, everything the program left running goes with it. The run
// dir (a tmpfs holding the spec, the sealed credentials opened, the hosts
// file) is unmounted, and the work folder removed. A bastion that dies
// mid-run leaves both behind, and the next start sweeps them (opStartupSweep).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	opActionSubcommand      = "__op-action"
	opActionChildSubcommand = "__op-action-child"
	opActionProbeSubcommand = "__op-action-probe"
	// The uids an action op's program runs as: one per run, counted up and
	// never handed out twice while the machine's record lasts. Far above any
	// account, subordinate id range or dynamic user this machine hands out
	// (checked every run, opUIDRangeFree).
	opUIDBase             = 0x70000000
	opUIDSpan             = 0x0FFF0000
	opUIDFile             = "op_uid_next"
	opActionRunTmpfsBytes = 16 << 20
	opBuilderInSandbox    = "/run/privatae-builder/buildkitd.sock"
	opActionUnitPrefix    = "privatae-op-"
	landlockRuleNetPort   = 2 // LANDLOCK_RULE_NET_PORT
	// opActionRetryAfter: a machine that could not run action ops is asked
	// again after this long, not only at the next restart.
	opActionRetryAfter = 10 * time.Minute
)

// opPrivilegedGroups are the groups whose membership reaches past a builder
// socket: the admin, disk, log and container groups.
var opPrivilegedGroups = map[string]bool{"root": true, "sudo": true, "wheel": true, "adm": true, "admin": true,
	"disk": true, "shadow": true, "docker": true, "lxd": true, "libvirt": true, "kvm": true,
	"systemd-journal": true, "systemd-network": true, "staff": true}

var (
	// opBuilderSocket is the machine's builder (a buildkitd running as its own
	// service user), handed to an op that declares `builder`, in apply only.
	opBuilderSocket = "/run/privatae-builder/buildkitd.sock"
	// Seams, so the tests can name a destination on this machine.
	opActionResolve  = lookupIPs
	opActionOwnAddrs = func() []net.IP {
		var out []net.IP
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, n.IP)
			}
		}
		return out
	}
)

// opActionSpec is what the bastion hands the unit, as a file on the run's
// tmpfs. It holds paths, never a credential's value.
type opActionSpec struct {
	OpDir       string            `json:"op_dir"`
	Interpreter string            `json:"interpreter"`
	Mode        string            `json:"mode"`
	Root        string            `json:"root"`
	UID         uint32            `json:"uid"`
	GID         uint32            `json:"gid"`
	Groups      []uint32          `json:"groups,omitempty"`
	TimeLimit   int               `json:"time_limit"`
	Masks       []string          `json:"masks"`
	Visible     []string          `json:"visible"`
	EmptyDir    string            `json:"empty_dir"`
	EmptyFile   string            `json:"empty_file"`
	Work        string            `json:"work,omitempty"` // bound at /tmp; "" = a fresh tmpfs
	Hosts       string            `json:"hosts"`
	Builder     string            `json:"builder,omitempty"`
	Creds       map[string]string `json:"creds,omitempty"` // env name -> file on the run's tmpfs
	Ports       []uint16          `json:"ports,omitempty"`
}

// ── availability ────────────────────────────────────────────────────────────

var (
	opActionMu      sync.Mutex
	opActionAt      time.Time
	opActionProbing bool
	opActionOK      bool
	opActionReason  string
)

// opActionAvailable: the files-op sandbox, systemd to run the unit, the
// unified cgroup hierarchy the address allowlist lives on, and a Landlock
// that can close ports and abstract sockets (ABI 6, Linux 6.12).
//
// The probe runs outside the lock: a caller that arrives while another is
// probing is told "not yet" at once rather than waiting on a unit.
func opActionAvailable() (bool, string) {
	opActionMu.Lock()
	if opActionProbing {
		ok, why := opActionOK, opActionReason
		opActionMu.Unlock()
		if !ok && why == "" {
			why = "this machine is still checking whether it can run action ops"
		}
		return ok, why
	}
	if !opActionAt.IsZero() && (opActionOK || time.Since(opActionAt) < opActionRetryAfter) {
		ok, why := opActionOK, opActionReason
		opActionMu.Unlock()
		return ok, why
	}
	opActionProbing = true
	opActionMu.Unlock()
	ok, why := false, ""
	// Stored on every way out, a panic included, so "probing" never sticks.
	defer func() {
		opActionMu.Lock()
		opActionAt, opActionOK, opActionReason, opActionProbing = time.Now(), ok, why, false
		opActionMu.Unlock()
	}()
	func() {
		if sok, swhy := opSandboxAvailable(); !sok {
			why = swhy
			return
		}
		for _, b := range []string{"systemd-run", "systemctl"} {
			if _, err := exec.LookPath(b); err != nil {
				why = b + " is not installed, and an action op runs as a systemd unit"
				return
			}
		}
		if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
			why = "this machine does not run the unified cgroup hierarchy, which an op's address allowlist needs"
			return
		}
		if v := landlockABI(); v < 6 {
			why = fmt.Sprintf("the kernel's Landlock (ABI %d) cannot hold an op to its ports and away from abstract sockets; ABI 6 (Linux 6.12) or newer is needed", v)
			return
		}
		if pwhy := opActionProbeUnit(); pwhy != "" {
			why = pwhy
			return
		}
		ok = true
	}()
	return ok, why
}

// opActionProbeUnit starts one unit the way a run does and checks, for real,
// the two things a run rests on that the system could quietly not give: the
// unit shares this process's mounts (the run's files are mounted here), and
// the address allowlist is enforced (a systemd without BPF firewalling warns
// and runs the unit anyway). "" when both hold.
func opActionProbeUnit() string {
	self, err := os.Executable()
	if err != nil {
		return "cannot find this binary: " + err.Error()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "cannot open a probe listener: " + err.Error()
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	unit := fmt.Sprintf("%sprobe-%d", opActionUnitPrefix, os.Getpid())
	out, err := exec.CommandContext(ctx, "systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
		"--unit="+unit, "-p", "IPAddressDeny=any", "-p", "RuntimeMaxSec=20",
		"--", self, opActionProbeSubcommand, ln.Addr().String()).Output()
	if err != nil {
		return "a probe unit could not run: " + err.Error()
	}
	mine, _ := os.Readlink("/proc/self/ns/mnt")
	got := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			got[k] = v
		}
	}
	if got["mnt"] == "" || got["mnt"] != mine {
		return "this bastion runs in a private mount namespace, so an op's unit cannot see the run's files"
	}
	if got["dial"] != "refused" {
		return "systemd does not enforce an op's address allowlist on this machine (no BPF firewalling)"
	}
	return ""
}

// opActionProbeMain is the probe unit's process: it names its mount
// namespace and whether it could dial addr.
func opActionProbeMain(addr string) int {
	mnt, _ := os.Readlink("/proc/self/ns/mnt")
	fmt.Println("mnt=" + mnt)
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		fmt.Println("dial=refused")
		return 0
	}
	_ = c.Close()
	fmt.Println("dial=reached")
	return 0
}

func landlockABI() int {
	v, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		return 0
	}
	return int(v)
}

// ── the run's uid ───────────────────────────────────────────────────────────

var opUIDMu sync.Mutex

// opNextUID hands out the next uid, counting up in the machine's record, so
// no file or process a run leaves could belong to a later one.
func opNextUID() (uint32, error) {
	opUIDMu.Lock()
	defer opUIDMu.Unlock()
	if err := opUIDRangeFree(); err != nil {
		return 0, err
	}
	d, err := configDir()
	if err != nil {
		return 0, err
	}
	p := filepath.Join(d, opUIDFile)
	var n uint64
	if raw, err := os.ReadFile(p); err == nil {
		if n, err = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err != nil {
			return 0, fmt.Errorf("this machine's %s does not read; ops are refused rather than reuse a uid", opUIDFile)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if n >= opUIDSpan {
		return 0, errors.New("this machine has used every uid set aside for ops")
	}
	// Counted before it is used: a crash here skips a uid, never repeats one.
	if err := atomicWrite(p, []byte(strconv.FormatUint(n+1, 10))); err != nil {
		return 0, err
	}
	return uint32(opUIDBase + n), nil
}

// opUIDRangeFree refuses when an account or a subordinate id range on this
// machine reaches into the uids set aside for ops.
func opUIDRangeFree() error {
	lo, hi := uint64(opUIDBase), uint64(opUIDBase+opUIDSpan)
	for _, f := range []string{"/etc/subuid", "/etc/subgid"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.Split(strings.TrimSpace(line), ":")
			if len(parts) != 3 {
				continue
			}
			start, e1 := strconv.ParseUint(parts[1], 10, 64)
			count, e2 := strconv.ParseUint(parts[2], 10, 64)
			if e1 == nil && e2 == nil && start < hi && start+count > lo {
				return fmt.Errorf("%s gives %s ids that overlap the ones set aside for ops", f, parts[0])
			}
		}
	}
	for _, f := range []string{"/etc/passwd", "/etc/group"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 3 {
				continue
			}
			if id, err := strconv.ParseUint(parts[2], 10, 64); err == nil && id >= lo && id < hi {
				return fmt.Errorf("%s has %s with an id set aside for ops", f, parts[0])
			}
		}
	}
	return nil
}

// ── destinations ────────────────────────────────────────────────────────────

type opResolvedDests struct {
	Addrs []string
	Ports []uint16
	Hosts []byte
}

// opResolveDests resolves every destination now, once: the addresses are
// what the unit is allowed to reach, and the names go in the run's own
// /etc/hosts (the machine's resolver is not reachable from the sandbox). A
// destination that resolves to this machine, its loopback or nothing is
// refused: a local service is never an op's destination.
func opResolveDests(ctx context.Context, dests []string) (*opResolvedDests, error) {
	own := map[string]bool{}
	for _, ip := range opActionOwnAddrs() {
		own[ip.String()] = true
	}
	var hosts strings.Builder
	hosts.WriteString("127.0.0.1 localhost\n::1 localhost\n")
	addrs, ports := map[string]bool{}, map[uint16]bool{}
	for _, d := range dests {
		dst, err := opParseDest(d)
		if err != nil {
			return nil, fmt.Errorf("destination %s: %v", d, err)
		}
		var ips []net.IP
		if ip := net.ParseIP(dst.Host); ip != nil {
			ips = []net.IP{ip}
		} else {
			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			ips, err = opActionResolve(rctx, dst.Host)
			cancel()
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("destination %s does not resolve on this machine", d)
			}
		}
		for _, ip := range ips {
			if why := opForbiddenDest(ip); why != "" {
				return nil, fmt.Errorf("destination %s resolves to %s: %s", d, ip, why)
			}
			if own[ip.String()] {
				return nil, fmt.Errorf("destination %s resolves to %s, which is this machine", d, ip)
			}
			addrs[ip.String()] = true
			if net.ParseIP(dst.Host) == nil {
				fmt.Fprintf(&hosts, "%s %s\n", ip, dst.Host)
			}
		}
		ports[dst.Port] = true
	}
	out := &opResolvedDests{Hosts: []byte(hosts.String())}
	for a := range addrs {
		out.Addrs = append(out.Addrs, a)
	}
	sort.Strings(out.Addrs)
	for p := range ports {
		out.Ports = append(out.Ports, p)
	}
	sort.Slice(out.Ports, func(i, j int) bool { return out.Ports[i] < out.Ports[j] })
	return out, nil
}

// ── the parent side ─────────────────────────────────────────────────────────

// opRunActionProgram runs the program once in one mode and returns its report
// and, in apply, the result file it left in its work folder.
func opRunActionProgram(opDir string, m *opManifest, mode, params string, creds map[string]string, runID string) (*opReport, []byte, error) {
	rep := &opReport{Mode: mode, Changes: []opChange{}}
	var declared []string
	for _, d := range m.Reads {
		forms := opDeclaredForms(d)
		if sens, err := opSensitiveMatchForms(forms); err != nil {
			return nil, nil, err
		} else if sens != "" {
			return nil, nil, opSensitiveRefusal(d, sens)
		}
		declared = append(declared, forms...)
	}
	offs, err := opMaskSet()
	if err != nil {
		return nil, nil, err
	}
	// A dry run, which nobody approved, has no network at all: what the op
	// would reach is on its card, and only an approved apply (and the verify
	// inside it) reaches it.
	dests := &opResolvedDests{Hosts: []byte("127.0.0.1 localhost\n::1 localhost\n")}
	if mode != opModeDryRun {
		if dests, err = opResolveDests(context.Background(), m.Destinations); err != nil {
			return nil, nil, err
		}
	}
	// A machine already down to the memory it keeps for its own services
	// starts no op (ops_memory_linux.go).
	floor := opMemoryFloor()
	if _, avail, ok := opMemInfo(); ok && avail <= floor {
		return nil, nil, fmt.Errorf("this machine has %s of memory free, under the %s it keeps for its own services%s, so the op did not start", opMiB(avail), opMiB(floor), opFloorNote())
	}
	runsRoot, err := opRunsRoot()
	if err != nil {
		return nil, nil, err
	}
	run, err := os.MkdirTemp(runsRoot, "run-")
	if err != nil {
		return nil, nil, err
	}
	work := ""
	mounted := false
	cleanup := func() {
		if mounted {
			_ = unix.Unmount(run, unix.MNT_DETACH)
		}
		_ = os.RemoveAll(run)
		if work != "" {
			_ = os.RemoveAll(work)
		}
	}
	defer cleanup()
	if err := unix.Mount("tmpfs", run, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC,
		fmt.Sprintf("size=%d,mode=0700", opActionRunTmpfsBytes)); err != nil {
		return nil, nil, fmt.Errorf("cannot mount the run's tmpfs: %v", err)
	}
	mounted = true
	uid, err := opNextUID()
	if err != nil {
		return nil, nil, err
	}
	interp := opInterpreters[m.Interpreter]
	spec := opActionSpec{OpDir: opDir, Interpreter: interp, Mode: mode, Root: filepath.Join(run, "root"),
		UID: uid, GID: uid, TimeLimit: m.TimeLimit, Masks: offs, Visible: opViewVisible(declared),
		EmptyDir: filepath.Join(run, "empty-dir"), EmptyFile: filepath.Join(run, "empty-file"),
		Hosts: filepath.Join(run, "hosts"), Ports: dests.Ports}
	if err := os.Mkdir(spec.Root, 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.Mkdir(spec.EmptyDir, 0o555); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(spec.EmptyFile, nil, 0o444); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(spec.Hosts, dests.Hosts, 0o444); err != nil {
		return nil, nil, err
	}
	if mode == opModeApply {
		// The work folder is on disk (a build's sources can outgrow memory),
		// beside the run dir, and belongs to the run's uid alone.
		work = run + "-work"
		if err := os.Mkdir(work, 0o700); err != nil {
			return nil, nil, err
		}
		if err := os.Chown(work, int(uid), int(uid)); err != nil {
			return nil, nil, err
		}
		spec.Work = work
	}
	if len(creds) > 0 {
		spec.Creds = map[string]string{}
		i := 0
		for name, val := range creds {
			f := filepath.Join(run, fmt.Sprintf("cred-%d", i))
			i++
			if err := os.WriteFile(f, []byte(val), 0o400); err != nil {
				return nil, nil, err
			}
			spec.Creds[opCredEnv(name)] = f
		}
	}
	if m.Builder && mode == opModeApply {
		st, err := os.Stat(opBuilderSocket)
		if err != nil || st.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("the op builds, and this machine has no builder at %s", opBuilderSocket)
		}
		spec.Builder = opBuilderSocket
		// The program joins the socket's group to reach it, so that group
		// must be the builder's own, never one that carries other power.
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, nil, errors.New("the builder's socket cannot be read")
		}
		if g, err := user.LookupGroupId(strconv.FormatUint(uint64(s.Gid), 10)); s.Gid == 0 || (err == nil && opPrivilegedGroups[g.Name]) {
			return nil, nil, fmt.Errorf("the builder's socket belongs to a privileged group (gid %d); give it the builder's own group", s.Gid)
		}
		spec.Groups = []uint32{s.Gid}
	}
	specRaw, _ := json.Marshal(spec)
	specPath := filepath.Join(run, "spec.json")
	if err := os.WriteFile(specPath, specRaw, 0o600); err != nil {
		return nil, nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	unit := opActionUnitPrefix + truncate(runID, 16) + "-" + strings.ReplaceAll(mode, "_", "-")
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--unit=" + unit, "--slice=" + opActionSlice,
		"-p", "IPAddressDeny=any",
		"-p", "RuntimeMaxSec=" + strconv.Itoa(m.TimeLimit),
		"-p", "TasksMax=512",
		// No memory ceiling (ops_memory_linux.go): the op may use what the
		// machine has to spare, and is the first thing the kernel kills.
		"-p", "OOMScoreAdjust=1000",
		"-p", "KillMode=control-group",
		"-p", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
	}
	if len(dests.Addrs) > 0 {
		args = append(args, "-p", "IPAddressAllow="+strings.Join(dests.Addrs, " "))
	}
	args = append(args, "--", self, opActionSubcommand, specPath)
	limit := time.Duration(m.TimeLimit) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), limit+15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemd-run", args...)
	cmd.Stdin = strings.NewReader(params)
	out := &cappedBuffer{max: opOutputMaxBytes}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.WaitDelay = 5 * time.Second
	start := time.Now()
	stopWatch := opMemoryWatch(unit, floor)
	runErr := cmd.Run()
	mem := stopWatch()
	if ctx.Err() != nil {
		// The unit outlived its own RuntimeMaxSec and the wait: kill it.
		opKillUnit(unit)
	}
	rep.Seconds = time.Since(start).Seconds()
	rep.Output = opScrub(out.String(), creds)
	// Stopped only if the kill landed and the program did not finish anyway
	// (a kill that came as it was exiting leaves a successful run alone).
	if mem.Stopped && runErr != nil {
		rep.Exit = 137
		return rep, nil, errors.New(mem.reason())
	}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			rep.Exit = ee.ExitCode()
		} else {
			return rep, nil, fmt.Errorf("the op's unit could not start: %v", runErr)
		}
	}
	if rep.Exit != 0 && time.Since(start) >= limit {
		rep.TimedOut = true
		return rep, nil, fmt.Errorf("the op did not finish inside its time limit (%ds)", m.TimeLimit)
	}
	lastLine := func() string {
		lines := strings.Split(strings.TrimSpace(rep.Output), "\n")
		return lines[len(lines)-1]
	}
	if rep.Exit == 125 || rep.Exit == 126 {
		return rep, nil, fmt.Errorf("the sandbox could not run the op: %s", lastLine())
	}
	if rep.Exit != 0 && mode != opModeVerify {
		return rep, nil, fmt.Errorf("the op exited %d in %s mode: %s", rep.Exit, mode, lastLine())
	}
	var result []byte
	if work != "" {
		result, err = opReadResult(filepath.Join(work, opResultName))
		if err != nil {
			return rep, nil, err
		}
	}
	return rep, result, nil
}

// opReadResult reads the program's result file without following a link:
// the folder belongs to the program, and the bastion reads it as root.
func opReadResult(p string) ([]byte, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("the program's result is not a plain file")
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > opResultMaxBytes {
		return nil, errors.New("the program's result is not a plain file under 64 KiB")
	}
	buf := make([]byte, st.Size())
	n, _ := f.Read(buf)
	return buf[:n], nil
}

// opScrub takes every credential value out of what the program printed.
func opScrub(s string, creds map[string]string) string {
	for _, v := range creds {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}

// ── inside the unit ─────────────────────────────────────────────────────────

// opActionOuterMain is the unit's process: it starts the sandbox's pid 1 in
// fresh namespaces and returns its exit.
func opActionOuterMain(specPath string) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		return 125
	}
	cmd := exec.Command(self, opActionChildSubcommand, specPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Pdeathsig:  syscall.SIGKILL,
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return opExitOf(cmd.Run())
}

func opExitOf(err error) int {
	if err == nil {
		return 0
	}
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

// opActionChildMain is pid 1 of the sandbox. Every restriction below is set
// on this thread and the program is forked from it: no-new-privs, the
// bounding set and Landlock are all per thread.
func opActionChildMain(specPath string) int {
	runtime.LockOSThread()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: no spec:", err)
		return 125
	}
	var spec opActionSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: bad spec:", err)
		return 125
	}
	// The credentials are read before the view is built: their files are on
	// the run's tmpfs, which the view hides.
	env := []string{
		"PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"LANG=C.UTF-8",
		"USER=privatae-op",
		"PRIVATAE_OP_MODE=" + spec.Mode,
		"PRIVATAE_OP_RESULT=/tmp/" + opResultName,
	}
	if spec.Builder != "" {
		env = append(env, "BUILDKIT_HOST=unix://"+opBuilderInSandbox)
	}
	for name, f := range spec.Creds {
		v, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sandbox: a credential cannot be read:", err)
			return 125
		}
		env = append(env, name+"="+string(v))
	}
	if err := opActionSetup(&spec); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		return 125
	}
	_ = unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{Cur: 256, Max: 256})
	_ = unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 1 << 30, Max: 1 << 30})
	_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 1024, Max: 1024})
	_ = unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: uint64(spec.TimeLimit), Max: uint64(spec.TimeLimit)})
	// The program runs as a uid with no capability at all, and can gain none.
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: no_new_privs:", err)
		return 125
	}
	if err := opLandlock(spec.Ports); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox: landlock:", err)
		return 125
	}
	cmd := exec.Command(spec.Interpreter, opActionMount+"/run", "--mode", spec.Mode)
	cmd.Dir = "/tmp"
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	groups := spec.Groups
	if groups == nil {
		groups = []uint32{}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: spec.UID, Gid: spec.GID, Groups: groups}}
	return opExitOf(cmd.Run())
}

// opActionSetup builds the program's filesystem and pivots into it.
func opActionSetup(spec *opActionSpec) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %v", err)
	}
	r := spec.Root
	// The machine, read-only, every mount under it too. Nothing below this
	// line writes to it: each mount point used is on a fresh tmpfs or exists.
	if err := unix.Mount("/", r, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind /: %v", err)
	}
	if err := unix.MountSetattr(unix.AT_FDCWD, r, unix.AT_RECURSIVE,
		&unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}); err != nil {
		return fmt.Errorf("read-only /: %v", err)
	}
	tmpDirs := []string{"sys", "run", "var/tmp"}
	if spec.Work != "" {
		tmp := filepath.Join(r, "tmp")
		if err := unix.Mount(spec.Work, tmp, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("work folder: %v", err)
		}
		if err := unix.Mount("", tmp, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return fmt.Errorf("work folder flags: %v", err)
		}
	} else {
		tmpDirs = append(tmpDirs, "tmp")
	}
	if err := opSandboxCommon(r, tmpDirs, spec.Visible, spec.EmptyDir, spec.EmptyFile, spec.Masks); err != nil {
		return err
	}
	hosts := filepath.Join(r, "etc/hosts")
	if st, err := os.Lstat(hosts); err != nil || !st.Mode().IsRegular() {
		return errors.New("this machine's /etc/hosts is not a plain file to cover")
	}
	if err := opBindReadOnly(spec.Hosts, hosts); err != nil {
		return fmt.Errorf("hosts: %v", err)
	}
	mnt := filepath.Join(r, strings.TrimPrefix(opActionMount, "/"))
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return err
	}
	if err := opBindReadOnly(spec.OpDir, mnt); err != nil {
		return fmt.Errorf("op mount: %v", err)
	}
	if spec.Builder != "" {
		sock := filepath.Join(r, strings.TrimPrefix(opBuilderInSandbox, "/"))
		if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(sock, nil, 0o600); err != nil {
			return err
		}
		if err := opBindReadOnly(spec.Builder, sock); err != nil {
			return fmt.Errorf("builder: %v", err)
		}
	}
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

type landlockNetPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}

// opLandlock: TCP connects to the declared ports only, no TCP bind, and no
// abstract unix socket or signal that leaves the sandbox. The addresses are
// the unit's allowlist; the two together are the destinations.
func opLandlock(ports []uint16) error {
	attr := unix.LandlockRulesetAttr{
		Access_net: unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP,
		Scoped:     unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL,
	}
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if e != 0 {
		return fmt.Errorf("create ruleset: %v", e)
	}
	defer unix.Close(int(fd))
	for _, p := range ports {
		na := landlockNetPortAttr{AllowedAccess: unix.LANDLOCK_ACCESS_NET_CONNECT_TCP, Port: uint64(p)}
		if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, landlockRuleNetPort, uintptr(unsafe.Pointer(&na)), 0, 0, 0); e != 0 {
			return fmt.Errorf("allow port %d: %v", p, e)
		}
	}
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); e != 0 {
		return fmt.Errorf("restrict: %v", e)
	}
	return nil
}

// ── the startup sweep ───────────────────────────────────────────────────────

// opStartupSweep removes what a run left behind when the bastion died under
// it: every run dir (unmounting its tmpfs, where an action run's opened
// credentials were), every work folder, and any op unit still running. It runs
// once, before any pairing serves, so no run of this process is in flight.
func opStartupSweep() {
	if !processIsRoot() {
		return
	}
	root, err := opRunsRoot()
	if err != nil {
		return
	}
	// The units first, so no program is still writing into what is removed.
	for _, u := range opActionUnits() {
		opKillUnit(u)
		_ = exec.Command("systemctl", "stop", u).Run()
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "run-") {
			continue
		}
		p := filepath.Join(root, e.Name())
		if !strings.HasSuffix(e.Name(), "-work") {
			_ = unix.Unmount(p, unix.MNT_DETACH)
		}
		_ = os.RemoveAll(p)
	}
	// A ship plan's line the dead process was running is settled as failed
	// (ops_plan_linux.go), now that its unit is gone.
	planSettleStopped()
}

// opActionUnits lists the op units running: the cgroups in the ops' slice,
// read straight from the kernel (a unit with no process left has none), plus
// any op unit systemd still lists.
func opActionUnits() []string {
	seen := map[string]bool{}
	var units []string
	add := func(u string) {
		u = strings.TrimSuffix(u, ".service")
		if strings.HasPrefix(u, opActionUnitPrefix) && !seen[u] {
			seen[u] = true
			units = append(units, u)
		}
	}
	if entries, err := os.ReadDir(filepath.Join("/sys/fs/cgroup", opActionSlice)); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasSuffix(e.Name(), ".service") {
				add(e.Name())
			}
		}
	}
	if out, err := exec.Command("systemctl", "list-units", "--all", "--plain", "--no-legend", opActionUnitPrefix+"*").Output(); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(out)))
		for sc.Scan() {
			if f := strings.Fields(sc.Text()); len(f) > 0 {
				add(f[0])
			}
		}
	}
	return units
}
