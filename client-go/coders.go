package main

// coders.go — CODER MODE: one sealed coding run per container on this machine.
//
// A Host can place a coding run (codex, claude-code, ...) on a machine its
// user owns instead of the platform pool. The run reaches the internet over
// this machine's own connection, and nothing else: the container has no
// network at all, and its only way out is egress.sock, a proxy in this bastion
// that refuses this machine, its LAN and every private range (coder_egress.go).
// The Host reaches the run's control plane through one tunnel port per run
// (coder_forward.go), which accepts only the owning pairing's tunnel address.
//
// THE VERBS (mode "coder" on the harness lane, coder_op):
//   - run-up     start one container for one run and return as soon as it
//                answers /health. The harness worker is released then; the
//                run lives on without holding one, so the 2-worker pool
//                (harness.go harnessWorkerCount) does not bound how many runs
//                this machine holds.
//   - run-down   stop it, report what it used (cgroup memory.peak, cpu.stat),
//                remove it and its files.
//   - run-status what this pairing has running here.
//
// WHAT THE OWNER DECIDES. `privatae-bastion coders set|on|off` stores the
// machine-wide limits (how many runs, how big each one is, which engines). It
// is off by default. A run that does not fit is answered "full" — a capacity
// answer with exit 0, never a refusal, so a burst cannot trip the quarantine.
//
// Linux only in this cut (the socket forward pins the inode through /proc,
// service_sock_linux.go), and the bastion must run as root because the run's
// files are handed to the engine's uid instead of being opened 0777.

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	coderCapability      = "coders"
	coderGateOp          = "mode:coder"
	coderContainerPrefix = "privatae-run-"

	// Tunnel-side ports, one per run. The service slot owns 18100-18199
	// (service.go); these sit right after it.
	coderPortBase = 18200
	coderPortMax  = 18299

	coderLabelRun      = "privatae.coder.run"
	coderLabelOwner    = "privatae.coder.owner"
	coderLabelEngine   = "privatae.coder.engine"
	coderLabelDeadline = "privatae.coder.deadline"

	// Paths inside the container. The sockets are mounted as DIRECTORIES: a
	// listener's socket file does not exist before the container starts, so it
	// cannot be bind-mounted itself.
	coderCtlDirIn     = "/run/privatae/ctl"
	coderEgressDirIn  = "/run/privatae/egress"
	coderControlSock  = "control.sock"
	coderEgressSock   = "egress.sock"
	coderWorkspaceIn  = "/var/lib/skema/projects"
	coderHomeIn       = "/home/privatae"
	coderSeccompFile  = "seccomp-personal.json"
	coderDefaultMins  = 240
	coderDeadlineSlop = 15 * time.Minute

	// Defaults until the load test (plan section 4) sets them.
	coderDefaultMemMB = 2048
	coderDefaultCPUs  = 2.0

	// THE MACHINE GUARD. Runs must never take the memory the machine itself
	// needs: on a 2-CPU 3.7 GiB machine, twelve 512 MiB runs were each inside
	// their own limit and together left 0 MiB free, and sshd stopped answering
	// until the machine was rebooted. So run-up counts every run's limit
	// against what the machine can spare (coderReserveMB), and the watchdog
	// (coderWatch) stops the newest run when the machine runs short anyway,
	// because something outside the runs grew.
	//
	// coderEvictFloorMB is the kubelet's and GKE's hard eviction threshold
	// (memory.available < 100Mi). The pressure limit and its duration are
	// systemd-oomd's defaults: PSI memory "full" avg10 over 60% for 30 s.
	coderEvictFloorMB   = 100
	coderPressureLimit  = 60.0
	coderPressureFor    = 30 * time.Second
	coderPressureSettle = 10 * time.Second // one avg10 window: what a stop did shows up after this
	coderWatchEvery     = 2 * time.Second

	coderStartWait   = 60 * time.Second
	coderCredsMax    = 1 << 20
	coderPullTimeout = 10 * time.Minute
)

// coderEngines are the coding engines a run may name: the controller's
// _HARNESS_SPECS rows minus browser, and workspace, the harness control plane
// with a toolchain and no coding agent, which a Host's own threads build and
// test in. vscode is retired and is not one.
var coderEngines = []string{"codex", "cursor", "grok", "claude-code", "opencode", "kimi", "antigravity", "workspace"}

// coderDefaultImagePrefix is where every engine's image lives unless the
// owner names another prefix (`coders set --image-prefix`). A run names
// <prefix>harness-<engine>@sha256:<digest>.
const coderDefaultImagePrefix = gitForgeHost + "/privatae-harness/"

var (
	coderRunIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{6,61}[a-z0-9]$`)
	coderDigestRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	coderCredsDirRe = regexp.MustCompile(`^/home/privatae/\.[a-z0-9-]{1,32}$`)
	coderCredNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	coderCapRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
)

// seccomp-personal.json is the profile every pool harness pod runs under (the
// cluster's node addon installs the same bytes; a test pins the sha256). It is
// written next to the coder config and handed to the runtime on every run.
//
//go:embed seccomp-personal.json
var coderSeccompProfile []byte

// The seams. Package-level so the tests can drive every verb without a real
// container runtime, a Linux kernel or root.
var (
	coderGOOS     = runtime.GOOS
	coderIsRoot   = processIsRoot
	coderRuntime  = detectRuntime
	coderRun      = runCmd
	coderRunEnv   = runCmdEnv
	coderMemInfo  = coderReadMemInfo
	coderPSIMem   = coderReadPSIMem
	coderChown    = os.Chown
	coderNow      = time.Now
	coderWaitUp   = coderWaitHealthy
	coderCgroupFS = "/sys/fs/cgroup"
	coderProcFS   = "/proc"

	// coderNvidiaConfig is NVIDIA's container toolkit config (coderNvidiaSwarmEnv).
	coderNvidiaConfig = "/etc/nvidia-container-runtime/config.toml"
	coderEnvNameRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ── config ──────────────────────────────────────────────────────────────────

// coderConfig is <configDir>/coders/config.json. Machine-wide: the owner sizes
// the machine once, whichever hosts are paired.
type coderConfig struct {
	Enabled    bool     `json:"enabled"`
	Max        int      `json:"max"`            // 0 = unset
	MemPerRun  int      `json:"mem_per_run_mb"` // 0 = unset
	CPUsPerRun float64  `json:"cpus_per_run"`   // 0 = unset
	Engines    []string `json:"engines"`        // nil = unset; stored explicitly, never empty-for-all
	AllowLAN   []string `json:"allow_lan"`      // host[:port] the egress proxy lets through to a private address
	// Where a run's image may come from, set by the owner (`coders set
	// --image-prefix`). "" is coderDefaultImagePrefix, and is omitted from the
	// file, so a machine that never set it keeps the bytes it had.
	ImagePrefix string `json:"image_prefix,omitempty"`
}

// imagePrefix is the owner's prefix, or the default.
func (c coderConfig) imagePrefix() string {
	if c.ImagePrefix == "" {
		return coderDefaultImagePrefix
	}
	return c.ImagePrefix
}

var (
	coderPrefixDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)
	coderPrefixPathRe   = regexp.MustCompile(`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*$`)
)

// coderPrefixRefusal checks an image prefix the owner names: image-reference
// components ending in "/", the first one a registry host (with an optional
// port) or a path component, lowercase, at most 200 bytes. "" when it is good.
func coderPrefixRefusal(p string) string {
	if p == "" || len(p) > 200 || !strings.HasSuffix(p, "/") || strings.ContainsAny(p, "@ \t\r\n") {
		return "--image-prefix must be a registry path ending in '/', like " + coderDefaultImagePrefix
	}
	for i, c := range strings.Split(strings.TrimSuffix(p, "/"), "/") {
		if coderPrefixPathRe.MatchString(c) || (i == 0 && coderPrefixDomainRe.MatchString(c)) {
			continue
		}
		return fmt.Sprintf("--image-prefix: %q is not a lowercase image-path component", c)
	}
	return ""
}

// coderPrefixRegistry is the registry a prefix pulls from, by the container
// runtimes' own rule: a first component with a '.' or ':', or localhost, is a
// registry host; anything else is on docker.io.
func coderPrefixRegistry(p string) string {
	first, _, _ := strings.Cut(p, "/")
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return "docker.io"
}

// coderImageRefusal: the image must be <prefix>harness-<engine>@sha256:<digest>,
// the engine's own image under the prefix the owner set.
func coderImageRefusal(image, engine, prefix string) string {
	repo, digest, ok := strings.Cut(image, "@")
	if !ok || repo != prefix+"harness-"+engine || !coderDigestRe.MatchString(digest) {
		return "image must be " + prefix + "harness-" + engine + "@sha256:<digest>"
	}
	return ""
}

func codersDir() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "coders")
	return p, os.MkdirAll(p, 0o700)
}

func coderConfigPath() (string, error) {
	d, err := codersDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// loadCoderConfig: a missing file is the default (off). A file that does not
// parse is also off — a box never runs coders on a config it cannot read.
func loadCoderConfig() coderConfig {
	p, err := coderConfigPathNoCreate()
	if err != nil {
		return coderConfig{}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return coderConfig{}
	}
	var c coderConfig
	if json.Unmarshal(b, &c) != nil {
		return coderConfig{}
	}
	return c
}

// coderConfigPathNoCreate reads without creating the coders dir, so a box
// that never used coder mode gets no new directory from a heartbeat.
func coderConfigPathNoCreate() (string, error) {
	d, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "coders", "config.json"), nil
}

func saveCoderConfig(c coderConfig) error {
	p, err := coderConfigPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b)
}

// ready: on, and every size is set (`coders on` fills what `set` left).
func (c coderConfig) ready() bool {
	return c.Enabled && c.Max >= 1 && c.MemPerRun >= 512 && c.CPUsPerRun > 0 && len(c.Engines) > 0
}

func (c coderConfig) allowsEngine(e string) bool {
	return containsStr(c.Engines, e)
}

func isCoderEngine(e string) bool { return containsStr(coderEngines, e) }

// ── run records ─────────────────────────────────────────────────────────────

// coderRecord is R/run.json, written once the container answers /health and
// removed by run-down. The forward, the egress loop, the heartbeat and the
// reaper all read it.
type coderRecord struct {
	RunID      string  `json:"run_id"`
	Owner      string  `json:"owner"`
	Engine     string  `json:"engine"`
	Image      string  `json:"image"`
	Container  string  `json:"container"`
	TunnelPort int     `json:"tunnel_port"`
	UID        int     `json:"uid"`
	CreatedAt  string  `json:"created_at"`
	Deadline   string  `json:"deadline"`
	PullS      float64 `json:"pull_s"`
	MemMB      int     `json:"mem_mb,omitempty"`     // the run's memory limit; 0 in a record from before it was kept
	Cgroup     string  `json:"cgroup,omitempty"`     // the container's cgroup, as /proc/<pid>/cgroup names it
	StoppedBy  string  `json:"stopped_by,omitempty"` // why the watchdog stopped it, "" when it did not
}

func coderRunsDir() (string, error) {
	d, err := codersDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "runs")
	return p, os.MkdirAll(p, 0o700)
}

func coderRunDir(runID string) (string, error) {
	d, err := coderRunsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, runID), nil
}

func loadCoderRecord(runID string) (*coderRecord, error) {
	if !coderRunIDRe.MatchString(runID) {
		return nil, errors.New("bad run_id")
	}
	R, err := coderRunDir(runID)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(R, "run.json"))
	if err != nil {
		return nil, err
	}
	var r coderRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.RunID != runID {
		return nil, errors.New("record names another run")
	}
	return &r, nil
}

// loadCoderRecords returns every readable run record, sorted by run_id. It
// creates nothing: a box that never ran a coder answers an empty list.
func loadCoderRecords() []coderRecord {
	d, err := configDirPath()
	if err != nil {
		return nil
	}
	ents, err := os.ReadDir(filepath.Join(d, "coders", "runs"))
	if err != nil {
		return nil
	}
	var out []coderRecord
	for _, e := range ents {
		if !e.IsDir() || !coderRunIDRe.MatchString(e.Name()) {
			continue
		}
		if r, err := loadCoderRecord(e.Name()); err == nil {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out
}

func saveCoderRecord(R string, r *coderRecord) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(R, "run.json"), b)
}

// coderRewriteRecord replaces the record of a run that already has one. Unlike
// saveCoderRecord (atomicWrite makes missing directories) it never creates R:
// `coders drop` tears runs down from its own process, which coderMu does not
// cover, so R can go between reading a record and writing it back. Writing
// the temporary file inside R fails once R is gone, and the run stays gone.
func coderRewriteRecord(R string, r *coderRecord) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(R, ".run-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // nothing to remove once renamed
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(R, "run.json"))
}

// ── capacity ────────────────────────────────────────────────────────────────

// coderMu guards the reservation table and every record add/remove, so two
// run-ups cannot both take the last slot or the same tunnel port.
var (
	coderMu       sync.Mutex
	coderStarting = map[string]coderReservation{} // run_id -> a run-up in progress
)

type coderReservation struct {
	owner string
	port  int
	memMB int
}

// coderCounts: box-wide runs and this pairing's, records plus run-ups in
// flight. Caller holds coderMu.
func coderCountsLocked(self string, recs []coderRecord) (all, mine int) {
	for _, r := range recs {
		all++
		if r.Owner == self {
			mine++
		}
	}
	for id, s := range coderStarting {
		if coderHasRecord(recs, id) {
			continue
		}
		all++
		if s.owner == self {
			mine++
		}
	}
	return all, mine
}

func coderHasRecord(recs []coderRecord, id string) bool {
	for _, r := range recs {
		if r.RunID == id {
			return true
		}
	}
	return false
}

// allocCoderPort takes the lowest tunnel port no record or reservation holds.
// 0 = all 100 are taken. Caller holds coderMu.
func allocCoderPortLocked(recs []coderRecord) int {
	used := map[int]bool{}
	for _, r := range recs {
		used[r.TunnelPort] = true
	}
	for _, s := range coderStarting {
		used[s.port] = true
	}
	for p := coderPortBase; p <= coderPortMax; p++ {
		if !used[p] {
			return p
		}
	}
	return 0
}

// coderReserveMB is the memory a machine of totalMB keeps for itself: GKE's
// node reservation (255 MiB under 1 GiB; otherwise 25% of the first 4 GiB, 20%
// of the next 4, 10% of the next 8, 6% of the next 112 and 2% above 128 GiB)
// plus the eviction threshold. On the 3.7 GiB machine that is 1055 MiB; a Host
// and its database there, with 64 threads in flight and the operating system,
// used under 1.1 GiB.
func coderReserveMB(totalMB int) int {
	if totalMB < 1024 {
		return 255 + coderEvictFloorMB
	}
	tiers := []struct {
		upTo int
		frac float64
	}{{4 << 10, 0.25}, {8 << 10, 0.20}, {16 << 10, 0.10}, {128 << 10, 0.06}, {math.MaxInt32, 0.02}}
	r, low := 0.0, 0
	for _, t := range tiers {
		if totalMB <= low {
			break
		}
		r += float64(min(totalMB, t.upTo)-low) * t.frac
		low = t.upTo
	}
	return int(math.Ceil(r)) + coderEvictFloorMB
}

// coderBudgetMB is what the limits of every run together may add up to.
func coderBudgetMB(totalMB int) int { return totalMB - coderReserveMB(totalMB) }

// coderRecordMem is one run's memory limit; a record from before the limit
// was kept counts at today's per-run size.
func coderRecordMem(r coderRecord, perRun int) int {
	if r.MemMB > 0 {
		return r.MemMB
	}
	return perRun
}

// coderCommittedLocked is the memory promised to runs: the limit of every run
// not known to have stopped, plus every run-up in flight. A stopped run's
// memory is free again, though its record stays for run-down to read. Caller
// holds coderMu.
func coderCommittedLocked(recs []coderRecord, perRun int) int {
	sum := 0
	for _, r := range recs {
		if up, known := coderRecordRunning(r); known && !up {
			continue
		}
		sum += coderRecordMem(r, perRun)
	}
	for id, s := range coderStarting {
		if !coderHasRecord(recs, id) {
			sum += s.memMB
		}
	}
	return sum
}

// coderRecordRunning reads whether a run's container still has processes,
// from its cgroup's cgroup.events, without asking the container runtime: the
// runtime is slowest exactly when the machine is short of memory. known is
// false when the record carries no cgroup (one from before it was kept, or a
// runtime whose cgroup was not found).
func coderRecordRunning(r coderRecord) (running, known bool) {
	dir := coderCgroupPath(r.Cgroup)
	if dir == "" {
		return false, false
	}
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.events"))
	if err != nil {
		// The cgroup is gone with its container.
		return false, os.IsNotExist(err)
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if f := strings.Fields(ln); len(f) == 2 && f[0] == "populated" {
			return f[1] == "1", true
		}
	}
	return false, false
}

// coderCgroupPath is a cgroup path as /proc/<pid>/cgroup names it ("0::/x"
// without the prefix), under coderCgroupFS. "" when it is empty or climbs out.
func coderCgroupPath(p string) string {
	if p == "" || strings.Contains(p, "..") {
		return ""
	}
	return filepath.Join(coderCgroupFS, filepath.Clean("/"+p))
}

// coderParsePSIFull reads "full avg10" from a /proc/pressure file: the share
// of the last 10 s in which every task was stalled.
func coderParsePSIFull(s string) (float64, bool) {
	for _, ln := range strings.Split(s, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || f[0] != "full" {
			continue
		}
		for _, kv := range f[1:] {
			if v, ok := strings.CutPrefix(kv, "avg10="); ok {
				x, err := strconv.ParseFloat(v, 64)
				return x, err == nil
			}
		}
	}
	return 0, false
}

// ── the lane ────────────────────────────────────────────────────────────────

// coderPull is the per-run registry credential the Host mints for this pull.
// It is used once, in a throwaway config dir, and never stored or logged.
type coderPull struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// coderSpecRefusal is everything about the request itself, checked before the
// lane spends any gate (handleHarnessConn), like serviceSpecRefusal.
func coderSpecRefusal(spec harnessSpec) string {
	switch spec.CoderOp {
	case "run-status":
		return ""
	case "run-down":
		if !coderRunIDRe.MatchString(spec.RunID) {
			return "run_id must be 8-63 of a-z, 0-9 and '-', starting and ending with a letter or digit"
		}
		return ""
	case "run-up":
		return validateCoderUp(spec)
	}
	return "coder_op must be run-up, run-down or run-status"
}

func validateCoderUp(spec harnessSpec) string {
	if !coderRunIDRe.MatchString(spec.RunID) {
		return "run_id must be 8-63 of a-z, 0-9 and '-', starting and ending with a letter or digit"
	}
	if !isCoderEngine(spec.Engine) {
		return "engine must be one of " + strings.Join(coderEngines, ", ")
	}
	prefix := loadCoderConfig().imagePrefix()
	if why := coderImageRefusal(spec.Image, spec.Engine, prefix); why != "" {
		return why
	}
	if spec.UID < 10001 || spec.UID > 10099 {
		return "uid must be the engine's own uid (10001-10099)"
	}
	if !coderCredsDirRe.MatchString(spec.CredsDir) {
		return "creds_dir must be /home/privatae/.<name>"
	}
	total := 0
	for name, body := range spec.Creds {
		if !coderCredNameRe.MatchString(name) || name == "." || name == ".." {
			return "a creds file name is not a plain file name"
		}
		total += len(name) + len(body)
	}
	if total > coderCredsMax {
		return "creds exceed 1 MiB"
	}
	if !coderCapRe.MatchString(spec.ControlCap) {
		return "control_cap must be 32-128 of A-Z, a-z, 0-9, '_' and '-'"
	}
	if spec.MaxMinutes != 0 && (spec.MaxMinutes < 1 || spec.MaxMinutes > 1440) {
		return "max_minutes must be 1-1440"
	}
	if p := spec.Pull; p != nil {
		if reg := coderPrefixRegistry(prefix); p.Registry != reg {
			return "pull.registry must be " + reg
		}
		if p.Username == "" || p.Password == "" {
			return "pull needs a username and a password"
		}
		if strings.ContainsAny(p.Username, ":\x00\r\n") || strings.ContainsAny(p.Password, "\x00\r\n") {
			return "pull.username or pull.password contains a character a registry login cannot hold"
		}
	}
	return ""
}

// coderGate is harnessGate's branch for mode=coder on an ANCHORED box (the
// caller has already returned for an unanchored one). run-status is a read and
// answers even under quarantine. run-up and run-down are writes: the
// quarantine applies, and the pairing must hold a valid standing coder grant
// (coder_grant.go) — approved once by the person, never per run.
func coderGate(self, dcnDir string, spec harnessSpec) string {
	if spec.CoderOp == "run-status" {
		return ""
	}
	why := ""
	now := coderNow()
	if until := quarantinedUntil(self, now); !until.IsZero() {
		why = quarantineRefusal(until)
	} else if _, gwhy := coderGrantFor(dcnDir, self); gwhy != "" {
		why = "refused: " + coderGateOp + " — " + gwhy
	}
	if why != "" {
		noteRefusal(self, coderGateOp, why, refusalCounts(coderGateOp, why), now)
	}
	return why
}

func coderBase(spec harnessSpec) map[string]any {
	res := map[string]any{"mode": "coder", "coder_op": spec.CoderOp}
	if spec.RunID != "" {
		res["run_id"] = spec.RunID
	}
	return res
}

func coderFail(res map[string]any, reason, msg string) ([]byte, int) {
	res["ok"] = false
	if reason != "" {
		res["reason"] = reason
	}
	res["error"] = msg
	b, _ := json.Marshal(res)
	return b, 1
}

// runCoder dispatches one coder job. spec.owner is the pairing it arrived on.
func runCoder(spec harnessSpec) ([]byte, int) {
	switch spec.CoderOp {
	case "run-up":
		return coderRunUp(spec)
	case "run-down":
		return coderRunDown(spec)
	case "run-status":
		return coderRunStatus(spec)
	}
	return coderFail(coderBase(spec), "", "coder_op must be run-up, run-down or run-status")
}

// coderHostReady is the part of run-up that does not depend on the request:
// the machine can run coders at all. Also the heartbeat's honesty check.
func coderHostReady() (string, string) {
	if coderGOOS != "linux" {
		return "", "coder runs need a Linux machine"
	}
	if !coderIsRoot() {
		return "", "coder runs need the bastion running as root (the run's files are handed to the engine's own uid)"
	}
	rt := coderRuntime()
	if rt == "" {
		return "", "no container runtime (docker/podman/nerdctl) on this machine"
	}
	return rt, ""
}

func coderRunUp(spec harnessSpec) ([]byte, int) {
	res := coderBase(spec)
	rt, why := coderHostReady()
	if why != "" {
		return coderFail(res, "", why)
	}
	res["runtime"] = rt
	cfg := loadCoderConfig()
	if !cfg.ready() {
		return coderFail(res, "", "coder runs are off on this machine (`privatae-bastion coders on`)")
	}
	if !cfg.allowsEngine(spec.Engine) {
		return coderFail(res, "", "engine '"+spec.Engine+"' is not allowed on this machine")
	}
	var grantMax *int
	if currentAnchor() != nil {
		g, gwhy := coderGrantFor(spec.dcnDir, spec.owner)
		if gwhy != "" {
			return coderFail(res, "", gwhy)
		}
		if !containsStr(g.Engines, spec.Engine) {
			return coderFail(res, "", "engine '"+spec.Engine+"' is not in this host's coder grant")
		}
		m := g.Max
		grantMax = &m
	}
	if why := validateCoderUp(spec); why != "" {
		return coderFail(res, "", why)
	}
	if why := coderTransportRefusal(spec.owner); why != "" {
		return coderFail(res, "", why)
	}

	// Reserve a slot and a port, or answer full. The answer is a capacity
	// answer: ok:true, exit 0, never noteRefusal.
	coderMu.Lock()
	recs := loadCoderRecords()
	if _, busy := coderStarting[spec.RunID]; busy || coderHasRecord(recs, spec.RunID) || coderContainerExists(rt, spec.RunID) {
		coderMu.Unlock()
		return coderFail(res, "run_exists", "a run with this run_id is already on this machine")
	}
	all, mine := coderCountsLocked(spec.owner, recs)
	total, avail, memOK := coderMemInfo()
	availMB, budget := int(avail>>20), coderBudgetMB(int(total>>20))
	committed := coderCommittedLocked(recs, cfg.MemPerRun)
	pressure, psiOK := coderPSIMem()
	// Memory: free memory now is not enough, because runs that started
	// together all see the same free memory before any of them has grown. So
	// this run's limit must also fit in the budget beside the limits already
	// promised, and the machine must not be stalling on memory already.
	memFull := memOK && (availMB < cfg.MemPerRun || committed+cfg.MemPerRun > budget)
	pressured := psiOK && pressure >= coderPressureLimit
	full := all >= cfg.Max || (grantMax != nil && mine >= *grantMax) || memFull || pressured
	port := 0
	if !full {
		port = allocCoderPortLocked(recs)
		full = port == 0
	}
	if full {
		coderMu.Unlock()
		res["ok"], res["started"], res["reason"] = true, false, "full"
		res["max"], res["running"], res["running_mine"] = cfg.Max, all, mine
		res["mem_avail_mb"], res["mem_budget_mb"], res["mem_pressure"] = nil, nil, nil
		res["mem_committed_mb"] = committed
		if memOK {
			res["mem_avail_mb"], res["mem_budget_mb"] = availMB, budget
		}
		if psiOK {
			res["mem_pressure"] = round2(pressure)
		}
		b, _ := json.Marshal(res)
		return b, 0
	}
	coderStarting[spec.RunID] = coderReservation{owner: spec.owner, port: port, memMB: cfg.MemPerRun}
	coderMu.Unlock()
	defer func() {
		coderMu.Lock()
		delete(coderStarting, spec.RunID)
		coderMu.Unlock()
	}()

	pullS, runImage, err := coderPullImage(rt, spec)
	if err != nil {
		return coderFail(res, "pull_failed", truncate(err.Error(), 220))
	}
	spec.runImage = runImage
	if runImage != spec.Image {
		res["local_image_id"] = runImage
	}
	res["pull_s"] = pullS
	return coderStart(rt, spec, cfg, port, pullS, res)
}

// coderPullImage makes the run's image present and returns what to start the
// container from. It skips the pull when the digest is already here, or when
// the image was built or loaded on this machine and is here by its ID
// (coderLocalImage). Otherwise it pulls with a throwaway config dir that holds
// only this run's credential, so the pull never reads (or writes) the
// machine's own registry logins.
func coderPullImage(rt string, spec harnessSpec) (float64, string, error) {
	if _, err := coderRun(30*time.Second, rt, "image", "inspect", spec.Image); err == nil {
		return 0, spec.Image, nil
	}
	if id := coderLocalImage(rt, spec.Image); id != "" {
		return 0, id, nil
	}
	pullS, err := coderPullImageFromRegistry(rt, spec)
	return pullS, spec.Image, err
}

// coderLocalImage is the image ID to start a run from when its image
// (<repo>@sha256:<d>, already validated) was built or loaded on this machine,
// or "" when it is not here that way.
//
// WHY. Docker's classic image store records a repo digest only for an image
// pulled from or pushed to a registry. Measured on Docker 29.1.3 with the
// containerd snapshotter off: after `docker load` and after `docker build`,
// RepoDigests is empty, `inspect <repo>@sha256:<id>` fails, and `run` of that
// reference tries to pull. The containerd image store does record one (the
// same version with it on), so there the inspect in coderPullImage answers.
//
// THE RULE. The runtime's image whose ID is exactly sha256:<d>, and which
// carries a tag of <repo>. The ID is the digest of the image's config, which
// names every layer by the digest of its content, so it pins the content as a
// manifest digest does. The tag keeps the owner's prefix deciding what may
// run: the ID of some other image on this machine is never enough. The run
// is then started from the ID, which no tag moved after this check changes.
func coderLocalImage(rt, image string) string {
	repo, digest, ok := strings.Cut(image, "@")
	if !ok || !coderDigestRe.MatchString(digest) {
		return ""
	}
	out, err := coderRun(30*time.Second, rt, "image", "inspect", "--format", "{{.Id}}|{{json .RepoTags}}", digest)
	if err != nil {
		return ""
	}
	id, tagsJSON, ok := strings.Cut(strings.TrimSpace(out), "|")
	// podman prints the ID without its "sha256:".
	if !ok || (id != digest && "sha256:"+id != digest) {
		return ""
	}
	var tags []string
	if json.Unmarshal([]byte(tagsJSON), &tags) != nil {
		return ""
	}
	for _, t := range tags {
		if coderTagRepo(t) == repo {
			return digest
		}
	}
	return ""
}

// coderTagRepo is the repository of "repo:tag": the tag is after the last ':'
// that follows the last '/', so a registry's port stays in the repository.
func coderTagRepo(t string) string {
	slash := strings.LastIndex(t, "/")
	if i := strings.LastIndex(t, ":"); i > slash {
		return t[:i]
	}
	return t
}

// coderPullImageFromRegistry is the pull itself.
func coderPullImageFromRegistry(rt string, spec harnessSpec) (float64, error) {
	d, err := codersDir()
	if err != nil {
		return 0, err
	}
	dir := filepath.Join(d, "pull-"+spec.RunID)
	_ = os.RemoveAll(dir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	auths := map[string]any{}
	if p := spec.Pull; p != nil {
		auths[p.Registry] = map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))}
	}
	authJSON, _ := json.Marshal(map[string]any{"auths": auths})
	start := coderNow()
	var out string
	switch rt {
	case "podman":
		f := filepath.Join(dir, "auth.json")
		if err := os.WriteFile(f, authJSON, 0o600); err != nil {
			return 0, err
		}
		out, err = coderRun(coderPullTimeout, rt, "pull", "--authfile", f, spec.Image)
	case "nerdctl":
		if err := os.WriteFile(filepath.Join(dir, "config.json"), authJSON, 0o600); err != nil {
			return 0, err
		}
		out, err = coderRunEnv(coderPullTimeout, []string{"DOCKER_CONFIG=" + dir}, rt, "pull", spec.Image)
	default:
		if err := os.WriteFile(filepath.Join(dir, "config.json"), authJSON, 0o600); err != nil {
			return 0, err
		}
		out, err = coderRun(coderPullTimeout, rt, "--config", dir, "pull", spec.Image)
	}
	if err != nil {
		if p := spec.Pull; p != nil && p.Password != "" {
			out = strings.ReplaceAll(out, p.Password, "<password>")
		}
		return 0, fmt.Errorf("%s", strings.TrimSpace(out))
	}
	return round2(coderNow().Sub(start).Seconds()), nil
}

// coderWriteSeccomp writes the embedded profile when it is missing or differs.
func coderWriteSeccomp() (string, error) {
	d, err := codersDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, coderSeccompFile)
	if b, err := os.ReadFile(p); err == nil && sha256.Sum256(b) == sha256.Sum256(coderSeccompProfile) {
		_ = os.Chmod(p, 0o644)
		return p, nil
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, coderSeccompProfile, 0o644); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return "", err
	}
	return p, os.Rename(tmp, p)
}

// coderMkdirOwned makes one directory handed to the engine's uid, 0700.
func coderMkdirOwned(p string, uid int) error {
	if err := os.MkdirAll(p, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(p, 0o700); err != nil {
		return err
	}
	return coderChown(p, uid, uid)
}

// coderArgs is the container's command line, exactly as the contract states.
func coderArgs(spec harnessSpec, cfg coderConfig, R, seccomp, deadline string) []string {
	mem := strconv.Itoa(cfg.MemPerRun) + "m"
	args := []string{"run", "-d", "--name", coderContainerPrefix + spec.RunID,
		"--label", coderLabelRun + "=" + spec.RunID,
		"--label", coderLabelOwner + "=" + spec.owner,
		"--label", coderLabelEngine + "=" + spec.Engine,
		"--label", coderLabelDeadline + "=" + deadline,
		"--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + seccomp,
		"--read-only", "--user", strconv.Itoa(spec.UID) + ":" + strconv.Itoa(spec.UID),
		"--memory", mem, "--memory-swap", mem,
		"--cpus", strconv.FormatFloat(cfg.CPUsPerRun, 'f', -1, 64),
		// CPU: the lowest share there is (cgroup v2 cpu.weight 1, measured
		// on runc 1.3; the machine's own services sit at the default 100),
		// as the kubelet gives a BestEffort pod. A run may use any CPU
		// nothing else wants, up to --cpus, and yields it the moment the
		// Host, sshd or anything else on the machine needs it.
		"--cpu-shares", "2",
		"--pids-limit", "4096",
		"--tmpfs", "/tmp:rw,nosuid,nodev,exec,mode=1777,size=" + mem,
		"-v", filepath.Join(R, "work") + ":" + coderWorkspaceIn,
		"-v", filepath.Join(R, "home") + ":" + coderHomeIn,
		"-v", filepath.Join(R, "ctl") + ":" + coderCtlDirIn,
		"-v", filepath.Join(R, "egress") + ":" + coderEgressDirIn + ":ro",
		"-e", "SKEMA_APP_ID=" + spec.Engine,
		"-e", "PRIVATAE_RUN_ID=" + spec.RunID,
		"-e", "HOME=" + coderHomeIn,
		"-e", "SKEMA_WORKSPACE=" + coderWorkspaceIn,
		"-e", "PRIVATAE_HARNESS_CAP=" + spec.ControlCap,
		"-e", "PRIVATAE_HARNESS_CAP_ENFORCE=1",
		"-e", "PRIVATAE_SIDECAR_CONTROL_SOCK=" + coderCtlDirIn + "/" + coderControlSock,
		"-e", "PRIVATAE_SIDECAR_EGRESS_SOCK=" + coderEgressDirIn + "/" + coderEgressSock,
		// GPU: none. A run gets no --gpus and no --device, and where NVIDIA's
		// runtime is the default one, "void" makes it behave like runc and
		// expose no GPU, even for an image built on a CUDA base, which
		// sets NVIDIA_VISIBLE_DEVICES=all.
		"-e", "NVIDIA_VISIBLE_DEVICES=void",
	}
	for _, n := range coderNvidiaSwarmEnv() {
		args = append(args, "-e", n+"=void")
	}
	img := spec.Image
	if spec.runImage != "" {
		img = spec.runImage // a local image, by its ID (coderLocalImage)
	}
	return append(args, img)
}

// coderNvidiaSwarmEnv is every variable name the machine's NVIDIA toolkit
// config lists in swarm-resource. The toolkit reads those names in place of
// NVIDIA_VISIBLE_DEVICES whenever the container sets one of them, so an image
// that set one would get GPUs past NVIDIA_VISIBLE_DEVICES=void. The toolkit
// ships the setting commented out, with DOCKER_RESOURCE_GPU as its example
// value, for Docker Swarm. A run sets each listed name to "void" itself, and
// the run's value replaces the image's. No config, or no such setting, adds
// nothing.
func coderNvidiaSwarmEnv() []string {
	b, err := os.ReadFile(coderNvidiaConfig)
	if err != nil {
		return nil
	}
	var names []string
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok || strings.TrimSpace(k) != "swarm-resource" {
			continue // "#swarm-resource = ..." is the commented-out default
		}
		v, _, _ = strings.Cut(v, "#")
		for _, n := range strings.Split(strings.Trim(strings.TrimSpace(v), `"'`), ",") {
			if n = strings.TrimSpace(n); coderEnvNameRe.MatchString(n) && !containsStr(names, n) {
				names = append(names, n)
			}
		}
	}
	return names
}

func coderStart(rt string, spec harnessSpec, cfg coderConfig, port int, pullS float64, res map[string]any) ([]byte, int) {
	R, err := coderRunDir(spec.RunID)
	if err != nil {
		return coderFail(res, "start_failed", "no run directory: "+err.Error())
	}
	cname := coderContainerPrefix + spec.RunID
	started := false
	cleanup := func() {
		if started {
			_, _ = coderRun(30*time.Second, rt, "rm", "-f", cname)
		}
		coderCloseEgress(spec.RunID)
		_ = os.RemoveAll(R)
	}
	fail := func(msg string) ([]byte, int) {
		cleanup()
		return coderFail(res, "start_failed", truncate(msg, 220))
	}
	_ = os.RemoveAll(R)
	if err := os.MkdirAll(R, 0o700); err != nil {
		return fail("run directory: " + err.Error())
	}
	for _, sub := range []string{"work", "home", "ctl"} {
		if err := coderMkdirOwned(filepath.Join(R, sub), spec.UID); err != nil {
			return fail("run directory: " + err.Error())
		}
	}
	credDir := filepath.Join(R, "home", filepath.Base(spec.CredsDir))
	if err := coderMkdirOwned(credDir, spec.UID); err != nil {
		return fail("creds directory: " + err.Error())
	}
	names := make([]string, 0, len(spec.Creds))
	for n := range spec.Creds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := filepath.Join(credDir, n)
		if err := os.WriteFile(f, []byte(spec.Creds[n]), 0o600); err != nil {
			return fail("creds file: " + err.Error())
		}
		if err := os.Chmod(f, 0o600); err != nil {
			return fail("creds file: " + err.Error())
		}
		if err := coderChown(f, spec.UID, spec.UID); err != nil {
			return fail("creds file: " + err.Error())
		}
	}
	egDir := filepath.Join(R, "egress")
	if err := os.MkdirAll(egDir, 0o755); err != nil {
		return fail("egress directory: " + err.Error())
	}
	_ = os.Chmod(egDir, 0o755)
	if err := coderListenEgress(spec.RunID, egDir, spec.UID); err != nil {
		return fail("egress proxy: " + err.Error())
	}
	seccomp, err := coderWriteSeccomp()
	if err != nil {
		return fail("seccomp profile: " + err.Error())
	}
	maxMin := spec.MaxMinutes
	if maxMin == 0 {
		maxMin = coderDefaultMins
	}
	now := coderNow().UTC()
	deadline := now.Add(time.Duration(maxMin)*time.Minute + coderDeadlineSlop).Format(time.RFC3339)
	t0 := coderNow()
	out, err := coderRun(60*time.Second, rt, coderArgs(spec, cfg, R, seccomp, deadline)...)
	if err != nil {
		started = coderContainerExists(rt, spec.RunID)
		return fail("run failed: " + out)
	}
	started = true
	if err := coderWaitUp(rt, cname, filepath.Join(R, "ctl", coderControlSock), spec.UID, coderStartWait); err != nil {
		return fail(err.Error())
	}
	rec := &coderRecord{RunID: spec.RunID, Owner: spec.owner, Engine: spec.Engine, Image: spec.Image,
		Container: cname, TunnelPort: port, UID: spec.UID, CreatedAt: now.Format(time.RFC3339),
		Deadline: deadline, PullS: pullS, MemMB: cfg.MemPerRun, Cgroup: coderCgroupOf(rt, cname)}
	coderMu.Lock()
	err = saveCoderRecord(R, rec)
	coderMu.Unlock()
	if err != nil {
		return fail("could not record the run, so it was removed: " + err.Error())
	}
	// A Host on this machine reaches the run through a socket in its runs
	// directory (coder_socket.go), open before this answer goes back.
	sock, err := coderOpenRunSocket(spec.owner, spec.RunID)
	if err != nil {
		return fail("could not open the run's control socket, so it was removed: " + err.Error())
	}
	if sock != "" {
		res["control_socket"] = sock
	}
	res["ok"], res["started"] = true, true
	res["container"], res["tunnel_port"] = cname, port
	res["pull_s"], res["start_s"] = pullS, round2(coderNow().Sub(t0).Seconds())
	res["deadline"], res["ran_on"] = deadline, orUnknown(hostnameSafe())
	b, _ := json.Marshal(res)
	return b, 0
}

// coderWaitHealthy waits for the sidecar to create its control socket, owned
// by the engine's uid, then asks /health over it. A container that stops
// running on the way is a failure at once, not after the full wait.
func coderWaitHealthy(rt, cname, sock string, uid int, within time.Duration) error {
	deadline := time.Now().Add(within)
	lastCheck := time.Time{}
	for time.Now().Before(deadline) {
		if owner, isSock := coderSocketOwner(sock); isSock && owner == uid {
			if err := coderHealth(sock, uid); err == nil {
				return nil
			}
		}
		if time.Since(lastCheck) > 2*time.Second {
			lastCheck = time.Now()
			if coderContainerState(rt, cname) != "running" {
				return errors.New("the container stopped before it answered /health")
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("the container did not answer /health on its control socket within 60 s")
}

// coderDialControl connects to a run's control socket, pinned to the inode
// and only when the far end is the engine's uid (the spliceUnix walls).
func coderDialControl(sock string, uid int) (net.Conn, error) {
	c, err := serviceDialSocket(sock, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if got, err := servicePeerUID(c); err != nil || int(got) != uid {
		_ = c.Close()
		return nil, errors.New("the control socket is not the engine's")
	}
	return c, nil
}

func coderHealth(sock string, uid int) error {
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return coderDialControl(sock, uid) },
	}}
	resp, err := cl.Get("http://run/health")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("/health answered %d", resp.StatusCode)
	}
	return nil
}

// coderContainerState is running | exited | missing.
func coderContainerState(rt, cname string) string {
	out, err := coderRun(10*time.Second, rt, "inspect", "-f", "{{.State.Running}}", cname)
	if err != nil {
		return "missing"
	}
	if strings.TrimSpace(out) == "true" {
		return "running"
	}
	return "exited"
}

func coderContainerExists(rt, runID string) bool {
	_, err := coderRun(10*time.Second, rt, "inspect", "-f", "{{.Id}}", coderContainerPrefix+runID)
	return err == nil
}

// coderContainerGone is true only when the runtime says the container does not
// exist. Any other failure is unknown, never absence (serviceContainerGone).
func coderContainerGone(rt, cname string) bool {
	out, err := coderRun(10*time.Second, rt, "inspect", "-f", "{{.Id}}", cname)
	if err == nil {
		return false
	}
	o := strings.ToLower(out)
	return strings.Contains(o, "no such") || strings.Contains(o, "not found")
}

// ── run-down ────────────────────────────────────────────────────────────────

// coderOwnerRefusal: only the pairing that started a run may stop it, or the
// anchor pairing on an anchored box (serviceOwnerRefusal's rule).
// An unknown owner proves nothing about self, so it gets the anchor-only rule
// too: every run this bastion starts records and labels its owner.
//
// A local machine has no anchor, so anchorOnly lets every pairing through
// there; once it serves several Hosts (localServesSeveralHosts), each stops
// only the runs it started, as with the servers each built.
func coderOwnerRefusal(self, owner string) string {
	if owner != "" && owner == self {
		return ""
	}
	if localServesSeveralHosts() {
		return "refused: that run was started by " + orUnknown(owner) + "; on a local machine that serves several Hosts each stops only the runs it started"
	}
	if why := anchorOnly(self, "stopping a run another host started"); why != "" {
		return "refused: that run was started by " + orUnknown(owner) + "; " + why
	}
	return ""
}

func coderRunDown(spec harnessSpec) ([]byte, int) {
	res := coderBase(spec)
	if !coderRunIDRe.MatchString(spec.RunID) {
		return coderFail(res, "", "run_id is not a valid run id")
	}
	rt := coderRuntime()
	rec, _ := loadCoderRecord(spec.RunID)
	owner := ""
	notFound := func() ([]byte, int) {
		res["ok"], res["stopped"], res["reason"] = true, false, "not_found"
		b, _ := json.Marshal(res)
		return b, 0
	}
	if rec != nil {
		owner = rec.Owner
	} else {
		cname := coderContainerPrefix + spec.RunID
		if rt == "" || coderContainerGone(rt, cname) {
			return notFound()
		}
		// No record: only the container's own labels say whose run it is. A
		// container that merely has the name, without this run's label, is
		// not a coder run and run-down never stops it.
		run, err := coderLabelErr(rt, cname, coderLabelRun)
		if err != nil {
			return coderFail(res, "", "the runtime could not say whose container "+cname+" is; nothing was changed")
		}
		if run != spec.RunID {
			return notFound()
		}
		owner = coderLabel(rt, cname, coderLabelOwner)
	}
	if why := coderOwnerRefusal(spec.owner, owner); why != "" {
		return coderFail(res, "", why)
	}
	if rt == "" {
		return coderFail(res, "", "no container runtime answers on this machine, so the run cannot be confirmed stopped; nothing was changed")
	}
	m, err := coderTeardown(rt, spec.RunID, rec)
	if err != nil {
		return coderFail(res, "", err.Error())
	}
	res["ok"], res["stopped"] = true, true
	for k, v := range m {
		res[k] = v
	}
	res["stopped_by"] = nil
	if rec != nil && rec.StoppedBy != "" {
		res["stopped_by"] = rec.StoppedBy
	}
	b, _ := json.Marshal(res)
	return b, 0
}

func coderLabel(rt, cname, key string) string {
	v, _ := coderLabelErr(rt, cname, key)
	return v
}

// coderLabelErr is one label of a container; "" when it is not set, an error
// when the runtime did not answer.
func coderLabelErr(rt, cname, key string) (string, error) {
	out, err := coderRun(10*time.Second, rt, "inspect", "-f", "{{index .Config.Labels \""+key+"\"}}", cname)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(out)
	if v == "<no value>" {
		return "", nil
	}
	return v, nil
}

// coderTeardown is run-down without the reply: measure, stop, remove, confirm,
// then close the listeners and delete the run's files. The reaper calls it too.
// A container that cannot be confirmed gone keeps its record so the reaper
// retries.
func coderTeardown(rt, runID string, rec *coderRecord) (map[string]any, error) {
	cname := coderContainerPrefix + runID
	m := map[string]any{"peak_mem_bytes": nil, "cpu_s": nil, "oom_killed": nil, "exit_code": nil}
	peak, cpu := coderMeasure(rt, cname)
	if peak != nil {
		m["peak_mem_bytes"] = *peak
	}
	if cpu != nil {
		m["cpu_s"] = *cpu
	}
	// The start time lives only in the run record. Without it (run-down by
	// the container's labels, or a record with no readable created_at) the
	// wall time is not known: null, never 0.
	m["wall_s"] = nil
	if rec != nil {
		if t, err := time.Parse(time.RFC3339, rec.CreatedAt); err == nil {
			m["wall_s"] = round2(coderNow().Sub(t).Seconds())
		}
	}
	_, _ = coderRun(30*time.Second, rt, "stop", "-t", "10", cname)
	// One inspect per field: nerdctl's inspect has no State.OOMKilled and
	// fails the whole template that names it, so a joint template would
	// lose the exit code there too. On nerdctl oom_killed stays null.
	if out, err := coderRun(10*time.Second, rt, "inspect", "-f", "{{.State.ExitCode}}", cname); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil {
			m["exit_code"] = n
		}
	}
	if out, err := coderRun(10*time.Second, rt, "inspect", "-f", "{{.State.OOMKilled}}", cname); err == nil {
		if b, err := strconv.ParseBool(strings.TrimSpace(out)); err == nil {
			m["oom_killed"] = b
		}
	}
	if out, err := coderRun(30*time.Second, rt, "rm", "-f", cname); err != nil || !coderContainerGone(rt, cname) {
		if err == nil {
			out = "the runtime still lists it"
		}
		return nil, fmt.Errorf("could not remove the run's container; it may still be there: %s", truncate(out, 200))
	}
	m["egress_refused"] = coderCloseEgress(runID)
	coderMu.Lock()
	if R, err := coderRunDir(runID); err == nil {
		_ = os.RemoveAll(R)
	}
	coderMu.Unlock()
	// After the record is gone: a reconcile that read it before then and
	// opens the run's socket meanwhile has it closed here, and one that
	// opens later finds no record (coderOpenRunSocket).
	coderCloseRunSocket(runID)
	return m, nil
}

// coderMeasure reads the container's cgroup from the host side before it is
// stopped: memory.peak (bytes) and cpu.stat usage_usec (as seconds). Either
// is nil when it cannot be read — never 0, never estimated.
func coderMeasure(rt, cname string) (*int64, *float64) {
	dir := coderCgroupPath(coderCgroupOf(rt, cname))
	if dir == "" {
		return nil, nil
	}
	var peak *int64
	if b, err := os.ReadFile(filepath.Join(dir, "memory.peak")); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n >= 0 {
			peak = &n
		}
	}
	var cpu *float64
	if b, err := os.ReadFile(filepath.Join(dir, "cpu.stat")); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(ln)
			if len(f) == 2 && f[0] == "usage_usec" {
				if n, err := strconv.ParseInt(f[1], 10, 64); err == nil && n >= 0 {
					v := math.Round(float64(n)/1e6*1000) / 1000
					cpu = &v
				}
			}
		}
	}
	return peak, cpu
}

// coderCgroupOf is the container's cgroup as /proc/<pid>/cgroup names it
// (cgroup v2), "" when the runtime gives no pid, there is no v2 line, or the
// line does not name a cgroup that exists under coderCgroupFS.
//
// That last check matters on cgroup v1 and hybrid machines. There the "0::"
// line names a path in a v2 tree mounted elsewhere (or "/"), so the path is
// absent under coderCgroupFS. Recorded anyway, the run would read as stopped
// (coderRecordRunning), its memory would not count against the budget, and
// the watchdog would never stop it. Recorded as "", the run counts at its
// limit and the watchdog stops it through the runtime. The root cgroup is
// refused as well: it holds every process on the machine.
func coderCgroupOf(rt, cname string) string {
	out, err := coderRun(10*time.Second, rt, "inspect", "-f", "{{.State.Pid}}", cname)
	if err != nil {
		return ""
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || pid <= 0 {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(coderProcFS, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(ln, "0::") {
			continue
		}
		p := strings.TrimSpace(strings.TrimPrefix(ln, "0::"))
		dir := coderCgroupPath(p)
		if dir == "" || dir == filepath.Clean(coderCgroupFS) {
			return ""
		}
		if _, err := os.Stat(filepath.Join(dir, "cgroup.events")); err != nil {
			return ""
		}
		return p
	}
	return ""
}

// ── the watchdog ────────────────────────────────────────────────────────────

// coderGuard is what the watchdog remembers between rounds.
type coderGuard struct {
	overSince time.Time // when memory pressure went over the limit; zero while under it
	lastStop  time.Time
	lastRun   string // the run stopped at lastStop
}

// exiting is true while the run stopped last still has processes and has had
// under coderPressureSettle to exit. Its memory is not free until they exit,
// and on a machine short of memory a killed process can take more than one
// round to finish exiting. Stopping the next run then would stop two where
// one was enough. The kubelet likewise waits for an evicted pod to be cleaned
// up before it evicts another. Bounded by the settle time, so a run that
// never empties cannot hold the watchdog back for long.
func (g *coderGuard) exiting(recs []coderRecord, now time.Time) bool {
	if g.lastRun == "" || now.Sub(g.lastStop) >= coderPressureSettle {
		return false
	}
	for _, r := range recs {
		if r.RunID == g.lastRun {
			up, known := coderRecordRunning(r)
			return known && up
		}
	}
	return false
}

// coderWatch runs a watchdog round every 2 s for as long as the daemon runs.
func coderWatch(ctx context.Context) {
	g := &coderGuard{}
	t := time.NewTicker(coderWatchEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.round()
		}
	}
}

// round stops at most one run, the newest one still running, when this
// machine has under 100 MiB free, or when memory pressure has stayed over the
// limit for 30 s and the last stop has had 10 s to show. Run-up already keeps
// the runs' limits inside the budget, so this acts when something outside the
// runs grew into the machine's reserve. The newest run has done the least
// work, so stopping it loses the least.
//
// The run is killed through its cgroup (cgroup.kill), not through the
// container runtime, which can take minutes to answer on a machine that is
// short of memory. Its record stays, marked with why, so the Host's run-down
// reads what happened, and the reaper removes it like any stopped run.
func (g *coderGuard) round() (stopped, why string) {
	recs := loadCoderRecords()
	now := coderNow()
	p, psiOK := coderPSIMem()
	over := psiOK && p >= coderPressureLimit
	if !over {
		g.overSince = time.Time{}
	} else if g.overSince.IsZero() {
		g.overSince = now
	}
	if len(recs) == 0 {
		return "", ""
	}
	_, avail, memOK := coderMemInfo()
	availMB := int(avail >> 20)
	switch {
	case memOK && availMB < coderEvictFloorMB && g.exiting(recs, now):
		return "", ""
	case memOK && availMB < coderEvictFloorMB:
		why = fmt.Sprintf("this machine had %d MiB of memory free, under the %d MiB it keeps", availMB, coderEvictFloorMB)
	case over && now.Sub(g.overSince) >= coderPressureFor && now.Sub(g.lastStop) >= coderPressureSettle:
		why = fmt.Sprintf("this machine stalled on memory %.0f%% of the time for %s (the limit is %.0f%%)",
			p, coderPressureFor, coderPressureLimit)
	default:
		return "", ""
	}
	created := func(r coderRecord) time.Time {
		t, _ := time.Parse(time.RFC3339, r.CreatedAt)
		return t
	}
	sort.SliceStable(recs, func(i, j int) bool {
		ti, tj := created(recs[i]), created(recs[j])
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return recs[i].RunID > recs[j].RunID
	})
	rt := ""
	for _, r := range recs {
		if r.StoppedBy != "" {
			continue
		}
		if up, known := coderRecordRunning(r); known && !up {
			continue
		}
		if !coderKillCgroup(r.Cgroup) {
			if rt == "" {
				if rt = coderRuntime(); rt == "" {
					return "", ""
				}
			}
			if r.Cgroup == "" && coderContainerState(rt, r.Container) != "running" {
				continue
			}
			if _, err := coderRun(30*time.Second, rt, "kill", r.Container); err != nil {
				continue
			}
		}
		g.lastStop, g.lastRun = now, r.RunID
		coderMu.Lock()
		if R, err := coderRunDir(r.RunID); err == nil {
			if cur, err := loadCoderRecord(r.RunID); err == nil {
				cur.StoppedBy = why
				_ = coderRewriteRecord(R, cur)
			}
		}
		coderMu.Unlock()
		// A stopped run's control plane is gone with it: its socket, if a
		// Host on this machine owns it, is removed now, not at run-down.
		coderCloseRunSocket(r.RunID)
		fmt.Printf("coders: stopped run %s to protect this machine: %s\n", r.RunID, why)
		return r.RunID, why
	}
	return "", ""
}

// coderKillCgroup kills every process in a run's cgroup at once (cgroup.kill,
// Linux 5.14 and later). false when there is no cgroup to kill this way.
func coderKillCgroup(cg string) bool {
	dir := coderCgroupPath(cg)
	if dir == "" {
		return false
	}
	// Never O_CREATE: on an older kernel the file is absent, not to be made.
	f, err := os.OpenFile(filepath.Join(dir, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_, err = f.WriteString("1")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err == nil
}

// ── run-status ──────────────────────────────────────────────────────────────

func coderIsAnchor(self string) bool {
	a := currentAnchor()
	return a != nil && a.AnchorHost == self
}

type coderRunReport struct {
	RunID      string `json:"run_id"`
	Engine     string `json:"engine"`
	Container  string `json:"container"`
	TunnelPort int    `json:"tunnel_port"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	Deadline   string `json:"deadline"`
	StoppedBy  string `json:"stopped_by,omitempty"`
}

func coderReports(self string, all bool) []coderRunReport {
	recs := loadCoderRecords()
	out := []coderRunReport{}
	if len(recs) == 0 {
		return out
	}
	rt := coderRuntime()
	for _, r := range recs {
		if !all && r.Owner != self {
			continue
		}
		st := "missing"
		if rt != "" {
			st = coderContainerState(rt, r.Container)
		}
		out = append(out, coderRunReport{RunID: r.RunID, Engine: r.Engine, Container: r.Container,
			TunnelPort: r.TunnelPort, State: st, CreatedAt: r.CreatedAt, Deadline: r.Deadline, StoppedBy: r.StoppedBy})
	}
	return out
}

func coderRunStatus(spec harnessSpec) ([]byte, int) {
	res := coderBase(spec)
	res["ok"] = true
	res["runs"] = coderReports(spec.owner, coderIsAnchor(spec.owner))
	b, _ := json.Marshal(res)
	return b, 0
}

// ── heartbeat ───────────────────────────────────────────────────────────────

// coderHeartbeat is the `coders` capability block for pairing self, or nil
// when ANY of the conditions fails: Linux, root, coders on, a runtime, the
// pairing may be asked for mode:coder, and (anchored) it holds a valid coder
// grant. Never sent empty. The cheap checks run first, so a machine with
// coders off never runs its container runtime for a heartbeat.
func coderHeartbeat(self string) map[string]any {
	if coderGOOS != "linux" || !coderIsRoot() {
		return nil
	}
	cfg := loadCoderConfig()
	if !cfg.ready() {
		return nil
	}
	if capsAllow(self, coderGateOp) != "" {
		return nil
	}
	var grantMax any
	if currentAnchor() != nil {
		g, why := coderGrantFor(coderDcnDirFor(self), self)
		if why != "" {
			return nil
		}
		grantMax = g.Max
	}
	rt := coderRuntime()
	if rt == "" {
		return nil
	}
	recs := loadCoderRecords()
	coderMu.Lock()
	all, mine := coderCountsLocked(self, recs)
	coderMu.Unlock()
	total, avail, ok := coderMemInfo()
	var memTotal, memAvail, memBudget any
	if ok {
		memTotal, memAvail, memBudget = int(total>>20), int(avail>>20), coderBudgetMB(int(total>>20))
	}
	return map[string]any{
		"max": cfg.Max, "running": all, "running_mine": mine, "grant_max": grantMax,
		"mem_per_run_mb": cfg.MemPerRun, "cpus_per_run": cfg.CPUsPerRun,
		"mem_total_mb": memTotal, "mem_avail_mb": memAvail, "mem_budget_mb": memBudget,
		"cpus": runtime.NumCPU(), "arch": runtime.GOARCH, "runtime": rt,
		"engines": append([]string(nil), cfg.Engines...),
	}
}

// coderDcnDirFor is the grant directory of pairing self, "" when unknown.
func coderDcnDirFor(self string) string {
	cfgs, err := loadPairings()
	if err != nil {
		return ""
	}
	if c := pairingFor(cfgs, self); c != nil && c.HostName == self {
		return c.dcnDir()
	}
	return ""
}

// ── the box-wide loop and the reaper ────────────────────────────────────────

var coderInitOnce sync.Once

// coderInit starts the box-wide coder loop once per daemon: it re-opens the
// egress proxy for runs that outlived a restart, closes it for runs whose
// record is gone (a `coders drop` from the CLI), reaps once at start, and
// runs the watchdog (coderWatch). A machine that never used coder mode does
// nothing here: no files, no runtime.
func coderInit(ctx context.Context) {
	coderInitOnce.Do(func() {
		go func() {
			go coderWatch(ctx)
			coderReconcileEgress()
			coderReap("", nil, false)
			t := time.NewTicker(serviceForwardPoll)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					coderReconcileEgress()
				}
			}
		}()
	})
}

// coderMisses counts, per run, consecutive heartbeat replies from its owner
// that carried coder_runs and did not list it.
//
// coderStoppedSeen holds, per run, when the reaper first saw it not running
// without an exit time from the runtime: a record whose container is missing,
// or a runtime that keeps no exit time for it. It is held in memory, not in
// the run record: the reaper reads it on every heartbeat, and a daemon restart
// that loses it only restarts that run's 600 s grace, which delays a reap and
// never brings one forward. It also holds the first sighting of a run whose
// exit time was after now (the clock stepped back); coderExitAhead keeps that
// exit time, so the count stays on the first sighting once the clock passes
// it.
var (
	coderReapMu      sync.Mutex
	coderMisses      = map[string]int{}
	coderStoppedSeen = map[string]time.Time{}
	coderExitAhead   = map[string]time.Time{}
)

// coderHeartbeatReply reads `coder_runs` from one pairing's heartbeat reply
// and runs the reaper. An absent key is no information: only the deadline and
// the other local rules apply.
func coderHeartbeatReply(self string, body []byte) {
	var hb struct {
		CoderRuns *[]string `json:"coder_runs"`
	}
	if json.Unmarshal(body, &hb) != nil || hb.CoderRuns == nil {
		coderReap(self, nil, false)
		return
	}
	coderReap(self, *hb.CoderRuns, true)
}

type coderSeen struct {
	runID, owner, deadline string
	running                bool
	created                time.Time
	finished               time.Time // the runtime's exit time; zero when it gave none
}

// coderStoppedGrace is how long an exited or missing run is kept after it
// stopped, so the Host's run-down can still read its exit code and OOM flag.
const coderStoppedGrace = 600 * time.Second

// coderReap removes a coder container (run-down without a reply) when it is
// past its deadline, its owner pairing no longer exists, it has been exited or
// missing for more than 600 s, or it is older than 120 s and two consecutive
// replies from its owner that carried coder_runs left it out. The 600 s count
// from the runtime's exit time; when the runtime gives none (the container is
// missing, or the runtime keeps no exit time) or one after now (the clock
// stepped back), from when this daemon first saw the run not running; that
// exit time keeps counting from the first sighting after the clock passes
// it. Deadlines, owners and creation times are rebuilt from the containers'
// labels and the records on every round, so they survive a restart; the
// first-seen time does not (coderStoppedSeen).
func coderReap(replyFrom string, listed []string, hasKey bool) {
	recs := loadCoderRecords()
	if len(recs) == 0 && !loadCoderConfig().Enabled {
		return
	}
	coderReapMu.Lock()
	defer coderReapMu.Unlock()
	rt := coderRuntime()
	if rt == "" {
		return
	}
	now := coderNow()
	listedNow, ok := coderListContainers(rt)
	if !ok {
		// The runtime did not answer (a slow daemon under many runs): no
		// information, never "everything exited". Next round retries.
		return
	}
	seen := map[string]*coderSeen{}
	for _, c := range listedNow {
		c := c
		seen[c.runID] = &c
	}
	byID := map[string]*coderRecord{}
	for i := range recs {
		r := &recs[i]
		byID[r.RunID] = r
		s, ok := seen[r.RunID]
		if !ok {
			s = &coderSeen{runID: r.RunID}
			seen[r.RunID] = s
		}
		if s.owner == "" {
			s.owner = r.Owner
		}
		// The earlier of the label's and the record's deadline applies.
		if s.deadline == "" || coderBefore(r.Deadline, s.deadline) {
			s.deadline = r.Deadline
		}
		if t, err := time.Parse(time.RFC3339, r.CreatedAt); err == nil && (s.created.IsZero() || t.Before(s.created)) {
			s.created = t
		}
	}
	cfgs, _ := loadPairings()
	listedSet := map[string]bool{}
	for _, id := range listed {
		listedSet[id] = true
	}
	coderMu.Lock()
	starting := map[string]bool{}
	for id := range coderStarting {
		starting[id] = true
	}
	coderMu.Unlock()
	for id, s := range seen {
		if starting[id] {
			continue // a run-up in progress owns it
		}
		age := time.Duration(-1)
		if !s.created.IsZero() {
			age = now.Sub(s.created)
		}
		// How long the run has been exited or missing; -1 while it runs.
		stopped := time.Duration(-1)
		if s.running {
			delete(coderStoppedSeen, id)
			delete(coderExitAhead, id)
		} else {
			// An exit time after now (the clock stepped back) counts as
			// none: the run has exited by now, so counting from when this
			// daemon first saw it stopped never reaps it early. Read as a
			// negative time stopped, it would hold the run for the skew;
			// so would counting from it once the clock passes it, hence
			// coderExitAhead remembers it.
			since := s.finished
			if since.After(now) {
				coderExitAhead[id] = since
			}
			if ahead, ok := coderExitAhead[id]; ok && !ahead.Equal(since) {
				delete(coderExitAhead, id) // a different exit: its own time
			}
			if _, ahead := coderExitAhead[id]; since.IsZero() || ahead {
				first, ok := coderStoppedSeen[id]
				if !ok {
					first = now
					coderStoppedSeen[id] = now
				}
				since = first
			}
			stopped = now.Sub(since)
		}
		if hasKey && s.owner == replyFrom {
			if listedSet[id] {
				delete(coderMisses, id)
			} else {
				coderMisses[id]++
			}
		}
		why := ""
		if dl, err := time.Parse(time.RFC3339, s.deadline); err == nil && now.After(dl) {
			why = "past its deadline"
		} else if s.owner != "" && cfgs != nil && pairingFor(cfgs, s.owner) == nil {
			why = "its host is no longer paired"
		} else if stopped > coderStoppedGrace {
			why = "it stopped more than 600 s ago (exited or missing)"
		} else if age > 120*time.Second && coderMisses[id] >= 2 {
			why = "its host no longer holds it"
		}
		if why == "" {
			continue
		}
		if _, err := coderTeardown(rt, id, byID[id]); err == nil {
			delete(coderMisses, id)
			delete(coderStoppedSeen, id)
			delete(coderExitAhead, id)
			fmt.Printf("coders: reaped run %s (%s)\n", id, why)
		}
	}
	for id := range coderMisses {
		if _, ok := seen[id]; !ok {
			delete(coderMisses, id)
		}
	}
	for id := range coderStoppedSeen {
		if _, ok := seen[id]; !ok {
			delete(coderStoppedSeen, id)
		}
	}
	for id := range coderExitAhead {
		if _, ok := seen[id]; !ok {
			delete(coderExitAhead, id)
		}
	}
}

// coderBefore: a parses as RFC 3339 and is before b (or b does not parse).
func coderBefore(a, b string) bool {
	ta, err := time.Parse(time.RFC3339, a)
	if err != nil {
		return false
	}
	tb, err := time.Parse(time.RFC3339, b)
	return err != nil || ta.Before(tb)
}

// coderListContainers lists every container carrying the coder label, from
// the runtime itself (the records may be gone). ok is false when the runtime
// did not answer: that is unknown, never an empty list.
func coderListContainers(rt string) ([]coderSeen, bool) {
	out, err := coderRun(15*time.Second, rt, "ps", "-aq", "--filter", "label="+coderLabelRun)
	if err != nil {
		return nil, false
	}
	ids := strings.Fields(out)
	if len(ids) == 0 {
		return nil, true
	}
	tmpl := `{{index .Config.Labels "` + coderLabelRun + `"}}|{{index .Config.Labels "` + coderLabelOwner +
		`"}}|{{index .Config.Labels "` + coderLabelDeadline + `"}}|{{.State.Running}}|{{.Created}}|{{.State.FinishedAt}}`
	got, err := coderRun(15*time.Second, rt, append([]string{"inspect", "-f", tmpl}, ids...)...)
	if err != nil {
		return nil, false
	}
	var res []coderSeen
	for _, ln := range strings.Split(strings.TrimSpace(got), "\n") {
		p := strings.SplitN(strings.TrimSpace(ln), "|", 6)
		if len(p) != 6 || !coderRunIDRe.MatchString(p[0]) {
			continue
		}
		s := coderSeen{runID: p[0], owner: p[1], deadline: p[2], running: p[3] == "true",
			created: coderInspectTime(p[4]), finished: coderInspectTime(p[5])}
		if s.owner == "<no value>" {
			s.owner = ""
		}
		res = append(res, s)
	}
	return res, true
}

// coderInspectTime reads a time the runtime's inspect template printed:
// RFC 3339 from docker and nerdctl, Go's time.Time String form from podman.
// Zero when it is empty, does not parse, or is the runtime's "never" (docker
// and podman print year 1 for a container that has not exited, which is Go's
// zero time; nerdctl prints nothing). podman's form ends in the zone's
// abbreviation, and a zone without one prints its offset there instead
// ("+0330 +0330" in Tehran, "+0545 +0545" in Kathmandu), which the MST
// layout does not take; the offset before it already fixes the instant, so
// the form is read again without that last word.
func coderInspectTime(v string) time.Time {
	v = strings.TrimSpace(v)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999 -0700 MST"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	if i := strings.LastIndexByte(v, ' '); i > 0 {
		if t, err := time.Parse("2006-01-02 15:04:05.999999999 -0700", v[:i]); err == nil {
			return t
		}
	}
	return time.Time{}
}

// runCmdEnv is runCmd with extra environment (nerdctl's DOCKER_CONFIG).
func runCmdEnv(timeout time.Duration, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
