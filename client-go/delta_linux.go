//go:build linux

package main

// The three things the noise filter needs from the platform: how old a process is,
// which processes hold a listening socket, and what the package database says
// about an executable. Linux can answer all three; delta_other.go answers none
// of them, and deltanoise.go treats "cannot answer" as "report it".

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// deltaClockTicks is the kernel's USER_HZ, which /proc/<pid>/stat's start time
// is counted in. Go exposes no sysconf(_SC_CLK_TCK), and the value has been 100
// on every mainstream Linux architecture since the 2.6 era — it is part of the
// /proc ABI rather than a tunable, because changing it would reinterpret every
// field userspace already reads.
//
// A wrong constant here would only ever mis-time the short-lived rule, which
// holds a finding for one pass. It cannot hide one.
const deltaClockTicks = 100

// deltaAgeReader reads the boot clock ONCE and returns the age function for
// this pass. Per-pid it is then a single small read of /proc/<pid>/stat.
func deltaAgeReader() func(int) (time.Duration, bool) {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return func(int) (time.Duration, bool) { return 0, false }
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return func(int) (time.Duration, bool) { return 0, false }
	}
	up, err := strconv.ParseFloat(f[0], 64)
	if err != nil || up <= 0 {
		return func(int) (time.Duration, bool) { return 0, false }
	}
	return func(pid int) (time.Duration, bool) {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			// GONE IS YOUNG, and the two used to be one answer. The filter runs
			// 50-100 ms after the walk — a parent map, the package database and
			// two `ss` execs later — so a process that exited in between is
			// unreadable here for the most ordinary reason there is. Treating
			// that as "cannot tell" reported the shortest-lived processes on the
			// box at warn instead of counting them, which is the exact
			// population the short-lived rule exists to keep out of the list.
			//
			// Anything else — a permission error, a /proc that cannot be read —
			// stays "cannot tell", which the caller treats as report-it.
			if os.IsNotExist(err) {
				return 0, true
			}
			return 0, false
		}
		ticks, ok := parseProcStatStartTicks(string(stat))
		if !ok {
			return 0, false
		}
		started := float64(ticks) / deltaClockTicks
		age := up - started
		if age < 0 {
			// The process started after the uptime read — this pass raced it.
			// Zero, not an error: it IS that young.
			age = 0
		}
		return time.Duration(age * float64(time.Second)), true
	}
}

// deltaListeningPIDs is the set of processes holding a listening socket, read
// through the observe plane's own socket reader so this and `observe:sockets`
// can never disagree about what is listening.
// deltaSockets is readSockets as a var so a test can hand this a partial table
// — the state a live `ss` timeout produces and nothing else can reproduce.
var deltaSockets = readSockets

func deltaListeningPIDs() (map[int]bool, bool) {
	r := deltaSockets()
	// PARTIAL IS UNREADABLE, by this file's own rule. readSockets returns
	// Supported with HALF a table when `ss` runs out of budget
	// (observe_ops_linux.go:160-168), and a half table would let the short-lived
	// rule check its listener exemption against a set that may simply not
	// contain the socket. An exemption that cannot be checked is not an
	// exemption.
	// A FAILED RUN JOINS THE PARTIAL ONE, for the same reason: `ss` exiting
	// non-zero yields an empty table that would silently answer "nothing is
	// listening".
	if !r.Supported || r.Partial != "" || r.Failed != "" {
		return nil, false
	}
	out := map[int]bool{}
	for _, s := range r.Sockets {
		if s.PID > 0 {
			out[s.PID] = true
		}
	}
	return out, true
}

// ── the package database ────────────────────────────────────────────────────

const dpkgInfoDir = "/var/lib/dpkg/info"

// deltaPackagedLookup answers, for the executables asked about, which ones dpkg
// owns and still matches byte for byte.
//
// IT IS AN MD5 COMPARISON BECAUSE THAT IS WHAT DPKG RECORDS. `dpkg -V` verifies
// against these same .md5sums files; there is no stronger digest in the
// database to check against. So a chosen-prefix collision against a
// distribution binary would earn a `known` tier here — and that is the whole
// prize, because this sets a TIER and never removes a finding: the level table drops a
// known-tier proc_new from warn to notice, and a process with a model endpoint
// or an agent signature stays high whatever the package database says
// (deltaLevel). The bound on being wrong is one level, not silence.
//
// Returns nil on a box with no dpkg database, which leaves every candidate at
// its undemoted level.
func deltaPackagedLookup(paths []string) map[string]string {
	files, err := filepath.Glob(filepath.Join(dpkgInfoDir, "*.md5sums"))
	if err != nil || len(files) == 0 {
		return nil
	}
	// The wanted paths, in dpkg's spelling (relative to /, no leading slash),
	// mapped back to what the caller asked about.
	want := map[string]string{}
	for _, p := range paths {
		for _, k := range dpkgPathForms(p) {
			want[k] = p
		}
	}
	type hit struct{ pkg, sum string }
	found := map[string]hit{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		pkg := strings.TrimSuffix(filepath.Base(f), ".md5sums")
		for _, line := range strings.Split(string(b), "\n") {
			// "<32 hex>  <path>" — two spaces, and the path may contain them.
			if len(line) < 34 {
				continue
			}
			sum, rest := line[:32], line[32:]
			rest = strings.TrimLeft(rest, " ")
			orig, ok := want[rest]
			if !ok {
				continue
			}
			if _, already := found[orig]; !already {
				found[orig] = hit{pkg: pkg, sum: strings.ToLower(sum)}
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	out := map[string]string{}
	for path, h := range found {
		if fileMD5(path) == h.sum {
			out[path] = h.pkg
		}
	}
	return out
}

// dpkgPathForms is the path as dpkg might have recorded it. THE /usr MERGE IS
// WHY THIS IS A LIST: the kernel reports /usr/bin/ls while a package built
// before the merge records bin/ls, and matching only one spelling would leave
// half a distribution's binaries reading as unowned — a filter that quietly
// stops filtering.
func dpkgPathForms(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	out := []string{p}
	switch {
	case strings.HasPrefix(p, "usr/"):
		out = append(out, strings.TrimPrefix(p, "usr/"))
	case strings.HasPrefix(p, "bin/"), strings.HasPrefix(p, "sbin/"), strings.HasPrefix(p, "lib/"):
		out = append(out, "usr/"+p)
	}
	return out
}

func fileMD5(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// deltaPackagedFn is nil where there is no package database to ask, which is
// what turns the rule off rather than having it answer "not packaged" about
// every file on a box that simply uses a different packager.
func deltaPackagedFn() func([]string) map[string]string {
	if fi, err := os.Stat(dpkgInfoDir); err != nil || !fi.IsDir() {
		return nil
	}
	return deltaPackagedLookup
}
