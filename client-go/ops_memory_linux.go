//go:build linux

package main

// ops_memory_linux.go — an action op may use as much memory as the machine has
// to spare, and is the first thing stopped when it has none.
//
// There is no ceiling on a run. A fixed one stops a legitimate build or scan
// on a machine with memory to spare, which is exactly when it should not.
// What a run must never do is take memory the machine's own services need,
// and on a Kubernetes node that line comes before the kernel's: the kubelet
// evicts pods once free memory falls under its hard eviction threshold. So:
//
//   - the run's unit carries OOMScoreAdjust=1000: if the kernel must kill
//     something, it kills the op first;
//   - while a run is going, the bastion watches the machine's free memory
//     (MemAvailable), and when it falls to the floor it stops the op's unit,
//     before the kubelet or the kernel pick anything else, and says so. The
//     op yields whether or not it is what used the memory: of everything
//     running, it is the thing that can simply be run again;
//   - it is stopped too when the machine's own services start waiting on
//     memory: when any top-level cgroup other than the ops' own slice (the
//     services, the pods, the users) stalls on memory 7 points more of the
//     time than its lowest reading since the run began (PSI "some", 10-second average). A
//     rise, not a level: a pod reclaiming against its own limit keeps its
//     group stalling whatever the machine has free, and must not stop every
//     op. That is the partial-stall level at
//     which Android's low-memory killer stops background apps (70 ms of
//     every second); here it sits 15x above the worst reading on the three
//     ship machines (0.44%). It catches what free
//     memory alone misses on a machine with swap, where the kernel makes
//     room by swapping the services out and free memory hardly moves (an op
//     reached 7.8 GiB on a build machine while free memory fell by 5.8 GiB). The op's
//     own stalls do not count: it runs in its own slice;
//   - a run does not start on a machine already under the floor;
//   - the kill is tried on every tick the machine is short until it lands,
//     and a run counts as stopped only if the kill landed and the program
//     did not finish anyway.
//
// The floor is the largest of: 1 GiB; 5% of the machine's memory (earlyoom,
// the common userspace killer, acts at 10% by default, and the op must go
// well before a machine-wide killer does); and, on a k3s node, the kubelet's
// own hard eviction threshold plus 512 MiB, so the op always yields before a
// pod is evicted.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	opActionSlice       = "privatae_ops.slice"
	opMemoryFloorMin    = 1 << 30
	opMemoryKubeletPad  = 512 << 20
	opMemoryWatchPeriod = 250 * time.Millisecond
)

// Seams, so the tests can move the floor and read a unit's cgroup.
var (
	opMemoryFloor    = opMemoryFloorForMachine
	opMemoryStallMax = 7.0              // percent, PSI some avg10, of any cgroup but the ops'
	opCgroupRoot     = "/sys/fs/cgroup" // where the pressures are read
)

// opUnitCgroupDir is an op unit's own cgroup, in the ops' slice.
func opUnitCgroupDir(unit string) string {
	return filepath.Join("/sys/fs/cgroup", opActionSlice, unit+".service")
}

// opKillUnit kills every process of an op's unit at once, through the
// kernel (cgroup.kill), which needs no bus; systemd is asked only if that
// cannot be written.
func opKillUnit(unit string) bool {
	if err := os.WriteFile(filepath.Join(opUnitCgroupDir(unit), "cgroup.kill"), []byte("1"), 0); err == nil {
		return true
	}
	return exec.Command("systemctl", "kill", "--signal=SIGKILL", unit).Run() == nil
}

// opOthersStalls is each top-level cgroup's memory stall (PSI some avg10,
// percent), the ops' own slice left out.
func opOthersStalls() map[string]float64 {
	out := map[string]float64{}
	entries, err := os.ReadDir(opCgroupRoot)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == opActionSlice {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(opCgroupRoot, e.Name(), "memory.pressure"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "some ") {
				continue
			}
			for _, f := range strings.Fields(line) {
				if v, ok := strings.CutPrefix(f, "avg10="); ok {
					if x, err := strconv.ParseFloat(v, 64); err == nil {
						out[e.Name()] = x
					}
				}
			}
		}
	}
	return out
}

// opStallRise is the cgroup whose stall rose most above its lowest reading
// so far in the run, and by how much. A group stalling throughout (a pod
// reclaiming against its own limit, a service at its MemoryMax) is that
// group's own business, not a sign the machine is short: only a rise counts.
func opStallRise(base, now map[string]float64) (float64, string) {
	var worst float64
	var who string
	for cg, x := range now {
		if r := x - base[cg]; r > worst {
			worst, who = r, cg
		}
	}
	return worst, who
}

// opMemInfo reads MemTotal and MemAvailable, in bytes.
func opMemInfo() (total, avail uint64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	got := 0
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 {
			continue
		}
		n, err := strconv.ParseUint(fs[1], 10, 64)
		if err != nil {
			continue
		}
		switch fs[0] {
		case "MemTotal:":
			total, got = n<<10, got+1
		case "MemAvailable:":
			avail, got = n<<10, got+1
		}
	}
	return total, avail, got == 2
}

// The places a k3s node's kubelet eviction settings live: the config file,
// its drop-ins, and --kubelet-arg flags on the k3s units and their drop-ins.
// Seams, so the tests can point them at fixtures.
var (
	opK3sConfigGlobs = []string{"/etc/rancher/k3s/config.yaml", "/etc/rancher/k3s/config.yaml.d/*.yaml",
		// The kubelet config k3s writes (and a person may add to), v1.35.
		"/var/lib/rancher/k3s/agent/etc/kubelet.conf.d/*.conf"}
	opK3sUnitGlobs = []string{"/etc/systemd/system/k3s*.service", "/etc/systemd/system/k3s*.service.d/*.conf"}
)

// memory.available<VALUE (a flag or config value) and memory.available: VALUE
// (a kubelet config file's evictionHard / evictionSoft).
var (
	opEvictionFlagRe = regexp.MustCompile(`memory\.available\s*<\s*["']?([^"',\s]+)`)
	opEvictionYAMLRe = regexp.MustCompile(`memory\.available["']?\s*:\s*["']?([^"',\s}]+)`)
	opQuantityRe     = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(%|Ki|Mi|Gi|Ti|K|M|G|T|k)?$`)
)

// opParseMemQuantity reads a kubelet memory quantity: plain bytes, the
// binary (Ki..Ti) or decimal (K..T) suffixes, a decimal, or a percentage of
// the machine's memory. ok=false: it cannot be read.
func opParseMemQuantity(v string, total uint64) (uint64, bool) {
	m := opQuantityRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, false
	}
	x, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	mult := map[string]float64{"": 1, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12,
		"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40}
	if m[2] == "%" {
		return uint64(x / 100 * float64(total)), true
	}
	return uint64(x * mult[m[2]]), true
}

// opKubeletEviction is the highest memory eviction line the kubelet on this
// machine is set to act at, hard or soft (the kubelet evicts on both), and
// whether a setting was there that could not be read.
func opKubeletEviction() (bytes uint64, unreadable bool) {
	total, _, _ := opMemInfo()
	var files []string
	for _, g := range append(append([]string{}, opK3sConfigGlobs...), opK3sUnitGlobs...) {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	seen := map[string]bool{}
	for i := 0; i < len(files); i++ {
		f := files[i]
		if seen[f] {
			continue
		}
		seen[f] = true
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		// A kubelet config file or folder a flag names is read too; one that
		// cannot be read may hold the line, so the floor takes it as unknown.
		for _, named := range opKubeletNamed(raw) {
			m, err := filepath.Glob(named)
			if err != nil || len(m) == 0 {
				// A folder that is there and holds no config is empty, not
				// unknown; anything else named and missing is unknown.
				if st, e := os.Stat(filepath.Dir(named)); !(strings.HasSuffix(named, "*.conf") && e == nil && st.IsDir()) {
					unreadable = true
				}
				continue
			}
			for _, x := range m {
				if _, err := os.Stat(x); err != nil {
					unreadable = true
					continue
				}
				files = append(files, x)
			}
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if i := strings.Index(line, "#"); i >= 0 {
				line = line[:i]
			}
			var vals []string
			if strings.Contains(line, "eviction-hard") || strings.Contains(line, "eviction-soft") {
				for _, m := range opEvictionFlagRe.FindAllStringSubmatch(line, -1) {
					vals = append(vals, m[1])
				}
			}
			for _, m := range opEvictionYAMLRe.FindAllStringSubmatch(line, -1) {
				vals = append(vals, m[1])
			}
			for _, v := range vals {
				n, ok := opParseMemQuantity(v, total)
				if !ok {
					unreadable = true
					continue
				}
				if n > bytes {
					bytes = n
				}
			}
		}
	}
	return bytes, unreadable
}

var opKubeletConfigArgRe = regexp.MustCompile(`(?:^|[\s"'=,\[-])(config|config-dir)=([^\s"',\]]+)`)

// opKubeletNamed is every kubelet config file (config=) or folder
// (config-dir=, its *.conf) a kubelet-arg in raw names.
func opKubeletNamed(raw []byte) []string {
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		// Every line, not only ones naming kubelet-arg: a unit file splits
		// `'--kubelet-arg' \` and `'config=…' \` over two lines. A match
		// that is not a kubelet's only adds a file to read, or raises the
		// floor.
		for _, m := range opKubeletConfigArgRe.FindAllStringSubmatch(line, -1) {
			if m[1] == "config-dir" {
				out = append(out, filepath.Join(m[2], "*.conf"))
			} else {
				out = append(out, m[2])
			}
		}
	}
	return out
}

// opFloorNote explains a floor raised because a kubelet eviction setting on
// this machine could not be read, so a stop it causes says why; "" otherwise.
func opFloorNote() string {
	if _, unreadable := opKubeletEviction(); unreadable {
		return " (raised to 10% of memory plus 512 MiB because a kubelet eviction setting on this machine could not be read)"
	}
	return ""
}

func opMemoryFloorForMachine() uint64 {
	total, _, _ := opMemInfo()
	floor := uint64(opMemoryFloorMin)
	if total/20 > floor {
		floor = total / 20
	}
	k, unreadable := opKubeletEviction()
	if k > 0 && k+opMemoryKubeletPad > floor {
		floor = k + opMemoryKubeletPad
	}
	// A kubelet setting this could not read is taken as high as a kubelet
	// is usually set (10%), never as absent: the op must still go first.
	if unreadable && total/10+opMemoryKubeletPad > floor {
		floor = total/10 + opMemoryKubeletPad
	}
	return floor
}

// opMemoryWatch stops unit if the machine's free memory falls to the floor,
// and tracks the unit's own peak. stop() ends the watch and says whether it
// stopped the op, the free memory when it did, and the op's peak.
type opMemoryVerdict struct {
	Stopped bool
	Avail   uint64
	Floor   uint64
	Peak    uint64
	Stall   float64 // set when others' stall stopped it
	Staller string
}

// reason is the sentence for a run the watch stopped.
func (v opMemoryVerdict) reason() string {
	if v.Stall > 0 {
		return fmt.Sprintf("this machine's %s began waiting on memory %.1f%% more of the time than it had during the run, so the op was stopped first (it had used %s at its peak). Nothing limits an op while the machine has memory to spare",
			v.Staller, v.Stall, opMiB(v.Peak))
	}
	return fmt.Sprintf("this machine ran down to %s of memory free, under the %s it keeps for its own services%s, so the op was stopped first (it had used %s at its peak). Nothing limits an op while the machine has memory to spare",
		opMiB(v.Avail), opMiB(v.Floor), opFloorNote(), opMiB(v.Peak))
}

func opMemoryWatch(unit string, floor uint64) (stop func() opMemoryVerdict) {
	done := make(chan struct{})
	var mu sync.Mutex
	v := opMemoryVerdict{Floor: floor}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(opMemoryWatchPeriod)
		defer t.Stop()
		cur := filepath.Join(opUnitCgroupDir(unit), "memory.current")
		// Each group's lowest reading during the run: a group that spiked as
		// the run began must not hide a rise the run causes later, and one
		// held at its own limit throughout still never counts.
		low := opOthersStalls()
		for {
			if raw, err := os.ReadFile(cur); err == nil {
				if n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err == nil {
					mu.Lock()
					if n > v.Peak {
						v.Peak = n
					}
					mu.Unlock()
				}
			}
			_, avail, ok := opMemInfo()
			short := ok && avail <= floor
			now := opOthersStalls()
			rise, who := opStallRise(low, now)
			for cg, x := range now {
				if l, ok := low[cg]; !ok || x < l {
					low[cg] = x
				}
			}
			// Killed on every tick the machine is short, until a kill lands:
			// one that finds no cgroup yet (the unit still starting) is tried
			// again, and only a kill that landed counts as the op stopped.
			if (short || rise >= opMemoryStallMax) && opKillUnit(unit) {
				mu.Lock()
				if !v.Stopped {
					v.Stopped, v.Avail = true, avail
					if !short {
						v.Stall, v.Staller = rise, who
					}
				}
				mu.Unlock()
			}
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	}()
	return func() opMemoryVerdict {
		close(done)
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		return v
	}
}

func opMiB(n uint64) string { return strconv.FormatUint(n>>20, 10) + " MiB" }
