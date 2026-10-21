//go:build linux

package main

// The connection watch on Linux: each root command starts inside a cgroup of
// its own (CLONE_INTO_CGROUP, so no child is ever outside it), and an
// nftables table this bastion creates for that command records every
// connection a socket of that cgroup opens: `socket cgroupv2` matches the
// cgroup the socket was made in, and a dynamic set with a counter keeps each
// destination once. The table's chain has policy accept and gives no verdict,
// so it changes nothing about what the machine allows: the firewall that is
// already here (ufw, its own nftables tables) is never edited, flushed or
// reordered, and a packet it drops is still dropped.
//
// When the command ends, the sets are read, any process the command left
// running is moved back to the bastion's own cgroup (where every command ran
// before this watch, so it lives on exactly as it did), and the cgroup and
// the table are removed. If the bastion dies first, systemd removes the
// cgroup with the unit, and the next start (and every new watch) deletes any
// table of this name it did not make itself.
//
// What it cannot see, plainly: connections another program makes on the
// command's behalf. `docker build` / `docker pull` ask dockerd, which pulls
// with its own sockets, and a container's processes live in docker's
// cgroups; `systemctl start`, `systemd-run` and snapd are the same. Those are
// not the command's process tree and are not attributed. A local proxy is
// seen at its door: a connection to one of the list's loopback_relays ports
// is recorded and counts as outside. A root command can also leave its cgroup
// or delete the table on purpose; a table that is gone when the command ends
// reads as "not watched". This is a tripwire for an accidental outside fetch,
// not a boundary: root can always defeat it.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	rootExecWatchTablePrefix  = "privatae_rootexec_"
	rootExecWatchCgroupPrefix = "privatae-rootexec-"
	rootExecWatchSetSize      = 65535
	cgroupRoot                = "/sys/fs/cgroup"
)

var rootExecWatching = struct {
	sync.Mutex
	ids map[string]bool
}{ids: map[string]bool{}}

func rootExecWatchActive(id string) bool {
	rootExecWatching.Lock()
	defer rootExecWatching.Unlock()
	return rootExecWatching.ids[id]
}

func rootExecNft() (string, error) {
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return exec.LookPath("nft")
}

func rootExecRunNft(stdin string, args ...string) ([]byte, error) {
	bin, err := rootExecNft()
	if err != nil {
		return nil, errors.New("nft is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("nft %s: %v %s", strings.Join(args, " "), err, msg)
	}
	return out.Bytes(), nil
}

// rootExecOwnCgroup is this process's cgroup v2 path, e.g.
// /system.slice/privatae-bastion.service.
func rootExecOwnCgroup() (string, error) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok && strings.HasPrefix(p, "/") {
			return p, nil
		}
	}
	return "", errors.New("this machine does not run the unified cgroup hierarchy")
}

func rootExecWatchStartKernel(sessionID string) *rootExecWatch {
	_ = sessionID
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return &rootExecWatch{fd: -1, Err: "no randomness for the watch's name"}
	}
	w := &rootExecWatch{ID: hex.EncodeToString(b[:]), fd: -1}
	rootExecWatching.Lock()
	rootExecWatching.ids[w.ID] = true
	rootExecWatching.Unlock()
	rootExecWatchSweep()
	if err := rootExecWatchSetup(w); err != nil {
		w.Err = err.Error()
		rootExecWatchCleanup(w)
	}
	return w
}

func rootExecWatchSetup(w *rootExecWatch) error {
	if _, err := rootExecNft(); err != nil {
		return errors.New("nft is not installed")
	}
	own, err := rootExecOwnCgroup()
	if err != nil {
		return err
	}
	rel := strings.Trim(filepath.Join(own, rootExecWatchCgroupPrefix+w.ID), "/")
	if strings.ContainsAny(rel, "\"\\\n") {
		return fmt.Errorf("this bastion's cgroup path %q cannot be named in an nftables rule", own)
	}
	dir := filepath.Join(cgroupRoot, rel)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return fmt.Errorf("cannot make the command's cgroup: %v", err)
	}
	w.dir = dir
	level := strings.Count(rel, "/") + 1
	table := rootExecWatchTablePrefix + w.ID
	// Loopback is skipped, except TCP to a local relay's port (a proxy that
	// fetches from outside, rootExecLoopbackRelays): that is recorded, and
	// rootExecClassify counts it as outside.
	lo := `oifname "lo" return`
	if relays := rootExecLoopbackRelays(); len(relays) > 0 {
		ports := make([]string, len(relays))
		for i, p := range relays {
			ports[i] = strconv.Itoa(p)
		}
		lo = `oifname "lo" meta l4proto != tcp return
		oifname "lo" tcp dport != { ` + strings.Join(ports, ", ") + ` } return`
	}
	// ct state: one entry per connection opened, not per packet. untracked is
	// there too, so a raw-table notrack rule elsewhere cannot hide a flow.
	script := fmt.Sprintf(`table inet %[1]s {
	set out4 {
		type ipv4_addr . inet_proto . inet_service
		flags dynamic
		counter
		size %[2]d
	}
	set out6 {
		type ipv6_addr . inet_proto . inet_service
		flags dynamic
		counter
		size %[2]d
	}
	set other4 {
		type ipv4_addr . inet_proto
		flags dynamic
		counter
		size %[2]d
	}
	set other6 {
		type ipv6_addr . inet_proto
		flags dynamic
		counter
		size %[2]d
	}
	chain seen {
		meta nfproto ipv4 meta l4proto { tcp, udp } add @out4 { ip daddr . meta l4proto . th dport }
		meta nfproto ipv6 meta l4proto { tcp, udp } add @out6 { ip6 daddr . meta l4proto . th dport }
		meta nfproto ipv4 meta l4proto != { tcp, udp } add @other4 { ip daddr . meta l4proto }
		meta nfproto ipv6 meta l4proto != { tcp, udp } add @other6 { ip6 daddr . meta l4proto }
	}
	chain out {
		type filter hook output priority -190; policy accept;
		%[5]s
		socket cgroupv2 level %[3]d "%[4]s" ct state { new, untracked } jump seen
	}
}
`, table, rootExecWatchSetSize, level, rel, lo)
	if _, err := rootExecRunNft(script, "-f", "-"); err != nil {
		return fmt.Errorf("cannot create the watch's nftables table: %v", err)
	}
	w.table = table
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot open the command's cgroup: %v", err)
	}
	w.fd = fd
	return nil
}

// nftListTable is the part of `nft -j list table` the watch reads.
type nftListTable struct {
	Nftables []struct {
		Set *struct {
			Name string `json:"name"`
			Size int    `json:"size"`
			Elem []struct {
				Elem struct {
					Val struct {
						Concat []any `json:"concat"`
					} `json:"val"`
					Counter struct {
						Packets int64 `json:"packets"`
					} `json:"counter"`
				} `json:"elem"`
			} `json:"elem"`
		} `json:"set"`
		Rule *struct {
			Chain string `json:"chain"`
		} `json:"rule"`
	} `json:"nftables"`
}

func nftScalar(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatInt(int64(x), 10)
	}
	return fmt.Sprint(v)
}

// rootExecWatchRead reads what the table recorded. A table that is gone, or
// whose watching rule is gone, is reported as not watched.
func rootExecWatchRead(table string) ([]rootExecConn, error) {
	out, err := rootExecRunNft("", "-j", "list", "table", "inet", table)
	if err != nil {
		return nil, errors.New("the watch's table was gone when the command ended")
	}
	var lt nftListTable
	if err := json.Unmarshal(out, &lt); err != nil {
		return nil, fmt.Errorf("cannot read the watch's table: %v", err)
	}
	watching, sets := false, 0
	var conns []rootExecConn
	for _, o := range lt.Nftables {
		if o.Rule != nil && o.Rule.Chain == "out" {
			watching = true
		}
		s := o.Set
		if s == nil {
			continue
		}
		sets++
		if s.Size > 0 && len(s.Elem) >= s.Size {
			return nil, fmt.Errorf("more than %d destinations", s.Size)
		}
		for _, e := range s.Elem {
			c := e.Elem.Val.Concat
			if len(c) < 2 {
				continue
			}
			rc := rootExecConn{Addr: nftScalar(c[0]), Proto: nftScalar(c[1]), Count: e.Elem.Counter.Packets}
			if len(c) >= 3 {
				rc.Port, _ = strconv.Atoi(nftScalar(c[2]))
			}
			conns = append(conns, rc)
		}
	}
	if !watching || sets != 4 {
		return nil, errors.New("the watch's rule or sets were removed while the command ran")
	}
	return conns, nil
}

func rootExecWatchStopKernel(w *rootExecWatch) ([]rootExecConn, string) {
	if w == nil {
		return nil, "no watch was started"
	}
	defer func() {
		rootExecWatchCleanup(w)
		rootExecWatching.Lock()
		delete(rootExecWatching.ids, w.ID)
		rootExecWatching.Unlock()
	}()
	if w.Err != "" {
		return nil, w.Err
	}
	conns, err := rootExecWatchRead(w.table)
	if err != nil {
		return nil, err.Error()
	}
	return conns, ""
}

// rootExecWatchCleanup removes what a watch created. Safe to call twice.
func rootExecWatchCleanup(w *rootExecWatch) {
	if w.fd >= 0 {
		_ = unix.Close(w.fd)
		w.fd = -1
	}
	if w.dir != "" {
		if rootExecCgroupRemove(w.dir) == nil {
			w.dir = ""
		}
	}
	if w.table != "" {
		if _, err := rootExecRunNft("", "delete", "table", "inet", w.table); err == nil {
			w.table = ""
		}
	}
}

// rootExecKillPid sends SIGKILL to one process of a command's cgroup. A var
// so a test can fence it; it never takes pid 0 or 1.
var rootExecKillPid = func(pid int) error {
	if pid <= 1 {
		return syscall.EINVAL
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

// rootExecWatchKillKernel kills every process in the command's cgroup:
// cgroup.kill (Linux 5.14+), which the kernel applies to the whole cgroup at
// once, so a process forking meanwhile cannot slip out; on an older kernel,
// SIGKILL to each pid cgroup.procs lists, read again until it is empty or a
// few rounds have passed. A process that moved itself to another cgroup is not
// here; the process-group kill that runs beside this one still reaches it if it
// kept the command's group.
func rootExecWatchKillKernel(w *rootExecWatch) {
	if w == nil || w.dir == "" {
		return
	}
	if f, err := os.OpenFile(filepath.Join(w.dir, "cgroup.kill"), os.O_WRONLY, 0); err == nil {
		_, werr := f.Write([]byte("1"))
		_ = f.Close()
		if werr == nil {
			return
		}
	}
	for round := 0; round < 20; round++ {
		raw, err := os.ReadFile(filepath.Join(w.dir, "cgroup.procs"))
		if err != nil {
			return
		}
		pids := strings.Fields(string(raw))
		if len(pids) == 0 {
			return
		}
		for _, f := range pids {
			if pid, err := strconv.Atoi(f); err == nil && pid > 1 {
				_ = rootExecKillPid(pid)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// rootExecCgroupRemove moves whatever is left in a command's cgroup into its
// parent (the bastion's own cgroup, where a command's leftovers lived before
// the watch) and removes the cgroup.
func rootExecCgroupRemove(dir string) error {
	parent := filepath.Join(filepath.Dir(dir), "cgroup.procs")
	var err error
	for i := 0; i < 50; i++ {
		if err = syscall.Rmdir(dir); err == nil || errors.Is(err, syscall.ENOENT) {
			return nil
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
		if rerr != nil {
			return rerr
		}
		for _, f := range strings.Fields(string(raw)) {
			_ = os.WriteFile(parent, []byte(f), 0)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

// rootExecWatchSweep removes every watch table and command cgroup that no
// watch of this process holds: what a bastion that died mid-command left.
func rootExecWatchSweep() {
	if os.Geteuid() != 0 {
		return
	}
	if out, err := rootExecRunNft("", "-j", "list", "tables", "inet"); err == nil {
		var lt struct {
			Nftables []struct {
				Table *struct {
					Family string `json:"family"`
					Name   string `json:"name"`
				} `json:"table"`
			} `json:"nftables"`
		}
		if json.Unmarshal(out, &lt) == nil {
			for _, o := range lt.Nftables {
				if o.Table == nil || o.Table.Family != "inet" {
					continue
				}
				id, ok := strings.CutPrefix(o.Table.Name, rootExecWatchTablePrefix)
				if !ok || rootExecWatchActive(id) {
					continue
				}
				_, _ = rootExecRunNft("", "delete", "table", "inet", o.Table.Name)
			}
		}
	}
	own, err := rootExecOwnCgroup()
	if err != nil {
		return
	}
	ents, err := os.ReadDir(filepath.Join(cgroupRoot, own))
	if err != nil {
		return
	}
	for _, e := range ents {
		id, ok := strings.CutPrefix(e.Name(), rootExecWatchCgroupPrefix)
		if !e.IsDir() || !ok || rootExecWatchActive(id) {
			continue
		}
		_ = rootExecCgroupRemove(filepath.Join(cgroupRoot, own, e.Name()))
	}
}

// rootExecIntoCgroup starts the command inside the watch's cgroup, so the
// shell and every child it makes are in it from their first instruction.
func rootExecIntoCgroup(attr *syscall.SysProcAttr, fd int) {
	if fd >= 0 {
		attr.UseCgroupFD = true
		attr.CgroupFD = fd
	}
}
