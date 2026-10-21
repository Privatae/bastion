package main

// Where a root command connects.
//
// A root command's output goes back to the host, and the host reads it. If the
// command fetched anything from outside the platform, that output may carry
// words someone else wrote, so the host must treat it as untrusted and end root
// for that turn. This file decides which connections count: the watch itself
// is per platform (rootexec_watch_linux.go records every outbound connection
// the command's process tree opens), and here each one is looked up in the
// machine's list of the platform's own hosts.
//
// The list is <config dir>/platform_hosts.json, written by the person who runs
// the machine:
//
//	{"hosts": ["2001:db8::/32", "203.0.113.0/24", "git.example.org"]}
//
// Each entry is an address, a CIDR or a name (resolved when the command ends).
// It defaults to EMPTY: with no list, every connection that leaves this machine
// counts as outside. Loopback is this machine's own, with one exception: a
// local relay. A proxy listening on this machine (squid on 3128, say) fetches
// from outside for whoever connects to it, so a connection to one of its ports
// on a loopback or local address counts as outside. The ports are the list's
// "loopback_relays" (TCP), defaulting to the common proxy ports 1080 (SOCKS),
// 3128 (squid), 8118 (privoxy) and 9050 (tor) when the key is absent:
//
//	{"hosts": [...], "loopback_relays": [3128]}
//
// The local DNS resolver (127.0.0.53:53) stays loopback: its answers are
// addresses, not content. A list that cannot be read counts as empty, and its
// relays as the default, so a broken file never makes anything trusted.
//
// This is a tripwire for a command that fetches from outside by accident, not
// a boundary: a root command can always leave its cgroup, delete the table or
// reach out through another program on purpose.
//
// The J frame carries the outside destinations as untrusted_connections, and
// leaves the field out when there are none, so a host that does not know the
// field reads the frame as before. A command whose connections could not be
// watched gets one entry with addr "*" and a note saying why: unwatched output
// is not known to be clean, so it is handled as if it had connected out.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// rootExecConn is one destination a command's process tree opened connections
// to, and how many times it was seen opening one (a retried SYN counts again).
type rootExecConn struct {
	Addr  string `json:"addr"`
	Proto string `json:"proto"`
	Port  int    `json:"port,omitempty"`
	Count int64  `json:"count"`
	// Own is set in the audit row for a destination on the platform's list;
	// the J frame lists only the others, so it never carries it.
	Own  bool   `json:"own,omitempty"`
	Note string `json:"note,omitempty"`
}

const (
	// rootExecUntrustedMax bounds the list the host is given; the rest is a count.
	rootExecUntrustedMax = 32
	// rootExecAuditConnsMax bounds the list kept in the audit row.
	rootExecAuditConnsMax = 256
	// rootExecOwnHostsMax bounds the platform list read from disk.
	rootExecOwnHostsMax = 1024
)

// rootExecWatch is one command's connection watch. Err says why it is not
// watching ("" = it is); every field but Err belongs to the platform code.
type rootExecWatch struct {
	ID    string
	Err   string
	fd    int    // the command's cgroup, opened for CLONE_INTO_CGROUP; -1 when none
	dir   string // that cgroup's folder
	table string // the nftables table this watch created
}

// CgroupFD is what the starter places the command into; -1 = nowhere.
func (w *rootExecWatch) CgroupFD() int {
	if w == nil {
		return -1
	}
	return w.fd
}

// rootExecWatchStart starts one command's watch. A var so tests can choose
// whether the kernel is touched.
var rootExecWatchStart = rootExecWatchStartKernel

// rootExecWatchStop ends a watch: what it saw, and why it saw nothing when it
// could not watch. Everything the watch created is removed.
var rootExecWatchStop = rootExecWatchStopKernel

// rootExecWatchKill ends every process still in the command's cgroup, however
// it left the command's process group (setsid, a new process group, a double
// fork): used when a wall stops holding mid-run, so nothing the command started
// keeps running as root after the grant is gone. A no-op where the command has
// no cgroup of its own. A var so tests can see it called without a kernel.
var rootExecWatchKill = rootExecWatchKillKernel

// ── the platform's own hosts ────────────────────────────────────────────────

func rootExecOwnHostsPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "platform_hosts.json"), nil
}

type rootExecOwnHostsFile struct {
	Hosts []string `json:"hosts"`
	// LoopbackRelays: TCP ports on this machine that relay outside (a local
	// proxy). nil (the key absent) = rootExecDefaultRelays.
	LoopbackRelays *[]int `json:"loopback_relays"`
}

// rootExecDefaultRelays are the common local proxy ports: SOCKS, squid,
// privoxy, tor. A connection to one that does not listen still counts.
var rootExecDefaultRelays = []int{1080, 3128, 8118, 9050}

// rootExecLoopbackRelays is the list's loopback_relays, sorted, or the
// default when the file or the key is missing, the file cannot be read, or a
// port is out of range.
func rootExecLoopbackRelays() []int {
	def := append([]int(nil), rootExecDefaultRelays...)
	p, err := rootExecOwnHostsPath()
	if err != nil {
		return def
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return def
	}
	var f rootExecOwnHostsFile
	if json.Unmarshal(raw, &f) != nil || f.LoopbackRelays == nil {
		return def
	}
	seen := map[int]bool{}
	out := []int{}
	for _, port := range *f.LoopbackRelays {
		if port < 1 || port > 65535 {
			return def
		}
		if !seen[port] {
			seen[port] = true
			out = append(out, port)
		}
	}
	sort.Ints(out)
	return out
}

// rootExecLocalAddr says whether an address is this machine's own (one of its
// interfaces' addresses); a var so a test needs no interfaces.
var rootExecLocalAddr = func(a netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ia := range addrs {
		if n, ok := ia.(*net.IPNet); ok {
			if b, ok := netip.AddrFromSlice(n.IP); ok && b.Unmap() == a {
				return true
			}
		}
	}
	return false
}

// rootExecIsRelay says whether a connection went to a local relay: TCP to one
// of `relays` on a loopback address or one of this machine's own.
func rootExecIsRelay(c rootExecConn, relays []int) bool {
	if c.Proto != "tcp" || len(relays) == 0 {
		return false
	}
	hit := false
	for _, p := range relays {
		if p == c.Port {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	a, err := netip.ParseAddr(c.Addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || rootExecLocalAddr(a)
}

// rootExecOwnHosts reads the list. A missing file is an empty list; a file
// that cannot be read or parsed is an empty list too, with the reason.
func rootExecOwnHosts() (prefixes []netip.Prefix, names []string, problem string) {
	p, err := rootExecOwnHostsPath()
	if err != nil {
		return nil, nil, "no config folder: " + err.Error()
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ""
		}
		return nil, nil, p + ": " + err.Error()
	}
	var f rootExecOwnHostsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, p + ": " + err.Error()
	}
	if len(f.Hosts) > rootExecOwnHostsMax {
		return nil, nil, fmt.Sprintf("%s: more than %d entries", p, rootExecOwnHostsMax)
	}
	for _, h := range f.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if pf, err := netip.ParsePrefix(h); err == nil {
			prefixes = append(prefixes, pf.Masked())
			continue
		}
		if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
			a = a.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		if strings.ContainsAny(h, " /\\:") {
			return nil, nil, fmt.Sprintf("%s: %q is not an address, a CIDR or a name", p, h)
		}
		names = append(names, strings.ToLower(strings.TrimSuffix(h, ".")))
	}
	return prefixes, names, ""
}

// rootExecResolve is the resolver the platform names go through; a var so a
// test needs no DNS.
var rootExecResolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

// rootExecOwnSet is the list made ready to look addresses up in: the names
// resolved now, when the command has ended. A name that does not resolve
// adds nothing, so a connection to it counts as outside.
func rootExecOwnSet() []netip.Prefix {
	prefixes, names, _ := rootExecOwnHosts()
	if len(names) == 0 {
		return prefixes
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, n := range names {
		addrs, err := rootExecResolve(ctx, n)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			a = a.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return prefixes
}

func rootExecIsOwn(addr string, own []netip.Prefix) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	for _, p := range own {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// rootExecClassify marks each connection own or not, and returns the outside
// ones for the host (capped, with how many more there were) and every one for
// the audit row (capped). A connection to a local relay (`relays`) is
// outside, with a note. A watch that could not watch gives one outside entry
// saying why.
func rootExecClassify(conns []rootExecConn, unwatched string, own []netip.Prefix, relays []int) (untrusted []rootExecConn, more int, all []rootExecConn) {
	if unwatched != "" {
		e := rootExecConn{Addr: "*", Proto: "*", Note: "connections not watched: " + unwatched}
		return []rootExecConn{e}, 0, []rootExecConn{e}
	}
	for _, c := range conns {
		c.Own = rootExecIsOwn(c.Addr, own)
		if rootExecIsRelay(c, relays) {
			c.Own = false
			c.Note = "a local relay: this port fetches from outside (loopback_relays)"
		}
		all = append(all, c)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Count != all[j].Count {
			return all[i].Count > all[j].Count
		}
		if all[i].Addr != all[j].Addr {
			return all[i].Addr < all[j].Addr
		}
		if all[i].Proto != all[j].Proto {
			return all[i].Proto < all[j].Proto
		}
		return all[i].Port < all[j].Port
	})
	for _, c := range all {
		if c.Own {
			continue
		}
		if len(untrusted) == rootExecUntrustedMax {
			more++
			continue
		}
		c.Own = false
		untrusted = append(untrusted, c)
	}
	if len(all) > rootExecAuditConnsMax {
		all = all[:rootExecAuditConnsMax]
	}
	return untrusted, more, all
}

// rootExecConnsText is the transcript's line for the connections.
func rootExecConnsText(all []rootExecConn) string {
	if len(all) == 0 {
		return "none outside this machine"
	}
	parts := make([]string, 0, len(all))
	for _, c := range all {
		if c.Addr == "*" {
			parts = append(parts, c.Note)
			continue
		}
		where := "outside"
		if c.Own {
			where = "platform"
		}
		dest := c.Addr
		if c.Port != 0 {
			dest = net.JoinHostPort(c.Addr, fmt.Sprint(c.Port))
		}
		parts = append(parts, fmt.Sprintf("%s %s x%d (%s)", c.Proto, dest, c.Count, where))
	}
	return strings.Join(parts, ", ")
}

// rootExecOwnHostsLine is the console's line about the platform list.
func rootExecOwnHostsLine() string {
	p, _ := rootExecOwnHostsPath()
	prefixes, names, problem := rootExecOwnHosts()
	relays := fmt.Sprintf("; local relays (TCP ports that count as outside): %v", rootExecLoopbackRelays())
	if problem != "" {
		return "platform hosts: unreadable, so every connection off this machine counts as outside (" + problem + ")" + relays
	}
	if len(prefixes)+len(names) == 0 {
		return "platform hosts: none listed in " + p + ", so every connection off this machine counts as outside" + relays
	}
	return fmt.Sprintf("platform hosts (%s): %d addresses or ranges, %d names; any other connection a command makes counts as outside", p, len(prefixes), len(names)) + relays
}
