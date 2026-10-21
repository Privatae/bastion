package main

// observe:* — read-only root ops on the networked bastion.
//
// The bastion runs as root (deploy/install.sh has no User=), so anything it
// execs runs as root.
// The discipline is the one a read-only sudoers policy lives by: every op is
// a FIXED argv, read-only forms only, and no byte of a job's args ever reaches a shell or an
// argv position. The single exception is observe:net, whose one argument is
// a host[:port] that passes a strict charset check and is then handed to
// Go's net package — never to a program.
//
// Every op answers typed JSON on stdout and exit 0. A box that cannot answer
// (a tool missing, a platform without the probes) says so in the JSON —
// "absent"/"unknown"/-1 per field, or {"unsupported": platform} for the whole
// op — and never invents a value, because these fields feed findings and a
// guessed "drop" hides an open firewall.
//
// Layout: this file is platform-neutral — the handler table entries, the
// parsers (pure functions over captured text, unit-tested with fixtures),
// the observe:net probe (pure Go), and the posture cache the heartbeat reads.
// observe_ops_linux.go holds the drivers that run the fixed argvs;
// observe_ops_other.go answers unsupported everywhere else.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// observeOpBudget bounds a whole op: every exec it runs shares ONE deadline.
// The host waits 30 s for a dispatch and the lane's own timeout is 25 s;
// seven execs each allowed 20 s would be 140 s, past the 180 s after which
// the host marks this box offline, so a per-exec bound is the wrong shape. With one
// budget a hung tool costs the fields after it — marked "timeout" — and the
// op still answers inside the wait. A variable only so a test can shrink it.
var observeOpBudget = 20 * time.Second

// observeTextCap is the byte cap on the free-text ops (observe:firewall,
// observe:kernel). A typical ruleset is a few KB; 200 KB is room for a
// pathological one without letting a job body grow without bound.
const observeTextCap = 200 * 1024

// observeExec is the ONE seam through which every observe driver runs a
// program. It is a variable so the test can replace it with a recorder and
// prove that no job argument ever appears in an argv (TestObserveArgsNeverReachArgv).
var observeExec = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd) // console_windows.go
	// A grandchild that inherited stdout (apt's helpers, a kubectl plugin)
	// would otherwise keep Output() blocked after the deadline killed the
	// child; WaitDelay closes the pipe 1 s after the kill.
	cmd.WaitDelay = time.Second
	return cmd.Output()
}

// opBudget is the context every op runs its execs under.
func opBudget() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), observeOpBudget)
}

// observeHave reports whether a program resolves on PATH. The drivers ask
// before running so a missing tool reads "absent" (a posture in its own
// right: an edge box may have no ufw binary at all) rather than an exec error.
var observeHave = func(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ── observe:host ─────────────────────────────────────────────────────────────

// hostPosture reproduces the host's own probe field for field, same names and
// same value vocabulary, so the finding rules already written against that
// table read this unchanged.
//   - ufw:     status word from `ufw status` line 1 ("active"/"inactive");
//     "absent" = no binary; "unknown" = binary answered nothing.
//   - pubwall: `<policy>[+tdrop]` of the `inet pubwall input` chain, or
//     "absent". "drop+tdrop" is the hardened shape; "accept+tdrop"
//     fails OPEN if the last rule is lost.
//   - ssh22:   "scoped"/"unscoped"/"unknown" — whether tcp/22 is source-
//     restricted; the WORST match wins (one bare accept = unscoped).
//   - f2b:     `systemctl is-active fail2ban` verbatim; "absent" = no systemctl.
//   - input:   iptables INPUT policy; "absent" = no iptables; "unknown" = no
//     policy line.
//   - sec:     pending security packages (^Inst lines only — counting the
//     Conf lines too doubles it); -1 = no apt-get.
//   - load:    1-minute load; cpus: core count so load is judged per core.
//   - reboot:  "yes"/"no" for /var/run/reboot-required.
//   - diskpct: root filesystem use percent as df -P reports it; -1 unreadable.
//   - jrn:     seconds since the last journal line; -1 = could not read one.
//   - puv:     first word of /run/privatae/post-upgrade-verify.status, or "absent".
type hostPosture struct {
	Ufw     string  `json:"ufw"`
	Pubwall string  `json:"pubwall"`
	Ssh22   string  `json:"ssh22"`
	F2b     string  `json:"f2b"`
	Input   string  `json:"input"`
	Sec     int     `json:"sec"`
	Load    float64 `json:"load"`
	Cpus    int     `json:"cpus"`
	Reboot  string  `json:"reboot"`
	DiskPct int     `json:"diskpct"`
	Jrn     int64   `json:"jrn"`
	Puv     string  `json:"puv"`
	// Fields whose probe did not finish inside the op budget. String fields
	// also read "timeout"; sec and jrn read -1, so this list is the only
	// place that tells "timed out" from "could not read".
	Timeouts []string `json:"timeouts,omitempty"`
}

// heartbeatPosture is the compact subset the heartbeat carries: the fields a
// finding rule reads at a glance. input and puv stay on observe:host.
type heartbeatPosture struct {
	Ufw     string  `json:"ufw"`
	Pubwall string  `json:"pubwall"`
	Ssh22   string  `json:"ssh22"`
	F2b     string  `json:"f2b"`
	Sec     int     `json:"sec"`
	Load    float64 `json:"load"`
	Cpus    int     `json:"cpus"`
	Reboot  string  `json:"reboot"`
	DiskPct int     `json:"diskpct"`
	Jrn     int64   `json:"jrn"`
}

func (p hostPosture) compact() heartbeatPosture {
	return heartbeatPosture{Ufw: p.Ufw, Pubwall: p.Pubwall, Ssh22: p.Ssh22, F2b: p.F2b,
		Sec: p.Sec, Load: p.Load, Cpus: p.Cpus, Reboot: p.Reboot, DiskPct: p.DiskPct, Jrn: p.Jrn}
}

// parseUfwStatus reads the first line of `ufw status` ("Status: active").
func parseUfwStatus(out string) string {
	line, _, _ := strings.Cut(out, "\n")
	f := strings.Fields(line)
	if len(f) < 2 {
		return "unknown"
	}
	return f[1]
}

var nftPolicyRe = regexp.MustCompile(`hook input.*policy ([a-z]+)`)
var nftTerminalDropRe = regexp.MustCompile(`(?m)^\s+counter packets [0-9]+ bytes [0-9]+ drop`)

// parsePubwall classifies the text of `nft list chain inet pubwall input`.
// It reads ONE chain, not the table: an unconditional drop in forward/output
// would otherwise count as this chain's terminal drop. Empty text (no table,
// nft missing, chain renamed) is "absent" — the direction that raises a
// finding rather than hiding one.
func parsePubwall(chain string) string {
	m := nftPolicyRe.FindStringSubmatch(chain)
	if m == nil {
		return "absent"
	}
	if nftTerminalDropRe.MatchString(chain) {
		return m[1] + "+tdrop"
	}
	return m[1]
}

var nftSSHAcceptRe = regexp.MustCompile(`dport (22|\{ ?22)`)

// parseSSH22 answers whether sshd is source-restricted, from the pubwall
// TABLE text first (every non-ufw host) and the ufw rule list second. Worst
// match wins: a chain with one scoped accept and one bare one is "unscoped",
// because additive hand edits are how these rulesets actually change and a
// debug leftover below a scoped rule is exactly the case that must not read
// as protected. haveUfw says whether the second source was even consulted.
func parseSSH22(nftTable, ufwStatus string, haveUfw bool) string {
	found := false
	for _, l := range strings.Split(nftTable, "\n") {
		if !nftSSHAcceptRe.MatchString(l) || !strings.Contains(l, "accept") {
			continue
		}
		found = true
		if !strings.Contains(l, "saddr") {
			return "unscoped"
		}
	}
	if found {
		return "scoped"
	}
	if haveUfw {
		for _, l := range strings.Split(ufwStatus, "\n") {
			if !strings.HasPrefix(l, "22/tcp") || !strings.Contains(l, "ALLOW") {
				continue
			}
			found = true
			if strings.Contains(l, "Anywhere") {
				return "unscoped"
			}
		}
		if found {
			return "scoped"
		}
	}
	return "unknown"
}

// parseIptablesInputPolicy reads the `-P INPUT <policy>` line of `iptables -S`.
func parseIptablesInputPolicy(out string) string {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && f[0] == "-P" && f[1] == "INPUT" {
			return f[2]
		}
	}
	return "unknown"
}

// parseAptSecurityCount counts PACKAGES with a pending security upgrade in
// `apt-get -s upgrade` output. Anchored on ^Inst: the simulation prints an
// Inst and a Conf line per package and both name the pocket, so counting
// every line that says "security" reported exactly double (measured: 40
// lines for 20 packages, the same 2:1 on every host checked). Empty output
// is -1, "could not read", never 0: a 0 here
// clears a finding, and an apt that printed nothing has not said there is
// nothing pending.
func parseAptSecurityCount(out string) int {
	if strings.TrimSpace(out) == "" {
		return -1
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Inst") && (strings.Contains(l, "security") || strings.Contains(l, "Security")) {
			n++
		}
	}
	return n
}

// parseLoadavg reads the 1-minute figure from /proc/loadavg text.
func parseLoadavg(out string) float64 {
	f := strings.Fields(out)
	if len(f) == 0 {
		return -1
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return -1
	}
	return v
}

// parseJournalAge turns one `journalctl -n1 -o short-unix` line into seconds
// since it was written, against now. -1 when there is no timestamp to read —
// journald has died silently on a production box, which then ran 24 h with
// no logs; that is the state this field exists to catch.
func parseJournalAge(out string, now time.Time) int64 {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	f := strings.Fields(lines[len(lines)-1])
	if len(f) == 0 {
		return -1
	}
	stamp, _, _ := strings.Cut(f[0], ".")
	ts, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || ts <= 0 {
		return -1
	}
	return now.Unix() - ts
}

// ── observe:sockets ──────────────────────────────────────────────────────────

type listenSocket struct {
	Proto   string `json:"proto"`
	Local   string `json:"local"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

var ssUsersRe = regexp.MustCompile(`\("([^"]*)",pid=([0-9]+)`)

// parseSS parses `ss -tlnpH` / `ss -ulnpH` (no header; -H). Columns are
// State Recv-Q Send-Q Local:Port Peer:Port [Process]; the local address is
// split at its LAST colon so "[::]:22" and "10.99.0.1:443" both read right.
// Only the first owning process is kept (sshd's socket also lists systemd,
// pid 1, which is the socket activator, not the listener that matters).
func parseSS(proto, out string) []listenSocket {
	socks := []listenSocket{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		local := f[3]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		s := listenSocket{Proto: proto, Local: local[:i], Port: port}
		if m := ssUsersRe.FindStringSubmatch(l); m != nil {
			s.Process = m[1]
			s.PID, _ = strconv.Atoi(m[2])
		}
		socks = append(socks, s)
	}
	return socks
}

// ── observe:units ────────────────────────────────────────────────────────────

type failedUnit struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

type timerUnit struct {
	Next      string `json:"next"`
	Left      string `json:"left"`
	Last      string `json:"last"`
	Passed    string `json:"passed"`
	Unit      string `json:"unit"`
	Activates string `json:"activates"`
}

// parseFailedUnits parses `systemctl list-units --failed --no-legend --plain`:
// UNIT LOAD ACTIVE SUB DESCRIPTION..., description free text.
func parseFailedUnits(out string) []failedUnit {
	units := []failedUnit{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		units = append(units, failedUnit{Unit: f[0], Load: f[1], Active: f[2], Sub: f[3],
			Description: strings.Join(f[4:], " ")})
	}
	return units
}

var weekdays = map[string]bool{"Mon": true, "Tue": true, "Wed": true, "Thu": true, "Fri": true, "Sat": true, "Sun": true}

// timerStampLen says how many tokens the timestamp at f[i] occupies: 1 for
// "-"/"n/a", 4 for "<weekday> <yyyy-mm-dd> <hh:mm:ss> UTC", 0 if f[i] is not a stamp.
func timerStampLen(f []string, i int) int {
	if i >= len(f) {
		return 0
	}
	if f[i] == "-" || f[i] == "n/a" {
		return 1
	}
	if weekdays[f[i]] && i+3 < len(f) && len(f[i+1]) == 10 && f[i+1][4] == '-' {
		return 4
	}
	return 0
}

// parseTimers parses `systemctl list-timers --all --no-legend --plain`. The
// LEFT and PASSED columns are free text of varying token count ("14s",
// "4min 39s ago"), so the line is read from both ends: UNIT and ACTIVATES are
// the last two tokens (unit names carry no spaces), NEXT and LAST are either
// "-" or a four-token timestamp, and whatever lies between is LEFT / PASSED.
func parseTimers(out string) []timerUnit {
	timers := []timerUnit{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		t := timerUnit{Unit: f[len(f)-2], Activates: f[len(f)-1]}
		f = f[:len(f)-2]
		n := timerStampLen(f, 0)
		if n == 0 {
			continue
		}
		t.Next = strings.Join(f[:n], " ")
		rest := f[n:]
		// LEFT is at least one token ("14s", "-", "1 day 2h left") and runs
		// until the next timestamp starts — so a "-" in first position is
		// LEFT, not LAST.
		j := 1
		for j < len(rest) && timerStampLen(rest, j) == 0 {
			j++
		}
		t.Left = strings.Join(rest[:j], " ")
		if m := timerStampLen(rest, j); m > 0 {
			t.Last = strings.Join(rest[j:j+m], " ")
			t.Passed = strings.Join(rest[j+m:], " ")
		}
		timers = append(timers, t)
	}
	return timers
}

// ── observe:disk ─────────────────────────────────────────────────────────────

type diskFS struct {
	Filesystem string `json:"filesystem"`
	SizeKB     int64  `json:"size_kb"`
	UsedKB     int64  `json:"used_kb"`
	AvailKB    int64  `json:"avail_kb"`
	Pct        int    `json:"pct"`
	Mount      string `json:"mount"`
}

// parseDF parses `df -P` (POSIX format: one line per filesystem, header
// first). Returns the root filesystem's percent too, for the posture field.
func parseDF(out string) []diskFS {
	fss := []diskFS{}
	for i, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 6 {
			continue
		}
		size, e1 := strconv.ParseInt(f[1], 10, 64)
		used, e2 := strconv.ParseInt(f[2], 10, 64)
		avail, e3 := strconv.ParseInt(f[3], 10, 64)
		pct, e4 := strconv.Atoi(strings.TrimSuffix(f[4], "%"))
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			continue
		}
		fss = append(fss, diskFS{Filesystem: f[0], SizeKB: size, UsedKB: used, AvailKB: avail, Pct: pct,
			Mount: strings.Join(f[5:], " ")})
	}
	return fss
}

func rootDiskPct(fss []diskFS) int {
	for _, d := range fss {
		if d.Mount == "/" {
			return d.Pct
		}
	}
	return -1
}

// ── observe:k8s ──────────────────────────────────────────────────────────────

// observeKubeconfig is placed by the control-plane installer as a READ-ONLY
// kubeconfig (a ServiceAccount bound to `view`, nothing more). This code never
// creates it: a bastion on a worker or a home box has no file and observe:k8s
// says so. Where it exists the op is read-only by the credential, not by
// argument discipline alone.
const observeKubeconfig = "/etc/privatae-bastion/observe.kubeconfig"

type k8sNode struct {
	Name    string `json:"name"`
	Ready   bool   `json:"ready"`
	Version string `json:"version"`
}

type k8sPods struct {
	Running   int      `json:"running"`
	Pending   int      `json:"pending"`
	Failed    int      `json:"failed"`
	Crashloop []string `json:"crashloop"`
}

// parseK8sNodes reduces `kubectl get nodes -o json` to name/ready/version.
func parseK8sNodes(raw []byte) ([]k8sNode, error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
				NodeInfo struct {
					KubeletVersion string `json:"kubeletVersion"`
				} `json:"nodeInfo"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	nodes := []k8sNode{}
	for _, it := range list.Items {
		n := k8sNode{Name: it.Metadata.Name, Version: it.Status.NodeInfo.KubeletVersion}
		for _, c := range it.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				n.Ready = true
			}
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// parseK8sPods reduces `kubectl get pods -A -o json` to phase counts and the
// ns/name of every pod with a container in CrashLoopBackOff.
func parseK8sPods(raw []byte) (k8sPods, error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					State struct {
						Waiting *struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	out := k8sPods{Crashloop: []string{}}
	if err := json.Unmarshal(raw, &list); err != nil {
		return out, err
	}
	for _, it := range list.Items {
		switch it.Status.Phase {
		case "Running":
			out.Running++
		case "Pending":
			out.Pending++
		case "Failed":
			out.Failed++
		}
		for _, cs := range it.Status.ContainerStatuses {
			if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
				out.Crashloop = append(out.Crashloop, it.Metadata.Namespace+"/"+it.Metadata.Name)
				break
			}
		}
	}
	return out, nil
}

// ── observe:net ──────────────────────────────────────────────────────────────

// netTargetRe is the whole grammar of the one caller-supplied value in this
// family: letters, digits, dot, dash, colon, and brackets for a v6 literal.
// No slash (a path), no space, no shell character of any kind — and the value
// still never reaches a program; it goes to net.Dial.
var netTargetRe = regexp.MustCompile(`^[A-Za-z0-9.\-:\[\]]{1,253}$`)

// parseNetTarget validates and splits host[:port]. Port defaults to 443, the
// port a public front door answers on. A v6 literal must be bracketed
// when it carries a port ("[::1]:443"); a bare "::1" is accepted as a host.
func parseNetTarget(target string) (host string, port int, err error) {
	if !netTargetRe.MatchString(target) {
		return "", 0, errors.New("target must be host[:port] using letters, digits, '.', '-', ':' and [] only")
	}
	port = 443
	host = target
	switch {
	case strings.HasPrefix(target, "["):
		end := strings.Index(target, "]")
		if end < 0 {
			return "", 0, errors.New("unclosed '[' in target")
		}
		host = target[1:end]
		rest := target[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", 0, errors.New("expected ':port' after ']'")
			}
			p, e := strconv.Atoi(rest[1:])
			if e != nil || p < 1 || p > 65535 {
				return "", 0, errors.New("bad port")
			}
			port = p
		}
		if net.ParseIP(host) == nil {
			return "", 0, errors.New("bracketed target must be an IPv6 literal")
		}
	case strings.Count(target, ":") == 1:
		h, p, _ := strings.Cut(target, ":")
		host = h
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", 0, errors.New("bad port")
		}
		port = n
	case strings.Count(target, ":") > 1:
		if net.ParseIP(target) == nil {
			return "", 0, errors.New("multiple ':' but not an IPv6 literal")
		}
	}
	if host == "" || strings.HasPrefix(host, "-") || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
		return "", 0, errors.New("bad host")
	}
	for _, ch := range host {
		if ch == '[' || ch == ']' {
			return "", 0, errors.New("bad host")
		}
	}
	return host, port, nil
}

// nonPublicRanges are the addresses observe:net refuses: the unspecified
// net, loopback, RFC1918, CGNAT (100.64/10), link-local, ULA. The purpose of
// this op is an external vantage on a NAMED PUBLIC door; a probe of a
// mesh or LAN address from this box is a different tool, so this is the
// default, not an option.
var nonPublicRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "::/128", "::1/128", "fc00::/7", "fe80::/10"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func isPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range nonPublicRanges {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

const errNetNotPublic = "observe:net probes public doors only"

// netResolve is the resolver seam (tests answer without DNS).
var netResolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// publicTarget resolves host and returns its addresses, or an error when ANY
// of them is non-public: one private record among public ones is enough to
// turn the probe inward, so all must pass.
func publicTarget(ctx context.Context, host string) ([]string, error) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		var err error
		if addrs, err = netResolve(ctx, host); err != nil {
			return nil, errors.New("resolve: " + err.Error())
		}
		if len(addrs) == 0 {
			return nil, errors.New("resolve: no addresses")
		}
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if !isPublicAddr(a) {
			return nil, errors.New(errNetNotPublic)
		}
		out = append(out, a.Unmap().String())
	}
	return out, nil
}

type netProbe struct {
	Target string `json:"target"`
	// ValidatedTarget is the normalized host:port the probe actually dialed
	// and Resolved the addresses that passed the public check, so the pod
	// can audit what was reached, not just what was asked.
	ValidatedTarget string   `json:"validated_target"`
	Resolved        []string `json:"resolved"`
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	TCP             bool     `json:"tcp"`
	TCPMs           int64    `json:"tcp_ms"`
	TCPError        string   `json:"tcp_error,omitempty"`
	TLS             *bool    `json:"tls,omitempty"`
	TLSDaysLeft     *int     `json:"tls_days_left,omitempty"`
	TLSSubject      string   `json:"tls_subject,omitempty"`
	TLSVerified     *bool    `json:"tls_verified,omitempty"`
	TLSError        string   `json:"tls_error,omitempty"`
	HTTPStatus      *int     `json:"http_status,omitempty"`
	HTTPError       string   `json:"http_error,omitempty"`
	ProbedFrom      string   `json:"probed_from"`
	ProbedAt        string   `json:"probed_at"`
	Unsupported     *string  `json:"unsupported,omitempty"`
}

const netProbeTimeout = 5 * time.Second

// probeNet is the external vantage: tcp connect, then TLS days-left when the
// port is 443 or the target is a name, then GET / on 443/80. Pure Go; nothing
// is exec'd. The TLS handshake skips verification so an expired or self-signed
// leaf still yields its dates — that is the fact an operator wants — and
// reports verification separately against the system roots.
func probeNet(target string) (netProbe, error) {
	host, port, err := parseNetTarget(target)
	if err != nil {
		return netProbe{}, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	rctx, rcancel := context.WithTimeout(context.Background(), netProbeTimeout)
	defer rcancel()
	resolved, err := publicTarget(rctx, host)
	if err != nil {
		return netProbe{}, err
	}
	p := netProbe{Target: target, ValidatedTarget: addr, Resolved: resolved, Host: host, Port: port,
		ProbedAt: time.Now().UTC().Format(time.RFC3339)}
	if hn, e := os.Hostname(); e == nil {
		p.ProbedFrom = hn
	}
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", addr, netProbeTimeout)
	p.TCPMs = time.Since(t0).Milliseconds()
	if err != nil {
		p.TCPError = err.Error()
		return p, nil
	}
	p.TCP = true
	_ = conn.Close()

	if port == 443 || net.ParseIP(host) == nil {
		ok := false
		p.TLS = &ok
		d := &net.Dialer{Timeout: netProbeTimeout}
		tc, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, InsecureSkipVerify: true}) //nolint:gosec // dates first, verification reported below
		if err != nil {
			p.TLSError = err.Error()
		} else {
			ok = true
			_ = tc.SetDeadline(time.Now().Add(netProbeTimeout))
			certs := tc.ConnectionState().PeerCertificates
			if len(certs) > 0 {
				leaf := certs[0]
				days := int(time.Until(leaf.NotAfter).Hours() / 24)
				p.TLSDaysLeft = &days
				p.TLSSubject = leaf.Subject.CommonName
				verified := verifyChain(certs, host) == nil
				p.TLSVerified = &verified
			}
			_ = tc.Close()
		}
	}

	if port == 443 || port == 80 {
		scheme := "http"
		if port == 443 {
			scheme = "https"
		}
		client := &http.Client{
			Timeout: netProbeTimeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec // status of the door, not trust in it
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := client.Get(scheme + "://" + addr + "/")
		if err != nil {
			p.HTTPError = err.Error()
		} else {
			resp.Body.Close()
			code := resp.StatusCode
			p.HTTPStatus = &code
		}
	}
	return p, nil
}

func verifyChain(certs []*x509.Certificate, host string) error {
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return err
}

// ── heartbeat posture cache ──────────────────────────────────────────────────

// posturePayload is what buildHeartbeatBody folds in: the LAST value the
// background refresh produced, never a fresh read. The heartbeat ticks every
// 60 s (run.go) and a late beat is what flips this box stale on the host
// (180 s without a beat) and can trigger quarantine, so a beat may not wait on
// a probe at all — one op budget (20 s) of hung apt would already be a third
// of the window. Measured on a real box: `apt-get -s upgrade`
// costs 0.70 s CPU, the other nine probes 45 ms together; a refresh every
// 5 minutes is 12 apt simulations an hour instead of 60. The first beat after
// start may carry no posture; off Linux there is never one (no key).
const postureRefreshEvery = 5 * time.Minute

var (
	postureMu   sync.Mutex
	postureLast *heartbeatPosture
)

func posturePayload() *heartbeatPosture {
	postureMu.Lock()
	defer postureMu.Unlock()
	return postureLast
}

// refreshPosture reads the posture once and publishes it.
func refreshPosture() {
	if !observeHostSupported {
		return
	}
	p := readHostPosture().compact()
	postureMu.Lock()
	postureLast = &p
	postureMu.Unlock()
}

// runPostureRefresh is started by the heartbeat goroutine (run.go) and lives
// as long as it does: one read now, then one per window.
func runPostureRefresh(ctx context.Context) {
	if !observeHostSupported {
		return
	}
	refreshPosture()
	t := time.NewTicker(postureRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refreshPosture()
		}
	}
}

// ── the handlers ─────────────────────────────────────────────────────────────

// writeObserve answers with the JSON on stdout and exit 0 — an unsupported box
// or a missing tool is a true answer, not a refusal (126 stays "not permitted").
func writeObserve(ws *websocket.Conn, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		sendMgmt(ws, 'R', []byte("report: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	// The machine's own record of what it answered (machinestore.go, the
	// observe shelf): the same bytes that go down the lane, filed under the op
	// and the host that asked. Read off this connection's account rather than
	// threaded through eleven handlers. BEFORE the reply, so a slow disk
	// cannot leave a result sent-but-unrecorded; a failed write is counted,
	// never allowed to fail the reply.
	if a := mgmtAccountOf(ws); a != nil {
		storeRecordObserve(a.op, a.self, a.args, b, time.Now())
	}
	observeSendFrame(ws, 'O', append(b, '\n'))
	sendMgmtExit(ws, 0)
}

// observeSendFrame is the seam the ordering test uses: it swaps this for a
// sender that checks the record is already on disk at the moment the reply
// goes. The property the comment above calls load-bearing had no test behind
// it — moving the record after the reply passed the entire suite.
var observeSendFrame = sendMgmt

func observeUnsupported() map[string]string { return map[string]string{"unsupported": runtime.GOOS} }

// Every handler below ignores args (there are none) except observe:net, which
// reads exactly one and validates it before use. That property is what
// TestObserveArgsNeverReachArgv checks through the observeExec seam.

func handleObserveHost(ws *websocket.Conn, _ string, _ []string) {
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	writeObserve(ws, readHostPosture())
}

func handleObserveSockets(ws *websocket.Conn, _ string, _ []string) {
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	writeObserve(ws, readSockets())
}

func handleObserveFirewall(ws *websocket.Conn, _ string, _ []string) {
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	writeObserve(ws, readFirewall())
}

func handleObserveUnits(ws *websocket.Conn, _ string, _ []string) {
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	writeObserve(ws, readUnits())
}

func handleObserveDisk(ws *websocket.Conn, _ string, _ []string) {
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	writeObserve(ws, readDisk())
}

func handleObserveKernel(ws *websocket.Conn, _ string, _ []string) {
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	writeObserve(ws, readKernel())
}

func handleObserveK8s(ws *websocket.Conn, _ string, _ []string) {
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	writeObserve(ws, readK8s())
}

// observe:net works on every platform: it is pure Go.
func handleObserveNet(ws *websocket.Conn, _ string, args []string) {
	if len(args) != 1 {
		sendMgmt(ws, 'R', []byte("observe:net takes exactly one argument: host[:port]\n"))
		sendMgmtExit(ws, 2)
		return
	}
	p, err := probeNet(args[0])
	if err != nil {
		sendMgmt(ws, 'R', []byte("refused: "+err.Error()+"\n"))
		sendMgmtExit(ws, 2)
		return
	}
	writeObserve(ws, p)
}

// capLines keeps the LAST n lines and at most capBytes of text, and says
// whether anything was cut.
func capLines(s string, n, capBytes int) (string, bool) {
	cut := false
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
		cut = true
	}
	out := strings.Join(lines, "\n")
	if len(out) > capBytes {
		out = out[len(out)-capBytes:]
		cut = true
	}
	return out, cut
}

func capBytes(s string, capBytes int) (string, bool) {
	if len(s) > capBytes {
		return s[:capBytes], true
	}
	return s, false
}
