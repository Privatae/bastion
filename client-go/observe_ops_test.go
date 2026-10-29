package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── fixtures ─────────────────────────────────────────────────────────────────
// ss, df, apt, systemctl and fxPubwallDropBareCounter were captured on
// a real box. fxPubwallDropTdrop is ILLUSTRATIVE: the
// hardened `drop+tdrop` shape with a terminal drop verdict appended. That
// box's own chain ends in a bare counter (no verdict) and reads "drop".

const fxPubwallDropTdrop = `table inet pubwall {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname != "enp1s0" accept comment "lo/mgmt0/docker0 — loopback and mesh are trusted"
		ct state established,related accept comment "replies to outbound (collector dials the fleet)"
		meta l4proto icmp accept
		udp dport 51829 accept comment "wireguard mgmt0 hub"
		tcp dport 22 ip saddr 192.168.122.1 accept comment "ssh from hypervisor (a fleet box)"
		counter packets 0 bytes 0 drop comment "terminal"
	}
}
`

// As captured: policy drop, last rule is a counter with no verdict.
const fxPubwallDropBareCounter = `table inet pubwall {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname != "enp1s0" accept comment "lo/mgmt0/docker0 — loopback and mesh are trusted"
		tcp dport 22 ip saddr 192.168.122.1 accept comment "ssh from hypervisor (a fleet box)"
		counter packets 0 bytes 0 comment "falls through to policy drop"
	}
}
`

const fxPubwallAcceptNoTdrop = `table inet pubwall {
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "lo" accept
		counter packets 0 bytes 0 comment "falls through to policy"
	}
}
`

// A terminal drop in FORWARD must not count for the input chain.
const fxPubwallForwardOnly = `table inet pubwall {
	chain forward {
		type filter hook forward priority filter; policy accept;
		counter packets 0 bytes 0 drop
	}
}
`

const fxSS = `LISTEN 0      4096       10.99.0.1:443   0.0.0.0:* users:(("caddy",pid=2074,fd=4))
LISTEN 0      32         10.99.0.1:53    0.0.0.0:* users:(("dnsmasq",pid=2068,fd=5))
LISTEN 0      4096         0.0.0.0:22    0.0.0.0:* users:(("sshd",pid=2180924,fd=3),("systemd",pid=1,fd=305))
LISTEN 0      4096            [::]:22       [::]:* users:(("sshd",pid=2180924,fd=4))
LISTEN 0      128                *:8011          *:*
`

const fxDF = `Filesystem     1024-blocks     Used Available Capacity Mounted on
tmpfs              9766696     1700   9764996       1% /run
/dev/vda1        120846448 34820680  86009384      29% /
tmpfs             24416736       28  24416708       1% /dev/shm
/dev/sdb1        976283K    12 976283 1% /mnt/with space
`

const fxApt = `Reading package lists...
Inst motd-news-config [14ubuntu6.1] (14ubuntu6.2 Ubuntu:26.04/resolute-updates [all])
Inst base-files [14ubuntu6.1] (14ubuntu6.2 Ubuntu:26.04/resolute-security [amd64])
Conf base-files (14ubuntu6.2 Ubuntu:26.04/resolute-security [amd64])
Inst openssl [3.0.2] (3.0.3 Ubuntu:26.04/resolute-security [amd64])
Conf openssl (3.0.3 Ubuntu:26.04/resolute-security [amd64])
Conf motd-news-config (14ubuntu6.2 Ubuntu:26.04/resolute-updates [all])
`

const fxFailed = `backup-report.service loaded failed failed Nightly backup confirmation email for the whole fleet
foo.service loaded failed failed
`

const fxTimers = `Tue 2026-09-08 01:03:00 UTC      14s Tue 2026-09-08 01:02:02 UTC       42s ago sentinel-scheduler.timer                         sentinel-scheduler.service
Tue 2026-09-08 01:03:06 UTC      20s Tue 2026-09-08 00:58:06 UTC  4min 39s ago privatae-zone-probe.timer                        privatae-zone-probe.service
- - Mon 2026-09-07 06:00:00 UTC 19h ago apt-daily.timer apt-daily.service
Wed 2026-09-09 00:00:00 UTC 1 day 2h left - - never-ran.timer never-ran.service
`

const fxNodes = `{"items":[
 {"metadata":{"name":"cp-1"},"status":{"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"kubeletVersion":"v1.33.1+k3s1"}}},
 {"metadata":{"name":"w-1"},"status":{"conditions":[{"type":"Ready","status":"False"}],"nodeInfo":{"kubeletVersion":"v1.33.1+k3s1"}}}
]}`

const fxPods = `{"items":[
 {"metadata":{"name":"a","namespace":"x"},"status":{"phase":"Running","containerStatuses":[{"state":{"running":{}}}]}},
 {"metadata":{"name":"b","namespace":"x"},"status":{"phase":"Pending","containerStatuses":[]}},
 {"metadata":{"name":"c","namespace":"y"},"status":{"phase":"Running","containerStatuses":[{"state":{"waiting":{"reason":"CrashLoopBackOff"}}},{"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}},
 {"metadata":{"name":"d","namespace":"y"},"status":{"phase":"Failed"}}
]}`

// ── parsers ──────────────────────────────────────────────────────────────────

func TestParseUfwStatus(t *testing.T) {
	if got := parseUfwStatus("Status: inactive\n"); got != "inactive" {
		t.Fatalf("got %q", got)
	}
	if got := parseUfwStatus("Status: active\n\nTo   Action\n"); got != "active" {
		t.Fatalf("got %q", got)
	}
	if got := parseUfwStatus(""); got != "unknown" {
		t.Fatalf("empty must be unknown, got %q", got)
	}
}

func TestParsePubwall(t *testing.T) {
	cases := map[string]string{
		fxPubwallDropTdrop:       "drop+tdrop",
		fxPubwallDropBareCounter: "drop",
		fxPubwallAcceptNoTdrop:   "accept",
		fxPubwallForwardOnly:     "absent",
		"":                       "absent",
	}
	for in, want := range cases {
		if got := parsePubwall(in); got != want {
			t.Fatalf("want %s got %s for:\n%s", want, got, in)
		}
	}
}

func TestParseSSH22WorstMatchWins(t *testing.T) {
	if got := parseSSH22(fxPubwallDropTdrop, "", false); got != "scoped" {
		t.Fatalf("scoped rule only: %s", got)
	}
	mixed := fxPubwallDropTdrop + "\t\ttcp dport 22 accept comment \"debug leftover\"\n"
	if got := parseSSH22(mixed, "", false); got != "unscoped" {
		t.Fatalf("one bare accept must read unscoped: %s", got)
	}
	set := "\t\ttcp dport { 22, 443 } accept\n"
	if got := parseSSH22(set, "", false); got != "unscoped" {
		t.Fatalf("set form without saddr: %s", got)
	}
	// no pubwall rule: fall to ufw
	ufwAny := "Status: active\n\nTo   Action  From\n22/tcp  ALLOW  Anywhere\n"
	if got := parseSSH22("", ufwAny, true); got != "unscoped" {
		t.Fatalf("ufw Anywhere: %s", got)
	}
	ufwScoped := "Status: active\n\n22/tcp  ALLOW  10.0.0.0/8\n"
	if got := parseSSH22("", ufwScoped, true); got != "scoped" {
		t.Fatalf("ufw scoped: %s", got)
	}
	if got := parseSSH22("", ufwAny, false); got != "unknown" {
		t.Fatalf("no ufw binary means its text is not consulted: %s", got)
	}
	if got := parseSSH22("", "", true); got != "unknown" {
		t.Fatalf("nothing anywhere: %s", got)
	}
}

func TestParseIptablesInputPolicy(t *testing.T) {
	if got := parseIptablesInputPolicy("-P INPUT ACCEPT\n-P FORWARD DROP\n"); got != "ACCEPT" {
		t.Fatalf("got %q", got)
	}
	if got := parseIptablesInputPolicy("-P FORWARD DROP\n"); got != "unknown" {
		t.Fatalf("got %q", got)
	}
}

// Anchored on ^Inst: the Conf lines carry the pocket too and doubled the count.
func TestParseAptSecurityCountsPackagesNotLines(t *testing.T) {
	if got := parseAptSecurityCount(fxApt); got != 2 {
		t.Fatalf("want 2 packages, got %d", got)
	}
	// Empty or whitespace output is "could not read", never a clean 0.
	for _, in := range []string{"", "\n  \n"} {
		if got := parseAptSecurityCount(in); got != -1 {
			t.Fatalf("%q must be -1, got %d", in, got)
		}
	}
	if got := parseAptSecurityCount("Reading package lists...\nBuilding dependency tree...\n"); got != 0 {
		t.Fatalf("apt that spoke and listed nothing is a real 0: %d", got)
	}
}

func TestParseLoadavgAndJournal(t *testing.T) {
	if got := parseLoadavg("0.42 0.30 0.25 1/512 1234\n"); got != 0.42 {
		t.Fatalf("load %v", got)
	}
	if got := parseLoadavg(""); got != -1 {
		t.Fatalf("empty load must be -1: %v", got)
	}
	now := time.Unix(1788829400, 0)
	line := "1788829339.762969 a measured box systemd[1]: code-index-sweep.service: Consumed 862ms\n"
	if got := parseJournalAge(line, now); got != 61 {
		t.Fatalf("jrn %d", got)
	}
	if got := parseJournalAge("", now); got != -1 {
		t.Fatalf("no line must be -1: %d", got)
	}
	if got := parseJournalAge("-- No entries --\n", now); got != -1 {
		t.Fatalf("no entries must be -1: %d", got)
	}
}

func TestParseSS(t *testing.T) {
	got := parseSS("tcp", fxSS)
	if len(got) != 5 {
		t.Fatalf("want 5 sockets, got %d: %+v", len(got), got)
	}
	if got[0].Local != "10.99.0.1" || got[0].Port != 443 || got[0].Process != "caddy" || got[0].PID != 2074 {
		t.Fatalf("row 0: %+v", got[0])
	}
	if got[2].Process != "sshd" || got[2].PID != 2180924 {
		t.Fatalf("first owner wins, not systemd: %+v", got[2])
	}
	if got[3].Local != "[::]" || got[3].Port != 22 {
		t.Fatalf("v6 local split at last colon: %+v", got[3])
	}
	if got[4].Local != "*" || got[4].Port != 8011 || got[4].Process != "" || got[4].PID != 0 {
		t.Fatalf("no owner column: %+v", got[4])
	}
}

func TestParseDF(t *testing.T) {
	got := parseDF(fxDF)
	if len(got) != 3 {
		t.Fatalf("header skipped, bad row skipped: %+v", got)
	}
	if got[1].Filesystem != "/dev/vda1" || got[1].UsedKB != 34820680 || got[1].Pct != 29 || got[1].Mount != "/" {
		t.Fatalf("root row: %+v", got[1])
	}
	if rootDiskPct(got) != 29 {
		t.Fatalf("rootDiskPct")
	}
	if rootDiskPct(nil) != -1 {
		t.Fatalf("no root must be -1")
	}
}

func TestParseFailedUnits(t *testing.T) {
	got := parseFailedUnits(fxFailed)
	if len(got) != 2 || got[0].Unit != "backup-report.service" || got[0].Sub != "failed" ||
		!strings.HasPrefix(got[0].Description, "Nightly backup") || got[1].Description != "" {
		t.Fatalf("%+v", got)
	}
}

func TestParseTimers(t *testing.T) {
	got := parseTimers(fxTimers)
	if len(got) != 4 {
		t.Fatalf("want 4, got %d: %+v", len(got), got)
	}
	if got[1].Next != "Tue 2026-09-08 01:03:06 UTC" || got[1].Left != "20s" || got[1].Last != "Tue 2026-09-08 00:58:06 UTC" ||
		got[1].Passed != "4min 39s ago" || got[1].Unit != "privatae-zone-probe.timer" || got[1].Activates != "privatae-zone-probe.service" {
		t.Fatalf("row 1: %+v", got[1])
	}
	if got[2].Next != "-" || got[2].Left != "-" || got[2].Last != "Mon 2026-09-07 06:00:00 UTC" || got[2].Passed != "19h ago" || got[2].Unit != "apt-daily.timer" {
		t.Fatalf("no-next row: %+v", got[2])
	}
	if got[3].Left != "1 day 2h left" || got[3].Last != "-" || got[3].Passed != "-" {
		t.Fatalf("never-ran row: %+v", got[3])
	}
}

func TestParseK8s(t *testing.T) {
	nodes, err := parseK8sNodes([]byte(fxNodes))
	if err != nil || len(nodes) != 2 || !nodes[0].Ready || nodes[1].Ready || nodes[0].Version != "v1.33.1+k3s1" {
		t.Fatalf("nodes: %v %+v", err, nodes)
	}
	pods, err := parseK8sPods([]byte(fxPods))
	if err != nil || pods.Running != 2 || pods.Pending != 1 || pods.Failed != 1 {
		t.Fatalf("pods: %v %+v", err, pods)
	}
	if len(pods.Crashloop) != 1 || pods.Crashloop[0] != "y/c" {
		t.Fatalf("crashloop listed once per pod: %+v", pods.Crashloop)
	}
	if _, err := parseK8sNodes([]byte("not json")); err == nil {
		t.Fatalf("bad json must error")
	}
}

func TestCapLines(t *testing.T) {
	in := strings.Repeat("x\n", 300)
	out, cut := capLines(in, 200, 1<<20)
	if !cut || strings.Count(out, "\n") != 199 {
		t.Fatalf("keep last 200: cut=%v n=%d", cut, strings.Count(out, "\n"))
	}
	out, cut = capLines("a\nb\n", 200, 1<<20)
	if cut || out != "a\nb" {
		t.Fatalf("short input untouched: %q %v", out, cut)
	}
}

// ── observe:net validator ────────────────────────────────────────────────────

func TestParseNetTargetAccepts(t *testing.T) {
	cases := map[string][2]any{
		"privatae.ai":           {"privatae.ai", 443},
		"privatae.ai:8443":      {"privatae.ai", 8443},
		"203.0.113.10":          {"203.0.113.10", 443},
		"203.0.113.10:22":       {"203.0.113.10", 22},
		"[2001:db8::1]:443":     {"2001:db8::1", 443},
		"2001:db8::1":           {"2001:db8::1", 443},
		"edge.example.net":      {"edge.example.net", 443},
		"localhost:80":          {"localhost", 80},
		"[fe80::1]":             {"fe80::1", 443},
		"a-b.c-d.example:65535": {"a-b.c-d.example", 65535},
	}
	for in, want := range cases {
		h, p, err := parseNetTarget(in)
		if err != nil || h != want[0] || p != want[1] {
			t.Fatalf("%q: got (%q,%d,%v) want %v", in, h, p, err, want)
		}
	}
}

func TestParseNetTargetRejects(t *testing.T) {
	bad := []string{
		"", " ", "host name", "host;id", "host|id", "host&&id", "$(id)", "`id`", "host\nid",
		"/etc/passwd", "../x", "host/path", "host:", "host:0", "host:70000", "host:abc",
		"-flag", "--kubeconfig", ".hidden", "a..b", "[::1", "[::1]x", "[::1]:", "[notv6]:443",
		"a:b:c", "host:22:22", "user@host", "host?x=1", "host#frag", "héllo.example",
		strings.Repeat("a", 300),
	}
	for _, in := range bad {
		if _, _, err := parseNetTarget(in); err == nil {
			t.Fatalf("%q must be rejected", in)
		}
	}
}

// observe:net probes public doors only: every non-public range is refused,
// by literal and by resolution, and one private record among public ones
// is enough.
func TestNetTargetPublicOnly(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"100.64.0.1", "100.127.255.255", "169.254.169.254", "0.0.0.0", "::1", "::", "fc00::1", "fd12::1", "fe80::1",
		"::ffff:10.0.0.1"} {
		if isPublicAddr(netip.MustParseAddr(ip)) {
			t.Fatalf("%s must be non-public", ip)
		}
	}
	for _, ip := range []string{"203.0.113.10", "203.0.113.11", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700::1111"} {
		if !isPublicAddr(netip.MustParseAddr(ip)) {
			t.Fatalf("%s must be public", ip)
		}
	}
	orig := netResolve
	defer func() { netResolve = orig }()
	netResolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "public.example":
			return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2606:4700::1111")}, nil
		case "split.example":
			return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("10.0.0.5")}, nil
		}
		return nil, errors.New("no such host")
	}
	if got, err := publicTarget(context.Background(), "public.example"); err != nil || len(got) != 2 {
		t.Fatalf("public name: %v %v", got, err)
	}
	if _, err := publicTarget(context.Background(), "split.example"); err == nil || err.Error() != errNetNotPublic {
		t.Fatalf("one private record must refuse the whole name: %v", err)
	}
	if _, err := publicTarget(context.Background(), "10.0.0.5"); err == nil || err.Error() != errNetNotPublic {
		t.Fatalf("private literal: %v", err)
	}
	if _, err := publicTarget(context.Background(), "nx.example"); err == nil {
		t.Fatalf("unresolvable must error")
	}
	// through the dispatcher: a private literal is refused with the plain reason and never dialed
	for _, target := range []string{"127.0.0.1:1", "10.0.0.1", "[fe80::1]:443", "100.64.0.1:22", "[fc00::1]"} {
		_, errOut, code := driveObserve(t, "observe:net", []string{target})
		if code == 0 || !strings.Contains(errOut, errNetNotPublic) {
			t.Fatalf("%s: code=%d err=%q", target, code, errOut)
		}
	}
}

// ── the wall: table membership and args never reaching argv ──────────────────

var observeOps = []string{"observe:host", "observe:sockets", "observe:firewall", "observe:units",
	"observe:disk", "observe:kernel", "observe:k8s", "observe:net",
	"observe:alerts", "observe:metrics", "observe:logs",
	"observe:folders", "observe:journal", "observe:logins", "observe:cert"}

// observeArgOps are the ops in the family that read a caller value. Every one
// of them must REFUSE the poison set rather than answer it; the rest ignore
// args entirely. observe:alerts is deliberately not here — it takes no
// argument, like observe:host.
// observeArgRefusal pins the REASON each of them gives when handed the wrong
// number of arguments, not merely the fact that it refused. observe:net's
// "one argument" was asserted before the pull ops joined this list and the
// assertion must not weaken to a bare exit code because two more ops arrived:
// a refusal that stops saying why is exactly the regression worth catching.
var observeArgRefusal = map[string]string{
	"observe:net":     "one argument",
	"observe:metrics": "exactly one argument",
	"observe:logs":    "takes a name",
	"observe:folders": "takes a folder path",
	"observe:journal": "takes a unit name",
	"observe:logins":  "at most one argument",
	"observe:cert":    "takes a local tcp port",
}

var observeArgOps = func() map[string]bool {
	m := map[string]bool{}
	for op := range observeArgRefusal {
		m[op] = true
	}
	return m
}()

func TestObserveOpsInVocabulary(t *testing.T) {
	vocab := mgmtOpVocabulary()
	for _, op := range observeOps {
		i := sort.SearchStrings(vocab, op)
		if i >= len(vocab) || vocab[i] != op {
			t.Fatalf("%s missing from the enforcing vocabulary: %v", op, vocab)
		}
		if handlerOps[op].root != rootNone {
			t.Fatalf("%s must need no configured root", op)
		}
	}
}

// driveObserve sends one job through the real dispatcher and returns stdout,
// stderr and the exit code.
func driveObserve(t *testing.T, op string, args []string) (string, string, int) {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConn(ws, "", "", "")
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	job, _ := json.Marshal(mgmtJob{Op: op, Args: args})
	if err := c.WriteMessage(websocket.BinaryMessage, append([]byte("C"), job...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errOut string
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch data[0] {
		case 'O':
			out += string(data[1:])
		case 'R':
			errOut += string(data[1:])
		case 'X':
			code, err := strconv.Atoi(strings.TrimSpace(string(data[1:])))
			if err != nil {
				t.Fatalf("exit: %v", err)
			}
			return out, errOut, code
		}
	}
}

// fixedArgvs is the pinned argv set per op — the sudoers discipline
// (a read-only sudoers policy pins every argument exactly)
// applied here as a test: the recorded set must EQUAL this list, so an
// added flag or a new exec is a test failure, not a quiet widening. Every
// tool is "present" in the test (observeHave → true); observe:k8s runs its
// two kubectls only where the read-only kubeconfig exists.
func fixedArgvs(op string) []string {
	switch op {
	case "observe:host":
		return []string{
			"ufw status",
			"nft list chain inet pubwall input",
			"nft list table inet pubwall",
			"systemctl is-active fail2ban",
			"iptables -S",
			"apt-get -s upgrade",
			"journalctl -n1 -o short-unix --no-pager",
		}
	case "observe:sockets":
		return []string{"ss -tlnpH", "ss -ulnpH"}
	case "observe:firewall":
		return []string{"nft list ruleset", "ufw status verbose"}
	case "observe:units":
		return []string{"systemctl list-units --failed --no-legend --plain",
			"systemctl list-timers --all --no-legend --plain"}
	case "observe:disk":
		return []string{"df -P"}
	case "observe:kernel":
		return []string{"dmesg -T"}
	case "observe:k8s":
		if _, err := os.Stat(observeKubeconfig); err != nil {
			return nil
		}
		return []string{"kubectl --kubeconfig " + observeKubeconfig + " get nodes -o json",
			"kubectl --kubeconfig " + observeKubeconfig + " get pods -A -o json"}
	}
	return nil // observe:net execs nothing
}

// Every observe op is fed poisoned args through the real dispatcher while the
// exec seam records every argv. The recorded set must equal the pinned fixed
// list for the op (so no poison byte, no extra flag, no extra exec), and
// observe:net must refuse before doing anything. This is the mechanical form
// of the rule in the file header: fixed argvs, one validated value, nothing
// from the job reaches a program.
func TestObserveArgsNeverReachArgv(t *testing.T) {
	if !observeHostSupported {
		t.Skip("the drivers are linux; the stub execs nothing")
	}
	// Each value is one a fixed argv could never contain by accident; a bare
	// "-o" would collide with journalctl's own flag and prove nothing.
	poison := []string{"; rm -rf /", "$(id)", "`id`", "--kubeconfig=/tmp/evil", "--output=/tmp/x", "/etc/shadow", "|| true"}
	var recorded []string
	origExec, origHave := observeExec, observeHave
	observeExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		recorded = append(recorded, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	}
	observeHave = func(string) bool { return true }
	defer func() { observeExec, observeHave = origExec, origHave }()
	// The pull ops read an endpoints file; point them at one that is not there
	// so this test is hermetic and they answer "unconfigured" instead of
	// dialling whatever the box that runs the suite happens to have.
	defer withNoEndpointsFile(t)()
	// And prove it, rather than assuming: nothing in this test may leave the
	// process. The HTTP seam records any URL and fails the test on sight.
	origGet := observeHTTPGet
	observeHTTPGet = func(_ context.Context, rawURL string) ([]byte, int, error) {
		t.Fatalf("an observe op reached the network at %q with no endpoints file", rawURL)
		return nil, 0, nil
	}
	defer func() { observeHTTPGet = origGet }()

	for _, op := range observeOps {
		recorded = nil
		out, errOut, code := driveObserve(t, op, poison)
		if observeArgOps[op] {
			if code == 0 {
				t.Fatalf("%s with %d poisoned args must refuse: code=%d err=%q", op, len(poison), code, errOut)
			}
			// The REASON, pinned per op — see observeArgRefusal.
			if want := observeArgRefusal[op]; !strings.Contains(errOut, want) {
				t.Fatalf("%s: the arity refusal must say %q, got %q", op, want, errOut)
			}
			// exactly one poisoned value: still refused — by the charset check
			// for observe:net, by the fixed query table for metrics and logs,
			// and by the written grammar of each of the four in observe_reads.go.
			_, errOut, code = driveObserve(t, op, poison[:1])
			if code == 0 {
				t.Fatalf("%s with a shell value must refuse: code=%d err=%q", op, code, errOut)
			}
			if !strings.Contains(errOut, "refused") {
				t.Fatalf("%s: a refusal must say so: %q", op, errOut)
			}
			for _, p := range poison {
				if strings.Contains(errOut, p) {
					t.Fatalf("%s echoed the caller's value back: %q", op, errOut)
				}
			}
		} else {
			if code != 0 {
				t.Fatalf("%s: exit %d err=%q", op, code, errOut)
			}
			if !json.Valid([]byte(out)) {
				t.Fatalf("%s: not JSON: %q", op, out)
			}
		}
		want := fixedArgvs(op)
		got := append([]string(nil), recorded...)
		sort.Strings(want)
		sort.Strings(got)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%s: recorded argv set differs from the pinned list\n got: %q\nwant: %q", op, got, want)
		}
		for _, argv := range got {
			for _, p := range poison {
				if strings.Contains(argv, p) {
					t.Fatalf("job arg %q reached argv %q", p, argv)
				}
			}
		}
	}
}

// A hung tool costs the fields after it, marked "timeout", and the op still
// answers: the exec seam sleeps past a tiny budget on the second nft call.
func TestObserveHostBudgetMarksTimeouts(t *testing.T) {
	if !observeHostSupported {
		t.Skip("linux drivers only")
	}
	origExec, origHave := observeExec, observeHave
	observeExec = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "nft" && args[1] == "table" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if name == "ufw" {
			return []byte("Status: active\n"), nil
		}
		return nil, nil
	}
	observeHave = func(string) bool { return true }
	origBudget := observeOpBudget
	observeOpBudget = 50 * time.Millisecond // the real 20 s is too long for a unit test
	defer func() { observeExec, observeHave, observeOpBudget = origExec, origHave, origBudget }()
	t0 := time.Now()
	p := readHostPosture()
	if time.Since(t0) > 5*time.Second {
		t.Fatalf("op did not answer inside a bound: %v", time.Since(t0))
	}
	if p.Ufw != "active" {
		t.Fatalf("a field read before the hang keeps its value: %+v", p)
	}
	if p.Ssh22 != "timeout" || len(p.Timeouts) == 0 || p.Timeouts[0] != "ssh22" {
		t.Fatalf("the hung field is marked: %+v", p)
	}
}

// Off Linux every driver op answers {"unsupported": goos} and exit 0; on Linux
// the same shape is what observe_ops_other.go would send. Checked here for the
// build that runs the tests so the contract has a witness on every CI.
func TestObserveUnsupportedShape(t *testing.T) {
	b, _ := json.Marshal(observeUnsupported())
	if string(b) != `{"unsupported":"`+runtime.GOOS+`"}` {
		t.Fatalf("%s", b)
	}
}

// ── heartbeat posture ────────────────────────────────────────────────────────

// A beat NEVER runs a probe: it serves what the background refresh last
// published, and carries no key until one has.
func TestHeartbeatPostureServedNeverProbed(t *testing.T) {
	postureMu.Lock()
	postureLast = nil
	postureMu.Unlock()
	defer func() {
		postureMu.Lock()
		postureLast = nil
		postureMu.Unlock()
	}()
	calls := 0
	origExec, origHave := observeExec, observeHave
	observeExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	observeHave = func(string) bool { return true }
	defer func() { observeExec, observeHave = origExec, origHave }()

	raw := buildHeartbeatBody("", "box", runtime.GOOS, "test", "pub", "fp", "", "", false, nil, nil, nil)
	if strings.Contains(raw, `"posture"`) {
		t.Fatalf("before any refresh the beat carries no posture: %s", raw)
	}
	if calls != 0 {
		t.Fatalf("a beat ran %d probes; it must run none", calls)
	}
	if !observeHostSupported {
		refreshPosture()
		raw = buildHeartbeatBody("", "box", runtime.GOOS, "test", "pub", "fp", "", "", false, nil, nil, nil)
		if strings.Contains(raw, `"posture"`) || calls != 0 {
			t.Fatalf("no posture key off linux: %s", raw)
		}
	}
}

func TestHeartbeatPostureCachedAndTyped(t *testing.T) {
	if !observeHostSupported {
		t.Skip("linux drivers only")
	}
	calls := 0
	origExec, origHave := observeExec, observeHave
	observeExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		switch name {
		case "ufw":
			return []byte("Status: inactive\n"), nil
		case "nft":
			return []byte(fxPubwallDropTdrop), nil
		case "apt-get":
			return []byte(fxApt), nil
		case "systemctl":
			return []byte("active\n"), nil
		}
		return nil, nil
	}
	observeHave = func(string) bool { return true }
	postureMu.Lock()
	postureLast = nil
	postureMu.Unlock()
	defer func() {
		observeExec, observeHave = origExec, origHave
		postureMu.Lock()
		postureLast = nil
		postureMu.Unlock()
	}()

	refreshPosture() // what the background loop does once per window
	raw := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	var body struct {
		Posture heartbeatPosture `json:"posture"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("%v", err)
	}
	p := body.Posture
	if p.Ufw != "inactive" || p.Pubwall != "drop+tdrop" || p.Ssh22 != "scoped" || p.F2b != "active" || p.Sec != 2 ||
		p.Cpus < 1 || p.Reboot == "" || p.DiskPct < 0 {
		t.Fatalf("posture: %+v", p)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	keys := m["posture"].(map[string]any)
	for _, k := range []string{"ufw", "pubwall", "ssh22", "f2b", "sec", "load", "cpus", "reboot", "diskpct", "jrn"} {
		if _, ok := keys[k]; !ok {
			t.Fatalf("posture missing %s: %v", k, keys)
		}
	}
	if _, ok := keys["input"]; ok {
		t.Fatalf("input stays on observe:host, not the heartbeat")
	}
	first := calls
	if first == 0 {
		t.Fatalf("no probes ran")
	}
	_ = buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	_ = buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if calls != first {
		t.Fatalf("beats must be served from the published value, never probe: %d -> %d execs", first, calls)
	}
}

// The external vantage, for real — gated like the other live tests because it
// dials out.
func TestObserveNetLive(t *testing.T) {
	if os.Getenv("PRIVATAE_OBSERVE_LIVE") != "1" {
		t.Skip("set PRIVATAE_OBSERVE_LIVE=1 to dial out")
	}
	for _, target := range []string{"privatae.ai", "privatae.ai:80", "203.0.113.10:9"} {
		out, errOut, code := driveObserve(t, "observe:net", []string{target})
		if code != 0 {
			t.Fatalf("%s: exit %d %s", target, code, errOut)
		}
		if !strings.Contains(out, `"validated_target":`) || !strings.Contains(out, `"resolved":[`) {
			t.Fatalf("%s: result must carry the validated target and resolved addresses: %s", target, out)
		}
		t.Logf("%s: %s", target, strings.TrimSpace(out))
	}
}

// The real thing on this machine — same switch as the other live tests.
func TestObserveLive(t *testing.T) {
	if !observeHostSupported {
		t.Skip("linux only")
	}
	if testing.Short() {
		t.Skip("runs the real probes")
	}
	for _, op := range observeOps[:7] {
		out, errOut, code := driveObserve(t, op, nil)
		if code != 0 {
			t.Fatalf("%s: exit %d %s", op, code, errOut)
		}
		if len(out) > 400 {
			out = out[:400] + "…"
		}
		t.Logf("%s: %s", op, strings.TrimSpace(out))
	}
}
