//go:build !windows

package main

// The connection watch's decisions (rootexec_watch.go), without the kernel:
// which destinations count as outside, what the J frame carries, and that a
// command whose connections could not be watched is never reported clean.
// The kernel half is rootexec_watch_linux_test.go, in a private network
// namespace.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// No test in this package touches this machine's nftables or cgroups unless
// it says so: the default watch here records nothing and creates nothing. The
// kernel tests put the real one back, inside their own network namespace.
func init() {
	rootExecWatchStart = func(string) *rootExecWatch { return &rootExecWatch{fd: -1} }
	rootExecWatchStop = func(w *rootExecWatch) ([]rootExecConn, string) { return nil, w.Err }
	rootExecWatchKill = func(*rootExecWatch) {}
}

// When a wall stops holding mid-run, the command's whole cgroup is killed as
// well as its process group, so a child that left the group (setsid, a double
// fork) does not keep running as root after a revoke. A command that ends by
// itself is never killed that way: what it left running lives on, as before.
func TestRootExecWallStopKillsTheCommandsCgroup(t *testing.T) {
	old := rootExecRecheck
	rootExecRecheck = 50 * time.Millisecond
	oldStart, oldKill := rootExecWatchStart, rootExecWatchKill
	t.Cleanup(func() { rootExecRecheck, rootExecWatchStart, rootExecWatchKill = old, oldStart, oldKill })
	var mine *rootExecWatch
	rootExecWatchStart = func(string) *rootExecWatch { mine = &rootExecWatch{fd: -1}; return mine }
	var killed []*rootExecWatch
	var mu sync.Mutex
	rootExecWatchKill = func(w *rootExecWatch) { mu.Lock(); killed = append(killed, w); mu.Unlock() }

	env := rootExecBox(t, true)
	withFakeExec(t, "", "", 0, false)
	j := runWatched(t, env, "exec-cg-clean")
	if j["exit"] != float64(0) {
		t.Fatalf("the clean command: %v", j)
	}
	mu.Lock()
	n := len(killed)
	mu.Unlock()
	if n != 0 {
		t.Fatal("a command that ended by itself must not have its cgroup killed")
	}

	fe := withFakeExec(t, "started\n", "", 0, true)
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, "exec-cg-fall", "setsid sleep 999 & sleep 999", 600, 0)
	for i := 0; i < 300 && len(fe.ran()) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := rootExecRevoke(env.DcnDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := readUntil(t, ws, 'X', 3*time.Second)
	if string(got['X']) != "126" {
		t.Fatalf("stopped by the revoke: X=%q E=%q", got['X'], got['E'])
	}
	mu.Lock()
	defer mu.Unlock()
	if len(killed) != 1 || killed[0] != mine {
		t.Fatalf("the revoke must kill this command's own cgroup once: %v (watch %p)", killed, mine)
	}
}

// withWatchResult stands in a watch that saw conns, or could not watch (why).
func withWatchResult(t *testing.T, conns []rootExecConn, why string) {
	t.Helper()
	oldStart, oldStop := rootExecWatchStart, rootExecWatchStop
	rootExecWatchStart = func(string) *rootExecWatch { return &rootExecWatch{fd: -1, Err: why} }
	rootExecWatchStop = func(w *rootExecWatch) ([]rootExecConn, string) { return conns, w.Err }
	t.Cleanup(func() { rootExecWatchStart, rootExecWatchStop = oldStart, oldStop })
}

func writeOwnHosts(t *testing.T, body string) {
	t.Helper()
	p, err := rootExecOwnHostsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func withResolver(t *testing.T, m map[string][]string) {
	t.Helper()
	old := rootExecResolve
	rootExecResolve = func(_ context.Context, name string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, s := range m[name] {
			out = append(out, netip.MustParseAddr(s))
		}
		if len(out) == 0 {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
	t.Cleanup(func() { rootExecResolve = old })
}

// runWatched sends one command through the handler and returns the raw J.
func runWatched(t *testing.T, env sessionEnv, sid string) map[string]any {
	t.Helper()
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, sid, "true", 30, 0)
	got := readUntil(t, ws, 'X', 5*time.Second)
	var j map[string]any
	if err := json.Unmarshal(got['J'], &j); err != nil {
		t.Fatalf("J: %v (X=%q E=%q)", err, got['X'], got['E'])
	}
	return j
}

// A command that reached outside reports each destination once, with its
// count; one that reached only loopback and the platform's own hosts has no
// untrusted_connections at all, so the frame reads as an older one did.
//
// MUTATION: drop UntrustedConnections from the J frame in handleRootExec.
// RESULT: red — the outside destination is missing.
func TestRootExecJCarriesOnlyOutsideConnections(t *testing.T) {
	env := rootExecBox(t, true)
	withFakeExec(t, "ok\n", "", 0, false)
	withResolver(t, map[string][]string{"git.example": {"198.51.100.20", "2001:db8::20"}})
	writeOwnHosts(t, `{"hosts": ["2001:db8::/32", "203.0.113.4", "git.example"]}`)
	withWatchResult(t, []rootExecConn{
		{Addr: "127.0.0.1", Proto: "tcp", Port: 5432, Count: 3},
		{Addr: "2001:db8::7", Proto: "tcp", Port: 22, Count: 1},
		{Addr: "203.0.113.4", Proto: "udp", Port: 53, Count: 2},
		{Addr: "198.51.100.20", Proto: "tcp", Port: 443, Count: 1},
		{Addr: "2001:db8::20", Proto: "tcp", Port: 443, Count: 1},
		{Addr: "192.0.2.80", Proto: "tcp", Port: 443, Count: 4},
		{Addr: "192.0.2.81", Proto: "icmp", Count: 1},
	}, "")
	j := runWatched(t, env, "exec-watch-out")
	raw, _ := json.Marshal(j["untrusted_connections"])
	var got []rootExecConn
	_ = json.Unmarshal(raw, &got)
	want := []rootExecConn{{Addr: "192.0.2.80", Proto: "tcp", Port: 443, Count: 4}, {Addr: "192.0.2.81", Proto: "icmp", Count: 1}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("untrusted_connections = %s, want %+v", raw, want)
	}
	row := auditRow(t, env, "exec-watch-out")
	if n, _ := row["untrusted_connections"].(float64); n != 2 {
		t.Fatalf("the stop row counts the outside ones: %v", row)
	}
	if cs, _ := row["connections"].([]any); len(cs) != 7 {
		t.Fatalf("the stop row lists every connection, own ones marked: %v", row["connections"])
	}
	tr, _ := os.ReadFile(env.CtxRoot + "/sessions/exec-watch-out.log")
	if !strings.Contains(string(tr), "== connections: ") || !strings.Contains(string(tr), "tcp 192.0.2.80:443 x4 (outside)") ||
		!strings.Contains(string(tr), "(platform)") {
		t.Fatalf("the transcript records the connections:\n%s", tr)
	}

	withWatchResult(t, []rootExecConn{{Addr: "::1", Proto: "tcp", Port: 80, Count: 1}, {Addr: "2001:db8::9", Proto: "udp", Port: 53, Count: 1}}, "")
	j = runWatched(t, env, "exec-watch-own")
	if _, ok := j["untrusted_connections"]; ok {
		t.Fatalf("only loopback and own hosts: the field must be absent, J=%v", j)
	}
	if _, ok := j["untrusted_connections_more"]; ok {
		t.Fatalf("no overflow count either: %v", j)
	}
}

// Output whose connections were not watched is not known to be clean: it is
// reported with one entry that says why, so the host fences it.
//
// MUTATION: return nothing from rootExecClassify when unwatched != "".
// RESULT: red — the J frame says nothing and the host would trust the output.
func TestRootExecUnwatchedCountsAsOutside(t *testing.T) {
	env := rootExecBox(t, true)
	withFakeExec(t, "ok\n", "", 0, false)
	withWatchResult(t, nil, "nft is not installed")
	j := runWatched(t, env, "exec-watch-none")
	cs, _ := j["untrusted_connections"].([]any)
	if len(cs) != 1 {
		t.Fatalf("an unwatched command must report one untrusted entry: %v", j)
	}
	e, _ := cs[0].(map[string]any)
	if e["addr"] != "*" || !strings.Contains(fmt.Sprint(e["note"]), "nft is not installed") {
		t.Fatalf("the entry says why: %v", e)
	}
}

// The list's edges: empty or missing = nothing is own but loopback, a broken
// file = empty, a name that does not resolve adds nothing, the host's list is
// capped and the rest counted.
func TestRootExecOwnHostsList(t *testing.T) {
	setupBox(t)
	withResolver(t, map[string][]string{"edge.example": {"203.0.113.9"}})
	own := rootExecOwnSet()
	if len(own) != 0 || !rootExecIsOwn("127.0.0.5", own) || !rootExecIsOwn("::1", own) || rootExecIsOwn("10.0.0.1", own) {
		t.Fatalf("no list: only loopback is own (%v)", own)
	}
	writeOwnHosts(t, `{"hosts": ["10.0.0.0/8", "nowhere.example", "edge.example", "::ffff:192.0.2.1"]}`)
	own = rootExecOwnSet()
	for a, want := range map[string]bool{"10.1.2.3": true, "203.0.113.9": true, "192.0.2.1": true, "::ffff:10.0.0.1": true,
		"203.0.113.10": false, "11.0.0.1": false} {
		if rootExecIsOwn(a, own) != want {
			t.Errorf("%s own=%v, want %v", a, !want, want)
		}
	}
	writeOwnHosts(t, `{"hosts": ["10.0.0.0/8",`)
	if own := rootExecOwnSet(); len(own) != 0 {
		t.Fatalf("a broken list must read as empty: %v", own)
	}
	if _, _, problem := rootExecOwnHosts(); problem == "" {
		t.Fatal("a broken list says why")
	}
	writeOwnHosts(t, `{"hosts": ["a b"]}`)
	if own := rootExecOwnSet(); len(own) != 0 {
		t.Fatalf("an entry that is not an address, CIDR or name refuses the list: %v", own)
	}

	var many []rootExecConn
	for i := 0; i < rootExecUntrustedMax+5; i++ {
		many = append(many, rootExecConn{Addr: fmt.Sprintf("192.0.2.%d", i+1), Proto: "tcp", Port: 443, Count: 1})
	}
	u, more, all := rootExecClassify(many, "", nil, nil)
	if len(u) != rootExecUntrustedMax || more != 5 || len(all) != len(many) {
		t.Fatalf("capped at %d with the rest counted: %d %d %d", rootExecUntrustedMax, len(u), more, len(all))
	}
}

// A local proxy fetches from outside for whoever connects to it, so a
// connection to one of the list's loopback_relays (default: the common proxy
// ports) on a loopback or local address is outside. The local DNS resolver,
// and loopback on any other port, stay this machine's own.
//
// MUTATION: drop the rootExecIsRelay test from rootExecClassify.
// RESULT: red — 127.0.0.1:3128 reads as loopback and the J frame says nothing.
func TestRootExecLoopbackRelaysCountAsOutside(t *testing.T) {
	env := rootExecBox(t, true)
	if got := fmt.Sprint(rootExecLoopbackRelays()); got != "[1080 3128 8118 9050]" {
		t.Fatalf("no list: the common proxy ports, got %s", got)
	}
	oldLocal := rootExecLocalAddr
	rootExecLocalAddr = func(a netip.Addr) bool { return a == netip.MustParseAddr("10.9.9.1") }
	t.Cleanup(func() { rootExecLocalAddr = oldLocal })
	conns := []rootExecConn{
		{Addr: "127.0.0.1", Proto: "tcp", Port: 3128, Count: 2},   // squid on loopback
		{Addr: "10.9.9.1", Proto: "tcp", Port: 8118, Count: 1},    // a proxy on this machine's own address
		{Addr: "127.0.0.53", Proto: "udp", Port: 53, Count: 4},    // the local resolver
		{Addr: "127.0.0.1", Proto: "tcp", Port: 5433, Count: 1},   // a platform relay, not listed
		{Addr: "127.0.0.1", Proto: "udp", Port: 3128, Count: 1},   // TCP only
		{Addr: "2001:db8::7", Proto: "tcp", Port: 3128, Count: 1}, // a platform host's proxy, not local
	}
	writeOwnHosts(t, `{"hosts": ["2001:db8::/32"]}`)
	withFakeExec(t, "ok\n", "", 0, false)
	withWatchResult(t, conns, "")
	j := runWatched(t, env, "exec-watch-relay")
	u := map[string]string{}
	cs, _ := j["untrusted_connections"].([]any)
	for _, c := range cs {
		m, _ := c.(map[string]any)
		u[fmt.Sprintf("%v %v %v", m["addr"], m["proto"], m["port"])] = fmt.Sprint(m["note"])
	}
	if len(u) != 2 || !strings.Contains(u["127.0.0.1 tcp 3128"], "local relay") || u["10.9.9.1 tcp 8118"] == "" {
		t.Fatalf("the two relay connections, each with its note, and nothing else: %v", u)
	}

	// The list sets its own ports; an empty list has none; a bad port keeps the default.
	writeOwnHosts(t, `{"hosts": [], "loopback_relays": [5433, 5433]}`)
	if got := fmt.Sprint(rootExecLoopbackRelays()); got != "[5433]" {
		t.Fatalf("listed ports: %s", got)
	}
	unt, _, _ := rootExecClassify(conns, "", nil, rootExecLoopbackRelays())
	got := map[string]bool{}
	for _, c := range unt {
		got[fmt.Sprintf("%s %s %d", c.Addr, c.Proto, c.Port)] = true
	}
	// 127.0.0.1:5433 is now the relay and 127.0.0.1:3128 plain loopback; with
	// no platform hosts listed, the other two addresses are outside anyway.
	if len(got) != 3 || !got["127.0.0.1 tcp 5433"] || got["127.0.0.1 tcp 3128"] {
		t.Fatalf("with loopback_relays [5433]: %v", got)
	}
	writeOwnHosts(t, `{"hosts": [], "loopback_relays": []}`)
	if r := rootExecLoopbackRelays(); len(r) != 0 {
		t.Fatalf("an empty list has no relays: %v", r)
	}
	writeOwnHosts(t, `{"hosts": [], "loopback_relays": [0]}`)
	if got := fmt.Sprint(rootExecLoopbackRelays()); got != "[1080 3128 8118 9050]" {
		t.Fatalf("a port out of range keeps the default: %s", got)
	}
	if !strings.Contains(rootExecOwnHostsLine(), "local relays") {
		t.Fatal("the console line names the relays")
	}
}
