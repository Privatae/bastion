//go:build linux

// Uses setupBox / writePairing / signedTerms / deviceSign / tAnchor / tMember
// from the unix-only test fixtures. buildtags_test.go enforces the tag.

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The image path is spelled out rather than built from coderImagePrefix, so a
// change to that prefix fails here. The forge host comes from gitForgeHost,
// which claims_git_test.go pins.
const testCoderImage = gitForgeHost + "/privatae-harness/harness-claude-code@sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// ── fakes ───────────────────────────────────────────────────────────────────

// fakeCoderRT stands in for docker: every call is recorded, containers are a map.
type fakeCoderRT struct {
	mu        sync.Mutex
	calls     [][]string
	running   map[string]bool // container name -> running
	labels    map[string]map[string]string
	pid       map[string]int
	created   map[string]time.Time // container name -> creation time; unset: 10 minutes ago
	finished  map[string]time.Time // container name -> exit time; unset: none (docker's year 1)
	imageHere bool
	failRun   bool
	failPs    bool // the runtime cannot list containers (a slow or wedged daemon)
	noOOM     bool // nerdctl: inspect has no State.OOMKilled and fails any template naming it
}

func stubCoders(t *testing.T) *fakeCoderRT {
	t.Helper()
	f := &fakeCoderRT{running: map[string]bool{}, pid: map[string]int{}, labels: map[string]map[string]string{},
		created: map[string]time.Time{}, finished: map[string]time.Time{}}
	oldGOOS, oldRoot, oldRT, oldRun, oldEnv := coderGOOS, coderIsRoot, coderRuntime, coderRun, coderRunEnv
	oldMem, oldChown, oldWait, oldPSI := coderMemInfo, coderChown, coderWaitUp, coderPSIMem
	oldNV := coderNvidiaConfig
	// The machine's own NVIDIA config never reaches a test's command line.
	coderNvidiaConfig = filepath.Join(t.TempDir(), "no-nvidia-config.toml")
	t.Cleanup(func() {
		coderGOOS, coderIsRoot, coderRuntime, coderRun, coderRunEnv = oldGOOS, oldRoot, oldRT, oldRun, oldEnv
		coderMemInfo, coderChown, coderWaitUp, coderPSIMem = oldMem, oldChown, oldWait, oldPSI
		coderNvidiaConfig = oldNV
		for id := range coderEgress {
			coderCloseEgress(id)
		}
	})
	coderGOOS = "linux"
	coderIsRoot = func() bool { return true }
	coderRuntime = func() string { return "docker" }
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 12 << 30, true }
	coderPSIMem = func() (float64, bool) { return 0, true }
	coderChown = func(string, int, int) error { return nil }
	coderWaitUp = func(rt, cname, sock string, uid int, within time.Duration) error { return nil }
	coderRunEnv = func(_ time.Duration, env []string, name string, args ...string) (string, error) {
		return coderRun(0, name, args...)
	}
	coderRun = func(_ time.Duration, name string, args ...string) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, append([]string{name}, args...))
		if len(args) == 0 {
			return "", nil
		}
		last := args[len(args)-1]
		switch args[0] {
		case "image":
			if f.imageHere {
				return "[]", nil
			}
			return "Error: No such image", errors.New("exit 1")
		case "--config", "pull":
			return "pulled", nil
		case "run":
			if f.failRun {
				return "boom", errors.New("exit 125")
			}
			name, lb := "", map[string]string{}
			for i, a := range args {
				if a == "--name" {
					name = args[i+1]
				}
				if a == "--label" {
					kv := strings.SplitN(args[i+1], "=", 2)
					lb[kv[0]] = kv[1]
				}
			}
			f.running[name], f.labels[name] = true, lb
			return "cid\n", nil
		case "stop", "kill":
			if _, ok := f.running[last]; ok {
				f.running[last] = false
			}
			return "", nil
		case "rm":
			delete(f.running, last)
			return "", nil
		case "ps":
			if f.failPs {
				return "Cannot connect to the Docker daemon", errors.New("exit 1")
			}
			var ids []string
			for n := range f.running {
				ids = append(ids, n)
			}
			return strings.Join(ids, "\n"), nil
		case "inspect":
			tmpl := args[2]
			if strings.Contains(tmpl, coderLabelRun) && strings.Contains(tmpl, "|") {
				var lines []string
				for _, n := range args[3:] {
					lb := f.labels[n]
					created, ok := f.created[n]
					if !ok {
						created = time.Now().Add(-10 * time.Minute)
					}
					fin := f.finished[n].UTC().Format(time.RFC3339Nano) // zero prints docker's 0001-01-01T00:00:00Z
					lines = append(lines, fmt.Sprintf("%s|%s|%s|%v|%s|%s", lb[coderLabelRun], lb[coderLabelOwner],
						lb[coderLabelDeadline], f.running[n], created.UTC().Format(time.RFC3339Nano), fin))
				}
				return strings.Join(lines, "\n"), nil
			}
			st, ok := f.running[last]
			if !ok {
				return "Error: No such object: " + last, errors.New("exit 1")
			}
			if strings.HasPrefix(tmpl, "{{index .Config.Labels ") {
				key := strings.TrimSuffix(strings.TrimPrefix(tmpl, `{{index .Config.Labels "`), `"}}`)
				if v, ok := f.labels[last][key]; ok {
					return v + "\n", nil
				}
				return "<no value>\n", nil
			}
			switch {
			case strings.Contains(tmpl, "State.Running"):
				return fmt.Sprintf("%v\n", st), nil
			case strings.Contains(tmpl, "State.Pid"):
				return fmt.Sprintf("%d\n", f.pid[last]), nil
			case strings.Contains(tmpl, "OOMKilled") || strings.Contains(tmpl, "ExitCode"):
				if f.noOOM && strings.Contains(tmpl, "OOMKilled") {
					// nerdctl's message; the whole template fails, every field.
					return `template parsing error: template: executing "" at <.State.OOMKilled>: ` +
						`map has no entry for key "OOMKilled"`, errors.New("exit 1")
				}
				return strings.NewReplacer("{{.State.OOMKilled}}", "false", "{{.State.ExitCode}}", "137").Replace(tmpl) + "\n", nil
			}
			return "x\n", nil
		}
		return "", nil
	}
	return f
}

func (f *fakeCoderRT) has(verb string) [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]string
	for _, c := range f.calls {
		if len(c) > 1 && c[1] == verb {
			out = append(out, c)
		}
	}
	return out
}

func coderOn(t *testing.T, max int) {
	t.Helper()
	if err := saveCoderConfig(coderConfig{Enabled: true, Max: max, MemPerRun: 2048, CPUsPerRun: 2,
		Engines: append([]string(nil), coderEngines...)}); err != nil {
		t.Fatal(err)
	}
}

func upSpec(runID, owner string) harnessSpec {
	return harnessSpec{Mode: "coder", CoderOp: "run-up", RunID: runID, Engine: "claude-code",
		Image: testCoderImage, UID: 10005, CredsDir: "/home/privatae/.claude",
		Creds:      map[string]string{".credentials.json": `{"claudeAiOauth":{}}`},
		ControlCap: strings.Repeat("c", 43), owner: owner,
		Pull: &coderPull{Registry: gitForgeHost, Username: "run-puller", Password: "s3cret-token"}}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("reply is not JSON: %s", b)
	}
	return m
}

// ── seccomp ─────────────────────────────────────────────────────────────────

// The embedded profile must be byte-identical to the one the cluster's node
// addon installs for every pool harness pod (sha256 9b8d06ec…cca61).
func TestCoderSeccompProfileIsTheClusterOne(t *testing.T) {
	sum := sha256.Sum256(coderSeccompProfile)
	if got := hex.EncodeToString(sum[:]); got != "9b8d06ec2bef2cb06e8523c7595b11b9c6ba2557a3f008bf7f5dfb3553bcca61" {
		t.Fatalf("seccomp-personal.json drifted from the cluster profile: %s", got)
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, err := coderWriteSeccomp()
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p, []byte("{}"), 0o600) // tampered on disk
	if _, err := coderWriteSeccomp(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if sha256.Sum256(b) != sum || fi.Mode().Perm() != 0o644 {
		t.Fatalf("a changed profile on disk must be rewritten 0644: mode %v", fi.Mode().Perm())
	}
}

// ── egress: destination refusal ─────────────────────────────────────────────

func stubResolve(t *testing.T, m map[string][]string) {
	t.Helper()
	old := coderResolve
	t.Cleanup(func() { coderResolve = old })
	coderResolve = func(_ context.Context, host string) ([]net.IP, error) {
		ips, ok := m[strings.ToLower(host)]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []net.IP
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

// Every class the proxy must refuse, named by address AND by a name that
// resolves to it — the check runs after resolution.
func TestCoderEgressRefusesEveryInternalClass(t *testing.T) {
	classes := map[string][]string{
		"loopback v4":          {"127.0.0.1", "127.8.9.10"},
		"loopback v6":          {"::1"},
		"rfc1918":              {"10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.10"},
		"cgnat":                {"100.64.0.1", "100.127.255.254"},
		"link-local/metadata":  {"169.254.169.254", "169.254.0.1", "fe80::1"},
		"ula (incl. fd00:ec2)": {"fd00::1", "fc00::5", "fd00:ec2::254"},
		"ipv4-mapped":          {"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254"},
		"ipv4-compatible":      {"::127.0.0.1", "::a00:1"},
		"ipv4-translated":      {"::ffff:0:7f00:1"},
		"nat64":                {"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::1"},
		"6to4":                 {"2002:7f00:1::1", "2002:a00:1::1"},
		"unspecified":          {"0.0.0.0", "::"},
		"this-network 0/8":     {"0.1.2.3"},
		"benchmark 198.18/15":  {"198.18.0.1", "198.19.255.1"},
		"reserved 240/4":       {"240.0.0.1", "255.255.255.255"},
		"multicast":            {"224.0.0.1", "ff02::1"},
		"site-local fec0::/10": {"fec0::1"},
	}
	names := map[string][]string{}
	i := 0
	for _, addrs := range classes {
		for _, a := range addrs {
			names[fmt.Sprintf("n%d.example", i)] = []string{"93.184.216.34", a} // one bad answer is enough
			i++
		}
	}
	stubResolve(t, names)
	ctx := context.Background()
	for class, addrs := range classes {
		for _, a := range addrs {
			if got, why := coderVettedAddr(ctx, net.JoinHostPort(a, "443"), nil); why == "" {
				t.Errorf("%s: %s must be refused, got dial %s", class, a, got)
			}
		}
	}
	for n := range names {
		if got, why := coderVettedAddr(ctx, n+":443", nil); why == "" {
			t.Errorf("%s resolves to an internal address among public ones and must be refused, got %s", n, got)
		}
	}
	for _, n := range []string{"localhost:80", "LOCALHOST.:80", "db.localhost:5432", "unresolvable.example:443"} {
		if _, why := coderVettedAddr(ctx, n, nil); why == "" {
			t.Errorf("%s must be refused", n)
		}
	}
}

// stubLocalAddrs puts these addresses on the machine's NICs for the test.
func stubLocalAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	old := ownInterfaceAddrs
	t.Cleanup(func() { ownInterfaceAddrs = old; ownAddrReset() })
	ownInterfaceAddrs = func() ([]net.Addr, error) {
		var out []net.Addr
		for _, a := range addrs {
			_, n, err := net.ParseCIDR(a)
			if err != nil {
				t.Fatal(err)
			}
			ip, _, _ := net.ParseCIDR(a)
			out = append(out, &net.IPNet{IP: ip, Mask: n.Mask})
		}
		return out, nil
	}
	ownAddrReset()
}

// A machine whose NIC holds a PUBLIC address (a VPS) is still this machine: a
// service on 0.0.0.0 answers there. Every spelling of that address, and every
// name resolving to it, is refused; a neighbour on the same subnet is not.
func TestCoderEgressRefusesThisMachinesOwnPublicAddress(t *testing.T) {
	stubLocalAddrs(t, "127.0.0.1/8", "198.51.100.7/24", "2001:db8:5::7/64")
	stubResolve(t, map[string][]string{
		"me.example":        {"93.184.216.34", "198.51.100.7"},
		"me6.example":       {"2001:db8:5::7"},
		"neighbour.example": {"198.51.100.8"},
	})
	ctx := context.Background()
	for _, hp := range []string{
		"198.51.100.7:8080", "[::ffff:198.51.100.7]:8080", "[2001:db8:5::7]:22",
		"[64:ff9b::c633:6407]:80", "[2002:c633:6407::1]:80", // NAT64 / 6to4 carrying it
		"me.example:443", "me6.example:443",
	} {
		if got, why := coderVettedAddr(ctx, hp, nil); why == "" {
			t.Errorf("%s is this machine and must be refused, got dial %s", hp, got)
		}
	}
	if got, why := coderVettedAddr(ctx, "neighbour.example:443", nil); why != "" || got != "198.51.100.8:443" {
		t.Fatalf("another host on the subnet is the internet: %q %q", got, why)
	}
	if got, why := coderVettedAddr(ctx, "me.example:443", []string{"me.example"}); why != "" || got != "93.184.216.34:443" {
		t.Fatalf("allow_lan stays the one exception: %q %q", got, why)
	}
}

// The machine's addresses are re-read, so one added after start is refused;
// and a machine whose addresses cannot be read refuses rather than guesses.
func TestCoderEgressLocalAddressesAreReread(t *testing.T) {
	oldTTL := ownAddrTTL
	t.Cleanup(func() { ownAddrTTL = oldTTL })
	ownAddrTTL = 0
	stubLocalAddrs(t, "127.0.0.1/8")
	ctx := context.Background()
	if _, why := coderVettedAddr(ctx, "198.51.100.7:80", nil); why != "" {
		t.Fatalf("not yet this machine's address: %q", why)
	}
	ownInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("198.51.100.7"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	if _, why := coderVettedAddr(ctx, "198.51.100.7:80", nil); why == "" {
		t.Fatal("an address the machine gained since the last read must be refused")
	}
	ownInterfaceAddrs = func() ([]net.Addr, error) { return nil, errors.New("netlink: permission denied") }
	if _, why := coderVettedAddr(ctx, "93.184.216.34:443", nil); why == "" {
		t.Fatal("unreadable interfaces: refuse")
	}
}

// Numeric spellings the platform resolver may turn into loopback: whatever it
// does with them, the result is refused (resolution failure or 127.0.0.1).
func TestCoderEgressRefusesNumericLoopbackSpellings(t *testing.T) {
	for _, hp := range []string{"2130706433:80", "0x7f000001:80", "127.1:80", "017700000001:80"} {
		if got, why := coderVettedAddr(context.Background(), hp, nil); why == "" {
			t.Errorf("%s must be refused, got %s", hp, got)
		}
	}
}

// A public name dials the vetted ADDRESS (never the name again), and the
// owner's allow_lan lets exactly the named LAN host through.
func TestCoderEgressDialsTheVettedAddressAndHonoursAllowLAN(t *testing.T) {
	stubResolve(t, map[string][]string{"api.example": {"93.184.216.34", "2606:2800:220:1::1"},
		"dual.example": {"2606:2800:220:1::1", "93.184.216.34"}, "nas.lan": {"192.168.1.5"}})
	if all, why := coderVettedAddrs(context.Background(), "dual.example:443", nil); why != "" ||
		strings.Join(all, ",") != "93.184.216.34:443,[2606:2800:220:1::1]:443" {
		t.Fatalf("every vetted address is tried, IPv4 first: %v %q", all, why)
	}
	got, why := coderVettedAddr(context.Background(), "api.example:443", nil)
	if why != "" || got != "93.184.216.34:443" {
		t.Fatalf("public name: got %q %q", got, why)
	}
	if _, why := coderVettedAddr(context.Background(), "nas.lan:443", nil); why == "" {
		t.Fatal("a LAN host is refused unless the owner named it")
	}
	if got, why := coderVettedAddr(context.Background(), "nas.lan:443", []string{"NAS.lan"}); why != "" || got != "192.168.1.5:443" {
		t.Fatalf("an allow_lan host passes: %q %q", got, why)
	}
	if _, why := coderVettedAddr(context.Background(), "nas.lan:22", []string{"nas.lan:443"}); why == "" {
		t.Fatal("an allow_lan entry with a port allows only that port")
	}
}

// The proxy end to end over a real unix socket: a LAN/loopback CONNECT and an
// absolute-form GET to a private address are refused with 403 and counted; a
// public destination is spliced through.
func TestCoderEgressProxyOverTheSocket(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubResolve(t, map[string][]string{"public.example": {"93.184.216.34"}, "me.example": {"198.51.100.7"}})
	stubLocalAddrs(t, "127.0.0.1/8", "198.51.100.7/24") // a public address on this machine's NIC
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	oldDial := coderDialOut
	t.Cleanup(func() { coderDialOut = oldDial })
	var dialled []string
	coderDialOut = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialled = append(dialled, addr)
		return net.Dial("tcp", echo.Addr().String()) // the "internet"
	}
	dir := t.TempDir()
	if err := coderListenEgress("run-egress-1", dir, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	defer coderCloseEgress("run-egress-1")
	sock := filepath.Join(dir, coderEgressSock)
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o600 {
		t.Fatalf("egress.sock must be 0600, is %v", fi.Mode().Perm())
	}
	ask := func(req string) (string, net.Conn) {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte(req))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		var head strings.Builder
		for {
			l, err := br.ReadString('\n')
			head.WriteString(l)
			if err != nil || l == "\r\n" {
				break
			}
		}
		return head.String(), c
	}
	for _, req := range []string{
		"CONNECT " + echo.Addr().String() + " HTTP/1.1\r\nHost: x\r\n\r\n", // loopback
		"CONNECT 192.168.1.1:443 HTTP/1.1\r\n\r\n",                         // LAN
		"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n",                      // metadata
		"GET http://10.0.0.1/admin HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n",     // absolute-form, private
		"GET http://user@127.0.0.1:8080/ HTTP/1.1\r\n\r\n",                 // userinfo does not hide the host
		"CONNECT 198.51.100.7:8080 HTTP/1.1\r\n\r\n",                       // this machine's public address
		"GET http://me.example:8080/ HTTP/1.1\r\nHost: me.example\r\n\r\n", // a name for it, plain HTTP
	} {
		head, c := ask(req)
		c.Close()
		want := "HTTP/1.1 403"
		if strings.Contains(req, "user@") {
			// Userinfo is refused outright, before any lookup, as the Host's
			// egress gate refuses it (parseEgressAuthority); still counted.
			want = "HTTP/1.1 400"
		}
		if !strings.HasPrefix(head, want) || !strings.Contains(head, "X-Privatae-Refused:") {
			t.Fatalf("must be refused with %s + X-Privatae-Refused: %q -> %q", want, req, head)
		}
	}
	head, c := ask("CONNECT public.example:443 HTTP/1.1\r\n\r\n")
	defer c.Close()
	if !strings.HasPrefix(head, "HTTP/1.1 200") {
		t.Fatalf("a public destination is let through: %q", head)
	}
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("the tunnel carries bytes: %q %v", buf, err)
	}
	if len(dialled) != 1 || dialled[0] != "93.184.216.34:443" {
		t.Fatalf("the proxy dials the vetted address only: %v", dialled)
	}
	if n := coderCloseEgress("run-egress-1"); n != 7 {
		t.Fatalf("refusals are counted per run: %d", n)
	}
}

// ── run-up: the full answer, the container, the files ───────────────────────

// Full is a capacity answer: ok:true, exit 0, started:false — and it is never
// a refusal, so no number of them trips the quarantine.
func TestCoderFullIsACapacityAnswerNotARefusal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	coderOn(t, 1)
	if b, code := runCoder(upSpec("run-first-0001", "h.example")); code != 0 || decode(t, b)["started"] != true {
		t.Fatalf("the first run starts: %d %s", code, b)
	}
	for i := 0; i < 8; i++ {
		b, code := runCoder(upSpec(fmt.Sprintf("run-burst-%04d", i), "h.example"))
		m := decode(t, b)
		if code != 0 || m["ok"] != true || m["started"] != false || m["reason"] != "full" ||
			m["max"] != float64(1) || m["running"] != float64(1) || m["running_mine"] != float64(1) {
			t.Fatalf("a run past max is the full answer: %d %s", code, b)
		}
		if _, ok := m["mem_avail_mb"]; !ok {
			t.Fatalf("the full answer carries mem_avail_mb: %s", b)
		}
	}
	if q := quarantineLoad(); len(q.Ring) != 0 {
		t.Fatalf("a full answer is never recorded as a refusal: %+v", q.Ring)
	}
	// Memory: MemAvailable under one run's size is full too.
	coderOn(t, 10)
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 1 << 30, true }
	b, code := runCoder(upSpec("run-lowmem-01", "h.example"))
	if m := decode(t, b); code != 0 || m["reason"] != "full" || m["mem_avail_mb"] != float64(1024) {
		t.Fatalf("too little free memory is the full answer: %d %s", code, b)
	}
}

// The container is started with exactly the hardened flags, the files are
// handed to the engine's uid and never opened 0777, the pull uses a throwaway
// config holding only this run's credential, and run-down of one of three
// leaves the other two.
func TestCoderRunUpStartsTheSealedContainerAndRunDownMeasures(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 6)
	var chowned []string
	coderChown = func(p string, uid, gid int) error {
		if uid != 10005 || gid != 10005 {
			t.Errorf("chown %s to %d:%d, want the engine's uid", p, uid, gid)
		}
		chowned = append(chowned, p)
		return nil
	}
	var pullCfg string
	baseRun := coderRun
	coderRun = func(d time.Duration, name string, args ...string) (string, error) {
		if len(args) > 2 && args[0] == "--config" {
			b, err := os.ReadFile(filepath.Join(args[1], "config.json"))
			fi, _ := os.Stat(filepath.Join(args[1], "config.json"))
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("the pull config must be a 0600 file: %v", err)
			}
			pullCfg = string(b)
		}
		return baseRun(d, name, args...)
	}

	b, code := runCoder(upSpec("run-alpha-0001", "h.example"))
	m := decode(t, b)
	if code != 0 || m["ok"] != true || m["started"] != true || m["tunnel_port"] != float64(coderPortBase) ||
		m["container"] != "privatae-run-run-alpha-0001" {
		t.Fatalf("run-up: %d %s", code, b)
	}
	want := base64.StdEncoding.EncodeToString([]byte("run-puller:s3cret-token"))
	if !strings.Contains(pullCfg, `"`+gitForgeHost+`":{"auth":"`+want+`"}`) {
		t.Fatalf("the pull config holds this run's credential for %s only: %s", gitForgeHost, pullCfg)
	}
	d, _ := codersDir()
	if _, err := os.Stat(filepath.Join(d, "pull-run-alpha-0001")); !os.IsNotExist(err) {
		t.Fatal("the throwaway pull config is removed after the pull")
	}
	if strings.Contains(string(b), "s3cret-token") {
		t.Fatal("the pull credential never comes back in the reply")
	}

	R, _ := coderRunDir("run-alpha-0001")
	var run []string
	for _, c := range f.has("run") {
		run = c[1:]
	}
	exp := []string{"run", "-d", "--name", "privatae-run-run-alpha-0001",
		"--label", "privatae.coder.run=run-alpha-0001", "--label", "privatae.coder.owner=h.example",
		"--label", "privatae.coder.engine=claude-code", "--label", "privatae.coder.deadline=" + m["deadline"].(string),
		"--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + filepath.Join(d, "seccomp-personal.json"),
		"--read-only", "--user", "10005:10005",
		"--memory", "2048m", "--memory-swap", "2048m", "--cpus", "2", "--cpu-shares", "2", "--pids-limit", "4096",
		"--tmpfs", "/tmp:rw,nosuid,nodev,exec,mode=1777,size=2048m",
		"-v", R + "/work:/var/lib/skema/projects", "-v", R + "/home:/home/privatae",
		"-v", R + "/ctl:/run/privatae/ctl", "-v", R + "/egress:/run/privatae/egress:ro",
		"-e", "SKEMA_APP_ID=claude-code", "-e", "PRIVATAE_RUN_ID=run-alpha-0001", "-e", "HOME=/home/privatae",
		"-e", "SKEMA_WORKSPACE=/var/lib/skema/projects", "-e", "PRIVATAE_HARNESS_CAP=" + strings.Repeat("c", 43),
		"-e", "PRIVATAE_HARNESS_CAP_ENFORCE=1",
		"-e", "PRIVATAE_SIDECAR_CONTROL_SOCK=/run/privatae/ctl/control.sock",
		"-e", "PRIVATAE_SIDECAR_EGRESS_SOCK=/run/privatae/egress/egress.sock",
		"-e", "NVIDIA_VISIBLE_DEVICES=void",
		testCoderImage}
	if strings.Join(run, "\x00") != strings.Join(exp, "\x00") {
		t.Fatalf("container args:\n got %q\nwant %q", run, exp)
	}
	for _, sub := range []string{"work", "home", "ctl", "home/.claude"} {
		fi, err := os.Stat(filepath.Join(R, sub))
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s must be 0700: %v %v", sub, fi.Mode().Perm(), err)
		}
	}
	cf, err := os.Stat(filepath.Join(R, "home/.claude/.credentials.json"))
	if err != nil || cf.Mode().Perm() != 0o600 {
		t.Fatalf("the creds file is 0600: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(R, "egress", "egress.sock")); fi == nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatal("the bastion listens on R/egress/egress.sock, 0600")
	}
	if len(chowned) < 6 {
		t.Fatalf("work, home, ctl, the creds dir, the creds file and egress.sock go to the engine's uid: %v", chowned)
	}
	_ = filepath.Walk(R, func(p string, fi os.FileInfo, _ error) error {
		if fi != nil && fi.Mode().Perm()&0o002 != 0 {
			t.Errorf("%s is world-writable", p)
		}
		return nil
	})

	// Two more runs: ports are distinct.
	for i, id := range []string{"run-bravo-0002", "run-charlie-03"} {
		if b, code := runCoder(upSpec(id, "h.example")); code != 0 || decode(t, b)["tunnel_port"] != float64(coderPortBase+1+i) {
			t.Fatalf("run %s: %d %s", id, code, b)
		}
	}
	// A second run-up of the same id is refused, not duplicated.
	if b, code := runCoder(upSpec("run-alpha-0001", "h.example")); code == 0 || decode(t, b)["reason"] != "run_exists" {
		t.Fatalf("the same run_id twice: %d %s", code, b)
	}

	// Measures come from the container's cgroup, read on the host side.
	proc, cg := t.TempDir(), t.TempDir()
	coderProcFS, coderCgroupFS = proc, cg
	t.Cleanup(func() { coderProcFS, coderCgroupFS = "/proc", "/sys/fs/cgroup" })
	f.pid["privatae-run-run-alpha-0001"] = 4242
	_ = os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	_ = os.WriteFile(filepath.Join(proc, "4242", "cgroup"), []byte("0::/system.slice/docker-abc.scope\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(cg, "system.slice/docker-abc.scope"), 0o755)
	_ = os.WriteFile(filepath.Join(cg, "system.slice/docker-abc.scope/cgroup.events"), []byte("populated 1\nfrozen 0\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cg, "system.slice/docker-abc.scope/memory.peak"), []byte("734003200\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cg, "system.slice/docker-abc.scope/cpu.stat"), []byte("usage_usec 12345678\nuser_usec 1\n"), 0o644)

	// Another host may not stop it (local box: one host, so use the anchor rule's own test below).
	down := harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: "run-alpha-0001", owner: "h.example"}
	b, code = runCoder(down)
	m = decode(t, b)
	if code != 0 || m["stopped"] != true || m["peak_mem_bytes"] != float64(734003200) || m["cpu_s"] != 12.346 ||
		m["oom_killed"] != false || m["exit_code"] != float64(137) || m["egress_refused"] != float64(0) {
		t.Fatalf("run-down: %d %s", code, b)
	}
	if _, err := os.Stat(R); !os.IsNotExist(err) {
		t.Fatal("run-down removes the run's directory, creds included")
	}
	if len(f.has("stop")) != 1 || f.has("stop")[0][2] != "-t" || f.has("stop")[0][3] != "10" {
		t.Fatalf("run-down stops with -t 10: %v", f.has("stop"))
	}
	st := decode(t, mustStatus(t, "h.example"))
	runs := st["runs"].([]any)
	if len(runs) != 2 {
		t.Fatalf("run-down of one leaves two: %v", runs)
	}
	for _, r := range runs {
		if r.(map[string]any)["state"] != "running" {
			t.Fatalf("the other two keep running: %v", runs)
		}
	}
	// An unknown run is not an error.
	b, code = runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: "run-unknown-1", owner: "h.example"})
	if m := decode(t, b); code != 0 || m["stopped"] != false || m["reason"] != "not_found" {
		t.Fatalf("unknown run: %d %s", code, b)
	}
}

func mustStatus(t *testing.T, owner string) []byte {
	t.Helper()
	b, code := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-status", owner: owner})
	if code != 0 {
		t.Fatalf("run-status: %d %s", code, b)
	}
	return b
}

// A run that fails to come up leaves nothing behind.
func TestCoderStartFailureRemovesEverything(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 4)
	coderWaitUp = func(string, string, string, int, time.Duration) error { return errors.New("no /health") }
	b, code := runCoder(upSpec("run-broken-001", "h.example"))
	if m := decode(t, b); code != 1 || m["reason"] != "start_failed" {
		t.Fatalf("start failure: %d %s", code, b)
	}
	if len(f.has("rm")) != 1 || len(f.running) != 0 {
		t.Fatalf("the container is removed: %v", f.running)
	}
	R, _ := coderRunDir("run-broken-001")
	if _, err := os.Stat(R); !os.IsNotExist(err) {
		t.Fatal("the run directory is removed")
	}
	if _, ok := coderEgress["run-broken-001"]; ok {
		t.Fatal("the egress proxy is closed")
	}
}

// The machine-level refusals, in the contract's order.
func TestCoderRunUpRefusesOffLinuxRootAndEngine(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	coderOn(t, 2)
	coderGOOS = "darwin"
	if b, code := runCoder(upSpec("run-mac-00001", "h")); code != 1 || !strings.Contains(string(b), "Linux") {
		t.Fatalf("not Linux: %d %s", code, b)
	}
	coderGOOS = "linux"
	coderIsRoot = func() bool { return false }
	if b, code := runCoder(upSpec("run-user-0001", "h")); code != 1 || !strings.Contains(string(b), "root") {
		t.Fatalf("not root: %d %s", code, b)
	}
	coderIsRoot = func() bool { return true }
	_ = saveCoderConfig(coderConfig{Enabled: true, Max: 2, MemPerRun: 2048, CPUsPerRun: 1, Engines: []string{"codex"}})
	if b, code := runCoder(upSpec("run-eng-00001", "h")); code != 1 || !strings.Contains(string(b), "not allowed") {
		t.Fatalf("engine not allowed: %d %s", code, b)
	}
	_ = saveCoderConfig(coderConfig{Enabled: false, Max: 2, MemPerRun: 2048, CPUsPerRun: 1, Engines: coderEngines})
	if b, code := runCoder(upSpec("run-off-00001", "h")); code != 1 || !strings.Contains(string(b), "off") {
		t.Fatalf("coders off: %d %s", code, b)
	}
}

func TestCoderSpecRefusals(t *testing.T) {
	good := upSpec("run-spec-0001", "h")
	if why := coderSpecRefusal(good); why != "" {
		t.Fatalf("a good spec passes: %s", why)
	}
	bad := map[string]func(*harnessSpec){
		"run_id":      func(s *harnessSpec) { s.RunID = "UPPER-case-id" },
		"run_id len":  func(s *harnessSpec) { s.RunID = "short" },
		"engine":      func(s *harnessSpec) { s.Engine = "vscode" },
		"image tag":   func(s *harnessSpec) { s.Image = gitForgeHost + "/privatae-harness/harness-x:latest" },
		"image repo":  func(s *harnessSpec) { s.Image = strings.Replace(testCoderImage, "privatae-harness", "other", 1) },
		"image name":  func(s *harnessSpec) { s.Image = strings.Replace(testCoderImage, "/harness-", "/other-", 1) },
		"uid root":    func(s *harnessSpec) { s.UID = 0 },
		"uid range":   func(s *harnessSpec) { s.UID = 10100 },
		"creds dir":   func(s *harnessSpec) { s.CredsDir = "/root/.ssh" },
		"creds name":  func(s *harnessSpec) { s.Creds = map[string]string{"../x": "y"} },
		"creds dot":   func(s *harnessSpec) { s.Creds = map[string]string{"..": "y"} },
		"creds size":  func(s *harnessSpec) { s.Creds = map[string]string{"a": strings.Repeat("x", 1<<20)} },
		"cap short":   func(s *harnessSpec) { s.ControlCap = "abc" },
		"minutes":     func(s *harnessSpec) { s.MaxMinutes = 1441 },
		"pull reg":    func(s *harnessSpec) { s.Pull = &coderPull{Registry: "docker.io", Username: "u", Password: "p"} },
		"pull nouser": func(s *harnessSpec) { s.Pull = &coderPull{Registry: gitForgeHost, Password: "p"} },
		"op":          func(s *harnessSpec) { s.CoderOp = "run-sideways" },
	}
	for name, mut := range bad {
		s := upSpec("run-spec-0001", "h")
		mut(&s)
		if why := coderSpecRefusal(s); why == "" {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// ── the forward ─────────────────────────────────────────────────────────────

func TestCoderForwardWall(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	host := netip.MustParseAddr("fd00:9::e:5")
	now := time.Now()
	rec := &coderRecord{RunID: "run-fwd-00001", Owner: "a.example", UID: 10005,
		Deadline: now.Add(time.Hour).UTC().Format(time.RFC3339)}
	if why := coderForwardRefusal("a.example", rec, host, host, now); why != "" {
		t.Fatalf("the owner from its tunnel address passes: %s", why)
	}
	if why := coderForwardRefusal("a.example", rec, netip.MustParseAddr("fd00:9::e:6"), host, now); why == "" {
		t.Fatal("another address is refused")
	}
	if why := coderForwardRefusal("b.example", rec, host, host, now); why == "" {
		t.Fatal("another pairing's forward never serves this run")
	}
	if why := coderForwardRefusal("a.example", rec, host, host, now.Add(2*time.Hour)); why == "" {
		t.Fatal("a run past its deadline is refused")
	}
	if why := coderForwardRefusal("a.example", nil, host, host, now); why == "" {
		t.Fatal("no record, no connection")
	}
	if why := coderForwardRefusal("a.example", rec, host, netip.Addr{}, now); why == "" {
		t.Fatal("a pairing with no host tunnel address accepts nothing")
	}
}

// serveControlSocket listens on sock as a non-root uid and answers "pong" to
// anything, returning that uid. As root it runs the listener in a child
// process under uid 65534; otherwise in-process as the test's own uid.
func serveControlSocket(t *testing.T, sock string) int {
	t.Helper()
	if os.Getuid() != 0 {
		ln, err := coderListenUnix(filepath.Dir(sock), filepath.Base(sock))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("pong"))
				c.Close()
			}
		}()
		return os.Getuid()
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3 to serve a socket as another uid")
	}
	_ = os.Chown(filepath.Dir(sock), 65534, 65534)
	cmd := exec.Command(py, "-I", "-c", `import os,socket,sys
s=socket.socket(socket.AF_UNIX); s.bind("/proc/self/fd/3/" + os.path.basename(sys.argv[1])); s.listen(8)
while True:
    c,_=s.accept(); c.sendall(b"pong"); c.close()`, sock)
	// The test's temp dirs are 0700 root, so the child gets the directory as
	// fd 3 and binds through it rather than walking the path.
	dirf, err := os.Open(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	defer dirf.Close()
	cmd.ExtraFiles = []*os.File{dirf}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a socket server as uid 65534: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	for i := 0; i < 100; i++ {
		if _, ok := coderSocketOwner(sock); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return 65534
}

// The owner-only forward end to end: a connection from the pairing's host
// tunnel address is spliced to the run's control socket; one from any other
// address, or to another pairing's run, gets nothing.
func TestCoderForwardSplicesOnlyTheOwnersTunnelAddress(t *testing.T) {
	cfgHome := t.TempDir()
	_ = os.Chmod(cfgHome, 0o755)
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	d, _ := configDir()
	_ = os.Chmod(d, 0o755)
	runs, _ := coderRunsDir()
	_ = os.Chmod(filepath.Dir(runs), 0o755)
	_ = os.Chmod(runs, 0o755)
	R := filepath.Join(runs, "run-fwd-00002")
	_ = os.MkdirAll(filepath.Join(R, "ctl"), 0o755)
	_ = os.Chmod(R, 0o755)
	uid := serveControlSocket(t, filepath.Join(R, "ctl", coderControlSock))
	rec := &coderRecord{RunID: "run-fwd-00002", Owner: "a.example", UID: uid, TunnelPort: coderPortBase,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Deadline: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := saveCoderRecord(R, rec); err != nil {
		t.Fatal(err)
	}
	try := func(self, hostTunnel string) string {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ready := make(chan string, 1)
		go serveCoderForwardsOn(ctx, self, hostTunnel, func(port int) (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				ready <- ln.Addr().String()
			}
			return ln, err
		})
		var addr string
		select {
		case addr = <-ready:
		case <-time.After(time.Second):
			return "<no listener>"
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return "<dial: " + err.Error() + ">"
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b, _ := io.ReadAll(c)
		return string(b)
	}
	if got := try("a.example", "127.0.0.1"); got != "pong" {
		t.Fatalf("the owner, from its tunnel address, reaches the run: %q", got)
	}
	if got := try("a.example", "127.0.0.2"); got != "" {
		t.Fatalf("a connection from any other address gets nothing: %q", got)
	}
	if got := try("b.example", "127.0.0.1"); got != "<no listener>" {
		t.Fatalf("another pairing never listens for this run: %q", got)
	}
}

// ── config persistence ──────────────────────────────────────────────────────

func TestCoderConfigPersistsAndBounds(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	if c := loadCoderConfig(); c.Enabled || c.ready() {
		t.Fatal("coder runs are off by default")
	}
	c, err := coderApplySet(loadCoderConfig(), []string{"--max", "6", "--mem", "3072", "--cpus", "1.5",
		"--engines", "codex,claude-code", "--allow-lan", "nas.lan:443,printer.lan"}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveCoderConfig(c); err != nil {
		t.Fatal(err)
	}
	got := loadCoderConfig()
	if got.Enabled || got.Max != 6 || got.MemPerRun != 3072 || got.CPUsPerRun != 1.5 ||
		strings.Join(got.Engines, ",") != "codex,claude-code" || strings.Join(got.AllowLAN, ",") != "nas.lan:443,printer.lan" {
		t.Fatalf("set persists and does not toggle on: %+v", got)
	}
	p, _ := coderConfigPath()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("config.json is 0600: %v", fi.Mode().Perm())
	}
	for _, args := range [][]string{{"--max", "0"}, {"--max", "101"}, {"--mem", "511"}, {"--mem", "65537"},
		{"--cpus", "0.2"}, {"--cpus", "9"}, {"--engines", "vscode"}, {"--engines", "browser"}, {"--bogus", "1"}, {"--max"}} {
		if _, err := coderApplySet(got, args, 8); err == nil {
			t.Errorf("%v must be refused", args)
		}
	}
	// `on` keeps what was set and fills only the rest.
	on, err := coderTurnOn(got)
	if err != nil || !on.Enabled || on.Max != 6 || on.MemPerRun != 3072 || !loadCoderConfig().ready() {
		t.Fatalf("on keeps set values: %+v %v", on, err)
	}
	// Defaults: a 16 GiB machine keeps 2763 MiB (coderReserveMB), so
	// (16384 - 2763) / 2048 = 6, every engine.
	_ = saveCoderConfig(coderConfig{})
	on, err = coderTurnOn(loadCoderConfig())
	if err != nil || on.Max != 6 || on.MemPerRun != 2048 || len(on.Engines) != len(coderEngines) {
		t.Fatalf("on with nothing set: %+v %v", on, err)
	}
	// A machine that cannot hold one run refuses.
	_ = saveCoderConfig(coderConfig{})
	coderMemInfo = func() (uint64, uint64, bool) { return 2 << 30, 1 << 30, true }
	if _, err := coderTurnOn(loadCoderConfig()); err == nil {
		t.Fatal("a 2 GiB machine cannot hold a 2 GiB run plus 612 MiB for itself")
	}
	if loadCoderConfig().Enabled {
		t.Fatal("a refused on leaves coders off")
	}
}

// ── heartbeat ───────────────────────────────────────────────────────────────

func heartbeatCoders(t *testing.T, self string) (bool, map[string]any) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(buildHeartbeatBody(self, "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)), &body); err != nil {
		t.Fatal(err)
	}
	capOn := false
	for _, c := range body["capabilities"].([]any) {
		if c == coderCapability {
			capOn = true
		}
	}
	block, _ := body["coders"].(map[string]any)
	if capOn != (block != nil) {
		t.Fatalf("the capability and the block travel together: cap %v block %v", capOn, block)
	}
	return capOn, block
}

func TestCoderHeartbeatBlockIsHonest(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	writePairing(t, "local.example")
	if on, _ := heartbeatCoders(t, "local.example"); on {
		t.Fatal("off by default: no capability, no block")
	}
	var rtCalls int
	coderRuntime = func() string { rtCalls++; return "docker" }
	_, _ = heartbeatCoders(t, "local.example")
	if rtCalls != 0 {
		t.Fatal("a machine with coders off never runs its container runtime for a heartbeat")
	}
	coderOn(t, 5)
	on, block := heartbeatCoders(t, "local.example")
	if !on {
		t.Fatal("on, Linux, root, a runtime, an unanchored box: advertised")
	}
	for _, k := range []string{"max", "running", "running_mine", "grant_max", "mem_per_run_mb", "cpus_per_run",
		"mem_total_mb", "mem_avail_mb", "cpus", "arch", "runtime", "engines"} {
		if _, ok := block[k]; !ok {
			t.Fatalf("block lacks %s: %v", k, block)
		}
	}
	if block["max"] != float64(5) || block["grant_max"] != nil || block["mem_total_mb"] != float64(16384) ||
		block["mem_avail_mb"] != float64(12288) || block["runtime"] != "docker" || len(block["engines"].([]any)) != len(coderEngines) {
		t.Fatalf("block values: %v", block)
	}
	for name, breakIt := range map[string]func(){
		"not linux":  func() { coderGOOS = "windows" },
		"not root":   func() { coderIsRoot = func() bool { return false } },
		"no runtime": func() { coderRuntime = func() string { return "" } },
		"off":        func() { c := loadCoderConfig(); c.Enabled = false; _ = saveCoderConfig(c) },
	} {
		oldG, oldR, oldRT := coderGOOS, coderIsRoot, coderRuntime
		breakIt()
		if on, _ := heartbeatCoders(t, "local.example"); on {
			t.Errorf("%s: must not advertise", name)
		}
		coderGOOS, coderIsRoot, coderRuntime = oldG, oldR, oldRT
		coderOn(t, 5)
	}
}

// The block is only advertised to a pairing that may be asked for mode:coder.
// On a local box the person at the machine switching the harness family off
// for that host withdraws it, and switching it back on restores it.
func TestCoderHeartbeatHonoursTheLocalSwitch(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	writePairing(t, "local.example")
	coderOn(t, 5)
	if on, _ := heartbeatCoders(t, "local.example"); !on {
		t.Fatal("on, Linux, root, a runtime, an unanchored box: advertised")
	}
	if err := localDenySet("local.example", opFamily(coderGateOp), true); err != nil {
		t.Fatal(err)
	}
	if on, block := heartbeatCoders(t, "local.example"); on {
		t.Fatalf("the harness family is switched off for this host: must not advertise, got %v", block)
	}
	if err := localDenySet("local.example", opFamily(coderGateOp), false); err != nil {
		t.Fatal(err)
	}
	if on, _ := heartbeatCoders(t, "local.example"); !on {
		t.Fatal("switched back on: advertised again")
	}
}

func coderGrantTerms(subject string, engines []string, max, days int) map[string]any {
	hn, _ := os.Hostname()
	return map[string]any{"kind": coderGrantKind, "server": hn, "subject": subject, "engines": engines,
		"max": max, "ttl_days": days,
		"expires": time.Now().Add(time.Duration(days-1) * 24 * time.Hour).UTC().Format(time.RFC3339)}
}

func coderGrantPayload(t *testing.T, priv ed25519.PrivateKey, id int64, terms map[string]any) string {
	t.Helper()
	tc, sig := signedTerms(t, priv, terms)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	b, _ := json.Marshal(map[string]any{"grant_id": id, "terms_canonical": tc, "signature": sig, "verify_pubkey": pub})
	return base64.StdEncoding.EncodeToString(b)
}

func approveCoderGrant(t *testing.T, terms map[string]any) {
	t.Helper()
	p, err := purposeForCoderGrant(&coderTerms{Server: terms["server"].(string), Subject: terms["subject"].(string),
		Engines: terms["engines"].([]string), Max: terms["max"].(int), TTLDays: terms["ttl_days"].(int)})
	if err != nil {
		t.Fatal(err)
	}
	a, err := deviceSign(p, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	terms["approval"] = a
}

// On an anchored box the block and the run-up need a standing coder grant:
// approved once, for this host, this machine; dropped by the host's revoke.
func TestCoderStandingGrantOnAnAnchoredBox(t *testing.T) {
	priv := setupBox(t)
	stubCoders(t)
	coderOn(t, 8)
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	dir := coderDcnDirFor(tAnchor)
	if dir == "" {
		t.Fatal("the anchor pairing has a grant dir")
	}
	if on, _ := heartbeatCoders(t, tAnchor); on {
		t.Fatal("anchored, no coder grant: not advertised")
	}
	spec := upSpec("run-anch-00001", tAnchor)
	spec.dcnDir = dir
	if why := harnessGate(tAnchor, dir, spec); why == "" || !strings.Contains(why, "coder grant") {
		t.Fatalf("run-up without a standing grant is refused at the gate: %q", why)
	}
	if why := harnessGate(tAnchor, dir, harnessSpec{Mode: "coder", CoderOp: "run-status"}); why != "" {
		t.Fatalf("run-status is a read: %q", why)
	}

	bare := coderGrantTerms(tAnchor, []string{"claude-code"}, 2, 30)
	if _, errOut, code := driveDirOp(t, tAnchor, dir, "coder_grant_sync", []string{coderGrantPayload(t, priv, 1, bare)}); code != 126 {
		t.Fatalf("an unapproved coder grant is refused: %d %s", code, errOut)
	}
	other := coderGrantTerms(tMember, []string{"claude-code"}, 2, 30)
	approveCoderGrant(t, other)
	if _, errOut, code := driveDirOp(t, tAnchor, dir, "coder_grant_sync", []string{coderGrantPayload(t, priv, 2, other)}); code != 126 ||
		!strings.Contains(errOut, "not the host that sent it") {
		t.Fatalf("a host cannot install a grant for another host: %d %s", code, errOut)
	}
	good := coderGrantTerms(tAnchor, []string{"claude-code"}, 2, 30)
	approveCoderGrant(t, good)
	if _, errOut, code := driveDirOp(t, tAnchor, dir, "coder_grant_sync", []string{coderGrantPayload(t, priv, 3, good)}); code != 0 {
		t.Fatalf("an approved coder grant installs: %d %s", code, errOut)
	}
	if why := harnessGate(tAnchor, dir, spec); why != "" {
		t.Fatalf("with the grant, run-up spends no per-run approval: %q", why)
	}
	on, block := heartbeatCoders(t, tAnchor)
	if !on || block["grant_max"] != float64(2) {
		t.Fatalf("with the grant the block is advertised with grant_max: %v", block)
	}
	// The grant's engines and max bind run-up.
	cx := upSpec("run-anch-codex1", tAnchor)
	cx.Engine, cx.dcnDir = "codex", dir
	if b, code := runCoder(cx); code != 1 || !strings.Contains(string(b), "grant") {
		t.Fatalf("an engine outside the grant is refused: %d %s", code, b)
	}
	for i := 0; i < 3; i++ {
		s := upSpec(fmt.Sprintf("run-anch-%05d", i+10), tAnchor)
		s.dcnDir = dir
		b, code := runCoder(s)
		m := decode(t, b)
		if i < 2 && (code != 0 || m["started"] != true) {
			t.Fatalf("run %d within the grant starts: %s", i, b)
		}
		if i == 2 && (code != 0 || m["reason"] != "full" || m["running_mine"] != float64(2)) {
			t.Fatalf("past the grant's max is the full answer: %s", b)
		}
	}
	if enf := buildEnforcingReport(dir, nil); len(enf["coder_grants"].([]map[string]any)) != 1 {
		t.Fatalf("the enforcing report names the held grant: %v", enf["coder_grants"])
	}
	if _, errOut, code := driveDirOp(t, tAnchor, dir, "coder_grant_drop", []string{"3"}); code != 0 {
		t.Fatalf("drop: %d %s", code, errOut)
	}
	if on, _ := heartbeatCoders(t, tAnchor); on {
		t.Fatal("after the revoke: withdrawn")
	}
}

func TestCoderGrantKindAndPurpose(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	tc, sig := signedTerms(t, priv, reachTermsFor("h.example", "forge", 30))
	if _, err := coderVerifyRec(pub, dcnGrantRec{TermsCanonical: tc, Signature: sig}); err == nil {
		t.Fatal("a reach grant must not verify as a coder grant")
	}
	tc, sig = signedTerms(t, priv, coderGrantTerms("h.example", []string{"vscode"}, 2, 30))
	if _, err := coderVerifyRec(pub, dcnGrantRec{TermsCanonical: tc, Signature: sig}); err == nil {
		t.Fatal("a grant naming a non-coding engine is refused")
	}
	got, err := purposeForCoderGrant(&coderTerms{Server: "box1", Subject: "h.example",
		Engines: []string{"codex", "claude-code"}, Max: 4, TTLDays: 30})
	if err != nil || got != "coder_grant|box1|h.example|engines:claude-code,codex|max:4|ttl:30" {
		t.Fatalf("purpose: %q %v", got, err)
	}
	if p, _ := purposeFromDetails(map[string]any{"kind": coderGrantKind, "server": "box1", "subject": "h.example",
		"engines": []any{"codex", "claude-code"}, "max": float64(4), "ttl_days": float64(30)}); p != got {
		t.Fatalf("the details the person reads build the same purpose: %q", p)
	}
	if stepupKindFamily(coderGrantKind) != "harness" || opFamily("coder_grant_sync") != "harness" ||
		!opTightens("coder_grant_drop") || !ownApproval("coder_grant_sync") {
		t.Fatal("coder grants are the harness family; the drop is a tighten; the sync carries its own approval")
	}
}

// ── the reaper ──────────────────────────────────────────────────────────────

func TestCoderReaper(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 10)
	writePairing(t, "h.example")
	for _, id := range []string{"run-keep-00001", "run-late-00001", "run-gone-00001"} {
		if b, code := runCoder(upSpec(id, "h.example")); code != 0 {
			t.Fatalf("%s: %s", id, b)
		}
	}
	// Age them past 120 s; push one past its deadline.
	for _, id := range []string{"run-keep-00001", "run-late-00001", "run-gone-00001"} {
		r, _ := loadCoderRecord(id)
		r.CreatedAt = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
		if id == "run-late-00001" {
			r.Deadline = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		}
		R, _ := coderRunDir(id)
		_ = saveCoderRecord(R, r)
	}
	// A reply without the key is no information: only the deadline applies.
	coderHeartbeatReply("h.example", []byte(`{}`))
	if _, ok := f.running["privatae-run-run-late-00001"]; ok {
		t.Fatal("a run past its deadline is reaped")
	}
	if len(f.running) != 2 {
		t.Fatalf("nothing else is reaped on a reply without coder_runs: %v", f.running)
	}
	// Two consecutive replies that leave one out reap it; one is not enough.
	coderHeartbeatReply("h.example", []byte(`{"coder_runs":["run-keep-00001"]}`))
	if len(f.running) != 2 {
		t.Fatal("one reply that leaves a run out is not enough")
	}
	coderHeartbeatReply("h.example", []byte(`{"coder_runs":["run-keep-00001"]}`))
	if _, ok := f.running["privatae-run-run-gone-00001"]; ok {
		t.Fatal("a run its host stopped holding is reaped after two replies")
	}
	if _, ok := f.running["privatae-run-run-keep-00001"]; !ok {
		t.Fatal("a run its host still holds is kept")
	}
	// A run whose host is no longer paired is reaped.
	pd, _ := pairingsDir()
	_ = os.Remove(filepath.Join(pd, "h.example.json"))
	writePairing(t, "other.example")
	coderReap("", nil, false)
	if len(f.running) != 0 || len(loadCoderRecords()) != 0 {
		t.Fatalf("a run whose host is gone is reaped: %v", f.running)
	}
}

// The 600 s an exited or missing run is kept count from when it stopped, not
// from when it was created. The reaper once counted from creation, so a run
// created 11 minutes ago that exited now was torn down on the next heartbeat
// and the Host's run-down got not_found instead of the exit code and OOM flag.
func TestCoderReaperCountsTheGraceFromTheExit(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 10)
	writePairing(t, "h.example")
	now := time.Now().UTC()
	oldNow := coderNow
	coderNow = func() time.Time { return now }
	t.Cleanup(func() {
		coderNow = oldNow
		coderReapMu.Lock()
		coderStoppedSeen = map[string]time.Time{}
		coderReapMu.Unlock()
	})
	const exitedNow, exitedOld, missing, runDown = "run-exnow-00001", "run-exold-00001", "run-miss-000001", "run-exrd-000001"
	far := now.Add(2 * time.Hour).Format(time.RFC3339) // no deadline is reached in this test
	cn := func(id string) string { return coderContainerPrefix + id }
	for _, id := range []string{exitedNow, exitedOld, missing, runDown} {
		if b, code := runCoder(upSpec(id, "h.example")); code != 0 {
			t.Fatalf("%s: %s", id, b)
		}
		r, _ := loadCoderRecord(id)
		r.CreatedAt = now.Add(-11 * time.Minute).Format(time.RFC3339)
		r.Deadline = far
		R, _ := coderRunDir(id)
		if err := saveCoderRecord(R, r); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.created[cn(id)] = now.Add(-11 * time.Minute)
		f.labels[cn(id)][coderLabelDeadline] = far
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.running[cn(exitedNow)], f.finished[cn(exitedNow)] = false, now
	f.running[cn(runDown)], f.finished[cn(runDown)] = false, now
	f.running[cn(exitedOld)], f.finished[cn(exitedOld)] = false, now.Add(-11*time.Minute)
	delete(f.running, cn(missing)) // the record stays; the container is gone
	f.mu.Unlock()

	coderReap("", nil, false)
	if _, ok := f.running[cn(exitedNow)]; !ok {
		t.Fatal("a run created 11 minutes ago that exited now is kept")
	}
	if _, ok := f.running[cn(exitedOld)]; ok {
		t.Fatal("a run that exited 11 minutes ago is reaped")
	}
	if r, _ := loadCoderRecord(exitedOld); r != nil {
		t.Fatal("the reaped run's record is gone")
	}
	if r, _ := loadCoderRecord(missing); r == nil {
		t.Fatal("a run first seen missing now keeps its record")
	}
	// What the grace is for: the Host's run-down still reads the exit code.
	b, code := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: runDown, owner: "h.example"})
	if m := decode(t, b); code != 0 || m["stopped"] != true || m["exit_code"] != float64(137) || m["oom_killed"] != false {
		t.Fatalf("run-down of a run that exited now reads its exit: %d %v", code, m)
	}

	// Eleven minutes on, both remaining runs are past their 600 s.
	now = now.Add(11 * time.Minute)
	coderReap("", nil, false)
	if _, ok := f.running[cn(exitedNow)]; ok {
		t.Fatal("a run that exited 11 minutes ago is reaped")
	}
	if r, _ := loadCoderRecord(missing); r != nil {
		t.Fatal("a run first seen missing 11 minutes ago is reaped")
	}
	if len(loadCoderRecords()) != 0 {
		t.Fatalf("no records are left: %v", loadCoderRecords())
	}
}

// A future exit time (the clock stepped back after the container exited)
// counts as none: the 600 s run from when the reaper first saw the run
// stopped. Read as is, the time stopped was negative, so the run was held
// for the whole skew on top of its 600 s.
//
// A skew shorter than the grace is the same: once the clock passes the
// stamp, the count stays on the first sighting rather than restarting at the
// stamp, which would hold the run for the skew.
//
// MUTATION: count from s.finished whenever it is set, future or not.
// RESULT: red — eleven minutes on, the run is still kept (an hour of skew).
// MUTATION: count from s.finished once the clock has passed it.
// RESULT: red — five minutes of skew, the run is still kept at eleven.
func TestCoderReaperReadsAFutureExitAsNow(t *testing.T) {
	for _, skew := range []time.Duration{time.Hour, 5 * time.Minute} {
		t.Run(skew.String(), func(t *testing.T) { testCoderReaperFutureExit(t, skew) })
	}
}

func testCoderReaperFutureExit(t *testing.T, skew time.Duration) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 10)
	writePairing(t, "h.example")
	now := time.Now().UTC()
	oldNow := coderNow
	coderNow = func() time.Time { return now }
	t.Cleanup(func() {
		coderNow = oldNow
		coderReapMu.Lock()
		coderStoppedSeen = map[string]time.Time{}
		coderExitAhead = map[string]time.Time{}
		coderReapMu.Unlock()
	})
	const id = "run-skew-000001"
	cn := coderContainerPrefix + id
	far := now.Add(3 * time.Hour).Format(time.RFC3339)
	if b, code := runCoder(upSpec(id, "h.example")); code != 0 {
		t.Fatalf("run-up: %s", b)
	}
	r, _ := loadCoderRecord(id)
	r.CreatedAt, r.Deadline = now.Add(-11*time.Minute).Format(time.RFC3339), far
	R, _ := coderRunDir(id)
	if err := saveCoderRecord(R, r); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.created[cn], f.labels[cn][coderLabelDeadline] = now.Add(-11*time.Minute), far
	f.running[cn], f.finished[cn] = false, now.Add(skew)
	f.mu.Unlock()

	coderReap("", nil, false)
	if _, ok := f.running[cn]; !ok {
		t.Fatal("a run whose exit time is ahead of the clock is never reaped early")
	}
	now = now.Add(9 * time.Minute)
	coderReap("", nil, false)
	if _, ok := f.running[cn]; !ok {
		t.Fatal("nine minutes after it was first seen stopped, the run is kept")
	}
	now = now.Add(2 * time.Minute)
	coderReap("", nil, false)
	if _, ok := f.running[cn]; ok {
		t.Fatal("eleven minutes after it was first seen stopped, the run is reaped despite its future exit time")
	}
}

// nerdctl's inspect has no State.OOMKilled (its dockercompat ContainerState
// leaves it a TODO), and a template naming it fails whole. run-down once read
// both fields in one template, so on nerdctl the exit code was lost with the
// OOM flag. Each is read on its own: the exit code is reported and
// oom_killed is null.
//
// MUTATION: read "{{.State.OOMKilled}}|{{.State.ExitCode}}" in one inspect.
// RESULT: red — exit_code is null on nerdctl.
func TestCoderRunDownOnNerdctlKeepsTheExitCode(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderRuntime = func() string { return "nerdctl" }
	f.noOOM = true
	coderOn(t, 2)
	writePairing(t, "h.example")
	if b, code := runCoder(upSpec("run-nerd-00001", "h.example")); code != 0 {
		t.Fatalf("run-up: %s", b)
	}
	b, code := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: "run-nerd-00001", owner: "h.example"})
	m := decode(t, b)
	if oom, ok := m["oom_killed"]; code != 0 || m["stopped"] != true || m["exit_code"] != float64(137) || !ok || oom != nil {
		t.Fatalf("run-down on nerdctl reports the exit code and a null OOM flag: %d %v", code, m)
	}
}

// coderInspectTime reads every runtime's form of an inspect time, and the
// "never" forms are zero, so a container that has not exited never reads as
// having exited in year 1. podman's form in a zone with no abbreviation ends
// in the offset twice; with minutes in it ("+0330", "+0545") the MST layout
// does not take it.
//
// MUTATION: drop the read without the last word.
// RESULT: red — the Tehran, Kathmandu and Chatham forms read as zero.
func TestCoderInspectTime(t *testing.T) {
	want := time.Date(2026, 10, 13, 17, 58, 20, 413778580, time.UTC)
	forms := []string{
		"2026-10-13T17:58:20.41377858Z",          // docker, nerdctl
		"2026-10-13 17:58:20.41377858 +0000 UTC", // podman (time.Time)
		" 2026-10-13T17:58:20.41377858Z\n",       // surrounding space
	}
	// podman's form in each kind of zone, printed by Go itself: a zone with no
	// abbreviation prints its offset in its place (as Tehran, Kathmandu and
	// Chatham do), one with an abbreviation prints that (as Kolkata, Berlin
	// and St John's do). Fixed zones, so no zone database is needed.
	for _, z := range []*time.Location{time.FixedZone("", 3*3600+30*60), time.FixedZone("", 5*3600+45*60),
		time.FixedZone("", 13*3600+45*60), time.FixedZone("", -3*3600), time.FixedZone("IST", 5*3600+30*60),
		time.FixedZone("CEST", 2*3600), time.FixedZone("NDT", -(2*3600 + 30*60))} {
		forms = append(forms, want.In(z).String())
	}
	// The zone database's own forms: Tehran, Kathmandu, São Paulo.
	forms = append(forms, "2026-10-13 21:28:20.41377858 +0330 +0330", "2026-10-13 23:43:20.41377858 +0545 +0545",
		"2026-10-13 14:58:20.41377858 -0300 -03")
	for _, v := range forms {
		if got := coderInspectTime(v); !got.Equal(want) {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
	// docker's and podman's "never" (Go's zero time, as each prints it), and
	// nerdctl's empty field.
	for _, v := range []string{"0001-01-01T00:00:00Z", time.Time{}.String(), "0001-01-01 00:00:00 +0000 UTC",
		"", "<no value>", "garbage", "2026-10-13 17:58:20 garbage", "garbage +0330"} {
		if got := coderInspectTime(v); !got.IsZero() {
			t.Errorf("%q is no time: %v", v, got)
		}
	}
}

// A machine that never used coder mode does nothing on a heartbeat: no
// runtime call, no directory.
func TestCoderReaperIsInertWhenUnused(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderHeartbeatReply("h.example", []byte(`{"coder_runs":[]}`))
	coderReconcileEgress()
	if len(f.calls) != 0 {
		t.Fatalf("no runtime calls: %v", f.calls)
	}
	d, _ := configDirPath()
	if _, err := os.Stat(filepath.Join(d, "coders")); !os.IsNotExist(err) {
		t.Fatal("no coders directory is created")
	}
}

// The H frame end to end on a local box: the spec is refused before any gate
// when it is malformed, and a run-status answers.
func TestCoderOverTheHarnessLane(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	coderOn(t, 2)
	b, code := driveHarness(t, "h.example", harnessSpec{Mode: "coder", CoderOp: "run-up", RunID: "BAD"})
	if code != 1 || b["ok"] != false || !strings.Contains(fmt.Sprint(b["error"]), "run_id") {
		t.Fatalf("a bad spec is refused: %d %v", code, b)
	}
	b, code = driveHarness(t, "h.example", harnessSpec{Mode: "coder", CoderOp: "run-status"})
	if runs, ok := b["runs"].([]any); code != 0 || !ok || len(runs) != 0 {
		t.Fatalf("run-status: %d %v", code, b)
	}
}

// A runtime that cannot list its containers (a daemon slow under 30 parallel
// runs, past the 15 s listing timeout) is no information. The reaper once
// read it as "every run has exited" and tore down every live run older than
// 600 s.
func TestCoderReaperKeepsRunsWhenTheRuntimeCannotList(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 10)
	writePairing(t, "h.example")
	if b, code := runCoder(upSpec("run-live-00001", "h.example")); code != 0 {
		t.Fatalf("run-up: %s", b)
	}
	r, _ := loadCoderRecord("run-live-00001")
	r.CreatedAt = time.Now().Add(-11 * time.Minute).UTC().Format(time.RFC3339)
	R, _ := coderRunDir("run-live-00001")
	_ = saveCoderRecord(R, r)
	f.failPs = true
	coderReap("", nil, false)
	coderHeartbeatReply("h.example", []byte(`{}`))
	if running, ok := f.running["privatae-run-run-live-00001"]; !ok || !running {
		t.Fatalf("a running run is kept when the runtime cannot list: %v", f.running)
	}
	if len(f.has("stop")) != 0 || len(loadCoderRecords()) != 1 {
		t.Fatalf("nothing is stopped and the record stays: stops=%v", f.has("stop"))
	}
	// The listing back, the run still running: still kept.
	f.failPs = false
	coderReap("", nil, false)
	if _, ok := f.running["privatae-run-run-live-00001"]; !ok {
		t.Fatal("a running run is kept once the runtime lists it")
	}
}

// run-down with no record falls back to the container's labels. A container
// that merely has the name, without this bastion's run label, is not a coder
// run and is never stopped. On an anchored box, one whose owner label is
// missing is not a member pairing's to stop: only the anchor's.
func TestCoderRunDownWithoutARecordNeedsTheCoderLabels(t *testing.T) {
	setupBox(t)
	writePairing(t, tMember)
	f := stubCoders(t)
	coderOn(t, 4)
	// Not a coder container: only the name matches.
	f.running["privatae-run-foreign-0001"] = true
	f.labels["privatae-run-foreign-0001"] = map[string]string{}
	// A coder container whose owner label is gone.
	f.running["privatae-run-noowner-001"] = true
	f.labels["privatae-run-noowner-001"] = map[string]string{coderLabelRun: "noowner-001"}
	b, _ := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: "foreign-0001", owner: tAnchor})
	if m := decode(t, b); m["stopped"] != false || m["reason"] != "not_found" {
		t.Fatalf("a container without the coder run label is not stopped, even by the anchor: %v", m)
	}
	b, code := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: "noowner-001", owner: tMember})
	if m := decode(t, b); code != 1 || m["ok"] != false || !strings.Contains(fmt.Sprint(m["error"]), "refused") {
		t.Fatalf("a run with no known owner is refused to a member pairing: %d %v", code, m)
	}
	if len(f.has("stop")) != 0 || len(f.has("rm")) != 0 || !f.running["privatae-run-foreign-0001"] ||
		!f.running["privatae-run-noowner-001"] {
		t.Fatalf("neither container is touched: stops=%v rms=%v", f.has("stop"), f.has("rm"))
	}
	// The anchor may stop it.
	b, code = runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: "noowner-001", owner: tAnchor})
	m := decode(t, b)
	if code != 0 || m["stopped"] != true {
		t.Fatalf("the anchor stops a run with no known owner: %d %v", code, m)
	}
	// With no record there is no start time, so the run's wall time is not
	// known: null, never 0 (a measurement that cannot be read is null).
	if w, ok := m["wall_s"]; !ok || w != nil {
		t.Fatalf("run-down without a record reports wall_s null: %v", m)
	}
}

// ── the machine guard ───────────────────────────────────────────────────────

func TestCoderReserveFollowsTheGKETiers(t *testing.T) {
	for _, c := range []struct{ total, want int }{
		{512, 355},      // under 1 GiB: 255 MiB
		{3819, 1055},    // the 3.7 GiB machine of the load test
		{4096, 1124},    // 25% of 4 GiB
		{8192, 1944},    // + 20% of the next 4
		{16384, 2763},   // + 10% of the next 8
		{131072, 9644},  // + 6% of the next 112
		{262144, 12266}, // + 2% above 128 GiB
	} {
		if got := coderReserveMB(c.total); got != c.want {
			t.Errorf("reserve for %d MiB: got %d, want %d (tiers plus the 100 MiB eviction threshold)", c.total, got, c.want)
		}
		if coderBudgetMB(c.total) != c.total-c.want {
			t.Errorf("budget for %d MiB is what the reserve leaves", c.total)
		}
	}
}

// stubCoderCgroups gives every run container a pid, a /proc/<pid>/cgroup line
// and a populated cgroup with a cgroup.kill file, under temporary roots.
// ids are the run ids, in the order their pids are handed out.
func stubCoderCgroups(t *testing.T, f *fakeCoderRT, ids ...string) (cgRoot string) {
	t.Helper()
	proc, cg := t.TempDir(), t.TempDir()
	oldProc, oldCg := coderProcFS, coderCgroupFS
	coderProcFS, coderCgroupFS = proc, cg
	t.Cleanup(func() { coderProcFS, coderCgroupFS = oldProc, oldCg })
	for i, id := range ids {
		pid := 5000 + i
		f.mu.Lock()
		f.pid[coderContainerPrefix+id] = pid
		f.mu.Unlock()
		scope := "system.slice/docker-" + id + ".scope"
		_ = os.MkdirAll(filepath.Join(proc, fmt.Sprint(pid)), 0o755)
		_ = os.WriteFile(filepath.Join(proc, fmt.Sprint(pid), "cgroup"), []byte("0::/"+scope+"\n"), 0o644)
		_ = os.MkdirAll(filepath.Join(cg, scope), 0o755)
		setCoderPopulated(t, cg, id, true)
		_ = os.WriteFile(filepath.Join(cg, scope, "cgroup.kill"), nil, 0o644)
	}
	return cg
}

func setCoderPopulated(t *testing.T, cg, id string, up bool) {
	t.Helper()
	v := "0"
	if up {
		v = "1"
	}
	p := filepath.Join(cg, "system.slice/docker-"+id+".scope", "cgroup.events")
	if err := os.WriteFile(p, []byte("populated "+v+"\nfrozen 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The load test that hung a machine: 3819 MiB, twelve 512 MiB runs asked for
// together. Free memory was 3000 MiB at every run-up, because none of the
// runs had grown yet, so every one of them started. Run-up now counts each
// run's limit against the budget (3819 - 1055 = 2764 MiB): five fit.
func TestCoderRunUpCountsEveryRunsLimitAgainstTheBudget(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderMemInfo = func() (uint64, uint64, bool) { return 3819 << 20, 3000 << 20, true }
	ids := make([]string, 8)
	for i := range ids {
		ids[i] = fmt.Sprintf("run-budget-%04d", i)
	}
	cg := stubCoderCgroups(t, f, ids...)
	if err := saveCoderConfig(coderConfig{Enabled: true, Max: 12, MemPerRun: 512, CPUsPerRun: 0.25,
		Engines: append([]string(nil), coderEngines...)}); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[:5] {
		if b, code := runCoder(upSpec(id, "h.example")); code != 0 || decode(t, b)["started"] != true {
			t.Fatalf("%s fits: %d %s", id, code, b)
		}
	}
	r, _ := loadCoderRecord(ids[0])
	if r.MemMB != 512 || r.Cgroup != "/system.slice/docker-"+ids[0]+".scope" {
		t.Fatalf("the record keeps the run's limit and cgroup: %+v", r)
	}
	b, code := runCoder(upSpec(ids[5], "h.example"))
	m := decode(t, b)
	if code != 0 || m["started"] != false || m["reason"] != "full" || m["running"] != float64(5) ||
		m["mem_budget_mb"] != float64(2764) || m["mem_committed_mb"] != float64(2560) || m["mem_avail_mb"] != float64(3000) {
		t.Fatalf("a sixth 512 MiB run does not fit in 2764 MiB beside five: %d %s", code, b)
	}
	// A larger size set now does not shrink what the running five hold.
	c := loadCoderConfig()
	c.MemPerRun = 256 + 256
	_ = saveCoderConfig(c)
	// A run whose container has stopped holds no memory, though its record
	// stays for run-down: its share is free again.
	setCoderPopulated(t, cg, ids[1], false)
	if b, code := runCoder(upSpec(ids[5], "h.example")); code != 0 || decode(t, b)["started"] != true {
		t.Fatalf("a stopped run's share is free again: %d %s", code, b)
	}
	// A run whose cgroup is gone has stopped too; one whose cgroup was never
	// recorded counts at its limit.
	_ = os.RemoveAll(filepath.Join(cg, "system.slice/docker-"+ids[2]+".scope"))
	r, _ = loadCoderRecord(ids[3])
	r.Cgroup = ""
	R, _ := coderRunDir(ids[3])
	_ = saveCoderRecord(R, r)
	if b, code := runCoder(upSpec(ids[6], "h.example")); code != 0 || decode(t, b)["started"] != true {
		t.Fatalf("a run whose cgroup is gone holds nothing: %d %s", code, b)
	}
	if b, code := runCoder(upSpec(ids[7], "h.example")); code != 0 || decode(t, b)["reason"] != "full" {
		t.Fatalf("five runs held again (one of them unknown, counted at its limit): %d %s", code, b)
	}
}

// A machine already stalling on memory starts nothing more.
func TestCoderRunUpRefusesWhileTheMachineStallsOnMemory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubCoders(t)
	coderOn(t, 4)
	coderPSIMem = func() (float64, bool) { return 72.5, true }
	b, code := runCoder(upSpec("run-stall-0001", "h.example"))
	if m := decode(t, b); code != 0 || m["reason"] != "full" || m["mem_pressure"] != 72.5 {
		t.Fatalf("memory pressure over 60%% is the full answer: %d %s", code, b)
	}
	coderPSIMem = func() (float64, bool) { return 0, false }
	if b, code := runCoder(upSpec("run-stall-0001", "h.example")); code != 0 || decode(t, b)["started"] != true {
		t.Fatalf("a kernel without PSI is no reason to refuse: %d %s", code, b)
	}
}

func TestCoderWatchdogStopsTheNewestRunToProtectTheMachine(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 10)
	ids := []string{"run-watch-0001", "run-watch-0002", "run-watch-0003", "run-watch-0004"}
	cg := stubCoderCgroups(t, f, ids...)
	now := time.Now().UTC().Truncate(time.Second)
	oldNow := coderNow
	coderNow = func() time.Time { return now }
	t.Cleanup(func() { coderNow = oldNow })
	g := &coderGuard{}

	// No runs: nothing to do, and the runtime is never asked.
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 50 << 20, true }
	if id, _ := g.round(); id != "" || len(f.calls) != 0 {
		t.Fatalf("no runs, nothing stopped, no runtime: %q %v", id, f.calls)
	}
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 12 << 30, true }
	for i, id := range ids {
		if b, code := runCoder(upSpec(id, "h.example")); code != 0 {
			t.Fatalf("%s: %s", id, b)
		}
		r, _ := loadCoderRecord(id)
		r.CreatedAt = now.Add(time.Duration(i-10) * time.Minute).Format(time.RFC3339) // 0001 oldest
		R, _ := coderRunDir(id)
		_ = saveCoderRecord(R, r)
	}
	killed := func(id string) bool {
		b, _ := os.ReadFile(filepath.Join(cg, "system.slice/docker-"+id+".scope", "cgroup.kill"))
		return string(b) == "1"
	}
	calls := len(f.calls)
	if id, _ := g.round(); id != "" {
		t.Fatalf("plenty free and no pressure: nothing stopped, got %s", id)
	}

	// Under 100 MiB free: the newest run, at once, through its cgroup.
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 80 << 20, true }
	id, why := g.round()
	if id != ids[3] || !killed(ids[3]) || killed(ids[2]) || !strings.Contains(why, "80 MiB") {
		t.Fatalf("the newest run is stopped first: %q %q", id, why)
	}
	if len(f.calls) != calls {
		t.Fatalf("the cgroup kill needs no runtime: %v", f.calls[calls:])
	}
	if r, _ := loadCoderRecord(ids[3]); r == nil || r.StoppedBy != why {
		t.Fatalf("the record stays, marked with why: %+v", r)
	}
	setCoderPopulated(t, cg, ids[3], false) // the kernel empties the cgroup
	// Still short: the next newest, on the very next round.
	if id, _ := g.round(); id != ids[2] {
		t.Fatalf("still under the floor: the next newest, got %q", id)
	}
	setCoderPopulated(t, cg, ids[2], false)

	// Pressure, with memory free: only once it has held for 30 s, and not
	// again until the last stop has had 10 s to show.
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 2 << 30, true }
	coderPSIMem = func() (float64, bool) { return 70, true }
	g.lastStop = time.Time{}
	t0 := now
	for _, d := range []time.Duration{0, 29 * time.Second} {
		now = t0.Add(d)
		if id, _ := g.round(); id != "" {
			t.Fatalf("pressure for %s is not yet 30 s: stopped %s", d, id)
		}
	}
	now = t0.Add(30 * time.Second)
	if id, _ := g.round(); id != ids[1] {
		t.Fatalf("30 s over the limit: the newest running run, got %q", id)
	}
	now = t0.Add(38 * time.Second)
	if id, _ := g.round(); id != "" {
		t.Fatalf("8 s after a stop its effect has not shown yet: stopped %s", id)
	}
	// Pressure that drops starts the 30 s again.
	now = t0.Add(41 * time.Second)
	coderPSIMem = func() (float64, bool) { return 10, true }
	_, _ = g.round()
	coderPSIMem = func() (float64, bool) { return 70, true }
	now = t0.Add(42 * time.Second)
	if id, _ := g.round(); id != "" {
		t.Fatalf("pressure that dropped counts its 30 s afresh: stopped %s", id)
	}
	now = t0.Add(72 * time.Second)
	if id, _ := g.round(); id != ids[0] {
		t.Fatalf("30 s over again: the last run, got %q", id)
	}

	// The Host's run-down and run-status read why.
	b, _ := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: ids[3], owner: "h.example"})
	if m := decode(t, b); m["stopped"] != true || !strings.Contains(fmt.Sprint(m["stopped_by"]), "MiB of memory free") {
		t.Fatalf("run-down reports why the watchdog stopped the run: %s", b)
	}
	st := decode(t, mustStatus(t, "h.example"))
	for _, r := range st["runs"].([]any) {
		if r.(map[string]any)["stopped_by"] == nil {
			t.Fatalf("run-status reports why: %v", r)
		}
	}
}

// A record without a cgroup (written before it was kept) is stopped through
// the runtime, and only while the runtime says it runs.
func TestCoderWatchdogFallsBackToTheRuntime(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 4)
	for _, id := range []string{"run-old-000001", "run-old-000002"} {
		if b, code := runCoder(upSpec(id, "h.example")); code != 0 {
			t.Fatalf("%s: %s", id, b)
		}
	}
	f.mu.Lock()
	f.running["privatae-run-run-old-000002"] = false
	f.mu.Unlock()
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 10 << 20, true }
	g := &coderGuard{}
	if id, _ := g.round(); id != "run-old-000001" || len(f.has("kill")) != 1 || f.has("kill")[0][2] != "privatae-run-run-old-000001" {
		t.Fatalf("the exited one is passed over, the running one killed through the runtime: %q %v", id, f.has("kill"))
	}
	if id, _ := g.round(); id != "" {
		t.Fatalf("nothing left running: %q", id)
	}
}

func TestCoderParsePSIFull(t *testing.T) {
	in := "some avg10=81.20 avg60=40.00 avg300=9.00 total=123\nfull avg10=64.50 avg60=30.00 avg300=7.00 total=99\n"
	if v, ok := coderParsePSIFull(in); !ok || v != 64.5 {
		t.Fatalf("full avg10: %v %v", v, ok)
	}
	if _, ok := coderParsePSIFull("some avg10=1.00 avg60=0 avg300=0 total=1\n"); ok {
		t.Fatal("no full line is unknown, not 0")
	}
}

// On a cgroup v1 or hybrid machine the "0::" line of /proc/<pid>/cgroup names
// a path in a v2 tree that is not mounted at /sys/fs/cgroup (or names "/").
// Such a run must count at its limit and stay stoppable; it must never read
// as stopped because its cgroup is "gone".
func TestCoderRunOutsideTheV2TreeCountsAndIsStopped(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderMemInfo = func() (uint64, uint64, bool) { return 3819 << 20, 3000 << 20, true }
	proc, cg := t.TempDir(), t.TempDir()
	oldProc, oldCg := coderProcFS, coderCgroupFS
	coderProcFS, coderCgroupFS = proc, cg
	t.Cleanup(func() { coderProcFS, coderCgroupFS = oldProc, oldCg })
	ids := []string{"run-v1-0000001", "run-v1-0000002", "run-v1-0000003"}
	lines := []string{
		"4:memory:/docker/abc\n0::/system.slice/docker-abc.scope\n", // hybrid: the v2 tree is elsewhere
		"4:memory:/docker/def\n0::/\n",                              // legacy: every process sits at the v2 root
		"4:memory:/docker/ghi\n0::/system.slice/docker-ghi.scope\n",
	}
	for i, id := range ids {
		pid := 6000 + i
		f.mu.Lock()
		f.pid[coderContainerPrefix+id] = pid
		f.mu.Unlock()
		_ = os.MkdirAll(filepath.Join(proc, fmt.Sprint(pid)), 0o755)
		_ = os.WriteFile(filepath.Join(proc, fmt.Sprint(pid), "cgroup"), []byte(lines[i]), 0o644)
	}
	if err := saveCoderConfig(coderConfig{Enabled: true, Max: 12, MemPerRun: 1024, CPUsPerRun: 0.25,
		Engines: append([]string(nil), coderEngines...)}); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[:2] {
		if b, code := runCoder(upSpec(id, "h.example")); code != 0 || decode(t, b)["started"] != true {
			t.Fatalf("%s fits: %d %s", id, code, b)
		}
		if r, _ := loadCoderRecord(id); r == nil || r.Cgroup != "" {
			t.Fatalf("a cgroup that is not under the v2 mount is not recorded: %+v", r)
		}
	}
	b, code := runCoder(upSpec(ids[2], "h.example"))
	if m := decode(t, b); code != 0 || m["reason"] != "full" || m["mem_committed_mb"] != float64(2048) {
		t.Fatalf("two 1024 MiB runs are held, so a third does not fit in 2764 MiB: %d %s", code, b)
	}
	coderMemInfo = func() (uint64, uint64, bool) { return 3819 << 20, 50 << 20, true }
	g := &coderGuard{}
	if id, _ := g.round(); id != ids[1] || len(f.has("kill")) != 1 || f.has("kill")[0][2] != coderContainerPrefix+ids[1] {
		t.Fatalf("the newest run is stopped through the runtime: %q %v", id, f.has("kill"))
	}
}

// A killed run's memory is free only once its processes have exited. While
// the run stopped last still has processes (for at most the settle time),
// the watchdog stops no other, so one stop is not turned into two.
func TestCoderWatchdogWaitsForTheLastStopToExit(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 10)
	ids := []string{"run-exit-00001", "run-exit-00002", "run-exit-00003"}
	cg := stubCoderCgroups(t, f, ids...)
	now := time.Now().UTC().Truncate(time.Second)
	oldNow := coderNow
	coderNow = func() time.Time { return now }
	t.Cleanup(func() { coderNow = oldNow })
	for i, id := range ids {
		if b, code := runCoder(upSpec(id, "h.example")); code != 0 {
			t.Fatalf("%s: %s", id, b)
		}
		r, _ := loadCoderRecord(id)
		r.CreatedAt = now.Add(time.Duration(i-10) * time.Minute).Format(time.RFC3339)
		R, _ := coderRunDir(id)
		_ = saveCoderRecord(R, r)
	}
	coderMemInfo = func() (uint64, uint64, bool) { return 16 << 30, 80 << 20, true }
	g := &coderGuard{}
	t0 := now
	if id, _ := g.round(); id != ids[2] {
		t.Fatalf("the newest run first: %q", id)
	}
	// Its processes are still exiting (the cgroup stays populated).
	now = t0.Add(coderWatchEvery)
	if id, _ := g.round(); id != "" {
		t.Fatalf("the last stop has not exited yet, so no second stop: %q", id)
	}
	// Once it has exited, a machine still short stops the next newest.
	setCoderPopulated(t, cg, ids[2], false)
	now = t0.Add(2 * coderWatchEvery)
	if id, _ := g.round(); id != ids[1] {
		t.Fatalf("the last stop exited and memory is still short: %q", id)
	}
	// A stop that never empties holds the watchdog back for the settle time only.
	t1 := now
	now = t1.Add(coderPressureSettle - time.Second)
	if id, _ := g.round(); id != "" {
		t.Fatalf("inside the settle time: %q", id)
	}
	now = t1.Add(coderPressureSettle)
	if id, _ := g.round(); id != ids[0] {
		t.Fatalf("past the settle time the watchdog acts again: %q", id)
	}
}

// Rewriting a record never brings back a run directory that a teardown in
// another process removed.
func TestCoderRewriteRecordNeverRecreatesARemovedRun(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	R, err := coderRunDir("run-gone-000009")
	if err != nil {
		t.Fatal(err)
	}
	r := &coderRecord{RunID: "run-gone-000009", StoppedBy: "x"}
	if err := coderRewriteRecord(R, r); err == nil {
		t.Fatal("a rewrite with no run directory fails")
	}
	if _, err := os.Stat(R); !os.IsNotExist(err) {
		t.Fatalf("the run directory stays gone: %v", err)
	}
	if err := os.MkdirAll(R, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := coderRewriteRecord(R, r); err != nil {
		t.Fatal(err)
	}
	if got, err := loadCoderRecord("run-gone-000009"); err != nil || got.StoppedBy != "x" {
		t.Fatalf("an existing run's record is replaced: %+v %v", got, err)
	}
	if fi, err := os.Stat(filepath.Join(R, "run.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the record stays 0600: %v %v", fi, err)
	}
}

// CPU and GPU: a run takes the lowest CPU share, so the machine's own work
// always comes first, and it never gets a GPU, by flag, by device or through
// a default NVIDIA runtime.
func TestCoderRunYieldsTheCPUAndGetsNoGPU(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 2)
	if b, code := runCoder(upSpec("run-share-0001", "h.example")); code != 0 {
		t.Fatalf("run-up: %s", b)
	}
	run := f.has("run")
	if len(run) != 1 {
		t.Fatalf("one container started: %v", run)
	}
	args := strings.Join(run[0], "\x00")
	for _, want := range []string{"\x00--cpu-shares\x002\x00", "\x00-e\x00NVIDIA_VISIBLE_DEVICES=void\x00"} {
		if !strings.Contains(args, want) {
			t.Errorf("the run's command line lacks %q: %q", strings.ReplaceAll(want, "\x00", " "), run[0])
		}
	}
	for _, a := range run[0] {
		for _, bad := range []string{"--gpus", "--device", "--privileged", "--runtime"} {
			if a == bad || strings.HasPrefix(a, bad+"=") {
				t.Errorf("a run never gets %s: %q", bad, run[0])
			}
		}
	}
}

// NVIDIA's toolkit reads the names its config lists in swarm-resource in
// place of NVIDIA_VISIBLE_DEVICES when a container sets one. An image that set
// one would get GPUs past NVIDIA_VISIBLE_DEVICES=void, so a run sets every
// listed name to "void" itself; the commented-out default adds nothing.
func TestCoderRunVoidsTheNvidiaSwarmResourceNames(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubCoders(t)
	coderOn(t, 2)
	cfg := "#swarm-resource = \"DOCKER_RESOURCE_GPU\"\n" +
		"accept-nvidia-visible-devices-envvar-when-unprivileged = true\n" +
		"swarm-resource = \"DOCKER_RESOURCE_GPU, GPU_SLOT ,not a name\" # set for Swarm\n" +
		"\n[nvidia-container-runtime]\nmode = \"auto\"\n"
	if err := os.WriteFile(coderNvidiaConfig, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, code := runCoder(upSpec("run-swarm-0001", "h.example")); code != 0 {
		t.Fatalf("run-up: %s", b)
	}
	run := f.has("run")
	if len(run) != 1 {
		t.Fatalf("one container started: %v", run)
	}
	n := len(run[0])
	tail := strings.Join(run[0][n-7:], " ")
	want := "-e NVIDIA_VISIBLE_DEVICES=void -e DOCKER_RESOURCE_GPU=void -e GPU_SLOT=void " + testCoderImage
	if tail != want {
		t.Fatalf("every swarm-resource name is voided, before the image:\n got %q\nwant %q", tail, want)
	}
	if strings.Contains(strings.Join(run[0], " "), "not a name") {
		t.Fatalf("only valid variable names are passed: %q", run[0])
	}
}
