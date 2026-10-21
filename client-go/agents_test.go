package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestParseEnvToken(t *testing.T) {
	env := []byte("PATH=/usr/bin\x00PRIVATAE_AGENT_TOKEN=del_abc123\x00HOME=/root\x00")
	if got := parseEnvToken(env, "PRIVATAE_AGENT_TOKEN"); got != "del_abc123" {
		t.Errorf("parseEnvToken = %q, want del_abc123", got)
	}
	if got := parseEnvToken([]byte("PATH=/usr/bin\x00HOME=/root\x00"), "PRIVATAE_AGENT_TOKEN"); got != "" {
		t.Errorf("parseEnvToken(absent) = %q, want empty", got)
	}
	// must not partial-match a different var ending in the key
	if got := parseEnvToken([]byte("X_PRIVATAE_AGENT_TOKEN=nope\x00"), "PRIVATAE_AGENT_TOKEN"); got != "" {
		t.Errorf("parseEnvToken(suffix) = %q, want empty", got)
	}
}

func TestPidFromSSLine(t *testing.T) {
	line := `ESTAB 0 0 10.0.0.1:54321 1.2.3.4:443 users:(("python3",pid=12345,fd=7))`
	if got := pidFromSSLine(line); got != 12345 {
		t.Errorf("pidFromSSLine = %d, want 12345", got)
	}
	if got := pidFromSSLine("ESTAB 0 0 10.0.0.1:1 1.2.3.4:443"); got != 0 {
		t.Errorf("pidFromSSLine(no proc) = %d, want 0", got)
	}
}

func TestBinBase(t *testing.T) {
	cases := map[string]string{
		"claude":                         "claude",
		"/usr/local/bin/claude":          "claude",
		`C:\Program Files\node\node.exe`: "node",
		`C:/tools/claude.EXE`:            "claude",
		"  /opt/x/AIDER  ":               "aider",
		"":                               "",
	}
	for in, want := range cases {
		if got := binBase(in); got != want {
			t.Errorf("binBase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchAgentSignature(t *testing.T) {
	cases := []struct {
		argv []string
		want string
		ok   bool
	}{
		{[]string{"claude"}, "claude-code", true},
		{[]string{"/usr/local/bin/claude", "--resume"}, "claude-code", true},
		{[]string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, "claude-code", true},
		{[]string{"aider", "--model", "gpt-4"}, "aider", true},
		{[]string{"cursor-agent"}, "cursor", true},
		{[]string{"python3", "-m", "interpreter"}, "open-interpreter", false}, // bare "interpreter" only matches argv0 basename
		{[]string{"interpreter"}, "open-interpreter", true},
		{[]string{"sleep", "60"}, "", false},
		{[]string{"bash"}, "", false},
		{[]string{"/home/claudefile/script.sh"}, "", false},                   // no false positive on a path substring
		{[]string{"bash", "-c", "echo deploying claude-code now"}, "", false}, // a shell that MENTIONS the marker is NOT an agent
		{[]string{"sh", "-c", "exec -a claude-code sleep 600"}, "", false},    // ditto — argv0=sh, not an interpreter
		{[]string{"claude-code"}, "claude-code", true},                        // direct binary named claude-code
		{nil, "", false},

		// Windows: Toolhelp hands back an image name, and the raw command line
		// arrives as ONE extra element (never tokenized — see agents_windows.go).
		{[]string{"claude.exe"}, "claude-code", true},
		{[]string{"node.exe", `"C:\Program Files\nodejs\node.exe" C:\Users\a\AppData\npm\@anthropic-ai\claude-code\cli.js`}, "claude-code", true},
		{[]string{"node.exe", `"C:\Program Files\nodejs\node.exe" server.js`}, "", false},
		{[]string{"NOTEPAD.EXE"}, "", false},
	}
	for _, c := range cases {
		got, ok := matchAgentSignature(c.argv)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("matchAgentSignature(%v) = (%q,%v), want (%q,%v)", c.argv, got, ok, c.want, c.ok)
		}
	}
}

func TestSplitHostPortLoose(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
		ok   bool
	}{
		{"1.2.3.4:443", "1.2.3.4", 443, true},
		{"[fd00::1]:11434", "fd00::1", 11434, true},
		{"[::1]:1234", "::1", 1234, true},
		{"127.0.0.1:11434", "127.0.0.1", 11434, true},
		{"nonsense", "", 0, false},
		{"1.2.3.4:0", "", 0, false},
		{"1.2.3.4:99999", "", 0, false},
		{"", "", 0, false},
	}
	for _, c := range cases {
		ip, port, ok := splitHostPortLoose(c.in)
		if ok != c.ok || ip != c.ip || port != c.port {
			t.Errorf("splitHostPortLoose(%q) = (%q,%d,%v), want (%q,%d,%v)", c.in, ip, port, ok, c.ip, c.port, c.ok)
		}
	}
}

func TestPortOfAddr(t *testing.T) {
	cases := map[string]int{
		"127.0.0.1:11434":       11434,
		"http://127.0.0.1:8080": 8080,
		"[::1]:1234":            1234,
		"localhost:5000/v1":     5000,
		"11434":                 0, // a bare port is not an address
		"localhost":             0,
		"":                      0,
	}
	for in, want := range cases {
		if got := portOfAddr(in); got != want {
			t.Errorf("portOfAddr(%q) = %d, want %d", in, got, want)
		}
	}
}

// The local-inference tiering is the part most able to cause harm: a wrong
// "strong" verdict raises an unrequested-agent alert on a developer running an
// ordinary web server on :8080.
func TestLocalLLMPortTiers(t *testing.T) {
	t.Setenv("OLLAMA_ADDR", "")
	t.Setenv("PRIVATAE_LLM_ADDR", "")
	strong, weak := localLLMPorts()
	if strong[11434] == "" {
		t.Error("11434 must be strong: it is ollama's published default")
	}
	if weak[8080] == "" {
		t.Error("8080 must be WEAK by default — it collides with ordinary web development")
	}
	if strong[8080] != "" {
		t.Error("8080 must not be strong on a box that never declared an inference server there")
	}

	// Declared by the operator => the same port becomes evidence on its own.
	t.Setenv("PRIVATAE_LLM_ADDR", "127.0.0.1:8080")
	strong, weak = localLLMPorts()
	if strong[8080] == "" {
		t.Error("a port named by PRIVATAE_LLM_ADDR must be strong — the operator declared it")
	}
	if weak[8080] != "" {
		t.Error("a port promoted to strong must not also remain weak")
	}
}

func TestClassifyConn(t *testing.T) {
	cloud := map[string]string{"1.2.3.4": "api.anthropic.com"}
	strong := map[int]string{11434: "ollama"}
	weak := map[int]string{8080: "llama.cpp/localai"}

	if label, alone := classifyConn(connObs{RemoteIP: "1.2.3.4", RemotePort: 443}, cloud, strong, weak); label != "api.anthropic.com" || !alone {
		t.Errorf("cloud endpoint = (%q,%v), want (api.anthropic.com,true)", label, alone)
	}
	if label, alone := classifyConn(connObs{RemoteIP: "127.0.0.1", RemotePort: 11434}, cloud, strong, weak); label != "local:11434 (ollama)" || !alone {
		t.Errorf("known local = (%q,%v), want (local:11434 (ollama),true)", label, alone)
	}
	// A LAN GPU box is the same signal as loopback — the address is the user's
	// choice, the port is the server's default.
	if label, _ := classifyConn(connObs{RemoteIP: "192.168.1.50", RemotePort: 11434}, cloud, strong, weak); label != "local:11434 (ollama)" {
		t.Errorf("LAN ollama = %q, want local:11434 (ollama)", label)
	}
	if label, alone := classifyConn(connObs{RemoteIP: "127.0.0.1", RemotePort: 8080}, cloud, strong, weak); label == "" || alone {
		t.Errorf("ambiguous local = (%q,%v), want (non-empty,false)", label, alone)
	}
	if label, _ := classifyConn(connObs{RemoteIP: "10.0.0.9", RemotePort: 22}, cloud, strong, weak); label != "" {
		t.Errorf("ssh = %q, want no classification", label)
	}
}

func TestMergeConnections(t *testing.T) {
	cloud := map[string]string{"1.2.3.4": "api.openai.com"}
	strong := map[int]string{11434: "ollama"}
	weak := map[int]string{8080: "llama.cpp/localai"}
	info := func(pid int) procDetail {
		return procDetail{User: "user", Cmdline: "some-cmd", Exe: "/opt/x/some-cmd"}
	}
	noParent := func(int) int { return 0 }

	// A strong endpoint on an unknown process CREATES the disguised-agent observation.
	byPid := map[int]agentObs{}
	mergeConnections(byPid, []connObs{{PID: 7, RemoteIP: "127.0.0.1", RemotePort: 11434}}, cloud, strong, weak, info, noParent)
	if a, ok := byPid[7]; !ok || a.Signature != "llm-client" || a.User != "user" || a.Kind != kindClient {
		t.Fatalf("a strong local endpoint must create an llm-client observation, got %+v", byPid)
	}

	// A WEAK endpoint on an unknown process must NOT — this is the alarm-noise wall.
	byPid = map[int]agentObs{}
	mergeConnections(byPid, []connObs{{PID: 8, RemoteIP: "127.0.0.1", RemotePort: 8080}}, cloud, strong, weak, info, noParent)
	if len(byPid) != 0 {
		t.Fatalf("an ambiguous port must never promote an unknown process, got %+v", byPid)
	}

	// ...but it DOES annotate a process the signature scan already matched.
	byPid = map[int]agentObs{9: {PID: 9, Signature: "aider"}}
	mergeConnections(byPid, []connObs{{PID: 9, RemoteIP: "127.0.0.1", RemotePort: 8080}}, cloud, strong, weak, info, noParent)
	if len(byPid[9].LLMEndpoints) != 1 {
		t.Fatalf("an ambiguous port must annotate a known agent, got %+v", byPid[9])
	}

	// Endpoints de-duplicate across many connections to the same place.
	byPid = map[int]agentObs{9: {PID: 9, Signature: "aider"}}
	mergeConnections(byPid, []connObs{
		{PID: 9, RemoteIP: "1.2.3.4", RemotePort: 443},
		{PID: 9, RemoteIP: "1.2.3.4", RemotePort: 443},
	}, cloud, strong, weak, info, noParent)
	if got := byPid[9].LLMEndpoints; len(got) != 1 || got[0] != "api.openai.com" {
		t.Fatalf("endpoints must de-duplicate, got %v", got)
	}
}

// ── Linux ───────────────────────────────────────────────────────────────────

// Fixture copied from real `ss -tnpH state established` output. Filtering by
// state makes ss OMIT the State column, so the peer is field 3, not field 4 —
// the reason this parser is pinned by a test rather than eyeballed.
func TestParseSSOutput(t *testing.T) {
	out := `0      0      10.0.0.1:54321      1.2.3.4:443    users:(("claude",pid=111,fd=7))
0      0      [fd00::2]:5555      [fd00::1]:11434 users:(("python3",pid=222,fd=9))
0      0      10.0.0.1:1          10.0.0.2:22
0      0      10.0.0.1:2          10.0.0.3:443   users:(("self",pid=999,fd=3))`
	conns := parseSSOutput(out, 999)
	if len(conns) != 2 {
		t.Fatalf("want 2 (no-pid line and self dropped), got %d: %+v", len(conns), conns)
	}
	if conns[0].PID != 111 || conns[0].RemoteIP != "1.2.3.4" || conns[0].RemotePort != 443 {
		t.Errorf("v4 row = %+v", conns[0])
	}
	if conns[1].PID != 222 || conns[1].RemoteIP != "fd00::1" || conns[1].RemotePort != 11434 {
		t.Errorf("v6 row = %+v", conns[1])
	}
}

// ── macOS ───────────────────────────────────────────────────────────────────

func TestParsePSOutput(t *testing.T) {
	out := `  501   400 user            /usr/local/bin/claude --resume
  502     1 root             /usr/bin/node /opt/x/@anthropic-ai/claude-code/cli.js
    1     0 root             /sbin/launchd
 junk`
	users, argvs, parents := parsePSOutput(out)
	if users[501] != "user" || len(argvs[501]) != 2 || argvs[501][0] != "/usr/local/bin/claude" {
		t.Fatalf("pid 501 = %q %v", users[501], argvs[501])
	}
	if parents[501] != 400 || parents[502] != 1 {
		t.Fatalf("parents = %v, want 501->400 and 502->1", parents)
	}
	if sig, ok := matchAgentSignature(argvs[502]); !ok || sig != "claude-code" {
		t.Errorf("interpreter-wrapped agent from ps = (%q,%v)", sig, ok)
	}
	if _, ok := argvs[0]; ok {
		t.Error("a malformed line must not produce a pid")
	}
}

// ── the kernel's executable path (sanitizeExePath, parseProcargs2ExePath) ────

// The rule every platform's procExe answers through: ABSOLUTE OR EMPTY, and
// Linux's " (deleted)" marker stripped.
//
// The deleted case is measured, not assumed: a running binary here read
// "/tmp/x/sleepy" before `rm` and "/tmp/x/sleepy (deleted)" after. Keeping the
// suffix would silently un-mark a running agent the moment its package updated
// in place, which is the shape of control people stop using.
//
// MUTATION: drop the TrimSuffix for " (deleted)".
// RESULT: red — the same running program produced two different identities
// either side of an in-place update.
// MUTATION: return s unchanged instead of "" when !isAbsExePath(s).
// RESULT: red — "claude" (a relative exec) became an identity that any process
// started from any directory could match.
func TestSanitizeExePath(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/usr/local/bin/claude", "/usr/local/bin/claude"},
		{"/tmp/x/sleepy (deleted)", "/tmp/x/sleepy"},
		{`C:\Program Files\Claude\claude.exe`, `C:\Program Files\Claude\claude.exe`},
		{`\\fileserver\tools\claude.exe`, `\\fileserver\tools\claude.exe`},
		{"  /usr/bin/node  ", "/usr/bin/node"},
		// Not identities: they name a file only against a working directory
		// nobody recorded, so two processes started from different places would
		// share one. Dropped to "" — unmarkable, which is the safe direction.
		{"claude", ""},
		{"./bin/claude", ""},
		{"../claude", ""},
		{"", ""},
		{"   ", ""},
		// A relative path that merely LOOKS absolute on the other platform's
		// convention is still relative. binBase (agents_parse.go:18-21) records
		// why filepath.* cannot be used for this.
		{`Program Files\claude.exe`, ""},
		{"C:claude.exe", ""}, // drive-relative: no separator after the colon
	} {
		if got := sanitizeExePath(c.in); got != c.want {
			t.Errorf("sanitizeExePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// A path past any kernel's own limit is REFUSED, not cut down: two
	// executables under one long directory would truncate to the same string
	// and become one identity, which is a collision in the field whose whole
	// job is telling programs apart.
	//
	// MUTATION: `return s[:4096]` instead of "" for an over-long path.
	// RESULT: red — a path this machine could not have produced became an
	// identity, and two of them would have become the same one.
	long := "/" + strings.Repeat("a", 5000)
	if got := sanitizeExePath(long); got != "" {
		t.Errorf("a %d-character path became an identity of %d characters", len(long), len(got))
	}
	if got := sanitizeExePath("/" + strings.Repeat("a", 4095)); got == "" {
		t.Error("a 4096-character path is inside Linux's own PATH_MAX and must be kept")
	}
}

// macOS: the kernel's saved executable path is the first string after argc in a
// KERN_PROCARGS2 blob, and `ps -o comm=` cannot answer this question because it
// SKIPS that string to reach argv[0] (adv_cmds ps/print.c, getproclline).
//
// The fixture is built the way the kernel lays it out: argc, the exec path, the
// NUL padding it is aligned with, then argv[0] — which is given a DIFFERENT
// value on purpose, because reading argv[0] by mistake is the bug this parser
// exists to avoid and a fixture where they matched could not catch it.
//
// MUTATION: return the SECOND string instead of the first (skip past the exec
// path, as ps does).
// RESULT: red — the parser returned /home/user/.local/bin/claude, the forged
// argv[0], instead of the file the kernel loaded.
func TestParseProcargs2ExePath(t *testing.T) {
	blob := func(argc int32, strs ...string) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(argc))
		for i, s := range strs {
			b = append(b, []byte(s)...)
			b = append(b, 0)
			if i == 0 {
				b = append(b, 0, 0, 0) // the kernel pads the exec path for alignment
			}
		}
		return b
	}
	got := parseProcargs2ExePath(blob(2, "/usr/bin/sleep",
		"/home/user/.local/bin/claude", "25"))
	if got != "/usr/bin/sleep" {
		t.Errorf("parseProcargs2ExePath = %q, want the kernel's /usr/bin/sleep — "+
			"argv[0] is the value this must never return", got)
	}
	// The same sanitising as everywhere else: an app bundle path with spaces is
	// kept whole, a relative saved path is not an identity.
	if got := parseProcargs2ExePath(blob(1, "/Applications/My App.app/Contents/MacOS/My App", "x")); got !=
		"/Applications/My App.app/Contents/MacOS/My App" {
		t.Errorf("a path with spaces must survive whole, got %q", got)
	}
	if got := parseProcargs2ExePath(blob(1, "claude", "claude")); got != "" {
		t.Errorf("a relative saved path must not become an identity, got %q", got)
	}
	// Refusals: nothing here may guess past a blob it does not understand. A
	// short read is what a racing exec produces (the kernel then copies out the
	// TAIL of the argument area, not its head — xnu sysctl_procargsx), and
	// parsing that would invent a path out of somebody's environment.
	for _, bad := range [][]byte{
		nil,
		{1, 2, 3},                                // shorter than argc
		{1, 0, 0, 0},                             // argc with nothing after it
		append(blob(1)[:4], []byte("/usr/b")...), // no terminator inside the buffer
		{0xff, 0xff, 0xff, 0xff, '/', 'x', 0},    // negative argc: not this layout
	} {
		if got := parseProcargs2ExePath(bad); got != "" {
			t.Errorf("parseProcargs2ExePath(% x) = %q, want empty", bad, got)
		}
	}
}

func TestParseLsofOutput(t *testing.T) {
	out := `p111
n127.0.0.1:52000->127.0.0.1:11434
n10.0.0.1:52001->1.2.3.4:443
p222
n[::1]:52002->[::1]:1234
p999
n10.0.0.1:1->10.0.0.2:443
pbogus
n10.0.0.1:2->10.0.0.3:443`
	conns := parseLsofOutput(out, 999)
	if len(conns) != 3 {
		t.Fatalf("want 3 (self and bogus-pid blocks dropped), got %d: %+v", len(conns), conns)
	}
	if conns[0].PID != 111 || conns[0].RemotePort != 11434 {
		t.Errorf("row 0 = %+v", conns[0])
	}
	if conns[2].PID != 222 || conns[2].RemoteIP != "::1" || conns[2].RemotePort != 1234 {
		t.Errorf("v6 row = %+v", conns[2])
	}
}

func TestParseEnvTokenSpaced(t *testing.T) {
	out := "node cli.js PATH=/usr/bin PRIVATAE_AGENT_TOKEN=del_xyz HOME=/Users/user"
	if got := parseEnvTokenSpaced(out, "PRIVATAE_AGENT_TOKEN"); got != "del_xyz" {
		t.Errorf("= %q, want del_xyz", got)
	}
	if got := parseEnvTokenSpaced("node cli.js PATH=/usr/bin", "PRIVATAE_AGENT_TOKEN"); got != "" {
		t.Errorf("(absent) = %q, want empty", got)
	}
}

// ── Windows ─────────────────────────────────────────────────────────────────
//
// The Win32 calls cannot run here, but every byte layout they produce can be
// built and decoded — which is the whole reason the parsers live outside the
// build-tagged file.

func winRow4(state uint32, remoteIP [4]byte, remotePort uint16, pid uint32) []byte {
	row := make([]byte, winTCPRow4Size)
	binary.LittleEndian.PutUint32(row[0:4], state)
	copy(row[12:16], remoteIP[:])
	binary.BigEndian.PutUint16(row[16:18], remotePort) // network order, low 16 bits
	binary.LittleEndian.PutUint32(row[20:24], pid)
	return row
}

func winRow6(state uint32, remoteIP [16]byte, remotePort uint16, pid uint32) []byte {
	row := make([]byte, winTCPRow6Size)
	copy(row[24:40], remoteIP[:])
	binary.BigEndian.PutUint16(row[44:46], remotePort)
	binary.LittleEndian.PutUint32(row[48:52], state)
	binary.LittleEndian.PutUint32(row[52:56], pid)
	return row
}

func winTable(rows ...[]byte) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(rows)))
	for _, r := range rows {
		buf = append(buf, r...)
	}
	return buf
}

func TestParseTCPTableV4(t *testing.T) {
	buf := winTable(
		winRow4(winTCPStateEst, [4]byte{1, 2, 3, 4}, 443, 111),
		winRow4(2 /* SYN_SENT */, [4]byte{5, 6, 7, 8}, 443, 222), // not established
		winRow4(winTCPStateEst, [4]byte{127, 0, 0, 1}, 11434, 333),
		winRow4(winTCPStateEst, [4]byte{9, 9, 9, 9}, 443, 999), // self
	)
	conns := parseTCPTable(buf, false, 999)
	if len(conns) != 2 {
		t.Fatalf("want 2 (non-established and self dropped), got %d: %+v", len(conns), conns)
	}
	if conns[0].PID != 111 || conns[0].RemoteIP != "1.2.3.4" || conns[0].RemotePort != 443 {
		t.Errorf("row 0 = %+v", conns[0])
	}
	if conns[1].PID != 333 || conns[1].RemoteIP != "127.0.0.1" || conns[1].RemotePort != 11434 {
		t.Errorf("row 1 = %+v", conns[1])
	}
}

func TestParseTCPTableV6(t *testing.T) {
	var loop [16]byte
	loop[15] = 1 // ::1
	buf := winTable(winRow6(winTCPStateEst, loop, 1234, 444))
	conns := parseTCPTable(buf, true, 1)
	if len(conns) != 1 {
		t.Fatalf("want 1, got %d: %+v", len(conns), conns)
	}
	if conns[0].PID != 444 || conns[0].RemoteIP != "::1" || conns[0].RemotePort != 1234 {
		t.Errorf("v6 row = %+v", conns[0])
	}
}

func TestParseTCPTableTruncated(t *testing.T) {
	// A table claiming more rows than the buffer holds must stop, not panic.
	buf := make([]byte, 4+winTCPRow4Size)
	binary.LittleEndian.PutUint32(buf[0:4], 50)
	binary.LittleEndian.PutUint32(buf[4:8], winTCPStateEst)
	binary.LittleEndian.PutUint32(buf[24:28], 7)
	if got := parseTCPTable(buf, false, 1); len(got) > 1 {
		t.Fatalf("truncated table must stop at the buffer end, got %d rows", len(got))
	}
	if got := parseTCPTable(nil, false, 1); len(got) != 0 {
		t.Fatalf("nil buffer = %d rows, want 0", len(got))
	}
	if got := parseTCPTable([]byte{1, 2}, true, 1); len(got) != 0 {
		t.Fatalf("short buffer = %d rows, want 0", len(got))
	}
}

func utf16le(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func TestParseWinEnvBlock(t *testing.T) {
	var blk []byte
	for _, e := range []string{`PATH=C:\Windows`, "PRIVATAE_AGENT_TOKEN=del_win1", `HOME=C:\Users\a`} {
		blk = append(blk, utf16le(e)...)
		blk = append(blk, 0, 0)
	}
	blk = append(blk, 0, 0) // terminating empty entry
	if got := parseWinEnvBlock(blk, "PRIVATAE_AGENT_TOKEN"); got != "del_win1" {
		t.Errorf("= %q, want del_win1", got)
	}
	// Windows environment names are case-insensitive.
	var lower []byte
	lower = append(lower, utf16le("privatae_agent_token=del_win2")...)
	lower = append(lower, 0, 0, 0, 0)
	if got := parseWinEnvBlock(lower, "PRIVATAE_AGENT_TOKEN"); got != "del_win2" {
		t.Errorf("case-insensitive lookup = %q, want del_win2", got)
	}
	// A block truncated by the bounded read must not loop or panic.
	if got := parseWinEnvBlock(utf16le(`PATH=C:\Windows`), "PRIVATAE_AGENT_TOKEN"); got != "" {
		t.Errorf("truncated block = %q, want empty", got)
	}
	if got := parseWinEnvBlock(nil, "PRIVATAE_AGENT_TOKEN"); got != "" {
		t.Errorf("nil block = %q, want empty", got)
	}
}

// ── the bastion must not report its own local agent as an unsanctioned agent ──

func TestFaOwnChildExclusion(t *testing.T) {
	if faIsOwnChild(4242) {
		t.Fatal("an untracked pid must not read as our own child")
	}
	faTrackPID(4242)
	if !faIsOwnChild(4242) {
		t.Fatal("a tracked local agent child must be excluded from the observe plane")
	}
	faUntrackPID(4242)
	if faIsOwnChild(4242) {
		t.Fatal("an exited child must stop being excluded — its pid gets reused")
	}
	faTrackPID(0)
	if faIsOwnChild(0) {
		t.Fatal("pid 0 is not a child")
	}
}

// TestScanAgentsLive exercises the REAL enumerators on the machine running the
// tests. Guarded like the local agent end-to-end test: it asserts nothing about
// what it finds (a quiet box is a valid result) — it proves the platform path
// executes and returns coherent records. PRIVATAE_OBSERVE_LIVE=1 to run.
func TestScanAgentsLive(t *testing.T) {
	if os.Getenv("PRIVATAE_OBSERVE_LIVE") != "1" {
		t.Skip("set PRIVATAE_OBSERVE_LIVE=1 to scan this machine")
	}
	if !agentScanSupported {
		t.Skipf("no observe-plane enumerator for this platform (%s)", agentScanKind)
	}
	agents, err := scanAgents()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("scan kind=%s observed=%d", agentScanKind, len(agents))
	for _, a := range agents {
		if a.PID <= 0 || a.Signature == "" {
			t.Errorf("incoherent observation: %+v", a)
		}
		t.Logf("  pid=%-8d sig=%-14s user=%-10s endpoints=%v cmd=%.60s",
			a.PID, a.Signature, a.User, a.LLMEndpoints, a.Cmdline)
	}
}

// ── review follow-ups ───────────────────────────────────────────────────────

func TestIsLocalScope(t *testing.T) {
	local := []string{"127.0.0.1", "::1", "192.168.1.50", "10.0.0.9", "172.16.0.1",
		"fd00::1", "fe80::1", "100.64.0.9"} // incl. the mesh's own CGNAT range
	for _, ip := range local {
		if !isLocalScope(ip) {
			t.Errorf("isLocalScope(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{"1.2.3.4", "8.8.8.8", "2606:4700::1", "", "garbage"} {
		if isLocalScope(ip) {
			t.Errorf("isLocalScope(%q) = true, want false", ip)
		}
	}
}

// A model served from a PUBLIC address is still self-hosted inference — the
// behaviour is deliberate — but labelling it "local:" reads as a lie.
func TestClassifyConnNamesNonLocalByAddress(t *testing.T) {
	strong := map[int]string{11434: "ollama"}
	weak := map[int]string{8080: "llama.cpp/localai"}
	cloud := map[string]string{}

	if label, alone := classifyConn(connObs{RemoteIP: "192.168.1.50", RemotePort: 11434}, cloud, strong, weak); label != "local:11434 (ollama)" || !alone {
		t.Errorf("LAN = (%q,%v), want (local:11434 (ollama),true)", label, alone)
	}
	if label, alone := classifyConn(connObs{RemoteIP: "203.0.113.7", RemotePort: 11434}, cloud, strong, weak); label != "203.0.113.7:11434 (ollama)" || !alone {
		t.Errorf("public = (%q,%v), want (203.0.113.7:11434 (ollama),true)", label, alone)
	}
	// The two facts stay independent: address class in the prefix, port
	// confidence in the "?" suffix.
	if label, alone := classifyConn(connObs{RemoteIP: "203.0.113.7", RemotePort: 8080}, cloud, strong, weak); label != "203.0.113.7:8080 (llama.cpp/localai?)" || alone {
		t.Errorf("public ambiguous = (%q,%v)", label, alone)
	}
	if label, _ := classifyConn(connObs{RemoteIP: "127.0.0.1", RemotePort: 8080}, cloud, strong, weak); label != "local:8080 (llama.cpp/localai?)" {
		t.Errorf("loopback ambiguous = %q", label)
	}
}

// The contain guard must ask the same question the heartbeat answers, on every
// platform — it was /proc-only (inert on Windows and macOS) and
// signature-only (an observed llm-client could never be contained).
func TestObservedAgentPIDsCoversEveryObservation(t *testing.T) {
	prev := observedAgents
	defer func() { observedAgents = prev }()

	observedAgents = func() ([]agentObs, error) {
		return []agentObs{
			{PID: 101, Signature: "claude-code"},
			// caught by the NETWORK signal only — no process signature at all
			{PID: 202, Signature: "llm-client", LLMEndpoints: []string{"local:11434 (ollama)"}},
		}, nil
	}
	got := observedAgentMap()
	if _, ok := got[101]; !ok {
		t.Error("a signature-matched agent must be containable")
	}
	if _, ok := got[202]; !ok {
		t.Error("an llm-client must be containable — it is exactly what the network signal exists to catch")
	}
	if _, ok := got[303]; ok {
		t.Error("a pid that was never observed must NEVER be containable")
	}

	// A platform with no enumerator contains nothing: a box that cannot see
	// must not kill on the host's belief.
	observedAgents = func() ([]agentObs, error) { return nil, nil }
	if len(observedAgentMap()) != 0 {
		t.Error("a blind box must contain nothing")
	}
}

func TestMaybeContainRefusesUnobserved(t *testing.T) {
	prev := observedAgents
	defer func() { observedAgents = prev }()
	observedAgents = func() ([]agentObs, error) { return []agentObs{{PID: 101, Signature: "claude-code"}}, nil }

	// Nothing here may kill: pid 1, our own pid, and an unobserved pid are all
	// refused. If the guard regressed, this test would terminate the test run.
	self := os.Getpid()
	body := []byte(`{"contain":[1,` + itoa(self) + `,303]}`)
	maybeContain("", "", body) // must return without killing anything
	maybeContain("", "", []byte(`{}`))
	maybeContain("", "", []byte(`not json`))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A walk that did not happen must not travel as an empty list. The host reads
// `agents: []` from a box advertising agent-observe as "looked and found
// nothing" — which marks a containment the user ordered as done — so a failed
// enumeration withholds the key and the host holds the order.
func TestTheBeatWithholdsAgentsWhenTheWalkFails(t *testing.T) {
	t.Setenv("OLLAMA_ADDR", "127.0.0.1:1")
	prev := scanProcessesFn
	t.Cleanup(func() { scanProcessesFn = prev })
	beat := func() map[string]any {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal([]byte(buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	scanProcessesFn = func() (map[int]agentObs, error) { return nil, errors.New("read /proc: permission denied") }
	m := beat()
	if v, present := m["agents"]; present {
		t.Fatalf("a failed walk travelled as %v — the host reads that as 'looked, nothing there'", v)
	}
	if _, present := m["agent_scan_ok"]; present {
		t.Fatal("a failed walk must not claim the walk happened")
	}
	if _, present := m["agent_scan"]; !present {
		t.Fatal("the enumerator kind must still travel: the failure is this beat's, not the platform's")
	}

	// The same box, the walk working: the key travels, as a list. (Not
	// asserted empty — the connection scan is a second enumerator and on a
	// live box it still finds model clients when the process map is empty.)
	// Absent and present are the two answers, and they must stay two.
	scanProcessesFn = func() (map[int]agentObs, error) { return map[int]agentObs{}, nil }
	m = beat()
	if _, ok := m["agents"].([]any); !ok {
		t.Fatalf("a walk that happened must travel as a list, got %T %v", m["agents"], m["agents"])
	}
	// ...and says so: the host clears a containment only on a beat that
	// carries this, so a box that cannot say it (an older build) holds.
	if v, _ := m["agent_scan_ok"].(bool); !v {
		t.Fatalf("a walk that happened must travel with agent_scan_ok=true, got %v", m["agent_scan_ok"])
	}
}

// observedAgents — what the kill guard, the sanction page and the policy
// census consult — reads a failed walk as nothing observed: a box that cannot
// see must not kill on belief.
func TestAFailedWalkObservesNothingForTheGuard(t *testing.T) {
	prev := scanProcessesFn
	t.Cleanup(func() { scanProcessesFn = prev })
	scanProcessesFn = func() (map[int]agentObs, error) { return nil, errors.New("boom") }
	got, err := observedAgents()
	if err == nil || len(got) != 0 {
		t.Fatalf("a failed walk observed %v with err=%v — the seam must hand the error on", got, err)
	}
	if got := observedAgentMap(); len(got) != 0 {
		t.Fatalf("the guard's map was %v after a failed walk", got)
	}
	// The error wins over anything that came back beside it: a seam stub (or
	// a future enumerator) handing a partial list WITH an error must not have
	// that list believed by the thing that kills.
	prevObs := observedAgents
	t.Cleanup(func() { observedAgents = prevObs })
	observedAgents = func() ([]agentObs, error) {
		return []agentObs{{PID: 4242, Kind: kindAgent, Signature: "claude-code"}}, errors.New("partial walk")
	}
	if got := observedAgentMap(); len(got) != 0 {
		t.Fatalf("a list that came with an error was believed by the guard: %v", got)
	}
}
