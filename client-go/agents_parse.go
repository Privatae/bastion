package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// Pure parsers and classifiers for the observe plane — NO build tag, on
// purpose. Every platform's enumeration output is decoded here, so the Linux
// box that runs the tests exercises the macOS and Windows paths too. The
// platform files (agents_<goos>.go) are left holding only the calls that
// genuinely cannot run anywhere else: reading /proc, spawning ps/lsof/ss, and
// the Win32 syscalls. Those are a handful of lines each; everything with a
// decision or an offset in it lives in this file, under test.

// binBase is filepath.Base for BOTH separator conventions, lowercased, with a
// ".exe" suffix dropped. Deliberately not filepath.Base: that function follows
// the separator of the machine it RUNS on, so a Windows argv would keep its
// whole path when the same rule is exercised from a Linux test run.
func binBase(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSuffix(s, ".exe")
}

// matchAgentSignature: argv[0] basename exact-match, OR (only for an interpreter) a distinctive
// script-path substring. The interpreter gate kills the "merely mentions the marker" false positive.
func matchAgentSignature(argv []string) (string, bool) {
	sig, auto, ok := matchSignature(argv)
	if !ok || auto {
		return "", false
	}
	return sig, true
}

// matchSignature is matchAgentSignature over BOTH tables: the agent tables
// first (an agent that also drives a browser is an agent), then the
// automation tables. `automation` reports which table answered.
func matchSignature(argv []string) (sig string, automation bool, ok bool) {
	if len(argv) == 0 {
		return "", false, false
	}
	base := binBase(argv[0])
	if sig, ok := agentBinaries[base]; ok {
		return sig, false, true
	}
	if sig, ok := automationBinaries[base]; ok {
		return sig, true, true
	}
	if interpreters[base] {
		full := strings.ToLower(strings.Join(argv, " "))
		for _, s := range agentSubstrings {
			if strings.Contains(full, s.Sub) {
				return s.Sig, false, true
			}
		}
		for _, s := range automationSubstrings {
			if strings.Contains(full, s.Sub) {
				return s.Sig, true, true
			}
		}
	}
	return "", false, false
}

// ── Kind: agent, app, or client ─────────────────────────────────────────────
//
// The signature tables answer "which product is this binary". They cannot
// answer "is this an agent", because the same binary name serves two products:
// `claude.exe` is Claude Code (an agent) AND the Claude desktop app (a chat
// window). The desktop app is Electron, and Electron — like every Chromium
// host — runs its renderer, GPU, network and utility work in child processes
// launched from the SAME executable with a `--type=<role>` flag. One open app
// therefore matched the agent table nine times, and eight of those were not
// even the app: they were its helpers.
//
// Two rules, both measured on the box that produced the false alarm:
//
//	helper  — a `--type=` process WHOSE PARENT RUNS THE SAME PROGRAM (same
//	          executable, or the same .app bundle on macOS). The flag alone
//	          is not enough: an agent whose prompt text mentions "--type=json"
//	          must stay an agent, and "add --type=x to your argv" must never be
//	          a way to vanish from the report. A helper is dropped and its
//	          parent remembered.
//	app     — a matched process that owns helpers, or whose EXECUTABLE lives
//	          inside a macOS .app bundle, is an APP: the user is running it. It
//	          stays visible (what it talks to matters) but it is not an agent.
//
// Everything else the tables matched is an agent. A process caught by the
// network signal alone is a client — unless the socket belongs to a helper,
// in which case the APP that owns the helper is what talks to the model.

const (
	kindAgent  = "agent"
	kindApp    = "app"
	kindClient = "client"
	// automation: drives the machine with no model of its own —
	// a browser driver, an input injector, an RPA runtime. Inventory, never
	// an alert. Model traffic promotes it to an agent (mergeConnections).
	kindAutomation = "automation"
)

// appSignatures renames a product signature when the process turns out to be
// the interactive app rather than the agent, so the host never says
// "claude-code" about a chat window. Unlisted products keep their name with an
// "-app" suffix.
var appSignatures = map[string]string{
	"claude-code": "claude-desktop",
}

func appSignature(sig string) string {
	if s, ok := appSignatures[sig]; ok {
		return s
	}
	return sig + "-app"
}

// argv0 is the program a command line starts with: the first token, honouring
// a quoted Windows path ("C:\Program Files\...\claude.exe" --type=renderer).
func argv0(cmdline string) string {
	s := strings.TrimSpace(cmdline)
	if s == "" {
		return ""
	}
	if s[0] == '"' || s[0] == '\'' {
		if end := strings.IndexByte(s[1:], s[0]); end >= 0 {
			return s[1 : end+1]
		}
		return s[1:]
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// ── the kernel's executable path ────────────────────────────────────────────
//
// Every platform answers procExe() through sanitizeExePath, so ONE rule decides
// what counts as an executable path and it is tested from any OS.
//
// ABSOLUTE OR EMPTY. A relative path ("claude", "./bin/claude") names a file
// only against a working directory nobody recorded, so it is not an identity —
// two processes started from different directories would share it. macOS is
// where this actually bites: the kernel saves the path as it was PASSED to
// execve (xnu bsd/kern/kern_exec.c exec_save_path, which copyinstr's the
// caller's string before namei resolves it), so a relative exec produces a
// relative saved path. Linux (readlink /proc/pid/exe) and Windows
// (QueryFullProcessImageName) always answer absolute.
//
// Dropping it yields "" — an observation that cannot be marked as yours — which
// is the safe direction: a mark that names nothing checkable is worse than no
// mark (sanction.go, agentSanction).
func sanitizeExePath(s string) string {
	s = strings.TrimSpace(s)
	// Linux appends " (deleted)" once the file has been unlinked — measured on
	// this box: a running binary read "/tmp/x/sleepy" before `rm` and
	// "/tmp/x/sleepy (deleted)" after. STRIPPED, exactly as origin_linux.go:85
	// already does, because the alternative silently un-marks a running agent
	// the moment its package updates in place, and a mark the user has to
	// re-apply after every update is a control they stop using (sanction.go,
	// STORAGE). It concedes nothing an attacker did not already have: writing a
	// file called "claude (deleted)" into that directory needs the same write
	// access as overwriting `claude` itself.
	s = strings.TrimSuffix(s, " (deleted)")
	if !isAbsExePath(s) {
		return ""
	}
	// REFUSED, NEVER TRUNCATED, past a bound no real path reaches. Truncation is
	// not available to this function whatever the length: two different
	// executables under one long directory would cut down to the SAME string and
	// therefore to the same identity, which is a collision in the one field that
	// is supposed to tell programs apart. So an absurd path becomes "" —
	// unmarkable, the safe direction — and this field cannot be used to inflate
	// the heartbeat it travels on (agents.go, agentObs.Exe).
	//
	// 4096 is Linux's PATH_MAX, the largest of the three kernels' own limits
	// (macOS is 1024; Windows' extended form goes further but nothing a person
	// installs lives out there). It admits every real path and bounds the field.
	if len(s) > 4096 {
		return ""
	}
	return s
}

// isAbsExePath answers for BOTH path conventions, deliberately not
// filepath.IsAbs: that function follows the separator of the machine it RUNS
// on, so a Windows path would read as relative under the Linux test run that
// exercises this file — the same trap binBase() (agents_parse.go:18-21) is
// written to avoid.
func isAbsExePath(s string) bool {
	switch {
	case s == "":
		return false
	case s[0] == '/':
		return true // POSIX, and the \Device\... form never reaches here
	case strings.HasPrefix(s, `\\`):
		return true // UNC: \\server\share\thing.exe
	case len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') &&
		((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')):
		return true // C:\thing.exe
	}
	return false
}

// parseProcargs2ExePath pulls the kernel's saved executable path out of a macOS
// KERN_PROCARGS2 blob. Lives here, with a fixture, because it is a byte layout
// and the Linux box that runs the tests must exercise it (this file's header).
//
// The layout, from Apple's own two sources rather than from a blog: the kernel
// writes argc as the first word and the executable path as the first string
// after it (xnu bsd/kern/kern_sysctl.c sysctl_procargsx, which stores the path
// prefixed with "executable_path=" and strips that prefix back off on the way
// out), and Apple's ps walks the same blob by SKIPPING that string to reach
// argv[0] — "/* Skip the saved exec_path. */" in adv_cmds ps/print.c,
// getproclline. Only that prefix is decoded here; argv and the environment
// follow and are none of this function's business.
//
// WHY THE PATH AND NOT `ps -o comm=`: because comm on macOS is argv[0]. The
// same getproclline is what backs the `comm` keyword (ps/keyword.c maps it to
// just_command), so it reports the string the launcher chose, which is the
// exact value this whole change exists to stop trusting. origin_darwin.go's
// header and origin.go's procFacts.Exe both used to say the opposite;
// both now say what it is.
func parseProcargs2ExePath(buf []byte) string {
	if len(buf) < 5 {
		return ""
	}
	// argc rides in the first word, native endian — and both machines macOS
	// runs on (amd64, arm64) are little-endian.
	if argc := int32(binary.LittleEndian.Uint32(buf[:4])); argc < 0 {
		return "" // not a blob this function understands; never guess past it
	}
	rest := buf[4:]
	end := 0
	for end < len(rest) && rest[end] != 0 {
		end++
	}
	if end == len(rest) {
		return "" // no terminator inside the buffer: a truncated read, not a path
	}
	return sanitizeExePath(string(rest[:end]))
}

// bundleRoot is the OUTERMOST macOS .app a path sits in, lowercased, or "".
// "Google Chrome Helper.app" lives inside "Google Chrome.app/Contents/..."; the
// outermost bundle is what makes a helper and its app the same program.
func bundleRoot(path string) string {
	p := strings.ToLower(path)
	i := strings.Index(p, ".app/")
	if i < 0 {
		return ""
	}
	return p[:i+5]
}

// isAppBundle: the EXECUTABLE (argv[0], never an argument) lives inside a
// macOS application bundle.
func isAppBundle(cmdline string) bool {
	return bundleRoot(argv0(cmdline)) != ""
}

// hasTypeFlag: the raw Chromium marker. Necessary for a helper, never
// sufficient — see isGUIHelper.
func hasTypeFlag(cmdline string) bool {
	return strings.Contains(strings.ToLower(cmdline), " --type=")
}

// sameProgram: child and parent run the same executable, or live in the same
// .app bundle. This is what makes a `--type=` process a helper rather than an
// agent that happens to mention the flag.
func sameProgram(childCmd, parentCmd string) bool {
	c, p := argv0(childCmd), argv0(parentCmd)
	if c == "" || p == "" {
		return false
	}
	if binBase(c) == binBase(p) {
		return true
	}
	if r := bundleRoot(c); r != "" && r == bundleRoot(p) {
		return true
	}
	return false
}

// isGUIHelper: a `--type=` process whose parent runs the same program.
func isGUIHelper(cmdline, parentCmdline string) bool {
	return hasTypeFlag(cmdline) && sameProgram(cmdline, parentCmdline)
}

// maxHelperHops bounds the walk from a helper up to its app. Chromium nests
// at most a few levels (browser → zygote → renderer); a chain longer than
// this is a corrupt parent map, and the walk stops rather than loops.
const maxHelperHops = 8

// classifyObservations applies the kind rules to a process snapshot IN PLACE:
// helpers are removed, every survivor gets a kind and a parent, and an app's
// signature is renamed. Returns helper pid -> the app pid that owns it, so the
// caller can re-attribute the helpers' connections.
//
// A helper's parent must itself be in the snapshot: helpers run the same
// executable as their app, so if the app matched the tables, so did they, and
// if the parent is NOT a candidate the child is not its helper (an agent under
// a shell). A helper whose parent cannot be read is kept as an agent — reported
// rather than silently dropped, and never pinned to pid 0.
func classifyObservations(byPid map[int]agentObs, parent func(int) int) map[int]int {
	cmdOf := func(a agentObs) string {
		if a.raw != "" {
			return a.raw
		}
		return a.Cmdline
	}
	helper := map[int]bool{}
	for pid, a := range byPid {
		pp := parent(pid)
		if pp <= 1 {
			continue
		}
		pa, ok := byPid[pp]
		if !ok {
			continue
		}
		if isGUIHelper(cmdOf(a), cmdOf(pa)) {
			helper[pid] = true
		}
	}
	helperRoot := map[int]int{}
	for pid := range helper {
		root := parent(pid)
		for hops := 0; helper[root] && hops < maxHelperHops; hops++ {
			root = parent(root) // the zygote pattern: a helper spawned by a helper
		}
		if root <= 1 || helper[root] {
			continue // unresolvable: leave it reported as what it matched
		}
		if _, ok := byPid[root]; !ok {
			continue
		}
		helperRoot[pid] = root
		delete(byPid, pid)
	}
	ownsHelpers := map[int]bool{}
	for _, root := range helperRoot {
		ownsHelpers[root] = true
	}
	for pid, a := range byPid {
		a.PPID = parent(pid)
		if ownsHelpers[pid] || isAppBundle(cmdOf(a)) {
			a.Kind = kindApp
			a.Signature = appSignature(a.Signature)
		} else if a.automation {
			a.Kind = kindAutomation
		} else {
			a.Kind = kindAgent
		}
		byPid[pid] = a
	}
	return helperRoot
}

// descendantsOf walks a pid -> parent map and returns every process below
// root (children, grandchildren, ...), root excluded. Contain uses it so an
// agent's shells and sub-processes go with it instead of being orphaned. A
// cycle in a corrupt map terminates because each pid is visited once.
func descendantsOf(parents map[int]int, root int) []int {
	children := map[int][]int{}
	for pid, pp := range parents {
		if pp > 0 && pid != pp {
			children[pp] = append(children[pp], pid)
		}
	}
	seen := map[int]bool{root: true}
	out := []int{}
	queue := []int{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[cur] {
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
			queue = append(queue, c)
		}
	}
	return out
}

// parseProcStatPPID pulls the parent pid out of /proc/<pid>/stat. The comm
// field is parenthesised and may itself contain spaces or parens, so the
// fields are counted from the LAST ')' — state is next, then ppid.
func parseProcStatPPID(stat string) int {
	i := strings.LastIndex(stat, ")")
	if i < 0 {
		return 0
	}
	f := strings.Fields(stat[i+1:])
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.Atoi(f[1])
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// parseProcStatStartTicks pulls the process start time out of /proc/<pid>/stat.
// Same technique as parseProcStatPPID and for the same reason — the comm field
// is parenthesised and may itself contain spaces or parens, so the fields are
// counted from the LAST ')'.
//
// starttime is field 22 of the whole line; the first field after ')' is field 3,
// so it sits at index 19 of that slice. It counts clock ticks since boot, which
// is what the delta's short-lived rule turns into an age (delta_linux.go).
//
// Here rather than in the Linux file, with no build tag, for the reason the top
// of this file gives: one `go test` on any OS covers the byte layout, and a
// parser only a Linux box can run is a parser only a Linux box checks.
func parseProcStatStartTicks(stat string) (uint64, bool) {
	i := strings.LastIndex(stat, ")")
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(stat[i+1:])
	if len(f) < 20 {
		return 0, false
	}
	n, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// splitHostPortLoose parses the "address:port" forms the platform enumerators
// hand back — `1.2.3.4:443`, `[fd00::1]:443`, `[::1]:11434` — into a bare IP
// and a numeric port. Brackets are stripped so a v6 literal compares equal to
// the same address from a DNS lookup.
func splitHostPortLoose(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		i := strings.LastIndex(s, ":")
		if i < 0 {
			return "", 0, false
		}
		host, port = s[:i], s[i+1:]
	}
	host = strings.Trim(host, "[]")
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 || host == "" {
		return "", 0, false
	}
	return host, n, true
}

// portOfAddr pulls the port out of a "host:port" env value (OLLAMA_ADDR,
// PRIVATAE_LLM_ADDR). A bare host, a bare port, or junk yields 0 — never a guess.
func portOfAddr(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0
	}
	addr = strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://")
	if i := strings.IndexAny(addr, "/?"); i >= 0 {
		addr = addr[:i]
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}

// isLocalScope reports whether an address is on the user's own side of the
// internet: loopback, RFC1918 / ULA, link-local, or CGNAT (100.64/10, which the
// mesh itself uses and net.IP.IsPrivate does not cover).
func isLocalScope(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

// classifyConn names the inference endpoint a connection is talking to, and
// says whether that alone is enough to call an unknown process an agent.
// Returns ("", false) when the connection is not inference traffic.
//
// The label carries two INDEPENDENT facts, so neither one overstates:
//
//	prefix  address class — "local:" only when the peer really is on the
//	        user's own side (loopback/LAN/mesh). A model served from a public
//	        address is still self-hosted inference, but calling it "local"
//	        reads as a lie, so it is named by its address instead.
//	suffix  port confidence — a trailing "?" marks an ambiguous port that only
//	        corroborates and never promotes an unknown process.
func classifyConn(c connObs, cloud map[string]string, strong, weak map[int]string) (string, bool) {
	if host, ok := cloud[c.RemoteIP]; ok {
		return host, true
	}
	where := c.RemoteIP
	if isLocalScope(c.RemoteIP) {
		where = "local"
	}
	if name, ok := strong[c.RemotePort]; ok {
		return where + ":" + strconv.Itoa(c.RemotePort) + " (" + name + ")", true
	}
	if name, ok := weak[c.RemotePort]; ok {
		return where + ":" + strconv.Itoa(c.RemotePort) + " (" + name + "?)", false
	}
	return "", false
}

// procDetail is what the per-pid lookups answer for a process the signature
// scan never matched. A STRUCT rather than the tuple this used to be
// (user, cmdline, token), because the field added to it is the one field that
// must never be confused with the command line: a positional fourth string is
// one transposition away from writing argv[0] into Exe, which is the forgery
// sanction.go exists to stop. The compiler now refuses that mistake.
type procDetail struct {
	User    string
	Cmdline string
	Token   string
	// Exe is the KERNEL's executable path for the pid, or "" — see agentObs.Exe.
	Exe string
}

// mergeConnections folds the network signal into the process snapshot: an
// endpoint annotates the agent (or app) that owns the connection, and a
// STRONG endpoint on a process the signature scan missed becomes an
// "llm-client" observation — the disguised case the network signal exists to
// catch. A weak (ambiguous port) endpoint never creates an observation on its
// own.
//
// GUI helpers: a socket held by a Chromium/Electron helper is the
// APP's socket. A connection already re-attributed by the caller (ViaHelper)
// annotates the app; an unknown `--type=` process found here is a helper only
// if its parent runs the same program, and is then attributed up the chain to
// the app. A process that merely mentions the flag is an ordinary client.
func mergeConnections(byPid map[int]agentObs, conns []connObs, cloud map[string]string,
	strong, weak map[int]string, info func(int) procDetail, parent func(int) int) {
	annotate := func(pid int, label string, alone bool) bool {
		a, ok := byPid[pid]
		if !ok {
			return false
		}
		if !containsStr(a.LLMEndpoints, label) {
			a.LLMEndpoints = append(a.LLMEndpoints, label)
		}
		// An automation that talks to a model is an agent: the browser
		// driver was the hands, the model is the head. Only a strong
		// endpoint promotes — an ambiguous port annotates, as everywhere.
		if a.Kind == kindAutomation && alone {
			a.Kind = kindAgent
		}
		byPid[pid] = a
		return true
	}
	for _, c := range conns {
		label, alone := classifyConn(c, cloud, strong, weak)
		if label == "" {
			continue
		}
		if annotate(c.PID, label, alone) {
			continue
		}
		if !alone {
			continue
		}
		if c.ViaHelper {
			continue // the caller only rewrites to a root it kept, so this is unreachable; never invent one
		}
		d := info(c.PID)
		user, cmdline, token, exe := d.User, d.Cmdline, d.Token, d.Exe
		target, kind, sig := c.PID, kindClient, "llm-client"
		if hasTypeFlag(cmdline) {
			// Walk up while the parent runs the same program and is itself a
			// helper; the first same-program non-helper is the app.
			cur, curCmd := c.PID, cmdline
			resolved := false
			for hops := 0; hops < maxHelperHops; hops++ {
				root := parent(cur)
				if root <= 1 {
					break
				}
				rd := info(root)
				if !isGUIHelper(curCmd, rd.Cmdline) {
					break // not the same program: cur is what it is
				}
				if annotate(root, label, alone) {
					resolved = true
					break
				}
				if !hasTypeFlag(rd.Cmdline) {
					// The APP is now the observation, so its OWN exe travels
					// with it. Keeping the helper's would key a mark on a file
					// that is not the program the row names.
					target, user, cmdline, token, exe = root, rd.User, rd.Cmdline, rd.Token, rd.Exe
					kind, sig = kindApp, "gui-app"
					resolved = true
					break
				}
				cur, curCmd = root, rd.Cmdline
			}
			if resolved && target == c.PID {
				continue // annotated an existing observation up the chain
			}
			if !resolved && hasTypeFlag(cmdline) && target == c.PID {
				// A `--type=` process with no same-program parent (an agent
				// mentioning the flag, or an unreadable parent): a client.
				kind, sig = kindClient, "llm-client"
			}
		}
		byPid[target] = agentObs{
			PID: target, PPID: parent(target), Kind: kind, User: user, Signature: sig,
			Cmdline: cmdline, Exe: exe, LLMEndpoints: []string{label}, DelegationToken: token,
		}
	}
}

// ── Linux: `ss -tnpH state established` ─────────────────────────────────────

// pidFromSSLine extracts the pid from an ss process column: users:(("comm",pid=N,fd=M)).
func pidFromSSLine(line string) int {
	i := strings.Index(line, "pid=")
	if i < 0 {
		return 0
	}
	rest := line[i+4:]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	pid, _ := strconv.Atoi(rest[:j])
	return pid
}

// parseSSOutput turns `ss -tnpH state established` into connections. Column 4
// is the peer address; the pid rides in the users:(...) column.
func parseSSOutput(out string, self int) []connObs {
	conns := []connObs{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		ip, port, ok := splitHostPortLoose(f[3])
		if !ok {
			continue
		}
		pid := pidFromSSLine(line)
		if pid > 0 && pid != self {
			conns = append(conns, connObs{PID: pid, RemoteIP: ip, RemotePort: port})
		}
	}
	return conns
}

// ── macOS: `ps` and `lsof` ──────────────────────────────────────────────────

// parsePSOutput turns `ps -axo pid=,ppid=,user=,args=` into per-pid parent,
// user and argv.
func parsePSOutput(out string) (map[int]string, map[int][]string, map[int]int) {
	users := map[int]string{}
	argvs := map[int][]string{}
	parents := map[int]int{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || pid <= 0 {
			continue
		}
		ppid, err := strconv.Atoi(f[1])
		if err != nil || ppid < 0 {
			continue
		}
		parents[pid] = ppid
		users[pid] = f[2]
		argvs[pid] = f[3:]
	}
	return users, argvs, parents
}

// parseLsofOutput reads lsof's machine-readable field output (-Fpn): a `p<pid>`
// line opens a process block, and each following `n<local>-><remote>` line is
// one of its connections.
func parseLsofOutput(out string, self int) []connObs {
	conns := []connObs{}
	pid := 0
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
			if err != nil {
				pid = 0
				continue
			}
			pid = n
		case 'n':
			if pid <= 0 || pid == self {
				continue
			}
			i := strings.Index(line, "->")
			if i < 0 {
				continue
			}
			ip, port, ok := splitHostPortLoose(line[i+2:])
			if !ok {
				continue
			}
			conns = append(conns, connObs{PID: pid, RemoteIP: ip, RemotePort: port})
		}
	}
	return conns
}

// parseEnvTokenSpaced pulls one variable out of `ps -E` output, where the
// environment is space-separated rather than NUL-separated. The value ends at
// the next whitespace: a token with spaces in it could not survive this, and
// the tokens the host mints (del_ + base64url) never contain any.
func parseEnvTokenSpaced(s, key string) string {
	pre := key + "="
	for _, field := range strings.Fields(s) {
		if strings.HasPrefix(field, pre) {
			return field[len(pre):]
		}
	}
	return ""
}

// ── Windows: the GetExtendedTcpTable buffers ────────────────────────────────
//
// Parsed here rather than beside the syscall so the byte layout is under test
// on the machine that runs CI. Layouts are the documented MIB structures; the
// two row shapes differ enough to be worth separate constants:
//
//	MIB_TCPROW_OWNER_PID   (24B): state, localAddr, localPort, remoteAddr, remotePort, pid
//	MIB_TCP6ROW_OWNER_PID  (56B): localAddr[16], localScope, localPort,
//	                              remoteAddr[16], remoteScope, remotePort, state, pid
//
// Both tables are { DWORD dwNumEntries; ROW table[] } with the rows at offset 4.
// Ports are DWORDs whose LOW 16 bits hold the port in NETWORK byte order, so
// the first two bytes of the little-endian DWORD are the port, big-endian.
const (
	winTCPRow4Size = 24
	winTCPRow6Size = 56
	winTCPStateEst = 5 // MIB_TCP_STATE_ESTAB
)

func winPortAt(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(b[:2]))
}

// parseTCPTable decodes an IPv4 or IPv6 owner-pid TCP table into the
// established outbound connections owned by other processes.
func parseTCPTable(buf []byte, v6 bool, self int) []connObs {
	conns := []connObs{}
	if len(buf) < 4 {
		return conns
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := winTCPRow4Size
	if v6 {
		rowSize = winTCPRow6Size
	}
	for i := 0; i < n; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		var state, pid, port int
		var ip net.IP
		if v6 {
			port = winPortAt(row[44:48])
			state = int(binary.LittleEndian.Uint32(row[48:52]))
			pid = int(binary.LittleEndian.Uint32(row[52:56]))
			ip = net.IP(append([]byte(nil), row[24:40]...))
		} else {
			state = int(binary.LittleEndian.Uint32(row[0:4]))
			ip = net.IP(append([]byte(nil), row[12:16]...))
			port = winPortAt(row[16:20])
			pid = int(binary.LittleEndian.Uint32(row[20:24]))
		}
		if state != winTCPStateEst || pid <= 0 || pid == self || port == 0 {
			continue
		}
		conns = append(conns, connObs{PID: pid, RemoteIP: ip.String(), RemotePort: port})
	}
	return conns
}

// parseWinEnvBlock finds one variable in a process environment block read out
// of another process: UTF-16LE, NUL-separated entries, terminated by an empty
// entry. Bounded by the caller's read; a truncated block simply stops early
// rather than erroring, because a missing tag and an unreadable tag lead to
// the same conservative outcome (the agent reads as unrequested).
func parseWinEnvBlock(b []byte, key string) string {
	pre := strings.ToUpper(key) + "="
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	start := 0
	for i := 0; i <= len(u16); i++ {
		if i == len(u16) || u16[i] == 0 {
			if i == start {
				break // empty entry: end of block
			}
			entry := string(utf16Runes(u16[start:i]))
			if len(entry) >= len(pre) && strings.ToUpper(entry[:len(pre)]) == pre {
				return entry[len(pre):]
			}
			start = i + 1
		}
	}
	return ""
}

// utf16Runes decodes a UTF-16 code-unit slice, including surrogate pairs.
func utf16Runes(u []uint16) []rune {
	out := make([]rune, 0, len(u))
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c >= 0xD800 && c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000 {
			out = append(out, ((rune(c)-0xD800)<<10|(rune(u[i+1])-0xDC00))+0x10000)
			i++
			continue
		}
		out = append(out, rune(c))
	}
	return out
}
