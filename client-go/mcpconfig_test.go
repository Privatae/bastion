package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every fixture here is invented: server names, packages, hosts, paths and
// the secret-shaped values, which are built from repeated letters so no real
// credential can be in this file.

var (
	fakeAnthropicKey = "sk-ant-api03-" + strings.Repeat("Q", 40)
	fakeGitHubToken  = "ghp_" + strings.Repeat("Z", 36)
	fakeLiteral      = "plain-" + strings.Repeat("k", 12)
)

func entriesByName(t *testing.T, format, body string) map[string]mcpEntry {
	t.Helper()
	es, _, err := mcpParse(format, []byte(body))
	if err != nil {
		t.Fatalf("%s: %v", format, err)
	}
	out := map[string]mcpEntry{}
	for _, e := range es {
		out[e.name] = e
	}
	return out
}

func TestMCPParseClaudeDesktopShape(t *testing.T) {
	es := entriesByName(t, mcpFormatServers, `{"mcpServers": {
		"files": {"command": "npx", "args": ["-y", "@demo-scope/server-files@1.4.2", "/srv/demo"]},
		"search": {"command": "uvx", "args": ["demo-search"], "env": {"DEMO_API_KEY": "`+fakeLiteral+`"}}
	}, "otherSetting": true}`)
	if len(es) != 2 || es["files"].command != "npx" || es["search"].env["DEMO_API_KEY"] == "" {
		t.Fatalf("entries: %+v", es)
	}
}

func TestMCPParseClaudeCodeUserAndProjects(t *testing.T) {
	body := `{"numStartups": 3, "mcpServers": {"u1": {"type": "stdio", "command": "demo-tool"}},
	  "projects": {
	    "/home/demo/proj-a": {"mcpServers": {"p1": {"type": "http", "url": "https://tools.example.com/x"}}},
	    "/home/demo/proj-b": {"allowedTools": []}
	  }}`
	es, projects, err := mcpParse(mcpFormatClaude, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 || es[0].name != "u1" || es[0].projectScoped || es[1].name != "p1" || !es[1].projectScoped {
		t.Fatalf("entries: %+v", es)
	}
	want := []string{filepath.FromSlash("/home/demo/proj-a"), filepath.FromSlash("/home/demo/proj-b")}
	if !reflect.DeepEqual(projects, want) {
		t.Fatalf("projects: %v", projects)
	}
}

func TestMCPParseVSCodeJSONC(t *testing.T) {
	es := entriesByName(t, mcpFormatVSCode, `{
	  // a comment the file is allowed to carry
	  "inputs": [{"id": "tok", "type": "promptString", "password": true}],
	  "servers": {
	    "remote": {"type": "sse", "url": "https://tools.example.com/sse", "headers": {"Authorization": "Bearer ${input:tok}"},},
	    /* a block comment, "with a quote" */
	    "local": {"command": "node", "args": ["/opt/demo/server.js"],},
	  },
	}`)
	if es["remote"].typ != "sse" || es["local"].command != "node" || len(es) != 2 {
		t.Fatalf("entries: %+v", es)
	}
	// A // inside a string is data, not a comment.
	es = entriesByName(t, mcpFormatVSCode, `{"servers": {"u": {"url": "https://h.example.com//x"}}}`)
	if es["u"].url != "https://h.example.com//x" {
		t.Fatalf("a URL lost its slashes: %q", es["u"].url)
	}
}

func TestMCPParseZedBothCommandForms(t *testing.T) {
	es := entriesByName(t, mcpFormatZed, `{
	  "theme": "One Dark", // Zed's settings carry everything else too
	  "context_servers": {
	    "flat": {"source": "custom", "command": "demo-mcp-server", "args": ["--stdio"], "env": {"DEMO_TOKEN": "`+fakeLiteral+`"}},
	    "nested": {"command": {"path": "/usr/local/bin/demo", "args": ["serve"], "env": {"LOG_LEVEL": "info"}}},
	    "remote": {"url": "https://zed-tools.example.com/mcp", "headers": {"X-Api-Key": "`+fakeLiteral+`"}}
	  }
	}`)
	if es["flat"].command != "demo-mcp-server" || es["nested"].command != "/usr/local/bin/demo" ||
		!reflect.DeepEqual(es["nested"].args, []string{"serve"}) || es["nested"].env["LOG_LEVEL"] != "info" ||
		es["remote"].headers["X-Api-Key"] == "" {
		t.Fatalf("entries: %+v", es)
	}
}

func TestMCPParseWindsurfServerURL(t *testing.T) {
	es := entriesByName(t, mcpFormatServers, `{"mcpServers": {"w": {"serverUrl": "https://ws-tools.example.com/mcp"}}}`)
	if es["w"].url != "https://ws-tools.example.com/mcp" {
		t.Fatalf("serverUrl not read: %+v", es)
	}
}

func TestMCPParseCodexTOML(t *testing.T) {
	body := `# invented Codex config
model = "demo-model"

[mcp_servers.docs]
command = "npx"
args = [
  "-y",          # a comment inside an array
  "demo-docs-server@2.0.1",
]
env = { "DEMO_KEY" = "` + fakeLiteral + `", PLAIN = 'x' }
env_vars = ["HOME_HINT", { name = "FORWARDED", source = "local" }]
startup_timeout_sec = 20

[mcp_servers."remote tools"]
url = "https://codex-tools.example.com/mcp"
bearer_token_env_var = "DEMO_BEARER"
enabled = false

[mcp_servers.docs.tools.search]
approval_mode = "approve"

[[profiles_list]]
command = "not a server"
`
	es := entriesByName(t, mcpFormatCodex, body)
	d := es["docs"]
	if d.command != "npx" || !reflect.DeepEqual(d.args, []string{"-y", "demo-docs-server@2.0.1"}) ||
		d.env["DEMO_KEY"] == "" || d.env["PLAIN"] != "x" ||
		!reflect.DeepEqual(d.envNames, []string{"HOME_HINT", "FORWARDED"}) {
		t.Fatalf("docs: %+v", d)
	}
	r := es["remote tools"]
	if r.url == "" || !r.authHint || !r.disabled || !reflect.DeepEqual(r.envNames, []string{"DEMO_BEARER"}) {
		t.Fatalf("remote: %+v", r)
	}
	if len(es) != 2 {
		t.Fatalf("an [[array of tables]] leaked in, or a server was lost: %v", es)
	}
	if _, err := parseTOMLSubset("[mcp_servers.x]\ncommand = \"unterminated\n"); err == nil {
		t.Fatal("a broken line must fail the file, not half-read it")
	}
	if v, _ := parseTOMLSubset(`k = "a\tb\u00e9\"q"`); v["k"] != "a\tbé\"q" {
		t.Fatalf("escapes: %q", v["k"])
	}
}

// THE VALUE NEVER LEAVES. A secret in env, a header, an argument or the URL
// sets one bool; the marshalled record carries the variable's NAME and
// nothing of the value.
func TestMCPAnalyzeKeepsNamesAndDropsValues(t *testing.T) {
	cases := []struct {
		name string
		e    mcpEntry
	}{
		{"env, known prefix", mcpEntry{name: "a", command: "npx", args: []string{"demo"},
			env: map[string]string{"ANTHROPIC_API_KEY": fakeAnthropicKey}}},
		{"env, known prefix under a plain name", mcpEntry{name: "a2", command: "demo",
			env: map[string]string{"DEMO_SETTING": fakeAnthropicKey}}},
		{"env, literal under a secret name", mcpEntry{name: "b", command: "demo",
			env: map[string]string{"SERVICE_TOKEN": fakeLiteral}}},
		{"header", mcpEntry{name: "c", url: "https://h.example.com/mcp",
			headers: map[string]string{"Authorization": "Bearer " + fakeLiteral}}},
		{"argument after a flag", mcpEntry{name: "d", command: "demo", args: []string{"--api-key", fakeLiteral}}},
		{"argument with =", mcpEntry{name: "e", command: "demo", args: []string{"--token=" + fakeLiteral}}},
		{"bare token argument", mcpEntry{name: "f", command: "demo", args: []string{fakeGitHubToken}}},
		{"docker -e NAME=value", mcpEntry{name: "g", command: "docker",
			args: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN=" + fakeLiteral, "ghcr.io/demo/server"}}},
		{"URL query", mcpEntry{name: "h", url: "https://h.example.com/mcp?api_key=" + fakeLiteral}},
		{"URL password", mcpEntry{name: "i", url: "https://u:" + fakeLiteral + "@h.example.com/mcp"}},
	}
	for _, c := range cases {
		o := mcpAnalyze(c.e)
		if !o.SecretInPlaintext {
			t.Errorf("%s: the secret was not seen", c.name)
		}
		b, _ := json.Marshal(o)
		for _, v := range []string{fakeAnthropicKey, fakeLiteral, fakeGitHubToken} {
			if strings.Contains(string(b), v) {
				t.Errorf("%s: a value left in the record: %s", c.name, b)
			}
		}
	}
	o := mcpAnalyze(mcpEntry{name: "a", command: "npx", args: []string{"demo"},
		env: map[string]string{"B_KEY": "${env:B_KEY}", "A_URL": "https://h.example.com", "LOG": "debug",
			"KEY_FILE": "/etc/demo/key.pem"}, envNames: []string{"FORWARDED", "LOG"}})
	if o.SecretInPlaintext {
		t.Fatal("a reference, a URL, a path and a short value are not secrets in plain text")
	}
	if !reflect.DeepEqual(o.EnvNames, []string{"A_URL", "B_KEY", "FORWARDED", "KEY_FILE", "LOG"}) {
		t.Fatalf("env names: %v", o.EnvNames)
	}
	if b, _ := json.Marshal(o); strings.Contains(string(b), "debug") || strings.Contains(string(b), "key.pem") {
		t.Fatalf("an env value travelled: %s", b)
	}
}

func TestMCPPackageAndPinned(t *testing.T) {
	cases := []struct {
		cmd                  string
		args                 []string
		source, name, pinned string
	}{
		{"npx", []string{"-y", "@demo-scope/server-files@1.4.2", "/srv"}, "npx", "@demo-scope/server-files", "yes"},
		{"npx", []string{"-y", "@demo-scope/server-files"}, "npx", "@demo-scope/server-files", "no"},
		{"npx", []string{"demo-server@latest"}, "npx", "demo-server", "no"},
		{"npx", []string{"demo-server@^1.2.0"}, "npx", "demo-server", "no"},
		{"npx", []string{"--package", "demo-pkg@3.0.0", "demo-bin"}, "npx", "demo-pkg", "yes"},
		{"C:\\Program Files\\nodejs\\npx.cmd", []string{"-y", "demo-win@0.1.0"}, "npx", "demo-win", "yes"},
		{"pnpm", []string{"dlx", "demo-dlx@1.0.0"}, "npx", "demo-dlx", "yes"},
		{"npx", []string{"github:demo/repo"}, "npx", "github:demo/repo", "unknown"},
		{"uvx", []string{"demo-py==0.3.1"}, "uvx", "demo-py", "yes"},
		{"uvx", []string{"demo-py@0.3.1"}, "uvx", "demo-py", "yes"},
		{"uvx", []string{"--from", "demo-py>=0.3", "demo-cli"}, "uvx", "demo-py", "no"},
		{"uvx", []string{"demo-py"}, "uvx", "demo-py", "no"},
		{"uv", []string{"tool", "run", "demo-py==1.0"}, "uvx", "demo-py", "yes"},
		{"pipx", []string{"run", "demo-pipx==2.1"}, "pip", "demo-pipx", "yes"},
		{"docker", []string{"run", "-i", "--rm", "-e", "X", "ghcr.io/demo/srv:1.2"}, "docker", "ghcr.io/demo/srv", "no"},
		{"docker", []string{"run", "--rm", "localhost:5000/demo/srv@sha256:" + strings.Repeat("a", 64)}, "docker", "localhost:5000/demo/srv", "yes"},
		{"docker", []string{"run", "-i", "demo/srv"}, "docker", "demo/srv", "no"},
		{"node", []string{"/opt/demo/server.js"}, "unknown", "", "unknown"},
		{"/usr/local/bin/demo-mcp-server", []string{"stdio"}, "binary", "", "unknown"},
	}
	for _, c := range cases {
		s, n, p := mcpPackage(c.cmd, c.args)
		if s != c.source || n != c.name || p != c.pinned {
			t.Errorf("%s %v: got %s %q %s, want %s %q %s", c.cmd, c.args, s, n, p, c.source, c.name, c.pinned)
		}
	}
}

func TestMCPTransportLocalityAuth(t *testing.T) {
	cases := []struct {
		e                                 mcpEntry
		transport, locality, auth, urlHst string
	}{
		{mcpEntry{command: "demo"}, "stdio", "local_process", "not_applicable", ""},
		{mcpEntry{typ: "streamable-http", url: "https://tools.example.com/mcp"}, "http", "remote", "unknown", "tools.example.com"},
		{mcpEntry{url: "https://tools.example.com/sse"}, "sse", "remote", "unknown", "tools.example.com"},
		{mcpEntry{url: "wss://tools.example.com/x"}, "websocket", "remote", "unknown", "tools.example.com"},
		{mcpEntry{typ: "ws", url: "ws://127.0.0.1:9000"}, "websocket", "loopback", "unknown", "127.0.0.1"},
		{mcpEntry{url: "http://localhost:3333/mcp"}, "http", "loopback", "unknown", "localhost"},
		{mcpEntry{url: "http://10.20.30.40:80/mcp"}, "http", "lan", "unknown", "10.20.30.40"},
		{mcpEntry{url: "http://toolbox.internal/mcp"}, "http", "lan", "unknown", "toolbox.internal"},
		{mcpEntry{url: "http://toolbox/mcp"}, "http", "lan", "unknown", "toolbox"},
		{mcpEntry{url: "https://t.example.com/mcp", headers: map[string]string{"Authorization": "Bearer ${env:T}"}}, "http", "remote", "yes", "t.example.com"},
		{mcpEntry{url: "https://t.example.com/mcp", authHint: true}, "http", "remote", "yes", "t.example.com"},
		{mcpEntry{typ: "carrier-pigeon", url: "https://t.example.com"}, "unknown", "remote", "unknown", "t.example.com"},
	}
	for _, c := range cases {
		o := mcpAnalyze(c.e)
		if o.Transport != c.transport || o.Locality != c.locality || o.AuthConfigured != c.auth || o.URLHost != c.urlHst {
			t.Errorf("%+v: got %s %s %s %q", c.e, o.Transport, o.Locality, o.AuthConfigured, o.URLHost)
		}
		if c.transport == "stdio" && o.BindClass != "not_applicable" || c.transport != "stdio" && o.BindClass != "unknown" {
			t.Errorf("%+v: bind %s", c.e, o.BindClass)
		}
	}
	// The command is the cmdline handling's: joined, and cut at 200.
	long := mcpAnalyze(mcpEntry{command: "demo", args: []string{strings.Repeat("a", 300)}})
	if len(long.Command) != 200 {
		t.Fatalf("command not truncated like a cmdline: %d", len(long.Command))
	}
}

func TestCorrelateMCPStates(t *testing.T) {
	declared := []mcpServerObs{
		mcpAnalyze(mcpEntry{name: "files", command: "npx", args: []string{"-y", "@demo-scope/server-files@1.4.2"}}),
		mcpAnalyze(mcpEntry{name: "idle", command: "uvx", args: []string{"demo-idle"}}),
		mcpAnalyze(mcpEntry{name: "bin", command: "/opt/demo/bin/demo-tool", args: []string{"serve"}}),
		mcpAnalyze(mcpEntry{name: "saas", url: "https://tools.example.com/mcp"}),
		mcpAnalyze(mcpEntry{name: "local-url", url: "http://127.0.0.1:7000/mcp"}),
	}
	procs := []mcpProc{
		{PID: 10, PPID: 1, Argv: []string{"demo-client"}},
		{PID: 20, PPID: 10, Argv: []string{"npm", "exec", "-y", "@demo-scope/server-files@1.4.2"}},
		// npx's child: no package name in its own line, inherits the match.
		{PID: 21, PPID: 20, Argv: []string{"node", "/home/demo/.npm/_npx/abc/node_modules/.bin/mcp-server-files"}},
		{PID: 30, PPID: 10, Argv: []string{"/opt/demo/bin/demo-tool", "serve"}},
		// Shadow: a server nobody declared, and its own child (collapsed).
		{PID: 40, PPID: 1, Argv: []string{"node", "/opt/x/node_modules/@modelcontextprotocol/server-memory/dist/index.js"}},
		{PID: 41, PPID: 40, Argv: []string{"node", "/opt/x/mcp-worker.js"}},
		{PID: 50, PPID: 1, Argv: []string{"/usr/bin/github-mcp-server", "stdio", "--token=" + fakeGitHubToken}},
		// Not servers: an agent run with an MCP flag, and a grep.
		{PID: 60, PPID: 1, Argv: []string{"claude", "--mcp-config", "/tmp/mcp.json"}},
		{PID: 61, PPID: 1, Argv: []string{"grep", "-r", "mcp-server", "/srv"}},
		{PID: 70, PPID: 1}, // a process whose command line was not read
	}
	got := correlateMCP(declared, procs, true)
	state := map[string]mcpServerObs{}
	var shadows []mcpServerObs
	for _, o := range got {
		if o.RunningState == mcpStateShadow {
			shadows = append(shadows, o)
			continue
		}
		state[o.Name] = o
	}
	if s := state["files"]; s.RunningState != mcpStateRunning || !reflect.DeepEqual(s.PIDs, []int{20, 21}) {
		t.Errorf("files: %s %v", s.RunningState, s.PIDs)
	}
	if s := state["idle"]; s.RunningState != mcpStateIdle {
		t.Errorf("idle: %s", s.RunningState)
	}
	if s := state["bin"]; s.RunningState != mcpStateRunning || !reflect.DeepEqual(s.PIDs, []int{30}) {
		t.Errorf("bin: %s %v", s.RunningState, s.PIDs)
	}
	if s := state["saas"]; s.RunningState != mcpStateNotLocal {
		t.Errorf("saas: %s", s.RunningState)
	}
	if s := state["local-url"]; s.RunningState != mcpStateUnknown {
		t.Errorf("local-url: %s", s.RunningState)
	}
	if len(shadows) != 2 || !reflect.DeepEqual(shadows[0].PIDs, []int{40}) || !reflect.DeepEqual(shadows[1].PIDs, []int{50}) {
		t.Fatalf("shadow servers: %+v", shadows)
	}
	if !shadows[1].SecretInPlaintext || strings.Contains(shadows[1].Command, fakeGitHubToken) {
		t.Fatalf("a running server's secret argument travelled: %+v", shadows[1])
	}

	// No process list: nothing is guessed, and no shadow is invented.
	for _, o := range correlateMCP(declared, nil, false) {
		if o.RunningState == mcpStateShadow || (o.Transport == "stdio" && o.RunningState != mcpStateUnknown) {
			t.Errorf("with no process list %s read %s", o.Name, o.RunningState)
		}
	}
}

// The whole reader over invented homes: the per-OS path table, the projects
// Claude Code lists, the system file, and an unreadable file that must be
// counted rather than read as empty.
func TestReadMCPConfigsOverFixtureHomes(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "demo")
	proj := filepath.Join(root, "work", "proj")
	write := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := mcpHome{Dir: home, ConfigDir: filepath.Join(home, ".config")}
	projJSON, _ := json.Marshal(proj)
	write(filepath.Join(home, ".claude.json"), `{"mcpServers": {"u": {"command": "demo-u"}},
		"projects": {`+string(projJSON)+`: {}}}`)
	write(filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers": {"c": {"url": "https://c.example.com/mcp"}}}`)
	write(filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.x]\ncommand = \"demo-x\"\n")
	write(filepath.Join(proj, ".mcp.json"), `{"mcpServers": {"p": {"command": "demo-p"}}}`)
	write(filepath.Join(proj, ".vscode", "mcp.json"), `{"servers": {"v": {"command": "demo-v"},},}`)
	write(filepath.Join(home, ".config", "zed", "settings.json"), `{"context_servers": {"z": {"command": "demo-z"}`) // broken
	// A directory where a file should be: present, and unreadable as a file.
	if err := os.MkdirAll(filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	sys := filepath.Join(root, "etc", "managed-mcp.json")
	write(sys, `{"mcpServers": {"s": {"command": "demo-s"}}}`)

	oldH, oldS, oldOS := mcpHomesFn, mcpSystemFn, mcpGOOS
	t.Cleanup(func() { mcpHomesFn, mcpSystemFn, mcpGOOS = oldH, oldS, oldOS })
	mcpGOOS = "linux"
	mcpHomesFn = func() ([]mcpHome, bool) { return []mcpHome{h}, true }
	mcpSystemFn = func() []mcpSource { return []mcpSource{{mcpClientCode, mcpScopeSystem, sys, mcpFormatServers}} }

	got, scan := readMCPConfigs()
	where := map[string]string{}
	for _, o := range got {
		where[o.Name] = o.Client + "/" + o.Scope
	}
	want := map[string]string{"s": "claude-code/system", "u": "claude-code/user", "c": "cursor/user",
		"x": "codex/user", "p": "claude-code/project", "v": "vscode/project"}
	if !reflect.DeepEqual(where, want) {
		t.Fatalf("servers: %v", where)
	}
	if scan.Accounts != 1 || scan.Projects != 1 || scan.Unparsed != 1 || scan.Unreadable != 1 || scan.FilesRead != 7 {
		t.Fatalf("scan: %+v", scan)
	}

	mcpHomesFn = func() ([]mcpHome, bool) { return nil, false }
	if got, scan := readMCPConfigs(); got != nil || scan.Supported {
		t.Fatal("an unsupported platform must say so, not report an empty machine")
	}
}

// The path table names each client's file on each platform.
func TestMCPConfigSourcesPerPlatform(t *testing.T) {
	find := func(srcs []mcpSource, client, suffix string) bool {
		for _, s := range srcs {
			if s.Client == client && strings.HasSuffix(filepath.ToSlash(s.Path), suffix) {
				return true
			}
		}
		return false
	}
	mac := mcpConfigSources("darwin", mcpHome{Dir: "/Users/demo", ConfigDir: "/Users/demo/Library/Application Support"})
	win := mcpConfigSources("windows", mcpHome{Dir: `C:\Users\demo`, ConfigDir: `C:\Users\demo\AppData\Roaming`})
	lin := mcpConfigSources("linux", mcpHome{Dir: "/home/demo", ConfigDir: "/home/demo/.config"})
	for _, c := range []struct {
		srcs           []mcpSource
		client, suffix string
	}{
		{mac, mcpClientDesktop, "Library/Application Support/Claude/claude_desktop_config.json"},
		{win, mcpClientDesktop, "Roaming/Claude/claude_desktop_config.json"},
		{lin, mcpClientCode, "/home/demo/.claude.json"},
		{lin, mcpClientCursor, ".cursor/mcp.json"},
		{mac, mcpClientVSCode, "Application Support/Code/User/mcp.json"},
		{lin, mcpClientWindsurf, ".config/devin/mcp_config.json"},
		{lin, mcpClientWindsurf, ".codeium/windsurf/mcp_config.json"},
		{lin, mcpClientCodex, ".codex/config.toml"},
		{mac, mcpClientZed, "/Users/demo/.config/zed/settings.json"},
		{win, mcpClientZed, "Roaming/Zed/settings.json"},
	} {
		if !find(c.srcs, c.client, filepath.ToSlash(c.suffix)) {
			t.Errorf("%s: no source ending %s", c.client, c.suffix)
		}
	}
	if s := mcpSystemSources("windows", `C:\Program Files`); len(s) != 1 || !strings.HasSuffix(filepath.ToSlash(s[0].Path), "ClaudeCode/managed-mcp.json") {
		t.Errorf("windows system sources: %v", s)
	}
}

// The heartbeat's report: a process walk that failed says so, and every
// local server then reads unknown rather than "not running".
func TestMCPServersReportWhenTheProcessWalkFails(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"),
		[]byte(`{"mcpServers": {"u": {"command": "demo-u"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	oldH, oldS, oldP := mcpHomesFn, mcpSystemFn, scanMCPProcessesFn
	t.Cleanup(func() { mcpHomesFn, mcpSystemFn, scanMCPProcessesFn = oldH, oldS, oldP })
	resetMCPConfigCache()
	t.Cleanup(resetMCPConfigCache)
	mcpHomesFn = func() ([]mcpHome, bool) { return []mcpHome{{Dir: home, ConfigDir: home}}, true }
	mcpSystemFn = func() []mcpSource { return nil }

	scanMCPProcessesFn = func(map[string]bool) ([]mcpProc, error) { return nil, os.ErrPermission }
	got, scan := mcpServersReport()
	if len(got) != 1 || got[0].RunningState != mcpStateUnknown || scan.ProcessScan == "ok" {
		t.Fatalf("failed walk: %+v %+v", got, scan)
	}

	scanMCPProcessesFn = func(want map[string]bool) ([]mcpProc, error) {
		if !want["demo-u"] {
			t.Error("the declared program was not in the set whose command lines are read")
		}
		return []mcpProc{{PID: 9, PPID: 1, Argv: []string{"/usr/bin/demo-u"}}}, nil
	}
	got, scan = mcpServersReport()
	if len(got) != 1 || got[0].RunningState != mcpStateRunning || scan.ProcessScan != "ok" {
		t.Fatalf("walk: %+v %+v", got, scan)
	}
}
