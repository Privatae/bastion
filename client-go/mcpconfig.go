package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// THE TOOL SERVERS THIS MACHINE'S AGENT CLIENTS ARE SET UP TO START.
//
// Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Codex and Zed each
// keep a file that lists the tool servers (Model Context Protocol servers) the
// client may start or connect to. An assessment needs that list: which servers
// a person's agents can reach, how each is launched, whether a secret sits in
// the file in plain text, and whether the server the file names is actually
// running — or a server is running that no file names.
//
// THIS FILE ONLY READS FILES. It opens no socket, starts no process and never
// talks to a server; the bastion does not speak that protocol, and
// TestNoRouteOpOrDependencySpeaksMCP (claims_static_test.go) holds it to that
// by walking the call graph out of every function declared here. The process
// list it correlates against is handed IN by agents.go, which reads it with
// the platform's own enumerator (scanMCPProcesses, agents_<goos>.go).
//
// WHAT LEAVES THE MACHINE, AND WHAT NEVER DOES. Per declared server: the
// client, the config scope, the file path, the server's name, transport,
// whether it is a local process or a URL (and the URL's host), the launch
// command truncated the way agent command lines are, the package and whether
// it is pinned, the NAMES of the environment variables it is given, whether a
// value matched a secret's shape, whether a remote server has authentication
// configured, and whether it is running. NEVER a value of an environment
// variable or a header: a value is looked at once, for its shape, and dropped
// in the same function. A command-line argument that looks like a secret is
// replaced by a marker before the command is kept at all. Paths and names
// travel only inside the heartbeat's `observing` gate, beside the agent list.
//
// WHERE EACH CLIENT KEEPS ITS FILE is mcpConfigSources below, with the page
// each path was checked against on 2026-10-20. Paths a page did not state are
// marked there as not confirmed; they are still read, because reading a file
// that is not there costs a stat and finds nothing.

// mcpServerObs is one declared (or running, undeclared) tool server.
type mcpServerObs struct {
	Client string `json:"client,omitempty"` // claude-desktop, claude-code, cursor, vscode, windsurf, codex, zed
	Scope  string `json:"scope,omitempty"`  // user, project, system
	Path   string `json:"path,omitempty"`
	Name   string `json:"name,omitempty"`
	// Transport: stdio, http, sse, websocket, unknown.
	Transport string `json:"transport"`
	// Locality: local_process (the client starts it here), loopback, lan,
	// remote (a URL host off this network), unknown.
	Locality string `json:"locality"`
	URLHost  string `json:"url_host,omitempty"`
	// Command is the launch command and its arguments, joined and truncated
	// to 200 characters like an agent's cmdline, with any argument that
	// looked like a secret replaced by mcpRedacted first.
	Command string `json:"command,omitempty"`
	// PackageSource: npx, uvx, pip, docker, binary, unknown.
	PackageSource string `json:"package_source,omitempty"`
	PackageName   string `json:"package_name,omitempty"`
	// PackagePinned: yes (an exact version or an image digest), no (a
	// range, a tag, or nothing), unknown (a path or binary).
	PackagePinned string   `json:"package_pinned,omitempty"`
	EnvNames      []string `json:"env_names,omitempty"`
	// SecretInPlaintext: a value in this entry (an env value, a header, an
	// argument, the URL) matched a secret's shape. The value is not kept.
	SecretInPlaintext bool `json:"secret_in_plaintext"`
	// AuthConfigured: yes when the file gives a remote server a credential
	// (a header, a bearer-token variable, credentials in the URL);
	// not_applicable for a local process; unknown otherwise, because a client
	// may negotiate OAuth when it connects and that leaves nothing in a file.
	AuthConfigured string `json:"auth_configured"`
	// BindClass: what the server listens on. not_applicable for stdio;
	// unknown for a URL, which says where the client connects, not what the
	// server binds.
	BindClass string `json:"bind_class"`
	Disabled  bool   `json:"disabled,omitempty"`
	// RunningState: declared_running, declared_not_running,
	// running_not_declared; not_local for a URL off this machine; unknown
	// when the process list could not be read or a loopback URL cannot be
	// matched to a process from a file.
	RunningState string `json:"running_state"`
	PIDs         []int  `json:"pids,omitempty"`

	// The correlation key, never sent: a package name or a script path to
	// find in a command line, or a program's basename to find as argv[0].
	matchSub  string
	matchBase string
}

// mcpConfigScan says how much was looked at, so "no servers" from a box that
// read nothing is visibly different from one that read forty files.
type mcpConfigScan struct {
	Supported  bool `json:"supported"`
	Accounts   int  `json:"accounts"`
	Projects   int  `json:"projects"`
	FilesRead  int  `json:"files_read"`
	Unreadable int  `json:"files_unreadable"`
	Unparsed   int  `json:"files_unparsed"`
	Truncated  bool `json:"truncated,omitempty"`
	// ForeignOwner: files skipped because neither the account they were
	// read for nor root (SYSTEM or Administrators on Windows) owns them
	// (mcpReadFileAs).
	ForeignOwner int `json:"files_foreign_owner,omitempty"`
	// TimedOut: the file read did not finish within mcpReadTimeout; the
	// list is the last complete read, or empty when there was none.
	TimedOut bool `json:"timed_out,omitempty"`
	// ProcessScan: ok, failed or unsupported — whether running_state could
	// be measured at all.
	ProcessScan string `json:"process_scan"`
}

const (
	mcpRedacted       = "<redacted>"
	mcpUnknown        = "unknown"
	mcpMaxFileBytes   = 1 << 20
	mcpMaxAccounts    = 64
	mcpMaxProjects    = 200
	mcpMaxServers     = 500
	mcpMaxPIDs        = 8
	mcpCommandMax     = 200
	mcpNameMax        = 128 // a server name, an env name, a package name
	mcpHostMax        = 253 // a DNS name's own limit
	mcpPathMax        = 1024
	mcpMaxEnvNames    = 32
	mcpMaxNesting     = 64  // TOML arrays and inline tables
	mcpNoOwnerCheck   = ""  // the owner a file is read for when no owner check applies
	mcpOwnerUnknown   = "?" // an owner that could not be read: matches nothing
	mcpStateRunning   = "declared_running"
	mcpStateIdle      = "declared_not_running"
	mcpStateShadow    = "running_not_declared"
	mcpStateNotLocal  = "not_local"
	mcpStateUnknown   = "unknown"
	mcpLocalProcess   = "local_process"
	mcpNotApplicable  = "not_applicable"
	mcpFormatServers  = "mcpServers"      // a top-level mcpServers object
	mcpFormatClaude   = "claude-json"     // ~/.claude.json: user and per-project servers
	mcpFormatVSCode   = "vscode"          // a top-level servers object
	mcpFormatZed      = "context_servers" // Zed settings, JSON with comments
	mcpFormatCodex    = "codex-toml"      // [mcp_servers.<name>] tables
	mcpScopeUser      = "user"
	mcpScopeProject   = "project"
	mcpScopeSystem    = "system"
	mcpClientDesktop  = "claude-desktop"
	mcpClientCode     = "claude-code"
	mcpClientCursor   = "cursor"
	mcpClientVSCode   = "vscode"
	mcpClientWindsurf = "windsurf"
	mcpClientCodex    = "codex"
	mcpClientZed      = "zed"
)

// mcpHome is one account's home directory and the per-user application
// configuration directory under it (XDG on Linux, Application Support on
// macOS, AppData\Roaming on Windows).
type mcpHome struct {
	Dir       string
	ConfigDir string
}

// mcpSource is one file to read.
type mcpSource struct {
	Client, Scope, Path, Format string
}

// mcpConfigSources is every file the seven clients keep for one account, for
// the platform goos. Checked against each vendor's page on 2026-10-20:
//
//	claude-desktop  https://modelcontextprotocol.io/docs/develop/connect-local-servers
//	                macOS and Windows stated; the Linux path is NOT CONFIRMED
//	                (the page says Linux is supported and gives no path).
//	claude-code     https://code.claude.com/docs/en/mcp — user and local scope in
//	                ~/.claude.json (local nested under projects.<path>), project
//	                scope in .mcp.json; https://code.claude.com/docs/en/managed-mcp
//	                for the system file on each platform.
//	cursor          https://cursor.com/docs/context/mcp — ~/.cursor/mcp.json and
//	                .cursor/mcp.json; given only in the ~ form, so the Windows
//	                location (the user profile) is NOT CONFIRMED.
//	vscode          https://code.visualstudio.com/docs/copilot/reference/mcp-configuration
//	                — .vscode/mcp.json, and an mcp.json "in your user profile";
//	                the profile folder is from
//	                https://code.visualstudio.com/docs/configure/profiles. The
//	                exact user-file path is NOT CONFIRMED on any platform.
//	windsurf        https://docs.devin.ai/windsurf/plugins/cascade/mcp — the
//	                config-directory file (devin/mcp_config.json) and the
//	                editor's own ~/.codeium/windsurf[-next]/mcp_config.json; the
//	                Windows form of the second is NOT CONFIRMED.
//	codex           https://learn.chatgpt.com/docs/config-file/config-basic and
//	                https://learn.chatgpt.com/docs/extend/mcp — ~/.codex/config.toml,
//	                /etc/codex/config.toml, and .codex/config.toml in a trusted
//	                project; the Windows path is NOT CONFIRMED.
//	zed             https://zed.dev/docs/configuring-zed — ~/.config/zed/settings.json
//	                (macOS and Linux), %APPDATA%\Zed\settings.json, and
//	                .zed/settings.json in a project; "JSON with support for //
//	                comments".
func mcpConfigSources(goos string, h mcpHome) []mcpSource {
	j := filepath.Join
	out := []mcpSource{
		{mcpClientDesktop, mcpScopeUser, j(h.ConfigDir, "Claude", "claude_desktop_config.json"), mcpFormatServers},
		{mcpClientCode, mcpScopeUser, j(h.Dir, ".claude.json"), mcpFormatClaude},
		{mcpClientCursor, mcpScopeUser, j(h.Dir, ".cursor", "mcp.json"), mcpFormatServers},
		{mcpClientVSCode, mcpScopeUser, j(h.ConfigDir, "Code", "User", "mcp.json"), mcpFormatVSCode},
		{mcpClientWindsurf, mcpScopeUser, j(h.ConfigDir, "devin", "mcp_config.json"), mcpFormatServers},
		{mcpClientWindsurf, mcpScopeUser, j(h.Dir, ".codeium", "windsurf", "mcp_config.json"), mcpFormatServers},
		{mcpClientWindsurf, mcpScopeUser, j(h.Dir, ".codeium", "windsurf-next", "mcp_config.json"), mcpFormatServers},
		{mcpClientCodex, mcpScopeUser, j(h.Dir, ".codex", "config.toml"), mcpFormatCodex},
	}
	if goos == "windows" {
		out = append(out, mcpSource{mcpClientZed, mcpScopeUser, j(h.ConfigDir, "Zed", "settings.json"), mcpFormatZed})
	} else {
		// macOS and Linux both: Zed keeps ~/.config/zed on macOS too, not
		// Application Support.
		out = append(out, mcpSource{mcpClientZed, mcpScopeUser, j(h.Dir, ".config", "zed", "settings.json"), mcpFormatZed})
	}
	return out
}

// mcpSystemSources is the machine-wide files: Claude Code's managed file and
// Codex's system config. programFiles is %ProgramFiles% on Windows.
func mcpSystemSources(goos, programFiles string) []mcpSource {
	switch goos {
	case "darwin":
		return []mcpSource{
			{mcpClientCode, mcpScopeSystem, filepath.Join("/Library", "Application Support", "ClaudeCode", "managed-mcp.json"), mcpFormatServers},
			{mcpClientCodex, mcpScopeSystem, filepath.Join("/etc", "codex", "config.toml"), mcpFormatCodex},
		}
	case "windows":
		if programFiles == "" {
			return nil
		}
		return []mcpSource{
			{mcpClientCode, mcpScopeSystem, filepath.Join(programFiles, "ClaudeCode", "managed-mcp.json"), mcpFormatServers},
		}
	default:
		return []mcpSource{
			{mcpClientCode, mcpScopeSystem, filepath.Join("/etc", "claude-code", "managed-mcp.json"), mcpFormatServers},
			{mcpClientCodex, mcpScopeSystem, filepath.Join("/etc", "codex", "config.toml"), mcpFormatCodex},
		}
	}
}

// mcpProjectSources is the per-project files under one project directory.
// Project directories come from Claude Code's own list of projects in
// ~/.claude.json; the disk is never walked looking for projects, so a
// project only another client has opened is not seen. That is a stated
// limit, not a finding of "none".
func mcpProjectSources(dir string) []mcpSource {
	j := filepath.Join
	return []mcpSource{
		{mcpClientCode, mcpScopeProject, j(dir, ".mcp.json"), mcpFormatServers},
		{mcpClientCursor, mcpScopeProject, j(dir, ".cursor", "mcp.json"), mcpFormatServers},
		{mcpClientVSCode, mcpScopeProject, j(dir, ".vscode", "mcp.json"), mcpFormatVSCode},
		{mcpClientZed, mcpScopeProject, j(dir, ".zed", "settings.json"), mcpFormatZed},
		{mcpClientCodex, mcpScopeProject, j(dir, ".codex", "config.toml"), mcpFormatCodex},
	}
}

// mcpGOOS is the platform whose paths are read; a test reads another's.
var mcpGOOS = runtime.GOOS

// mcpHomesFn and mcpSystemFn are the platform's account list and system files
// (mcpconfig_<goos>.go); a test points them at a fixture.
var (
	mcpHomesFn  = mcpHomes
	mcpSystemFn = mcpSystemFiles
)

// readMCPConfigs reads every source for every account and returns the
// declared servers (running state not yet known) and what was looked at.
func readMCPConfigs() ([]mcpServerObs, mcpConfigScan) {
	homes, supported := mcpHomesFn()
	scan := mcpConfigScan{Supported: supported}
	if !supported {
		return nil, scan
	}
	if len(homes) > mcpMaxAccounts {
		homes, scan.Truncated = homes[:mcpMaxAccounts], true
	}
	scan.Accounts = len(homes)
	var out []mcpServerObs
	// A project is read for the account whose list named it, and its files
	// are held to that account's ownership: one account naming another's
	// directory as a project reads nothing of the other's.
	type project struct {
		dir   string
		owner string
	}
	seenProject := map[project]bool{}
	var projects []project
	read := func(src mcpSource, owner string) {
		raw, ok := mcpReadFileAs(src.Path, owner, &scan)
		if !ok {
			return
		}
		entries, projs, err := mcpParse(src.Format, raw)
		if err != nil {
			scan.Unparsed++
			return
		}
		for _, d := range projs {
			p := project{d, owner}
			if !seenProject[p] {
				seenProject[p] = true
				projects = append(projects, p)
			}
		}
		for _, e := range entries {
			o := mcpAnalyze(e)
			o.Client, o.Path = src.Client, truncate(src.Path, mcpPathMax)
			o.Scope = src.Scope
			if e.projectScoped {
				o.Scope = mcpScopeProject
			}
			out = append(out, o)
		}
	}
	// The system files sit where only an administrator can write.
	for _, src := range mcpSystemFn() {
		read(src, mcpNoOwnerCheck)
	}
	for _, h := range homes {
		owner := mcpPathOwner(h.Dir)
		for _, src := range mcpConfigSources(mcpGOOS, h) {
			read(src, owner)
		}
	}
	sort.Slice(projects, func(i, j int) bool {
		if projects[i].dir != projects[j].dir {
			return projects[i].dir < projects[j].dir
		}
		return projects[i].owner < projects[j].owner
	})
	if len(projects) > mcpMaxProjects {
		projects, scan.Truncated = projects[:mcpMaxProjects], true
	}
	scan.Projects = len(projects)
	for _, p := range projects {
		for _, src := range mcpProjectSources(p.dir) {
			read(src, p.owner)
		}
	}
	if len(out) > mcpMaxServers {
		out, scan.Truncated = out[:mcpMaxServers], true
	}
	return out, scan
}

// mcpReadFile reads one config file, bounded. A file that is not there is
// not counted; one that is there and cannot be read is, so a bastion without
// the right to look says so instead of reporting "no servers".
//
// On linux and darwin a symlink is followed, as the client itself would, but
// what it points at is OPENED only once it is known to be a regular file
// (mcpOpenRegular, mcpconfig_open_<goos>.go). On Windows a link at the path
// itself is refused (mcpconfig_winopen.go). These paths sit in other people's home directories
// and this service reads them with every right it has: opening a FIFO would
// hold the heartbeat, and opening a device runs its driver (a watchdog arms,
// a serial line toggles), so a crafted link must never get that far.
func mcpReadFile(path string, scan *mcpConfigScan) ([]byte, bool) {
	return mcpReadFileAs(path, mcpNoOwnerCheck, scan)
}

// mcpReadFileAs is mcpReadFile for one account: the file is read only when
// that account or an administrative owner owns it (root; on Windows SYSTEM
// or the Administrators group), so an account cannot point its own config
// path at another's file and have this service read it for it. owner is a
// uid on unix and a SID on Windows; mcpNoOwnerCheck reads whatever is there
// (the system files; a platform with no owner model).
func mcpReadFileAs(path string, owner string, scan *mcpConfigScan) ([]byte, bool) {
	f, fileOwner, err := mcpOpenRegularFn(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			scan.Unreadable++
		}
		return nil, false
	}
	defer f.Close()
	if !mcpOwnerAllowed(fileOwner, owner, mcpAdminOwners) {
		scan.ForeignOwner++
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, mcpMaxFileBytes+1))
	if err != nil {
		scan.Unreadable++
		return nil, false
	}
	if len(b) > mcpMaxFileBytes {
		scan.Unparsed++
		return nil, false
	}
	scan.FilesRead++
	return b, true
}

// errMCPNotRegular: the path names something other than a regular file.
var errMCPNotRegular = errors.New("not a regular file")

// mcpOpenRegularFn is the seam a test uses to stand a platform's open in;
// production never reassigns it.
var mcpOpenRegularFn = mcpOpenRegular

// mcpOwnerAllowed: a file owned by file may be read for want. An owner that
// could not be read is never allowed where a check applies.
func mcpOwnerAllowed(file, want string, admins map[string]bool) bool {
	if want == mcpNoOwnerCheck {
		return true
	}
	if file == "" || file == mcpOwnerUnknown {
		return false
	}
	return file == want || admins[file]
}

// mcpEntry is one server as a file declares it, before analysis. Values live
// here only between parsing and mcpAnalyze.
type mcpEntry struct {
	name          string
	typ           string
	command       string
	args          []string
	env           map[string]string
	envNames      []string // names passed through without a value (Codex env_vars)
	url           string
	headers       map[string]string
	authHint      bool // a credential configured by reference: bearer_token_env_var, env_http_headers, a headers helper
	disabled      bool
	projectScoped bool
}

// mcpParse turns one file into entries, plus any project directories the
// file lists (Claude Code's ~/.claude.json).
func mcpParse(format string, raw []byte) ([]mcpEntry, []string, error) {
	if format == mcpFormatCodex {
		t, err := parseTOMLSubset(string(raw))
		if err != nil {
			return nil, nil, err
		}
		return mcpCodexEntries(t), nil, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(stripJSONC(raw), &doc); err != nil {
		return nil, nil, err
	}
	switch format {
	case mcpFormatVSCode:
		return mcpJSONEntries(doc["servers"], false), nil, nil
	case mcpFormatZed:
		return mcpJSONEntries(doc["context_servers"], false), nil, nil
	case mcpFormatClaude:
		out := mcpJSONEntries(doc["mcpServers"], false)
		var projects []string
		if ps, ok := doc["projects"].(map[string]any); ok {
			for dir, v := range ps {
				projects = append(projects, filepath.FromSlash(dir))
				if p, ok := v.(map[string]any); ok {
					out = append(out, mcpJSONEntries(p["mcpServers"], true)...)
				}
			}
		}
		sort.Strings(projects)
		return out, projects, nil
	default:
		return mcpJSONEntries(doc["mcpServers"], false), nil, nil
	}
}

// mcpJSONEntries reads one servers object. The clients agree on command,
// args, env, url and headers; type is spelled `type` (and `transport` by some
// older files); Windsurf also spells the URL serverUrl; Zed's older form nests
// the command as {path, args, env}.
func mcpJSONEntries(v any, projectScoped bool) []mcpEntry {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []mcpEntry
	for _, name := range names {
		s, ok := m[name].(map[string]any)
		if !ok {
			continue
		}
		e := mcpEntry{name: name, projectScoped: projectScoped,
			typ: jsonStr(s["type"]), url: jsonStr(s["url"])}
		if e.typ == "" {
			e.typ = jsonStr(s["transport"])
		}
		if e.url == "" {
			e.url = jsonStr(s["serverUrl"])
		}
		e.args = jsonStrList(s["args"])
		e.env = jsonStrMap(s["env"])
		switch c := s["command"].(type) {
		case string:
			e.command = c
		case map[string]any:
			e.command = jsonStr(c["path"])
			e.args = append(e.args, jsonStrList(c["args"])...)
			for k, v := range jsonStrMap(c["env"]) {
				if e.env == nil {
					e.env = map[string]string{}
				}
				e.env[k] = v
			}
		}
		e.headers = jsonStrMap(s["headers"])
		if s["headersHelper"] != nil || s["oauth"] != nil {
			e.authHint = true
		}
		if d, ok := s["disabled"].(bool); ok && d {
			e.disabled = true
		}
		if en, ok := s["enabled"].(bool); ok && !en {
			e.disabled = true
		}
		out = append(out, e)
	}
	return out
}

func jsonStr(v any) string {
	s, _ := v.(string)
	return s
}

func jsonStrList(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// jsonStrMap keeps string values; any other value is kept as "" so its NAME
// still counts (a number in env is still a variable passed to the server).
func jsonStrMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, x := range m {
		s, _ := x.(string)
		out[k] = s
	}
	return out
}

// mcpCodexEntries reads [mcp_servers.<name>] tables (Codex config.toml):
// command, args, env, env_vars, url, bearer_token_env_var, http_headers,
// env_http_headers, enabled.
func mcpCodexEntries(t map[string]any) []mcpEntry {
	servers, ok := t["mcp_servers"].(map[string]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(servers))
	for k := range servers {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []mcpEntry
	for _, name := range names {
		s, ok := servers[name].(map[string]any)
		if !ok {
			continue
		}
		e := mcpEntry{name: name, command: jsonStr(s["command"]), url: jsonStr(s["url"]),
			args: jsonStrList(s["args"]), env: jsonStrMap(s["env"]), headers: jsonStrMap(s["http_headers"])}
		if l, ok := s["env_vars"].([]any); ok {
			for _, x := range l {
				switch v := x.(type) {
				case string:
					e.envNames = append(e.envNames, v)
				case map[string]any:
					if n := jsonStr(v["name"]); n != "" {
						e.envNames = append(e.envNames, n)
					}
				}
			}
		}
		if n := jsonStr(s["bearer_token_env_var"]); n != "" {
			e.authHint = true
			e.envNames = append(e.envNames, n)
		}
		if h, ok := s["env_http_headers"].(map[string]any); ok && len(h) > 0 {
			e.authHint = true
		}
		if en, ok := s["enabled"].(bool); ok && !en {
			e.disabled = true
		}
		out = append(out, e)
	}
	return out
}

// mcpAnalyze turns an entry into the record that leaves the machine. Every
// value it looks at is used for a shape check and then goes out of scope with
// the entry; nothing but names and classes is copied into the result.
func mcpAnalyze(e mcpEntry) mcpServerObs {
	o := mcpServerObs{Name: truncate(e.name, mcpNameMax), Disabled: e.disabled}
	o.Transport = mcpTransport(e)
	for k := range e.env {
		o.EnvNames = append(o.EnvNames, k)
	}
	o.EnvNames = append(o.EnvNames, e.envNames...)
	o.EnvNames = dedupeStrings(o.EnvNames)
	sort.Strings(o.EnvNames)
	if len(o.EnvNames) > mcpMaxEnvNames {
		o.EnvNames = o.EnvNames[:mcpMaxEnvNames]
	}
	for i, n := range o.EnvNames {
		o.EnvNames[i] = truncate(n, mcpNameMax)
	}
	for k, v := range e.env {
		if secretShaped(k, v) {
			o.SecretInPlaintext = true
		}
	}
	headerAuth := false
	for k, v := range e.headers {
		if secretShaped(k, v) {
			o.SecretInPlaintext = true
		}
		if mcpAuthHeader(k) {
			headerAuth = true
		}
	}
	args, argSecret := redactSecretArgs(e.args)
	if argSecret {
		o.SecretInPlaintext = true
	}
	if e.command != "" {
		// A file may put the whole command line in command; it is redacted
		// word by word like the arguments.
		cmd, cmdSecret := redactSecretArgs(strings.Fields(e.command))
		if cmdSecret {
			o.SecretInPlaintext = true
		}
		o.Command = truncate(strings.Join(append(cmd, args...), " "), mcpCommandMax)
		o.PackageSource, o.PackageName, o.PackagePinned = mcpPackage(e.command, e.args)
		o.matchSub, o.matchBase = mcpMatchKey(e.command, e.args, o.PackageName)
		o.PackageName = truncate(o.PackageName, mcpNameMax)
	}
	if o.Transport == "stdio" {
		o.Locality, o.AuthConfigured, o.BindClass = mcpLocalProcess, mcpNotApplicable, mcpNotApplicable
		return o
	}
	o.BindClass = mcpUnknown
	o.AuthConfigured = mcpUnknown
	o.Locality = mcpUnknown
	if e.url != "" {
		host, urlSecret, urlAuth := mcpURLFacts(e.url)
		o.URLHost = truncate(host, mcpHostMax)
		o.Locality = hostLocality(host)
		if urlSecret {
			o.SecretInPlaintext = true
		}
		if urlAuth {
			headerAuth = true
		}
	}
	if headerAuth || e.authHint {
		o.AuthConfigured = ownerYes
	}
	return o
}

// mcpTransport is the declared type, or what the entry's shape implies.
func mcpTransport(e mcpEntry) string {
	switch strings.ToLower(strings.TrimSpace(e.typ)) {
	case "stdio":
		return "stdio"
	case "http", "streamable-http", "streamablehttp", "streamable_http":
		return "http"
	case "sse":
		return "sse"
	case "ws", "websocket":
		return "websocket"
	case "":
	default:
		return mcpUnknown
	}
	switch {
	case e.command != "":
		return "stdio"
	case e.url == "":
		return mcpUnknown
	}
	u, err := url.Parse(e.url)
	if err != nil {
		return mcpUnknown
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss":
		return "websocket"
	}
	if strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/sse") {
		return "sse"
	}
	return "http"
}

// mcpURLFacts: the URL's host, whether credentials sit in it (a password in
// the userinfo, or a secret-named query parameter with a value), and whether
// that amounts to authentication being configured. The URL itself is not
// kept: its path and query can carry a token.
func mcpURLFacts(raw string) (host string, secret bool, auth bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, false
	}
	host = strings.ToLower(u.Hostname())
	if u.User != nil {
		if _, has := u.User.Password(); has {
			secret, auth = true, true
		}
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			if secretName(k) && v != "" && !isReference(v) {
				secret, auth = true, true
			}
		}
	}
	return host, secret, auth
}

// hostLocality classes a URL host without resolving it. Resolving a name is
// a network request, which this file does not make, so a name is classed
// by its form: loopback names and addresses, private and link-local
// addresses, and names no public resolver answers (one label, .local,
// .internal, .lan, .home.arpa) are local; anything else is remote.
func hostLocality(host string) string {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	switch {
	case h == "":
		return mcpUnknown
	case h == "localhost" || strings.HasSuffix(h, ".localhost"):
		return "loopback"
	}
	if ip := net.ParseIP(h); ip != nil {
		switch {
		case ip.IsLoopback():
			return "loopback"
		case ip.IsPrivate() || ip.IsLinkLocalUnicast():
			return "lan"
		case ip.IsUnspecified():
			return "loopback"
		}
		return "remote"
	}
	if !strings.Contains(h, ".") {
		return "lan"
	}
	for _, suffix := range []string{".local", ".internal", ".lan", ".home.arpa"} {
		if strings.HasSuffix(h, suffix) {
			return "lan"
		}
	}
	return "remote"
}

// mcpAuthHeader: a header whose name carries a credential.
func mcpAuthHeader(name string) bool {
	n := strings.ToLower(name)
	return n == "authorization" || n == "cookie" || n == "proxy-authorization" || secretName(n)
}

// ── secrets: the shape, never the value ─────────────────────────────────────

// secretPrefixes are the shapes of credentials whose issuers publish a fixed
// prefix: Anthropic and OpenAI keys, GitHub tokens, Slack tokens, AWS access
// key ids, Google API keys, GitLab tokens, Hugging Face and npm tokens, JWTs,
// and PEM private keys.
var secretPrefixes = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(?:` +
	`sk-ant-[A-Za-z0-9_-]{16,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|` +
	`gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|` +
	`xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|` +
	`glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|` +
	`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|-----BEGIN [A-Z ]*PRIVATE KEY-----)`)

// secretNameRe: a variable, header or flag whose name says it holds a secret.
var secretNameRe = regexp.MustCompile(`(?i)(key|token|secret|passw|pwd|credential|auth|bearer|cookie|session)`)

func secretName(name string) bool { return secretNameRe.MatchString(name) }

// isReference: the value names where the secret comes from (${env:X},
// ${input:x}, $X, %X%) rather than holding it.
func isReference(v string) bool {
	v = strings.TrimSpace(v)
	return strings.Contains(v, "${") || strings.HasPrefix(v, "$") ||
		(len(v) > 2 && strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%"))
}

// secretShaped answers whether one name/value pair holds a secret in plain
// text: the value has a known credential's shape, or the name says secret and
// the value is a literal long enough to be one. The value is not returned or
// kept; the caller gets a bool.
func secretShaped(name, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || isReference(v) {
		return false
	}
	if secretPrefixes.MatchString(v) {
		return true
	}
	if strings.HasPrefix(strings.ToLower(v), "bearer ") || strings.HasPrefix(strings.ToLower(v), "basic ") {
		rest := strings.TrimSpace(v[strings.IndexByte(v, ' ')+1:])
		return len(rest) >= 8 && !isReference(rest)
	}
	if !secretName(name) || len(v) < 8 {
		return false
	}
	// A path or a plain URL under a secret-sounding name (a key FILE, an
	// auth SERVER) is where a secret lives, not the secret.
	if filepath.IsAbs(v) || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "./") {
		return false
	}
	if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" {
		return false
	}
	return true
}

// isPureReference: the whole value is one ${...} reference (${VAR},
// ${env:VAR}, ${input:id}), which the client expands and which names where
// the secret comes from. Only that form is kept on a redacted command line:
// a bare $NAME is passed through literally by clients that start a server
// without a shell, so it may well be the secret itself.
func isPureReference(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") && strings.Count(v, "${") == 1 &&
		strings.IndexByte(v, '}') == len(v)-1
}

// redactSecretArgs replaces every argument that holds a secret with
// mcpRedacted: one with a credential's shape, the value after or inside a
// flag whose name says secret, a NAME=value whose name does, a header
// argument (Authorization: ..., X-Api-Key: ...), and the userinfo, path and
// query of a URL. found reports whether a value matched a secret's shape;
// redaction itself is wider than that, because a value that does not look
// like a secret can still be one.
func redactSecretArgs(args []string) (out []string, found bool) {
	out = make([]string, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flag, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
			if hasVal {
				v, f := redactValue(flag, val)
				out[i], found = a[:len(a)-len(val)]+v, found || f
				continue
			}
			out[i] = a
			if secretName(flag) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				v, f := redactValue(flag, args[i+1])
				out[i+1], found = v, found || f
				i++
			}
			continue
		}
		v, f := redactValue("", a)
		out[i], found = v, found || f
	}
	return out, found
}

// redactValue is one value with whatever secret it carries replaced. name is
// the flag or variable it was given under, "" for a positional argument.
func redactValue(name, v string) (string, bool) {
	if v == "" || isPureReference(v) {
		return v, false
	}
	if secretPrefixes.MatchString(v) {
		return mcpRedacted, true
	}
	if secretName(name) {
		return mcpRedacted, secretShaped(name, v)
	}
	if low := strings.ToLower(v); strings.HasPrefix(low, "bearer ") || strings.HasPrefix(low, "basic ") {
		return mcpRedacted, secretShaped(name, v)
	}
	if i := strings.Index(v, "://"); i > 0 && !strings.ContainsAny(v[:i], " =:") {
		return redactURL(v)
	}
	if k, val, ok := strings.Cut(v, "="); ok && k != "" && !strings.ContainsAny(k, " /\\:") {
		r, f := redactValue(k, val)
		return k + "=" + r, f
	}
	if k, val, ok := strings.Cut(v, ":"); ok && k != "" && !strings.ContainsAny(k, " /\\") && mcpAuthHeader(k) {
		val = strings.TrimSpace(val)
		rest := val
		if low := strings.ToLower(rest); strings.HasPrefix(low, "bearer ") || strings.HasPrefix(low, "basic ") {
			rest = strings.TrimSpace(rest[strings.IndexByte(rest, ' ')+1:])
		}
		if rest == "" || isPureReference(rest) {
			return v, false
		}
		return k + ": " + mcpRedacted, secretShaped(k, val)
	}
	return v, false
}

// redactURL keeps a URL's scheme and host and replaces the rest: userinfo
// carries credentials, and a path or query can carry a token as easily as a
// named parameter does. found: a password, a secret-shaped user, or a
// secret-named query parameter with a value.
func redactURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return mcpRedacted, secretPrefixes.MatchString(raw)
	}
	_, found, _ := mcpURLFacts(raw)
	out := u.Scheme + "://"
	if u.User != nil {
		out += mcpRedacted + "@"
		if secretPrefixes.MatchString(u.User.Username()) {
			found = true
		}
	}
	out += truncate(u.Host, mcpHostMax)
	if strings.Trim(u.EscapedPath(), "/") != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		out += "/" + mcpRedacted
	}
	return out, found
}

// ── packages: where the server's code comes from, and whether it is pinned ──

var (
	exactSemver = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	exactPEP440 = regexp.MustCompile(`^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$`)
)

// npm flags that take a value, so the value is not mistaken for the package.
var npxValueFlags = map[string]bool{"-p": true, "--package": true, "--registry": true,
	"--cache": true, "--prefix": true, "-c": true, "--call": true, "--userconfig": true}

// uvx flags that take a value; --from names the package itself.
var uvxValueFlags = map[string]bool{"--from": true, "--with": true, "-w": true, "--python": true,
	"-p": true, "--index": true, "--index-url": true, "--extra-index-url": true,
	"--with-requirements": true, "--constraint": true, "-c": true}

// docker run flags that take a value (the common ones a server entry uses).
var dockerValueFlags = map[string]bool{"-e": true, "--env": true, "--env-file": true, "-v": true,
	"--volume": true, "--mount": true, "--name": true, "--network": true, "--net": true,
	"-p": true, "--publish": true, "-w": true, "--workdir": true, "-u": true, "--user": true,
	"--entrypoint": true, "-l": true, "--label": true, "--platform": true, "--pull": true,
	"--memory": true, "-m": true, "--cpus": true, "--add-host": true, "--cap-add": true,
	"--cap-drop": true, "--security-opt": true, "--hostname": true, "-h": true, "--init-path": true}

// mcpPackage names where a stdio server's code comes from.
func mcpPackage(command string, args []string) (source, name, pinned string) {
	base := runnerBase(command)
	switch {
	case base == "npx" || base == "bunx" || base == "pnpx" ||
		((base == "pnpm" || base == "yarn") && len(args) > 0 && args[0] == "dlx") ||
		(base == "npm" && len(args) > 0 && args[0] == "exec"):
		if base == "pnpm" || base == "yarn" || base == "npm" {
			args = args[1:]
		}
		spec := firstPositional(args, npxValueFlags, map[string]bool{"-p": true, "--package": true})
		n, ver := splitNPMSpec(spec)
		return "npx", n, pinnedWord(ver, exactSemver, spec)
	case base == "uvx" || (base == "uv" && len(args) > 1 && args[0] == "tool" && args[1] == "run"):
		if base == "uv" {
			args = args[2:]
		}
		spec := firstPositional(args, uvxValueFlags, map[string]bool{"--from": true})
		n, ver := splitPySpec(spec)
		return "uvx", n, pinnedWord(ver, exactPEP440, spec)
	case base == "pipx" && len(args) > 0 && args[0] == "run":
		spec := firstPositional(args[1:], map[string]bool{"--spec": true, "--python": true}, map[string]bool{"--spec": true})
		n, ver := splitPySpec(spec)
		return "pip", n, pinnedWord(ver, exactPEP440, spec)
	case base == "docker" || base == "podman":
		i := 0
		for i < len(args) && args[i] != "run" {
			i++
		}
		if i == len(args) {
			return "docker", "", mcpUnknown
		}
		image := firstPositional(args[i+1:], dockerValueFlags, nil)
		n, digest := splitImage(image)
		if image == "" {
			return "docker", "", mcpUnknown
		}
		return "docker", n, yesNo(digest)
	case interpreters[base]:
		// node server.js, python -m pkg: the code is a script or module on
		// disk, not a package the command line names.
		return mcpUnknown, "", mcpUnknown
	}
	return "binary", "", mcpUnknown
}

// runnerBase is binBase with the Windows script suffixes dropped too: npm
// installs npx as npx.cmd there, and a config names it either way.
func runnerBase(s string) string {
	b := binBase(s)
	for _, suf := range []string{".cmd", ".bat", ".ps1"} {
		b = strings.TrimSuffix(b, suf)
	}
	return b
}

// firstPositional is the first argument that is not a flag or a flag's value.
// A flag in pick names the package itself, and its value is returned.
func firstPositional(args []string, valueFlags, pick map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if f, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(a, "-") {
			if pick[f] {
				return v
			}
			continue
		}
		if pick[a] && i+1 < len(args) {
			return args[i+1]
		}
		if valueFlags[a] {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// splitNPMSpec splits "@scope/name@1.2.3" or "name@^1" into name and version.
func splitNPMSpec(spec string) (name, version string) {
	if spec == "" {
		return "", ""
	}
	if strings.Contains(spec, "://") {
		// git+https://user:token@host/..., a tarball URL: not a registry
		// name, and its userinfo can carry a credential.
		n, _ := redactURL(spec)
		return n, ""
	}
	at := strings.LastIndexByte(spec, '@')
	if at <= 0 {
		return spec, ""
	}
	return spec[:at], spec[at+1:]
}

// splitPySpec splits "name==1.2", "name@1.2" or "name>=1" into name and the
// exact version when the spec pins one ("" otherwise, with a range kept as a
// non-matching version so it reads as not pinned).
func splitPySpec(spec string) (name, version string) {
	if strings.Contains(spec, "://") {
		n, _ := redactURL(spec)
		return n, ""
	}
	if i := strings.Index(spec, "=="); i > 0 {
		return spec[:i], spec[i+2:]
	}
	if i := strings.IndexByte(spec, '@'); i > 0 {
		return spec[:i], spec[i+1:]
	}
	if i := strings.IndexAny(spec, "<>~!="); i > 0 {
		return spec[:i], spec[i:]
	}
	return spec, ""
}

// splitImage splits an image reference into its name and whether it is
// pinned by digest. A tag can be moved to other content; only a digest
// cannot, so only a digest counts as pinned.
func splitImage(ref string) (name string, digest bool) {
	if i := strings.Index(ref, "@sha256:"); i > 0 {
		return ref[:i], true
	}
	slash := strings.LastIndexByte(ref, '/')
	if c := strings.LastIndexByte(ref, ':'); c > slash {
		return ref[:c], false
	}
	return ref, false
}

// pinnedWord: yes for an exact version, no for a range, a tag or none, and
// unknown when the spec is a path, a URL or a git reference.
func pinnedWord(version string, exact *regexp.Regexp, spec string) string {
	if spec == "" || strings.ContainsAny(spec, `/\`) && !strings.HasPrefix(spec, "@") ||
		strings.Contains(spec, ":") {
		return mcpUnknown
	}
	return yesNo(exact.MatchString(version))
}

// mcpMatchKey is what finds this server in a process list: the package name
// for a packaged server, the script for an interpreter, the program's
// basename otherwise.
func mcpMatchKey(command string, args []string, pkg string) (sub, base string) {
	if pkg != "" {
		return strings.ToLower(pkg), ""
	}
	b := runnerBase(command)
	if interpreters[b] {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				return strings.ToLower(a), ""
			}
		}
		return "", ""
	}
	return "", b
}

// ── correlation with the process list ───────────────────────────────────────

// mcpProc is one process as the platform enumerator saw it. Argv is empty
// when the platform did not read this process's command line (Windows reads
// it only for candidates); such a process still carries its parent link.
type mcpProc struct {
	PID  int
	PPID int
	Argv []string
}

// mcpWantedBases is the program basenames whose command lines the Windows
// enumerator must read: every interpreter and package runner, plus every
// program a declared server names.
func mcpWantedBases(declared []mcpServerObs) map[string]bool {
	want := map[string]bool{"docker": true, "podman": true, "pipx": true, "pnpm": true, "yarn": true,
		"npm": true, "bunx": true, "pnpx": true}
	for b := range interpreters {
		want[b] = true
	}
	for _, d := range declared {
		if d.matchBase != "" {
			want[d.matchBase] = true
		}
	}
	return want
}

// correlateMCP sets running_state on every declared server and adds the
// servers that are running with no declaration. procsOK false means the
// process list could not be read, and then nothing is guessed: every local
// server reads unknown and no undeclared server is reported.
func correlateMCP(declared []mcpServerObs, procs []mcpProc, procsOK bool) []mcpServerObs {
	byPID := map[int]mcpProc{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	// Direct matches: a process whose command line names a declared server.
	owner := map[int][]int{} // pid -> indexes into declared
	for pid, p := range byPID {
		if len(p.Argv) == 0 {
			continue
		}
		low := strings.ToLower(strings.Join(p.Argv, " "))
		for i, d := range declared {
			if d.Transport != "stdio" {
				continue
			}
			if (d.matchSub != "" && strings.Contains(low, d.matchSub)) ||
				(d.matchBase != "" && binBase(p.Argv[0]) == d.matchBase) {
				owner[pid] = append(owner[pid], i)
			}
		}
	}
	// A package runner starts the server as a child (npx -> node .../bin/x),
	// and the child is the same server: it inherits its parent's match.
	inherit := func(pid int) []int {
		seen := map[int]bool{}
		for hop := 0; hop < maxHelperHops; hop++ {
			p, ok := byPID[pid]
			if !ok || seen[pid] {
				return nil
			}
			seen[pid] = true
			if m := owner[p.PPID]; len(m) > 0 {
				return m
			}
			pid = p.PPID
		}
		return nil
	}
	matched := map[int][]int{}
	for pid := range byPID {
		if m := owner[pid]; len(m) > 0 {
			matched[pid] = m
		} else if m := inherit(pid); len(m) > 0 {
			matched[pid] = m
		}
	}
	pids := make([][]int, len(declared))
	for pid, idx := range matched {
		for _, i := range idx {
			pids[i] = append(pids[i], pid)
		}
	}
	out := make([]mcpServerObs, 0, len(declared))
	for i, d := range declared {
		switch {
		case d.Transport != "stdio" && (d.Locality == "remote" || d.Locality == "lan"):
			d.RunningState = mcpStateNotLocal
		case d.Transport != "stdio" || !procsOK:
			d.RunningState = mcpStateUnknown
		case len(pids[i]) > 0:
			d.RunningState = mcpStateRunning
			sort.Ints(pids[i])
			if len(pids[i]) > mcpMaxPIDs {
				pids[i] = pids[i][:mcpMaxPIDs]
			}
			d.PIDs = pids[i]
		default:
			d.RunningState = mcpStateIdle
		}
		out = append(out, d)
	}
	if !procsOK {
		return out
	}
	// Undeclared: a process that looks like a tool server, matched by no
	// declaration, and not itself the child of one already reported.
	shadow := map[int]bool{}
	for pid, p := range byPID {
		if len(matched[pid]) == 0 && looksLikeMCPServer(p.Argv) {
			shadow[pid] = true
		}
	}
	var shadowPIDs []int
	for pid := range shadow {
		if !shadowAncestor(byPID, shadow, pid) {
			shadowPIDs = append(shadowPIDs, pid)
		}
	}
	sort.Ints(shadowPIDs)
	for _, pid := range shadowPIDs {
		if len(out) >= mcpMaxServers {
			break
		}
		p := byPID[pid]
		args, secret := redactSecretArgs(p.Argv[1:])
		src, name, pinned := mcpPackage(p.Argv[0], p.Argv[1:])
		name = truncate(name, mcpNameMax)
		out = append(out, mcpServerObs{Name: name, Transport: mcpUnknown, Locality: mcpLocalProcess,
			Command:       truncate(strings.Join(append([]string{p.Argv[0]}, args...), " "), mcpCommandMax),
			PackageSource: src, PackageName: name, PackagePinned: pinned, SecretInPlaintext: secret,
			AuthConfigured: mcpNotApplicable, BindClass: mcpUnknown,
			RunningState: mcpStateShadow, PIDs: []int{pid}})
	}
	return out
}

func shadowAncestor(byPID map[int]mcpProc, shadow map[int]bool, pid int) bool {
	seen := map[int]bool{pid: true}
	for hop := 0; hop < maxHelperHops; hop++ {
		p, ok := byPID[pid]
		if !ok {
			return false
		}
		if shadow[p.PPID] {
			return true
		}
		if seen[p.PPID] {
			return false
		}
		seen[p.PPID] = true
		pid = p.PPID
	}
	return false
}

// mcpNPMScope is the npm scope the protocol's reference servers are published
// under; a command line naming it is running one of them.
const mcpNPMScope = "@modelcontextprotocol/"

// looksLikeMCPServer: a process whose command line names a tool server — a
// program or package whose name carries "mcp" as a word (github-mcp-server,
// mcp-server-git, fastmcp, mcp-remote) or the reference servers' npm scope.
// Only for a program that runs servers (an interpreter or package runner) or
// one whose own name carries the word: an agent started with --mcp-config is
// a client, and flags are never read. Soft, like every process signal here.
func looksLikeMCPServer(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	if _, isAgent := matchAgentSignature(argv); isAgent {
		return false
	}
	base := runnerBase(argv[0])
	if mcpWord(base) {
		return true
	}
	if !interpreters[base] && base != "docker" && base != "podman" && base != "npm" && base != "pipx" {
		return false
	}
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		low := strings.ToLower(a)
		if strings.Contains(low, mcpNPMScope) {
			return true
		}
		for _, part := range strings.FieldsFunc(low, func(r rune) bool {
			return r == '/' || r == '\\' || r == '@' || r == ':' || r == '='
		}) {
			if mcpWord(part) {
				return true
			}
		}
	}
	return false
}

// mcpWord: "mcp" as a whole word inside one name, split on - _ and .
func mcpWord(s string) bool {
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
		if w == "mcp" || w == "fastmcp" {
			return true
		}
	}
	return false
}

// ── JSON with comments, and the subset of TOML Codex writes ─────────────────

// stripJSONC removes // and /* */ comments and trailing commas outside
// strings, so Zed's and VS Code's files parse as JSON. Plain JSON passes
// through unchanged.
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case c == '}' || c == ']':
			// Drop a comma that only whitespace separates from this close.
			j := len(out) - 1
			for j >= 0 && (out[j] == ' ' || out[j] == '\t' || out[j] == '\n' || out[j] == '\r') {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// parseTOMLSubset reads the part of TOML a Codex config uses: [table] and
// [a."b c"] headers, key = value with dotted and quoted keys, basic and
// literal strings (and their multi-line forms), arrays (across lines),
// inline tables, and bare scalars kept as their text (true/false become
// booleans). [[array of tables]] sections are skipped: Codex keeps no
// server there. A line it cannot read is an error for the whole file, which
// counts as unparsed rather than silently half-read.
func parseTOMLSubset(src string) (map[string]any, error) {
	root := map[string]any{}
	cur := root
	skipping := false
	p := &tomlParser{s: src}
	for {
		p.skipSpaceAndComments(true)
		if p.eof() {
			return root, nil
		}
		if p.peek() == '[' {
			if strings.HasPrefix(p.s[p.i:], "[[") {
				skipping = true
				p.skipLine()
				continue
			}
			p.i++
			keys, err := p.keyPath(']')
			if err != nil {
				return nil, err
			}
			p.i++ // ]
			skipping = false
			cur = root
			for _, k := range keys {
				next, ok := cur[k].(map[string]any)
				if !ok {
					next = map[string]any{}
					cur[k] = next
				}
				cur = next
			}
			p.skipLine()
			continue
		}
		keys, err := p.keyPath('=')
		if err != nil {
			return nil, err
		}
		p.i++ // =
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if !skipping {
			setDotted(cur, keys, v)
		}
		p.skipLine()
	}
}

func setDotted(m map[string]any, keys []string, v any) {
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	m[keys[len(keys)-1]] = v
}

type tomlParser struct {
	s     string
	i     int
	depth int // arrays and inline tables open around the current value
}

var errTOML = errors.New("toml: cannot read this line")

func (p *tomlParser) eof() bool  { return p.i >= len(p.s) }
func (p *tomlParser) peek() byte { return p.s[p.i] }

func (p *tomlParser) skipSpaceAndComments(newlines bool) {
	for !p.eof() {
		c := p.peek()
		switch {
		case c == ' ' || c == '\t' || c == '\r' || (newlines && c == '\n'):
			p.i++
		case c == '#':
			for !p.eof() && p.peek() != '\n' {
				p.i++
			}
		default:
			return
		}
	}
}

// skipLine moves past the rest of the line (trailing space and a comment).
func (p *tomlParser) skipLine() {
	for !p.eof() && p.peek() != '\n' {
		p.i++
	}
}

// keyPath reads a dotted key up to (not past) the stop byte.
func (p *tomlParser) keyPath(stop byte) ([]string, error) {
	var keys []string
	for {
		p.skipSpaceAndComments(false)
		if p.eof() {
			return nil, errTOML
		}
		var k string
		switch p.peek() {
		case '"', '\'':
			s, err := p.str()
			if err != nil {
				return nil, err
			}
			k = s
		default:
			st := p.i
			for !p.eof() && (isBareKeyByte(p.peek())) {
				p.i++
			}
			if p.i == st {
				return nil, errTOML
			}
			k = p.s[st:p.i]
		}
		keys = append(keys, k)
		p.skipSpaceAndComments(false)
		if p.eof() {
			return nil, errTOML
		}
		switch p.peek() {
		case '.':
			p.i++
		case stop:
			return keys, nil
		default:
			return nil, errTOML
		}
	}
}

func isBareKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func (p *tomlParser) value() (any, error) {
	p.skipSpaceAndComments(false)
	if p.eof() {
		return nil, errTOML
	}
	switch p.peek() {
	case '"', '\'':
		return p.str()
	case '[', '{':
		// Each level is a stack frame; a crafted file a million deep must
		// not walk the stack that far.
		if p.depth >= mcpMaxNesting {
			return nil, errTOML
		}
		p.depth++
		defer func() { p.depth-- }()
	}
	switch p.peek() {
	case '[':
		p.i++
		var out []any
		for {
			p.skipSpaceAndComments(true)
			if p.eof() {
				return nil, errTOML
			}
			if p.peek() == ']' {
				p.i++
				return out, nil
			}
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			p.skipSpaceAndComments(true)
			if !p.eof() && p.peek() == ',' {
				p.i++
			}
		}
	case '{':
		p.i++
		out := map[string]any{}
		for {
			p.skipSpaceAndComments(false)
			if p.eof() {
				return nil, errTOML
			}
			if p.peek() == '}' {
				p.i++
				return out, nil
			}
			keys, err := p.keyPath('=')
			if err != nil {
				return nil, err
			}
			p.i++
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			setDotted(out, keys, v)
			p.skipSpaceAndComments(false)
			if !p.eof() && p.peek() == ',' {
				p.i++
			}
		}
	}
	st := p.i
	for !p.eof() && !strings.ContainsRune(",]}\n#", rune(p.peek())) {
		p.i++
	}
	raw := strings.TrimSpace(p.s[st:p.i])
	switch raw {
	case "":
		return nil, errTOML
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return raw, nil
}

// str reads a basic ("...", with escapes) or literal ('...') string, either
// in its one-line or its triple-quoted multi-line form.
func (p *tomlParser) str() (string, error) {
	q := p.peek()
	triple := strings.Repeat(string(q), 3)
	if strings.HasPrefix(p.s[p.i:], triple) {
		p.i += 3
		if strings.HasPrefix(p.s[p.i:], "\n") {
			p.i++
		} else if strings.HasPrefix(p.s[p.i:], "\r\n") {
			p.i += 2
		}
		end := strings.Index(p.s[p.i:], triple)
		if end < 0 {
			return "", errTOML
		}
		body := p.s[p.i : p.i+end]
		p.i += end + 3
		if q == '"' {
			return tomlUnescape(body), nil
		}
		return body, nil
	}
	p.i++
	var b strings.Builder
	for !p.eof() {
		c := p.peek()
		switch {
		case c == '\n':
			return "", errTOML
		case c == q:
			p.i++
			if q == '"' {
				return tomlUnescape(b.String()), nil
			}
			return b.String(), nil
		case c == '\\' && q == '"' && p.i+1 < len(p.s):
			b.WriteByte(c)
			b.WriteByte(p.s[p.i+1])
			p.i += 2
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return "", errTOML
}

// tomlUnescape decodes the escapes of a TOML basic string: \\ \" \b \t
// \n \f \r and \uXXXX / \UXXXXXXXX. An escape it does not know is kept
// as written.
func tomlUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case '\\', '"':
			b.WriteByte(s[i])
		case 'b':
			b.WriteByte('\b')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'f':
			b.WriteByte('\f')
		case 'r':
			b.WriteByte('\r')
		case 'u', 'U':
			n := 4
			if s[i] == 'U' {
				n = 8
			}
			if i+n < len(s) {
				if r, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32); err == nil {
					b.WriteRune(rune(r))
					i += n
					continue
				}
			}
			b.WriteByte('\\')
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
