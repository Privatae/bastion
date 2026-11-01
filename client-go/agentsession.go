package main

// agentsession.go — what an agent is DOING, not only that it runs.
//
// "Seven Claude Code sessions on this machine" tells the owner nothing (the
// owner, 2026-10-30). Each agent gets, beside the detection facts (agents.go):
//
//   - the folder it works in, that folder's git branch, how long it has run,
//     and what it is running right now (its child commands, secrets redacted)
//     — read from the operating system, for every agent;
//   - what the agent says about itself, read from the agent's OWN state files
//     on this machine: for Claude Code its per-process session record
//     (~/.claude/sessions/<pid>.json: the session's name, whether it is idle,
//     working, or waiting for the person and on what) and the tail of its
//     transcript (the title Claude Code keeps for the session, its permission
//     mode, the last prompt).
//
// No model is asked anything. The title is the agent's own, kept by the agent.
//
// WHAT IS NEVER READ: a process's environment (where tokens live), the key
// files beside the session records, and any transcript content other than
// the title, the permission mode, the branch and the last prompt.
//
// TRUST. A session record is written by the agent, so it is the agent's
// description of itself: an agent can name itself anything. It is shown as
// what the agent says (json "self_reported"), never as what the bastion
// found, and the detection facts stay the bastion's own. A record is used only
// if it names this pid AND, where the platform can tell, this process's start
// time (procStart against the kernel's), so a record left by a process that
// has exited cannot be pinned on a new one that got its number.
//
// WHERE IT GOES. This is built for the console and the command line on this
// machine. It is not in agentObs, so it is not in the heartbeat: nothing here
// reaches a Host.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	sessionRecordMax  = 64 << 10  // a session record is a few hundred bytes
	transcriptTailMax = 400 << 10 // the title, mode and branch recur; the tail holds the latest
	titleMax          = 120
	promptMax         = 240
	nameMax           = 60
	runningNowMax     = 3
	runningNowWidth   = 100
)

// agentSelf is what the agent says about itself.
type agentSelf struct {
	Source         string `json:"source"`
	Verified       bool   `json:"verified"` // the record named this pid and its start time
	SessionID      string `json:"session_id,omitempty"`
	Name           string `json:"name,omitempty"`
	Title          string `json:"title,omitempty"`
	Status         string `json:"status,omitempty"`
	WaitingFor     string `json:"waiting_for,omitempty"`
	Background     bool   `json:"background,omitempty"`
	PermissionMode string `json:"permission_mode,omitempty"`
	LastActive     string `json:"last_active,omitempty"`
	LastPrompt     string `json:"last_prompt,omitempty"`
}

// agentView is one agent as the console and `agents` show it.
type agentView struct {
	agentObs
	// Role separates a session from the agent's own supervisor process
	// ("service"): Claude Code's background service starts background
	// sessions and is not one, and counting it as one is how a machine with
	// five sessions read as six.
	Role       string   `json:"role"`
	Folder     string   `json:"folder,omitempty"`
	GitBranch  string   `json:"git_branch,omitempty"`
	StartedAt  string   `json:"started_at,omitempty"`
	RunningNow []string `json:"running_now,omitempty"`
	// ToolServers are the long-running children the agent started with
	// itself (its MCP servers, by their program names), kept apart from
	// RunningNow so the commands of this moment are not buried under them.
	ToolServers []string   `json:"tool_servers,omitempty"`
	Self        *agentSelf `json:"self_reported,omitempty"`
}

// Seams: the platform's answers, so the views are testable from fixtures.
var (
	uidForUserFn    = uidForUser
	procCwdFn       = osProcCwd
	procStartedFn   = osProcStarted
	homeForUserFn   = homeForUser
	procCmdArgsFn   = osProcCmdArgs
	sessionNowFn    = time.Now
	agentViewsLimit = 200
)

// uidForUser is the account number session files must belong to; -1 (no
// check) where accounts are not numbers (Windows). ok is false when the
// account cannot be resolved, and then nothing of the agent's is read.
func uidForUser(name string) (int, bool) {
	if runtime.GOOS == "windows" {
		return -1, true
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(u.Uid)
	return n, err == nil
}

func homeForUser(name string) string {
	if name == "" {
		return ""
	}
	u, err := user.Lookup(name)
	if err != nil {
		return ""
	}
	return u.HomeDir
}

// buildAgentViews turns one scan into what a person reads.
func buildAgentViews(agents []agentObs, tree map[int]int) []agentView {
	children := map[int][]int{}
	for c, p := range tree {
		children[p] = append(children[p], c)
	}
	out := make([]agentView, 0, len(agents))
	for i, a := range agents {
		if i >= agentViewsLimit {
			break
		}
		v := agentView{agentObs: a, Role: "session"}
		if a.Signature == "claude-code" && isClaudeCodeService(a.Cmdline) {
			v.Role = "service"
		}
		v.Folder = procCwdFn(a.PID)
		v.GitBranch = gitBranchOf(v.Folder)
		started, hasStart := procStartedFn(a.PID)
		if hasStart {
			v.StartedAt = started.UTC().Format(time.RFC3339)
		}
		v.RunningNow, v.ToolServers = runningNow(a.PID, children, started, hasStart)
		if a.Signature == "claude-code" && v.Role == "session" {
			if uid, ok := uidForUserFn(a.User); ok {
				v.Self = claudeCodeSelf(a.PID, homeForUserFn(a.User), uid)
			}
		}
		out = append(out, v)
	}
	return out
}

// isClaudeCodeService is Claude Code's background service, `claude daemon run`.
func isClaudeCodeService(cmdline string) bool {
	f := strings.Fields(cmdline)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "daemon" && f[i+1] == "run" {
			return true
		}
	}
	return false
}

var sessionIDShape = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)

// claudeCodeSelf reads the session record Claude Code keeps for this pid, and
// the tail of that session's transcript. nil when there is none this bastion
// can read (another account's home without root, an older Claude Code).
//
// Every file is read only if it is a regular file the agent's own account
// owns (openOwned): the daemon may run as the machine's administrator, and a
// link planted in one account's home must not make it read another's.
func claudeCodeSelf(pid int, home string, uid int) *agentSelf {
	if home == "" {
		return nil
	}
	raw := readCappedOwned(filepath.Join(home, ".claude", "sessions", strconv.Itoa(pid)+".json"), sessionRecordMax, uid)
	if raw == nil {
		return nil
	}
	var rec struct {
		PID        int    `json:"pid"`
		SessionID  string `json:"sessionId"`
		ProcStart  string `json:"procStart"`
		Kind       string `json:"kind"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		WaitingFor string `json:"waitingFor"`
		UpdatedAt  int64  `json:"updatedAt"`
	}
	if json.Unmarshal(raw, &rec) != nil || rec.PID != pid {
		return nil
	}
	id, _, idOK := procIdentity(pid)
	if idOK && rec.ProcStart != id {
		return nil // another process's record: this number has changed hands
	}
	s := &agentSelf{
		Source:     "Claude Code's session record",
		Verified:   idOK,
		Name:       cleanText(rec.Name, nameMax),
		Status:     cleanText(rec.Status, 30),
		WaitingFor: cleanText(rec.WaitingFor, 60),
		Background: rec.Kind == "bg",
	}
	if rec.UpdatedAt > 0 {
		s.LastActive = time.UnixMilli(rec.UpdatedAt).UTC().Format(time.RFC3339)
	}
	if !sessionIDShape.MatchString(rec.SessionID) {
		return s
	}
	s.SessionID = rec.SessionID
	matches, _ := filepath.Glob(filepath.Join(home, ".claude", "projects", "*", rec.SessionID+".jsonl"))
	sort.Strings(matches)
	if len(matches) == 0 {
		return s
	}
	for _, line := range tailLinesOwned(matches[0], transcriptTailMax, uid) {
		var e struct {
			Type           string `json:"type"`
			AITitle        string `json:"aiTitle"`
			PermissionMode string `json:"permissionMode"`
			LastPrompt     string `json:"lastPrompt"`
		}
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		switch e.Type {
		case "ai-title":
			if e.AITitle != "" {
				s.Title = cleanText(e.AITitle, titleMax)
			}
		case "permission-mode":
			if e.PermissionMode != "" {
				s.PermissionMode = cleanText(e.PermissionMode, 40)
			}
		case "last-prompt":
			if e.LastPrompt != "" {
				s.LastPrompt = cleanText(e.LastPrompt, promptMax)
			}
		}
	}
	return s
}

// toolServerWindow: a direct child started this soon after the agent is one
// it started with itself (an MCP server), not a command of this moment.
const toolServerWindow = 2 * time.Minute

// toolServerName is the program a tool server runs: past the interpreter
// (agents.go's table) and its flags, the base name of what it was given.
func toolServerName(args []string) string {
	name := binBase(args[0])
	if !interpreters[name] {
		return name
	}
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			return cleanText(filepath.Base(a), 60)
		}
	}
	return name
}

// runningNow is what the agent is running at this moment: the commands at
// the ends of its process tree, secrets redacted, newest pids first. The
// direct children it started with itself come back apart, as tool servers.
func runningNow(pid int, children map[int][]int, started time.Time, hasStart bool) ([]string, []string) {
	var tools []string
	// top: the agent's direct child each process descends from. A tool server
	// is often a grandchild (npx → sh → node), so it is the direct child's
	// start that says whether the agent started it with itself.
	top := map[int]int{}
	var leaves []int
	seen := map[int]bool{pid: true}
	queue := []int{pid}
	for len(queue) > 0 && len(seen) < 500 {
		p := queue[0]
		queue = queue[1:]
		kids := children[p]
		if len(kids) == 0 && p != pid {
			leaves = append(leaves, p)
		}
		for _, k := range kids {
			if !seen[k] {
				seen[k] = true
				queue = append(queue, k)
				if p == pid {
					top[k] = k
				} else {
					top[k] = top[p]
				}
			}
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(leaves)))
	var out []string
	for _, l := range leaves {
		args := splitRetitled(procCmdArgsFn(l))
		if len(args) == 0 {
			continue
		}
		if hasStart {
			if t, ok := procStartedFn(top[l]); ok && t.Sub(started) < toolServerWindow {
				tools = append(tools, toolServerName(args))
				continue
			}
		}
		if len(out) == runningNowMax {
			continue
		}
		red, _ := redactSecretArgs(args)
		red[0] = filepath.Base(red[0])
		out = append(out, cleanText(strings.Join(red, " "), runningNowWidth))
	}
	return out, countedNames(tools)
}

// splitRetitled undoes a retitled command line: a program that rewrote its
// argv as one string (a browser, a server setting its title) arrives as a
// single argument with spaces in it, and its "program" would otherwise be
// whatever follows the last slash in the whole line.
func splitRetitled(args []string) []string {
	if len(args) == 1 && strings.ContainsAny(args[0], " \t") {
		return strings.Fields(args[0])
	}
	return args
}

// countedNames sorts names and folds repeats: "chrome ×3".
func countedNames(names []string) []string {
	n := map[string]int{}
	for _, x := range names {
		n[x]++
	}
	out := make([]string, 0, len(n))
	for x, c := range n {
		if c > 1 {
			x += " ×" + strconv.Itoa(c)
		}
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// gitBranchOf reads the branch of the repository holding dir from its HEAD
// file. It runs no git: the folder is the agent's, and so is its git config.
func gitBranchOf(dir string) string {
	for i := 0; dir != "" && i < 40; i++ {
		g := filepath.Join(dir, ".git")
		if st, err := os.Lstat(g); err == nil {
			head := filepath.Join(g, "HEAD")
			if !st.IsDir() {
				// a worktree or submodule: ".git" is a file naming the real dir
				b := readCapped(g, 4096)
				rest, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
				if !ok {
					return ""
				}
				gd := strings.TrimSpace(rest)
				if !filepath.IsAbs(gd) {
					gd = filepath.Join(dir, gd)
				}
				head = filepath.Join(gd, "HEAD")
			}
			h := strings.TrimSpace(string(readCapped(head, 4096)))
			if b, ok := strings.CutPrefix(h, "ref: refs/heads/"); ok {
				return cleanText(b, 80)
			}
			if len(h) >= 12 {
				return "detached at " + h[:12]
			}
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

// readCapped reads a small file without following a final symlink or
// waiting on a pipe (openOwned, no owner check): .git/HEAD in an agent's
// folder is that account's to plant anything in.
func readCapped(path string, max int64) []byte { return readCappedOwned(path, max, -1) }

func readCappedOwned(path string, max int64, uid int) []byte {
	f, err := openOwned(path, uid)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > max {
		return nil
	}
	b := make([]byte, max)
	n, _ := f.Read(b)
	return b[:n]
}

// tailLines is the last max bytes of a file, split into whole lines.
func tailLines(path string, max int64) [][]byte { return tailLinesOwned(path, max, -1) }

func tailLinesOwned(path string, max int64, uid int) [][]byte {
	f, err := openOwned(path, uid)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	start := st.Size() - max
	if start < 0 {
		start = 0
	}
	buf := make([]byte, st.Size()-start)
	n, _ := f.ReadAt(buf, start)
	lines := bytes.Split(buf[:n], []byte("\n"))
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // the first is cut in the middle
	}
	return lines
}

// cleanText is agent-written text made safe to show: control characters out,
// whitespace collapsed, cut to max runes with an ellipsis.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
