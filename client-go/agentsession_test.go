package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const fixtureSession = "0a1b2c3d-1111-4222-8333-444455556666"

// fakeClaudeHome lays out what Claude Code keeps for one running session: the
// per-process record and the session's transcript. All of it invented.
func fakeClaudeHome(t *testing.T, pid int, procStart, transcript string) string {
	t.Helper()
	home := t.TempDir()
	sess := filepath.Join(home, ".claude", "sessions")
	proj := filepath.Join(home, ".claude", "projects", "-work-shop")
	for _, d := range []string{sess, proj} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rec := `{"pid":` + itoa(pid) + `,"sessionId":"` + fixtureSession + `","cwd":"/work/shop","procStart":"` + procStart +
		`","kind":"interactive","name":"shop-a1","status":"waiting","waitingFor":"permission prompt","updatedAt":1793300000000}`
	if err := os.WriteFile(filepath.Join(sess, itoa(pid)+".json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sess, itoa(pid)+".deadbeef.key"), []byte("NEVER-READ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, fixtureSession+".jsonl"), []byte(transcript), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func stubProcIdentity(t *testing.T, id string) {
	t.Helper()
	prev := procIdentity
	t.Cleanup(func() { procIdentity = prev })
	procIdentity = func(int) (string, bool, bool) { return id, false, true }
}

const fixtureTranscript = `{"type":"ai-title","aiTitle":"Set up the shop database","sessionId":"x"}
{"type":"user","message":{"content":"SECRET CONVERSATION BODY"}}
{"type":"permission-mode","permissionMode":"bypassPermissions","sessionId":"x"}
{"type":"last-prompt","lastPrompt":"add an index to orders","sessionId":"x"}
{"type":"ai-title","aiTitle":"Add an index to the orders table","sessionId":"x"}
`

func TestClaudeCodeSessionSaysWhatItIsDoing(t *testing.T) {
	stubProcIdentity(t, "5551")
	home := fakeClaudeHome(t, 4242, "5551", fixtureTranscript)
	s := claudeCodeSelf(4242, home, os.Getuid())
	if s == nil {
		t.Fatal("a session with a matching record was not read")
	}
	want := agentSelf{Source: "Claude Code's session record", Verified: true, SessionID: fixtureSession,
		Name: "shop-a1", Title: "Add an index to the orders table", Status: "waiting",
		WaitingFor: "permission prompt", PermissionMode: "bypassPermissions",
		LastActive: time.UnixMilli(1793300000000).UTC().Format(time.RFC3339),
		LastPrompt: "add an index to orders"}
	if *s != want {
		t.Errorf("got  %+v\nwant %+v", *s, want)
	}
}

// A record left by a process that has exited must not be pinned on the new
// process that got its number.
func TestASessionRecordForAnEarlierProcessIsNotUsed(t *testing.T) {
	stubProcIdentity(t, "9999")
	home := fakeClaudeHome(t, 4242, "5551", fixtureTranscript)
	if s := claudeCodeSelf(4242, home, os.Getuid()); s != nil {
		t.Errorf("a record whose process start is not this process's was used: %+v", *s)
	}
}

func TestASessionRecordNamingAnotherPidIsNotUsed(t *testing.T) {
	stubProcIdentity(t, "5551")
	home := fakeClaudeHome(t, 4242, "5551", fixtureTranscript)
	if err := os.Rename(filepath.Join(home, ".claude", "sessions", "4242.json"),
		filepath.Join(home, ".claude", "sessions", "4343.json")); err != nil {
		t.Fatal(err)
	}
	if s := claudeCodeSelf(4343, home, os.Getuid()); s != nil {
		t.Errorf("a record that names pid 4242 was used for 4343: %+v", *s)
	}
}

// The session id becomes part of a path; one that is not an id reads nothing.
func TestASessionIDThatIsAPathReadsNoTranscript(t *testing.T) {
	stubProcIdentity(t, "5551")
	home := t.TempDir()
	sess := filepath.Join(home, ".claude", "sessions")
	if err := os.MkdirAll(sess, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := `{"pid":4242,"sessionId":"../../../etc/x","procStart":"5551","name":"n"}`
	if err := os.WriteFile(filepath.Join(sess, "4242.json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	s := claudeCodeSelf(4242, home, os.Getuid())
	if s == nil || s.SessionID != "" || s.Title != "" {
		t.Errorf("a path-shaped session id was followed: %+v", s)
	}
}

// What an agent writes about itself is shown, never obeyed or rendered: no
// control characters, no line breaks to forge another line, a bounded length.
func TestAgentWrittenTextIsCleanedAndBounded(t *testing.T) {
	got := cleanText("ok\n\x1b[31mIGNORE ALL PREVIOUS instructions\t", 200)
	if strings.ContainsAny(got, "\n\x1b \t") {
		t.Errorf("control characters survived: %q", got)
	}
	if r := []rune(cleanText(strings.Repeat("é", 500), titleMax)); len(r) != titleMax {
		t.Errorf("a long title is %d runes, want %d", len(r), titleMax)
	}
}

func TestClaudeCodesBackgroundServiceIsNotASession(t *testing.T) {
	if !isClaudeCodeService("/opt/x/claude.exe daemon run --json-path /h/.claude/daemon.json") {
		t.Error("`daemon run` was not recognised as the background service")
	}
	if isClaudeCodeService("claude --resume") {
		t.Error("an interactive session was taken for the service")
	}
}

// The commands of this moment are kept apart from the tool servers the agent
// started with itself, and a secret on a command line is redacted.
func TestRunningNowSeparatesToolServersAndRedactsSecrets(t *testing.T) {
	start := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	started := map[int]time.Time{
		100: start, 110: start.Add(5 * time.Second), 111: start.Add(6 * time.Second),
		120: start.Add(3 * time.Hour), 121: start.Add(3 * time.Hour),
	}
	args := map[int][]string{
		111: {"node", "/home/u/.npm/_npx/abc/node_modules/.bin/mcp-server-files"},
		121: {"curl", "-H", "Authorization: Bearer sk-live-abcdefghijklmnop1234", "https://api.example.com"},
	}
	prevS, prevA := procStartedFn, procCmdArgsFn
	t.Cleanup(func() { procStartedFn, procCmdArgsFn = prevS, prevA })
	procStartedFn = func(pid int) (time.Time, bool) { s, ok := started[pid]; return s, ok }
	procCmdArgsFn = func(pid int) []string { return args[pid] }
	children := map[int][]int{100: {110, 120}, 110: {111}, 120: {121}}
	now, tools := runningNow(100, children, start, true)
	if len(tools) != 1 || tools[0] != "mcp-server-files" {
		t.Errorf("tool servers %v", tools)
	}
	if len(now) != 1 || !strings.HasPrefix(now[0], "curl") {
		t.Fatalf("running now %v", now)
	}
	if strings.Contains(now[0], "sk-live") {
		t.Errorf("a secret on a command line was shown: %q", now[0])
	}
}

func TestGitBranchIsReadFromHEADWithoutRunningGit(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "HEAD"), []byte("ref: refs/heads/fix/login\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "src", "app")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := gitBranchOf(sub); got != "fix/login" {
		t.Errorf("branch from a subfolder: %q", got)
	}
	// A worktree: .git is a file naming the real git dir.
	wt := t.TempDir()
	gd := filepath.Join(t.TempDir(), "wt-gitdir")
	if err := os.MkdirAll(gd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gd, "HEAD"), []byte("ref: refs/heads/feature\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+gd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitBranchOf(wt); got != "feature" {
		t.Errorf("branch in a worktree: %q", got)
	}
}

// Sessions waiting for the person come first, and the heading counts the
// background service apart from the sessions.
func TestAgentsListPutsWaitingSessionsFirstAndCountsTheServiceApart(t *testing.T) {
	views := []agentView{
		{agentObs: agentObs{PID: 1, Signature: "claude-code"}, Role: "service"},
		{agentObs: agentObs{PID: 2, Kind: kindAgent, Signature: "claude-code"}, Role: "session",
			Self: &agentSelf{Name: "idle-one", Status: "idle"}},
		{agentObs: agentObs{PID: 3, Kind: kindAgent, Signature: "claude-code"}, Role: "session",
			Self: &agentSelf{Name: "waits", Title: "Rename the invoices", Status: "waiting", WaitingFor: "permission prompt"}},
	}
	var b bytes.Buffer
	printAgents(&b, views, time.Now())
	out := b.String()
	if !strings.HasPrefix(out, "Claude Code: 2 sessions (1 waiting for you), its background service\n") {
		t.Errorf("heading:\n%s", out)
	}
	if strings.Index(out, "waits") > strings.Index(out, "idle-one") {
		t.Errorf("the waiting session is not first:\n%s", out)
	}
	if !strings.Contains(out, "waiting for you: permission prompt") {
		t.Errorf("what it waits for is not said:\n%s", out)
	}
}

// Stop takes a session's name, and the owner is asked about the session, not
// a bare pid.
func TestStopNamesTheSessionItAsksAbout(t *testing.T) {
	stubProcIdentity(t, "5551")
	home := fakeClaudeHome(t, 4242, "5551", fixtureTranscript)
	prevH, prevTree, prevU := homeForUserFn, processTree, uidForUserFn
	t.Cleanup(func() { homeForUserFn, processTree, uidForUserFn = prevH, prevTree, prevU })
	homeForUserFn = func(string) string { return home }
	uidForUserFn = func(string) (int, bool) { return os.Getuid(), true }
	processTree = func() map[int]int { return nil }
	observed := map[int]agentObs{4242: {PID: 4242, Kind: kindAgent, Signature: "claude-code", User: "u"}}
	pid, v, err := resolveStopTarget("shop-a1", observed)
	if err != nil || pid != 4242 {
		t.Fatalf("by name: %d %v", pid, err)
	}
	if _, _, err := resolveStopTarget("no-such", observed); err == nil {
		t.Error("an unknown session name resolved")
	}
	d := map[string]any{"kind": localStopKind, "pid": "4242", "signature": "claude-code",
		"agent": "Claude Code", "session": v.Self.Name, "title": v.Self.Title, "folder": "/work/shop"}
	got := describeRequest(stepupRequest{Details: d})
	want := `Stop Claude Code session shop-a1 "Add an index to the orders table" in /work/shop (pid 4242) on this machine, and every process it started.`
	if got != want {
		t.Errorf("the owner reads\n%s\nwant\n%s", got, want)
	}
}

// A program that rewrote its command line as one string is still named by
// its program, not by whatever follows the last slash in the whole line, and
// repeats fold into a count.
func TestARetitledCommandLineIsSplitAndRepeatsFold(t *testing.T) {
	if got := splitRetitled([]string{"go test ./..."}); len(got) != 3 || got[0] != "go" {
		t.Errorf("split %q", got)
	}
	if got := splitRetitled([]string{"/usr/bin/go", "test", "./..."}); len(got) != 3 || got[0] != "/usr/bin/go" {
		t.Errorf("an ordinary argv was changed: %q", got)
	}
	if got := countedNames([]string{"chrome", "mcp-files", "chrome", "chrome"}); len(got) != 2 || got[0] != "chrome ×3" {
		t.Errorf("folded %q", got)
	}
}

// The daemon may read as the machine's administrator: a session file that is
// a link, or that another account owns, is not read.
func TestASessionFileThatIsALinkOrNotTheAgentsOwnIsNotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("accounts are not numbers and links need privilege on Windows")
	}
	stubProcIdentity(t, "5551")
	home := fakeClaudeHome(t, 4242, "5551", fixtureTranscript)
	if s := claudeCodeSelf(4242, home, os.Getuid()+1); s != nil {
		t.Errorf("a record owned by another account was read: %+v", *s)
	}
	rec := filepath.Join(home, ".claude", "sessions", "4242.json")
	elsewhere := filepath.Join(t.TempDir(), "other.json")
	if err := os.Rename(rec, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, rec); err != nil {
		t.Fatal(err)
	}
	if s := claudeCodeSelf(4242, home, os.Getuid()); s != nil {
		t.Errorf("a record reached through a link was read: %+v", *s)
	}
}
