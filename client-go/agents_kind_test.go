package main

import (
	"os"
	"sort"
	"testing"
)

// Kind classification. The fixture below is the measured shape
// that produced the false alarm: the Claude DESKTOP app on Windows, installed
// from the Store, with its eight Chromium helpers — every one of them
// `claude.exe`, every one of them matched as "claude-code".

const winClaudeExe = `"C:\Program Files\WindowsApps\Claude_1.40609.1.0_x64__pzs8sxrjxfjjc\app\claude.exe"`

func claudeDesktopSnapshot() (map[int]agentObs, func(int) int) {
	helpers := map[int]string{
		5948:  ` --type=renderer --user-data-dir="C:\Users\u\AppData\Roaming\Claude" --standard-schemes`,
		11168: ` --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US`,
		28084: ` --type=gpu-process --user-data-dir="C:\Users\u\AppData\Roaming\Claude"`,
		29304: ` --type=crashpad-handler --user-data-dir=C:\Users\u\AppData\Roaming\Claude`,
		33640: ` --type=utility --utility-sub-type=video_capture.mojom.VideoCaptureService`,
		37528: ` --type=renderer --user-data-dir="C:\Users\u\AppData\Roaming\Claude"`,
		37616: ` --type=utility --utility-sub-type=audio.mojom.AudioService --lang=en-US`,
		38520: ` --type=utility --utility-sub-type=node.mojom.NodeService --lang=en-US`,
	}
	byPid := map[int]agentObs{
		4532: {PID: 4532, Signature: "claude-code", Cmdline: winClaudeExe, raw: winClaudeExe},
		// Claude Code itself, in a terminal: stays an agent.
		7000: {PID: 7000, Signature: "claude-code", Cmdline: "claude --resume", raw: "claude --resume"},
		// A macOS app bundle with no helper of its own in the candidate set.
		8000: {PID: 8000, Signature: "cursor", Cmdline: "/Applications/Cursor.app/Contents/MacOS/Cursor",
			raw: "/Applications/Cursor.app/Contents/MacOS/Cursor"},
	}
	for pid, args := range helpers {
		full := winClaudeExe + args
		byPid[pid] = agentObs{PID: pid, Signature: "claude-code", Cmdline: truncate(full, 200), raw: full}
	}
	parent := func(pid int) int {
		switch {
		case helpers[pid] != "":
			return 4532
		case pid == 4532:
			return 1200 // explorer
		case pid == 7000:
			return 6000 // a shell
		case pid == 8000:
			return 1 // launchd
		}
		return 0
	}
	return byPid, parent
}

func TestArgv0AndBundleRoot(t *testing.T) {
	cases := map[string]string{
		winClaudeExe + ` --type=renderer`: `C:\Program Files\WindowsApps\Claude_1.40609.1.0_x64__pzs8sxrjxfjjc\app\claude.exe`,
		"/usr/local/bin/claude --resume":  "/usr/local/bin/claude",
		"claude":                          "claude",
		"'/Applications/Foo Bar.app/Contents/MacOS/foo' --type=gpu": "/Applications/Foo Bar.app/Contents/MacOS/foo",
		"": "",
	}
	for in, want := range cases {
		if got := argv0(in); got != want {
			t.Errorf("argv0(%q) = %q, want %q", in, got, want)
		}
	}
	if got := bundleRoot("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"); got != "/applications/google chrome.app/" {
		t.Errorf("bundleRoot must be the OUTERMOST bundle, got %q", got)
	}
	if got := bundleRoot("/usr/local/bin/claude"); got != "" {
		t.Errorf("no bundle = %q", got)
	}
}

// A helper is a --type= process whose PARENT runs the same program. The flag
// alone must never be enough: that would let any process vanish by adding it.
func TestIsGUIHelperNeedsSameProgramParent(t *testing.T) {
	helper := winClaudeExe + ` --type=renderer --user-data-dir="C:\x"`
	if !isGUIHelper(helper, winClaudeExe) {
		t.Error("a --type= child of the same exe is a helper")
	}
	if !isGUIHelper("/opt/Claude/claude --type=zygote", "/opt/Claude/claude") {
		t.Error("linux same-binary helper")
	}
	chromeHelper := "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper (GPU).app/Contents/MacOS/Google Chrome Helper (GPU) --type=gpu-process"
	if !isGUIHelper(chromeHelper, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome") {
		t.Error("macOS helper in the same outer bundle is a helper")
	}
	// The evasion / false-positive reproduced here: an agent whose
	// PROMPT mentions the flag, under a shell.
	if isGUIHelper("claude -p add a --type=json flag to the export command", "-bash") {
		t.Error("an agent mentioning --type= under a shell is NOT a helper")
	}
	if isGUIHelper("foo --type=x", "") {
		t.Error("no parent command line: never a helper")
	}
	if isGUIHelper(winClaudeExe, winClaudeExe) {
		t.Error("no --type= flag: not a helper even under the same exe")
	}
	if hasTypeFlag("node cli.js --type-check") {
		t.Error("a flag that merely starts with the marker is not the marker")
	}
}

func TestClassifyObservationsClaudeDesktop(t *testing.T) {
	byPid, parent := claudeDesktopSnapshot()
	helperRoot := classifyObservations(byPid, parent)

	if len(helperRoot) != 8 {
		t.Fatalf("want 8 helpers collapsed, got %d: %v", len(helperRoot), helperRoot)
	}
	for pid, root := range helperRoot {
		if root != 4532 {
			t.Errorf("helper %d attributed to %d, want 4532", pid, root)
		}
		if _, still := byPid[pid]; still {
			t.Errorf("helper %d must be dropped from the report", pid)
		}
	}
	if len(byPid) != 3 {
		t.Fatalf("want 3 observations (app, agent, bundle app), got %d: %+v", len(byPid), byPid)
	}

	app := byPid[4532]
	if app.Kind != kindApp || app.Signature != "claude-desktop" || app.PPID != 1200 {
		t.Errorf("the desktop app = %+v, want kind=app signature=claude-desktop ppid=1200", app)
	}
	cli := byPid[7000]
	if cli.Kind != kindAgent || cli.Signature != "claude-code" || cli.PPID != 6000 {
		t.Errorf("claude code in a terminal = %+v, want kind=agent signature=claude-code", cli)
	}
	bundle := byPid[8000]
	if bundle.Kind != kindApp || bundle.Signature != "cursor-app" {
		t.Errorf("a .app bundle = %+v, want kind=app signature=cursor-app", bundle)
	}
}

// Four rules pinned here: an agent that mentions the flag
// stays an agent; a bundle path as an ARGUMENT is not a bundle; a helper with
// an unreadable parent is never pinned to pid 0; nested helpers resolve to
// the app.
func TestClassifyObservationsEdges(t *testing.T) {
	mention := "claude -p add a --type=json flag to the export command"
	byPid := map[int]agentObs{
		7000: {PID: 7000, Signature: "claude-code", Cmdline: mention, raw: mention},
		7001: {PID: 7001, Signature: "aider", Cmdline: "aider /Applications/Foo.app/Contents/MacOS/foo.swift",
			raw: "aider /Applications/Foo.app/Contents/MacOS/foo.swift"},
		// a --type= candidate whose parent cannot be read
		7002: {PID: 7002, Signature: "claude-code", Cmdline: winClaudeExe + " --type=gpu-process", raw: winClaudeExe + " --type=gpu-process"},
		// zygote pattern: browser → zygote helper → renderer helper
		4532: {PID: 4532, Signature: "claude-code", Cmdline: "/opt/Claude/claude", raw: "/opt/Claude/claude"},
		4600: {PID: 4600, Signature: "claude-code", Cmdline: "/opt/Claude/claude --type=zygote", raw: "/opt/Claude/claude --type=zygote"},
		4601: {PID: 4601, Signature: "claude-code", Cmdline: "/opt/Claude/claude --type=renderer", raw: "/opt/Claude/claude --type=renderer"},
	}
	parents := map[int]int{7000: 6000, 7001: 6000, 7002: 0, 4532: 1200, 4600: 4532, 4601: 4600}
	helperRoot := classifyObservations(byPid, func(pid int) int { return parents[pid] })

	if a := byPid[7000]; a.Kind != kindAgent || a.Signature != "claude-code" {
		t.Errorf("an agent mentioning --type= must stay an agent, got %+v", a)
	}
	if a := byPid[7001]; a.Kind != kindAgent || a.Signature != "aider" {
		t.Errorf("a bundle path as an argument must not make an app, got %+v", a)
	}
	if a, ok := byPid[7002]; !ok || a.Kind != kindAgent {
		t.Errorf("a --type= candidate with an unreadable parent stays reported as what it matched, got %+v (present=%v)", a, ok)
	}
	if _, phantom := helperRoot[7002]; phantom {
		t.Error("an unreadable parent must never produce a helper root")
	}
	if helperRoot[4600] != 4532 || helperRoot[4601] != 4532 {
		t.Errorf("nested helpers must resolve to the app, got %v", helperRoot)
	}
	if a := byPid[4532]; a.Kind != kindApp || a.Signature != "claude-desktop" {
		t.Errorf("the app owning nested helpers = %+v", a)
	}
	for _, pid := range []int{4600, 4601} {
		if _, still := byPid[pid]; still {
			t.Errorf("helper %d must be dropped", pid)
		}
	}
	if _, phantom := byPid[0]; phantom {
		t.Error("pid 0 must never be observed")
	}
}

// The helper that actually holds the socket (network.mojom.NetworkService)
// is credited to the app, so "Claude desktop, talking to api.anthropic.com"
// is one observation — and a helper never becomes a "client".
func TestMergeConnectionsAttributesHelperSocketsToTheApp(t *testing.T) {
	byPid, parent := claudeDesktopSnapshot()
	helperRoot := classifyObservations(byPid, parent)
	cloud := map[string]string{"1.2.3.4": "api.anthropic.com"}
	strong := map[int]string{11434: "ollama"}
	weak := map[int]string{}
	info := func(pid int) procDetail {
		return procDetail{User: "u", Cmdline: byPid[pid].raw, Exe: byPid[pid].Exe}
	}

	conns := []connObs{{PID: 11168, RemoteIP: "1.2.3.4", RemotePort: 443}}
	for i := range conns {
		if root, ok := helperRoot[conns[i].PID]; ok {
			conns[i].PID, conns[i].ViaHelper = root, true
		}
	}
	mergeConnections(byPid, conns, cloud, strong, weak, info, parent)
	if got := byPid[4532].LLMEndpoints; len(got) != 1 || got[0] != "api.anthropic.com" {
		t.Fatalf("the app must carry its helper's endpoint, got %v", got)
	}
	if _, leaked := byPid[11168]; leaked {
		t.Fatal("a helper must never appear as its own observation")
	}
	if byPid[4532].Kind != kindApp {
		t.Fatalf("annotating must not change the kind, got %+v", byPid[4532])
	}
	if _, phantom := byPid[0]; phantom {
		t.Fatal("pid 0 must never be observed")
	}
}

// An unknown Chromium helper (a browser tab calling a model API) is the
// user's APP, attributed to its parent — never a disguised-agent "client".
// An unknown process that merely MENTIONS the flag is an ordinary client, and
// the shell above it is never blamed.
func TestMergeConnectionsUnknownHelperBecomesAnApp(t *testing.T) {
	cloud := map[string]string{"1.2.3.4": "api.openai.com"}
	strong := map[int]string{11434: "ollama"}
	weak := map[int]string{}
	chrome := `"C:\Program Files\Google\Chrome\Application\chrome.exe"`
	cmd := map[int]string{
		700:  chrome,
		750:  chrome + ` --type=zygote`,
		800:  chrome + ` --type=utility --utility-sub-type=network.mojom.NetworkService`,
		900:  `"C:\x\orphan.exe" --type=renderer`,
		1000: "-bash",
		1001: "python3 agent.py --type=fast", // mentions the flag; parent is a shell
	}
	parents := map[int]int{800: 750, 750: 700, 700: 4, 900: 1, 1001: 1000, 1000: 5}
	// The kernel's executable path per pid. A helper and its app run the same
	// binary in life; here they are given DIFFERENT paths on purpose, so the
	// assertion below can tell which one the observation kept.
	exe := map[int]string{
		700:  `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		750:  `C:\Program Files\Google\Chrome\Application\zygote.exe`,
		800:  `C:\Program Files\Google\Chrome\Application\helper.exe`,
		900:  `C:\x\orphan.exe`,
		1001: `/usr/bin/python3`,
	}
	info := func(pid int) procDetail {
		return procDetail{User: "u", Cmdline: cmd[pid], Exe: exe[pid]}
	}
	parent := func(pid int) int { return parents[pid] }

	byPid := map[int]agentObs{}
	mergeConnections(byPid, []connObs{
		{PID: 800, RemoteIP: "1.2.3.4", RemotePort: 443},
		{PID: 900, RemoteIP: "1.2.3.4", RemotePort: 443},  // parent is init: dropped
		{PID: 1001, RemoteIP: "1.2.3.4", RemotePort: 443}, // not a helper: a client
	}, cloud, strong, weak, info, parent)

	for _, pid := range []int{800, 750, 0, 1, 1000} {
		if _, ok := byPid[pid]; ok {
			t.Errorf("pid %d must not be observed: %+v", pid, byPid[pid])
		}
	}
	// A --type= process whose parent is init (or unreadable) has no app to be
	// credited to: it is reported under its OWN pid as a client — visible and
	// containable — never as a phantom pid-0 app, never silently dropped.
	if c, ok := byPid[900]; !ok || c.Kind != kindClient || c.PID != 900 {
		t.Errorf("an orphaned --type= process is a client under its own pid, got %+v", byPid[900])
	}
	app, ok := byPid[700]
	if !ok || app.Kind != kindApp || app.Signature != "gui-app" || app.PPID != 4 {
		t.Fatalf("the browser must be observed as an app (through the zygote), got %+v", byPid)
	}
	if len(app.LLMEndpoints) != 1 || app.LLMEndpoints[0] != "api.openai.com" {
		t.Errorf("endpoints = %v", app.LLMEndpoints)
	}
	// The observation is the APP, so the file it names must be the APP's. Keeping
	// the helper's would key a mark (sanction.go) on a file that is not the
	// program the row names — the user would vouch for one thing by clicking
	// another.
	//
	// MUTATION: leave `exe` untouched when the walk resolves to the app
	// (drop `exe = rd.Exe` from the app branch of mergeConnections).
	// RESULT: red — the app row carried helper.exe.
	if want := exe[700]; app.Exe != want {
		t.Errorf("the app's row carries exe %q, want its own %q", app.Exe, want)
	}
	if c, ok := byPid[1001]; !ok || c.Kind != kindClient || c.Signature != "llm-client" {
		t.Errorf("a process mentioning the flag under a shell is a client, got %+v", byPid[1001])
	}
	// MUTATION: drop `Exe: exe` from the agentObs literal mergeConnections builds.
	// RESULT: red — an observation the network signal created could never be
	// marked as yours, because it carried no file at all.
	if got := byPid[1001].Exe; got != "/usr/bin/python3" {
		t.Errorf("a client observation must carry the kernel's path, got %q", got)
	}
}

func TestDescendantsOf(t *testing.T) {
	parents := map[int]int{
		101: 50, 102: 101, 103: 102, 104: 101, // a tree under 101
		200: 50, 201: 200, // a sibling tree
		300: 300, // self-parent junk must not loop
	}
	got := descendantsOf(parents, 101)
	sort.Ints(got)
	want := []int{102, 103, 104}
	if len(got) != len(want) {
		t.Fatalf("descendantsOf(101) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("descendantsOf(101) = %v, want %v", got, want)
		}
	}
	if got := descendantsOf(parents, 103); len(got) != 0 {
		t.Errorf("a leaf has no descendants, got %v", got)
	}
	if got := descendantsOf(parents, 999); len(got) != 0 {
		t.Errorf("an unknown pid has no descendants, got %v", got)
	}
	if got := descendantsOf(parents, 300); len(got) != 0 {
		t.Errorf("a self-parented pid must not recurse, got %v", got)
	}
}

func TestParseProcStatPPID(t *testing.T) {
	cases := map[string]int{
		"1234 (claude) S 999 1234 1234 0 -1":  999,
		"1234 (a (weird) name) R 77 1 1 0 -1": 77, // parens in comm
		"1234 (x y) S 5 1":                    5,  // spaces in comm
		"garbage":                             0,
		"":                                    0,
		"1 (systemd) S 0 1 1 0 -1 4194560 1 0 0 0 0 0 0": 0,
	}
	for in, want := range cases {
		if got := parseProcStatPPID(in); got != want {
			t.Errorf("parseProcStatPPID(%q) = %d, want %d", in, got, want)
		}
	}
}

// Contain takes the agent's tree, refuses an app, and spares the bastion's own
// local agent child — decided from stubs, so nothing real is ever signalled.
func TestMaybeContainKillsTreeAndRefusesApps(t *testing.T) {
	prevObs, prevTree, prevKill := observedAgents, processTree, killProcess
	defer func() { observedAgents, processTree, killProcess = prevObs, prevTree, prevKill }()

	self := os.Getpid()
	observedAgents = func() ([]agentObs, error) {
		return []agentObs{
			{PID: 101, Kind: kindAgent, Signature: "claude-code"},
			{PID: 4532, Kind: kindApp, Signature: "claude-desktop"},
			{PID: 202, Kind: kindClient, Signature: "llm-client"},
		}, nil
	}
	processTree = func() map[int]int {
		return map[int]int{
			102: 101, 103: 102, // the agent's shell and its child
			104:  101,  // our own local agent, launched under the agent's shell
			4533: 4532, // the app's helper
			self: 101,  // a corrupt map naming us as the agent's child
			1:    101,  // ...and init
		}
	}
	faTrackPID(104)
	defer faUntrackPID(104)
	killed := []int{}
	killProcess = func(pid int) error { killed = append(killed, pid); return nil }

	maybeContain("", "", []byte(`{"contain":[101, 4532, 202, 303]}`))
	sort.Ints(killed)
	want := []int{101, 102, 103, 202}
	if len(killed) != len(want) {
		t.Fatalf("killed %v, want %v", killed, want)
	}
	for i := range want {
		if killed[i] != want[i] {
			t.Fatalf("killed %v, want %v", killed, want)
		}
	}
}
