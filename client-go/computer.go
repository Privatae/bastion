package main

// computer:* — the OBSERVE rung of governed computer use.
//
// The host plans from a MACHINE MAP, not a screenshot. "Get into Fusion 360
// and build me a flowerpot" starts with the host
// reading what this box has installed and, for each app, the deepest way in:
// the app's own scripting door first, the accessibility tree second, a cropped
// screenshot last. These two ops are that map. They READ; they never inject.
//
//   computer:inventory  — installed applications with version, publisher, path,
//                         where the fact came from, and `ways_in` (deepest first).
//   computer:windows    — the top-level windows open right now: title, owning
//                         process, app, which one has focus.
//
// Both ride the management lane like any other op — signed grant on the pod
// side (default-deny; a deny beats an allow), the op vocabulary in the
// enforcing report — and are dedicated no-exec handlers: nothing here takes
// caller arguments into a shell. Where an OS needs a helper (system_profiler,
// osascript, wmctrl) it is a fixed argv, and the parser is a pure function
// unit-tested from any OS with captured fixtures ("leech, don't adopt": no new
// Go module).
//
// Honesty over coverage: a platform or a box that cannot enumerate says so
// (supported:false + reason) instead of answering an empty list that would be
// read as "nothing installed" or "no windows open".

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// computerApp is one installed application on this box. Path is the program,
// never a user file. WaysIn is ordered deepest first; the host picks the first
// rung it can drive.
type computerApp struct {
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	Publisher string   `json:"publisher,omitempty"`
	Path      string   `json:"path,omitempty"`
	Source    string   `json:"source"` // registry | applications | desktop | flatpak | snap
	WaysIn    []string `json:"ways_in"`
}

// computerWindow is one top-level window open now. PID/App are best effort;
// Title is what a person sees, which is how a recorded step addresses it.
type computerWindow struct {
	Title   string `json:"title"`
	PID     int    `json:"pid,omitempty"`
	App     string `json:"app,omitempty"`
	Focused bool   `json:"focused,omitempty"`
}

// computerReport is the wire shape of both ops. Supported=false carries the
// reason in the user's terms (a missing tool, a permission not granted, a
// headless box) — the host relays it, never guesses at it.
type computerReport struct {
	Platform  string           `json:"platform"`
	Scan      string           `json:"scan"` // which enumerator answered
	Supported bool             `json:"supported"`
	Reason    string           `json:"reason,omitempty"`
	ScannedAt string           `json:"scanned_at"`
	Apps      []computerApp    `json:"apps,omitempty"`
	Windows   []computerWindow `json:"windows,omitempty"`
}

const computerCmdTimeout = 20 * time.Second

// ── ways in: the judgement, platform-neutral, table-driven ───────────────────

// The rung names the host reads. Ordered deepest first when several apply.
const (
	wayCLI = "cli" // a command-line entry point (drive it without a window)
	wayGUI = "gui" // the accessibility tree, then a cropped screenshot — every app has this rung
)

// scriptDoor is one app family with a known scripting door: a way to hand the
// program a script and have it act, with no clicking. `match` are lowercase
// substrings tested against the app name and its executable's basename;
// `doors` are per-GOOS ("" = every OS), deepest first. This is a table of
// well-known, documented interfaces, not a guess — an entry is added when the
// vendor documents the door.
type scriptDoor struct {
	match   []string
	exclude []string // a name carrying one of these is a sibling, not the app (an updater, a runtime, a theme)
	doors   map[string][]string
	cli     bool
}

var scriptDoors = []scriptDoor{
	{match: []string{"fusion 360", "fusion360", "autodesk fusion"},
		doors: map[string][]string{"": {"script:python (Fusion 360 API — scripts run inside the app)"}}},
	{match: []string{"blender"},
		doors: map[string][]string{"": {"script:python (bpy)"}}, cli: true},
	{match: []string{"freecad"},
		doors: map[string][]string{"": {"script:python (FreeCAD API)"}}, cli: true},
	{match: []string{"kicad"},
		doors: map[string][]string{"": {"script:python (pcbnew)"}}},
	{match: []string{"gimp"},
		doors: map[string][]string{"": {"script:python-fu / script-fu"}}, cli: true},
	{match: []string{"inkscape"},
		doors: map[string][]string{"": {"script:actions (inkscape --actions)"}}, cli: true},
	{match: []string{"libreoffice", "openoffice", "soffice"},
		doors: map[string][]string{"": {"script:python-uno"}}, cli: true},
	// Outlook is deliberately absent: the new Outlook has no COM object model.
	{match: []string{"microsoft excel", "excel.exe", "microsoft word", "winword", "microsoft powerpoint", "powerpnt"},
		doors: map[string][]string{"windows": {"script:com-automation (Office object model)"}, "darwin": {"script:applescript (Office dictionary)"}}},
	{match: []string{"adobe photoshop", "adobe illustrator", "adobe indesign", "adobe after effects", "adobe premiere"},
		doors: map[string][]string{"": {"script:extendscript / uxp"}}},
	{match: []string{"autocad"},
		doors: map[string][]string{"windows": {"script:autolisp", "script:com-automation"}, "darwin": {"script:autolisp"}}},
	{match: []string{"solidworks"},
		doors: map[string][]string{"windows": {"script:com-automation (SolidWorks API)"}}},
	{match: []string{"visual studio code", "code.exe", "vscodium", "cursor"}, exclude: []string{"theme", "cursors"},
		doors: map[string][]string{}, cli: true},
	{match: []string{"google chrome", "chromium", "microsoft edge", "brave"}, exclude: []string{"webview2", "update", "updater"},
		doors: map[string][]string{"": {"script:chrome-devtools-protocol (launch with --remote-debugging-port)"}}, cli: true},
	{match: []string{"firefox"},
		doors: map[string][]string{"": {"script:webdriver-bidi / marionette"}}, cli: true},
	{match: []string{"obsidian"},
		doors: map[string][]string{"": {"script:uri (obsidian://)"}}},
	{match: []string{"notepad++"},
		doors: map[string][]string{}, cli: true},
	{match: []string{"vlc"},
		doors: map[string][]string{"": {"script:lua / http interface"}}, cli: true},
	{match: []string{"audacity"},
		doors: map[string][]string{"": {"script:mod-script-pipe"}}},
	{match: []string{"matlab"}, exclude: []string{"runtime"},
		doors: map[string][]string{"": {"script:matlab (-batch)"}}, cli: true},
	{match: []string{"docker desktop"},
		doors: map[string][]string{}, cli: true},
	{match: []string{"terminal", "iterm", "windows terminal", "powershell", "gnome-terminal", "konsole"},
		doors: map[string][]string{}, cli: true},
}

func (d scriptDoor) matches(key string) bool {
	for _, x := range d.exclude {
		if strings.Contains(key, x) {
			return false
		}
	}
	for _, m := range d.match {
		if strings.Contains(key, m) {
			return true
		}
	}
	return false
}

// waysIn is the judgement: given an app's name and program path, the rungs the
// host can drive, deepest first. goos is a parameter so the table is testable
// for every platform from one CI. onPath says whether the program resolves on
// PATH — a CLI rung the table did not know about.
func waysIn(name, path, goos string, onPath bool) []string {
	key := strings.ToLower(name) + " " + strings.ToLower(binBase(path)) + " " + strings.ToLower(filepath.Base(path))
	var out []string
	cli := onPath
	for _, d := range scriptDoors {
		if !d.matches(key) {
			continue
		}
		out = append(out, d.doors[goos]...)
		if goos != "" {
			out = append(out, d.doors[""]...)
		}
		if d.cli {
			cli = true
		}
	}
	out = dedupeStrings(out)
	if cli {
		out = append(out, wayCLI)
	}
	return append(out, wayGUI)
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// execOnPath reports whether a program name (or an absolute path that exists)
// resolves to something runnable — the honest test for a CLI rung.
func execOnPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	if filepath.IsAbs(p) {
		st, err := os.Stat(p)
		return err == nil && !st.IsDir()
	}
	_, err := exec.LookPath(p)
	return err == nil
}

// finishApps dedupes by name (first fact wins — the more authoritative source
// enumerates first on every platform), fills ways_in, and sorts by name so two
// scans of an unchanged box compare equal.
func finishApps(apps []computerApp) []computerApp {
	seen := map[string]bool{}
	out := make([]computerApp, 0, len(apps))
	for _, a := range apps {
		a.Name = strings.TrimSpace(a.Name)
		if a.Name == "" {
			continue
		}
		k := strings.ToLower(a.Name)
		if seen[k] {
			continue
		}
		seen[k] = true
		a.WaysIn = waysIn(a.Name, a.Path, runtime.GOOS, execOnPath(a.Path))
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// ── the two ops ──────────────────────────────────────────────────────────────

func computerInventoryReport() computerReport {
	rep := computerReport{Platform: runtime.GOOS, Scan: computerInventoryKind,
		ScannedAt: time.Now().UTC().Format(time.RFC3339)}
	if !computerObserveSupported {
		rep.Reason = "no inventory enumerator for this platform"
		return rep
	}
	apps, err := listInstalledApps()
	if err != nil {
		rep.Reason = err.Error()
		return rep
	}
	rep.Supported = true
	rep.Apps = finishApps(apps)
	return rep
}

func computerWindowsReport() computerReport {
	rep := computerReport{Platform: runtime.GOOS, Scan: computerWindowsKind,
		ScannedAt: time.Now().UTC().Format(time.RFC3339)}
	if !computerObserveSupported {
		rep.Reason = "no window enumerator for this platform"
		return rep
	}
	wins, err := listWindows()
	if err != nil {
		rep.Reason = err.Error()
		return rep
	}
	rep.Supported = true
	if wins == nil {
		wins = []computerWindow{}
	}
	rep.Windows = wins
	return rep
}

// The handlers answer with the JSON report on stdout and exit 0 — an
// unsupported box is a true answer ("I cannot see"), not a refusal (126 is
// reserved for "not permitted"). Caller args are ignored: there are none.
func handleComputerInventory(ws *websocket.Conn, _ string, _ []string) {
	writeComputerReport(ws, computerInventoryReport())
}

func handleComputerWindows(ws *websocket.Conn, _ string, _ []string) {
	writeComputerReport(ws, computerWindowsReport())
}

func writeComputerReport(ws *websocket.Conn, rep computerReport) {
	b, err := json.Marshal(rep)
	if err != nil {
		sendMgmt(ws, 'R', []byte("report: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	sendMgmt(ws, 'O', append(b, '\n'))
	sendMgmtExit(ws, 0)
}

// runFixed runs a fixed argv with the op's timeout and returns stdout. Used by
// the drivers that lean on an OS tool; the argv never carries caller input.
// On failure the *exec.ExitError carries stderr (Output() folds it in); the
// drivers read it from there, never from err.Error(), which says only
// "exit status N".
func runFixed(name string, args ...string) ([]byte, error) {
	return runFixedEnv(nil, name, args...)
}

// runFixedEnv is runFixed with extra environment entries (DISPLAY=:0 for a
// service that has no display of its own).
func runFixedEnv(extraEnv []string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), computerCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd) // the Windows UIAutomation helper is PowerShell — console_windows.go
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	return cmd.Output()
}
