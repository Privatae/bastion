package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The judgement is platform-neutral and table-driven, so every platform's
// answer is testable from one CI by passing goos explicitly.
func TestWaysInDeepestFirst(t *testing.T) {
	got := waysIn("Autodesk Fusion 360", `C:\Users\u\AppData\Local\Autodesk\webdeploy\Fusion360.exe`, "windows", false)
	if len(got) < 2 || !strings.HasPrefix(got[0], "script:python") || got[len(got)-1] != wayGUI {
		t.Fatalf("Fusion 360 must lead with its Python door and end with gui: %v", got)
	}
	// per-GOOS doors: Office is COM on Windows, AppleScript on macOS, nothing special elsewhere
	if w := waysIn("Microsoft Excel", "", "windows", false); !strings.HasPrefix(w[0], "script:com") {
		t.Fatalf("Excel on Windows: %v", w)
	}
	if w := waysIn("Microsoft Excel", "", "darwin", false); !strings.HasPrefix(w[0], "script:applescript") {
		t.Fatalf("Excel on macOS: %v", w)
	}
	if w := waysIn("Microsoft Excel", "", "linux", false); len(w) != 1 || w[0] != wayGUI {
		t.Fatalf("Excel on Linux has only the gui rung: %v", w)
	}
	// the table's cli flag and the PATH probe both earn the cli rung, once
	if w := waysIn("Blender", "/usr/bin/blender", "linux", true); countOf(w, wayCLI) != 1 || w[0] != "script:python (bpy)" {
		t.Fatalf("Blender: %v", w)
	}
	if w := waysIn("Some Tool", "/usr/bin/sometool", "linux", true); len(w) != 2 || w[0] != wayCLI || w[1] != wayGUI {
		t.Fatalf("an unknown program on PATH is cli then gui: %v", w)
	}
	// an unknown app that is not on PATH has exactly the gui rung — never an invented door
	if w := waysIn("Mystery App", "", "linux", false); len(w) != 1 || w[0] != wayGUI {
		t.Fatalf("unknown app: %v", w)
	}
	// the exe basename matches too (Office names its binaries, not its products)
	if w := waysIn("Word", `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`, "windows", false); !strings.HasPrefix(w[0], "script:com") {
		t.Fatalf("winword.exe: %v", w)
	}
	// siblings are not the app: an updater, a runtime, a theme earn nothing
	for _, sib := range []string{"Microsoft Edge WebView2 Runtime", "Microsoft Edge Update", "MATLAB Runtime R2024b", "Cursor Theme Pack"} {
		if w := waysIn(sib, "", "windows", false); len(w) != 1 || w[0] != wayGUI {
			t.Fatalf("%s must earn only gui: %v", sib, w)
		}
	}
	if w := waysIn("Microsoft Edge", "", "windows", false); !strings.HasPrefix(w[0], "script:chrome-devtools") {
		t.Fatalf("the real Edge keeps its door: %v", w)
	}
	// the new Outlook has no COM object model — no door is asserted
	if w := waysIn("Microsoft Outlook", "", "windows", false); len(w) != 1 || w[0] != wayGUI {
		t.Fatalf("Outlook: %v", w)
	}
	// a flatpak's program is the app id, never the flatpak binary — no cli from PATH
	if w := waysIn("Obsidian", "flatpak:md.obsidian.Obsidian", "linux", execOnPath("flatpak:md.obsidian.Obsidian")); countOf(w, wayCLI) != 0 {
		t.Fatalf("flatpak must not earn cli: %v", w)
	}
}

func countOf(xs []string, s string) int {
	n := 0
	for _, x := range xs {
		if x == s {
			n++
		}
	}
	return n
}

func TestFinishAppsDedupesAndSorts(t *testing.T) {
	apps := finishApps([]computerApp{
		{Name: "zed", Source: "desktop"},
		{Name: "Blender", Source: "desktop", Path: "/nonexistent/blender"},
		{Name: "blender", Source: "flatpak"}, // duplicate by name, first fact wins
		{Name: "  ", Source: "desktop"},      // no name → dropped
	})
	if len(apps) != 2 || apps[0].Name != "Blender" || apps[1].Name != "zed" {
		t.Fatalf("dedupe+sort: %+v", apps)
	}
	if apps[0].Source != "desktop" {
		t.Fatalf("first fact wins on a duplicate: %+v", apps[0])
	}
	if len(apps[0].WaysIn) == 0 || apps[0].WaysIn[len(apps[0].WaysIn)-1] != wayGUI {
		t.Fatalf("ways_in filled for every app: %+v", apps[0])
	}
}

// The wire shape both ops answer with, and the honesty rule: unsupported is a
// true answer with a reason, never an empty list.
func TestComputerReportShape(t *testing.T) {
	rep := computerReport{Platform: "plan9", Scan: "unsupported", Reason: "no enumerator"}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back["supported"] != false || back["reason"] != "no enumerator" {
		t.Fatalf("unsupported must carry supported:false + reason: %s", b)
	}
	if _, ok := back["apps"]; ok {
		t.Fatalf("an unsupported report must not carry an apps list at all: %s", b)
	}
}

// Both ops are in the ONE handler table, so the enforcing report's vocabulary
// carries them (mgmtOpVocabulary reads handlerOps) and a grant can name them.
func TestComputerOpsInVocabulary(t *testing.T) {
	vocab := mgmtOpVocabulary()
	for _, op := range []string{"computer:inventory", "computer:windows"} {
		found := false
		for _, v := range vocab {
			if v == op {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s missing from the enforcing vocabulary: %v", op, vocab)
		}
		if handlerOps[op].root != rootNone {
			t.Fatalf("%s must need no configured root", op)
		}
	}
}

// The real thing, on this machine — same switch as TestScanAgentsLive.
func TestComputerObserveLive(t *testing.T) {
	if os.Getenv("PRIVATAE_OBSERVE_LIVE") != "1" {
		t.Skip("set PRIVATAE_OBSERVE_LIVE=1 to read this machine")
	}
	inv := computerInventoryReport()
	t.Logf("inventory: platform=%s scan=%s supported=%v reason=%q apps=%d", inv.Platform, inv.Scan, inv.Supported, inv.Reason, len(inv.Apps))
	for i, a := range inv.Apps {
		if i >= 15 {
			break
		}
		t.Logf("  %-32s %-10s %-24s %s", a.Name, a.Version, a.Source, strings.Join(a.WaysIn, " · "))
	}
	win := computerWindowsReport()
	t.Logf("windows: scan=%s supported=%v reason=%q n=%d", win.Scan, win.Supported, win.Reason, len(win.Windows))
	for _, w := range win.Windows {
		t.Logf("  pid=%-7d app=%-16s focused=%-5v %s", w.PID, w.App, w.Focused, w.Title)
	}
}

func TestExecOnPath(t *testing.T) {
	if execOnPath("") || execOnPath("/definitely/not/here/xyz") {
		t.Fatal("empty or missing program is never on PATH")
	}
	if execOnPath("/") {
		t.Fatal("a directory is not a program")
	}
}
