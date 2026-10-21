//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// macOS drivers for computer:*.
//
// Inventory: `system_profiler SPApplicationsDataType -json` — one fixed call,
// the same list the "About This Mac → Applications" report shows, with name,
// version, path and the signing identity (the publisher). Shelling out once
// beats reading a few hundred Info.plist files, half of them binary plists.
//
// Windows: one osascript against System Events listing every window of every
// foreground process with its pid and whether the process is frontmost. Two
// permissions can refuse it, and macOS names them by error code on stderr:
// -1743 is AUTOMATION (privatae-bastion may not send Apple Events to System
// Events), -25211 / "assistive access" is ACCESSIBILITY. The report names the
// pane that fixes the code seen, in the user's terms.

const (
	computerObserveSupported = true
	computerInventoryKind    = "system_profiler"
	computerWindowsKind      = "osascript+system-events"
)

func listInstalledApps() ([]computerApp, error) {
	out, err := runFixed("system_profiler", "SPApplicationsDataType", "-json")
	if err != nil {
		return nil, errors.New("system_profiler failed: " + execFailure(err))
	}
	return parseSystemProfiler(out)
}

// parseSystemProfiler reads the JSON report. Apps under /System are Apple's
// own and skipped: the map is what the user installed and can be asked to
// open, not the OS. Signing identity "Developer ID Application: X (TEAM)"
// becomes publisher X.
func parseSystemProfiler(raw []byte) ([]computerApp, error) {
	var doc struct {
		Apps []struct {
			Name     string   `json:"_name"`
			Version  string   `json:"version"`
			Path     string   `json:"path"`
			Obtained string   `json:"obtained_from"`
			SignedBy []string `json:"signed_by"`
		} `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.New("system_profiler output unreadable: " + err.Error())
	}
	var apps []computerApp
	for _, a := range doc.Apps {
		if strings.HasPrefix(a.Path, "/System/") || a.Obtained == "apple" {
			continue
		}
		apps = append(apps, computerApp{Name: a.Name, Version: a.Version, Path: a.Path,
			Publisher: publisherFromSigner(a.SignedBy), Source: "applications"})
	}
	return apps, nil
}

func publisherFromSigner(signed []string) string {
	for _, s := range signed {
		s = strings.TrimSpace(s)
		if i := strings.Index(s, ":"); i >= 0 {
			s = strings.TrimSpace(s[i+1:])
		}
		if i := strings.LastIndex(s, " ("); i > 0 {
			s = s[:i]
		}
		if s != "" && !strings.HasPrefix(s, "Apple") {
			return s
		}
	}
	return ""
}

// One script, one process spawn. Columns are tab-separated per line:
// pid \t process name \t frontmost \t window title. An untitled window's
// name is `missing value`, which cannot be concatenated — it becomes "".
const windowsScript = `tell application "System Events"
	set out to ""
	repeat with p in (every process whose background only is false)
		set pn to name of p
		set fm to frontmost of p
		set pi to unix id of p
		repeat with w in (every window of p)
			set wn to name of w
			if wn is missing value then set wn to ""
			set out to out & pi & tab & pn & tab & fm & tab & wn & linefeed
		end repeat
	end repeat
	return out
end tell`

func listWindows() ([]computerWindow, error) {
	out, err := runFixed("osascript", "-e", windowsScript)
	if err != nil {
		return nil, errors.New(osascriptReason(execFailure(err)))
	}
	return parseSystemEventsWindows(string(out)), nil
}

// execFailure is the text a failed exec.Cmd.Output() actually left behind:
// its stderr, when there is one, else the exit status. Output() folds stderr
// into *exec.ExitError.Stderr and (*ExitError).Error() says only "exit status
// 1" — reading err.Error() alone loses the reason.
func execFailure(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return strings.TrimSpace(string(ee.Stderr))
	}
	return err.Error()
}

// osascriptReason turns the stderr macOS wrote into the pane the user opens.
func osascriptReason(stderr string) string {
	low := strings.ToLower(stderr)
	switch {
	case strings.Contains(stderr, "-1743"):
		return "macOS Automation permission not granted: allow privatae-bastion to control " +
			"System Events (System Settings → Privacy & Security → Automation) — the screen cannot be read"
	case strings.Contains(stderr, "-25211"), strings.Contains(low, "assistive"):
		return "macOS Accessibility permission not granted to privatae-bastion " +
			"(System Settings → Privacy & Security → Accessibility) — the screen cannot be read"
	}
	return "osascript failed: " + stderr
}

func parseSystemEventsWindows(text string) []computerWindow {
	var wins []computerWindow
	for _, line := range strings.Split(text, "\n") {
		f := strings.SplitN(line, "\t", 4)
		if len(f) < 4 {
			continue
		}
		title := strings.TrimSpace(f[3])
		if title == "" {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(f[0]))
		wins = append(wins, computerWindow{Title: title, PID: pid, App: strings.TrimSpace(f[1]),
			Focused: strings.TrimSpace(f[2]) == "true"})
	}
	return wins
}
