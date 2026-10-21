//go:build linux

package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Linux drivers for computer:*.
//
// Inventory reads freedesktop .desktop entries — the same files the app menu
// reads, so "installed" means "the user can launch it", which is the map the
// host wants. Flatpak and snap export theirs into the same format. A .desktop
// file carries no application version (its `Version=` key is the spec
// version of the file itself), so Version stays empty rather than invented.
//
// The bastion runs as a system service (deploy/install.sh), so its own
// environment has no DISPLAY and its HOME is /root while the person's desktop
// lives under /home/<user>. Both drivers look where the person is: per-user
// application dirs under every home, and the X socket in /tmp/.X11-unix when
// DISPLAY is unset. What cannot be reached is reported as the reason.
//
// Windows: wmctrl -lp (X11, incl. XWayland) — a fixed argv, parsed here.
// `xprop -root _NET_ACTIVE_WINDOW` names the focused one.

const (
	computerObserveSupported = true
	computerInventoryKind    = "desktop-entries"
	computerWindowsKind      = "wmctrl"
)

var desktopDirs = []string{
	"/usr/share/applications",
	"/usr/local/share/applications",
	"/var/lib/flatpak/exports/share/applications",
	"/var/lib/snapd/desktop/applications",
}

// userHomes is every home a person could have installed an app into: the
// service's own, plus /home/*. Reading a home that is not ours fails on
// permissions and is simply skipped.
func userHomes() []string {
	var homes []string
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		homes = append(homes, h)
	}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, filepath.Join("/home", e.Name()))
			}
		}
	}
	return dedupeStrings(homes)
}

func listInstalledApps() ([]computerApp, error) {
	dirs := append([]string{}, desktopDirs...)
	for _, home := range userHomes() {
		dirs = append(dirs,
			filepath.Join(home, ".local/share/applications"),
			filepath.Join(home, ".local/share/flatpak/exports/share/applications"))
	}
	var apps []computerApp
	found := false
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		found = true
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(d, e.Name()))
			if err != nil {
				continue
			}
			if a, ok := parseDesktopEntry(string(raw), d); ok {
				apps = append(apps, a)
			}
		}
	}
	if !found {
		return nil, errors.New("no applications directory found (not a desktop install?)")
	}
	return apps, nil
}

// parseDesktopEntry reads the [Desktop Entry] group: Type=Application only,
// NoDisplay/Hidden skipped (menu conventions), Exec's program as the path
// with the %-field codes stripped. dir tells flatpak/snap from a plain install.
func parseDesktopEntry(text, dir string) (computerApp, bool) {
	a := computerApp{Source: "desktop"}
	if strings.Contains(dir, "flatpak") {
		a.Source = "flatpak"
	} else if strings.Contains(dir, "snap") {
		a.Source = "snap"
	}
	inMain := false
	typ := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inMain = line == "[Desktop Entry]"
			continue
		}
		if !inMain {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Type":
			typ = v
		case "Name":
			if a.Name == "" {
				a.Name = v
			}
		case "Exec":
			a.Path = execProgram(v)
		case "NoDisplay", "Hidden":
			if strings.EqualFold(v, "true") {
				return computerApp{}, false
			}
		}
	}
	if typ != "Application" || a.Name == "" {
		return computerApp{}, false
	}
	return a, true
}

// execProgram is the program of an Exec= line: the first token, unquoted, with
// an `env VAR=x` prefix skipped, and the field codes (%f %u …) never included.
// A flatpak export (`flatpak run <app-id> …`) names the APP, "flatpak:<id>",
// not the flatpak binary — otherwise every flatpak would earn a cli rung for
// a program the user never runs by hand.
func execProgram(v string) string {
	fields := strings.Fields(v)
	for i, raw := range fields {
		f := strings.Trim(raw, `"`)
		if f == "env" || strings.Contains(f, "=") {
			continue
		}
		if filepath.Base(f) == "flatpak" {
			for _, arg := range fields[i+1:] {
				arg = strings.Trim(arg, `"`)
				if arg == "run" || strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
					continue
				}
				return "flatpak:" + arg
			}
			return "flatpak:"
		}
		return f
	}
	return ""
}

// x11Display is the display the person is on: DISPLAY when the service has
// one, else the first socket in /tmp/.X11-unix (":0" for X0). "" when neither.
func x11Display() string {
	if d := os.Getenv("DISPLAY"); d != "" {
		return d
	}
	entries, err := os.ReadDir("/tmp/.X11-unix")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if n, ok := strings.CutPrefix(e.Name(), "X"); ok && n != "" {
			return ":" + n
		}
	}
	return ""
}

func listWindows() ([]computerWindow, error) {
	display := x11Display()
	if display == "" {
		return nil, errors.New("no X display on this machine — headless, or Wayland without XWayland; no window list")
	}
	if !execOnPath("wmctrl") {
		return nil, errors.New("wmctrl not installed — install it (apt/dnf: wmctrl) to list windows")
	}
	out, err := runFixedEnv([]string{"DISPLAY=" + display}, "wmctrl", "-lp")
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, errors.New("wmctrl could not read display " + display + " (the bastion runs as a " +
				"service without the desktop session's X authority): " + strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, errors.New("wmctrl failed: " + err.Error())
	}
	active := ""
	if execOnPath("xprop") {
		if x, err := runFixedEnv([]string{"DISPLAY=" + display}, "xprop", "-root", "_NET_ACTIVE_WINDOW"); err == nil {
			active = parseActiveWindow(string(x))
		}
	}
	wins := parseWmctrl(string(out), active)
	for i := range wins {
		if wins[i].PID > 0 {
			if comm, err := os.ReadFile("/proc/" + strconv.Itoa(wins[i].PID) + "/comm"); err == nil {
				wins[i].App = strings.TrimSpace(string(comm))
			}
		}
	}
	return wins, nil
}

// wmctrl -lp: id, desktop, pid, client host, then the title — which keeps
// its own spacing (a recorded step may match it byte for byte).
var wmctrlLine = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s(.*))?$`)

// parseWmctrl reads `wmctrl -lp` lines:
//
//	0x03400003  0 12345  hostname Window title with spaces
//
// Sticky windows carry desktop -1. activeID (from xprop) marks the focused
// one; ids compare numerically so 0x3400003 and 0x03400003 are the same.
func parseWmctrl(text, activeID string) []computerWindow {
	var wins []computerWindow
	act := hexID(activeID)
	for _, line := range strings.Split(text, "\n") {
		m := wmctrlLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		title := m[5]
		if strings.TrimSpace(title) == "" {
			continue
		}
		pid, _ := strconv.Atoi(m[3])
		w := computerWindow{Title: title, PID: pid}
		if act != 0 && hexID(m[1]) == act {
			w.Focused = true
		}
		wins = append(wins, w)
	}
	return wins
}

// parseActiveWindow reads `_NET_ACTIVE_WINDOW(WINDOW): window id # 0x3400003`.
func parseActiveWindow(text string) string {
	if i := strings.LastIndex(text, "#"); i >= 0 {
		return strings.TrimSpace(text[i+1:])
	}
	return ""
}

func hexID(s string) uint64 {
	s = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(s)), "0x")
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0
	}
	return v
}
