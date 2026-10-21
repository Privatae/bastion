package main

// The tray's testable half. The systray plumbing cannot run here — there is no
// notification area on a Linux CI box — so what is checked is everything that
// does not need one: the wording, the build tag that keeps the darwin release
// alive, and the icons themselves.

import (
	"encoding/binary"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestTrayStateLine(t *testing.T) {
	up := func(n int) []uiPairing {
		var p []uiPairing
		for i := 0; i < n; i++ {
			p = append(p, uiPairing{Listening: true})
		}
		return p
	}
	cases := []struct {
		name string
		in   uiStatus
		want string
	}{
		{"nothing paired", uiStatus{}, "No host paired yet"},
		{"all served", uiStatus{Pairings: up(3)}, "Serving 3 host(s)"},
		{"some served", uiStatus{Pairings: append(up(1), uiPairing{})}, "Serving 1 of 2 hosts"},
		{"none served", uiStatus{Pairings: []uiPairing{{}, {}}}, "Serving 0 of 2 hosts"},
		// The whole point of this case: an unanchored networked box serves
		// NOTHING (anchor.go), so a host count there would be true about
		// pairings and a lie about the machine.
		{"networked, unanchored", uiStatus{Pairings: up(3), AnchorRequired: true},
			"Not anchored — answering nothing"},
	}
	for _, c := range cases {
		if got := trayStateLine(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestShutdownRequestIsIdempotent(t *testing.T) {
	// A menu item can be clicked twice before the daemon winds down, and closing
	// a closed channel panics. sync.Once is the whole fix; this is the proof.
	requestShutdown()
	requestShutdown()
	select {
	case <-shutdownCh:
	default:
		t.Fatal("shutdownCh was not closed — the tray's Stop would do nothing")
	}
}

// THE ONE THAT MATTERS MOST. fyne.io/systray needs cgo on darwin (measured:
// `undefined: nativeLoop`), and deploy/publish.sh builds all six
// targets in ONE alpine container at CGO_ENABLED=0. So an import that escapes
// the Windows build tag does not fail here, or in `go build`, or in `go vet` —
// it fails inside the publish container, for two of six targets, at release
// time. This test is where that gets caught instead.
func TestTheSystrayImportStaysBehindTheWindowsTag(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	darwin := build.Default
	darwin.GOOS = "darwin"

	found := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		imports := false
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == "fyne.io/systray" || strings.HasPrefix(p, "fyne.io/systray/") {
				imports = true
			}
		}
		if !imports {
			continue
		}
		found = true
		onDarwin, err := darwin.MatchFile(".", name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if onDarwin {
			t.Errorf("%s imports fyne.io/systray and IS compiled into a darwin build. "+
				"That library needs cgo on darwin, and deploy/publish.sh cross-builds "+
				"all six targets in one container with CGO_ENABLED=0 — so this breaks "+
				"darwin/amd64 and darwin/arm64 at PUBLISH time, not here. Put the "+
				"import behind `//go:build windows`.", name)
		}
	}
	if !found {
		t.Fatal("no file imports fyne.io/systray — either the tray was removed (delete " +
			"this test with it) or it moved somewhere this check no longer looks, " +
			"which would make the check a green light that proves nothing")
	}
}

// A tray icon that fails to decode leaves a blank space in the notification
// area, which looks exactly like the bastion not running — the one thing this
// whole feature exists to make unambiguous.
func TestTheTrayIconsAreRealIcons(t *testing.T) {
	for _, state := range []string{"ok", "warn", "bad"} {
		path := "uiassets/tray-" + state + ".ico"
		b, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if len(b) < 22 {
			t.Errorf("%s is %d bytes — not an icon", path, len(b))
			continue
		}
		// ICONDIR: reserved=0, type=1 (icon), count
		if binary.LittleEndian.Uint16(b[0:2]) != 0 || binary.LittleEndian.Uint16(b[2:4]) != 1 {
			t.Errorf("%s does not start with an ICONDIR header", path)
			continue
		}
		count := int(binary.LittleEndian.Uint16(b[4:6]))
		if count == 0 {
			t.Errorf("%s declares no images", path)
			continue
		}
		has16 := false
		for i := 0; i < count; i++ {
			off := 6 + i*16
			if off+16 > len(b) {
				t.Errorf("%s: directory entry %d runs past the file", path, i)
				break
			}
			if b[off] == 16 { // width; 0 would mean 256
				has16 = true
			}
		}
		// 16px is the size Windows actually draws in the notification area at
		// 100% scaling. An icon file without one gets downscaled from whatever
		// is nearest and turns to mush.
		if !has16 {
			t.Errorf("%s carries no 16x16 image — that is the size the tray draws", path)
		}
	}
}

// THE CONTEXT SURFACE HAS TO BE REACHABLE WITHOUT A TERMINAL, AND IT IS CALLED
// CONTEXT.
//
// A person looking at the tray menu expects to find the way in there, and the
// entry is named for what it is: we are not serving files, we are serving
// context built from files, and the App decides what becomes context on the
// network. Files are what you look at; context is what you decide they
// become, and the deciding is what this surface is for. The label is asserted
// because it is the product's noun, not a caption.
//
// Source-read for the reason console_test.go gives: the platform that runs the
// suite is Linux, and tray_windows.go is the file that carries the menu.
func TestTheTrayOffersTheContextSurface(t *testing.T) {
	src := readSourceFile(t, "tray_windows.go")
	if !strings.Contains(src, "AddMenuItem") {
		t.Fatal("the tray builds no menu at all any more — this check would pass for ever")
	}
	if !strings.Contains(src, "Your context") {
		t.Error("the tray menu has no entry for the context surface. It is the only way " +
			"in without typing a command, and typing a command is what the tray exists " +
			"to replace.")
	}
	if strings.Contains(src, "Your files") {
		t.Error("the tray menu calls it \"Your files\". We do not serve files, we serve " +
			"the context built from them — the surface exists so a person can choose " +
			"which files become context on their network.")
	}
	if !strings.Contains(src, "openContextSurface") {
		t.Error("nothing in the tray calls openContextSurface, so the menu entry — if there " +
			"is one — does nothing when clicked")
	}
}

// And it starts a SEPARATE process rather than serving from the daemon. On a
// one-person Windows desktop both would work; on a networked box the daemon is
// root, and serving files from it would render somebody's files under an
// authority they never granted.
func TestTheContextSurfaceIsStartedAsItsOwnProcess(t *testing.T) {
	src := readSourceFile(t, "tray.go")
	i := strings.Index(src, "func openContextSurface")
	if i < 0 {
		t.Fatal("openContextSurface is gone — this check would pass for ever")
	}
	body := src[i:]
	// j indexes into body[1:], so the slice bound is j+1.
	// Harmless as written — it only trimmed one byte early — but a slice bound
	// that is quietly wrong is the kind of thing the next person copies.
	if j := strings.Index(body[1:], "\nfunc "); j > 0 {
		body = body[:j+1]
	}
	if !strings.Contains(body, `exec.Command(exe, "context")`) {
		t.Error("the tray does not launch the `context` verb as a child process. The " +
			"security argument for that surface is that the walk is done BY the user, " +
			"so it cannot be served from a daemon that may be root.")
	}
	if !strings.Contains(body, "hideConsole") {
		t.Error("the child is started without hideConsole, so clicking a tray item " +
			"flashes a console window — the defect the tray was built to end")
	}
	if strings.Contains(body, "cmd.Wait()") && !strings.Contains(body, "go func()") {
		t.Error("the tray waits on the child, which freezes the menu for as long as " +
			"the person has their files open")
	}
}
