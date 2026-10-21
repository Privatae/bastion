//go:build linux

package main

import "testing"

const blenderDesktop = `[Desktop Entry]
Name=Blender
GenericName=3D modeler
Comment=3D modeling, animation, rendering and post-production
Keywords=3d;cg;modeling;
Exec=blender %f
Icon=blender
Terminal=false
Type=Application
Version=1.0
Categories=Graphics;3DGraphics;
MimeType=application/x-blender;
[Desktop Action Foo]
Name=Not the app name
`

func TestParseDesktopEntry(t *testing.T) {
	a, ok := parseDesktopEntry(blenderDesktop, "/usr/share/applications")
	if !ok || a.Name != "Blender" || a.Path != "blender" || a.Source != "desktop" {
		t.Fatalf("blender: ok=%v %+v", ok, a)
	}
	// Version= in a .desktop file is the SPEC version of the file (htop.desktop
	// says 1.0 while htop is 3.4.1) — it must never be reported as the app's.
	if a.Version != "" {
		t.Fatalf("desktop-entry Version must not become the app version: %q", a.Version)
	}
	// the [Desktop Action] group's Name must not overwrite the entry's
	if a.Name != "Blender" {
		t.Fatalf("name from the main group only: %q", a.Name)
	}
	if _, ok := parseDesktopEntry("[Desktop Entry]\nType=Link\nName=x\n", "d"); ok {
		t.Fatal("only Type=Application is an app")
	}
	if _, ok := parseDesktopEntry("[Desktop Entry]\nType=Application\nName=x\nNoDisplay=true\n", "d"); ok {
		t.Fatal("NoDisplay entries are not launchable apps")
	}
	fp, _ := parseDesktopEntry("[Desktop Entry]\nType=Application\nName=Obsidian\nExec=env FOO=1 \"/usr/bin/flatpak\" run --branch=stable --arch=x86_64 md.obsidian.Obsidian %u\n",
		"/var/lib/flatpak/exports/share/applications")
	if fp.Source != "flatpak" || fp.Path != "flatpak:md.obsidian.Obsidian" {
		t.Fatalf("a flatpak's program is the app id, not the flatpak binary: %+v", fp)
	}
}

func TestParseWmctrl(t *testing.T) {
	out := "0x03400003  0 12345  box Terminal — bash\n" +
		"0x0480000a -1 0      box Desktop\n" +
		"0x05000007  1 777    box Fusion 360 -  flowerpot.f3d\n" + // two spaces, kept
		"garbage line\n"
	wins := parseWmctrl(out, parseActiveWindow("_NET_ACTIVE_WINDOW(WINDOW): window id # 0x5000007"))
	if len(wins) != 3 {
		t.Fatalf("three windows: %+v", wins)
	}
	if wins[0].Title != "Terminal — bash" || wins[0].PID != 12345 || wins[0].Focused {
		t.Fatalf("first: %+v", wins[0])
	}
	if !wins[2].Focused || wins[2].PID != 777 || wins[2].Title != "Fusion 360 -  flowerpot.f3d" {
		t.Fatalf("the active id (short hex) must match the padded id, and spacing is kept: %+v", wins[2])
	}
	if wins[1].PID != 0 || wins[1].Title != "Desktop" {
		t.Fatalf("sticky window with no pid: %+v", wins[1])
	}
}

func TestX11DisplayPrefersEnv(t *testing.T) {
	t.Setenv("DISPLAY", ":7")
	if d := x11Display(); d != ":7" {
		t.Fatalf("DISPLAY wins: %q", d)
	}
}
