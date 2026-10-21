package main

// Fuzz targets for how the op sandbox places an effect on a mount (Linux only,
// where the sandbox runs): the mount a path lives on, and the fixed part of an
// effect the mount is looked up by.

import (
	"path/filepath"
	"strings"
	"testing"
)

// opMountOf names the mount a path lives on, which decides whether the sandbox
// can carry an effect there. The answer must be a mount that holds the path on
// a whole-segment boundary ("/srv" does not hold "/srvx"), and no longer mount
// in the table may also hold it.
func FuzzOpMountOfIsTheLongestMountHoldingThePath(f *testing.F) {
	for _, s := range [][2]string{
		{"/,/srv,/srv/share,/home", "/srv/share/x"}, {"/,/srv", "/srvx/y"}, {"/srv,/srv/a", "/srv/a"},
		{"/,/srv/a/b", "/srv/a"}, {"/", "/"}, {"/a,/a/b,/a/b/c", "/a/b/c/d"}, {"", "/x"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, table, p string) {
		if !strings.HasPrefix(p, "/") || filepath.Clean(p) != p {
			return
		}
		var mounts []opHostMount
		for _, pt := range strings.Split(table, ",") {
			if strings.HasPrefix(pt, "/") && filepath.Clean(pt) == pt {
				mounts = append(mounts, opHostMount{Point: pt, FSType: "ext4"})
			}
		}
		holds := func(point string) bool {
			return point == "/" || p == point || strings.HasPrefix(p, point+"/")
		}
		got := opMountOf(mounts, p)
		if !holds(got.Point) {
			t.Fatalf("opMountOf(%v, %q) = %q, which does not hold the path", mounts, p, got.Point)
		}
		for _, m := range mounts {
			if holds(m.Point) && len(m.Point) > len(got.Point) {
				t.Fatalf("opMountOf(%v, %q) = %q, but %q is longer and holds it", mounts, p, got.Point, m.Point)
			}
		}
	})
}

// The sandbox looks an effect's mount up by its fixed part (opEffectPrefix).
// For that to name the right mount, every path the effect covers must sit at
// or under that fixed part.
func FuzzOpEffectPrefixHoldsEveryPathTheEffectCovers(f *testing.F) {
	for _, s := range [][2]string{
		{"/srv/app/", "/srv/app/x/y"}, {"/srv/a*/x", "/srv/ab/x"}, {"/srv/*", "/srv/q"}, {"/*/x", "/srv/x"},
		{"/srv/app/a.conf", "/srv/app/a.conf"}, {"/srv/[ab]pp/*", "/srv/app/c"}, {"/srv/ap?/", "/srv/ap?/z"},
		{"/srv/app", "/srv/app"},
	} {
		f.Add(s[0], s[1])
	}
	opsFuzzBox(f)
	f.Fuzz(func(t *testing.T, effect, changed string) {
		if effectOK(effect) != nil {
			return
		}
		c := filepath.Clean(changed)
		if !strings.HasPrefix(c, "/") || !effectCovers([]string{effect}, c) {
			return
		}
		pre := opEffectPrefix(effect)
		if pre != "/" && c != pre && !strings.HasPrefix(c, pre+"/") {
			t.Fatalf("effect %q covers %q, which is not under its fixed part %q", effect, c, pre)
		}
	})
}
