//go:build !windows

package main

// Fuzz targets for the path walls that follow symlinks or read this box's own
// record: a store read, a move plan, an op's declared effects and its path
// params. Unix-only because the fixtures are symlinks and the op checks judge
// unix paths; the seeds run on every `go test` on Linux and macOS.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// storeFixture builds a store root with links that stay inside it and links
// that lead out of it (and one that leads out and back in), next to an
// outside tree holding a secret.
func storeFixture(f *testing.F) (root, outside string) {
	base, err := filepath.EvalSymlinks(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	root, outside = filepath.Join(base, "store"), filepath.Join(base, "outside")
	for _, d := range []string{"sub/deeper", ".agent/plans", "archive", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			f.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(outside, "dir"), 0o700); err != nil {
		f.Fatal(err)
	}
	for p, body := range map[string]string{
		filepath.Join(root, "sub", "a.txt"): "a", filepath.Join(root, "sub", "deeper", "b.txt"): "b",
		filepath.Join(root, ".ssh", "id"): "k", filepath.Join(outside, "secret"): "s",
		filepath.Join(outside, "dir", "secret"): "s",
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			f.Fatal(err)
		}
	}
	links := map[string]string{
		"in":        "sub",                              // relative, inside
		"in-abs":    filepath.Join(root, "sub"),         // absolute, inside
		"in-file":   "sub/a.txt",                        // to a file, inside
		"out":       outside,                            // to a directory outside
		"out-file":  filepath.Join(outside, "secret"),   // to a file outside
		"up":        "..",                               // the root's parent
		"up2":       "sub/../..",                        // the same, spelled longer
		"slash":     "/",                                // the filesystem root
		"dangling":  filepath.Join(outside, "missing"),  // outside, not there yet
		"loop":      "loop",                             // a link to itself
		"sub/back":  "../..",                            // from inside a subfolder, up and out
		"sub/in2":   "deeper",                           // chained, inside
		"sub/chain": "../out",                           // a link to a link that leads out
		".agent/x":  filepath.Join(outside, "dir"),      // a link where the plan report goes
		"archive/o": filepath.Join(outside, "dir", "."), // outside, spelled with a dot
		"keys":      ".ssh",                             // inside, to an excluded folder
		"key":       ".ssh/id",                          // inside, to an excluded file
		"sub/keys2": "../keys",                          // a link to that link
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			f.Skipf("symlinks unavailable: %v", err)
		}
	}
	return root, outside
}

// insideRoot: p is root or below it (both already resolved).
func insideRoot(root, p string) bool {
	return p == root || strings.HasPrefix(p, root+"/")
}

// whereItLeads is where p actually is on disk: the deepest part of it that
// exists, with every link on the way followed. A path that passes out through
// one link and back in through another is judged by where it lands. It fails
// when the deepest existing part is a link that leads nowhere (or a loop).
func whereItLeads(p string) (string, error) {
	for {
		if _, err := os.Lstat(p); err == nil {
			return filepath.EvalSymlinks(p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p, nil
		}
		p = parent
	}
}

// storeSeeds are the names a host could send that reach each kind of link.
var storeSeeds = []string{
	"sub/a.txt", "in/a.txt", "in-abs/a.txt", "in-file", "out", "out/secret", "out-file", "up", "up/store",
	"up2/outside/secret", "slash/etc/passwd", "dangling", "dangling/x", "loop", "loop/x", "sub/back/outside",
	"sub/in2/b.txt", "sub/chain/secret", ".agent/x/secret", ".agent/plans/1.json", "archive/o/secret",
	"sub/nope.txt", "nope/deeper/x", "sub/../out/secret", "./sub/./a.txt", "sub//a.txt", "../outside/secret",
	".ssh/id", "sub/a.txt/..", "in/../in-file", "keys/id", "key", "sub/keys2/id", " keys/id", "keys",
}

// dcnResolvePath is the wall between a host's store read and the rest of the
// disk. An accepted path is lexically inside the root, and wherever it leads
// through links it lands inside the root: the whole path if it exists, and
// otherwise the deepest part of it that does.
func FuzzDcnResolvePathNeverLeavesTheRoot(f *testing.F) {
	for _, s := range storeSeeds {
		f.Add(s)
	}
	root, _ := storeFixture(f)
	f.Fuzz(func(t *testing.T, rpath string) {
		got, ok := dcnResolvePath(root, rpath)
		if !ok {
			return
		}
		if !strings.HasPrefix(got, root+"/") {
			t.Fatalf("dcnResolvePath(%q) = %q, which is not strictly inside %q", rpath, got, root)
		}
		if !landsInside(root, got) {
			t.Fatalf("dcnResolvePath(%q) accepted %q, which does not land inside the root", rpath, got)
		}
	})
}

// landsInside: p, followed through its links, is inside root. A broken link as
// the last part is judged where the link itself sits: a stat of it reads as
// gone, and a move renames the link, never its target.
func landsInside(root, p string) bool {
	if r, err := whereItLeads(p); err == nil {
		return insideRoot(root, r)
	}
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		r, err := whereItLeads(filepath.Dir(p))
		return err == nil && insideRoot(root, r)
	}
	return false
}

// excludedOnDisk is the fixture's excludes (".ssh", "*.key"), and the local
// search agent's folder (".agent", which no grant reaches), judged
// independently of dcnExcluded: on the path relative to the root after every
// link is followed, and on the text of the path the sandbox opens.
func excludedOnDisk(root, p string) bool {
	check := func(rel string) bool {
		for _, seg := range strings.Split(rel, "/") {
			if seg == ".ssh" || strings.HasSuffix(seg, ".key") || strings.EqualFold(seg, ".agent") {
				return true
			}
		}
		return false
	}
	rel, _ := filepath.Rel(root, p)
	if check(rel) {
		return true
	}
	if r, err := whereItLeads(p); err == nil {
		rr, _ := filepath.Rel(root, r)
		return check(rr)
	}
	return false
}

// A grant's excludes hold for every read of the store and every move. Whatever
// path a host sends, one the sandbox accepts and the excludes pass never opens
// an excluded name: not by its spelling (whitespace cleanRel trims, a ".."
// it resolves) and not through a link inside the store that leads into one.
func FuzzAnExcludedPathIsExcludedHoweverItIsSpelled(f *testing.F) {
	for _, s := range storeSeeds {
		f.Add(s)
	}
	for _, s := range []string{" .ssh/id", ".ssh/id ", "sub/../.ssh/id", "a.key", "a.key ", ".key /", "\t.ssh"} {
		f.Add(s)
	}
	root, _ := storeFixture(f)
	excludes := []string{".ssh", "*.key"}
	f.Fuzz(func(t *testing.T, rpath string) {
		got, ok := dcnResolvePath(root, rpath)
		if !ok || dcnExcludedAsSent(excludes, root, rpath) {
			return
		}
		if excludedOnDisk(root, got) {
			t.Fatalf("%q passed the excludes, and it opens %q, which is excluded", rpath, got)
		}
	})
}

// A move plan is the one lane that renames things in a store. Whatever moves
// the host proposes, a plan the dry run passes renames a source that is inside
// the root to a target that is inside the root, does not exist yet, is not
// inside the source, and is not in an excluded folder.
func FuzzMovePlanStaysInsideTheRoot(f *testing.F) {
	for _, from := range []string{"sub/a.txt", "in-file", "out/secret", "sub/deeper", ".ssh/id", "sub", "keys/id", "key", "dangling"} {
		for _, to := range []string{"archive/a.txt", "out/x", "dangling", "sub/back/x", "archive/o/x",
			".agent/x/y", "sub/deeper/x", "Archive/A.txt", ".ssh/moved", "sub/a.txt", "loop/x", "../x", "keys/x"} {
			f.Add(from, to)
		}
	}
	root, _ := storeFixture(f)
	excludes := []string{".ssh", "*.key"}
	f.Fuzz(func(t *testing.T, from, to string) {
		if problems := dcnCheckPlan(root, excludes, []dcnMove{{From: from, To: to}}); len(problems) > 0 {
			return
		}
		src, ok1 := cleanRel(root, from)
		dst, ok2 := cleanRel(root, to)
		if !ok1 || !ok2 {
			t.Fatalf("a plan moving %q to %q passed with a path the traversal wall refuses", from, to)
		}
		if !landsInside(root, src) {
			t.Fatalf("a plan moving %q passed, and the source does not land inside the root", from)
		}
		if _, err := os.Lstat(dst); err == nil {
			t.Fatalf("a plan moving to %q passed, and the target already exists", to)
		}
		if r, err := whereItLeads(dst); err != nil || !insideRoot(root, r) {
			t.Fatalf("a plan moving to %q passed, and the target leads to %q (%v), outside the root", to, r, err)
		}
		if strings.HasPrefix(strings.ToLower(dst), strings.ToLower(src)+"/") {
			t.Fatalf("a plan moving %q into itself (%q) passed", from, to)
		}
		for _, p := range []string{src, dst} {
			if excludedOnDisk(root, p) {
				t.Fatalf("a plan moving %q to %q passed, and %q is excluded", from, to, p)
			}
		}
	})
}

// opsFuzzBox is a config dir, a pairing whose DCN dir is kept elsewhere, and a
// free-agent state dir outside /tmp, so the record an op must never touch
// includes places effectOK's own /tmp refusal does not already cover.
func opsFuzzBox(f *testing.F) {
	f.Setenv("XDG_CONFIG_HOME", f.TempDir())
	f.Setenv("HOME", f.TempDir())
	old := faStateBaseOverride
	faStateBaseOverride = "/opt/fuzzbox/freeagent"
	f.Cleanup(func() { faStateBaseOverride = old })
	pd, err := pairingsDir()
	if err != nil {
		f.Fatal(err)
	}
	b, _ := json.Marshal(Config{HostName: "h.example", WGPrivateKey: "k", BastionTunnelIP: "fd00:9::a:1",
		DCNDir: "/srv/fuzzbox/dcn"})
	if err := os.WriteFile(filepath.Join(pd, "h.example.json"), b, 0o600); err != nil {
		f.Fatal(err)
	}
}

// An op's effects are the files it may change. An effect effectOK accepts can
// never cover this machine's own record: not the record, not anything inside
// it, not a folder that holds it; and nothing at or under /proc, /sys, /dev,
// /run, /tmp, /var/tmp or /boot except through a folder effect above one (the
// sandbox masks those). Checked against every protected place (and the
// record's parents) directly, and against whatever path the fuzzer pairs with
// the effect.
func FuzzAnOpEffectNeverCoversTheMachinesOwnRecord(f *testing.F) {
	for _, s := range [][2]string{
		{"/srv/app/", "/srv/app/x"}, {"/etc/*", "/etc/privatae-bastion"}, {"/etc/privatae-*/", "/etc/privatae-bastion/x"},
		{"/var/lib/*/bastion", "/var/lib/privatae/bastion"}, {"/*", "/var"}, {"/var/lib/privatae/", "/var/lib/privatae"},
		{"/var//lib/privatae/bastion/", "/var/lib/privatae/bastion/x"}, {"/etc/[p]rivatae-bastion/*", "/etc/privatae-bastion/k"},
		{"/etc/x[/]y", "/etc/x/y"}, {"/opt/fuzzbox/*", "/opt/fuzzbox/freeagent"}, {"/srv/fuzzbox/dcn/", "/srv/fuzzbox/dcn/g"},
		{"/srv/*/dcn", "/srv/fuzzbox/dcn"}, {"/proc/self/", "/proc/self/x"}, {"/boot", "/boot"},
		{"/etc/\\*", "/etc/*"}, {"/e?c/privatae-bastion/", "/etc/privatae-bastion/x"}, {"/srv/app/*.conf", "/srv/app/a.conf"},
		{"/b*/*", "/boot/vmlinuz"}, {"/*/vmlinuz", "/boot/vmlinuz"}, {"/var/t?p/*", "/var/tmp/x"}, {"/var/", "/var/tmp/x"},
	} {
		f.Add(s[0], s[1])
	}
	opsFuzzBox(f)
	offs, err := opOffLimits()
	if err != nil {
		f.Fatal(err)
	}
	var protected []string
	for _, off := range offs {
		protected = append(protected, off, off+"/x", off+"/x/y")
		for p := filepath.Dir(off); p != "/"; p = filepath.Dir(p) {
			protected = append(protected, p)
		}
	}
	system := []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/boot"}
	for _, s := range system {
		protected = append(protected, s, s+"/x", s+"/x/y")
	}
	f.Fuzz(func(t *testing.T, effect, changed string) {
		if effectOK(effect) != nil {
			return
		}
		for _, p := range protected {
			masked := false
			for _, s := range system {
				masked = masked || (strings.HasSuffix(effect, "/") && strings.HasPrefix(s, filepath.Clean(effect)+"/") &&
					(p == s || strings.HasPrefix(p, s+"/")))
			}
			if !masked && effectCovers([]string{effect}, p) {
				t.Fatalf("effect %q was accepted and covers %q, which is protected (the machine's record, inside or above it, or a system folder)", effect, p)
			}
		}
		c := filepath.Clean(changed)
		if !strings.HasPrefix(c, "/") || !effectCovers([]string{effect}, c) {
			return
		}
		for _, off := range offs {
			if c == off || strings.HasPrefix(c, off+"/") || strings.HasPrefix(off, c+"/") {
				t.Fatalf("effect %q was accepted and covers %q, which is at, under or above %q", effect, c, off)
			}
		}
		for _, s := range system {
			// A folder effect above one of these covers it by name, and the
			// sandbox masks it with an empty tmpfs, so no change there lands.
			above := strings.HasSuffix(effect, "/") && strings.HasPrefix(s, filepath.Clean(effect)+"/")
			if (c == s || strings.HasPrefix(c, s+"/")) && !above {
				t.Fatalf("effect %q was accepted and covers %q, which is at or under %q", effect, c, s)
			}
		}
	})
}

// A path param is a value the host fills in per run. Whatever it sends, a
// value checkParams accepts cleans to the param's root or below, and one that
// also passes an approved folder bound cleans to that folder or below. The
// bound itself must sit under the root to be accepted at all.
func FuzzAPathParamStaysUnderItsApprovedFolder(f *testing.F) {
	for _, s := range [][2]string{
		{"/srv/data/a", "/srv/data/a"}, {"/srv/data/a/../../x", "/srv/data"}, {"/srv/database", "/srv/data"},
		{"/srv/data", "/srv/data/a"}, {"srv/data/a", "/srv/data"}, {"/srv/data/a/", "/srv/data/a/b"},
		{"/srv/data/./a", "/srv/data/a/.."}, {"/srv/data\x00/x", "/srv/data"}, {"//srv/data/a", "/srv//data"},
	} {
		f.Add(s[0], s[1])
	}
	const root = "/srv/data"
	m := &opManifest{Params: map[string]opParam{"p": {Type: "path", Root: root}}}
	f.Fuzz(func(t *testing.T, value, prefix string) {
		raw, _ := json.Marshal(map[string]string{"p": value})
		vals, err := checkParams(m, string(raw))
		if err != nil {
			return
		}
		c := filepath.Clean(value)
		if c != root && !strings.HasPrefix(c, root+"/") {
			t.Fatalf("path param %q was accepted, and it cleans to %q, outside %s", value, c, root)
		}
		braw, _ := json.Marshal(map[string]map[string]string{"p": {"prefix": prefix}})
		bounds, err := parseBounds(m, string(braw))
		if err != nil {
			return
		}
		pc := filepath.Clean(prefix)
		if pc != root && !strings.HasPrefix(pc, root+"/") {
			t.Fatalf("bound prefix %q was accepted, and it cleans to %q, outside %s", prefix, pc, root)
		}
		if checkBounds(m, bounds, vals) != nil {
			return
		}
		if c != pc && !strings.HasPrefix(c, pc+"/") {
			t.Fatalf("path param %q passed the bound %q, and it cleans to %q, outside %q", value, prefix, c, pc)
		}
	})
}

// What an op can see (ops_view.go). Whatever effect or read effectOK accepts,
// nothing at or inside a credential store is ever in the op's view: the
// closed view keeps a path only when a visible path holds it, and an accepted
// declared path never reaches a store. Checked against every store (a `*`
// replaced by a name) and whatever path the fuzzer pairs with the declared one.
func FuzzAnOpNeverSeesACredentialStore(f *testing.F) {
	for _, s := range [][2]string{
		{"/srv/app/", "/srv/app/x"}, {"/etc/*.conf", "/etc/shadow"}, {"/etc/nginx/", "/etc/ssh/sshd_config"},
		{"/home/alice/site/", "/home/alice/.ssh/id_ed25519"}, {"/var/lib/*/state", "/var/lib/rancher/state"},
		{"/opt/*/x", "/opt/acme/x"}, {"/etc/ssl/", "/etc/ssl/private/key.pem"}, {"/usr/local/bin/tool", "/root/.docker/config.json"},
		{"/srv/[a-z]*/", "/srv/app/x"}, {"/etc/s?stemd/", "/etc/systemd/system/x"},
	} {
		f.Add(s[0], s[1])
	}
	opsFuzzBox(f)
	var stores []string
	for _, s := range opSensitiveBuiltIn {
		c := strings.ReplaceAll(s, "*", "alice")
		stores = append(stores, c, c+"/x", c+"/x/y")
	}
	f.Fuzz(func(t *testing.T, declared, probe string) {
		if effectOK(declared) != nil {
			return
		}
		m := &opManifest{Effects: opEffects{Files: []string{declared}}, Reads: []string{declared}}
		segs := opViewSegments(opViewVisible(opViewDeclared(m)))
		check := append([]string{}, stores...)
		// The probe is a real path (a `*` in it is a character, not a glob):
		// it is checked when it lies at or inside a store.
		if c := filepath.Clean(probe); strings.HasPrefix(c, "/") {
			cs := pathSegments(c)
			for _, s := range opSensitiveBuiltIn {
				ss := pathSegments(s)
				inside := len(cs) >= len(ss)
				for i := 0; inside && i < len(ss); i++ {
					inside = opSegMatch(ss[i], cs[i])
				}
				if inside {
					check = append(check, c)
				}
			}
		}
		for _, p := range check {
			if opViewDecide(p, segs) == opViewKeep {
				t.Fatalf("declared %q was accepted and the op would see %q, inside a credential store", declared, p)
			}
		}
	})
}
