package main

// Fuzz targets for the path walls that take a name from a host and turn it
// into a path on this machine. Each one states the property the wall exists
// for and lets the fuzzer look for an input that breaks it. The seeds run on
// every `go test`; deploy/fuzz.sh runs each target for a bounded time.
//
// These two are pure (no filesystem state), so they run on every platform.
// The walls that follow symlinks are in fuzz_paths_unix_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cleanRel is the traversal wall every store read, context write and session
// log goes through. Whatever the host sends, an accepted path is strictly
// inside the root: never the root itself, never beside it, never above it.
func FuzzCleanRelStaysInsideTheRoot(f *testing.F) {
	for _, s := range []string{
		"a", "a/b", "sub/a.txt", "..", "../x", "a/../../x", "a/..", ".", "./a", "a//b",
		"/etc/passwd", "a\x00b", "  a  ", "..\\x", "a/../b/../../c", "....", "...",
		"a/./../..", "\u2025/x", "a/b/c/../../..", "C:\\x", "\\\\host\\share",
	} {
		f.Add(s)
	}
	root := filepath.Join(f.TempDir(), "root")
	f.Fuzz(func(t *testing.T, rpath string) {
		got, ok := cleanRel(root, rpath)
		if !ok {
			if got != "" {
				t.Fatalf("a refusal returned a path: %q", got)
			}
			return
		}
		if !strings.HasPrefix(got, root+string(os.PathSeparator)) {
			t.Fatalf("cleanRel(%q) = %q, which is not strictly inside %q", rpath, got, root)
		}
		rel, err := filepath.Rel(root, got)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			t.Fatalf("cleanRel(%q) = %q, which is outside %q (rel %q)", rpath, got, root, rel)
		}
		if got != filepath.Clean(got) {
			t.Fatalf("cleanRel(%q) = %q is not clean", rpath, got)
		}
	})
}

// A service slot's record, data dir and socket are joined from the name and
// socket the host sends. Once validateServiceSpec accepts them, each must be
// exactly one path element: the record lands in the services dir, the data dir
// is <services>/<name>/data, and the socket sits directly in that data dir.
func FuzzServiceSlotPathsStayInTheirDirectory(f *testing.F) {
	for _, s := range [][3]string{
		{"gitea", "gitea.sock", "/data"},
		{"../x", "gitea.sock", "/data"},
		{"a", "../../x.sock", "/data"},
		{"a", ".", "/data"},
		{"a", "..", "/data"},
		{"a", "s/../../x", "/data"},
		{"a", "x.sock", "/"},
		{"a", "x.sock", "/data/../.."},
		{"a", "x.sock", "c:/data"},
		{"a-", "x.sock", "/srv/data"},
		{"A", "x.sock", "/data"},
		{"a", "x\x00.sock", "/data"},
	} {
		f.Add(s[0], s[1], s[2])
	}
	services := filepath.Join(f.TempDir(), "services")
	f.Fuzz(func(t *testing.T, name, socket, dataPath string) {
		spec := harnessSpec{ServiceName: name, Image: "registry.example.com/app:1", Socket: socket,
			DataPath: dataPath, DataUID: 1000}
		if validateServiceSpec(spec) != "" {
			return
		}
		rec := filepath.Join(services, name+".json")
		if filepath.Dir(rec) != services || filepath.Base(rec) != name+".json" {
			t.Fatalf("the record for %q lands at %q, outside %q", name, rec, services)
		}
		data := filepath.Join(services, name, "data")
		if filepath.Dir(filepath.Dir(data)) != services || filepath.Base(filepath.Dir(data)) != name {
			t.Fatalf("the data dir for %q is %q, not <services>/%s/data", name, data, name)
		}
		sock := filepath.Join(data, socket)
		if filepath.Dir(sock) != data || filepath.Base(sock) != socket {
			t.Fatalf("socket %q joins to %q, which is not directly in %q", socket, sock, data)
		}
		// data_path is a path inside the container; it must name one clean
		// absolute place other than the container's root: every segment a
		// real name, none empty, "." or "..".
		if !strings.HasPrefix(dataPath, "/") || dataPath == "/" {
			t.Fatalf("data_path %q was accepted", dataPath)
		}
		for _, seg := range strings.Split(dataPath[1:], "/") {
			if seg == "" || seg == "." || seg == ".." {
				t.Fatalf("data_path %q was accepted, with the segment %q", dataPath, seg)
			}
		}
	})
}
