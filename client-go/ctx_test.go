package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanRel(t *testing.T) {
	root := filepath.Join(string(os.PathSeparator), "var", "ctx-root")

	// Paths that MUST be rejected — traversal, absolute, dot/empty, NUL.
	reject := []string{
		"/etc/passwd",
		"../x",
		"a/../../x",
		"..",
		".",
		"",
		"  ",     // whitespace-only trims to empty
		"a\x00b", // NUL byte
		"../../../etc/shadow",
		"e/../../x",
	}
	for _, rp := range reject {
		if abs, ok := cleanRel(root, rp); ok {
			t.Errorf("cleanRel(root, %q) accepted (%q), want rejected", rp, abs)
		}
	}

	// Paths that MUST be accepted — all resolve strictly inside root.
	accept := []struct {
		rpath    string
		wantBase string // basename of the resolved path, sanity check
	}{
		{"entity-1/m.txt", "m.txt"},
		{"e/a/b.bin", "b.bin"},
		{"./e2/x", "x"},
	}
	for _, c := range accept {
		abs, ok := cleanRel(root, c.rpath)
		if !ok {
			t.Errorf("cleanRel(root, %q) rejected, want accepted", c.rpath)
			continue
		}
		cleanRoot := filepath.Clean(root)
		if abs != cleanRoot && !strings.HasPrefix(abs, cleanRoot+string(os.PathSeparator)) {
			t.Errorf("cleanRel(root, %q) = %q, escapes root %q", c.rpath, abs, cleanRoot)
		}
		if filepath.Base(abs) != c.wantBase {
			t.Errorf("cleanRel(root, %q) base = %q, want %q", c.rpath, filepath.Base(abs), c.wantBase)
		}
	}
}

func TestAtomicWriteRoundtrip(t *testing.T) {
	root := t.TempDir()
	abs, ok := cleanRel(root, "entity-1/blob.bin")
	if !ok {
		t.Fatal("cleanRel rejected a valid path")
	}
	want := []byte("hello\x00world")
	if err := atomicWrite(abs, want); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}
	got, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("readback = %q, want %q", got, want)
	}
	// File must be 0600, and no stray temp files left in the dir.
	fi, err := os.Stat(abs)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 600", perm)
	}
	entries, _ := os.ReadDir(filepath.Dir(abs))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ctx-") {
			t.Errorf("stray temp file left behind: %s", e.Name())
		}
	}
}
