//go:build !windows

package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const tarOutsideSecret = "outside-the-tree-3f9a"

// tarInsideA is as long as the outside file: a writer who knows a file's size
// can make the one it swaps out the same size, so the tar's header fits.
const tarInsideA = "inside-the-tree-a-000"

// tarEntries reads back what makeTar produced: name -> content.
func tarEntries(t *testing.T, b []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = string(data)
	}
}

// outsideAndTree makes a file outside the tree that a run must never return,
// and a tree with one file and one folder.
func outsideAndTree(t *testing.T) (outsideDir, secret, tree string) {
	t.Helper()
	outsideDir = t.TempDir()
	secret = filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(secret, []byte(tarOutsideSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	tree = t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "a.txt"), []byte(tarInsideA), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Named as the outside file is: a writer who knows the names in a folder
	// outside can fill a folder of the tree with the same names, then swap it.
	if err := os.WriteFile(filepath.Join(tree, "sub", "secret"), []byte("inside b"), 0o644); err != nil {
		t.Fatal(err)
	}
	return outsideDir, secret, tree
}

func assertNoOutside(t *testing.T, ents map[string]string) {
	t.Helper()
	for name, data := range ents {
		if strings.Contains(data, tarOutsideSecret) {
			t.Fatalf("the tar holds a file from outside the tree, as %q", name)
		}
	}
}

// The tree's writer swaps a file for a link, and a folder for a link, after
// the walk has seen each one as a plain file or folder and before it opens it.
// The hook stands exactly in that gap, so the swap lands there every time.
func TestMakeTarNeverReadsThroughALinkSwappedInBeforeTheOpen(t *testing.T) {
	for _, swap := range []string{"a.txt", "sub"} {
		t.Run(swap, func(t *testing.T) {
			outsideDir, secret, tree := outsideAndTree(t)
			packTreeBeforeOpen = func(rel string) {
				if rel != swap {
					return
				}
				p := filepath.Join(tree, swap)
				_ = os.RemoveAll(p)
				if swap == "sub" {
					_ = os.Symlink(outsideDir, p)
				} else {
					_ = os.Symlink(secret, p)
				}
			}
			defer func() { packTreeBeforeOpen = nil }()
			b, err := makeTar(tree)
			if err != nil {
				t.Fatalf("makeTar: %v", err)
			}
			ents := tarEntries(t, b)
			assertNoOutside(t, ents)
			if swap == "a.txt" {
				if _, ok := ents["a.txt"]; ok {
					t.Fatalf("a.txt was a link when it was opened and must be left out, got it in the tar")
				}
			}
		})
	}
}

// No hook: a writer flips one name between a plain file and a link to a file
// outside the tree as fast as it can while the tree is packed again and again.
func TestMakeTarNeverReadsThroughALinkUnderAConcurrentWriter(t *testing.T) {
	_, secret, tree := outsideAndTree(t)
	name := filepath.Join(tree, "a.txt")
	tmpLink, tmpFile := filepath.Join(tree, ".l"), filepath.Join(tree, ".f")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.WriteFile(tmpFile, []byte(tarInsideA), 0o644)
			_ = os.Rename(tmpFile, name)
			_ = os.Symlink(secret, tmpLink)
			_ = os.Rename(tmpLink, name)
		}
	}()
	defer func() { close(stop); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	passes := 0
	defer func() { t.Logf("%d passes", passes) }()
	for i := 0; time.Now().Before(deadline); i++ {
		passes = i + 1
		b, err := makeTar(tree)
		if err != nil {
			continue // a name that vanished mid-walk; the next pass tries again
		}
		for n, data := range tarEntries(t, b) {
			if strings.Contains(data, tarOutsideSecret) {
				t.Fatalf("pass %d: the tar holds the file outside the tree, as %q", i, n)
			}
		}
	}
}

// A link, a named pipe and a socket in the tree are left out and named as
// left out; the pipe is never opened, so the walk does not wait on it.
func TestMakeTarLeavesOutAndNamesWhatIsNotAPlainFileOrFolder(t *testing.T) {
	_, secret, tree := outsideAndTree(t)
	if err := os.Symlink(secret, filepath.Join(tree, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(tree, "sub", "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tree, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, ".git", "config"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	type res struct {
		b       []byte
		skipped []string
		err     error
	}
	ch := make(chan res, 1)
	go func() { b, s, err := packWorktree(tree); ch <- res{b, s, err} }()
	var r res
	select {
	case r = <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("packing the tree waited on the named pipe")
	}
	if r.err != nil {
		t.Fatalf("packWorktree: %v", r.err)
	}
	ents := tarEntries(t, r.b)
	assertNoOutside(t, ents)
	for _, want := range []string{"a.txt", "sub", "sub/secret"} {
		if _, ok := ents[want]; !ok {
			t.Errorf("%s missing from the tar (got %v)", want, ents)
		}
	}
	if ents["a.txt"] != tarInsideA || ents["sub/secret"] != "inside b" {
		t.Errorf("file contents changed in the tar: %v", ents)
	}
	for _, gone := range []string{"link", "sub/pipe", ".git", ".git/config"} {
		if _, ok := ents[gone]; ok {
			t.Errorf("%s is in the tar and must not be", gone)
		}
	}
	got := strings.Join(r.skipped, ",")
	if got != "link,sub/pipe" {
		t.Errorf("left out = %q, want link,sub/pipe", got)
	}
}
