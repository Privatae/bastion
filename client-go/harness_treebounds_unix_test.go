//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// A copy of a tree of very many empty files stops at its limit, and what it
// holds in memory does not grow with the number of files.
func TestACopyOfVeryManyEmptyFilesIsRefusedWithBoundedMemory(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for i := 0; i < 50; i++ {
		d := filepath.Join(src, "d"+strconv.Itoa(i))
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 400; j++ {
			if err := os.WriteFile(filepath.Join(d, "f"+strconv.Itoa(j)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := mirrorTree(src, dst, 1<<20)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, errTreeTooLarge) {
		t.Fatalf("20000 empty files under a 1 MiB limit: %v", err)
	}
	got := after.TotalAlloc - before.TotalAlloc
	t.Logf("refused: %v; %d KiB allocated", err, got>>10)
	if got > 16<<20 {
		t.Errorf("the copy allocated %d MiB", got>>20)
	}
	n := 0
	_ = filepath.WalkDir(dst, func(string, os.DirEntry, error) error { n++; return nil })
	if n > (1<<20)/512+1 {
		t.Errorf("%d entries were written under a limit of %d", n, (1<<20)/512)
	}
}

// Left-out entries are counted in full, and only the first
// maxSkippedReported names are kept.
func TestLeftOutEntriesAreCountedAndTheirNamesBounded(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for i := 0; i < 3*maxSkippedReported; i++ {
		if err := os.Symlink("x", filepath.Join(src, "l"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	skips, err := mirrorTree(src, dst, maxCopiedTreeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if skips.count != 3*maxSkippedReported || len(skips.names) != maxSkippedReported {
		t.Errorf("count %d, %d names kept", skips.count, len(skips.names))
	}
	res := map[string]interface{}{}
	skips.report(res)
	if res["worktree_skipped_count"] != 3*maxSkippedReported {
		t.Errorf("reported %v", res)
	}
}

func TestRepoGitAuthPutsTheTokenOnlyInTheEnvironment(t *testing.T) {
	bare, env, err := repoGitAuth("https://host-user:tok3n0f7hisrun5a1e@git.example.invalid/o/r.git")
	if err != nil || bare != "https://git.example.invalid/o/r.git" {
		t.Fatalf("bare = %q, %v", bare, err)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "GIT_CONFIG_KEY_0=http.https://git.example.invalid/o/r.git.extraHeader") ||
		!strings.Contains(joined, "GIT_CONFIG_VALUE_0=Authorization: Basic ") {
		t.Errorf("env = %q", env)
	}
	if _, env, _ := repoGitAuth("/srv/x/origin.git"); env != nil {
		t.Errorf("a path got credentials: %v", env)
	}
}

// One folder holding very many names is refused once the names read pass
// the limit, without the whole folder being read first.
func TestAFolderOfVeryManyNamesIsRefusedWithoutReadingItWhole(t *testing.T) {
	src := t.TempDir()
	long := strings.Repeat("n", 190)
	for i := 0; i < 30000; i++ {
		if err := os.WriteFile(filepath.Join(src, long+strconv.Itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	saved := maxReturnedTreeBytes
	maxReturnedTreeBytes = 1 << 20
	t.Cleanup(func() { maxReturnedTreeBytes = saved })
	for name, walk := range map[string]func() error{
		"copy": func() error { _, err := mirrorTree(src, t.TempDir(), 1<<20); return err },
		"tar":  func() error { _, _, err := packWorktree(src); return err },
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		err := walk()
		runtime.ReadMemStats(&after)
		got := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: %v; %d KiB allocated", name, err, got>>10)
		if !errors.Is(err, errTreeTooLarge) {
			t.Errorf("%s: a folder of 30000 names under a 1 MiB limit: %v", name, err)
		}
		if got > 4<<20 {
			t.Errorf("%s: %d KiB allocated; the 30000 names alone are about 6 MiB", name, got>>10)
		}
	}
}
