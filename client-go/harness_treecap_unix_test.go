//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A file far larger than the tree a run may return (sparse, so it costs
// nothing to make) is refused from its size: packing returns at once, with
// an error and no tar, having read none of it.
func TestPackingRefusesAFileLargerThanTheLaneCarriesWithoutReadingIt(t *testing.T) {
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(tree, "huge.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64 << 30); err != nil {
		t.Skipf("no sparse file here: %v", err)
	}
	f.Close()
	type res struct {
		b   []byte
		err error
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	ch := make(chan res, 1)
	start := time.Now()
	go func() { b, _, err := packWorktree(tree); ch <- res{b, err} }()
	var r res
	select {
	case r = <-ch:
	case <-time.After(20 * time.Second):
		t.Fatal("packing a tree with a 64 GiB file was still going after 20 s")
	}
	runtime.ReadMemStats(&after)
	t.Logf("returned in %v, %d MiB allocated", time.Since(start), (after.TotalAlloc-before.TotalAlloc)>>20)
	if r.err == nil || !strings.Contains(r.err.Error(), "huge.bin") || !strings.Contains(r.err.Error(), "too large") {
		t.Fatalf("want the tree refused for huge.bin, got %v", r.err)
	}
	if r.b != nil {
		t.Fatal("a tar came back with the refusal")
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 64<<20 {
		t.Fatalf("packing allocated %d MiB", got>>20)
	}
}

// A result larger than one message on the lane is replaced by a refusal that
// says so, never sent to be dropped by the host; one that fits goes as it is.
func TestAResultTheLaneCannotCarryIsRefusedNotSent(t *testing.T) {
	small := []byte(`{"ok":true,"mode":"worktree"}`)
	if b, code := fitLane(small, 0); string(b) != string(small) || code != 0 {
		t.Fatalf("a result that fits was changed: %s %d", b, code)
	}
	big := append([]byte(`{"ok":true,"mode":"worktree","worktree_b64":"`), make([]byte, uvicornWSMaxSize)...)
	b, code := fitLane(big, 0)
	if code == 0 || len(b) > 1024 || !strings.Contains(string(b), `"result_too_large":true`) ||
		!strings.Contains(string(b), `"ok":false`) {
		t.Fatalf("an oversized result was not refused: %d bytes, code %d: %.200s", len(b), code, b)
	}
}
