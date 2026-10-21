package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSwapBinaryAt is the regression guard for the self-update swap. The old code
// os.Rename'd a temp file OVER the running binary, which fails on Windows (a running
// .exe is locked) — so Windows bastions never updated. swapBinaryAt moves the current
// binary aside first, then writes the new one at the original path (works on every OS).
func TestSwapBinaryAt(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "privatae-bastion")
	if err := os.WriteFile(bin, []byte("OLD-BINARY-v1"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := swapBinaryAt(bin, []byte("NEW-BINARY-v2")); err != nil {
		t.Fatalf("swap: %v", err)
	}

	// The path now holds the new bytes...
	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW-BINARY-v2" {
		t.Errorf("after swap, binary = %q, want NEW-BINARY-v2", got)
	}
	// ...and the previous binary is preserved as the .old rollback (a running binary
	// can't delete itself; cleanupStaleBinaries clears it next start).
	oldb, err := os.ReadFile(bin + ".old")
	if err != nil {
		t.Fatalf("rollback .old missing: %v", err)
	}
	if string(oldb) != "OLD-BINARY-v1" {
		t.Errorf(".old = %q, want OLD-BINARY-v1", oldb)
	}

	// A second swap must succeed (it overwrites the stale .old, not error on it).
	if err := swapBinaryAt(bin, []byte("NEWER-v3")); err != nil {
		t.Fatalf("second swap: %v", err)
	}
	got, _ = os.ReadFile(bin)
	if string(got) != "NEWER-v3" {
		t.Errorf("after second swap, binary = %q, want NEWER-v3", got)
	}
}
