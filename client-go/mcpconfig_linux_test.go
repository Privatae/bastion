//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO left where a client keeps its config must not hold the read, and
// with it the heartbeat: it is counted unreadable and the scan moves on.
func TestReadMCPConfigsDoesNotBlockOnAFIFO(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(home, ".cursor", "mcp.json"), 0o600); err != nil {
		t.Skipf("cannot make a FIFO here: %v", err)
	}
	oldH, oldS := mcpHomesFn, mcpSystemFn
	t.Cleanup(func() { mcpHomesFn, mcpSystemFn = oldH, oldS })
	mcpHomesFn = func() ([]mcpHome, bool) { return []mcpHome{{Dir: home, ConfigDir: home}}, true }
	mcpSystemFn = func() []mcpSource { return nil }

	done := make(chan mcpConfigScan, 1)
	go func() { _, scan := readMCPConfigs(); done <- scan }()
	select {
	case scan := <-done:
		if scan.Unreadable != 1 {
			t.Fatalf("the FIFO was not counted: %+v", scan)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading the config files blocked on a FIFO")
	}
}
