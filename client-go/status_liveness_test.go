//go:build !windows

package main

import (
	"net"
	"os"
	"testing"
)

// cmdStatus must actually answer "is it running", not just print pairings.
// Drives the real liveness probe against a real listener rather than asserting
// the string, because the probe is the part that can be wrong.
func TestStatusReportsWhetherItIsRunning(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writePairing(t, tAnchor)

	cfgs, err := loadPairings()
	if err != nil || len(cfgs) == 0 {
		t.Fatalf("setup: %v", err)
	}
	// writePairing leaves ListenAddr empty; give it one nothing is on.
	if err := cfgs[0].updateOnDisk(func(d *Config) { d.ListenAddr = "127.0.0.1:53999" }); err != nil {
		t.Fatal(err)
	}
	if bastionListening("127.0.0.1:53999") {
		t.Fatal("nothing should be listening on the probe port yet")
	}
	if bastionListening("") {
		t.Fatal("an empty address must never read as running")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:53999")
	if err != nil {
		t.Skipf("cannot bind the probe port here: %v", err)
	}
	defer ln.Close()
	if !bastionListening("127.0.0.1:53999") {
		t.Fatal("a real listener must read as running — this is the whole probe")
	}
	// And cmdStatus itself must not explode on either path.
	if err := cmdStatus(); err != nil {
		t.Fatalf("status must not error while running: %v", err)
	}
	_ = os.Stdout
}
