package main

// The deny list has two writers in two processes: the daemon (the console page)
// and `switch` from a terminal (switch_cli.go). localDenyMu serialises only
// the goroutines of one process, so each test below stands in for the other
// process by going around it. Every host name here is invented.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The gate reads the list on every op and fails OPEN on a file it cannot
// parse. A reader that catches the other process mid-write must therefore see
// the old list or the new one, never an empty or partial file.
func TestALocalDenyReaderNeverSeesAHalfWrittenList(t *testing.T) {
	uiTestConfigDir(t)
	const hosts = 200
	f := &localDenyFile{Off: map[string][]string{}, At: map[string]string{}}
	for i := 0; i < hosts; i++ {
		f.Off[fmt.Sprintf("host-%03d.example", i)] = []string{"egress", "harness", "inference", "session"}
	}
	if err := localDenySave(f); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 400; i++ {
			if err := localDenySave(f); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	torn, reads := 0, 0
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("the writer failed: %v", err)
			}
			if torn > 0 {
				t.Fatalf("%d of %d reads during a write saw a list that was not whole; "+
					"each of those lets every switched-off family through", torn, reads)
			}
			return
		default:
		}
		got, err := localDenyLoad()
		reads++
		if err != nil || len(got.Off) != hosts {
			torn++
		}
	}
}

// A switch waits while another process holds the list's lock, and once the
// lock is released it writes on top of what is there rather than over it.
func TestASwitchWaitsWhileAnotherProcessHoldsTheList(t *testing.T) {
	uiTestConfigDir(t)
	const host = "box-one.example"
	givenPairing(t, host, pairingActive)
	d, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	lf, err := os.OpenFile(filepath.Join(d, "local-deny.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := flockFile(lf); err != nil {
		_ = lf.Close()
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- localDenySet(host, "egress", true) }()
	select {
	case err := <-done:
		_ = lf.Close()
		t.Fatalf("the switch wrote the list while another process held its lock (err %v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	// The other process's own change lands while it holds the lock.
	if err := localDenySave(&localDenyFile{Off: map[string][]string{host: {"session"}}}); err != nil {
		_ = lf.Close()
		t.Fatal(err)
	}
	_ = lf.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the switch failed once the lock was free: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the switch never went ahead after the lock was released")
	}
	if !localDenied(host, "egress") || !localDenied(host, "session") {
		t.Fatalf("both switches must stand, the list holds %v", localDenyFamilies(host))
	}
}
