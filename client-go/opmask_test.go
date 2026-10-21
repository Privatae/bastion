package main

// Gate: a host's backup folder on a mount that stopped answering cannot
// stop op runs. Its mask is left out for the run when a stat of it errors
// or does not return in time, and it stays refused by every text check.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func opMaskFixture(t *testing.T) (nas, conf string) {
	t.Helper()
	uiTestConfigDir(t)
	nas = filepath.Join(t.TempDir(), "nas")
	_ = os.MkdirAll(nas, 0o700)
	savePairingWithRoot(t, "nas.host.privatae.ai", nas)
	conf, _ = configDirPath()
	prevT, prevS, prevR, prevL := opMaskProbeTimeout, opMaskStat, opResolveFn, opMaskLog
	opMaskProbeTimeout = 100 * time.Millisecond
	var logged []string
	opMaskLog = func(format string, a ...any) { logged = append(logged, format) }
	t.Cleanup(func() {
		opMaskProbeTimeout, opMaskStat, opResolveFn, opMaskLog = prevT, prevS, prevR, prevL
		opProbeMu.Lock()
		opProbeLogged = map[string]bool{}
		opProbeMu.Unlock()
	})
	return nas, conf
}

func has(list []string, p string) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

func stillRefused(t *testing.T, nas string) {
	t.Helper()
	offs, err := opOffLimits()
	if err != nil || !has(offs, nas) {
		t.Fatalf("the backup folder left the off-limits set: %v %v", err, offs)
	}
	if off, err := underOffLimits(filepath.Join(nas, fixtureData)); err != nil || off == "" {
		t.Fatalf("an op may now name the backup folder: %q %v", off, err)
	}
}

func TestOpMasksSkipABackupFolderWhoseStatErrors(t *testing.T) {
	nas, conf := opMaskFixture(t)
	masks, err := opMaskSet()
	if err != nil || !has(masks, nas) || !has(masks, conf) {
		t.Fatalf("a folder that answers is masked: %v %v", err, masks)
	}
	opMaskStat = func(p string) (os.FileInfo, error) {
		if p == nas {
			return nil, errors.New("stale file handle")
		}
		return os.Stat(p)
	}
	masks, err = opMaskSet()
	if err != nil {
		t.Fatalf("an erroring backup folder refused the run: %v", err)
	}
	if has(masks, nas) {
		t.Fatal("an erroring backup folder is still masked, so the run would fail on it")
	}
	if !has(masks, conf) {
		t.Fatal("the configuration folder lost its mask")
	}
	stillRefused(t, nas)
	// Missing is not an error: the mask step skips it itself.
	opMaskStat = func(p string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	if masks, _ := opMaskSet(); !has(masks, nas) {
		t.Fatal("a missing backup folder was treated as unanswering")
	}
}

func TestOpMasksDoNotWaitOnABackupFolderThatHangs(t *testing.T) {
	nas, conf := opMaskFixture(t)
	gate := make(chan struct{})
	// Release the blocked probes and wait for them to finish before the
	// fixture puts the hooks back, so nothing still running reads them.
	t.Cleanup(func() {
		close(gate)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			opProbeMu.Lock()
			n := len(opProbeInFlight)
			opProbeMu.Unlock()
			if n == 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Error("the released probes never finished")
	})
	calls := 0
	opMaskStat = func(p string) (os.FileInfo, error) {
		if p == nas {
			opProbeMu.Lock()
			calls++
			opProbeMu.Unlock()
			<-gate
		}
		return os.Stat(p)
	}
	opResolveFn = func(p string) string {
		if p == nas {
			<-gate
		}
		return resolveExisting(p)
	}
	for i := 0; i < 3; i++ {
		start := time.Now()
		masks, err := opMaskSet()
		if err != nil {
			t.Fatal(err)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("building the masks waited %s on a folder that does not answer", el)
		}
		if has(masks, nas) || !has(masks, conf) {
			t.Fatalf("masks %v", masks)
		}
	}
	opProbeMu.Lock()
	n := calls
	opProbeMu.Unlock()
	if n != 1 {
		t.Fatalf("a hung stat was started %d times; later runs must not pile up behind it", n)
	}
	stillRefused(t, nas)
	// Said once, not per run.
	opProbeMu.Lock()
	logged := opProbeLogged[nas]
	opProbeMu.Unlock()
	if !logged {
		t.Fatal("the unanswering folder was not logged")
	}
}

func TestOpMaskNoteLogsOnce(t *testing.T) {
	opMaskFixture(t)
	var lines []string
	opMaskLog = func(format string, a ...any) { lines = append(lines, format) }
	for i := 0; i < 3; i++ {
		opMaskNote("/mnt/nas/x", errors.New("stale"))
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "cannot be checked") {
		t.Fatalf("logged %d lines: %v", len(lines), lines)
	}
}

// hangFolder makes resolving (and stating) the folder p block until the
// test ends, as a network mount that stopped answering does. The blocked
// probes are released and waited for before the hooks go back.
func hangFolder(t *testing.T, p string) {
	t.Helper()
	gate := make(chan struct{})
	prevR, prevS := opResolveFn, opMaskStat
	opResolveFn = func(q string) string {
		if q == p {
			<-gate
		}
		return prevR(q)
	}
	opMaskStat = func(q string) (os.FileInfo, error) {
		if q == p {
			<-gate
		}
		return prevS(q)
	}
	t.Cleanup(func() {
		close(gate)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			opProbeMu.Lock()
			n := len(opProbeInFlight)
			opProbeMu.Unlock()
			if n == 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		opResolveFn, opMaskStat = prevR, prevS
	})
}

// One host's folder not answering blocks no other host's backup ops, and a
// host whose own folder does not answer is refused with a sentence.
func TestBackupRootChecksDoNotWaitOnAStaleFolder(t *testing.T) {
	opMaskFixture(t)
	const a, b = "a.host.privatae.ai", "b.host.privatae.ai"
	rootA := filepath.Join(t.TempDir(), "a")
	stale := filepath.Join(t.TempDir(), "stale")
	_ = os.MkdirAll(rootA, 0o700)
	_ = os.MkdirAll(stale, 0o700)
	savePairingWithRoot(t, a, rootA)
	savePairingWithRoot(t, b, stale)
	hangFolder(t, stale)
	for i := 0; i < 3; i++ {
		start := time.Now()
		if why := backupRootProblem(a, rootA); why != "" {
			t.Fatalf("another host's stale folder refused this one: %s", why)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("the check waited %s on another host's stale folder", el)
		}
	}
	start := time.Now()
	why := backupRootProblem(b, stale)
	if why == "" || !strings.Contains(why, "does not answer") {
		t.Fatalf("a host whose own folder does not answer was not refused as such: %q", why)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("refusing took %s", el)
	}
}

// While a folder does not answer, where it last resolved to still counts:
// no op may name the real place, and no host's folder may be set over it.
func TestAStaleBackupFolderKeepsItsLastKnownPlace(t *testing.T) {
	opMaskFixture(t)
	const a, b = "a.host.privatae.ai", "b.host.privatae.ai"
	real := filepath.Join(t.TempDir(), "nas-real")
	_ = os.MkdirAll(real, 0o700)
	link := filepath.Join(t.TempDir(), "nas-link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("no symlinks here")
	}
	savePairingWithRoot(t, b, link)
	// It answers once: its real place is learned.
	offs, err := opOffLimits()
	if err != nil || !has(offs, real) {
		t.Fatalf("the real place is not off limits while it answers: %v %v", err, offs)
	}
	hangFolder(t, link)
	offs, err = opOffLimits()
	if err != nil || !has(offs, real) || !has(offs, link) {
		t.Fatalf("the real place left the off-limits set during the outage: %v %v", err, offs)
	}
	if off, err := underOffLimits(filepath.Join(real, fixtureData)); err != nil || off == "" {
		t.Fatalf("an op may name the real place during the outage: %q %v", off, err)
	}
	// Another host set over the real place is refused during the outage too.
	rootA := filepath.Join(real, "a")
	_ = os.MkdirAll(rootA, 0o700)
	savePairingWithRoot(t, a, rootA)
	if why := backupRootProblem(a, rootA); why == "" || !strings.Contains(why, b) {
		t.Fatalf("a folder inside the stale host's real place was accepted: %q", why)
	}
	// And the last place survives a restart.
	lastResolvedMu.Lock()
	lastResolvedLoaded, lastResolvedMap = false, nil
	lastResolvedMu.Unlock()
	abs, _ := filepath.Abs(link)
	if got := lastResolved(abs); got != real {
		t.Fatalf("after a restart the last place is %q, not %q", got, real)
	}
}

// The record of where each backup folder last resolved is bounded: past
// lastResolvedMax folders, the one resolved longest ago goes. A folder still
// in use keeps its place (its time is refreshed at least daily, on disk
// too), and the record's first shape (folder -> place) still loads.
func TestLastResolvedIsBounded(t *testing.T) {
	uiTestConfigDir(t)
	reset := func() {
		lastResolvedMu.Lock()
		lastResolvedLoaded, lastResolvedMap = false, nil
		lastResolvedMu.Unlock()
	}
	reset()
	prevNow := lastResolvedNow
	clock := int64(1_000_000)
	lastResolvedNow = func() int64 { return clock }
	t.Cleanup(func() { lastResolvedNow = prevNow; reset() })

	noteResolved("/in-use", "/real/in-use")
	for i := 0; i < lastResolvedMax+50; i++ {
		clock += 3600
		noteResolved(fmt.Sprintf("/f%04d", i), fmt.Sprintf("/real/f%04d", i))
		if i%20 == 0 {
			noteResolved("/in-use", "/real/in-use") // resolved again, in use
		}
	}
	lastResolvedMu.Lock()
	n := len(lastResolvedMap)
	lastResolvedMu.Unlock()
	if n > lastResolvedMax {
		t.Fatalf("%d folders kept, bound %d", n, lastResolvedMax)
	}
	if lastResolved("/in-use") != "/real/in-use" {
		t.Fatal("a folder in use was dropped")
	}
	if lastResolved("/f0000") != "" || lastResolved(fmt.Sprintf("/f%04d", lastResolvedMax+49)) == "" {
		t.Fatal("the oldest folder was kept or the newest dropped")
	}
	// After a restart: the same, read from disk.
	reset()
	if lastResolved("/in-use") != "/real/in-use" || lastResolved("/f0000") != "" {
		t.Fatal("the bound or the order did not survive a restart")
	}
	// The first shape of the file loads.
	p, _ := lastResolvedPath()
	_ = os.WriteFile(p, []byte(`{"/old":"/real/old"}`), 0o600)
	reset()
	if lastResolved("/old") != "/real/old" {
		t.Fatal("the first shape of the record did not load")
	}
}
