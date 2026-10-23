package main

// THE SUITE NEVER NAMES THE UNITS A RUNNING BASTION OWNS.
//
// The startup sweep (ops_action_linux.go opStartupSweep) stops every unit in
// the ops' slice whose name has an op's prefix, and a test runs it for real.
// Under the production names, a suite run on a machine whose own bastion is
// running an op would stop that op; under names shared between runs, two
// suites at once would stop each other's. So before any test runs (TestMain),
// this run takes a slice and prefixes of its own, with its pid and a random
// number in each.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The names every bastion so far gives its ops' slice and units. Written out
// rather than read from the code: they are what a bastion already installed
// on the machine uses, whatever this tree says.
const (
	opBastionSlice       = "privatae_ops.slice"
	opBastionActionUnits = "privatae-op-"
	opBastionScopeUnits  = "privatae-opfiles-"
)

// opIsolateOpsUnits gives this run its own ops' slice and unit prefixes. A
// slice name has no "-", which systemd would read as a slice inside another.
func opIsolateOpsUnits() {
	var b [4]byte
	_, _ = rand.Read(b[:])
	run := fmt.Sprintf("%dx%08x", os.Getpid(), binary.BigEndian.Uint32(b[:]))
	opActionSlice = "privatae_optest" + run + ".slice"
	opActionUnitPrefix = "privatae-optest" + run + "-"
	opScopeUnitPrefix = "privatae-optest" + run + "files-"
}

// opIsolatedOpsUnitsDone stops this run's own slice, which systemd keeps
// after its last unit ends. Never a slice a bastion uses.
func opIsolatedOpsUnitsDone() {
	if opActionSlice == opBastionSlice || !strings.HasPrefix(opActionSlice, "privatae_optest") {
		return
	}
	if _, err := os.Stat(filepath.Join("/sys/fs/cgroup", opActionSlice)); err == nil {
		_ = exec.Command("systemctl", "stop", opActionSlice).Run()
	}
}

// No name this run gives the ops' slice or units is a bastion's, sits in a
// bastion's slice, or shares a prefix with a bastion's units either way (so
// neither sweep takes the other's), and each holds this run's pid.
func TestTheSuiteNeverNamesTheUnitsABastionOwns(t *testing.T) {
	if opActionSlice == opBastionSlice || strings.HasPrefix(opActionSlice, strings.TrimSuffix(opBastionSlice, ".slice")+"-") {
		t.Errorf("the suite's ops' slice is %q: a bastion's own, or inside it", opActionSlice)
	}
	for _, mine := range []string{opActionUnitPrefix, opScopeUnitPrefix} {
		for _, theirs := range []string{opBastionActionUnits, opBastionScopeUnits} {
			if strings.HasPrefix(mine, theirs) || strings.HasPrefix(theirs, mine) {
				t.Errorf("the suite's unit prefix %q and a bastion's %q: a sweep under one takes the other's units", mine, theirs)
			}
		}
	}
	if strings.HasPrefix(opScopeUnitPrefix, opActionUnitPrefix) {
		t.Errorf("the suite's scope prefix %q starts with its action prefix %q: the action sweep would take a scope for its own", opScopeUnitPrefix, opActionUnitPrefix)
	}
	pid := strconv.Itoa(os.Getpid())
	for _, n := range []string{opActionSlice, opActionUnitPrefix, opScopeUnitPrefix} {
		if !strings.Contains(n, pid) {
			t.Errorf("%q does not hold this run's pid %s", n, pid)
		}
	}
}
