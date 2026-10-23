package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// opFakeStalls points the stall readings at a folder of stand-in cgroups and
// returns how to set one's PSI some avg10.
func opFakeStalls(t *testing.T) func(cg string, some float64) {
	t.Helper()
	fake := t.TempDir()
	prev := opCgroupRoot
	opCgroupRoot = fake
	t.Cleanup(func() { opCgroupRoot = prev })
	return func(cg string, some float64) {
		_ = os.MkdirAll(filepath.Join(fake, cg), 0o755)
		_ = os.WriteFile(filepath.Join(fake, cg, "memory.pressure"),
			[]byte(fmt.Sprintf("some avg10=%.2f avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n", some)), 0o644)
	}
}

// Two ops can run at once: the management lane has more than one worker
// (mgmtWorkerCount) and a ship plan runs its own, and a root op runs in a
// scope in the ops' slice. Another op's scope or unit there is another
// program whose memory can make the machine wait, and its stalls are read
// beside every top-level group's.
func TestAnotherOpsStallsAreReadBesideTheMachinesOwn(t *testing.T) {
	write := opFakeStalls(t)
	rootOp := opActionSlice + "/" + opScopeUnitPrefix + "4242.scope"
	otherAction := opActionSlice + "/" + opActionUnitPrefix + "run2-apply.service"
	write("system.slice", 0.10)
	write(opActionSlice, 0.10)
	write(rootOp, 3.5)
	write(otherAction, 1.25)
	got := opOthersStalls()
	if got["system.slice"] != 0.10 {
		t.Errorf("a top-level group's stall: %v", got)
	}
	if got[rootOp] != 3.5 || got[otherAction] != 1.25 {
		t.Errorf("a root op's scope and another action op's unit are read as other programs: %v", got)
	}
	if _, ok := got[opActionSlice]; ok {
		t.Errorf("the ops' slice's own figure holds the op that is measuring, and is never read: %v", got)
	}
}

// What an action op's watch compares: a root op's scope rising beside it
// stops it, while its own unit's stalls and the slice's figure never do.
func TestAnActionOpYieldsToARootOpBesideItNeverToItself(t *testing.T) {
	write := opFakeStalls(t)
	own := opActionUnitPrefix + "run1-apply"
	rootOp := opActionSlice + "/" + opScopeUnitPrefix + "4242.scope"
	write("system.slice", 0.10)
	write(opActionSlice, 0.10)
	write(opActionSlice+"/"+own+".service", 0.10)
	write(rootOp, 0.10)
	base := opStallsBut(opOthersStalls(), own)

	write(opActionSlice, 60)
	write(opActionSlice+"/"+own+".service", 60)
	if rise, who := opStallRise(base, opStallsBut(opOthersStalls(), own)); rise != 0 {
		t.Errorf("the op's own stalls rose %.2f in %s and counted", rise, who)
	}
	write(rootOp, 12.5)
	if rise, who := opStallRise(base, opStallsBut(opOthersStalls(), own)); who != rootOp || rise < 12.3 || rise > 12.5 {
		t.Errorf("a root op's scope beside it began waiting 12.4%% more: got %.2f in %q", rise, who)
	}
}
