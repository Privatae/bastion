//go:build !windows

// The three checks the async lane needs that the wire cannot reach: the job
// table's own bounds, and the two numbers this lane chose. Split out of
// modelswap_async_test.go so THAT file compiles against the synchronous handler
// and its failures are behavioural rather than a build error.

package main

import (
	"fmt"
	"testing"
	"time"
)

// ── a test must outlive the job it started ─────────────────────────────────
//
// runModelPull is spawned off the management frame and keeps writing after the
// start has answered: progress into the job table, then the approval and the
// ownership ledger into the pairing's ROOT (stepupMarkUsed, recordPlaced, both
// through atomicWrite's temp-file-and-rename). A test that returns while its
// job is still running has that goroutine writing into a t.TempDir() that
// t.Cleanup is deleting at the same moment — and RemoveAll then fails with
// "directory not empty", reported against the test at its function line, at
// 0.00s. That was the whole intermittent failure of this file's tests: not an
// order effect, not shared table state, a goroutine outliving the test.
//
// modelPullJobIDs / awaitModelPullsSince are the two halves of the fix: note
// which jobs already exist, and at cleanup wait on `done` for every job this
// test added. Scoped to this test's own jobs so a record some other file left
// running (or built by hand, with no done channel) cannot hang a cleanup.

func modelPullJobIDs() map[string]bool {
	modelPullJobsMu.Lock()
	defer modelPullJobsMu.Unlock()
	out := map[string]bool{}
	for id := range modelPullJobs {
		out[id] = true
	}
	return out
}

// awaitModelPullsSince blocks until every job not in `before` has finished.
// The deadline is a GUARD against a job that can never finish (a daemon that
// was closed under it would take modelPullTimeout to notice), not a wait: a
// finished job returns at once.
func awaitModelPullsSince(t *testing.T, before map[string]bool) {
	t.Helper()
	modelPullJobsMu.Lock()
	var pending []<-chan struct{}
	for id, j := range modelPullJobs {
		if !before[id] && j.done != nil {
			pending = append(pending, j.done)
		}
	}
	modelPullJobsMu.Unlock()
	deadline := time.After(30 * time.Second)
	for _, d := range pending {
		select {
		case <-d:
		case <-deadline:
			t.Errorf("a model pull this test started was still running 30s after the test " +
				"ended — its goroutine would be writing into a directory the test is deleting")
			return
		}
	}
}

// A finished record is kept so a late poll can still be answered, but a
// long-lived daemon must not accumulate them for ever. Eviction takes the
// OLDEST FINISHED job and never a running one — forgetting a live download is
// how a host ends up starting a second one on the same approval.
func TestFinishedJobsAreEvictedOldestFirstAndRunningOnesAreNot(t *testing.T) {
	resetModelPullJobs()
	f := &fakeDaemon{}
	release := newSlowPullDaemon(t, f)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// One job that stays RUNNING for the whole test. Its root comes from
	// newPullRoot, whose cleanup releases the daemon and then waits for this
	// job before the directory is deleted — the `defer close(release)` that
	// used to sit here let the goroutine finish INTO the RemoveAll.
	liveRoot := newPullRoot(t, release)
	liveApproval := proposeAndApprove(t, liveRoot, "slowmodel", "embed", 1<<30, "")
	live := startPull(t, tAnchor, liveRoot, "slowmodel", "embed", 1<<30, liveApproval)
	liveID, _ := live["id"].(string)

	// The download goroutine reads the daemon's address only when it sends
	// its request, so the switch to the instant daemon below must wait until
	// that request has reached the slow one: its 400-of-1000 progress line is
	// the proof. Without this, a goroutine scheduled late sends to the instant
	// daemon, the "running" job finishes, and it is evicted like any other.
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, _, code, _ := driveModelOp(t, tAnchor, "model:pull", []string{statusArg(liveID)}, liveRoot)
		if code != 0 {
			t.Fatalf("status exit %d", code)
		}
		st := mustJSON(t, out)
		if st["state"] == "running" && st["got_bytes"] == float64(400) && st["want_bytes"] == float64(1000) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the live download never reached the slow daemon: %v", st)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Then fill the table past its cap with finished ones. A separate daemon, so
	// these complete instantly. Bare TempDirs here, deliberately: each is polled
	// to completion below, and a newPullRoot cleanup on them would run BEFORE
	// liveRoot's (last registered, first run) and wait on the live job while
	// nothing had yet released it.
	newFakeDaemon(t, &fakeDaemon{})
	var firstID string
	for i := 0; i <= modelPullJobsMax; i++ {
		root := t.TempDir()
		enrollFactor(t, root)
		name := fmt.Sprintf("m%d", i)
		ap := proposeAndApprove(t, root, name, "embed", 1<<20, "")
		j := startPull(t, tAnchor, root, name, "embed", 1<<20, ap)
		id, _ := j["id"].(string)
		if i == 0 {
			firstID = id
		}
		pollUntilFinished(t, tAnchor, root, id)
	}

	// The running job is still there and still answerable.
	out, _, code, _ := driveModelOp(t, tAnchor, "model:pull", []string{statusArg(liveID)}, liveRoot)
	if code != 0 {
		t.Fatalf("status exit %d", code)
	}
	if got := mustJSON(t, out); got["state"] != "running" {
		t.Fatalf("a RUNNING job must never be evicted: %v", got)
	}
	// The oldest FINISHED one has gone.
	out, _, code, _ = driveModelOp(t, tAnchor, "model:pull", []string{statusArg(firstID)}, liveRoot)
	if code != 0 {
		t.Fatalf("status exit %d", code)
	}
	if got := mustJSON(t, out); got["state"] != "unknown" {
		t.Fatalf("the table grew past its cap of %d without evicting the oldest "+
			"finished record: %v", modelPullJobsMax, got)
	}
}

// A record past its retention is forgotten even when the table is small.
func TestAFinishedJobIsForgottenPastItsRetention(t *testing.T) {
	resetModelPullJobs()
	modelPullJobsMu.Lock()
	modelPullJobs["mp-old"] = &modelPullJob{ID: "mp-old", State: "done",
		finishedAt: time.Now().Add(-modelPullJobRetention - time.Hour)}
	modelPullJobs["mp-new"] = &modelPullJob{ID: "mp-new", State: "done",
		finishedAt: time.Now()}
	modelPullJobs["mp-live"] = &modelPullJob{ID: "mp-live", State: "running"}
	modelPullPrune()
	_, old := modelPullJobs["mp-old"]
	_, fresh := modelPullJobs["mp-new"]
	_, live := modelPullJobs["mp-live"]
	modelPullJobsMu.Unlock()
	if old {
		t.Fatal("a record past its retention must be forgotten")
	}
	if !fresh {
		t.Fatal("a record inside its retention must still answer a late poll")
	}
	if !live {
		t.Fatal("a RUNNING job has no finished time and must never be pruned")
	}
	resetModelPullJobs()
}

// The retention window is the approval's own, not a number invented for this
// lane — the same argument modelswap.go's TTL block already makes for not
// introducing a clock of its own.
func TestJobRetentionIsTheApprovalsOwnWindow(t *testing.T) {
	if modelPullJobRetention != stepupApprovalTTL {
		t.Fatalf("a job record outliving the approval that authorized it can tell "+
			"nobody anything actionable; want %v, got %v", stepupApprovalTTL, modelPullJobRetention)
	}
}

// The cadence the box asks for is the one the host already runs against
// backup_fetch: 2 s, x1.5, capped at 30 s. One lane, one cadence.
func TestThePollCadenceIsBackupFetchs(t *testing.T) {
	if got := modelPullPollAfter(0); got != 2.0 {
		t.Fatalf("first poll: want 2s, got %v", got)
	}
	if got := modelPullPollAfter(1); got != 3.0 {
		t.Fatalf("second poll: want 3s (x1.5), got %v", got)
	}
	if got := modelPullPollAfter(40); got != 30.0 {
		t.Fatalf("the cadence must cap at 30s, got %v", got)
	}
}

// Both sub-ops ride ONE op id, in ONE caps family. A separate op id would be
// ungranted in every signed grant already written, so a user whose grant says
// model:pull could start a download and not be allowed to watch it finish.
func TestStatusRidesTheModelPullOpAndTheModelsFamily(t *testing.T) {
	if fam := opFamily("model:pull"); fam != modelGateOpFamily {
		t.Fatalf("model:pull must be in %q, got %q", modelGateOpFamily, fam)
	}
	if _, ok := handlerOps["model:pull"]; !ok {
		t.Fatal("model:pull must be in the handler table")
	}
	for _, gone := range []string{"model:status", "model:pull_status", "model:poll"} {
		if _, ok := handlerOps[gone]; ok {
			t.Fatalf("%q exists as its own op — every grant already written names "+
				"model:pull and would not cover it", gone)
		}
	}
}
