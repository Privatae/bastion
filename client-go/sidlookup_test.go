package main

// Account lookups made outside a scan (sidnames.go): the approvals pipe and the
// folder agent's drop. Fake lookups stand in for LookupAccountSid, so these run
// on every platform. Every SID and name here is invented.

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSIDDana = "S-1-5-21-1000000001-1000000002-1000000003-1201"

// hangingLookup blocks until release is closed, then answers with acct.
func hangingLookup(calls *int32, release <-chan struct{}, acct sidAccount) func(string) (sidAccount, error) {
	return func(string) (sidAccount, error) {
		atomic.AddInt32(calls, 1)
		<-release
		return acct, nil
	}
}

// A directory that does not answer: every caller is told "timed out" within
// its budget, only one lookup is ever started on the lane, and the answer that
// comes late fills the cache for the next caller.
func TestSIDDirectoryUnreachableTimesOutWithinBudget(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	dir := newSIDDirectory(hangingLookup(&calls, release,
		sidAccount{Account: "dana", Domain: "EXAMPLECORP", Type: winSidTypeUser}))
	lane := sidLane{slots: make(chan struct{}, 1), budget: 100 * time.Millisecond}

	for i := 0; i < 5; i++ {
		start := time.Now()
		if _, out := dir.resolve(testSIDDana, lane); out != sidTimedOut {
			t.Fatalf("call %d: outcome %v while the directory does not answer", i, out)
		}
		if took := time.Since(start); took > lane.budget+500*time.Millisecond {
			t.Fatalf("call %d waited %v, budget %v", i, took, lane.budget)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("%d lookups started while the first was still blocked", n)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		a, out := dir.resolve(testSIDDana, lane)
		if out == sidResolved {
			if sidAccountLabel(a) != `EXAMPLECORP\dana` {
				t.Fatalf("late answer = %+v", a)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the late answer never reached the cache")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("the late answer was asked again: %d lookups", n)
	}
}

// Answers are kept for sidDirectoryTTL; a failure is asked again every time.
func TestSIDDirectoryCachesAnswersNotFailures(t *testing.T) {
	var calls int32
	dir := newSIDDirectory(func(sid string) (sidAccount, error) {
		atomic.AddInt32(&calls, 1)
		if sid == testSIDDana {
			return sidAccount{Account: "dana", Domain: "EXAMPLECORP", Type: winSidTypeUser}, nil
		}
		return sidAccount{}, errors.New("none mapped")
	})
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	dir.now = func() time.Time { return now }
	lane := sidLane{slots: make(chan struct{}, 1), budget: time.Second}

	for i := 0; i < 3; i++ {
		if _, out := dir.resolve(testSIDDana, lane); out != sidResolved {
			t.Fatalf("outcome %v", out)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("%d lookups for one account within the TTL", n)
	}
	now = now.Add(sidDirectoryTTL)
	dir.resolve(testSIDDana, lane)
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("an expired answer was not asked again: %d lookups", n)
	}
	for i := 0; i < 2; i++ {
		if _, out := dir.resolve("S-1-5-21-9-9-9-9", lane); out != sidUnmapped {
			t.Fatalf("unmapped SID outcome %v", out)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 4 {
		t.Fatalf("a failure was cached: %d lookups", n)
	}
}

// A lookup hung on one lane does not hold another lane.
func TestSIDDirectoryLanesAreIndependent(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	dir := newSIDDirectory(func(sid string) (sidAccount, error) {
		if sid == testSIDDana {
			<-release
		}
		return sidAccount{Account: "erin", Type: winSidTypeUser}, nil
	})
	stuck := sidLane{slots: make(chan struct{}, 1), budget: 50 * time.Millisecond}
	other := sidLane{slots: make(chan struct{}, 1), budget: time.Second}
	if _, out := dir.resolve(testSIDDana, stuck); out != sidTimedOut {
		t.Fatalf("stuck lane outcome %v", out)
	}
	if _, out := dir.resolve("S-1-5-21-1000000001-1000000002-1000000003-1202", other); out != sidResolved {
		t.Fatalf("the other lane was held by the stuck one: %v", out)
	}
}

// THE APPROVALS PIPE FAILS CLOSED. A client whose account the directory could
// not name in time is never approved, even with a right code; it is not
// counted as a wrong code; list still answers. Once the directory answers,
// the same code approves.
func TestPipeApproveRefusedWhenTheAccountLookupTimedOut(t *testing.T) {
	dir, idA, purposeA, _, _ := pipeBox(t)
	now := time.Now()

	release := make(chan struct{})
	var calls int32
	accounts := newSIDDirectory(hangingLookup(&calls, release,
		sidAccount{Account: "pat", Domain: "EXAMPLE", Type: winSidTypeUser}))
	lane := sidLane{slots: make(chan struct{}, 1), budget: 100 * time.Millisecond}

	c := thePerson
	c.UserName = ""
	start := time.Now()
	pipeClientName(&c, accounts, lane)
	if took := time.Since(start); took > lane.budget+500*time.Millisecond {
		t.Fatalf("the client's name lookup took %v, budget %v", took, lane.budget)
	}
	if !c.NameTimedOut || c.UserName != "" {
		t.Fatalf("a lookup that did not answer must be marked: %+v", c)
	}

	code := pipeCodeNow()
	approve := pipeRequest{Op: "approve", Host: pipeTestHost, ID: idA, Purpose: purposeDigest(purposeA), Code: code}
	if resp := pipeServe(approve, c, now); resp.OK || !strings.Contains(resp.Error, "did not answer") {
		t.Fatalf("an approve on a timed-out lookup must be refused: %+v", resp)
	}
	if r := stateOf(t, dir, idA); r.State != "pending" {
		t.Fatalf("a timed-out lookup changed the request: %s", r.State)
	}
	if f := pipeThrottleLoad(dir); f.Failures != 0 {
		t.Fatalf("the refusal was counted as a wrong code: %d", f.Failures)
	}
	if resp := pipeServe(pipeRequest{Op: "list"}, c, now); !resp.OK {
		t.Fatalf("list must still answer by SID: %+v", resp)
	}

	close(release)
	c2 := thePerson
	c2.UserName = ""
	deadline := time.Now().Add(2 * time.Second)
	for {
		c2.NameTimedOut = false
		pipeClientName(&c2, accounts, lane)
		if !c2.NameTimedOut {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the directory's late answer never reached the pipe")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c2.UserName != `EXAMPLE\pat` {
		t.Fatalf("name = %q", c2.UserName)
	}
	if resp := pipeServe(approve, c2, now); !resp.OK {
		t.Fatalf("with the account named, the code approves: %+v", resp)
	}
}

// An account the directory says does not exist is still served by SID, as
// before: that is an answer, not a timeout.
func TestPipeClientNameUnmappedIsNotATimeout(t *testing.T) {
	accounts := newSIDDirectory(func(string) (sidAccount, error) { return sidAccount{}, errors.New("none mapped") })
	c := thePerson
	c.UserName = ""
	pipeClientName(&c, accounts, sidLane{slots: make(chan struct{}, 1), budget: time.Second})
	if c.NameTimedOut || c.UserName != "" {
		t.Fatalf("unmapped: %+v", c)
	}
}

// THE DROP FAILS CLOSED. The folder owner's lookup is bounded, and a
// directory that does not answer starts no agent; no account starts none.
func TestFaWinDropOwnerAccountFailsClosed(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var calls int32
	slow := newSIDDirectory(hangingLookup(&calls, release, sidAccount{Account: "dana", Type: winSidTypeUser}))
	lane := sidLane{slots: make(chan struct{}, 1), budget: 100 * time.Millisecond}
	start := time.Now()
	if _, err := faWinDropOwnerAccount(testSIDDana, slow, lane); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("a directory that does not answer must refuse the start: %v", err)
	}
	if took := time.Since(start); took > lane.budget+500*time.Millisecond {
		t.Fatalf("the drop waited %v, budget %v", took, lane.budget)
	}

	none := newSIDDirectory(func(string) (sidAccount, error) { return sidAccount{}, errors.New("none mapped") })
	if _, err := faWinDropOwnerAccount(testSIDDana, none, sidLane{slots: make(chan struct{}, 1), budget: time.Second}); err == nil ||
		!strings.Contains(err.Error(), "has no account") {
		t.Fatalf("no account must refuse the start: %v", err)
	}

	ok := newSIDDirectory(func(string) (sidAccount, error) {
		return sidAccount{Account: "dana", Domain: "EXAMPLECORP", Type: winSidTypeUser}, nil
	})
	a, err := faWinDropOwnerAccount(testSIDDana, ok, sidLane{slots: make(chan struct{}, 1), budget: time.Second})
	if err != nil || a.Type != winSidTypeUser || sidAccountLabel(a) != `EXAMPLECORP\dana` {
		t.Fatalf("answered: %+v %v", a, err)
	}
}
