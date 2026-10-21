package main

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// Invented SIDs: the domain part is made up and names no real domain.
const (
	testSIDAlice = "S-1-5-21-1000000001-1000000002-1000000003-1101"
	testSIDBob   = "S-1-5-21-1000000001-1000000002-1000000003-1102"
)

// One scan asks each SID once, and the account label (winTokenUser) and the
// owner's domain (ownerFactsReader) share the answer.
func TestSIDNamesAsksEachSIDOncePerScan(t *testing.T) {
	var calls int32
	lookup := func(sid string) (string, string, error) {
		atomic.AddInt32(&calls, 1)
		switch sid {
		case testSIDAlice:
			return "alice", "EXAMPLECORP", nil
		case testSIDBob:
			return "bob", "EXAMPLECORP", nil
		}
		return "", "", errors.New("none mapped")
	}
	names := newSIDNames(lookup, time.Second, make(chan struct{}, 1))
	for i := 0; i < 40; i++ {
		if got := winAccountLabel(testSIDAlice, names); got != `EXAMPLECORP\alice` {
			t.Fatalf("label = %q", got)
		}
		if got := winAccountDomain(testSIDAlice, names); got != "EXAMPLECORP" {
			t.Fatalf("domain = %q", got)
		}
		winAccountLabel(testSIDBob, names)
	}
	if got := winAccountLabel("S-1-5-21-9-9-9-9", names); got != "S-1-5-21-9-9-9-9" {
		t.Fatalf("an unmapped SID must be shown as itself, got %q", got)
	}
	winAccountDomain("S-1-5-21-9-9-9-9", names)
	if n := atomic.LoadInt32(&calls); n != 3 {
		t.Fatalf("%d lookups for 3 distinct SIDs in one scan", n)
	}
}

// A domain controller that does not answer: the first lookup hangs. The scan
// must stop waiting at its budget, every later SID must come back unresolved
// at once (no second lookup started), the owner's class must read unknown,
// and the next scan must not stack a second blocked lookup behind the first.
func TestSIDNamesUnreachableDirectoryDegradesWithinBudget(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var calls int32
	lookup := func(sid string) (string, string, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		return "", "", errors.New("released")
	}
	slots := make(chan struct{}, 1)
	const budget = 150 * time.Millisecond

	for scan := 0; scan < 3; scan++ {
		names := newSIDNames(lookup, budget, slots)
		start := time.Now()
		for i := 0; i < 30; i++ {
			sid := fmt.Sprintf("S-1-5-21-1000000001-1000000002-1000000003-%d", 2000+i)
			if got := winAccountLabel(sid, names); got != sid {
				t.Fatalf("scan %d: unresolved SID shown as %q", scan, got)
			}
			o := classifyWinOwner(winOwner{SID: sid, Domain: winAccountDomain(sid, names),
				Computer: "DESKTOP-TEST", Groups: map[string]bool{}, GroupsKnown: true})
			if o.Class != ownerUnknown {
				t.Fatalf("scan %d: class %q for an account whose domain could not be read", scan, o.Class)
			}
		}
		if took := time.Since(start); took > budget+time.Second {
			t.Fatalf("scan %d spent %v on lookups, budget %v", scan, took, budget)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("%d lookups started while the first was still blocked", n)
	}
}

// A slow but answering lookup is used, and only what it took counts against
// the budget.
func TestSIDNamesSlowLookupWithinBudgetIsUsed(t *testing.T) {
	lookup := func(sid string) (string, string, error) {
		time.Sleep(20 * time.Millisecond)
		return "carol", "EXAMPLECORP", nil
	}
	names := newSIDNames(lookup, 2*time.Second, make(chan struct{}, 1))
	for i := 0; i < 5; i++ {
		sid := fmt.Sprintf("S-1-5-21-1000000001-1000000002-1000000003-%d", 3000+i)
		if d := winAccountDomain(sid, names); d != "EXAMPLECORP" {
			t.Fatalf("lookup %d within budget came back %q", i, d)
		}
	}
}
