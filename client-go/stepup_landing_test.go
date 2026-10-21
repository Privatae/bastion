package main

// stepupApproveRequest spends a code only when the approval actually lands
// (stepupIssueLocked): a request answered meanwhile, or a store that cannot be
// written, leaves the code good for the person's next try. Every value here is
// invented.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestACodeIsNotSpentWhenTheApprovalCannotBeSaved(t *testing.T) {
	dir, idA, _, _, _ := pipeBox(t)
	code := pipeCodeNow()
	// approvals.json cannot be written: a directory stands where it goes.
	blocker := approvalsPath(dir)
	if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := stepupApproveRequest(dir, idA, code); err == nil {
		t.Fatal("the approval could not be saved, yet the approve succeeded")
	}
	if r := stateOf(t, dir, idA); r.State != "pending" {
		t.Fatalf("the request is %s after a failed approve; it must still be pending", r.State)
	}
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	// The same code, the next moment: it was never spent.
	if _, err := stepupApproveRequest(dir, idA, code); err != nil {
		t.Fatalf("the person's code was spent by an approve that did not land: %v", err)
	}
	if r := stateOf(t, dir, idA); r.State != "approved" || r.Approval == "" {
		t.Fatalf("not approved: %+v", r)
	}
}

func TestACodeIsNotSpentWhenTheRequestIsDeniedMeanwhile(t *testing.T) {
	dir, idA, _, idB, _ := pipeBox(t)
	code := pipeCodeNow()
	// Another process (the service, a terminal) denies A between the code
	// check and the approval landing: it shares the files, not the lock.
	stepupLandingHook = func() {
		m := requestsLoad(dir)
		r := m[idA]
		r.State = "denied"
		m[idA] = r
		if err := requestsSave(dir, m); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { stepupLandingHook = nil })
	_, err := stepupApproveRequest(dir, idA, code)
	if err == nil || !strings.Contains(err.Error(), "no longer pending") {
		t.Fatalf("a request denied meanwhile must not be approved: %v", err)
	}
	if r := stateOf(t, dir, idA); r.State != "denied" || r.Approval != "" {
		t.Fatalf("the deny must stand, with no approval on it: %+v", r)
	}
	if n := len(approvalsLoad(dir)); n != 0 {
		t.Fatalf("%d approval(s) stand for a request that was denied", n)
	}
	stepupLandingHook = nil
	// The code the person typed still works, here for the other request.
	if _, err := stepupApproveRequest(dir, idB, code); err != nil {
		t.Fatalf("the code was spent on an approval that did not land: %v", err)
	}
}

func TestACodeThatLandsIsSpent(t *testing.T) {
	dir, idA, _, idB, _ := pipeBox(t)
	code := pipeCodeNow()
	if _, err := stepupApproveRequest(dir, idA, code); err != nil {
		t.Fatal(err)
	}
	if _, err := stepupApproveRequest(dir, idB, code); err == nil || err.Error() != "code already used" {
		t.Fatalf("a code that approved one request must not approve another: %v", err)
	}
}
