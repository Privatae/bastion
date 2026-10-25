//go:build !lab

package main

import (
	"encoding/json"
	"testing"
)

// A release build has no lab harness: a lab run is refused with exit 126, the
// shape of an ungranted op, and touches nothing.
func TestAReleaseBuildRefusesALabRun(t *testing.T) {
	out, code := runHarness(harnessSpec{Mode: "lab", HarnessID: "lab-1", Gate: "auto", Image: "x", Tests: []string{"a"}})
	if code != 126 {
		t.Fatalf("exit %d, want 126", code)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil || m["ok"] != false || m["error"] != labUnavailable {
		t.Fatalf("reply %s", out)
	}
}
