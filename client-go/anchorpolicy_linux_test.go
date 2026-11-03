//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The policy readers accept only what the machine's administrator or policy
// engine could have written: on Linux a file root owns that nobody else can
// write. Run as an ordinary user, the suite's own file is not root's, so it is
// no policy.
func TestALinuxPolicyFileMustBeRoots(t *testing.T) {
	dir := t.TempDir()
	prev := anchorPolicyFile
	anchorPolicyFile = filepath.Join(dir, "policy.json")
	t.Cleanup(func() { anchorPolicyFile = prev })
	if err := os.WriteFile(anchorPolicyFile, []byte(`{"anchor_host":"`+"managed.host.privatae.ai"+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := readAnchorPolicyOS()
	if os.Geteuid() == 0 {
		if p == nil || p.Host != "managed.host.privatae.ai" {
			t.Fatalf("root's own policy file was not read: %+v", p)
		}
		_ = os.Chmod(anchorPolicyFile, 0o666)
		if readAnchorPolicyOS() != nil {
			t.Error("a policy file anyone can write was read")
		}
		return
	}
	if p != nil {
		t.Errorf("a policy file root does not own was read: %+v", p)
	}
}
