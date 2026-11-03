//go:build !windows && !darwin

package main

import (
	"encoding/json"
	"os"
	"strings"
	"syscall"
)

// anchorPolicyFile is the managed configuration an organisation deploys to a
// Linux machine (by its configuration management) for the bastion: root's,
// and writable by nobody else. A file anyone else could have written is not a
// policy.
var anchorPolicyFile = "/etc/privatae-bastion/policy.json"

func readAnchorPolicyOS() *anchorPolicy {
	fi, err := os.Lstat(anchorPolicyFile)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 {
		return nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return nil
	}
	raw, err := os.ReadFile(anchorPolicyFile)
	if err != nil {
		return nil
	}
	var p struct {
		AnchorHost string `json:"anchor_host"`
	}
	if json.Unmarshal(raw, &p) != nil || strings.TrimSpace(p.AnchorHost) == "" {
		return nil
	}
	return &anchorPolicy{Host: p.AnchorHost, Source: anchorPolicyFile + " anchor_host"}
}
