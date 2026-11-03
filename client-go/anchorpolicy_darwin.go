//go:build darwin

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// anchorPolicyPlist is the machine-wide managed preference domain a
// configuration profile (MDM) installs for the bastion. The folder is root's
// and the system writes it; a file there not owned by root is not a policy.
const anchorPolicyPlist = "/Library/Managed Preferences/ai.privatae.bastion.plist"

func readAnchorPolicyOS() *anchorPolicy {
	fi, err := os.Lstat(anchorPolicyPlist)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 {
		return nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return nil
	}
	// defaults reads the binary and the XML form alike.
	out, err := exec.Command("/usr/bin/defaults", "read", strings.TrimSuffix(anchorPolicyPlist, ".plist"), "AnchorHost").Output()
	if err != nil {
		return nil
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return nil
	}
	return &anchorPolicy{Host: v, Source: "the managed preference ai.privatae.bastion AnchorHost"}
}
