//go:build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// anchorPolicyKey is where Group Policy and Intune deploy a machine policy for
// the bastion: under HKLM\SOFTWARE\Policies, which only an administrator or
// the policy engine writes. Domain membership is not read.
const anchorPolicyKey = `SOFTWARE\Policies\Privatae\Bastion`

func readAnchorPolicyOS() *anchorPolicy {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, anchorPolicyKey, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetStringValue("AnchorHost")
	if err != nil || strings.TrimSpace(v) == "" {
		return nil
	}
	return &anchorPolicy{Host: v, Source: `HKLM\` + anchorPolicyKey + ` AnchorHost`}
}
