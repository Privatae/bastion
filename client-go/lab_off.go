//go:build !lab

package main

// lab_off.go: mode=lab and `lab-selftest` in every release build. The lab
// harness is test tooling for one test lab and is built only with -tags lab,
// so a release bastion answers a lab run the way any bastion without a lab
// answers it: exit 126, in the same shape as an ungranted op.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const labUnavailable = "mode 'lab' not available on this server — this build has no lab harness"

func runLab(_ harnessSpec) ([]byte, int) {
	b, _ := json.Marshal(map[string]any{"mode": "lab", "ran_on": orUnknown(hostnameSafe()), "ok": false, "error": labUnavailable})
	return b, 126
}

// cmdLabSelftest prints the same refusal the relay would give.
func cmdLabSelftest(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, labUnavailable)
	return errors.New("lab run exit 126")
}
