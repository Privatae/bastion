//go:build !darwin && !windows

package main

// The startup check on a platform whose system service is the systemd unit:
// systemServiceInstalled answers no here, and that answer must not stop the
// check from recording whether this process is root. Tagged like
// sysservice_other.go, because the probe it drives is that file's.

import (
	"os"
	"strings"
	"testing"
)

func TestTheStartupCheckRecordsRootWithNoServiceInstalled(t *testing.T) {
	saved := systemService
	oldHeld := machineAuthorityHeld
	t.Cleanup(func() { systemService, machineAuthorityHeld = saved, oldHeld })
	home := os.Getenv("HOME")

	for _, c := range []struct {
		name string
		root bool
	}{{"root", true}, {"an ordinary account", false}} {
		t.Run(c.name, func(t *testing.T) {
			systemService.installed, systemService.authority, systemService.err = false, false, nil
			machineAuthorityHeld = func() bool { return c.root }
			adoptSystemServiceState()

			if systemService.installed {
				t.Fatal("no service is installed on this platform, yet one was recorded")
			}
			if systemService.authority != c.root {
				t.Fatalf("authority recorded as %v for %s", systemService.authority, c.name)
			}
			if got := os.Getenv("HOME"); got != home {
				t.Fatalf("the state directory was moved: HOME is %q, was %q", got, home)
			}
			why := enrolServiceState()
			if c.root && why != "" {
				t.Fatalf("stepup-enroll --console-only must take root here, whose state the systemd unit reads; refused: %s", why)
			}
			if !c.root && !strings.Contains(why, "does not administer the machine") {
				t.Fatalf("an ordinary account must still be refused; got %q", why)
			}
		})
	}
}
