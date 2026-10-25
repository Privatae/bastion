//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// runGuardFile holds the "one running bastion" lock for the life of this
// process. It is a package-level holder so the handle is never collected and
// the lock is never released while we are still serving.
var runGuardFile atomic.Pointer[os.File]

// guardSingleRun refuses to start a SECOND bastion on this machine.
//
// WHY WINDOWS NEEDS ITS OWN. acquireSingletonLock (singleton.go) is the
// machine-wide exclusion lock, and it opens with
// `if !singletonSupported() || !processIsRoot() { return nil, nil }` —
// singletonSupported() is `runtime.GOOS == "linux"`. So on Windows there has
// never been any run lock, two `privatae-bastion run` processes coexist
// happily, and the loser dies on whichever loopback control port it reaches
// first with:
//
//	listen tcp 127.0.0.1:7879: bind: Only one usage of each socket address …
//
// which names a port and tells the operator nothing about the actual problem.
// Hit exactly that on a real box.
//
// 0.24.0 is what made it likely. relaunchAfterUpdate starts the replacement
// itself after a self-update — correct, because Windows has no service to do it
// — but the operator has also been told for two versions to run it by hand when
// an update appears to kill it. Both are now true at once, so the collision is
// the normal case rather than a rare one.
//
// REFUSES rather than waiting, and that is the deliberate difference from
// Linux. There the loser becomes a standby blocked in the kernel until the
// primary dies, which is useful because systemd is holding the unit open. An
// ordinary Windows install is a logon task, not a service, so a standby is just
// a terminal window that never returns. Saying so and exiting is the honest
// behaviour. A networked install IS a service (sysservice_windows.go), and an
// administrator's `run` beside it lands on this same lock, because their
// commands use the service's state directory: it is refused the same way.
//
// The lock lives in the per-user config dir, which is the right scope: a second
// OS user forking the machine's bastion is a different hazard, and the machine
// MARKER already covers it at pair time (singleton.go).
// THE REFUSAL WAS WRITTEN WHERE NOBODY COULD READ IT. Every return below goes
// to main's `fmt.Fprintln(os.Stderr, "error:", err)` (main.go:294) and then
// exit 1 — which is right on a terminal and is nothing at all in the case this
// guard exists for. 0.24.0's relaunchAfterUpdate starts the replacement with
// DETACHED_PROCESS (relaunch_windows.go:46-48), so the bastion this refusal is
// about is running with NO console; and the user who double-clicks the exe a
// second time gets a console that appears and closes with the process, which is
// a flash, not a message. The person at that machine has no terminal open and
// no way to tell where it is running.
//
// So every refusal goes through refuseVisibly: it puts the same fact in a dialog
// box that waits to be dismissed, AND returns the error unchanged, so stderr and
// the non-zero exit are exactly what they were. Nothing downstream can tell the
// difference — main still prints and still exits 1.
//
// Enforced by TestEveryRunGuardRefusalIsVisible, which reads this function and
// fails on any error return that skips it, because the next branch added here
// would otherwise be silent again in exactly the same way.
func refuseVisibly(shown uiNotice, err error) error {
	showBlockingNotice(shown)
	return err
}

// cannotStart is the wording for the two I/O failures below. They have no
// prepared words the way the already-running case does (secondRunNotice,
// notify.go), and the error itself is the most accurate thing there is to say:
// both mean the config directory is unusable, which is not a state anyone can be
// given advice about from here.
func cannotStart(err error) uiNotice {
	return uiNotice{Title: "Privatae bastion could not start", Body: err.Error()}
}

func guardSingleRun() error {
	d, err := configDir()
	if err != nil {
		return refuseVisibly(cannotStart(err), err)
	}
	f, err := os.OpenFile(filepath.Join(d, "run.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		err = fmt.Errorf("cannot open the run lock: %w", err)
		return refuseVisibly(cannotStart(err), err)
	}
	if err := flockFileNB(f); err != nil {
		_ = f.Close()
		// The dialog and the console get DIFFERENT words for the same fact, and
		// that is on purpose: this text is laid out for a terminal — indented
		// continuation lines, and "you can close this window" meaning the console
		// window it is being printed into. secondRunNotice says it for a dialog.
		return refuseVisibly(secondRunNotice(), errors.New(
			"a bastion is already running on this machine — that one is serving "+
				"your hosts, and a second would fight it for the same local ports.\n"+
				"  Nothing is wrong: you can close this window.\n"+
				"  If you believe the running one is dead, stop it (Task Manager → "+
				"privatae-bastion.exe) and run this again"))
	}
	runGuardFile.Store(f)
	return nil
}
