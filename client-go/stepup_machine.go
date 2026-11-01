package main

// stepup_machine.go — the second factor that belongs to the machine's OWNER,
// not to a Host.
//
// Every factor before this file was enrolled per Host pairing (stepupPairing,
// cfg.dcnDir): it proves the person approved what THAT Host asked. A bastion
// with no Host had no factor at all, so nothing asked of the machine itself
// could ever be proved to come from a person: not stopping an agent from the
// console or the command line, and not a request an agent on this machine
// makes through the command line. The command line cannot tell a person at a
// terminal from an agent driving one, so the code from the owner's
// authenticator is the only proof there is.
//
// It is the same mechanism in a different directory: the same secret file,
// the same request and approval stores, the same verify-and-burn
// (stepup.go). Only where it lives changes: <configDir>/machine-factor, beside
// the pairings rather than inside one, because it outlives every pairing.
//
// Which one a command uses: --machine names it; with no Host paired it is the
// only one there is, so it is the default; otherwise a command without
// --machine keeps meaning a Host's factor, exactly as before.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// stepupTarget is where one second factor and the requests it approves live.
type stepupTarget struct {
	dir  string
	host string // the Host pairing; "" is the machine's owner
}

func (t stepupTarget) machine() bool { return t.host == "" }

// forWhom names the factor in a sentence: "for <host> on this machine" or
// "for this machine".
func (t stepupTarget) forWhom() string {
	if t.machine() {
		return "for this machine"
	}
	return "for " + t.host + " on this machine"
}

// flag is what a printed command needs to reach the same factor again.
func (t stepupTarget) flag() string {
	if t.machine() {
		return " --machine"
	}
	return ""
}

// machineFactorDir is the owner's factor directory, created 0700.
func machineFactorDir() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(d, "machine-factor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create this machine's second-factor directory: %w", err)
	}
	return dir, nil
}

// resolveStepupTarget picks the factor a command means: the owner's with
// --machine or when no Host is paired, otherwise a Host's (stepupPairing).
func resolveStepupTarget(host string, machine bool) (stepupTarget, error) {
	if machine && host != "" {
		return stepupTarget{}, errors.New("--machine and --host name two different second factors; give one")
	}
	if !machine && host == "" {
		if cfgs, err := loadPairings(); err == nil && len(cfgs) == 0 {
			machine = true
		}
	}
	if machine {
		dir, err := machineFactorDir()
		if err != nil {
			return stepupTarget{}, err
		}
		return stepupTarget{dir: dir}, nil
	}
	cfg, err := stepupPairing(host)
	if err != nil {
		return stepupTarget{}, err
	}
	dir := cfg.dcnDir()
	if dir == "" {
		return stepupTarget{}, fmt.Errorf("cannot open this pairing's state directory")
	}
	return stepupTarget{dir: dir, host: cfg.HostName}, nil
}

// takeMachineFlag removes --machine from args.
func takeMachineFlag(args []string) (bool, []string) {
	machine := false
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--machine" {
			machine = true
			continue
		}
		rest = append(rest, a)
	}
	return machine, rest
}

// machineCodeMu makes the throttle's check, the attempt and the count one
// step, as pipeApproveMu does for the tray.
var machineCodeMu sync.Mutex

// machineCodeSpend is every code typed into the console for the owner's
// factor: spend checks the code; wrong ones are counted and throttled.
//
// WHY THE CONSOLE IS THROTTLED HERE when the Host approvals page is not
// (ui.go, approve): that page's reasoning is that whoever reaches it can read
// the seed. The owner's code exists for the opposite case, an agent driving the
// person's browser, which on a whole-machine install cannot read
// <configDir>/machine-factor and so can only guess. Unthrottled, a page script
// posting guesses finds a six-digit code within hours. The tray's numbers
// (approvalpipe.go): pipeFreeFailures free, then one per pipeSlowEvery, none
// after pipeLockAfter until a code is accepted at an administrator terminal
// (stepupApproveRequest resets the count).
func machineCodeSpend(dir string, now time.Time, spend func() (string, error)) (string, error) {
	return codeSpend(dir, now, machineCodeLockedHint, spend)
}

// The way back from a lockout, named for whichever factor locked: the
// owner's, or a Host pairing's typed through the owner's lane (consolelane.go).
const (
	machineCodeLockedHint = "At an administrator terminal, answer one waiting request (privatae-bastion approve --machine <id>) or " +
		"set up a new code (privatae-bastion stepup-enroll --machine --rotate), and it takes codes again"
	hostCodeLockedHint = "At an administrator terminal, answer one waiting request of that Host's " +
		"(sudo -H privatae-bastion approve <id>), and it takes codes again"
)

// codeSpend is machineCodeSpend for any factor's directory.
func codeSpend(dir string, now time.Time, lockedHint string, spend func() (string, error)) (string, error) {
	machineCodeMu.Lock()
	defer machineCodeMu.Unlock()
	// The daemon (the console) and a terminal (`stop`) are two processes:
	// a file lock makes read-count, try, write-count one step across both,
	// so codes typed in both at once cannot lose a failure.
	if lf, err := os.OpenFile(filepath.Join(dir, "code-spend.lock"), os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		defer lf.Close() // closing releases the lock
		if err := flockFile(lf); err != nil {
			return "", fmt.Errorf("could not take the code lock: %w", err)
		}
	}
	stepupMu.Lock()
	thr := pipeThrottleLoad(dir)
	stepupMu.Unlock()
	if thr.Failures >= pipeLockAfter {
		return "", fmt.Errorf("%d wrong codes in a row were typed here, so this console takes no more codes. %s",
			thr.Failures, lockedHint)
	}
	if why := pipeThrottleRefusal(thr, now); why != "" {
		return "", errors.New(why)
	}
	id, err := spend()
	if err != nil {
		if pipeCodeError(err) {
			pipeThrottleFail(dir, now)
		}
		return "", err
	}
	stepupMu.Lock()
	pipeThrottleReset(dir)
	stepupMu.Unlock()
	return id, nil
}
