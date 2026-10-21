package main

// The machine-authority gate, in ONE place.
//
// Five call sites used to ask `os.Geteuid() != 0` directly: set-mode networked
// (mode.go), claim-anchor and claim-anchor --repin (anchor.go), claim-owner
// (owner.go), and unpair-on-a-networked-box (config.go). On Windows that
// expression is always true — Go hardcodes Geteuid to -1 there — so all five
// were permanently refused, and a Windows machine could never become a networked
// bastion or be anchored. Nobody chose that; it fell out of a Unix idiom used
// where the platform has no such concept.
//
// So the question is asked through processIsRoot(), which each platform answers
// in its own terms (euid 0 on Unix; elevated + Administrators on Windows,
// privilege_windows.go), and the REFUSAL text is written once, here, so it tells
// the user what to actually do on the machine they are actually on.

import (
	"fmt"
	"runtime"
)

// adminHowTo is the platform's instruction for "do this with machine authority".
// Kept beside the check so a new gate cannot invent its own wording, and so the
// Unix text never reaches a Windows user (telling someone to run `sudo` on
// Windows is how a real instruction becomes noise).
func adminHowTo() string { return adminHowToFor(runtime.GOOS) }

func adminHowToFor(goos string) string {
	if goos == "windows" {
		return "run this from an Administrator terminal (right-click → Run as administrator)"
	}
	return "run it with `sudo -H`"
}

// machineAuthorityHeld is processIsRoot, held in a variable so a test can
// assert both sides of every machine-authority gate whatever euid the suite
// runs under. Nothing outside tests assigns it.
var machineAuthorityHeld = processIsRoot

// requireMachineAuthority returns nil when this process administers the machine,
// and otherwise an error naming the ACT being refused and how to retry it.
//
// `act` reads into "X must run with machine authority" — pass the command, e.g.
// "claim-anchor".
func requireMachineAuthority(act string) error {
	if machineAuthorityHeld() {
		return nil
	}
	return fmt.Errorf("%s needs machine authority — whoever administers this box is what stands behind it; %s",
		act, adminHowTo())
}

// anchorCommandHint is the claim-anchor line to print after `set-mode
// networked` succeeded — the same command on both platforms, but reached
// differently, so the prefix has to match where the user actually is.
//
// NO `<token>`. It said `claim-anchor <token>` and kept saying it after the
// token became optional, so the one instruction the user is handed at the exact
// moment they need it still sent them looking for a credential that no longer
// exists. A usage string is not documentation about the command, it is the
// command — when they disagree the string wins, because it is what gets typed.
func anchorCommandHint() string { return anchorCommandHintFor(runtime.GOOS) }

func anchorCommandHintFor(goos string) string {
	if goos == "windows" {
		return "privatae-bastion claim-anchor   (from this Administrator terminal)"
	}
	return "sudo -H privatae-bastion claim-anchor"
}

// setModeCommandHint is the same shape for `set-mode`, and it exists because
// the setup page hardcoded the unix spelling with no platform branch — so a
// Windows user reading the anchor panel was told to run `sudo -H`. `sudo` is
// not a command on Windows; the line was not merely unidiomatic, it was
// untypeable.
//
// -H on unix is not decoration either: set-mode writes through configDir()
// (mode.go), which is $HOME-derived, so a bare `sudo` can land the mode file in
// the invoking user's directory while the root daemon reads its own and sees no
// change. That is the same hazard fixed one command over for claim-owner,
// and main.go printed the un--H form for BOTH.
func setModeCommandHint() string { return setModeCommandHintFor(runtime.GOOS) }

func setModeCommandHintFor(goos string) string {
	if goos == "windows" {
		return "privatae-bastion set-mode networked   (from this Administrator terminal)"
	}
	return "sudo -H privatae-bastion set-mode networked"
}

// runCommandHint is how to START the bastion on THIS machine, said the way the
// operator would type it. Separate from restartHint, which is about a change
// taking effect on a daemon that is already up.
func runCommandHint() string {
	if systemService.installed && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		return serviceRunHintFor(runtime.GOOS)
	}
	return runCommandHintFor(runtime.GOOS)
}

func runCommandHintFor(goos string) string {
	if goos == "windows" {
		return "privatae-bastion run"
	}
	return "systemctl start privatae-bastion"
}

// restartHint is how to bring the daemon back on THIS machine after a change
// that only takes at startup.
//
// It said `systemctl restart privatae-bastion` unconditionally — the third
// Linux instruction printed at a Windows user inside one command's output,
// after `sudo` in the machine-authority error and PowerShell at every Mac in
// the dashboard. Windows has no systemctl, and an ordinary install has no
// service: deploy/install.ps1 installs the exe and registers a logon task. So
// the honest instruction there is to start it again. A networked install on
// macOS or Windows runs as a system service (sysservice.go), and for that
// machine restartHint names the service manager's own restart instead.
//
// TAKES THE PLATFORM AS AN ARGUMENT, and that is the point. The first version
// branched on runtime.GOOS directly, so the only machine that could test the
// Windows string was a Windows machine — a mutation reverting this exact fix
// passed clean on the Linux builder. That is the same hole that let 'darwin'
// match 'win' in the dashboard: a platform branch nothing off-platform can
// reach is a platform branch nothing checks.
func restartHint() string {
	if systemService.installed && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		return serviceRestartHintFor(runtime.GOOS)
	}
	return restartHintFor(runtime.GOOS)
}

func restartHintFor(goos string) string {
	if goos == "windows" {
		return "Start the bastion again so the change takes:  privatae-bastion run\n" +
			"  (Windows has no service for it — it runs in a terminal, so close the old one first.)"
	}
	return "Restart the service so the change takes:  systemctl restart privatae-bastion"
}

// stepupEnrollHint is the stepup-enroll line to print after a networked
// machine is anchored: approvals on it need a second factor or a device.
func stepupEnrollHint() string { return stepupEnrollHintFor(runtime.GOOS) }

func stepupEnrollHintFor(goos string) string {
	if goos == "windows" {
		return "privatae-bastion stepup-enroll   (from this Administrator terminal)"
	}
	return "sudo -H privatae-bastion stepup-enroll"
}
