//go:build windows

package main

// WHO STANDS BEHIND THE ANCHOR, ON WINDOWS.
//
// Every machine-authority decision in this binary asks one question: does the
// caller administer this box? On Unix that is euid 0. On Windows there is no
// euid at all — Go's syscall package answers `Geteuid() (euid int) { return -1 }`
// unconditionally (syscall_windows.go), so the historic `os.Geteuid() != 0` gate
// was not "needs admin" on Windows, it was PERMANENTLY CLOSED. Running as
// Administrator made no difference; nothing could ever satisfy it.
//
// That silently made three things impossible on every Windows install:
// `set-mode networked`, `claim-anchor`, and `claim-owner`. A Windows machine
// could therefore never be a networked bastion and never be anchored — so the
// whole anchor-governed model (a machine several hosts share, later pairings
// held pending until the anchor approves) was Linux-only by accident rather than
// by decision.
//
// The Windows equivalent of "root on this machine" is a process that is BOTH
// running elevated AND whose token carries the local Administrators group. Both
// halves are needed and neither implies the other:
//
//   - IsElevated alone would accept a token that was elevated in some other
//     context but is not an administrator of THIS machine.
//   - IsMember alone would accept an un-elevated admin user. On such a token the
//     Administrators group is present but DENY-only, which is exactly the UAC
//     split-token state — the user COULD administer the box but this process is
//     not doing so. Treating that as authority would let any admin-account
//     process anchor a machine without ever passing a UAC prompt, which is the
//     consent step that makes "root stands behind the anchor" mean anything.
//
// LocalSystem (a service) satisfies both, which is correct: a machine-wide
// service is exactly the networked bastion's shape.

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// processIsRoot reports whether this process administers the machine.
//
// Fails CLOSED: any error asking the question answers "no". An authority check
// that cannot be completed has not been passed.
func processIsRoot() bool {
	ok, err := machineAuthority()
	if err != nil {
		// SAY SO. A silent "no" here is the exact bug this file exists to fix,
		// one layer down: an administrator would read "run as Administrator"
		// while already in an elevated terminal, with nothing anywhere saying
		// the check itself failed to run.
		fmt.Printf("privilege: cannot determine machine authority on this system: %v\n", err)
		return false
	}
	return ok
}

// machineAuthority is the check itself, with its failure kept distinguishable
// from a plain "no".
func machineAuthority() (bool, error) {
	// TokenElevation off the process pseudo-handle is a GetTokenInformation
	// read, which a PRIMARY token answers fine.
	if !windows.GetCurrentProcessToken().IsElevated() {
		return false, nil
	}
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("cannot build the Administrators SID: %w", err)
	}
	// Token(0) — a NULL handle — NOT GetCurrentProcessToken().
	//
	// IsMember hands its receiver straight to CheckTokenMembership
	// (x/sys@v0.46.0/windows/security_windows.go:832-838), and that API takes an
	// IMPERSONATION token; a primary token is refused with
	// ERROR_NO_IMPERSONATION_TOKEN. GetCurrentProcessToken returns the PRIMARY
	// token's pseudo-handle (:664-669) — so asking it this way would have
	// errored for a genuine elevated administrator and, under the fail-closed
	// rule above, answered "no". The gate this whole change exists to OPEN would
	// have stayed shut, indistinguishably from a real refusal.
	//
	// Passing NULL is the documented way to avoid that: the API duplicates the
	// calling thread's token into an impersonation token itself. It is also what
	// .NET's WindowsIdentity.IsInRole does internally, which is why the
	// PowerShell check in install.ps1 works while this one would not have.
	member, err := windows.Token(0).IsMember(sid)
	if err != nil {
		return false, fmt.Errorf("CheckTokenMembership failed: %w", err)
	}
	return member, nil
}
