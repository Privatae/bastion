package main

// approvals_owner.go — the one account whose tray the approvals pipe serves.
//
// The pipe (approvalpipe.go) admits a process only when it runs as the person
// signed in to its own active session. On a machine with more than one
// account, that is any of them. The approvals belong to the person who set the
// bastion up for their Host, so the service records that account's SID in its
// own state, and the pipe refuses every other SID for list, deny and approve.
//
// WHO WRITES IT. An installer's elevated step (`npx cseries`), with machine
// authority, into the system service's state, which a process running as the
// person can neither write nor read: `approvals-owner --sid <SID>`. The SID is
// the account that ran the installer, which the elevated step may not be (it
// may run as another administrator), so it is passed in.
//
// A RERUN FROM ANOTHER ACCOUNT can neither change the owner silently nor lock
// the first owner out. The same SID again changes nothing. A different SID is
// refused, and the recorded owner stays exactly as it was, unless --replace is
// given. --replace is taken only on a console, so it is a person at an
// Administrator terminal handing the approvals over on purpose: an installer
// runs its commands with their output captured, so it can never pass it. A
// record that exists but cannot be read counts as an owner for this rule, so
// a damaged file is never quietly replaced; the pipe serves nobody until an
// administrator rewrites it with --replace. Refusing here costs the second
// account a message naming the command; taking the record over would hand the
// first person's approvals to someone else, and clearing it would lock them out.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const approvalsOwnerFile = "approvals_owner.json"

type approvalsOwnerRecord struct {
	SID   string `json:"sid"`
	SetAt string `json:"set_at"`
}

var winSIDShape = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)

// approvalsOwnerSIDOK: a well-formed SID of a person's account.
func approvalsOwnerSIDOK(sid string) bool {
	return winSIDShape.MatchString(sid) && winPersonSID(sid)
}

func approvalsOwnerPath() (string, error) {
	d, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, approvalsOwnerFile), nil
}

// approvalsOwnerLoad reads the record. present is true when a record exists,
// readable or not; sid is "" unless it is readable and names a person.
func approvalsOwnerLoad() (sid string, present bool, err error) {
	p, err := approvalsOwnerPath()
	if err != nil {
		return "", false, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", true, err
	}
	var r approvalsOwnerRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", true, fmt.Errorf("%s cannot be read: %w", p, err)
	}
	if !approvalsOwnerSIDOK(r.SID) {
		return "", true, fmt.Errorf("%s names no person's account", p)
	}
	return r.SID, true, nil
}

// approvalsOwner is the SID the pipe serves, "" when none is recorded or the
// record cannot be read: the pipe then serves nobody.
func approvalsOwner() string {
	sid, _, err := approvalsOwnerLoad()
	if err != nil {
		return ""
	}
	return sid
}

// pipeOwnerRefusal says why client c is not the account the lane serves, or ""
// when it is.
func pipeOwnerRefusal(c pipeClient, owner string) string {
	switch {
	case owner == "":
		return "no account is recorded as owning this machine's approvals; from an Administrator terminal: " +
			"privatae-bastion approvals-owner --sid <your account's SID>"
	case !strings.EqualFold(owner, c.UserSID):
		return "this machine's approvals belong to another account, not " + pipeWho(c)
	}
	return ""
}

// ownerConsole and ownerServiceState are seams so the suite drives the
// command on any machine; nothing outside tests assigns them.
var (
	ownerConsole      = stdioIsConsole
	ownerServiceState = func() string {
		return enrolServiceStateRefusal(runtime.GOOS, systemService.installed, systemService.authority, systemService.err)
	}
)

// privatae-bastion approvals-owner --sid <SID> [--replace]
func cmdApprovalsOwner(sid string, replace bool) error {
	if err := requireMachineAuthority("approvals-owner"); err != nil {
		return err
	}
	if why := ownerServiceState(); why != "" {
		return fmt.Errorf("approvals-owner records the owner in the system service's state: %s — nothing was changed", why)
	}
	if !approvalsOwnerSIDOK(sid) {
		return fmt.Errorf("%q is not the SID of a person's account (S-1-5-21-… or S-1-12-1-…) — nothing was changed", sid)
	}
	if replace && !ownerConsole() {
		return errors.New("approvals-owner --replace hands this machine's approvals to another account, and is taken only " +
			"in an Administrator terminal; this one's input or output goes to a file or a pipe — nothing was changed")
	}
	cur, present, err := approvalsOwnerLoad()
	switch {
	case err == nil && strings.EqualFold(cur, sid):
		fmt.Printf("approvals on this machine already belong to %s\n", sid)
		return nil
	case present && !replace:
		was := cur
		if err != nil {
			was = "an account its record no longer names readably (" + err.Error() + ")"
		}
		return fmt.Errorf("this machine's approvals belong to %s, and stay with it — nothing was changed.\n"+
			"  To hand them to %s, run from an Administrator terminal: privatae-bastion approvals-owner --sid %s --replace", was, sid, sid)
	}
	p, err := approvalsOwnerPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(approvalsOwnerRecord{SID: sid, SetAt: time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(p, raw); err != nil {
		return err
	}
	fmt.Printf("approvals on this machine belong to %s; the tray serves that account only\n", sid)
	return nil
}
