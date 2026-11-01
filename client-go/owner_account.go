package main

// owner_account.go — on Linux and macOS, the one account the machine's
// bastion opens its console to without sudo (consolelane.go).
//
// Installed for the whole machine, the bastion runs as root and its console
// signs in with root's ui.secret. The person who installed it works in their
// own account, and before this record they reached the console only through
// sudo. The record names that account by uid, in the service's own state,
// where a process running as the person can neither read nor write it.
//
// WHO WRITES IT. The installer's root step, from the account sudo ran it for
// (SUDO_UID), or an administrator by hand: `approvals-owner --account <name>`.
// The rules are approvals_owner.go's for the Windows SID: the same account
// again changes nothing; another account is refused unless --replace is
// typed at a terminal; a record that cannot be read is never quietly replaced.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// lookupOwnerAccount finds an account by name, or by uid when given a number.
var lookupOwnerAccount = func(who string) (*user.User, error) {
	if _, err := strconv.ParseUint(who, 10, 32); err == nil {
		return user.LookupId(who)
	}
	return user.Lookup(who)
}

// privatae-bastion approvals-owner --account <name|uid> [--replace]
func cmdOwnerAccount(who string, replace bool) error {
	if err := requireMachineAuthority("approvals-owner"); err != nil {
		return err
	}
	if why := ownerServiceState(); why != "" {
		return fmt.Errorf("approvals-owner records the owner in the system service's state: %s — nothing was changed", why)
	}
	who = strings.TrimSpace(who)
	u, err := lookupOwnerAccount(who)
	if err != nil {
		return fmt.Errorf("no account %q on this machine — nothing was changed", who)
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("account %s has a uid this system does not use (%q) — nothing was changed", u.Username, u.Uid)
	}
	uid := uint32(n)
	if uid == 0 {
		return errors.New("root administers this machine already and opens the console with its own key; " +
			"name the person's own account — nothing was changed")
	}
	if replace && !ownerConsole() {
		return errors.New("approvals-owner --replace hands this machine's console to another account, and is taken only " +
			"at a terminal; this one's input or output goes to a file or a pipe — nothing was changed")
	}
	cur, curName, present, err := ownerAccountLoad()
	switch {
	case err == nil && present && cur == uid:
		fmt.Printf("this machine's owner account is already %s\n", u.Username)
		return nil
	case present && !replace:
		was := curName
		if was == "" {
			was = "uid " + strconv.FormatUint(uint64(cur), 10)
		}
		if err != nil {
			was = "an account its record no longer names readably (" + err.Error() + ")"
		}
		return fmt.Errorf("this machine's owner account is %s, and stays so — nothing was changed.\n"+
			"  To hand it to %s, run at a terminal: sudo -H privatae-bastion approvals-owner --account %s --replace",
			was, u.Username, u.Username)
	}
	p, err := approvalsOwnerPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(approvalsOwnerRecord{UID: &uid, Account: u.Username,
		SetAt: time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(p, raw); err != nil {
		return err
	}
	fmt.Printf("this machine's owner account is %s: `privatae-bastion ui` opens the console from it.\n"+
		"  Anything that stops an agent or widens access still takes the owner's code.\n", u.Username)
	return nil
}
