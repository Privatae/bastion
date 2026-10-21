package main

// switch_cli.go — the local switch (localdeny.go) from a terminal.
//
//	privatae-bastion switch <host> <family> on|off
//	privatae-bastion switch --list
//
// The console page has had this switch since localdeny.go was written; a
// machine with no browser and no person at it (a server the bastion guards
// for a Host on the same box) had no way to reach it. The command writes the
// same deny list through the same localDenySet, so the invariant there holds
// unchanged: "off" removes reach, "on" clears a refusal and grants nothing.
//
// MACHINE AUTHORITY, for both directions. On a machine that serves a Host it
// does not belong to the person using that Host, the switch is part of how
// the machine was set up, and the one who stands behind that is whoever
// administers the box. --list only reads, and needs no authority of its own;
// beside a system service on macOS or Windows an ordinary account is refused
// it (serviceGuard, sysservice.go), because it would read that account's own
// state rather than the machine's.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const switchUsage = "usage: sudo -H privatae-bastion switch <host> <family> on|off\n" +
	"       privatae-bastion switch --list"

// cmdSwitch parses the arguments and runs one switch, or the listing.
func cmdSwitch(args []string) error {
	if len(args) == 1 && args[0] == "--list" {
		return switchList(os.Stdout)
	}
	if len(args) != 3 {
		return errors.New(switchUsage)
	}
	var off bool
	switch strings.ToLower(args[2]) {
	case "off":
		off = true
	case "on":
		off = false
	default:
		return fmt.Errorf("the last word is on or off, not %q\n%s", args[2], switchUsage)
	}
	if err := requireMachineAuthority("switch"); err != nil {
		return err
	}
	host, err := switchResolveHost(args[0])
	if err != nil {
		return err
	}
	family := strings.TrimSpace(args[1])
	if err := localDenySet(host, family, off); err != nil {
		return err
	}
	if off {
		fmt.Printf("%s %s off: this machine now refuses it, and tells the host why. Its grant is untouched.\n", host, family)
	} else {
		fmt.Printf("%s %s on: the refusal is cleared, up to whatever its signed grant already allowed.\n", host, family)
	}
	return nil
}

// switchResolveHost accepts a paired host's full name or a unique prefix of
// one, the way --host does everywhere else. A name no pairing matches is
// passed through unchanged so that localDenySet gives its own refusal, which
// names the problem in the same words the console page uses.
func switchResolveHost(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", errors.New("no host named\n" + switchUsage)
	}
	cfgs, err := loadPairings()
	if err != nil {
		return key, nil
	}
	c, err := findPairing(cfgs, key)
	if err != nil {
		return "", err
	}
	if c == nil {
		return key, nil
	}
	return c.HostName, nil
}

// switchList prints one line per paired host and family:
//
//	<host> <family> on|off [since <time>]
//
// Plain columns so a setup script can read it as well as a person.
func switchList(w io.Writer) error {
	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	if len(cfgs) == 0 {
		// Name the state that was read. On Linux the root service keeps its
		// state under /root, and an ordinary account's --list reads its own,
		// so "no host is paired with this machine" would be untrue there.
		dir, _ := configDirPath()
		fmt.Fprintf(w, "no host is paired in this account's bastion state (%s); "+
			"the machine's bastion may keep its state under another account (%s)\n", dir, adminHowTo())
		return nil
	}
	localDenyMu.Lock()
	f, readErr := localDenyLoad()
	localDenyMu.Unlock()
	if readErr != nil {
		// The same direction the page takes (localDenyIndex): say so, because
		// every family below then reads "on" while the person may believe
		// something is off.
		fmt.Fprintf(w, "warning: %v\n", readErr)
	}
	names := hostNames(cfgs)
	sort.Strings(names)
	fams := localSwitchFamilies()
	for _, host := range names {
		off := map[string]bool{}
		for _, fam := range f.Off[host] {
			off[fam] = true
		}
		for _, fam := range fams {
			if off[fam] {
				line := host + " " + fam + " off"
				if at := f.At[host+"/"+fam]; at != "" {
					line += " since " + at
				}
				fmt.Fprintln(w, line)
				continue
			}
			fmt.Fprintln(w, host+" "+fam+" on")
		}
	}
	return nil
}
