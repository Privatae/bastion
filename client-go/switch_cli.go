package main

// switch_cli.go — the local switch (localdeny.go) from a terminal.
//
//	privatae-bastion switch <host> <family> on|off
//	privatae-bastion switch --list [--json]
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
// administers the box. --list only reads, and needs no authority of its own:
// beside a system service on Linux or macOS the owner's account reads the
// machine's list through the lane (reads.go); on Windows an ordinary account
// is refused it (serviceGuard, sysservice.go), because it would read that
// account's own state rather than the machine's.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const switchUsage = "usage: sudo -H privatae-bastion switch <host> <family> on|off\n" +
	"       privatae-bastion switch --list [--json]\n" +
	"       sudo -H privatae-bastion switch --reset   (only when the list cannot be read)"

// cmdSwitch parses the arguments and runs one switch, the listing, or the
// reset of an unreadable list.
func cmdSwitch(args []string) error {
	if len(args) >= 1 && args[0] == "--list" {
		asJSON, err := jsonOnly(switchUsage, args[1:])
		if err != nil {
			return err
		}
		v, err := readMachine("switches", readOpts{}, readSwitches)
		if err != nil {
			return laneRefusalError("switch --list", err)
		}
		if asJSON {
			return printJSON(os.Stdout, v)
		}
		printSwitches(os.Stdout, v)
		return nil
	}
	if len(args) == 1 && args[0] == "--reset" {
		// The same authority as switching anything back on: a reset leaves
		// nothing switched off.
		if err := requireMachineAuthority("switch"); err != nil {
			return err
		}
		kept, err := localDenyReset()
		if err != nil {
			return err
		}
		fmt.Printf("The unreadable list is kept at %s. Nothing is switched off now; "+
			"switch off again whatever you had off: switch <host> <family> off\n", kept)
		return nil
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
	if readsGoThroughLane() {
		// The owner's account, beside the machine's bastion: the console's
		// rule, through its ask socket (owneracts.go). Off takes reach away and
		// needs nothing; on takes the owner's code.
		req := agentAskRequest{Act: "switch", Host: args[0], Family: args[1], Off: off}
		if !off {
			code, ok := promptOwnerCode("Switch " + args[0] + " " + args[1] + " back on? Enter the code from your authenticator (or leave empty to cancel): ")
			if !ok {
				return nil
			}
			req.Code = code
		}
		done, err := actViaSock(req)
		if err != nil {
			return laneRefusalError("switch "+strings.Join(args, " "), err)
		}
		fmt.Println(done)
		return nil
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
	fmt.Println(switchDoneText(host, family, off))
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

// switchRow is one family of one paired host: off (refused here) or on.
type switchRow struct {
	Host   string `json:"host"`
	Family string `json:"family"`
	Off    bool   `json:"off"`
	Since  string `json:"since,omitempty"`
}

// switchesRead is the local switch as it stands. Unreadable: the list cannot
// be read, so the gate refuses everything (localDenied) and every row is off.
type switchesRead struct {
	Switches   []switchRow `json:"switches"`
	Unreadable string      `json:"unreadable,omitempty"`
	// StateDir is the bastion state that was read, named when nothing is
	// paired in it: an ordinary account's own state is not the machine's.
	StateDir string `json:"state_dir,omitempty"`
}

func readSwitches(readOpts) (switchesRead, error) {
	v := switchesRead{Switches: []switchRow{}}
	cfgs, err := loadPairings()
	if err != nil {
		return v, err
	}
	if len(cfgs) == 0 {
		v.StateDir, _ = configDirPath()
		return v, nil
	}
	localDenyMu.Lock()
	f, readErr := localDenyLoad()
	localDenyMu.Unlock()
	if readErr != nil {
		v.Unreadable = localDenyUnreadableText(readErr)
	}
	names := hostNames(cfgs)
	sort.Strings(names)
	fams := localSwitchFamilies()
	for _, host := range names {
		off := map[string]bool{}
		if readErr == nil {
			for _, fam := range f.Off[host] {
				off[fam] = true
			}
		}
		for _, fam := range fams {
			r := switchRow{Host: host, Family: fam, Off: readErr != nil || off[fam]}
			if readErr == nil && off[fam] {
				r.Since = f.At[host+"/"+fam]
			}
			v.Switches = append(v.Switches, r)
		}
	}
	return v, nil
}

// switchList is the listing of this process's own state, in words.
func switchList(w io.Writer) error {
	v, err := readSwitches(readOpts{})
	if err != nil {
		return err
	}
	printSwitches(w, v)
	return nil
}

// printSwitches prints one line per paired host and family:
//
//	<host> <family> on|off [since <time>]
//
// Plain columns so a setup script can read it as well as a person.
func printSwitches(w io.Writer, v switchesRead) {
	if len(v.Switches) == 0 {
		// Name the state that was read: an ordinary account's own is not
		// the machine's, so "nothing is paired with this machine" could be
		// untrue.
		fmt.Fprintf(w, "no host is paired in the bastion state at %s\n", v.StateDir)
		return
	}
	if v.Unreadable != "" {
		// The gate refuses everything while the list cannot be read
		// (localDenied), so every line says off, and the warning says why.
		fmt.Fprintf(w, "warning: %s\n", v.Unreadable)
	}
	for _, r := range v.Switches {
		line := r.Host + " " + r.Family + " on"
		if r.Off {
			line = r.Host + " " + r.Family + " off"
			if r.Since != "" {
				line += " since " + r.Since
			}
		}
		fmt.Fprintln(w, line)
	}
}
