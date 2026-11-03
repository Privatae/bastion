package main

// uninstall.go — `privatae-bastion uninstall [--delete-data]`.
//
// Removes what the installers put in place: the service that starts the
// bastion (the systemd unit, the launchd daemon, the Windows service, or the
// account's own user unit, LaunchAgent or logon task) and the program. The
// bastion's state stays unless --delete-data is given: the pairings and keys,
// and the audit log, which is the record of what every Host and agent did on
// this machine and is the one thing a person may need after the bastion is
// gone. --delete-data takes a typed confirmation at a terminal.
//
// Installed for the whole machine, uninstalling needs the machine's
// administrator, as stopping the service does. The steps are decided in
// uninstallSteps, untagged, so the suite checks every platform's on any.

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type uninstallStep struct {
	Run    []string // a command to run; its failure is reported and the rest go on
	Remove string   // a file to remove; one already gone is fine
	Call   string   // "system-service": uninstallSystemService (macOS, Windows)
	Say    string   // printed as it is done
}

// uninstallSteps is what uninstalling removes on goos. whole: the bastion is
// installed for the whole machine.
func uninstallSteps(goos string, whole bool, home string, uid int) []uninstallStep {
	var s []uninstallStep
	switch goos {
	case "linux":
		if whole {
			s = append(s,
				uninstallStep{Run: []string{"systemctl", "disable", "--now", "privatae-bastion"}, Say: "stopped the system service privatae-bastion"},
				uninstallStep{Remove: linuxSystemUnitPath},
				uninstallStep{Run: []string{"systemctl", "daemon-reload"}},
				uninstallStep{Remove: "/usr/local/bin/privatae-bastion", Say: "removed /usr/local/bin/privatae-bastion"})
		} else {
			unit := filepath.Join(home, ".config", "systemd", "user", "privatae-bastion.service")
			if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
				unit = filepath.Join(x, "systemd", "user", "privatae-bastion.service")
			}
			s = append(s,
				uninstallStep{Run: []string{"systemctl", "--user", "disable", "--now", "privatae-bastion"}, Say: "stopped your own service privatae-bastion"},
				uninstallStep{Remove: unit},
				uninstallStep{Run: []string{"systemctl", "--user", "daemon-reload"}},
				uninstallStep{Remove: filepath.Join(home, ".local", "bin", "privatae-bastion")})
		}
	case "darwin":
		if whole {
			s = append(s,
				uninstallStep{Call: "system-service"},
				uninstallStep{Remove: "/Library/Application Support/privatae/bin/privatae-bastion", Say: "removed the program"},
				uninstallStep{Remove: "/usr/local/bin/privatae-bastion"})
		} else {
			s = append(s,
				uninstallStep{Run: []string{"/bin/launchctl", "bootout", "gui/" + strconv.Itoa(uid) + "/ai.privatae.bastion.user"}, Say: "stopped your own LaunchAgent"},
				uninstallStep{Remove: filepath.Join(home, "Library", "LaunchAgents", "ai.privatae.bastion.user.plist")},
				uninstallStep{Remove: filepath.Join(home, ".local", "bin", "privatae-bastion")})
		}
	case "windows":
		if whole {
			s = append(s, uninstallStep{Call: "system-service"})
		} else {
			s = append(s,
				uninstallStep{Run: []string{"schtasks", "/End", "/TN", "PrivataeBastion"}},
				uninstallStep{Run: []string{"schtasks", "/Delete", "/TN", "PrivataeBastion", "/F"}, Say: "removed your sign-in task PrivataeBastion"})
		}
	}
	// The program is removed only from the installers' own places, never from
	// wherever else someone keeps a copy. On Windows a running program cannot
	// be removed; cmdUninstall says where it is.
	return s
}

// uninstallWhole reports whether this machine's bastion is installed for the
// whole machine.
func uninstallWhole() bool {
	if runtime.GOOS == "linux" {
		return linuxSystemUnitPresent()
	}
	return systemService.installed
}

// uninstallHomeRefusal: on Linux, root's state is found through root's HOME
// (the unit runs with HOME=/root), and a sudo that keeps the caller's HOME (no
// -H) or XDG_CONFIG_HOME (sudo -E, env_keep) would name the person's own state
// as the machine's, and with --delete-data delete it. dataDir is the folder
// this process would name. "" when fine.
func uninstallHomeRefusal(goos string, root bool, dataDir, rootHome string) string {
	if goos != "linux" || !root || rootHome == "" ||
		filepath.Clean(dataDir) == filepath.Join(rootHome, ".config", "privatae-bastion") {
		return ""
	}
	return "run it as: sudo -H privatae-bastion uninstall, with no XDG_CONFIG_HOME kept. This sudo kept your HOME or XDG_CONFIG_HOME, " +
		"so the state it would name (" + dataDir + ") is your account's, not the machine's — nothing was removed"
}

// uninstallRootStateRefusal is uninstallHomeRefusal for this process.
func uninstallRootStateRefusal() string {
	if !machineAuthorityHeld() {
		return ""
	}
	rootHome := ""
	if u, err := user.LookupId("0"); err == nil {
		rootHome = u.HomeDir
	}
	dataDir, _ := configDirPath()
	return uninstallHomeRefusal(runtime.GOOS, true, dataDir, rootHome)
}

func cmdUninstall(deleteData bool) error {
	if why := uninstallRootStateRefusal(); why != "" {
		return errors.New(why)
	}
	// From an account that does not administer the machine, uninstall
	// removes that account's own bastion and leaves the machine's alone.
	machine := uninstallWhole()
	whole := machine && machineAuthorityHeld()
	if machine && !whole && !accountInstallPresent() {
		return requireMachineAuthority("uninstall")
	}
	dataDir, err := configDirPath()
	if err != nil {
		return err
	}
	if deleteData && !uninstallConfirm(dataDir) {
		return errors.New("nothing was removed")
	}
	home, _ := os.UserHomeDir()
	self, _ := resolvedSelf()
	cfgs, _ := loadPairings()
	hadHosts := len(cfgs) > 0
	failed := 0
	// The door's own firewall rules (doorfw.go): once the first step has
	// stopped the service, so nothing adds one back, and while the program a
	// rule names is still in place.
	fwDone := false
	removeFirewall := func() {
		if fwDone {
			return
		}
		fwDone = true
		fwSaid, fwErr := doorFirewallRemoveAll()
		for _, l := range fwSaid {
			fmt.Println("  " + l)
		}
		if fwErr != nil {
			fmt.Fprintf(os.Stderr, "  could not remove the bastion's own firewall rule: %v\n", fwErr)
			failed++
		}
	}
	for i, st := range uninstallSteps(runtime.GOOS, whole, home, os.Getuid()) {
		if i == 1 {
			removeFirewall()
		}
		switch {
		case st.Call == "system-service":
			if err := uninstallSystemService(); err != nil {
				fmt.Fprintf(os.Stderr, "  %v\n", err)
				failed++
			}
		case len(st.Run) > 0:
			cmd := exec.Command(st.Run[0], st.Run[1:]...)
			hideConsole(cmd)
			out, err := cmd.CombinedOutput()
			if err != nil && st.Say != "" {
				fmt.Fprintf(os.Stderr, "  %s: %v %s\n", strings.Join(st.Run, " "), err, strings.TrimSpace(string(out)))
				failed++
				continue
			}
		case st.Remove != "":
			if err := os.Remove(st.Remove); err != nil && !errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "  could not remove %s: %v\n", st.Remove, err)
				failed++
				continue
			}
		}
		if st.Say != "" {
			fmt.Println("  " + st.Say)
		}
	}
	removeFirewall() // a platform with one step
	if deleteData {
		if err := os.RemoveAll(dataDir); err != nil {
			return fmt.Errorf("the bastion is removed, but its state could not be deleted: %w", err)
		}
		fmt.Printf("Deleted %s: its pairings, keys and audit log.\n", dataDir)
	} else {
		fmt.Printf("Kept %s: its pairings, keys and the audit log of what Hosts and agents did here.\n"+
			"  Delete it with: privatae-bastion uninstall --delete-data, or remove the folder.\n", dataDir)
	}
	if runtime.GOOS == "windows" && self != "" {
		fmt.Printf("The program is still at %s; Windows cannot remove a running program. Delete it now this has finished.\n", self)
	}
	if failed > 0 {
		return fmt.Errorf("%d step(s) did not finish (above); the rest was removed", failed)
	}
	if machine && !whole {
		fmt.Println("Your account's own bastion is removed. The machine's stays; removing it needs: sudo -H privatae-bastion uninstall")
		return nil
	}
	if hadHosts {
		fmt.Println("The bastion is uninstalled. The Hosts it was connected to see it go quiet.")
	} else {
		fmt.Println("The bastion is uninstalled.")
	}
	return nil
}

// uninstallConfirm asks for the word "delete" at a terminal before the state
// goes. Not at a terminal, the answer is no.
func uninstallConfirm(dir string) bool {
	if !stdinIsConsole() {
		fmt.Fprintln(os.Stderr, "--delete-data deletes the audit log too, so it is confirmed at a terminal; this one's input is a file or a pipe.")
		return false
	}
	fmt.Printf("This deletes %s: the pairings, keys and the audit log of what Hosts and agents did here.\n"+
		"Type delete to go on: ", dir)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line) == "delete"
}

// accountInstallPresent: this account has a bastion of its own installed (its
// user unit, LaunchAgent or program in ~/.local/bin).
func accountInstallPresent() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	for _, st := range uninstallSteps(runtime.GOOS, false, home, os.Getuid()) {
		if st.Remove != "" {
			if _, err := os.Stat(st.Remove); err == nil {
				return true
			}
		}
	}
	return false
}
