//go:build darwin

package main

// The macOS half of sysservice.go: a launchd daemon in the system domain.
//
// launchctl is run by its absolute path with a fixed argument list. This code
// runs as root, so a launchctl found through PATH would be whatever the
// caller's PATH named first.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const launchctlPath = "/bin/launchctl"

// systemServiceInstalled reports whether the daemon's job file is in place. A
// file that cannot be checked is reported as an error, which the caller treats
// as installed for the guard (adoptSystemServiceState).
func systemServiceInstalled() (bool, error) {
	_, err := os.Stat(launchdPlistPath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// darwinOwnerMode is pathOwnerMode for this machine: Lstat, so a symlink is
// seen as one rather than followed.
func darwinOwnerMode(p string) (uint32, fs.FileMode, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("no owner information for %s", p)
	}
	return st.Uid, fi.Mode(), nil
}

func installSystemService() error {
	self, err := resolvedSelf()
	if err != nil {
		return fmt.Errorf("cannot find this program's own path: %w", err)
	}
	if err := binaryChainRootOnly(self, darwinOwnerMode); err != nil {
		return fmt.Errorf("refusing to register %s as the system service: %w.\n"+
			"  The installer's --networked option puts the program in a folder only root can change", self, err)
	}
	plist, err := launchdPlist(self)
	if err != nil {
		return err
	}
	if err := writeRootFile(launchdPlistPath, plist, 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", launchdPlistPath, err)
	}
	// launchd creates a missing log file readable by everyone. What the bastion
	// reports about this machine (the agents it sees, the hosts it serves) is
	// the administrator's to read, so the file is made first, root-only, and
	// launchd appends to it as it finds it.
	if f, err := os.OpenFile(darwinDaemonLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		_ = f.Close()
	}
	_ = os.Chmod(darwinDaemonLog, 0o600)
	// A job already loaded under this label keeps its old definition until it
	// is booted out, so a reinstall boots it out first. Not loaded is fine.
	_ = exec.Command(launchctlPath, "bootout", "system/"+launchdLabel).Run()
	// bootout returns before launchd has finished removing the job, and a
	// bootstrap in that window fails. A few short retries cover it.
	var out []byte
	for i := 0; i < 5; i++ {
		out, err = exec.Command(launchctlPath, "bootstrap", "system", launchdPlistPath).CombinedOutput()
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("launchctl bootstrap failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command(launchctlPath, "enable", "system/"+launchdLabel).Run()
	fmt.Printf("System service installed: launchd daemon %s, running %s as root.\n", launchdLabel, self)
	fmt.Println("  It starts at boot, before anyone signs in, and launchd restarts it whenever it stops.")
	fmt.Printf("  Its log is %s.\n", darwinDaemonLog)
	return nil
}

func uninstallSystemService() error {
	_ = exec.Command(launchctlPath, "bootout", "system/"+launchdLabel).Run()
	if err := os.Remove(launchdPlistPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cannot remove %s: %w", launchdPlistPath, err)
	}
	fmt.Printf("System service removed: %s is no longer registered with launchd.\n", launchdLabel)
	fmt.Println("  The bastion's state under /var/root is left in place.")
	return nil
}

func printSystemServiceStatus() error {
	installed, err := systemServiceInstalled()
	if err != nil {
		return err
	}
	if !installed {
		fmt.Println("No system service is installed on this machine.")
		return nil
	}
	out, err := exec.Command(launchctlPath, "print", "system/"+launchdLabel).CombinedOutput()
	if err != nil {
		fmt.Printf("System service %s is installed but not loaded (launchctl: %s).\n", launchdLabel, strings.TrimSpace(string(out)))
		return nil
	}
	state, pid := "unknown", ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "state = "); ok && state == "unknown" {
			state = v
		}
		if v, ok := strings.CutPrefix(line, "pid = "); ok && pid == "" {
			pid = v
		}
	}
	if pid != "" {
		fmt.Printf("System service %s: %s (pid %s).\n", launchdLabel, state, pid)
	} else {
		fmt.Printf("System service %s: %s.\n", launchdLabel, state)
	}
	return nil
}

// writeRootFile writes a root-owned file with an exact mode, through a temp
// file and a rename in the same directory, so launchd never reads half a job.
func writeRootFile(p string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".privatae-bastion-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
