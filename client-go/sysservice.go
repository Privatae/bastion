package main

// The bastion as the SYSTEM's service on macOS and Windows.
//
// On Linux the networked bastion has always been a root-owned systemd unit
// (deploy/install.sh). macOS and Windows had nothing like it: the Mac installer
// refused --networked, and on Windows the bastion ran as a logon task under the
// signed-in person's own account. That is right on a person's own computer and
// wrong on a machine an organisation enrols, where the organisation's policy
// has to hold whoever is signed in. A process the signed-in user started is a
// process the signed-in user can stop.
//
// So a networked install on those platforms now registers the bastion with the
// operating system's own service manager: a launchd daemon running as root on
// macOS, and a Windows service running as LocalSystem. Whoever administers the
// machine holds the service; the person using it works in their own account.
//
// Two rules follow, and they are decided here, in an untagged file, so the
// suite checks them on every platform. The operating-system calls are in
// sysservice_darwin.go and sysservice_windows.go.
//
//   - ONE STATE DIRECTORY. The service and an administrator's commands must
//     read and write the same pairings. The state directory comes from
//     os.UserConfigDir, which follows HOME on macOS and APPDATA on Windows, and
//     an administrator's terminal does not carry the service's values: `sudo`
//     on macOS keeps the caller's HOME unless given -H, and an elevated Windows
//     terminal keeps the administrator's own profile. So when the service is
//     installed and the caller administers the machine, the process points
//     that one variable at the service's own before anything reads state.
//   - NO SECOND BASTION FROM AN ORDINARY ACCOUNT. With the service installed,
//     `pair`, `run` and `status` from an account that does not administer the
//     machine would act on an empty bastion of that account's own, beside the
//     machine's. They are refused with a sentence saying what to do instead. As
//     with the machine marker (singleton.go), this binds a cooperating binary
//     only; an older copy will not refuse. What stops the person from removing
//     the service is that they do not administer the machine.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"runtime"
	"strings"
	"time"
)

const (
	launchdLabel     = "ai.privatae.bastion"
	launchdPlistPath = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	// darwinRootHome is root's home on macOS. The daemon runs with it as HOME,
	// which puts its state under /var/root/Library/Application Support, a
	// directory only root can enter.
	darwinRootHome  = "/var/root"
	darwinDaemonLog = "/var/log/privatae-bastion.log"

	winServiceName    = "PrivataeBastion"
	winServiceDisplay = "Privatae bastion"
	winServiceDesc    = "Serves this machine to the Hosts it is paired with. It runs as the system, " +
		"so the machine's administrator, not the signed-in user, decides whether it runs."
)

// runningAsService is set by the Windows service entry point (sysservice_windows.go)
// before anything else runs, and never changes after. The tray, the blocking
// dialogs and the relaunch after an update all read it: a service has no
// desktop to show them on, and the service manager restarts it.
var runningAsService bool

// windowsSystemAppData is LocalSystem's own roaming profile folder, which is
// where a Windows service running as LocalSystem keeps the bastion's state.
// It sits under System32\config, which only SYSTEM and administrators can open,
// so the pairings and keys there are out of reach of the signed-in user
// without any permission change of ours.
func windowsSystemAppData(systemRoot string) string {
	systemRoot = strings.TrimRight(strings.TrimSpace(systemRoot), `\`)
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	return systemRoot + `\System32\config\systemprofile\AppData\Roaming`
}

// serviceStateEnv names the environment variable to set, and its value, so this
// process reads and writes the system service's state. An empty key means
// change nothing: no service is installed, or this caller does not administer
// the machine (and so could not open the service's state anyway).
func serviceStateEnv(goos string, installed, authority bool, systemRoot string) (key, value string) {
	if !installed || !authority {
		return "", ""
	}
	switch goos {
	case "darwin":
		return "HOME", darwinRootHome
	case "windows":
		return "APPDATA", windowsSystemAppData(systemRoot)
	}
	return "", ""
}

// serviceGuardedCommands would each act on a bastion in the caller's own
// profile. Beside a system service that is a second bastion (pair, run) or a
// view of an empty one (status, and `switch --list`, which would print the
// caller's own pairings and switches as though they were the machine's).
var serviceGuardedCommands = map[string]bool{"pair": true, "run": true, "status": true, "switch": true}

// serviceGuard refuses a guarded command from an account that does not
// administer a machine whose bastion is a system service.
func serviceGuard(goos, cmd string, installed, authority bool) error {
	if !installed || authority || !serviceGuardedCommands[cmd] {
		return nil
	}
	if goos != "darwin" && goos != "windows" {
		return nil
	}
	return fmt.Errorf("this machine's bastion runs as a system service, and it belongs to whoever administers the machine.\n"+
		"  `%s` from your own account would act on a separate, empty bastion of your own, not on the machine's.\n"+
		"  To work with the machine's bastion, %s", cmd, adminHowToFor(goos))
}

// launchdPlist is the launchd job for the daemon. KeepAlive restarts it
// whenever it exits, which is also how a self-update takes effect: update.go
// exits after swapping the binary, exactly as it does under systemd's
// Restart=always. RunAtLoad starts it at boot, before anyone signs in.
func launchdPlist(binary string) ([]byte, error) {
	if !strings.HasPrefix(binary, "/") {
		return nil, fmt.Errorf("the service's program must be an absolute path, not %q", binary)
	}
	for _, r := range binary {
		if r < 0x20 || r == 0x7f {
			return nil, fmt.Errorf("the service's program path holds a control character")
		}
	}
	x := xmlText
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + x(launchdLabel) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + x(binary) + `</string>
		<string>run</string>
	</array>
	<key>UserName</key>
	<string>root</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key>
		<string>` + x(darwinRootHome) + `</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>` + x(darwinDaemonLog) + `</string>
	<key>StandardErrorPath</key>
	<string>` + x(darwinDaemonLog) + `</string>
</dict>
</plist>
`), nil
}

func xmlText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// pathOwnerMode reports a path's owning uid and mode WITHOUT following a final
// symlink. A function value so the rule below is tested off macOS.
type pathOwnerMode func(p string) (uid uint32, mode fs.FileMode, err error)

// binaryChainRootOnly refuses a program the root daemon would run if anyone but
// root could replace it. The file and every directory above it must be owned by
// root and writable by neither group nor others: a user who can write the
// directory can rename the file away and put their own in its place, and the
// next restart runs it as root.
//
// This is not hypothetical on macOS. /usr/local/bin is handed to the signed-in
// user on many Macs by a common package manager, which is why the installer
// puts the daemon's program under /Library/Application Support instead.
func binaryChainRootOnly(binary string, stat pathOwnerMode) error {
	if !strings.HasPrefix(binary, "/") {
		return fmt.Errorf("%q is not an absolute path", binary)
	}
	p := path.Clean(binary)
	for {
		uid, mode, err := stat(p)
		if err != nil {
			return fmt.Errorf("cannot check %s: %w", p, err)
		}
		if mode&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link; the service must name the program itself", p)
		}
		if uid != 0 {
			return fmt.Errorf("%s is owned by uid %d, not root, so its owner could replace the program the service runs as root", p, uid)
		}
		if mode.Perm()&0o022 != 0 {
			return fmt.Errorf("%s can be written by its group or by everyone (%v), so they could replace the program the service runs as root", p, mode.Perm())
		}
		if p == "/" {
			return nil
		}
		p = path.Dir(p)
	}
}

// windowsServiceBinaryOK refuses to register a program the signed-in user
// could replace. Program Files is writable only by administrators unless
// someone has changed that, which is why the installer puts the program there:
// a service runs as LocalSystem, so whoever can swap its file runs code as
// the system on the next restart. The per-user install folder under
// %LOCALAPPDATA% is exactly such a file.
func windowsServiceBinaryOK(exe, programFiles string) error {
	norm := func(s string) string {
		s = strings.ReplaceAll(strings.TrimSpace(s), "/", `\`)
		return strings.ToLower(strings.TrimRight(s, `\`))
	}
	e, pf := norm(exe), norm(programFiles)
	if pf == "" {
		return errors.New("cannot tell where Program Files is (HKLM ProgramFilesDir is empty)")
	}
	for _, part := range strings.Split(e, `\`) {
		if part == ".." {
			return fmt.Errorf("%s holds a '..' step", exe)
		}
	}
	if !strings.HasPrefix(e, pf+`\`) {
		return fmt.Errorf("the service's program must live under %s, which only administrators can change; it is at %s.\n"+
			"  Install it with the installer's -Networked switch, which puts it there", programFiles, exe)
	}
	return nil
}

// serviceRestartHintFor / serviceRunHintFor are restartHint and runCommandHint
// for a machine whose bastion is a system service.
func serviceRestartHintFor(goos string) string {
	switch goos {
	case "darwin":
		return "Restart the service so the change takes:  sudo launchctl kickstart -k system/" + launchdLabel
	case "windows":
		return "Restart the service so the change takes:  Restart-Service " + winServiceName + "   (from an Administrator terminal)"
	}
	return restartHintFor(goos)
}

func serviceRunHintFor(goos string) string {
	switch goos {
	case "darwin":
		return "sudo launchctl kickstart system/" + launchdLabel
	case "windows":
		return "Start-Service " + winServiceName + "   (from an Administrator terminal)"
	}
	return runCommandHintFor(goos)
}

// serviceLogCap is the size past which a service's log is set aside when the
// service starts. A service has no console, so its file is all that is kept of
// what it says, and an unpaired service restarting adds a line each time.
const serviceLogCap = 8 << 20

// keepOneLogAside sets a log aside once it is larger than limit: its content
// is copied to <path>.1, replacing the previous one, and the file is emptied
// in place. In place rather than renamed, because on macOS launchd opened the
// file for the daemon and keeps writing to whatever file that is; after a
// rename it would go on filling the copy. A missing log is not an error.
func keepOneLogAside(p string, limit int64) error {
	fi, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Size() <= limit {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p+".1", data, 0o600); err != nil {
		return err
	}
	return os.Truncate(p, 0)
}

// waitForPairing holds the service until this machine has a pairing, checking
// every `every`, and reports false if asked to stop first.
//
// A fresh service is installed before anything is paired. On Linux the unit
// then exits "not paired" and restarts every two seconds until a pairing
// lands. A Windows service that did that would fill the event log with
// failures, so it waits instead, and starts serving within one check of the
// first pairing.
func waitForPairing(paired func() bool, stop <-chan struct{}, every time.Duration) bool {
	said := false
	for !paired() {
		if !said {
			fmt.Println("service: not paired yet. It starts serving as soon as a pairing is added (from an Administrator terminal).")
			said = true
		}
		select {
		case <-stop:
			return false
		case <-time.After(every):
		}
	}
	return true
}

// systemService is what this process learned about the system service before
// it ran its command (adoptSystemServiceState).
var systemService struct {
	installed bool
	authority bool
	err       error
}

// adoptSystemServiceState runs before any command. It records whether the
// system service is installed and whether this caller administers the machine,
// and points the state directory at the service's when both are true.
//
// A machine where the question cannot be answered is treated as one that HAS
// the service for the guard (so an ordinary account is refused rather than
// forking state on a box that may well be enrolled) and as one that does NOT
// for the redirection (the state is left where it was).
//
// Authority is recorded whether or not a service is installed. On Linux
// systemServiceInstalled always answers no, because the service there is the
// systemd unit, and root's own state is the state that unit reads. Recording
// authority only after an installed service left root on Linux looking like
// an ordinary account, and enrolServiceStateRefusal refused it.
func adoptSystemServiceState() {
	installed, err := systemServiceInstalled()
	systemService.err = err
	systemService.installed = installed || err != nil
	systemService.authority = machineAuthorityHeld()
	if !systemService.installed {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "service: cannot tell whether this machine runs the bastion as a system service: %v\n", err)
		return
	}
	if k, v := serviceStateEnv(runtime.GOOS, installed, systemService.authority, os.Getenv("SystemRoot")); k != "" {
		_ = os.Setenv(k, v)
	}
}

// guardServiceFork is serviceGuard for this process.
func guardServiceFork(cmd string) error {
	return serviceGuard(runtime.GOOS, cmd, systemService.installed, systemService.authority)
}

// cmdService is `privatae-bastion service install|uninstall|status`.
func cmdService(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: privatae-bastion service install|uninstall|status")
	}
	switch args[0] {
	case "install":
		if err := requireMachineAuthority("service install"); err != nil {
			return err
		}
		return installSystemService()
	case "uninstall":
		if err := requireMachineAuthority("service uninstall"); err != nil {
			return err
		}
		return uninstallSystemService()
	case "status":
		return printSystemServiceStatus()
	}
	return fmt.Errorf("unknown service command %q: use install, uninstall or status", args[0])
}
