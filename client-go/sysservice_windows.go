//go:build windows

package main

// The Windows half of sysservice.go: a service running as LocalSystem,
// registered with the Service Control Manager.
//
// THE SAME BINARY IS THE SERVICE. When the Service Control Manager starts it,
// maybeRunAsWindowsService takes over before main parses any argument, points
// the state directory at LocalSystem's profile, and runs the ordinary `run`
// under the service's stop and shutdown requests. A stop request is the same
// shutdown the tray's "Stop the bastion" asks for (requestShutdown), so the
// tunnels are torn down rather than dropped.
//
// HOW IT COMES BACK. `service install` sets the service to restart five
// seconds after any failure, including a stop that reports an error. That
// covers both ways the bastion leaves on its own: `run` returning an error,
// and the exit that follows a self-update (update.go), which ends the process
// without reporting a stop and is therefore a failure to the manager.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// systemServiceInstalled asks the Service Control Manager whether the service
// exists, with the least access that answers it: connect, then query status,
// both of which an ordinary signed-in user holds.
//
// An error here is treated as "installed" by the guard (sysservice.go), which
// would refuse `pair` and `run` on a machine with no service at all. So when
// the manager cannot answer, the service's registry key, which every user can
// read, answers instead, and only a machine where neither can is reported as
// unknown.
func systemServiceInstalled() (bool, error) {
	installed, scmErr := serviceManagerHasService()
	if scmErr == nil {
		return installed, nil
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+winServiceName, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return true, nil
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	return false, fmt.Errorf("%v; the registry cannot answer either: %w", scmErr, err)
}

func serviceManagerHasService() (bool, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, fmt.Errorf("cannot ask the Service Control Manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(winServiceName)
	if err != nil {
		return false, err
	}
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, fmt.Errorf("cannot query the %s service: %w", winServiceName, err)
	}
	windows.CloseServiceHandle(h)
	return true, nil
}

// maybeRunAsWindowsService runs the bastion as the service when the Service
// Control Manager started this process, and reports whether it did.
func maybeRunAsWindowsService() bool {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false
	}
	runningAsService = true
	// main's adoptSystemServiceState never runs in this process, so say here
	// what it would have found: the hints the service prints (the local UI's
	// "start it with", restartHint) then name the service manager, not `run`.
	systemService.installed, systemService.authority = true, true
	// LocalSystem's APPDATA already is this folder. Setting it anyway makes the
	// service and an administrator's commands agree by construction rather
	// than by two environments happening to match (sysservice.go).
	_ = os.Setenv("APPDATA", windowsSystemAppData(os.Getenv("SystemRoot")))
	redirectServiceLog()
	fmt.Printf("service: starting %s %s\n", winServiceName, clientVersion)
	if err := svc.Run(winServiceName, bastionService{}); err != nil {
		fmt.Printf("service: %v\n", err)
		os.Exit(1)
	}
	return true
}

// redirectServiceLog sends everything the bastion prints to a file in its
// state directory, keeping one previous file once it passes serviceLogCap.
func redirectServiceLog() {
	d, err := configDir()
	if err != nil {
		return
	}
	p := filepath.Join(d, "bastion.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > serviceLogCap {
		_ = os.Remove(p + ".1")
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	// The Go runtime writes a panic through the process's standard error
	// HANDLE, looked up at the moment it writes, not through os.Stderr. Without
	// these the one message that explains a crash would go nowhere.
	_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd()))
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
}

type bastionService struct{}

// Execute is the service's life: start `run`, answer the manager, stop when
// asked. A `run` that ends with an error is reported as a service-specific
// failure so the recovery actions restart it.
func (bastionService) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() { done <- runSystemService() }()
	s <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case err := <-done:
			s <- svc.Status{State: svc.StopPending}
			if err != nil {
				fmt.Printf("service: the bastion stopped: %v\n", err)
				return true, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				requestShutdown()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
					fmt.Println("service: the bastion did not stop within 20 seconds; stopping anyway")
				}
				return false, 0
			}
		}
	}
}

// runSystemService waits for a pairing, then runs the bastion exactly as `run` does.
// The approvals pipe comes up first, so the signed-in person's tray can say
// "not paired yet" rather than "cannot reach the bastion".
func runSystemService() error {
	startApprovalPipe(shutdownCh)
	paired := func() bool {
		cfgs, err := loadPairings()
		return err == nil && len(cfgs) > 0
	}
	if !waitForPairing(paired, shutdownCh, 5*time.Second) {
		return nil
	}
	return cmdRun()
}

func installSystemService() error {
	self, err := resolvedSelf()
	if err != nil {
		return fmt.Errorf("cannot find this program's own path: %w", err)
	}
	pf, err := programFilesDir()
	if err != nil {
		return fmt.Errorf("refusing to register %s as the system service: cannot read where Program Files is: %w", self, err)
	}
	if err := windowsServiceBinaryOK(self, pf); err != nil {
		return fmt.Errorf("refusing to register %s as the system service: %w", self, err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot open the Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(winServiceName)
	if err == nil {
		// Already registered: point it at this program and restart it, so a
		// reinstall from a new location cannot leave the service running the
		// old one.
		cfg, err := s.Config()
		if err != nil {
			s.Close()
			return fmt.Errorf("cannot read the %s service's configuration: %w", winServiceName, err)
		}
		cfg.BinaryPathName = syscall.EscapeArg(self) + " run"
		cfg.DisplayName = winServiceDisplay
		cfg.Description = winServiceDesc
		cfg.StartType = mgr.StartAutomatic
		cfg.ServiceStartName = "LocalSystem"
		cfg.Password = ""
		if err := s.UpdateConfig(cfg); err != nil {
			s.Close()
			return fmt.Errorf("cannot update the %s service: %w", winServiceName, err)
		}
		stopServiceAndWait(s)
	} else {
		s, err = m.CreateService(winServiceName, self, mgr.Config{
			DisplayName:  winServiceDisplay,
			Description:  winServiceDesc,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, "run")
		if err != nil {
			return fmt.Errorf("cannot create the %s service: %w", winServiceName, err)
		}
	}
	defer s.Close()

	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
		return fmt.Errorf("cannot set the %s service to restart after a failure: %w", winServiceName, err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("cannot set the %s service to restart after a failed stop: %w", winServiceName, err)
	}
	// Already running is success: the manager can restart it between the stop
	// above and this start, after a failure it is set to recover from.
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("the %s service is registered but did not start: %w", winServiceName, err)
	}
	fmt.Printf("System service installed: %s, running %s as LocalSystem.\n", winServiceName, self)
	// Audit rows go to the Application event log under their own source as
	// well as to their files (auditlog.go). A failure costs that copy only.
	if err := registerAuditEventSource(); err != nil {
		fmt.Printf("  Audit rows will not reach the event log (%v); they are still written to their files.\n", err)
	} else {
		fmt.Printf("  Every audit row is also written to the Application event log, source %s.\n", auditEventSource)
	}
	fmt.Println("  It starts at boot, before anyone signs in, and restarts five seconds after any failure.")
	// The person's tray, at every sign-in (tray.go trayFor). A failure here
	// leaves the service serving; approvals still work from this terminal.
	if err := setTrayLogonEntry(self); err != nil {
		fmt.Printf("  The tray will not start at sign-in (%v); start it with:  %s\n", err, trayRunValue(self))
	} else {
		fmt.Println("  The tray starts at every sign-in, as whoever signs in, for approvals.")
	}
	fmt.Printf("  Its log is %s.\n", filepath.Join(windowsSystemAppData(os.Getenv("SystemRoot")), "privatae-bastion", "bastion.log"))
	return nil
}

// stopServiceAndWait asks the service to stop and waits up to thirty seconds
// for it to say it has. A service that is not running is already stopped.
func stopServiceAndWait(s *mgr.Service) {
	st, err := s.Control(svc.Stop)
	if err != nil {
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	for st.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return
		}
	}
}

func uninstallSystemService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot open the Service Control Manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(winServiceName)
	if err != nil {
		fmt.Println("No system service is installed on this machine.")
		return nil
	}
	defer s.Close()
	stopServiceAndWait(s)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("cannot remove the %s service: %w", winServiceName, err)
	}
	removeTrayLogonEntry()
	removeAuditEventSource()
	fmt.Printf("System service removed: %s is no longer registered.\n", winServiceName)
	fmt.Printf("  The bastion's state under %s is left in place.\n", windowsSystemAppData(os.Getenv("SystemRoot")))
	return nil
}

// programFilesDir is Program Files as HKLM records it (ProgramFilesDir, the
// 64-bit view), which only an administrator can change. Not %ProgramFiles%:
// an elevated process's environment is built with the elevating account's
// own environment variables, which that account can set unelevated, and the
// folder this check trusts must not be one the person's processes can name.
// The installer's elevated script reads the same value (cseries elevated.js).
func programFilesDir() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("ProgramFilesDir")
	return v, err
}

// setTrayLogonEntry writes the machine-wide logon entry that starts the tray
// in every person's session (trayRunKey, trayRunValue). HKLM, so only an
// administrator can change what it runs.
func setTrayLogonEntry(exe string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, trayRunKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(trayRunName, trayRunValue(exe))
}

func removeTrayLogonEntry() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, trayRunKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(trayRunName)
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
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(winServiceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return err
	}
	state := map[uint32]string{
		windows.SERVICE_STOPPED:          "stopped",
		windows.SERVICE_START_PENDING:    "starting",
		windows.SERVICE_STOP_PENDING:     "stopping",
		windows.SERVICE_RUNNING:          "running",
		windows.SERVICE_CONTINUE_PENDING: "resuming",
		windows.SERVICE_PAUSE_PENDING:    "pausing",
		windows.SERVICE_PAUSED:           "paused",
	}[st.CurrentState]
	if state == "" {
		state = fmt.Sprintf("state %d", st.CurrentState)
	}
	if st.ProcessId != 0 {
		fmt.Printf("System service %s: %s (pid %d).\n", winServiceName, state, st.ProcessId)
	} else {
		fmt.Printf("System service %s: %s.\n", winServiceName, state)
	}
	return nil
}
