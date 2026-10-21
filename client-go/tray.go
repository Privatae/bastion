package main

// tray.go — the parts of the tray that are not Windows.
//
// The systray plumbing has to live behind //go:build windows (tray_windows.go
// explains why in full: the library needs cgo on darwin, which would end the
// single-container CGO_ENABLED=0 build for all six release targets). But the
// SHUTDOWN channel and the menu's wording are ordinary logic, and logic behind a
// build tag is logic that is never tested, because the suite runs on Linux.

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// trayRefresh is how often the icon re-reads the machine's state. The heartbeat
// is 60s and the liveness probe is a 400ms TCP connect per pairing, so five
// seconds is responsive without being a busy loop on a laptop battery.
//
// It lives HERE, untagged, rather than beside the systray plumbing, because it
// is also the rate at which an approval notification decides whether to fire —
// and the rules in notify.go are stated in ticks of this. A cadence the test
// suite cannot see is a cadence the rules cannot be tested against.
const trayRefresh = 5 * time.Second

// shutdownCh is closed when the user asks the daemon to stop from somewhere
// other than a signal — today, "Stop the bastion" in the tray menu. It exists on
// every platform so cmdRun's select needs no build tag; off Windows nothing
// closes it and that case is simply never chosen.
var (
	shutdownOnce sync.Once
	shutdownCh   = make(chan struct{})
)

// requestShutdown asks cmdRun to stop, exactly as Ctrl-C or SIGTERM does. Once
// only — closing a closed channel panics, and a menu item can be clicked twice.
func requestShutdown() { shutdownOnce.Do(func() { close(shutdownCh) }) }

// openLocalUI is what every "take me to the page" affordance does: the tray's
// menu item, and a click on an approval notification (notify_windows.go).
//
// One function because they must behave identically — both mint a one-use ticket
// against the RUNNING daemon through localUIEntryURL (ui.go:591) rather than
// building a URL, so neither can drift into handing out a link that does not
// authenticate. `from` only names the caller in the log line.
//
// It is untagged so that a build off Windows still compiles it; nothing off
// Windows calls it today.
func openLocalUI(from string) {
	entry, _, err := localUIEntryURL()
	if err != nil {
		uilogf("%s: %v\n", from, err)
		return
	}
	if err := openBrowser(entry); err != nil {
		uilogf("%s: %v\n", from, err)
	}
}

// trayStateLine is the disabled label at the top of the tray menu: the one
// sentence a person wants when they click the icon.
//
// "Not anchored" outranks the count on purpose. A networked box with no anchor
// serves NOTHING (anchor.go), so reporting "Serving 3 hosts" there would be
// true about pairings and a lie about the machine — and it is the exact state
// that is otherwise invisible until some op fails far away.
func trayStateLine(s uiStatus) string {
	switch {
	case len(s.Pairings) == 0:
		return "No host paired yet"
	case s.AnchorRequired:
		return "Not anchored — answering nothing"
	default:
		n := 0
		for _, p := range s.Pairings {
			if p.Listening {
				n++
			}
		}
		if n == len(s.Pairings) {
			return fmt.Sprintf("Serving %d host(s)", n)
		}
		return fmt.Sprintf("Serving %d of %d hosts", n, len(s.Pairings))
	}
}

// openContextSurface starts the context surface and opens it (contextui.go).
//
// A SEPARATE PROCESS, DELIBERATELY, even though the tray is already running as
// this person. contextui.go's whole security argument is that the walk is done by a
// process running as the user, so the only files it can draw are the ones the
// kernel already lets them open. Serving it from inside the daemon would work
// on a one-person Windows desktop and would be wrong everywhere else — on a
// networked box that daemon is root, and the same code would then be rendering
// somebody's files under an authority they never granted. One path, right on
// both machines.
//
// The child gets no console (hideConsole) and opens the browser itself, so the
// person who clicked a tray item never sees a window they did not ask for.
func openContextSurface(from string) {
	exe, err := os.Executable()
	if err != nil {
		uilogf("%s: %v\n", from, err)
		return
	}
	cmd := exec.Command(exe, "context")
	hideConsole(cmd)
	if err := cmd.Start(); err != nil {
		uilogf("%s: could not start the context surface: %v\n", from, err)
		return
	}
	// NOT Wait(): this runs on the tray's goroutine, and waiting here would
	// freeze the menu for as long as the person had their files open. The child
	// is a server with its own lifetime — it prints its address, opens a
	// browser, and exits when they close it.
	go func() { _ = cmd.Wait() }()
}

// trayKind is which tray, if any, a process puts up.
type trayKind int

const (
	// trayNone: no icon from this process.
	trayNone trayKind = iota
	// trayInProcess: the daemon's own icon (tray_windows.go), for a bastion
	// that runs as the signed-in person.
	trayInProcess
	// trayPipe: the signed-in person's icon beside a system service
	// (tray_pipe_windows.go), which reads the service over the approvals pipe.
	trayPipe
)

// trayFor is THE START RULE, decided here so the suite checks it off Windows.
//
//   - `run` as the service: none. The service runs in session 0, which has no
//     desktop, so an icon there would be on a screen nobody sees.
//   - `run` beside an installed service: none. That is a second bastion the
//     guard refuses for an ordinary account (sysservice.go); an administrator
//     who runs it anyway gets no second icon.
//   - `run` with no service: the daemon's own icon, as before.
//   - `tray` with a service installed, not as the service: the person's icon,
//     over the pipe. This is what the logon entry starts for every person who
//     signs in (trayRunValue).
//   - `tray` with no service: none; the daemon's own icon is the tray there.
//
// Only Windows has a tray at all (tray_windows.go says why).
func trayFor(goos string, asService, serviceInstalled bool, cmd string) trayKind {
	if goos != "windows" || asService {
		return trayNone
	}
	switch cmd {
	case "run":
		if serviceInstalled {
			return trayNone
		}
		return trayInProcess
	case "tray":
		if serviceInstalled {
			return trayPipe
		}
	}
	return trayNone
}

// trayRunKey and trayRunName are the machine-wide logon entry `service install`
// writes: Windows starts it in every person's session at their sign-in, as
// that person and unelevated, which is exactly who the tray must run as.
const (
	trayRunKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	trayRunName = "PrivataeBastionTray"
)

// trayRunValue is that entry's command line: the service's own program, which
// lives under Program Files where only administrators can change it, and the
// tray verb. Quoted, because Program Files has a space in it.
func trayRunValue(exe string) string {
	return `"` + exe + `" tray`
}

// trayApprovalsLine is the tray menu's approvals entry: the count of what is
// waiting on the person, or that nothing is. Untagged so the words are tested
// on the platform the suite runs on.
func trayApprovalsLine(n int) string {
	switch n {
	case 0:
		return "No approvals waiting"
	case 1:
		return "1 approval waiting — open…"
	}
	return fmt.Sprintf("%d approvals waiting — open…", n)
}
