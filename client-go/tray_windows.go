//go:build windows

package main

// tray_windows.go — the icon in the notification area, which is the only part of
// this UI that answers "is it running" without anyone opening anything.
//
// WHY WINDOWS ONLY, AND WHY THAT IS NOT ARBITRARY. deploy/publish.sh builds all
// six targets in ONE alpine container at CGO_ENABLED=0, which is what makes the
// bastion a static binary with no runtime dependencies. Measured with
// fyne.io/systray v1.12.2 against every one of those targets:
//
//	windows/amd64  OK      windows/arm64  OK
//	linux/amd64    OK      linux/arm64    OK      (pure-Go D-Bus/AppIndicator)
//	darwin/amd64   FAIL    darwin/arm64   FAIL    (undefined: nativeLoop — Cocoa, cgo)
//
// So an untagged import would break half the release. Behind //go:build windows
// the darwin files are never compiled and the build is unchanged.
//
// Linux is left out on purpose rather than because it cannot: those boxes are
// headless servers running under systemd, where `systemctl status` already
// answers liveness and there is no notification area to put an icon in. macOS
// would need cgo and gets the web UI plus a launchd agent instead. If a desktop
// Linux user ever needs this, the tag is the only thing in the way.
//
// THREADING, which is the part that silently does not work if you get it wrong.
// A Windows tray icon belongs to a window, a window belongs to the thread that
// created it, and GetMessage only ever returns messages for its OWN thread.
// systray.Register calls CreateWindowEx synchronously on the calling goroutine
// (systray_windows.go:442) and systray.Run then pumps on that same goroutine —
// so Run must be called from a goroutine pinned to one OS thread. The package's
// init() locks the MAIN goroutine, which is right if you call Run from main();
// this daemon cannot, because cmdRun owns main. So this file locks its own.
// RunWithExternalLoop is the trap: its start func pumps on a fresh, unlocked
// goroutine, which is a different thread from the one holding the window.

import (
	"context"
	"embed"
	"runtime"
	"time"

	"fyne.io/systray"
)

//go:embed uiassets/tray-ok.ico uiassets/tray-warn.ico uiassets/tray-bad.ico
var trayIconFS embed.FS

func trayIcon(class string) []byte {
	b, err := trayIconFS.ReadFile("uiassets/tray-" + class + ".ico")
	if err != nil {
		return nil
	}
	return b
}

// startTray puts the icon up and keeps it current until ctx is done.
//
// Every failure here is non-fatal and silent-but-logged by design: a machine
// with no interactive session (a task started before logon, a locked-down
// desktop policy) must still serve its hosts. The tray is how you SEE the
// bastion, never how it runs.
func startTray(ctx context.Context) {
	// A service runs in a session with no desktop, so there is nowhere to put
	// an icon, and the approval notifier the tray starts would have no one to
	// show. Beside a service, the signed-in person's icon is the `tray` verb,
	// started at their logon (tray_pipe_windows.go). trayFor (tray.go) is the
	// whole rule; the first test is kept literal for TestServiceModeOpensNothingOnTheDesktop.
	if runningAsService {
		return
	}
	if trayFor(runtime.GOOS, runningAsService, systemService.installed, "run") != trayInProcess {
		return
	}
	go func() {
		// See the threading note above — this is the load-bearing line.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		systray.Run(func() { trayReady(ctx) }, func() {})
	}()
	go func() {
		<-ctx.Done()
		systray.Quit()
	}()
}

func trayReady(ctx context.Context) {
	systray.SetIcon(trayIcon("bad"))
	systray.SetTooltip("Privatae bastion")

	mState := systray.AddMenuItem("Checking…", "")
	mState.Disable() // a label, not a control
	// THE APPROVALS LINE, first under the state so a waiting approval is one
	// click from the icon: it opens the approvals popup (uidevice.go), never a
	// menu. Disabled and saying so when nothing is waiting; its words are
	// trayApprovalsLine (tray.go), tested off Windows.
	mApprovals := systray.AddMenuItem(trayApprovalsLine(0), "Open what your hosts are waiting on you for")
	mApprovals.Disable()
	systray.AddSeparator()
	mOpen := systray.AddMenuItem("Open Privatae…", "See what this machine is doing")
	// YOUR CONTEXT, FROM THE TRAY. A person who sees the tray icon expects the
	// way in to be on its menu, and the entry is named for what it serves: not
	// files, but the context built from files — the App determines what becomes
	// context on the network.
	//
	// So the menu says CONTEXT, not files. Files are what you look at; context
	// is what you decide they become, and the deciding is the whole point of
	// the surface. It also shipped as a verb you type, which is the terminal
	// this tray exists to remove — a feature reachable only from a command line
	// does not exist for the person who asked for it.
	mFiles := systray.AddMenuItem("Your context…",
		"Choose what your files become on your network")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Stop the bastion",
		"Stops serving every host on this machine until you start it again")

	// The approvals lane rides THIS poll rather than starting its own.
	//
	// One reason of substance and one of cost. The substance: startApprovalNotifier
	// needs a window station to put an icon on, and trayReady only runs when
	// systray came up, which is the same condition — a machine with no
	// interactive session (a task with a background logon, a locked-down desktop
	// policy) has nobody to notify, so a notifier that ran there would be
	// raising notifications into an empty room. The cost: collectUIStatus probes
	// every pairing with a TCP connect (ui.go:152), and a second poll would
	// double that on a laptop battery for a list this one already has.
	notes := &approvalNotifier{}
	sink := startApprovalNotifier(ctx)

	var last string
	refresh := func() {
		s := collectUIStatus()
		if s.StateClass != last {
			if b := trayIcon(s.StateClass); b != nil {
				systray.SetIcon(b)
			}
			last = s.StateClass
		}
		// SetTooltip is capped at 128 chars on Windows, so this stays one line.
		systray.SetTooltip("Privatae bastion — " + s.State)
		mState.SetTitle(trayStateLine(s))
		// Everything waiting on the person: every pairing's step-up requests
		// (collectUIStatus appends them machine-wide) and the asks waiting on
		// this machine as the approval device — the list the notification's
		// count, and the approvals line, have to be about.
		pending := approvalsForNotice(s)
		mApprovals.SetTitle(trayApprovalsLine(len(pending)))
		if len(pending) > 0 {
			mApprovals.Enable()
		} else {
			mApprovals.Disable()
		}
		notes.poll(time.Now(), pending, sink)
	}
	refresh()

	go func() {
		t := time.NewTicker(trayRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			case <-mApprovals.ClickedCh:
				// Off the menu goroutine for the same reason the notification
				// click is (notify_windows.go): minting the ticket is an HTTP
				// round trip, and this loop is what keeps the icon current.
				go openApprovalsPopup("tray")
			case <-mOpen.ClickedCh:
				openLocalUI("tray")
			case <-mFiles.ClickedCh:
				openContextSurface("tray")
			case <-mQuit.ClickedCh:
				// Not systray.Quit() alone — that would take the icon away and
				// leave the daemon serving invisibly, which is the exact state
				// this whole UI exists to end.
				requestShutdown()
				return
			}
		}
	}()
}
