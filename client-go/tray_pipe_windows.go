//go:build windows

package main

// tray_pipe_windows.go — `privatae-bastion tray`: the signed-in person's icon
// beside a bastion that runs as the machine's service.
//
// The service runs in session 0 and has no desktop (tray_windows.go), so the
// icon is a separate process: this verb, started at every sign-in by the
// machine-wide logon entry `service install` writes (tray.go trayRunValue),
// running as whoever signed in, unelevated. It holds nothing of the
// service's: it asks over the approvals pipe (approvalpipe_windows.go) what is
// waiting, shows it, and sends the person's code for one request. The secret
// the code is checked against stays in the service.
//
// ONE PER SESSION. The logon entry and `npx cseries` may both start it; a
// session-local mutex makes the second one exit at once.
//
// THE CONSOLE. The bastion is one console program for the command line, the
// service and this, so Windows gives a process started from the logon entry a
// console window of its own. The tray lets go of it at once when it is the
// only process on it (started that way, not from a terminal); the window may
// show for a moment at sign-in.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"time"
	"unsafe"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
)

var (
	modKernel32Tray           = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = modKernel32Tray.NewProc("GetConsoleProcessList")
	procFreeConsole           = modKernel32Tray.NewProc("FreeConsole")
)

// letGoOfOwnConsole frees a console that only this process is on.
func letGoOfOwnConsole() {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	if n == 1 {
		procFreeConsole.Call()
	}
}

func cmdTray() error {
	if trayFor(runtime.GOOS, runningAsService, systemService.installed, "tray") != trayPipe {
		return errors.New("this machine's bastion is not a system service, so it has no separate tray: " +
			"its icon shows while `privatae-bastion run` runs")
	}
	name, err := windows.UTF16PtrFromString(`Local\PrivataeBastionTray`)
	if err != nil {
		return err
	}
	m, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if m != 0 {
			_ = windows.CloseHandle(m)
		}
		return nil // a tray already runs in this session
	}
	if err != nil {
		return fmt.Errorf("cannot start the tray: %w", err)
	}
	defer windows.CloseHandle(m)
	letGoOfOwnConsole()

	page, err := startTrayPage()
	if err != nil {
		return err
	}
	defer page.close()
	approvalsOpener = page.open
	// systray's own init locked the main goroutine to the main thread, and
	// main runs this verb on it, so Run is called right here (tray_windows.go
	// explains why that matters).
	systray.Run(func() { trayPipeReady(page) }, func() {})
	return nil
}

// trayPage is the tray's approvals window (uitray.go), served on loopback by
// this process.
type trayPage struct {
	srv  *uiServer
	addr string
	h    *http.Server
}

func startTrayPage() (*trayPage, error) {
	// LOOPBACK ONLY, any free port: the page draws what a Host asks of this
	// machine, and nothing off it has any business reading that.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("the tray cannot open its approvals window: %w", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	secret, err := genSecret(32)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	srv, err := newUIServer(port, secret)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	srv.trayPipe = true
	srv.pipe = pipeCall
	h := &http.Server{Handler: srv.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = h.Serve(ln) }()
	return &trayPage{srv: srv, addr: ln.Addr().String(), h: h}, nil
}

// open shows the approvals window, signed in by a ticket minted in-process.
func (p *trayPage) open(from string) {
	tok, err := p.srv.tickets.mint()
	if err != nil {
		uilogf("%s: %v\n", from, err)
		return
	}
	if err := openPopupWindow("http://" + p.addr + "/?k=" + tok); err != nil {
		uilogf("%s: %v\n", from, err)
	}
}

func (p *trayPage) close() {
	sh, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = p.h.Shutdown(sh)
}

func trayPipeReady(page *trayPage) {
	systray.SetIcon(trayIcon("bad"))
	systray.SetTooltip("Privatae bastion")
	mState := systray.AddMenuItem("Checking…", "")
	mState.Disable()
	mApprovals := systray.AddMenuItem(trayApprovalsLine(0), "Open what your hosts are waiting on you for")
	mApprovals.Disable()
	systray.AddSeparator()
	// NOT "Stop the bastion": the bastion is the machine's service, and it is
	// whoever administers the machine who stops it. This closes the icon only.
	mQuit := systray.AddMenuItem("Close this icon",
		"The bastion keeps running as this machine's service; the icon comes back at your next sign-in")

	ctx, cancel := context.WithCancel(context.Background())
	notes := &approvalNotifier{}
	sink := startApprovalNotifier(ctx)
	var last string
	refresh := func() {
		s := trayPipeStatus(pipeCall)
		if s.StateClass != last {
			if b := trayIcon(s.StateClass); b != nil {
				systray.SetIcon(b)
			}
			last = s.StateClass
		}
		line := trayStateLineFrom(s)
		systray.SetTooltip(clipUTF16("Privatae bastion — "+line, 127))
		mState.SetTitle(line)
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
			case <-t.C:
				refresh()
			case <-mApprovals.ClickedCh:
				go page.open("tray")
			case <-mQuit.ClickedCh:
				cancel()
				systray.Quit()
				return
			}
		}
	}()
}
