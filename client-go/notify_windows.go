//go:build windows

package main

// notify_windows.go — the Win32 half of notify.go: a notification the user
// cannot miss, and a dialog for the refusal that today goes to a console that
// does not exist.
//
// ── WHY THIS CALLS shell32 DIRECTLY, AND WHAT WAS REJECTED ──────────────────
//
// fyne.io/systray v1.12.2 is already in this binary and already owns a
// notification-area icon, so the first thing tried was to raise the balloon
// through THAT icon. It cannot be done. Read in the source of
// fyne.io/systray@v1.12.2:
//
//   - The package exposes no balloon API at all. Its NOTIFYICONDATAW
//     transcription carries szInfo/szInfoTitle/dwInfoFlags/hBalloonIcon
//     (systray_windows.go:116-129) and NOTHING in the package ever sets them —
//     `NIF_INFO` appears nowhere in the tree.
//   - Its window handle and icon id are unexported (`wt` at
//     systray_windows.go:293, `t.nid` built at systray_windows.go:471-478), so
//     there is no supported way to address the icon we already own. Reaching it
//     by FindWindow on its class name, or by go:linkname, would bind this
//     feature to another package's private details and break silently on any
//     upgrade — a notification that stops appearing is invisible by definition.
//   - Even if the balloon were raised on that icon, it could not be CLICKED:
//     systray's wndProc switches its callback message on WM_LBUTTONUP and
//     WM_RBUTTONUP only (systray_windows.go:327-334), so NIN_BALLOONUSERCLICK
//     falls through and nothing happens. The whole point is a notification that
//     takes you to the page.
//
// So this file owns its own hidden window and its own notification icon. Also
// rejected, and why:
//
//   - A toast through WinRT / an AppUserModelID (or a library like go-toast,
//     which shells out to powershell.exe). It needs a registered Start Menu
//     shortcut to have an identity, costs a process spawn per notification, and
//     powershell.exe is exactly what console_windows.go exists to stop flashing
//     windows at the user. It would also be a new dependency that has to be
//     shown cgo-free on all six release targets.
//   - MessageBoxW for approvals as well. It is right for the second-instance
//     refusal below, where the process is exiting anyway and there is one thing
//     to say. As a consent prompt it is wrong: it steals keyboard focus from
//     whatever the user is typing, every time a host asks for a folder, and a
//     stray Enter dismisses it. A notification is the right shape here.
//
// THE COST, stated plainly: while a request is waiting there are TWO Privatae
// icons in the notification area — systray's, which says whether the bastion is
// running, and this one, which says something is waiting on you. It is added
// when the first request appears and deleted when the last one is answered, so
// the steady state is unchanged. A user seeing a second icon appear at the same
// moment a notification arrives reads it as part of the same event.
//
// FAILURE IS ALWAYS SILENT-BUT-LOGGED, and that is deliberate: every failure
// path here degrades to exactly today's behaviour, which is the page. A machine
// with no interactive window station (see deploy/install.ps1 on why the logon
// task is LogonType Interactive) has nobody to notify in the first place.
//
// ── THREADING ───────────────────────────────────────────────────────────────
//
// Same rule as the tray, for the same reason (tray_windows.go:26-35): a window
// belongs to the thread that created it and GetMessage only ever returns
// messages for its OWN thread. So the window is created and pumped on a
// goroutine pinned with runtime.LockOSThread. Shell_NotifyIcon itself is not
// thread-affine and is called from the tray's refresh goroutine — which is what
// systray does too (SetIcon at systray_windows.go:988 calls Shell_NotifyIcon
// from whatever goroutine calls it).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Every constant below was read out of mingw-w64's shellapi.h and winuser.h
// rather than remembered, because a wrong flag here does not fail to
// compile — it fails to notify, which looks identical to working.
const (
	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010

	niifInfo = 0x00000001

	wmUser               = 0x0400
	wmDestroy            = 0x0002
	wmClose              = 0x0010
	wmLButtonUp          = 0x0202
	ninBalloonUserClick  = wmUser + 5
	notifyCallbackMsg    = wmUser + 1
	notifyIconID         = 1
	notifyWindowClass    = "PrivataeBastionNotify"
	notifyTaskbarCreated = "TaskbarCreated"

	swHide             = 0
	cwUseDefault       = 0x80000000
	csHRedraw          = 0x0002
	csVRedraw          = 0x0001
	wsOverlappedWindow = 0x00CF0000 // WS_OVERLAPPED|CAPTION|SYSMENU|THICKFRAME|MINIMIZEBOX|MAXIMIZEBOX

	imageIcon      = 1
	lrLoadFromFile = 0x0010
	lrDefaultSize  = 0x0040
)

var (
	modShell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellNotifyIcon = modShell32.NewProc("Shell_NotifyIconW")

	// modUser32 is computer_windows.go:111 — one LazyDLL per library in this
	// package, not one per file.
	procRegisterClassExW       = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW        = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW         = modUser32.NewProc("DefWindowProcW")
	procDestroyWindow          = modUser32.NewProc("DestroyWindow")
	procGetMessageW            = modUser32.NewProc("GetMessageW")
	procTranslateMessage       = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW       = modUser32.NewProc("DispatchMessageW")
	procPostMessageW           = modUser32.NewProc("PostMessageW")
	procPostQuitMessage        = modUser32.NewProc("PostQuitMessage")
	procRegisterWindowMessageW = modUser32.NewProc("RegisterWindowMessageW")
	procLoadImageW             = modUser32.NewProc("LoadImageW")
	procShowWindow             = modUser32.NewProc("ShowWindow")
)

// winNotifyIconData is NOTIFYICONDATAW.
//
// Transcribed field-for-field from mingw-w64's shellapi.h and checked against
// fyne.io/systray's copy of the same struct (systray_windows.go:116-129), which
// is the one version of this that is known to work on real machines. Getting
// Size or a field width wrong here does not fail to build: Shell_NotifyIcon
// simply returns FALSE and no notification ever appears.
type winNotifyIconData struct {
	Size                       uint32
	Wnd                        windows.Handle
	ID, Flags, CallbackMessage uint32
	Icon                       windows.Handle
	Tip                        [128]uint16
	State, StateMask           uint32
	Info                       [256]uint16
	Timeout, Version           uint32
	InfoTitle                  [64]uint16
	InfoFlags                  uint32
	GuidItem                   windows.GUID
	BalloonIcon                windows.Handle
}

// winWndClassEx is WNDCLASSEXW (systray_windows.go:75-83).
type winWndClassEx struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background windows.Handle
	MenuName, ClassName                *uint16
	IconSm                             windows.Handle
}

// winMsg is MSG. mingw-w64's winuser.h has exactly these six members on every
// non-_MAC target, so it is 48 bytes on both amd64 and arm64 — and it MUST be,
// because GetMessageW writes into it.
type winMsg struct {
	Wnd     uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

// ONE callback for the life of the process. computer_windows.go:119-126 carries
// the measurement: the Go runtime keeps every distinct func value handed to
// syscall.NewCallback in a fixed 2000-slot table and never frees a slot, so a
// callback built per notification would eventually kill the daemon.
var notifyWndProcCB = syscall.NewCallback(notifyWndProc)

// approvalNotify is the process's one notification icon.
var approvalNotify = &winNotifier{}

type winNotifier struct {
	mu    sync.Mutex
	hwnd  uintptr
	icon  windows.Handle
	added bool
	tip   string

	// taskbarCreated is the broadcast explorer.exe sends when it restarts, at
	// which point every notification-area icon in the system is gone and has to
	// be added again. systray handles the same message the same way
	// (systray_windows.go:336-339). Written before the window exists and read
	// only on the window's own thread.
	taskbarCreated uint32
}

// startApprovalNotifier brings the hidden window up and returns the sink the
// tray's poll writes to. It returns even when the window could not be created —
// the sink is then inert, which is today's behaviour, not a new failure.
func startApprovalNotifier(ctx context.Context) approvalSink {
	ready := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := approvalNotify.create(); err != nil {
			uilogf("notify: no notification icon (%v) — approvals still show on the page\n", err)
			close(ready)
			return
		}
		close(ready)
		approvalNotify.pump()
	}()
	go func() {
		<-ctx.Done()
		approvalNotify.stop()
	}()
	// Wait for the window before the first poll can call show(), so the FIRST
	// request of a session is announced rather than dropped into a nil handle.
	<-ready
	return approvalNotify
}

func (w *winNotifier) create() error {
	var inst windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &inst); err != nil {
		return fmt.Errorf("GetModuleHandleEx: %w", err)
	}
	classPtr, err := windows.UTF16PtrFromString(notifyWindowClass)
	if err != nil {
		return err
	}
	namePtr, err := windows.UTF16PtrFromString("")
	if err != nil {
		return err
	}
	taskbarPtr, err := windows.UTF16PtrFromString(notifyTaskbarCreated)
	if err != nil {
		return err
	}
	// Registered BEFORE the window exists, so the wndProc can never see the
	// broadcast while the field it compares against is still zero.
	r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(taskbarPtr)))
	w.taskbarCreated = uint32(r)

	// No class icon, cursor or background: this window is created hidden and is
	// never painted. Each of those is a call that can fail, and none of them can
	// affect anything the user sees.
	wc := winWndClassEx{
		Style:     csHRedraw | csVRedraw,
		WndProc:   notifyWndProcCB,
		Instance:  inst,
		ClassName: classPtr,
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassExW: %w", err)
	}

	hwnd, _, err := procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(classPtr)), uintptr(unsafe.Pointer(namePtr)),
		wsOverlappedWindow, cwUseDefault, cwUseDefault, cwUseDefault, cwUseDefault,
		0, 0, uintptr(inst), 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW: %w", err)
	}
	// A top-level window rather than a message-only one (HWND_MESSAGE), because
	// message-only windows do not receive broadcasts and TaskbarCreated is a
	// broadcast. Hidden immediately; it is never shown.
	procShowWindow.Call(hwnd, swHide)

	icon, err := loadNotifyIcon()
	if err != nil {
		procDestroyWindow.Call(hwnd)
		return err
	}
	w.mu.Lock()
	w.hwnd, w.icon = hwnd, icon
	w.mu.Unlock()
	return nil
}

// loadNotifyIcon gives the notification icon the SAME picture the tray uses for
// "something needs you", so the two icons read as one program.
//
// LoadImageW has no byte-array entry point, so the embedded .ico has to be on
// disk. It goes in the bastion's own config directory rather than %TEMP%: that
// directory is per-user, already created by configDir (config.go:137-143), and
// ours — a fixed name in a shared temp directory is a file another program can
// be holding open.
func loadNotifyIcon() (windows.Handle, error) {
	b := trayIcon("warn")
	if b == nil {
		return 0, errors.New("the warn tray icon is not embedded")
	}
	d, err := configDir()
	if err != nil {
		return 0, err
	}
	p := filepath.Join(d, "notify.ico")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}
	// Same flags systray loads its icon with (systray_windows.go:815-823), so
	// this icon is sized exactly as the tray's is.
	h, _, err := procLoadImageW.Call(0, uintptr(unsafe.Pointer(ptr)),
		imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize)
	if h == 0 {
		return 0, fmt.Errorf("LoadImageW %s: %w", p, err)
	}
	return windows.Handle(h), nil
}

func (w *winNotifier) pump() {
	var msg winMsg
	for {
		// GetMessage returns 0 for WM_QUIT and -1 for an error; anything else is
		// a message. The signed conversion is load-bearing — the raw uintptr for
		// -1 is the largest possible value.
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// stop takes the icon down and ends the pump. Deleting the icon explicitly
// matters: an icon whose owning process has gone stays drawn in the notification
// area until someone moves a mouse over it, which is a picture of a running
// bastion that is not running.
func (w *winNotifier) stop() {
	w.hide()
	w.mu.Lock()
	hwnd := w.hwnd
	w.mu.Unlock()
	if hwnd != 0 {
		procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}
}

func notifyWndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	// Tested before the switch, and the non-zero test is not decoration:
	// RegisterWindowMessage returns 0 on failure, and a zero case here would
	// then match WM_NULL and re-add the icon on a message the system sends for
	// other reasons entirely.
	if tc := approvalNotify.taskbarCreated; tc != 0 && msg == tc {
		// explorer.exe restarted and took every icon with it. Ours goes back
		// only if it was up — a re-add after the user answered everything would
		// be an icon claiming work that is done.
		approvalNotify.readd()
		return 0
	}
	switch msg {
	case notifyCallbackMsg:
		// The icon is left at the default NOTIFYICON_VERSION, so lParam is the
		// plain message id — the same thing systray relies on
		// (systray_windows.go:330-334). Both events are handled: the balloon
		// click is the one this feature is for, and a left click on the icon is
		// what someone does when the balloon has already timed out.
		switch lparam {
		case ninBalloonUserClick, wmLButtonUp:
			// NOT on this thread. localUIEntryURL does an HTTP round trip with a
			// 5 s timeout (ui.go:612), and this goroutine is the message pump —
			// blocking it would stall the icon and every balloon after it.
			// Straight to the approvals popup (uidevice.go): the notification is
			// about something waiting, and the page that answers it is the one
			// place a click here should land — not the front page's menu.
			go approvalsOpener("notify")
		}
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wparam, lparam)
	return r
}

// ── the approvalSink half (notify.go decides WHEN; this does it) ────────────

func (w *winNotifier) show(tip string, notice *uiNotice) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hwnd == 0 {
		return
	}
	if !w.added {
		if !w.addLocked(tip) {
			return
		}
	} else if tip != w.tip {
		nid := w.newData(nifTip)
		putUTF16(nid.Tip[:], tip)
		if w.send(nimModify, nid) {
			w.tip = tip
		}
	}
	if notice == nil {
		return
	}
	nid := w.newData(nifInfo)
	putUTF16(nid.Info[:], notice.Body)
	putUTF16(nid.InfoTitle[:], notice.Title)
	nid.InfoFlags = niifInfo
	if !w.send(nimModify, nid) {
		uilogf("notify: could not raise the notification for %q\n", notice.Title)
	}
}

func (w *winNotifier) hide() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.added {
		return
	}
	w.send(nimDelete, w.newData(0))
	w.added, w.tip = false, ""
}

// readd is the explorer-restart path. It runs on the window thread while show()
// may be running on the tray's, so it takes the same lock.
func (w *winNotifier) readd() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hwnd == 0 || !w.added {
		return
	}
	w.added = false
	w.addLocked(w.tip)
}

func (w *winNotifier) addLocked(tip string) bool {
	nid := w.newData(nifMessage | nifIcon | nifTip)
	putUTF16(nid.Tip[:], tip)
	if !w.send(nimAdd, nid) {
		uilogf("notify: could not add the waiting icon\n")
		return false
	}
	w.added, w.tip = true, tip
	return true
}

func (w *winNotifier) newData(flags uint32) *winNotifyIconData {
	nid := &winNotifyIconData{
		Wnd:             windows.Handle(w.hwnd),
		ID:              notifyIconID,
		Flags:           flags,
		CallbackMessage: notifyCallbackMsg,
		Icon:            w.icon,
	}
	nid.Size = uint32(unsafe.Sizeof(*nid))
	return nid
}

func (w *winNotifier) send(op uint32, nid *winNotifyIconData) bool {
	r, _, _ := procShellNotifyIcon.Call(uintptr(op), uintptr(unsafe.Pointer(nid)))
	return r != 0
}

// ── the blocking dialog ─────────────────────────────────────────────────────

// showBlockingNotice puts a message on the screen and waits for the person to
// dismiss it.
//
// It BLOCKS on purpose, and the caller (runguard_windows.go) is a process that
// is about to exit either way. The whole defect being fixed is a message written
// to a stream nobody is reading; a dialog that closed itself before it was read
// would be the same defect with extra steps.
//
// MB_SETFOREGROUND|MB_TOPMOST because the case this exists for is a second
// bastion started by double-clicking the exe while something else is in front.
// MB_ICONINFORMATION, not an error icon: the machine is fine, the first copy is
// still serving, and the words say so.
func showBlockingNotice(n uiNotice) {
	// In a service a dialog would open on a desktop nobody sees and wait there
	// for ever. The words still reach the log through the error it goes with.
	if runningAsService {
		return
	}
	title, err := windows.UTF16PtrFromString(n.Title)
	if err != nil {
		return
	}
	body, err := windows.UTF16PtrFromString(n.Body)
	if err != nil {
		return
	}
	_, _ = windows.MessageBox(0, body, title,
		windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_SETFOREGROUND|windows.MB_TOPMOST)
}
