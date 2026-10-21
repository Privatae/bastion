//go:build windows

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows drivers for computer:*.
//
// Inventory: the Uninstall registry keys — HKLM 64-bit, HKLM 32-bit (WOW6432),
// HKCU — the same source "Apps & features" reads. Entries flagged
// SystemComponent, or with no DisplayName, are not applications. DisplayIcon
// usually names the executable, InstallLocation the folder; the first is the
// path when it ends in .exe.
//
// Windows: EnumWindows over visible top-level windows with a title, the owning
// pid from GetWindowThreadProcessId, the app from the process image name, and
// GetForegroundWindow for focus. user32 through the same LazyDLL pattern as
// iphlpapi in agents_windows.go — no new module.

const (
	computerObserveSupported = true
	computerInventoryKind    = "registry-uninstall"
	computerWindowsKind      = "user32-enumwindows"
)

var uninstallKeys = []struct {
	root registry.Key
	path string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
}

func listInstalledApps() ([]computerApp, error) {
	var apps []computerApp
	opened := false
	for _, k := range uninstallKeys {
		key, err := registry.OpenKey(k.root, k.path, registry.READ)
		if err != nil {
			continue
		}
		opened = true
		names, err := key.ReadSubKeyNames(-1)
		key.Close()
		if err != nil {
			continue
		}
		for _, n := range names {
			sub, err := registry.OpenKey(k.root, k.path+`\`+n, registry.READ)
			if err != nil {
				continue
			}
			if a, ok := appFromUninstallKey(sub); ok {
				apps = append(apps, a)
			}
			sub.Close()
		}
	}
	if !opened {
		return nil, errors.New("could not open the Uninstall registry keys")
	}
	return apps, nil
}

func appFromUninstallKey(k registry.Key) (computerApp, bool) {
	name, _, err := k.GetStringValue("DisplayName")
	if err != nil || strings.TrimSpace(name) == "" {
		return computerApp{}, false
	}
	if sc, _, err := k.GetIntegerValue("SystemComponent"); err == nil && sc == 1 {
		return computerApp{}, false
	}
	a := computerApp{Name: name, Source: "registry"}
	a.Version, _, _ = k.GetStringValue("DisplayVersion")
	a.Publisher, _, _ = k.GetStringValue("Publisher")
	a.Path = exePathFromUninstall(k)
	return a, true
}

// exePathFromUninstall picks the program: DisplayIcon when it is an .exe
// (strip a trailing ",0" icon index), else InstallLocation.
func exePathFromUninstall(k registry.Key) string {
	if icon, _, err := k.GetStringValue("DisplayIcon"); err == nil {
		icon = strings.Trim(strings.TrimSpace(icon), `"`)
		if i := strings.LastIndex(icon, ","); i > 0 {
			icon = icon[:i]
		}
		icon = strings.Trim(icon, `"`)
		if strings.EqualFold(filepath.Ext(icon), ".exe") {
			return icon
		}
	}
	if loc, _, err := k.GetStringValue("InstallLocation"); err == nil {
		return strings.Trim(strings.TrimSpace(loc), `"`)
	}
	return ""
}

var (
	modUser32                  = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows            = modUser32.NewProc("EnumWindows")
	procIsWindowVisible        = modUser32.NewProc("IsWindowVisible")
	procGetWindowTextW         = modUser32.NewProc("GetWindowTextW")
	procGetWindowThreadProcess = modUser32.NewProc("GetWindowThreadProcessId")
	procGetForegroundWindow    = modUser32.NewProc("GetForegroundWindow")
)

// ONE callback for the life of the process. The Go runtime registers every
// distinct func value handed to syscall.NewCallback in a fixed table of 2000
// slots and never frees a slot (runtime/syscall_windows.go compileCallback);
// a closure created per call would exhaust it — a host polling the window
// list every 30 s would kill the bastion inside a day. So the callback is a
// package-level function created once, and
// the per-call state lives in winEnum under a mutex: EnumWindows is
// synchronous, so one enumeration at a time is exactly what happens.
var (
	enumWindowsCB = syscall.NewCallback(enumWindowsProc)
	winEnum       struct {
		sync.Mutex
		wins  []computerWindow
		names map[uint32]string
		fg    uintptr
	}
)

func enumWindowsProc(hwnd uintptr, _ uintptr) uintptr {
	if v, _, _ := procIsWindowVisible.Call(hwnd); v == 0 {
		return 1
	}
	var buf [512]uint16
	n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return 1
	}
	title := windows.UTF16ToString(buf[:n])
	var pid uint32
	procGetWindowThreadProcess.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	app, ok := winEnum.names[pid]
	if !ok {
		app = processImageBase(pid)
		winEnum.names[pid] = app
	}
	winEnum.wins = append(winEnum.wins, computerWindow{Title: title, PID: int(pid), App: app,
		Focused: hwnd == winEnum.fg})
	return 1
}

func listWindows() ([]computerWindow, error) {
	winEnum.Lock()
	defer winEnum.Unlock()
	winEnum.wins = nil
	winEnum.names = map[uint32]string{}
	winEnum.fg, _, _ = procGetForegroundWindow.Call()
	r, _, err := procEnumWindows.Call(enumWindowsCB, 0)
	wins := winEnum.wins
	winEnum.wins, winEnum.names = nil, nil
	if r == 0 && len(wins) == 0 {
		return nil, errors.New("EnumWindows failed: " + err.Error())
	}
	return wins, nil
}

// processImageBase is the executable's basename for a pid, "" when the process
// cannot be opened (an elevated window from a non-elevated bastion, for one).
func processImageBase(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var buf [windows.MAX_LONG_PATH]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return filepath.Base(windows.UTF16ToString(buf[:size]))
}
