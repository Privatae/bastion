//go:build windows

package main

import (
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows facts for the origin walk: exe and parent from one Toolhelp
// snapshot, the session from ProcessIdToSessionId. Session 0 is where
// services and scheduled tasks live; a non-zero session is a logged-in
// desktop. Scheduled tasks are children of the svchost.exe that hosts the
// Schedule service, whose pid is looked up once per cache window, so a
// generic svchost parent is recognised as THE scheduler rather than guessed.
//
// Not done yet: telling an RDP session from a console one. Both read
// as `interactive` here; it is later work.

func procFactsReader() func(int) (procFacts, bool) {
	var facts map[int]procFacts
	return func(pid int) (procFacts, bool) {
		if facts == nil {
			facts = winProcFacts()
		}
		f, ok := facts[pid]
		return f, ok
	}
}

func winProcFacts() map[int]procFacts {
	out := map[int]procFacts{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		pid := int(e.ProcessID)
		if pid <= 0 {
			continue
		}
		exe := windows.UTF16ToString(e.ExeFile[:])
		f := procFacts{PID: pid, PPID: int(e.ParentProcessID), Comm: binBase(exe), Exe: exe}
		var sess uint32
		if windows.ProcessIdToSessionId(uint32(pid), &sess) == nil && sess > 0 {
			f.Interactive, f.Detail = true, "session "+strconv.Itoa(int(sess))
		}
		out[pid] = f
	}
	return out
}

// The Schedule service's host pid. One PowerShell CIM query as a fixed
// -EncodedCommand (no quoting through the Win32 command line), cached; an
// empty answer (no PowerShell, service stopped) means no scheduler pid and
// tasks fall through to `service` (session 0 under services.exe), which is
// still true.
var schedSvcCache = struct {
	sync.Mutex
	at  time.Time
	pid int
}{}

func scheduleServicePID() int {
	schedSvcCache.Lock()
	defer schedSvcCache.Unlock()
	if !schedSvcCache.at.IsZero() && time.Since(schedSvcCache.at) < schedCacheFor {
		return schedSvcCache.pid
	}
	pid := 0
	if out, err := runTimed("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", windowsScheduleSvcEncoded); err == nil {
		pid, _ = strconv.Atoi(strings.TrimSpace(string(out)))
	}
	schedSvcCache.at, schedSvcCache.pid = time.Now(), pid
	return pid
}

func originExtras() originExtra {
	ex := originExtra{SchedulerPIDs: map[int]bool{}}
	if pid := scheduleServicePID(); pid > 0 {
		ex.SchedulerPIDs[pid] = true
	}
	return ex
}

const windowsScheduleSvcScript = `(Get-CimInstance Win32_Service -Filter "Name='Schedule'").ProcessId`

var windowsScheduleSvcEncoded = encodePowerShell(windowsScheduleSvcScript)
