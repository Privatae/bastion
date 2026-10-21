//go:build windows

package main

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

// hideConsole stops a child process from opening a console window.
//
// THE SYMPTOM: two flashing blue screens, seen again and again. Two, and
// they flash, and they come back — that is the shape of this bug exactly.
// Three Windows paths shell out to powershell.exe:
//
//	schedulers_windows.go:44   Get-ScheduledTask        (the scheduled-job inventory)
//	origin_windows.go:79       Win32_Service 'Schedule' (the scheduler's own pid)
//	computer_tree_windows.go:97 UIAutomation             (on demand, not on the beat)
//
// The first two sit on the heartbeat path and are each cached for
// schedCacheFor = 10 minutes (schedulers.go:435), so they expire together and
// respawn together: TWO windows, every ten minutes, for ever. The third only
// runs when the host asks to read the screen.
//
// WHY IT ONLY STARTED NOW, AND WHY IT IS 0.24.0's DOING. A console child
// INHERITS its parent's console when the parent has one — started from a
// terminal, these three were invisible for as long as they have existed. 0.24.0
// added relaunchAfterUpdate, which restarts the bastion with DETACHED_PROCESS
// (relaunch_windows.go:47) because Windows has no service to do it. A detached
// process has NO console, so there is none to inherit, and Windows allocates a
// fresh one for each child — which is a window, on screen, in front of whatever
// the user was doing. The same commit that made the bastion survive an update
// is what made its shell-outs visible.
//
// CREATE_NO_WINDOW is the correct flag for a child whose output we capture and
// whose input we never supply: it still gets a console object, so PowerShell
// runs normally, but no window is created for it. HideWindow alone would ask
// the child politely to start minimised and PowerShell does not always honour
// it. Both are set because they cost nothing together.
//
// Not applied to relaunchAfterUpdate: that one sets DETACHED_PROCESS already
// and must keep it — it is the flag that lets the replacement outlive us.
func hideConsole(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &windows.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW
}
