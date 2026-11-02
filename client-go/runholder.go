package main

// runholder.go — what a second start on Windows is told about the first.
//
// A bastion that finds its run lock held (runguard_windows.go) used to say
// only that one was running, and that if it seemed dead it could be ended in
// Task Manager. On a machine where `privatae-bastion ui` then failed, that
// was the one thing to try, so a running bastion was killed for a symptom
// that was not its. The bastion that holds the lock now writes who it is
// beside it, and the refusal names it: its process, its program, how it was
// started, and the commands that open, check and restart it.
//
// And the relaunch after a self-update (relaunch_windows.go) starts the new
// binary while the old one still holds the lock, a few milliseconds from
// exiting. The new one waits for it (takeRunLock) rather than refusing and
// leaving the machine with no bastion at all.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type runHolder struct {
	PID     int    `json:"pid"`
	Program string `json:"program,omitempty"`
	Started string `json:"started,omitempty"` // RFC3339
	Service bool   `json:"service,omitempty"` // the Windows service
	Console bool   `json:"console,omitempty"` // started from a terminal
}

func runHolderPath(dir string) string { return filepath.Join(dir, "run.holder.json") }

// writeRunHolder records this process as the lock's holder. Best effort: a
// refusal without it is only less specific.
func writeRunHolder(dir string, console bool) {
	h := runHolder{PID: os.Getpid(), Started: time.Now().UTC().Format(time.RFC3339),
		Service: runningAsService, Console: console}
	if exe, err := os.Executable(); err == nil {
		h.Program = exe
	}
	if raw, err := json.Marshal(h); err == nil {
		_ = atomicWrite(runHolderPath(dir), raw)
	}
}

func readRunHolder(dir string) (runHolder, bool) {
	var h runHolder
	raw, err := os.ReadFile(runHolderPath(dir))
	if err != nil || json.Unmarshal(raw, &h) != nil || h.PID <= 0 {
		return runHolder{}, false
	}
	return h, true
}

// secondRunWords is the refusal of a second start, for the terminal and for
// the dialog a start with no console shows. known is false
// when the running bastion left no record (an older version holds the lock).
func secondRunWords(h runHolder, known bool) (console string, dialog uiNotice) {
	what := "A bastion is already running on this machine"
	restart := "Get-Process privatae-bastion | Format-List Id, Path, StartTime shows it; " +
		"Stop-Process -Id <its Id>, then Start-ScheduledTask -TaskName " + winServiceName
	if known {
		how := "in the background (its sign-in task, or itself after an update)"
		switch {
		case h.Service:
			how = "as the " + winServiceName + " service"
		case h.Console:
			how = "from a terminal"
		}
		what += " (process " + strconv.Itoa(h.PID)
		if h.Program != "" {
			what += ", " + h.Program
		}
		if t, err := time.Parse(time.RFC3339, h.Started); err == nil {
			what += ", started " + t.Local().Format("2 Jan 15:04")
		}
		what += ", " + how + ")"
		switch {
		case h.Service:
			restart = "Restart-Service " + winServiceName + "   (from an Administrator terminal)"
		default:
			restart = "Stop-Process -Id " + strconv.Itoa(h.PID) + ", then start it again: Start-ScheduledTask -TaskName " +
				winServiceName + " (or privatae-bastion run)"
		}
	}
	console = fmt.Sprintf("%s.\n"+
		"  It is the one serving your Hosts, and a second copy would fight it for the same local ports,\n"+
		"  so this one is stopping. Nothing is wrong, and nothing needs ending.\n"+
		"  To open it:     privatae-bastion ui\n"+
		"  To check it:    privatae-bastion status\n"+
		"  To restart it:  %s", what, restart)
	dialog = uiNotice{
		Title: "Privatae bastion is already running",
		Body: what + ".\r\n\r\n" +
			"It is the one serving your Hosts. A second copy would fight it for the same local ports, so this one " +
			"is stopping. Nothing is wrong, and nothing needs ending.\r\n\r\n" +
			"To open it, run: privatae-bastion ui\r\n" +
			"To restart it: " + restart,
	}
	return console, dialog
}

// relaunchOfEnv names, in the environment of a bastion started by its
// predecessor's self-update, the predecessor's process id.
const relaunchOfEnv = "PRIVATAE_BASTION_RELAUNCH_OF"

// takeRunLock takes the run lock with try. A bastion relaunched by its
// predecessor (replaces > 0) first waits up to patience for that process to
// exit (waitExit), then tries again until patience has passed: the lock is
// released as the predecessor's handles close, a moment after it exits.
func takeRunLock(try func() error, replaces int, waitExit func(pid int, d time.Duration), patience time.Duration,
	now func() time.Time, sleep func(time.Duration)) error {
	if replaces <= 0 {
		return try()
	}
	deadline := now().Add(patience)
	waitExit(replaces, patience)
	for {
		err := try()
		if err == nil || !now().Before(deadline) {
			return err
		}
		sleep(200 * time.Millisecond)
	}
}

// relaunchOf reads relaunchOfEnv once and clears it, so nothing this process
// starts inherits it.
func relaunchOf() int {
	v := os.Getenv(relaunchOfEnv)
	_ = os.Unsetenv(relaunchOfEnv)
	pid, err := strconv.Atoi(v)
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}
