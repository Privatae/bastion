//go:build !windows

package main

// The real root-command starter: /bin/sh -c in its own process group, so a
// deadline or the host going away ends every child with it. The daemon is
// already root when this runs (handleRootExec checked), so nothing is
// dropped or raised; the environment is a plain root login's, not the
// daemon's own, so no credential the daemon holds in its environment leaks
// into a command.

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type shellProc struct {
	cmd  *exec.Cmd
	once sync.Once
	wait sync.Once
	code int
}

func startRootExec(command string, stdout, stderr io.Writer, cgroupFD int) (rootExecProc, error) {
	home := "/root"
	if u, err := user.Lookup("root"); err == nil && u.HomeDir != "" {
		home = u.HomeDir
	}
	// A home this process cannot enter is no working folder for the command.
	// The daemon is root here, so that is only a home that is not there; the
	// tests also run this as an ordinary user, for whom /root is shut.
	if st, err := os.Stat(home); err != nil || !st.IsDir() || unix.Access(home, unix.X_OK) != nil {
		home = "/"
	}
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Dir = home
	cmd.Env = []string{
		"HOME=" + home,
		"USER=root",
		"LOGNAME=root",
		"SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if lang := os.Getenv("LANG"); lang != "" {
		cmd.Env = append(cmd.Env, "LANG="+lang)
	}
	cmd.Stdin = nil // /dev/null: nothing reads from the host
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Inside the connection watch's cgroup from the start (rootexec_watch_linux.go).
	rootExecIntoCgroup(cmd.SysProcAttr, cgroupFD)
	// A child left in the background holding the output open must not hold
	// the answer for ever: once the shell has exited, its output gets this
	// long to close. Longer than rootExecKillGrace, so Kill's SIGKILL lands
	// before the output is cut off.
	cmd.WaitDelay = rootExecOutputGrace
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &shellProc{cmd: cmd}, nil
}

func (p *shellProc) Wait() int {
	p.wait.Do(func() {
		err := p.cmd.Wait()
		p.code = 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				p.code = ee.ExitCode()
				if p.code < 0 {
					if st, ok := ee.Sys().(syscall.WaitStatus); ok && st.Signaled() {
						p.code = 128 + int(st.Signal())
					}
				}
			} else if p.cmd.ProcessState != nil {
				// exec.ErrWaitDelay: the shell exited and a background child kept
				// the output open past the grace; the shell's own status stands.
				p.code = p.cmd.ProcessState.ExitCode()
			} else {
				p.code = 1
			}
		}
	})
	return p.code
}

// rootExecSignalGroup signals the process group pgid (sig 0 only asks whether
// any member is left). A var so the real-shell tests can fence it. It never
// takes a pgid of 0 or 1: kill(0) is the daemon's own group, kill(-1) every
// process it can reach.
var rootExecSignalGroup = func(pgid int, sig syscall.Signal) error {
	if pgid <= 1 {
		return syscall.EINVAL
	}
	return syscall.Kill(-pgid, sig)
}

// rootExecGroupPoll is how often Kill looks whether the group is gone.
// rootExecKillSettle bounds the look after SIGKILL: a killed process ends as
// soon as it next runs, but one whose new parent never collects it stays a
// zombie, still counted in its group, so that look cannot wait for an empty
// group the way the grace before it does.
const (
	rootExecGroupPoll  = 25 * time.Millisecond
	rootExecKillSettle = 250 * time.Millisecond
)

// Kill sends the whole group SIGTERM, and SIGKILL after rootExecKillGrace
// unless every member has gone by then. What decides is the group, not the
// shell: a child that ignores SIGTERM outlives its shell, and Wait returns as
// soon as the shell has exited and the output has closed (or WaitDelay has
// passed), so Wait returning says nothing about the rest of the group.
//
// Like a terminal's kill it does not reach what a command detached on purpose
// (setsid, nohup into a new session, a systemd-run unit); the transcript
// shows the command that did it.
func (p *shellProc) Kill() {
	p.once.Do(func() {
		pgid := p.cmd.Process.Pid
		go p.Wait() // collect the shell, so a dead one does not keep the group alive
		_ = rootExecSignalGroup(pgid, syscall.SIGTERM)
		gone := false
		for end := time.Now().Add(rootExecKillGrace); !gone && time.Now().Before(end); {
			time.Sleep(rootExecGroupPoll)
			gone = errors.Is(rootExecSignalGroup(pgid, 0), syscall.ESRCH)
		}
		if !gone {
			_ = rootExecSignalGroup(pgid, syscall.SIGKILL)
			// SIGKILL cannot be caught, but a process ends only when it next
			// runs; the answer waits a moment for that, so the host is not told
			// a command is over while part of it is still running.
			for end := time.Now().Add(rootExecKillSettle); !gone && time.Now().Before(end); {
				gone = errors.Is(rootExecSignalGroup(pgid, 0), syscall.ESRCH)
				if !gone {
					time.Sleep(rootExecGroupPoll)
				}
			}
		}
		p.Wait()
	})
}
