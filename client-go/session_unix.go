//go:build !windows

package main

// The real pty spawner: creack/pty gives the shell a controlling terminal, Setsid
// puts it in its own session (so killing -pid takes every child with it), and
// syscall.Credential drops privilege before exec when the daemon runs as root.

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// Paths the spawner reads; vars so tests can point them at fixtures.
var (
	sessionPasswdPath = "/etc/passwd"
	sessionShellsPath = "/etc/shells"
)

// sessionUnprivUsers: the dedicated account a root daemon drops a shell into,
// in preference order, before falling back to nobody. A list so a second
// account name can be added without touching the lookup.
var sessionUnprivUsers = []string{"privatae-session"}

func processIsRoot() bool { return os.Geteuid() == 0 }

// sessionIdentity is who the shell runs as. cred is nil when the shell runs as the
// daemon itself (already unprivileged, or a step-upped root session).
type sessionIdentity struct {
	name  string
	home  string
	shell string
	cred  *syscall.Credential
}

// sessionResolveIdentity decides the OS user for op, per the rule in session.go's
// header. requestedShell "" = that user's login shell (falling back to /bin/sh);
// anything else must be listed in /etc/shells.
func sessionResolveIdentity(op, requestedShell string) (*sessionIdentity, error) {
	id := &sessionIdentity{}
	switch {
	case op == sessionOpRoot:
		// The handler already checked the daemon is root and the step-up passed.
		id.name, id.home = "root", "/root"
		if u, err := user.Lookup("root"); err == nil && u.HomeDir != "" {
			id.home = u.HomeDir
		}
	case processIsRoot():
		var u *user.User
		var err error
		for _, name := range sessionUnprivUsers {
			if u, err = user.Lookup(name); err == nil {
				break
			}
		}
		if err != nil {
			u, err = user.Lookup("nobody")
			if err != nil {
				return nil, fmt.Errorf("no unprivileged account to run the session as (create a '%s' system user)", sessionUnprivUsers[0])
			}
		}
		uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
		gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("account %s has a non-numeric uid/gid", u.Username)
		}
		id.name, id.home = u.Username, u.HomeDir
		// Groups nil + NoSetGroups false = setgroups() with an EMPTY list. NoSetGroups
		// true would SKIP setgroups and the shell would inherit the daemon's
		// supplementary groups — measured as root: groups=65534(nogroup),0(root).
		id.cred = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: nil, NoSetGroups: false}
	default:
		u, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("cannot tell which user the bastion runs as: %v", err)
		}
		id.name, id.home = u.Username, u.HomeDir
	}
	if st, err := os.Stat(id.home); id.home == "" || err != nil || !st.IsDir() {
		id.home = "/"
	}
	if requestedShell != "" {
		if !sessionShellListed(sessionShellsPath, requestedShell) {
			return nil, fmt.Errorf("shell '%s' is not listed in %s on this machine", requestedShell, sessionShellsPath)
		}
		if sessionShellIsServer(requestedShell) {
			return nil, fmt.Errorf("'%s' is a terminal server, not a shell: it would outlive this session and its kill; open your shell and run it inside if you must", requestedShell)
		}
		id.shell = requestedShell
		return id, nil
	}
	// The user's own login shell; nobody and the session account usually carry nologin, and a
	// bare shell entry may be missing on macOS, so anything unusable becomes /bin/sh.
	sh := sessionShellFromPasswd(sessionPasswdPath, id.name)
	if id.cred == nil && op != sessionOpRoot {
		if env := os.Getenv("SHELL"); env != "" {
			sh = env
		}
	}
	if sh == "" || filepath.Base(sh) == "nologin" || filepath.Base(sh) == "false" {
		sh = "/bin/sh"
	}
	if _, err := os.Stat(sh); err != nil {
		sh = "/bin/sh"
	}
	id.shell = sh
	return id, nil
}

type ptyProc struct {
	f     *os.File
	cmd   *exec.Cmd
	ident *sessionIdentity
	once  sync.Once
	wait  sync.Once
	code  int
}

func spawnSessionProc(op, shell string, cols, rows int) (sessionProc, error) {
	ident, err := sessionResolveIdentity(op, shell)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(ident.shell)
	cmd.Args = []string{"-" + filepath.Base(ident.shell)} // the login-shell convention every shell honours
	cmd.Dir = ident.home
	cmd.Env = []string{
		"TERM=xterm-256color",
		"HOME=" + ident.home,
		"USER=" + ident.name,
		"LOGNAME=" + ident.name,
		"SHELL=" + ident.shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if lang := os.Getenv("LANG"); lang != "" {
		cmd.Env = append(cmd.Env, "LANG="+lang)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: ident.cred} // pty adds Setsid+Setctty
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, fmt.Errorf("cannot start %s as %s: %v", ident.shell, ident.name, err)
	}
	return &ptyProc{f: f, cmd: cmd, ident: ident}, nil
}

func (p *ptyProc) Read(b []byte) (int, error)  { return p.f.Read(b) }
func (p *ptyProc) Write(b []byte) (int, error) { return p.f.Write(b) }
func (p *ptyProc) User() string                { return p.ident.name }
func (p *ptyProc) Shell() string               { return p.ident.shell }

func (p *ptyProc) Resize(cols, rows int) error {
	return pty.Setsize(p.f, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// Wait reaps the shell once and closes the pty master; safe to call more than once.
func (p *ptyProc) Wait() int {
	p.wait.Do(func() {
		err := p.cmd.Wait()
		_ = p.f.Close()
		p.code = 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				p.code = ee.ExitCode()
				if p.code < 0 { // killed by a signal: report 128+signal like a shell would
					if st, ok := ee.Sys().(syscall.WaitStatus); ok && st.Signaled() {
						p.code = 128 + int(st.Signal())
					}
				}
			} else {
				p.code = 1
			}
		}
	})
	return p.code
}

// Kill hangs up the whole process group (the shell is its own session leader), then
// SIGKILLs anything that ignored it. Idempotent.
//
// What this does NOT reach, said plainly: anything the user detached from the group
// on purpose — `nohup cmd &`, `setsid cmd`, a tmux/screen server, a systemd-run
// unit. Those are ordinary escapes any shell allows and this lane does not try to
// police them; the transcript shows what was typed, and tmux/screen are refused as
// the session shell itself (sessionShellIsServer) so a session cannot BE a server.
func (p *ptyProc) Kill() {
	p.once.Do(func() {
		pid := p.cmd.Process.Pid
		_ = syscall.Kill(-pid, syscall.SIGHUP)
		done := make(chan struct{})
		go func() { p.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(sessionKillGrace):
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			<-done
		}
	})
}
