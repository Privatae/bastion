//go:build windows

package main

// The drop on Windows: a managed agent runs as the person who owns the granted
// folder, never as LocalSystem.
//
// WHEN IT APPLIES. Only when the bastion runs as the Windows service
// (sysservice_windows.go), which is LocalSystem. An ordinary install runs as a
// logon task under the person's own account, so the daemon already IS the
// user and there is nothing to drop.
//
// WHO. The folder's owner, read from its security descriptor, refused for the
// machine's own identities, groups, the built-in Administrator and Guest
// (faWinOwnerRefusal). That is the unix rule (root, nobody, no account) in
// Windows terms.
//
// HOW. With the owner's own token from their signed-in session
// (WTSQueryUserToken), and CreateProcessAsUser. So the agent runs while its
// owner is signed in to this machine; when they are not, the start is refused
// with a sentence saying so and retried on the supervisor's backoff. Starting it
// for an owner who is not signed in needs a token made without their password
// (an S4U logon), which this build does not make. os/exec is not used for this
// start: it cannot name the window station, and a process started from a
// service under another account's token inherits the service's, which that
// account cannot open. An empty desktop name lets the system connect the child
// to its own session's.
//
// WHERE. The state lives under the service's own state directory, inside
// LocalSystem's profile, which only SYSTEM and administrators can open; every
// ancestor of the store's directories is therefore out of the owner's reach,
// as /var/lib/privatae is on unix. The owner is given access to exactly three
// places, by a permission entry rather than by ownership: their store's state
// leaf (modify), its public cert directory (read), and the runtime (read, for
// every local user: it is the published artifact). Reaching a leaf without
// access to its ancestors relies on the "bypass traverse checking" right every
// account holds by default; where a policy has removed it, the agent fails to
// start and says so, and nothing runs as LocalSystem instead.
//
// WHAT IS NEVER DONE. Nothing is written into the person's folder (no `.agent`
// there; the agent's directory stays in the state leaf): an entry added there
// by path could be steered by a junction. And the leaf's permissions are set
// only while it is empty, or found already right: setting a directory's
// permissions also pushes them into what is inside, and the owner can put a
// junction inside their leaf.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// faDropSupported: only the service is LocalSystem.
func faDropSupported() bool { return runningAsService }

// faRootStateBase: under the service's state directory, in LocalSystem's
// profile (sysservice.go windowsSystemAppData).
func faRootStateBase() string {
	d, err := configDirPath()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "freeagent-state")
}

// faHandsOverByChown: on Windows the hand-over is a permission entry on the
// state leaf, inherited by everything later created in it.
const faHandsOverByChown = false

// faWinModify is the "Modify" right: read, write, execute and delete, without
// the right to change permissions or take ownership.
const faWinModify = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE | windows.DELETE

const faWinReadExecute = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE

var errOwnerNotSignedIn = errors.New("is not signed in to this machine; the agent starts when they are")

func faResolveDropOwner(root, stateDir string) (*faOwner, error) {
	sd, err := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("cannot read the folder's owner: %v", err)
	}
	sid, _, err := sd.Owner()
	if err != nil || sid == nil {
		return nil, fmt.Errorf("cannot read the folder's owner: %v", err)
	}
	// Bounded and cached (sidnames.go); no answer in time refuses the start.
	acct, err := faWinDropOwnerAccount(sid.String(), winAccounts, faDropSIDLane)
	if err != nil {
		return nil, err
	}
	name, full := acct.Account, sidAccountLabel(acct)
	if why := faWinOwnerRefusal(sid.String(), acct.Type, full); why != "" {
		return nil, errors.New(why)
	}
	home := faWinProfileDir(sid.String())
	if home == "" {
		home = stateDir
	}
	return &faOwner{drop: true, name: full, home: home, plat: faOwnerPlat{sid: sid.String(), user: name}}, nil
}

// faWinProfileDir is the owner's profile folder from the machine's profile
// list, or "" when the account has never signed in here.
func faWinProfileDir(sid string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	p, _, err := k.GetStringValue("ProfileImagePath")
	if err != nil {
		return ""
	}
	if x, err := registry.ExpandString(p); err == nil {
		p = x
	}
	if st, err := os.Stat(p); err != nil || !st.IsDir() {
		return ""
	}
	return p
}

// faHandPath gives the owner Modify on the store's state leaf: set while the
// leaf is empty, accepted when the entry is already there, refused otherwise.
// A leaf with content and no entry for this owner holds another account's
// state (the folder changed hands); it is left as it is, never re-granted, and
// the card says what to do.
func faHandPath(o *faOwner, path string) error {
	sid, err := windows.StringToSid(o.plat.sid)
	if err != nil {
		return err
	}
	if ok, err := faWinGranted(path, sid, faWinModify); err != nil {
		return err
	} else if ok {
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s holds state made for another account, and its permissions are not changed while it has content; remove it to start this store afresh for %s", path, o.name)
	}
	return faWinGrant(path, sid, faWinModify, windows.TRUSTEE_IS_USER)
}

// faSharePub lets the owner read the store's public cert directory. Only the
// service writes there, so a by-path change cannot be steered.
func faSharePub(pub string, o *faOwner) error {
	if o == nil || !o.drop {
		return nil
	}
	sid, err := windows.StringToSid(o.plat.sid)
	if err != nil {
		return err
	}
	if ok, err := faWinGranted(pub, sid, faWinReadExecute); err != nil || ok {
		return err
	}
	return faWinGrant(pub, sid, faWinReadExecute, windows.TRUSTEE_IS_USER)
}

// faShareRuntime lets every local user read the runtime (the published agent
// artifact). Only the service writes there.
func faShareRuntime(dir string) error {
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	if ok, err := faWinGranted(dir, users, faWinReadExecute); err != nil || ok {
		return err
	}
	return faWinGrant(dir, users, faWinReadExecute, windows.TRUSTEE_IS_WELL_KNOWN_GROUP)
}

// faWinGrant adds an inheritable allow entry for sid to path's existing
// permissions, keeping what is inherited.
func faWinGrant(path string, sid *windows.SID, mask windows.ACCESS_MASK, kind windows.TRUSTEE_TYPE) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  kind,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, dacl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// faWinGranted reports whether path's permissions hold an allow entry for sid
// with every right in mask, inheritable to what is created inside.
func faWinGranted(path string, sid *windows.SID, mask windows.ACCESS_MASK) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, err
	}
	const inherits = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&mask != mask ||
			ace.Header.AceFlags&inherits != inherits || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return true, nil
		}
	}
	return false, nil
}

// faCheckOwnedRoot: the directory the service is about to write into is a real
// directory, not a junction or a link to somewhere else. On Windows the service
// writes only into the state leaf, whose ancestors the owner cannot change.
func faCheckOwnedRoot(_ *os.Root, dir string, _ *faOwner) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a plain directory — refusing to write into it", dir)
	}
	return nil
}

// faDropEnv: faWinDropEnv with this owner's name and profile.
func faDropEnv(o *faOwner, stateDir string) (set []string, passthrough []string) {
	profile := o.home
	if profile == stateDir {
		profile = ""
	}
	return faWinDropEnv(o.plat.user, profile, stateDir)
}

// faStartChild starts the child as the owner when dropping, as itself otherwise.
func faStartChild(ctx context.Context, cmd *exec.Cmd, o *faOwner) (faChild, error) {
	if o == nil || !o.drop {
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return execChild{cmd}, nil
	}
	if cmd.Err != nil {
		return nil, cmd.Err
	}
	tok, err := faWinSessionToken(o.plat.sid)
	if err != nil {
		return nil, fmt.Errorf("%s %w", o.name, err)
	}
	defer tok.Close()
	return faWinStartAs(ctx, tok, cmd)
}

// faWinSessionToken is the owner's token from a session they are signed in to,
// an active one before a disconnected one. The token is the one their session
// holds: for an administrator under UAC that is the limited token, not the
// elevated one.
func faWinSessionToken(sid string) (windows.Token, error) {
	var sessions *windows.WTS_SESSION_INFO
	var n uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &n); err != nil {
		return 0, fmt.Errorf("cannot list this machine's sessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	var other windows.Token
	for _, s := range unsafe.Slice(sessions, n) {
		var t windows.Token
		if windows.WTSQueryUserToken(s.SessionID, &t) != nil {
			continue
		}
		u, err := t.GetTokenUser()
		if err != nil || u.User.Sid.String() != sid {
			t.Close()
			continue
		}
		if s.State == windows.WTSActive {
			if other != 0 {
				other.Close()
			}
			return t, nil
		}
		if other == 0 {
			other = t
		} else {
			t.Close()
		}
	}
	if other != 0 {
		return other, nil
	}
	return 0, errOwnerNotSignedIn
}

// faWinStartAs creates the child under tok. Its standard input is NUL and its
// output and error go to the log the caller opened (cmd.Stdout); those two
// handles are the only ones it inherits.
func faWinStartAs(ctx context.Context, tok windows.Token, cmd *exec.Cmd) (faChild, error) {
	logf, ok := cmd.Stdout.(*os.File)
	if !ok || logf == nil {
		return nil, errors.New("the agent's log is not a file")
	}
	app, err := windows.UTF16PtrFromString(cmd.Path)
	if err != nil {
		return nil, err
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(cmd.Args))
	if err != nil {
		return nil, err
	}
	var dir *uint16
	if cmd.Dir != "" {
		if dir, err = windows.UTF16PtrFromString(cmd.Dir); err != nil {
			return nil, err
		}
	}
	env := faWinEnvBlock(cmd.Env)

	self := windows.CurrentProcess()
	var out windows.Handle
	if err := windows.DuplicateHandle(self, windows.Handle(logf.Fd()), self, &out, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, fmt.Errorf("cannot hand the log to the agent: %w", err)
	}
	defer windows.CloseHandle(out)
	nulName, _ := windows.UTF16PtrFromString("NUL")
	sa := &windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	in, err := windows.CreateFile(nulName, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		sa, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open NUL for the agent: %w", err)
	}
	defer windows.CloseHandle(in)

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	handles := []windows.Handle{in, out}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, err
	}
	desktop, _ := windows.UTF16PtrFromString("")
	si := &windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	si.StdInput, si.StdOutput, si.StdErr = in, out, out
	si.Desktop = desktop

	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW)
	if err := windows.CreateProcessAsUser(tok, app, line, nil, nil, true, flags, &env[0], dir, &si.StartupInfo, &pi); err != nil {
		return nil, fmt.Errorf("cannot start the agent as its owner: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	// FindProcess opens its own handle while pi.Process is still open, so the
	// pid cannot have been reused in between.
	p, err := os.FindProcess(int(pi.ProcessId))
	windows.CloseHandle(pi.Process)
	if err != nil {
		return nil, err
	}
	return &winChild{p: p, ctx: ctx}, nil
}

// winChild is a child created by faWinStartAs. Waiting ends it when ctx does,
// as exec.CommandContext would.
type winChild struct {
	p   *os.Process
	ctx context.Context
}

func (c *winChild) Pid() int { return c.p.Pid }

func (c *winChild) Wait() error {
	done := make(chan struct{})
	go func() {
		select {
		case <-c.ctx.Done():
			_ = c.p.Kill()
		case <-done:
		}
	}()
	st, err := c.p.Wait()
	close(done)
	if err != nil {
		return err
	}
	if !st.Success() {
		return fmt.Errorf("exit status %d", st.ExitCode())
	}
	return nil
}

// sysProcAttr: the Windows drop does not go through a credential; faStartChild
// starts the child under the owner's token itself.
func (o *faOwner) sysProcAttr() *syscall.SysProcAttr { return nil }

// faFdSane: the open log is a plain file with one link and no reparse point. A
// hard link the child planted to a file the service can write would otherwise
// hand the child the service's append on it.
func faFdSane(f *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return errors.New("not a regular file")
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("has %d links", info.NumberOfLinks)
	}
	return nil
}

func faInfoLinks(os.FileInfo) (uint64, bool) { return 0, false }
