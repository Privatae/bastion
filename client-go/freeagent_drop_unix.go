//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

func faDropSupported() bool { return true }

// faRootStateBase: root-owned 0755, so every dropped child can traverse to its
// own 0700 leaf.
func faRootStateBase() string { return "/var/lib/privatae/freeagent" }

// faOwnerPlat: a unix owner is fully described by its uid, gid, name and home.
type faOwnerPlat struct{}

// faHandsOverByChown: on unix every file root writes for the child is handed
// over by changing its owner.
const faHandsOverByChown = true

// faResolveDropOwner is the folder's owner on a root install, refused for root /
// nobody / unknown; Stat, not Lstat, so a symlinked root resolves to its
// target's owner. HOME is the owner's home when that is a directory, else the
// (owner-owned) store state dir — never `/`, which is wrong for a Python child
// that writes ~/.cache.
func faResolveDropOwner(root, stateDir string) (*faOwner, error) {
	uid, gid, err := faPathOwner(root)
	if err != nil {
		return nil, fmt.Errorf("cannot read the folder's owner: %v", err)
	}
	if uid == 0 {
		return nil, errors.New("refusing to run the agent as root: the granted folder is owned by root — grant a folder owned by the user who should read it")
	}
	if uid == 65534 {
		return nil, errors.New("refusing to run the agent as nobody: the granted folder reports owner 65534 (nobody, or an NFS export with root_squash) — a shared account would hold this store's vault")
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, fmt.Errorf("refusing to run the agent: the granted folder's owner (uid %d) has no account on this machine", uid)
	}
	if u.Username == "nobody" {
		return nil, errors.New("refusing to run the agent as nobody: a shared account would hold this store's vault")
	}
	if g, err := strconv.ParseUint(u.Gid, 10, 32); err == nil {
		gid = uint32(g) // the account's primary group, not the folder's group
	}
	// The owner must be able to REACH the folder: a user-owned leaf under a
	// root-only parent (/srv/data/alice with /srv/data 0700) would otherwise
	// start two children that exit-loop forever with the card reading
	// "starting". Checked as the dropped credential will see it: owner, or
	// group with g+x, or o+x, on every ancestor.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		for d := filepath.Dir(resolved); d != "/" && d != "."; d = filepath.Dir(d) {
			if why := faTraversable(d, uid, gid); why != "" {
				return nil, fmt.Errorf("refusing to run the agent as %s: it cannot reach the granted folder — %s", u.Username, why)
			}
		}
	}
	home := u.HomeDir
	if st, err := os.Stat(home); home == "" || err != nil || !st.IsDir() {
		home = stateDir
	}
	return &faOwner{drop: true, uid: uid, gid: gid, name: u.Username, home: home}, nil
}

// faTraversable: can uid/gid pass through directory d? "" = yes.
func faTraversable(d string, uid, gid uint32) string {
	st, err := os.Stat(d)
	if err != nil {
		return d + ": " + err.Error()
	}
	duid, dgid, err := faPathOwner(d)
	if err != nil {
		return d + ": " + err.Error()
	}
	m := st.Mode().Perm()
	switch {
	case duid == uid && m&0o100 != 0, dgid == gid && m&0o010 != 0, m&0o001 != 0:
		return ""
	}
	return fmt.Sprintf("%s is %04o, owner uid %d", d, m, duid)
}

// faHandPath hands the store's state leaf to the owner. Lchown: a link is
// re-owned as a link, never followed.
func faHandPath(o *faOwner, path string) error { return faChown(path, o.uid, o.gid) }

// faCheckOwnedRoot: the directory root is about to write into belongs to the
// owner. A directory the child swapped for one of root's would fail this.
func faCheckOwnedRoot(r *os.Root, dir string, o *faOwner) error {
	st, err := r.Stat(".")
	if err != nil {
		return err
	}
	uid, _, ok := faInfoOwner(st)
	if !ok || uid != o.uid {
		return fmt.Errorf("%s is not owned by %s (uid %d) — refusing to write into it", dir, o.name, uid)
	}
	return nil
}

// faSharePub / faShareRuntime: on unix the public cert directory and the
// runtime are made readable by their modes (faStoreDirs, faEnsurePyz).
func faSharePub(string, *faOwner) error { return nil }
func faShareRuntime(string) error       { return nil }

// faDropEnv is what a dropped child is told about who it is, and which of the
// daemon's variables it may keep. It must not inherit root's HOME (/root —
// wrong and unwritable after the drop) or root's XDG config dir.
func faDropEnv(o *faOwner, stateDir string) (set []string, passthrough []string) {
	return []string{"HOME=" + o.home, "USER=" + o.name, "LOGNAME=" + o.name},
		[]string{"PATH", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP"}
}

// faStartChild starts the child. On unix the drop is the credential in
// cmd.SysProcAttr, so this is an ordinary start.
func faStartChild(_ context.Context, cmd *exec.Cmd, _ *faOwner) (faChild, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execChild{cmd}, nil
}

// faPathOwner: uid/gid of the file at path, following symlinks.
func faPathOwner(path string) (uint32, uint32, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("no ownership information for this path")
	}
	return sys.Uid, sys.Gid, nil
}

func faChown(path string, uid, gid uint32) error {
	return os.Lchown(path, int(uid), int(gid))
}

// sysProcAttr is the credential the child is started with. Groups nil +
// NoSetGroups false = setgroups() with an EMPTY list — the same as
// session_unix.go:71, and for the same measured reason: skipping setgroups
// leaves the child in root's supplementary groups.
func (o *faOwner) sysProcAttr() *syscall.SysProcAttr {
	if o == nil || !o.drop {
		return nil
	}
	return &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: o.uid, Gid: o.gid, Groups: nil, NoSetGroups: false}}
}

// faFdSane: the open log is a plain file with one link. A hard link to a file
// root owns would pass the os.Root walk (it is inside the directory) and still
// hand the child root's append on the target.
func faFdSane(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Nlink != 1 {
		return fmt.Errorf("has %d links", sys.Nlink)
	}
	return nil
}

// faInfoOwner: uid/gid from a FileInfo obtained through an os.Root handle.
func faInfoOwner(st os.FileInfo) (uint32, uint32, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return sys.Uid, sys.Gid, true
}

// faInfoLinks: the link count from a FileInfo.
func faInfoLinks(st os.FileInfo) (uint64, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(sys.Nlink), true
}
