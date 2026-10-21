package main

// Privilege drop for MANAGED agents.
//
// The daemon runs as root on every fleet install (install.sh: no User= line),
// and until this file a managed agent — Python, over the granted folder, with
// the store's plaintext PII vault — ran as root too, activated by one `search`
// store grant. This drops every functional child (`serve`, `sweep`,
// `sweep --once`) to the uid that OWNS the granted folder:
//
//   - bounded by construction: that user can already read their own files, so
//     the agent gains nothing the grant did not already name;
//   - different per store, with no new account: a single shared drop uid (a
//     `privatae-freeagent` account, or `nobody`) would pool every store's PII
//     vault under one uid readable across hosts and entities, which is the
//     cross-host bleed the design refuses;
//   - refused when the owner is root, nobody (65534 — what an NFS export with
//     root_squash reports for files root created through the squash), or has
//     no passwd entry, or cannot traverse the folder's own ancestors. "Cannot
//     resolve" is not enough: uid 0 resolves, and a grant over /srv, /opt or
//     anything under /root would otherwise yield a root agent with no error —
//     the exact defect this step removes, surviving silently.
//
// The trade-off, stated so it is a decision and not an omission: the child
// runs as a REAL user, so a compromised runtime or extract tool can write that
// user's .bashrc, .ssh or crontab — and where that user holds passwordless
// sudo (common on cloud images) it can escalate through it. Accepted, because
// the alternative pools the vaults. The credential also drops the owner's
// supplementary groups (setgroups with an empty list, as the session lane
// does), so a file in the folder readable only through one of those groups is
// not readable by the agent.
//
// THE LAYOUT, and why root never writes by path into anything the child owns.
// A dropped child needs `x` on every ancestor of its state, and configDir()
// is 0700 root — pairing credentials live there, so it is not opened. On a
// root install the store therefore gets three siblings under a root-owned,
// traversable base (faStateBase):
//
//	<base>/<pairing>/<id>          0700 OWNER  — vault, port file, logs, the child's key copy
//	<base>/<pairing>/<id>.private  0700 root   — the minted identity, the recipient, manifest staging
//	<base>/<pairing>/<id>.pub      0755 root   — host.crt, 0644: the cert the manifest signature names
//
// Root reads only from .private and .pub (paths it owns). Every root-side
// write INTO an owner-writable directory goes through os.Root on that
// directory (faOwnedWrite / faOwnedMkdir / faOpenLog), which refuses a symlink
// that leaves it: without that, a child could
// replace serve.log or manifest.yaml with a link and have root append to, or
// clobber, any file on the box. The signature's cert path is under .pub so the
// child can verify it but can never swap what its signature names; `sign`
// runs root-side over the .private staging copy and only the finished bytes
// are placed in the folder. The child still holds a COPY of the signing key
// (it serves with it), so it can produce a valid signature for a manifest it
// widened — what bounds that is the per-store uid plus dcnLoadGrantMask on
// every op, the accepted trade-off; splitting serve-key from
// signing key is a change in the agent itself. Each directory root writes
// into is opened ONCE per ensure and verified to be the owner's (faOpenOwned),
// and every deeper name is resolved inside that handle — a component the
// child swaps for a link mid-operation errors instead of being followed.
// Non-root installs keep the in-configDir layout
// with all three the same directory and take no drop: the daemon is already
// the user. Windows takes no drop either (no setuid); freeagent_drop_windows.go
// says what that means for a Windows service.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// faOwner is who a store's managed agent runs as. drop=false means the
// daemon's own identity (non-root install, or a platform with no drop).
type faOwner struct {
	drop bool
	uid  uint32
	gid  uint32
	name string
	home string
	// plat is what this platform needs beyond the above: nothing on unix, the
	// owner's SID on Windows (freeagent_drop_windows.go).
	plat faOwnerPlat
}

// faResolveOwner decides the identity for a store's agent. Where this
// platform drops and the daemon holds machine authority it is the granted
// folder's owner, refused for the machine's own accounts and for anyone who
// cannot reach the folder (faResolveDropOwner, per platform); otherwise it is
// the daemon's own identity.
func faResolveOwner(root, stateDir string) (*faOwner, error) {
	if !faDropSupported() || !processIsRoot() {
		return &faOwner{drop: false}, nil
	}
	return faResolveDropOwner(root, stateDir)
}

// faChild is a started agent child: its pid, for the observe plane, and a
// wait that returns when it exits.
type faChild interface {
	Pid() int
	Wait() error
}

// execChild is a child started through os/exec.
type execChild struct{ cmd *exec.Cmd }

func (c execChild) Pid() int    { return c.cmd.Process.Pid }
func (c execChild) Wait() error { return c.cmd.Wait() }

// faAgentDirInFolder says whether the agent's directory may be created inside
// the granted folder (`.agent`). It may wherever the hand-over is a chown, or
// when nothing is dropped. Where the hand-over is a permission entry (Windows),
// the daemon writes nothing into the person's folder at all: an entry added
// there by path could be steered by a junction the child plants, and the agent
// keeps its directory in the bastion's own state instead.
func faAgentDirInFolder(o *faOwner) bool {
	return faAgentDirInFolderFor(o != nil && o.drop, faHandsOverByChown)
}

func faAgentDirInFolderFor(drop, handsOverByChown bool) bool { return !drop || handsOverByChown }

// faAgentKeptInStateNote is the store card's line where the agent's directory
// is kept in the bastion's state by design rather than because the folder
// could not take it.
const faAgentKeptInStateNote = "agent kept in the bastion's state: on this machine the bastion writes nothing into the shared folder"

// faAgentDirNote is the store card's line when the agent's directory is not in
// the folder: by design (inFolder false), or because the folder refused it (a
// read-only mount or share), which names the reason.
func faAgentDirNote(inFolder bool, err error) string {
	if !inFolder {
		return faAgentKeptInStateNote
	}
	return "folder not usable for the agent dir; agent kept in bastion state (" + err.Error() + ")"
}

// faOwn hands a path to the owner (no-op when not dropping). Lchown: a link
// is re-owned as a link, never followed.
func faOwn(o *faOwner, path string) error {
	if o == nil || !o.drop {
		return nil
	}
	return faHandPath(o, path)
}

// faOpenOwned opens a directory the CHILD may write into (its state leaf, the
// granted folder) as an os.Root, after checking the directory itself belongs
// to the owner: the path to it can be user-controlled (a granted folder under
// the user's home), so a folder the child swapped for a link to /etc must not
// become the place root creates `.agent`. Every name is then resolved inside
// this handle. Not dropping: a plain OpenRoot.
func faOpenOwned(dir string, o *faOwner) (*os.Root, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if o != nil && o.drop {
		if err := faCheckOwnedRoot(r, dir, o); err != nil {
			r.Close()
			return nil, err
		}
	}
	return r, nil
}

// faOwnTree re-owns name and everything under it INSIDE r. The walk and each
// Lchown resolve through the root handle, so a directory the child swaps for
// a link during the walk errors instead of steering the chown outside.
// A non-directory with more than one link is skipped: a hard
// link to a root file would otherwise be handed over, and the sysctl that
// forbids creating one is not a guarantee.
func faOwnTree(r *os.Root, name string, o *faOwner) error {
	if o == nil || !o.drop || !faHandsOverByChown {
		return nil
	}
	return fs.WalkDir(r.FS(), name, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		st, err := r.Lstat(p)
		if err != nil {
			return err
		}
		if !st.IsDir() {
			if n, ok := faInfoLinks(st); ok && n != 1 {
				return nil
			}
		}
		return r.Lchown(p, int(o.uid), int(o.gid))
	})
}

// ── root-side writes into owner-writable directories ────────────────────────
// Every one of these takes the os.Root of the directory (faOpenOwned) and
// works by name inside it: a symlink that would leave the root is refused by
// the walk, so the child cannot aim root's write at a file of its choosing.

// faOwnedWrite replaces name with data (mode) inside r, then hands it to the
// owner. Remove + O_EXCL: an existing entry — file or link — is dropped first,
// and the create refuses anything that reappears in between.
func faOwnedWrite(r *os.Root, name string, data []byte, mode os.FileMode, o *faOwner) error {
	_ = r.Remove(name)
	f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if o != nil && o.drop && faHandsOverByChown {
		return r.Lchown(name, int(o.uid), int(o.gid))
	}
	return nil
}

// faOwnedMkdir ensures name inside r is a real directory (not a link) owned by
// the owner. A read-only parent errors, which the caller treats as "keep the
// agent in the state dir instead".
func faOwnedMkdir(r *os.Root, name string, o *faOwner) error {
	if err := r.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	st, err := r.Lstat(name)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", name)
	}
	if o != nil && o.drop && faHandsOverByChown {
		return r.Lchown(name, int(o.uid), int(o.gid))
	}
	return nil
}

// faOwnIn re-owns an existing name inside r without following a link out.
func faOwnIn(r *os.Root, name string, o *faOwner) error {
	if o == nil || !o.drop || !faHandsOverByChown {
		return nil
	}
	return r.Lchown(name, int(o.uid), int(o.gid))
}

// faReadIn reads dir/name without following a link out of dir — the port
// file lives in the directory the child writes. dir here is the state leaf,
// whose own path is root-owned all the way down.
func faReadIn(dir, name string) ([]byte, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.ReadFile(name)
}

// faOpenLog opens the child's log for append inside its state dir, refusing a
// link out of it, a hard link, or anything that is not a plain file — then
// hands the open file to the owner by descriptor, not by path. The child gets
// this fd as stdout/stderr; it must never be an append handle on a file root
// was tricked into opening.
func faOpenLog(dir, name string, o *faOwner) (*os.File, error) {
	r, err := faOpenOwned(dir, o)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	f, err := r.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := faFdSane(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %v", filepath.Join(dir, name), err)
	}
	if o != nil && o.drop && faHandsOverByChown {
		if err := f.Chown(int(o.uid), int(o.gid)); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}

// ── layout ──────────────────────────────────────────────────────────────────

// faStateBaseOverride lets a test relocate the root-install base.
var faStateBaseOverride = ""

// faStateBase is where a ROOT install keeps managed-agent state: a root-owned
// base every dropped child can reach its own leaf through (faRootStateBase, per
// platform). "" on a non-root install (configDir layout).
func faStateBase() string {
	if faStateBaseOverride != "" {
		return faStateBaseOverride
	}
	if !faDropSupported() || !processIsRoot() {
		return ""
	}
	return faRootStateBase()
}

var faPairingKeyBad = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// faPairingKey names the pairing's slot under the base from its DCN dir
// (<config>/dcn/<host_name> by default): the host name, made path-safe.
func faPairingKey(dcnDir string) string {
	k := faPairingKeyBad.ReplaceAllString(filepath.Base(dcnDir), "_")
	k = strings.Trim(k, "._")
	if k == "" {
		return "default"
	}
	return k
}

// faStoreDirs returns the store's three directories (see the header): the
// owner leaf, the root-private sibling and the root-owned public sibling. On
// a non-root install all three are <dcnDir>/freeagent/<id>.
func faStoreDirs(dcnDir string, storeID int64) (dir, priv, pub string, err error) {
	id := strconv.FormatInt(storeID, 10)
	if base := faStateBase(); base != "" {
		slot := filepath.Join(base, faPairingKey(dcnDir))
		dir, priv, pub = filepath.Join(slot, id), filepath.Join(slot, id+".private"), filepath.Join(slot, id+".pub")
		if err = faMkdirAllMode(dir, 0o700); err != nil {
			return
		}
		if err = faMkdirAllMode(priv, 0o700); err != nil {
			return
		}
		err = faMkdirAllMode(pub, 0o755)
		return
	}
	dir = filepath.Join(dcnDir, "freeagent", id)
	return dir, dir, dir, os.MkdirAll(dir, 0o700)
}

// faMkdirAllMode is MkdirAll where the LEAF gets mode and every created
// parent is chmod'd 0755 explicitly — not left to the umask, which the unit
// does not set.
func faMkdirAllMode(p string, mode os.FileMode) error {
	parent := filepath.Dir(p)
	var missing []string
	for d := parent; d != "/" && d != "."; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		}
		missing = append(missing, d)
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	for _, d := range missing {
		if err := os.Chmod(d, 0o755); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(p, mode); err != nil {
		return err
	}
	return os.Chmod(p, mode)
}
