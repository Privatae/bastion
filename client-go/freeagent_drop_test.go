//go:build !windows

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// faTestUser finds a real, non-root, non-nobody account with a home directory
// on this box — the identity a granted folder would be owned by. "" when the
// box has none (a bare container): the root-only tests skip.
func faTestUser(t *testing.T) *user.User {
	t.Helper()
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		if uid < 1000 || uid == 65534 || f[0] == "nobody" {
			continue
		}
		if st, err := os.Stat(f[5]); err != nil || !st.IsDir() {
			continue
		}
		if u, err := user.LookupId(f[2]); err == nil {
			return u
		}
	}
	return nil
}

// makeTraversable opens t.TempDir's 0700 chain so a dropped child can reach
// the leaf — what /var/lib/privatae/freeagent's 0755 base gives for real.
func makeTraversable(t *testing.T, p string) {
	t.Helper()
	for d := p; d != "/" && d != "."; d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFaResolveOwnerNonRootTakesNoDrop(t *testing.T) {
	if processIsRoot() {
		t.Skip("runs as a user")
	}
	o, err := faResolveOwner(t.TempDir(), t.TempDir())
	if err != nil || o == nil || o.drop {
		t.Fatalf("a non-root install has no privilege to shed: %+v %v", o, err)
	}
	if o.sysProcAttr() != nil {
		t.Fatal("no credential when not dropping")
	}
}

func TestFaResolveOwnerRefusesRootNobodyAndUnknown(t *testing.T) {
	if !processIsRoot() {
		t.Skip("needs root to chown")
	}
	state := t.TempDir()
	// root-owned folder: refused, and the reason says root (uid 0 resolves —
	// "cannot resolve" would not have caught this)
	if _, err := faResolveOwner(t.TempDir(), state); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("a root-owned folder must be refused with the reason: %v", err)
	}
	// nobody: refused (a shared account would hold the vault)
	d := t.TempDir()
	if err := os.Chown(d, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := faResolveOwner(d, state); err == nil || !strings.Contains(err.Error(), "nobody") {
		t.Fatalf("a nobody-owned folder must be refused with the reason: %v", err)
	}
	// an owner with no passwd entry: refused
	d = t.TempDir()
	orphan := 61234
	for ; orphan < 61300; orphan++ {
		if _, err := user.LookupId(strconv.Itoa(orphan)); err != nil {
			break
		}
	}
	if err := os.Chown(d, orphan, orphan); err != nil {
		t.Fatal(err)
	}
	if _, err := faResolveOwner(d, state); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatalf("an unknown owner must be refused with the reason: %v", err)
	}
	// a symlinked root resolves to its TARGET's owner (Stat, not Lstat)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	if _, err := faResolveOwner(link, state); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatalf("a symlinked root must resolve to the target's owner: %v", err)
	}
}

func TestFaDropRunsTheChildAsTheFolderOwner(t *testing.T) {
	if !processIsRoot() {
		t.Skip("needs root to drop")
	}
	u := faTestUser(t)
	if u == nil {
		t.Skip("no ordinary user account on this box")
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	base := t.TempDir()
	makeTraversable(t, base)
	old := faStateBaseOverride
	faStateBaseOverride = base
	t.Cleanup(func() { faStateBaseOverride = old })

	root := t.TempDir()
	if err := os.Chown(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	// the store dir lands under the base, not under configDir
	dir, err := faStoreDir("/root/.config/privatae-bastion/dcn/anchor.host.privatae.ai", 7)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dir, base) || !strings.HasSuffix(dir, "/anchor.host.privatae.ai/7") {
		t.Fatalf("root-install store dir must be <base>/<pairing>/<store>: %s", dir)
	}
	if st, _ := os.Stat(filepath.Dir(dir)); st.Mode().Perm() != 0o755 {
		t.Fatalf("the pairing slot must be traversable: %v", st.Mode())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("the store leaf stays private: %v", st.Mode())
	}
	o, err := faResolveOwner(root, dir)
	if err != nil || !o.drop || int(o.uid) != uid || o.name != u.Username {
		t.Fatalf("owner must be the folder's owner: %+v %v", o, err)
	}
	if o.home != u.HomeDir {
		t.Fatalf("HOME must be the owner's home: %q", o.home)
	}
	// hand the state over; a file written by root afterwards is re-owned
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "host.key")
	if err := atomicWrite(secret, []byte("k")); err != nil {
		t.Fatal(err)
	}
	rd, err := faOpenOwned(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	if err := faOwnTree(rd, ".", o); err != nil {
		t.Fatal(err)
	}
	if su, _, _ := faPathOwner(secret); int(su) != uid {
		t.Fatal("the identity must belong to the owner")
	}
	if err := atomicWrite(secret, []byte("k2")); err != nil { // a rewrite: root-owned again
		t.Fatal(err)
	}
	if su, _, _ := faPathOwner(secret); su != 0 {
		t.Fatal("test premise: atomicWrite leaves a root-owned file")
	}
	if err := faOwn(o, secret); err != nil {
		t.Fatal(err)
	}
	if su, _, _ := faPathOwner(secret); int(su) != uid {
		t.Fatal("faOwn must re-own after every write")
	}

	// the drop itself: a child started with the credential IS the owner, with
	// the owner's HOME and no supplementary groups from root
	inst := &faInstance{Dir: dir, owner: o}
	cmd := exec.Command("sh", "-c", "id -u; id -G; echo $HOME")
	cmd.Dir = dir
	cmd.Env = faChildEnv(inst)
	cmd.SysProcAttr = o.sysProcAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child as %s: %v\n%s", u.Username, err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 3 || lines[0] != u.Uid {
		t.Fatalf("the child must run as uid %s:\n%s", u.Uid, out)
	}
	if strings.Contains(" "+lines[1]+" ", " 0 ") {
		t.Fatalf("the child must not carry root's groups: %q", lines[1])
	}
	if lines[2] != u.HomeDir {
		t.Fatalf("HOME must be the owner's, got %q", lines[2])
	}
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "XDG_CONFIG_HOME=") {
			t.Fatal("root's XDG_CONFIG_HOME must not pass through to a dropped child")
		}
	}
}

func TestFaPairingKey(t *testing.T) {
	for in, want := range map[string]string{
		"/root/.config/privatae-bastion/dcn/anchor.host.privatae.ai": "anchor.host.privatae.ai",
		"/x/dcn/we ird/../name": "name",
		"/x/dcn/..":             "default",
	} {
		if got := faPairingKey(in); got != want {
			t.Errorf("faPairingKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// Root-side writes into the child's directories never follow a link the child
// planted: the log fd, the manifest placement, the .agent directory itself.
func TestFaRootSideWritesRefuseThePlantedLink(t *testing.T) {
	if !processIsRoot() {
		t.Skip("needs root: the attack is a user aiming root's write")
	}
	u := faTestUser(t)
	if u == nil {
		t.Skip("no ordinary user account on this box")
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	o := &faOwner{drop: true, uid: uint32(uid), gid: uint32(gid), name: u.Username, home: u.HomeDir}

	target := filepath.Join(t.TempDir(), "root-owned")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir() // the child's dir: owner-writable, so a link can appear in it
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Fatal(err)
	}

	// serve.log -> a root file. The open must refuse; the target is untouched.
	if err := os.Symlink(target, filepath.Join(dir, "serve.log")); err != nil {
		t.Fatal(err)
	}
	if f, err := faOpenLog(dir, "serve.log", o); err == nil {
		f.Close()
		t.Fatal("a log that is a link out of the child's dir must be refused")
	}
	// a hard link to a root file inside the dir: two links, refused
	if err := os.Link(target, filepath.Join(dir, "sweep.log")); err == nil {
		if f, err := faOpenLog(dir, "sweep.log", o); err == nil {
			f.Close()
			t.Fatal("a hard link to a root file must be refused")
		}
	}
	// a plain file is opened, owned by the child, and appendable
	f, err := faOpenLog(dir, "ok.log", o)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if su, _, _ := faPathOwner(filepath.Join(dir, "ok.log")); int(su) != uid {
		t.Fatal("the log must belong to the child")
	}

	// manifest.yaml -> a root file. The placement drops the link and
	// writes a real file; the target keeps its bytes.
	if err := os.Symlink(target, filepath.Join(dir, "manifest.yaml")); err != nil {
		t.Fatal(err)
	}
	rd, err := faOpenOwned(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	if err := faOwnedWrite(rd, "manifest.yaml", []byte("manifest\n"), 0o600, o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Fatalf("the root-owned target was written through the link: %q", b)
	}
	if st, err := os.Lstat(filepath.Join(dir, "manifest.yaml")); err != nil || !st.Mode().IsRegular() {
		t.Fatal("the manifest must be a plain file after placement")
	}
	if b, _ := rd.ReadFile("manifest.yaml"); string(b) != "manifest\n" {
		t.Fatal("the placed manifest must read back")
	}

	// .agent -> a directory root owns. Mkdir must not write into it.
	folder := t.TempDir()
	if err := os.Chown(folder, uid, gid); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(folder, ".agent")); err != nil {
		t.Fatal(err)
	}
	rf, err := faOpenOwned(folder, o)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	if err := faOwnedMkdir(rf, ".agent", o); err == nil {
		t.Fatal("a .agent that is a link out of the folder must be refused")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("nothing may be written through the linked .agent")
	}
	// a folder that is itself a link to a root-owned directory is refused at
	// open — the path to a granted folder can be the user's to swap
	swapped := filepath.Join(t.TempDir(), "docs")
	if err := os.Symlink(elsewhere, swapped); err != nil {
		t.Fatal(err)
	}
	if r, err := faOpenOwned(swapped, o); err == nil {
		r.Close()
		t.Fatal("a granted folder resolving to a root-owned directory must be refused")
	}
	// a chown through the handle never follows a directory the child
	// swapped for a link out of the tree — the walk and Lchown resolve inside
	// the root, so the target keeps its owner
	if err := os.Mkdir(filepath.Join(folder, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(folder, "real"), uid, gid); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "shadow"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(folder, ".agent"))
	if err := os.Symlink(outside, filepath.Join(folder, ".agent")); err != nil {
		t.Fatal(err)
	}
	if err := rf.Lchown(".agent/shadow", uid, gid); err == nil {
		t.Fatal("Lchown through a linked directory must be refused by the root handle")
	}
	if err := faOwnTree(rf, ".", o); err != nil {
		t.Fatal(err)
	}
	if su, _, _ := faPathOwner(filepath.Join(outside, "shadow")); su != 0 {
		t.Fatal("a tree chown must not re-own anything outside the folder")
	}
	if su, _, _ := faPathOwner(filepath.Join(folder, "real")); int(su) != uid {
		t.Fatal("the real subtree must be re-owned")
	}

	// the recipient is read from the root-private dir, never the child's
	priv := t.TempDir()
	if err := os.WriteFile(filepath.Join(priv, "recipient"), []byte("age1x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(target, filepath.Join(dir, "recipient"))
	if got := faRecipientOf(&faInstance{Dir: dir, PrivDir: priv}); got != "age1x" {
		t.Fatalf("recipient must come from the private dir, got %q", got)
	}

	// an owner that cannot reach its folder is refused with the reason
	parent := t.TempDir() // 0700 root
	leaf := filepath.Join(parent, "leaf")
	if err := os.Mkdir(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(leaf, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := faResolveOwner(leaf, dir); err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Fatalf("a user-owned leaf under a root-only parent must be refused: %v", err)
	}
}
