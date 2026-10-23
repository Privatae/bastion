package main

// A git run's tree is the agent's, .git included. These tests stand in for an
// agent that uses that .git against the bastion: hooks, a file system
// monitor, a filter, a signing program, a changed remote and a link to a file
// outside the tree, besides ordinary edits. The container runtime is a
// stand-in script that does the agent's work on the mounted tree; the sidecar
// it would start is a local HTTP server on the sidecar's port.

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const gitRunOutsideSecret = "outside-the-tree-7c41"

// gitRunFixture is an origin with one commit, a decoy repository, a file
// outside the tree, a folder the agent's code marks when it runs, and a
// stand-in runtime that runs agent (a shell script, given the tree's path as
// $1) when the run starts its container.
type gitRunFixture struct {
	origin, decoy, outside, marks, agentFile string
}

// setAgent writes the script the stand-in runtime runs as the agent.
func (f gitRunFixture) setAgent(t *testing.T, script string) {
	t.Helper()
	if err := os.WriteFile(f.agentFile, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func testGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

func newGitRunFixture(t *testing.T) gitRunFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	tmp := t.TempDir()
	// The test's own git, and git as the code before this change ran it, read
	// no config of this machine's.
	home := filepath.Join(tmp, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "seed")
	t.Setenv("GIT_AUTHOR_EMAIL", "seed@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "seed")
	t.Setenv("GIT_COMMITTER_EMAIL", "seed@example.invalid")
	f := gitRunFixture{
		origin:  filepath.Join(tmp, "origin.git"),
		decoy:   filepath.Join(tmp, "decoy.git"),
		outside: filepath.Join(tmp, "outside", "secret"),
		marks:   filepath.Join(tmp, "marks"),
	}
	for _, d := range []string{filepath.Dir(f.outside), f.marks} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.outside, []byte(gitRunOutsideSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	testGit(t, tmp, "init", "-q", "--bare", "-b", "main", f.origin)
	testGit(t, tmp, "init", "-q", "--bare", "-b", "main", f.decoy)
	seed := filepath.Join(tmp, "seed")
	testGit(t, tmp, "init", "-q", "-b", "main", seed)
	for name, body := range map[string]string{"keep.txt": "keep\n", "edit.txt": "old\n", "gone.txt": "bye\n"} {
		if err := os.WriteFile(filepath.Join(seed, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(seed, "tool.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	testGit(t, seed, "add", "-A")
	testGit(t, seed, "commit", "-q", "-m", "seed")
	testGit(t, seed, "push", "-q", f.origin, "main")

	bin := t.TempDir()
	f.agentFile = filepath.Join(bin, "agent.sh")
	agentFile := f.agentFile
	runtime := "#!/bin/sh\ncase \"$1\" in\nps|pull|rm) exit 0;;\ninspect) echo 127.0.0.1; exit 0;;\n" +
		"run) for a; do case \"$a\" in *:/work) d=${a%:/work};; esac; done\n" +
		"  /bin/sh " + agentFile + " \"$d\" > " + filepath.Join(bin, "agent.log") + " 2>&1 || exit 1\n" +
		"  echo standin0123456789; exit 0;;\nesac\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(runtime), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() {
		if t.Failed() {
			if b, err := os.ReadFile(filepath.Join(bin, "agent.log")); err == nil {
				t.Logf("agent log:\n%s", b)
			}
		}
	})

	// The sidecar the run drives: it answers, and /run reports success.
	ln, err := net.Listen("tcp", "127.0.0.1:8844")
	if err != nil {
		t.Fatalf("the sidecar's port is taken: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/run" {
			_, _ = w.Write([]byte(`{"ok":true,"transcript":"done"}`))
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f gitRunFixture) run(t *testing.T) (map[string]any, int) {
	t.Helper()
	b, code := runGit(harnessSpec{Mode: "git", HarnessID: "h1", Image: "harness:test",
		RepoURL: f.origin, Branch: "agent-work", MaxMinutes: 1})
	var res map[string]any
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("result: %v: %s", err, b)
	}
	return res, code
}

// theAgent turns its tree's .git against whoever runs git in it next, and
// makes ordinary changes to the files.
func theAgent(f gitRunFixture) string {
	mark := func(name string) string { return "touch " + filepath.Join(f.marks, name) }
	return `set -e
d="$1"; cd "$d"
g="$d/.git"
printf '#!/bin/sh\n` + mark("pre-commit") + `\n' > "$g/hooks/pre-commit"
printf '#!/bin/sh\n` + mark("post-commit") + `\n' > "$g/hooks/post-commit"
chmod +x "$g/hooks/pre-commit" "$g/hooks/post-commit"
printf '#!/bin/sh\n` + mark("fsmonitor") + `\nexit 1\n' > "$g/fsmon.sh"; chmod +x "$g/fsmon.sh"
git config core.fsmonitor "$g/fsmon.sh"
printf '* filter=evil\n' > .gitattributes
git config filter.evil.clean '` + mark("filter") + `; cat ` + f.outside + `'
git config filter.evil.smudge cat
printf '#!/bin/sh\n` + mark("gpg") + `\necho >&2; echo "[GNUPG:] SIG_CREATED D 1 8 00 0 X" >&2\necho "-----BEGIN PGP SIGNATURE-----"; echo x; echo "-----END PGP SIGNATURE-----"\n' > "$g/gpg.sh"
chmod +x "$g/gpg.sh"
git config commit.gpgsign true
git config gpg.program "$g/gpg.sh"
git config remote.origin.url ` + f.decoy + `
ln -s ` + f.outside + ` link-to-outside
echo new > edit.txt
echo added > added.txt
rm gone.txt
mkdir sub; echo deep > sub/deep.txt
`
}

func TestAGitRunNeverRunsGitInTheAgentsTree(t *testing.T) {
	f := newGitRunFixture(t)
	f.setAgent(t, theAgent(f))
	res, code := f.run(t)
	if code != 0 || res["ok"] != true {
		t.Errorf("the run failed: code %d, %v", code, res)
	}

	// Nothing the agent set in its .git ran.
	ents, _ := os.ReadDir(f.marks)
	for _, e := range ents {
		t.Errorf("the agent's %s ran as this process", e.Name())
	}
	// The push went to the repository the run was given, not the one the
	// agent named.
	if refs := strings.TrimSpace(testGit(t, f.decoy, "for-each-ref")); refs != "" {
		t.Errorf("the push went to the agent's remote: %s", refs)
	}
	out, err := exec.Command("git", "--git-dir", f.origin, "rev-parse", "--verify", "-q", "agent-work").Output()
	if err != nil {
		t.Fatalf("the branch is not in the origin: %v", err)
	}
	tip := strings.TrimSpace(string(out))
	if n := strings.TrimSpace(testGit(t, f.origin, "rev-list", "--count", "main.."+tip)); n != "1" {
		t.Errorf("the branch carries %s commits on main, want 1", n)
	}
	// Exactly the agent's file changes: the link is not there, and the outside
	// file's content is in no file of the commit.
	files := strings.Fields(testGit(t, f.origin, "ls-tree", "-r", "--format=%(objectmode) %(path)", tip))
	got := map[string]string{}
	for i := 0; i+1 < len(files); i += 2 {
		got[files[i+1]] = files[i]
	}
	want := map[string]string{".gitattributes": "100644", "added.txt": "100644", "edit.txt": "100644",
		"keep.txt": "100644", "sub/deep.txt": "100644", "tool.sh": "100755"}
	if !sameMap(got, want) {
		t.Errorf("the commit holds %v, want %v", got, want)
	}
	for path := range got {
		body := testGit(t, f.origin, "show", tip+":"+path)
		if strings.Contains(body, gitRunOutsideSecret) {
			t.Errorf("%s in the commit holds the file outside the tree", path)
		}
	}
	for path, body := range map[string]string{"edit.txt": "new\n", "added.txt": "added\n", "keep.txt": "keep\n"} {
		if _, ok := got[path]; ok {
			if b := testGit(t, f.origin, "show", tip+":"+path); b != body {
				t.Errorf("%s = %q, want %q", path, b, body)
			}
		}
	}
	if s, _ := res["worktree_skipped"].([]any); len(s) != 1 || s[0] != "link-to-outside" {
		t.Errorf("left out = %v, want [link-to-outside]", res["worktree_skipped"])
	}
	for _, k := range []string{"branch", "commit", "commit_out"} {
		if _, ok := res[k]; !ok {
			t.Errorf("the result has no %s", k)
		}
	}
	if res["commit"] != tip {
		t.Errorf("the result names commit %v, the branch is at %s", res["commit"], tip)
	}
}

// A link the repository itself holds stays as it is when the agent leaves it
// alone: a run that cannot copy a link must not delete it.
func TestAGitRunKeepsALinkTheRepositoryHolds(t *testing.T) {
	f := newGitRunFixture(t)
	seed := filepath.Join(t.TempDir(), "s")
	testGit(t, "", "clone", "-q", f.origin, seed)
	if err := os.Symlink("keep.txt", filepath.Join(seed, "alias")); err != nil {
		t.Fatal(err)
	}
	testGit(t, seed, "add", "-A")
	testGit(t, seed, "commit", "-q", "-m", "a link")
	testGit(t, seed, "push", "-q", "origin", "main")
	f.setAgent(t, "cd \"$1\" && echo new > edit.txt\n")
	res, code := f.run(t)
	if code != 0 {
		t.Fatalf("the run failed: %v", res)
	}
	if mode := strings.Fields(testGit(t, f.origin, "ls-tree", "agent-work", "alias")); len(mode) == 0 || mode[0] != "120000" {
		t.Errorf("the repository's link is gone from the branch: %v", mode)
	}
	if diff := strings.Fields(testGit(t, f.origin, "diff", "--name-only", "main", "agent-work")); len(diff) != 1 || diff[0] != "edit.txt" {
		t.Errorf("the branch changes %v, want [edit.txt]", diff)
	}
}

// A file far larger than the copy may take (sparse, so it costs nothing to
// make) is refused from its size, before a byte of it is read: the run ends
// at once, pushes nothing, and says why.
func TestAGitRunRefusesATreeLargerThanItCopies(t *testing.T) {
	f := newGitRunFixture(t)
	f.setAgent(t, "cd \"$1\" && truncate -s 64G huge.bin && echo new > edit.txt\n")
	type out struct {
		res  map[string]any
		code int
	}
	ch := make(chan out, 1)
	start := time.Now()
	go func() { r, c := f.run(t); ch <- out{r, c} }()
	var o out
	select {
	case o = <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("a run with a 64 GiB file was still going after 30 s")
	}
	t.Logf("returned in %v", time.Since(start))
	if o.code == 0 || o.res["ok"] != false {
		t.Fatalf("a tree over the cap was pushed: %v", o.res)
	}
	if e, _ := o.res["error"].(string); !strings.Contains(e, "huge.bin") || !strings.Contains(e, "too large") {
		t.Errorf("the error does not say what was too large: %q", e)
	}
	if err := exec.Command("git", "--git-dir", f.origin, "rev-parse", "--verify", "-q", "agent-work").Run(); err == nil {
		t.Error("the branch was pushed")
	}
}

// The tree a worktree run returns is refused the same way, and no part of
// it is returned.
func TestAWorktreeRunRefusesATreeLargerThanTheLaneCarries(t *testing.T) {
	f := newGitRunFixture(t)
	f.setAgent(t, "cd \"$1\" && truncate -s 64G huge.bin\n")
	ch := make(chan []byte, 1)
	start := time.Now()
	go func() {
		b, _ := runWorktree(harnessSpec{Mode: "worktree", HarnessID: "h1", Image: "harness:test", MaxMinutes: 1})
		ch <- b
	}()
	var b []byte
	select {
	case b = <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("a run with a 64 GiB file was still going after 30 s")
	}
	t.Logf("returned in %v", time.Since(start))
	var res map[string]any
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false || res["worktree_b64"] != nil {
		t.Fatalf("a tree over the cap was returned: ok=%v, %d bytes of tree", res["ok"], len(b))
	}
	if e, _ := res["error"].(string); !strings.Contains(e, "huge.bin") || !strings.Contains(e, "too large") {
		t.Errorf("the error does not say what was too large: %q", e)
	}
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	ka := make([]string, 0, len(a))
	for k := range a {
		ka = append(ka, k)
	}
	sort.Strings(ka)
	for _, k := range ka {
		if b[k] != a[k] {
			return false
		}
	}
	return true
}

// A repository with no commit yet gets the run's commit as its first.
func TestAGitRunIntoAnEmptyRepositoryPushesItsFirstCommit(t *testing.T) {
	f := newGitRunFixture(t)
	empty := filepath.Join(t.TempDir(), "empty.git")
	testGit(t, "", "init", "-q", "--bare", "-b", "main", empty)
	f.setAgent(t, "cd \"$1\" && echo first > first.txt\n")
	b, code := runGit(harnessSpec{Mode: "git", HarnessID: "h1", Image: "harness:test",
		RepoURL: empty, Branch: "agent-work", MaxMinutes: 1})
	if code != 0 {
		t.Fatalf("the run failed: %s", b)
	}
	if got := testGit(t, empty, "show", "agent-work:first.txt"); got != "first\n" {
		t.Errorf("first.txt = %q", got)
	}
}
