package main

// What a git run hands the agent, how it ends when its commit cannot be made,
// and the git-lfs filter it supplies itself.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const gitRunToken = "tok3n0f7hisrun5a1e"

// The agent's clone names the repository without the run's token, and the
// token is in no file of the tree it is handed; the run still pushes.
func TestAGitRunHandsTheAgentNoToken(t *testing.T) {
	f := newGitRunFixture(t)
	snap := filepath.Join(t.TempDir(), "agent-saw")
	f.setAgent(t, "cp -a \"$1\" "+snap+" && cd \"$1\" && echo new > edit.txt\n")
	b, code := runGit(harnessSpec{Mode: "git", HarnessID: "h1", Image: "harness:test",
		RepoURL: "file://harness:" + gitRunToken + "@" + f.origin, Branch: "agent-work", MaxMinutes: 1})
	if code != 0 {
		t.Fatalf("the run failed: %s", b)
	}
	if bytes.Contains(b, []byte(gitRunToken)) {
		t.Errorf("the result carries the token: %s", b)
	}
	n := 0
	err := filepath.WalkDir(snap, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		n++
		body, err := os.ReadFile(p)
		if err == nil && bytes.Contains(body, []byte(gitRunToken)) {
			t.Errorf("the token is in the agent's tree, in %s", p[len(snap):])
		}
		return err
	})
	if err != nil || n == 0 {
		t.Fatalf("the agent's tree was not read (%d files): %v", n, err)
	}
	if got := testGit(t, f.origin, "show", "agent-work:edit.txt"); got != "new\n" {
		t.Errorf("edit.txt = %q", got)
	}
}

func TestRepoURLPartsAndLFSPins(t *testing.T) {
	bare, secret, err := repoURLParts("https://host-user:" + gitRunToken + "@git.example.invalid/o/r.git")
	if err != nil || bare != "https://git.example.invalid/o/r.git" || secret != gitRunToken {
		t.Errorf("parts = %q, %q, %v", bare, secret, err)
	}
	if bare, secret, err := repoURLParts("/srv/x/origin.git"); err != nil || bare != "/srv/x/origin.git" || secret != "" {
		t.Errorf("a path = %q, %q, %v", bare, secret, err)
	}
	pins := strings.Join(lfsEndpointPins("https://u:"+gitRunToken+"@git.example.invalid/o/r"), " ")
	for _, k := range []string{"lfs.url", "lfs.pushurl", "remote.origin.lfsurl", "remote.origin.lfspushurl"} {
		if !strings.Contains(pins, k+"=https://u:"+gitRunToken+"@git.example.invalid/o/r.git/info/lfs") {
			t.Errorf("%s is not pinned to the repository's own LFS address: %s", k, pins)
		}
	}
	if p := lfsEndpointPins("/srv/x/origin.git"); p != nil {
		t.Errorf("a path got pins: %v", p)
	}
}

// standInGit puts a git on PATH that fails on the subcommand fail and is the
// real git otherwise.
func standInGit(t *testing.T, fail string) {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nfor a; do [ \"$a\" = " + fail + " ] && { echo 'stand-in: " + fail + " failed' >&2; exit 128; }; done\nexec " + real + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func branchPushed(f gitRunFixture) bool {
	return exec.Command("git", "--git-dir", f.origin, "rev-parse", "--verify", "-q", "agent-work").Run() == nil
}

// A commit that fails is the run failing: nothing is pushed.
func TestAGitRunWhoseCommitFailsPushesNothing(t *testing.T) {
	f := newGitRunFixture(t)
	f.setAgent(t, "cd \"$1\" && echo new > edit.txt\n")
	standInGit(t, "commit")
	res, code := f.run(t)
	if code == 0 || res["ok"] != false {
		t.Errorf("a run whose commit failed reads ok: code %d, %v", code, res)
	}
	if e, _ := res["error"].(string); !strings.Contains(e, "commit") || !strings.Contains(e, "nothing was pushed") {
		t.Errorf("the error does not say the commit failed: %q", e)
	}
	if branchPushed(f) {
		t.Error("the branch was pushed")
	}
}

// A run that changed nothing is ok, says so, and pushes no branch.
func TestAGitRunThatChangesNothingPushesNothing(t *testing.T) {
	f := newGitRunFixture(t)
	f.setAgent(t, "true\n")
	res, code := f.run(t)
	if code != 0 || res["ok"] != true || res["changed"] != false {
		t.Errorf("want ok with changed false: code %d, %v", code, res)
	}
	if _, ok := res["branch"]; ok {
		t.Errorf("the result names a branch: %v", res["branch"])
	}
	if branchPushed(f) {
		t.Error("a branch was pushed for a run that changed nothing")
	}
}

// Names a file system may open as .git are left out of the copy, and the
// rest of the run goes on.
func TestAGitRunLeavesOutEveryNameThatOpensAsDotGit(t *testing.T) {
	f := newGitRunFixture(t)
	names := []string{".git.", ".GIT  ", "git~1", "GIT~1. ", ".g\u200cit", ".git::$INDEX_ALLOCATION"}
	script := "cd \"$1\" && echo new > edit.txt\n"
	for _, n := range names {
		script += "mkdir '" + n + "' && echo '[core]' > '" + n + "/config'\n"
	}
	f.setAgent(t, script)
	res, code := f.run(t)
	if code != 0 || res["ok"] != true {
		t.Fatalf("the run failed: code %d, %v", code, res)
	}
	files := testGit(t, f.origin, "ls-tree", "-r", "--name-only", "-z", "agent-work")
	for _, n := range names {
		if strings.Contains(files, n+"/") {
			t.Errorf("%q is in the commit", n)
		}
	}
	skipped, _ := res["worktree_skipped"].([]any)
	listed := map[string]bool{}
	for _, s := range skipped {
		listed[fmt.Sprint(s)] = true
	}
	for _, n := range names {
		if !listed[n] {
			t.Errorf("%q is not listed as left out: %v", n, skipped)
		}
	}
	for _, n := range []string{".git", ".Git", ".git.", ".git . .", "GiT~1", ".gi\ufefft", ".git:x"} {
		if !dotGitName(n) {
			t.Errorf("dotGitName(%q) = false", n)
		}
	}
	for _, n := range []string{".gitignore", ".gitattributes", "git", ".github", "git~2", "x.git"} {
		if dotGitName(n) {
			t.Errorf("dotGitName(%q) = true", n)
		}
	}
}

// With git-lfs installed, the bastion's own git calls clean and smudge
// through it and push its objects; the agent's .git cannot replace it, and a
// filter of another name the agent's .gitattributes names runs nothing.
func TestAGitRunUsesTheLFSFilterOnlyFromThisProcess(t *testing.T) {
	f := newGitRunFixture(t)
	seed := filepath.Join(t.TempDir(), "s")
	testGit(t, "", "clone", "-q", f.origin, seed)
	if err := os.WriteFile(filepath.Join(seed, ".gitattributes"), []byte("*.bin filter=lfs -text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed, "big.bin"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, seed, "add", "-A")
	testGit(t, seed, "commit", "-q", "-m", "lfs")
	testGit(t, seed, "push", "-q", "origin", "main")

	bin := t.TempDir()
	lfsLog := filepath.Join(t.TempDir(), "lfs.log")
	wrapper := "#!/bin/sh\nGO_HELPER_GITLFS=1 GO_HELPER_GITLFS_LOG=" + lfsLog + " exec " + os.Args[0] +
		" -test.run='^TestHelperGitLFS$' -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git-lfs"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	mark := func(name string) string { return "touch " + filepath.Join(f.marks, name) }
	f.setAgent(t, `set -e
cd "$1"
git config filter.lfs.process '`+mark("agent-lfs-process")+`; exit 1'
git config filter.lfs.clean '`+mark("agent-lfs-clean")+`; cat'
git config filter.evil.clean '`+mark("evil")+`; cat'
printf '*.bin filter=lfs -text\n*.txt filter=evil\n' > .gitattributes
echo v2 > big.bin
echo new > edit.txt
`)
	res, code := f.run(t)
	if code != 0 || res["ok"] != true {
		t.Fatalf("the run failed: code %d, %v", code, res)
	}
	ents, _ := os.ReadDir(f.marks)
	for _, e := range ents {
		t.Errorf("the agent's %s ran as this process", e.Name())
	}
	logged, _ := os.ReadFile(lfsLog)
	for _, want := range []string{"smudge big.bin", "clean big.bin", "push origin agent-work"} {
		if !strings.Contains(string(logged), want+"\n") {
			t.Errorf("git-lfs did not %s; it logged:\n%s", want, logged)
		}
	}
	for _, line := range strings.Split(string(logged), "\n") {
		if strings.HasSuffix(line, ".txt") {
			t.Errorf("git-lfs ran for a file of another filter: %s", line)
		}
	}
	if got := testGit(t, f.origin, "show", "agent-work:big.bin"); got != "v2\n" {
		t.Errorf("big.bin = %q", got)
	}
}

// TestHelperGitLFS is the stand-in git-lfs: run by the wrapper above, it is
// an identity filter that logs what it was asked to do.
func TestHelperGitLFS(t *testing.T) {
	if os.Getenv("GO_HELPER_GITLFS") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	logf, err := os.OpenFile(os.Getenv("GO_HELPER_GITLFS_LOG"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		os.Exit(2)
	}
	switch {
	case len(args) > 0 && args[0] == "filter-process":
		if err := helperFilterProcess(logf); err != nil {
			fmt.Fprintln(os.Stderr, "stand-in git-lfs:", err)
			os.Exit(1)
		}
	case len(args) > 0 && (args[0] == "clean" || args[0] == "smudge"):
		fmt.Fprintf(logf, "%s %s\n", args[0], args[len(args)-1])
		_, _ = io.Copy(os.Stdout, os.Stdin)
	default:
		fmt.Fprintln(logf, strings.Join(args, " "))
	}
	logf.Close()
	os.Exit(0)
}

func pktRead(r *bufio.Reader) ([]byte, bool, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, false, err
	}
	n, err := strconv.ParseUint(string(h[:]), 16, 16)
	if err != nil {
		return nil, false, err
	}
	if n == 0 {
		return nil, true, nil
	}
	b := make([]byte, n-4)
	_, err = io.ReadFull(r, b)
	return b, false, err
}

func pktList(r *bufio.Reader) ([]string, error) {
	var out []string
	for {
		b, flush, err := pktRead(r)
		if err != nil || flush {
			return out, err
		}
		out = append(out, strings.TrimSuffix(string(b), "\n"))
	}
}

func pktWrite(w io.Writer, lines ...string) {
	for _, l := range lines {
		fmt.Fprintf(w, "%04x%s", len(l)+4, l)
	}
	_, _ = w.Write([]byte("0000"))
}

// helperFilterProcess speaks git's long-running filter protocol, version 2,
// returning every file as it came.
func helperFilterProcess(logf io.Writer) error {
	r, w := bufio.NewReader(os.Stdin), bufio.NewWriter(os.Stdout)
	if _, err := pktList(r); err != nil {
		return err
	}
	pktWrite(w, "git-filter-server\n", "version=2\n")
	if err := w.Flush(); err != nil {
		return err
	}
	if _, err := pktList(r); err != nil {
		return err
	}
	pktWrite(w, "capability=clean\n", "capability=smudge\n")
	if err := w.Flush(); err != nil {
		return err
	}
	for {
		head, err := pktList(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		cmd, path := "", ""
		for _, kv := range head {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "command":
				cmd = v
			case "pathname":
				path = v
			}
		}
		var body bytes.Buffer
		for {
			b, flush, err := pktRead(r)
			if err != nil {
				return err
			}
			if flush {
				break
			}
			body.Write(b)
		}
		fmt.Fprintf(logf, "%s %s\n", cmd, path)
		pktWrite(w, "status=success\n")
		data := body.Bytes()
		for len(data) > 0 {
			n := min(len(data), 65516)
			fmt.Fprintf(w, "%04x", n+4)
			_, _ = w.Write(data[:n])
			data = data[n:]
		}
		_, _ = w.Write([]byte("0000"))
		pktWrite(w)
		if err := w.Flush(); err != nil {
			return err
		}
	}
}
