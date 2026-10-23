package main

// A harness run's tree is bind-mounted into the container at /work and opened
// to every user, because the agent runs as a uid of its own. What keeps the
// other users of this machine out of it is the folder it sits in, which only
// this process can enter. Opening the tree follows no link in it.

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// harnessStandIn writes a stand-in container runtime named name into a new
// folder. On `ps` and `pull` it succeeds; on `run` it records, into the
// returned file, the mode and owner of the folder the /work tree sits in, then
// fails, so the run stops there.
func harnessStandIn(t *testing.T, name string) (bin, record string) {
	t.Helper()
	bin = t.TempDir()
	record = filepath.Join(bin, "record")
	script := "#!/bin/sh\ncase \"$1\" in ps|pull) exit 0;; run) ;; *) exit 1;; esac\n" +
		"for a; do case \"$a\" in *:/work) d=${a%:/work};; esac; done\n" +
		"[ -n \"$d\" ] && stat -c '%a %u' \"$(dirname \"$d\")\" > " + record + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, record
}

func TestAWorktreeRunsTreeSitsInAFolderOnlyTheBastionCanEnter(t *testing.T) {
	bin, record := harnessStandIn(t, "docker")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	// The temporary folder every user may write in, as /tmp is.
	shared := t.TempDir()
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", shared)

	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	_ = tw.WriteHeader(&tar.Header{Name: "src/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "src/a.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	_, _ = tw.Write([]byte("a\n"))
	_ = tw.Close()
	spec := harnessSpec{Mode: "worktree", HarnessID: "h1", Image: "harness:test",
		WorktreeB64: base64.StdEncoding.EncodeToString(tb.Bytes())}
	if _, code := runWorktree(spec); code == 0 {
		t.Fatal("the stand-in runtime fails the start; the run must report it")
	}
	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the tree was not mounted: %v", err)
	}
	if want := "700 " + strconv.Itoa(os.Geteuid()); strings.TrimSpace(string(got)) != want {
		t.Fatalf("the folder the tree sits in: want %q, got %q", want, strings.TrimSpace(string(got)))
	}
}

func TestOpeningARunsTreeFollowsNoLinkAndKeepsWhatIsExecutable(t *testing.T) {
	bin, _ := harnessStandIn(t, "runtime")
	rt := filepath.Join(bin, "runtime")
	outside := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(outside, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := t.TempDir()
	files := map[string]os.FileMode{"run.sh": 0o755, "notes.txt": 0o644}
	for name, mode := range files {
		if err := os.WriteFile(filepath.Join(tree, name), nil, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tree, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := driveHarnessAgent(rt, tree, harnessSpec{HarnessID: "h1", Image: "harness:test"}, 1); err == nil {
		t.Fatal("the stand-in runtime fails the start; the run must report it")
	}
	for p, want := range map[string]os.FileMode{
		tree: 0o777, filepath.Join(tree, "sub"): 0o777,
		filepath.Join(tree, "run.sh"): 0o777, filepath.Join(tree, "notes.txt"): 0o666,
		outside: 0o600,
	} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: want %04o, got %04o", p, want, fi.Mode().Perm())
		}
	}
}

func TestARunsTreeInAFolderOtherUsersCanEnterIsRefused(t *testing.T) {
	bin, record := harnessStandIn(t, "runtime")
	rt := filepath.Join(bin, "runtime")
	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(open, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := driveHarnessAgent(rt, tree, harnessSpec{HarnessID: "h1", Image: "harness:test"}, 1)
	if err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Fatalf("want the tree refused for its folder, got %v", err)
	}
	if _, err := os.Stat(record); err == nil {
		t.Fatal("a refused tree must start no container")
	}
	if fi, _ := os.Stat(tree); fi.Mode().Perm() != 0o755 {
		t.Fatalf("a refused tree must not be opened: %04o", fi.Mode().Perm())
	}
}
