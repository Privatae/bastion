package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── k8s.set_image, against a stand-in kubectl ───────────────────────────────

type fakeKube struct {
	containers map[string]string // container -> image
	calls      [][]string
	failSet    bool
}

func (f *fakeKube) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, args)
	switch {
	case len(args) >= 3 && args[2] == "get":
		type c struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		}
		var cs []c
		for n, im := range f.containers {
			cs = append(cs, c{n, im})
		}
		raw, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": cs}}}})
		return string(raw), nil
	case len(args) >= 3 && args[2] == "set":
		if f.failSet {
			return "boom", errors.New("exit 1")
		}
		// set image <workload> <container>=<ref>: the workload now runs it.
		if len(args) >= 6 {
			if c, ref, ok := strings.Cut(args[5], "="); ok {
				f.containers[c] = ref
			}
		}
		return "", nil
	}
	return "", nil
}

func (f *fakeKube) sets() [][]string {
	var out [][]string
	for _, c := range f.calls {
		if len(c) >= 3 && c[2] == "set" {
			out = append(out, c)
		}
	}
	return out
}

func useFakeKube(t *testing.T, f *fakeKube) {
	prev := opKubectl
	opKubectl = f.run
	t.Cleanup(func() { opKubectl = prev })
}

func useAncestry(t *testing.T, fn func(source, older, newer string, env []string) error) {
	prev := opAncestry
	opAncestry = fn
	t.Cleanup(func() { opAncestry = prev })
}

const tImage = "forge.example.com/acme/web"
const tRepo = "https://forge.example.com/acme/app.git"

func setImageLine(digest string) opVerbLine {
	return opVerbLine{Verb: "k8s.set_image", Args: map[string]string{"namespace": "ds", "kind": "deployment",
		"name": "bridge", "container": "bridge", "image": tImage, "digest": digest, "repo": tRepo}}
}

func issueReceiptFrom(t *testing.T, digest, source, commit string) {
	t.Helper()
	if _, err := opIssueReceipts("r", "bridge-build", strings.Repeat("e", 64), "{}", []opResultImage{{Image: tImage,
		Digest: digest, Source: source, Commit: commit}}); err != nil {
		t.Fatal(err)
	}
}

func issueReceipt(t *testing.T, digest, commit string) { issueReceiptFrom(t, digest, tRepo, commit) }

// The gate's workload cases: only the named container of the named workload
// is changed, only to a digest this machine holds a receipt for, only forward
// from a live image it has a record of.
func TestSetImageTouchesOnlyTheNamedContainerAndOnlyForward(t *testing.T) {
	setupBox(t)
	live := "sha256:" + strings.Repeat("1", 64)
	next := "sha256:" + strings.Repeat("2", 64)
	unknown := "sha256:" + strings.Repeat("3", 64)
	foreign := "sha256:" + strings.Repeat("4", 64)
	oldC, newC := strings.Repeat("a", 40), strings.Repeat("b", 40)
	issueReceipt(t, live, oldC)
	issueReceipt(t, next, newC)
	issueReceiptFrom(t, foreign, "https://forge.example.com/someone/else.git", newC)
	ctx := context.Background()

	// A digest without a receipt: refused at the plan, nothing set.
	f := &fakeKube{containers: map[string]string{"bridge": tImage + "@" + live, "sidecar": "other@" + live}}
	useFakeKube(t, f)
	useAncestry(t, func(_, _, _ string, _ []string) error { return nil })
	if _, err := opImagePlan(ctx, setImageLine(unknown), nil); err == nil || !strings.Contains(err.Error(), "no receipt") {
		t.Fatalf("a digest without a receipt: %v", err)
	}
	if _, err := opImageDo(ctx, setImageLine(unknown), nil, nil, ""); err == nil || len(f.sets()) != 0 {
		t.Fatalf("and never set: %v %v", err, f.sets())
	}
	// A container the workload does not have: refused, nothing set.
	other := setImageLine(next)
	other.Args["container"] = "nope"
	if _, err := opImageDo(ctx, other, nil, nil, ""); err == nil || !strings.Contains(err.Error(), "no container nope") || len(f.sets()) != 0 {
		t.Fatalf("a container that is not there: %v", err)
	}
	// A receipt that names another repository than the manifest's: refused
	// (the ancestry check would fetch whatever the receipt said).
	if _, err := opImagePlan(ctx, setImageLine(foreign), nil); err == nil || !strings.Contains(err.Error(), "says it was built from") {
		t.Fatalf("a receipt from another repository: %v", err)
	}
	// A live image this machine holds a receipt for but never rolled: no
	// record, so it asks — a receipt alone never makes an image "live".
	if _, err := opImageDo(ctx, setImageLine(next), nil, nil, ""); err == nil || !strings.Contains(err.Error(), "no record of the commit behind the live image") {
		t.Fatalf("a live image this machine never rolled: %v", err)
	}
	if err := opRecordRoll(live, opRollRec{Image: tImage, Source: tRepo, Commit: oldC}); err != nil {
		t.Fatal(err)
	}
	// A live image this machine has no record of: refused, and it says so.
	f.containers["bridge"] = tImage + "@" + unknown
	if _, err := opImageDo(ctx, setImageLine(next), nil, nil, ""); err == nil || !strings.Contains(err.Error(), "no record of the commit behind the live image") {
		t.Fatalf("an unknown live image: %v", err)
	}
	f.containers["bridge"] = tImage + ":latest"
	if _, err := opImageDo(ctx, setImageLine(next), nil, nil, ""); err == nil || !strings.Contains(err.Error(), "no record") {
		t.Fatalf("a live image by tag: %v", err)
	}
	// A workload running another image: refused.
	f.containers["bridge"] = "forge.example.com/acme/other@" + live
	if _, err := opImageDo(ctx, setImageLine(next), nil, nil, ""); err == nil || !strings.Contains(err.Error(), "runs forge.example.com/acme/other") {
		t.Fatalf("another image: %v", err)
	}
	// Backwards: refused by the ancestry check, nothing set.
	f.containers["bridge"] = tImage + "@" + live
	useAncestry(t, func(_, older, newer string, _ []string) error {
		return fmt.Errorf("the new image's commit %s does not descend from the live image's %s", newer, older)
	})
	if _, err := opImageDo(ctx, setImageLine(next), nil, nil, ""); err == nil || !strings.Contains(err.Error(), "does not descend") || len(f.sets()) != 0 {
		t.Fatalf("backwards: %v", err)
	}
	// Forward: exactly one set, of the named container, then the rollout.
	var asked []string
	useAncestry(t, func(source, older, newer string, _ []string) error {
		asked = []string{source, older, newer}
		return nil
	})
	f.calls = nil
	note, err := opImageDo(ctx, setImageLine(next), nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(asked, " ") != "https://forge.example.com/acme/app.git "+oldC+" "+newC {
		t.Fatalf("ancestry was asked of the receipts' commits: %v", asked)
	}
	sets := f.sets()
	if len(sets) != 1 || strings.Join(sets[0], " ") != "-n ds set image deployment/bridge bridge="+tImage+"@"+next {
		t.Fatalf("one set of the named container: %v", sets)
	}
	if last := f.calls[len(f.calls)-1]; strings.Join(last[:4], " ") != "-n ds rollout status" {
		t.Fatalf("then the rollout is waited on: %v", last)
	}
	if _, _, c, ok := opRolledCommit(next); !ok || c != newC || !strings.Contains(note, "rolled out") {
		t.Fatal("the roll is recorded, so the next roll knows what is live")
	}
	// The same digest again: nothing is set, and the rollout is still waited
	// on — a set image is not a rolled-out one (a retry after a rollout that
	// did not finish lands here).
	f.containers["bridge"] = tImage + "@" + next
	f.calls = nil
	if note, err := opImageDo(ctx, setImageLine(next), nil, nil, ""); err != nil || note != "already live, rolled out" || len(f.sets()) != 0 {
		t.Fatalf("already live: %q %v", note, err)
	}
	if last := f.calls[len(f.calls)-1]; len(last) < 4 || last[2] != "rollout" || last[3] != "status" {
		t.Fatalf("an image already set still waits for its rollout: %v", f.calls)
	}
	prev := opKubectl
	opKubectl = func(ctx context.Context, args ...string) (string, error) {
		if len(args) >= 3 && args[2] == "rollout" {
			return "timed out", errors.New("exit 1")
		}
		return f.run(ctx, args...)
	}
	defer func() { opKubectl = prev }()
	if _, err := opImageDo(ctx, setImageLine(next), nil, nil, ""); err == nil || !strings.Contains(err.Error(), "rollout did not finish") {
		t.Fatalf("an image already set whose rollout does not finish: %v", err)
	}
}

// ── unit verbs and log checks, against stand-ins ────────────────────────────

func TestUnitVerbsRestartTheNamedUnitAndCheckItCameBack(t *testing.T) {
	var calls [][]string
	state := map[string]string{"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "42"}
	prev := opSystemctl
	opSystemctl = func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		if args[0] == "show" {
			var b strings.Builder
			for k, v := range state {
				fmt.Fprintf(&b, "%s=%s\n", k, v)
			}
			return b.String(), nil
		}
		return "", nil
	}
	t.Cleanup(func() { opSystemctl = prev })
	ctx := context.Background()
	v := opVerbLine{Verb: "unit.restart", Args: map[string]string{"unit": "app.service"}}
	c, err := opUnitPlan(ctx, v)
	if err != nil || c.Note != "active/running → restarted" {
		t.Fatalf("plan: %+v %v", c, err)
	}
	if _, err := opUnitDo(ctx, v); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls[len(calls)-2], " ") != "restart app.service" {
		t.Fatalf("restart of the named unit only: %v", calls)
	}
	state["ActiveState"], state["SubState"] = "failed", "failed"
	if _, err := opUnitDo(ctx, v); err == nil || !strings.Contains(err.Error(), "failed/failed") {
		t.Fatalf("a unit that did not come back fails the verb: %v", err)
	}
	state["LoadState"] = "not-found"
	if _, err := opUnitPlan(ctx, v); err == nil || !strings.Contains(err.Error(), "not a unit") {
		t.Fatalf("a unit that is not there: %v", err)
	}
}

func TestLogsCheckGivesAVerdictAndOneLine(t *testing.T) {
	var since []string
	prev := opJournalctl
	opJournalctl = func(_ context.Context, args ...string) (string, error) {
		since = args
		return "starting\nconnected to db password=hunter2\nTraceback (most recent call last)\nready\n", nil
	}
	t.Cleanup(func() { opJournalctl = prev })
	at := time.Unix(1700000000, 0)
	ok, line, err := opLogsCheck(context.Background(), opVerbLine{Verb: opVerbLogs, Args: map[string]string{"unit": "a.service", "must": "^ready$"}}, at)
	if err != nil || !ok || line != "ready" {
		t.Fatalf("must: %v %q %v", ok, line, err)
	}
	if strings.Join(since[:4], " ") != "-u a.service --since @1700000000" {
		t.Fatalf("only what came after the apply began: %v", since)
	}
	ok, line, _ = opLogsCheck(context.Background(), opVerbLine{Verb: opVerbLogs, Args: map[string]string{"unit": "a.service", "must_not": "Traceback"}}, at)
	if ok || !strings.Contains(line, "Traceback (most recent") || strings.Contains(line, "hunter2") {
		t.Fatalf("must_not reports the one line that decided it, nothing else: %v %q", ok, line)
	}
	ok, line, _ = opLogsCheck(context.Background(), opVerbLine{Verb: opVerbLogs, Args: map[string]string{"unit": "a.service", "must": "never"}}, at)
	if ok || line != "no line showed /never/" {
		t.Fatalf("a must that never showed: %v %q", ok, line)
	}
}

// ── tree.checkout, against real repositories ────────────────────────────────

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func useFileRepos(t *testing.T) {
	prevP, prevR := opTreeProtocols, opRepoURLOK
	opTreeProtocols = []string{"file"}
	opRepoURLOK = func(s string) error {
		if !strings.HasPrefix(s, "file:///") {
			return errors.New("not a test repo")
		}
		return nil
	}
	t.Cleanup(func() { opTreeProtocols, opRepoURLOK = prevP, prevR })
}

// A tree moves forward to the exact commit, with no hook of its own running,
// leaves untracked files and nested repositories alone, and refuses to go
// back, to move with local changes, or to run git under a config that could
// run a program.
func TestTreeCheckoutMovesOnlyForward(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: the op moves only a tree root owns, and the fixtures are made by this user")
	}
	setupBox(t)
	useFileRepos(t)
	base := t.TempDir()
	origin := filepath.Join(base, "origin")
	_ = os.MkdirAll(origin, 0o755)
	gitT(t, origin, "init", "-q")
	_ = os.WriteFile(filepath.Join(origin, "a.txt"), []byte("one\n"), 0o644)
	gitT(t, origin, "add", "a.txt")
	gitT(t, origin, "commit", "-qm", "one")
	c1 := gitT(t, origin, "rev-parse", "HEAD")
	tree := filepath.Join(base, "tree")
	gitT(t, base, "clone", "-q", "file://"+origin, tree)
	nested := filepath.Join(origin, "nested")
	_ = os.MkdirAll(nested, 0o755)
	gitT(t, nested, "init", "-q")
	gitT(t, nested, "commit", "-q", "--allow-empty", "-m", "n")
	gitT(t, origin, "add", "nested")
	_ = os.WriteFile(filepath.Join(origin, "a.txt"), []byte("two\n"), 0o644)
	gitT(t, origin, "commit", "-qam", "two")
	c2 := gitT(t, origin, "rev-parse", "HEAD")
	gitT(t, origin, "checkout", "-q", "-b", "side", c1)
	_ = os.WriteFile(filepath.Join(origin, "b.txt"), []byte("side\n"), 0o644)
	gitT(t, origin, "add", "b.txt")
	gitT(t, origin, "commit", "-qm", "side")
	side := gitT(t, origin, "rev-parse", "HEAD")
	gitT(t, origin, "checkout", "-q", "main")
	// A hook planted in the tree must not run as root.
	marker := filepath.Join(base, "hook-ran")
	_ = os.WriteFile(filepath.Join(tree, ".git/hooks/post-merge"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)
	_ = os.WriteFile(filepath.Join(tree, "untracked.log"), []byte("keep\n"), 0o644)

	line := func(commit string) opVerbLine {
		return opVerbLine{Verb: "tree.checkout", Args: map[string]string{"path": tree, "repo": "file://" + origin, "commit": commit}}
	}
	ctx := context.Background()
	if c, err := opTreePlan(ctx, line(c2)); err != nil || c.Note != c1+" → "+c2 {
		t.Fatalf("plan: %+v %v", c, err)
	}
	note, err := opTreeDo(ctx, line(c2), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if gitT(t, tree, "rev-parse", "HEAD") != c2 || !strings.Contains(note, "nested") {
		t.Fatalf("moved to %s and named the nested repository: %q", c2, note)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the tree's own hook ran")
	}
	if b, _ := os.ReadFile(filepath.Join(tree, "untracked.log")); string(b) != "keep\n" {
		t.Fatal("an untracked file was touched")
	}
	// Backwards and sideways: refused, the tree stays.
	for _, bad := range []string{c1, side} {
		if _, err := opTreeDo(ctx, line(bad), nil, ""); err == nil || !strings.Contains(err.Error(), "only moves forward") {
			t.Fatalf("%s: %v", bad, err)
		}
		if _, err := opTreePlan(ctx, line(bad)); err == nil {
			t.Fatalf("the plan refuses %s already, the commit being here", bad)
		}
	}
	if gitT(t, tree, "rev-parse", "HEAD") != c2 {
		t.Fatal("the tree moved on a refusal")
	}
	// Another origin: refused.
	wrong := line(c2)
	wrong.Args["repo"] = "file://" + base + "/elsewhere"
	if _, err := opTreePlan(ctx, wrong); err == nil || !strings.Contains(err.Error(), "origin is not") {
		t.Fatalf("another origin: %v", err)
	}
	// A local change to a tracked file: refused.
	_ = os.WriteFile(filepath.Join(tree, "a.txt"), []byte("local\n"), 0o644)
	if _, err := opTreePlan(ctx, line(c2)); err == nil || !strings.Contains(err.Error(), "local changes") {
		t.Fatalf("local changes: %v", err)
	}
	gitT(t, tree, "checkout", "-q", "--", "a.txt")
	// A config that runs a program when git does: refused by name.
	for _, kv := range [][2]string{{"core.fsmonitor", "touch " + marker}, {"filter.x.smudge", "touch " + marker}, {"core.worktree", "/etc"}, {"include.path", "/nonexistent/privatae-optest.inc"}} {
		gitT(t, tree, "config", kv[0], kv[1])
		if _, err := opTreePlan(ctx, line(c2)); err == nil || !strings.Contains(err.Error(), "will not run git under") {
			t.Fatalf("%s: %v", kv[0], err)
		}
		gitT(t, tree, "config", "--unset", kv[0])
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a configured program ran")
	}
}

// twoCommitRepo makes an origin with two commits and a clone at the first.
// before runs in the origin before the first commit, after before the second.
func twoCommitRepo(t *testing.T, before, after func(origin string)) (origin, tree, c1, c2 string) {
	t.Helper()
	base := t.TempDir()
	origin = filepath.Join(base, "origin")
	_ = os.MkdirAll(origin, 0o755)
	gitT(t, origin, "init", "-q")
	_ = os.WriteFile(filepath.Join(origin, "a.txt"), []byte("one\n"), 0o644)
	before(origin)
	gitT(t, origin, "add", "-A")
	gitT(t, origin, "commit", "-qm", "one")
	c1 = gitT(t, origin, "rev-parse", "HEAD")
	tree = filepath.Join(base, "tree")
	gitT(t, base, "clone", "-q", "file://"+origin, tree)
	after(origin)
	gitT(t, origin, "commit", "-qam", "two")
	c2 = gitT(t, origin, "rev-parse", "HEAD")
	return origin, tree, c1, c2
}

// Git runs as root only in a tree no one else controls: a tree, .git or
// config another user owns or can write is refused before git runs there.
// And a move never overwrites an ignored file the machine keeps (a .env).
func TestTreeCheckoutRefusesATreeRootDoesNotControlAndKeepsIgnoredFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to own and hand over the fixtures")
	}
	setupBox(t)
	useFileRepos(t)
	origin, tree, _, c2 := twoCommitRepo(t, func(o string) {
		_ = os.WriteFile(filepath.Join(o, ".gitignore"), []byte(".env\n"), 0o644)
	}, func(o string) {
		_ = os.WriteFile(filepath.Join(o, ".env"), []byte("FROM-REPO\n"), 0o644)
		gitT(t, o, "add", "-f", ".env")
		_ = os.WriteFile(filepath.Join(o, "a.txt"), []byte("two\n"), 0o644)
	})
	line := opVerbLine{Verb: "tree.checkout", Args: map[string]string{"path": tree, "repo": "file://" + origin, "commit": c2}}
	ctx := context.Background()
	for _, c := range []struct {
		what  string
		apply func()
		undo  func()
		want  string
	}{
		{"a tree another user owns", func() { _ = os.Chown(tree, 65534, 65534) }, func() { _ = os.Chown(tree, 0, 0) }, "is not root's"},
		{"a .git another user owns", func() { _ = os.Chown(tree+"/.git", 65534, 0) }, func() { _ = os.Chown(tree+"/.git", 0, 0) }, "is not root's"},
		{"a ref deep in .git another user owns", func() { _ = os.Chown(tree+"/.git/HEAD", 65534, 0) }, func() { _ = os.Chown(tree+"/.git/HEAD", 0, 0) }, "is not root's"},
		{"a config anyone can write", func() { _ = os.Chmod(tree+"/.git/config", 0o666) }, func() { _ = os.Chmod(tree+"/.git/config", 0o644) }, "written by anyone"},
		{"a config another group can write", func() {
			_ = os.Chown(tree+"/.git/config", 0, 65534)
			_ = os.Chmod(tree+"/.git/config", 0o664)
		}, func() {
			_ = os.Chown(tree+"/.git/config", 0, 0)
			_ = os.Chmod(tree+"/.git/config", 0o644)
		}, "group other than root's"},
	} {
		c.apply()
		if _, err := opTreePlan(ctx, line); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.what, c.want, err)
		}
		if _, err := opTreeDo(ctx, line, nil, ""); err == nil {
			t.Errorf("%s: the move ran", c.what)
		}
		c.undo()
	}
	// The machine's own ignored .env, which the target commit starts to
	// track: the move is refused and the file is untouched.
	_ = os.WriteFile(filepath.Join(tree, ".env"), []byte("LOCAL-SECRET\n"), 0o600)
	if _, err := opTreeDo(ctx, line, nil, ""); err == nil || !strings.Contains(err.Error(), "could not move the tree") {
		t.Fatalf("an ignored file in the way: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(tree, ".env")); string(b) != "LOCAL-SECRET\n" {
		t.Fatalf("the ignored file was overwritten: %q", b)
	}
}

// The ancestry check k8s.set_image makes, run for real against a repository.
func TestAncestryByFetchRefusesABackwardOrSidewaysCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	setupBox(t)
	useFileRepos(t)
	origin, _, c1, c2 := twoCommitRepo(t, func(string) {}, func(o string) {
		_ = os.WriteFile(filepath.Join(o, "a.txt"), []byte("two\n"), 0o644)
	})
	gitT(t, origin, "checkout", "-q", "-b", "side", c1)
	_ = os.WriteFile(filepath.Join(origin, "b.txt"), []byte("side\n"), 0o644)
	gitT(t, origin, "add", "b.txt")
	gitT(t, origin, "commit", "-qm", "side")
	side := gitT(t, origin, "rev-parse", "HEAD")
	gitT(t, origin, "checkout", "-q", "main")
	src := "file://" + origin
	if err := opAncestryByFetch(src, c1, c2, nil); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if err := opAncestryByFetch(src, c2, c2, nil); err != nil {
		t.Fatalf("the same commit (a rebuild): %v", err)
	}
	for _, bad := range [][2]string{{c2, c1}, {c2, side}} {
		if err := opAncestryByFetch(src, bad[0], bad[1], nil); err == nil || !strings.Contains(err.Error(), "only moves forward") {
			t.Fatalf("%s → %s: %v", bad[0], bad[1], err)
		}
	}
	if err := opAncestryByFetch(src, c1, strings.Repeat("9", 40), nil); err == nil || !strings.Contains(err.Error(), "is not in") {
		t.Fatalf("a commit the repository does not have: %v", err)
	}
}

func TestAVerbsCredentialNeverReachesTheProgram(t *testing.T) {
	verbs := []opVerbLine{{Verb: "tree.checkout", Args: map[string]string{"credential": "forge-read"}}, {Verb: "unit.restart", Args: map[string]string{}}}
	got := opProgramCreds(verbs, map[string]string{"forge-read": "f", "registry": "r"})
	if len(got) != 1 || got["registry"] != "r" {
		t.Fatalf("only the program's own credential: %v", got)
	}
}

// A tree may hold a folder another user owns (a service's workspace). A move
// that would have git write into it, as root, is refused; one that leaves it
// alone goes ahead.
func TestTreeCheckoutNeverWritesIntoAFolderRootDoesNotControl(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand a folder to another user")
	}
	setupBox(t)
	useFileRepos(t)
	origin, tree, _, c2 := twoCommitRepo(t, func(o string) {
		_ = os.MkdirAll(filepath.Join(o, "workspace/deep"), 0o755)
		_ = os.WriteFile(filepath.Join(o, "workspace/deep/f.txt"), []byte("one\n"), 0o644)
	}, func(o string) {
		_ = os.WriteFile(filepath.Join(o, "workspace/deep/f.txt"), []byte("two\n"), 0o644)
	})
	ctx := context.Background()
	line := func(c string) opVerbLine {
		return opVerbLine{Verb: "tree.checkout", Args: map[string]string{"path": tree, "repo": "file://" + origin, "commit": c}}
	}
	_ = os.Chown(filepath.Join(tree, "workspace"), 65534, 65534)
	if _, err := opTreeDo(ctx, line(c2), nil, ""); err == nil || !strings.Contains(err.Error(), "writes into workspace") {
		t.Fatalf("a move into another user's folder: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(tree, "workspace/deep/f.txt")); string(b) != "one\n" {
		t.Fatal("the file was written")
	}
	// A folder whose name begins with a space is checked by its real name.
	gitT(t, tree, "reset", "-q", "--hard")
	_ = os.Chown(filepath.Join(tree, "workspace"), 0, 0)
	sp := " sp"
	_ = os.MkdirAll(filepath.Join(origin, sp), 0o755)
	_ = os.WriteFile(filepath.Join(origin, sp, "f.txt"), []byte("one\n"), 0o644)
	gitT(t, origin, "add", "-A")
	gitT(t, origin, "commit", "-qm", "space")
	cs1 := gitT(t, origin, "rev-parse", "HEAD")
	_ = os.WriteFile(filepath.Join(origin, sp, "f.txt"), []byte("two\n"), 0o644)
	gitT(t, origin, "commit", "-qam", "space two")
	cs2 := gitT(t, origin, "rev-parse", "HEAD")
	gitT(t, tree, "fetch", "-q", "origin")
	gitT(t, tree, "merge", "-q", "--ff-only", cs1)
	_ = os.Chown(filepath.Join(tree, sp), 65534, 65534)
	if err := opTreeWriteDirs(tree, cs1, cs2); err == nil || !strings.Contains(err.Error(), "writes into  sp") {
		t.Fatalf("a folder named with a leading space: %v", err)
	}
	_ = os.Chown(filepath.Join(tree, sp), 0, 0)
	// A commit that changes only a.txt goes ahead with that folder there.
	_ = os.WriteFile(filepath.Join(origin, "a.txt"), []byte("three\n"), 0o644)
	gitT(t, origin, "commit", "-qam", "three")
	c3 := gitT(t, origin, "rev-parse", "HEAD")
	gitT(t, tree, "fetch", "-q", "origin")
	gitT(t, tree, "merge", "-q", "--ff-only", c2) // as a person at the machine would have
	_ = os.Chown(filepath.Join(tree, "workspace"), 65534, 65534)
	if _, err := opTreeDo(ctx, line(c3), nil, ""); err != nil {
		t.Fatalf("a move that leaves the folder alone: %v", err)
	}
}

// Every command a verb runs has a deadline, so one that never answers
// cannot hold its target's lock for good.
func TestEveryCommandAVerbRunsHasADeadline(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		want time.Duration
	}{
		{"kubectl", []string{"-n", "ds", "get", "deployment", "web"}, time.Minute},
		{"kubectl", []string{"-n", "ds", "set", "image", "deployment/web", "web=x"}, time.Minute},
		{"kubectl", []string{"-n", "ds", "rollout", "status", "deployment/web", "--timeout=5m"}, 6 * time.Minute},
		{"systemctl", []string{"restart", "a.service"}, 6 * time.Minute},
		{"journalctl", []string{"-u", "a.service"}, time.Minute},
	} {
		if got := opCmdDeadline(c.name, c.args); got != c.want {
			t.Errorf("%s %v: %v, want %v", c.name, c.args, got, c.want)
		}
	}
	prev := opCmdDeadline
	t.Cleanup(func() { opCmdDeadline = prev })
	opCmdDeadline = func(string, []string) time.Duration { return 200 * time.Millisecond }
	start := time.Now()
	if _, err := opCmd(context.Background(), "sleep", "30"); err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("a command past its deadline: %v after %v", err, time.Since(start))
	}
}
