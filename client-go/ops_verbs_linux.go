//go:build linux

package main

// ops_verbs_linux.go — the verbs an action op declares, done by the bastion
// with its own root and bounded by their arguments (ops_action.go), and the
// run that puts the program and the verbs together.
//
// An apply is, in order: the change list observed again and compared with the
// one the person approved; the program's apply (a build, a push); receipts for
// what it pushed; each verb in the manifest's order, stopping at the first
// that fails; the program's verify; then each logs.check. A verb never runs
// in a dry run: the dry run observes what each would move from and to.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Seams, so the tests can stand in for systemd and Kubernetes.
var (
	opSystemctl  = func(ctx context.Context, args ...string) (string, error) { return opCmd(ctx, "systemctl", args...) }
	opJournalctl = func(ctx context.Context, args ...string) (string, error) { return opCmd(ctx, "journalctl", args...) }
	opKubectl    = func(ctx context.Context, args ...string) (string, error) {
		return opCmd(ctx, "kubectl", append([]string{"--kubeconfig", opKubeconfig}, args...)...)
	}
	// opKubeconfig is the machine's own admin kubeconfig: only a verb uses
	// it, never the program.
	opKubeconfig = "/etc/rancher/k3s/k3s.yaml"
	// opTreeProtocols: the transports tree.checkout's git may use.
	opTreeProtocols = []string{"https"}
	// opAncestry answers "does commit b descend from a" in a repository.
	opAncestry = opAncestryByFetch
)

const opVerbOutputMax = 64 << 10

// opCmdDeadline is how long one command a verb runs may take: a verb holds
// its target's lock (opLockTarget) while it runs, so a command that never
// answers (an API server that accepts and then stalls) must not hold it for
// good. A rollout waits up to its own --timeout=5m, and a unit's reload or
// restart up to the five minutes opUnitDo gives it; each gets a minute more
// here, so its own limit is the one that answers.
var opCmdDeadline = func(name string, args []string) time.Duration {
	switch name {
	case "kubectl":
		for _, a := range args {
			if a == "rollout" {
				return 6 * time.Minute
			}
		}
		return time.Minute
	case "systemctl":
		return 6 * time.Minute
	}
	return time.Minute
}

func opCmd(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, opCmdDeadline(name, args))
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	out := &cappedBuffer{max: opVerbOutputMax}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	return out.String(), err
}

// opRunAction runs one mode of an action op (ops.go opRunTerms).
func opRunAction(opDir string, m *opManifest, t *opTerms, mode, runID string, blobs []string, pc *opPlanCtx) (*opReport, error) {
	if ok, why := opActionAvailable(); !ok {
		return nil, errors.New("this machine cannot run an action op: " + why)
	}
	if mode != opModeDryRun && mode != opModeApply {
		return nil, errors.New("an action op is run as dry_run or apply; its verify runs inside the apply")
	}
	vals, err := checkParams(m, t.Params)
	if err != nil {
		return nil, err
	}
	verbs, err := opResolveVerbs(m, vals)
	if err != nil {
		return nil, err
	}
	creds, err := opOpenCreds(blobs, m, t.Nonce, mode == opModeDryRun)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	plan, err := opPlanVerbs(ctx, verbs, pc)
	if err != nil {
		return nil, err
	}
	planSHA := opChangesDigest(plan)
	if mode == opModeDryRun {
		rep, _, err := opRunActionProgram(opDir, m, opModeDryRun, t.Params, nil, runID)
		if rep != nil {
			rep.Changes, rep.ChangesSHA256 = plan, planSHA
		}
		return rep, err
	}
	// APPLY: the approval is for the change list the dry run showed, each
	// line with the state it moves from. A machine that moved since lands
	// nothing (a run under a grant carries no list: its bounds were approved).
	if t.Changes != "" && planSHA != t.Changes {
		return nil, fmt.Errorf("refused before anything ran: the apply would do something other than what the dry run showed (%s vs approved %s) — dry-run again and approve that",
			truncate(planSHA, 12), truncate(t.Changes, 12))
	}
	start := time.Now()
	rep, result, err := opRunActionProgram(opDir, m, opModeApply, t.Params, opProgramCreds(verbs, creds), runID)
	if rep == nil {
		return nil, err
	}
	rep.Changes, rep.ChangesSHA256 = plan, planSHA
	if err != nil {
		return rep, err
	}
	if len(result) > 0 {
		images, err := opParseResult(result)
		if err != nil {
			return rep, err
		}
		receipts, err := opIssueReceipts(runID, t.Op, t.SHA256, t.Params, images)
		rep.Receipts = receipts
		if err != nil {
			return rep, fmt.Errorf("could not hold a receipt: %v", err)
		}
	}
	for i, v := range verbs {
		if v.Verb == opVerbLogs {
			continue
		}
		// The state the verb may move from is the one the change list
		// read (and the person approved). The verb reads its target again
		// as it runs and refuses any other state, so what is recorded for
		// the undo is always what the verb moved: a target something else
		// moved while the program ran is left alone.
		want := plan[i].from
		// Recorded before it runs, with where it starts and is to end: a verb
		// that fails part-way (an image set, its rollout not done), or that
		// the bastion dies in, is still one an undo may have to take back
		// (ops_plan_linux.go).
		if pc != nil && pc.beforeVerb != nil {
			if err := pc.beforeVerb(v, want, opVerbTo(v)); err != nil {
				return rep, fmt.Errorf("stopped before %s %s: it could not be recorded for its undo (%v)", v.Verb, v.target(), err)
			}
		}
		note, err := opVerbDo(ctx, v, creds, pc, want)
		rep.Verbs = append(rep.Verbs, opVerbResult{Verb: v.Verb, Target: v.target(), OK: err == nil, Note: opScrub(note, creds)})
		if err != nil {
			return rep, fmt.Errorf("%s %s: %v", v.Verb, v.target(), errors.New(opScrub(err.Error(), creds)))
		}
		rep.Committed = append(rep.Committed, v.Verb+" "+v.target())
	}
	// The checks: the program's verify (an HTTP probe, a grep in the built
	// image), then each log check, reading only what came after the apply
	// began.
	var failed []string
	if ver, _, err := opRunActionProgram(opDir, m, opModeVerify, t.Params, nil, runID); err != nil {
		failed = append(failed, "verify: "+err.Error())
	} else if ver.Exit != 0 {
		failed = append(failed, fmt.Sprintf("verify exited %d", ver.Exit))
	}
	for _, v := range verbs {
		if v.Verb != opVerbLogs {
			continue
		}
		ok, line, err := opLogsCheck(ctx, v, start)
		r := opVerbResult{Verb: v.Verb, Target: v.target(), OK: ok && err == nil, Note: line}
		if err != nil {
			r.Note = err.Error()
		}
		rep.Checks = append(rep.Checks, r)
		if !r.OK {
			failed = append(failed, "logs.check "+v.target()+": "+r.Note)
		}
	}
	if len(failed) > 0 {
		rep.VerifyError = strings.Join(failed, "; ")
	}
	return rep, nil
}

// opPlanVerbs observes, for every verb line, the state it would move from,
// and refuses a line that could not run (a tree with local changes, a unit
// that is not there, a digest with no receipt, a live image with no record).
func opPlanVerbs(ctx context.Context, verbs []opVerbLine, pc *opPlanCtx) ([]opChange, error) {
	var out []opChange
	for _, v := range verbs {
		var c opChange
		var err error
		switch v.Verb {
		case "tree.checkout":
			c, err = opTreePlan(ctx, v)
		case "unit.reload", "unit.restart":
			c, err = opUnitPlan(ctx, v)
		case "k8s.set_image":
			c, err = opImagePlan(ctx, v, pc)
		case opVerbLogs:
			var parts []string
			if p := v.Args["must"]; p != "" {
				parts = append(parts, "must show /"+p+"/")
			}
			if p := v.Args["must_not"]; p != "" {
				parts = append(parts, "must not show /"+p+"/")
			}
			c = opActionChange(v, "", "", "checked after the apply: "+strings.Join(parts, ", "))
		default:
			err = fmt.Errorf("%q is not a verb this bastion runs", v.Verb)
		}
		if err != nil {
			return nil, fmt.Errorf("%s %s: %v", v.Verb, v.target(), err)
		}
		out = append(out, c)
	}
	return out, nil
}

// opVerbDo performs one verb line.
// opTargetLocks: one lock per tree and per workload, held by a verb and by
// an undo from its read of the target to the end of its write, so no two
// changes this bastion makes to one target interleave between a read and a
// write (a change from outside the bastion is still caught by the second
// read, one command before the write).
var opTargetLocks sync.Map

// opLockTarget takes the lock of the tree or workload a verb moves and
// returns its unlock.
func opLockTarget(v opVerbLine) func() {
	key := v.Verb
	switch v.Verb {
	case "tree.checkout":
		key += " " + filepath.Clean(v.Args["path"])
	case "k8s.set_image":
		key += " " + v.Args["namespace"] + "/" + v.Args["kind"] + "/" + v.Args["name"]
	}
	mu, _ := opTargetLocks.LoadOrStore(key, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	return mu.(*sync.Mutex).Unlock
}

// opTreeBeforeMove runs right before a tree's second read (a test moves the
// tree there).
var opTreeBeforeMove = func(path string) {}

// opMovedSince refuses a target that is not in the state the verb was
// approved, and recorded, to move it from.
func opMovedSince(now, want string) error {
	if want != "" && now != want {
		return fmt.Errorf("it is at %s, not the %s it was at when the op's changes were read: something else moved it since, and it is left alone", truncate(now, 90), truncate(want, 90))
	}
	return nil
}

// opVerbDo runs one verb. want, when set, is the state the verb may move
// its target from (a tree's commit, an image reference): any other refuses.
func opVerbDo(ctx context.Context, v opVerbLine, creds map[string]string, pc *opPlanCtx, want string) (string, error) {
	switch v.Verb {
	case "tree.checkout":
		return opTreeDo(ctx, v, creds, want)
	case "unit.reload", "unit.restart":
		return opUnitDo(ctx, v)
	case "k8s.set_image":
		return opImageDo(ctx, v, creds, pc, want)
	}
	return "", fmt.Errorf("%q is not a verb this bastion runs", v.Verb)
}

// ── tree.checkout ───────────────────────────────────────────────────────────

// opTreeConfigAllowed is every key a tree's own git config may hold for the
// bastion to run git in it as root. Anything else (a filter, an fsmonitor, a
// worktree elsewhere, an include) could run a program or write outside the
// tree when git does, and is refused by name.
var opTreeConfigAllowed = regexp.MustCompile(`^(` +
	`core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks)` +
	`|credential\.helper` +
	`|remote\..+\.(url|fetch|pushurl|prune|tagopt)` +
	`|branch\..+\.(remote|merge|rebase|pushremote)` +
	`|user\.(name|email)|pull\.(rebase|ff)|fetch\.prune|gc\.auto|init\.defaultbranch|extensions\.objectformat` +
	`)$`)

// opTreeGitArgs is the config every tree git call carries: no hooks, no
// fsmonitor, no credential helper (the credential comes sealed), no
// redirects, and only the allowed transports. There is deliberately no
// safe.directory: git itself refuses, on every call, a tree root does not own,
// so a tree another user can rewrite never runs git as root.
func opTreeGitArgs(path string) []string {
	a := []string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
		"-c", "credential.helper=", "-c", "core.askPass=", "-c", "http.followRedirects=false",
		"-c", "submodule.recurse=false", "-c", "protocol.allow=never"}
	for _, p := range opTreeProtocols {
		a = append(a, "-c", "protocol."+p+".allow=always")
	}
	return append(a, "-C", path)
}

func opTreeGit(path string, env []string, args ...string) (string, error) {
	out, err := runGitEnv(5*time.Minute, env, append(opTreeGitArgs(path), args...)...)
	return strings.TrimSpace(out), err
}

// opTreeGitStdout runs git in the tree like opTreeGit and returns its
// standard output exactly as written: no stderr mixed in and nothing trimmed,
// for output that names files (a name may begin or end with a space).
func opTreeGitStdout(path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append(opTreeGitArgs(path), args...)...)
	home, err := os.MkdirTemp("", "privatae-tree-home-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(home)
	cmd.Env = []string{"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=", "PATH=" + os.Getenv("PATH")}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New(truncate(strings.TrimSpace(stderr.String()), 200))
	}
	return string(out), nil
}

// opTreeState checks a tree is one the verb may move and reads where it is.
func opTreeState(v opVerbLine) (head, branch string, err error) {
	path := v.Args["path"]
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() {
		return "", "", errors.New("is not a folder on this machine")
	}
	if gst, err := os.Lstat(filepath.Join(path, ".git")); err != nil || !gst.IsDir() {
		return "", "", errors.New("is not a git working tree with its own .git folder")
	}
	// The repository is what git runs under and reads refs from, so only
	// root may change any of it: the config check below reads it once, and
	// the fetch and the move come after.
	if why := opRootOnlyWritable(path); why != "" {
		return "", "", errors.New(why)
	}
	if why := opRootOnlyTree(filepath.Join(path, ".git")); why != "" {
		return "", "", errors.New(why)
	}
	// The config first: nothing else git does in the tree may run under it.
	keys, err := opTreeGit(path, nil, "config", "--local", "--no-includes", "--name-only", "--list")
	if err != nil {
		return "", "", errors.New("its git config cannot be read: " + truncate(keys, 200))
	}
	for _, k := range strings.Split(keys, "\n") {
		if k = strings.TrimSpace(k); k != "" && !opTreeConfigAllowed.MatchString(k) {
			return "", "", fmt.Errorf("its git config sets %s, which the bastion will not run git under as root", k)
		}
	}
	if top, err := opTreeGit(path, nil, "rev-parse", "--show-toplevel"); err != nil || filepath.Clean(top) != path {
		return "", "", errors.New("is not the top of a git working tree")
	}
	if bare, _ := opTreeGit(path, nil, "config", "--local", "--bool", "core.bare"); bare == "true" {
		return "", "", errors.New("is a bare repository")
	}
	origin, err := opTreeGit(path, nil, "config", "--local", "remote.origin.url")
	if err != nil || opCleanRepoURL(origin) != v.Args["repo"] {
		return "", "", fmt.Errorf("its origin is not %s", v.Args["repo"])
	}
	// Tracked files only; a nested repository (a gitlink) is its own tree
	// and is left as it is — the report names any whose pointer moves.
	dirty, err := opTreeGit(path, nil, "status", "--porcelain=v1", "--untracked-files=no", "--ignore-submodules=all")
	if err != nil {
		return "", "", errors.New("git status failed: " + truncate(dirty, 200))
	}
	if dirty != "" {
		return "", "", fmt.Errorf("has local changes to tracked files (%s)", truncate(strings.ReplaceAll(dirty, "\n", "; "), 200))
	}
	if head, err = opTreeGit(path, nil, "rev-parse", "HEAD"); err != nil || !opCommitRe.MatchString(head) {
		return "", "", errors.New("has no commit checked out")
	}
	branch, _ = opTreeGit(path, nil, "symbolic-ref", "-q", "HEAD")
	return head, branch, nil
}

// opRootOnlyWritable: "" when p is root's and no one else can write it (a
// group may, only if the group is root's), else why not.
func opRootOnlyWritable(p string) string {
	st, err := os.Lstat(p)
	if err != nil {
		return p + " cannot be read"
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return p + " is a link"
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return p + " cannot be read"
	}
	perm := st.Mode().Perm()
	switch {
	case sys.Uid != 0:
		return p + " is not root's: the bastion runs git as root only in a tree no one else controls"
	case perm&0o002 != 0:
		return p + " can be written by anyone"
	case perm&0o020 != 0 && sys.Gid != 0:
		return p + " can be written by a group other than root's"
	}
	return ""
}

// opRootOnlyTree applies opRootOnlyWritable to root and everything under it
// (a link is judged by its owner only: its mode means nothing).
func opRootOnlyTree(root string) string {
	var why string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			why = p + " cannot be read"
			return filepath.SkipAll
		}
		if d.Type()&os.ModeSymlink != 0 {
			if st, err := os.Lstat(p); err != nil || st.Sys().(*syscall.Stat_t).Uid != 0 {
				why = p + " is not root's"
				return filepath.SkipAll
			}
			return nil
		}
		if w := opRootOnlyWritable(p); w != "" {
			why = w
			return filepath.SkipAll
		}
		return nil
	})
	return why
}

// opTreeWriteDirs refuses a move that would have git, as root, write into a
// folder another user controls: every folder on the way to a file the move
// changes must be root's and writable by no one else. A tree may hold such
// folders (a service's own workspace); a move that leaves them alone is fine.
func opTreeWriteDirs(path, from, to string) error {
	names, err := opTreeGitStdout(path, "diff", "--name-only", "--no-renames", "-z", from, to)
	if err != nil {
		return errors.New("git diff failed: " + err.Error())
	}
	seen := map[string]bool{}
	for _, n := range strings.Split(names, "\x00") {
		for d := filepath.Dir(n); d != "." && d != "/" && !seen[d]; d = filepath.Dir(d) {
			seen[d] = true
			full := filepath.Join(path, d)
			if _, err := os.Lstat(full); errors.Is(err, os.ErrNotExist) {
				continue // git makes it, as root, under a folder checked here
			}
			if why := opRootOnlyWritable(full); why != "" {
				return fmt.Errorf("the move writes into %s, which root does not control (%s)", d, why)
			}
		}
	}
	return nil
}

func opTreePlan(_ context.Context, v opVerbLine) (opChange, error) {
	head, _, err := opTreeState(v)
	if err != nil {
		return opChange{}, err
	}
	to := v.Args["commit"]
	if head == to {
		c := opActionChange(v, head, to, "already at "+truncate(to, 12))
		c.from = head
		return c, nil
	}
	// When the target is already here, going backwards is refused now, not
	// after an approval; otherwise the apply's fetch decides it.
	if _, err := opTreeGit(v.Args["path"], nil, "cat-file", "-e", to+"^{commit}"); err == nil {
		if _, err := opTreeGit(v.Args["path"], nil, "merge-base", "--is-ancestor", head, to); err != nil {
			return opChange{}, fmt.Errorf("%s does not descend from the tree's commit %s: a tree only moves forward", truncate(to, 12), truncate(head, 12))
		}
		if err := opTreeWriteDirs(v.Args["path"], head, to); err != nil {
			return opChange{}, err
		}
	}
	c := opActionChange(v, head, to, "")
	c.from = head
	return c, nil
}

// opCredHeaderEnv hands git a forge token without putting it on a command
// line (the mirror's way, service_mirror.go).
func opCredHeaderEnv(creds map[string]string, name string) ([]string, error) {
	if name == "" {
		return nil, nil
	}
	tok, ok := creds[name]
	if !ok {
		return nil, fmt.Errorf("the run was not handed %s", name)
	}
	return []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: token " + tok}, nil
}

func opTreeDo(_ context.Context, v opVerbLine, creds map[string]string, want string) (string, error) {
	defer opLockTarget(v)()
	path, to := v.Args["path"], v.Args["commit"]
	head, branch, err := opTreeState(v)
	if err != nil {
		return "", err
	}
	if err := opMovedSince(head, want); err != nil {
		return "", err
	}
	if head == to {
		return "already at " + truncate(to, 12), nil
	}
	env, err := opCredHeaderEnv(creds, v.Args["credential"])
	if err != nil {
		return "", err
	}
	if out, err := opTreeGit(path, env, "fetch", "--no-tags", "--quiet", v.Args["repo"], "+refs/heads/*:refs/remotes/origin/*"); err != nil {
		return "", errors.New("fetch failed: " + truncate(out, 300))
	}
	if _, err := opTreeGit(path, nil, "cat-file", "-e", to+"^{commit}"); err != nil {
		return "", fmt.Errorf("%s is not in %s", truncate(to, 12), v.Args["repo"])
	}
	if _, err := opTreeGit(path, nil, "merge-base", "--is-ancestor", head, to); err != nil {
		return "", fmt.Errorf("%s does not descend from the tree's commit %s: a tree only moves forward", truncate(to, 12), truncate(head, 12))
	}
	if err := opTreeWriteDirs(path, head, to); err != nil {
		return "", err
	}
	// Read again right before the move: the fetch above can take seconds,
	// and a tree something else moved in that time is left alone.
	opTreeBeforeMove(path)
	if now, err := opTreeGit(path, nil, "rev-parse", "HEAD"); err != nil {
		return "", errors.New("could not read the tree's commit: " + truncate(now, 300))
	} else if err := opMovedSince(now, head); err != nil {
		return "", err
	}
	var out string
	if branch != "" {
		out, err = opTreeGit(path, nil, "merge", "--ff-only", "--no-overwrite-ignore", "--quiet", to)
	} else {
		out, err = opTreeGit(path, nil, "checkout", "--no-overwrite-ignore", "--quiet", "--detach", to)
	}
	if err != nil {
		return "", errors.New("could not move the tree: " + truncate(out, 300))
	}
	if now, _ := opTreeGit(path, nil, "rev-parse", "HEAD"); now != to {
		return "", fmt.Errorf("the tree is at %s after the move, not %s", truncate(now, 12), truncate(to, 12))
	}
	note := truncate(head, 12) + " → " + truncate(to, 12)
	if raw, err := opTreeGit(path, nil, "diff", "--raw", "--no-renames", head, to); err == nil {
		var nested []string
		for _, l := range strings.Split(raw, "\n") {
			if f := strings.Fields(l); len(f) >= 6 && (f[0] == ":160000" || f[1] == "160000") {
				nested = append(nested, f[len(f)-1])
			}
		}
		if len(nested) > 0 {
			note += "; nested repositories left as they are, their recorded commit moved: " + strings.Join(nested, ", ")
		}
	}
	return note, nil
}

// ── unit.reload / unit.restart ──────────────────────────────────────────────

func opUnitShow(ctx context.Context, unit string) (map[string]string, error) {
	out, err := opSystemctl(ctx, "show", unit, "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "MainPID")
	if err != nil {
		return nil, errors.New("systemctl show failed: " + truncate(out, 200))
	}
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, val, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = val
		}
	}
	return m, nil
}

func opUnitPlan(ctx context.Context, v opVerbLine) (opChange, error) {
	s, err := opUnitShow(ctx, v.Args["unit"])
	if err != nil {
		return opChange{}, err
	}
	if s["LoadState"] != "loaded" {
		return opChange{}, fmt.Errorf("is not a unit on this machine (%s)", s["LoadState"])
	}
	// MainPID is not part of the state bound: it changes on every restart
	// the unit does by itself.
	from := s["ActiveState"] + "/" + s["SubState"]
	to := strings.TrimPrefix(v.Verb, "unit.") + "ed"
	return opActionChange(v, from, "", from+" → "+to), nil
}

func opUnitDo(ctx context.Context, v opVerbLine) (string, error) {
	unit := v.Args["unit"]
	act := strings.TrimPrefix(v.Verb, "unit.")
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if out, err := opSystemctl(cctx, act, unit); err != nil {
		return "", fmt.Errorf("systemctl %s failed: %s", act, truncate(out, 300))
	}
	s, err := opUnitShow(ctx, unit)
	if err != nil {
		return "", err
	}
	if s["ActiveState"] != "active" {
		return "", fmt.Errorf("after the %s the unit is %s/%s", act, s["ActiveState"], s["SubState"])
	}
	return act + "ed; " + s["ActiveState"] + "/" + s["SubState"] + ", pid " + s["MainPID"], nil
}

// ── k8s.set_image ───────────────────────────────────────────────────────────

// opLiveImage reads the one container's image off the workload.
func opLiveImage(ctx context.Context, v opVerbLine) (string, error) {
	a := v.Args
	out, err := opKubectl(ctx, "-n", a["namespace"], "get", a["kind"], a["name"], "-o", "json")
	if err != nil {
		return "", errors.New("the workload cannot be read: " + truncate(out, 200))
	}
	var w struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name  string `json:"name"`
						Image string `json:"image"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(out), &w); err != nil {
		return "", errors.New("the workload does not parse")
	}
	for _, c := range w.Spec.Template.Spec.Containers {
		if c.Name == a["container"] {
			return c.Image, nil
		}
	}
	return "", fmt.Errorf("the workload has no container %s", a["container"])
}

// opSplitImage splits image@sha256:… into its image and digest ("" when the
// reference carries no digest).
func opSplitImage(ref string) (string, string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

// opImageFacts is what the verb knows before it moves anything: the live
// digest, the receipt for the new one, and the commit behind the live one.
type opImageFacts struct {
	live, liveDigest       string
	rc                     *opReceipt
	liveSource, liveCommit string
	adopt                  bool // the first roll: the live image taken as the start
}

func opImageCheck(ctx context.Context, v opVerbLine, pc *opPlanCtx) (*opImageFacts, error) {
	a := v.Args
	live, err := opLiveImage(ctx, v)
	if err != nil {
		return nil, err
	}
	f := &opImageFacts{live: live}
	liveImage, liveDigest := opSplitImage(live)
	f.liveDigest = liveDigest
	// Inside a plan the receipt is the build step's line receipt, handed with
	// the line and verified under the key the device pinned for the building
	// machine; outside one, a receipt this machine signed itself.
	var rc *opReceipt
	if pc != nil {
		if rc = pc.receiptFor(a["digest"]); rc == nil {
			return nil, fmt.Errorf("no step of this plan built %s: a plan rolls only an image one of its own steps built", truncate(a["digest"], 19))
		}
		if rc.Commit != pc.Commit {
			return nil, fmt.Errorf("the image %s was built from %s, not the plan's commit", truncate(a["digest"], 19), truncate(rc.Commit, 12))
		}
	} else {
		if rc, err = opReceiptFor(a["digest"]); err != nil {
			return nil, err
		}
		if rc == nil {
			return nil, fmt.Errorf("this machine holds no receipt for %s: an image goes live only from a build this machine has a receipt for", truncate(a["digest"], 19))
		}
	}
	if rc.Image != a["image"] {
		return nil, fmt.Errorf("the receipt for %s is for %s, not %s", truncate(a["digest"], 19), rc.Image, a["image"])
	}
	// The repository ancestry is checked in is the manifest's, never one a
	// program reported: the check fetches it, with the verb's credential.
	if rc.Source != a["repo"] {
		return nil, fmt.Errorf("the receipt for %s says it was built from %s, not %s", truncate(a["digest"], 19), rc.Source, a["repo"])
	}
	f.rc = rc
	if liveDigest == a["digest"] {
		return f, nil
	}
	img, src, commit, ok := opRolledCommit(liveDigest)
	if (liveDigest == "" || !ok) && pc != nil && pc.AdoptLive && liveImage == a["image"] {
		// The first roll, approved on the device as one: the live image is
		// taken as the starting point, with no ancestry to check it against.
		f.adopt = true
		return f, nil
	}
	if liveDigest == "" || !ok {
		return nil, fmt.Errorf("this machine has no record of the commit behind the live image %s, so it cannot tell forward from back; its first roll needs your approval of the live image as the starting point", truncate(live, 90))
	}
	if liveImage != a["image"] || img != a["image"] {
		return nil, fmt.Errorf("the container runs %s, not %s", liveImage, a["image"])
	}
	if src != a["repo"] {
		return nil, fmt.Errorf("the live image was built from %s, not %s", src, a["repo"])
	}
	f.liveSource, f.liveCommit = src, commit
	return f, nil
}

func opImagePlan(ctx context.Context, v opVerbLine, pc *opPlanCtx) (opChange, error) {
	f, err := opImageCheck(ctx, v, pc)
	if err != nil {
		return opChange{}, err
	}
	// Both commits are bound, not only shown: the approval is for moving
	// from this commit to that one.
	to := v.Args["image"] + "@" + v.Args["digest"] + " " + f.rc.Commit
	if f.liveDigest == v.Args["digest"] {
		c := opActionChange(v, f.live, to, "already live")
		c.from = f.live
		return c, nil
	}
	if f.adopt {
		c := opActionChange(v, f.live+" adopted", to, "adopts the live image "+truncate(f.live, 90)+
			" as the starting point (this machine has no record of its commit) → "+truncate(v.Args["digest"], 19)+" ("+truncate(f.rc.Commit, 12)+")")
		c.from = f.live
		return c, nil
	}
	c := opActionChange(v, f.live+" "+f.liveCommit, to, truncate(f.liveDigest, 19)+" ("+truncate(f.liveCommit, 12)+") → "+
		truncate(v.Args["digest"], 19)+" ("+truncate(f.rc.Commit, 12)+")")
	c.from = f.live
	return c, nil
}

func opImageDo(ctx context.Context, v opVerbLine, creds map[string]string, pc *opPlanCtx, want string) (string, error) {
	defer opLockTarget(v)()
	a := v.Args
	f, err := opImageCheck(ctx, v, pc)
	if err != nil {
		return "", err
	}
	if err := opMovedSince(f.live, want); err != nil {
		return "", err
	}
	if f.liveDigest == a["digest"] {
		// Set is not rolled out: a retry after a rollout that did not finish
		// finds the image set, and still waits for the rollout.
		wl := a["kind"] + "/" + a["name"]
		if out, err := opKubectl(ctx, "-n", a["namespace"], "rollout", "status", wl, "--timeout=5m"); err != nil {
			return "", errors.New("the image is set and its rollout did not finish: " + truncate(out, 300))
		}
		return "already live, rolled out", nil
	}
	env, err := opCredHeaderEnv(creds, a["credential"])
	if err != nil {
		return "", err
	}
	if !f.adopt {
		if err := opAncestry(a["repo"], f.liveCommit, f.rc.Commit, env); err != nil {
			return "", err
		}
	}
	// Read again right before the write: the ancestry fetch above can take
	// seconds, and a workload something else rolled in that time is left
	// alone.
	if now, err := opLiveImage(ctx, v); err != nil {
		return "", err
	} else if err := opMovedSince(now, f.live); err != nil {
		return "", err
	}
	wl := a["kind"] + "/" + a["name"]
	if out, err := opKubectl(ctx, "-n", a["namespace"], "set", "image", wl, a["container"]+"="+a["image"]+"@"+a["digest"]); err != nil {
		return "", errors.New("set image failed: " + truncate(out, 300))
	}
	if err := opRecordRoll(a["digest"], opRollRec{Image: a["image"], Source: f.rc.Source, Commit: f.rc.Commit,
		Workload: a["namespace"] + "/" + wl + ":" + a["container"], At: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		return "", fmt.Errorf("the image is set and its record could not be written: %v", err)
	}
	if out, err := opKubectl(ctx, "-n", a["namespace"], "rollout", "status", wl, "--timeout=5m"); err != nil {
		return "", errors.New("the rollout did not finish: " + truncate(out, 300))
	}
	return truncate(f.liveDigest, 19) + " → " + truncate(a["digest"], 19) + ", rolled out", nil
}

// opAncestryByFetch fetches the source repository into the bastion's own
// cache and asks git whether newer descends from older.
func opAncestryByFetch(source, older, newer string, env []string) error {
	if older == newer {
		return nil
	}
	d, err := configDir()
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(source))
	cache := filepath.Join(d, "op-ancestry", hex.EncodeToString(sum[:8])+".git")
	if _, err := os.Stat(cache); err != nil {
		if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
			return err
		}
		if out, err := runGitEnv(time.Minute, nil, "init", "--bare", "--quiet", cache); err != nil {
			return errors.New("ancestry cache: " + truncate(out, 200))
		}
	}
	if out, err := opTreeGit(cache, env, "fetch", "--no-tags", "--quiet", source, "+refs/heads/*:refs/heads/*"); err != nil {
		return errors.New("fetching the source to check ancestry failed: " + truncate(out, 300))
	}
	for _, c := range []string{older, newer} {
		if _, err := opTreeGit(cache, nil, "cat-file", "-e", c+"^{commit}"); err != nil {
			return fmt.Errorf("%s is not in %s", truncate(c, 12), source)
		}
	}
	if _, err := opTreeGit(cache, nil, "merge-base", "--is-ancestor", older, newer); err != nil {
		return fmt.Errorf("the new image's commit %s does not descend from the live image's %s: an image only moves forward", truncate(newer, 12), truncate(older, 12))
	}
	return nil
}

// ── logs.check ──────────────────────────────────────────────────────────────

// opLogsCheck reads what the unit or workload logged since the apply began
// and returns the verdict and the one line that decided it — never the log.
func opLogsCheck(ctx context.Context, v opVerbLine, since time.Time) (bool, string, error) {
	a := v.Args
	n := 200
	if a["lines"] != "" {
		n, _ = strconv.Atoi(a["lines"])
	}
	var out string
	var err error
	if a["unit"] != "" {
		out, err = opJournalctl(ctx, "-u", a["unit"], "--since", "@"+strconv.FormatInt(since.Unix(), 10),
			"-n", strconv.Itoa(n), "-o", "cat", "--no-pager", "-q")
	} else {
		args := []string{"-n", a["namespace"], "logs", a["kind"] + "/" + a["name"],
			"--since-time=" + since.UTC().Format(time.RFC3339), "--tail=" + strconv.Itoa(n)}
		if a["container"] != "" {
			args = append(args, "-c", a["container"])
		}
		out, err = opKubectl(ctx, args...)
	}
	if err != nil {
		return false, "", errors.New("the log could not be read")
	}
	lines := strings.Split(out, "\n")
	if p := a["must_not"]; p != "" {
		re := regexp.MustCompile(p)
		for _, l := range lines {
			if re.MatchString(l) {
				return false, "must not show /" + p + "/, and did: " + truncate(l, 300), nil
			}
		}
	}
	if p := a["must"]; p != "" {
		re := regexp.MustCompile(p)
		for _, l := range lines {
			if re.MatchString(l) {
				return true, truncate(l, 300), nil
			}
		}
		return false, "no line showed /" + p + "/", nil
	}
	return true, "", nil
}

// opProgramCreds is what the program is handed: every credential the op
// declared except those a verb names, which are the bastion's to use for that
// verb (a forge read for tree.checkout), never the program's.
func opProgramCreds(verbs []opVerbLine, creds map[string]string) map[string]string {
	verbOnly := map[string]bool{}
	for _, v := range verbs {
		if c := v.Args["credential"]; c != "" {
			verbOnly[c] = true
		}
	}
	out := map[string]string{}
	for k, val := range creds {
		if !verbOnly[k] {
			out[k] = val
		}
	}
	return out
}

// opVerbTo is the state a verb line moves its target to: a commit, an image
// reference; "" for a unit, which has no state to move back from.
func opVerbTo(v opVerbLine) string {
	switch v.Verb {
	case "tree.checkout":
		return v.Args["commit"]
	case "k8s.set_image":
		return v.Args["image"] + "@" + v.Args["digest"]
	}
	return ""
}
