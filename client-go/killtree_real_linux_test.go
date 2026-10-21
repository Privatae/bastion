//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A REAL TREE, REALLY KILLED. Everything else here decides from stubs; this is
// the one test that sends SIGSTOP and SIGKILL, and only to processes it started
// itself: a shell that backgrounds two sleeps and waits. It proves the freeze
// and the kill reach real grandchildren through the real parent map.
//
// MUTATION: make osStopProcess a no-op and killProcess skip descendants.
// RESULT: red — a sleep survives.
func TestKillTreeKillsARealProcessTree(t *testing.T) {
	prevStop, prevResume, prevKill, prevTree, prevID := stopProcess, resumeProcess, killProcess, processTree, procIdentity
	t.Cleanup(func() {
		stopProcess, resumeProcess, killProcess, processTree, procIdentity = prevStop, prevResume, prevKill, prevTree, prevID
	})
	// THE FENCE. Real signals, as root, on the host's own process table: a
	// tree-kill with one guard removed can SIGKILL every child of pid 1 on the
	// machine running the test. Here every signal goes through `fenced`, which
	// refuses — and fails the test for — any pid that is not the shell this
	// test started or one of its descendants at the moment of asking. A
	// mutant of killTree/descendantsOf can then fail this test, never reach
	// another process.
	// `allowed` is fixed BEFORE killTree runs: the shell and the children it
	// had then. Re-deriving it at signal time would refuse the sleeps once the
	// shell is dead and they are re-parented.
	var root int
	allowed := map[int]bool{}
	refused := []int{}
	fenced := func(pid int, sig syscall.Signal) error {
		if !allowed[pid] {
			refused = append(refused, pid)
			return syscall.EPERM
		}
		return syscall.Kill(pid, sig)
	}
	stopProcess = func(pid int) error { return fenced(pid, syscall.SIGSTOP) }
	resumeProcess = func(pid int) error { return fenced(pid, syscall.SIGCONT) }
	killProcess = func(pid int) error { return fenced(pid, syscall.SIGKILL) }
	procIdentity = osProcIdentity
	processTree = processParents
	defer func() {
		if len(refused) > 0 {
			t.Errorf("killTree asked to signal pids outside the test's own tree: %v", refused)
		}
	}()

	cmd := exec.Command("sh", "-c", "sleep 300 & sleep 300 & wait")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a shell here: %v", err)
	}
	root = cmd.Process.Pid
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()

	// Wait until both sleeps are the shell's children in the real parent map.
	// The shell's children, read from /proc by THIS TEST, not through
	// descendantsOf or processParents: the fence below is built from this list,
	// and a fence built with the code under test falls when that code does (a
	// mutant descendantsOf returning every pid put every pid in the fence).
	var kids []int
	for i := 0; i < 100; i++ {
		kids = childrenFromProc(root)
		if len(kids) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(kids) < 2 {
		_ = syscall.Kill(root, syscall.SIGKILL)
		t.Fatalf("the shell's two sleeps never appeared under pid %d (saw %v)", root, kids)
	}

	allowed[root] = true
	for _, k := range kids {
		allowed[k] = true
	}
	if n := killTree(root, spareFromContain); n < 3 {
		t.Fatalf("killTree reached %d processes, want 3 (the shell and two sleeps)", n)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the shell did not die")
	}
	for _, k := range kids {
		// A reaped or zombie child is dead. A SIGKILL lands when the task next
		// runs, so on a loaded machine a killed sleep can still read 'R' (or
		// be part-way out) for a moment after the shell is gone: it is given
		// five seconds to finish dying, and only one still alive then
		// survived.
		var stat string
		for i := 0; i < 250; i++ {
			s, err := readProcStat(k)
			if err != nil || strings.Contains(s, ") Z ") {
				stat = ""
				break
			}
			stat = s
			time.Sleep(20 * time.Millisecond)
		}
		if stat != "" {
			t.Fatalf("sleep %d survived the tree kill: %s", k, stat)
		}
	}
}

// A REAL RELAYING PARENT, REALLY THAWED. The parent here does what sudo does:
// it waits on its child with WUNTRACED, and when the child is reported stopped
// it stops itself, then goes on waiting. killTree freezes and kills the child;
// with the fix the parent is continued, collects the exit, and leaves — so the
// child's pid is GONE (not a zombie) and the parent has exited. Without it the
// parent stays `T` and the child stays `Z`, which is what a machine showed
// after a real containment of an agent started through sudo.
//
// Same fence as the test above: every signal goes through `fenced`, and the
// allowed set is the parent and the child, read from /proc by this test.
//
// MUTATION: drop the thawRelayingAncestors call.  RESULT: red — the parent is
// still stopped and the child is a zombie after the kill.
func TestKillTreeThawsARealRelayingParent(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to stand in for sudo here")
	}
	prevStop, prevResume, prevKill, prevTree, prevID := stopProcess, resumeProcess, killProcess, processTree, procIdentity
	t.Cleanup(func() {
		stopProcess, resumeProcess, killProcess, processTree, procIdentity = prevStop, prevResume, prevKill, prevTree, prevID
	})
	allowed := map[int]bool{}
	refused := []int{}
	fenced := func(pid int, sig syscall.Signal) error {
		if !allowed[pid] {
			refused = append(refused, pid)
			return syscall.EPERM
		}
		return syscall.Kill(pid, sig)
	}
	stopProcess = func(pid int) error { return fenced(pid, syscall.SIGSTOP) }
	resumeProcess = func(pid int) error { return fenced(pid, syscall.SIGCONT) }
	var parent int
	killProcess = func(pid int) error {
		// The relay needs the stand-in to be scheduled between our SIGSTOP and
		// SIGKILL: a kill that lands first hands it an exit instead of a stop and
		// nothing relays anything. sudo has the same window. The test closes it
		// by letting the kill wait until the parent has stopped, bounded.
		for i := 0; i < 200 && parent != 0; i++ {
			if _, stopped, ok := osProcIdentity(parent); ok && stopped {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		return fenced(pid, syscall.SIGKILL)
	}
	procIdentity = osProcIdentity
	processTree = processParents
	defer func() {
		if len(refused) > 0 {
			t.Errorf("killTree asked to signal pids outside the test's own tree: %v", refused)
		}
	}()

	// The stand-in for sudo: start the child, wait for it to be reported
	// STOPPED, stop ourselves the way sudo does, then wait for it to end and
	// exit 0. If what it collects is an exit instead of a stop it leaves with
	// status 3 — the relay never happened and the run below has to say so
	// rather than pass on a parent that was never stopped.
	prog := "import os,signal,subprocess,sys\n" +
		"p=subprocess.Popen(['sleep','300'])\n" +
		"_, st = os.waitpid(p.pid, os.WUNTRACED)\n" +
		"if not os.WIFSTOPPED(st):\n" +
		"    sys.exit(3)\n" +
		"os.kill(os.getpid(), signal.SIGSTOP)\n" +
		"p.wait()\n"
	cmd := exec.Command(py, "-c", prog)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start python3 here: %v", err)
	}
	parent = cmd.Process.Pid
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		// Only while the stand-in is still ours: once Wait has returned, the
		// number may belong to someone else and is not signalled.
		select {
		case <-done:
		default:
			_ = syscall.Kill(parent, syscall.SIGCONT)
			_ = syscall.Kill(parent, syscall.SIGKILL)
		}
	})

	var kids []int
	for i := 0; i < 100; i++ {
		kids = childrenFromProc(parent)
		if len(kids) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(kids) != 1 {
		t.Fatalf("the stand-in's child never appeared under pid %d (saw %v)", parent, kids)
	}
	child := kids[0]
	allowed[parent] = true
	allowed[child] = true

	if n := killTree(child, spareFromContain); n != 1 {
		t.Fatalf("killTree reached %d processes, want 1 (the child)", n)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		stat, _ := readProcStat(parent)
		t.Fatalf("the parent never left: it was not continued after its child was killed (%s)", strings.TrimSpace(stat))
	}
	// Continued, not killed: a thaw that SIGKILLed the parent would also make
	// it leave, with the child reaped by init. Exit 0 is the stand-in reaching
	// the end of its script; exit 3 is the relay never having happened, which
	// is a broken test, not a passing one.
	if waitErr != nil {
		t.Fatalf("the parent did not exit cleanly after being continued (3 = it never saw the stop): %v", waitErr)
	}
	if stat, err := readProcStat(child); err == nil {
		t.Fatalf("the child is still in the process table after its parent exited: %s", strings.TrimSpace(stat))
	}
}

// childrenFromProc lists the direct children of parent by reading
// /proc/<pid>/stat's ppid field (after the last ')', so a name with spaces
// cannot shift it). Deliberately independent of the package's own walk.
func childrenFromProc(parent int) []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := []int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(raw)
		i := strings.LastIndex(s, ")")
		if i < 0 || i+2 > len(s) {
			continue
		}
		f := strings.Fields(s[i+2:])
		if len(f) > 1 {
			if pp, err := strconv.Atoi(f[1]); err == nil && pp == parent {
				out = append(out, pid)
			}
		}
	}
	return out
}

func readProcStat(pid int) (string, error) {
	out, err := exec.Command("cat", "/proc/"+strconv.Itoa(pid)+"/stat").Output()
	return string(out), err
}
