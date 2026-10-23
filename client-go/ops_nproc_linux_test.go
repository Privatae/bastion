package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// opNprocTestUID is a uid no account on a test machine uses.
const opNprocTestUID = 61999

// A user-privilege op starts however many tasks other programs already run
// as its user (a busy machine's daemons running as nobody), and the cap on
// its tasks still stops the op's own fork bomb.
func TestAUserOpStartsWhateverElseRunsAsItsUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if ok, why := opSandboxAvailable(); !ok {
		t.Skip(why)
	}
	opUnprivilegedIdentityHook = func() (uint32, uint32, error) { return opNprocTestUID, opNprocTestUID, nil }
	t.Cleanup(func() { opUnprivilegedIdentityHook = nil })
	var others []*exec.Cmd
	t.Cleanup(func() {
		for _, c := range others {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})
	for i := 0; i < 64; i++ { // the sandbox's cap
		c := exec.Command("sleep", "60")
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: opNprocTestUID, Gid: opNprocTestUID, NoSetGroups: true}}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		others = append(others, c)
	}

	runOp := func(extra string) (*opReport, error) {
		n := time.Now().UnixNano()
		root := filepath.Join(opTestRoot, fmt.Sprintf("np%d", n))
		opDir := filepath.Join(opTestRoot, fmt.Sprintf("npop%d", n))
		for _, p := range []string{root, opDir} {
			p := p
			t.Cleanup(func() { _ = os.RemoveAll(p) })
		}
		_ = os.MkdirAll(root, 0o777)
		_ = os.Chmod(root, 0o777)
		_ = os.MkdirAll(opDir, 0o755)
		for _, f := range opFixture(root, extra) {
			raw, _ := base64.StdEncoding.DecodeString(f.B64)
			_ = os.WriteFile(filepath.Join(opDir, f.Path), raw, os.FileMode(f.Mode))
		}
		man := strings.Replace(fmt.Sprintf(opTestManifest, root), "privilege: root", "privilege: user", 1)
		m, err := parseOpManifest([]byte(man))
		if err != nil {
			t.Fatal(err)
		}
		rep, err := opRunSandboxed(opDir, m, opModeDryRun, `{"name":"x","count":1,"kind":"a"}`)
		if rep != nil {
			t.Cleanup(rep.cleanup)
		}
		return rep, err
	}

	rep, err := runOp(`echo "RAN-AS=$(id -u)"; true`)
	if err != nil {
		t.Fatalf("a user op with 64 other tasks of its user on the machine: %v", err)
	}
	if !strings.Contains(rep.Output, fmt.Sprintf("RAN-AS=%d", opNprocTestUID)) {
		t.Errorf("the op did not run as its user: %q", rep.Output)
	}

	// The op's own tasks are still capped: a loop starting 100 is stopped,
	// and only after about as many as the cap, its own, not the others'.
	rep, err = runOp(`i=0; while [ $i -lt 100 ]; do echo "STARTING=$i"; sleep 5 & i=$((i+1)); done; echo DONE; true`)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "fork") || strings.Contains(rep.Output, "DONE") {
		t.Fatalf("100 background tasks were not stopped by the cap: %v, %q", err, rep.Output)
	}
	last := ""
	for _, line := range strings.Split(rep.Output, "\n") {
		if strings.HasPrefix(line, "STARTING=") {
			last = strings.TrimPrefix(line, "STARTING=")
		}
	}
	if n, _ := strconv.Atoi(last); n < 50 {
		t.Errorf("the cap stopped the op after %s of its own tasks: it counts other tasks too", last)
	}
	t.Logf("the op's fork loop was stopped at task %s", last)
}
