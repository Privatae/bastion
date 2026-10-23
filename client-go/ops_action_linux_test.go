package main

// The action-op gate, run for real (ops_action_linux.go): a program in a
// systemd transient unit, as a fresh uid, held to its destinations, seeing
// only the closed view, leaving nothing behind. These need root and systemd,
// and start real units on the machine; they skip anywhere else.
//
// Run them in a private PID namespace but NOT a private mount namespace: the
// unit is started by the machine's systemd, in the machine's mounts, and must
// see the run's tmpfs the test mounted. GOTMPDIR and TMPDIR name a folder
// on a disk, not under /tmp (a run gets its own /tmp):
//
//	GOTMPDIR=<dir> TMPDIR=<dir> unshare --pid --fork go test -run Action .

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requireActionSandbox(t *testing.T) {
	t.Helper()
	if ok, why := opActionAvailable(); !ok {
		t.Skip("no action sandbox here: " + why)
	}
	if err := os.MkdirAll(opTestRoot, 0o755); err != nil {
		t.Fatal(err)
	}
}

// actionOp writes an action op (a manifest with extra lines, a shell program)
// to a fresh directory and parses it.
func actionOp(t *testing.T, extra, program string) (string, *opManifest) {
	t.Helper()
	man := `name: optest-action
version: 1.0.0
summary: An action op under test.
kind: action
target: machine
privilege: user
interpreter: /bin/sh
time_limit: 30
params:
  name: {type: string, max_len: 32}
` + extra + `modes: [dry_run, apply, verify]
undo: none
`
	m, err := parseOpManifest([]byte(man))
	if err != nil {
		t.Fatalf("manifest: %v\n%s", err, man)
	}
	dir := filepath.Join(opTestRoot, fmt.Sprintf("aop%d", time.Now().UnixNano()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_ = os.WriteFile(filepath.Join(dir, "op.yaml"), []byte(man), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run"), []byte("#!/bin/sh\n"+program+"\n"), 0o755)
	return dir, m
}

func actionTerms(m *opManifest) *opTerms {
	return &opTerms{Kind: opKindRun, Op: m.Name, Version: m.Version, SHA256: strings.Repeat("a", 64),
		Privilege: m.Privilege, Params: `{"name":"x"}`, Nonce: fmt.Sprintf("n-%d-0123456789", time.Now().UnixNano()),
		Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Uses: 1}
}

func runAction(t *testing.T, dir string, m *opManifest, tm *opTerms, mode string, blobs []string) (*opReport, error) {
	t.Helper()
	id, _ := newID()
	actionRunsMu.Lock()
	actionRuns[t.Name()] = append(actionRuns[t.Name()], id)
	actionRunsMu.Unlock()
	t.Cleanup(func() {
		actionRunsMu.Lock()
		delete(actionRuns, t.Name())
		actionRunsMu.Unlock()
	})
	return opRunAction(dir, m, tm, mode, id, blobs, nil)
}

var (
	actionRunsMu sync.Mutex
	actionRuns   = map[string][]string{} // test name -> the run ids it started
)

// leftUnits is the op units still on the machine from the runs this test
// started. The machine's list is not asked alone: another test run on the
// same machine has units of its own, and those are not this test's leftovers.
func leftUnits(t *testing.T) []string {
	actionRunsMu.Lock()
	ids := append([]string(nil), actionRuns[t.Name()]...)
	actionRunsMu.Unlock()
	var out []string
	for _, u := range opActionUnits() {
		for _, id := range ids {
			if strings.HasPrefix(u, opActionUnitPrefix+truncate(id, 16)+"-") {
				out = append(out, u)
			}
		}
	}
	return out
}

// localAddr is an address of this machine that is not loopback, so a test
// can listen on it and name it as a destination.
func localAddr(t *testing.T) net.IP {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && n.IP.IsGlobalUnicast() {
			return n.IP
		}
	}
	t.Skip("no non-loopback IPv4 address here")
	return nil
}

func listen(t *testing.T, addr string) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hello\n"))
			_ = c.Close()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// A destination the op did not declare is out of reach: another port on the
// declared address (Landlock), another address (the unit's allowlist), and
// this machine's loopback.
func TestActionProgramReachesOnlyItsDestinations(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	ip := localAddr(t)
	_, declared := listen(t, net.JoinHostPort(ip.String(), "0"))
	_, otherPort := listen(t, net.JoinHostPort(ip.String(), "0"))
	_, loop := listen(t, "127.0.0.1:0")
	// The declared port on another address: only the unit's address
	// allowlist stands between the program and it (Landlock allows the port).
	listen(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(declared)))
	// This machine's own address is refused as a destination outside tests;
	// here it stands in for a remote one, reached by a name.
	prevOwn, prevRes := opActionOwnAddrs, opActionResolve
	opActionOwnAddrs = func() []net.IP { return nil }
	opActionResolve = func(_ context.Context, h string) ([]net.IP, error) {
		switch h {
		case "dest.optest.invalid":
			return []net.IP{ip}, nil
		case "meta.optest.invalid":
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return nil, fmt.Errorf("no")
	}
	t.Cleanup(func() { opActionOwnAddrs, opActionResolve = prevOwn, prevRes })
	probe := func(host string, port int) string {
		return fmt.Sprintf(`python3 -c 'import socket,sys
try:
    s=socket.create_connection((%q,%d),timeout=3); print("REACHED %s:%d", s.recv(6).decode().strip())
except Exception as e:
    print("BLOCKED %s:%d", type(e).__name__)'`, host, port, host, port, host, port)
	}
	prog := strings.Join([]string{
		probe("dest.optest.invalid", declared),
		probe(ip.String(), otherPort),
		probe("127.0.0.1", loop),
		probe("127.0.0.1", declared),
		probe("1.1.1.1", 443),
	}, "\n")
	dir, m := actionOp(t, fmt.Sprintf("destinations: [\"dest.optest.invalid:%d\"]\n", declared), prog)
	rep, err := runAction(t, dir, m, actionTerms(m), opModeApply, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, repOut(rep))
	}
	for _, want := range []string{
		fmt.Sprintf("REACHED dest.optest.invalid:%d hello", declared),
		fmt.Sprintf("BLOCKED %s:%d", ip, otherPort),
		fmt.Sprintf("BLOCKED 127.0.0.1:%d", loop),
		fmt.Sprintf("BLOCKED 127.0.0.1:%d", declared),
		"BLOCKED 1.1.1.1:443",
	} {
		if !strings.Contains(rep.Output, want) {
			t.Errorf("want %q in:\n%s", want, rep.Output)
		}
	}
	// A dry run, which nobody approved, reaches nothing at all, its declared
	// destination included.
	rep, err = runAction(t, dir, m, actionTerms(m), opModeDryRun, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, repOut(rep))
	}
	if strings.Contains(rep.Output, "REACHED") || !strings.Contains(rep.Output, fmt.Sprintf("BLOCKED dest.optest.invalid:%d", declared)) {
		t.Fatalf("a dry run has no network:\n%s", rep.Output)
	}
	// A name that resolves to the metadata service is refused at run start.
	if _, err := opResolveDests(context.Background(), []string{"meta.optest.invalid:80"}); err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("a destination that resolves to the metadata service: %v", err)
	}
}

func repOut(r *opReport) string {
	if r == nil {
		return "(no report)"
	}
	return r.Output
}

// The program is a uid no one else is, with no capability, and it sees only
// the closed view: not /root, not the docker socket, not /etc/shadow, not an
// abstract socket outside it, and it writes nowhere but /tmp.
func TestActionProgramSeesNothingItWasNotGiven(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	abs := fmt.Sprintf("privatae-optest-%d", time.Now().UnixNano())
	aln, err := net.Listen("unix", "@"+abs)
	if err != nil {
		t.Fatal(err)
	}
	defer aln.Close()
	go func() {
		for {
			c, err := aln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	readable := filepath.Join(opTestRoot, fmt.Sprintf("r%d.txt", time.Now().UnixNano()))
	_ = os.WriteFile(readable, []byte("DECLARED-READ\n"), 0o644)
	t.Cleanup(func() { _ = os.RemoveAll(readable) })
	// A folder anyone may write, declared as a read: only the read-only
	// machine keeps the program from writing into it.
	open := filepath.Join(opTestRoot, fmt.Sprintf("w%d", time.Now().UnixNano()))
	_ = os.Mkdir(open, 0o777)
	_ = os.Chmod(open, 0o777)
	t.Cleanup(func() { _ = os.RemoveAll(open) })
	prog := `echo "UID=$(id -u)"
grep -E '^(CapEff|CapBnd|NoNewPrivs)' /proc/self/status
echo "ROOT=[$(ls -A /root 2>&1 | tr '\n' ' ')]"
echo "SHADOW=[$(cat /etc/shadow 2>&1 | head -c 40)]"
for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /run/systemd/private; do
  [ -e "$s" ] && echo "SEES $s" || echo "NO $s"
done
python3 -c 'import socket
s=socket.socket(socket.AF_UNIX)
try:
    s.connect("\0` + abs + `"); print("ABSTRACT REACHED")
except Exception as e:
    print("ABSTRACT BLOCKED", type(e).__name__)'
cat ` + readable + `
touch /usr/local/optest-probe 2>/dev/null && echo "WROTE /usr/local" || echo "RO /usr/local"
touch ` + opTestRoot + `/optest-probe 2>/dev/null && echo "WROTE optest" || echo "RO optest"
touch ` + open + `/probe 2>/dev/null && echo "WROTE open" || echo "RO open"
touch /tmp/ok && echo "WROTE /tmp"
echo x > /dev/null && echo "DEVNULL-OK"
echo "HOSTNAME=$(hostname)"
echo "CGROUP=$(cat /proc/self/cgroup)"`
	dir, m := actionOp(t, "reads: ["+strconv.Quote(readable)+", "+strconv.Quote(open+"/")+"]\n", prog)
	rep, err := runAction(t, dir, m, actionTerms(m), opModeApply, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, repOut(rep))
	}
	out := rep.Output
	var uid uint64
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "UID=") {
			uid, _ = strconv.ParseUint(strings.TrimPrefix(l, "UID="), 10, 64)
		}
	}
	if uid < opUIDBase || uid >= opUIDBase+opUIDSpan {
		t.Errorf("the program runs as a uid set aside for ops, got %d", uid)
	}
	for _, want := range []string{"CapEff:\t0000000000000000", "CapBnd:\t0000000000000000", "NoNewPrivs:\t1",
		"ROOT=[]", "SHADOW=[]", "NO /var/run/docker.sock", "NO /run/docker.sock", "NO /run/systemd/private",
		"CGROUP=0::/" + opActionSlice + "/" + opActionUnitPrefix, "ABSTRACT BLOCKED", "DECLARED-READ", "RO /usr/local", "RO optest", "RO open", "WROTE /tmp", "DEVNULL-OK", "HOSTNAME=op-sandbox"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	if _, err := os.Stat("/usr/local/optest-probe"); err == nil {
		_ = os.Remove("/usr/local/optest-probe")
		t.Error("the program wrote to the machine")
	}
}

// A credential reaches the program, never its output, and nothing of the run
// is left afterwards: not the value on disk, not the tmpfs it sat on, not the
// work folder, not the unit, not a process the program left running.
func TestActionCredentialIsHandedAndNothingIsLeft(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	secret := fmt.Sprintf("optest-secret-%d", time.Now().UnixNano())
	// Every process of the program carries this mark, so a leftover is told
	// apart from a process of another test run that was given the same uid.
	mark := fmt.Sprintf("OPTEST_MARK=optest-mark-%d", time.Now().UnixNano())
	prog := `export ` + mark + `
echo "TOKEN=$PRIVATAE_CRED_TOKEN"
echo "$PRIVATAE_CRED_TOKEN" > /tmp/leak
echo "UID=$(id -u)"
setsid sleep 300 >/dev/null 2>&1 < /dev/null &
echo started`
	dir, m := actionOp(t, "credentials: [token]\n", prog)
	tm := actionTerms(m)
	pub, _, err := opEncKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := opSealCredFor(pub, opSealedCred{Name: "token", Value: secret, Nonce: tm.Nonce, Expires: tm.Expires})
	// A dry run is handed nothing.
	if _, err := runAction(t, dir, m, tm, opModeDryRun, []string{blob}); err == nil {
		t.Fatal("a dry run handed a credential is refused")
	}
	rep, err := runAction(t, dir, m, tm, opModeApply, []string{blob})
	if err != nil {
		t.Fatalf("%v\n%s", err, repOut(rep))
	}
	if strings.Contains(rep.Output, secret) || !strings.Contains(rep.Output, "TOKEN=***") {
		t.Fatalf("the program had it and its output does not: %s", rep.Output)
	}
	var uid string
	for _, l := range strings.Split(rep.Output, "\n") {
		if strings.HasPrefix(l, "UID=") {
			uid = strings.TrimPrefix(l, "UID=")
		}
	}
	root, _ := opRunsRoot()
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Errorf("the run left %d entries in %s", len(entries), root)
	}
	mi, _ := os.ReadFile("/proc/self/mountinfo")
	if strings.Contains(string(mi), root) {
		t.Error("the run's tmpfs is still mounted")
	}
	d, _ := configDir()
	_ = filepath.Walk(d, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), secret) {
				t.Errorf("the credential is on disk at %s", p)
			}
		}
		return nil
	})
	// The machine's systemd starts the unit outside this test's pid
	// namespace, so the check reads every process it can see: any with the
	// run's uid and this run's mark.
	time.Sleep(500 * time.Millisecond)
	procs, _ := filepath.Glob("/proc/[0-9]*/status")
	for _, p := range procs {
		b, _ := os.ReadFile(p)
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "Uid:" && f[1] == uid {
				env, _ := os.ReadFile(filepath.Join(filepath.Dir(p), "environ"))
				if strings.Contains(string(env), mark) {
					t.Errorf("a process of the run's uid %s is still running: %s", uid, p)
				}
			}
		}
	}
	if u := leftUnits(t); len(u) != 0 {
		t.Errorf("op units remain: %v", u)
	}
}

// An apply whose machine moved since the dry run lands nothing, and runs
// nothing: the program is never started.
func TestActionApplyOfAnotherChangeListRunsNothing(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	marker := filepath.Join(opTestRoot, fmt.Sprintf("ran%d", time.Now().UnixNano()))
	dir, m := actionOp(t, "", "echo ran")
	tm := actionTerms(m)
	tm.Changes = strings.Repeat("0", 64)
	d, _ := configDir()
	before, _ := os.ReadFile(filepath.Join(d, opUIDFile))
	rep, err := runAction(t, dir, m, tm, opModeApply, nil)
	if err == nil || !strings.Contains(err.Error(), "refused before anything ran") || rep != nil {
		t.Fatalf("refused, with no run: %v %+v", err, rep)
	}
	after, _ := os.ReadFile(filepath.Join(d, opUIDFile))
	if string(before) != string(after) {
		t.Fatal("a uid was spent, so a program started")
	}
	_ = marker
}

// What the program reports it pushed becomes a receipt signed here; a result
// file that is a link is refused, never followed as root.
func TestActionResultBecomesAReceiptAndALinkIsRefused(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	digest := "sha256:" + strings.Repeat("7", 64)
	res := `{"images":[{"image":"forge.example.com/acme/web","digest":"` + digest +
		`","source":"https://forge.example.com/acme/app.git","commit":"` + strings.Repeat("6", 40) + `"}]}`
	dir, m := actionOp(t, "", "[ \"$PRIVATAE_OP_MODE\" = apply ] && printf '%s' '"+res+"' > \"$PRIVATAE_OP_RESULT\"; true")
	rep, err := runAction(t, dir, m, actionTerms(m), opModeApply, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, repOut(rep))
	}
	if len(rep.Receipts) != 1 {
		t.Fatalf("one receipt: %+v", rep.Receipts)
	}
	if r, err := opReceiptFor(digest); err != nil || r == nil || r.Commit != strings.Repeat("6", 40) || r.Op != "optest-action" {
		t.Fatalf("held and verified: %+v %v", r, err)
	}
	dir2, m2 := actionOp(t, "", "[ \"$PRIVATAE_OP_MODE\" = apply ] && ln -s /etc/passwd \"$PRIVATAE_OP_RESULT\"; true")
	if _, err := runAction(t, dir2, m2, actionTerms(m2), opModeApply, nil); err == nil || !strings.Contains(err.Error(), "not a plain file") {
		t.Fatalf("a link is refused: %v", err)
	}
}

// A bastion that died mid-run leaves a mounted run dir and a work folder;
// the next start removes both.
func TestStartupSweepRemovesWhatADeadRunLeft(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	root, _ := opRunsRoot()
	run := filepath.Join(root, "run-dead")
	_ = os.Mkdir(run, 0o700)
	if err := unix.Mount("tmpfs", run, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(run, "cred-0"), []byte("x"), 0o400)
	_ = os.Mkdir(run+"-work", 0o700)
	opStartupSweep()
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("left: %v", entries)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(run, &st); err == nil {
		t.Fatal("the dead run's tmpfs is still there")
	}
}

// The builder's socket reaches the program in an apply, through the socket's
// group, and never in a dry run.
func TestActionBuilderSocketOnlyInApply(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	sock := filepath.Join(t.TempDir(), "buildkitd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("builder\n"))
			_ = c.Close()
		}
	}()
	// root:nogroup 0660: only the socket's group reaches it.
	_ = os.Chown(sock, 0, 65534)
	_ = os.Chmod(sock, 0o660)
	prev := opBuilderSocket
	opBuilderSocket = sock
	t.Cleanup(func() { opBuilderSocket = prev })
	prog := `echo "HOST=$BUILDKIT_HOST"
python3 -c 'import socket
s=socket.socket(socket.AF_UNIX)
try:
    s.connect("/run/privatae-builder/buildkitd.sock"); print("BUILDER", s.recv(8).decode().strip())
except Exception as e:
    print("NO BUILDER", type(e).__name__)'`
	dir, m := actionOp(t, "builder: true\n", prog)
	rep, err := runAction(t, dir, m, actionTerms(m), opModeApply, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, repOut(rep))
	}
	if !strings.Contains(rep.Output, "HOST=unix:///run/privatae-builder/buildkitd.sock") || !strings.Contains(rep.Output, "BUILDER builder") {
		t.Fatalf("the apply reaches the builder: %s", rep.Output)
	}
	rep, err = runAction(t, dir, m, actionTerms(m), opModeDryRun, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, repOut(rep))
	}
	if !strings.Contains(rep.Output, "HOST=\n") || !strings.Contains(rep.Output, "NO BUILDER") {
		t.Fatalf("a dry run never does: %s", rep.Output)
	}
	// A socket in root's group would hand the program that group: refused.
	_ = os.Chown(sock, 0, 0)
	if _, err := runAction(t, dir, m, actionTerms(m), opModeApply, nil); err == nil || !strings.Contains(err.Error(), "privileged group") {
		t.Fatalf("a builder socket in root's group: %v", err)
	}
	// A machine with no builder refuses an apply that builds.
	opBuilderSocket = filepath.Join(t.TempDir(), "absent.sock")
	if _, err := runAction(t, dir, m, actionTerms(m), opModeApply, nil); err == nil || !strings.Contains(err.Error(), "no builder") {
		t.Fatalf("no builder: %v", err)
	}
}

// Through a real unit: a credential a verb names never reaches the program,
// and the program's own does (scrubbed from what it prints).
func TestActionVerbCredentialNeverReachesTheRealProgram(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	useFileRepos(t)
	origin, tree, _, c2 := twoCommitRepo(t, func(string) {}, func(o string) {
		_ = os.WriteFile(filepath.Join(o, "a.txt"), []byte("two\n"), 0o644)
	})
	extra := fmt.Sprintf(`params:
  commit: {type: string, max_len: 64}
credentials: [forge-read, registry]
verbs:
  - {verb: tree.checkout, path: %q, repo: %q, commit: "{{commit}}", credential: forge-read}
`, tree, "file://"+origin)
	prog := `echo "FORGE=[$PRIVATAE_CRED_FORGE_READ]"; echo "REG=[$PRIVATAE_CRED_REGISTRY]"`
	man := strings.Replace(strings.Replace(`name: optest-action
version: 1.0.0
summary: An action op under test.
kind: action
target: machine
privilege: root
interpreter: /bin/sh
time_limit: 30
EXTRA
modes: [dry_run, apply, verify]
undo: none
`, "EXTRA\n", extra, 1), "\n\n", "\n", -1)
	m, err := parseOpManifest([]byte(man))
	if err != nil {
		t.Fatalf("%v\n%s", err, man)
	}
	dir := filepath.Join(opTestRoot, fmt.Sprintf("aopv%d", time.Now().UnixNano()))
	_ = os.MkdirAll(dir, 0o755)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_ = os.WriteFile(filepath.Join(dir, "op.yaml"), []byte(man), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run"), []byte("#!/bin/sh\n"+prog+"\n"), 0o755)
	tm := actionTerms(m)
	tm.Params = fmt.Sprintf(`{"commit":%q}`, c2)
	pub, _, _ := opEncKey()
	var blobs []string
	for name, val := range map[string]string{"forge-read": "forge-secret-value", "registry": "registry-secret-value"} {
		b, _ := opSealCredFor(pub, opSealedCred{Name: name, Value: val, Nonce: tm.Nonce, Expires: tm.Expires})
		blobs = append(blobs, b)
	}
	rep, err := runAction(t, dir, m, tm, opModeApply, blobs)
	if err != nil {
		t.Fatalf("%v\n%s", err, repOut(rep))
	}
	if !strings.Contains(rep.Output, "FORGE=[]") || !strings.Contains(rep.Output, "REG=[***]") {
		t.Fatalf("the verb's credential is withheld and the program's handed:\n%s", rep.Output)
	}
	if gitT(t, tree, "rev-parse", "HEAD") != c2 {
		t.Fatal("the verb ran with its credential")
	}
}

// allocProg holds `mib` MiB, touching every page, in 50 MiB steps.
func allocProg(mib int) string {
	return fmt.Sprintf(`python3 -c '
import time
print("ADJ", open("/proc/self/oom_score_adj").read().strip(), flush=True)
held = []
for i in range(%d // 50):
    b = bytearray(50 << 20)
    b[::4096] = b"\x01" * len(b[::4096])
    held.append(b)
    time.sleep(0.05)
print("HELD", len(held) * 50, flush=True)
rss = [l for l in open("/proc/self/status") if l.startswith("VmRSS:")][0].split()[1]
print("RSS", int(rss) // 1024, flush=True)
'`, mib)
}

// No ceiling: a run holds what it needs while the machine has it to spare.
// When the machine runs down to its floor, the op is stopped first and says
// why; a machine already under the floor starts no op; and the kernel, if it
// must kill, prefers the op.
func TestActionMemoryIsNotCappedAndTheOpYieldsFirst(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	_, avail, ok := opMemInfo()
	if !ok || avail < 10<<30 {
		t.Skip("needs 10 GiB free to show a run is not capped and yields")
	}
	dir, m := actionOp(t, "", allocProg(1500))
	rep, err := runAction(t, dir, m, actionTerms(m), opModeApply, nil)
	if err != nil {
		t.Fatalf("a run with memory to spare is not limited: %v\n%s", err, repOut(rep))
	}
	if !strings.Contains(rep.Output, "HELD 1500") || !strings.Contains(rep.Output, "ADJ 1000") {
		t.Fatalf("it held 1500 MiB, and the kernel would kill it first:\n%s", rep.Output)
	}
	// In memory, not pushed to swap by a limit on the unit.
	var rss int
	for _, l := range strings.Split(rep.Output, "\n") {
		if strings.HasPrefix(l, "RSS ") {
			rss, _ = strconv.Atoi(strings.TrimPrefix(l, "RSS "))
		}
	}
	if rss < 1400 {
		t.Fatalf("it held its 1500 MiB in memory, got %d MiB resident:\n%s", rss, rep.Output)
	}
	// The machine runs short: the floor is put 300 MiB under what is free now.
	prev := opMemoryFloor
	t.Cleanup(func() { opMemoryFloor = prev })
	_, avail, _ = opMemInfo()
	opMemoryFloor = func() uint64 { return avail - 300<<20 }
	bigDir, big := actionOp(t, "", allocProg(8000))
	rep, err = runAction(t, bigDir, big, actionTerms(big), opModeApply, nil)
	if err == nil || !strings.Contains(err.Error(), "stopped first") || strings.Contains(repOut(rep), "HELD") {
		t.Fatalf("the op yields when the machine runs short: %v\n%s", err, repOut(rep))
	}
	if !strings.Contains(err.Error(), "at its peak") || strings.Contains(err.Error(), "used 0 MiB") {
		t.Fatalf("the refusal says what the op had used: %v", err)
	}
	// Already under the floor: nothing starts, no uid is spent.
	_, avail, _ = opMemInfo()
	opMemoryFloor = func() uint64 { return avail + 1<<30 }
	d, _ := configDir()
	before, _ := os.ReadFile(filepath.Join(d, opUIDFile))
	if _, err := runAction(t, dir, m, actionTerms(m), opModeDryRun, nil); err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("a machine under its floor starts no op: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(d, opUIDFile)); string(before) != string(after) {
		t.Fatal("a uid was spent")
	}
	if u := leftUnits(t); len(u) != 0 {
		t.Fatalf("op units remain: %v", u)
	}
}

func TestMemoryFloorSitsAboveTheKubeletsEviction(t *testing.T) {
	total, _, _ := opMemInfo()
	gib := uint64(1 << 30)
	for _, c := range []struct {
		what       string
		files      map[string]string // relative path -> content
		want       uint64
		unreadable bool
	}{
		{"the config's setting, not its comment", map[string]string{"config.yaml": "#   eviction-hard   9Gi = a comment\nkubelet-arg:\n  - \"eviction-hard=memory.available<3Gi,nodefs.available<10%\"\n"}, 3 * gib, false},
		{"a percentage of the machine", map[string]string{"config.yaml.d/10-evict.yaml": "kubelet-arg:\n  - eviction-hard=memory.available<10%\n"}, total / 10, false},
		{"a decimal", map[string]string{"config.yaml": "kubelet-arg: [\"eviction-hard=memory.available<1.5Gi\"]\n"}, 3 * gib / 2, false},
		{"a decimal unit", map[string]string{"config.yaml": "kubelet-arg: [\"eviction-hard=memory.available<2G\"]\n"}, 2e9, false},
		{"soft eviction counts too", map[string]string{"config.yaml": "kubelet-arg:\n  - eviction-hard=memory.available<512Mi\n  - eviction-soft=memory.available<4Gi\n"}, 4 * gib, false},
		{"a flag on the k3s unit", map[string]string{"k3s.service": "ExecStart=/usr/local/bin/k3s server --kubelet-arg=eviction-hard=memory.available<2Gi\n"}, 2 * gib, false},
		{"a kubelet config file's form", map[string]string{"config.yaml.d/kubelet.yaml": "evictionHard:\n  memory.available: \"3Gi\"\n"}, 3 * gib, false},
		{"a value that cannot be read", map[string]string{"config.yaml": "kubelet-arg: [\"eviction-hard=memory.available<lots\"]\n"}, 0, true},
		{"the kubelet config k3s writes", map[string]string{"kubelet.conf.d/00-k3s-defaults.conf": "evictionHard:\n  imagefs.available: 5%\n  memory.available: 2Gi\n"}, 2 * gib, false},
		{"a kubelet config file a flag names", map[string]string{"config.yaml": "kubelet-arg:\n  - \"config={DIR}/kubelet.yaml\"\n", "kubelet.yaml": "evictionHard:\n  memory.available: \"4Gi\"\n"}, 4 * gib, false},
		{"a kubelet config folder a flag names", map[string]string{"k3s.service": "ExecStart=/usr/local/bin/k3s agent --kubelet-arg=config-dir={DIR}/kd\n", "kd/10.conf": "evictionSoft:\n  memory.available: 5Gi\n"}, 5 * gib, false},
		{"an empty kubelet config folder", map[string]string{"config.yaml": "kubelet-arg:\n  - config-dir={DIR}/empty\n", "empty/.keep": ""}, 0, false},
		{"a kubelet config file that is not there", map[string]string{"config.yaml": "kubelet-arg:\n  - config={DIR}/missing.yaml\n"}, 0, true},
		{"a flag split over two lines of the unit", map[string]string{"k3s.service": "ExecStart=/usr/local/bin/k3s \\\n    server \\\n    '--kubelet-arg' \\\n    'config={DIR}/kubelet.yaml' \\\n", "kubelet.yaml": "evictionHard:\n  memory.available: 4Gi\n"}, 4 * gib, false},
		{"a split flag naming a file that is not there", map[string]string{"k3s.service": "ExecStart=/usr/local/bin/k3s \\\n    '--kubelet-arg' \\\n    'config={DIR}/missing.yaml' \\\n"}, 0, true},
		{"single quotes", map[string]string{"kubelet.conf.d/50.conf": "evictionSoft:\n  'memory.available': '3Gi'\n"}, 3 * gib, false},
	} {
		dir := t.TempDir()
		for rel, body := range c.files {
			_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755)
			_ = os.WriteFile(filepath.Join(dir, rel), []byte(strings.ReplaceAll(body, "{DIR}", dir)), 0o644)
		}
		prevC, prevU := opK3sConfigGlobs, opK3sUnitGlobs
		opK3sConfigGlobs = []string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yaml.d/*.yaml"), filepath.Join(dir, "kubelet.conf.d/*.conf")}
		opK3sUnitGlobs = []string{filepath.Join(dir, "k3s*.service")}
		got, unreadable := opKubeletEviction()
		floor := opMemoryFloorForMachine()
		opK3sConfigGlobs, opK3sUnitGlobs = prevC, prevU
		if got != c.want || unreadable != c.unreadable {
			t.Errorf("%s: got %d unreadable=%v, want %d unreadable=%v", c.what, got, unreadable, c.want, c.unreadable)
		}
		if c.want > 0 && floor < c.want+opMemoryKubeletPad {
			t.Errorf("%s: the floor %d is not above the kubelet's line %d", c.what, floor, c.want)
		}
		if c.unreadable && floor < total/10+opMemoryKubeletPad {
			t.Errorf("%s: an unreadable setting makes the floor cautious, got %d", c.what, floor)
		}
		opK3sConfigGlobs = []string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yaml.d/*.yaml"), filepath.Join(dir, "kubelet.conf.d/*.conf")}
		opK3sUnitGlobs = []string{filepath.Join(dir, "k3s*.service")}
		note := opFloorNote()
		opK3sConfigGlobs, opK3sUnitGlobs = prevC, prevU
		if (note != "") != c.unreadable {
			t.Errorf("%s: a stop says when the floor was raised for an unreadable setting, and only then: %q", c.what, note)
		}
	}
	// The product reads where k3s v1.35 writes the kubelet's own config.
	found := false
	for _, g := range opK3sConfigGlobs {
		found = found || g == "/var/lib/rancher/k3s/agent/etc/kubelet.conf.d/*.conf"
	}
	if !found {
		t.Fatal("the kubelet config k3s writes is not read")
	}
	// No kubelet: the largest of 1 GiB and 5%.
	prevC, prevU := opK3sConfigGlobs, opK3sUnitGlobs
	opK3sConfigGlobs, opK3sUnitGlobs = []string{filepath.Join(t.TempDir(), "absent")}, nil
	defer func() { opK3sConfigGlobs, opK3sUnitGlobs = prevC, prevU }()
	want := gib
	if total/20 > want {
		want = total / 20
	}
	if got := opMemoryFloorForMachine(); got != want {
		t.Fatalf("with no kubelet: %d, want %d", got, want)
	}
}

// A kill that does not land (no such unit, no cgroup yet) is never reported
// as the op stopped.
func TestTheMemoryWatchReportsOnlyAKillThatLanded(t *testing.T) {
	stop := opMemoryWatch("privatae-op-nonexistent-optest", 1<<62)
	time.Sleep(4 * opMemoryWatchPeriod)
	v := stop()
	if v.Stopped {
		t.Fatalf("a kill that found nothing is not a stop: %+v", v)
	}
}

// The second signal: the machine's own services waiting on memory. The op's
// own stalls (its slice) never count; another cgroup's do, and stop it.
func TestActionYieldsWhenTheServicesWaitOnMemoryNotForItsOwnStalls(t *testing.T) {
	requireActionSandbox(t)
	setupBox(t)
	fake := t.TempDir()
	write := func(cg string, some float64) {
		_ = os.MkdirAll(filepath.Join(fake, cg), 0o755)
		_ = os.WriteFile(filepath.Join(fake, cg, "memory.pressure"),
			[]byte(fmt.Sprintf("some avg10=%.2f avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n", some)), 0o644)
	}
	write("system.slice", 0.10)
	write("kubepods.slice", 40) // a pod reclaiming against its own limit, already
	write(opActionSlice, 0.10)
	prev := opCgroupRoot
	opCgroupRoot = fake
	t.Cleanup(func() { opCgroupRoot = prev })
	// The op's own slice rises to 90 during the run: its own stalls.
	dir, m := actionOp(t, "", "sleep 3; echo DONE")
	go func() { time.Sleep(time.Second); write(opActionSlice, 90) }()
	rep, err := runAction(t, dir, m, actionTerms(m), opModeApply, nil)
	if err != nil || !strings.Contains(rep.Output, "DONE") {
		t.Fatalf("neither the op's own stalls nor a group already stalling stop it: %v\n%s", err, repOut(rep))
	}
	// The services start waiting one second into a longer run.
	dir2, m2 := actionOp(t, "", "sleep 20; echo DONE")
	go func() { time.Sleep(time.Second); write("system.slice", 12.5) }()
	start := time.Now()
	rep, err = runAction(t, dir2, m2, actionTerms(m2), opModeApply, nil)
	if err == nil || !strings.Contains(err.Error(), "system.slice began waiting on memory 12.4% more of the time than it had during the run") || strings.Contains(repOut(rep), "DONE") {
		t.Fatalf("the services waiting stops the op: %v\n%s", err, repOut(rep))
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("it was not stopped promptly")
	}
	// A group that keeps stalling at a level does not stop the next run: only
	// a rise during the run does.
	rep, err = runAction(t, dir, m, actionTerms(m), opModeDryRun, nil)
	if err != nil || !strings.Contains(rep.Output, "DONE") {
		t.Fatalf("a steady level is not a rise: %v\n%s", err, repOut(rep))
	}
	// A group that spiked as the run began and fell back does not hide a
	// rise the run causes later: the rise is from its lowest reading.
	write("system.slice", 30)
	dir3, m3 := actionOp(t, "", "sleep 20; echo DONE")
	go func() {
		time.Sleep(time.Second)
		write("system.slice", 0)
		time.Sleep(time.Second)
		write("system.slice", 12)
	}()
	rep, err = runAction(t, dir3, m3, actionTerms(m3), opModeApply, nil)
	if err == nil || !strings.Contains(err.Error(), "system.slice began waiting on memory 12.0% more") || strings.Contains(repOut(rep), "DONE") {
		t.Fatalf("a rise after a spike at the start: %v\n%s", err, repOut(rep))
	}
}

// The watch keeps trying: the machine is short before the op's unit exists
// (the first kill finds nothing), and the unit that starts a second later is
// still stopped.
func TestTheMemoryWatchKeepsTryingUntilTheKillLands(t *testing.T) {
	requireActionSandbox(t)
	unit := fmt.Sprintf("%swatchtest-%d", opActionUnitPrefix, time.Now().UnixNano())
	stop := opMemoryWatch(unit, 1<<62)
	defer func() { opKillUnit(unit) }()
	time.Sleep(time.Second)
	// Started the way a run starts its unit (--wait, so it holds until the
	// unit ends), in the background. Without --quiet, systemd-run reports how
	// the unit ended: that is the proof it ran and was killed. Polling for its
	// cgroup is not: the watch kills within one period of the unit starting,
	// so the cgroup can come and go between two polls.
	var report bytes.Buffer
	cmd := exec.Command("systemd-run", "--wait", "--collect", "--unit="+unit, "--slice="+opActionSlice,
		"-p", "RuntimeMaxSec=60", "/bin/sleep", "30")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout, cmd.Stderr = &report, &report
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the unit: %v", err)
	}
	ended := make(chan struct{})
	go func() { _ = cmd.Wait(); close(ended) }()
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the unit was not stopped: its 30-second sleep is still running")
	}
	v := stop()
	gone := false
	for i := 0; i < 100 && !gone; i++ {
		if _, err := os.Stat(opUnitCgroupDir(unit)); err != nil {
			gone = true
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}
	out := report.String()
	killed := strings.Contains(out, "Finished with result: signal") && regexp.MustCompile(`code=killed.*KILL`).MatchString(out)
	if !killed || !gone || !v.Stopped {
		t.Fatalf("the unit that came after the first try was stopped: killed=%v gone=%v %+v\n%s", killed, gone, v, out)
	}
}
