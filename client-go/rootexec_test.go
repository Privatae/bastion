//go:build !windows

package main

// Root commands (rootexec.go): the exec frame's round trip, every wall that
// refuses it, the output cap and the deadline, the transcript and audit rows,
// and the console ceremony that is the only way a grant comes to exist.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const rootExecTestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// fakeExec is a rootExecProc: it writes what it was told to, then exits with
// code — or, with block set, waits until it is killed.
type fakeExec struct {
	mu      sync.Mutex
	killed  bool
	done    chan struct{}
	code    int
	started []string
}

func withFakeExec(t *testing.T, stdout, stderr string, code int, block bool) *fakeExec {
	t.Helper()
	fe := &fakeExec{done: make(chan struct{}), code: code}
	old := rootExecStart
	rootExecStart = func(command string, so, se io.Writer, cgroupFD int) (rootExecProc, error) {
		fe.mu.Lock()
		fe.started = append(fe.started, command)
		fe.mu.Unlock()
		_, _ = io.WriteString(so, stdout)
		_, _ = io.WriteString(se, stderr)
		if !block {
			fe.Kill()
		}
		return fe, nil
	}
	t.Cleanup(func() { rootExecStart = old; fe.Kill() })
	return fe
}

func (f *fakeExec) Wait() int { <-f.done; return f.code }
func (f *fakeExec) Kill() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.killed {
		f.killed = true
		close(f.done)
	}
}
func (f *fakeExec) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.started...)
}

func withDaemonRoot(t *testing.T, root bool) {
	t.Helper()
	old := sessionDaemonIsRoot
	sessionDaemonIsRoot = func() bool { return root }
	t.Cleanup(func() { sessionDaemonIsRoot = old })
}

func rootExecCode(t *testing.T, at time.Time) string {
	t.Helper()
	raw, err := b32decode(rootExecTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	return hotp(raw, at.Unix()/stepupPeriod)
}

// rootExecBox is an anchored box whose anchor pairing has a factor enrolled,
// with the daemon reading as root. grant=true gives the standing grant through
// the console ceremony itself.
func rootExecBox(t *testing.T, grant bool) sessionEnv {
	t.Helper()
	env, _ := rootExecBoxKey(t, grant)
	return env
}

func rootExecBoxKey(t *testing.T, grant bool) (sessionEnv, ed25519.PrivateKey) {
	t.Helper()
	priv := setupBox(t)
	env, _, _ := sessionTestEnv(t, nil, nil)
	env.HostName = tAnchor
	withDaemonRoot(t, true)
	if err := stepupSave(env.DcnDir, &stepupFile{SecretB32: rootExecTestSecret,
		EnrolledAt: "2026-10-11T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	if grant {
		now := time.Now()
		if _, err := rootExecGrantWithCode(env.DcnDir, tAnchor, env.Server, rootExecCode(t, now), 24*time.Hour, now); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}
	return env, priv
}

func sendExec(t *testing.T, ws *websocket.Conn, sid, command string, deadline, maxOut int) {
	t.Helper()
	sendSpec(t, ws, sessionSpec{Op: sessionOpRootExec, SessionID: sid, Command: command,
		DeadlineS: deadline, MaxOutputBytes: maxOut})
}

func execResult(t *testing.T, got map[byte][]byte) rootExecResult {
	t.Helper()
	var r rootExecResult
	if len(got['J']) == 0 {
		t.Fatalf("no J frame: X=%q E=%q", got['X'], got['E'])
	}
	if err := json.Unmarshal(got['J'], &r); err != nil {
		t.Fatalf("J frame: %v", err)
	}
	return r
}

func auditText(t *testing.T, env sessionEnv) string {
	t.Helper()
	raw, _ := os.ReadFile(filepath.Join(env.DcnDir, "audit.jsonl"))
	return string(raw)
}

func TestRootExecRoundTrip(t *testing.T) {
	env := rootExecBox(t, true)
	fe := withFakeExec(t, "hello out\n", "a warning\n", 3, false)
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, "exec-0001", "systemctl status x", 30, 0)
	got := readUntil(t, ws, 'X', 5*time.Second)
	if string(got['X']) != "3" {
		t.Fatalf("X must carry the command's own status: X=%q E=%q", got['X'], got['E'])
	}
	r := execResult(t, got)
	if r.Stdout != "hello out\n" || r.Stderr != "a warning\n" || r.Exit != 3 || r.User != "root" ||
		r.TimedOut || r.StdoutTruncated || r.StderrTruncated || r.DeadlineS != 30 || r.StdoutBytes != 10 {
		t.Fatalf("result: %+v", r)
	}
	if ran := fe.ran(); len(ran) != 1 || ran[0] != "systemctl status x" {
		t.Fatalf("the command run must be the one sent: %q", ran)
	}
	tr, err := os.ReadFile(filepath.Join(env.CtxRoot, "sessions", "exec-0001.log"))
	if err != nil {
		t.Fatalf("transcript: %v", err)
	}
	for _, want := range []string{"== root command exec-0001 host=" + tAnchor + " user=root", "systemctl status x\n",
		"hello out\n", "a warning\n", "exit=3 reason=exit"} {
		if !strings.Contains(string(tr), want) {
			t.Fatalf("transcript lacks %q:\n%s", want, tr)
		}
	}
	a := auditText(t, env)
	for _, want := range []string{`"op":"session:root:exec"`, `"event":"start"`, `"command":"systemctl status x"`,
		`"event":"stop"`, `"exit":3`, `"op":"root_exec_grant"`} {
		if !strings.Contains(a, want) {
			t.Fatalf("audit lacks %s:\n%s", want, a)
		}
	}
}

// Every wall refuses with E + X 126, runs nothing, sends no J, leaves no
// transcript and is audited with the command it refused.
func TestRootExecRefusals(t *testing.T) {
	cases := []struct {
		name  string
		self  string
		setup func(t *testing.T, env sessionEnv)
		want  string
	}{
		{"no grant", tAnchor, func(t *testing.T, env sessionEnv) {}, "no standing grant"},
		{"grant expired", tAnchor, func(t *testing.T, env sessionEnv) {
			g, _ := rootExecGrantLoad(env.DcnDir)
			g.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
			_ = rootExecGrantSave(env.DcnDir, g)
		}, "expired"},
		{"grant revoked", tAnchor, func(t *testing.T, env sessionEnv) {
			if _, err := rootExecRevoke(env.DcnDir, time.Now()); err != nil {
				t.Fatal(err)
			}
		}, "revoked"},
		{"grant for another host", tAnchor, func(t *testing.T, env sessionEnv) {
			g, _ := rootExecGrantLoad(env.DcnDir)
			g.Host = tMember
			_ = rootExecGrantSave(env.DcnDir, g)
		}, "is for '" + tMember + "'"},
		{"grant for another machine", tAnchor, func(t *testing.T, env sessionEnv) {
			g, _ := rootExecGrantLoad(env.DcnDir)
			g.Server = "other-box"
			_ = rootExecGrantSave(env.DcnDir, g)
		}, "machine 'other-box'"},
		{"member pairing", tMember, func(t *testing.T, env sessionEnv) {}, "anchor host"},
		{"daemon not root", tAnchor, func(t *testing.T, env sessionEnv) { withDaemonRoot(t, false) }, "run as root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, priv := rootExecBoxKey(t, c.name != "no grant")
			if c.self == tMember {
				// A member the anchor DID give the session family: the caps
				// wall passes it, so what refuses is the anchor-only wall.
				writePairingState(t, tMember, pairingPending)
				grantMemberCaps(t, priv, "session")
			}
			c.setup(t, env)
			fe := withFakeExec(t, "should not run", "", 0, false)
			ws := sessionDialAs(t, env, c.self)
			sendExec(t, ws, "exec-refuse", "id", 0, 0)
			got := readUntil(t, ws, 'X', 5*time.Second)
			if string(got['X']) != "126" || len(got['J']) != 0 || !strings.Contains(string(got['E']), c.want) {
				t.Fatalf("want X 126, no J, E ~%q; got X=%q J=%q E=%q", c.want, got['X'], got['J'], got['E'])
			}
			if len(fe.ran()) != 0 {
				t.Fatal("a refused command must never start")
			}
			if e := string(got['E']); !strings.HasPrefix(e, "refused") || strings.Contains(e, "refused: refused") {
				t.Fatalf("the refusal says refused once: %q", e)
			}
			if _, err := os.Stat(filepath.Join(env.CtxRoot, "sessions", "exec-refuse.log")); err == nil {
				t.Fatal("a refused command must not leave a transcript")
			}
			if a := auditText(t, env); !strings.Contains(a, `"event":"refused"`) || !strings.Contains(a, `"command":"id"`) {
				t.Fatalf("refusal not audited with its command:\n%s", a)
			}
		})
	}
}

// The person's local switch ("session" off on this machine) stops root
// commands too, grant or not.
func TestRootExecLocalSwitchRefuses(t *testing.T) {
	env := rootExecBox(t, true)
	if err := localDenySet(tAnchor, "session", true); err != nil {
		t.Fatal(err)
	}
	fe := withFakeExec(t, "", "", 0, false)
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, "exec-switch", "id", 0, 0)
	got := readUntil(t, ws, 'X', 5*time.Second)
	if string(got['X']) != "126" || len(fe.ran()) != 0 {
		t.Fatalf("switched off here must refuse: X=%q E=%q", got['X'], got['E'])
	}
}

func TestRootExecOutputCapIsStated(t *testing.T) {
	env := rootExecBox(t, true)
	big := strings.Repeat("a", 6000) + strings.Repeat("z", 4240) // 10240 bytes
	withFakeExec(t, big, "", 0, false)
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, "exec-cap01", "yes | head", 0, 10) // asks below the floor: held to 1 KiB
	got := readUntil(t, ws, 'X', 5*time.Second)
	r := execResult(t, got)
	if !r.StdoutTruncated || r.StdoutBytes != 10240 || r.MaxOutputBytes != rootExecMinOutput {
		t.Fatalf("cap: %+v", r)
	}
	if !strings.HasPrefix(r.Stdout, strings.Repeat("a", 512)) || !strings.HasSuffix(r.Stdout, strings.Repeat("z", 512)) ||
		!strings.Contains(r.Stdout, "bytes cut here: 10240 bytes in all") {
		t.Fatalf("the kept head and tail and the cut must be stated: %q", r.Stdout)
	}
	// The local transcript keeps the whole output, not the capped copy.
	tr, _ := os.ReadFile(filepath.Join(env.CtxRoot, "sessions", "exec-cap01.log"))
	if !strings.Contains(string(tr), big) {
		t.Fatal("the transcript must hold the whole output")
	}
}

func TestRootExecDeadlineKills(t *testing.T) {
	env := rootExecBox(t, true)
	fe := withFakeExec(t, "started\n", "", 0, true)
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, "exec-dead1", "sleep 999", 1, 0)
	got := readUntil(t, ws, 'X', 10*time.Second)
	r := execResult(t, got)
	if string(got['X']) != "124" || !r.TimedOut || r.Exit != 124 || r.Stdout != "started\n" {
		t.Fatalf("deadline: X=%q %+v", got['X'], r)
	}
	fe.mu.Lock()
	k := fe.killed
	fe.mu.Unlock()
	if !k {
		t.Fatal("the deadline must kill the command")
	}
}

func TestRootExecHostCloseKills(t *testing.T) {
	env := rootExecBox(t, true)
	fe := withFakeExec(t, "", "", 0, true)
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, "exec-close", "sleep 999", 600, 0)
	deadline := time.Now().Add(3 * time.Second)
	for len(fe.ran()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_ = ws.Close()
	for time.Now().Before(deadline.Add(2 * time.Second)) {
		fe.mu.Lock()
		k := fe.killed
		fe.mu.Unlock()
		if k {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the host closing the socket must kill the command")
}

func TestRootExecBadCommandIsExit1(t *testing.T) {
	env := rootExecBox(t, true)
	fe := withFakeExec(t, "", "", 0, false)
	for i, c := range []string{"", "   ", "a\x00b", strings.Repeat("x", rootExecCommandMax+1)} {
		ws := sessionDialAs(t, env, tAnchor)
		sendExec(t, ws, fmt.Sprintf("exec-bad-%d", i), c, 0, 0)
		got := readUntil(t, ws, 'X', 5*time.Second)
		if string(got['X']) != "1" {
			t.Fatalf("case %d: want X 1, got %q", i, got['X'])
		}
	}
	if len(fe.ran()) != 0 {
		t.Fatal("a bad command must never start")
	}
}

// The real starter, as whoever runs the suite: both streams, the exit status,
// and a deadline that ends the whole process group.
func TestRootExecRealShell(t *testing.T) {
	var so, se strings.Builder
	var mu sync.Mutex
	w := func(b *strings.Builder) io.Writer {
		return writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return b.Write(p) })
	}
	p, err := startRootExec("echo out; echo err >&2; exit 7", w(&so), w(&se), -1)
	if err != nil {
		t.Fatal(err)
	}
	if code := p.Wait(); code != 7 || so.String() != "out\n" || se.String() != "err\n" {
		t.Fatalf("code=%d out=%q err=%q", code, so.String(), se.String())
	}
	admit := fenceRootExecGroups(t)
	p, err = startRootExec("sleep 30 & sleep 30; echo never", io.Discard, io.Discard, -1)
	if err != nil {
		t.Fatal(err)
	}
	admit(p.(*shellProc).cmd.Process.Pid)
	start := time.Now()
	p.Kill()
	p.Wait()
	if time.Since(start) > 10*time.Second {
		t.Fatal("kill must end the group, background children included, promptly")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// A grant taken back while a command runs stops that command: the walls are
// looked at again every rootExecRecheck, and the first one that no longer
// holds kills the group. The answer is X 126 with a J that says why.
//
// MUTATION: drop the recheck case from handleRootExec's run loop.
// RESULT: red — the command runs on to its deadline and X never arrives.
func TestRootExecStopsWhenAWallFallsMidRun(t *testing.T) {
	old := rootExecRecheck
	rootExecRecheck = 50 * time.Millisecond
	t.Cleanup(func() { rootExecRecheck = old })
	cases := []struct {
		name string
		fall func(t *testing.T, env sessionEnv)
		want string
	}{
		{"revoked at the console", func(t *testing.T, env sessionEnv) {
			if _, err := rootExecRevoke(env.DcnDir, time.Now()); err != nil {
				t.Fatal(err)
			}
		}, "revoked"},
		{"expired", func(t *testing.T, env sessionEnv) {
			g, _ := rootExecGrantLoad(env.DcnDir)
			g.Expires = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
			if err := rootExecGrantSave(env.DcnDir, g); err != nil {
				t.Fatal(err)
			}
		}, "expired"},
		{"switched off here", func(t *testing.T, env sessionEnv) {
			if err := localDenySet(tAnchor, "session", true); err != nil {
				t.Fatal(err)
			}
		}, "session"},
		{"quarantined", func(t *testing.T, env sessionEnv) {
			for i := 0; i < quarantineStrikes; i++ {
				noteRefusal(tAnchor, sessionOpRootExec, "refused: test", true, time.Now())
			}
		}, "quarantined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := rootExecBox(t, true)
			fe := withFakeExec(t, "started\n", "", 0, true)
			ws := sessionDialAs(t, env, tAnchor)
			sendExec(t, ws, "exec-fall1", "sleep 999", 600, 0)
			for i := 0; i < 300 && len(fe.ran()) == 0; i++ {
				time.Sleep(10 * time.Millisecond)
			}
			// While every wall holds, the recheck leaves the command alone.
			time.Sleep(4 * rootExecRecheck)
			fe.mu.Lock()
			early := fe.killed
			fe.mu.Unlock()
			if early {
				t.Fatal("the recheck killed a command whose grant still holds")
			}
			fell := time.Now()
			c.fall(t, env)
			got := readUntil(t, ws, 'X', 3*time.Second)
			if took := time.Since(fell); took > rootExecRecheck+time.Second {
				t.Fatalf("stopped %s after the wall fell; the recheck is every %s", took, rootExecRecheck)
			}
			if string(got['X']) != "126" {
				t.Fatalf("a command stopped by this machine answers X 126: X=%q E=%q", got['X'], got['E'])
			}
			var j map[string]any
			if err := json.Unmarshal(got['J'], &j); err != nil {
				t.Fatalf("a command that ran answers J: %v (J=%q)", err, got['J'])
			}
			if s, _ := j["stopped"].(string); !strings.Contains(s, c.want) {
				t.Fatalf("J must say why it stopped (~%q): %q", c.want, got['J'])
			}
			if j["stdout"] != "started\n" || !strings.Contains(string(got['E']), c.want) {
				t.Fatalf("J keeps the output and E says why: J=%q E=%q", got['J'], got['E'])
			}
			fe.mu.Lock()
			k := fe.killed
			fe.mu.Unlock()
			if !k {
				t.Fatal("the command must be killed")
			}
			if a := auditText(t, env); !strings.Contains(a, `"event":"stop"`) || !strings.Contains(a, `"exit":126`) {
				t.Fatalf("the stop must be audited with its reason:\n%s", a)
			}
		})
	}
}

// fenceRootExecGroups routes every group signal the code sends through a
// fence that admits only the process groups this test started itself. A
// group is admitted once the test has read it from /proc as its own child
// leading its own group, never from what the code under test reports, so a
// Kill that aimed anywhere else (0 is the test's own group, -1 is every
// process) is refused and fails the test instead of reaching the machine.
func fenceRootExecGroups(t *testing.T) (admit func(pid int)) {
	t.Helper()
	var mu sync.Mutex
	allowed := map[int]bool{}
	var refused []int
	old := rootExecSignalGroup
	rootExecSignalGroup = func(pgid int, sig syscall.Signal) error {
		mu.Lock()
		ok := allowed[pgid]
		if !ok {
			refused = append(refused, pgid)
		}
		mu.Unlock()
		if !ok {
			return syscall.EPERM
		}
		return syscall.Kill(-pgid, sig)
	}
	t.Cleanup(func() {
		rootExecSignalGroup = old
		mu.Lock()
		defer mu.Unlock()
		if len(refused) > 0 {
			t.Errorf("Kill signalled process groups this test did not start: %v", refused)
		}
	})
	return func(pid int) {
		st, ok := procStat(pid)
		if !ok || pid <= 1 || st.ppid != os.Getpid() || st.pgrp != pid {
			t.Fatalf("pid %d is not a group leader this test started: %+v", pid, st)
		}
		mu.Lock()
		allowed[pid] = true
		mu.Unlock()
	}
}

type procStatLine struct {
	state byte
	ppid  int
	pgrp  int
}

// procStat reads state, parent and process group from /proc/<pid>/stat.
func procStat(pid int) (procStatLine, bool) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return procStatLine{}, false
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return procStatLine{}, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 3 || len(f[0]) != 1 {
		return procStatLine{}, false
	}
	ppid, _ := strconv.Atoi(f[1])
	pgrp, _ := strconv.Atoi(f[2])
	return procStatLine{state: f[0][0], ppid: ppid, pgrp: pgrp}, true
}

// groupLiving lists the processes in group pgid that are still alive: a
// zombie has ended and is only waiting for its parent to collect it.
func groupLiving(pgid int) []int {
	ents, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if st, ok := procStat(pid); ok && st.pgrp == pgid && st.state != 'Z' && st.state != 'X' {
			out = append(out, pid)
		}
	}
	return out
}

// The deadline ends the whole process group, a child that ignores SIGTERM
// included: SIGKILL follows the grace whether or not the shell has already
// gone. Run through the handler with the real starter, so the measured time
// is the one the host sees.
//
// MUTATION: skip the SIGKILL when Wait has returned within the grace.
// RESULT: red — the sleep that traps SIGTERM is still alive after X.
func TestRootExecDeadlineKillsAChildThatIgnoresSIGTERM(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc here to read the process group from")
	}
	for _, c := range []struct{ name, command string }{
		// the trapping child holds nothing open: Wait returns the moment the shell dies
		{"output closed", "(trap '' TERM; exec sleep 37) >/dev/null 2>&1 & sleep 37"},
		// the trapping child holds the output open, as far as WaitDelay
		{"output held", "(trap '' TERM; exec sleep 37) & sleep 37"},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := rootExecBox(t, true)
			admit := fenceRootExecGroups(t)
			var mu sync.Mutex
			pgid := 0
			old := rootExecStart
			rootExecStart = func(command string, so, se io.Writer, cgroupFD int) (rootExecProc, error) {
				p, err := startRootExec(command, so, se, cgroupFD)
				if err == nil {
					pid := p.(*shellProc).cmd.Process.Pid
					admit(pid)
					mu.Lock()
					pgid = pid
					mu.Unlock()
				}
				return p, err
			}
			t.Cleanup(func() { rootExecStart = old })
			ws := sessionDialAs(t, env, tAnchor)
			start := time.Now()
			sendExec(t, ws, "exec-trap1", c.command, 1, 0)
			got := readUntil(t, ws, 'X', 15*time.Second)
			took := time.Since(start)
			mu.Lock()
			g := pgid
			mu.Unlock()
			if g == 0 {
				t.Fatalf("the command never started: X=%q E=%q", got['X'], got['E'])
			}
			t.Cleanup(func() {
				for _, pid := range groupLiving(g) {
					_ = syscall.Kill(pid, syscall.SIGKILL) // only what this test started, read back from /proc
				}
			})
			if string(got['X']) != "124" {
				t.Fatalf("deadline: X=%q E=%q", got['X'], got['E'])
			}
			if lim := time.Second + rootExecKillGrace + 1500*time.Millisecond; took > lim {
				t.Fatalf("answered after %s; the deadline is 1s and the grace %s", took, rootExecKillGrace)
			}
			// SIGKILL has been sent by now; a killed process ends when it next
			// runs, so it gets a moment, never the trap's 37 seconds.
			left := groupLiving(g)
			for end := time.Now().Add(time.Second); len(left) > 0 && time.Now().Before(end); left = groupLiving(g) {
				time.Sleep(20 * time.Millisecond)
			}
			if len(left) > 0 {
				t.Fatalf("the process group outlived the deadline and the grace: %v still alive", left)
			}
		})
	}
}

// Every outcome leaves an audit row, the ones that never reach the walls too.
//
// MUTATION: remove the rootExecAudit call from the bad-command or the
// transcript branch of handleRootExec.
// RESULT: red — that case finds no row.
func TestRootExecBadCommandAndTranscriptFailureAreAudited(t *testing.T) {
	env := rootExecBox(t, true)
	fe := withFakeExec(t, "", "", 0, false)
	for i, c := range []string{"", "a\x00b", strings.Repeat("x", rootExecCommandMax+1)} {
		sid := fmt.Sprintf("exec-audbad-%d", i)
		ws := sessionDialAs(t, env, tAnchor)
		sendExec(t, ws, sid, c, 0, 0)
		if got := readUntil(t, ws, 'X', 5*time.Second); string(got['X']) != "1" {
			t.Fatalf("case %d: want X 1, got %q", i, got['X'])
		}
		row := auditRow(t, env, sid)
		if row == nil {
			t.Fatalf("case %d: a bad command left no audit row:\n%s", i, auditText(t, env))
		}
		if row["exit"] != float64(1) || !strings.Contains(fmt.Sprint(row["decision"]), "bad command") ||
			row["command_bytes"] != float64(len(c)) || row["command_sha256"] == nil {
			t.Fatalf("case %d: the row must say bad command, exit 1, its size and its sha256: %v", i, row)
		}
	}
	// A session id the lane will not take, on a root command.
	ws0 := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws0, "bad id!", "id", 0, 0)
	if got := readUntil(t, ws0, 'X', 5*time.Second); string(got['X']) != "1" {
		t.Fatalf("bad session id: want X 1, got %q", got['X'])
	}
	if row := auditRow(t, env, "bad id!"); row == nil || row["command"] != "id" ||
		!strings.Contains(fmt.Sprint(row["decision"]), "session_id") {
		t.Fatalf("a root command with a bad session id must leave a row with its command: %v\n%s", row, auditText(t, env))
	}
	// A transcript that cannot be opened: one already there under that id.
	sid := "exec-audtr1"
	if err := os.MkdirAll(filepath.Join(env.CtxRoot, "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.CtxRoot, "sessions", sid+".log"), []byte("earlier\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := sessionDialAs(t, env, tAnchor)
	sendExec(t, ws, sid, "id", 0, 0)
	if got := readUntil(t, ws, 'X', 5*time.Second); string(got['X']) != "1" {
		t.Fatalf("transcript failure: want X 1, got X=%q E=%q", got['X'], got['E'])
	}
	row := auditRow(t, env, sid)
	if row == nil {
		t.Fatalf("a transcript that failed to open left no audit row:\n%s", auditText(t, env))
	}
	if row["exit"] != float64(1) || !strings.Contains(fmt.Sprint(row["decision"]), "transcript") || row["command"] != "id" {
		t.Fatalf("the row must say transcript, exit 1 and the command: %v", row)
	}
	if len(fe.ran()) != 0 {
		t.Fatal("neither may start")
	}
}

// auditRow is the last root-command row in the audit file for one session id.
func auditRow(t *testing.T, env sessionEnv, sid string) map[string]any {
	t.Helper()
	var last map[string]any
	for _, line := range strings.Split(auditText(t, env), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["session_id"] == sid && m["op"] == sessionOpRootExec {
			last = m
		}
	}
	return last
}

// The ceremony: the grant exists only through the code enrolled here, once
// per code, with an expiry, and a revoke takes it back.
func TestRootExecGrantCeremony(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if _, err := rootExecGrantWithCode(dir, "h", "box1", "123456", time.Hour, now); err == nil ||
		!strings.Contains(err.Error(), "second factor") {
		t.Fatalf("no factor enrolled must refuse: %v", err)
	}
	if err := stepupSave(dir, &stepupFile{SecretB32: rootExecTestSecret, EnrolledAt: "2026-10-11T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	code := rootExecCode(t, now)
	if _, err := rootExecGrantWithCode(dir, "h", "box1", code, 0, now); err == nil {
		t.Fatal("a grant with no expiry must be refused")
	}
	if _, err := rootExecGrantWithCode(dir, "h", "box1", code, 400*24*time.Hour, now); err == nil {
		t.Fatal("a grant past the longest term must be refused")
	}
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	if _, err := rootExecGrantWithCode(dir, "h", "box1", wrong, time.Hour, now); err == nil {
		t.Fatal("a wrong code must not grant")
	}
	if _, err := os.Stat(rootExecGrantPath(dir)); err == nil {
		t.Fatal("no grant may exist before a code checked out")
	}
	g, err := rootExecGrantWithCode(dir, "h", "box1", code, 30*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if why := rootExecGrantCheck(dir, "h", "box1", now); why != "" {
		t.Fatalf("a fresh grant must admit: %s", why)
	}
	if why := rootExecGrantCheck(dir, "h", "box1", now.Add(31*24*time.Hour)); !strings.Contains(why, "expired") {
		t.Fatalf("past its expiry the grant must refuse: %q", why)
	}
	if _, err := rootExecGrantWithCode(dir, "h", "box1", code, time.Hour, now); err == nil {
		t.Fatal("REPLAY: the same code must not grant twice")
	}
	if g.Expires != now.Add(30*24*time.Hour).UTC().Format(time.RFC3339) {
		t.Fatalf("expiry: %s", g.Expires)
	}
	if _, err := rootExecRevoke(dir, now); err != nil {
		t.Fatal(err)
	}
	if why := rootExecGrantCheck(dir, "h", "box1", now); !strings.Contains(why, "revoked") {
		t.Fatalf("a revoked grant must refuse: %q", why)
	}
	for in, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "12h": 12 * time.Hour, "90m": 90 * time.Minute} {
		if d, err := parseGrantFor(in); err != nil || d != want {
			t.Fatalf("parseGrantFor(%q) = %v, %v", in, d, err)
		}
	}
	for _, bad := range []string{"", "0d", "-1d", "forever", "-5h"} {
		if _, err := parseGrantFor(bad); err == nil {
			t.Fatalf("parseGrantFor(%q) must fail", bad)
		}
	}
}

// The op is advertised with the other session ops, so a grant can name it
// and a deny can refuse it.
func TestRootExecOpAdvertised(t *testing.T) {
	found := false
	for _, o := range sessionOps {
		found = found || o == sessionOpRootExec
	}
	if !found || opFamily(sessionOpRootExec) != "session" {
		t.Fatalf("sessionOps=%v family=%q", sessionOps, opFamily(sessionOpRootExec))
	}
}
