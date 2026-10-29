//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// stubObserveReads puts every exec of the four ops behind answer and records
// each argv, joined by spaces, in the order run. Every tool is present and
// the journal readable unless a test says otherwise.
func stubObserveReads(t *testing.T, answer func(argv string) ([]byte, error)) func() []string {
	t.Helper()
	var mu sync.Mutex
	var recorded []string
	origExec, origHave, origAccess, origOwn := observeExec, observeHave, observeJournalAccess, observeOwnAddrs
	observeExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		argv := strings.Join(append([]string{name}, args...), " ")
		mu.Lock()
		recorded = append(recorded, argv)
		mu.Unlock()
		return answer(argv)
	}
	observeHave = func(string) bool { return true }
	observeJournalAccess = func() string { return "" }
	t.Cleanup(func() {
		observeExec, observeHave, observeJournalAccess, observeOwnAddrs = origExec, origHave, origAccess, origOwn
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), recorded...)
		recorded = nil
		return out
	}
}

func unitAnswers(journal string) func(string) ([]byte, error) {
	return func(argv string) ([]byte, error) {
		switch {
		case strings.HasPrefix(argv, "systemctl list-units "):
			return []byte(fxListUnits), nil
		case strings.HasPrefix(argv, "systemctl list-unit-files "):
			return []byte(fxUnitFiles), nil
		case strings.HasPrefix(argv, "journalctl "):
			return []byte(journal), nil
		}
		return nil, errors.New("unexpected " + argv)
	}
}

// ── observe:journal ──────────────────────────────────────────────────────────

// observe:journal runs exactly three argvs, and the unit reaches the third
// only as a name this machine's own lists hold, bound to --unit=.
func TestObserveJournalRunsOnlyItsPinnedArgv(t *testing.T) {
	log := "2026-10-29T10:00:00+00:00 box-a example[42]: started\n" +
		"2026-10-29T10:00:05+00:00 box-a example[42]: listening on 8080\n"
	recorded := stubObserveReads(t, unitAnswers(log))
	out, errOut, code := driveObserve(t, "observe:journal", []string{"example", "5"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	want := []string{
		"systemctl list-units --all --no-legend --plain",
		"systemctl list-unit-files --no-legend --plain",
		"journalctl --unit=example.service --since=-5min -o short-iso --no-pager -q --lines=" +
			strconv.Itoa(observeLogLineLimit),
	}
	if got := recorded(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("argvs\n got: %q\nwant: %q", got, want)
	}
	var rep journalReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !rep.Supported || rep.Unit != "example.service" || rep.Minutes != 5 || rep.Lines != 2 || rep.Truncated ||
		!strings.HasSuffix(rep.Log, "listening on 8080") || rep.Note != "" || rep.Source != "journal" {
		t.Fatalf("%+v", rep)
	}

	// Installed and unloaded since, and an instance of an installed template:
	// both are this machine's units.
	for unit, want := range map[string]string{"report": "--unit=report.service", "worker@3": "--unit=worker@3.service"} {
		if _, errOut, code := driveObserve(t, "observe:journal", []string{unit}); code != 0 {
			t.Fatalf("%s: exit %d %s", unit, code, errOut)
		}
		got := recorded()
		if len(got) != 3 || !strings.HasPrefix(got[2], "journalctl "+want+" --since=-15min ") {
			t.Fatalf("%s: %q", unit, got)
		}
	}

	// A unit this machine does not have, or knows only as not-found, is
	// refused before journalctl runs, and the refusal names the near ones.
	for unit, hint := range map[string]string{"ssh": "ssh.socket", "gone": "no unit gone.service"} {
		_, errOut, code := driveObserve(t, "observe:journal", []string{unit})
		if code != 2 || !strings.Contains(errOut, "refused: this machine has no unit") || !strings.Contains(errOut, hint) {
			t.Fatalf("%s: code=%d err=%q", unit, code, errOut)
		}
		for _, argv := range recorded() {
			if strings.HasPrefix(argv, "journalctl") {
				t.Fatalf("%s: journalctl ran for a unit this machine does not have: %q", unit, argv)
			}
		}
	}
}

func TestObserveJournalSaysWhyItCannotAnswer(t *testing.T) {
	recorded := stubObserveReads(t, unitAnswers(""))
	// Empty: a note that names the unit and the window.
	out, _, code := driveObserve(t, "observe:journal", []string{"example.service", "1"})
	var rep journalReport
	_ = json.Unmarshal([]byte(out), &rep)
	if code != 0 || !rep.Supported || rep.Lines != 0 || rep.Log != "" ||
		rep.Note != "no lines from example.service in the last 1 minutes" {
		t.Fatalf("empty: %d %+v", code, rep)
	}
	recorded()

	// An account that cannot read the system journal: said, at exit 0, and
	// nothing is run — journalctl would show that account's own lines only.
	observeJournalAccess = func() string { return "cannot read the system journal" }
	out, _, code = driveObserve(t, "observe:journal", []string{"example"})
	rep = journalReport{}
	_ = json.Unmarshal([]byte(out), &rep)
	if code != 0 || rep.Supported || rep.Reason != "cannot read the system journal" || len(recorded()) != 0 {
		t.Fatalf("no access: %d %+v", code, rep)
	}
	observeJournalAccess = func() string { return "" }

	// A list-units that failed is not an empty list: every unit would be
	// refused as unknown.
	observeExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("exit status 1")
	}
	out, _, code = driveObserve(t, "observe:journal", []string{"example"})
	rep = journalReport{}
	_ = json.Unmarshal([]byte(out), &rep)
	if code != 0 || rep.Supported || !strings.Contains(rep.Reason, "systemctl list-units: exit status 1") {
		t.Fatalf("failed list: %d %+v", code, rep)
	}
	// And a failed list-unit-files: an installed unit that is not loaded now
	// would otherwise be refused as one this machine does not have.
	observeExec = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if args[0] == "list-units" {
			return []byte(fxListUnits), nil
		}
		return nil, errors.New("exit status 1")
	}
	out, _, code = driveObserve(t, "observe:journal", []string{"report"})
	rep = journalReport{}
	_ = json.Unmarshal([]byte(out), &rep)
	if code != 0 || rep.Supported || !strings.Contains(rep.Reason, "systemctl list-unit-files: exit status 1") {
		t.Fatalf("failed unit files: %d %+v", code, rep)
	}
}

// ── observe:logins ───────────────────────────────────────────────────────────

func TestObserveLoginsRunsItsPinnedArgv(t *testing.T) {
	recorded := stubObserveReads(t, func(argv string) ([]byte, error) { return []byte(fxSSHD), nil })
	out, errOut, code := driveObserve(t, "observe:logins", []string{"48"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	want := "journalctl --since=-48h -o short-iso --no-pager -q --lines=" + strconv.Itoa(loginsLineCap) +
		" _COMM=sshd _COMM=sshd-session _COMM=sshd-auth _UID=0 + _SYSTEMD_UNIT=ssh.service _SYSTEMD_UNIT=sshd.service _UID=0"
	if got := recorded(); len(got) != 1 || got[0] != want {
		t.Fatalf("argv\n got: %q\nwant: %q", got, want)
	}
	var rep loginsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !rep.Supported || rep.Hours != 48 || rep.FailedTotal != 8 || rep.FailedSources != 5 || rep.AcceptedTotal != 2 ||
		rep.EntriesRead != 16 || rep.Truncated || rep.Note != "" || rep.OldestEntry != "2026-10-29T10:00:01Z" {
		t.Fatalf("%+v", rep)
	}
	if _, _, code := driveObserve(t, "observe:logins", nil); code != 0 || !strings.HasPrefix(recorded()[0], "journalctl --since=-24h ") {
		t.Fatalf("the default window is 24 hours")
	}

	// No journal access: unknown, not zero.
	observeJournalAccess = func() string { return "cannot read the system journal" }
	out, _, code = driveObserve(t, "observe:logins", nil)
	rep = loginsReport{}
	_ = json.Unmarshal([]byte(out), &rep)
	if code != 0 || rep.Supported || rep.FailedTotal != -1 || rep.AcceptedTotal != -1 || len(recorded()) != 0 {
		t.Fatalf("no access must read unknown (-1), never 0: %d %+v", code, rep)
	}
	observeJournalAccess = func() string { return "" }

	// Nothing logged: zeros, and a note that says which window was empty.
	observeExec = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	out, _, _ = driveObserve(t, "observe:logins", []string{"1"})
	rep = loginsReport{}
	_ = json.Unmarshal([]byte(out), &rep)
	if !rep.Supported || rep.FailedTotal != 0 || rep.Note != "no sshd entries in the journal in the last 1 hours" ||
		rep.FailedBySource == nil || rep.Accepted == nil {
		t.Fatalf("empty: %+v", rep)
	}
}

// Any account can name a process sshd (copy a logger, call it sshd) and
// write lines journald files under _COMM=sshd, and an account whose shell
// stays in ssh.service's cgroup (no pam_systemd) writes under that unit. Only
// root's lines count: every message this op reads is the root monitor's
// (OpenSSH logs its unprivileged child through it), and _UID is journald's
// own, from the sender's credentials. Each disjunct carries _UID=0, so no
// match reads a non-root line.
func TestObserveLoginsCountsOnlyRootsSSHDLines(t *testing.T) {
	recorded := stubObserveReads(t, func(string) ([]byte, error) { return nil, nil })
	if _, errOut, code := driveObserve(t, "observe:logins", nil); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := recorded()
	if len(got) != 1 {
		t.Fatalf("%q", got)
	}
	f := strings.Fields(got[0])
	start := 0
	for i, a := range f {
		if strings.HasPrefix(a, "--lines=") {
			start = i + 1
		}
	}
	if start == 0 || start >= len(f) {
		t.Fatalf("no matches after --lines: %q", got[0])
	}
	var groups [][]string
	cur := []string{}
	for _, a := range f[start:] {
		if a == "+" {
			groups, cur = append(groups, cur), []string{}
			continue
		}
		cur = append(cur, a)
	}
	groups = append(groups, cur)
	for _, g := range groups {
		uid := false
		for _, a := range g {
			uid = uid || a == "_UID=0"
		}
		if !uid {
			t.Fatalf("a match reads lines any account can write: %q in %q", g, got[0])
		}
	}
}

// ── observe:cert ─────────────────────────────────────────────────────────────

func ssLine(local string, port int) string {
	return "LISTEN 0      4096       " + local + ":" + strconv.Itoa(port) + "   0.0.0.0:* users:((\"example\",pid=10,fd=3))\n"
}

// The port must be one this machine listens on, the listener table is ss's,
// and the handshake goes to loopback or this machine's own addresses only.
func TestObserveCertReadsOnlyThisMachinesListener(t *testing.T) {
	cert := observeTestCert(t, "box-a.example", []string{"box-a.example"}, nil, time.Now().Add(10*24*time.Hour+time.Hour))
	port := observeTLSListener(t, cert)
	foreign := closedPort(t)
	ss := ssLine("127.0.0.1", port) + ssLine("192.0.2.50", foreign)
	recorded := stubObserveReads(t, func(argv string) ([]byte, error) {
		if argv == "ss -tlnpH" {
			return []byte(ss), nil
		}
		return nil, errors.New("unexpected " + argv)
	})
	observeOwnAddrs = func() map[netip.Addr]bool { return map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true} }

	out, errOut, code := driveObserve(t, "observe:cert", []string{strconv.Itoa(port), "box-a.example"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if got := recorded(); len(got) != 1 || got[0] != "ss -tlnpH" {
		t.Fatalf("the one argv is observe:sockets' tcp read: %q", got)
	}
	var rep certReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !rep.Supported || rep.ConnectedTo != "127.0.0.1:"+strconv.Itoa(port) || !rep.TLS || rep.ServerName != "box-a.example" ||
		len(rep.Listening) != 1 || rep.Listening[0] != "127.0.0.1" || rep.DaysLeft == nil || *rep.DaysLeft != 10 ||
		rep.ChainVerified == nil || *rep.ChainVerified || rep.CheckedAt == "" {
		t.Fatalf("%s", out)
	}

	// Nothing listens: refused, and nothing dialled.
	_, errOut, code = driveObserve(t, "observe:cert", []string{"1"})
	if code != 2 || !strings.Contains(errOut, "refused: nothing on this machine listens on tcp port 1") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}

	// A listener bound to an address this machine does not hold: loopback is
	// tried and the other address never is — it would reach another machine.
	out, _, code = driveObserve(t, "observe:cert", []string{strconv.Itoa(foreign)})
	rep = certReport{}
	_ = json.Unmarshal([]byte(out), &rep)
	if code != 0 || !rep.Supported || rep.ConnectedTo != "" || len(rep.Tried) != 2 || rep.TLS {
		t.Fatalf("%d %s", code, out)
	}
	for _, tried := range rep.Tried {
		if strings.Contains(tried, "192.0.2.50") {
			t.Fatalf("dialled an address this machine does not hold: %v", rep.Tried)
		}
	}

	// A failed ss is not an empty table: it says so instead of refusing.
	observeExec = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("exit status 1") }
	out, _, code = driveObserve(t, "observe:cert", []string{strconv.Itoa(port)})
	rep = certReport{}
	_ = json.Unmarshal([]byte(out), &rep)
	if code != 0 || rep.Supported || rep.Reason != "ss: exit status 1" {
		t.Fatalf("%d %s", code, out)
	}
}

// ── observe:folders ──────────────────────────────────────────────────────────

func writeFile(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), n), 0o644); err != nil {
		t.Fatal(err)
	}
}

// folderTree is a tree with a nested chain, a folder with one file linked
// twice, a file linked from a second folder, and an empty folder.
func folderTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root+"/a/a1", 64<<10)
	writeFile(t, root+"/a/b/b1", 32<<10)
	writeFile(t, root+"/a/b/c/c1", 16<<10)
	writeFile(t, root+"/a/b/c/d/d1", 8<<10)
	writeFile(t, root+"/big/big1", 256<<10)
	if err := os.Link(root+"/big/big1", root+"/big/big1-again"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/empty", 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func blocksOf(t *testing.T, p string) int64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return int64(st.Blocks) * 512
}

func TestObserveFoldersSizesTheTree(t *testing.T) {
	root := folderTree(t)
	rep, err := readFolders(root, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Supported || !rep.Complete || rep.Partial != "" || rep.Path != root || rep.Resolved != "" || rep.Depth != 2 {
		t.Fatalf("%+v", rep)
	}
	// What is expected, from the blocks of each thing: big1 once, though two
	// names link it.
	dirs := func(ps ...string) (n int64) {
		for _, p := range ps {
			n += blocksOf(t, p)
		}
		return n
	}
	c := dirs(root+"/a/b/c", root+"/a/b/c/c1", root+"/a/b/c/d", root+"/a/b/c/d/d1")
	b := dirs(root+"/a/b", root+"/a/b/b1") + c
	a := dirs(root+"/a", root+"/a/a1") + b
	bigd := dirs(root+"/big", root+"/big/big1")
	empty := dirs(root + "/empty")
	want := map[string]int64{root + "/a": a, root + "/a/b": b, root + "/big": bigd, root + "/empty": empty}
	if rep.Sized != len(want) || len(rep.Folders) != len(want) {
		t.Fatalf("depth 2 sizes the folders at 1 and 2 below the path: %+v", rep.Folders)
	}
	for _, f := range rep.Folders {
		if want[f.Path] != f.Bytes {
			t.Fatalf("%s: %d, want %d", f.Path, f.Bytes, want[f.Path])
		}
		if f.Depth != strings.Count(strings.TrimPrefix(f.Path, root), "/") {
			t.Fatalf("depth of %s: %d", f.Path, f.Depth)
		}
		if strings.Contains(f.Path, "/a/b/c") {
			t.Fatalf("a folder below the depth was named: %s", f.Path)
		}
	}
	if rep.TotalBytes != blocksOf(t, root)+a+bigd+empty {
		t.Fatalf("total %d", rep.TotalBytes)
	}
	if rep.Folders[0].Path != root+"/big" && rep.Folders[0].Path != root+"/a" {
		t.Fatalf("largest first: %+v", rep.Folders)
	}
	// Only folders: no file name anywhere in the answer.
	raw, _ := json.Marshal(rep)
	for _, file := range []string{"a1", "b1", "c1", "d1", "big1"} {
		if strings.Contains(string(raw), "/"+file) {
			t.Fatalf("a file name reached the answer: %s", raw)
		}
	}

	// Through a symlink: sized where it leads, and said so.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	rep, err = readFolders(link, 1)
	if err != nil || rep.Resolved != root || rep.Path != link || rep.Sized != 3 {
		t.Fatalf("%v %+v", err, rep)
	}
}

// The same tree measured by du: the op's numbers are du -x's, folder for
// folder. Skipped where there is no GNU du to ask.
func TestObserveFoldersAgreesWithDu(t *testing.T) {
	if _, err := exec.LookPath("du"); err != nil {
		t.Skip("no du here")
	}
	root := folderTree(t)
	out, err := exec.Command("du", "-x", "-B1", "--max-depth=2", root).Output()
	if err != nil {
		t.Skipf("not a du that takes -B1 --max-depth: %v", err)
	}
	du := map[string]int64{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		n, p, _ := strings.Cut(l, "\t")
		du[p], _ = strconv.ParseInt(n, 10, 64)
	}
	rep, err := readFolders(root, 2)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalBytes != du[root] {
		t.Fatalf("total %d, du %d", rep.TotalBytes, du[root])
	}
	for _, f := range rep.Folders {
		if du[f.Path] != f.Bytes {
			t.Fatalf("%s: %d, du %d", f.Path, f.Bytes, du[f.Path])
		}
	}
}

// A mount point under the path is not crossed and not stat'd, and is
// reported against the folder at the asked depth that holds it.
func TestObserveFoldersDoesNotCrossAMount(t *testing.T) {
	root := folderTree(t)
	var st syscall.Stat_t
	if err := syscall.Lstat(root, &st); err != nil {
		t.Fatal(err)
	}
	walk := func(depth int, mounts ...string) *folderWalk {
		w := &folderWalk{ctx: context.Background(), root: root, depth: depth, dev: uint64(st.Dev),
			mounts: map[string]bool{}, linked: map[uint64]struct{}{}}
		for _, m := range mounts {
			w.mounts[m] = true
		}
		w.dir(root, 0, &st)
		return w
	}
	w := walk(2, root+"/a/b")
	for _, f := range w.top.sorted() {
		if f.Path == root+"/a/b" {
			t.Fatalf("a mount point was sized: %+v", f)
		}
		if f.Path == root+"/a" && f.Bytes != blocksOf(t, root+"/a")+blocksOf(t, root+"/a/a1") {
			t.Fatalf("what is under the mount was counted: %+v", f)
		}
	}
	if l := w.skips.list(); len(l) != 1 || l[0].Path != root+"/a/b" || l[0].Reason != reasonOtherFS || l[0].Count != 1 {
		t.Fatalf("%+v", l)
	}
	w = walk(1, root+"/a/b/c/d")
	if l := w.skips.list(); len(l) != 1 || l[0].Path != root+"/a" {
		t.Fatalf("a deep skip is named by its folder at the asked depth: %+v", l)
	}
	// A different device on a folder, as a mount made after the table was
	// read looks: not crossed either.
	w = &folderWalk{ctx: context.Background(), root: root, depth: 2, dev: uint64(st.Dev) + 1,
		mounts: map[string]bool{}, linked: map[uint64]struct{}{}}
	w.dir(root, 0, &st)
	if w.sized != 0 || w.skips.total != 3 {
		t.Fatalf("every subfolder is on another device here: sized %d skipped %d", w.sized, w.skips.total)
	}
}

// A folder swapped for a link between the walk's stat and its open, or one
// reached through a folder above it that was, is not read: the walk reads
// only the folder it stat'd, so a link can never lead it elsewhere, onto
// another filesystem or into /proc. Here elsewhere is on the same filesystem,
// so the device alone would not tell; the inode does.
func TestObserveFoldersReadsOnlyTheFolderItStatd(t *testing.T) {
	for _, tc := range []struct{ name, swap string }{
		{"the folder itself", "/a/b"},
		{"a folder above it", "/a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := folderTree(t)
			elsewhere := t.TempDir()
			writeFile(t, elsewhere+"/b/elsewhere1", 4<<20)
			target := elsewhere
			if tc.swap == "/a/b" {
				target = elsewhere + "/b"
			}
			orig := folderBeforeOpen
			t.Cleanup(func() { folderBeforeOpen = orig })
			folderBeforeOpen = func(p string) {
				if p != root+"/a/b" {
					return
				}
				if err := os.Rename(root+tc.swap, root+tc.swap+".moved"); err != nil {
					t.Error(err)
				}
				if err := os.Symlink(target, root+tc.swap); err != nil {
					t.Error(err)
				}
			}
			rep, err := readFolders(root, 3)
			if err != nil {
				t.Fatal(err)
			}
			if rep.TotalBytes >= 4<<20 {
				t.Fatalf("the walk read a folder it never stat'd: total %d, %+v", rep.TotalBytes, rep.Folders)
			}
			for _, f := range rep.Folders {
				if f.Bytes >= 4<<20 {
					t.Fatalf("the walk read a folder it never stat'd: %+v", f)
				}
			}
			found := false
			for _, s := range rep.Skipped {
				found = found || (s.Path == root+"/a/b" && s.Reason == reasonChanged)
			}
			if !found {
				t.Fatalf("the swapped folder is not said: %+v", rep.Skipped)
			}
		})
	}
}

// A walk inside a read that never returns (a hard network mount that went
// away) keeps its thread however long that read hangs. The op answers at the
// budget either way, and past folderStuckMax such walks it starts no more, so
// a Host asking again and again cannot pile threads up until the bastion can
// start none. A walk that comes back frees its place.
func TestObserveFoldersStartsNoWalkPastTheStuckOnes(t *testing.T) {
	origSizer, origGrace, origBudget := folderSizer, folderStuckGrace, observeOpBudget
	release := make(chan struct{})
	var started atomic.Int32
	folderSizer = func(context.Context, string, int) (foldersReport, error) {
		started.Add(1)
		<-release
		return foldersReport{}, nil
	}
	folderStuckGrace, observeOpBudget = time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		folderSizer, folderStuckGrace, observeOpBudget = origSizer, origGrace, origBudget
	})
	for i := 0; i < folderStuckMax+3; i++ {
		rep, err := readFolders("/srv", 1)
		if err != nil || rep.Partial == "" || len(rep.Folders) != 0 {
			t.Fatalf("call %d: %v %+v", i, err, rep)
		}
	}
	if n := started.Load(); n != folderStuckMax {
		t.Fatalf("%d walks started behind reads that never returned; at most %d may", n, folderStuckMax)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for folderWalksStuck.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := folderWalksStuck.Load(); n != 0 {
		t.Fatalf("walks that came back still hold %d places", n)
	}
	folderSizer = func(context.Context, string, int) (foldersReport, error) {
		started.Add(1)
		return foldersReport{Supported: true, Complete: true}, nil
	}
	observeOpBudget = time.Second
	if rep, err := readFolders("/srv", 1); err != nil || !rep.Complete {
		t.Fatalf("a walk once the stuck ones came back: %v %+v", err, rep)
	}
}

func TestObserveFoldersRefusalsAndBudget(t *testing.T) {
	root := folderTree(t)
	for p, want := range map[string]string{
		root + "/a/a1":      "not a folder",
		root + "/missing":   "no folder at that path",
		root + "/a/missing": "no folder at that path",
	} {
		if _, err := readFolders(p, 2); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	// A link into /proc is refused like /proc.
	link := filepath.Join(t.TempDir(), "into-proc")
	if err := os.Symlink("/proc/self", link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFolders(link, 1); err == nil || err.Error() != errFolderKernelTree {
		t.Fatalf("%v", err)
	}
	// Through the dispatcher: refused at exit 2 without the path.
	_, errOut, code := driveObserve(t, "observe:folders", []string{root + "/a/a1"})
	if code != 2 || !strings.Contains(errOut, "not a folder") || strings.Contains(errOut, root) {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	// An unreadable folder is named in skipped. Root reads every folder, so
	// this half runs as a user only.
	if os.Geteuid() != 0 {
		if err := os.Chmod(root+"/a/b", 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(root+"/a/b", 0o755)
		rep, err := readFolders(root, 1)
		if err != nil || len(rep.Skipped) != 1 || rep.Skipped[0].Path != root+"/a" || rep.Skipped[0].Reason != "permission denied" {
			t.Fatalf("%v %+v", err, rep.Skipped)
		}
		_ = os.Chmod(root+"/a/b", 0o755)
	}
	// Out of budget: an answer, marked incomplete, never a hang.
	orig := observeOpBudget
	observeOpBudget = time.Nanosecond
	defer func() { observeOpBudget = orig }()
	rep, err := readFolders(root, 2)
	if err != nil || rep.Complete || rep.Partial != "timeout" || rep.Note == "" {
		t.Fatalf("%v %+v", err, rep)
	}
}

// Through the dispatcher, the answer is the report.
func TestObserveFoldersThroughTheLane(t *testing.T) {
	root := folderTree(t)
	out, errOut, code := driveObserve(t, "observe:folders", []string{root, "1"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var rep foldersReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !rep.Supported || rep.Depth != 1 || rep.Sized != 3 || len(rep.Folders) != 3 || !rep.Complete || rep.Skipped == nil {
		t.Fatalf("%s", out)
	}
	for _, f := range rep.Folders {
		if f.Depth != 1 {
			t.Fatalf("depth 1 names only the folders directly under the path: %+v", f)
		}
	}
}

// The four against this machine, through the real dispatcher with the real
// programs — the same switch as TestObserveLive. A machine without systemd
// answers journal and logins with a reason, which is an answer.
func TestObserveReadsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real programs")
	}
	cert := observeTestCert(t, "box-a.example", []string{"box-a.example"}, nil, time.Now().Add(48*time.Hour))
	port := strconv.Itoa(observeTLSListener(t, cert))
	for _, c := range []struct {
		op   string
		args []string
		want string
	}{
		{"observe:folders", []string{"/etc", "1"}, `"supported":true`},
		{"observe:journal", []string{"systemd-journald", "5"}, `"source":"journal"`},
		{"observe:logins", []string{"1"}, `"hours":1`},
		{"observe:cert", []string{port, "box-a.example"}, `"connected_to":"127.0.0.1:` + port + `"`},
	} {
		// A machine without ss cannot say which ports it listens on, and the
		// cert read answers that as its own state (CI's container has no ss).
		if c.op == "observe:cert" {
			if _, err := exec.LookPath("ss"); err != nil {
				c.want = `"reason":"ss not installed`
			}
		}
		out, errOut, code := driveObserve(t, c.op, c.args)
		if code != 0 || !json.Valid([]byte(out)) || !strings.Contains(out, c.want) {
			t.Fatalf("%s: exit %d %s %s", c.op, code, errOut, out)
		}
		if len(out) > 300 {
			out = out[:300] + "…"
		}
		t.Logf("%s: %s", c.op, strings.TrimSpace(out))
	}
}
