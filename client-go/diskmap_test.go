package main

// The size walk, and the line it must not cross.
//
// The first two tests in this file are the reason the feature is allowed to
// exist at all: a size walk and a content index are different products with
// different consent (diskmap.go's header), and a comment saying so is not a
// wall. One holds the line structurally, one behaviourally, and they fail for
// different reasons on purpose.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dmTree writes a known tree and returns its root. Sizes are distinct primes
// of a sort, so a roll-up that double-counts or drops one is arithmetically
// visible rather than coincidentally right.
func dmTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel string, n int) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.mp4", 1000)
	write("b.txt", 200)
	write("docs/c.pdf", 3000)
	write("docs/d.pdf", 40)
	write("docs/deep/e.go", 7)
	write("empty/.keep", 0)
	return root
}

func dmScanTree(t *testing.T, root string) *dmResult {
	t.Helper()
	res := dmScan(context.Background(), []string{root}, dmMaxEntries, nil)
	if res == nil || len(res.Nodes) == 0 {
		t.Fatal("the walk produced nothing")
	}
	return res
}

// ── the line ────────────────────────────────────────────────────────────────

// dmContentReaders is the allow-list, and it is an allow-list on purpose.
//
// A DENY-LIST CANNOT WORK HERE. "a function that reads a file" is open-ended —
// os.Open, os.ReadFile, os.OpenFile, io.ReadAll, bufio.NewScanner,
// mmap, a third-party sniffer — and the one somebody adds next year is by
// definition the one not on the list. So this names the metadata calls the
// walk is allowed to make into os/io/bufio/ioutil, and every other call into
// those packages is a failure.
var dmMetadataOnly = map[string]bool{
	"os.Lstat":       true, // the walk's own device probe
	"os.Stat":        true, // never used today; harmless, follows a link but opens nothing
	"os.UserHomeDir": true, // a root, not a read
	"os.Getenv":      true,

	// Windows metadata, added when the audit was widened to cover
	// diskmap_windows.go. None of these opens a file:
	// GetLogicalDrives returns a bitmask, GetDriveType classifies a root by
	// name, UTF16PtrFromString converts a string in memory.
	"windows.GetLogicalDrives":   true,
	"windows.GetDriveType":       true,
	"windows.UTF16PtrFromString": true,
}

// TestTheWalkerNeverOpensAFile parses the walker's own source and fails on any
// call into os/io/bufio/io-util that is not metadata.
//
// AN AST WALK RATHER THAN A GREP, and the difference is the whole value: a
// substring search for "os.Open" trips on the words appearing in this file's
// own header — which is exactly where they DO appear, at length — and it
// passes a walker that reaches content through io.ReadAll(f). Parsing sees
// code and only code.
func TestTheWalkerNeverOpensAFile(t *testing.T) {
	// EVERY file, on EVERY platform. This used to parse three files and skip
	// diskmap_unix.go on Windows — which left diskmap_windows.go parsed by
	// NOBODY, anywhere, while diskmap_fifo_windows_test.go told the reader "the
	// AST half is what holds it there". The uncovered file
	// was precisely the one whose comments discuss opening a handle.
	//
	// Build tags are irrelevant here: parser.ParseFile reads source, it does not
	// select a build. A guard that only inspects the platform it happens to run
	// on is not a guard, it is a coincidence.
	for _, file := range []string{"diskmap.go", "diskmap_unix.go",
		"diskmap_windows.go", "uidiskmap.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		calls := 0
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			calls++
			switch pkg.Name {
			// syscall / x-sys are the OTHER way to open a file, and the audit
			// watched neither — so syscall.Open or windows.CreateFile would have
			// sailed through the check that exists to stop exactly that. Denied
			// by default; the handful of genuine metadata calls are named in
			// dmMetadataOnly.
			case "syscall", "unix":
				t.Errorf("%s:%d calls %s.%s — a raw syscall is how a walker opens a "+
					"file without touching os/io. The disk map reads names, sizes and "+
					"mtimes and NOTHING else (diskmap.go header). If this is genuinely "+
					"metadata, add it to dmMetadataOnly and say why.",
					file, fset.Position(call.Pos()).Line, pkg.Name, sel.Sel.Name)
			case "windows":
				full := "windows." + sel.Sel.Name
				if !dmMetadataOnly[full] {
					t.Errorf("%s:%d calls %s — not on the metadata allow-list. "+
						"windows.CreateFile and friends open handles; this feature may "+
						"not. Add it to dmMetadataOnly with a reason, or do not call it.",
						file, fset.Position(call.Pos()).Line, full)
				}
			case "io", "bufio", "ioutil":
				t.Errorf("%s:%d calls %s.%s — the disk map reads names, sizes and "+
					"mtimes and NOTHING else. A size walk and a content index are "+
					"different products with different consent (diskmap.go header).",
					file, fset.Position(call.Pos()).Line, pkg.Name, sel.Sel.Name)
			case "os":
				full := "os." + sel.Sel.Name
				if !dmMetadataOnly[full] {
					t.Errorf("%s:%d calls %s — not on the metadata allow-list. If this "+
						"is genuinely metadata, add it to dmMetadataOnly and say why; if "+
						"it touches content, it does not belong in this feature.",
						file, fset.Position(call.Pos()).Line, full)
				}
			}
			return true
		})
		// A file that parsed to nothing would pass every assertion above
		// without running one of them.
		if calls == 0 {
			t.Fatalf("%s: no package-qualified calls were inspected at all — "+
				"this test proved nothing", file)
		}
	}
}

// TestTheWalkerDoesNotOpenAFifo is the behavioural half, and it is sharper
// than the AST check in the one way that matters: it does not care HOW the
// content would be read.
//
// Opening a FIFO for reading blocks until a writer arrives. lstat on the same
// FIFO returns immediately. So a walker that opens what it finds hangs here
// and a walker that only stats it finishes in microseconds. The deadline is
// what turns that into a red test.
func TestTheWalkerDoesNotOpenAFifo(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := dmMkfifo(fifo); err != nil {
		t.Skipf("this platform has no named pipes to test with: %v", err)
	}
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("fixture is broken: %s is not a fifo (%v, %v)", fifo, fi, err)
	}
	if err := os.WriteFile(filepath.Join(root, "ordinary.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan *dmResult, 1)
	go func() { done <- dmScan(context.Background(), []string{root}, dmMaxEntries, nil) }()
	select {
	case res := <-done:
		// And it must have SEEN the fifo, or the walk skipped it and the test
		// proved nothing about opening.
		found := false
		for i := range res.Nodes {
			if res.Nodes[i].Name == "pipe" {
				found = true
			}
		}
		if !found {
			t.Fatal("the walk never reached the fifo, so this test did not exercise the open")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the walk did not finish within 10s with a named pipe in the tree. " +
			"Opening a fifo for reading blocks until a writer arrives; lstat does not. " +
			"Something in the walk is OPENING what it finds.")
	}
}

// ── what the walk counts ────────────────────────────────────────────────────

func TestASizeWalkRollsUpEveryDirectoryExactly(t *testing.T) {
	root := dmTree(t)
	res := dmScanTree(t, root)

	// 1000 + 200 + 3000 + 40 + 7 + 0
	const wantTotal = 4247
	if res.Bytes != wantTotal {
		t.Errorf("total bytes = %d, want %d", res.Bytes, wantTotal)
	}
	if res.Files != 6 {
		t.Errorf("files = %d, want 6", res.Files)
	}
	// root, docs, docs/deep, empty
	if res.Dirs != 4 {
		t.Errorf("dirs = %d, want 4", res.Dirs)
	}

	for path, want := range map[string]int64{
		root:                                        wantTotal,
		filepath.Join(root, "docs"):                 3047,
		filepath.Join(root, "docs", "deep"):         7,
		filepath.Join(root, "empty"):                0,
		filepath.Join(root, "a.mp4"):                1000,
		filepath.Join(root, "docs", "c.pdf"):        3000,
		filepath.Join(root, "docs", "deep", "e.go"): 7,
	} {
		i := res.dmFind(path)
		if i < 0 {
			t.Errorf("%s is not in the map", path)
			continue
		}
		if got := res.Nodes[i].Size; got != want {
			t.Errorf("%s rolled up to %d, want %d", path, got, want)
		}
	}
}

// A directory's own inode size is not space anybody can free. Counting it adds
// a phantom ~4 KB per directory — 340 MB across the 87,016 directories
// measured on this box — spread thinly enough to be invisible and wrong
// everywhere.
func TestADirectoryContributesNoSizeOfItsOwn(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a", "a/b", "a/b/c", "d", "e"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	res := dmScanTree(t, root)
	if res.Nodes[res.Roots[0]].Size != 0 {
		t.Errorf("a tree of empty directories totals %d bytes, want 0 — the inode "+
			"size is being counted as space", res.Nodes[res.Roots[0]].Size)
	}
}

// ── the boundaries ──────────────────────────────────────────────────────────

// TestTheWalkNeverFollowsASymlinkOutOfTheRoot pins a property of a function in
// another package (filepath.WalkDir + os.ReadDir), which is exactly the kind
// of thing that must be asserted rather than assumed.
func TestTheWalkNeverFollowsASymlinkOutOfTheRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "huge.bin"), make([]byte, 100000), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "small.txt"), make([]byte, 5), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("this platform will not make a symlink: %v", err)
	}

	res := dmScanTree(t, root)
	if res.Bytes >= 100000 {
		t.Errorf("the walk counted %d bytes — it followed the symlink out of the "+
			"root and counted another tree's files as this one's", res.Bytes)
	}
	for i := range res.Nodes {
		if res.Nodes[i].Name == "huge.bin" {
			t.Fatal("huge.bin is in the map; the walk descended through a symlink")
		}
	}
	// It must still SEE the link — a link is a real directory entry with a
	// real (tiny) size, and dropping it would be a different bug.
	found := false
	for i := range res.Nodes {
		if res.Nodes[i].Name == "link" {
			found = true
			if res.Nodes[i].Dir {
				t.Error("the symlink is recorded as a directory; WalkDir would descend into it")
			}
		}
	}
	if !found {
		t.Error("the symlink itself is missing from the map")
	}
}

// The pseudo-filesystems, and the specific file that is the reason for the
// list rather than the general reason.
func TestPseudoFilesystemsAreNeverWalked(t *testing.T) {
	for _, p := range []string{"/proc", "/sys", "/dev"} {
		if !dmSkipped(p) {
			t.Errorf("%s is not in dmSkipRoots", p)
		}
	}
	if dmSkipped("/home") || dmSkipped("/Users") || dmSkipped("/proc-notes") {
		t.Error("dmSkipped is matching more than the exact names")
	}
	if runtime.GOOS != "linux" {
		return
	}
	// The measured hazard, checked on the machine running the test rather than
	// quoted: /proc/kcore reports the kernel's view of physical memory as a
	// file size. On this box that is 140,737,471,598,592 bytes, which would be
	// 99.9999% of every rectangle in a map of a 48 GB disk.
	if fi, err := os.Lstat("/proc/kcore"); err == nil && fi.Size() < 1<<40 {
		t.Logf("note: /proc/kcore here reports only %d bytes, so this box does not "+
			"show the hazard the skip list exists for", fi.Size())
	}
	res := dmScan(context.Background(), []string{"/proc"}, dmMaxEntries, nil)
	if len(res.Nodes) != 0 {
		t.Errorf("a walk rooted at /proc produced %d nodes — the skip list must "+
			"apply to a root as well as to what is found under one", len(res.Nodes))
	}
	if len(res.Skipped) == 0 {
		t.Error("the walk skipped /proc and did not record that it had")
	}
}

// The device check's INPUT, checked against the kernel rather than assumed:
// /proc really is a different device from /, so comparing st_dev really does
// stop a walk at a mount point.
func TestTheDeviceProbeSeesAMountBoundary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no st_dev; the drive letter is the boundary (diskmap_windows.go)")
	}
	rootDev, ok := dmDeviceOf("/")
	if !ok {
		t.Fatal("no device for / — the crossing check would be disabled entirely")
	}
	if runtime.GOOS != "linux" {
		return
	}
	procDev, ok := dmDeviceOf("/proc")
	if !ok {
		t.Fatal("no device for /proc")
	}
	if procDev == rootDev {
		t.Error("/proc and / report the same device, so st_dev cannot be what " +
			"stops a walk crossing a mount on this platform")
	}
}

// A tree with no mounts in it must produce NO crossings. The device check
// firing on ordinary subdirectories would silently amputate the map.
func TestAnOrdinaryTreeCrossesNothing(t *testing.T) {
	res := dmScanTree(t, dmTree(t))
	if len(res.Crossings) != 0 {
		t.Errorf("an ordinary tree reported %d mount crossings: %v",
			len(res.Crossings), res.Crossings)
	}
}

// ── failure, tolerated per entry and reported ───────────────────────────────

func TestAnUnreadableRootIsCountedAndNamedRatherThanFatal(t *testing.T) {
	good := dmTree(t)
	gone := filepath.Join(t.TempDir(), "never-existed")
	res := dmScan(context.Background(), []string{gone, good}, dmMaxEntries, nil)

	if res.Denied != 1 {
		t.Errorf("denied = %d, want 1", res.Denied)
	}
	if len(res.DeniedPaths) != 1 || !strings.Contains(res.DeniedPaths[0], "never-existed") {
		t.Errorf("the unreadable path is not named: %v", res.DeniedPaths)
	}
	// And the SECOND root still got walked. A per-entry failure must never
	// abort the map — dcn.go:523 takes the same position for the same reason.
	if res.Bytes != 4247 {
		t.Errorf("bytes = %d, want 4247 — a bad root aborted the rest of the walk", res.Bytes)
	}
}

func TestAnUnreadableDirectoryIsSkippedNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read a 0000 directory; this case is " +
			"covered as uid 65534, the way this suite is also run")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "seen.txt"), make([]byte, 11), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(filepath.Join(locked, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "inner", "big.bin"), make([]byte, 5000), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	res := dmScanTree(t, root)
	if res.Denied == 0 {
		t.Fatal("a 0000 directory produced no denial — either the fixture did not " +
			"take or the walk is not counting refusals")
	}
	if res.Bytes != 11 {
		t.Errorf("bytes = %d, want 11 — the unreadable subtree leaked into the total", res.Bytes)
	}
}

// ── cancellation and the cap ────────────────────────────────────────────────

func TestACancelledWalkKeepsWhatItCountedAndSaysSo(t *testing.T) {
	root := dmTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already dead before the first entry
	res := dmScan(ctx, []string{root}, dmMaxEntries, nil)
	if res == nil {
		t.Fatal("a cancelled walk returned nothing at all")
	}
	if !res.Cancelled {
		t.Error("the result does not say it was cancelled, so the page would " +
			"present a partial count as a complete one")
	}
}

func TestACancelMidWalkStopsItAndTheResultIsLabelled(t *testing.T) {
	// A tree big enough that the cancel lands inside the walk rather than
	// before it. 4,000 entries at the measured 300k-530k entries/sec is ~10ms.
	root := t.TempDir()
	for i := 0; i < 4000; i++ {
		d := filepath.Join(root, "d"+string(rune('a'+i%26)))
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "f"+strconv.Itoa(i)), []byte("x"), 0o644)
	}
	ctx, cancel := context.WithCancel(context.Background())
	seen := make(chan struct{}, 1)
	go func() {
		<-seen
		cancel()
	}()
	res := dmScan(ctx, []string{root}, dmMaxEntries, func(dmProgress) {
		select {
		case seen <- struct{}{}:
		default:
		}
	})
	// Either it was cancelled, or it finished before the cancel landed — say
	// which rather than asserting a race.
	if !res.Cancelled && res.Files < 4000 {
		t.Errorf("the walk stopped early (%d files) without saying it was cancelled", res.Files)
	}
}

func TestTheEntryCapStopsTheWalkAndTheResultSaysWhere(t *testing.T) {
	root := dmTree(t)
	// The cap is an ARGUMENT, so exercising it needs no package variable and
	// therefore cannot race with a scan another test left running — which is
	// what the race detector found when it was a var.
	res := dmScan(context.Background(), []string{root}, 3, nil)
	if !res.Capped {
		t.Fatal("the walk passed the cap without recording that it had — a map " +
			"that quietly omits is worse than no map")
	}
	if res.CappedAt == "" {
		t.Error("the result does not say WHERE it stopped, so the page cannot tell " +
			"the user which part of their disk is missing")
	}
	if len(res.Nodes) > 3 {
		t.Errorf("the cap is %d and the walk kept %d nodes", 3, len(res.Nodes))
	}
}

// ── resolving a path ────────────────────────────────────────────────────────

// dmFind is the whole reason a query-string path is safe here: it resolves
// against the SCANNED TREE, so a path that exists on disk but was not walked
// does not resolve, and nothing is ever joined onto the filesystem. ui.go:442
// makes the same argument for an approval's host name.
func TestAPathOutsideTheMapNeverResolvesEvenIfItExistsOnDisk(t *testing.T) {
	parent := t.TempDir()
	inside := filepath.Join(parent, "mapped")
	sibling := filepath.Join(parent, "not-mapped")
	for _, d := range []string{inside, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(sibling, "secret.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := dmScanTree(t, inside)

	if _, err := os.Stat(secret); err != nil {
		t.Fatalf("fixture is broken: %s does not exist on disk, so this test would "+
			"pass without proving anything: %v", secret, err)
	}
	for _, p := range []string{sibling, secret, parent, "/etc/passwd",
		filepath.Join(inside, "..", "not-mapped"),
		filepath.Join(inside, "no-such-child")} {
		if i := res.dmFind(p); i >= 0 {
			t.Errorf("dmFind(%q) resolved to %q — the map answered for a path this "+
				"scan never walked", p, res.dmPath(i))
		}
	}
	if res.dmFind(inside) < 0 {
		t.Error("dmFind cannot find its own root, so this test is refusing everything")
	}
}

func TestAPathRebuildsToWhatWasWalked(t *testing.T) {
	root := dmTree(t)
	res := dmScanTree(t, root)
	want := filepath.Join(root, "docs", "deep", "e.go")
	i := res.dmFind(want)
	if i < 0 {
		t.Fatalf("%s is not in the map", want)
	}
	if got := res.dmPath(i); got != want {
		t.Errorf("dmPath rebuilt %q, want %q", got, want)
	}
}

func TestChildrenComeBackLargestFirst(t *testing.T) {
	res := dmScanTree(t, dmTree(t))
	kids := res.dmChildren(res.Roots[0])
	var sizes []int64
	for _, k := range kids {
		sizes = append(sizes, res.Nodes[k].Size)
	}
	if !sort.SliceIsSorted(sizes, func(a, b int) bool { return sizes[a] > sizes[b] }) {
		t.Errorf("children are not descending: %v — dmSquarify is only near-optimal "+
			"on sorted input and the biggest-things table would be unsorted", sizes)
	}
}

// ── the roots ───────────────────────────────────────────────────────────────

func TestTheDefaultRootsAreAbsoluteAndNotDuplicated(t *testing.T) {
	roots, _ := dmMachineRoots()
	if len(roots) == 0 {
		t.Fatal("no roots at all — the map would have nothing to walk")
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if !filepath.IsAbs(r) {
			t.Errorf("root %q is relative; filepath.Abs would resolve it against the "+
				"daemon's working directory, which under systemd is /", r)
		}
		if seen[r] {
			t.Errorf("root %q is listed twice", r)
		}
		seen[r] = true
	}
	// The home directory must not be added when it already sits inside a
	// volume root — walking the same bytes twice would double the map.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		home = filepath.Clean(home)
		inside := false
		for _, r := range roots {
			if r != home && strings.HasPrefix(home, ensureSep(r)) {
				inside = true
			}
		}
		if inside && seen[home] {
			t.Errorf("%s is a root AND is inside another root %v — its files would "+
				"be counted twice", home, roots)
		}
	}
}
