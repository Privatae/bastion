package main

// diskmap.go — the size walk behind the disk map.
//
// ══════════════════════════════════════════════════════════════════════════
// THIS READS NAMES, SIZES AND MODIFICATION TIMES. NOTHING ELSE. EVER.
//
// It never opens a file, never reads a byte of content, never hashes, never
// extracts, never embeds. Every fact in this map comes from a directory entry
// and an lstat — the same two syscalls `ls -l` makes.
//
// That line is the whole reason this ships before whole-machine indexing. A
// SIZE WALK AND A CONTENT INDEX ARE DIFFERENT PRODUCTS WITH DIFFERENT CONSENT,
// and conflating them is how a privacy product becomes the thing that gets
// written about. Whole-machine indexing runs the opposite way to the grant
// model and deserves its own decision — this unit must not pre-empt that
// decision by drifting into it one convenience at a time.
//
// The line is held by TWO tests, because a comment is not a wall:
//
//   - TestTheWalkerNeverOpensAFile parses THIS FILE with go/parser and fails
//     on any call into os/io/bufio that is not on a short allow-list of
//     metadata calls. An AST walk rather than a grep, so a mention in a
//     comment or a string cannot satisfy it and cannot trip it.
//   - TestTheWalkerDoesNotOpenAFifo puts a named pipe in the walked tree.
//     Opening a FIFO for reading BLOCKS until a writer arrives, so a walker
//     that opens what it finds hangs and the test fails on a deadline. An
//     lstat on the same FIFO returns instantly.
//
// The rejected alternative was a substring check for "os.Open" over the file.
// It passes on a walker that reaches content through io.ReadAll(f) or a
// bufio.Scanner and it trips on the word appearing in this header, which is
// the worst of both.
// ══════════════════════════════════════════════════════════════════════════
//
// WHY A TREE IN MEMORY RATHER THAN A LIVE READ PER PAGE. The page resolves a
// drilled-into path by finding that NODE IN THE SCANNED TREE — it never joins
// a query-string path onto the filesystem. ui.go:442-448 already refuses to do
// that for an approval's host name ("a handler that joins a posted string onto
// a directory is the shape of bug that turns a local UI into a file-system
// reach"), and a path parameter is the same shape with the joining already
// done for you. Holding the tree means the rendering path touches no disk at
// all, so there is nothing for a crafted `p=` to reach.
//
// WHAT IT IS NOT BUILT ON. The treemap looks closer than it is, because
// handleDcnCatalog already answers a paged dirs/files catalog. That is true of
// a GRANTED FOLDER and not of this
// machine: handleDcnCatalog (freeagent.go:342-406) requires a store id, a
// signed grant carrying both the 'read' and 'index' masks, and a running
// local agent sidecar to proxy to — it answers the HOST about one approved
// folder. A disk map answers the person sitting here about their own disk,
// before any grant exists, which is the whole demo. So this is a direct local
// walk and shares nothing with that path.

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── the numbers, every one of them measured ─────────────────────────────────

// All four constants below were derived from walks of the machine this was
// written on: a whole-machine walk of / — device-bounded, pseudo-
// filesystems skipped — is 799,953 entries over 48.2 GB (87,016 directories,
// 712,907 files), i.e. ~16,600 entries per GB.

// dmMaxEntries is the ceiling on retained nodes, and it is a MEMORY number
// rather than a filesystem one. MEASURED BY THE SHIPPING CODE
// (TestMeasureARealMap, DISKMAP_MEASURE=/): a whole-machine map of 801,782
// entries HOLDS 63 MB after a collection — 82 bytes/entry — so 1,200,000
// entries is 94 MB. That is held only while a map exists and is released by
// the drop timer.
//
// Peak during the walk is higher — 114 MB, 149 bytes/entry — and the gap is
// the walk's own garbage rather than the map, which is why the cap is set
// against the held figure: the cap has to bound what is KEPT.
//
// 1,200,000 is the measured whole-machine total with half again on top: the
// machine this was developed on maps completely, and one 50% fuller still
// does. The cap is not a safety net nobody trips — a 2 TB disk at the measured
// density is 33 million entries and 2.5 GB of heap, so on a large consumer
// drive this is the operative limit and the page has to say so, which it does
// (dmResult.Capped, rendered as its own line above the map).
//
// PASSED INTO dmScan rather than read from here, so a test can exercise the
// cap by asking for three entries instead of by writing a package variable.
// It was a var for exactly one release of this file, and the race detector
// found what that costs: a background scan from an earlier test reading the
// value while the next test wrote it.
const dmMaxEntries = 1_200_000

// dmStaleAfter is when the page starts saying the map is old, AND the idle
// window after which an unviewed map is released. One constant with two
// consequences on purpose: the moment a map is worth re-taking is the moment
// it stops being worth 92 MB.
//
// Derived from measured churn rather than chosen. Share of entries whose mtime
// was inside the window, on this box:
//
//	root    <1h      <24h     <7d
//	/       1.56%    7.03%    14.34%
//	/root   3.75%    8.65%    20.35%
//
// Churn is front-loaded, so interpolate on log-time between the two measured
// points and solve for a 5%-of-entries error budget. The HOME root is the one
// that decides, because it is the one that changes: slope (8.65-3.75)/ln(24) =
// 1.54 %/ln-hour, so 5% lands at exp((5-3.75)/1.54) = 2.25 hours. The whole-
// machine root gives 7.4 hours by the same arithmetic and is the looser bound.
//
// It only changes a LABEL and a drop — nothing re-scans on a timer, because
// the one thing this feature must never do is walk the disk off a poll.
//
// HELD ON dmState (staleAfter) rather than read from here, so a test can
// shorten it to milliseconds on its own state. This was a package var until
// the race detector caught a timer goroutine from one test reading it while
// the next test wrote it — a real race, in the seam rather than in the
// feature, and the fix is that the window belongs to the map that is ageing.
const dmStaleAfter = 135 * time.Minute

// dmProgressEvery is how often a running scan publishes what it has counted.
// Measured rate is 300,000–530,000 entries/sec warm, so a per-entry update
// would be half a million mutex acquisitions a second to move a number a human
// reads three times. Every 20,000 entries is ~25 updates over the measured
// whole-machine walk — more than enough for a progress line that is only ever
// read by a 2-second poll.
const dmProgressEvery = 20_000

// dmMaxDenied is how many unreadable paths are kept BY NAME. The count is
// always exact; this bounds only the list. A user needs to see WHICH places
// the map could not look, and after a few dozen the answer is "a lot of them"
// and the list has stopped being information.
const dmMaxDenied = 64

// ── the tree ────────────────────────────────────────────────────────────────

// dmNode is one directory entry. NAME ONLY, never the path: a path is rebuilt
// by walking Parent, and every node in a deep tree storing its own absolute
// path is most of the memory.
//
// Name is strings.Clone'd at the call site and that is load-bearing, not
// hygiene. filepath.Base and fs.DirEntry.Name both hand back a string that may
// share the backing array of the buffer they came from, so storing one pins
// that whole buffer — the entry's whole absolute path — for the life of the
// map. MEASURED over 800k entries on this box, same walk, clone the only
// difference: 148.4 bytes/entry retained without it, 76.3 with it. The map
// costs half as much because of one call.
type dmNode struct {
	Name string
	// Size is the file's own size for a file, and the rolled-up total of
	// everything beneath it for a directory. Rolled up after the walk, in
	// dmRollUp, rather than incrementally: a walk that is cancelled or capped
	// mid-flight must not leave half-summed directories that LOOK complete.
	Size  int64
	Mtime int64 // unix seconds; 0 when the entry could not be stat'd
	// Parent, FirstChild and NextSibling are indices into dmResult.Nodes.
	// -1 is "none". Indices rather than pointers so the whole tree is one
	// allocation the garbage collector does not have to trace through.
	Parent      int32
	FirstChild  int32
	NextSibling int32
	Dir         bool
	// Root marks a node this scan started at. A root's Name is its full path,
	// because it has no parent to rebuild one from.
	Root bool
}

// dmResult is a finished (or abandoned) map.
type dmResult struct {
	// Scope is what this map COVERS. Stamped by dmStart from the scope that
	// was asked for, never by the walker, so a stubbed or future walker cannot
	// mislabel a map — and a map labelled "your files" that quietly held the
	// whole machine would be the worst possible lie for this page to tell.
	Scope dmScope
	Nodes []dmNode
	// Roots are indices into Nodes, in the order they were walked.
	Roots []int32
	// TakenAt is when the walk FINISHED. Every "how old is this" question on
	// the page is asked against this and nothing else.
	TakenAt time.Time
	Elapsed time.Duration
	Files   int64
	Dirs    int64
	Bytes   int64
	// Capped is dmMaxEntries reached, so the walk STOPPED and what is below
	// CappedAt was never looked at. The page says this in words above the map;
	// a map that quietly omits is worse than no map.
	Capped   bool
	CappedAt string
	// Denied counts every entry the OS refused, and DeniedPaths names the
	// first dmMaxDenied of them. This is the honest half of "your disk is 48
	// GB but this map adds up to 31": the OS is the wall, and where it stood
	// is a fact about the machine the user is entitled to.
	Denied      int64
	DeniedPaths []string
	// Crossings are the mount points the walk refused to cross, and they are
	// the OTHER half of the same accounting. A second disk mounted at
	// /mnt/data is a real thing on a real machine, and it is NOT in this map:
	// naming the boundary is what keeps the map from lying by omission.
	Crossings []string
	// Skipped are the pseudo-filesystems refused by name (dmSkipRoots).
	Skipped []string
	// Cancelled: ctx ended before the walk did. The partial tree is kept and
	// labelled, never discarded — the user asked to stop, not to be told
	// nothing.
	Cancelled bool
}

// dmPath rebuilds a node's absolute path by walking up to its root.
func (r *dmResult) dmPath(i int32) string {
	if r == nil || i < 0 || int(i) >= len(r.Nodes) {
		return ""
	}
	var parts []string
	for i >= 0 {
		n := &r.Nodes[i]
		parts = append(parts, n.Name)
		if n.Root {
			break
		}
		i = n.Parent
	}
	// Reverse, then join with the PLATFORM separator: this path is shown to a
	// person looking at their own machine, so a Windows user sees backslashes.
	for a, b := 0, len(parts)-1; a < b; a, b = a+1, b-1 {
		parts[a], parts[b] = parts[b], parts[a]
	}
	if len(parts) == 1 {
		return parts[0]
	}
	root := parts[0]
	rest := filepath.Join(parts[1:]...)
	// A root already carries its own separator (`/`, `C:\`), so Join would
	// give `//usr` or `C:\\Users`. Trim exactly one.
	return strings.TrimSuffix(root, string(filepath.Separator)) +
		string(filepath.Separator) + rest
}

// dmChildren returns a node's children as indices, largest first. Largest
// first because that is the order the treemap needs (dmSquarify requires
// descending input) and the order the "biggest things here" list wants, and
// sorting once at the point of use beats holding a second ordering.
func (r *dmResult) dmChildren(i int32) []int32 {
	if r == nil || i < 0 || int(i) >= len(r.Nodes) {
		return nil
	}
	var out []int32
	for c := r.Nodes[i].FirstChild; c >= 0; c = r.Nodes[c].NextSibling {
		out = append(out, c)
	}
	sort.SliceStable(out, func(a, b int) bool {
		return r.Nodes[out[a]].Size > r.Nodes[out[b]].Size
	})
	return out
}

// dmFind resolves a path to a node index, BY WALKING THE TREE. It never
// touches the filesystem and it never joins the argument onto anything, which
// is the whole point: the only paths that resolve are ones this scan actually
// saw. -1 for anything else.
func (r *dmResult) dmFind(path string) int32 {
	if r == nil || strings.TrimSpace(path) == "" {
		return -1
	}
	want := filepath.Clean(path)
	// Longest matching root first, so a home directory nested inside a volume
	// root resolves against the more specific one.
	best := int32(-1)
	bestLen := -1
	for _, ri := range r.Roots {
		rp := filepath.Clean(r.Nodes[ri].Name)
		if want == rp || strings.HasPrefix(want, ensureSep(rp)) {
			if len(rp) > bestLen {
				best, bestLen = ri, len(rp)
			}
		}
	}
	if best < 0 {
		return -1
	}
	rp := filepath.Clean(r.Nodes[best].Name)
	if want == rp {
		return best
	}
	rest := strings.TrimPrefix(want, ensureSep(rp))
	at := best
	for _, seg := range strings.Split(rest, string(filepath.Separator)) {
		if seg == "" {
			continue
		}
		found := int32(-1)
		for c := r.Nodes[at].FirstChild; c >= 0; c = r.Nodes[c].NextSibling {
			if r.Nodes[c].Name == seg {
				found = c
				break
			}
		}
		if found < 0 {
			return -1
		}
		at = found
	}
	return at
}

func ensureSep(p string) string {
	if strings.HasSuffix(p, string(filepath.Separator)) {
		return p
	}
	return p + string(filepath.Separator)
}

// ── what is never walked ────────────────────────────────────────────────────

// dmSkipRoots are refused BY NAME, before anything is read from them.
//
// The device check below would catch most of these on unix, since every one of
// them is its own mount. The name list is kept anyway for two reasons, and
// they are different reasons:
//
//  1. ONE FILE IN /proc DESTROYS THE WHOLE MAP. Measured on this box,
//     /proc/kcore reports a size of 140,737,471,598,592 bytes — 128 TiB, the
//     kernel's view of physical memory as a file. Include it and it is
//     99.9999% of every rectangle drawn; the map of a 48 GB disk becomes one
//     grey square. The device check is a general rule and this is a specific
//     guarantee, and the specific guarantee is the one worth having.
//  2. THE DEVICE CHECK DOES NOT EXIST ON WINDOWS. FileInfo.Sys() there is a
//     *syscall.Win32FileAttributeData with no device field at all
//     (diskmap_windows.go), so on the platform this UI was built for the name
//     list is all there is.
var dmSkipRoots = []string{
	// linux
	"/proc", "/sys", "/dev", "/run", "/var/run", "/var/lock",
	// darwin. /dev is shared with linux above; the rest are the synthesised
	// mounts Apple hangs off the root. /Volumes holds OTHER volumes, which are
	// other devices and therefore other maps — not this one's business.
	"/System/Volumes/VM", "/System/Volumes/Preboot", "/System/Volumes/Update",
	"/private/var/vm", "/Volumes",
}

func dmSkipped(path string) bool {
	for _, s := range dmSkipRoots {
		if path == s {
			return true
		}
	}
	return false
}

// ── the walk ────────────────────────────────────────────────────────────────

// dmScan walks every root and returns the tree.
//
// It follows handleDcnList's idiom for the parts that are the same problem
// (dcn.go:522-550): filepath.WalkDir, and an error on one entry returns nil so
// an unreadable subtree is skipped rather than aborting the listing. It
// differs in three ways that matter here:
//
//   - errors are COUNTED and NAMED, not swallowed. dcn_list answers a host
//     that asked for files it was granted; this answers the person who owns
//     the disk, and "there is 12 GB I could not see" is the single most
//     useful sentence on the page.
//   - the walk never leaves the device it started on (dmSameDevice), so a
//     network share mounted under the root cannot turn a local walk into a
//     minutes-long round trip over someone's VPN, and a bind mount cannot
//     make the same bytes appear twice.
//   - it is cancellable. dcn_list is one bounded reply on a management frame;
//     this can run for minutes, and the user must be able to stop it.
//
// SYMLINKS ARE NEVER FOLLOWED, and that needs no code: filepath.WalkDir reads
// directories with os.ReadDir, whose fs.DirEntry is lstat-shaped, so a symlink
// to a directory has IsDir() == false and WalkDir does not descend into it.
// d.Info() is lstat too, so a symlink contributes its OWN few bytes and not
// its target's. That is also the correct answer for a disk map: following a
// link would count the target twice and a link loop would never terminate.
// Asserted by TestTheWalkNeverFollowsASymlinkOutOfTheRoot rather than assumed,
// because it is a property of a function in another package.
func dmScan(ctx context.Context, roots []string, maxEntries int, progress func(dmProgress)) *dmResult {
	r := &dmResult{Nodes: make([]dmNode, 0, 1<<16)}
	if maxEntries <= 0 {
		maxEntries = dmMaxEntries
	}
	start := time.Now()
	seenRoot := map[string]bool{}
	var seen int64

	for _, root := range roots {
		// CANCELLED BEFORE THE FIRST ENTRY IS STILL CANCELLED. This read
		// `break` with no label, and the result then carried Cancelled=false —
		// so a scan stopped between two roots, or stopped before it started at
		// all, came back as an EMPTY MAP THAT CLAIMED TO BE COMPLETE. Caught by
		// TestACancelledWalkKeepsWhatItCountedAndSaysSo, which cancels the
		// context before calling.
		if ctx.Err() != nil {
			r.Cancelled = true
			break
		}
		root = filepath.Clean(root)
		if seenRoot[root] || r.Capped {
			continue
		}
		seenRoot[root] = true
		rootDev, haveDev := dmDeviceOf(root)

		// open is the chain of directories the walk is currently inside, so a
		// child can find its parent's index without a search.
		//
		// A STACK, NOT A MAP FROM PATH TO INDEX. The map was the first cut and
		// it is the obvious one, and it holds a full absolute path for every
		// directory in the tree — 87,016 of them on this box, which is most of
		// what dmNode's whole name-not-path design exists to avoid, brought
		// straight back in as scratch. filepath.WalkDir is depth-first
		// pre-order, so the parent of the entry being visited is always the
		// deepest still-open directory: pop until the top IS the parent.
		// Bounded by the tree's DEPTH rather than its size — measured maximum
		// 19 on a whole-machine walk here — so the scratch is 19 entries
		// instead of 87,016 and the peak stops being something this file
		// quotes a number for and cannot stand behind.
		type dmOpen struct {
			path string
			idx  int32
		}
		var open []dmOpen

		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				// Permission denied, a file that vanished mid-walk, a broken
				// mount. Per entry, never fatal: a map of 95% of a disk is
				// worth having and the missing 5% is reported as missing.
				r.Denied++
				if len(r.DeniedPaths) < dmMaxDenied {
					r.DeniedPaths = append(r.DeniedPaths, p)
				}
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			// The skip applies to the ROOT too, not only to what is found under
			// it. A root is whatever dmVolumeRoots and $HOME produced, and on a
			// misconfigured box that can be one of these — at which point
			// walking it is precisely the disaster the list exists to prevent,
			// and "but you asked for it" is not a defence when one file in
			// there claims to be 128 TiB.
			if dmSkipped(p) {
				r.Skipped = append(r.Skipped, p)
				return filepath.SkipDir
			}
			info, ierr := d.Info()
			if ierr != nil {
				r.Denied++
				if len(r.DeniedPaths) < dmMaxDenied {
					r.DeniedPaths = append(r.DeniedPaths, p)
				}
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() && p != root && haveDev {
				if dev, ok := dmDeviceOfInfo(info); ok && dev != rootDev {
					r.Crossings = append(r.Crossings, p)
					return filepath.SkipDir
				}
			}
			if len(r.Nodes) >= maxEntries {
				r.Capped, r.CappedAt = true, p
				return filepath.SkipAll
			}

			parent := int32(-1)
			if p != root {
				dir := filepath.Dir(p)
				for len(open) > 0 && open[len(open)-1].path != dir {
					open = open[:len(open)-1]
				}
				if len(open) == 0 {
					// The parent is not open, which means it was skipped.
					// Nothing to hang this off, so drop it rather than
					// inventing a second root.
					return nil
				}
				parent = open[len(open)-1].idx
			}
			name := d.Name()
			if p == root {
				name = root
			}
			// A DIRECTORY STARTS AT ZERO. info.Size() on a directory is the
			// size of its own inode — 4096 on ext4 — which is not the space
			// anyone is looking for. Counting it would add a phantom 340 MB
			// to the map of this box (87,016 directories × 4 KB) spread
			// evenly enough to be invisible and wrong everywhere.
			own := info.Size()
			if d.IsDir() {
				own = 0
			}
			idx := int32(len(r.Nodes))
			r.Nodes = append(r.Nodes, dmNode{
				// strings.Clone: see dmNode. Measured 2x on retained memory.
				Name:        strings.Clone(name),
				Size:        own,
				Mtime:       info.ModTime().Unix(),
				Parent:      parent,
				FirstChild:  -1,
				NextSibling: -1,
				Dir:         d.IsDir(),
				Root:        p == root,
			})
			if parent >= 0 {
				// Prepend rather than append: O(1), and the order is
				// irrelevant because dmChildren sorts by size anyway.
				r.Nodes[idx].NextSibling = r.Nodes[parent].FirstChild
				r.Nodes[parent].FirstChild = idx
			}
			if d.IsDir() {
				open = append(open, dmOpen{path: strings.Clone(p), idx: idx})
				r.Dirs++
			} else {
				r.Files++
				r.Bytes += info.Size()
			}
			if p == root {
				r.Roots = append(r.Roots, idx)
			}
			seen++
			if progress != nil && seen%dmProgressEvery == 0 {
				progress(dmProgress{At: p, Entries: seen, Bytes: r.Bytes})
			}
			return nil
		})
		// ASK THE CONTEXT, NOT THE ERROR. errors.Is(err, ctx.Err()) was the
		// first cut and it is fragile in both directions: WalkDir wraps what
		// the callback returns, and ctx.Err() is nil at the moment of
		// comparison in the ordinary case, which makes errors.Is(nil) the
		// question being asked. The context is the authority on whether it was
		// cancelled; the error only says the walk stopped.
		if err != nil && ctx.Err() != nil {
			r.Cancelled = true
			break
		}
	}

	dmRollUp(r)
	r.TakenAt, r.Elapsed = time.Now(), time.Since(start)
	return r
}

// dmRollUp gives every directory the total of everything beneath it.
//
// ONE BACKWARDS PASS OVER THE SLICE, not a recursion, and the reason it is
// allowed to be that cheap is an invariant of the walk: filepath.WalkDir is
// pre-order, so a node is always appended AFTER its parent, so index(child) >
// index(parent) always. Walking the slice backwards therefore visits every
// child before its parent, and adding each node's size into its parent is
// complete in one pass with no stack. At the measured 800k nodes a recursion
// would be 19 levels deep per node for exactly the same answer.
//
// AFTER THE WALK, NOT DURING IT, and that is the point of having a function at
// all: a walk that is cancelled or capped mid-flight must not leave
// half-summed directories that LOOK complete. Running the roll-up once at the
// end means a partial map is partial everywhere and says so, rather than being
// confidently wrong in the subtree where the walk stopped.
func dmRollUp(r *dmResult) {
	for i := len(r.Nodes) - 1; i >= 0; i-- {
		if p := r.Nodes[i].Parent; p >= 0 {
			r.Nodes[p].Size += r.Nodes[i].Size
		}
	}
}

// ── progress ────────────────────────────────────────────────────────────────

type dmProgress struct {
	At      string
	Entries int64
	Bytes   int64
}

// ── the one map this machine holds ──────────────────────────────────────────

// dmState is the machine-wide disk map: at most one scan running, at most one
// result held.
//
// ONE AT A TIME, and that is the point rather than a simplification. Two
// concurrent full-disk walks do not go twice as fast; on anything but an NVMe
// they fight for the same head and both take longer than either alone would.
// A second "Scan" press while one is running is answered with the running
// scan's progress, which is also what the person actually wanted to know.
type dmState struct {
	mu      sync.Mutex
	res     *dmResult
	running bool
	prog    dmProgress
	started time.Time
	cancel  context.CancelFunc
	viewed  time.Time
	// drop is the pending release timer. Held so a later view can push it out
	// rather than leaving a map to die under someone who is looking at it.
	drop *time.Timer
	// scan is the walker, swapped in tests. Every seam below is a FIELD and
	// not a package variable, and that is not taste: two of them started as
	// package vars and the race detector found a timer goroutine from one test
	// reading a value the next test was writing. A seam on the object races
	// with nothing, because each test has its own object.
	scan func(context.Context, []string, int, func(dmProgress)) *dmResult
	// roots is what to walk FOR A SCOPE, swapped in tests so a test never walks
	// a developer's real disk.
	roots func(dmScope) ([]string, []string)
	// scope is what the held map covers, and what a re-scan repeats. Kept on
	// the state as well as the result because the page has to name it while a
	// walk is still running and there is no result yet.
	scope dmScope
	// maxEntries and staleAfter default to the constants above when zero, so a
	// zero-value dmState is a working one.
	maxEntries int
	staleAfter time.Duration
}

var diskMap = &dmState{scan: dmScan, roots: dmRootsFor}

func (s *dmState) staleWindowLocked() time.Duration {
	if s.staleAfter > 0 {
		return s.staleAfter
	}
	return dmStaleAfter
}

func (s *dmState) capLocked() int {
	if s.maxEntries > 0 {
		return s.maxEntries
	}
	return dmMaxEntries
}

// dmSnapshot is everything the page needs about the held map, read under one
// lock. A struct rather than five return values because staleness has to be
// decided in HERE — the window lives on the state, and handing the caller a
// duration to compare against would put the same arithmetic in two places.
type dmSnapshot struct {
	Res     *dmResult
	Running bool
	Prog    dmProgress
	Since   time.Duration
	Stale   bool
	// Scope is what is being walked now, or what the held map covers.
	Scope dmScope
}

// dmView returns what the page should show and records that somebody looked,
// which is what keeps a map alive past its stale window while it is being read.
func (s *dmState) dmView() dmSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Recording the view is ALL this does about the drop. Resetting the timer
	// here as well was the first cut and it made the idle check inside the
	// timer dead code — TestLookingAtAMapKeepsItAlive passed with that check
	// deleted, which is the tautological-test shape this repo keeps catching.
	// One mechanism: the timer fires on its own schedule and asks whether
	// anyone has looked since.
	s.viewed = uiNow()
	// Scope comes off the STATE, not off the result: while a walk is running
	// there is no result yet, and "mapping your files" versus "mapping this
	// whole machine" is exactly what the person needs to read at that moment.
	v := dmSnapshot{Res: s.res, Scope: s.scope}
	if s.res != nil {
		v.Stale = uiNow().Sub(s.res.TakenAt) >= s.staleWindowLocked()
	}
	if s.running {
		v.Running, v.Prog, v.Since = true, s.prog, uiNow().Sub(s.started)
	}
	return v
}

// dmStart begins a scan of ONE scope unless one is already running.
func (s *dmState) dmStart(scope dmScope) bool {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return false
	}
	roots, _ := s.roots(scope)
	s.scope = scope
	// context.Background(), NOT the UI server's context, and that is the
	// difference between "it keeps going if you leave this page" (which the
	// page promises in those words) and a walk that dies when a browser tab
	// closes. Process shutdown still ends it, because the process ending ends
	// everything; nothing else does but dmStop, which is the Stop button.
	ctx, cancel := context.WithCancel(context.Background())
	s.running, s.cancel, s.started = true, cancel, uiNow()
	s.prog = dmProgress{}
	scan, cap := s.scan, s.capLocked()
	s.mu.Unlock()

	go func() {
		defer cancel()
		res := scan(ctx, roots, cap, func(p dmProgress) {
			s.mu.Lock()
			s.prog = p
			s.mu.Unlock()
		})
		s.mu.Lock()
		if res != nil {
			res.Scope = scope
		}
		s.res, s.running, s.cancel = res, false, nil
		s.dmArmDropLocked()
		s.mu.Unlock()
	}()
	return true
}

// dmStop cancels a running scan. The partial tree is kept.
func (s *dmState) dmStop() {
	s.mu.Lock()
	c := s.cancel
	s.mu.Unlock()
	if c != nil {
		c()
	}
}

// dmArmDropLocked schedules the release of a map nobody is reading.
//
// A TIMER RATHER THAN A SWEEP IN startUIServer, deliberately: the lifetime of
// this memory is this file's business, and reaching into the server's start-up
// to add a goroutine would put half of one feature's bookkeeping in another
// unit's file. The timer re-arms itself if the map was viewed while it slept,
// so a page left open never has the map pulled out from under it.
func (s *dmState) dmArmDropLocked() {
	if s.drop != nil {
		s.drop.Stop()
	}
	window := s.staleWindowLocked()
	s.drop = time.AfterFunc(window, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.running {
			return
		}
		w := s.staleWindowLocked()
		if idle := uiNow().Sub(s.viewed); idle < w {
			s.drop.Reset(w - idle)
			return
		}
		s.res = nil
	})
}

// ── the roots ───────────────────────────────────────────────────────────────

// dmDefaultRoots answers what "this machine's drives" means here, and returns
// the roots plus a plain-words note about anything it decided NOT to walk.
//
// THE RULE IS ONE RULE ON ALL THREE PLATFORMS: the machine's fixed volumes,
// plus the user's home directory when that is not already inside one of them.
// What differs is only what a volume is, which is the platform's question and
// is answered in diskmap_unix.go and diskmap_windows.go.
//
//   - LINUX. The volume is `/`. The walk is device-bounded, so it stops at
//     every mount — measured on this box, 16 boundaries refused on one walk of
//     `/`, including /boot and /srv, which are real ext4 disks holding
//     real data. That is a genuine limitation and it is NAMED on the page
//     (dmResult.Crossings) rather than papered over: a second disk mounted at
//     /mnt/data is not in this map. Parsing /proc/self/mountinfo to add local
//     filesystems back was the rejected alternative — it is a fourth
//     platform-specific parser for a v1 whose job is to make the machine
//     visible, and a boundary the user can SEE is not the same as one hidden.
//
//   - DARWIN. $HOME is listed separately from `/` and that is not belt and
//     braces. Since Catalina the system volume and the data volume are two
//     APFS volumes joined by firmlinks, so /Users can sit on a different
//     st_dev from /, and a device-bounded walk from / would then map the OS
//     and none of the user's files — the exact inverse of what was asked for.
//     UNVERIFIED: no Mac was available to confirm the st_dev behaviour of a
//     firmlink. Listing both makes the question moot, because dmScan dedupes
//     an already-walked root (seenRoot) and dmFind resolves against the
//     longest matching root, so the same tree can never be counted twice
//     whichever way the kernel answers.
//
//   - WINDOWS. The volumes are the FIXED drive letters, and only the fixed
//     ones (diskmap_windows.go). A DRIVE_REMOTE walk goes over the network and
//     can hang for minutes on a VPN that is not up; DRIVE_CDROM and
//     DRIVE_REMOVABLE spin up hardware to answer. WinDirStat itself opens with
//     "pick a drive" for the same reason.
//
// The home directory is resolved LAST and only added if it is outside every
// volume root, because on a normal machine it is inside one and adding it
// would walk the same bytes twice.
// dmScope is WHAT a map covers, and there are exactly two because there are
// exactly two questions people ask of a drive map.
//
// THE DEFAULT IS YOUR OWN FILES, and that is a decision rather than a
// convenience: a full drive map is a request.
// Mapping the whole machine reaches into every account on it, and on a shared
// box that is somebody else's private life rendered as rectangles. It is a
// bigger act than a button labelled "Map" implies, so it is asked for
// separately and the page says what it will cover before it runs.
//
// The scope is also what makes a files view safe for a person who is not the
// machine's admin: a walk done AS them can only read what they can already
// open, so the kernel draws the boundary and this code never has to decide.
type dmScope string

const (
	dmScopeHome    dmScope = "home"
	dmScopeMachine dmScope = "machine"
)

// dmScopeOf reads a scope off a form value, defaulting to home. An unknown
// value is home rather than an error: the failure mode of a typo must be the
// SMALLER walk, never the bigger one.
func dmScopeOf(s string) dmScope {
	if strings.TrimSpace(s) == string(dmScopeMachine) {
		return dmScopeMachine
	}
	return dmScopeHome
}

func (s dmScope) words() string {
	if s == dmScopeMachine {
		return "this whole machine"
	}
	return "your files"
}

// dmRootsFor resolves the roots for a scope. The seam on dmState is keyed on
// this so a test swaps one function and gets both scopes.
func dmRootsFor(scope dmScope) (roots []string, notes []string) {
	if scope == dmScopeMachine {
		return dmMachineRoots()
	}
	return dmHomeRoots()
}

// dmHomeRoots is the default: the home directory of whoever this process is
// running as, and nothing else.
func dmHomeRoots() (roots []string, notes []string) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		// Refusing to walk anything is the right answer here. Quietly widening
		// to the volumes because this account has no home would be the exact
		// thing the scope exists to stop, and it would happen on a service
		// account — the case where the widening is least expected.
		return nil, []string{"this account has no home directory of its own, so there is " +
			"nothing to map as your files — map the whole machine instead, which covers every " +
			"drive on it"}
	}
	return []string{filepath.Clean(home)}, nil
}

// dmMachineRoots is the explicit request: every fixed volume, plus the home
// directory when it lives outside them.
func dmMachineRoots() (roots []string, notes []string) {
	vols, volNotes := dmVolumeRoots()
	notes = append(notes, volNotes...)
	for _, v := range vols {
		roots = append(roots, filepath.Clean(v))
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		// Not a failure worth refusing over: the volume roots still map the
		// machine. It IS worth saying, because a daemon with no HOME is a
		// service account and the person reading the page is entitled to know
		// their own directory was not singled out.
		notes = append(notes, "this machine's daemon has no home directory of its own, so the map covers the volumes only")
		return roots, notes
	}
	home = filepath.Clean(home)
	for _, v := range roots {
		if home == v || strings.HasPrefix(home, ensureSep(v)) {
			return roots, notes
		}
	}
	return append(roots, home), notes
}
