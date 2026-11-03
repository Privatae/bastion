package main

// servicecarry.go — an install that moves a machine's bastion from an account
// to the system service brings that bastion's state with it.
//
// THE PROBLEM. A bastion installed for one account keeps its pairings, keys,
// grants and audit under that account's profile. The Windows service keeps
// its own under LocalSystem's (sysservice.go). Until this, the switch started
// the service with empty state: the per-user bastion was stopped and removed
// by the installer, the service had no pairing, and the machine went silent to
// every Host it served until someone paired it again by hand. The installer's
// header said so; nothing else did.
//
// THE CARRY. `service install` (elevated) moves the account's state folder
// into the service's before the service starts, when the service has no
// pairing of its own yet:
//
//   - a service that already serves a Host takes the account's pairings too,
//     with no question (a move to the service never leaves a pairing
//     behind). Only the pairings for Hosts the service does not serve
//     come in, each with its own folders and a loopback port of its own
//     (carryAddedHosts); nothing of the account's that the service keeps
//     machine-wide (keys, owner, code, anchor, mode, audit) ever becomes the
//     service's. On an anchored machine each added pairing waits, pending,
//     for the anchor Host to admit it, as any new pairing there does; on an
//     unanchored one it is served as it was;
//   - not while a bastion still runs from that folder (its run lock is held,
//     waited for a moment), and the lock is held through the copy, the check
//     and the emptying, so none starts in the middle;
//   - a file the service already has is kept, the service's own; where the
//     account's version differs, it is kept beside it (carryAsideSuffix);
//   - every path in the carried JSON that names the old folder is rewritten
//     to the new one (a pairing's context, DCN and backup folders);
//   - every file written is read back and compared, and every pairing must
//     be in the service's folder, before anything is removed; a copy that
//     fails takes back what it wrote, so a later install carries it again;
//   - then the account's folder is removed, so the pairing's keys and bearer
//     no longer sit where any program running as that account can read them.
//     One that will not go is said, and the service still starts.
//
// The decisions are here, untagged, so the suite runs them on every platform;
// finding the account's folder is in sysservice_windows.go.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The carry's file operations, so the suite can fail one part way.
var (
	carryWriteFile = os.WriteFile
	carryRemoveAll = os.RemoveAll
)

// carryAsideSuffix names the account's version of a file the service already
// had, kept beside the service's own: the account's folder is removed after
// the carry, and its version would go with it.
const carryAsideSuffix = ".from-account"

// carryLockPatience is how long the carry waits for the account's run lock.
// The installer stops the account's bastion just before (Stop-Process), and
// Windows releases a killed process's file locks a moment after it is gone.
var carryLockPatience = 10 * time.Second

// carrySkip are the files that belong to a running bastion, not to its state.
var carrySkip = map[string]bool{"run.lock": true, "run.holder.json": true, "pairings.lock": true,
	"ui.addr": true, "bastion.log": true, "bastion.log.1": true}

// carryResult is what a carry did.
type carryResult struct {
	Hosts []string // the pairings carried, by Host
	Kept  int      // files the service already had, left as they were
	// Aside are the files the service already had whose account version
	// differed; that version is beside each, named with carryAsideSuffix.
	Aside []string
	Note  string // why nothing was carried, when nothing was
	// Beside: the Hosts the service already served, when Hosts were added
	// beside them (carryAddedHosts); Hosts are then the ones added.
	Beside []string
	// Pending: the added pairings wait for the machine's anchor to admit them;
	// Anchor names it.
	Pending bool
	Anchor  string
	// Stayed: the account's pairings for Hosts the service already served,
	// left in the account's folder.
	Stayed []string
	// Left: the pairings are in the service, but the account's folder could
	// not be removed, and still holds copies of their keys.
	Left string
}

// pairingHosts lists the Hosts dir/pairings holds a pairing for. A Host's
// signed grant beside it (pairingGrantSuffix) is not a pairing (loadPairings).
func pairingHosts(dir string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(dir, "pairings"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hosts []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && !strings.HasSuffix(e.Name(), pairingGrantSuffix) {
			hosts = append(hosts, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(hosts)
	return hosts, nil
}

// carryLock takes the account's run lock, waiting up to carryLockPatience for
// a bastion that is exiting to let it go.
func carryLock(f *os.File) error {
	deadline := time.Now().Add(carryLockPatience)
	for {
		err := flockFileNB(f)
		if err == nil || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// carryTakeLock takes the account folder's run lock for a carry and returns
// what lets it go. It is held until only the lock itself is left to remove, so
// no bastion starts from the folder while it is copied, checked and emptied;
// letting it go twice is harmless.
func carryTakeLock(from string) (func(), error) {
	lock, err := os.OpenFile(filepath.Join(from, "run.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the run lock under %s: %w", from, err)
	}
	if err := carryLock(lock); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("a bastion is still running from %s (it holds that folder's run lock), so its pairings "+
			"were not moved into the service. Stop it, then run `privatae-bastion service install` again", from)
	}
	locked := true
	return func() {
		if locked {
			_ = lock.Close()
			locked = false
		}
	}, nil
}

// carryStateInto moves the bastion state at from into to (see the header).
func carryStateInto(from, to string) (carryResult, error) {
	var res carryResult
	if from == "" || samePath(from, to) {
		return res, nil
	}
	// Only ever a bastion's own folder: from is removed at the end.
	if filepath.Base(filepath.Clean(from)) != "privatae-bastion" {
		return res, fmt.Errorf("%s is not a bastion's state folder; nothing was moved", from)
	}
	hosts, err := pairingHosts(from)
	if err != nil {
		return res, fmt.Errorf("cannot read the pairings under %s: %w", from, err)
	}
	if len(hosts) == 0 {
		return res, nil
	}
	have, err := pairingHosts(to)
	if err != nil {
		return res, fmt.Errorf("cannot read the service's pairings under %s: %w", to, err)
	}
	if len(have) > 0 {
		return carryAddedHosts(from, to, hosts, have)
	}
	unlock, err := carryTakeLock(from)
	if err != nil {
		return res, err
	}
	defer unlock()
	// A copy that fails takes back every file it wrote: a service left with
	// some of the pairings serves a Host, so no later install would carry the
	// rest, and the service would serve only those few.
	written, kept, aside, err := copyStateTree(from, to)
	undo := func() {
		for p := range written {
			_ = os.Remove(p)
		}
	}
	if err != nil {
		undo()
		return res, fmt.Errorf("could not copy %s into the service's %s: %w. Nothing was removed from %s", from, to, err, from)
	}
	for p, want := range written {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, want) {
			undo()
			return res, fmt.Errorf("%s did not read back as written; nothing was removed from %s", p, from)
		}
	}
	// Every pairing counted above is in the service's folder, or nothing is
	// removed: a source the walk could not enter (a link) copies nothing.
	got, err := pairingHosts(to)
	if err != nil || strings.Join(got, "\x00") != strings.Join(hosts, "\x00") {
		undo()
		return res, fmt.Errorf("the service's folder %s holds the pairings %v after the copy, not %v; nothing was "+
			"removed from %s", to, got, hosts, from)
	}
	res.Hosts, res.Kept, res.Aside = hosts, kept, aside
	// From here the service has everything, so a folder that will not go is
	// said, not a failure: failing would leave the service stopped.
	var leftErr error
	ents, err := os.ReadDir(from)
	if err != nil {
		leftErr = err
	}
	for _, e := range ents {
		if e.Name() == "run.lock" {
			continue // open here; Windows will not delete an open file
		}
		if err := carryRemoveAll(filepath.Join(from, e.Name())); err != nil && leftErr == nil {
			leftErr = err
		}
	}
	unlock()
	if err := carryRemoveAll(from); err != nil && leftErr == nil {
		leftErr = err
	}
	if leftErr != nil {
		res.Left = fmt.Sprintf("%s could not be removed (%v). It still holds copies of the pairings' keys: delete that folder",
			from, leftErr)
	}
	return res, nil
}

// copyStateTree copies from into to, file by file, and returns what it wrote
// (path to content, so far when it fails), how many files to already had,
// and which of those differed from the account's (see carryAsideSuffix).
// JSON files have every string that names a path under from rewritten to the
// same path under to. The pairing files go last: a service that starts
// meanwhile serves a pairing only once its file is there, and by then
// everything it reads is too.
func copyStateTree(from, to string) (map[string][]byte, int, []string, error) {
	type item struct {
		src, dst string
		name     string
	}
	var first, last []item
	written := map[string][]byte{}
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(dst, 0o700)
		case !d.Type().IsRegular():
			return nil // a link or a device is never part of the state
		case rel == d.Name() && carrySkip[d.Name()]:
			return nil
		}
		it := item{p, dst, d.Name()}
		if filepath.Dir(rel) == "pairings" {
			last = append(last, it)
		} else {
			first = append(first, it)
		}
		return nil
	})
	if err != nil {
		return written, 0, nil, err
	}
	kept := 0
	var aside []string
	write := func(p string, data []byte) error {
		if err := carryWriteFile(p, data, 0o600); err != nil {
			_ = os.Remove(p)
			return err
		}
		written[p] = data
		return nil
	}
	for _, it := range append(first, last...) {
		data, err := os.ReadFile(it.src)
		if err != nil {
			return written, 0, nil, err
		}
		if strings.HasSuffix(it.name, ".json") {
			data = rebaseJSONPaths(data, from, to)
		}
		if _, err := os.Lstat(it.dst); err == nil {
			kept++
			if have, err := os.ReadFile(it.dst); err == nil && bytes.Equal(have, data) {
				continue
			}
			p := it.dst + carryAsideSuffix
			if _, err := os.Lstat(p); err == nil {
				return written, 0, nil, fmt.Errorf("%s is already there; the account's %s was not put beside the "+
					"service's", p, it.name)
			}
			if err := write(p, data); err != nil {
				return written, 0, nil, err
			}
			aside = append(aside, p)
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return written, 0, nil, err
		}
		if err := write(it.dst, data); err != nil {
			return written, 0, nil, err
		}
	}
	return written, kept, aside, nil
}

// rebaseJSONPaths rewrites every string in a JSON document that is from, or a
// path under it, to the same path under to. A document that does not parse is
// returned as it was.
func rebaseJSONPaths(data []byte, from, to string) []byte {
	var v any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return data
	}
	changed := false
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case string:
			if r, ok := rebasePath(t, from, to); ok {
				changed = true
				return r
			}
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		case map[string]any:
			for k := range t {
				t[k] = walk(t[k])
			}
		}
		return x
	}
	v = walk(v)
	if !changed {
		return data
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return data
	}
	return out
}

// rebasePath is p moved from under from to under to, and whether p was there.
func rebasePath(p, from, to string) (string, bool) {
	sep := string(filepath.Separator)
	f := strings.TrimRight(from, `\/`)
	switch {
	case samePath(p, f):
		return to, true
	case len(p) > len(f) && samePath(p[:len(f)], f) && (p[len(f)] == '\\' || p[len(f)] == '/'):
		return strings.TrimRight(to, `\/`) + sep + strings.TrimLeft(p[len(f):], `\/`), true
	}
	return p, false
}

// samePath compares two paths as this platform's filesystem does: without
// case on Windows.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// carryReport is what `service install` says of a carry.
func carryReport(r carryResult, from string) string {
	switch {
	case r.Note != "":
		return "  " + sentenceCase(r.Note) + "."
	case len(r.Hosts) == 0:
		return ""
	}
	s := "  Moved this machine's pairings into the service from " + from + ": " + strings.Join(r.Hosts, ", ") +
		". They go on serving as they were; nothing needs pairing again."
	if len(r.Beside) > 0 {
		s = "  Added " + strings.Join(r.Hosts, ", ") + " to the service, beside " + strings.Join(r.Beside, ", ") +
			", from " + from + "; nothing needs pairing again."
		if !r.Pending {
			s += " Each goes on serving as it was."
		}
		if r.Pending {
			if r.Anchor != "" {
				s += " Each waits until " + r.Anchor + ", the Host in charge of this machine, admits it: " + r.Anchor +
					" asks you to approve it, and it is served from then on."
			} else {
				s += " Each waits until the Host in charge of this machine admits it."
			}
		}
		if len(r.Stayed) > 0 {
			s += " The service already served " + strings.Join(r.Stayed, ", ") + ", so your account's pairing for it " +
				"was left in " + from + "."
		}
	}
	if r.Kept > 0 {
		s += fmt.Sprintf(" %d file(s) the service already had were kept as the service's.", r.Kept)
	}
	if len(r.Aside) > 0 {
		s += " Your account's own version of " + strconv.Itoa(len(r.Aside)) + " of them differed, and is kept " +
			"beside it in the service's folder as: " + strings.Join(r.Aside, ", ") + "."
	}
	if r.Left != "" {
		s += "\n  " + sentenceCase(r.Left) + "."
	}
	return s
}

// carryHostRoots are the folders under from that belong to host's pairing
// alone (config.go contextRoot, dcnDir; backupfetch.go backupRootPath;
// mirror.go mirrorDir), and any other folder or file its pairing names under
// from, relative to from. A pairing that keeps its state in a folder every
// pairing shares (the layout before 0.10.0, migrateLegacyConfig) is refused:
// that folder is not its alone to move.
func carryHostRoots(raw []byte, from, host string) ([]string, error) {
	roots := map[string]bool{}
	for _, top := range []string{"context", "dcn", "backups", "mirror"} {
		roots[filepath.Join(top, host)] = true
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("the pairing for %s does not read: %w", host, err)
	}
	var walkErr error
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			if _, ok := rebasePath(t, from, from); !ok {
				return
			}
			rel, err := filepath.Rel(from, t)
			if err != nil {
				return
			}
			first := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
			switch {
			case first == "pairings":
				return
			case rel == "." || !strings.Contains(filepath.ToSlash(rel), "/"):
				if walkErr == nil {
					walkErr = fmt.Errorf("the pairing for %s keeps its state in %s, which every pairing under %s "+
						"shares, so it was not added", host, t, from)
				}
				return
			}
			roots[rel] = true
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	if walkErr != nil {
		return nil, walkErr
	}
	var out []string
	for r := range roots {
		out = append(out, r)
	}
	sort.Strings(out)
	// A root inside another is the other's already.
	var kept []string
	for _, r := range out {
		inside := false
		for _, k := range kept {
			if strings.HasPrefix(filepath.ToSlash(r)+"/", filepath.ToSlash(k)+"/") {
				inside = true
				break
			}
		}
		if !inside {
			kept = append(kept, r)
		}
	}
	return kept, nil
}

// carryUsedAddrs are the loopback addresses the service's own pairings hold:
// their control ports and git proxies (config.go nextListenAddr,
// nextGitProxyAddr). An added pairing that held one of them in the account
// would fail to bind beside the pairing that has it here.
func carryUsedAddrs(to string) (map[string]bool, error) {
	used := map[string]bool{}
	hosts, err := pairingHosts(to)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		raw, err := os.ReadFile(filepath.Join(to, "pairings", h+".json"))
		if err != nil {
			return nil, err
		}
		var c Config
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("the service's pairing for %s does not read: %w", h, err)
		}
		used[c.ListenAddr], used[c.GitProxyAddr] = true, true
	}
	delete(used, "")
	return used, nil
}

// carryFreeAddr is the first loopback port from start up that used does not
// hold, marked used.
func carryFreeAddr(start int, used map[string]bool) string {
	for port := start; ; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		if !used[addr] {
			used[addr] = true
			return addr
		}
	}
}

// carriedPairing is an account's pairing as the service keeps it: its paths
// moved under to, its loopback ports its own among the service's, and on an
// anchored machine pending, as `pair` writes any new pairing there
// (pairPrecheckState). Every other field, its keys and bearer included, is
// as it was.
func carriedPairing(raw []byte, from, to string, used map[string]bool, anchored bool) ([]byte, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(rebaseJSONPaths(raw, from, to)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	la, _ := m["listen_addr"].(string)
	if la == "" || used[la] {
		la = carryFreeAddr(7878, used)
	}
	used[la] = true
	m["listen_addr"] = la
	if ga, _ := m["git_proxy_addr"].(string); ga != "" {
		if used[ga] {
			ga = carryFreeAddr(7978, used)
		}
		used[ga] = true
		m["git_proxy_addr"] = ga
	}
	// On a machine an organisation's policy governs, a Host it does not name
	// waits for the one it does, anchored yet or not, as `pair` writes it
	// (pairPrecheckState).
	host, _ := m["host_name"].(string)
	if p := currentAnchorPolicy(); anchored || (p != nil && !policyNames(p, host)) {
		m["state"] = pairingPending
	}
	m["origin"] = pairingOriginCarried
	return json.MarshalIndent(m, "", "  ")
}

// carryAddedHosts adds the account's pairings for Hosts the service does not
// serve to a service that serves others (see the
// header). The account's pairings for Hosts the service already serves stay
// where they are. When none stays, the rest of the account's folder (its
// keys, owner, code, anchor, mode, audit) is kept beside the service's own
// files with carryAsideSuffix, never in their place, and the folder is
// removed, as a whole carry removes it.
func carryAddedHosts(from, to string, hosts, have []string) (carryResult, error) {
	var res carryResult
	serving := map[string]bool{}
	for _, h := range have {
		serving[h] = true
	}
	var add, stay []string
	for _, h := range hosts {
		if serving[h] {
			stay = append(stay, h)
		} else {
			add = append(add, h)
		}
	}
	if len(add) == 0 {
		res.Note = fmt.Sprintf("the service already serves every Host the pairings under %s are for (%s), so nothing "+
			"was added", from, strings.Join(hosts, ", "))
		return res, nil
	}
	unlock, err := carryTakeLock(from)
	if err != nil {
		return res, err
	}
	defer unlock()
	_, aerr := os.Lstat(filepath.Join(to, "anchor.json"))
	anchored := aerr == nil
	anchorName := ""
	if raw, err := os.ReadFile(filepath.Join(to, "anchor.json")); err == nil {
		var a struct {
			AnchorHost string `json:"anchor_host"`
		}
		if json.Unmarshal(raw, &a) == nil && validHostName(a.AnchorHost) {
			anchorName = a.AnchorHost
		}
	}
	used, err := carryUsedAddrs(to)
	if err != nil {
		return res, fmt.Errorf("cannot read the service's pairings under %s: %w", to, err)
	}

	type item struct {
		rel   string
		data  []byte // set: written as it is; nil: read from from and rebased
		aside bool   // kept beside the service's file of that name, never in its place
	}
	var items, last []item
	carried := map[string]bool{} // rel paths (and roots) this carry moves
	for _, h := range add {
		praw, err := os.ReadFile(filepath.Join(from, "pairings", h+".json"))
		if err != nil {
			return res, fmt.Errorf("cannot read the pairing for %s under %s: %w", h, from, err)
		}
		roots, err := carryHostRoots(praw, from, h)
		if err != nil {
			return res, err
		}
		for _, r := range roots {
			carried[r] = true
			err := filepath.WalkDir(filepath.Join(from, r), func(p string, d fs.DirEntry, err error) error {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				if err != nil {
					return err
				}
				if !d.Type().IsRegular() {
					return nil
				}
				rel, err := filepath.Rel(from, p)
				if err != nil {
					return err
				}
				items = append(items, item{rel: rel})
				return nil
			})
			if err != nil {
				return res, fmt.Errorf("cannot read %s: %w", filepath.Join(from, r), err)
			}
		}
		data, err := carriedPairing(praw, from, to, used, anchored)
		if err != nil {
			return res, fmt.Errorf("the pairing for %s does not read: %w", h, err)
		}
		prel := filepath.Join("pairings", h+".json")
		grel := filepath.Join("pairings", h+pairingGrantSuffix)
		carried[prel] = true
		last = append(last, item{rel: prel, data: data})
		// A grant is the anchor's word for this machine. On an anchored
		// machine the account's grant was another anchor's, and the pairing
		// waits for this one's instead; it is kept beside, like any file of
		// the account's the service does not take.
		if _, err := os.Lstat(filepath.Join(from, grel)); err == nil && !anchored {
			carried[grel] = true
			last = append(last, item{rel: grel})
		}
	}
	if len(stay) == 0 {
		// Nothing stays: the rest of the folder goes beside the service's.
		err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(from, p)
			if err != nil {
				return err
			}
			if carried[rel] {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || (rel == d.Name() && carrySkip[d.Name()]) {
				return nil
			}
			items = append(items, item{rel: rel, aside: true})
			return nil
		})
		if err != nil {
			return res, fmt.Errorf("cannot read %s: %w", from, err)
		}
	}

	written := map[string][]byte{}
	undo := func() {
		for p := range written {
			_ = os.Remove(p)
		}
	}
	for _, it := range append(items, last...) {
		data := it.data
		if data == nil {
			if data, err = os.ReadFile(filepath.Join(from, it.rel)); err != nil {
				undo()
				return res, fmt.Errorf("cannot read %s: %w. Nothing was removed from %s", filepath.Join(from, it.rel), err, from)
			}
			if strings.HasSuffix(it.rel, ".json") {
				data = rebaseJSONPaths(data, from, to)
			}
		}
		dst := filepath.Join(to, it.rel)
		if it.aside {
			dst += carryAsideSuffix
		}
		if have, err := os.ReadFile(dst); err == nil {
			if bytes.Equal(have, data) {
				continue
			}
			if !it.aside {
				res.Kept++
				dst += carryAsideSuffix
				if _, err := os.Lstat(dst); err == nil {
					undo()
					return res, fmt.Errorf("%s is already there; the account's %s was not put beside the service's. "+
						"Nothing was removed from %s", dst, it.rel, from)
				}
				res.Aside = append(res.Aside, dst)
			} else {
				undo()
				return res, fmt.Errorf("%s is already there; the account's %s was not put beside it. Nothing was "+
					"removed from %s", dst, it.rel, from)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			undo()
			return res, err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			undo()
			return res, err
		}
		if err := carryWriteFile(dst, data, 0o600); err != nil {
			_ = os.Remove(dst)
			undo()
			return res, fmt.Errorf("could not write %s: %w. Nothing was removed from %s", dst, err, from)
		}
		written[dst] = data
	}
	for p, want := range written {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, want) {
			undo()
			return res, fmt.Errorf("%s did not read back as written; nothing was removed from %s", p, from)
		}
	}
	got, err := pairingHosts(to)
	if err != nil {
		undo()
		return res, err
	}
	in := map[string]bool{}
	for _, h := range got {
		in[h] = true
	}
	for _, h := range append(append([]string{}, have...), add...) {
		if !in[h] {
			undo()
			return res, fmt.Errorf("the service's folder %s holds the pairings %v after the copy, not %s's; nothing "+
				"was removed from %s", to, got, h, from)
		}
	}
	res.Hosts, res.Beside, res.Pending, res.Stayed, res.Anchor = add, have, anchored, stay, anchorName

	// From here the service has every added pairing, so what will not go is
	// said, not a failure.
	var leftErr error
	if len(stay) > 0 {
		var rels []string
		for r := range carried {
			rels = append(rels, r)
		}
		sort.Strings(rels)
		for _, r := range rels {
			if err := carryRemoveAll(filepath.Join(from, r)); err != nil && leftErr == nil {
				leftErr = err
			}
		}
	} else {
		ents, err := os.ReadDir(from)
		if err != nil {
			leftErr = err
		}
		for _, e := range ents {
			if e.Name() == "run.lock" {
				continue
			}
			if err := carryRemoveAll(filepath.Join(from, e.Name())); err != nil && leftErr == nil {
				leftErr = err
			}
		}
		unlock()
		if err := carryRemoveAll(from); err != nil && leftErr == nil {
			leftErr = err
		}
	}
	if leftErr != nil {
		res.Left = fmt.Sprintf("part of %s could not be removed (%v). It may still hold copies of the added pairings' "+
			"keys: delete those files", from, leftErr)
	}
	return res, nil
}
