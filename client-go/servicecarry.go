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
//   - only then: a service that already serves a Host is never merged into;
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
		res.Note = fmt.Sprintf("the service already serves %s, so the pairings under %s (%s) were left where they are",
			strings.Join(have, ", "), from, strings.Join(hosts, ", "))
		return res, nil
	}
	lock, err := os.OpenFile(filepath.Join(from, "run.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return res, fmt.Errorf("cannot open the run lock under %s: %w", from, err)
	}
	if err := carryLock(lock); err != nil {
		_ = lock.Close()
		return res, fmt.Errorf("a bastion is still running from %s (it holds that folder's run lock), so its pairings "+
			"were not moved into the service. Stop it, then run `privatae-bastion service install` again", from)
	}
	// Held until only the lock itself is left to remove, so no bastion starts
	// from the folder while it is copied, checked and emptied.
	locked := true
	unlock := func() {
		if locked {
			_ = lock.Close()
			locked = false
		}
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
