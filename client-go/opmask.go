package main

// opmask.go — the masks a run puts over this machine's own record, taken so
// that a host's backup folder on a network mount that stopped answering
// cannot stop every op.
//
// A stale NFS mount makes a stat of it fail with an error that is not "no
// such file", or never return. The mask step stats every entry, and a
// failure there fails the run, so one such backup folder would refuse or
// hang every op on the machine. So each BACKUP-folder entry is probed here,
// on this side, with a bound: one that errors or does not answer in time is
// left out of the masks for this run and said once in the log. It stays in
// every text check (effects, verb paths), which compare paths as written and
// need no stat, so no op may name it; and the run's closed view (only the
// declared paths are visible) already covers it, as it covers everything an
// op did not declare. The machine's own record in the config folder is never
// probed this way: a failure there still fails the run.
//
// A probe that never returns keeps one goroutine blocked on that path; a
// second probe of the same path while it is blocked is not started, it
// reads as "did not answer".

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	// opMaskProbeTimeout bounds one probe of a backup folder.
	opMaskProbeTimeout = 2 * time.Second
	// opMaskStat and opResolveFn are os.Stat and resolveExisting; tests
	// replace them with ones that fail or block.
	opMaskStat  = os.Stat
	opResolveFn = resolveExisting
	// opMaskLog is where the one line per unanswering folder goes.
	opMaskLog = func(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }

	opProbeMu       sync.Mutex
	opProbeInFlight = map[string]bool{}
	opProbeLogged   = map[string]bool{}
)

var (
	errProbeBusy    = errors.New("an earlier probe of it has not returned")
	errProbeTimeout = errors.New("did not answer")
)

// opProbe runs f for the path p with the bound. It never waits longer than
// the bound, whatever f does.
func opProbe(p string, f func() error) error {
	opProbeMu.Lock()
	if opProbeInFlight[p] {
		opProbeMu.Unlock()
		return errProbeBusy
	}
	opProbeInFlight[p] = true
	opProbeMu.Unlock()
	done := make(chan error, 1)
	go func() {
		err := f()
		opProbeMu.Lock()
		delete(opProbeInFlight, p)
		opProbeMu.Unlock()
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(opMaskProbeTimeout):
		return fmt.Errorf("%w within %s", errProbeTimeout, opMaskProbeTimeout)
	}
}

// backupFolderResolve resolves a host's backup folder with the bound. It
// returns the folder as it resolves and true when it answered in time; when
// it did not, "" and false, with the last path it ever resolved to (kept on
// disk, so a restart during the outage still knows it) or "" when it never
// answered. While the folder does not answer, every check that needs where
// it really is uses that last path as well as the path as written, so an op
// cannot name the real place during the outage and a backup folder cannot
// be set over another host's.
func backupFolderResolve(p string) (string, bool, string) {
	c := p
	if abs, err := filepath.Abs(filepath.Clean(p)); err == nil {
		c = abs
	}
	var r string
	var mu sync.Mutex
	if err := opProbe("resolve:"+c, func() error {
		v := opResolveFn(c)
		mu.Lock()
		r = v
		mu.Unlock()
		return nil
	}); err != nil {
		opMaskNote(c, err)
		return "", false, lastResolved(c)
	}
	mu.Lock()
	defer mu.Unlock()
	noteResolved(c, r)
	return r, true, r
}

// opResolveBounded is backupFolderResolve for the off-limits set: the
// folder as it resolves, or, while it does not answer, the last place it
// resolved to ("" when there is none).
func opResolveBounded(p string) string {
	r, ok, last := backupFolderResolve(p)
	if ok {
		return r
	}
	return last
}

// ── the last place each backup folder resolved to ──────────────────────────

// The record is keyed by folder as written, and only folders the person set
// (backup_root, shares) are ever resolved, so it stays small; it is bounded
// all the same, at lastResolvedMax folders, the one resolved longest ago
// going first. A folder's time is kept on disk at most a day stale, so the
// order survives a restart.
const (
	lastResolvedMax   = 256
	lastResolvedFresh = 24 * 60 * 60 // seconds
)

type lastResolvedEntry struct {
	Resolved string `json:"resolved"`
	Seen     int64  `json:"seen"` // unix seconds, when it last resolved
}

var (
	lastResolvedMu     sync.Mutex
	lastResolvedMap    map[string]lastResolvedEntry // as written (absolute) -> where it resolved
	lastResolvedLoaded bool
	lastResolvedNow    = func() int64 { return time.Now().Unix() }
)

func lastResolvedPath() (string, error) {
	d, err := backupStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "resolved.json"), nil
}

func lastResolvedLoadLocked() {
	if lastResolvedLoaded {
		return
	}
	lastResolvedLoaded = true
	lastResolvedMap = map[string]lastResolvedEntry{}
	p, err := lastResolvedPath()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if json.Unmarshal(raw, &lastResolvedMap) != nil {
		// The first shape of this record: folder -> resolved, no time.
		lastResolvedMap = map[string]lastResolvedEntry{}
		var old map[string]string
		if json.Unmarshal(raw, &old) == nil {
			for k, v := range old {
				lastResolvedMap[k] = lastResolvedEntry{Resolved: v}
			}
		}
	}
	if lastResolvedMap == nil {
		lastResolvedMap = map[string]lastResolvedEntry{}
	}
	lastResolvedTrimLocked()
}

// lastResolvedTrimLocked drops the folders resolved longest ago until at
// most lastResolvedMax remain.
func lastResolvedTrimLocked() {
	for len(lastResolvedMap) > lastResolvedMax {
		oldest, first := "", true
		for k, e := range lastResolvedMap {
			if first || e.Seen < lastResolvedMap[oldest].Seen || (e.Seen == lastResolvedMap[oldest].Seen && k < oldest) {
				oldest, first = k, false
			}
		}
		delete(lastResolvedMap, oldest)
	}
}

func lastResolved(p string) string {
	lastResolvedMu.Lock()
	defer lastResolvedMu.Unlock()
	lastResolvedLoadLocked()
	return lastResolvedMap[p].Resolved
}

func noteResolved(p, r string) {
	lastResolvedMu.Lock()
	defer lastResolvedMu.Unlock()
	lastResolvedLoadLocked()
	now := lastResolvedNow()
	e, had := lastResolvedMap[p]
	if had && e.Resolved == r && now-e.Seen < lastResolvedFresh {
		return
	}
	lastResolvedMap[p] = lastResolvedEntry{Resolved: r, Seen: now}
	lastResolvedTrimLocked()
	if f, err := lastResolvedPath(); err == nil {
		if raw, err := json.Marshal(lastResolvedMap); err == nil {
			_ = atomicWrite(f, raw)
		}
	}
}

func opMaskNote(p string, err error) {
	opProbeMu.Lock()
	first := !opProbeLogged[p]
	opProbeLogged[p] = true
	opProbeMu.Unlock()
	if first {
		opMaskLog("backup folder %s cannot be checked (%v): op runs go on without masking it and no op may "+
			"name it; that host's backup ops wait until it answers\n", p, err)
	}
}

// opMaskSet is the masks for one run: every off-limits place, less any
// backup folder that errors or does not answer in time.
func opMaskSet() ([]string, error) {
	offs, backups, err := opOffLimitsSplit()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(offs))
	for _, off := range offs {
		if backups[off] {
			err := opProbe("stat:"+off, func() error {
				_, err := opMaskStat(off)
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			})
			if err != nil {
				opMaskNote(off, err)
				continue
			}
		}
		out = append(out, off)
	}
	return out, nil
}
