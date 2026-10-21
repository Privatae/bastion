package main

// backupretention.go — how many backups this machine keeps.
//
// A host sends its backup here every night (backup_fetch). Kept forever, they
// would fill the disk; so after each new backup arrives, the pairing's backup
// folder is thinned the way the host's other copies are: the newest 7, and
// the newest of each of the last 14 days, 8 weeks and 12 months.
//
// ONLY WHAT THIS BASTION FETCHED. Thinning considers the files in the record
// of arrivals (backupstate.go), which only a completed backup_fetch writes,
// and each only while it is still the file that arrived (same size and
// modification time). A file the person put in the folder, one that was
// there before this version, or one replaced since it arrived, is never
// counted and never removed; a changed or vanished file just leaves the
// record.
//
// BY ARRIVAL, NOT BY NAME. The record keeps the moment each file arrived,
// and that decides its day, week and month. The name comes from the host; if
// it decided, a host that had been taken over could send a batch of newer-
// named files into every past day and push the real backups of those days
// out. By arrival, everything a host sends today competes only with today.
//
// Backups are thinned in pairs (<stamp>.tar.zst.age and its <stamp>.key.age),
// the backup that just arrived is never removed, and a file named .keep-all
// in the folder turns thinning off.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// backupFileRe is the name of a backup file: its stamp, then data or sidecar.
var backupFileRe = regexp.MustCompile(`^([0-9]{8}T[0-9]{6}Z)\.(tar\.zst\.age|key\.age)$`)

const (
	keepLast    = 7
	keepDaily   = 14
	keepWeekly  = 8
	keepMonthly = 12
)

type backupGroup struct {
	stamp   string
	arrived time.Time
	files   []string
}

// pruneBackupRoot thins the pairing's backup folder root after the backup
// file `justArrived` (a name at its top) arrived. Returns the files removed.
func pruneBackupRoot(root, justArrived string) ([]string, error) {
	m := backupFileRe.FindStringSubmatch(justArrived)
	if m == nil {
		return nil, nil
	}
	if _, err := os.Lstat(filepath.Join(root, ".keep-all")); err == nil {
		return nil, nil
	}
	backupStateMu.Lock()
	defer backupStateMu.Unlock()
	a, err := arrivalsLoadLocked(root)
	if err != nil {
		return nil, err
	}
	groups := map[string]*backupGroup{}
	for name, rec := range a.Files {
		mm := backupFileRe.FindStringSubmatch(name)
		fi, err := os.Lstat(filepath.Join(root, name))
		if mm == nil || err != nil || !stillTheArrival(fi, rec) {
			delete(a.Files, name)
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, rec.Arrived)
		if err != nil {
			delete(a.Files, name)
			continue
		}
		g := groups[mm[1]]
		if g == nil {
			g = &backupGroup{stamp: mm[1]}
			groups[mm[1]] = g
		}
		g.files = append(g.files, name)
		// The data file's arrival decides; a sidecar alone counts by its own.
		if mm[2] == "tar.zst.age" || g.arrived.IsZero() {
			g.arrived = at
		}
	}
	var list []*backupGroup
	for _, g := range groups {
		list = append(list, g)
	}
	keep := backupKeepSet(list)
	keep[m[1]] = true
	var removed []string
	for _, g := range list {
		if keep[g.stamp] {
			continue
		}
		for _, name := range g.files {
			err := os.Remove(filepath.Join(root, name))
			if err == nil {
				removed = append(removed, filepath.Join(root, name))
			}
			if err == nil || os.IsNotExist(err) {
				delete(a.Files, name)
			}
		}
	}
	sort.Strings(removed)
	return removed, arrivalsSaveLocked(root, a)
}

// backupKeepSet returns the stamps to keep: the newest keepLast, and the
// newest in each of the newest keepDaily days, keepWeekly ISO weeks and
// keepMonthly months that hold a backup, all by arrival.
func backupKeepSet(list []*backupGroup) map[string]bool {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].arrived.Equal(list[j].arrived) {
			return list[i].arrived.After(list[j].arrived)
		}
		return list[i].stamp > list[j].stamp
	})
	keep := map[string]bool{}
	for i, g := range list {
		if i < keepLast {
			keep[g.stamp] = true
		}
	}
	bucket := func(n int, key func(time.Time) string) {
		seen := map[string]bool{}
		for _, g := range list {
			k := key(g.arrived)
			if seen[k] {
				continue
			}
			if len(seen) == n {
				return
			}
			seen[k] = true
			keep[g.stamp] = true
		}
	}
	bucket(keepDaily, func(t time.Time) string { return t.UTC().Format("2006-01-02") })
	bucket(keepWeekly, func(t time.Time) string {
		y, w := t.UTC().ISOWeek()
		return fmt.Sprintf("%d-W%02d", y, w)
	})
	bucket(keepMonthly, func(t time.Time) string { return t.UTC().Format("2006-01") })
	return keep
}
