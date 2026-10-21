package main

// Gate: the backup folder is thinned the way the host's other copies are,
// by when each backup arrived here — never by the name a host gave it — and
// only ever among the files this bastion recorded fetching.

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

const stampFmt = "20060102T150405Z"

// arrive writes a data file and its sidecar and records both as having
// arrived at `at`, as a completed fetch does.
func arrive(t *testing.T, root, stamp string, at time.Time) {
	t.Helper()
	for _, suffix := range []string{".tar.zst.age", ".key.age"} {
		if err := os.WriteFile(filepath.Join(root, stamp+suffix), []byte(stamp+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recordArrival(root, stamp+suffix, "00", at); err != nil {
			t.Fatal(err)
		}
	}
}

func stampsIn(t *testing.T, dir string) []string {
	t.Helper()
	l, err := listBackupDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, b := range l {
		out = append(out, b.Stamp)
	}
	sort.Strings(out)
	return out
}

func TestRetentionKeepsSevenFourteenDailyEightWeeklyTwelveMonthly(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 28, 2, 0, 0, 0, time.UTC)
	var newest string
	for d := 399; d >= 0; d-- {
		at := now.AddDate(0, 0, -d)
		newest = at.Format(stampFmt)
		arrive(t, root, newest, at)
	}
	removed, err := pruneBackupRoot(root, newest+".tar.zst.age")
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, s := range stampsIn(t, root) {
		kept[s] = true
	}
	if len(removed) != 2*(400-len(kept)) {
		t.Fatalf("removed %d files for %d backups: data and sidecar go together", len(removed), 400-len(kept))
	}
	// Written out, not derived from the policy code: the last 14 days; the
	// last day held in each of the 8 newest ISO weeks; the last day held in
	// each of the 12 newest months; and nothing from the month before those.
	for d := 0; d < 14; d++ {
		if s := now.AddDate(0, 0, -d).Format(stampFmt); !kept[s] {
			t.Fatalf("the backup of %d days ago was not kept", d)
		}
	}
	for w := 0; w < 8; w++ {
		// 2026-09-28 is a Monday, alone in the newest ISO week; each of the
		// seven weeks before it has a Sunday as its newest day.
		s := now.Format(stampFmt)
		if w > 0 {
			s = now.AddDate(0, 0, -1-7*(w-1)).Format(stampFmt)
		}
		if !kept[s] {
			t.Fatalf("the newest backup of the week %d back (%s) was not kept", w, s)
		}
	}
	for m := 1; m < 12; m++ {
		last := time.Date(2026, time.Month(9-m+1), 1, 2, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
		if !kept[last.Format(stampFmt)] {
			t.Fatalf("the last backup of %s was not kept", last.Format("2006-01"))
		}
	}
	if kept[time.Date(2025, 9, 30, 2, 0, 0, 0, time.UTC).Format(stampFmt)] {
		t.Fatal("a 13th month was kept")
	}
	if len(kept) < 14+7 || len(kept) > 14+8+12 {
		t.Fatalf("kept %d; the policy keeps between 21 and 34 of a daily history", len(kept))
	}
	// The record forgets what was removed.
	backupStateMu.Lock()
	a, _ := arrivalsLoadLocked(root)
	backupStateMu.Unlock()
	if len(a.Files) != 2*len(kept) {
		t.Fatalf("the record holds %d files for %d kept backups", len(a.Files), len(kept))
	}
}

// A host that has been taken over names a batch of files for every past day.
// They all arrive today, so they compete with today only: the real history
// survives.
func TestRetentionIsNotSteeredByTheNamesAHostGives(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	var real []string
	for d := 20; d >= 1; d-- {
		at := now.AddDate(0, 0, -d)
		s := at.Format(stampFmt)
		arrive(t, root, s, at)
		real = append(real, s)
	}
	var last string
	for d := 30; d >= 0; d-- {
		// Named a minute after each real one, so by NAME each would win its day.
		last = now.AddDate(0, 0, -d).Add(time.Minute).Format(stampFmt)
		arrive(t, root, last, now)
	}
	if _, err := pruneBackupRoot(root, last+".tar.zst.age"); err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, s := range stampsIn(t, root) {
		kept[s] = true
	}
	for _, s := range real[len(real)-13:] {
		if !kept[s] {
			t.Fatalf("the real backup %s was pushed out by files that arrived today", s)
		}
	}
}

// Thinning never touches a file this bastion did not record fetching: one
// the person put there, one that was there before, one replaced since it
// arrived, a link, or anything named otherwise; and .keep-all stops it.
func TestRetentionRemovesOnlyWhatThisBastionFetched(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	old := now.AddDate(-3, 0, 0)
	// The person's own backup-named files, older than anything.
	for d := 0; d < 30; d++ {
		s := old.AddDate(0, 0, d).Format(stampFmt)
		_ = os.WriteFile(filepath.Join(root, s+".tar.zst.age"), []byte("mine"), 0o600)
	}
	other := filepath.Join(root, "notes.txt")
	_ = os.WriteFile(other, []byte("mine"), 0o600)
	target := filepath.Join(t.TempDir(), "20200101T000000Z.tar.zst.age")
	_ = os.WriteFile(target, []byte("x"), 0o600)
	link := filepath.Join(root, "20200101T000000Z.tar.zst.age")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("links cannot be made here: %v", err)
	}
	var stamps []string
	for d := 400; d >= 0; d-- {
		at := now.AddDate(0, 0, -d)
		stamps = append(stamps, at.Format(stampFmt))
		arrive(t, root, stamps[len(stamps)-1], at)
	}
	// One old arrival replaced by the person since: no longer the file that
	// arrived, so it is not this bastion's to remove.
	replaced := filepath.Join(root, stamps[0]+".tar.zst.age")
	_ = os.WriteFile(replaced, []byte("the person's own file now, longer"), 0o600)

	keep := filepath.Join(root, ".keep-all")
	_ = os.WriteFile(keep, nil, 0o600)
	if r, _ := pruneBackupRoot(root, stamps[len(stamps)-1]+".tar.zst.age"); len(r) != 0 {
		t.Fatalf(".keep-all was ignored: %d removed", len(r))
	}
	_ = os.Remove(keep)
	if r, _ := pruneBackupRoot(root, "export.tar.zst.age"); len(r) != 0 {
		t.Fatal("a non-backup arrival thinned the folder")
	}
	r, err := pruneBackupRoot(root, stamps[len(stamps)-1]+".tar.zst.age")
	if err != nil || len(r) == 0 {
		t.Fatalf("nothing thinned: %v", err)
	}
	for d := 0; d < 30; d++ {
		s := old.AddDate(0, 0, d).Format(stampFmt)
		if _, err := os.Stat(filepath.Join(root, s+".tar.zst.age")); err != nil {
			t.Fatalf("the person's own file %s was removed", s)
		}
	}
	if _, err := os.Stat(replaced); err != nil {
		t.Fatal("a file replaced since it arrived was removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("a file that is not a backup was removed")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("a link was removed")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("the file a link points to was removed")
	}
}

// The backup that just arrived is kept even when, by arrival, the policy
// would drop it: a fetch never removes what it just delivered.
func TestRetentionNeverRemovesTheBackupThatJustArrived(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	var oldest string
	for d := 400; d >= 0; d-- {
		at := now.AddDate(0, 0, -d)
		s := at.Format(stampFmt)
		arrive(t, root, s, at)
		if oldest == "" {
			oldest = s
		}
	}
	if _, err := pruneBackupRoot(root, oldest+".tar.zst.age"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, oldest+".tar.zst.age")); err != nil {
		t.Fatal("the backup that just arrived was removed")
	}
}

// Wired into backup_fetch: a backup file lands at the top of the pairing's
// folder whatever folder the host named, is recorded, and thins the folder.
func TestBackupFetchLandsAtTheRootRecordsAndThins(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	now := time.Now().UTC()
	for d := 40; d >= 1; d-- {
		at := now.AddDate(0, 0, -d)
		arrive(t, root, at.Format(stampFmt), at)
	}
	body := []byte("tonight's backup")
	srv, want := artifactServer(t, body)
	oldTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()

	stamp := now.Format(stampFmt)
	// The host names a subfolder; a backup file lands at the top regardless.
	req := backupFetchReq{Op: "start", URL: srv.URL + "/a", RPath: "privatae-backups/" + stamp + ".tar.zst.age",
		SHA256: want, Size: int64(len(body))}
	abs, arrival, why := backupFetchDest(root, req.RPath)
	if why != "" || !arrival || abs != filepath.Join(root, stamp+".tar.zst.age") {
		t.Fatalf("a backup file would land at %q (arrival=%v, %q)", abs, arrival, why)
	}
	job := &backupJob{ID: "r1", SHA256: want, Want: int64(len(body)), State: "running", root: root, arrival: true}
	runBackupFetch(job, srv.URL+"/a", abs, 1<<20)
	if job.State != "done" {
		t.Fatalf("%s %s", job.State, job.Error)
	}
	if job.Pruned == 0 {
		t.Fatal("the arrival thinned nothing out of 40 days of backups")
	}
	backupStateMu.Lock()
	a, _ := arrivalsLoadLocked(root)
	backupStateMu.Unlock()
	if rec, ok := a.Files[stamp+".tar.zst.age"]; !ok || rec.SHA256 != want {
		t.Fatalf("the arrival was not recorded: %+v", rec)
	}
	// Anything else keeps the folder the host named, and is not an arrival.
	if abs, arrival, _ := backupFetchDest(root, "exports/e1-"+stamp+".tar.zst.age"); arrival ||
		abs != filepath.Join(root, "exports", "e1-"+stamp+".tar.zst.age") {
		t.Fatalf("an export lands at %q (arrival=%v)", abs, arrival)
	}
}
