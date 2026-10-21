package main

// backuplist.go — backup_list: which backups this machine holds for a host,
// and where a backup_push may send one from.
//
// The host asks {"op":"list"} and gets
//
//	{"backups":[{"folder","stamp","data_bytes","has_data","has_sidecar",
//	             "sidecar_bytes","data_sha256","sidecar_sha256"}, ...]}
//
// newest first. `folder` is "." for this pairing's own backup folder, and
// "shared/<name>" for a folder the person shared with this host at this
// machine (`privatae-bastion backup share`), which is how a host that replaces
// a lost one finds the copies its predecessor kept here. Only the top of each
// folder is listed, and only files named like a backup: <stamp>.tar.zst.age
// and <stamp>.key.age. A backup_push names a file as folder + "/" + file.
//
// The digests are what backup_push must be given. Reading a multi-gigabyte
// file to hash it does not fit in one dispatch, so a listing never hashes:
// it answers from what this bastion already knows (the record of what it
// fetched, and a cache keyed by path, size and modification time), gives ""
// for anything not yet known, and starts one background job that hashes
// those files. The host lists again until the digest appears. A file that
// changes size or modification time is unknown again.
//
// A read: it creates no folder and changes nothing in any backup folder
// (backupRootReady creates the host's own folder only for an op that writes).
// What it does beyond reading: the background job reads files to learn their
// digests, and this bastion notes in its own state where each folder last
// resolved (opmask.go), as every op leaves its audit line.
//
// Every folder listed, the host's own and each shared one, is read with the
// same bound as the rest of the backup lane (opProbe): a shared folder on a
// network mount that stopped answering is left out of the reply and named in
// "unavailable", and the listing answers at once with the rest. A shared
// folder that now is, or holds, this bastion's own state (a link swapped in
// after it was shared) is left out the same way.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// backupListMax bounds one reply; the newest backups are the ones a restore
// wants, and the reply is one frame.
const backupListMax = 2000

type backupListEntry struct {
	Folder        string `json:"folder"`
	Stamp         string `json:"stamp"`
	DataBytes     int64  `json:"data_bytes"`
	HasData       bool   `json:"has_data"`
	HasSidecar    bool   `json:"has_sidecar"`
	SidecarBytes  int64  `json:"sidecar_bytes"`
	DataSHA256    string `json:"data_sha256"`
	SidecarSHA256 string `json:"sidecar_sha256"`
}

type backupFolder struct{ name, dir string }

// backupFolders is this pairing's own folder, then every folder shared with it.
func backupFolders(self, root string) []backupFolder {
	out := []backupFolder{{".", root}}
	for _, s := range sharesFor(self) {
		out = append(out, backupFolder{"shared/" + s.Slug, s.Dir})
	}
	return out
}

func handleBackupList(ws *websocket.Conn, root string, args []string) {
	var req struct {
		Op string `json:"op"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
			backupFail(ws, "backup_list: argument is not JSON: "+err.Error())
			return
		}
	}
	if req.Op != "" && req.Op != "list" {
		backupFail(ws, "backup_list: unknown op "+req.Op)
		return
	}
	list, unavailable := listBackupsReport(mgmtSelf(ws), root)
	reply := map[string]any{"backups": list}
	if len(unavailable) > 0 {
		reply["unavailable"] = unavailable
	}
	backupOK(ws, reply)
}

// backupUnavailable is a folder left out of a listing, and why.
type backupUnavailable struct {
	Folder string `json:"folder"`
	Why    string `json:"why"`
}

// backupReadDirFn is os.ReadDir; a test replaces it with one that blocks.
var backupReadDirFn = os.ReadDir

type backupDirFile struct {
	name string
	fi   os.FileInfo
}

// backupScanDir reads the backup-named regular files at the top of dir,
// with their size and time, within the probe bound. A folder that does not
// exist is empty.
func backupScanDir(dir string) ([]backupDirFile, error) {
	var mu sync.Mutex
	var out []backupDirFile
	err := opProbe("list:"+dir, func() error {
		entries, err := backupReadDirFn(dir)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		var got []backupDirFile
		for _, e := range entries {
			if !backupFileRe.MatchString(e.Name()) || !e.Type().IsRegular() {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			got = append(got, backupDirFile{e.Name(), fi})
		}
		mu.Lock()
		out = got
		mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	return out, nil
}

// sharedFolderProblem is why a folder shared with a host is not used now:
// it does not answer, or it resolves to or around this bastion's own state.
// "" when it may be read. Bounded, like every backup folder.
func sharedFolderProblem(dir string) string {
	r, ok, _ := backupFolderResolve(dir)
	if !ok {
		return "does not answer (a network mount that stopped?)"
	}
	if why := bastionStateOverlapResolved(dir, r); why != "" {
		return why
	}
	return ""
}

func listBackups(self, root string) []backupListEntry {
	l, _ := listBackupsReport(self, root)
	return l
}

func listBackupsReport(self, root string) ([]backupListEntry, []backupUnavailable) {
	var arrivals map[string]backupArrival
	backupStateMu.Lock()
	if a, err := arrivalsLoadLocked(root); err == nil {
		arrivals = a.Files
	}
	backupStateMu.Unlock()

	var out []backupListEntry
	var unavailable []backupUnavailable
	for _, f := range backupFolders(self, root) {
		if f.name != "." {
			if why := sharedFolderProblem(f.dir); why != "" {
				unavailable = append(unavailable, backupUnavailable{f.name, why})
				continue
			}
		}
		files, err := backupScanDir(f.dir)
		if err != nil {
			why := err.Error()
			if errors.Is(err, errProbeBusy) || errors.Is(err, errProbeTimeout) {
				why = fmt.Sprintf("does not answer (a network mount that stopped?): %v", err)
			}
			unavailable = append(unavailable, backupUnavailable{f.name, why})
			continue
		}
		byStamp := map[string]*backupListEntry{}
		for _, e := range files {
			m := backupFileRe.FindStringSubmatch(e.name)
			fi := e.fi
			abs := filepath.Join(f.dir, e.name)
			sha := cachedHash(abs, fi)
			if sha == "" && f.name == "." {
				if a, ok := arrivals[e.name]; ok && stillTheArrival(fi, a) {
					sha = a.SHA256
					noteHash(abs, fi, sha)
				}
			}
			if sha == "" {
				requestHash(abs)
			}
			l := byStamp[m[1]]
			if l == nil {
				l = &backupListEntry{Folder: f.name, Stamp: m[1]}
				byStamp[m[1]] = l
			}
			if m[2] == "tar.zst.age" {
				l.HasData, l.DataBytes, l.DataSHA256 = true, fi.Size(), sha
			} else {
				l.HasSidecar, l.SidecarBytes, l.SidecarSHA256 = true, fi.Size(), sha
			}
		}
		for _, l := range byStamp {
			out = append(out, *l)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Stamp != out[j].Stamp {
			return out[i].Stamp > out[j].Stamp
		}
		return out[i].Folder < out[j].Folder
	})
	if len(out) > backupListMax {
		out = out[:backupListMax]
	}
	if out == nil {
		out = []backupListEntry{}
	}
	return out, unavailable
}

// backupResolveFile maps a path a host names ("./<file>", "<file>" or
// "shared/<name>/<file>") to a backup file this pairing may send: named like a
// backup, directly inside its own folder or a folder shared with it, reached
// through no link that leaves that folder, and not itself a link. The refusal
// says which: the path is not one this op takes, or nothing is there.
func backupResolveFile(self, root, p string) (string, string) {
	const rejected = "path rejected (a backup file named <stamp>.tar.zst.age or <stamp>.key.age, in \".\" or a shared folder)"
	p = strings.TrimSpace(p)
	if p == "" || strings.ContainsRune(p, 0) || strings.Contains(p, "\\") || path.IsAbs(p) {
		return "", rejected
	}
	clean := path.Clean(p)
	if clean != p && "./"+clean != p {
		return "", rejected
	}
	parts := strings.Split(clean, "/")
	var dir, name string
	switch {
	case len(parts) == 1:
		dir, name = root, parts[0]
	case len(parts) == 3 && parts[0] == "shared":
		for _, s := range sharesFor(self) {
			if s.Slug == parts[1] {
				dir = s.Dir
			}
		}
		name = parts[2]
	default:
		return "", rejected
	}
	if dir == "" || !backupFileRe.MatchString(name) {
		return "", rejected
	}
	if dir != root {
		if why := sharedFolderProblem(dir); why != "" {
			return "", "the shared folder " + parts[0] + "/" + parts[1] + " " + why
		}
	}
	// Resolving and checking the file touch the folder, which may be a
	// network mount: bounded like the listing.
	var mu sync.Mutex
	var abs, why string
	err := opProbe("push:"+dir, func() error {
		a, w := backupResolveFileIn(dir, name, rejected)
		mu.Lock()
		abs, why = a, w
		mu.Unlock()
		return nil
	})
	if err != nil {
		return "", fmt.Sprintf("the folder of %s does not answer (a network mount that stopped?): %v", p, err)
	}
	mu.Lock()
	defer mu.Unlock()
	return abs, why
}

// backupResolveFileIn is the unbounded half of backupResolveFile.
func backupResolveFileIn(dir, name, rejected string) (string, string) {
	abs, ok := backupResolvePathFn(dir, name)
	if !ok {
		return "", rejected
	}
	fi, err := os.Lstat(abs)
	if err != nil || !fi.Mode().IsRegular() {
		return "", "no backup file at that path"
	}
	return abs, ""
}

// backupResolvePathFn is dcnResolvePath; a test replaces it with one that
// blocks.
var backupResolvePathFn = dcnResolvePath

// mgmtSelf is the pairing this management job came from ("" for an
// anonymous caller, which has no shares).
func mgmtSelf(ws *websocket.Conn) string {
	if a := mgmtAccountOf(ws); a != nil {
		return a.self
	}
	return ""
}
