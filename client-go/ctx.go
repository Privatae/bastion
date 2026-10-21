package main

// Context-store worker. Dedicated Go handlers for the host's bastion-backed
// context store: put/get/del a blob at a relative path under a sandboxed root. NO exec, NO
// shell — these never touch p8AllowedOps. Wire framing reuses the existing mgmt helpers
// (sendMgmt / sendMgmtExit): O = stdout, R = stderr, X = exit code.
//
// Not-found convention (matches the host's backend): a missing key exits 2 with no R payload, so
// the host can distinguish "absent" from "error" (exit 1, with an R message).

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/websocket"
)

// handleCtxPut writes args[1] (base64) to the relative path args[0] under root, atomically.
// ctxIsRecord: the paths under the context root that are THIS BOX'S RECORD,
// never the host's blobs — session transcripts (session.go
// sessionTranscriptPath, <root>/sessions/<id>.log). ctx_put and ctx_del are
// standing work the host runs without a tap (writes.go ownApproval), and a
// standing lane that could rewrite or delete the record of a shell the
// person approved would undo that approval's record. Refused as a bad path.
//
// Judged on the CLEANED path relative to the root — the one the write goes to
// — never on the argument as sent: `./sessions/x` and `a/../sessions/x` both
// clean to the transcripts directory. Case-insensitive, because the disks
// this runs on (macOS, Windows) are.
func ctxIsRecord(root, abs string) bool {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return true // cannot say where it lands: refuse
	}
	first := strings.ToLower(strings.SplitN(filepath.ToSlash(rel), "/", 2)[0])
	return first == "sessions"
}

func handleCtxPut(ws *websocket.Conn, root string, args []string) {
	if len(args) < 2 {
		sendMgmt(ws, 'R', []byte("ctx_put: need <rpath> <b64>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	abs, ok := cleanRel(root, args[0])
	if !ok || ctxIsRecord(root, abs) {
		sendMgmt(ws, 'R', []byte("path rejected\n"))
		sendMgmtExit(ws, 1)
		return
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args[1]))
	if err != nil {
		sendMgmt(ws, 'R', []byte("bad base64\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if err := atomicWrite(abs, data); err != nil {
		sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	sendMgmtExit(ws, 0)
}

// handleCtxGet reads the blob at args[0] and returns it base64 on O. Missing → exit 2 (not-found).
func handleCtxGet(ws *websocket.Conn, root string, args []string) {
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("ctx_get: need <rpath>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	abs, ok := cleanRel(root, args[0])
	if !ok {
		sendMgmt(ws, 'R', []byte("path rejected\n"))
		sendMgmtExit(ws, 1)
		return
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			sendMgmtExit(ws, 2)
			return
		}
		sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	sendMgmt(ws, 'O', []byte(base64.StdEncoding.EncodeToString(data)))
	sendMgmtExit(ws, 0)
}

// handleCtxDel removes the blob at args[0]. Missing → exit 2 (not-found, idempotent).
func handleCtxDel(ws *websocket.Conn, root string, args []string) {
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("ctx_del: need <rpath>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	abs, ok := cleanRel(root, args[0])
	if !ok || ctxIsRecord(root, abs) {
		sendMgmt(ws, 'R', []byte("path rejected\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if err := os.Remove(abs); err != nil {
		if os.IsNotExist(err) {
			sendMgmtExit(ws, 2)
			return
		}
		sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	sendMgmtExit(ws, 0)
}

// cleanRel resolves rpath against root and returns the cleaned absolute path, but ONLY if it
// stays strictly inside root. It rejects absolute paths, NUL bytes, empty/dot paths, and any
// traversal that escapes root (".." / "../x" / "a/../../x"). This is the path sandbox wall —
// a compromised host can ask for any rpath; this is what stops it reaching outside the store.
func cleanRel(root, rpath string) (string, bool) {
	rpath = strings.TrimSpace(rpath)
	if rpath == "" {
		return "", false
	}
	if strings.ContainsRune(rpath, 0) {
		return "", false
	}
	if filepath.IsAbs(rpath) {
		return "", false
	}
	cleanRoot := filepath.Clean(root)
	joined := filepath.Clean(filepath.Join(cleanRoot, filepath.FromSlash(rpath)))
	rel, err := filepath.Rel(cleanRoot, joined)
	if err != nil {
		return "", false
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	// Belt-and-braces: the joined path must be cleanRoot itself (rejected above via rel==".")
	// or a descendant of cleanRoot/. This catches edge cases Rel might not (e.g. odd roots).
	if joined != cleanRoot && !strings.HasPrefix(joined, cleanRoot+string(os.PathSeparator)) {
		return "", false
	}
	return joined, true
}

// atomicWrite writes data to path via a temp file + rename, so a reader never sees a partial
// blob. Dirs are 0700, the file 0600 — the context store is the bastion's private state.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".ctx-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once renamed away
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
