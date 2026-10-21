package main

// Accounting on the command lane.
//
// Every other wall on this box already leaves a record of what it decided:
// dcn.go writes the pairing's audit.jsonl for a store op, session.go writes a
// row per terminal, pairing_ops.go writes pairing_audit.jsonl for a membership
// change. The MANAGEMENT lane — the one every other op actually arrives on —
// wrote nothing. A host could ask this machine for an op it was told it does
// not hold, be refused correctly, and the only trace was a stderr frame that
// died with the websocket. The refusal worked and left no evidence it happened,
// which is the same failure shape directive_refusal.go was built to fix, one
// layer down: the gate refuses loudly and then nobody can show that it did.
//
// So: one JSON line per management job, allowed or refused, in
// <configDir>/mgmt_audit.jsonl. Box-level and not per-pairing, for the same
// reason pairing_audit.jsonl is — the interesting question is "what has been
// ASKED of this machine", across every host paired to it, and a per-pairing
// file can only ever answer it one pairing at a time.
//
//	{"ts":"<rfc3339 utc>","self":"acme.host.privatae.ai","op":"uptime",
//	 "family":"observe","verdict":"allowed","why":"","exit":0,
//	 "grant_sig":"<b64>","binary_sha256":"<hex>"}
//
// `self` is the PAIRING ID — the host name the pairing is filed under. Never a
// key, never a token: this file is read by a human on the user's own machine
// and fetched over the tunnel by the anchor, and neither of those is a reason
// to put a secret in it. `grant_sig` is the SIGNATURE of the grant that was
// consulted, which is the same public value the enforcing report already ships
// (enforcing.go:22-24) and is what lets the host tell "refused under the grant
// I issued" from "refused under a stale copy".
//
// Every line is written BEFORE the terminal frame leaves this box, and a
// refusal's line before any frame at all (refuseMgmt, mgmt.go). A refusal is
// the interesting half of this file, and a crash between the decision and the
// write would lose exactly the line somebody would later go looking for.
//
// Three things live here: the writer, the heartbeat summary the host reads
// without pulling anything (mgmtAuditReport), and the read-only fetch for when
// it wants the lines themselves (handleAuditFetch).

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

const (
	mgmtAuditFile = "mgmt_audit.jsonl"

	// auditAllowed / auditRefused are the only two verdicts. "allowed" means the
	// WALL let the op through — not that it succeeded. A handler that ran and
	// failed is allowed with a non-zero exit, and the distinction matters: one is
	// a permission event the host should react to, the other is a bad argument.
	auditAllowed = "allowed"
	auditRefused = "refused"

	// mgmtAuditFetchOp is the op name, held as a constant because three places
	// need to agree on it: handlerOps, the anchor-only gate in mgmt.go, and
	// opFamily's classification of it.
	mgmtAuditFetchOp = "audit_fetch"

	// mgmtAuditFetchMaxBytes caps ONE fetch, and it is a ceiling the caller can
	// only ask below, never above — the same shape as backupfetch.go's
	// max_bytes. 1 MiB is on the order of 4-5k lines of this file, which is far
	// more than anyone reads at once and still small enough to cross the
	// management frame without the host having to stream it.
	mgmtAuditFetchMaxBytes = 1 << 20

	// mgmtAuditLineMax is the longest single line the summary reader will take.
	// These records are machine-written and a few hundred bytes; anything longer
	// is not one of ours. A line over this is SKIPPED and the scan continues —
	// see mgmtAuditReport for why that distinction is the whole point.
	mgmtAuditLineMax = 64 * 1024

	// mgmtAuditOpMax / mgmtAuditWhyMax bound the two caller-influenced fields
	// BEFORE they are marshalled.
	//
	// op is job.Op straight off the wire and the refusal strings embed it again,
	// so without a bound here one job writes a record of whatever size the
	// sender chose. Sized from the real values, not guessed: the longest op name
	// in handlerOps is 22 bytes ("pairing_anchor_consent"), and the longest
	// refusal this lane produces is 293 bytes (unanchoredNetworkedRefusal with
	// the longest op interpolated). 128 and 512 clear both several times over,
	// so nothing legitimate is ever truncated, and a marker says so when
	// something is.
	mgmtAuditOpMax  = 128
	mgmtAuditWhyMax = 512

	// mgmtAuditMaxBytes is when the file rolls to mgmt_audit.jsonl.1, one
	// generation kept. At roughly 250 bytes a record that is ~33k ops of
	// history, and it bounds three things at once: the disk this takes on the
	// user's own machine (2x this, worst case), the work the heartbeat summary
	// does (it reads the current file only, every beat), and how much one
	// pairing can make either of those grow by driving traffic at the lane.
	mgmtAuditMaxBytes = 8 << 20
)

// mgmtAuditPath is <configDir>/mgmt_audit.jsonl. configDir (config.go:137)
// creates the directory as a side effect, which is what every other writer on
// this path already relies on.
func mgmtAuditPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, mgmtAuditFile), nil
}

// mgmtAudit appends one record. Best-effort, exactly like pairingAudit
// (pairing_ops.go:32-50) and dcnAudit: a decision stands whether or not the
// line lands, and a full disk must not turn into a lane that stops answering.
// That is a deliberate trade and not an oversight — the alternative is a box
// that refuses work because it cannot write about the work.
//
// args and approval (writes.go): the sha256 of the args array the job carried —
// the same digest the approval bound — and how a gated write was approved
// ("device" | "console"), so a line can be matched to the approval that let it
// run. Never the args themselves: the observe shelf records those, bounded, for
// the three ops that take a value (machinestore.go), and an audit line that
// carried a ctx_put body would be the wrong file holding user data.
func mgmtAudit(self, op, family, verdict, why string, exit int, args []string, approval string) {
	p, err := mgmtAuditPath()
	if err != nil {
		return
	}
	line := map[string]any{
		"ts":            time.Now().UTC().Format(time.RFC3339),
		"self":          self,
		"op":            auditClamp(op, mgmtAuditOpMax),
		"family":        family,
		"verdict":       verdict,
		"why":           auditClamp(why, mgmtAuditWhyMax),
		"exit":          exit,
		"grant_sig":     pairingGrantSig(self),
		"binary_sha256": selfDigest(),
		"args_sha256":   argsDigest(args),
	}
	if approval != "" {
		line["approval"] = approval
	}
	rec, _ := json.Marshal(line)
	mgmtAuditMu.Lock()
	defer mgmtAuditMu.Unlock()

	fh, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fh.Write(append(rec, '\n'))
	// CLOSED BEFORE THE ROLL, NOT DEFERRED PAST IT — see mgmtAuditRoll.
	_ = fh.Close()
	mgmtAuditRoll(p)
}

// mgmtAuditMu serialises the append-and-roll above.
//
// The append does not need it — O_APPEND is a single atomic write on both
// families (POSIX for one; FILE_APPEND_DATA for the other) — but the ROLL does.
// Two management jobs landing together can each stat an over-cap file, and the
// second rename then moves the fresh, nearly-empty live file over the
// generation the first one just saved: 8 MiB of history destroyed to preserve a
// few hundred bytes. The lane is one websocket per pairing and a box holds
// several, so concurrent jobs are the normal case, not the rare one.
//
// Taken AFTER pairingGrantSig/selfDigest deliberately: those read pairing files
// under saveMu (config.go), and a lock taken across them would be a second
// ordering between the two mutexes for no benefit. The cost is that record
// order under contention is the order writers reach this line rather than the
// order their decisions were made, which was already true.
var mgmtAuditMu sync.Mutex

// auditClamp bounds one caller-influenced field and SAYS when it did.
//
// A silent truncation in an audit record is its own small lie — a reader cannot
// tell a short op from a clipped one — so the marker carries the original
// length. Cut on a rune boundary: the bytes arrive from the network and may be
// any encoding, and json.Marshal would otherwise turn a split rune into a
// replacement character that looks like content rather than damage.
func auditClamp(v string, max int) string {
	if len(v) <= max {
		return v
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + fmt.Sprintf("...[truncated, %d bytes]", len(v))
}

// mgmtAuditRoll moves the file aside once it passes mgmtAuditMaxBytes, keeping
// exactly one previous generation. Best-effort like everything else here.
//
// Rolling rather than trimming in place because a record is only useful whole:
// chopping the front of a JSONL file leaves a partial first line, and every
// reader of it then has to know to discard one. Renaming leaves both files
// valid. One generation because the point is a bound, and the heartbeat summary
// reads the current file only — history past the roll is for a human with the
// machine in front of them, not for the wire.
//
// TAKES THE PATH, NOT THE OPEN HANDLE, AND THAT IS THE WHOLE FIX ON WINDOWS.
// The first cut of this was called as mgmtAuditRoll(p, fh) from inside mgmtAudit
// while `defer fh.Close()` still held the file. On unix that renames fine — the
// directory entry moves and the open handle keeps writing to the same inode —
// so every test here passed. On Windows it cannot: os.Rename is MoveFileEx with
// MOVEFILE_REPLACE_EXISTING (internal/syscall/windows/syscall_windows.go:366),
// which needs DELETE access on the source, and os.OpenFile's share mode is
// FILE_SHARE_READ|FILE_SHARE_WRITE with no FILE_SHARE_DELETE (the `sharemode :=`
// line in syscall/syscall_windows.go's Open) — so the handle this function was
// handed is exactly what refuses the rename, with a sharing violation.
//
// The failure was silent and permanent. The error is discarded by design
// (best-effort, like every writer on this path), so past 8 MiB the file simply
// kept growing at ~250 bytes a job, on the USER'S OWN MACHINE — and
// mgmtAuditReport re-reads the whole of it on every heartbeat, per pairing. The
// cap that is supposed to bound the disk, the summary's work, and how much one
// pairing can grow either by driving traffic at the lane was bounding none of
// them. mgmt_audit_test.go is //go:build !windows (it borrows setupBox), so no
// test in that file can ever see this; mgmt_audit_roll_test.go carries no tag.
//
// Because MoveFileEx is REPLACE_EXISTING, renaming over an existing .1 is
// correct on both families and needs no unlink first.
func mgmtAuditRoll(p string) {
	st, err := os.Stat(p)
	if err != nil || st.Size() < mgmtAuditMaxBytes {
		return
	}
	_ = os.Rename(p, p+".1")
}

// pairingGrantSig is the signature of the pairing grant that was consulted for
// this pairing, or "" when none was.
//
// Empty for the ANCHOR pairing, and that emptiness is meaningful rather than
// missing data: the anchor is unconstrained by construction (capsAllow,
// anchor.go:542-544), so no grant is read and there is no signature to name.
// Empty too when the pairing holds no grant that still verifies — pairingCaps
// (anchor.go:381-391) re-verifies on every call and returns ok=false for a
// missing, revoked, tampered or wrong-subject grant, and in every one of those
// cases nothing was consulted, so reporting a signature read off the file would
// be claiming an authority that was never established. Same order as
// pairingEnforcing (anchor.go:702-712): verify first, read the signature second.
func pairingGrantSig(self string) string {
	if self == "" {
		return ""
	}
	if a := currentAnchor(); a == nil || a.AnchorHost == self {
		return ""
	}
	if _, ok := pairingCaps(self); !ok {
		return ""
	}
	g, err := loadPairingGrant(self)
	if err != nil {
		return ""
	}
	return g.Signature
}

type mgmtAuditRecord struct {
	TS      string `json:"ts"`
	Op      string `json:"op"`
	Verdict string `json:"verdict"`
	Why     string `json:"why"`
}

// mgmtAuditReport is the enforcing-report fragment: how many lines the file
// holds, how many of them are refusals inside the last hour, and the last
// refusal itself.
//
// The point of the summary is that the host learns a machine is refusing its
// own host's requests WITHOUT pulling the file — the heartbeat already rides
// every beat and is replaced each time (directive_refusal.go:22-25), so a count
// here is live by construction. Pulling the file is the second step, taken only
// once the count says there is something in it worth reading.
//
// AN OVER-LONG LINE IS SKIPPED, NOT FATAL, and that is the whole reason this
// does not use bufio.Scanner. Scanner stops at the first token past its buffer
// and returns "token too long" — measured: five lines whose third is 70 KiB
// count as TWO, with the rest of the file never read. On a signal whose job is
// to say "this machine is refusing things", that turns one over-long record
// into a permanent freeze of the count, with no error on the wire and a block
// that still looks confident. Every input here arrives from a pairing, so a
// reader that can be stopped by its input is a reader that can be switched off
// by the party it is watching. bufio.Reader.ReadLine drops the fragment and
// carries on, and `unreadable` says how many it dropped.
//
// nil when the file does not exist: a box that has answered nothing says
// nothing, rather than reporting a confident zero that reads the same as a box
// whose audit was deleted.
func mgmtAuditReport() map[string]any {
	p, err := mgmtAuditPath()
	if err != nil {
		return nil
	}
	fh, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer fh.Close()

	cutoff := time.Now().UTC().Add(-time.Hour)
	lines, refusedLastHour, unreadable := 0, 0, 0
	var last *mgmtAuditRecord

	rd := bufio.NewReaderSize(fh, mgmtAuditLineMax)
	for {
		line, isPrefix, err := rd.ReadLine()
		if err != nil {
			break
		}
		if isPrefix {
			// Longer than the buffer. Drain its remaining fragments so the next
			// read starts on a real record boundary, count it as a line that is
			// there but unreadable, and keep going.
			for isPrefix && err == nil {
				_, isPrefix, err = rd.ReadLine()
			}
			lines++
			unreadable++
			if err != nil {
				break
			}
			continue
		}
		if len(line) == 0 {
			continue
		}
		lines++
		var r mgmtAuditRecord
		if err := json.Unmarshal(line, &r); err != nil {
			unreadable++
			continue
		}
		if r.Verdict != auditRefused {
			continue
		}
		rec := r
		last = &rec
		// An unparseable ts is not counted rather than counted as recent: this
		// number drives a posture drop on the host, and a clock or a format we
		// cannot read is not evidence that something was refused in the last hour.
		if ts, err := time.Parse(time.RFC3339, r.TS); err == nil && ts.After(cutoff) {
			refusedLastHour++
		}
	}

	out := map[string]any{"lines": lines, "refused_last_hour": refusedLastHour}
	if last != nil {
		out["last_refusal"] = map[string]any{"ts": last.TS, "op": last.Op, "why": last.Why}
	}
	// Only when there are any, so a clean file never carries a zero that invites
	// someone to go looking for damage that is not there.
	if unreadable > 0 {
		out["unreadable"] = unreadable
	}
	return out
}

type auditFetchReq struct {
	// MaxBytes is the caller's proposed ceiling. The smaller of it and
	// mgmtAuditFetchMaxBytes wins — a host asking for more gets this box's
	// number, the same rule contextextract.go states for its own pull.
	MaxBytes int64 `json:"max_bytes"`
}

// handleAuditFetch returns the TAIL of the audit file, whole lines only.
//
// The tail and not the head: this file only ever grows at the end, so the lines
// anybody wants are the recent ones, and a head-first read would hand back the
// oldest kilobyte of a machine that has been running for a year. Whole lines
// only because the consumer parses JSONL, and a fetch that starts mid-record
// makes its first line garbage.
//
// Read-only. There is no op here that truncates or rotates this file: the
// record of what was asked of a machine is not something a host gets to edit
// over the tunnel, and the same is true of every other audit file on this box.
func handleAuditFetch(ws *websocket.Conn, _ string, args []string) {
	max := int64(mgmtAuditFetchMaxBytes)
	if len(args) > 0 && args[0] != "" {
		var req auditFetchReq
		if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
			sendMgmt(ws, 'R', []byte("audit_fetch: argument is not JSON: "+err.Error()+"\n"))
			sendMgmtExit(ws, 1)
			return
		}
		if req.MaxBytes > 0 && req.MaxBytes < max {
			max = req.MaxBytes
		}
	}
	p, err := mgmtAuditPath()
	if err != nil {
		sendMgmt(ws, 'R', []byte("audit_fetch: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	fh, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing has been asked of this box yet. Empty, not an error — the
			// same call on a quiet machine and on a busy one must differ in its
			// CONTENT, not in whether it worked.
			auditFetchReply(ws, map[string]any{"bytes": 0, "truncated": false, "text": ""})
			return
		}
		sendMgmt(ws, 'R', []byte("audit_fetch: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		sendMgmt(ws, 'R', []byte("audit_fetch: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	size := st.Size()
	off, truncated := int64(0), false
	if size > max {
		off, truncated = size-max, true
	}
	buf := make([]byte, size-off)
	if _, err := fh.ReadAt(buf, off); err != nil {
		sendMgmt(ws, 'R', []byte("audit_fetch: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if truncated {
		// Drop the partial first record. If the window happens to hold no newline
		// at all there is no whole line in it, and the honest answer is nothing
		// rather than a fragment the caller will fail to parse.
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		} else {
			buf = nil
		}
	}
	auditFetchReply(ws, map[string]any{
		"bytes":     size,
		"truncated": truncated,
		"text":      string(buf),
	})
}

func auditFetchReply(ws *websocket.Conn, v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		sendMgmt(ws, 'R', []byte(fmt.Sprintf("audit_fetch: result marshal failed: %v\n", err)))
		sendMgmtExit(ws, 1)
		return
	}
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}
