package main

// Audit rows to the system log, as well as to their files.
//
// Every audit file on this box (mgmt_audit.jsonl, pairing_audit.jsonl, and a
// pairing's audit.jsonl for terminals, root commands, store ops and op runs)
// lives here, on this machine. The host can fetch them over the tunnel but
// never edit them (mgmt_audit.go handleAuditFetch). That still leaves the host
// as the only central view of a fleet, and the host is the agent the audit is
// about. So each row is also written to the machine's own system log, where
// whatever already collects that log (journald or syslog forwarding, a log
// shipper, a SIEM) takes it to a store the host cannot write:
//
//	Linux, macOS  syslog, facility auth, tag privatae-bastion-audit
//	              (journald on a systemd machine: SYSLOG_IDENTIFIER=privatae-bastion-audit)
//	Windows       the Application event log, source PrivataeBastionAudit, event id 1
//
// The system-log line is the file's row with two fields added in front of it:
// `audit`, which file the row went to, and `pairing`, the pairing it belongs to
// ("" for a box-level file). The file stays the record: a system log that is
// missing or refuses a write costs that copy and nothing else, and is never a
// reason to refuse or slow the op being audited.
//
// A root command's text is the one thing the file has that the system-log line
// does not: it is whatever the host typed, a password on a command line
// included, and the system log is readable by more accounts than the 0600 file
// and forwarded off the machine by design. The line keeps command_sha256 and
// command_bytes, so a collector can still match it to the file and the
// transcript and see if either was changed.
//
// The write itself never runs on the audited op's goroutine. The syslog socket
// is a blocking write: a journald or syslog daemon that is stuck or slow would
// otherwise hold every audited op, and every other audit writer behind the
// lock, for as long as it stays stuck. Lines go into a bounded queue that one
// goroutine drains; a full queue drops the line and counts it, and the next
// line queued after the gap carries the count (auditDroppedField).

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	auditSyslogTag    = "privatae-bastion-audit"
	auditEventSource  = "PrivataeBastionAudit"
	auditEventID      = 1
	auditFilePairing  = "pairing_audit.jsonl"
	auditFilePairingD = "audit.jsonl"
)

// auditSink takes one line for the system log. A variable so a test can watch
// the lines; the default queues it for the platform's writer and never blocks.
var auditSink = auditEnqueue

const (
	// auditQueueMax lines wait for the system log; beyond that they are
	// dropped and counted. A burst of audited ops far larger than any lane
	// produces fits; a system log stuck for good holds no more than this.
	auditQueueMax = 4096
	// auditDroppedField is added to the first line queued after a drop: how
	// many lines the system log lost just before it, so the gap shows where.
	auditDroppedField = "system_log_dropped"
	// auditFlushOnExit bounds how long a finished command waits for its rows
	// to reach a slow system log.
	auditFlushOnExit = 2 * time.Second
)

// auditQueue is the bounded queue in front of a system-log writer, drained by
// one goroutine so lines keep their order.
type auditQueue struct {
	ch      chan []byte
	write   func([]byte)
	once    sync.Once
	dropped atomic.Int64
	pending atomic.Int64 // queued or being written
}

func newAuditQueue(n int, write func([]byte)) *auditQueue {
	return &auditQueue{ch: make(chan []byte, n), write: write}
}

// The box's one queue, in front of systemAuditWrite (auditlog_*.go).
var auditQ = newAuditQueue(auditQueueMax, func(l []byte) { systemAuditWrite(l) })

func auditEnqueue(line []byte) { auditQ.enqueue(line) }

// auditFlush waits, at most d, for queued lines to reach the system log. A
// command that audits and then exits (pair, claim-anchor, set-mode) calls it
// on the way out (main.go), so its rows are not lost with the process; a
// stuck system log costs that wait and nothing more.
func auditFlush(d time.Duration) { auditQ.flush(d) }

// enqueue hands one line to the drain goroutine, or drops it and counts it
// when the queue is full. It never waits on the writer.
func (q *auditQueue) enqueue(line []byte) {
	q.once.Do(func() { go q.drain() })
	n := q.dropped.Swap(0)
	if n > 0 {
		line = auditWithDropped(line, n)
	}
	q.pending.Add(1)
	select {
	case q.ch <- line:
	default:
		q.pending.Add(-1)
		q.dropped.Add(n + 1)
	}
}

func (q *auditQueue) drain() {
	for line := range q.ch {
		q.write(line)
		q.pending.Add(-1)
	}
}

func (q *auditQueue) flush(d time.Duration) {
	deadline := time.Now().Add(d)
	for q.pending.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

// auditWithDropped adds the drop count to a line (every line here is the
// JSON object auditToSystemLog made).
func auditWithDropped(line []byte, n int64) []byte {
	fields := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		return line
	}
	fields[auditDroppedField] = n
	out, err := json.Marshal(fields)
	if err != nil {
		return line
	}
	return out
}

// auditToSystemLog sends one audit row, as it was written to its file, to the
// system log, with the file's name and the pairing in front.
func auditToSystemLog(file, pairing string, rec []byte) {
	fields := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(rec))
	dec.UseNumber() // numbers go out exactly as the file has them
	if err := dec.Decode(&fields); err != nil {
		return
	}
	if cmd, ok := fields["command"].(string); ok {
		// The text stays in the file; see the top of this file.
		delete(fields, "command")
		if _, ok := fields["command_bytes"]; !ok {
			fields["command_bytes"] = len(cmd)
		}
	}
	fields["audit"] = file
	fields["pairing"] = pairing
	line, err := json.Marshal(fields)
	if err != nil {
		return
	}
	auditSink(line)
}

// auditPairingOfDir names the pairing of a per-pairing audit file from its
// directory: the last path element, which is the pairing's host name
// (Config.dcnDir: dcn/<host_name>), except for a legacy pairing that kept the
// old shared directory, where it is that directory's name.
func auditPairingOfDir(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Base(filepath.Clean(dir))
}
