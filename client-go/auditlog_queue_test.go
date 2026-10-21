package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The sink the binary ships with, read before auditlog_test.go's init swaps
// it out (package variables are set before any init runs).
var auditSinkShipped = auditSink

// TestAuditSinkIsTheQueue: the shipped sink is the queue, never the
// platform's writer called on the audited op's own goroutine.
func TestAuditSinkIsTheQueue(t *testing.T) {
	if reflect.ValueOf(auditSinkShipped).Pointer() != reflect.ValueOf(auditEnqueue).Pointer() {
		t.Fatal("the system-log sink must be auditEnqueue: a direct write blocks the audited op while syslog is stuck")
	}
}

// TestAuditQueueNeverWaitsOnAStuckWriter: with a writer that never returns,
// far more rows than the queue holds are all taken at once; the ones past the
// bound are dropped and counted, and the count rides on the next line that
// gets into the queue.
func TestAuditQueueNeverWaitsOnAStuckWriter(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var got []string
	q := newAuditQueue(8, func(l []byte) {
		<-release
		mu.Lock()
		got = append(got, string(l))
		mu.Unlock()
	})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			q.enqueue([]byte(`{"n":1}`))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("audit rows waited on a stuck system log")
	}
	close(release)
	q.flush(5 * time.Second)
	// Nothing lost without a count: every one of the 1001 rows is either a
	// line written or counted on a line written after the gap.
	q.enqueue([]byte(`{"n":2}`))
	q.flush(5 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	var counted float64
	for _, l := range got {
		m := map[string]any{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		if n, ok := m[auditDroppedField].(float64); ok {
			counted += n
		}
	}
	if len(got) > 10 || counted == 0 || float64(len(got))+counted != 1001 {
		t.Fatalf("lines written %d (at most 10), dropped and counted %v: want 1001 in all", len(got), counted)
	}
}

// TestAuditSystemLogOmitsTheRootCommandText: a root command's text stays in
// the 0600 file; the system-log line carries its digest and length.
func TestAuditSystemLogOmitsTheRootCommandText(t *testing.T) {
	var line string
	prev := auditSink
	auditSink = func(l []byte) { line = string(l) }
	t.Cleanup(func() { auditSink = prev })
	auditToSystemLog(auditFilePairingD, "p", []byte(`{"event":"start","command":"PGPASSWORD=hunter2 psql","command_sha256":"ab"}`))
	m := map[string]any{}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, "hunter2") || m["command"] != nil {
		t.Fatalf("the command text reached the system log: %s", line)
	}
	if m["command_sha256"] != "ab" || m["command_bytes"] != float64(len("PGPASSWORD=hunter2 psql")) {
		t.Fatalf("the line must keep the digest and the length: %s", line)
	}
	auditToSystemLog(auditFilePairingD, "p", []byte(`{"command":"x","command_bytes":70000}`))
	if !strings.Contains(line, `"command_bytes":70000`) {
		t.Fatalf("a row's own command_bytes (the full length) is kept: %s", line)
	}
}
