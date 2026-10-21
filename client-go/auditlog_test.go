package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The test binary never writes to the real system log: the suite's audit
// rows would otherwise land in the journal of whatever machine runs it.
func init() { auditSink = func([]byte) {} }

// auditSinkCapture swaps the system-log sink for one that keeps the lines.
func auditSinkCapture(t *testing.T) func() []map[string]any {
	t.Helper()
	var mu sync.Mutex
	var lines [][]byte
	prev := auditSink
	auditSink = func(line []byte) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, append([]byte(nil), line...))
	}
	t.Cleanup(func() { auditSink = prev })
	return func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		var out []map[string]any
		for _, l := range lines {
			m := map[string]any{}
			if err := json.Unmarshal(l, &m); err != nil {
				t.Fatalf("system-log line is not JSON: %s", l)
			}
			out = append(out, m)
		}
		return out
	}
}

func auditFileRows(t *testing.T, path string) []map[string]any {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatalf("audit file %s: %v", path, err)
	}
	defer fh.Close()
	var out []map[string]any
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		m := map[string]any{}
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("audit row is not JSON: %s", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

// auditSameRow: the system-log line is the file's row, every field equal,
// with `audit` and `pairing` added.
func auditSameRow(t *testing.T, what string, file, logged map[string]any, wantFile, wantPairing string) {
	t.Helper()
	if logged["audit"] != wantFile || logged["pairing"] != wantPairing {
		t.Fatalf("%s: system-log line names audit=%v pairing=%v, want %q %q", what, logged["audit"], logged["pairing"], wantFile, wantPairing)
	}
	for k, v := range file {
		if lv, ok := logged[k]; !ok || !jsonEq(lv, v) {
			t.Fatalf("%s: field %q is %v in the file and %v in the system log", what, k, v, logged[k])
		}
	}
	if len(logged) != len(file)+2 {
		t.Fatalf("%s: system-log line has %d fields, the file row %d (+2 expected)", what, len(logged), len(file))
	}
}

func jsonEq(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// TestAuditRowsReachTheSystemLog: every audit writer on this box sends the row
// it writes to its file to the system log as well, unchanged, naming the file
// and the pairing: the management lane (mgmt_audit.jsonl), pairing changes
// (pairing_audit.jsonl), and a pairing's audit.jsonl for store ops and op runs,
// terminals and root commands.
func TestAuditRowsReachTheSystemLog(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	got := auditSinkCapture(t)
	cfgDir, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	pairDir := filepath.Join(t.TempDir(), "acme.host.example")
	if err := os.MkdirAll(pairDir, 0o700); err != nil {
		t.Fatal(err)
	}

	mgmtAudit("acme.host.example", "uptime", "observe", "allowed", "", 0, []string{"a"}, "")
	pairingAudit("pairing_add", "other.host.example", "ok")
	dcnAudit(pairDir, "dcn_read", 7, "/srv/notes.txt", "allowed")
	sessionAudit(pairDir, "session", "s-1", "ops", "start", 0, "opened")
	rootExecAudit(pairDir, map[string]any{"session_id": "s-2", "event": "stop", "exit": 0})

	lines := got()
	if len(lines) != 5 {
		t.Fatalf("got %d system-log lines, want 5: %v", len(lines), lines)
	}
	mgmt := auditFileRows(t, filepath.Join(cfgDir, mgmtAuditFile))
	pair := auditFileRows(t, filepath.Join(cfgDir, auditFilePairing))
	per := auditFileRows(t, filepath.Join(pairDir, auditFilePairingD))
	if len(mgmt) != 1 || len(pair) != 1 || len(per) != 3 {
		t.Fatalf("file rows: mgmt %d, pairing %d, per-pairing %d; want 1, 1, 3", len(mgmt), len(pair), len(per))
	}
	auditSameRow(t, "management lane", mgmt[0], lines[0], mgmtAuditFile, "acme.host.example")
	auditSameRow(t, "pairing change", pair[0], lines[1], auditFilePairing, "")
	auditSameRow(t, "store op", per[0], lines[2], auditFilePairingD, "acme.host.example")
	auditSameRow(t, "terminal", per[1], lines[3], auditFilePairingD, "acme.host.example")
	auditSameRow(t, "root command", per[2], lines[4], auditFilePairingD, "acme.host.example")
}

// TestAuditFileRowStandsWithoutASystemLog: a system log that takes nothing
// costs the copy only; the row is still written to its file.
func TestAuditFileRowStandsWithoutASystemLog(t *testing.T) {
	prev := auditSink
	auditSink = func([]byte) {}
	t.Cleanup(func() { auditSink = prev })
	pairDir := filepath.Join(t.TempDir(), "acme.host.example")
	if err := os.MkdirAll(pairDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dcnAudit(pairDir, "dcn_read", 1, "/x", "allowed")
	if rows := auditFileRows(t, filepath.Join(pairDir, auditFilePairingD)); len(rows) != 1 {
		t.Fatalf("file rows = %d, want 1", len(rows))
	}
}

// TestAuditSystemLogKeepsNumbersExact: a large id goes to the system log as
// the digits the file has, not as a float.
func TestAuditSystemLogKeepsNumbersExact(t *testing.T) {
	var line string
	prev := auditSink
	auditSink = func(l []byte) { line = string(l) }
	t.Cleanup(func() { auditSink = prev })
	auditToSystemLog(auditFilePairingD, "p", []byte(`{"store_id":9007199254740993}`))
	if !json.Valid([]byte(line)) || !strings.Contains(line, `"store_id":9007199254740993`) {
		t.Fatalf("system-log line %s does not carry the id exactly", line)
	}
}
