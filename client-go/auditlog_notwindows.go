//go:build !windows

package main

import (
	"log/syslog"
	"sync"
)

var (
	auditSyslogMu sync.Mutex
	auditSyslog   *syslog.Writer
)

// systemAuditWrite sends one line to syslog (journald on a systemd machine),
// facility auth, at info. Called only from auditQ's drain (auditlog.go), never on
// an audited op's own goroutine: the write blocks while the daemon is stuck. The connection is opened on first use and dropped
// after a failed write, so the next row tries again; a machine with no syslog
// socket costs the copy, never the row in the file.
func systemAuditWrite(line []byte) {
	auditSyslogMu.Lock()
	defer auditSyslogMu.Unlock()
	if auditSyslog == nil {
		w, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, auditSyslogTag)
		if err != nil {
			return
		}
		auditSyslog = w
	}
	if err := auditSyslog.Info(string(line)); err != nil {
		_ = auditSyslog.Close()
		auditSyslog = nil
	}
}
