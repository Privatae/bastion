//go:build windows

package main

import (
	"strings"
	"sync"

	"golang.org/x/sys/windows/svc/eventlog"
)

var (
	auditEventMu  sync.Mutex
	auditEventLog *eventlog.Log
)

// systemAuditWrite sends one line to the Application event log under the
// source PrivataeBastionAudit, event id 1, at information level. The source
// is registered when the system service is installed
// (registerAuditEventSource); before that, or if the log refuses, the copy is
// lost and the row in the file is not. Called only from auditQ's drain
// (auditlog.go): the event log service can be slow to answer.
func systemAuditWrite(line []byte) {
	auditEventMu.Lock()
	defer auditEventMu.Unlock()
	if auditEventLog == nil {
		l, err := eventlog.Open(auditEventSource)
		if err != nil {
			return
		}
		auditEventLog = l
	}
	if err := auditEventLog.Info(auditEventID, string(line)); err != nil {
		_ = auditEventLog.Close()
		auditEventLog = nil
	}
}

// registerAuditEventSource registers PrivataeBastionAudit as an Application
// event log source, so the rows show with their own source name. Already
// registered is success.
func registerAuditEventSource() error {
	err := eventlog.InstallAsEventCreate(auditEventSource, eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

// removeAuditEventSource unregisters the source when the service is removed.
// Events already written stay in the log.
func removeAuditEventSource() {
	_ = eventlog.Remove(auditEventSource)
}
