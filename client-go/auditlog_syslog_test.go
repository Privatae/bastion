//go:build !windows

package main

import (
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAuditRowsDoNotWaitOnAStuckSyslogSocket: a real syslog writer on a
// datagram socket nobody reads blocks once the socket's queue is full, as
// /dev/log does while journald is stuck. Audit rows behind the queue all
// return at once; the same writer called inline (as 0.54.0 first did) does not.
func TestAuditRowsDoNotWaitOnAStuckSyslogSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "al")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	// Closing the reading end is what lets the stuck writes below return
	// (refused) so their goroutines end; the writer itself is never closed,
	// since its Close would wait behind a write that is stuck.
	t.Cleanup(func() { l.Close() })
	w, err := syslog.Dial("unixgram", sock, syslog.LOG_AUTH|syslog.LOG_INFO, auditSyslogTag)
	if err != nil {
		t.Fatal(err)
	}
	write := func(line []byte) { _ = w.Info(string(line)) }

	// The inline writer does block: without this the test proves nothing.
	inline := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			write([]byte(`{"op":"x"}`))
		}
		close(inline)
	}()
	select {
	case <-inline:
		t.Skip("this kernel never blocked a datagram writer; nothing to bound")
	case <-time.After(2 * time.Second):
	}

	q := newAuditQueue(64, write)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			q.enqueue([]byte(`{"op":"y"}`))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("audit rows waited on a stuck syslog socket")
	}
	if q.dropped.Load() == 0 {
		t.Fatal("rows past the bound must be counted as dropped")
	}
}
