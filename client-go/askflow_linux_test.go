package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The socket answers "status" with the kernel's name for the caller, so a
// real connection reads the caller's own ask and nobody else's.
func TestTheAskSocketAnswersStatusOnlyForTheAsker(t *testing.T) {
	askFlowWorld(t)
	me, err := user.Current()
	if err != nil {
		t.Skip("no account name for this process:", err)
	}
	mine := fileAsk(agentAskRequest{Op: "stop", PID: 101}, me.Username, 0)
	theirs := fileAsk(agentAskRequest{Op: "stop", PID: 102}, me.Username+"-other", 0)
	if !mine.OK || !theirs.OK {
		t.Fatalf("asks: %+v %+v", mine, theirs)
	}
	sock := filepath.Join(t.TempDir(), "ask.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go askSockServe(c)
		}
	}()
	ask := func(id string) agentAskReply {
		t.Helper()
		c, err := net.DialTimeout("unix", sock, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = json.NewEncoder(c).Encode(agentAskRequest{Op: "status", Request: id})
		var r agentAskReply
		if err := json.NewDecoder(c).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := ask(mine.Request); !r.OK || r.State != askWaiting || r.User != me.Username {
		t.Errorf("my own ask over the socket: %+v", r)
	}
	if r := ask(theirs.Request); r.OK || r.State != askUnknown {
		t.Errorf("another account's ask over the socket: %+v", r)
	}
}

// `stop` run by an agent (no terminal) files the ask and prints it as JSON;
// `request` follows it to the outcome, with the exit status to branch on.
func TestStopAndRequestFromAnAgent(t *testing.T) {
	d := askFlowWorld(t)
	prevAuth := machineAuthorityHeld
	t.Cleanup(func() { machineAuthorityHeld = prevAuth })
	machineAuthorityHeld = func() bool { return true } // holds the state: the direct path
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prevIn := os.Stdin
	os.Stdin = r // a pipe, not a terminal: an agent
	t.Cleanup(func() { os.Stdin = prevIn; _ = w.Close(); _ = r.Close() })

	out := captureStdout(t)
	if err := cmdStop([]string{"101", "--json"}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	var v askView
	if err := json.Unmarshal([]byte(printedSince(out, 0, "}\n")), &v); err != nil || v.State != askWaiting ||
		v.Request == "" {
		t.Fatalf("stop --json printed %q (%v)", out(), err)
	}
	rows := auditRowsOf(t, d, localStopAskOp)
	if len(rows) != 1 {
		t.Fatalf("filing rows: %v", rows)
	}

	id := fullRequestID(t, d, v.Request)
	if _, err := stepupApproveRequest(d, id, codeFor(t, machineTestSecret)); err != nil {
		t.Fatal(err)
	}
	localStopOnce(d, time.Now())
	before := len(out())
	if err := cmdRequest([]string{v.Request}); err != nil {
		t.Fatalf("request after the stop: %v", err)
	}
	if got := printedSince(out, before, "done."); !strings.Contains(got, "approved by the machine's owner and done") {
		t.Errorf("request printed %q", got)
	}

	// A second ask, denied: `request` exits 1 without an error line.
	second := mustAsk(t, 102)
	if err := stepupDenyRequest(d, fullRequestID(t, d, second)); err != nil {
		t.Fatal(err)
	}
	var q quietExit
	if err := cmdRequest([]string{second, "--json"}); !errors.As(err, &q) || q.code != 1 {
		t.Errorf("a denied ask: %v", err)
	}
}

// printedSince waits (briefly) for captured output past from to hold want:
// captureStdout copies the pipe on its own goroutine.
func printedSince(out func() string, from int, want string) string {
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := out()[from:]
		if strings.Contains(got, want) || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mustAsk(t *testing.T, pid int) string {
	t.Helper()
	r := fileAsk(agentAskRequest{Op: "stop", PID: pid}, procUser(os.Getpid()), 0)
	if !r.OK {
		t.Fatal(r.Why)
	}
	return r.Request
}
