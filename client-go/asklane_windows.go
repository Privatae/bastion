//go:build windows

package main

// The ask pipe: ask.sock (agentask.go) for a bastion that runs as the Windows
// service.
//
// Installed for the whole machine, the bastion is a LocalSystem service and
// its state sits in LocalSystem's profile, where the person's own account can
// neither read nor write it. Before this pipe, that account had no way to the
// machine's bastion at all: `privatae-bastion ui` signed in with a key of its
// own and the console answered 401, the reads and owner acts were refused
// beside the service, and an agent could not ask for a stop. The pipe answers
// exactly what ask.sock answers, through the same code (askAnswer): a stop
// asked by any account, and the console, the reads and the owner's acts for
// the account recorded as the machine's owner (approvals-owner --sid), with
// the caller taken from the pipe client's token, never from the request.
//
// The pipe is the approvals pipe's machinery (approvalpipe_windows.go):
// overlapped I/O with a timeout on every call, a new instance created before
// the one it replaces is handed out, the first instance created with
// FILE_FLAG_FIRST_PIPE_INSTANCE, and the asking side checking the pipe's
// server is the service's own process before it sends anything, since an act
// carries the owner's code.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/windows"
)

// startAskPipe serves the ask pipe until done is closed, retrying with backoff
// when it cannot (pipeServeRetrying), as the approvals pipe does.
func startAskPipe(done <-chan struct{}) {
	wait := func(d time.Duration) bool {
		select {
		case <-done:
			return false
		case <-time.After(d):
			return true
		}
	}
	go pipeServeRetrying(func(ready func()) error {
		return servePipe(done, ready, askPipeName, askPipeSDDL, serveAskPipeConn)
	}, wait, func(f string, a ...any) { fmt.Printf(f, a...) })
}

// serveAskPipeConn answers one ask, then waits briefly for the client to
// close: closing first would discard an answer it has not read yet.
func serveAskPipeConn(c *pipeConn) {
	client, cerr := pipeClientOf(c.h)
	raw, err := c.readLine(askMaxBytes, pipeIOTimeout)
	if err != nil {
		return
	}
	var reply any
	switch {
	case cerr != nil:
		reply = askUnattributable(cerr)
	default:
		who := pipeWho(client)
		var req agentAskRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			reply = agentAskReply{User: who, Why: "the request could not be read"}
			break
		}
		peer := askPeer{SID: client.UserSID, Name: who, PID: int(client.PID)}
		reply = askAnswer(peer, req, func(time.Duration) {}, func() int { return int(client.PID) })
	}
	out, _ := json.Marshal(reply)
	if err := c.write(append(out, '\n'), pipeIOTimeout); err != nil {
		return
	}
	_, _ = c.read(pipeIOTimeout)
}

// dialAskLane opens the service's ask pipe; p, ask.sock's path, does not
// apply here.
func dialAskLane(string) (askConn, error) {
	c, err := dialServicePipe(askPipeName)
	if err != nil {
		return nil, err
	}
	if err := pipeServerIsService(c.h); err != nil {
		c.close()
		return nil, err
	}
	return &askPipeClient{c: c}, nil
}

// askLaneAddr is where the lane is, as a message names it.
func askLaneAddr(string) string { return askPipeName }

// askPipeClient is the asking side's end of the pipe, read and written the
// way the lane's code reads and writes a socket: a deadline for the whole
// exchange, bytes in, bytes out.
type askPipeClient struct {
	c        *pipeConn
	deadline time.Time
	pending  []byte
}

func (a *askPipeClient) SetDeadline(t time.Time) error {
	a.deadline = t
	return nil
}

// left is what remains of the deadline for one call; 0 waits as long as it
// takes, which only a caller that set no deadline gets.
func (a *askPipeClient) left() time.Duration {
	if a.deadline.IsZero() {
		return 0
	}
	if d := time.Until(a.deadline); d > 0 {
		return d
	}
	return time.Millisecond
}

func (a *askPipeClient) Read(b []byte) (int, error) {
	for len(a.pending) == 0 {
		n, err := a.c.read(a.left())
		a.pending = append(a.pending, a.c.buf[:n]...)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			if len(a.pending) > 0 {
				break
			}
			if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
				return 0, io.EOF
			}
			return 0, err
		}
	}
	n := copy(b, a.pending)
	a.pending = a.pending[n:]
	return n, nil
}

func (a *askPipeClient) Write(b []byte) (int, error) {
	if err := a.c.write(b, a.left()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (a *askPipeClient) Close() error {
	a.c.close()
	return nil
}
