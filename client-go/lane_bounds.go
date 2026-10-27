package main

// What a paired host sends down a worker lane is read at a size this machine
// chose, never at one the host chose: the host picks a frame's length, and a
// frame of any length must not be held whole in this machine's memory. The
// egress lane (egress_relay.go) and the context socket (contextsock.go) follow
// the same rule.
//
//   - A job's first frame (the H spec on a harness worker, the S spec on a
//     session worker) is read up to its lane's bound and refused past it, by
//     name, before any of it is parsed.
//   - What a lane carries after that is streamed: terminal input into the pty
//     (session.go), the replica's bytes into its socket (mirror.go). Frames that
//     nothing reads (a harness run and a root command, which read nothing after
//     their spec) are dropped as they arrive.

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/websocket"
)

const (
	// harnessSpecMaxBytes bounds the H frame. Its bulk is the worktree tar
	// (worktree_b64). The largest tree this lane hands back is
	// maxReturnedTreeBytes (9 MiB, so 12 MiB in base64) inside one message of
	// uvicornWSMaxSize (16 MiB), the most the host takes in (harness.go). A host
	// that sends that tree into its next run needs those 12 MiB, plus the
	// prompt and the run's credentials. Twice the lane's message size holds
	// that with 20 MiB to spare.
	harnessSpecMaxBytes = 2 * uvicornWSMaxSize

	// sessionSpecMaxBytes bounds the S frame: a signed grant (op ids and the
	// person's own words), ids, a public key, and for session:root:exec the
	// command, itself held to rootExecCommandMax (64 KiB), which is at most
	// 384 KiB even when JSON escapes every byte as \u00XX. 1 MiB is the bound
	// Go's own HTTP server puts on a request head.
	sessionSpecMaxBytes = http.DefaultMaxHeaderBytes

	// sessionInputMaxBytes bounds one frame on an open terminal. The host relays
	// what the person's browser sent it, one message each, and its own server
	// takes a message up to uvicornWSMaxSize; the tag is one byte more. Input is
	// streamed into the pty, so this caps a frame's length, not memory.
	sessionInputMaxBytes = uvicornWSMaxSize + 1

	// sessionResizeMaxBytes bounds the body of an R frame, {"cols":N,"rows":N}.
	sessionResizeMaxBytes = 4 << 10

	// heartbeatReplyMaxBytes bounds the host's answer to a heartbeat. It
	// carries directives and the lists of grants this box should hold, each
	// entry an id and a signature of about 130 bytes, so 4 MiB is tens of
	// thousands of grants. Nothing in it is bulk: an update names a version,
	// and the binary comes from the release manifest, not from this reply.
	heartbeatReplyMaxBytes = 4 << 20
)

// errLaneNotJob is a first frame that is not a binary frame with a tag.
var errLaneNotJob = errors.New("the first frame is not a job")

// readLaneJob reads a worker's first frame: its tag, and its body up to
// maxFor(tag) bytes. A body past its bound is never kept: tooBig reports it,
// and body is nil. A tag the caller does not take should get a bound of 0;
// its body is then not read at all.
func readLaneJob(ws *websocket.Conn, maxFor func(tag byte) int64) (tag byte, body []byte, tooBig bool, err error) {
	mt, r, err := ws.NextReader()
	if err != nil {
		return 0, nil, false, err
	}
	if mt != websocket.BinaryMessage {
		return 0, nil, false, errLaneNotJob
	}
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return 0, nil, false, errLaneNotJob // an empty frame
	}
	max := maxFor(t[0])
	if max <= 0 {
		return t[0], nil, false, nil
	}
	body, err = io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return t[0], nil, false, err
	}
	if int64(len(body)) > max {
		return t[0], nil, true, nil
	}
	return t[0], body, false, nil
}

// drainLane reads and drops every frame until the socket fails, holding none
// of them, and returns that failure. A lane that reads nothing after its job
// still has to read, to answer pings and to notice the host going away.
func drainLane(ws *websocket.Conn) error {
	for {
		_, r, err := ws.NextReader()
		if err != nil {
			return err
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
	}
}

// readHeartbeatReply reads the host's answer to a heartbeat up to
// heartbeatReplyMaxBytes. ok is false for a reply past the bound or one that
// failed to arrive: such a beat is treated as unanswered, so none of its
// directives runs and it does not count as the host answering.
func readHeartbeatReply(resp *http.Response) (body []byte, ok bool) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, heartbeatReplyMaxBytes+1))
	if err != nil {
		return nil, false
	}
	if len(body) > heartbeatReplyMaxBytes {
		fmt.Printf("heartbeat: the host's reply is more than %d MiB; ignored\n", heartbeatReplyMaxBytes>>20)
		return nil, false
	}
	return body, true
}
