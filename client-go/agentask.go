package main

// agentask.go — how something running as a person asks the machine's bastion
// to stop an agent, when the bastion is not theirs.
//
// The bastion installed for the whole machine keeps its state in its own
// account. An agent running as the person cannot write a request there, so
// `stop` run by it had nowhere to ask, and asking is the one thing an agent
// managing the bastion for the person must be able to do (2026-10-30).
// This is the context socket's mechanism (contextsock.go) for a second
// question, and on Windows the service's ask pipe (asklane_windows.go), which
// answers through the same askAnswer: any local account may connect; WHO connected comes from the
// kernel, never from the request; it may only ASK. The ask lands in the
// owner's factor as a pending request (stepup_machine.go), shown on Waiting
// for you and answered with the owner's code. Nothing here approves anything.
//
// Who asked is written into the request from the kernel's record of the
// connecting process: its account, and on Linux its pid, walked up to the
// agent it belongs to, so the owner reads "asked from Claude Code session
// notes-b2", not a sentence the asker wrote.

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const (
	askSockName      = "ask.sock"
	askMaxBytes      = 4 << 10
	askSockInFlight  = 16
	askMaxPendingPer = 5 // waiting requests one account may have at once
)

type agentAskRequest struct {
	Op      string `json:"op"` // "stop", "status" (askstatus.go), "console" (consolelane.go), "read" (reads.go) or "act" (owneracts.go)
	PID     int    `json:"pid"`
	Request string `json:"request,omitempty"` // "status": the id `stop` printed
	// "read": which one, and its flags (readOpts).
	Read    string `json:"read,omitempty"`
	Since   string `json:"since,omitempty"`
	Prompts bool   `json:"prompts,omitempty"`
	Host    string `json:"host,omitempty"`
	Machine bool   `json:"machine,omitempty"`
	// "act": approve, deny or switch (owneracts.go), and what it acts on.
	Act    string `json:"act,omitempty"`
	ID     string `json:"id,omitempty"`
	Code   string `json:"code,omitempty"`
	Family string `json:"family,omitempty"`
	Off    bool   `json:"off,omitempty"`
}

type agentAskReply struct {
	OK      bool   `json:"ok"`
	Request string `json:"request,omitempty"`
	Text    string `json:"text,omitempty"`
	Why     string `json:"why,omitempty"`
	User    string `json:"user,omitempty"`
	URL     string `json:"url,omitempty"` // "console": the link that signs the owner in
	// "status": where the ask is (askStatus) and, once carried out, what
	// happened.
	State   string `json:"state,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

func askSockPath() string { return filepath.Join(contextSockDir, askSockName) }

// askPeerPIDFn is the kernel's pid for the connecting process: SO_PEERCRED on
// Linux, 0 where the platform does not say (then only the account is named).
var askPeerPIDFn = askPeerPID

// askPeerIdentityFn is the kernel's account for the connecting process; a
// variable so a suite run as root can stand in for the owner's account.
var askPeerIdentityFn = contextPeerIdentity

func startAskSock(done <-chan struct{}) {
	if runtime.GOOS == "windows" {
		// The ask pipe (asklane_windows.go). Only the service serves it: a
		// bastion run by an account is that account's, and nobody else's
		// requests are its to answer.
		if runningAsService {
			startAskPipe(done)
		}
		return
	}
	p := askSockPath()
	ln, err := contextSockListen(p)
	if err != nil {
		uilogf("ask socket not available (%v) — an agent running as another account cannot ask "+
			"this bastion to stop anything\n", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
		_ = os.Remove(p)
	}()
	go func() {
		slots := make(chan struct{}, askSockInFlight)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer func() { <-slots }()
					askSockServe(c)
				}()
			default:
				_ = c.Close()
			}
		}
	}()
	uilogf("ask socket listening on %s\n", p)
}

var askMu sync.Mutex // one ask filed at a time: the per-account count is read then written

func askSockServe(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	uid, user, err := askPeerIdentityFn(c)
	if err != nil {
		_ = json.NewEncoder(c).Encode(askUnattributable(err))
		return
	}
	var req agentAskRequest
	if err := json.NewDecoder(io.LimitReader(c, askMaxBytes)).Decode(&req); err != nil {
		_ = json.NewEncoder(c).Encode(agentAskReply{User: user, Why: "the request could not be read"})
		return
	}
	extend := func(d time.Duration) { _ = c.SetDeadline(time.Now().Add(d)) }
	_ = json.NewEncoder(c).Encode(askAnswer(askPeer{UID: uid, Name: user}, req, extend,
		func() int { return askPeerPIDFn(c) }))
}

// askUnattributable is the answer to a connection whose account the
// operating system would not name.
func askUnattributable(err error) agentAskReply {
	return agentAskReply{Why: "this machine could not establish who is asking (" + err.Error() +
		"), so nothing was asked. An ask nobody can attribute is one nobody can answer."}
}

// askAnswer is the lane's answer to one request from peer, on either
// platform: ask.sock here, the ask pipe on Windows. extend gives the answer
// more time where it takes longer (a read, an act); pid is the connecting
// process, asked only for a stop.
func askAnswer(peer askPeer, req agentAskRequest, extend func(time.Duration), pid func() int) any {
	switch req.Op {
	case "console":
		r := agentAskReply{User: peer.Name}
		if link, err := consoleLaneEntryFor(peer); err != nil {
			r.Why = err.Error()
		} else {
			r.OK, r.URL = true, link
		}
		return r
	case "status":
		return askStatus(existingMachineFactorDir(), req.Request, peer.Name, false)
	case "read":
		extend(readDeadline)
		return serveReadFor(peer, req)
	case "act":
		extend(30 * time.Second)
		return serveActFor(peer, req)
	}
	return fileAsk(req, peer.Name, pid())
}

// fileAsk turns one ask into a pending request of the machine, or says why not.
func fileAsk(req agentAskRequest, user string, peerPID int) agentAskReply {
	r := agentAskReply{User: user}
	if req.Op != "stop" {
		r.Why = "this bastion is only asked to stop agents"
		return r
	}
	dir := existingMachineFactorDir()
	if !stepupEnrolled(dir) {
		r.Why = "the owner of this machine has not set up their code, so nothing can be asked of it yet"
		return r
	}
	now := time.Now()
	if until := askHeldUntil(dir, user, now); !until.IsZero() {
		r.Why = askHoldRefusal(user, until)
		return r
	}
	// A refusal that is the asker's own doing counts toward its hold.
	refuse := func(why string) agentAskReply {
		askStrike(dir, user, now)
		r.Why = why
		return r
	}
	observed := observedAgentMap()
	if why := stopRefusal(req.PID, observed); why != "" {
		return refuse(why)
	}
	a := observed[req.PID]
	purpose, err := purposeForLocalStop(req.PID, a.Signature)
	if err != nil {
		r.Why = err.Error()
		return r
	}
	view := buildAgentViews([]agentObs{a}, processTree())[0]
	details := map[string]any{"kind": localStopKind, "pid": strconv.Itoa(req.PID), "signature": a.Signature,
		"agent": familyLabel(a.Signature)}
	if view.Folder != "" {
		details["folder"] = view.Folder
	}
	if view.Self != nil {
		details["session"], details["title"] = view.Self.Name, view.Self.Title
	}
	by := "a program running as " + user
	if peerPID > 1 {
		if who, ok := askingAgent(peerPID, observed); ok {
			by = who + ", running as " + user
		}
	}
	details["asked_by"] = by
	details["asker"], details["target"] = askParties(user, peerPID, req.PID, observed)
	askMu.Lock()
	defer askMu.Unlock()
	// Asking again for a stop this account already has waiting is the same
	// request (stepupNewRequest hands it back), not a new one over the limit.
	if n, same := askPendingBy(dir, user, purpose); n >= askMaxPendingPer && !same {
		return refuse("you already have " + strconv.Itoa(askMaxPendingPer) + " requests waiting for the owner; " +
			"wait for them to be answered")
	}
	details["asked_by_account"] = user
	id, err := stepupNewRequest(dir, purpose, details)
	if errors.Is(err, errRefusedRecently) {
		return refuse("the machine's owner refused this same stop within the last 24 hours, so it cannot be " +
			"asked again yet")
	}
	if err != nil {
		r.Why = err.Error()
		return r
	}
	r.OK, r.Request, r.Text = true, id[:8], describeRequest(stepupRequest{Details: details})
	auditLocalStopAsk(dir, req.PID, a.Signature, details)
	return r
}

// auditLocalStopAsk records that an ask was filed, naming who asked for what.
func auditLocalStopAsk(dir string, pid int, signature string, details map[string]any) {
	dcnAuditWith(dir, localStopAskOp, 0, strconv.Itoa(pid)+" "+signature,
		"asked to stop "+describeStopTarget(details), askPartiesOf(details))
}

const localStopAskOp = "local_stop_ask"

// askPendingBy is how many requests user has waiting, and whether one of them
// is for purpose.
func askPendingBy(dir, user, purpose string) (n int, same bool) {
	stepupMu.Lock()
	m := requestsLoad(dir)
	stepupMu.Unlock()
	for _, id := range sortedPending(m) {
		if a, _ := m[id].Details["asked_by_account"].(string); a == user {
			n++
			same = same || m[id].Purpose == purpose
		}
	}
	return n, same
}

// askViaSock is the asking side: `stop` run where it cannot write the
// machine's state itself.
func askViaSock(req agentAskRequest) (agentAskReply, error) {
	c, err := dialAskLane(askSockPath())
	if err != nil {
		return agentAskReply{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return agentAskReply{}, err
	}
	var r agentAskReply
	err = json.NewDecoder(io.LimitReader(c, askMaxBytes*4)).Decode(&r)
	return r, err
}
