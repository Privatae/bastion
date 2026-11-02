package main

// askpeer.go — who is on the other end of the owner's lane, on every platform.
//
// The lane (agentask.go: ask.sock on Linux and macOS, the ask pipe on Windows,
// asklane_windows.go) learns the connecting account from the operating system,
// never from the request: a uid from the socket's peer credentials, or a SID
// from the pipe client's token. The machine's owner is recorded the same two
// ways (approvals_owner.go). Every refusal on the lane asks here, so both
// platforms answer with the same rules, and only the commands they name differ.

import (
	"strconv"
	"strings"
	"time"
)

type askPeer struct {
	UID  uint32 // Linux and macOS: the connecting process's account
	SID  string // Windows: the pipe client's token user; "" elsewhere
	Name string // the account as messages name it
	PID  int    // the connecting process; 0 when the platform does not say
}

// windows reports whether the peer came over the Windows pipe.
func (p askPeer) windows() bool { return p.SID != "" }

// laneOwnerMatch reads the recorded owner the way peer's platform names
// accounts. present is true when a record exists, readable or not; ownerName
// is how a refusal names the owner.
func laneOwnerMatch(p askPeer) (match bool, ownerName string, present bool, err error) {
	if p.windows() {
		sid, present, err := approvalsOwnerLoad()
		if err != nil || !present {
			return false, "", present, err
		}
		return strings.EqualFold(sid, p.SID), sid, true, nil
	}
	uid, name, present, err := ownerAccountLoad()
	if err != nil || !present {
		return false, "", present, err
	}
	if name == "" {
		name = "uid " + strconv.FormatUint(uint64(uid), 10)
	}
	return uid == p.UID, name, true, nil
}

// ownerRecordCommand is the administrator's command that records peer's
// account as the machine's owner.
func ownerRecordCommand(p askPeer) string {
	if p.windows() {
		return adminCommandFor(true, "approvals-owner --sid "+p.SID)
	}
	return "sudo -H privatae-bastion approvals-owner --account " + accountForHint(p.Name)
}

// adminCommandFor is `privatae-bastion <cmd>` as the machine's administrator
// types it: in an Administrator terminal on Windows, with `sudo -H` elsewhere.
func adminCommandFor(windows bool, cmd string) string {
	if windows {
		return "privatae-bastion " + cmd + "   (from an Administrator terminal)"
	}
	return "sudo -H privatae-bastion " + cmd
}

// askConn is one connection of the lane as the asking side holds it: a unix
// socket (net.Conn), or the Windows pipe client (asklane_windows.go).
type askConn interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	Close() error
	SetDeadline(t time.Time) error
}

const (
	// askPipeName is the Windows service's ask pipe, the counterpart of
	// ask.sock: any account on the machine may connect and ask; who it is
	// comes from the pipe client's token.
	askPipeName = `\\.\pipe\privatae-bastion-ask`

	// askPipeSDDL: SYSTEM and Administrators full control; Authenticated
	// Users (AU) read, write and synchronize, as any local account may
	// connect to ask.sock. Not FILE_CREATE_PIPE_INSTANCE (FILE_APPEND_DATA,
	// 0x4, on a pipe): 0x12019b is the approvals pipe's mask for the same
	// reason (approvalpipe.go), so no client can stand up its own end of this
	// name. P protects the DACL from inheritance.
	askPipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)"
)
