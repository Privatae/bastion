//go:build windows

package main

// The Windows half of approvalpipe.go: the pipe itself, who is on the other
// end of it, and the tray's way in.
//
// OVERLAPPED I/O, ALWAYS. Every connect, read and write waits on an event with
// a timeout and is cancelled when the time is up (CancelIoEx), so a client that
// connects and says nothing, or a service that hangs, holds nothing for longer
// than pipeIOTimeout. The OVERLAPPED structure lives in a heap object
// (pipeConn) for as long as the I/O on it can be pending: the kernel writes to
// it after the call returns, and a goroutine stack can move.
//
// NO GAP IN THE NAME. A pipe name exists only while one of its instances is
// open. Between the last instance closing and the next being created, any
// process could create the name and receive the tray's next code. So the
// next instance is always created BEFORE the one it replaces is handed to its
// handler or, after a failed connect, closed (pipeAcceptLoop, approvalpipe.go,
// where the suite checks it), and any instance created while none of ours is open carries
// FILE_FLAG_FIRST_PIPE_INSTANCE, which fails if someone else holds the name.
// The tray also checks that the pipe's server process is the PrivataeBastion
// service before it sends anything (pipeServerIsService).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pipeConn is one end of one pipe instance with its own OVERLAPPED, event and
// read buffer, all in this heap object: the kernel fills the buffer and the
// OVERLAPPED after the call that started the read has returned.
type pipeConn struct {
	h   windows.Handle
	ev  windows.Handle
	ov  windows.Overlapped
	buf [4096]byte
}

func newPipeConn(h windows.Handle) (*pipeConn, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	c := &pipeConn{h: h, ev: ev}
	c.ov.HEvent = ev
	return c, nil
}

func (c *pipeConn) close() {
	_ = windows.CloseHandle(c.h)
	_ = windows.CloseHandle(c.ev)
}

var errPipeTimeout = errors.New("timed out")

// wait completes an overlapped call that was started on c. stop, when not 0,
// is a second event that cancels the wait.
func (c *pipeConn) wait(callErr error, timeout time.Duration, stop windows.Handle) (uint32, error) {
	var n uint32
	switch {
	case callErr == nil:
	case errors.Is(callErr, windows.ERROR_IO_PENDING):
		ms := uint32(windows.INFINITE)
		if timeout > 0 {
			ms = uint32(timeout / time.Millisecond)
		}
		handles := []windows.Handle{c.ev}
		if stop != 0 {
			handles = append(handles, stop)
		}
		r, err := windows.WaitForMultipleObjects(handles, false, ms)
		if err != nil || r != windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(c.h, &c.ov)
			_ = windows.GetOverlappedResult(c.h, &c.ov, &n, true)
			if err != nil {
				return 0, err
			}
			if r == uint32(windows.WAIT_TIMEOUT) {
				return 0, errPipeTimeout
			}
			return 0, errPipeStopped
		}
	default:
		return 0, callErr
	}
	if err := windows.GetOverlappedResult(c.h, &c.ov, &n, false); err != nil {
		return n, err
	}
	return n, nil
}

// read reads into c.buf and returns how much arrived.
func (c *pipeConn) read(timeout time.Duration) (int, error) {
	_ = windows.ResetEvent(c.ev)
	var done uint32
	err := windows.ReadFile(c.h, c.buf[:], &done, &c.ov)
	n, err := c.wait(err, timeout, 0)
	return int(n), err
}

func (c *pipeConn) write(b []byte, timeout time.Duration) error {
	for len(b) > 0 {
		_ = windows.ResetEvent(c.ev)
		var done uint32
		err := windows.WriteFile(c.h, b, &done, &c.ov)
		n, err := c.wait(err, timeout, 0)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("short write")
		}
		b = b[n:]
	}
	return nil
}

// readLine reads up to one newline, within max bytes and timeout in all.
func (c *pipeConn) readLine(max int, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var out []byte
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, errPipeTimeout
		}
		n, err := c.read(left)
		out = append(out, c.buf[:n]...)
		if i := bytes.IndexByte(out, '\n'); i >= 0 {
			return out[:i], nil
		}
		if len(out) > max {
			return nil, errors.New("message too large")
		}
		if err != nil {
			if errors.Is(err, windows.ERROR_MORE_DATA) {
				continue
			}
			if errors.Is(err, windows.ERROR_BROKEN_PIPE) && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
	}
}

// ── the server, in the service ──────────────────────────────────────────────

// approvalPipeServer tracks how many of our instances are open, so an instance
// created while none is open asks for the name to be ours alone.
type approvalPipeServer struct {
	mu   sync.Mutex
	open int
	sa   *windows.SecurityAttributes
	name *uint16
	// stopEv is set when the service stops; it ends a connect that is waiting.
	stopEv windows.Handle
}

// connect waits for a client on c (pipeInstances).
func (s *approvalPipeServer) connect(c *pipeConn) error {
	_ = windows.ResetEvent(c.ev)
	cerr := windows.ConnectNamedPipe(c.h, &c.ov)
	if errors.Is(cerr, windows.ERROR_PIPE_CONNECTED) {
		// A client that connected between the create and this call is
		// already connected; anything else waits.
		return nil
	}
	_, err := c.wait(cerr, 0, s.stopEv)
	return err
}

func (s *approvalPipeServer) create() (*pipeConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if s.open == 0 {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	h, err := windows.CreateNamedPipe(s.name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, s.sa)
	if err != nil {
		if s.open == 0 {
			return nil, fmt.Errorf("cannot create %s; if another program holds that name the tray stays off: %w", approvalPipeName, err)
		}
		return nil, err
	}
	c, err := newPipeConn(h)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	s.open++
	return c, nil
}

func (s *approvalPipeServer) release(c *pipeConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.close()
	s.open--
}

// startApprovalPipe serves the pipe until stop is closed. A failure, including
// the name being held by another process when the service starts, is said in
// the service's log, leaves every other lane as it was, and is retried with
// backoff (pipeServeRetrying). Each attempt's first instance carries
// FILE_FLAG_FIRST_PIPE_INSTANCE, so the service never serves under a name some
// other process created.
func startApprovalPipe(stop <-chan struct{}) {
	wait := func(d time.Duration) bool {
		select {
		case <-stop:
			return false
		case <-time.After(d):
			return true
		}
	}
	go pipeServeRetrying(func(ready func()) error { return serveApprovalPipe(stop, ready) }, wait,
		func(f string, a ...any) { fmt.Printf(f, a...) })
}

func serveApprovalPipe(stop <-chan struct{}, ready func()) error {
	sd, err := windows.SecurityDescriptorFromString(approvalPipeSDDL)
	if err != nil {
		return fmt.Errorf("cannot build the pipe's permissions: %w", err)
	}
	name, err := windows.UTF16PtrFromString(approvalPipeName)
	if err != nil {
		return err
	}
	stopEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	go func() {
		<-stop
		_ = windows.SetEvent(stopEv)
	}()
	s := &approvalPipeServer{
		sa:     &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd},
		name:   name,
		stopEv: stopEv,
	}
	// The loop and its no-gap rule are in approvalpipe.go, where the suite runs them.
	return pipeAcceptLoop[*pipeConn](s, stop, pipeMaxClients, time.Second,
		func(f string, a ...any) { fmt.Printf(f, a...) }, ready, servePipeConn)
}

// servePipeConn answers one request and waits, briefly, for the client to
// close: closing first would discard an answer it has not read yet.
func servePipeConn(c *pipeConn) {
	client, cerr := pipeClientOf(c.h)
	raw, err := c.readLine(pipeMaxRequest, pipeIOTimeout)
	var resp pipeResponse
	switch {
	case err != nil:
		return
	case cerr != nil:
		resp = pipeResponse{Error: "refused: " + cerr.Error()}
	default:
		req, derr := pipeDecode(raw)
		if derr != nil {
			resp = pipeResponse{Error: derr.Error()}
		} else {
			resp = pipeServe(req, client, time.Now())
		}
	}
	// A refused client is said in the service's log: it is a process on this
	// machine trying a lane that is not its own.
	if cerr != nil || pipeAccessRefusal(client) != "" {
		fmt.Printf("approvals pipe: %s (pid %d)\n", resp.Error, client.PID)
	}
	out, _ := json.Marshal(resp)
	if err := c.write(append(out, '\n'), pipeIOTimeout); err != nil {
		return
	}
	_, _ = c.read(pipeIOTimeout)
}

// pipeClientOf identifies the process on the other end: its pid from the pipe
// (GetNamedPipeClientProcessId), its user and session from that process's
// token, and the person signed in to that session from the session's own token
// (WTSQueryUserToken, which LocalSystem may call).
func pipeClientOf(h windows.Handle) (pipeClient, error) {
	var c pipeClient
	if err := windows.GetNamedPipeClientProcessId(h, &c.PID); err != nil {
		return c, fmt.Errorf("cannot tell which process connected: %w", err)
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, c.PID)
	if err != nil {
		return c, fmt.Errorf("cannot open the connecting process (pid %d): %w", c.PID, err)
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return c, fmt.Errorf("cannot read the connecting process's account (pid %d): %w", c.PID, err)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return c, fmt.Errorf("cannot read the connecting process's account (pid %d): %w", c.PID, err)
	}
	c.UserSID = u.User.Sid.String()
	// Bounded and cached (sidnames.go): a directory that does not answer
	// leaves NameTimedOut set, and pipeApprove refuses.
	pipeClientName(&c, winAccounts, pipeSIDLane)
	var sess, n uint32
	if err := windows.GetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sess)), uint32(unsafe.Sizeof(sess)), &n); err != nil {
		return c, fmt.Errorf("cannot read the connecting process's session (pid %d): %w", c.PID, err)
	}
	c.SessionID = sess
	var st windows.Token
	if windows.WTSQueryUserToken(sess, &st) == nil {
		if su, err := st.GetTokenUser(); err == nil {
			c.SessionUserSID = su.User.Sid.String()
		}
		st.Close()
	}
	c.SessionActive = wtsSessionActive(sess)
	return c, nil
}

// wtsSessionActive reports whether a session is the one in front of a screen
// (WTSActive), rather than disconnected or idle.
func wtsSessionActive(id uint32) bool {
	var sessions *windows.WTS_SESSION_INFO
	var n uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &sessions, &n) != nil {
		return false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	for _, s := range unsafe.Slice(sessions, n) {
		if s.SessionID == id {
			return s.State == windows.WTSActive
		}
	}
	return false
}

// ── the client, in the tray ─────────────────────────────────────────────────

// pipeCall sends one request to the service and returns its answer.
func pipeCall(req pipeRequest) (pipeResponse, error) {
	var resp pipeResponse
	c, err := dialApprovalPipe()
	if err != nil {
		return resp, err
	}
	defer c.close()
	if err := pipeServerIsService(c.h); err != nil {
		return resp, err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	if err := c.write(append(raw, '\n'), pipeIOTimeout); err != nil {
		return resp, fmt.Errorf("the bastion service did not take the request: %w", err)
	}
	line, err := c.readLine(1<<20, 2*pipeIOTimeout)
	if err != nil {
		return resp, fmt.Errorf("the bastion service did not answer: %w", err)
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return resp, errors.New("the bastion service's answer could not be read")
	}
	return resp, nil
}

// dialApprovalPipe opens the pipe with exactly the rights its ACL grants
// (read, write data, synchronize; never FILE_APPEND_DATA, which GENERIC_WRITE
// would ask for), and lets the server identify this process but not act as it.
func dialApprovalPipe() (*pipeConn, error) {
	name, err := windows.UTF16PtrFromString(approvalPipeName)
	if err != nil {
		return nil, err
	}
	for i := 0; ; i++ {
		h, err := windows.CreateFile(name, windows.FILE_GENERIC_READ|windows.FILE_WRITE_DATA, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			c, err := newPipeConn(h)
			if err != nil {
				_ = windows.CloseHandle(h)
				return nil, err
			}
			return c, nil
		}
		if errors.Is(err, windows.ERROR_PIPE_BUSY) && i < 10 {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, errors.New("the bastion service is not running, or is older than this tray")
		}
		return nil, fmt.Errorf("cannot reach the bastion service: %w", err)
	}
}

// pipeServerIsService refuses a pipe whose server is not the PrivataeBastion
// service's own process, so a program that got the name first is never sent
// a code.
func pipeServerIsService(h windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil {
		return fmt.Errorf("cannot tell which process serves the approvals pipe: %w", err)
	}
	svcPID, err := bastionServicePID()
	if err != nil {
		return err
	}
	if svcPID == 0 || pid != svcPID {
		return fmt.Errorf("the approvals pipe is served by process %d, not by the %s service; nothing was sent", pid, winServiceName)
	}
	return nil
}

// bastionServicePID is the service's process id from the Service Control
// Manager, asked with the query right every signed-in user holds. 0 when it is
// not running.
func bastionServicePID() (uint32, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, fmt.Errorf("cannot ask the Service Control Manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(winServiceName)
	if err != nil {
		return 0, err
	}
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, fmt.Errorf("cannot query the %s service: %w", winServiceName, err)
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return 0, err
	}
	return st.ProcessId, nil
}
