//go:build windows

package main

// Windows has no unix sockets in the sense this file needs, and Go's net
// package will not listen on a named pipe. Implementing the pipe half means
// CreateNamedPipe/ConnectNamedPipe by hand plus a net.Listener wrapper around
// the handles — real work with real failure modes, and it is NOT done here.
//
// WHAT THAT LEAVES OUT: the socket exists so a person who is NOT the machine's
// administrator can ask for context on a box whose daemon runs as somebody
// else. An ordinary Windows install runs as a logon task under the person's own
// account (deploy/install.ps1), so their context surface and their daemon are
// the same user and the direct path in contextForwardDraft works. A networked
// install runs as a Windows service under LocalSystem (sysservice_windows.go),
// and there it does NOT: the signed-in person's `context` cannot reach the
// service until this pipe exists. Until then, on such a machine, folders are
// added from an Administrator terminal.
//
// The pieces are confirmed available cgo-free in x/sys/windows v0.46.0 —
// CreateNamedPipe, ConnectNamedPipe, GetNamedPipeClientProcessId, and the
// token calls for turning that pid into a SID — so this is a build, not a
// research question, whenever a multi-user Windows bastion is real.

import (
	"net"
	"os"
)

// Unused on windows; named so contextSockPath compiles on every platform.
const contextSockDir = `C:\ProgramData\privatae-bastion`

func contextSockDialable(string) string { return "" }

func contextSockListen(path string) (net.Listener, error) {
	return nil, contextSockUnsupported
}

func contextPeerUser(c net.Conn) (string, error) {
	return "", contextSockUnsupported
}

var _ = os.Remove
