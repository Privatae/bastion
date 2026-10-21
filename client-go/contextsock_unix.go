//go:build !windows

package main

// The kernel's answer to "who is on the other end of this socket", on unix.
//
// linux  SO_PEERCRED, filled by the kernel at connect() time. It cannot be set
//        by the caller and it is not re-read later, so it is the identity of
//        the process that connected even if that process is gone by now.
// darwin/bsd  getpeereid, the same guarantee through a different call.
//
// Neither reads anything the client sent. That is the whole reason this file
// exists rather than a username field in the request.

import (
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// contextSockListen binds the socket and sets its mode.
//
// 0666 ON THE SOCKET, DELIBERATELY, and it is the one line here worth arguing
// with. The daemon's config dir is 0700, so a socket inside it is unreachable
// by anyone else — which would make this whole path work only for the user who
// already did not need it. The socket is therefore created in a directory of
// its own at 0711: traversable by anyone, listable by nobody, so a local user
// can connect to a path they cannot enumerate.
//
// Connecting is not authority. Every connection is identified by the kernel
// and the ask still lands inert for a person on the host to approve, so what an
// unprivileged local user gains by reaching this socket is the ability to ASK
// in their own name — which is precisely the feature.
func contextSockListen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	// 0755: traversable AND listable by everyone, because the path is fixed and
	// public anyway — hiding it bought nothing and the 0711 version could not be
	// traversed at all from inside a 0700 config dir, which is how the first
	// version of this shipped dead.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	sock := path
	_ = os.Remove(sock) // a stale socket from a previous run refuses to bind
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// contextPeerUser reads the connecting process's user from the kernel.
func contextPeerUser(c net.Conn) (string, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return "", errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return "", err
	}
	var uid uint32
	var serr error
	err = raw.Control(func(fd uintptr) {
		uid, serr = contextPeerUID(fd)
	})
	if err != nil {
		return "", err
	}
	if serr != nil {
		return "", serr
	}
	name := ""
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = u.Username
	}
	return contextSockFmtUser(uid, name), nil
}

// contextSockDir is machine-wide and root-owned. See contextSockPath.
const contextSockDir = "/var/run/privatae-bastion"

// contextSockDialable refuses a socket that is not root's.
//
// The daemon that can forward a draft runs as root on the machines where this
// path matters. A socket at this address owned by anyone else is not that
// daemon, and handing it a folder path would be handing it to whoever made it.
func contextSockDialable(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return "" // absent: not an impostor, just not there — caller falls back
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	if st.Uid != 0 {
		return "the bastion's local socket at " + p + " is owned by uid " +
			strconv.FormatUint(uint64(st.Uid), 10) + ", not by root. That is not this " +
			"machine's bastion, so nothing was sent to it."
	}
	return ""
}
