//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// llmListenerTrusted: the program listening on the loopback port addr names
// runs as root, as this bastion's own user, or as the machine's recorded
// owner. Found without anyone setting PRIVATAE_LLM_ADDR, a model server is
// handed the Host's prompts, and any account on the machine can listen on
// 127.0.0.1:8080 while llama.cpp is not running; a server of another account
// is not taken (the variable still names one on purpose). The kernel's own
// table says who owns each listening socket (/proc/net/tcp, tcp6).
func llmListenerTrusted(addr string) bool {
	port := portOfAddr(addr)
	if port <= 0 {
		return false
	}
	var uids []uint32
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if raw, err := os.ReadFile(f); err == nil {
			uids = append(uids, loopbackListenerUIDs(string(raw), port)...)
		}
	}
	owner, _, ownerKnown, _ := ownerAccountLoad()
	return listenersTrusted(uids, uint32(os.Getuid()), owner, ownerKnown)
}

// listenersTrusted: there is a listener, and every one is root's, self's or
// the owner's.
func listenersTrusted(uids []uint32, self, owner uint32, ownerKnown bool) bool {
	if len(uids) == 0 {
		return false
	}
	for _, u := range uids {
		if u != 0 && u != self && (!ownerKnown || u != owner) {
			return false
		}
	}
	return true
}

// loopbackListenerUIDs reads a /proc/net/tcp table: the uid of every socket
// LISTENing on port at a loopback or any-address local address.
func loopbackListenerUIDs(table string, port int) []uint32 {
	var out []uint32
	for _, line := range strings.Split(table, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[3] != "0A" {
			continue
		}
		host, p, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		if n, err := strconv.ParseUint(p, 16, 16); err != nil || int(n) != port {
			continue
		}
		switch host {
		case "0100007F", "00000000", "00000000000000000000000001000000", "00000000000000000000000000000000":
		default:
			if !strings.HasSuffix(host, "7F") || len(host) != 8 { // 127.x.y.z, little-endian
				continue
			}
		}
		if u, err := strconv.ParseUint(f[7], 10, 32); err == nil {
			out = append(out, uint32(u))
		}
	}
	return out
}
