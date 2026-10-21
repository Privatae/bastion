package main

// coder_forward.go — how the Host reaches a coder run's control plane.
//
// One tunnel port per run (18200-18299), listened on the OWNING pairing's
// netstack only, spliced to the run's control.sock. Every accepted connection
// is checked again: the pairing still holds mode:coder, the run is still this
// pairing's and not past its deadline, and the connection comes from the
// pairing's own host tunnel address. The splice pins the socket's inode and
// checks the far end is the engine's uid (spliceUnix, service.go), because the
// container owns the directory the socket lives in.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// coderForwardRefusal is the per-connection wall: "" to splice, else why not.
func coderForwardRefusal(self string, rec *coderRecord, remote, hostTunnel netip.Addr, now time.Time) string {
	if why := capsAllow(self, coderGateOp); why != "" {
		return why
	}
	if rec == nil {
		return "no such run"
	}
	if rec.Owner != self {
		return "the run belongs to another host"
	}
	if dl, err := time.Parse(time.RFC3339, rec.Deadline); err != nil || now.After(dl) {
		return "the run is past its deadline"
	}
	if !hostTunnel.IsValid() || remote.Unmap() != hostTunnel.Unmap() {
		return "the connection does not come from this host's tunnel address"
	}
	return ""
}

// coderRemoteAddr is the peer address of an accepted connection.
func coderRemoteAddr(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(ta.IP); ok {
			return a.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// coderListenFunc opens a listener on the pairing's side of the tunnel.
type coderListenFunc func(port int) (net.Listener, error)

// serveCoderForwards listens on the pairing's tunnel stack, one port per run
// this pairing owns (the fifth gated forward; claims_static_test.go).
func serveCoderForwards(ctx context.Context, self, hostTunnelIP string, tnet *netstack.Net, gwIP netip.Addr) {
	serveCoderForwardsOn(ctx, self, hostTunnelIP, func(port int) (net.Listener, error) {
		return tnet.ListenTCP(&net.TCPAddr{IP: gwIP.AsSlice(), Port: port})
	})
}

// serveCoderForwardsOn keeps one listener per run this pairing owns, re-read
// from the records every serviceForwardPoll (a run brought up by a harness job
// becomes reachable within that interval; one taken down disappears).
func serveCoderForwardsOn(ctx context.Context, self, hostTunnelIP string, listen coderListenFunc) {
	hostTunnel, _ := netip.ParseAddr(hostTunnelIP)
	type fwd struct {
		port int
		ln   net.Listener
	}
	var mu sync.Mutex
	live := map[string]*fwd{}
	defer func() {
		mu.Lock()
		for id, f := range live {
			_ = f.ln.Close()
			delete(live, id)
		}
		mu.Unlock()
	}()
	var lastWhy string
	reconcile := func() {
		want := map[string]int{}
		for _, r := range loadCoderRecords() {
			if r.Owner == self && r.TunnelPort >= coderPortBase && r.TunnelPort <= coderPortMax {
				want[r.RunID] = r.TunnelPort
			}
		}
		mu.Lock()
		defer mu.Unlock()
		for id, f := range live {
			if p, ok := want[id]; !ok || p != f.port {
				_ = f.ln.Close()
				delete(live, id)
			}
		}
		for id, p := range want {
			if _, ok := live[id]; ok {
				continue
			}
			ln, err := listen(p)
			if err != nil {
				continue // retried next poll
			}
			live[id] = &fwd{port: p, ln: ln}
			go func(runID string, ln net.Listener) {
				for {
					in, err := ln.Accept()
					if err != nil {
						return
					}
					rec, _ := loadCoderRecord(runID)
					if why := coderForwardRefusal(self, rec, coderRemoteAddr(in), hostTunnel, coderNow()); why != "" {
						_ = in.Close()
						mu.Lock()
						if why != lastWhy {
							fmt.Printf("[%s] coder forward: %s\n", self, why)
							lastWhy = why
						}
						mu.Unlock()
						continue
					}
					R, err := coderRunDir(runID)
					if err != nil {
						_ = in.Close()
						continue
					}
					go spliceUnix(in, filepath.Join(R, "ctl", coderControlSock), rec.UID)
				}
			}(id, ln)
		}
	}
	reconcile()
	t := time.NewTicker(serviceForwardPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reconcile()
		}
	}
}
