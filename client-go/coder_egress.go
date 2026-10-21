package main

// coder_egress.go — a coder run's ONLY way out: egress.sock.
//
// The container runs with --network none (service.go measured why: the
// default bridge reaches the machine's LAN address and its own services, an
// --internal network still reaches the machine through its gateway, none
// reaches nothing). Its sidecar points HTTP(S)_PROXY at a loopback forwarder
// that carries each connection to this unix socket, and this proxy dials out
// over the machine's own connection.
//
// THE VETTING APPLIES ALWAYS, anchored box or not. The egress lane
// (egress.go) only vets on an anchored box, because on a local box the host
// using it is the person's own. A coding agent is not the person: it runs
// whatever a prompt or a repository talks it into, so this proxy reaches the
// public internet and nothing else — not this machine, not its LAN, not the
// cloud metadata address, nor any address this machine takes as its own (a
// public one on a NIC, or a range a `local` route delivers here; ownaddr.go)
// — unless the owner named the host in allow_lan.
// Every address a name resolves to is checked, and the address checked is the
// address dialled (egress.go's rebinding rule).

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The seams: how a name is resolved and how the vetted address is dialled.
var (
	coderResolve = func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, a.IP)
		}
		return out, nil
	}
	coderDialOut egressDialer = (&net.Dialer{Timeout: egressDialTimeout}).DialContext
)

// coderInternalIP is internalIP (egress.go) plus the IPv6 forms that carry an
// IPv4 address and are not covered there: IPv4-compatible ::a.b.c.d (::/96),
// IPv4-translated ::ffff:0:a.b.c.d, and the deprecated site-local fec0::/10.
// IPv4-mapped ::ffff:a.b.c.d is covered by internalIP through To4.
func coderInternalIP(ip net.IP) bool {
	if internalIP(ip) {
		return true
	}
	if ip.To4() != nil || len(ip) != net.IPv6len {
		return false
	}
	zero := true
	for _, b := range ip[:12] {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return true // ::/96 — never a public host
	}
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0 && ip[5] == 0 &&
		ip[6] == 0 && ip[7] == 0 && ip[8] == 0xff && ip[9] == 0xff && ip[10] == 0 && ip[11] == 0 {
		return true // ::ffff:0:0/96
	}
	if ip[0] == 0xfe && ip[1]&0xc0 == 0xc0 {
		return true // fec0::/10
	}
	return false
}

// coderLANAllowed: the owner's allow_lan names this requested host (an entry
// with a port must match host:port, one without matches any port).
func coderLANAllowed(allowLAN []string, host, port string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	for _, e := range allowLAN {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		eh, ep, err := net.SplitHostPort(e)
		if err != nil {
			eh, ep = strings.Trim(e, "[]"), ""
		}
		if eh == h && (ep == "" || ep == port) {
			return true
		}
	}
	return false
}

// coderVettedAddr: ("ip:port", "") to dial first, or ("", the refusal).
func coderVettedAddr(ctx context.Context, hostport string, allowLAN []string) (string, string) {
	all, why := coderVettedAddrs(ctx, hostport, allowLAN)
	if why != "" {
		return "", why
	}
	return all[0], ""
}

// coderVettedAddrs: every "ip:port" the name resolved to, IPv4 first, or the
// refusal. Refuses localhost names, names it cannot resolve, and any name
// with even ONE internal address or ONE address the kernel delivers to this
// machine. Only these addresses are ever dialled, never the name again;
// trying each in turn lets a run reach a dual-stack
// site from a machine whose IPv6 goes nowhere.
func coderVettedAddrs(ctx context.Context, hostport string, allowLAN []string) ([]string, string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, "refused: not a host:port"
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, "refused: bad port"
	}
	if host == "" {
		return nil, "refused: no host"
	}
	lh := strings.ToLower(strings.TrimSuffix(host, "."))
	lanOK := coderLANAllowed(allowLAN, host, port)
	if !lanOK && (lh == "localhost" || strings.HasSuffix(lh, ".localhost")) {
		return nil, "refused: this machine is not reachable from a coder run"
	}
	var addrs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		addrs = []net.IP{ip}
	} else {
		resolved, err := coderResolve(ctx, host)
		if err != nil || len(resolved) == 0 {
			return nil, "refused: the name does not resolve on this machine"
		}
		addrs = resolved
	}
	if !lanOK {
		for _, ip := range addrs {
			if coderInternalIP(ip) {
				return nil, "refused: a coder run reaches the public internet only, never this machine, its network or a private range"
			}
		}
		// The classes above miss this machine when it holds a PUBLIC address
		// on one of its interfaces (a VPS, a server with its own IP), or when
		// the kernel delivers a whole range locally through a `local` route
		// (AnyIP): a service listening on 0.0.0.0 answers there. ownDestination
		// (ownaddr.go) asks both.
		own, err := ownDestination(addrs)
		if err != nil {
			return nil, "refused: this machine could not tell whether the destination is itself, so it cannot be vetted"
		}
		if own {
			return nil, "refused: a coder run reaches the public internet only, never this machine, its network or a private range"
		}
	}
	var v4, v6 []string
	for _, ip := range addrs {
		if ip.To4() != nil {
			v4 = append(v4, net.JoinHostPort(ip.String(), port))
		} else {
			v6 = append(v6, net.JoinHostPort(ip.String(), port))
		}
	}
	return append(v4, v6...), ""
}

func coderRefuse(c net.Conn, why string) {
	_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\nX-Privatae-Refused: " +
		strings.NewReplacer("\r", " ", "\n", " ").Replace(why) + "\r\n\r\n"))
}

// handleCoderEgressConn serves one connection from a run: HTTP CONNECT or an
// absolute-form plain HTTP request, the same parsing as handleEgressConn.
// Destinations are never logged; refusals are counted on the run.
func handleCoderEgressConn(client net.Conn, allowLAN []string, refused *int64) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return
	}
	method, target := parts[0], parts[1]
	var head strings.Builder
	head.WriteString(line)
	hostHdr := ""
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(h)
		if h == "\r\n" || h == "\n" {
			break
		}
		if head.Len() > 64<<10 {
			return
		}
		if len(h) >= 5 && strings.EqualFold(h[:5], "host:") {
			hostHdr = strings.TrimSpace(h[5:])
		}
	}
	_ = client.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), egressDialTimeout)
	defer cancel()

	connect := strings.EqualFold(method, "CONNECT")
	hp := ""
	if connect {
		hp = ensurePort(target, "443")
	} else {
		host := hostHdr
		if i := strings.Index(target, "://"); i >= 0 {
			rest := target[i+3:]
			if s := strings.IndexAny(rest, "/?#"); s >= 0 {
				host = rest[:s]
			} else {
				host = rest
			}
			if at := strings.LastIndexByte(host, '@'); at >= 0 {
				host = host[at+1:]
			}
		}
		if host == "" {
			return
		}
		hp = ensurePort(host, "80")
	}
	dialAddrs, why := coderVettedAddrs(ctx, hp, allowLAN)
	if why != "" {
		atomic.AddInt64(refused, 1)
		coderRefuse(client, why)
		return
	}
	var upstream net.Conn
	err = errors.New("no address")
	for i, a := range dialAddrs {
		// Each address gets an even share of what is left of the dial budget,
		// so one that black-holes cannot use it all.
		actx, acancel := ctx, context.CancelFunc(func() {})
		if left := len(dialAddrs) - i; left > 1 {
			if dl, ok := ctx.Deadline(); ok {
				actx, acancel = context.WithTimeout(ctx, time.Until(dl)/time.Duration(left))
			}
		}
		upstream, err = coderDialOut(actx, "tcp", a)
		acancel()
		if err == nil {
			break
		}
	}
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}
	if connect {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			_ = upstream.Close()
			return
		}
	} else if _, err := upstream.Write([]byte(head.String())); err != nil {
		_ = upstream.Close()
		return
	}
	splice(br, client, upstream)
}

// The live proxies, one per run, in this daemon.
type coderEgressRun struct {
	ln      net.Listener
	refused int64
}

var (
	coderEgressMu sync.Mutex
	coderEgress   = map[string]*coderEgressRun{}
)

// coderListenEgress opens <dir>/egress.sock for one run: owned by the
// engine's uid, 0600, so only the run's own processes can connect.
func coderListenEgress(runID, dir string, uid int) error {
	coderEgressMu.Lock()
	defer coderEgressMu.Unlock()
	if old, ok := coderEgress[runID]; ok {
		_ = old.ln.Close()
		delete(coderEgress, runID)
	}
	p := filepath.Join(dir, coderEgressSock)
	_ = os.Remove(p)
	ln, err := coderListenUnix(dir, coderEgressSock)
	if err != nil {
		return err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false) // run-down removes the directory; a restart re-listens
	}
	if err := os.Chmod(p, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	if err := coderChown(p, uid, uid); err != nil {
		_ = ln.Close()
		return err
	}
	run := &coderEgressRun{ln: ln}
	coderEgress[runID] = run
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// allow_lan is read per connection: the owner's edit applies to
			// running runs at once.
			go handleCoderEgressConn(c, loadCoderConfig().AllowLAN, &run.refused)
		}
	}()
	return nil
}

// coderCloseEgress stops one run's proxy and returns how many requests it
// refused (0 when this daemon held no proxy for it).
func coderCloseEgress(runID string) int64 {
	coderEgressMu.Lock()
	defer coderEgressMu.Unlock()
	run, ok := coderEgress[runID]
	if !ok {
		return 0
	}
	_ = run.ln.Close()
	delete(coderEgress, runID)
	return atomic.LoadInt64(&run.refused)
}

// coderReconcileEgress makes the live proxies match the records: a run that
// outlived a daemon restart gets its proxy back, and a run whose record was
// removed by another process (the CLI's `coders drop`) loses it.
func coderReconcileEgress() {
	recs := loadCoderRecords()
	want := map[string]coderRecord{}
	for _, r := range recs {
		want[r.RunID] = r
	}
	coderMu.Lock()
	starting := map[string]bool{}
	for id := range coderStarting {
		starting[id] = true
	}
	coderMu.Unlock()
	coderEgressMu.Lock()
	var drop []string
	for id := range coderEgress {
		if _, ok := want[id]; !ok && !starting[id] {
			drop = append(drop, id)
		}
	}
	var add []coderRecord
	for id, r := range want {
		if _, ok := coderEgress[id]; !ok {
			add = append(add, r)
		}
	}
	coderEgressMu.Unlock()
	for _, id := range drop {
		coderCloseEgress(id)
	}
	for _, r := range add {
		if R, err := coderRunDir(r.RunID); err == nil {
			_ = coderListenEgress(r.RunID, filepath.Join(R, "egress"), r.UID)
		}
	}
}
