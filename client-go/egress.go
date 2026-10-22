package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

const egressDialTimeout = 20 * time.Second

// egressDialer dials the real destination over the bastion's OWN OS network (the user's
// internet) — never the tunnel. Injectable so tests can supply a loopback dialer.
type egressDialer func(ctx context.Context, network, addr string) (net.Conn, error)

// handleEgressConn serves ONE egress request off `client` (a worker connection the bastion
// opened to the host — reverse relay): read the request, dial the destination out the
// USER's own internet via dialOut, and relay. Supports HTTP CONNECT (HTTPS, the common
// case) and absolute-form plain HTTP. It NEVER logs destinations.
// self is the pairing this lane belongs to. On an anchored box a member's
// egress is refused (403, before any dial) unless its pairing grant carries
// the "egress" cap: this lane makes requests leave THIS machine's connection
// under its address, and nothing in the mgmt op table gates it.
func handleEgressConn(client net.Conn, dialOut egressDialer, self string) {
	defer client.Close()
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

	// Buffer the head so a plain-HTTP request can be replayed verbatim; capture Host.
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
		if len(h) >= 5 && strings.EqualFold(h[:5], "host:") {
			hostHdr = strings.TrimSpace(h[5:])
		}
	}

	if why := capsAllow(self, "egress"); why != "" {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Privatae-Refused: " + why + "\r\n\r\n"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), egressDialTimeout)
	defer cancel()

	if strings.EqualFold(method, "CONNECT") {
		dialAddrs, why := egressVettedAddrs(ctx, ensurePort(target, "443"))
		if why != "" {
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Privatae-Refused: " + why + "\r\n\r\n"))
			return
		}
		upstream, err := dialEach(ctx, dialOut, dialAddrs)
		if err != nil {
			_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			_ = upstream.Close()
			return
		}
		splice(br, client, upstream)
		return
	}

	// Plain HTTP, absolute-form: "GET http://host/path HTTP/1.1".
	host := hostHdr
	if i := strings.Index(target, "://"); i >= 0 {
		rest := target[i+3:]
		if s := strings.IndexByte(rest, '/'); s >= 0 {
			host = rest[:s]
		} else {
			host = rest
		}
	}
	if host == "" {
		return
	}
	dialAddrs, why := egressVettedAddrs(ctx, ensurePort(host, "80"))
	if why != "" {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Privatae-Refused: " + why + "\r\n\r\n"))
		return
	}
	upstream, err := dialEach(ctx, dialOut, dialAddrs)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if _, err := upstream.Write([]byte(head.String())); err != nil {
		_ = upstream.Close()
		return
	}
	splice(br, client, upstream)
}

// ensurePort returns host:port, adding defPort when target has no explicit port.
func ensurePort(target, defPort string) string {
	target = strings.TrimSpace(target)
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		target = target[1 : len(target)-1]
	}
	return net.JoinHostPort(target, defPort)
}

// splice pipes both directions until each side EOFs, half-closing the write end so the
// peer sees the close, then tears both down. clientReader carries any bytes already
// buffered off `client`.
func splice(clientReader io.Reader, client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst net.Conn, src io.Reader) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go cp(upstream, clientReader)
	go cp(client, upstream)
	<-done
	<-done
	_ = upstream.Close()
	_ = client.Close()
}

// egressInternalRefusal is the refusal egressVettedAddrs gives, or "".
//
// The lane is USE of the machine's connection (writes.go), and that holds only
// while it cannot be turned inward: `POST http://127.0.0.1:11434/api/pull`
// down this lane would reach ollama around the forward's filter and around the
// `models` switch, and this machine's other services around theirs. So on
// every box the lane refuses this machine: `localhost` names, loopback and
// unspecified addresses, link-local ones (the cloud metadata address
// included), and any address the machine takes as its own (ownaddr.go), such
// as a public one on its NIC or a range a `local` route delivers here.
//
// What differs is the network around it. On an ANCHORED box the lane reaches
// the public internet and nothing else: private, CGNAT and reserved addresses
// (the LAN, the mesh) are refused too. On a LOCAL box the LAN stays reachable:
// the host there is the one the person paired, and their own network is
// theirs to reach.
//
// Resolution failures refuse too: a name this box cannot resolve is not one
// it can vouch for.
//
// THE ADDRESS THE CHECK VETTED IS THE ADDRESS DIALLED. egressVettedAddrs
// returns "ip:port" forms, and the dial takes those, never the name: a name
// resolved once for the check and again for the dial is a rebinding hole (a
// public answer for the check, 127.0.0.1 for the dial).
func egressInternalRefusal(ctx context.Context, hostport string) string {
	_, why := egressVettedAddrs(ctx, hostport)
	return why
}

// egressResolve is how the lane resolves a name. A seam so a test can answer
// for a name without DNS.
var egressResolve = net.DefaultResolver.LookupIPAddr

// egressVettedAddr: (the first address to dial, "") or ("", the refusal).
func egressVettedAddr(ctx context.Context, hostport string) (string, string) {
	all, why := egressVettedAddrs(ctx, hostport)
	if why != "" {
		return "", why
	}
	return all[0], ""
}

// egressVettedAddrs: every address the name resolved to, as "ip:port" in the
// resolver's order, or (nil, the refusal). Any one refused address refuses the
// name. The dial tries them in order (dialEach), so a dual-stack site still
// answers from a machine whose IPv6 goes nowhere, as it did when the OS dialled
// the name.
func egressVettedAddrs(ctx context.Context, hostport string) ([]string, string) {
	anchored := currentAnchor() != nil
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, ""
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		if anchored {
			return nil, "refused: egress to " + host + " — this lane reaches the public internet only on an anchored machine"
		}
		return nil, "refused: egress to " + host + " — this lane never reaches this machine"
	}
	var addrs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		addrs = []net.IP{ip}
	} else {
		resolved, err := egressResolve(ctx, host)
		if err != nil || len(resolved) == 0 {
			return nil, "refused: egress to " + host + " — could not resolve it on this machine"
		}
		for _, r := range resolved {
			addrs = append(addrs, r.IP)
		}
	}
	for _, ip := range addrs {
		if anchored && internalIP(ip) {
			return nil, "refused: egress to " + host + " (" + ip.String() + ") — this lane reaches the public " +
				"internet only on an anchored machine, never this machine, its network or the mesh"
		}
		if !anchored && thisMachineOrLinkIP(ip) {
			return nil, "refused: egress to " + host + " (" + ip.String() + ") — this lane never reaches " +
				"this machine or a link-local address"
		}
	}
	// This machine is not only loopback: a public address on its NIC, a LAN
	// address on it, or a range the kernel delivers locally through a `local`
	// route, reaches its 0.0.0.0 services too, and a container's or VM's
	// address on a network made here reaches a service on it (ownaddr.go). This
	// lane has no allow list, so the refusal has no exception on either kind of
	// box.
	own, err := ownDestination(addrs)
	if err != nil {
		return nil, "refused: egress to " + host + " — this machine could not tell whether that is itself, so it cannot be vetted"
	}
	if own {
		if anchored {
			return nil, "refused: egress to " + host + " — that is this machine; this lane reaches the public " +
				"internet only on an anchored machine, never this machine, its network or the mesh"
		}
		return nil, "refused: egress to " + host + " — that is this machine; this lane never reaches this machine"
	}
	out := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		out = append(out, net.JoinHostPort(ip.String(), port))
	}
	return out, ""
}

// dialEachStagger is how long an attempt has to answer before the next
// address is tried beside it: the connection attempt delay of Happy Eyeballs
// (RFC 8305 recommends 250 ms), which the OS dialler used when it was given
// the name.
var dialEachStagger = 300 * time.Millisecond

// dialEach dials vetted addresses, in order, and returns the first that
// answers. The next address starts as soon as an attempt fails, or when the
// attempts in flight have not answered within dialEachStagger, so an address
// whose packets go nowhere costs a fraction of a second, not the dial budget.
// Only these addresses are ever dialled. The attempts still in flight when one
// answers are cancelled, and any that connects anyway is closed.
func dialEach(ctx context.Context, dialOut egressDialer, addrs []string) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no address")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type attempt struct {
		c   net.Conn
		err error
	}
	results := make(chan attempt, len(addrs))
	next, inFlight := 0, 0
	start := func() {
		a := addrs[next]
		next++
		inFlight++
		go func() {
			c, err := dialOut(ctx, "tcp", a)
			results <- attempt{c, err}
		}()
	}
	stagger := time.NewTimer(dialEachStagger)
	defer stagger.Stop()
	start()
	var err error
	for inFlight > 0 {
		var tick <-chan time.Time
		if next < len(addrs) {
			tick = stagger.C
		}
		select {
		case r := <-results:
			inFlight--
			if r.err == nil {
				go func(n int) {
					for ; n > 0; n-- {
						if late := <-results; late.c != nil {
							_ = late.c.Close()
						}
					}
				}(inFlight)
				return r.c, nil
			}
			err = r.err
			if next < len(addrs) {
				start()
				stagger.Reset(dialEachStagger)
			}
		case <-tick:
			start()
			stagger.Reset(dialEachStagger)
		}
	}
	return nil, err
}

// ipClass is what an address reaches, read by every lane that dials for
// someone else. The address rules live here once: internalIP is "anything but
// public", and the local egress lane refuses the classes that are this machine
// or its link.
type ipClass int

const (
	ipPublic      ipClass = iota // the public internet
	ipThisMachine                // loopback, unspecified, 0.0.0.0/8
	ipLink                       // link-local unicast and multicast (the cloud metadata address)
	ipNetwork                    // private (RFC 1918, ULA), CGNAT, multicast, benchmarking, reserved
	ipUnreadable                 // a translated form whose IPv4 address this box cannot read
	ipObsolete                   // IPv4-compatible ::/96, IPv4-translated ::ffff:0:0/96, site-local fec0::/10
)

func classifyIP(ip net.IP) ipClass {
	switch {
	case ip.IsLoopback(), ip.IsUnspecified():
		return ipThisMachine
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return ipLink
	case ip.IsPrivate(), ip.IsMulticast():
		return ipNetwork
	}
	if v4 := ip.To4(); v4 != nil {
		// 0.0.0.0/8 is "this host on this network".
		if v4[0] == 0 {
			return ipThisMachine
		}
		// 100.64.0.0/10 (carrier NAT) is as internal as 10/8 for this purpose;
		// 198.18.0.0/15 (benchmarking) and 240.0.0.0/4 (reserved) are never a
		// public host.
		if (v4[0] == 100 && v4[1]&0xc0 == 64) || (v4[0] == 198 && v4[1]&0xfe == 18) || v4[0] >= 240 {
			return ipNetwork
		}
		return ipPublic
	}
	// IPv6 forms that carry an IPv4 address inside them reach that address, so
	// they are judged by it: NAT64 64:ff9b::/96 (the last four bytes — how an
	// IPv6-only network with DNS64 reaches every IPv4 site, so refusing the
	// prefix outright would break those networks) and 6to4 2002::/16 (bytes 2-5).
	if len(ip) == net.IPv6len {
		if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b {
			if ip[4]|ip[5]|ip[6]|ip[7]|ip[8]|ip[9]|ip[10]|ip[11] == 0 {
				return classifyIP(net.IPv4(ip[12], ip[13], ip[14], ip[15]))
			}
			// The rest of 64:ff9b::/32 (local-use translators, RFC 8215) maps
			// to IPv4 in ways this box cannot read.
			return ipUnreadable
		}
		if ip[0] == 0x20 && ip[1] == 0x02 {
			return classifyIP(net.IPv4(ip[2], ip[3], ip[4], ip[5]))
		}
		// Deprecated forms that are no destination of their own: IPv4-compatible
		// ::a.b.c.d (RFC 4291 2.5.5.1), IPv4-translated ::ffff:0:a.b.c.d (SIIT)
		// and site-local fec0::/10 (RFC 3879). Where each is delivered depends on
		// the platform, so no lane dials them. (:: and ::1 are matched above.)
		if isZeros(ip[0:12]) ||
			(isZeros(ip[0:8]) && ip[8] == 0xff && ip[9] == 0xff && ip[10] == 0 && ip[11] == 0) ||
			(ip[0] == 0xfe && ip[1]&0xc0 == 0xc0) {
			return ipObsolete
		}
	}
	return ipPublic
}

func isZeros(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// internalIP: loopback, link-local, private (RFC 1918, ULA), CGNAT,
// unspecified, multicast and reserved, also inside a NAT64 or 6to4 address,
// and the deprecated IPv4-compatible, IPv4-translated and site-local forms.
func internalIP(ip net.IP) bool {
	return classifyIP(ip) != ipPublic
}

// thisMachineOrLinkIP: what the local egress lane refuses by address class.
// An address it cannot read is refused, since it could be either, and so is a
// deprecated form, which is no destination of its own.
func thisMachineOrLinkIP(ip net.IP) bool {
	switch classifyIP(ip) {
	case ipThisMachine, ipLink, ipUnreadable, ipObsolete:
		return true
	}
	return false
}
