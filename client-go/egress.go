package main

import (
	"bufio"
	"context"
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
		dialAddr, why := egressVettedAddr(ctx, ensurePort(target, "443"))
		if why != "" {
			_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Privatae-Refused: " + why + "\r\n\r\n"))
			return
		}
		upstream, err := dialOut(ctx, "tcp", dialAddr)
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
	dialAddr, why := egressVettedAddr(ctx, ensurePort(host, "80"))
	if why != "" {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Privatae-Refused: " + why + "\r\n\r\n"))
		return
	}
	upstream, err := dialOut(ctx, "tcp", dialAddr)
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

// egressInternalRefusal: on an ANCHORED box the egress lane reaches the public
// internet and nothing else. Loopback, link-local and private addresses — this
// machine's own services, the LAN it sits on, the mesh — are refused before
// any dial, whether named by address or by a name that resolves to one. The
// lane is USE of the machine's connection (writes.go), and that holds only
// while it cannot be turned inward: `POST http://127.0.0.1:11434/api/pull`
// down this lane would reach ollama around the forward's filter, and anything
// on the LAN around every other gate. So is any address the machine takes as
// its own (ownaddr.go): a public one on its NIC, or a range a `local` route
// delivers here. A local box keeps the lane it had.
// Resolution failures refuse too — a name this box cannot resolve is not one
// it can vouch for.
//
// THE ADDRESS THE CHECK VETTED IS THE ADDRESS DIALLED. egressVettedAddr
// returns "ip:port" on an anchored box, and the dial takes that, never the
// name: a name resolved once for the check and again for the dial is a
// rebinding hole (a public answer for the check, 127.0.0.1 for the dial).
func egressInternalRefusal(ctx context.Context, hostport string) string {
	_, why := egressVettedAddr(ctx, hostport)
	return why
}

// egressResolve is how the anchored lane resolves a name. A seam so a test can
// answer for a name without DNS.
var egressResolve = net.DefaultResolver.LookupIPAddr

// egressVettedAddr: (the address to dial, "") or ("", the refusal). On a
// local box the input is returned as it came (the OS resolves at the dial,
// as before); on an anchored box every address the name resolves to is
// checked and the FIRST one is what the dial gets, as "ip:port".
func egressVettedAddr(ctx context.Context, hostport string) (string, string) {
	if currentAnchor() == nil {
		return hostport, ""
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, ""
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return "", "refused: egress to " + host + " — this lane reaches the public internet only on an anchored machine"
	}
	var addrs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		addrs = []net.IP{ip}
	} else {
		resolved, err := egressResolve(ctx, host)
		if err != nil || len(resolved) == 0 {
			return "", "refused: egress to " + host + " — could not resolve it on this machine"
		}
		for _, r := range resolved {
			addrs = append(addrs, r.IP)
		}
	}
	for _, ip := range addrs {
		if internalIP(ip) {
			return "", "refused: egress to " + host + " (" + ip.String() + ") — this lane reaches the public " +
				"internet only on an anchored machine, never this machine, its network or the mesh"
		}
	}
	// This machine is not only loopback: a public address on its NIC, or a
	// range the kernel delivers locally through a `local` route, reaches its
	// 0.0.0.0 services too (ownaddr.go). This lane has no allow list, so the
	// refusal has no exception; a local box returned above and is unchanged.
	own, err := ownDestination(addrs)
	if err != nil {
		return "", "refused: egress to " + host + " — this machine could not tell whether that is itself, so it cannot be vetted"
	}
	if own {
		return "", "refused: egress to " + host + " — that is this machine; this lane reaches the public " +
			"internet only on an anchored machine, never this machine, its network or the mesh"
	}
	return net.JoinHostPort(addrs[0].String(), port), ""
}

// internalIP: loopback, link-local, private (RFC 1918, ULA), CGNAT, unspecified.
func internalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 (carrier NAT) is as internal as 10/8 for this purpose.
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return true
		}
		// 0.0.0.0/8 ("this network"), 198.18.0.0/15 (benchmarking) and
		// 240.0.0.0/4 (reserved) are never a public host.
		if v4[0] == 0 || (v4[0] == 198 && v4[1]&0xfe == 18) || v4[0] >= 240 {
			return true
		}
		return false
	}
	// IPv6 forms that carry an IPv4 address inside them reach that address, so
	// they are judged by it: NAT64 64:ff9b::/96 (the last four bytes — how an
	// IPv6-only network with DNS64 reaches every IPv4 site, so refusing the
	// prefix outright would break those networks) and 6to4 2002::/16 (bytes 2-5).
	if len(ip) == net.IPv6len {
		if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b {
			if ip[4]|ip[5]|ip[6]|ip[7]|ip[8]|ip[9]|ip[10]|ip[11] == 0 {
				return internalIP(net.IPv4(ip[12], ip[13], ip[14], ip[15]))
			}
			// The rest of 64:ff9b::/32 (local-use translators, RFC 8215) maps
			// to IPv4 in ways this box cannot read: refused.
			return true
		}
		if ip[0] == 0x20 && ip[1] == 0x02 {
			return internalIP(net.IPv4(ip[2], ip[3], ip[4], ip[5]))
		}
	}
	return false
}
