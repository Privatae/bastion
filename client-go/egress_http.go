package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http/httputil"
	"strconv"
	"strings"
)

// ONE plain-HTTP request per egress connection, read the way the Host's egress
// gate reads it (its strict request parse and its authority parse: the same
// refusals, the same normalised host, the same rebuilt head).
//
// Everything the lane writes to a destination is what it checked, and nothing
// more:
//   - the head is parsed strictly and REBUILT, so the destination reads the same
//     host, port and body length the lane vetted: never a second reading of the
//     Host's bytes (a Host header naming another site, a query or userinfo glued
//     to the host, a padded Transfer-Encoding);
//   - the request goes out with `Connection: close`, its body is framed by
//     Content-Length or chunked encoding, and a byte the Host sends after the
//     body closes the connection with nothing of it forwarded. Before this the
//     lane wrote the first head and then spliced the whole connection, so every
//     later request on a keep-alive connection reached the destination unread.
//
// An honest client sends its next request only after the response, which the
// destination closes behind `Connection: close`, so it opens a new connection
// and meets the vetting again.

// egressHostChars are the characters a host name may have here (lower-cased).
const egressHostChars = "abcdefghijklmnopqrstuvwxyz0123456789-._"

// egressTokenChars are RFC 9110 token characters: methods and header names.
const egressTokenChars = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// egressHopByHop are headers that belong to one hop. The lane speaks for itself
// on the next one, and a proxy credential never goes on to the destination.
var egressHopByHop = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true, "upgrade": true,
	"te": true, "trailer": true, "proxy-authorization": true, "proxy-authenticate": true,
}

// egressTrailerLimit bounds the trailer section of a chunked body, which is
// read to its end and dropped (the gate's limit).
const egressTrailerLimit = 8192

// egressRefusal is a request the lane refuses before it dials anything.
type egressRefusal struct{ status, body string }

func egressBad(body string) *egressRefusal {
	return &egressRefusal{"400 Bad Request", body}
}

const egressNoHost = "The bastion could not read where this request is going (no host in the " +
	"request line or in a Host header), so it sent nothing."

// egressUnreachable is the body of a 502: the destination passed the vetting,
// and no address of it answered from this machine.
const egressUnreachable = "The bastion could not reach that destination from this machine's own " +
	"connection, so nothing was sent."

// egressHostPort is host and port as the vetting takes them.
func egressHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// writeEgressRefusal answers the Host with a status and a short plain-text
// body saying why, and closes the exchange. why, when set, also goes in
// X-Privatae-Refused, the header the Host already reads.
func writeEgressRefusal(w io.Writer, status, body, why string) {
	body += "\n"
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("Connection: close\r\n")
	if why != "" {
		b.WriteString("X-Privatae-Refused: " + strings.NewReplacer("\r", " ", "\n", " ").Replace(why) + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	_, _ = io.WriteString(w, b.String())
}

// parseEgressAuthority: (host, port, true) from "host", "host:port", "[v6]" or
// "[v6]:port", or false when the lane can't read it exactly as the destination
// would. Refused rather than guessed: userinfo ("a@b"), an unbracketed IPv6
// literal, characters no host name has, a non-numeric or out-of-range port.
// The host is lower-cased and loses one trailing dot.
func parseEgressAuthority(s string, defaultPort int) (string, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "@") {
		return "", 0, false
	}
	var host string
	port := defaultPort
	digits := func(p string) bool {
		if len(p) == 0 || len(p) > 5 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", 0, false
		}
		// An IPv6 literal, IPv4-mapped forms included (the vetting judges the
		// address they map to); a bare IPv4 address in brackets or a zone is
		// not one.
		inner := s[1:end]
		ip := net.ParseIP(inner)
		if ip == nil || !strings.Contains(inner, ":") || strings.Contains(inner, "%") {
			return "", 0, false
		}
		host = ip.String()
		rest := s[end+1:]
		switch {
		case rest == "":
		case strings.HasPrefix(rest, ":") && digits(rest[1:]):
			port, _ = strconv.Atoi(rest[1:])
		default:
			return "", 0, false
		}
	} else {
		if strings.Count(s, ":") > 1 {
			return "", 0, false
		}
		h, p, hasPort := strings.Cut(s, ":")
		if hasPort {
			if !digits(p) {
				return "", 0, false
			}
			port, _ = strconv.Atoi(p)
		}
		h = strings.ToLower(h)
		h = strings.TrimSuffix(h, ".")
		if h == "" || strings.HasPrefix(h, ".") || strings.Contains(h, "..") {
			return "", 0, false
		}
		for _, c := range h {
			if !strings.ContainsRune(egressHostChars, c) {
				return "", 0, false
			}
		}
		host = h
	}
	if port <= 0 || port >= 65536 {
		return "", 0, false
	}
	return host, port, true
}

// fmtEgressAuthority writes host[:port] back, the port left out when it is the
// scheme's default.
func fmtEgressAuthority(host string, port, defaultPort int) string {
	h := host
	if strings.Contains(host, ":") {
		h = "[" + host + "]"
	}
	if port == defaultPort {
		return h
	}
	return h + ":" + strconv.Itoa(port)
}

// egressRequest is the one plain-HTTP request the lane forwards.
type egressRequest struct {
	host    string
	port    int
	head    []byte // rebuilt, CRLF, ends at its blank line
	chunked bool
	length  int64
}

func egressTokenOK(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune(egressTokenChars, c) {
			return false
		}
	}
	return true
}

// parseEgressRequest reads the one request in head (the request line and
// headers through their blank line, as handleEgressConn read them) and
// rebuilds it, or refuses it. CONNECT never comes here.
func parseEgressRequest(head string) (egressRequest, *egressRefusal) {
	lines := strings.Split(head, "\n")
	// The read stops at the first blank line, so the head ends "\n", blank, "\n":
	// drop the empty tail after the last "\n" and the blank line itself.
	if len(lines) < 3 {
		return egressRequest{}, egressBad("The request ended before its headers did, so the bastion sent nothing.")
	}
	lines = lines[:len(lines)-2]
	for i, ln := range lines {
		lines[i] = strings.TrimSuffix(ln, "\r")
		if strings.ContainsAny(lines[i], "\r\x00") {
			return egressRequest{}, egressBad("The request's headers carry a stray carriage return or NUL, so the bastion sent nothing.")
		}
	}
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" || !egressTokenOK(parts[0]) {
		return egressRequest{}, egressBad("The request line is not 'METHOD target HTTP/1.x', so the bastion sent nothing.")
	}
	method, rawTarget, version := strings.ToUpper(parts[0]), parts[1], parts[2]
	if version != "HTTP/1.1" && version != "HTTP/1.0" {
		return egressRequest{}, egressBad("The bastion forwards HTTP/1.0 and HTTP/1.1 only, so it sent nothing.")
	}
	type header struct{ name, value string }
	var headers []header
	for _, ln := range lines[1:] {
		if strings.HasPrefix(ln, " ") || strings.HasPrefix(ln, "\t") {
			return egressRequest{}, egressBad("A header is folded onto a second line (obsolete line folding), so the bastion sent nothing.")
		}
		name, value, ok := strings.Cut(ln, ":")
		if !ok || !egressTokenOK(name) {
			return egressRequest{}, egressBad("A header line is not 'Name: value' (no space may come before the colon), so the bastion sent nothing.")
		}
		headers = append(headers, header{name, strings.Trim(value, " \t")})
	}
	values := func(n string) []string {
		var out []string
		for _, h := range headers {
			if strings.EqualFold(h.name, n) {
				out = append(out, h.value)
			}
		}
		return out
	}

	hosts := values("host")
	if len(hosts) > 1 {
		return egressRequest{}, egressBad("The request carries more than one Host header, so the bastion sent nothing.")
	}
	var host, target, authority string
	var port int
	if scheme, after, abs := strings.Cut(rawTarget, "://"); abs {
		if strings.ToLower(scheme) != "http" {
			// https:// in absolute form asks the lane to make the TLS connection,
			// which it does not do: it used to send the request in plain text to
			// port 80. Every client sends https as a CONNECT.
			return egressRequest{}, egressBad("The bastion forwards plain http:// requests only; send https as a CONNECT. Nothing was sent.")
		}
		cut := len(after)
		for _, sep := range []string{"/", "?", "#"} {
			if i := strings.Index(after, sep); i >= 0 && i < cut {
				cut = i
			}
		}
		var ok bool
		if host, port, ok = parseEgressAuthority(after[:cut], 80); !ok {
			return egressRequest{}, egressBad(egressNoHost)
		}
		path, _, _ := strings.Cut(after[cut:], "#")
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		authority = fmtEgressAuthority(host, port, 80)
		target = "http://" + authority + path
	} else {
		if !strings.HasPrefix(rawTarget, "/") && rawTarget != "*" {
			return egressRequest{}, egressBad(egressNoHost)
		}
		hostHdr := ""
		if len(hosts) == 1 {
			hostHdr = hosts[0]
		}
		var ok bool
		if host, port, ok = parseEgressAuthority(hostHdr, 80); !ok {
			return egressRequest{}, egressBad(egressNoHost)
		}
		authority = fmtEgressAuthority(host, port, 80)
		target = rawTarget
	}

	// Body framing (RFC 9112 section 6). Every reading two parsers could disagree
	// on is refused: both length headers, an unknown or doubled coding, a coding
	// on HTTP/1.0, Content-Length values that differ.
	req := egressRequest{host: host, port: port}
	te, cl := values("transfer-encoding"), values("content-length")
	if len(te) > 0 {
		var codings []string
		for _, v := range te {
			for _, c := range strings.Split(v, ",") {
				codings = append(codings, strings.ToLower(strings.TrimSpace(c)))
			}
		}
		if len(cl) > 0 || version == "HTTP/1.0" || len(codings) != 1 || codings[0] != "chunked" {
			return egressRequest{}, egressBad("The request's body length is ambiguous (Transfer-Encoding with " +
				"Content-Length, on HTTP/1.0, or a coding other than chunked), so the bastion sent nothing.")
		}
		req.chunked = true
	} else if len(cl) > 0 {
		seen := map[string]bool{}
		for _, v := range cl {
			for _, c := range strings.Split(v, ",") {
				seen[strings.TrimSpace(c)] = true
			}
		}
		var one string
		for k := range seen {
			one = k
		}
		n, err := strconv.ParseInt(one, 10, 64)
		if len(seen) != 1 || one == "" || len(one) > 18 || err != nil || n < 0 || strings.TrimLeft(one, "0123456789") != "" {
			return egressRequest{}, egressBad("The request's Content-Length is not one number, so the bastion sent nothing.")
		}
		req.length = n
	}

	named := map[string]bool{}
	for _, v := range values("connection") {
		for _, t := range strings.Split(v, ",") {
			named[strings.ToLower(strings.TrimSpace(t))] = true
		}
	}
	var b strings.Builder
	b.WriteString(method + " " + target + " " + version + "\r\n")
	b.WriteString("Host: " + authority + "\r\n")
	for _, h := range headers {
		lk := strings.ToLower(h.name)
		if egressHopByHop[lk] || named[lk] || lk == "host" || lk == "content-length" || lk == "transfer-encoding" {
			continue
		}
		b.WriteString(h.name + ": " + h.value + "\r\n")
	}
	if req.chunked {
		b.WriteString("Transfer-Encoding: chunked\r\n")
	} else if len(cl) > 0 {
		b.WriteString("Content-Length: " + strconv.FormatInt(req.length, 10) + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	req.head = []byte(b.String())
	return req, nil
}

// forwardEgressBody copies the one request body from src to dst, framed as the
// rebuilt head says. A chunked body goes out re-encoded (plain sizes, no
// extensions, trailers read and dropped), so the destination parses exactly the
// body this parser found.
func forwardEgressBody(dst io.Writer, src *bufio.Reader, req egressRequest) error {
	if !req.chunked {
		if req.length == 0 {
			return nil
		}
		_, err := io.CopyN(dst, src, req.length)
		return err
	}
	cw := httputil.NewChunkedWriter(dst)
	if _, err := io.Copy(cw, httputil.NewChunkedReader(src)); err != nil {
		return err
	}
	// The trailer section, read to its blank line within a bound, and dropped.
	read := 0
	for {
		line, err := src.ReadSlice('\n')
		read += len(line)
		if err != nil || read > egressTrailerLimit {
			return errors.New("chunked body: bad trailer section")
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			break
		}
	}
	if err := cw.Close(); err != nil {
		return err
	}
	_, err := io.WriteString(dst, "\r\n")
	return err
}

// oneEgressExchange writes the one rebuilt request and its body to upstream,
// and carries the destination's answer back until the destination closes.
// Nothing the Host sends after the body is forwarded: its first byte closes
// both sides.
func oneEgressExchange(clientReader *bufio.Reader, client, upstream net.Conn, req egressRequest) {
	answered := make(chan struct{})
	go func() {
		_, _ = io.Copy(client, upstream)
		close(answered)
		_ = client.Close()
	}()
	defer func() {
		_ = upstream.Close()
		<-answered
	}()
	if _, err := upstream.Write(req.head); err != nil {
		return
	}
	if err := forwardEgressBody(upstream, clientReader, req); err != nil {
		return
	}
	// The request is complete. A further byte is a second request on this
	// connection: never forwarded, and the connection closes. End of stream
	// from the Host is passed on, as the splice did.
	go func() {
		var one [1]byte
		if n, _ := clientReader.Read(one[:]); n > 0 {
			_ = upstream.Close()
			_ = client.Close()
			return
		}
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	<-answered
}
