//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// The bastion's egress lanes carry ONE plain-HTTP request per connection, read
// the way the Host's egress gate reads it, and every refusal says
// why in its body.
//
// MUTATIONS, each red:
//   - handleEgressConn writes head.String() to upstream and splices, as before:
//     TestEgressPlainHTTPCarriesOneRequestPerConnection, ...SendsTheHostItChecked;
//   - oneEgressExchange's watcher forwards instead of closing: ...OneRequest...;
//   - parseEgressAuthority accepts "@" or cuts the authority at "/" only:
//     TestEgressPlainHTTPReadsTheHostAsTheGateDoes;
//   - writeEgressRefusal writes Content-Length: 0: TestEgressRefusalsCarryABody.

// recordingOrigin stands in for a destination that keeps a connection open
// after answering (it ignores Connection: close, as a careless server may),
// and records every byte one connection carried to it.
type recordingOrigin struct {
	ln    net.Listener
	conns chan string
	// silent: never answer, so the lane never holds an unread answer when it
	// closes (a close with unread data is a reset, which can cost the origin
	// bytes it has not read yet).
	silent bool
}

func newSilentOrigin(t *testing.T) *recordingOrigin {
	o := newRecordingOrigin(t)
	o.silent = true
	return o
}

func newRecordingOrigin(t *testing.T) *recordingOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &recordingOrigin{ln: ln, conns: make(chan string, 16)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go o.serve(c)
		}
	}()
	return o
}

func (o *recordingOrigin) serve(c net.Conn) {
	defer c.Close()
	var mu sync.Mutex
	var got bytes.Buffer
	answered := false
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		n, err := c.Read(buf)
		mu.Lock()
		got.Write(buf[:n])
		if !o.silent && !answered && bytes.Contains(got.Bytes(), []byte("\r\n\r\n")) {
			answered = true
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
		mu.Unlock()
		if err != nil {
			break
		}
	}
	o.conns <- got.String()
}

// next is everything the origin's next connection carried, once it ended.
func (o *recordingOrigin) next(t *testing.T) string {
	t.Helper()
	s, ok := o.nextWithin(8 * time.Second)
	if !ok {
		t.Fatal("the destination never saw its connection end")
	}
	return s
}

func (o *recordingOrigin) nextWithin(d time.Duration) (string, bool) {
	select {
	case s := <-o.conns:
		return s, true
	case <-time.After(d):
		return "", false
	}
}

func (o *recordingOrigin) addr() string { return o.ln.Addr().String() }

// A keep-alive connection carries one request to the destination, never two:
// neither a request sent after the first answer (a client reusing the
// connection) nor one pipelined behind the first.
func TestEgressPlainHTTPCarriesOneRequestPerConnection(t *testing.T) {
	first := "GET http://198.51.100.30/first HTTP/1.1\r\nHost: 198.51.100.30\r\n\r\n"
	second := "GET http://198.51.100.30/second HTTP/1.1\r\nHost: 198.51.100.30\r\n\r\n"

	t.Run("reused after the answer", func(t *testing.T) {
		o := newRecordingOrigin(t)
		var asked []string
		cli, cleanup := dialHandler(t, redirectDial(o.addr(), &asked))
		defer cleanup()
		_, _ = io.WriteString(cli, first)
		br := bufio.NewReader(cli)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("the first request got no answer: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "ok" {
			t.Fatalf("the first answer was %q", body)
		}
		_, _ = io.WriteString(cli, second)
		got := o.next(t)
		if strings.Contains(got, "/second") {
			t.Fatalf("a second request on one connection reached the destination unvetted:\n%s", got)
		}
		if !strings.Contains(got, "\r\nConnection: close\r\n") {
			t.Fatalf("the request went out without Connection: close:\n%s", got)
		}
		_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
		if rest, _ := io.ReadAll(br); len(rest) != 0 {
			t.Fatalf("the lane answered the second request: %q", rest)
		}
		if len(asked) != 1 {
			t.Fatalf("one connection, one dial: %v", asked)
		}
	})

	t.Run("pipelined", func(t *testing.T) {
		o := newRecordingOrigin(t)
		var asked []string
		cli, cleanup := dialHandler(t, redirectDial(o.addr(), &asked))
		defer cleanup()
		_, _ = io.WriteString(cli, first+second)
		got := o.next(t)
		if !strings.Contains(got, "GET http://198.51.100.30/first HTTP/1.1\r\n") {
			t.Fatalf("the first request did not reach the destination:\n%s", got)
		}
		if strings.Contains(got, "/second") {
			t.Fatalf("a pipelined second request reached the destination unvetted:\n%s", got)
		}
	})
}

// The destination reads the host the lane vetted, in the one Host header; hop
// headers, those Connection names and a proxy credential stay on this hop.
func TestEgressPlainHTTPSendsTheHostItChecked(t *testing.T) {
	o := newRecordingOrigin(t)
	var asked []string
	cli, cleanup := dialHandler(t, redirectDial(o.addr(), &asked))
	defer cleanup()
	_, _ = io.WriteString(cli, "GET http://198.51.100.31/p?q=1 HTTP/1.1\r\n"+
		"Host: inside.example.test\r\nProxy-Authorization: Basic eDp5\r\n"+
		"Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\nX-Keep: 2\r\n\r\n")
	got := o.next(t)
	head, _, _ := strings.Cut(got, "\r\n\r\n")
	want := "GET http://198.51.100.31/p?q=1 HTTP/1.1\r\nHost: 198.51.100.31\r\nX-Keep: 2\r\nConnection: close"
	if head != want {
		t.Fatalf("the destination got\n%q\nwant\n%q", head, want)
	}
	if len(asked) != 1 || asked[0] != "198.51.100.31:80" {
		t.Fatalf("the lane must dial the address it vetted: %v", asked)
	}
}

// stubEgressNames answers names without DNS and records each name exactly as
// the lane asked for it.
func stubEgressNames(t *testing.T, m map[string]string) *[]string {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	old := egressResolve
	t.Cleanup(func() { egressResolve = old })
	egressResolve = func(_ context.Context, host string) ([]net.IPAddr, error) {
		mu.Lock()
		asked = append(asked, host)
		mu.Unlock()
		ip, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	return &asked
}

// The host is read as the gate reads it: the authority ends at the first "/",
// "?" or "#", is lower-cased and loses one trailing dot; userinfo, an
// unbracketed IPv6 literal, a bad port, https in absolute form, two Host
// headers and an ambiguous body length are refused with 400 and a body, before
// anything is resolved or dialled.
func TestEgressPlainHTTPReadsTheHostAsTheGateDoes(t *testing.T) {
	for _, c := range []struct {
		req, wantName, wantLine string
	}{
		{"GET http://public.example.test?@10.0.0.1/ HTTP/1.1\r\n\r\n", "public.example.test",
			"GET http://public.example.test/?@10.0.0.1/ HTTP/1.1"},
		{"GET http://public.example.test#@10.0.0.1/ HTTP/1.1\r\n\r\n", "public.example.test",
			"GET http://public.example.test/ HTTP/1.1"},
		{"GET http://Public.Example.Test./x HTTP/1.1\r\n\r\n", "public.example.test",
			"GET http://public.example.test/x HTTP/1.1"},
		{"GET /x HTTP/1.1\r\nHost: Public.Example.Test:8080\r\n\r\n", "public.example.test",
			"GET /x HTTP/1.1"},
	} {
		o := newRecordingOrigin(t)
		names := stubEgressNames(t, map[string]string{"public.example.test": "198.51.100.40"})
		var asked []string
		cli, cleanup := dialHandler(t, redirectDial(o.addr(), &asked))
		_, _ = io.WriteString(cli, c.req)
		got, _ := o.nextWithin(4 * time.Second)
		cleanup()
		if len(*names) != 1 || (*names)[0] != c.wantName {
			t.Errorf("%q: the lane resolved %q; want only %q", c.req, *names, c.wantName)
		}
		if line, _, _ := strings.Cut(got, "\r\n"); line != c.wantLine {
			t.Errorf("%q: the destination got the request line %q; want %q", c.req, line, c.wantLine)
		}
	}

	for _, req := range []string{
		"GET http://user:pw@public.example.test/ HTTP/1.1\r\n\r\n",
		"GET http://198.51.100.41:80@public.example.test/ HTTP/1.1\r\n\r\n",
		"GET http://2001:db8::1/ HTTP/1.1\r\n\r\n",
		"GET http://public.example.test:80x/ HTTP/1.1\r\n\r\n",
		"GET https://public.example.test/ HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: public.example.test\r\nHost: 198.51.100.41\r\n\r\n",
		"GET / HTTP/1.1\r\n\r\n",
		"POST http://public.example.test/ HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
		"POST http://public.example.test/ HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
		"POST http://public.example.test/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
		"GET http://public.example.test/ HTTP/1.1\r\n X-Folded: 1\r\n\r\n",
		"CONNECT user@public.example.test:443 HTTP/1.1\r\n\r\n",
		"CONNECT 2001:db8::1:443 HTTP/1.1\r\n\r\n",
		"CONNECT [198.51.100.41]:443 HTTP/1.1\r\n\r\n",
	} {
		names := stubEgressNames(t, map[string]string{"public.example.test": "198.51.100.40"})
		var asked []string
		cli, cleanup := dialHandler(t, redirectDial("127.0.0.1:9", &asked))
		_, _ = io.WriteString(cli, req)
		resp, err := http.ReadResponse(bufio.NewReader(cli), nil)
		if err != nil {
			t.Errorf("%q: no answer: %v", req, err)
			cleanup()
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		cleanup()
		if resp.StatusCode != 400 || len(body) == 0 || int64(len(body)) != resp.ContentLength {
			t.Errorf("%q: answered %d with body %q; want 400 with a body saying why", req, resp.StatusCode, body)
		}
		if len(*names) != 0 || len(asked) != 0 {
			t.Errorf("%q: refused requests resolve and dial nothing; resolved %q, dialled %q", req, *names, asked)
		}
	}
}

// A request body goes out framed as its head says, chunked bodies re-encoded,
// and nothing after it.
func TestEgressPlainHTTPBodyIsFramed(t *testing.T) {
	for _, c := range []struct{ req, wantBody string }{
		{"POST http://198.51.100.42/u HTTP/1.1\r\nHost: 198.51.100.42\r\nContent-Length: 5\r\n\r\nhello" +
			"GET http://198.51.100.42/smuggled HTTP/1.1\r\n\r\n", "hello"},
		{"POST http://198.51.100.42/u HTTP/1.1\r\nHost: 198.51.100.42\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"5;ext=1\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n", "5\r\nhello\r\n0\r\n\r\n"},
	} {
		o := newSilentOrigin(t)
		var asked []string
		cli, cleanup := dialHandler(t, redirectDial(o.addr(), &asked))
		_, _ = io.WriteString(cli, c.req)
		got := o.next(t)
		cleanup()
		_, body, _ := strings.Cut(got, "\r\n\r\n")
		if body != c.wantBody {
			t.Errorf("the destination got the body %q; want %q", body, c.wantBody)
		}
	}
}

// A refusal says why in its body, not only in a header: a 403 from the vetting
// and a 502 from a dial that found no answer, on both request forms, and the
// coder-run proxy's refusals too.
func TestEgressRefusalsCarryABody(t *testing.T) {
	failDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("no route")
	}
	okDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("must not dial %s", addr)
	}
	check := func(name string, resp *http.Response, err error, want int) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: no answer: %v", name, err)
			return
		}
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want || len(body) < 10 || int64(len(body)) != resp.ContentLength {
			t.Errorf("%s: answered %d with body %q (Content-Length %d); want %d with a short body saying why",
				name, resp.StatusCode, body, resp.ContentLength, want)
		}
	}
	for _, c := range []struct {
		name string
		dial egressDialer
		req  string
		want int
	}{
		{"plain HTTP to this machine", okDial, "GET http://127.0.0.1:9/ HTTP/1.1\r\n\r\n", 403},
		{"CONNECT to this machine", okDial, "CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n", 403},
		{"plain HTTP, no answer", failDial, "GET http://198.51.100.43/ HTTP/1.1\r\n\r\n", 502},
		{"CONNECT, no answer", failDial, "CONNECT 198.51.100.43:443 HTTP/1.1\r\n\r\n", 502},
	} {
		cli, cleanup := dialHandler(t, c.dial)
		_, _ = io.WriteString(cli, c.req)
		resp, err := http.ReadResponse(bufio.NewReader(cli), nil)
		check(c.name, resp, err, c.want)
		cleanup()
	}

	oldDial := coderDialOut
	t.Cleanup(func() { coderDialOut = oldDial })
	coderDialOut = failDial
	for _, c := range []struct {
		name, req string
		want      int
	}{
		{"coder run to a private address", "GET http://10.0.0.1/ HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n", 403},
		{"coder run, no answer", "GET http://93.184.216.34/ HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n", 502},
	} {
		boxEnd, runEnd := net.Pipe()
		var refused int64
		go handleCoderEgressConn(boxEnd, nil, &refused)
		_ = runEnd.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(runEnd, c.req)
		resp, err := http.ReadResponse(bufio.NewReader(runEnd), nil)
		check(c.name, resp, err, c.want)
		_ = runEnd.Close()
	}
}

// The coder-run proxy carries one request per connection too: the run's own
// processes are the sender there.
func TestCoderEgressCarriesOneRequestPerConnection(t *testing.T) {
	o := newRecordingOrigin(t)
	oldDial := coderDialOut
	t.Cleanup(func() { coderDialOut = oldDial })
	coderDialOut = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, o.addr())
	}
	boxEnd, runEnd := net.Pipe()
	var refused int64
	go handleCoderEgressConn(boxEnd, nil, &refused)
	_ = runEnd.SetDeadline(time.Now().Add(8 * time.Second))
	_, _ = io.WriteString(runEnd, "GET http://93.184.216.34/first HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n")
	br := bufio.NewReader(runEnd)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("the first request got no answer: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_, _ = io.WriteString(runEnd, "GET http://93.184.216.34/second HTTP/1.1\r\nHost: inside.example.test\r\n\r\n")
	got := o.next(t)
	_ = runEnd.Close()
	if strings.Contains(got, "/second") || strings.Contains(got, "inside.example.test") {
		t.Fatalf("a second request on one connection reached the destination unvetted:\n%s", got)
	}
	if !strings.Contains(got, "\r\nConnection: close\r\n") {
		t.Fatalf("the request went out without Connection: close:\n%s", got)
	}
}
