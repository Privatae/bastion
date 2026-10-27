//go:build linux

// The serve lane dials a target set by name at each address it checked, in
// turn (servelane.go: serveVetTarget, serveDial, servePick). Uses the fixtures
// of servelane_linux_test.go, modelscope_test.go and modelswap_test.go.

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// A target set by name is dialled at every address it was checked for, in
// turn, as a plain dial of the name is. OLLAMA_ADDR=localhost:<port>, a
// resolver that answers ::1 first (as most do) and a server listening on
// 127.0.0.1 only (ollama's default): a job on the lane, the beat and model
// management each reach it. The resolver's two addresses are both this
// machine's and are the only ones there are to dial.
//
// MUTATION: serveVetTarget returns only the first address it checked (as it
// did), or serveJob dials only addrs[0].
// RESULT: red — the job's request gets no answer (its one dial, to [::1], is
// refused), the beat has no ollama in lane_serves, and model management is
// handed [::1].
func TestTheServeLaneDialsEachCheckedAddressInTurn(t *testing.T) {
	up := newFakeOllama(t)
	listening := up.srv.Listener.Addr().String()
	if !strings.HasPrefix(listening, "127.0.0.1:") {
		t.Fatalf("the stand-in listens on %s, not 127.0.0.1 only, so this case proves nothing", listening)
	}
	port := portOf(up.srv.Listener)
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("::1", port), time.Second); err == nil {
		_ = c.Close()
		t.Fatalf("something answers on [::1]:%s, so the first address would not fail and this case proves nothing", port)
	}
	old := serveLookupIP
	t.Cleanup(func() { serveLookupIP = old })
	serveLookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "localhost" {
			return nil, fmt.Errorf("no such host")
		}
		return []net.IPAddr{{IP: net.IPv6loopback}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	t.Setenv("OLLAMA_ADDR", "localhost:"+port)
	t.Setenv("PRIVATAE_LLM_ADDR", "")
	t.Setenv("PRIVATAE_PII_ADDR", "")
	resetModelDaemonCache()
	h, cfg := serveLaneBox(t, "dual.example.test")
	runInBackground(t, cfg)

	if got := strsOf(h.beat(t)["lane_serves"]); !slices.Contains(got, "ollama") {
		t.Errorf("the beat does not say ollama is served: lane_serves %q", got)
	}

	ws := h.take(t)
	if got := ask(t, ws, "ollama"); got != "A" {
		t.Fatalf("the lane must accept ollama: %q", got)
	}
	conn := laneConn(ws)
	req, _ := http.NewRequest(http.MethodGet, "http://serve/api/tags", nil)
	req.Close = true
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("no answer over the lane (only [::1] was dialled?): %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "qwen4-embed") {
		t.Fatalf("over the lane: %d %s", resp.StatusCode, b)
	}

	if addr, why := modelDaemonTarget(cfg.HostName); addr != listening || why != "" {
		t.Errorf("model management is handed %q (%q), want the address that answers, %s", addr, why, listening)
	}
	out, errOut, code, _ := driveModelOp(t, cfg.HostName, "model:list", nil, t.TempDir())
	if code != 0 || !strings.Contains(out, "qwen4-embed") {
		t.Errorf("model:list: exit %d, %q %q", code, out, errOut)
	}
	for _, s := range up.requests() {
		if !strings.HasPrefix(s, "GET ") {
			t.Errorf("the stand-in was asked %q", s)
		}
	}
}

// servePick returns the first checked address that accepts, and the first
// checked when none does; it never returns an address it was not given.
func TestServePickTakesTheFirstCheckedAddressThatAnswers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := portOf(ln)
	v6 := net.JoinHostPort("::1", port)
	if c, err := net.DialTimeout("tcp", v6, time.Second); err == nil {
		_ = c.Close()
		t.Fatalf("something answers on %s, so this case proves nothing", v6)
	}
	if got := servePick([]string{v6, ln.Addr().String()}); got != ln.Addr().String() {
		t.Errorf("pick %q, want %s", got, ln.Addr())
	}
	_ = ln.Close()
	if got := servePick([]string{v6, "127.0.0.1:" + port}); got != v6 {
		t.Errorf("with nothing answering, pick %q, want the first checked, %s", got, v6)
	}
	if got := servePick([]string{"127.0.0.1:" + port}); got != "127.0.0.1:"+port {
		t.Errorf("one address: %q", got)
	}
}
