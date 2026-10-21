//go:build !windows

package main

// Gates for the ctx_extract PULL path (contextpull.go).
//
// These are END TO END on this side of the wire, not unit tests of the parts:
// each one stands up a REAL HTTPS server standing in for the host, wires it
// through newHostSourcePuller and a tunnel-shaped transport exactly as run.go
// does, and then drives a REAL ctx_extract management frame through
// handleMgmtConnFor. The only thing faked is the host itself — and it is faked
// with the same checks the real route makes (bearer, then a single-use ticket
// bound to one machine), so a test that passes here is a test of the whole path
// from the job frame to the extracted text.
//
// The pull path's own header explains why there is no URL on the wire and so no
// SSRF wall to test: the box builds the URL from its configured host name and
// the transport pins the dial, so there is no destination for a host to name.
// TestPullRefusesAMalformedTicketWithoutDialing pins the one input that does
// reach that URL.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHost is the host's /api/network/bastions/context-source route, with the
// two checks that matter reproduced faithfully: the bastion's own bearer, and a
// ticket that is single-use and bound to one machine.
type fakeHost struct {
	t       *testing.T
	bearer  string
	mu      sync.Mutex
	tickets map[string][]byte // ticket -> the document it authorizes
	served  int
	dialed  []string
}

func (h *fakeHost) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/network/bastions/context-source" {
			http.Error(w, "no such route", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+h.bearer {
			http.Error(w, "invalid or revoked bastion bearer", http.StatusUnauthorized)
			return
		}
		h.mu.Lock()
		body, ok := h.tickets[r.URL.Query().Get("ticket")]
		if ok {
			// SINGLE USE: the real route pops the ticket on redeem, so a replay
			// gets nothing even if the first response never arrived.
			delete(h.tickets, r.URL.Query().Get("ticket"))
			h.served++
		}
		h.mu.Unlock()
		if !ok {
			http.Error(w, "no such fetch", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write(body)
	})
}

// startFakeHost returns the host name to configure and a puller wired the way
// run.go wires the real one: a client whose DialContext IGNORES the address in
// the URL and always dials the one endpoint, with ServerName pinned.
func startFakeHost(t *testing.T, bearer string) (*fakeHost, string) {
	t.Helper()
	h := &fakeHost{t: t, bearer: bearer, tickets: map[string][]byte{}}
	srv := httptest.NewTLSServer(h.handler())
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	// httptest's certificate is issued for example.com, so that is the name this
	// box is configured with — the same shape as a real <handle>.host.privatae.ai.
	const hostName = "example.com"
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsCfg.ServerName = hostName
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			h.mu.Lock()
			h.dialed = append(h.dialed, a)
			h.mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig: tlsCfg,
	}}
	setCtxSourcePuller(newHostSourcePuller(c, hostName, bearer))
	t.Cleanup(func() { setCtxSourcePuller(nil) })
	return h, hostName
}

var fakeTicketSeq int

func (h *fakeHost) issue(doc []byte) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	fakeTicketSeq++
	// 64 hex characters, like the real mint, and unique across the suite so the
	// "never minted" cases below can never collide with a live one.
	tk := fmt.Sprintf("%064x", fakeTicketSeq)
	h.tickets[tk] = doc
	return tk
}

func pullReq(t *testing.T, tool, ticket string, size, max int64) string {
	t.Helper()
	// 30 is the host's floor grant, i.e. what a small source
	// really gets on the wire.
	return pullReqBudget(t, tool, ticket, size, max, 30)
}

func pullReqBudget(t *testing.T, tool, ticket string, size, max int64, budget float64) string {
	t.Helper()
	b, err := json.Marshal(ctxExtractReq{Tool: tool, Mime: "application/pdf",
		Ticket: ticket, Size: size, MaxBytes: max, PullBudget: budget})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// THE WHOLE PULL PATH IN ONE ASSERTION: the host hands over a ticket, this box
// fetches the document over its own tunnel client, extracts it, and returns the
// text — with nothing left on disk afterwards.
func TestCtxExtractPullsTheDocumentAndReturnsItsText(t *testing.T) {
	setupBox(t)
	if ok, _ := probePrepTool(prepTool{Name: "pdf-text", Bin: "pdftotext", Args: []string{"-v"}}); !ok {
		t.Skip("pdftotext not installed on this box — a skip proves nothing, install poppler-utils")
	}
	h, _ := startFakeHost(t, "bearer-abc")
	doc, err := base64.StdEncoding.DecodeString(probePDFB64)
	if err != nil {
		t.Fatal(err)
	}
	tk := h.issue(doc)

	out, errOut, code, root := driveExtractIn(t, tAnchor,
		[]string{pullReq(t, "pdf-text", tk, int64(len(doc)), ctxPullMaxBytes)})
	if code != 0 {
		t.Fatalf("pull extraction failed: code=%d err=%s", code, errOut)
	}
	var resp ctxExtractResp
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("reply is not JSON: %v (%q)", err, out)
	}
	if !strings.Contains(resp.Text, probePDFText) {
		t.Fatalf("the pulled document's text is missing.\n  want substring: %q\n  got: %q",
			probePDFText, resp.Text)
	}
	if resp.Source != "pull" {
		t.Fatalf("the reply must say which transport carried the document, got %q", resp.Source)
	}
	if h.served != 1 {
		t.Fatalf("the host served %d fetches for one job, want 1", h.served)
	}
	// The user's document must not survive the call on this path either — the
	// pull writes it to the same scratch file the inline path does.
	left, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("the pulled document was left in the context root: %v", left)
	}
}

// THE TICKET IS THE AUTHORITY. Everything the host refuses, this box reports as
// a refusal with the host's status in it — never as a bad document, and never by
// falling back to some other way of getting the bytes.
//
// The replay case is the one that matters: it is what makes the ticket
// single-use rather than a bearer for that row. Delete the ticket check from the
// host and this case goes green while the others stay green, which is exactly
// how it would be noticed.
func TestCtxExtractPullRefusalsCarryTheHostsAnswer(t *testing.T) {
	setupBox(t)
	h, _ := startFakeHost(t, "bearer-abc")
	doc := []byte("%PDF-1.4 not really")
	tk := h.issue(doc)

	// First use is spent by a job that runs (whether the extractor likes the
	// document is beside the point here).
	_, _, _ = driveExtract(t, tAnchor, []string{pullReq(t, "pdf-text", tk, int64(len(doc)), 0)})

	for _, tc := range []struct {
		name, ticket, want string
	}{
		{"a replayed ticket", tk, "HTTP 404"},
		{"a ticket that was never minted", strings.Repeat("a", 64), "HTTP 404"},
	} {
		_, errOut, code := driveExtract(t, tAnchor,
			[]string{pullReq(t, "pdf-text", tc.ticket, 0, 0)})
		if code == 0 {
			t.Fatalf("%s was accepted", tc.name)
		}
		if !contains(errOut, tc.want) {
			t.Fatalf("%s: the refusal must carry the host's answer (%s), got %q",
				tc.name, tc.want, errOut)
		}
	}
}

// A BEARER THIS HOST DOES NOT KNOW GETS NOTHING. The bearer is what
// newHostSourcePuller puts on the request; a build that dropped it, or a box
// whose pairing was revoked, must fail here rather than anywhere later.
func TestCtxExtractPullNeedsTheBastionsOwnBearer(t *testing.T) {
	setupBox(t)
	h, _ := startFakeHost(t, "bearer-abc")
	tk := h.issue([]byte("%PDF-1.4"))
	// Rotate the bearer the host accepts, leaving the box's unchanged — the
	// shape of a revoked or re-minted pairing.
	h.mu.Lock()
	h.bearer = "bearer-rotated"
	h.mu.Unlock()

	_, errOut, code := driveExtract(t, tAnchor, []string{pullReq(t, "pdf-text", tk, 0, 0)})
	if code == 0 {
		t.Fatal("a fetch with a bearer the host does not accept was allowed to proceed")
	}
	if !contains(errOut, "HTTP 401") {
		t.Fatalf("the refusal must name the 401, got %q", errOut)
	}
}

// THE CEILING IS THIS BOX'S, not the host's. A host that declares a bigger
// max_bytes than this build allows gets this build's number, and a body that
// runs past it is stopped mid-stream with nothing extracted.
func TestCtxExtractPullStopsAtTheCeiling(t *testing.T) {
	setupBox(t)
	h, _ := startFakeHost(t, "bearer-abc")
	// A "document" of 3 MiB against a declared max of 1 KiB.
	tk := h.issue(make([]byte, 3<<20))
	_, errOut, code, root := driveExtractIn(t, tAnchor,
		[]string{pullReq(t, "pdf-text", tk, 0, 1024)})
	if code == 0 {
		t.Fatal("a body past the authorized size was accepted")
	}
	if !contains(errOut, "1024") || !contains(errOut, "nothing was extracted") {
		t.Fatalf("the refusal must name the ceiling and say nothing was extracted: %q", errOut)
	}
	left, _ := os.ReadDir(root)
	if len(left) != 0 {
		t.Fatalf("a partial download was left on the user's disk: %v", left)
	}
}

// A HOST ASKING FOR MORE THAN THIS BUILD ALLOWS GETS THIS BUILD'S NUMBER.
// pullSourceInto clamps rather than trusting the declared max, so "max_bytes:
// 1 TiB" cannot make this machine fill its own disk.
func TestPullClampsAnOversizeDeclaredMax(t *testing.T) {
	setupBox(t)
	h, _ := startFakeHost(t, "bearer-abc")
	tk := h.issue(make([]byte, ctxPullMaxBytes+1))
	var sink countingWriter
	n, err := pullSourceInto(&sink, tk, 1<<40, time.Minute)
	if err == nil {
		t.Fatal("a body past this build's ceiling was accepted because the host said so")
	}
	if n > ctxPullMaxBytes+int64(ctxPullChunk) {
		t.Fatalf("read %d bytes past the %d ceiling before stopping", n, ctxPullMaxBytes)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(ctxPullMaxBytes)) {
		t.Fatalf("the refusal must name THIS build's ceiling, got %q", err)
	}
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// ── THE ORDERING BETWEEN THE TWO CLOCKS ─────────────────────────────────────
//
// This box must give up before the host does, or the host reports "did not
// answer" about a machine that is downloading happily and then discards the
// text when it arrives. It used to be two constants in two repos with a comment
// on each side asserting the relationship, and the arithmetic said the opposite
// at every size the ceiling permits. Now the host GRANTS the budget and this box
// clamps it down, so the ordering is a property of one number.
//
// These pin the three things that make that true: the grant is honoured, it is
// never extended, and the clamp EQUALS the host's own cap — so a host running
// the matching formula is never silently shortened.
func TestPullHonoursTheHostsGrant(t *testing.T) {
	// The host's budget cap, budget floor and reply allowance,
	// mirrored here because they are what this box is being held against.
	const hostBudgetMax = 240 * time.Second
	const hostBudgetBase = 30 * time.Second
	const hostReplyAllowance = 40 * time.Second

	if ctxPullMaxTimeout != hostBudgetMax {
		t.Fatalf("the clamp (%s) must EQUAL the host's PULL_BUDGET_MAX (%s): smaller "+
			"silently shortens a legitimate grant, larger lets a buggy host park a "+
			"mgmt worker past its own wait — the host's extract route",
			ctxPullMaxTimeout, hostBudgetMax)
	}
	if ctxPullDefaultTimeout != hostBudgetBase {
		t.Fatalf("a host that grants nothing must get the host's own floor (%s), got %s",
			hostBudgetBase, ctxPullDefaultTimeout)
	}

	for _, tc := range []struct {
		granted float64
		want    time.Duration
		why     string
	}{
		{0, ctxPullDefaultTimeout, "a host that grants nothing gets the floor"},
		{-5, ctxPullDefaultTimeout, "a nonsense grant gets the floor"},
		{32, 32 * time.Second, "the grant for a 1 MiB source is used as sent"},
		{158, 158 * time.Second, "the grant at the 64 MiB ceiling is used as sent"},
		{3600, ctxPullMaxTimeout, "an hour is clamped DOWN to this box's ceiling"},
	} {
		if got := ctxPullBudget(tc.granted); got != tc.want {
			t.Fatalf("%s: ctxPullBudget(%v) = %s, want %s", tc.why, tc.granted, got, tc.want)
		}
	}

	// The relationship itself, across every grant the host's formula can emit —
	// its floor, the values at 1/8/25/64 MiB, its cap, and a hostile overshoot.
	for _, granted := range []float64{0, 30, 32, 46, 80, 158, 240, 3600} {
		box := ctxPullBudget(granted)
		eff := granted
		if eff <= 0 {
			eff = float64(hostBudgetBase / time.Second)
		}
		if eff > float64(hostBudgetMax/time.Second) {
			eff = float64(hostBudgetMax / time.Second)
		}
		hostWait := time.Duration(eff*float64(time.Second)) + hostReplyAllowance
		if box >= hostWait {
			t.Fatalf("grant %.0fs: this box waits %s but the host waits %s — the host "+
				"would give up first and report a downloading machine as unresponsive",
				granted, box, hostWait)
		}
	}
}

// AND THE GRANT IS ENFORCED, not merely computed. A host that trickles bytes is
// abandoned inside the budget, with a message saying the link is slow — because
// a slow link is not a broken machine, and that sentence is the entire reason
// the budget moved to the host in the first place.
func TestPullAbandonsATrickleInsideTheGrant(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bearer-abc" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Length", "10485760")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for i := 0; i < 200; i++ { // one byte per 50 ms — far under any real link
			if _, err := w.Write([]byte{'x'}); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsCfg.ServerName = "example.com"
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig: tlsCfg,
	}}
	setCtxSourcePuller(newHostSourcePuller(c, "example.com", "bearer-abc"))
	defer setCtxSourcePuller(nil)

	var sink countingWriter
	started := time.Now()
	_, err := pullSourceInto(&sink, strings.Repeat("c", 64), 0, 700*time.Millisecond)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("a transfer that outran its grant was allowed to continue")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the grant was not enforced — the fetch ran %s against a 700ms budget", elapsed)
	}
	if !strings.Contains(err.Error(), "not a fault in this machine") {
		t.Fatalf("a slow link must not be reported as a broken machine: %q", err)
	}
	if !strings.Contains(err.Error(), "700ms") {
		t.Fatalf("the refusal must name the budget it ran past: %q", err)
	}
}

// A job whose grant the host clamped still runs end to end — the budget path
// must not change what a normal extraction does.
func TestCtxExtractPullUsesTheGrantedBudgetEndToEnd(t *testing.T) {
	setupBox(t)
	if ok, _ := probePrepTool(prepTool{Name: "pdf-text", Bin: "pdftotext", Args: []string{"-v"}}); !ok {
		t.Skip("pdftotext not installed")
	}
	h, _ := startFakeHost(t, "bearer-abc")
	doc, err := base64.StdEncoding.DecodeString(probePDFB64)
	if err != nil {
		t.Fatal(err)
	}
	tk := h.issue(doc)
	out, errOut, code := driveExtract(t, tAnchor,
		[]string{pullReqBudget(t, "pdf-text", tk, int64(len(doc)), ctxPullMaxBytes, 158)})
	if code != 0 {
		t.Fatalf("a job carrying a real grant failed: code=%d err=%s", code, errOut)
	}
	var resp ctxExtractResp
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("reply is not JSON: %v", err)
	}
	if !strings.Contains(resp.Text, probePDFText) {
		t.Fatalf("text missing from a granted-budget pull: %q", resp.Text)
	}
}

// THE DECLARED LENGTH IS VERIFIED BEFORE THE DOCUMENT IS USED. A short body
// means the transfer or the row changed under the job; extracting it anyway
// would return the text of something other than what was asked for.
func TestCtxExtractPullVerifiesTheDeclaredLength(t *testing.T) {
	setupBox(t)
	h, _ := startFakeHost(t, "bearer-abc")
	doc, err := base64.StdEncoding.DecodeString(probePDFB64)
	if err != nil {
		t.Fatal(err)
	}
	tk := h.issue(doc)
	_, errOut, code := driveExtract(t, tAnchor,
		[]string{pullReq(t, "pdf-text", tk, int64(len(doc))+99, 0)})
	if code == 0 {
		t.Fatal("a document whose length disagreed with the host's declaration was extracted")
	}
	if !contains(errOut, "nothing was extracted") {
		t.Fatalf("the refusal must say nothing was extracted: %q", errOut)
	}
}

// ONE TRANSPORT PER JOB. Both fields set means the host does not know which
// document it is asking about, and picking one for it is how the wrong bytes
// get extracted.
func TestCtxExtractRefusesBothTransportsAtOnce(t *testing.T) {
	setupBox(t)
	startFakeHost(t, "bearer-abc")
	b, err := json.Marshal(ctxExtractReq{Tool: "pdf-text", Mime: "application/pdf",
		B64: probePDFB64, Ticket: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	_, errOut, code := driveExtract(t, tAnchor, []string{string(b)})
	if code == 0 {
		t.Fatal("a job carrying both a document and a ticket was accepted")
	}
	if !contains(errOut, "never both") {
		t.Fatalf("refused for the wrong reason: %q", errOut)
	}
}

// A TICKET THAT IS NOT THE SHAPE THIS HOST MINTS IS REFUSED BEFORE A REQUEST IS
// MADE. Not defence in depth for its own sake: the value goes into a URL, and
// the cheapest way to be sure nothing else can is to accept only 64 hex
// characters.
func TestPullRefusesAMalformedTicketWithoutDialing(t *testing.T) {
	setupBox(t)
	h, _ := startFakeHost(t, "bearer-abc")
	for _, bad := range []string{"", "short", strings.Repeat("z", 64),
		"../../etc/passwd", strings.Repeat("a", 63) + "&x=1"} {
		var sink countingWriter
		if _, err := pullSourceInto(&sink, bad, 0, time.Minute); err == nil {
			t.Fatalf("ticket %q was accepted", bad)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.dialed) != 0 {
		t.Fatalf("a malformed ticket still caused %d dial(s)", len(h.dialed))
	}
}

// UNCONFIGURED IS A SETUP STATE, NEVER AN OUTAGE. Before the daemon
// wires its tunnel client there is no pull path, and saying so has to read as
// "not up yet", not as a broken document or a broken machine.
func TestPullUnconfiguredReadsAsSetup(t *testing.T) {
	setCtxSourcePuller(nil)
	var sink countingWriter
	_, err := pullSourceInto(&sink, strings.Repeat("a", 64), 0, time.Minute)
	if err == nil {
		t.Fatal("an unconfigured pull path returned success")
	}
	if !strings.Contains(err.Error(), "setup state") {
		t.Fatalf("an unconfigured lane must read as setup, not as a failure: %q", err)
	}
}

// THE BOX ADVERTISES THE TRANSPORT, so the host never hands a ticket to a build
// that could not redeem it. Advertising means "this box COULD" — the host still
// picks the transport per job.
func TestPrepScanReportsWhetherThisBoxCanPull(t *testing.T) {
	setCtxSourcePuller(nil)
	prepCache.Lock()
	prepCache.at = time.Time{}
	prepCache.Unlock()
	if _, scan := scanPrepTools(); scan.Pull {
		t.Fatal("a box with no host connection advertised that it can pull")
	}
	setCtxSourcePuller(func(ctx context.Context, ticket string) (*http.Response, error) {
		return nil, fmt.Errorf("unused")
	})
	defer setCtxSourcePuller(nil)
	// Deliberately NOT clearing the cache: the transport must be read live, or a
	// box that probed before its tunnel came up keeps telling the host to send
	// documents inline for the next ten minutes.
	if _, scan := scanPrepTools(); !scan.Pull {
		t.Fatal("the pull flag is cached with the tool probes — it must be read live")
	}
}
