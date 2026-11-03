package main

// pair_window.go: pairing a server with a Host that connects to it.
//
//	privatae-bastion pair --open [--port 8812]
//
// Run on the server. It opens a pairing window for one Host: a code, good once
// and for 15 minutes, and the door (hostdoor.go) listening for it. The person
// gives their Host this server's address and the code; the Host connects, and
// the pairing is made over that connection the same way round as every other
// pairing: this bastion is the TLS client and the HTTP client, the Host
// answers, signs this bastion's operator CSR and issues its bearer.
//
// The code is what each side proves to the other. Neither sends it: each sends
// an HMAC of it over the Host's certificate as this connection presented it,
// the Host's CA and a nonce from each side. The Host proves first, so a
// stranger who connects to the open window learns nothing it could test codes
// against; the bastion proves second, before the Host signs anything, so a
// machine that is not this server can't pair itself with the Host even if the
// Host was sent to it. A proof made on one connection is worth nothing on
// another (the certificate differs), so neither can be relayed. The code is
// 100 bits, out of reach offline; online, a wrong one costs a wait that
// doubles each time, and the fifth closes the window.
//
// Opening the window at this server is the person's say-so for one Host, so
// it is the "yes at this computer's terminal" a local machine asks before a
// second Host. Everything after the Host has proved itself is pair.go's:
// the conflict rules, pending behind the Host in charge, the anchor rules,
// the atomic save.
//
// The wire contract is docs/host-connects.md.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// windowLifetime is how long a pairing window stays open.
	windowLifetime = 15 * time.Minute
	// windowMaxFailures wrong codes close the window.
	windowMaxFailures = 5
	// windowExchangeTimeout bounds the whole pairing exchange on one connection.
	windowExchangeTimeout = 60 * time.Second
	// windowCodeLen characters of windowAlphabet: 5 bits each, 100 bits.
	windowCodeLen = 20
	// windowAlphabet is Crockford's base32: no I, L, O or U to misread.
	windowAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// windowTransport is the transport a Host answers a window redeem with.
	windowTransport = "host_dials"
	// windowProofLabel starts every proof's MAC input.
	windowProofLabel = "privatae-pair-v1 "
)

// windowFailWait is the wait after the first wrong code; it doubles with each
// one after. A variable so a test can shorten it.
var windowFailWait = time.Second

// windowPollEvery is how often `pair --open` looks for the result. A variable
// so a test can shorten it.
var windowPollEvery = 500 * time.Millisecond

// newWindowCode is a fresh code, normalised (windowCodeLen characters).
func newWindowCode() (string, error) {
	b := make([]byte, windowCodeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = windowAlphabet[int(b[i])&31] // 256 is a multiple of 32: uniform
	}
	return string(b), nil
}

// formatWindowCode is the code as the person reads it: groups of five.
func formatWindowCode(code string) string {
	var parts []string
	for i := 0; i < len(code); i += 5 {
		parts = append(parts, code[i:min(i+5, len(code))])
	}
	return strings.Join(parts, "-")
}

// normalizeWindowCode is what both sides key the proofs with: upper case, no
// dashes or spaces, O read as 0 and I or L as 1. "" when it is not a code.
func normalizeWindowCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(windowAlphabet, r) {
			return ""
		}
		b.WriteRune(r)
	}
	if b.Len() != windowCodeLen {
		return ""
	}
	return b.String()
}

// windowProof is role's proof of the code on one connection: HMAC-SHA256
// keyed by the normalised code over the label, the role, the SHA-256 of the
// Host's certificate as presented, that of its CA, and both nonces.
func windowProof(code, role string, leafSHA, caSHA, nonceB, nonceH []byte) string {
	m := hmac.New(sha256.New, []byte(code))
	m.Write([]byte(windowProofLabel + role + "\x00"))
	for _, p := range [][]byte{leafSHA, caSHA, nonceB, nonceH} {
		m.Write(p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// ── the window file ──────────────────────────────────────────────────────────

// pairWindow is <configDir>/pairing-window.json: the one open window, written
// by `pair --open`, read by whichever door serves it, which writes the result
// into it. 0600 in the bastion's own state, like the pairings' bearers.
type pairWindow struct {
	ID      string `json:"id"`
	Code    string `json:"code"`
	Door    string `json:"door"`
	Opened  string `json:"opened"`
	Expires string `json:"expires"`
	// Authority: the person who opened it held machine authority, so the
	// Host paired on it may be put in charge of a machine nobody is in charge
	// of yet (anchor_local.go anchorAfterWindow).
	Authority bool          `json:"machine_authority,omitempty"`
	Result    *windowResult `json:"result,omitempty"`
}

// windowResult is how the window ended.
type windowResult struct {
	Host       string   `json:"host,omitempty"`
	State      string   `json:"state,omitempty"`
	AdmittedBy string   `json:"admitted_by,omitempty"`
	Rotated    bool     `json:"rotated,omitempty"`
	Taken      bool     `json:"anchor_taken,omitempty"`
	Why        string   `json:"anchor_why,omitempty"`
	Replaced   string   `json:"anchor_replaced,omitempty"`
	Waiting    []string `json:"anchor_waiting,omitempty"`
	Error      string   `json:"error,omitempty"`
}

var windowFileMu sync.Mutex

func windowPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "pairing-window.json"), nil
}

func readWindowFile() *pairWindow {
	p, err := windowPath()
	if err != nil {
		return nil
	}
	return readWindowAt(p)
}

func readWindowAt(p string) *pairWindow {
	raw, err := os.ReadFile(p)
	if err != nil || len(raw) > 64<<10 {
		return nil
	}
	var w pairWindow
	if json.Unmarshal(raw, &w) != nil || w.ID == "" {
		return nil
	}
	return &w
}

// claimedWindowPath is where a door moves the window the moment it commits a
// pairing on it. The move is one rename, and so is the terminal closing the
// window (removeWindow): whichever happens first wins, across processes, so a
// window closed at the terminal never pairs, and a pairing made is never
// reported as "nothing was paired".
func claimedWindowPath() (string, error) {
	p, err := windowPath()
	return p + ".claimed", err
}

// claimWindow takes the window with this id for the pairing about to be
// saved. False when it is closed, replaced or already ended.
func claimWindow(id string) bool {
	windowFileMu.Lock()
	defer windowFileMu.Unlock()
	if !windowStillOpen(id) {
		return false
	}
	p, err := windowPath()
	if err != nil {
		return false
	}
	c := p + ".claimed"
	if os.Rename(p, c) != nil {
		return false
	}
	if w := readWindowAt(c); w == nil || w.ID != id {
		_ = os.Rename(c, p) // a newer window landed between the check and the move
		return false
	}
	return true
}

// claimedWindow is the claimed window with this id, or nil.
func claimedWindow(id string) *pairWindow {
	c, err := claimedWindowPath()
	if err != nil {
		return nil
	}
	if w := readWindowAt(c); w != nil && w.ID == id {
		return w
	}
	return nil
}

// claimedWindowUnderWay is the window a door claimed for a pairing it has not
// finished: the window file is gone (claimWindow) and the pairing may not be
// saved yet, so neither reads as the door being in use, but it is. Bounded:
// a claim is made before the window expires and its exchange ends within
// windowExchangeTimeout, so a claimed file a killed process left behind
// stops counting then.
func claimedWindowUnderWay(now time.Time) *pairWindow {
	c, err := claimedWindowPath()
	if err != nil {
		return nil
	}
	w := readWindowAt(c)
	if w == nil || w.Result != nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339, w.Expires)
	if err != nil || !now.Before(t.Add(windowExchangeTimeout)) {
		return nil
	}
	return w
}

func (w *pairWindow) expired(now time.Time) bool {
	t, err := time.Parse(time.RFC3339, w.Expires)
	return err != nil || !now.Before(t)
}

// loadOpenWindow is the window a door may serve now: present, not expired,
// not ended, with a usable code.
func loadOpenWindow() *pairWindow {
	w := readWindowFile()
	if w == nil || w.Result != nil || w.expired(time.Now()) || normalizeWindowCode(w.Code) != w.Code {
		return nil
	}
	return w
}

func saveWindowFile(w *pairWindow) error {
	p, err := windowPath()
	if err != nil {
		return err
	}
	return writeWindowAt(p, w)
}

func writeWindowAt(p string, w *pairWindow) error {
	raw, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// endWindow writes the result into the window, if it is still the one with
// this id (a newer `pair --open` replaces it).
func endWindow(id string, res windowResult) {
	windowFileMu.Lock()
	defer windowFileMu.Unlock()
	if w := claimedWindow(id); w != nil {
		if w.Result == nil {
			w.Result = &res
			if c, err := claimedWindowPath(); err == nil {
				_ = writeWindowAt(c, w)
			}
		}
		return
	}
	w := readWindowFile()
	if w == nil || w.ID != id || w.Result != nil {
		return
	}
	w.Result = &res
	_ = saveWindowFile(w)
}

// removeWindow closes the window with this id: its file is removed, unless a
// door claimed it first (claimWindow), which removeWindow reports.
func removeWindow(id string) (claimed bool) {
	windowFileMu.Lock()
	defer windowFileMu.Unlock()
	if w := readWindowFile(); w != nil && w.ID == id {
		if p, err := windowPath(); err == nil && os.Remove(p) == nil {
			return false
		}
	}
	return claimedWindow(id) != nil
}

// awaitClaimedResult waits, at most an exchange's length, for the result of a
// pairing a door claimed the window for, and clears the claimed file.
func awaitClaimedResult(id string) *windowResult {
	deadline := time.Now().Add(windowExchangeTimeout)
	for time.Now().Before(deadline) {
		if w := claimedWindow(id); w == nil || w.Result != nil {
			if c, err := claimedWindowPath(); err == nil && w != nil {
				_ = os.Remove(c)
			}
			if w == nil {
				return nil
			}
			return w.Result
		}
		time.Sleep(windowPollEvery)
	}
	return &windowResult{Error: "a pairing was under way when the window closed, and it did not finish; run `privatae-bastion status` to see whether the Host was paired"}
}

// ── the door's side of a window ──────────────────────────────────────────────

// windowState is what a door knows of the window it serves: its wrong codes
// and the wait they cost, and whether a pairing is under way on it.
type windowState struct {
	id       string
	failures int
	next     time.Time
	busy     bool
}

// openWindow is the window this door offers pairing on now, or nil: none
// open, another door's, a pairing already under way on it, or a wrong code's
// wait not yet over.
func (d *hostDoor) openWindow() *pairWindow {
	w := loadOpenWindow()
	if w == nil || w.Door != d.addr {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.win.id != w.ID {
		d.win = windowState{id: w.ID}
	}
	if d.win.busy || d.win.failures >= windowMaxFailures || time.Now().Before(d.win.next) {
		return nil
	}
	return w
}

// windowBegin starts the pairing on the window, if it may still start: the
// window still open in its file (not closed at the terminal, ended or
// expired since the connection came in), no pairing under way on it, and no
// wrong code's wait or window-closing wrong code since that connection was
// offered it. Several connections can be in their handshake at once; each is
// asked here again.
func (d *hostDoor) windowBegin(w *pairWindow) bool {
	if !windowStillOpen(w.ID) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.win.id != w.ID || d.win.busy || d.win.failures >= windowMaxFailures || time.Now().Before(d.win.next) {
		return false
	}
	d.win.busy = true
	return true
}

// windowStillOpen: the window with this id is the open one.
func windowStillOpen(id string) bool {
	cur := loadOpenWindow()
	return cur != nil && cur.ID == id
}

func (d *hostDoor) windowEnd() {
	d.mu.Lock()
	d.win.busy = false
	d.mu.Unlock()
}

// windowFailed counts a wrong code: a wait of 1, 2, 4, 8 s before the next
// try, and the fifth closes the window.
func (d *hostDoor) windowFailed(w *pairWindow, src string) {
	d.mu.Lock()
	d.win.failures++
	n := d.win.failures
	d.win.next = time.Now().Add(time.Duration(1<<(n-1)) * windowFailWait)
	d.mu.Unlock()
	pairingAudit("window_wrong_code", src, fmt.Sprintf("refused: a wrong pairing code (%d of %d)", n, windowMaxFailures))
	if n >= windowMaxFailures {
		endWindow(w.ID, windowResult{Error: fmt.Sprintf("the window closed after %d wrong codes; nothing was paired", n)})
		pairingAudit("window_closed", d.addr, "closed after too many wrong codes")
	}
}

// The messages of a pairing exchange (docs/host-connects.md).
type windowHelloReq struct {
	V     int    `json:"v"`
	Nonce string `json:"nonce"`
}

type windowHelloResp struct {
	V          int    `json:"v"`
	HostHandle string `json:"host_handle"`
	HostName   string `json:"host_name"`
	Nonce      string `json:"nonce"`
	Proof      string `json:"proof"`
	Error      string `json:"error"`
}

type windowRedeemReq struct {
	V           int    `json:"v"`
	Proof       string `json:"proof"`
	WGPublicKey string `json:"wg_public_key"`
	OperatorCSR string `json:"operator_csr"`
	Hostname    string `json:"hostname"`
	Platform    string `json:"platform"`
	Handle      string `json:"handle"`
}

type windowDoneReq struct {
	V          int    `json:"v"`
	State      string `json:"state"`
	HostName   string `json:"host_name,omitempty"`
	AdmittedBy string `json:"admitted_by,omitempty"`
	Error      string `json:"error,omitempty"`
}

// oneConnClient is an HTTP client whose every request goes over tc, and over
// nothing else: no proxy, no redirect, no second connection.
func oneConnClient(tc *tls.Conn) *http.Client {
	var mu sync.Mutex
	used := false
	tr := &http.Transport{
		Proxy: nil, MaxConnsPerHost: 1, DisableCompression: true,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			if used {
				return nil, errors.New("the Host closed the pairing connection")
			}
			used = true
			return tc, nil
		},
	}
	return &http.Client{Transport: tr, Timeout: windowExchangeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// windowPost POSTs one message of the exchange and decodes the answer (into
// out, when it is not nil).
func windowPost(c *http.Client, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	resp, err := c.Post("https://"+tcpServerName+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rb, &e)
		if e.Error != "" {
			return fmt.Errorf("the Host refused: %s", e.Error)
		}
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(rb, out); err != nil {
		return fmt.Errorf("%s: the Host's answer is not JSON", path)
	}
	return nil
}

// serveWindow is a pairing on the window, over the connection the Host
// opened. ca is the CA its chain carried (chainCA).
func (d *hostDoor) serveWindow(tc *tls.Conn, w *pairWindow, ca *x509.Certificate, src string) {
	defer tc.Close()
	if !d.windowBegin(w) {
		return
	}
	defer d.windowEnd()
	_ = tc.SetDeadline(time.Now().Add(windowExchangeTimeout))
	cs := tc.ConnectionState()
	leaf := sha256.Sum256(cs.PeerCertificates[0].Raw)
	caSum := sha256.Sum256(ca.Raw)
	c := oneConnClient(tc)
	nb := make([]byte, 32)
	if _, err := rand.Read(nb); err != nil {
		return
	}
	var hello windowHelloResp
	if err := windowPost(c, "/v1/pair/hello", windowHelloReq{V: 1, Nonce: hex.EncodeToString(nb)}, &hello); err != nil {
		pairingAudit("window_failed", src, "refused: "+err.Error())
		return
	}
	nh, err := hex.DecodeString(hello.Nonce)
	if err != nil || len(nh) != 32 {
		pairingAudit("window_failed", src, "refused: the Host's hello carries no 32-byte nonce")
		return
	}
	want := windowProof(w.Code, "host", leaf[:], caSum[:], nb, nh)
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(hello.Proof))) {
		d.windowFailed(w, src)
		return
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	cfg, res := windowCommit(c, w, hello, caPEM, func() string { return windowProof(w.Code, "bastion", leaf[:], caSum[:], nb, nh) })
	done := windowDoneReq{V: 1, State: res.State, HostName: res.Host, AdmittedBy: res.AdmittedBy}
	if res.Error != "" {
		done = windowDoneReq{V: 1, State: "refused", Error: res.Error}
	}
	_ = windowPost(c, "/v1/pair/done", done, nil)
	endWindow(w.ID, res)
	if cfg == nil {
		pairingAudit("window_refused", firstNonEmpty(firstNonEmpty(hello.HostName, hello.HostHandle), src), "refused: "+res.Error)
		return
	}
	// Its lane connections follow from the same address: they count as a
	// known Host's from the first (admitHandshake).
	doorRememberHost(sourceKey(src), time.Now())
	pairingAudit("window_paired", cfg.HostName, fmt.Sprintf("ok: paired through the window from %s, %s; it connects to this server on %s",
		src, cfg.stateName(), cfg.doorAddr()))
}

// windowCommit is the pairing once the Host has proved the code: pair.go's
// rules, the redeem with this bastion's proof, the checks and the save.
// bastionProof makes the proof the redeem carries.
func windowCommit(c *http.Client, w *pairWindow, hello windowHelloResp, hostCA string, bastionProof func() string) (*Config, windowResult) {
	refuse := func(err error) (*Config, windowResult) { return nil, windowResult{Error: err.Error()} }
	handle := hello.HostHandle
	if !validHostName(handle) {
		return refuse(fmt.Errorf("the Host named itself %q, which is not a name this bastion keeps", handle))
	}
	if err := singletonGuardForPair(); err != nil {
		return refuse(err)
	}
	cfgs, err := loadPairings()
	if err != nil {
		return refuse(err)
	}
	wantCA := caSHA256(hostCA)
	replace := false
	// The same Host pairing this server again through a fresh window: a Host
	// whose connection presented the CA a pairing here already pins (its
	// certificate verified under it, chainCA) is that pairing's Host, whatever
	// handle it gives. Opening the window is the person's say-so to give it
	// new credentials, so this replaces the pairing in place, its state, its
	// anchor and its grants kept, with no `unpair` first.
	key := handle
	if same := doorPairingWithCA(cfgs, hostCA); same != nil {
		key = same.HostName
	}
	existing, state, err := pairPrecheck(cfgs, key, false, false)
	var already *alreadyPairedError
	if errors.As(err, &already) {
		// The same Host, its CA unchanged, through a window opened here: the
		// person's say-so to give it new credentials.
		if refusal := sameNameOtherHost(pairingFor(cfgs, key), wantCA); refusal != nil {
			return refuse(refusal)
		}
		replace = true
		existing, state, err = pairPrecheck(cfgs, key, true, false)
	}
	var second *localSecondHostError
	if errors.As(err, &second) {
		// Opening the window at this computer is the yes the terminal asks.
		existing, state, err = pairPrecheckState(false, handle)
	}
	if err != nil {
		return refuse(err)
	}
	if err := replaceKeepsTransport(existing, transportTCP); err != nil {
		return refuse(err)
	}
	if err := tcpPinRefusal(existing, hostCA); err != nil {
		return refuse(err)
	}
	if err := doorCARefusal(cfgs, existing, hostCA); err != nil {
		return refuse(err)
	}
	wgPriv, wgPub, err := genWGKeypair()
	if err != nil {
		return refuse(err)
	}
	fp, err := genSecret(20)
	if err != nil {
		return refuse(err)
	}
	opKey, opCSR, err := genOperatorCSR(fp, true)
	if err != nil {
		return refuse(err)
	}
	// The person may have closed the window at the terminal, or it expired,
	// during the exchange: the Host signs nothing then.
	if !windowStillOpen(w.ID) {
		return refuse(errors.New("the pairing window closed before the pairing finished; nothing was paired"))
	}
	hn, _ := os.Hostname()
	var rr tcpRedeemResp
	if err := windowPost(c, "/v1/pair/redeem", windowRedeemReq{V: 1, Proof: bastionProof(), WGPublicKey: wgPub,
		OperatorCSR: opCSR, Hostname: hn, Platform: runtime.GOOS, Handle: handle}, &rr); err != nil {
		return refuse(err)
	}
	if err := windowAnswerRefusal(rr, hostCA, opKey); err != nil {
		return refuse(err)
	}
	// The redeemed name is authoritative, as on every other path.
	if prev := pairingFor(cfgs, rr.hostName()); prev != nil && (existing == nil || prev.HostName != existing.HostName) {
		if refusal := sameNameOtherHost(prev, wantCA); refusal != nil {
			return refuse(refusal)
		}
		if err := replaceKeepsTransport(prev, transportTCP); err != nil {
			return refuse(err)
		}
		existing, replace = prev, true
		if prev.State == pairingRevoked {
			state = pairingPending
		} else {
			state = prev.State
		}
	}
	rr.LaneAddress = ""
	cfg, err := tcpPairingConfig(rr, cfgs, existing, replace, wgPriv, opKey, fp, hostCA)
	if err != nil {
		return refuse(err)
	}
	cfg.HostDials, cfg.DoorAddr, cfg.LaneAddr = true, w.Door, ""
	if !claimWindow(w.ID) {
		return refuse(errors.New("the pairing window closed before the pairing finished; nothing was paired"))
	}
	cfg, all, err := commitPairing(cfg, existing, replace, state)
	if err != nil {
		return refuse(err)
	}
	if err := carryAnchorToNewName(existing, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	took, aerr := anchorAfterWindow(cfg, all, w.Authority)
	if aerr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", aerr)
	}
	if took.Taken {
		if fresh, lerr := loadPairings(); lerr == nil {
			if c := pairingFor(fresh, cfg.HostName); c != nil {
				cfg = c
			}
		}
	}
	res := windowResult{Host: cfg.HostName, State: cfg.stateName(), Rotated: replace,
		Taken: took.Taken, Why: took.Why, Replaced: took.Replaced, Waiting: took.Waiting}
	if !cfg.active() {
		res.AdmittedBy = admitter()
	}
	return cfg, res
}

// windowAnswerRefusal checks a Host's redeem answer before anything is saved:
// the window's transport, every field, a name that can be a file name, the CA
// the one its connection presented, the operator certificate ours.
func windowAnswerRefusal(rr tcpRedeemResp, hostCA, opKey string) error {
	if rr.Transport != windowTransport {
		return fmt.Errorf("the Host answered transport %q; a Host that connects to this server answers %q", rr.Transport, windowTransport)
	}
	for k, v := range map[string]string{"operator_cert": rr.operatorCert(), "ca_cert": rr.caCert(), "bearer": rr.Bearer,
		"host_name": rr.hostName()} {
		if v == "" {
			return fmt.Errorf("redeem response missing %s", k)
		}
	}
	if !validHostName(rr.hostName()) {
		return fmt.Errorf("redeem response has an unsafe host name %q — refusing", rr.hostName())
	}
	if !sameCAs(rr.caCert(), hostCA) {
		return errors.New("the Host answered with a CA other than the one its connection presented — refusing")
	}
	return operatorCertRefusal(rr.operatorCert(), hostCA, opKey)
}

// carryAnchorToNewName: the anchor's Host paired again through a window under
// another name, its CA the one the anchor's pairing pinned (doorPairingWithCA),
// so it is the same Host and stays in charge under its new name, its pinned
// verify key kept, as claim-anchor --repin does for a renamed anchor. Every
// other case leaves the anchor as it is, and so does a process without
// machine authority (every anchor write needs it, claim-anchor --repin's too).
func carryAnchorToNewName(existing, cfg *Config) error {
	if existing == nil || cfg == nil || existing.HostName == cfg.HostName || !sameCAs(existing.CACert, cfg.CACert) {
		return nil
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != existing.HostName {
		return nil
	}
	if !machineAuthorityHeld() {
		return fmt.Errorf("%s was in charge of this machine as %s; moving that to its new name needs machine authority: `privatae-bastion claim-anchor --repin` (%s)",
			cfg.HostName, existing.HostName, adminHowTo())
	}
	a := currentAnchor()
	if a == nil || a.AnchorHost != existing.HostName {
		return nil
	}
	f, err := loadAnchorFile()
	if err != nil || f == nil {
		return err
	}
	owner := a.Owner
	if oc := currentOwnerClaim(); oc != nil && oc.Owner != "" {
		owner = oc.Owner
	}
	if err := writeAnchorPreservingPin(owner, cfg.HostName, f.VerifyPubkey); err != nil {
		return fmt.Errorf("%s was in charge of this machine as %s, and moving that to its new name failed: %w", cfg.HostName, existing.HostName, err)
	}
	pairingAudit("anchor_rename", cfg.HostName, "ok: in charge of this machine as before, now under this name (it was "+existing.HostName+")")
	return nil
}

// doorPairingWithCA is the pairing whose Host connects to this server and
// whose pinned CA is hostCA, or nil.
func doorPairingWithCA(cfgs []*Config, hostCA string) *Config {
	for _, o := range cfgs {
		if o.hostDials() && sameCAs(o.CACert, hostCA) {
			return o
		}
	}
	return nil
}

// doorCARefusal: two pairings whose Hosts connect to this server never pin
// the same CA, because the CA is how the door tells their connections apart.
func doorCARefusal(cfgs []*Config, existing *Config, hostCA string) error {
	for _, o := range cfgs {
		if existing != nil && o.HostName == existing.HostName {
			continue
		}
		if o.hostDials() && sameCAs(o.CACert, hostCA) {
			return fmt.Errorf("this Host is already paired with this server as %s; nothing was paired", o.HostName)
		}
	}
	return nil
}

// ── pair --open ──────────────────────────────────────────────────────────────

// parsePairOpenArgs reads `pair --open [--port N]`. ok is false when the
// arguments are not a --open pair at all.
func parsePairOpenArgs(args []string) (addr string, ok bool, err error) {
	port := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--open":
			ok = true
		case args[i] == "--port" && i+1 < len(args):
			port = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--port="):
			port = strings.TrimPrefix(args[i], "--port=")
		default:
			if ok {
				return "", true, fmt.Errorf("pair --open takes only --port <port>, not %s", args[i])
			}
		}
	}
	if !ok {
		return "", false, nil
	}
	if port == "" {
		return doorDefaultAddr, true, nil
	}
	var n int
	if _, err := fmt.Sscanf(port, "%d", &n); err != nil || n < 1 || n > 65535 || fmt.Sprint(n) != port {
		return "", true, fmt.Errorf("--port %q is not a port", port)
	}
	return ":" + port, true, nil
}

// cmdPairOpen opens the window, says what to give the Host, and waits for it.
func cmdPairOpen(addr string, out io.Writer) error {
	if err := singletonGuardForPair(); err != nil {
		return err
	}
	if _, err := loadPairings(); err != nil {
		return err
	}
	code, err := newWindowCode()
	if err != nil {
		return err
	}
	id, err := genSecret(9)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	w := &pairWindow{ID: id, Code: code, Door: addr, Opened: now.Format(time.RFC3339),
		Expires: now.Add(windowLifetime).Format(time.RFC3339), Authority: machineAuthorityHeld()}
	// A door of this window's own, unless the running bastion's door holds the
	// port: it serves the window then (it reads this file on every connection).
	ln, lerr := listenDoor(addr)
	if lerr != nil && pairDaemonRunning() && !doorHeldByRunningBastion(addr) {
		// The running bastion may still hold the port for a pairing just
		// removed (`unpair`): it lets go once it sees the file gone, within a
		// supervision period. Wait for that rather than fail.
		ln, lerr = awaitDoorReleased(addr, out)
	}
	if lerr != nil && !(pairDaemonRunning() && doorHeldByRunningBastion(addr)) {
		return fmt.Errorf("cannot listen on port %s: %v. Another program holds it; choose another with --port", doorPort(addr), lerr)
	}
	windowFileMu.Lock()
	err = saveWindowFile(w)
	windowFileMu.Unlock()
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return err
	}
	// The way in through this machine's own firewall, while the window is
	// open (doorfw.go). Released last, once the window file is gone: it stays
	// if the pairing made here is active, as the daemon's door then serves it.
	fwSaid := doorFirewallEnsure(addr)
	defer doorFirewallRelease(addr)
	// closed closes the window and says how it ended: a pairing a door had
	// already claimed it for is reported, never "nothing was paired".
	closed := func(why string, err error) error {
		if removeWindow(id) {
			if res := awaitClaimedResult(id); res != nil {
				return reportWindow(out, res)
			}
		}
		pairingAudit("window_closed", addr, why)
		return err
	}
	defer removeWindow(id)
	if ln != nil {
		d := newHostDoor(addr, false)
		go d.serve(ln)
		defer ln.Close()
	}
	pairingAudit("window_opened", addr, "ok: a pairing window for one Host until "+w.Expires)
	printWindow(out, w, fwSaid)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	tick := time.NewTicker(windowPollEvery)
	defer tick.Stop()
	for {
		select {
		case <-sig:
			return closed("closed by the person at this server", errors.New("the pairing window is closed; nothing was paired"))
		case <-tick.C:
		}
		if claimedWindow(id) != nil {
			if res := awaitClaimedResult(id); res != nil {
				return reportWindow(out, res)
			}
		}
		cur := readWindowFile()
		if cur == nil || cur.ID != id {
			return errors.New("another pairing window was opened on this server, so this one is closed; nothing was paired here")
		}
		if cur.Result != nil {
			return reportWindow(out, cur.Result)
		}
		if cur.expired(time.Now()) {
			return closed("closed after "+windowLifetime.String(), fmt.Errorf("the pairing window closed after %d minutes and nothing was paired. Run `privatae-bastion pair --open` again when your Host is ready", int(windowLifetime.Minutes())))
		}
	}
}

// doorReleaseWait is how long `pair --open` waits for the running bastion to
// let go of the door's port after its last pairing there was removed: a
// supervision period for it to see that (run.go superviseOnce), and the
// pairing's stop. A variable so a test can shorten it.
var doorReleaseWait = supervisePeriod + 10*time.Second

// awaitDoorReleased binds addr once the running bastion lets go of it, or
// returns the last bind error after doorReleaseWait. Only an address in use
// is waited for; any other error is returned at once.
func awaitDoorReleased(addr string, out io.Writer) (net.Listener, error) {
	deadline := time.Now().Add(doorReleaseWait)
	said := false
	for {
		ln, err := listenDoor(addr)
		if err == nil || !addrInUse(err) || !time.Now().Before(deadline) {
			return ln, err
		}
		if !said {
			fmt.Fprintf(out, "Port %s is in use, most likely by the bastion running here for a pairing that was removed; waiting for it to let go (at most %d seconds)...\n",
				doorPort(addr), int(doorReleaseWait.Seconds()))
			said = true
		}
		time.Sleep(doorReleasePoll)
	}
}

// addrInUse: err is a bind refused because the address is in use (Windows
// says so as WSAEADDRINUSE, 10048).
func addrInUse(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == syscall.EADDRINUSE || uintptr(errno) == 10048)
}

// doorReleasePoll is how often awaitDoorReleased tries the port again.
var doorReleasePoll = 250 * time.Millisecond

// doorHeldByRunningBastion: a pairing served here has its Host connect on
// addr, so the running bastion's door is what holds the port.
func doorHeldByRunningBastion(addr string) bool {
	cfgs, err := loadPairings()
	if err != nil {
		return false
	}
	for _, c := range cfgs {
		if c.hostDials() && c.active() && c.doorAddr() == addr {
			return true
		}
	}
	return false
}

// printWindow says, in the person's words, what to give their Host.
func printWindow(out io.Writer, w *pairWindow, fwSaid string) {
	port := doorPort(w.Door)
	fmt.Fprintf(out, "Your Host connects to this server. On your Host, choose \"Add a server\" and give it:\n\n")
	fmt.Fprintf(out, "  address:  this server's address, port %s\n", port)
	if addrs := machineAddrs(); len(addrs) > 0 {
		fmt.Fprintf(out, "            (this server's own addresses: %s - use the one your Host can reach)\n", strings.Join(addrs, ", "))
	}
	fmt.Fprintf(out, "  code:     %s\n\n", formatWindowCode(w.Code))
	fmt.Fprintf(out, "The code works once, for %d minutes. Nothing on your Host's network needs opening;\n", int(windowLifetime.Minutes()))
	fmt.Fprintf(out, "this server needs TCP port %s reachable from the internet.\n", port)
	if fwSaid != "" {
		fmt.Fprintln(out, fwSaid)
	}
	fmt.Fprintf(out, "Waiting for your Host... (Ctrl-C closes the window)\n")
}

// machineAddrs is this machine's own non-loopback unicast addresses.
func machineAddrs() []string {
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range ifs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsMulticast() {
			continue
		}
		out = append(out, ipn.IP.String())
		if len(out) == 6 {
			break
		}
	}
	return out
}

// reportWindow prints how the window ended: the pairing as `pair` reports
// one, or why nothing was paired.
func reportWindow(out io.Writer, res *windowResult) error {
	if res.Error != "" {
		return errors.New(res.Error)
	}
	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	cfg := pairingFor(cfgs, res.Host)
	if cfg == nil {
		return fmt.Errorf("the window reported %s paired, but no pairing for it is on this server", res.Host)
	}
	fmt.Fprintln(out)
	pairReport(out, cfg, cfgs, anchorTake{Taken: res.Taken, Why: res.Why, Replaced: res.Replaced, Waiting: res.Waiting})
	return nil
}
