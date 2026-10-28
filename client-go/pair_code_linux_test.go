//go:build linux

// The pairing code a Cloud Host's card hands out (pair_code.go): one string
// carrying the token, the enroll address and the Host CA's fingerprint, and
// the question a local machine asks before it serves a second Host
// (pair_terminal.go).
//
// Uses the fixtures of local_host_linux_test.go and local_host_tcp_linux_test.go
// (newTestCA, pairingBox, startTCPEnrollHost, homeToken), so it carries the same
// build tag.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// makePairCode builds a code the way a Host's card does: skp_ and base64url,
// no padding, of the JSON object fields.
func makePairCode(t *testing.T, fields map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return pairCodePrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func pairCodeFingerprint(ca *testCA) string {
	sum := sha256.Sum256(ca.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// chainWithCA is the enroll port's certificate as a Host from this release
// serves it: the leaf, then the CA.
func chainWithCA(t *testing.T, ca *testCA) tls.Certificate {
	t.Helper()
	c := ca.serverCert(t, tcpServerName)
	c.Certificate = append(c.Certificate, ca.cert.Raw)
	return c
}

func goodCodeFields(url, fp string) map[string]any {
	return map[string]any{"v": 1, "u": url, "ca": fp, "t": homeToken()}
}

// ── decoding ────────────────────────────────────────────────────────────────

func TestAPairingCodeDecodes(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	code := makePairCode(t, goodCodeFields("https://maple.example-id.cloud.example:8810/v1/local/redeem", fp))
	pc, err := decodePairCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if pc.RedeemURL != "https://maple.example-id.cloud.example:8810/v1/local/redeem" || pc.CASHA256 != fp || pc.Token != homeToken() {
		t.Fatalf("decoded: %+v", pc)
	}
	token, opts, err := pairOptsFor(code, "", "", false)
	if err != nil || token != homeToken() || opts.redeemURL != pc.RedeemURL || opts.caSHA256 != fp || opts.hostCAFile != "" || opts.askSecond == nil {
		t.Fatalf("pair's options from a code: %q %+v %v", token, opts, err)
	}
	if _, _, err := pairOptsFor(code, "", "host-ca.pem", false); err == nil {
		t.Fatal("a code carries its own certificate: --host-ca beside it must be refused")
	}
	if tok, opts, err := pairOptsFor(homeToken(), "", "", false); err != nil || tok != homeToken() || opts.caSHA256 != "" {
		t.Fatalf("a bare token passes through as it was: %q %+v %v", tok, opts, err)
	}
}

// A code this bastion cannot read is refused with what was wrong, never
// with its content: a log of a failed install must not hold the token.
func TestAPairingCodeIsReadStrictly(t *testing.T) {
	fp := strings.Repeat("0f", 32)
	u := "https://maple.example-id.cloud.example:8810/v1/local/redeem"
	with := func(edit func(m map[string]any)) string {
		m := goodCodeFields(u, fp)
		edit(m)
		return makePairCode(t, m)
	}
	for name, code := range map[string]string{
		"garbled":           "skp_%%%not-base64%%%",
		"not JSON":          pairCodePrefix + base64.RawURLEncoding.EncodeToString([]byte("secret-x home")),
		"wrong version":     with(func(m map[string]any) { m["v"] = 2 }),
		"version as text":   with(func(m map[string]any) { m["v"] = "1" }),
		"extra key":         with(func(m map[string]any) { m["x"] = "y" }),
		"missing key":       with(func(m map[string]any) { delete(m, "ca") }),
		"another key":       with(func(m map[string]any) { delete(m, "t"); m["token"] = homeToken() }),
		"http address":      with(func(m map[string]any) { m["u"] = "http://maple.example-id.cloud.example:8810/v1/local/redeem" }),
		"address with user": with(func(m map[string]any) { m["u"] = "https://a@maple.example-id.cloud.example/v1/local/redeem" }),
		"short fingerprint": with(func(m map[string]any) { m["ca"] = fp[:63] }),
		"upper fingerprint": with(func(m map[string]any) { m["ca"] = strings.ToUpper(fp) }),
		"not hex":           with(func(m map[string]any) { m["ca"] = strings.Repeat("zz", 32) }),
		"no skb_ token":     with(func(m map[string]any) { m["t"] = "secret-x" }),
		"malformed token":   with(func(m map[string]any) { m["t"] = "skb_bm9kb3Q" }), // base64url("nodot")
	} {
		_, err := decodePairCode(code)
		if err == nil {
			t.Errorf("%s: refused nothing", name)
			continue
		}
		if strings.Contains(err.Error(), "secret-x") || strings.Contains(err.Error(), homeToken()) {
			t.Errorf("%s: the refusal repeats the token: %v", name, err)
		}
	}
	_, err := decodePairCode(with(func(m map[string]any) { m["v"] = 2 }))
	if err == nil || !strings.Contains(err.Error(), "update the bastion") {
		t.Fatalf("a newer code says to update the bastion: %v", err)
	}
}

// ── the pinned CA ───────────────────────────────────────────────────────────

// SECURITY: the CA is taken from the enroll port's chain only when its
// SHA-256 is the code's, and the port's own certificate must verify under it
// for tcpServerName. A chain without the CA, another CA, or a leaf another CA
// signed are refused before the token is spent, and nothing is saved.
func TestAPairingCodePinsTheHostCAByFingerprint(t *testing.T) {
	ca := newTestCA(t, "maple host CA")
	impostor := newTestCA(t, "impostor")
	leafByImpostor := impostor.serverCert(t, tcpServerName)
	leafByImpostor.Certificate = append(leafByImpostor.Certificate, ca.cert.Raw)
	for name, c := range map[string]struct {
		serve tls.Certificate
		fp    string
		want  string
	}{
		"no CA in the chain":       {ca.serverCert(t, tcpServerName), pairCodeFingerprint(ca), "did not present"},
		"another CA in the chain":  {chainWithCA(t, impostor), pairCodeFingerprint(ca), "other than"},
		"another fingerprint":      {chainWithCA(t, ca), pairCodeFingerprint(impostor), "other than"},
		"a leaf another CA signed": {leafByImpostor, pairCodeFingerprint(ca), "not signed by"},
		"the CA, under another name": {func() tls.Certificate {
			c := ca.serverCert(t, "maple.example")
			c.Certificate = append(c.Certificate, ca.cert.Raw)
			return c
		}(), pairCodeFingerprint(ca), "not signed by"},
	} {
		t.Run(name, func(t *testing.T) {
			pairingBox(t)
			h := startTCPEnrollHost(t, ca, c.serve, "127.0.0.1:18821")
			token, opts, err := pairOptsFor(makePairCode(t, goodCodeFields(h.url, c.fp)), "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = pairWith(token, opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a refusal naming %q, got %v", c.want, err)
			}
			if h.hits.Load() != 0 {
				t.Fatal("the token went to an enroll port whose CA was never checked")
			}
			if cfgs, _ := loadPairings(); len(cfgs) != 0 {
				t.Fatalf("a refused pairing saved %d pairings", len(cfgs))
			}
		})
	}
}

// A good code pairs exactly as --redeem-url u --host-ca <that CA> t does: the
// same TCP pairing, the same CA pinned.
func TestAPairingCodePairsAsTheHostCAFileDoes(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "maple host CA")
	h := startTCPEnrollHost(t, ca, chainWithCA(t, ca), "127.0.0.1:18822")
	token, opts, err := pairOptsFor(makePairCode(t, goodCodeFields(h.url, pairCodeFingerprint(ca))), "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := pairWith(token, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.tcpTransport() || !sameCAs(cfg.CACert, ca.pem) || cfg.LaneAddr != "127.0.0.1:18822" || cfg.HostName != "home.example.test" {
		t.Fatalf("the pairing: transport %q lane %q host %q", cfg.Transport, cfg.LaneAddr, cfg.HostName)
	}
	h.mu.Lock()
	req, sni := h.last, h.sni
	h.mu.Unlock()
	if req.Secret != "secret-x" || req.Handle != "home" || sni != tcpServerName {
		t.Fatalf("the redeem is today's: secret %q handle %q sni %q", req.Secret, req.Handle, sni)
	}

	// The same code again: already paired with this Host, nothing changed,
	// and the error is the one `pair` exits 3 on.
	before, _ := os.ReadFile(filepath.Join(mustPairingsDir(t), "home.example.test.json"))
	token, opts, _ = pairOptsFor(makePairCode(t, goodCodeFields(h.url, pairCodeFingerprint(ca))), "", "", false)
	_, _, err = pairWith(token, opts)
	var already *alreadyPairedError
	if !errors.As(err, &already) {
		t.Fatalf("pairing the same Host again must be alreadyPairedError (exit %d), got %v", pairExitAlreadyPaired, err)
	}
	after, _ := os.ReadFile(filepath.Join(mustPairingsDir(t), "home.example.test.json"))
	if string(before) != string(after) || h.hits.Load() != 1 {
		t.Fatal("an already-paired Host must change nothing and spend no token")
	}

	// Another Host of the same name (Cloud names repeat): a different CA, so
	// never "already connected".
	other := newTestCA(t, "another maple")
	h2 := startTCPEnrollHost(t, other, chainWithCA(t, other), "127.0.0.1:18823")
	token, opts, _ = pairOptsFor(makePairCode(t, goodCodeFields(h2.url, pairCodeFingerprint(other))), "", "", false)
	_, _, err = pairWith(token, opts)
	if err == nil || errors.As(err, &already) || !strings.Contains(err.Error(), "different Host named") {
		t.Fatalf("a same-named Host under another CA is a plain refusal, not exit 3: %v", err)
	}
}

func mustPairingsDir(t *testing.T) string {
	t.Helper()
	d, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// ── an enroll port that does not answer ─────────────────────────────────────

// A Cloud Host's pairing port drops every address but the one the card opened
// it to. A pair from elsewhere says so within pairAnswerTimeout, in plain
// words, instead of waiting for the system's connect timeout. Both the code
// and --host-ca paths.
func TestAnEnrollPortThatDoesNotAnswerNamesThePairingWindow(t *testing.T) {
	pairingBox(t)
	oldTimeout, oldDial := pairAnswerTimeout, pairDial
	t.Cleanup(func() { pairAnswerTimeout, pairDial = oldTimeout, oldDial })
	pairAnswerTimeout = 150 * time.Millisecond
	pairDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	u := "https://maple.example-id.cloud.example:8810/v1/local/redeem"
	ca := newTestCA(t, "maple host CA")
	check := func(name string, err error, took time.Duration) {
		t.Helper()
		var we *pairWindowError
		if !errors.As(err, &we) {
			t.Fatalf("%s: want the pairing-window message, got %v", name, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "maple.example-id.cloud.example's pairing port didn't answer") ||
			!strings.Contains(msg, "15 minutes") || !strings.Contains(msg, "another network") || !strings.Contains(msg, "Nothing was paired") {
			t.Fatalf("%s: the message: %s", name, msg)
		}
		if took > 2*time.Second {
			t.Fatalf("%s: took %s, the timeout is %s", name, took, pairAnswerTimeout)
		}
	}
	start := time.Now()
	token, opts, _ := pairOptsFor(makePairCode(t, goodCodeFields(u, pairCodeFingerprint(ca))), "", "", false)
	_, _, err := pairWith(token, opts)
	check("pairing code", err, time.Since(start))

	start = time.Now()
	_, _, err = pairWithTokenVia(homeToken(), u, writeCA(t, ca), false, false)
	check("--host-ca", err, time.Since(start))
}

// ── a local machine that already serves a Host ──────────────────────────────

// fakeTerminal stands in a person at this machine: their answer, and what
// the question said. answer "" with noTerm set is a run with no terminal.
type fakeTerminal struct {
	answer string
	noTerm bool
	asked  strings.Builder
	opened int
}

func (f *fakeTerminal) use(t *testing.T) {
	t.Helper()
	old := openTerminal
	t.Cleanup(func() { openTerminal = old })
	openTerminal = func() (io.Reader, io.Writer, func(), error) {
		f.opened++
		if f.noTerm {
			return nil, nil, nil, errNoTerminal
		}
		return strings.NewReader(f.answer), &f.asked, func() {}, nil
	}
}

func otherToken() string { return "skb_b3RoZXIuc2VjcmV0LXk" } // base64url("other.secret-y")

// SECURITY: a local machine that serves a Host adds another only on a yes
// typed at this machine's terminal. No terminal, or any answer but y or yes,
// refuses before the token is spent, and the first pairing is untouched.
// Every caller but `pair` (claim-anchor, the pairing op) keeps the old
// refusal: it has no person to ask.
func TestALocalMachineAddsASecondHostOnlyOnAYesTypedHere(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "home host CA")
	home := startTCPEnrollHost(t, ca, ca.serverCert(t, tcpServerName), "127.0.0.1:18831")
	if _, _, err := pairWithTokenVia(homeToken(), home.url, writeCA(t, ca), false, false); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(mustPairingsDir(t), "home.example.test.json"))

	otherCA := newTestCA(t, "other host CA")
	other := startTCPEnrollHost(t, otherCA, chainWithCA(t, otherCA), "127.0.0.1:18832")
	other.set(func(h *tcpEnrollHost) {
		h.edit = func(ans map[string]any) { ans["host_handle"], ans["host_name"] = "other", "other.example.test" }
	})
	code := makePairCode(t, map[string]any{"v": 1, "u": other.url, "ca": pairCodeFingerprint(otherCA), "t": otherToken()})
	pairOther := func() error {
		token, opts, err := pairOptsFor(code, "", "", false)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = pairWith(token, opts)
		return err
	}
	untouched := func(why string) {
		t.Helper()
		now, _ := os.ReadFile(filepath.Join(mustPairingsDir(t), "home.example.test.json"))
		cfgs, _ := loadPairings()
		if string(now) != string(first) {
			t.Fatalf("%s: the first pairing changed", why)
		}
		if why != "yes" && (len(cfgs) != 1 || other.hits.Load() != 0) {
			t.Fatalf("%s: %d pairings, %d redeems", why, len(cfgs), other.hits.Load())
		}
	}

	// No terminal: refused, and it says where to run it instead.
	ft := &fakeTerminal{noTerm: true}
	ft.use(t)
	if err := pairOther(); err == nil || !strings.Contains(err.Error(), "terminal window on this computer") {
		t.Fatalf("no terminal must refuse in plain words: %v", err)
	}
	untouched("no terminal")

	// Anything but y or yes.
	for _, a := range []string{"\n", "n\n", "no\n", "yess\n", "sure\n", ""} {
		ft := &fakeTerminal{answer: a}
		ft.use(t)
		if err := pairOther(); err == nil || !strings.Contains(err.Error(), "stays the only Host") {
			t.Fatalf("answer %q must refuse: %v", a, err)
		}
		if !strings.Contains(ft.asked.String(), "already serves your Host home.example.test. Add other as well?") {
			t.Fatalf("the question: %q", ft.asked.String())
		}
		untouched("answer " + a)
	}

	// The callers with no person to ask keep the refusal, and ask nobody.
	ft = &fakeTerminal{answer: "y\n"}
	ft.use(t)
	var second *localSecondHostError
	if _, _, err := pairWithTokenVia(otherToken(), other.url, writeCA(t, otherCA), false, false); !errors.As(err, &second) {
		t.Fatalf("pairWithTokenVia (no person to ask) must keep the refusal: %v", err)
	}
	if ft.opened != 0 {
		t.Fatal("a caller with no person to ask opened the terminal")
	}
	untouched("no asker")

	// A typed yes adds it beside the first.
	ft = &fakeTerminal{answer: "Yes\n"}
	ft.use(t)
	if err := pairOther(); err != nil {
		t.Fatal(err)
	}
	cfgs, _ := loadPairings()
	if len(cfgs) != 2 || pairingFor(cfgs, "other.example.test") == nil {
		t.Fatalf("after yes: %d pairings", len(cfgs))
	}
	untouched("yes")
}

// secondHostStdinChild set to 1 makes this test binary the child of
// TestTheSecondHostAnswerIsNeverReadFromStandardInput.
const secondHostStdinChild = "PRIVATAE_TEST_SECOND_HOST_STDIN_CHILD"

// SECURITY: the answer to the second-Host question comes from the controlling
// terminal, never from standard input. The installers hand the pairing code to
// `pair -` on standard input, so a "y" piped in after the code must not add a
// Host. The real openTerminal runs in a child with no controlling terminal (a
// session of its own) and "y" waiting on its standard input: it must find no
// terminal, and leave standard input unread.
func TestTheSecondHostAnswerIsNeverReadFromStandardInput(t *testing.T) {
	if os.Getenv(secondHostStdinChild) == "1" {
		yes, err := confirmAddHost("home.example.test", "other")
		rest, _ := io.ReadAll(os.Stdin)
		fmt.Printf("child: yes=%v refused=%v stdin-left=%q\n", yes, err != nil && strings.Contains(err.Error(), "no terminal"), rest)
		os.Exit(0)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestTheSecondHostAnswerIsNeverReadFromStandardInput$")
	cmd.Env = append(os.Environ(), secondHostStdinChild+"=1")
	cmd.Stdin = strings.NewReader("y\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `child: yes=false refused=true stdin-left="y\n"`) {
		t.Fatalf("a y on standard input must neither answer the question nor be read: %s", out)
	}
}

// The refusal names this system's own way to a networked bastion, and says
// that the Host already here would have to be paired again.
func TestTheLocalRefusalSaysWhatANetworkedReinstallCosts(t *testing.T) {
	msg := localOneHostRefusal("home.example.test")
	if !strings.Contains(msg, "install.sh --networked") || strings.Contains(msg, "install.ps1") {
		t.Fatalf("on linux it names install.sh: %s", msg)
	}
	if !strings.Contains(msg, "home.example.test has to be paired with it again") || !strings.Contains(msg, "answer yes at this computer's terminal") {
		t.Fatalf("the refusal: %s", msg)
	}
}

// ── what the Host's card actually makes ─────────────────────────────────────

// Made by the C-Series Host's own pairing_code (bastion_enroll.py) from the CA
// below and an invented token, for an invented address: compact JSON with the
// keys v, u, ca and t in base64url without padding. The bastion must read
// exactly that, and the fingerprint must be the one caSHA256 computes from
// the same CA, or a real code would never pin.
const hostMadePairCode = "skp_eyJ2IjoxLCJ1IjoiaHR0cHM6Ly9tYXBsZS5leGFtcGxlLWlkLmNsb3VkLmV4YW1wbGU6ODgxMC92MS9sb2NhbC9yZWRlZW0iLCJjYSI6IjcyMzNkOWU4ODU5MzIyZjE1YTJiNmMzYWIyMmZiNjMxNGI4M2I0Njg2ZmNhYmZiYjRmNGU1NDE5NDA1MTFkMDciLCJ0Ijoic2tiX2JXRndiR1V1YzJWamNtVjBMV2x1ZG1WdWRHVmtMVEF3TURFIn0"

const hostMadePairCodeCA = `-----BEGIN CERTIFICATE-----
MIIBTTCB9KADAgECAgIQkjAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhleGFtcGxl
IGludmVudGVkIGhvc3QgQ0EwIBcNMjYwMTAxMDAwMDAwWhgPMjEyNTEyMDgwMDAw
MDBaMCMxITAfBgNVBAMMGGV4YW1wbGUgaW52ZW50ZWQgaG9zdCBDQTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABA32JMrh4sMMLvNNoSBq5FgXFgHd/2n71Qk9ayje
Kj9rdt+Q3CFYWgtCqFHc6ZLUfXexKkdWvnET3px2hGqZWbKjFjAUMBIGA1UdEwEB
/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwIDSAAwRQIhAIQ6sKtiqxcAQTPq7+toiEl0
qrWb4CKKB2UtvcQoC9YwAiBYGKbmvG9ZszE8X7uKUGexjP9x6lDOwqfmnLoruuVg
Kg==
-----END CERTIFICATE-----
`

func TestACodeTheHostMadeDecodesAndPins(t *testing.T) {
	pc, err := decodePairCode(hostMadePairCode)
	if err != nil {
		t.Fatal(err)
	}
	if pc.RedeemURL != "https://maple.example-id.cloud.example:8810/v1/local/redeem" ||
		pc.Token != "skb_bWFwbGUuc2VjcmV0LWludmVudGVkLTAwMDE" { // base64url("maple.secret-invented-0001")
		t.Fatalf("decoded: %+v", pc)
	}
	if got := caSHA256(hostMadePairCodeCA); got != pc.CASHA256 {
		t.Fatalf("the Host's fingerprint %s is not caSHA256 of its CA (%s)", pc.CASHA256, got)
	}
	if h, _, err := decodeToken(pc.Token); err != nil || h != "maple" {
		t.Fatalf("the token's handle: %q %v", h, err)
	}
}

// SECURITY: a key given twice is an extra key. A map would keep only the
// last, so two codes that differ in which token they carry could both read as
// "exactly v, u, ca and t".
func TestAPairingCodeWithAKeyGivenTwiceIsRefused(t *testing.T) {
	fp := strings.Repeat("0f", 32)
	u := "https://maple.example-id.cloud.example:8810/v1/local/redeem"
	raw := `{"v":1,"u":"` + u + `","ca":"` + fp + `","t":"` + otherToken() + `","t":"` + homeToken() + `"}`
	if _, err := decodePairCode(pairCodePrefix + base64.RawURLEncoding.EncodeToString([]byte(raw))); err == nil {
		t.Fatal("a code naming t twice was read")
	}
	once := `{"v":1,"u":"` + u + `","ca":"` + fp + `","t":"` + homeToken() + `"}`
	if _, err := decodePairCode(pairCodePrefix + base64.RawURLEncoding.EncodeToString([]byte(once))); err != nil {
		t.Fatalf("the same code with t once: %v", err)
	}
}

// pinnedChainCert is a certificate for the pinned-chain cases: signed by
// parent (self-signed when parent is nil), a CA or not, valid from nb to na.
func pinnedChainCert(t *testing.T, cn string, isCA bool, nb, na time.Time, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, dns ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: nb, NotAfter: na, DNSNames: dns, BasicConstraintsValid: true, IsCA: isCA}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage, tmpl.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

// SECURITY: the cases of the pinned chain the TLS tests do not reach. A
// certificate with the code's fingerprint that is not a CA, and a CA that has
// expired, are refused; the pinned CA anywhere after the leaf, beside other
// certificates, is the one returned.
func TestThePinnedChainTakesOnlyAValidCAWithTheFingerprint(t *testing.T) {
	now := time.Now()
	fpOf := func(c *x509.Certificate) string { s := sha256.Sum256(c.Raw); return hex.EncodeToString(s[:]) }

	ca, caKey := pinnedChainCert(t, "maple host CA", true, now.Add(-time.Hour), now.Add(24*time.Hour), nil, nil)
	leaf, _ := pinnedChainCert(t, "leaf", false, now.Add(-time.Hour), now.Add(time.Hour), ca, caKey, tcpServerName)
	other, _ := pinnedChainCert(t, "another CA", true, now.Add(-time.Hour), now.Add(24*time.Hour), nil, nil)
	got, err := verifyPinnedChain([]*x509.Certificate{leaf, other, ca}, fpOf(ca))
	if err != nil || caSHA256(got) != fpOf(ca) {
		t.Fatalf("the pinned CA after another certificate: %v", err)
	}

	// A self-signed certificate that is not a CA, signing the leaf.
	notCA, notCAKey := pinnedChainCert(t, "not a CA", false, now.Add(-time.Hour), now.Add(24*time.Hour), nil, nil)
	leaf2, _ := pinnedChainCert(t, "leaf", false, now.Add(-time.Hour), now.Add(time.Hour), notCA, notCAKey, tcpServerName)
	if _, err := verifyPinnedChain([]*x509.Certificate{leaf2, notCA}, fpOf(notCA)); err == nil {
		t.Fatal("a certificate with the fingerprint that is not a CA was pinned")
	}

	// An expired CA, with a leaf it signed that is still in its dates.
	old, oldKey := pinnedChainCert(t, "expired host CA", true, now.Add(-48*time.Hour), now.Add(-time.Hour), nil, nil)
	leaf3, _ := pinnedChainCert(t, "leaf", false, now.Add(-2*time.Hour), now.Add(time.Hour), old, oldKey, tcpServerName)
	if _, err := verifyPinnedChain([]*x509.Certificate{leaf3, old}, fpOf(old)); err == nil {
		t.Fatal("an expired CA was pinned")
	}

	if _, err := verifyPinnedChain([]*x509.Certificate{leaf}, fpOf(ca)); err == nil {
		t.Fatal("a chain of the leaf alone was accepted")
	}
}

// Exit 3 means the same Host, so the same CA, on every TCP pairing: a
// --host-ca pair to a Host of a name already paired here under another CA is
// a plain failure, as the pairing code's is.
func TestHostCAFileWithASameNamedHostUnderAnotherCAIsNotAlreadyPaired(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "home host CA")
	h := startTCPEnrollHost(t, ca, ca.serverCert(t, tcpServerName), "127.0.0.1:18841")
	if _, _, err := pairWithTokenVia(homeToken(), h.url, writeCA(t, ca), false, false); err != nil {
		t.Fatal(err)
	}
	var already *alreadyPairedError
	if _, _, err := pairWithTokenVia(homeToken(), h.url, writeCA(t, ca), false, false); !errors.As(err, &already) {
		t.Fatalf("the same Host under its own CA is already paired (exit 3): %v", err)
	}
	other := newTestCA(t, "another home")
	h2 := startTCPEnrollHost(t, other, other.serverCert(t, tcpServerName), "127.0.0.1:18842")
	_, _, err := pairWithTokenVia(homeToken(), h2.url, writeCA(t, other), false, false)
	if err == nil || errors.As(err, &already) || !strings.Contains(err.Error(), "different Host named") {
		t.Fatalf("a same-named Host under another CA is a plain refusal, not exit 3: %v", err)
	}
	if h2.hits.Load() != 0 {
		t.Fatal("the refusal spent the other Host's token")
	}
}

// SECURITY: the name in the question is the token's handle, which whoever
// made the token chose. A control character or escape sequence in it reaches
// the person's screen escaped, so it cannot rewrite the question.
func TestTheSecondHostQuestionEscapesTheTokensName(t *testing.T) {
	ft := &fakeTerminal{answer: "n\n"}
	ft.use(t)
	if _, err := confirmAddHost("home.example.test", "evil\r\x1b[2K\x1b[1Ainnocent"); err != nil {
		t.Fatal(err)
	}
	q := ft.asked.String()
	if strings.ContainsAny(q, "\x1b\r") {
		t.Fatalf("the question carries the handle's control bytes raw: %q", q)
	}
	if !strings.Contains(q, `Add "evil\r\x1b[2K\x1b[1Ainnocent" as well?`) {
		t.Fatalf("the question: %q", q)
	}
	ft = &fakeTerminal{answer: "n\n"}
	ft.use(t)
	if _, err := confirmAddHost("home.example.test", "maple"); err != nil || !strings.Contains(ft.asked.String(), "Add maple as well?") {
		t.Fatalf("a plain name is shown as it is: %q %v", ft.asked.String(), err)
	}
}

// The name the redeem answers with is checked again after the redeem (the
// token's handle can differ from it). There too, the same name under another
// CA is a plain failure, never exit 3.
func TestARedeemAnsweringAPairedNameUnderAnotherCAIsNotAlreadyPaired(t *testing.T) {
	pairingBox(t)
	ca := newTestCA(t, "home host CA")
	h := startTCPEnrollHost(t, ca, ca.serverCert(t, tcpServerName), "127.0.0.1:18843")
	if _, _, err := pairWithTokenVia(homeToken(), h.url, writeCA(t, ca), false, false); err != nil {
		t.Fatal(err)
	}
	other := newTestCA(t, "another home")
	h2 := startTCPEnrollHost(t, other, chainWithCA(t, other), "127.0.0.1:18844")
	// otherToken's handle is "other"; the Host answers home.example.test.
	token, opts, err := pairOptsFor(makePairCode(t, map[string]any{"v": 1, "u": h2.url, "ca": pairCodeFingerprint(other), "t": otherToken()}), "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	opts.askSecond = func(string, string) (bool, error) { return true, nil }
	_, _, err = pairWith(token, opts)
	var already *alreadyPairedError
	if err == nil || errors.As(err, &already) || !strings.Contains(err.Error(), "different Host named home.example.test") {
		t.Fatalf("a redeem naming a paired Host under another CA is a plain refusal, not exit 3: %v", err)
	}
	if cfgs, _ := loadPairings(); len(cfgs) != 1 {
		t.Fatalf("%d pairings after the refusal", len(cfgs))
	}
}
