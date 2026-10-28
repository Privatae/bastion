package main

// pair_code.go: the pairing code a Host's "Set up a bastion" card hands out,
// so pairing a machine is one pasted line.
//
//	privatae-bastion pair skp_…        or        … | privatae-bastion pair -
//
// The code is the single-use token plus the two things the person used to copy
// by hand: the Host's enroll address and its CA. The CA does not travel; its
// fingerprint does. The bastion takes the CA from the enroll port's own TLS
// chain and keeps it only when its SHA-256 is the one in the code, so the trust
// is the same as `--host-ca`: the fingerprint comes from the owner's own
// signed-in card, as the PEM did. From there the pairing is exactly
// `pair --redeem-url <u> --host-ca <that CA> <t>`.
//
// No error here repeats the code, for the reason pair_stdin.go gives: a log of
// a failed install must not hold the token.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// pairCodePrefix marks a pairing code; a bare token is skb_….
const pairCodePrefix = "skp_"

// pairCodeVersion is the one layout this bastion reads.
const pairCodeVersion = 1

// pairCode is a decoded pairing code: where to redeem, the Host CA's
// fingerprint, and the token.
type pairCode struct {
	RedeemURL string // "u": the Host's enroll port, https://<host>:<port>/<path>
	CASHA256  string // "ca": SHA-256 of the Host CA certificate's DER, lowercase hex
	Token     string // "t": the skb_ token
}

func isPairCode(s string) bool { return strings.HasPrefix(s, pairCodePrefix) }

// decodePairCode reads skp_<base64url(JSON)>: exactly the keys v, u, ca and t,
// v the one version this bastion knows, u an enroll URL parseTCPRedeemURL
// takes, ca 64 lowercase hex digits and t a token decodeToken takes.
func decodePairCode(code string) (pairCode, error) {
	var pc pairCode
	bad := func(why string) (pairCode, error) {
		return pairCode{}, fmt.Errorf("the pairing code is not one this bastion can read (%s); copy the whole line from the card again", why)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, pairCodePrefix))
	if err != nil {
		return bad("it is not base64url")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return bad("it holds no JSON object")
	}
	// A map keeps the last of two same-named keys, so "exactly these four"
	// is counted on the object as written: a key given twice is an extra key.
	if n, err := jsonObjectKeyCount(raw); err != nil || n != len(fields) {
		return bad("it names a field twice")
	}
	if len(fields) != 4 {
		return bad(fmt.Sprintf("it has %d fields, and a pairing code has 4", len(fields)))
	}
	var v int
	if err := json.Unmarshal(fields["v"], &v); err != nil {
		return bad("its version is missing")
	}
	if v != pairCodeVersion {
		return pairCode{}, fmt.Errorf("the pairing code is version %d, and this bastion reads version %d: update the bastion and pair again", v, pairCodeVersion)
	}
	for k, dst := range map[string]*string{"u": &pc.RedeemURL, "ca": &pc.CASHA256, "t": &pc.Token} {
		if err := json.Unmarshal(fields[k], dst); err != nil || *dst == "" {
			return bad("its " + k + " field is missing")
		}
	}
	if _, err := parseTCPRedeemURL(pc.RedeemURL); err != nil {
		return bad("its address is not an https enroll address")
	}
	if len(pc.CASHA256) != 64 || strings.ToLower(pc.CASHA256) != pc.CASHA256 {
		return bad("its certificate fingerprint is not 64 lowercase hex digits")
	}
	if _, err := hex.DecodeString(pc.CASHA256); err != nil {
		return bad("its certificate fingerprint is not hex")
	}
	if !strings.HasPrefix(pc.Token, "skb_") {
		return bad("it carries no pairing token")
	}
	if _, _, err := decodeToken(pc.Token); err != nil {
		return bad("its pairing token is malformed")
	}
	return pc, nil
}

// jsonObjectKeyCount counts the keys of the JSON object raw as written,
// repeats included. raw has already decoded as an object.
func jsonObjectKeyCount(raw []byte) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil { // the opening brace
		return 0, err
	}
	n := 0
	for dec.More() {
		if _, err := dec.Token(); err != nil { // the key
			return 0, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// pairAnswerTimeout is how long the enroll port has to answer the first
// connection. A Cloud Host's pairing port drops every address but the one the
// card opened it to, so a pair from anywhere else gets no answer at all, and
// without this it would wait for the system's own connect timeout, minutes.
// A variable so a test can shorten it; nothing else assigns it.
var pairAnswerTimeout = 10 * time.Second

// pairDial dials the enroll port. A variable so a test can stand in a port
// that never answers; nothing else assigns it.
var pairDial = (&net.Dialer{}).DialContext

// pairWindowError is what a pair says when the Host's enroll port did not
// answer: the plain reason, which is nearly always the pairing window. A type
// of its own so the redeem's HTTP client, which wraps every dial error in the
// request's URL, can hand it on as it is.
type pairWindowError struct{ host string }

func (e *pairWindowError) Error() string {
	return fmt.Sprintf("%s's pairing port didn't answer within %s. A Cloud Host opens it only to the address "+
		"your browser used when you opened \"Set up a bastion\", for 15 minutes. Pair from that network, or "+
		"on the card choose \"Pairing a machine on another network?\" and give this machine's address. Nothing was paired.",
		e.host, pairAnswerTimeout)
}

// dialEnrollPort opens a TCP connection to the redeem URL's host and port
// within pairAnswerTimeout, or says why not in plain words.
func dialEnrollPort(ctx context.Context, u *url.URL) (net.Conn, error) {
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	ctx, cancel := context.WithTimeout(ctx, pairAnswerTimeout)
	defer cancel()
	c, err := pairDial(ctx, "tcp", addr)
	if err == nil {
		return c, nil
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return nil, &pairWindowError{host: u.Hostname()}
	}
	return nil, fmt.Errorf("could not reach %s's pairing port: %v; nothing was paired", u.Hostname(), err)
}

// fetchPinnedHostCA takes the Host CA from the enroll port's TLS chain and
// returns it as PEM, only when it is a CA whose SHA-256 over its DER is
// wantSHA and the port's own certificate verifies under it alone for
// tcpServerName, the check hostCATLS makes on every later connection. No
// system roots are consulted at any point.
func fetchPinnedHostCA(u *url.URL, wantSHA string) (string, error) {
	conn, err := dialEnrollPort(context.Background(), u)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var caPEM string
	tc := &tls.Config{
		ServerName: tcpServerName, MinVersion: tls.VersionTLS12,
		// The chain is checked by verifyPinnedChain below, against the pinned
		// CA alone; the system roots must play no part, so the default
		// verification is the thing turned off here.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			p, err := verifyPinnedChain(cs.PeerCertificates, wantSHA)
			caPEM = p
			return err
		},
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	tlsConn := tls.Client(conn, tc)
	if err := tlsConn.Handshake(); err != nil {
		return "", fmt.Errorf("%s's pairing port: %v; nothing was paired", u.Hostname(), err)
	}
	_ = tlsConn.Close()
	return caPEM, nil
}

// verifyPinnedChain picks the pinned CA out of a presented chain and checks
// the leaf against it. The leaf is chain[0]; the CA is any later certificate
// whose SHA-256 is wantSHA.
func verifyPinnedChain(chain []*x509.Certificate, wantSHA string) (string, error) {
	if len(chain) == 0 {
		return "", errors.New("the Host's pairing port presented no certificate")
	}
	var ca *x509.Certificate
	sawCA := false
	for _, c := range chain[1:] {
		if !c.IsCA {
			continue
		}
		sawCA = true
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == wantSHA {
			ca = c
			break
		}
	}
	if ca == nil {
		if sawCA {
			return "", errors.New("the Host's pairing port presented a certificate authority other than the one this pairing code names — refusing")
		}
		return "", errors.New("the Host's pairing port did not present its certificate authority, so this pairing code cannot be checked — refusing (the Host needs a newer release, or pair with --host-ca)")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		if c != ca {
			inter.AddCert(c)
		}
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: tcpServerName}); err != nil {
		return "", fmt.Errorf("the Host's pairing port certificate is not signed by the certificate authority this pairing code names: %v — refusing", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})), nil
}

// caSHA256 is the fingerprint a pairing code carries for a PEM CA: SHA-256 of
// the first certificate's DER, lowercase hex. "" when the PEM holds none.
func caSHA256(caPEM string) string {
	certs := pemCerts(caPEM)
	if len(certs) == 0 {
		return ""
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:])
}
