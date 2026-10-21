package main

// pair_tcp.go: pairing with a Host that has no platform and shares no kernel
// with this machine: a Host in a VM on it, whose two pairing ports are
// forwarded to this machine's loopback.
//
//	privatae-bastion pair --redeem-url https://127.0.0.1:8810/v1/local/redeem \
//	    --host-ca host-ca.pem <token>
//
// The Host's installer hands over the token and the Host's CA together, from
// inside the VM. The redeem goes over TLS that trusts that CA and nothing else
// (no system roots) and checks the name tcpServerName on the Host's
// certificate. The request body is the platform redeem's. The answer names the
// Host's lane port; the lanes dial it with this bastion's operator certificate
// and check the Host the same way, then speak the protocol they speak over the
// unix lane socket and the tunnel. The CA is pinned for the pairing's life, as
// for a unix pairing.
//
// What the unix pairing's directory gave it, the certificates give here: the
// Host knows this bastion by its certificate's serial, not by a uid, and this
// bastion knows the Host by the CA it was handed. There is no runs directory,
// so a TCP pairing has no coder runs (coderTransportRefusal).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// tcpServerName is the one name on a Host's enroll and lane certificates
// (the Host's local bastion module names the same constant). Fixed, not
// the Host's handle: this bastion reaches the ports on an address of this
// machine, never by the Host's name.
const tcpServerName = "host.cseries.internal"

// maxHostCABytes bounds the --host-ca file: a CA certificate is under 2 KiB.
const maxHostCABytes = 64 << 10

// parseTCPRedeemURL accepts https://<host>[:<port>]/<path> and nothing else:
// no user info, no query, no fragment, an absolute clean path.
func parseTCPRedeemURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("--redeem-url %q does not parse: %v", raw, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("--redeem-url %q is not https://", raw)
	}
	if u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, fmt.Errorf("--redeem-url %q must name a host and a path only, like https://127.0.0.1:8810/v1/local/redeem", raw)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--redeem-url %q has a port that is not one", raw)
		}
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("--redeem-url %q carries a query or fragment", raw)
	}
	if u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || path.Clean(u.Path) != u.Path {
		return nil, fmt.Errorf("--redeem-url %q must have an absolute, clean path", raw)
	}
	return u, nil
}

// loadHostCA reads the Host CA the owner was handed with the token: PEM, one
// or more CA certificates and nothing else.
func loadHostCA(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", fmt.Errorf("--host-ca: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxHostCABytes+1))
	if err != nil {
		return "", fmt.Errorf("--host-ca: %w", err)
	}
	if len(raw) > maxHostCABytes {
		return "", fmt.Errorf("--host-ca %s is larger than a CA certificate can be", file)
	}
	cas := pemCerts(string(raw))
	if len(cas) == 0 {
		return "", fmt.Errorf("--host-ca %s holds no PEM certificate", file)
	}
	for _, c := range cas {
		if !c.IsCA {
			return "", fmt.Errorf("--host-ca %s holds a certificate that is not a CA (%s)", file, c.Subject)
		}
	}
	return string(raw), nil
}

// hostCATLS is the client side every TCP pairing connection uses: the Host CA
// as the only root, tcpServerName checked, and this bastion's operator
// certificate when it has one (none yet at the redeem).
func hostCATLS(caPEM string, cert *tls.Certificate) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("the Host CA holds no usable certificate")
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: tcpServerName, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg, nil
}

// tcpRedeemResp is the Host's answer on its enroll port: the unix answer's
// certificates, bearer and names (either spelling of the certificate fields),
// with the lane's address in place of the socket paths.
type tcpRedeemResp struct {
	OperatorCert    string `json:"operator_cert"`
	OperatorCertAlt string `json:"operator_crt"`
	CACert          string `json:"ca_cert"`
	CACertAlt       string `json:"ca_crt"`
	Bearer          string `json:"bearer"`
	Transport       string `json:"transport"`
	LaneAddress     string `json:"lane_address"`
	HostHandle      string `json:"host_handle"`
	HostName        string `json:"host_name"`
	Error           string `json:"error"`
}

func (r tcpRedeemResp) operatorCert() string { return firstNonEmpty(r.OperatorCert, r.OperatorCertAlt) }
func (r tcpRedeemResp) caCert() string       { return firstNonEmpty(r.CACert, r.CACertAlt) }
func (r tcpRedeemResp) hostName() string     { return firstNonEmpty(r.HostName, r.HostHandle) }

// redeemOverTCP POSTs the redeem body to the Host's enroll port over TLS
// pinned to caPEM. No proxy: the address is this machine's. No redirect
// either: a followed 307 sends the body, the token's secret in it, to an
// address nothing checked, and over plain HTTP when it says http://.
func redeemOverTCP(u *url.URL, caPEM string, body []byte) (tcpRedeemResp, error) {
	var rr tcpRedeemResp
	tc, err := hostCATLS(caPEM, nil)
	if err != nil {
		return rr, fmt.Errorf("--host-ca: %w", err)
	}
	httpc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: tc, ForceAttemptHTTP2: false,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := httpc.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return rr, fmt.Errorf("redeem: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(rb, &rr)
	if resp.StatusCode != 200 {
		if rr.Error != "" {
			return rr, fmt.Errorf("redeem rejected: %s", rr.Error)
		}
		return rr, fmt.Errorf("redeem rejected: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return rr, nil
}

// checkLaneAddr: host:port, the port a port, and the host the one the owner
// named in the redeem URL. The Host names its lane, but only on the address
// the owner already chose to reach it at; it cannot send the lanes elsewhere.
func checkLaneAddr(laneAddr string, redeem *url.URL) error {
	host, port, err := net.SplitHostPort(laneAddr)
	if err != nil {
		return fmt.Errorf("the Host's lane_address %q is not host:port", laneAddr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("the Host's lane_address %q has a port that is not one", laneAddr)
	}
	if !strings.EqualFold(host, redeem.Hostname()) {
		return fmt.Errorf("the Host's lane_address %q is not on %s, the address its redeem URL names — refusing",
			laneAddr, redeem.Hostname())
	}
	return nil
}

// tcpAnswerRefusal checks a Host's answer on its enroll port before anything
// is saved: a tcp answer with the certificates and the bearer, the CA in it
// the one the owner handed over, the operator certificate ours and signed by
// that CA, a host name that can be a file name, and the lane on the redeem
// URL's host. existing is the pairing a --replace rotates (nil otherwise);
// others are the box's other pairings.
func tcpAnswerRefusal(rr tcpRedeemResp, redeem *url.URL, hostCA, opKey string, existing *Config, others []*Config) error {
	if rr.Transport != transportTCP {
		return fmt.Errorf("the Host answered transport %q on its enroll port; only \"tcp\" is a pairing over it", rr.Transport)
	}
	for k, v := range map[string]string{"operator_cert": rr.operatorCert(), "ca_cert": rr.caCert(), "bearer": rr.Bearer,
		"lane_address": rr.LaneAddress, "host_handle": rr.hostName()} {
		if v == "" {
			return fmt.Errorf("redeem response missing %s", k)
		}
	}
	if !validHostName(rr.hostName()) {
		return fmt.Errorf("redeem response has an unsafe host name %q — refusing", rr.hostName())
	}
	if err := checkLaneAddr(rr.LaneAddress, redeem); err != nil {
		return err
	}
	if !sameCAs(rr.caCert(), hostCA) {
		return errors.New("the Host answered with a CA other than the --host-ca it was paired with — refusing")
	}
	pair, err := tls.X509KeyPair([]byte(rr.operatorCert()), []byte(opKey))
	if err != nil {
		return fmt.Errorf("the Host's operator_cert is not for this bastion's key: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("the Host's operator_cert does not parse: %v", err)
	}
	pool := x509.NewCertPool()
	for _, c := range pemCerts(hostCA) {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("the Host's operator_cert is not signed by its CA for client use: %v", err)
	}
	// Again here: the pairing the answer's name lands on may not be the one
	// the token's handle found before the redeem.
	if err := tcpPinRefusal(existing, hostCA); err != nil {
		return err
	}
	for _, o := range others {
		if existing != nil && o.HostName == existing.HostName {
			continue
		}
		if o.tcpTransport() && o.LaneAddr == rr.LaneAddress {
			return fmt.Errorf("%s already uses the lane at %s; each Host needs its own", o.HostName, rr.LaneAddress)
		}
	}
	return nil
}

// tcpPinRefusal is THE PIN, as for a unix pairing: a --replace keeps the CA
// the pairing was made with. pairWithTokenVia asks it before the redeem
// dials, because --host-ca is the only root that redeem trusts: under
// another CA the token would go to whoever holds that one.
func tcpPinRefusal(existing *Config, hostCA string) error {
	if existing != nil && existing.CACert != "" && !sameCAs(existing.CACert, hostCA) {
		return fmt.Errorf("the Host's CA is not the one %s was paired with — refusing. "+
			"A Host keeps its CA for life; to pair a new one, `privatae-bastion unpair %s` first", existing.HostName, existing.HostName)
	}
	return nil
}

// tcpPairingConfig builds the pairing a tcp answer makes. Per-host state is
// allocated exactly as for any other pairing; a --replace keeps it.
func tcpPairingConfig(rr tcpRedeemResp, cfgs []*Config, existing *Config, replace bool,
	wgPriv, opKey, fp, hostCA string) (*Config, error) {
	opSecret, err := genSecret(24)
	if err != nil {
		return nil, err
	}
	cd, err := configDir()
	if err != nil {
		return nil, err
	}
	host := rr.hostName()
	cfg := &Config{
		HostName: host,
		// Never dialled: kept so a re-pair shows as a new key (superviseOnce).
		WGPrivateKey: wgPriv,
		OperatorCert: rr.operatorCert(), OperatorKey: opKey, CACert: hostCA,
		Bearer: rr.Bearer, OperatorSecret: opSecret, Fingerprint: fp,
		Transport: transportTCP, LaneAddr: rr.LaneAddress,
		ListenAddr:   nextListenAddr(cfgs),
		GitProxyAddr: nextGitProxyAddr(cfgs),
		ContextRoot:  filepath.Join(cd, "context", host),
		DCNDir:       filepath.Join(cd, "dcn", host),
	}
	if replace && existing != nil {
		cfg.ListenAddr = existing.ListenAddr
		if existing.GitProxyAddr != "" {
			cfg.GitProxyAddr = existing.GitProxyAddr
		}
		cfg.ContextRoot = existing.ContextRoot
		cfg.DCNDir = existing.DCNDir
	}
	return cfg, nil
}

// tcpLaneDialer is the transport of a TCP pairing: a dial of the Host's lane
// port, and the mutual TLS every lane runs inside it, as unixLaneDialer does
// on the lane socket. The pinned Host CA is the only root, tcpServerName is
// checked, and this bastion presents its operator certificate. A pairing
// with no bearer gets no lane at all.
func tcpLaneDialer(cfg *Config) (func(ctx context.Context) (net.Conn, error), *tls.Config, error) {
	if cfg.Bearer == "" {
		return nil, nil, errors.New("this pairing holds no bearer, and its lane never opens without one")
	}
	if _, _, err := net.SplitHostPort(cfg.LaneAddr); err != nil {
		return nil, nil, fmt.Errorf("lane address %q is not host:port", cfg.LaneAddr)
	}
	cert, err := tls.X509KeyPair([]byte(cfg.OperatorCert), []byte(cfg.OperatorKey))
	if err != nil {
		return nil, nil, fmt.Errorf("operator cert/key: %w", err)
	}
	tc, err := hostCATLS(cfg.CACert, &cert)
	if err != nil {
		return nil, nil, fmt.Errorf("bad CA cert in config: %w", err)
	}
	addr := cfg.LaneAddr
	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{Timeout: egressDialTimeout}).DialContext(ctx, "tcp", addr)
	}
	return dial, tc, nil
}

// localLaneDialer is the lane transport of a pairing with a Host that has no
// platform: the lane socket or the lane port.
func localLaneDialer(cfg *Config) (func(ctx context.Context) (net.Conn, error), *tls.Config, error) {
	if cfg.tcpTransport() {
		return tcpLaneDialer(cfg)
	}
	return unixLaneDialer(cfg)
}

// laneWhere is where a local pairing's lanes go, for the log and status.
func (c *Config) laneWhere() string {
	if c.tcpTransport() {
		return c.LaneAddr
	}
	return c.LaneSocket
}

// coderTransportRefusal: a coder run's control plane is a tunnel port or a
// socket in a unix pairing's runs directory, and a TCP pairing has neither,
// so a run started for it could never be reached. "" for every other pairing.
// Pairings that cannot be read are a refusal: the run's transport is unknown.
func coderTransportRefusal(owner string) string {
	cfgs, err := loadPairings()
	if err != nil {
		return "coder runs need this machine's pairings to tell how the run would be reached, and they cannot be read: " + err.Error()
	}
	if c := pairingFor(cfgs, owner); c != nil && c.HostName == owner && c.tcpTransport() {
		return "coder runs are not served to a Host paired over TCP (pair --redeem-url https://…): " +
			"a run's control plane needs the platform's tunnel or a Host on this machine's own kernel"
	}
	return ""
}
