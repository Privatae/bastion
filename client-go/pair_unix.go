package main

// pair_unix.go: pairing with a Host on THIS machine, which has no platform.
//
// `privatae-bastion pair --redeem-url unix:///run/privatae-host/enroll.sock <token>`
// redeems the token over that socket instead of the platform's ingress. The
// request body is the one a platform redeem sends. The answer names no relay
// and no tunnel addresses. It names a lane socket and a runs directory in the
// same shared directory, and the Host's own CA, which this pairing pins the
// way a platform pairing pins the platform's CA: it is the only root the lanes
// trust, and a later redeem that brings a different CA is refused.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// unixRedeemPath is the Host's enrolment endpoint on its enroll socket.
const unixRedeemPath = "/bastion/enroll/redeem"

// parseUnixRedeemURL accepts unix:///<absolute socket path> and nothing
// else, and returns the path. A host, a port, user info, a query, a relative
// or unclean path are all refused: the URL names a file on this machine,
// never a network address.
func parseUnixRedeemURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("--redeem-url %q does not parse: %v", raw, err)
	}
	if u.Scheme != "unix" {
		return "", fmt.Errorf("--redeem-url must be unix:///<socket path> for a Host on this machine, got %q "+
			"(a platform pairing needs no --redeem-url)", raw)
	}
	if u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", fmt.Errorf("--redeem-url %q names a network address; a unix:// redeem URL names a socket path "+
			"on this machine only, like unix:///run/privatae-host/enroll.sock", raw)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("--redeem-url %q carries a query or fragment; it names a socket path only", raw)
	}
	if !cleanAbsSocketPath(u.Path) {
		return "", fmt.Errorf("--redeem-url %q must name an absolute, clean socket path", raw)
	}
	return u.Path, nil
}

// cleanAbsSocketPath: absolute, already clean, not the root, no NUL.
func cleanAbsSocketPath(p string) bool {
	return strings.HasPrefix(p, "/") && p != "/" && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}

// insideDir says p is strictly below dir (both clean and absolute).
func insideDir(p, dir string) bool {
	return cleanAbsSocketPath(p) && strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// unixRedeemResp is the Host's answer. The design spells the certificate
// fields operator_cert and ca_cert and names the Host by host_handle; the
// platform's answer spells them operator_crt, ca_crt and host_name. Either
// spelling is read, so the two sides cannot disagree on a key name.
type unixRedeemResp struct {
	OperatorCert    string `json:"operator_cert"`
	OperatorCertAlt string `json:"operator_crt"`
	CACert          string `json:"ca_cert"`
	CACertAlt       string `json:"ca_crt"`
	Bearer          string `json:"bearer"`
	Transport       string `json:"transport"`
	LaneSocket      string `json:"lane_socket"`
	RunsDir         string `json:"runs_dir"`
	HostHandle      string `json:"host_handle"`
	HostName        string `json:"host_name"`
	Error           string `json:"error"`
}

func (r unixRedeemResp) operatorCert() string {
	return firstNonEmpty(r.OperatorCert, r.OperatorCertAlt)
}
func (r unixRedeemResp) caCert() string { return firstNonEmpty(r.CACert, r.CACertAlt) }

// hostName is what the pairing is filed under and the name the Host's lane
// certificate must carry: host_name when the Host sends one, else host_handle.
func (r unixRedeemResp) hostName() string { return firstNonEmpty(r.HostName, r.HostHandle) }

// unixRedeemDial is how the redeem reaches the enroll socket. A seam only so
// a test can count that nothing was dialled; nothing outside tests sets it.
var unixRedeemDial = func(ctx context.Context, sock string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", sock)
}

// redeemOverUnix POSTs the redeem body to the Host's enroll socket. Plain
// HTTP: the socket is a file in a root-owned directory the Host shares with
// this bastion, and what is pinned comes back in the answer.
func redeemOverUnix(sock string, body []byte) (unixRedeemResp, error) {
	var rr unixRedeemResp
	fi, err := os.Lstat(sock)
	if err != nil {
		return rr, fmt.Errorf("redeem: the Host's enroll socket %s: %w", sock, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return rr, fmt.Errorf("redeem: %s is not a socket (a link or a file is never followed)", sock)
	}
	httpc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		// The URL's host is ignored: every request goes to this one socket.
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return unixRedeemDial(ctx, sock) },
	}}
	resp, err := httpc.Post("http://localhost"+unixRedeemPath, "application/json", bytes.NewReader(body))
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

// pemCerts is every CERTIFICATE block in s, parsed; nil when there is none or
// one does not parse.
func pemCerts(s string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil
		}
		out = append(out, c)
	}
	return out
}

// sameCAs: the two PEM bundles hold exactly the same certificates.
func sameCAs(a, b string) bool {
	ca, cb := pemCerts(a), pemCerts(b)
	if len(ca) == 0 || len(ca) != len(cb) {
		return false
	}
	seen := map[string]bool{}
	for _, c := range ca {
		seen[string(c.Raw)] = true
	}
	for _, c := range cb {
		if !seen[string(c.Raw)] {
			return false
		}
	}
	return true
}

// unixAnswerRefusal checks a Host's answer before anything is saved: it is a
// unix answer, it carries the certificates and the bearer, the operator
// certificate is ours and chains to the CA it came with, the host name can be
// a file name, and the lane socket and runs directory are inside the shared
// directory the owner named on the command line (the enroll socket's).
// existing is the pairing a --replace rotates (nil otherwise); others are the
// box's other pairings.
func unixAnswerRefusal(rr unixRedeemResp, enrollSock, opKey string, existing *Config, others []*Config) error {
	if rr.Transport != transportUnix {
		return fmt.Errorf("the Host answered transport %q over its enroll socket; only \"unix\" is a pairing with a Host on this machine", rr.Transport)
	}
	for k, v := range map[string]string{"operator_cert": rr.operatorCert(), "ca_cert": rr.caCert(), "bearer": rr.Bearer,
		"lane_socket": rr.LaneSocket, "runs_dir": rr.RunsDir, "host_handle": rr.hostName()} {
		if v == "" {
			return fmt.Errorf("redeem response missing %s", k)
		}
	}
	if !validHostName(rr.hostName()) {
		return fmt.Errorf("redeem response has an unsafe host name %q — refusing", rr.hostName())
	}
	shared := path.Dir(enrollSock)
	if !insideDir(rr.LaneSocket, shared) {
		return fmt.Errorf("the Host's lane_socket %q is not inside %s, the directory its enroll socket is in — refusing", rr.LaneSocket, shared)
	}
	if !insideDir(rr.RunsDir, shared) {
		return fmt.Errorf("the Host's runs_dir %q is not inside %s, the directory its enroll socket is in — refusing", rr.RunsDir, shared)
	}
	cas := pemCerts(rr.caCert())
	if len(cas) == 0 {
		return errors.New("the Host's ca_cert holds no certificate")
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
	for _, c := range cas {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("the Host's operator_cert is not signed by the CA it sent: %v", err)
	}
	// THE PIN. A --replace keeps the CA the pairing was made with. A Host
	// keeps its CA with its signing key from its first boot, so a different
	// one means a different Host, or someone else answering on its socket.
	if existing != nil && existing.CACert != "" && !sameCAs(existing.CACert, rr.caCert()) {
		return fmt.Errorf("the Host answered with a different CA than the one %s was paired with — refusing. "+
			"A Host keeps its CA for life; to pair a new one, `privatae-bastion unpair %s` first", existing.HostName, existing.HostName)
	}
	// One runs directory per pairing: the sockets in it are the runs of the
	// pairing that owns it, and a second pairing sharing it could reach them.
	for _, o := range others {
		if existing != nil && o.HostName == existing.HostName {
			continue
		}
		if o.unixTransport() && (o.RunsDir == rr.RunsDir || o.LaneSocket == rr.LaneSocket) {
			return fmt.Errorf("%s already uses that lane socket or runs directory; each Host on this machine needs its own", o.HostName)
		}
	}
	return nil
}

// replaceKeepsTransport: a --replace rotates credentials over the same
// transport ("" the platform, "unix" or "tcp"). A unix pairing re-pairs over
// its Host's socket, a tcp one on its Host's enroll port, a platform one
// through the platform; crossing over is a different pairing.
func replaceKeepsTransport(existing *Config, transport string) error {
	if existing == nil || existing.Transport == transport {
		return nil
	}
	switch {
	case existing.unixTransport():
		return fmt.Errorf("%s is paired with a Host on this machine — re-pair it with `pair --replace --redeem-url unix://<its enroll socket> <token>`", existing.HostName)
	case existing.tcpTransport():
		return fmt.Errorf("%s is paired with a Host over TCP — re-pair it with `pair --replace --redeem-url https://<its enroll port> --host-ca <its CA> <token>`", existing.HostName)
	}
	return fmt.Errorf("%s is paired through the platform — a --redeem-url cannot replace it; `privatae-bastion unpair %s` first", existing.HostName, existing.HostName)
}

// unixPairingConfig builds the pairing a unix answer makes. Per-host state is
// allocated exactly as for a platform pairing; a --replace keeps it.
func unixPairingConfig(rr unixRedeemResp, cfgs []*Config, existing *Config, replace bool,
	wgPriv, opKey, fp string) (*Config, error) {
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
		OperatorCert: rr.operatorCert(), OperatorKey: opKey, CACert: rr.caCert(),
		Bearer: rr.Bearer, OperatorSecret: opSecret, Fingerprint: fp,
		Transport: transportUnix, LaneSocket: rr.LaneSocket, RunsDir: rr.RunsDir,
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
