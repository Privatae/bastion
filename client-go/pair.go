package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// validHostName accepts only a bare DNS hostname (letters/digits/dot/hyphen, no
// traversal), so the redeem-supplied host_name can be safely used as a filename
// and directory name. Rejects "", anything with a path separator or "..", and a
// leading/trailing dot. Expected shape is <handle>.host.privatae.ai.
func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if strings.Contains(h, "..") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	for _, r := range h {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

// Token: skb_<base64url(handle "." secret)>. It carries WHERE to redeem (the
// host handle) + the single-use secret. The secret is the only sensitive thing
// the user copies, it's short-lived, and it grants exactly one enrollment.
func decodeToken(token string) (handle, secret string, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "skb_"))
	if err != nil {
		return "", "", fmt.Errorf("malformed token")
	}
	parts := strings.SplitN(string(raw), ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("malformed token")
	}
	return parts[0], parts[1], nil
}

func genWGKeypair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// fpSANPrefix carries the device fingerprint as a URI SAN in the operator CSR:
// the host extracts it from the device-signed CSR at redeem and binds it,
// instead of TOFU-trusting a self-reported heartbeat field.
const fpSANPrefix = "urn:skema:hwfp:"

// hostFPSANPrefix carries the same fingerprint under the name a Host with no
// platform reads (its bastion_enroll._FP_SAN_PREFIX).
const hostFPSANPrefix = "urn:privatae:hwfp:"

// fpURIs is the device fingerprint under the names the redeem's signer takes,
// in the order the CSR carries them. The platform signs a CSR whose one SAN is
// fpSANPrefix and refuses any other (the bridge's _checked_operator_csr: one
// name, that prefix), so a platform redeem carries that name alone. A redeem
// with a Host that has no platform (local: unix:// or https://) carries it and
// then hostFPSANPrefix.
func fpURIs(fp string, local bool) ([]*url.URL, error) {
	prefixes := []string{fpSANPrefix}
	if local {
		prefixes = append(prefixes, hostFPSANPrefix)
	}
	var out []*url.URL
	for _, p := range prefixes {
		u, err := url.Parse(p + fp)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// genOperatorCSR makes the gateway's OWN mTLS key + a CSR for the host to sign, with
// the device fingerprint embedded as URI SANs so it is signed by this device's key
// (fpURIs: which names depends on whether the redeem is local). The private key
// never leaves this machine.
func genOperatorCSR(fp string, local bool) (keyPEM, csrPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	uris, err := fpURIs(fp, local)
	if err != nil {
		return
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "operator"},
			URIs:    uris,
		}, key)
	if err != nil {
		return
	}
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return
}

type redeemReq struct {
	Secret      string `json:"secret"`
	WGPublicKey string `json:"wg_public_key"`
	OperatorCSR string `json:"operator_csr"`
	Hostname    string `json:"hostname"`
	Platform    string `json:"platform"`
	Handle      string `json:"handle"` // target host handle (from the token); forms host_name
}

type redeemResp struct {
	OperatorCert    string   `json:"operator_crt"`
	CACert          string   `json:"ca_crt"`
	Bearer          string   `json:"bearer"`
	Endpoint        string   `json:"endpoint"`
	Endpoints       []string `json:"endpoints"` // preferred first; absent from an older host
	EndpointPubKey  string   `json:"endpoint_pubkey"`
	BastionTunnelIP string   `json:"bastion_tunnel_ip"`
	HostTunnelIP    string   `json:"host_tunnel_ip"`
	HostName        string   `json:"host_name"`
	Error           string   `json:"error"`
}

// pairPrecheck is the whole pre-redeem wall, in one place and free of network
// so it can be tested: the multi-homing conflict rule (checkPairConflict), the
// mode rule, and the anchoring rule. Returns the existing pairing on a
// --replace and the state the new pairing file must carry.
//
//   - LOCAL mode (mode.go): one host, full stop. A second `pair` is refused with
//     a plain message; only --replace of the one host is allowed. This is the
//     entire protection for a single-user machine — a second host appearing
//     means someone else got a token onto the box.
//   - NETWORKED + anchored (anchor.go): every pairing after the anchor is written
//     PENDING. It gets nothing until the anchor host's grant arrives.
//   - --replace keeps the pairing's current state: rotating credentials is not
//     an approval.
//   - forceActive: claim-anchor redeems as active — the anchor never waits on
//     itself.
func pairPrecheck(cfgs []*Config, handle string, replace, forceActive bool) (existing *Config, state string, err error) {
	existing, err = checkPairConflict(cfgs, handle, replace)
	if err != nil {
		return nil, "", err
	}
	if replace {
		if forceActive {
			return existing, pairingActive, nil
		}
		// A revoked host that presents a FRESH token is a new request for the
		// anchor: pending again, never straight back to active (before this a
		// revoked host could never be re-approved at all).
		if existing.State == pairingRevoked {
			return existing, pairingPending, nil
		}
		return existing, existing.State, nil
	}
	if boxMode() == modeLocal && len(cfgs) > 0 {
		return nil, "", fmt.Errorf("this bastion is in local mode and already serves %s — a local bastion serves one host. "+
			"To rotate that host's credentials: `privatae-bastion pair --replace <token>`. "+
			"To serve several hosts, reinstall as a networked bastion (install.sh --networked, root) and anchor it.",
			cfgs[0].HostName)
	}
	if forceActive {
		return nil, pairingActive, nil
	}
	if currentAnchor() != nil {
		return nil, pairingPending, nil
	}
	return nil, "", nil
}

func cmdPair(token, redeemURL, hostCAFile string, replace bool) error {
	cfg, all, err := pairWithTokenVia(token, redeemURL, hostCAFile, replace, false)
	if err != nil {
		return err
	}
	// A networked machine is a server. Left unanchored it refuses every op to
	// every host (capsAllowIn: unanchoredNetworkedRefusal) until someone runs
	// claim-anchor, a step people missed. So the first pairing on a networked
	// box with no anchor anchors it, as `claim-anchor` with no token would, and
	// from then on every terminal and write waits for the person's approval and
	// every later pairing for this host's. Only with machine authority, which
	// claim-anchor needs anyway.
	// The pairing itself succeeded, so a failed anchor is reported, not
	// returned: `pair` failing here would read as "could not pair" to a caller
	// (npx cseries exits on it) when the pairing exists. claim-anchor, which
	// such a caller runs next, reports the anchor's own failure.
	anchored, err := anchorFirstNetworkedPairing(cfg, all)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	if anchored {
		if fresh, lerr := loadPairings(); lerr == nil {
			if c := pairingFor(fresh, cfg.HostName); c != nil {
				cfg, all = c, fresh
			}
		}
	}
	pairReport(os.Stdout, cfg, all, anchored)
	return nil
}

// pairReport is what `pair` prints once the pairing stands. Whatever the form
// (anchored just now, over TCP, over a unix socket, pending, or over the
// tunnel), it ends by saying to enrol a second factor when this pairing has
// none and no approval device is pinned: without one, a local machine installs
// a folder grant on the host's signed grant alone, and an anchored one has no
// way to approve anything the host asks for.
func pairReport(w io.Writer, cfg *Config, all []*Config, anchored bool) {
	enrol := ""
	if !secondFactorAvailable(cfg.dcnDir()) {
		enrol = stepupEnrollHint(cfg.HostName, len(all))
	}
	defer func() { pairEnrolNote(w, cfg.HostName, enrol) }()
	if anchored {
		fmt.Fprintf(w, "\nThis machine is networked and anchored to %s: every terminal and every write\n", cfg.HostName)
		fmt.Fprintln(w, "waits for your approval, and any later host waits for this one to approve it.")
		if enrol != "" {
			fmt.Fprintf(w, "Enrol your second factor now, so you can approve here:\n  %s\n\n", enrol)
			enrol = ""
		}
	}
	if cfg.tcpTransport() && cfg.active() {
		fmt.Fprintf(w, "Paired with %s over TCP.\n\n", cfg.HostName)
		fmt.Fprintf(w, "  lanes:     %s (mutual TLS, the Host's CA pinned, name %s)\n  coder runs: none over TCP\n", cfg.LaneAddr, tcpServerName)
		fmt.Fprintf(w, "  local:     http://%s\n\nStart (or restart) the bastion:\n  privatae-bastion run\n", cfg.ListenAddr)
		return
	}
	if cfg.unixTransport() && cfg.active() {
		fmt.Fprintf(w, "Paired with %s, a Host on this machine.\n\n", cfg.HostName)
		fmt.Fprintf(w, "  lanes:     %s (mutual TLS, the Host's CA pinned)\n  coder runs: a socket per run in %s\n", cfg.LaneSocket, cfg.RunsDir)
		fmt.Fprintf(w, "  local:     http://%s\n\nStart (or restart) the bastion:\n  privatae-bastion run\n", cfg.ListenAddr)
		return
	}
	if !cfg.active() {
		fmt.Fprintf(w, "Paired with %s — PENDING.\n\n", cfg.HostName)
		fmt.Fprintln(w, "This machine is anchored, so a new host waits until the anchor host approves it.")
		fmt.Fprintln(w, "Nothing is started for it yet: no tunnel, no lanes. It shows on the anchor host's")
		fmt.Fprintln(w, "Network app as a pending pairing; once approved the daemon opens its lanes by itself.")
		return
	}
	fmt.Fprintf(w, "Paired with %s.\n\nOne `privatae-bastion run` serves every pairing:\n", cfg.HostName)
	for _, c := range all {
		// The listen address is the CLI's loopback control port for that host
		// (add-folder, git-credential). The local secret that guards it is read
		// from the pairing file by those verbs and is never shown: there is no
		// operator client to hand it to since the MCP relay was removed.
		fmt.Fprintf(w, "\n  %s\n    local: http://%s\n", c.HostName, c.ListenAddr)
	}
	fmt.Fprintf(w, "\nStart (or restart) the tunnels:\n  privatae-bastion run\n")
	fmt.Fprintf(w, "\ngit to your forge goes through this bastion — one-time setup:\n  privatae-bastion git-setup\n")
}

// pairEnrolNote says what a pairing with no second factor means on this kind
// of machine, and how to enrol one. hint "" says nothing.
func pairEnrolNote(w io.Writer, host, hint string) {
	if hint == "" {
		return
	}
	if currentAnchor() != nil {
		fmt.Fprintf(w, "\nNo second factor is enrolled here for %s, so this machine cannot approve what it\n"+
			"asks for until you enrol one. Enrol it now:\n  %s\n", host, hint)
		return
	}
	fmt.Fprintf(w, "\nNo second factor is enrolled here for %s. Until you enrol one, a folder grant or a\n"+
		"move plan from it installs on its signed grant alone, and model pulls and root\n"+
		"sessions are refused. Enrol it now, so each needs a code from this machine:\n  %s\n", host, hint)
}

// anchorFirstNetworkedPairing anchors a networked machine that has no anchor
// to the pairing just made, when it is the machine's only one and the caller
// holds machine authority (see cmdPair). Reports whether it anchored.
func anchorFirstNetworkedPairing(cfg *Config, all []*Config) (bool, error) {
	if boxMode() != modeNetworked || currentAnchor() != nil || len(all) != 1 || !machineAuthorityHeld() {
		return false, nil
	}
	if err := cmdClaimAnchor("", false, "", cfg.HostName); err != nil {
		return false, fmt.Errorf("paired with %s, but anchoring this networked machine to it failed: %w\n  anchor it with: %s", cfg.HostName, err, anchorCommandHint())
	}
	return true, nil
}

// redeemURLBase is the platform's enrollment ingress. A variable so a test can
// serve a redeem response on loopback; nothing outside tests assigns it.
var redeemURLBase = "https://api.privatae.ai"

// pairWithToken redeems a token and writes the pairing file. Shared by `pair`
// and `claim-anchor` (forceActive). Returns the new pairing and every pairing
// on the box after the write.
func pairWithToken(token string, replace, forceActive bool) (*Config, []*Config, error) {
	return pairWithTokenAt(token, "", replace, forceActive)
}

// pairWithTokenAt is pairWithToken with the redeem address: "" is the
// platform's ingress, and a unix:// URL is a Host on this machine
// (pair_unix.go). Everything before the redeem is the same for both.
func pairWithTokenAt(token, redeemURL string, replace, forceActive bool) (*Config, []*Config, error) {
	return pairWithTokenVia(token, redeemURL, "", replace, forceActive)
}

// pairWithTokenVia is pairWithTokenAt with the Host CA file an https://
// redeem URL needs (pair_tcp.go): the Host's enroll port, trusted through
// that CA alone. A unix:// or platform redeem takes no --host-ca.
func pairWithTokenVia(token, redeemURL, hostCAFile string, replace, forceActive bool) (*Config, []*Config, error) {
	// ONE BASTION PER MACHINE, and this is the check that matters most.
	//
	// It is FIRST on purpose. loadPairings below reaches pairingsDir -> MkdirAll,
	// which CREATES the forked state directory — so a guard placed after it has
	// already done the damage it exists to prevent. The hole that matters is here
	// at `pair`, not at `run`: a second OS user's HOST holds a fully enrolled
	// record for this machine whether or not their daemon ever starts, and the
	// platform cannot link the two because the device fingerprint is fresh random
	// bytes per pairing by design. A host with an enrollment the anchor never
	// admitted is precisely the traceability failure the singleton exists to close.
	//
	// Marker absent ⇒ nil ⇒ exactly today's behaviour (singleton.go).
	if err := singletonGuardForPair(); err != nil {
		return nil, nil, err
	}
	// A bad redeem URL, or a --host-ca that does not go with it, is refused
	// before the token is read: nothing is created and nothing is dialled.
	enrollSock, transport, hostCA := "", "", ""
	var tcpRedeem *url.URL
	switch {
	case redeemURL == "":
		if hostCAFile != "" {
			return nil, nil, errors.New("--host-ca goes with --redeem-url https://<the Host's enroll port>; a platform pairing needs neither")
		}
	case strings.HasPrefix(strings.ToLower(redeemURL), "https:"):
		u, err := parseTCPRedeemURL(redeemURL)
		if err != nil {
			return nil, nil, err
		}
		if hostCAFile == "" {
			return nil, nil, errors.New("--redeem-url https://… needs --host-ca <the Host's CA, PEM>: it is the only certificate the redeem trusts")
		}
		if hostCA, err = loadHostCA(hostCAFile); err != nil {
			return nil, nil, err
		}
		tcpRedeem, transport = u, transportTCP
	default:
		s, err := parseUnixRedeemURL(redeemURL)
		if err != nil {
			return nil, nil, err
		}
		if hostCAFile != "" {
			return nil, nil, errors.New("--host-ca goes with an https:// --redeem-url; over a unix socket the Host's CA comes back in its answer")
		}
		enrollSock, transport = s, transportUnix
	}
	handle, secret, err := decodeToken(token)
	if err != nil {
		return nil, nil, err
	}
	// Multi-homing (0.10.0): pairing ADDS a host, never overwrites — the old
	// single-config overwrite silently unpaired the previous host (one host's
	// embed lane died when a box re-paired to another). Conflicts are
	// checked BEFORE the redeem so a refusal doesn't burn the single-use token.
	cfgs, err := loadPairings()
	if err != nil {
		return nil, nil, err
	}
	existing, state, err := pairPrecheck(cfgs, handle, replace, forceActive)
	if err != nil {
		return nil, nil, err
	}
	if err := replaceKeepsTransport(existing, transport); err != nil {
		return nil, nil, err
	}
	if tcpRedeem != nil {
		if err := tcpPinRefusal(existing, hostCA); err != nil {
			return nil, nil, err
		}
	}
	wgPriv, wgPub, err := genWGKeypair()
	if err != nil {
		return nil, nil, err
	}
	// The stable device fingerprint is generated BEFORE the CSR and embedded
	// in it, so the host binds it from the device-signed CSR at redeem (not via TOFU).
	fp, err := genSecret(20)
	if err != nil {
		return nil, nil, err
	}
	// transport is "" for a platform redeem, whose signer takes one SAN only.
	opKey, opCSR, err := genOperatorCSR(fp, transport != "")
	if err != nil {
		return nil, nil, err
	}
	hn, _ := os.Hostname()
	body, _ := json.Marshal(redeemReq{
		Secret: secret, WGPublicKey: wgPub, OperatorCSR: opCSR,
		Hostname: hn, Platform: runtime.GOOS, Handle: handle,
	})
	if enrollSock != "" {
		rr, err := redeemOverUnix(enrollSock, body)
		if err != nil {
			return nil, nil, err
		}
		// The same belt as the platform path below: the redeemed name is
		// authoritative, and it never overwrites a pairing without --replace.
		if prev := pairingFor(cfgs, rr.hostName()); prev != nil && validHostName(rr.hostName()) {
			existing = prev
			if !replace {
				return nil, nil, fmt.Errorf("already paired with %s — run `privatae-bastion pair --replace <token>` to rotate its credentials", prev.HostName)
			}
			if err := replaceKeepsTransport(existing, transportUnix); err != nil {
				return nil, nil, err
			}
		}
		if err := unixAnswerRefusal(rr, enrollSock, opKey, existing, cfgs); err != nil {
			return nil, nil, err
		}
		cfg, err := unixPairingConfig(rr, cfgs, existing, replace, wgPriv, opKey, fp)
		if err != nil {
			return nil, nil, err
		}
		return commitPairing(cfg, existing, replace, state)
	}
	if tcpRedeem != nil {
		rr, err := redeemOverTCP(tcpRedeem, hostCA, body)
		if err != nil {
			return nil, nil, err
		}
		// The same belt as the other paths: the redeemed name is
		// authoritative, and it never overwrites a pairing without --replace.
		if prev := pairingFor(cfgs, rr.hostName()); prev != nil && validHostName(rr.hostName()) {
			existing = prev
			if !replace {
				return nil, nil, fmt.Errorf("already paired with %s — run `privatae-bastion pair --replace <token>` to rotate its credentials", prev.HostName)
			}
			if err := replaceKeepsTransport(existing, transportTCP); err != nil {
				return nil, nil, err
			}
		}
		if err := tcpAnswerRefusal(rr, tcpRedeem, hostCA, opKey, existing, cfgs); err != nil {
			return nil, nil, err
		}
		cfg, err := tcpPairingConfig(rr, cfgs, existing, replace, wgPriv, opKey, fp, hostCA)
		if err != nil {
			return nil, nil, err
		}
		return commitPairing(cfg, existing, replace, state)
	}
	// The redeem is a short-lived, token-authed call on the platform's public
	// enrollment ingress (api.privatae.ai, a normal LE cert verified by system
	// roots — no CA bootstrap). Caddy terminates it and mTLS-forwards to THIS
	// host (router cert) which runs the redeem self-scoped. It is the ONLY time
	// the bastion talks to anything but its host's tunnel.
	url := fmt.Sprintf("%s/v1/bastions/%s/redeem", redeemURLBase, handle)
	httpc := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpc.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("redeem: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var rr redeemResp
	_ = json.Unmarshal(rb, &rr)
	if resp.StatusCode != 200 {
		if rr.Error != "" {
			return nil, nil, fmt.Errorf("redeem rejected: %s", rr.Error)
		}
		return nil, nil, fmt.Errorf("redeem rejected: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	for k, v := range map[string]string{
		"operator_crt": rr.OperatorCert, "ca_crt": rr.CACert, "bearer": rr.Bearer,
		"endpoint": rr.Endpoint, "endpoint_pubkey": rr.EndpointPubKey,
		"bastion_tunnel_ip": rr.BastionTunnelIP, "host_tunnel_ip": rr.HostTunnelIP,
		"host_name": rr.HostName,
	} {
		if v == "" {
			return nil, nil, fmt.Errorf("redeem response missing %s", k)
		}
	}
	// host_name becomes a filename (pairings/<host>.json) and two dir names
	// (context/<host>, dcn/<host>). Guard it: a hostile or MITM'd redeem response
	// with a path separator or ".." could write outside the config tree, or —
	// worse — clean to another pairing's path and silently overwrite it, the exact
	// cross-host clobber this change exists to prevent. Accept only a bare hostname.
	if !validHostName(rr.HostName) {
		return nil, nil, fmt.Errorf("redeem response has an unsafe host_name %q — refusing", rr.HostName)
	}
	// host_tunnel_ip becomes the tunnel's only allowed address. Checked here so a
	// pairing that could never bring its tunnel up is not saved at all.
	if _, err := hostTunnelAllowedIP(rr.HostTunnelIP); err != nil {
		return nil, nil, fmt.Errorf("redeem response: %w", err)
	}
	// endpoint and endpoints are written into the tunnel's configuration text.
	if err := checkEndpoints(append([]string{rr.Endpoint}, rr.Endpoints...)...); err != nil {
		return nil, nil, fmt.Errorf("redeem response: %w", err)
	}
	// Belt: the redeemed host_name is authoritative — if it lands on a pairing the
	// pre-redeem handle check missed, still refuse to overwrite it.
	if prev := pairingFor(cfgs, rr.HostName); prev != nil {
		existing = prev
		if !replace {
			return nil, nil, fmt.Errorf("already paired with %s — run `privatae-bastion pair --replace <token>` to rotate its credentials", prev.HostName)
		}
	}
	opSecret, err := genSecret(24)
	if err != nil {
		return nil, nil, err
	}
	cd, err := configDir()
	if err != nil {
		return nil, nil, err
	}
	cfg := &Config{
		HostName: rr.HostName, WGPrivateKey: wgPriv,
		BastionTunnelIP: rr.BastionTunnelIP, HostTunnelIP: rr.HostTunnelIP,
		// Boot on the v4 entry the host names in "endpoint": it is the one every relay
		// serves. The first heartbeat's rotate directive walks "endpoints" and moves
		// the tunnel to the preferred entry once a real handshake proves it reachable.
		Endpoint: rr.Endpoint, Endpoints: candidateList(rr.Endpoints, rr.Endpoint),
		EndpointPubKey: rr.EndpointPubKey,
		OperatorCert:   rr.OperatorCert, OperatorKey: opKey, CACert: rr.CACert,
		Bearer: rr.Bearer, OperatorSecret: opSecret, Fingerprint: fp,
		// Per-host everything: own loopback port, own context store, own DCN state
		// (the TOFU pin is per-entity — shared dirs would bleed across hosts).
		ListenAddr:   nextListenAddr(cfgs),
		GitProxyAddr: nextGitProxyAddr(cfgs),
		ContextRoot:  filepath.Join(cd, "context", rr.HostName),
		DCNDir:       filepath.Join(cd, "dcn", rr.HostName),
	}
	if replace && existing != nil {
		// A rotation, not a new home: keep the pairing's local address and stores so
		// the operator URL, context blobs, and TOFU-pinned DCN state all survive.
		cfg.ListenAddr = existing.ListenAddr
		if existing.GitProxyAddr != "" {
			cfg.GitProxyAddr = existing.GitProxyAddr
		}
		cfg.ContextRoot = existing.ContextRoot
		cfg.DCNDir = existing.DCNDir
	}
	return commitPairing(cfg, existing, replace, state)
}

// commitPairing is the tail every redeem shares, platform or a Host on this
// machine: the state and age, the atomic save, and the stale file a renaming
// --replace leaves behind.
func commitPairing(cfg, existing *Config, replace bool, state string) (*Config, []*Config, error) {
	cfg.State = state
	// first_seen: the pairing's age. Preserved across --replace so a credential
	// rotation (or a revoked host coming back) does not reset "since".
	cfg.FirstSeen = time.Now().UTC().Format(time.RFC3339)
	if replace && existing != nil && existing.FirstSeen != "" {
		cfg.FirstSeen = existing.FirstSeen
	}
	if err := cfg.save(); err != nil {
		return nil, nil, err
	}
	// A --replace that lands a DIFFERENT host_name renames the pairing's file:
	// saveLocked writes pairings/<host_name>.json, so the old file survives and
	// loadPairings then returns BOTH. cmdRun starts every pairing, and the
	// replacement deliberately inherits the old one's ListenAddr (just above),
	// so the two collide on the same loopback port; the second bind is a fatal
	// error and takes the whole daemon down — on a box that was just
	// successfully re-paired. The old pairing's credentials are rotated out by
	// this very redeem, so it could never work again anyway.
	//
	// Ordered AFTER the successful save on purpose: a crash between the two
	// leaves a duplicate (recoverable, and the next --replace clears it), never
	// zero pairings.
	//
	// This is reachable today because a host's name can change under it (a
	// host renamed when its address moved). unpair() is deliberately not
	// reused: it refuses to remove the anchor's own pairing, which is exactly
	// the case here — the anchor is re-paired like every other host. The anchor
	// RECORD is untouched by design; anchor.json still names the old host and
	// only `claim-anchor --rotate` may re-sign it.
	if replace && existing != nil && existing.HostName != cfg.HostName {
		if err := removeStalePairingFile(existing.HostName); err != nil {
			return nil, nil, fmt.Errorf("paired as %s, but the superseded pairing file for %s "+
				"could not be removed (%w) — remove it before `run`, or the daemon will refuse "+
				"to start on a port collision", cfg.HostName, existing.HostName, err)
		}
	}
	all, err := loadPairings()
	if err != nil {
		all = []*Config{cfg}
	}
	return cfg, all, nil
}
