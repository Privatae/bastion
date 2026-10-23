//go:build !windows

// Uses fakeToken from pairing_redeem_test.go, unix-only.

package main

// A tunnel endpoint arrives from the host three ways: in the pairing
// response, in the rotate directive on a heartbeat answer, and from the
// pairing file those were saved to. Each one refuses an endpoint that is
// not one host:port, the file by never serving that pairing (the
// device-level checks are in claims_tunnel_test.go).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pairing response whose endpoint, or any entry of its endpoints list, is
// not one host:port is refused and nothing is saved. An IPv4, an IPv6 and a
// host name endpoint pair.
func TestAPairingResponseWithAnUnsafeEndpointSavesNothing(t *testing.T) {
	cfgHome := uiTestConfigDir(t)
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	var endpoint, hostName string
	var endpoints []string
	redeem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"operator_crt": "CERT", "ca_crt": "CA", "bearer": "b",
			"endpoint": endpoint, "endpoints": endpoints,
			"endpoint_pubkey": testWGKey(t), "bastion_tunnel_ip": "2001:db8::a:1",
			"host_tunnel_ip": "2001:db8::e:3", "host_name": hostName,
		})
	}))
	defer redeem.Close()
	old := redeemURLBase
	redeemURLBase = redeem.URL
	t.Cleanup(func() { redeemURLBase = old })

	hostName = "acme.host.privatae.ai"
	for _, bad := range badTunnelEndpoints {
		if bad == "" {
			continue // a missing endpoint has its own refusal
		}
		for _, c := range []struct {
			endpoint string
			list     []string
		}{{bad, nil}, {"203.0.113.7:51820", []string{"[2001:db8::7]:51820", bad}}} {
			endpoint, endpoints = c.endpoint, c.list
			if _, _, err := pairWithToken(fakeToken("acme"), false, false); err == nil || !strings.Contains(err.Error(), "not a host:port") {
				t.Errorf("%q in %+v: the pairing must be refused for its endpoint, got %v", bad, c, err)
			}
		}
	}
	_ = filepath.Walk(cfgHome, func(path string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			t.Errorf("a refused pairing left a file behind: %s", path)
		}
		return nil
	})

	for _, good := range goodTunnelEndpoints {
		uiTestConfigDir(t) // a local bastion serves one host: a fresh box each
		withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
		endpoint, endpoints = good, []string{good}
		cfg, _, err := pairWithToken(fakeToken("acme"), false, false)
		if err != nil {
			t.Fatalf("%q must pair: %v", good, err)
		}
		if cfg.Endpoint != good || len(cfg.Endpoints) != 1 || cfg.Endpoints[0] != good {
			t.Fatalf("%q: saved %q %q", good, cfg.Endpoint, cfg.Endpoints)
		}
	}
}

// A pairing file that already holds an unsafe endpoint (written by an older
// build, or by hand) loads as invalid, naming the file and why: it is never
// served, while every other pairing still loads, status shows it, and unpair
// removes it. A machine that upgrades is never stopped by one such file.
func TestAPairingFileWithAnUnsafeEndpointLoadsButIsNeverServed(t *testing.T) {
	uiTestConfigDir(t)
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	supervised(t)
	prev := unpairNeedsRoot
	unpairNeedsRoot = func() bool { return false }
	t.Cleanup(func() { unpairNeedsRoot = prev })
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	write := func(c *Config) string {
		t.Helper()
		b, _ := json.Marshal(c)
		p := filepath.Join(pd, c.HostName+".json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const host, other = "acme.host.privatae.ai", "other.host.privatae.ai"
	write(&Config{HostName: other, Endpoint: goodTunnelEndpoints[0]})
	for _, bad := range badTunnelEndpoints {
		if bad == "" {
			continue // a pairing over a socket has no endpoint
		}
		for _, c := range []*Config{
			{HostName: host, Endpoint: bad},
			{HostName: host, Endpoint: "203.0.113.7:51820", Endpoints: []string{bad}},
		} {
			p := write(c)
			cfgs, err := loadPairings()
			if err != nil || len(cfgs) != 2 {
				t.Fatalf("%q: one bad file must not fail the load: %v %v", bad, cfgs, err)
			}
			got := pairingFor(cfgs, host)
			if got.active() || got.stateName() != "invalid" {
				t.Errorf("%q: the pairing must load invalid: active=%v %q", bad, got.active(), got.stateName())
			}
			if out := statusOutput(t); !strings.Contains(out, host+"  [invalid]") ||
				!strings.Contains(out, "not a host:port") || !strings.Contains(out, p) {
				t.Errorf("%q: status must show the pairing invalid, naming its file and why:\n%s", bad, out)
			}
			if !pairingFor(cfgs, other).active() {
				t.Errorf("%q: the other pairing must still be served", bad)
			}
			if startPairing(got) {
				t.Errorf("%q: an invalid pairing was started", bad)
			}
		}
	}
	// The supervisor starts nothing for it either (the other pairing is
	// removed first: starting it would raise a real tunnel).
	if err := os.Remove(filepath.Join(pd, other+".json")); err != nil {
		t.Fatal(err)
	}
	superviseOnce()
	supervisor.Lock()
	running := len(supervisor.runs)
	supervisor.Unlock()
	if running != 0 {
		t.Fatalf("the supervisor started %d run(s) for an invalid pairing", running)
	}

	if h, err := unpairHost(host); err != nil || h != host {
		t.Fatalf("unpair must remove an invalid pairing: %q %v", h, err)
	}
	if cfgs, err := loadPairings(); err != nil || len(cfgs) != 0 {
		t.Fatalf("after unpair nothing is left: %v %v", cfgs, err)
	}

	for _, good := range goodTunnelEndpoints {
		write(&Config{HostName: host, Endpoint: good, Endpoints: goodTunnelEndpoints})
		if cfgs, err := loadPairings(); err != nil || len(cfgs) != 1 || cfgs[0].Endpoint != good || !cfgs[0].active() {
			t.Fatalf("%q must load and be served: %v %v", good, cfgs, err)
		}
	}
	write(&Config{HostName: host, Transport: transportUnix})
	if cfgs, err := loadPairings(); err != nil || len(cfgs) != 1 || !cfgs[0].active() {
		t.Fatalf("a pairing with no endpoint must load and be served: %v %v", cfgs, err)
	}
}

// statusOutput is what `status` prints.
func statusOutput(t *testing.T) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	serr := cmdStatus()
	os.Stdout = stdout
	_ = w.Close()
	out, _ := io.ReadAll(r)
	if serr != nil {
		t.Fatalf("status: %v", serr)
	}
	return string(out)
}

// A rotate directive that names any unsafe endpoint is not acted on; one
// that names only host:port entries is.
func TestARotateDirectiveWithAnUnsafeEndpointIsIgnored(t *testing.T) {
	for _, bad := range badTunnelEndpoints {
		if bad == "" {
			continue // an empty entry is no entry
		}
		for _, d := range [][]byte{
			directive(bad, nil, "PK="),
			directive("203.0.113.7:51820", []string{bad, "[2001:db8::7]:51820"}, "PK="),
		} {
			if c, pk := parseRotateTarget(d); len(c) != 0 || pk != "" {
				t.Errorf("%q: the directive must be ignored, got %q %q", bad, c, pk)
			}
		}
	}
	c, pk := parseRotateTarget(directive("203.0.113.7:51820", goodTunnelEndpoints, "PK="))
	if pk != "PK=" || !sameList(c, goodTunnelEndpoints) {
		t.Fatalf("a directive of host:port entries must be taken: %q %q", c, pk)
	}
}
