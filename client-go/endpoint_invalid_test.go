//go:build !windows

// Uses fakeToken from pairing_redeem_test.go and setupBox/driveOp from
// anchor_test.go, both unix-only.

package main

// A pairing whose file holds an endpoint this build refuses loads as invalid
// and is never served (endpoint_test.go). These are the paths that could
// still act on it: anchoring the box to it, an approval from the anchor host,
// what the hosts are told about it, and the two ways a person clears it.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unservedEndpoint is one the endpoint check refuses (badTunnelEndpoints).
const unservedEndpoint = "203.0.113.7:51820\nallowed_ip=::/0"

// writeUnservedPairing writes a pairing file in the given state whose
// endpoint this build refuses, and returns its path.
func writeUnservedPairing(t *testing.T, host, state string) string {
	t.Helper()
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(Config{HostName: host, WGPrivateKey: "k", BastionTunnelIP: "fd12:9::a:1",
		State: state, Endpoint: unservedEndpoint})
	p := filepath.Join(pd, host+".json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fileState is the state field as written in host's pairing file.
func fileState(t *testing.T, host string) string {
	t.Helper()
	pd, _ := pairingsDir()
	raw, err := os.ReadFile(filepath.Join(pd, host+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c.State
}

// claim-anchor names the reason and writes nothing: the pairing keeps its
// state, and the box is neither anchored nor claimed. As the sole pairing and
// named with --host among others, in the legacy active state and pending.
func TestClaimAnchorRefusesAPairingThatIsNotServed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("claim-anchor needs machine authority, which needs root")
	}
	for _, c := range []struct {
		name   string
		others []string
		host   string
	}{{"sole pairing", nil, ""}, {"named with --host", []string{tAnchor}, tMember}} {
		for _, st := range []string{"", pairingPending} {
			t.Run(c.name+"/"+st, func(t *testing.T) {
				t.Setenv("XDG_CONFIG_HOME", t.TempDir())
				withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
				if err := setBoxMode(modeNetworked); err != nil {
					t.Fatal(err)
				}
				for _, o := range c.others {
					writePairing(t, o)
				}
				p := writeUnservedPairing(t, tMember, st)
				err := cmdClaimAnchor("", false, "", c.host)
				if err == nil || !contains(err.Error(), "not a host:port") || !contains(err.Error(), p) {
					t.Fatalf("claim-anchor must refuse the pairing, naming its file and why: %v", err)
				}
				if a := currentAnchor(); a != nil {
					t.Fatalf("a refused claim anchored the box: %+v", a)
				}
				if oc := currentOwnerClaim(); oc != nil {
					t.Fatalf("a refused claim wrote the owner claim: %+v", oc)
				}
				if got := fileState(t, tMember); got != st {
					t.Fatalf("a refused claim changed the pairing's state from %q to %q", st, got)
				}
			})
		}
	}
}

// The anchor host's approval of such a pairing is refused: it is not made
// active, no grant is kept, and the refusal names no file of this machine.
// The copy updatePairingOnDisk hands back carries the same mark, so a caller
// that starts a pairing from it starts nothing.
func TestAnApprovalOfAPairingThatIsNotServedIsRefused(t *testing.T) {
	priv := setupBox(t)
	writeUnservedPairing(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	_, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig})
	if code != 126 || !contains(errOut, "not served") {
		t.Fatalf("the approval must be refused (126, not served): %d %s", code, errOut)
	}
	pd, _ := pairingsDir()
	if contains(errOut, pd) {
		t.Fatalf("the refusal sent to the host names a file of this machine: %s", errOut)
	}
	if got := fileState(t, tMember); got != pairingPending {
		t.Fatalf("a refused approval changed the state to %q", got)
	}
	if _, err := loadPairingGrant(tMember); err == nil {
		t.Fatal("a refused approval kept the grant")
	}

	c, err := updatePairingOnDisk(tMember, func(d *Config) { d.State = pairingActive })
	if err != nil {
		t.Fatal(err)
	}
	if c.invalid == "" || c.active() {
		t.Fatalf("the copy written back must still be invalid and never active: invalid=%q active=%v", c.invalid, c.active())
	}
	if startPairing(c) {
		t.Fatal("a pairing that is not served was started")
	}
}

// What the hosts hear: neither the peer list every host gets, nor the
// pairing list the anchor host gets (in the heartbeat and from pairing_list),
// names such a pairing, and every state they do carry is one a host knows.
// The machine's own status still shows it invalid (endpoint_test.go).
func TestNoHostIsToldOfAPairingThatIsNotServed(t *testing.T) {
	setupBox(t)
	const beta, pend = "beta.host.privatae.ai", "pend.host.privatae.ai"
	writePairing(t, beta)
	writeUnservedPairing(t, tMember, "")
	writeUnservedPairing(t, pend, pairingPending)
	known := map[string]bool{pairingActive: true, pairingPending: true, pairingRevoked: true}

	peers := peersFor(tAnchor)
	if len(peers) != 1 || peers[0].HostName != beta {
		t.Fatalf("the peers must be only %s, got %+v", beta, peers)
	}
	for _, p := range peers {
		if !known[p.State] {
			t.Fatalf("a peer was sent with a state a host does not know: %+v", p)
		}
	}
	list := pairingsReport()
	var names []string
	for _, e := range list {
		names = append(names, e.HostName)
		if !known[e.State] {
			t.Fatalf("a pairing was sent with a state a host does not know: %+v", e)
		}
	}
	if got := strings.Join(names, ","); got != tAnchor+","+beta {
		t.Fatalf("the anchor host's list must be %s,%s, got %s", tAnchor, beta, got)
	}
	out, errOut, code := driveOp(t, tAnchor, "pairing_list", nil)
	if code != 0 || contains(out, tMember) || contains(out, pend) || contains(out, pairingInvalid) {
		t.Fatalf("pairing_list must leave the pairing out: %d %s %s", code, out, errOut)
	}
	if u := unapprovedAttempts(time.Now().Add(24 * time.Hour)); len(u) != 0 {
		t.Fatalf("a pairing that is not served is no unapproved attempt: %+v", u)
	}
	cfgs, err := loadPairings()
	if err != nil {
		t.Fatal(err)
	}
	if c := pairingFor(cfgs, tMember); c == nil || c.stateName() != pairingInvalid {
		t.Fatalf("this machine still lists it invalid: %+v", c)
	}
}

// pair --replace over such a pairing pairs it again, served; unpair removes
// one. Both through the commands a person runs.
func TestPairReplaceAndUnpairClearAPairingThatIsNotServed(t *testing.T) {
	uiTestConfigDir(t)
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	prev := unpairNeedsRoot
	unpairNeedsRoot = func() bool { return false }
	t.Cleanup(func() { unpairNeedsRoot = prev })
	const host, good = "acme.host.privatae.ai", "203.0.113.7:51820"
	redeem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"operator_crt": "CERT", "ca_crt": "CA", "bearer": "b",
			"endpoint": good, "endpoints": []string{good},
			"endpoint_pubkey": testWGKey(t), "bastion_tunnel_ip": "2001:db8::a:1",
			"host_tunnel_ip": "2001:db8::e:3", "host_name": host,
		})
	}))
	defer redeem.Close()
	old := redeemURLBase
	redeemURLBase = redeem.URL
	t.Cleanup(func() { redeemURLBase = old })

	writeUnservedPairing(t, host, "")
	if err := cmdPair(fakeToken("acme"), "", "", true); err != nil {
		t.Fatalf("pair --replace over a pairing that is not served: %v", err)
	}
	cfgs, err := loadPairings()
	if err != nil || len(cfgs) != 1 {
		t.Fatalf("after pair --replace one pairing loads: %v %v", cfgs, err)
	}
	if c := cfgs[0]; c.HostName != host || c.invalid != "" || !c.active() || c.Endpoint != good {
		t.Fatalf("pair --replace must leave a served pairing: %q invalid=%q active=%v endpoint=%q",
			c.HostName, c.invalid, c.active(), c.Endpoint)
	}

	writeUnservedPairing(t, host, "")
	if err := cmdUnpair(host); err != nil {
		t.Fatalf("unpair of a pairing that is not served: %v", err)
	}
	if cfgs, err := loadPairings(); err != nil || len(cfgs) != 0 {
		t.Fatalf("after unpair nothing is left: %v %v", cfgs, err)
	}
	pd, _ := pairingsDir()
	if _, err := os.Stat(filepath.Join(pd, host+".json")); !os.IsNotExist(err) {
		t.Fatalf("the pairing file is still there: %v", err)
	}
}
