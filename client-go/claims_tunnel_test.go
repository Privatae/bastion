package main

// Scoped tunnel: the WireGuard device a pairing brings up can reach only the
// paired host. Driven on a real device with an in-memory bind and an
// in-memory network stack, so nothing leaves the process.

import (
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func testWGKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// testWGDevice is a WireGuard device on an in-memory tun and bind: the same
// device type runPairing builds, with no socket and no interface.
func testWGDevice(t *testing.T, tunnelIP string) *device.Device {
	t.Helper()
	tun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(tunnelIP)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, bindtest.NewChannelBinds()[0], device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	return dev
}

// wgPeers splits a UAPI dump into its peers' lines.
func wgPeers(t *testing.T, dev *device.Device) [][]string {
	t.Helper()
	dump, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var peers [][]string
	for _, line := range strings.Split(dump, "\n") {
		if strings.HasPrefix(line, "public_key=") {
			peers = append(peers, nil)
		}
		if len(peers) > 0 && line != "" {
			peers[len(peers)-1] = append(peers[len(peers)-1], line)
		}
	}
	return peers
}

// The pairing response carries the host's alias as one bare address, and the
// platform sends it as it is. A value
// that is not one host's address is refused, at every place the peer is
// configured, and nothing is set on the device.
func TestATunnelAddressThatIsNotOneHostIsRefused(t *testing.T) {
	for _, bad := range []string{
		"2001:db8::e:3/64", "::/0", "2001:db8::e:3/128", "0.0.0.0/0", "10.0.0.1/32",
		"", " 2001:db8::e:3", "2001:db8::e:3 ", "2001:db8::e:3%eth0", "::", "0.0.0.0",
		"ff02::1", "::ffff:10.0.0.1", "not-an-address", "2001:db8::e:3,::/0",
	} {
		if got, err := hostTunnelAllowedIP(bad); err == nil {
			t.Errorf("%q must be refused, got allowed_ip %q", bad, got)
		}
		cfg := &Config{WGPrivateKey: testWGKey(t), EndpointPubKey: testWGKey(t),
			Endpoint: "203.0.113.7:51820", HostTunnelIP: bad}
		dev := testWGDevice(t, "2001:db8::a:1")
		if err := configureTunnelPeer(dev, cfg); err == nil {
			t.Errorf("%q: configureTunnelPeer must refuse", bad)
		}
		if err := swapPeer(cfg, dev, "198.51.100.9:51820", testWGKey(t)); err == nil {
			t.Errorf("%q: swapPeer must refuse", bad)
		}
		if peers := wgPeers(t, dev); len(peers) != 0 {
			t.Errorf("%q: a refused address must leave the device with no peer, it holds %v", bad, peers)
		}
	}
	for in, want := range map[string]string{"2001:db8::e:3": "2001:db8::e:3/128", "10.0.0.1": "10.0.0.1/32"} {
		if got, err := hostTunnelAllowedIP(in); err != nil || got != want {
			t.Errorf("%q: want %q, got %q %v", in, want, got, err)
		}
	}
}

// Tunnel endpoints as the host may send them. The first is the hostile
// shape: the configuration text is one setting per line, so a newline ends
// the endpoint and starts a setting of the sender's choosing.
var (
	badTunnelEndpoints = []string{
		"203.0.113.7:51820\nallowed_ip=::/0", "[fe80::1%x\nallowed_ip=::/0]:51820",
		"203.0.113.7:51820\r", "203.0.113.7:51820\t", " 203.0.113.7:51820", "203.0.113.7:51820 ",
		"relay\x00.example.net:51820", "relay a.example.net:51820", "", "203.0.113.7",
		"203.0.113.7:0", "203.0.113.7:65536", "203.0.113.7:+80", "relay.example.net:port",
		"-relay.example.net:51820", "relay..example.net:51820", "[relay.example.net]:51820",
		"[fe80::1%eth0]:51820", "0.0.0.0:51820", "[::]:51820", "2001:db8::7:51820",
	}
	goodTunnelEndpoints = []string{"203.0.113.7:51820", "[2001:db8::7]:51820", "relay-a.example.net:51820"}
)

// An endpoint that is not one host:port is refused at every place the peer
// is configured, and nothing is set on the device.
func TestATunnelEndpointThatIsNotHostPortIsRefused(t *testing.T) {
	for _, bad := range badTunnelEndpoints {
		cfg := &Config{WGPrivateKey: testWGKey(t), EndpointPubKey: testWGKey(t),
			Endpoint: bad, HostTunnelIP: "2001:db8::e:3"}
		dev := testWGDevice(t, "2001:db8::a:1")
		if err := configureTunnelPeer(dev, cfg); err == nil {
			t.Errorf("%q: configureTunnelPeer must refuse", bad)
		}
		if err := swapPeer(cfg, dev, bad, testWGKey(t)); err == nil {
			t.Errorf("%q: swapPeer must refuse", bad)
		}
		if peers := wgPeers(t, dev); len(peers) != 0 {
			t.Errorf("%q: a refused endpoint must leave the device with no peer, it holds %v", bad, peers)
		}
	}
}

// uapiRecorder keeps the configuration text it is given, in place of a device.
type uapiRecorder struct{ texts []string }

func (r *uapiRecorder) IpcSet(s string) error { r.texts = append(r.texts, s); return nil }

// Whatever endpoint the pairing holds, the text the device is given names
// one peer with exactly one allowed address, the host's alias, or the
// pairing is refused before any text is built.
func TestThePeerConfigurationHasExactlyOneAllowedAddress(t *testing.T) {
	for _, ep := range append(append([]string{}, goodTunnelEndpoints...), badTunnelEndpoints...) {
		rec := &uapiRecorder{}
		cfg := &Config{WGPrivateKey: testWGKey(t), EndpointPubKey: testWGKey(t),
			Endpoint: ep, HostTunnelIP: "2001:db8::e:3"}
		if err := configureTunnelPeer(rec, cfg); err != nil {
			continue
		}
		for _, text := range rec.texts {
			seen := map[string]int{}
			for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
				k, _, _ := strings.Cut(line, "=")
				seen[k]++
			}
			if seen["allowed_ip"] != 1 || seen["public_key"] != 1 || seen["endpoint"] != 1 ||
				!strings.Contains(text, "\nallowed_ip=2001:db8::e:3/128\n") {
				t.Errorf("%q: the configuration must name one peer with one allowed address, got %q", ep, text)
			}
		}
	}
}

func TestTheTunnelReachesOnlyThePairedHost(t *testing.T) {
	for _, hostIP := range []string{"2001:db8::e:3", "2001:db8::e:ffff", "2001:db8::1"} {
		cfg := &Config{
			HostName:        "h.host.privatae.ai",
			WGPrivateKey:    testWGKey(t),
			EndpointPubKey:  testWGKey(t),
			Endpoint:        "203.0.113.7:51820",
			BastionTunnelIP: "2001:db8::a:1",
			HostTunnelIP:    hostIP,
		}
		dev := testWGDevice(t, cfg.BastionTunnelIP)
		if err := configureTunnelPeer(dev, cfg); err != nil {
			t.Fatalf("%s: %v", hostIP, err)
		}
		check := func(when string) {
			t.Helper()
			peers := wgPeers(t, dev)
			if len(peers) != 1 {
				t.Fatalf("%s %s: the device must hold exactly one peer, holds %d", hostIP, when, len(peers))
			}
			if got := wgAllowedIPs(dev); len(got) != 1 || got[0] != hostIP+"/128" {
				t.Fatalf("%s %s: the only allowed address must be the host's alias as a /128, got %v", hostIP, when, got)
			}
		}
		check("after pairing")

		// The live endpoint rotation replaces the peer; the scope must not move.
		other := testWGKey(t)
		if err := swapPeer(cfg, dev, "198.51.100.9:51820", other); err != nil {
			t.Fatal(err)
		}
		check("after an endpoint rotation")
		pub, _ := b64ToHex(other)
		if !strings.Contains(strings.Join(wgPeers(t, dev)[0], "\n"), "public_key="+pub) {
			t.Fatalf("%s: the rotation did not take the new peer", hostIP)
		}
	}
}
