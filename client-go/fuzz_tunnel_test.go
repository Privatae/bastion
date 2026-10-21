package main

// Fuzz target for the tunnel's one allowed address. host_tunnel_ip arrives in
// the pairing response and becomes the WireGuard peer's AllowedIPs; whatever
// the string, the answer is either a refusal or exactly one address.

import (
	"net/netip"
	"testing"
)

func FuzzATunnelAddressIsOneHostOrRefused(f *testing.F) {
	for _, s := range []string{"2001:db8::e:3", "10.0.0.1", "2001:db8::e:3/64", "::/0", "0.0.0.0/0",
		"", "::", "2001:db8::e:3%eth0", "::ffff:10.0.0.1", "ff02::1", " 2001:db8::1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := hostTunnelAllowedIP(s)
		if err != nil {
			return
		}
		p, perr := netip.ParsePrefix(got)
		if perr != nil {
			t.Fatalf("%q -> %q, which is not a prefix: %v", s, got, perr)
		}
		if p.Bits() != p.Addr().BitLen() {
			t.Fatalf("%q -> %q covers more than one address", s, got)
		}
		if a, _ := netip.ParseAddr(s); a != p.Addr() {
			t.Fatalf("%q -> %q is not the address it was given", s, got)
		}
		if p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
			t.Fatalf("%q -> %q is not one host", s, got)
		}
	})
}
