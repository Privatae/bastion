//go:build !windows

// Tagged !windows: it borrows setupBox (anchor_test.go) and stubOwnAddrs
// (ownaddr_test.go).

package main

// The deprecated IPv6 forms are no destination of their own, and where each
// is delivered depends on the platform, so every lane refuses them: the
// anchored egress lane, the local one, and a coder run's proxy, which refused
// them first.

import (
	"context"
	"testing"
)

var obsoleteForms = []string{
	"[::c633:6408]:443",        // IPv4-compatible ::198.51.100.8
	"[::7f00:1]:11434",         // IPv4-compatible ::127.0.0.1
	"[::c0a8:3214]:80",         // IPv4-compatible ::192.168.50.20, a LAN address
	"[::ffff:0:c633:6408]:443", // IPv4-translated ::ffff:0:198.51.100.8
	"[::ffff:0:7f00:1]:80",     // IPv4-translated ::ffff:0:127.0.0.1
	"[fec0::5]:80",             // site-local
	"[feff:1::9]:443",          // the top of fec0::/10
	"compat.example.test:443",  // a name with one such answer among public ones
	"sitelocal.example.test:80",
}

func answerObsoleteNames(t *testing.T) {
	answerEgressNames(t, map[string][]string{
		"compat.example.test":    {"198.51.100.8", "::c633:6408"},
		"sitelocal.example.test": {"fec0::5"},
		"public.example.test":    {"198.51.100.8", "2001:db8::8"},
	})
}

// MUTATION: classify the three forms as public in classifyIP.
// RESULT: red — both egress lanes hand them to the dial.
func TestEveryLaneRefusesTheDeprecatedIPv6Forms(t *testing.T) {
	ctx := context.Background()
	refusedOn := func(t *testing.T, lane string) {
		t.Helper()
		for _, hp := range obsoleteForms {
			if addrs, why := egressVettedAddrs(ctx, hp); why == "" || addrs != nil {
				t.Errorf("%s must be refused on the %s egress lane, got dial %v", hp, lane, addrs)
			}
		}
		for _, hp := range []string{"198.51.100.8:443", "public.example.test:443"} {
			if _, why := egressVettedAddrs(ctx, hp); why != "" {
				t.Errorf("%s is the public internet and passes the %s egress lane: %s", hp, lane, why)
			}
		}
	}

	t.Run("anchored", func(t *testing.T) {
		setupBox(t)
		stubOwnAddrs(t, loopbackOnly, localRange())
		answerObsoleteNames(t)
		refusedOn(t, "anchored")
	})

	t.Run("local", func(t *testing.T) {
		localEgressFixture(t)
		answerObsoleteNames(t)
		refusedOn(t, "local")
	})

	t.Run("a coder run's proxy agrees", func(t *testing.T) {
		stubOwnAddrs(t, loopbackOnly, localRange())
		for _, hp := range obsoleteForms[:7] {
			if addrs, why := coderVettedAddrs(ctx, hp, nil); why == "" || addrs != nil {
				t.Errorf("%s must be refused on a coder run's proxy, got dial %v", hp, addrs)
			}
		}
		if _, why := coderVettedAddrs(ctx, "198.51.100.8:443", nil); why != "" {
			t.Errorf("the public internet passes a coder run's proxy: %s", why)
		}
	})
}
