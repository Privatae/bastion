package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writePairing drops a pairing file the way `pair` does, so peersFor reads real
// files through loadPairings rather than a stub.
func writePairing(t testing.TB, hostName string) {
	t.Helper()
	pd, err := pairingsDir()
	if err != nil {
		t.Fatalf("pairingsDir: %v", err)
	}
	b, _ := json.Marshal(Config{HostName: hostName, WGPrivateKey: "k", BastionTunnelIP: "fd00:9::a:1"})
	if err := os.WriteFile(filepath.Join(pd, hostName+".json"), b, 0o600); err != nil {
		t.Fatalf("write pairing: %v", err)
	}
}

// The whole feature in one assertion: a machine serving three hosts tells each
// of them about the OTHER two, and never about itself.
func TestPeersForExcludesSelfAndNamesTheRest(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, h := range []string{"acme.host.privatae.ai", "beta.host.privatae.ai", "gamma.host.privatae.ai"} {
		writePairing(t, h)
	}

	got := peersFor("acme.host.privatae.ai")
	if len(got) != 2 {
		t.Fatalf("expected 2 peers, got %d (%+v)", len(got), got)
	}
	for _, p := range got {
		if p.HostName == "acme.host.privatae.ai" {
			t.Fatal("a host was announced to itself as its own peer")
		}
		if p.Handle == "" {
			t.Errorf("peer %s carries no handle", p.HostName)
		}
		if p.Since == "" {
			t.Errorf("peer %s carries no since (the pairing file's mtime)", p.HostName)
		}
	}
	if got[0].Handle != "beta" || got[1].Handle != "gamma" {
		t.Errorf("handles should be the first DNS label, got %q and %q", got[0].Handle, got[1].Handle)
	}
}

// A machine that serves ONE host announces an EMPTY LIST — non-nil, so the
// heartbeat carries `"peers": []`.
//
// This test used to require nil, and that was the defect. The two states are
// not the same, and the host acts on the difference:
//
//	absent — "I cannot say." An older bastion sends no key at all, so the host
//	         keeps what it already has (its heartbeat upsert falls back to the
//	         stored list when the key is missing).
//	empty  — "I enumerated my pairings and I serve only this host." A real state
//	         change, and the one that happens the moment the user unpairs the
//	         last other host.
//
// Collapsing "none" into "absent" made that change unsendable: the fallback kept
// the stale list forever, so the Network app went on listing peers the machine
// no longer served, with nothing that could ever clear them. nil is now
// reserved for the one case that actually means it — see the sibling test.
func TestPeersForSinglePairingAnnouncesEmptyNotAbsent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writePairing(t, "acme.host.privatae.ai")

	got := peersFor("acme.host.privatae.ai")
	if got == nil {
		t.Fatalf("a sole pairing must announce an EMPTY list, not absence — " +
			"absence means 'I could not enumerate my pairings', and the host " +
			"deliberately cannot retract on it")
	}
	if len(got) != 0 {
		t.Fatalf("a sole pairing must announce no peers, got %+v", got)
	}
}

// The ONE case that is genuinely absent: the pairing directory cannot be read,
// so this box does not know what it serves. Saying "none" there would retract
// every peer the user has on the strength of a filesystem error.
func TestPeersForUnreadablePairingsIsAbsentNotEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	writePairing(t, "acme.host.privatae.ai")
	pd, err := pairingsDir()
	if err != nil {
		t.Fatalf("pairingsDir: %v", err)
	}
	if err := os.Chmod(pd, 0o000); err != nil {
		t.Skipf("cannot drop directory permissions here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(pd, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("running as root — mode 0000 does not deny root, so this case " +
			"cannot be provoked by permissions here")
	}
	if got := peersFor("acme.host.privatae.ai"); got != nil {
		t.Fatalf("an unreadable pairing directory must announce ABSENCE (nil), "+
			"never an empty list — got %+v, which would retract the user's peers "+
			"on a filesystem error", got)
	}
}

// The announcement carries NAME, HANDLE and SINCE — and nothing else. This is
// the privacy boundary this feature turns on: multi-homing keeps each pairing's
// keys and grants apart, and an announcement that leaked any of them would be
// the cross-host bleed that isolation exists to prevent. Asserted on the
// serialized JSON, because that is what actually crosses the wire.
func TestPeerAnnouncementCarriesNothingSensitive(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	pd, _ := pairingsDir()
	// A pairing fully populated with secrets, as a real one is.
	b, _ := json.Marshal(Config{
		HostName: "beta.host.privatae.ai", WGPrivateKey: "PRIVATE-WG-KEY",
		OperatorKey: "PRIVATE-OPERATOR-KEY", Bearer: "mcp-SECRET-BEARER",
		OperatorSecret: "LOCAL-SECRET", Fingerprint: "DEVICE-FINGERPRINT",
		CACert: "CA", OperatorCert: "CERT", HostTunnelIP: "fd00:9::e:9",
	})
	_ = os.WriteFile(filepath.Join(pd, "beta.host.privatae.ai.json"), b, 0o600)
	writePairing(t, "acme.host.privatae.ai")

	raw, err := json.Marshal(peersFor("acme.host.privatae.ai"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{
		"PRIVATE-WG-KEY", "PRIVATE-OPERATOR-KEY", "mcp-SECRET-BEARER",
		"LOCAL-SECRET", "DEVICE-FINGERPRINT", "CA", "CERT", "fd00:9::e:9",
	} {
		if contains(string(raw), secret) {
			t.Errorf("the peer announcement leaked %q — it must carry name/handle/since only\npayload: %s", secret, raw)
		}
	}
}

// The heartbeat must carry the three states apart: a list, an explicit empty
// list, and nothing at all. This is the wire contract the host halves on, so it
// is asserted on the serialized body rather than the slice.
//
//	non-empty -> "peers":[...]   the boxes this machine also serves
//	empty     -> "peers":[]      enumerated, and there are none. RETRACTS.
//	nil       -> key absent      cannot say; the host keeps what it has.
//
// The `empty` row is the one this test previously had backwards: it required
// `[]` to be omitted, which meant the host's retraction path (an explicit []
// clears the stored list; a missing key keeps it) could never be reached by a
// real bastion.
func TestHeartbeatDistinguishesEmptyPeersFromAbsent(t *testing.T) {
	withPeers := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil,
		[]peerAnnounce{{HostName: "beta.host.privatae.ai", Handle: "beta"}})
	if !contains(withPeers, `"peers"`) {
		t.Errorf("heartbeat dropped a non-empty peer list:\n%s", withPeers)
	}
	if !contains(withPeers, "beta.host.privatae.ai") {
		t.Errorf("heartbeat carries a peers key but not the peer:\n%s", withPeers)
	}

	// Enumerated and none: the key must be present and empty, or the user's
	// unpairing never reaches the host.
	empty := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil,
		[]peerAnnounce{})
	if !contains(empty, `"peers":[]`) {
		t.Errorf("an enumerated-but-empty peer set must travel as \"peers\":[] — "+
			"without it the host's COALESCE keeps the stale list forever:\n%s", empty)
	}

	// Could not say: no key at all, exactly like a bastion too old to report.
	absent := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if contains(absent, `"peers"`) {
		t.Errorf("a nil peer set means 'I cannot say' and must be ABSENT from the "+
			"body — sending it would retract the user's peers on a read error:\n%s", absent)
	}
}

func contains(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
