//go:build !windows

// Tagged !windows: it borrows setupBox (anchor_test.go) and
// withMachineAuthority (claims_unix_test.go).

package main

// `pair` says to enrol a second factor after every pairing that leaves this
// machine without one, not only after it anchors a networked machine. On a
// local machine a pairing with no factor installs a folder grant on the host's
// signed grant alone, so the person has to be told at the moment they pair.

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func pairReportOf(cfg *Config, all []*Config, anchored bool) string {
	var b strings.Builder
	pairReport(&b, cfg, all, anchored)
	return b.String()
}

func pairedHere(t *testing.T, host string, set func(*Config)) (*Config, []*Config) {
	t.Helper()
	all, err := loadPairings()
	if err != nil {
		t.Fatal(err)
	}
	cfg := pairingFor(all, host)
	if cfg == nil {
		t.Fatalf("%s is not paired", host)
	}
	if set != nil {
		set(cfg)
	}
	return cfg, all
}

func enrolFactor(t *testing.T, cfg *Config) {
	t.Helper()
	if err := stepupSave(cfg.dcnDir(), &stepupFile{SecretB32: "INVENTEDTESTAAAA", EnrolledAt: "2026-01-02T03:04:05Z"}); err != nil {
		t.Fatal(err)
	}
	if !stepupEnrolled(cfg.dcnDir()) {
		t.Fatal("the fixture factor does not read as enrolled")
	}
}

// MUTATION: print the hint only when the pairing anchored the machine.
// RESULT: red — the local, TCP, unix and pending forms say nothing.
func TestEveryPairingWithoutAFactorIsToldToEnrolOne(t *testing.T) {
	for _, f := range []struct {
		name string
		set  func(*Config)
	}{
		{"over the tunnel", nil},
		{"over TCP", func(c *Config) { c.Transport, c.LaneAddr = transportTCP, "127.0.0.1:8811" }},
		{"over a unix socket", func(c *Config) { c.Transport, c.LaneSocket = transportUnix, "/run/privatae-host/lane.sock" }},
	} {
		t.Run("local machine, "+f.name, func(t *testing.T) {
			withMachineAuthority(t, false)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			writePairing(t, tMember)
			cfg, all := pairedHere(t, tMember, f.set)
			out := pairReportOf(cfg, all, false)
			if !strings.Contains(out, "\n  privatae-bastion stepup-enroll\n") {
				t.Fatalf("a local pairing with no factor must be told to enrol one, as its own user:\n%s", out)
			}
			if !strings.Contains(out, "signed grant alone") {
				t.Fatalf("the hint says what no factor means here:\n%s", out)
			}
			enrolFactor(t, cfg)
			if out := pairReportOf(cfg, all, false); strings.Contains(out, "stepup-enroll") {
				t.Fatalf("a pairing that keeps its factor (a --replace) is not told to enrol again:\n%s", out)
			}
		})
	}

	t.Run("anchored by this pairing: said once", func(t *testing.T) {
		withMachineAuthority(t, true)
		setupBox(t)
		cfg, all := pairedHere(t, tAnchor, nil)
		out := pairReportOf(cfg, all, true)
		if strings.Count(out, "stepup-enroll") != 1 || !strings.Contains(out, "\n  sudo -H privatae-bastion stepup-enroll\n") {
			t.Fatalf("the anchoring pairing names the factor once, with machine authority:\n%s", out)
		}
	})

	t.Run("a pending host on an anchored machine", func(t *testing.T) {
		withMachineAuthority(t, true)
		setupBox(t)
		writePairingState(t, tMember, pairingPending)
		cfg, all := pairedHere(t, tMember, nil)
		out := pairReportOf(cfg, all, false)
		if !strings.Contains(out, "sudo -H privatae-bastion stepup-enroll --host "+tMember) ||
			!strings.Contains(out, "cannot approve") {
			t.Fatalf("a second host on an anchored machine is told to enrol a factor for it, by name:\n%s", out)
		}
	})

	t.Run("an approval device pinned is a way to approve", func(t *testing.T) {
		withMachineAuthority(t, true)
		setupBox(t)
		writePairingState(t, tMember, pairingPending)
		pub, _, _ := ed25519.GenerateKey(nil)
		if err := pinDeviceKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
			t.Fatal(err)
		}
		cfg, all := pairedHere(t, tMember, nil)
		if out := pairReportOf(cfg, all, false); strings.Contains(out, "stepup-enroll") {
			t.Fatalf("with a device pinned there is a way to approve; no hint:\n%s", out)
		}
	})
}

// The line is run as whoever ran `pair`, on each platform.
func TestStepupEnrollHintIsRunAsWhoeverPaired(t *testing.T) {
	for _, c := range []struct {
		goos      string
		authority bool
		paired    int
		want      string
	}{
		{"linux", false, 1, "privatae-bastion stepup-enroll"},
		{"linux", true, 1, "sudo -H privatae-bastion stepup-enroll"},
		{"darwin", true, 2, "sudo -H privatae-bastion stepup-enroll --host h1.example.test"},
		{"windows", true, 1, "privatae-bastion stepup-enroll   (from this Administrator terminal)"},
		{"windows", false, 2, "privatae-bastion stepup-enroll --host h1.example.test"},
	} {
		if got := stepupEnrollHintFor(c.goos, c.authority, "h1.example.test", c.paired); got != c.want {
			t.Errorf("%s authority=%v paired=%d: %q, want %q", c.goos, c.authority, c.paired, got, c.want)
		}
	}
}
