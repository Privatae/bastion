//go:build !windows

// Uses setupBox, withMarkerAt and withMachineAuthority, which live behind
// //go:build !windows (see anchor_test.go's header).

package main

// release-anchor (anchor_release.go): a Host deleted with its data and set up
// again can be paired and anchored on this box, through the administrator,
// and through nobody else. Every value here is invented.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// releaseTestCA is an invented self-signed CA certificate, PEM.
func releaseTestCA(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func releaseTestCAFile(t *testing.T, pemText string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "host-ca.pem")
	if err := os.WriteFile(p, []byte(pemText), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// releaseTestBox is a box anchored to tAnchor, which pinned oldCA, with the
// state the dead Host left. It returns that state's directory and oldCA.
func releaseTestBox(t *testing.T) (dcn, oldCA string) {
	t.Helper()
	setupBox(t)
	// A marker of this test's own: the machine-scoped one belongs to whatever
	// bastion is installed where the suite runs (TestClaimAnchorWalls says why).
	withMarkerAt(t, filepath.Join(t.TempDir(), "machine.json"))
	prev := unpairNeedsRoot
	unpairNeedsRoot = func() bool { return false }
	t.Cleanup(func() { unpairNeedsRoot = prev })
	prevConsole := releaseConsole
	releaseConsole = func() bool { return false }
	t.Cleanup(func() { releaseConsole = prevConsole })
	cfgs, err := loadPairings()
	if err != nil {
		t.Fatal(err)
	}
	c := pairingFor(cfgs, tAnchor)
	oldCA = releaseTestCA(t, "old host CA (invented)")
	c.CACert = oldCA
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	dcn = c.dcnDir()
	// What the dead Host left: its pinned signing key and the factor enrolled for it.
	if err := os.WriteFile(filepath.Join(dcn, "dcn.json"), []byte(`{"verify_pubkey":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stepupSave(dcn, &stepupFile{SecretB32: pipeTestSecret, EnrolledAt: "2026-10-01T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	return dcn, oldCA
}

// stillAnchoredAndPaired fails the test unless nothing was released.
func stillAnchoredAndPaired(t *testing.T, dcn, why string) {
	t.Helper()
	if a := currentAnchor(); a == nil || a.AnchorHost != tAnchor {
		t.Fatalf("%s: the anchor was dropped", why)
	}
	cfgs, _ := loadPairings()
	if pairingFor(cfgs, tAnchor) == nil {
		t.Fatalf("%s: the Host was unpaired", why)
	}
	if !fileExists(filepath.Join(dcn, "stepup.json")) {
		t.Fatalf("%s: the Host's factor was set aside", why)
	}
}

func TestReleaseAnchorRefusesAHostWhoseCAIsUnchanged(t *testing.T) {
	dcn, oldCA := releaseTestBox(t)
	withMachineAuthority(t, true)
	// The same CA is the same Host, alive: refused, and nothing changes.
	err := cmdReleaseAnchor(tAnchor, releaseTestCAFile(t, oldCA), false)
	if err == nil || !strings.Contains(err.Error(), "is not gone") {
		t.Fatalf("the same Host's CA must be refused: %v", err)
	}
	stillAnchoredAndPaired(t, dcn, "same CA")
	// No CA at all: nothing shows the Host is gone.
	if err := cmdReleaseAnchor(tAnchor, "", false); err == nil || !strings.Contains(err.Error(), "--host-ca") {
		t.Fatalf("a release with no new CA must be refused: %v", err)
	}
	stillAnchoredAndPaired(t, dcn, "no CA")
	// --force is for a person at a terminal; an installer's captured output is not one.
	if err := cmdReleaseAnchor(tAnchor, "", true); err == nil || !strings.Contains(err.Error(), "Administrator terminal") {
		t.Fatalf("--force off a console must be refused: %v", err)
	}
	stillAnchoredAndPaired(t, dcn, "--force off a console")
	// At a terminal, --force releases even the same CA.
	releaseConsole = func() bool { return true }
	if err := cmdReleaseAnchor(tAnchor, releaseTestCAFile(t, oldCA), true); err != nil {
		t.Fatalf("--force at a terminal: %v", err)
	}
	if currentAnchor() != nil {
		t.Fatal("--force at a terminal did not release the anchor")
	}
}

func TestReleaseAnchorRefusesWhenThisBoxPinnedNoCA(t *testing.T) {
	dcn, _ := releaseTestBox(t)
	withMachineAuthority(t, true)
	cfgs, _ := loadPairings()
	c := pairingFor(cfgs, tAnchor)
	c.CACert = ""
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	err := cmdReleaseAnchor(tAnchor, releaseTestCAFile(t, releaseTestCA(t, "new host CA (invented)")), false)
	if err == nil || !strings.Contains(err.Error(), "pinned no Host CA") {
		t.Fatalf("with no pin to compare, only --force releases: %v", err)
	}
	stillAnchoredAndPaired(t, dcn, "no pin")
}

func TestAReinstalledHostCannotPairAnAnchoredBoxWithoutTheRelease(t *testing.T) {
	releaseTestBox(t)
	cfgs, _ := loadPairings()
	// The same name: refused as already paired, and --replace keeps the old CA
	// (pair_tcp.go), so the new Host has no way in.
	if _, _, err := pairPrecheck(cfgs, handleOf(tAnchor), false, false); err == nil {
		t.Fatal("a second pairing under the anchor's name was let through")
	}
	// Another name: it would wait, pending, for an anchor that is gone.
	if _, state, err := pairPrecheck(cfgs, "fresh-host", false, false); err != nil || state != pairingPending {
		t.Fatalf("a new Host on an anchored box waits for the anchor: state %q err %v", state, err)
	}
	// And the anchor cannot be unpaired.
	if _, err := unpairHost(tAnchor); err == nil {
		t.Fatal("the anchor was unpaired")
	}
}

func TestReleaseAnchorNeedsMachineAuthorityAndTheAnchorsName(t *testing.T) {
	releaseTestBox(t)
	newCA := releaseTestCAFile(t, releaseTestCA(t, "new host CA (invented)"))
	withMachineAuthority(t, false)
	if err := cmdReleaseAnchor(tAnchor, newCA, false); err == nil || !strings.Contains(err.Error(), "machine authority") {
		t.Fatalf("release without machine authority: %v", err)
	}
	withMachineAuthority(t, true)
	writePairing(t, tMember)
	if err := cmdReleaseAnchor(tMember, newCA, false); err == nil || !strings.Contains(err.Error(), "anchored to "+tAnchor) {
		t.Fatalf("releasing a host that is not the anchor must be refused: %v", err)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != tAnchor {
		t.Fatal("a refused release changed the anchor")
	}
}

func TestReleaseAnchorLetsANewHostPairAndAnchor(t *testing.T) {
	dcn, _ := releaseTestBox(t)
	newCA := releaseTestCAFile(t, releaseTestCA(t, "new host CA (invented)"))
	withMachineAuthority(t, true)
	if p, err := anchorConsentPath(); err == nil {
		_ = os.WriteFile(p, []byte(`{}`), 0o600)
	}
	if err := cmdReleaseAnchor(tAnchor, newCA, false); err != nil {
		t.Fatalf("release: %v", err)
	}
	if currentAnchor() != nil {
		t.Fatal("still anchored")
	}
	if p, _ := anchorConsentPath(); fileExists(p) {
		t.Fatal("a rotation consent for the released anchor was left behind")
	}
	cfgs, _ := loadPairings()
	if pairingFor(cfgs, tAnchor) != nil {
		t.Fatal("the released Host is still paired")
	}
	if fileExists(dcn) {
		t.Fatal("the released Host's DCN state is still where a new pairing of that name would read it")
	}
	aside, _ := filepath.Glob(dcn + ".released-*")
	if len(aside) != 1 || !fileExists(filepath.Join(aside[0], "stepup.json")) || !fileExists(filepath.Join(aside[0], "dcn.json")) {
		t.Fatalf("its state must be kept, set aside: %v", aside)
	}
	// Again: nothing is left to release, and that is not an error, so an
	// installer can retry a step that stopped half-way.
	if err := cmdReleaseAnchor(tAnchor, newCA, false); err != nil {
		t.Fatalf("a second release must succeed with nothing to do: %v", err)
	}

	// The new Host, under the same name: the precheck lets it in as active,
	// and it starts with no inherited pin and no inherited factor.
	if _, state, err := pairPrecheck(cfgs, handleOf(tAnchor), false, false); err != nil || (state != "" && state != pairingActive) {
		t.Fatalf("the new Host must pair as active: state %q err %v", state, err)
	}
	writePairing(t, tAnchor)
	cfgs, _ = loadPairings()
	fresh := pairingFor(cfgs, tAnchor).dcnDir()
	if stepupEnrolled(fresh) || fileExists(filepath.Join(fresh, "dcn.json")) {
		t.Fatal("the new pairing inherited the old Host's pin or factor")
	}
	if err := cmdClaimAnchor("", false, "", ""); err != nil {
		t.Fatalf("claim-anchor after the release: %v", err)
	}
	if a := currentAnchor(); a == nil || a.AnchorHost != tAnchor {
		t.Fatalf("not anchored to the new Host: %+v", a)
	}
	if anchorVerifyKey() != "" {
		t.Fatal("the new anchor carries a key pin; it must be pinned on the new Host's first contact")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
