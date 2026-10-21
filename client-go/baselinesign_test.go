package main

// baselinesign_test.go — the accounting's signature.
//
// EVERY TEST HERE BUILDS A REAL CA AND A REAL LEAF with crypto/x509, the way
// the bridge issues an operator certificate, and drives baselineSave /
// baselineLoad / baselineVerify on the resulting files. None asserts a value it
// supplied a seam above the code under test.
//
// The last test is a FIXTURE GENERATOR: when BASELINE_FIXTURE_OUT names a
// directory it writes a signed accounting, the CA and the fingerprint there.
// The host-side test suite verifies THAT artefact — so the two
// languages are checked against one signed document, not each against its own
// fake. That is the cross-language claim baselinesign.go rests on, and it is
// tested rather than asserted.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureNotBefore is the start of every fixture certificate's validity: well
// before sampleBaseline's taken_at, so the accounting never predates its own
// certificate.
var fixtureNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// signingFixture is a CA, a leaf issued by it carrying the fingerprint SAN the
// bridge puts in an operator certificate, and the leaf's key — the same shape
// pair.go's CSR and the bridge's issuance produce.
type signingFixture struct {
	caPEM, leafPEM, keyPEM string
	fp                     string
}

func newSigningFixture(t *testing.T, fp string) signingFixture {
	t.Helper()
	uris, err := fpURIs(fp, true)
	if err != nil {
		t.Fatal(err)
	}
	return newSigningFixtureWithURIs(t, fp, uris)
}

// newSigningFixtureWithURIs issues the leaf with exactly these URI SANs, for
// the certificates a platform or an older Host issues.
func newSigningFixtureWithURIs(t *testing.T, fp string, uris []*url.URL) signingFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CEIGAS CA"},
		// VALID ACROSS THE SAMPLE'S taken_at. Both verifiers judge the
		// certificate at the moment the accounting was taken, and the sample is
		// stamped 2026-09-19T10:00:00Z — a certificate minted "now minus an hour"
		// post-dated the accounting and every host-side test failed with
		// cert_not_valid, which was the fixture's fault, not the verifier's.
		NotBefore: fixtureNotBefore, NotAfter: fixtureNotBefore.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "operator"},
		NotBefore: fixtureNotBefore, NotAfter: fixtureNotBefore.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        uris,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	return signingFixture{
		caPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		leafPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		fp:      fp,
	}
}

// newChainedSigningFixture is the shape a real pairing holds: the pairing's CA
// is the ROOT, the operator certificate is issued by an INTERMEDIATE, and
// operator_cert carries the leaf followed by that intermediate — twice, as the
// bridge returns it on the fleet. newSigningFixture issues the leaf straight
// from the CA, which is why every test passed while every real accounting was
// refused as "not issued by this pairing's CA".
func newChainedSigningFixture(t *testing.T, fp string) signingFixture {
	t.Helper()
	uris, err := fpURIs(fp, true)
	if err != nil {
		t.Fatal(err)
	}
	return newChainedSigningFixtureWithURIs(t, fp, uris)
}

// newChainedSigningFixtureWithURIs is newChainedSigningFixture with the leaf's
// URI SANs chosen by the caller.
func newChainedSigningFixtureWithURIs(t *testing.T, fp string, uris []*url.URL) signingFixture {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	issue := func(tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
		tpl.NotBefore, tpl.NotAfter = fixtureNotBefore, fixtureNotBefore.Add(10*365*24*time.Hour)
		if parent == nil {
			parent = tpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, der
	}
	rootKey, interKey, leafKey := key(), key(), key()
	root, rootDER := issue(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test Root CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, &rootKey.PublicKey, rootKey)
	inter, interDER := issue(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test Entity Intermediate"},
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &interKey.PublicKey, rootKey)
	_, leafDER := issue(&x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "operator"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: uris}, inter, &leafKey.PublicKey, interKey)
	enc := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	return signingFixture{
		caPEM:   enc(rootDER),
		leafPEM: enc(leafDER) + enc(interDER) + enc(interDER),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		fp:      fp,
	}
}

// chainFixture issues root -> interCA[0] -> interCA[1] ... -> leaf, where each
// entry says whether that intermediate is a CA. The chain PEM is the leaf
// followed by the intermediates, nearest first. For the shapes the fleet never
// sends and both verifiers must refuse the same way.
func chainFixture(t *testing.T, fp string, interCA []bool) signingFixture {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	serial := int64(1)
	issue := func(tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
		tpl.SerialNumber = big.NewInt(serial)
		serial++
		tpl.NotBefore, tpl.NotAfter = fixtureNotBefore, fixtureNotBefore.Add(10*365*24*time.Hour)
		tpl.BasicConstraintsValid = true
		if parent == nil {
			parent = tpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, der
	}
	enc := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	rootKey := key()
	parent, rootDER := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "chain root"},
		IsCA: true, KeyUsage: x509.KeyUsageCertSign}, nil, &rootKey.PublicKey, rootKey)
	parentKey := rootKey
	var inters []string
	for i, isCA := range interCA {
		k := key()
		tpl := &x509.Certificate{Subject: pkix.Name{CommonName: fmt.Sprintf("chain intermediate %d", i)}, IsCA: isCA}
		if isCA {
			tpl.KeyUsage = x509.KeyUsageCertSign
		}
		c, der := issue(tpl, parent, &k.PublicKey, parentKey)
		inters = append([]string{enc(der)}, inters...)
		parent, parentKey = c, k
	}
	leafKey := key()
	fpURIList, _ := fpURIs(fp, true)
	_, leafDER := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "operator"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: fpURIList}, parent, &leafKey.PublicKey, parentKey)
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	return signingFixture{
		caPEM:   enc(rootDER),
		leafPEM: enc(leafDER) + strings.Join(inters, ""),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		fp:      fp,
	}
}

// writeSigningPairing installs one active pairing holding the fixture's key,
// cert, CA and fingerprint — what `pair` writes at redeem.
func writeSigningPairing(t *testing.T, host string, fx signingFixture) {
	t.Helper()
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{HostName: host, OperatorKey: fx.keyPEM, OperatorCert: fx.leafPEM,
		CACert: fx.caPEM, Fingerprint: fx.fp, State: pairingActive}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(pd, host+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sampleBaseline() baselineFile {
	return baselineFile{
		Version: baselineVersion, TakenAt: "2026-09-19T10:00:00Z",
		Coverage: "processes=all,schedulers=all",
		Entries: []baselineEntry{
			{FP: "aaa", Kind: "process", Exe: "/usr/sbin/sshd", ExeDigest: "sha256:aaa",
				User: "root", Unit: "ssh.service", ArgvShape: "sshd -D"},
			// A path with characters both encoders must agree on: a quote, a
			// backslash, a non-ASCII rune, and the HTML characters Go escapes by
			// default and this scheme turns off.
			{FP: "bbb", Kind: "process", Exe: `/opt/naïve <app> & "co"\bin`, ExeDigest: "sha256:bbb",
				User: "alice", ArgvShape: "app --serve", Endpoints: []string{"http://127.0.0.1:11434"}},
		},
		Unreadable: 3,
	}
}

func TestASavedAccountingIsSignedAndVerifies(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)

	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	f, digestOK, err := baselineLoad()
	if err != nil || !digestOK {
		t.Fatalf("load: ok=%v err=%v", digestOK, err)
	}
	if f.Attestation == nil {
		t.Fatalf("the accounting was written unsigned: %q", f.UnsignedReason)
	}
	if f.Attestation.SignedBy != "one.host.privatae.ai" || f.Attestation.Alg != baselineSigAlg {
		t.Fatalf("attestation names %+v", f.Attestation)
	}
	ok, note := baselineVerify(f, fx.caPEM, fx.fp)
	if !ok {
		t.Fatalf("a freshly signed accounting did not verify: %s", note)
	}
	if n := baselineAttestationNote(f); n != "" {
		t.Fatalf("the on-disk check disagrees with the direct one: %q", n)
	}
}

// The self-digest and the attestation answer two questions and must not be
// coupled: signing must not change the digest, and the digest must not cover
// the signature.
func TestTheDigestDoesNotCoverTheAttestation(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	unsigned := sampleBaseline()
	d1, _ := baselineDigestOf(unsigned)
	if err := baselineSave(unsigned); err != nil {
		t.Fatal(err)
	}
	f, ok, _ := baselineLoad()
	if !ok {
		t.Fatal("digest broke on save")
	}
	if f.Digest != d1 {
		t.Fatalf("signing changed the digest: %s -> %s", d1, f.Digest)
	}
}

func TestEditedContentFailsTheSignatureAndNamesTheReason(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	p, _ := baselinePath()
	b, _ := os.ReadFile(p)
	edited := strings.Replace(string(b), `"unreadable": 3`, `"unreadable": 0`, 1)
	if edited == string(b) {
		t.Fatal("the fixture edit did not apply, so this test proves nothing")
	}
	if err := os.WriteFile(p, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _, err := baselineLoad()
	if err != nil {
		t.Fatal(err)
	}
	ok, note := baselineVerify(f, fx.caPEM, fx.fp)
	if ok {
		t.Fatal("an edited accounting verified")
	}
	if !strings.Contains(note, "content has changed") {
		t.Fatalf("the note must name a content change, got %q", note)
	}
}

func TestACertificateFromAnotherCAIsRefused(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	other := newSigningFixture(t, "fp-one") // same fingerprint, different CA
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	f, _, _ := baselineLoad()
	ok, note := baselineVerify(f, other.caPEM, fx.fp)
	if ok || !strings.Contains(note, "not issued by") {
		t.Fatalf("a foreign CA must be refused by name: ok=%v note=%q", ok, note)
	}
}

// THE FLEET'S SHAPE. A leaf issued by an intermediate, with the intermediate
// carried after it, verifies against a pairing that holds only the root — and
// the machine's own note, which is what rides the beat, is clean.
func TestAnAccountingSignedUnderAnIntermediateVerifiesAgainstTheRoot(t *testing.T) {
	isolateConfigDir(t)
	fx := newChainedSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	f, _, _ := baselineLoad()
	if ok, note := baselineVerify(f, fx.caPEM, fx.fp); !ok {
		t.Fatalf("an accounting signed under the pairing's intermediate was refused: %q", note)
	}
	if note := baselineAttestationNote(f); note != "" {
		t.Fatalf("the note the beat carries must be clean for the fleet's chain, got %q", note)
	}
}

// Carrying an intermediate must not let a chain END somewhere else: the same
// shape under a different root is still refused by name.
func TestAnIntermediateFromAnotherRootIsRefused(t *testing.T) {
	isolateConfigDir(t)
	fx := newChainedSigningFixture(t, "fp-one")
	other := newChainedSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	f, _, _ := baselineLoad()
	ok, note := baselineVerify(f, other.caPEM, fx.fp)
	if ok || !strings.Contains(note, "not issued by") {
		t.Fatalf("a chain ending at a foreign root must be refused by name: ok=%v note=%q", ok, note)
	}
}

// verifyChainShape signs the sample under fx and judges it against fx's root.
func verifyChainShape(t *testing.T, fx signingFixture, edit func(signerCert string) string) (bool, string) {
	t.Helper()
	isolateConfigDir(t)
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	p, _ := baselinePath()
	raw, _ := os.ReadFile(p)
	if edit != nil {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		att := doc["attestation"].(map[string]any)
		att["signer_cert"] = edit(att["signer_cert"].(string))
		raw, _ = json.Marshal(doc)
	}
	return baselineVerifyBytes(raw, fx.caPEM, fx.fp)
}

// The shape helper itself verifies at one CA intermediate, so every refusal
// below is about the shape and not a fixture that refuses everything.
func TestTheChainHelperVerifiesAtOneIntermediate(t *testing.T) {
	if ok, note := verifyChainShape(t, chainFixture(t, "fp-one", []bool{true}), nil); !ok {
		t.Fatalf("root -> CA intermediate -> leaf must verify: %q", note)
	}
}

func TestAChainThroughTwoIntermediatesIsRefused(t *testing.T) {
	ok, note := verifyChainShape(t, chainFixture(t, "fp-one", []bool{true, true}), nil)
	if ok || !strings.Contains(note, "longer than one intermediate") {
		t.Fatalf("the host accepts one intermediate at most, and so must the box: ok=%v note=%q", ok, note)
	}
}

func TestAnIntermediateThatIsNotACAIsRefused(t *testing.T) {
	ok, note := verifyChainShape(t, chainFixture(t, "fp-one", []bool{false}), nil)
	if ok || !strings.Contains(note, "not issued by") {
		t.Fatalf("a CA:FALSE certificate cannot vouch for a leaf: ok=%v note=%q", ok, note)
	}
}

// afterLeaf splits a signer text after the leaf's END line.
func afterLeaf(s string) (string, string) {
	i := strings.Index(s, "-----END CERTIFICATE-----\n") + len("-----END CERTIFICATE-----\n")
	return s[:i], s[i:]
}

// THE SIGNER TEXT MUST BE THE CANONICAL PEM OF ITS CERTIFICATES. Every shape
// here was, at some point, read one way by pem.Decode and another by the
// host's parser — some accepted on one side only. Each is refused on both.
// The same shapes are in the host's suite.
func TestANonCanonicalSignerTextIsRefused(t *testing.T) {
	const blockKey = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
	for name, edit := range map[string]func(string) string{
		"leading text":     func(s string) string { return "operator certificate:\n" + s },
		"leading space":    func(s string) string { return " " + s },
		"key block first":  func(s string) string { return blockKey + s },
		"key block inside": func(s string) string { h, t := afterLeaf(s); return h + blockKey + t },
		"other label": func(s string) string {
			h, t := afterLeaf(s)
			return h + strings.ReplaceAll(t, "CERTIFICATE-----", "X509 CERTIFICATE-----")
		},
		"indented intermediate": func(s string) string { h, t := afterLeaf(s); return h + "  " + t },
		"malformed trailing":    func(s string) string { return s + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" },
		"undecodable decoy":     func(s string) string { return "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n" + s },
		"header in leaf": func(s string) string {
			return strings.Replace(s, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n", 1)
		},
		"space after BEGIN": func(s string) string {
			return strings.Replace(s, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE----- \n", 1)
		},
		"text after leaf END": func(s string) string { h, t := afterLeaf(s); return strings.TrimSuffix(h, "\n") + " trailing\n" + t },
		"CRLF":                func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") },
		"no final newline":    func(s string) string { return strings.TrimSuffix(s, "\n") },
		"re-wrapped base64":   func(s string) string { return strings.Replace(s, "\n", "", 2) },
		"just a BEGIN line":   func(string) string { return "-----BEGIN CERTIFICATE-----" },
		"empty":               func(string) string { return "" },
		"extra final newline": func(s string) string { return s + "\n" },
		"text after last END": func(s string) string { return s + "trailing text\n" },
	} {
		ok, note := verifyChainShape(t, newChainedSigningFixture(t, "fp-one"), edit)
		if ok || !strings.Contains(note, "signer certificate on this accounting") {
			t.Fatalf("%s: a non-canonical signer text must be refused before it is read: ok=%v note=%q", name, ok, note)
		}
	}
}

// The canonical form is exactly what the fleet sends, so the check refuses
// nothing real: the chained fixture untouched verifies.
func TestTheCanonicalSignerTextVerifies(t *testing.T) {
	if ok, note := verifyChainShape(t, newChainedSigningFixture(t, "fp-one"), func(s string) string { return s }); !ok {
		t.Fatalf("the canonical chain must verify: %q", note)
	}
}

func TestACertificateForAnotherMachineIsRefused(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	f, _, _ := baselineLoad()
	ok, note := baselineVerify(f, fx.caPEM, "fp-two")
	if ok || !strings.Contains(note, "different machine") {
		t.Fatalf("a foreign fingerprint must be refused by name: ok=%v note=%q", ok, note)
	}
}

// The anchor's key signs on an anchored box even when other hosts are paired.
func TestTheAnchorPairingSignsOnAnAnchoredBox(t *testing.T) {
	isolateConfigDir(t)
	anchorFx := newSigningFixture(t, "fp-one")
	memberFx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "anchor.host.privatae.ai", anchorFx)
	writeSigningPairing(t, "member.host.privatae.ai", memberFx)
	cfgs, _ := loadPairings()
	// Two hosts, no anchor: nobody speaks for the machine.
	if signer, why := baselineSignerPairing(cfgs); signer != nil || why != baselineUnsignedNoAnchor {
		t.Fatalf("two unanchored hosts must not pick a signer: %v %q", signer, why)
	}
}

func TestAMultiHostBoxWithNoAnchorWritesUnsignedAndSaysWhy(t *testing.T) {
	isolateConfigDir(t)
	writeSigningPairing(t, "a.host.privatae.ai", newSigningFixture(t, "fp-one"))
	writeSigningPairing(t, "b.host.privatae.ai", newSigningFixture(t, "fp-one"))
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	f, _, _ := baselineLoad()
	if f.Attestation != nil {
		t.Fatal("an unanchored multi-host box signed with one host's key")
	}
	if f.UnsignedReason != baselineUnsignedNoAnchor {
		t.Fatalf("the reason must be recorded in the file: %q", f.UnsignedReason)
	}
	if n := baselineAttestationNote(f); n != "" {
		t.Fatalf("an honestly-unsigned file must not read as a problem: %q", n)
	}
}

func TestANoPairingBoxWritesUnsignedAndSaysWhy(t *testing.T) {
	isolateConfigDir(t)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	f, _, _ := baselineLoad()
	if f.Attestation != nil || f.UnsignedReason != baselineUnsignedNoPairing {
		t.Fatalf("got attestation=%v reason=%q", f.Attestation, f.UnsignedReason)
	}
}

// A key that is PRESENT but unreadable is an error, not a silent unsigned file:
// a reader cannot tell "meant to be unsigned" from "failed to sign".
func TestAnUnreadableOperatorKeyIsAnErrorNotAnUnsignedFile(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	fx.keyPEM = "-----BEGIN EC PRIVATE KEY-----\nnot a key\n-----END EC PRIVATE KEY-----\n"
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err == nil {
		t.Fatal("a corrupt operator key produced no error")
	}
	if _, err := os.Stat(func() string { p, _ := baselinePath(); return p }()); !os.IsNotExist(err) {
		t.Fatal("an accounting was written despite the signing failure")
	}
}

func TestTheAccountingIsMirroredIntoTheStore(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	p, _ := baselinePath()
	root, _ := storeDir()
	a, _ := os.ReadFile(p)
	b, err := os.ReadFile(filepath.Join(root, "baseline.json"))
	if err != nil {
		t.Fatalf("no mirror in the store: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("the store copy differs from the state-dir copy")
	}
	fi, _ := os.Stat(filepath.Join(root, "baseline.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mirror is %v, want 0600", fi.Mode().Perm())
	}
}

// Canonical form is stable across a round trip through the file, and the two
// derived keys never enter it.
func TestCanonicalFormIsStableAndExcludesDerivedKeys(t *testing.T) {
	f := sampleBaseline()
	c1, err := baselineCanonical(f)
	if err != nil {
		t.Fatal(err)
	}
	f.Digest = "anything"
	f.Attestation = &baselineAttestation{Signature: "x"}
	f.UnsignedReason = ""
	c2, _ := baselineCanonical(f)
	if string(c1) != string(c2) {
		t.Fatal("digest or attestation leaked into the canonical form")
	}
	if strings.Contains(string(c1), `"digest"`) || strings.Contains(string(c1), `"attestation"`) {
		t.Fatalf("derived keys present: %s", c1)
	}
	// TOP LEVEL ONLY. The host drops the two keys only at the top level; a
	// recursive delete here would diverge on any entry that ever carried a
	// `digest` field. Latent today (entries carry exe_digest), and a mutation
	// making the delete recursive survived — so it is pinned.
	nested, err := baselineCanonicalBytes([]byte(`{"entries":[{"digest":"keep","fp":"a"}],"digest":"drop","attestation":{"x":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(nested) != `{"entries":[{"digest":"keep","fp":"a"}]}` {
		t.Fatalf("nested derived-key names must be preserved, got %s", nested)
	}
	// No HTML escaping (a raw `<`, never `\u003c`) and non-ASCII raw: what the
	// Python side produces. The first version of this assertion had the sign
	// backwards and failed on correct output.
	if strings.Contains(string(c1), `\u003c`) || !strings.Contains(string(c1), `<app>`) ||
		!strings.Contains(string(c1), "naïve") {
		t.Fatalf("canonical escaping differs from the host's: %s", c1)
	}
}

// THE CROSS-LANGUAGE FIXTURE. Set BASELINE_FIXTURE_OUT=<dir> to write a signed
// accounting, its CA and its fingerprint for the host-side verifier's own
// test suite. Skipped otherwise.
func TestWriteCrossLanguageFixture(t *testing.T) {
	out := os.Getenv("BASELINE_FIXTURE_OUT")
	if out == "" {
		t.Skip("set BASELINE_FIXTURE_OUT to write the fixture the host verifies")
	}
	isolateConfigDir(t)
	// The fleet's shape (root CA, intermediate-issued leaf), so the host's
	// verifier is proven against what machines actually send.
	// Only the name a Host with no platform reads: the fixture ships in that
	// Host's source, and its verifier must need no other name.
	u, err := url.Parse(hostFPSANPrefix + "fp-fixture-0001")
	if err != nil {
		t.Fatal(err)
	}
	fx := newChainedSigningFixtureWithURIs(t, "fp-fixture-0001", []*url.URL{u})
	writeSigningPairing(t, "fixture.host.example.test", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	p, _ := baselinePath()
	b, _ := os.ReadFile(p)
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"baseline.json": string(b), "ca.pem": fx.caPEM, "fingerprint": fx.fp + "\n",
	} {
		if err := os.WriteFile(filepath.Join(out, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("fixture written to %s", out)
}

// THE NOTE IS WHAT THE MACHINE READS. `observe:baseline:show` and the delta
// pass both judge the accounting through baselineAttestationNote, not through
// baselineVerify directly — so a mutation that made the note ignore a failed
// verification survived every test above. This drives the note on an edited
// file and, where the pass can run, checks the note rides the delta's notes and
// so the beat.
func TestAnEditedAccountingIsFlaggedByTheNoteAndRidesTheDelta(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	p, _ := baselinePath()
	b, _ := os.ReadFile(p)
	edited := strings.Replace(string(b), `"unreadable": 3`, `"unreadable": 0`, 1)
	if edited == string(b) {
		t.Fatal("the fixture edit did not apply, so this test proves nothing")
	}
	// Keep the self-digest VALID so the only thing wrong is the signature —
	// otherwise the integrity note fires and the attestation note is untested.
	var f baselineFile
	if err := json.Unmarshal([]byte(edited), &f); err != nil {
		t.Fatal(err)
	}
	d, _ := baselineDigestOf(f)
	f.Digest = d
	re, _ := json.MarshalIndent(f, "", "  ")
	if err := os.WriteFile(p, re, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, digestOK, _ := baselineLoad()
	if !digestOK {
		t.Fatal("the fixture's digest is not valid, so the integrity note would mask this")
	}
	n := baselineAttestationNote(loaded)
	if !strings.Contains(n, "content has changed") {
		t.Fatalf("the note did not flag an edited accounting: %q", n)
	}
	if !processIsRoot() {
		t.Log("not root: the delta pass cannot run here; the note itself is verified above")
		return
	}
	r := deltaPass(&digestCache{}, time.Now(), deltaRoleOperator)
	found := false
	for _, note := range r.Notes {
		if strings.HasPrefix(note, "attestation: ") && strings.Contains(note, "content has changed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the delta pass did not carry the attestation failure in its notes: %v", r.Notes)
	}
}

// The canonical form REFUSES what the two encoders disagree on, so adding a
// float or a big integer to the accounting fails here — loudly, at signing —
// rather than as a false "tampered" verdict on every host.
func TestCanonicalRefusesNumbersTheEncodersDisagreeOn(t *testing.T) {
	for _, c := range []struct{ name, json string }{
		{"a float", `{"unreadable": 1.5}`},
		{"an integral float", `{"unreadable": 1.0}`},
		{"a small exponent", `{"unreadable": 1e-7}`},
		{"an integer past 2^53", `{"unreadable": 9223372036854775807}`},
	} {
		dec := json.NewDecoder(strings.NewReader(c.json))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		if err := baselineCheckNumbers(m, "$"); err == nil {
			t.Fatalf("%s was accepted into the canonical form", c.name)
		}
	}
	// And the accounting as it actually is — one small integer — is fine.
	if _, err := baselineCanonical(sampleBaseline()); err != nil {
		t.Fatalf("a real accounting was refused: %v", err)
	}
	// THE 2^53 BOUNDARY, probed AT the boundary. The cases above jump straight
	// to max-int64, so a mutation widening the bound to 2^60 survived: 2^54
	// would then be accepted here and refused by the host — a live asymmetry.
	for _, c := range []struct {
		lit    string
		accept bool
	}{
		{"9007199254740992", true},   // 2^53
		{"9007199254740993", false},  // 2^53 + 1
		{"-9007199254740992", true},  // -2^53
		{"-9007199254740993", false}, // -(2^53 + 1)
		{"18014398509481984", false}, // 2^54
	} {
		d := json.NewDecoder(strings.NewReader(`{"unreadable": ` + c.lit + `}`))
		d.UseNumber()
		var mm map[string]any
		_ = d.Decode(&mm)
		err := baselineCheckNumbers(mm, "$")
		if (err == nil) != c.accept {
			t.Fatalf("%s: accepted=%v, want %v", c.lit, err == nil, c.accept)
		}
	}
	// -0: the one form neither side would otherwise catch.
	dec := json.NewDecoder(strings.NewReader(`{"unreadable": -0}`))
	dec.UseNumber()
	var m map[string]any
	_ = dec.Decode(&m)
	if err := baselineCheckNumbers(m, "$"); err == nil {
		t.Fatal("-0 was accepted into the canonical form")
	}
	// A number INSIDE the derived keys is dropped before it can be refused —
	// the host does the same, and the two must agree.
	if _, err := baselineCanonicalBytes([]byte(`{"unreadable":1,"attestation":{"key_version":2.5},"digest":"d"}`)); err != nil {
		t.Fatalf("a number inside a derived key was refused, which the host would verify: %v", err)
	}
}

// ── signing review round ────────────────────────────────────────────────────

// THE GOLDEN VECTOR. The canonical bytes for a fixed accounting, as a literal.
// This is the cross-language contract: the box signs and verifies the same
// bytes, so a change here (a kept trailing newline, HTML escaping back on, a
// dropped key) passes every self-consistency test while breaking every host.
// Only a pinned literal catches it. If this changes deliberately, the Python
// side's fixture must be regenerated in the same change.
func TestCanonicalBytesAreTheGoldenVector(t *testing.T) {
	f := baselineFile{
		Version: "privatae-baseline-v2", TakenAt: "2026-09-19T10:00:00Z",
		Coverage: "processes=all,schedulers=all",
		Entries: []baselineEntry{{FP: "aaa", Kind: "process", Exe: `/opt/naïve <app> & "co"\bin`,
			User: "root", ArgvShape: "x --y"}},
		Unreadable: 3, Digest: "ignored", UnsignedReason: "",
	}
	got, err := baselineCanonical(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"coverage":"processes=all,schedulers=all","entries":[{"argv_shape":"x --y","exe":"/opt/naïve <app> & \"co\"\\bin","fp":"aaa","kind":"process","user":"root"}],"taken_at":"2026-09-19T10:00:00Z","unreadable":3,"version":"privatae-baseline-v2"}`
	if string(got) != want {
		t.Fatalf("canonical bytes moved.\n got: %s\nwant: %s", got, want)
	}
}

func TestAKeylessPairingWritesAnUnsignedAccountingWithTheReason(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	fx.keyPEM = "" // an older pairing that never held an operator key
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatalf("a keyless pairing must not block the accounting: %v", err)
	}
	f, _, _ := baselineLoad()
	if f.Attestation != nil || f.UnsignedReason != baselineUnsignedNoKey {
		t.Fatalf("attestation=%v reason=%q", f.Attestation, f.UnsignedReason)
	}
}

// Validity is judged at the moment the accounting was TAKEN. A certificate
// that has since expired still verifies an accounting taken while it was
// valid; one that was not yet valid when the accounting was taken is refused,
// and by name.
func TestCertificateValidityIsJudgedWhenTheAccountingWasTaken(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	p, _ := baselinePath()
	raw, _ := os.ReadFile(p)

	// The same bytes with taken_at moved BEFORE the certificate existed.
	before := strings.Replace(string(raw), `"taken_at": "2026-09-19T10:00:00Z"`,
		`"taken_at": "2025-01-01T00:00:00Z"`, 1)
	if before == string(raw) {
		t.Fatal("the fixture edit did not apply")
	}
	// (Content changed, so the signature fails too — assert the validity check
	// fires FIRST and names itself.)
	ok, note := baselineVerifyBytes([]byte(before), fx.caPEM, fx.fp)
	if ok || !strings.Contains(note, "not valid at the time this accounting was taken") {
		t.Fatalf("a certificate not yet valid at taken_at must be refused by name: ok=%v %q", ok, note)
	}
	// And the real file, whose certificate will one day expire, still verifies
	// because it is judged at its own taken_at, not at now.
	if ok, note := baselineVerifyBytes(raw, fx.caPEM, fx.fp); !ok {
		t.Fatalf("judged at taken_at the real accounting must verify: %s", note)
	}
}

func TestAnUnknownAlgorithmIsRefusedByName(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	p, _ := baselinePath()
	raw, _ := os.ReadFile(p)
	edited := strings.Replace(string(raw), `"alg": "ecdsa-p256-sha256"`, `"alg": "rsa-pss-sha512"`, 1)
	if edited == string(raw) {
		t.Fatal("the fixture edit did not apply")
	}
	ok, note := baselineVerifyBytes([]byte(edited), fx.caPEM, fx.fp)
	if ok || !strings.Contains(note, "rsa-pss-sha512") {
		t.Fatalf("an unknown alg must be refused by name: ok=%v %q", ok, note)
	}
}

// A newer bastion's extra field must not read as tampering on an older one:
// the box verifies from the file's own bytes, not through a lossy parse.
func TestAFieldThisBinaryDoesNotKnowStillVerifies(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	// Build the document as a MAP with an unknown field, sign it the way the
	// box does, and hand the bytes to the verifier.
	m := map[string]any{
		"version": baselineVersion, "taken_at": "2026-09-19T10:00:00Z",
		"coverage": "processes=all,schedulers=all", "entries": []any{},
		"unreadable": 0, "digest": "d",
		"future_field": "written by bastion 9.0",
	}
	rawUnsigned, _ := json.Marshal(m)
	canon, err := baselineCanonicalBytes(rawUnsigned)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := parseECPrivateKeyPEM(fx.keyPEM)
	sum := sha256.Sum256(canon)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, sum[:])
	m["attestation"] = baselineAttestation{Alg: baselineSigAlg, SignedBy: "one.host.privatae.ai",
		SignerCert: fx.leafPEM, Signature: base64.StdEncoding.EncodeToString(sig)}
	raw, _ := json.Marshal(m)
	ok, note := baselineVerifyBytes(raw, fx.caPEM, fx.fp)
	if !ok {
		t.Fatalf("a version-skewed file read as tampered on the box: %s", note)
	}
}

// unsigned_reason is COVERED by the signature — only digest and attestation
// are dropped — so planting one on a signed file is a content change.
func TestEditingTheUnsignedReasonOnASignedFileFails(t *testing.T) {
	isolateConfigDir(t)
	fx := newSigningFixture(t, "fp-one")
	writeSigningPairing(t, "one.host.privatae.ai", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	p, _ := baselinePath()
	raw, _ := os.ReadFile(p)
	edited := strings.Replace(string(raw), `"attestation": {`, `"unsigned_reason": "planted",
  "attestation": {`, 1)
	if edited == string(raw) {
		t.Fatal("the fixture edit did not apply")
	}
	if ok, _ := baselineVerifyBytes([]byte(edited), fx.caPEM, fx.fp); ok {
		t.Fatal("an edited unsigned_reason verified — it is not covered by the signature")
	}
}

// A platform-issued certificate names the fingerprint under the platform's name
// only, a Host with no platform's under its own; each verifies alone.
func TestAFingerprintUnderEitherNameVerifies(t *testing.T) {
	for _, prefix := range []string{fpSANPrefix, hostFPSANPrefix} {
		isolateConfigDir(t)
		u, _ := url.Parse(prefix + "fp-one")
		fx := newSigningFixtureWithURIs(t, "fp-one", []*url.URL{u})
		writeSigningPairing(t, "one.host.example.test", fx)
		if err := baselineSave(sampleBaseline()); err != nil {
			t.Fatal(err)
		}
		f, _, _ := baselineLoad()
		if ok, note := baselineVerify(f, fx.caPEM, "fp-one"); !ok {
			t.Fatalf("%s: a fingerprint under this name alone must verify: %q", prefix, note)
		}
	}
}

// Two names carrying two different fingerprints name two machines; the
// verifier refuses rather than picking one.
func TestACertificateNamingTwoMachinesIsRefused(t *testing.T) {
	isolateConfigDir(t)
	a, _ := url.Parse(fpSANPrefix + "fp-one")
	b, _ := url.Parse(hostFPSANPrefix + "fp-two")
	fx := newSigningFixtureWithURIs(t, "fp-one", []*url.URL{a, b})
	writeSigningPairing(t, "one.host.example.test", fx)
	if err := baselineSave(sampleBaseline()); err != nil {
		t.Fatal(err)
	}
	f, _, _ := baselineLoad()
	ok, note := baselineVerify(f, fx.caPEM, "")
	if ok || !strings.Contains(note, "two different device fingerprints") {
		t.Fatalf("two fingerprints must be refused by name: ok=%v note=%q", ok, note)
	}
}
