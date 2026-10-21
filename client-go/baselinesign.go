package main

// baselinesign.go — the accounting is SIGNED, and by a key the host already
// trusts: a signed baseline, kept on the box and mirrored to the anchor host.
//
// WHAT WAS THERE BEFORE. baseline.go's self-digest catches accident and casual
// edit and says so plainly: "it does NOT establish who took the measurement".
// The gap baseline.go used to name as "not signed" is closed here.
//
// ── WHICH KEY, AND WHY NO NEW ONE ───────────────────────────────────────────
//
// The obvious build mints a fresh signing keypair at claim-anchor and teaches
// the host to pin it. It was proposed and approved in that shape, and then
// found to be unnecessary: THE BOX ALREADY HOLDS A HOST-BOUND SIGNING KEY. At
// pair time genOperatorCSR (pair.go:85-96) generates a P-256 key that never
// leaves this machine, and the operator certificate the bridge issues for it
// carries this device's fingerprint as a URI SAN — which the host bound at
// redeem, from that device-signed CSR, under a standing invariant that the
// heartbeat is verify-not-bind and the redeem CSR is the only binder. The
// host also holds the CA that issued the certificate.
//
// So the accounting is signed with the ANCHOR pairing's operator key, and the
// host verifies it with three checks it can already make: the certificate
// chains to its CA, the certificate's fingerprint SAN is the fingerprint bound
// to this bastion's row, and the signature verifies under the certificate's
// key. No new key material on customer machines, no new pinning step, no new
// rotation path — certificate rotation already exists and this rides it.
//
// On a one-host box there is no anchor, and the only active pairing's key is
// the machine's voice. On a multi-host box with no anchor there is no single
// key that speaks for the machine, and the accounting is written UNSIGNED with
// the reason recorded in the file rather than guessed at by a reader.
//
// ── WHAT IS SIGNED ──────────────────────────────────────────────────────────
//
// Not the file bytes, and not Go's struct-ordered JSON: the host is Python, and
// reproducing encoding/json's field order and escaping there is exactly the
// kind of contract that drifts. Both sides canonicalise the same way instead:
//
//	parse the document to a map; drop the two derived keys (`digest`,
//	`attestation`); sort every key; no whitespace; NO HTML ESCAPING; NON-ASCII
//	WRITTEN RAW (Python: ensure_ascii=False — its default escapes every
//	non-ASCII character and produced a 19-byte difference on `ré` in review);
//	the host then re-escapes a raw U+2028/U+2029 to `\u2028`/`\u2029`, because
//	encoding/json escapes those two regardless. Numbers that the two encoders
//	print differently are REFUSED on both sides (baselineCanonical).
//
// SHA-256 of that, ECDSA P-256, ASN.1/DER, base64. The host-side verifier
// lives in the platform's network service and its proof verifies the
// document TestWriteCrossLanguageFixture writes — one signed document, two
// languages.
// The Go side pins the bytes with a golden vector (baselinesign_test.go) so a
// change to this form cannot pass while breaking every host silently.
//
// ── WHAT THIS PROVES, PRECISELY ─────────────────────────────────────────────
//
// CONTINUITY, NOT HARDWARE ATTESTATION. The fingerprint in the certificate's
// SAN is the value THIS BOX computed and put into its own CSR at redeem; the
// host pinned the first one a device-signed CSR carried. So a verified
// attestation proves "the pairing that redeemed as X signed this" — exactly as
// strong as that pairing, and no stronger.
//
// NOT A DEFENCE AGAINST ROOT ON THE BOX. The signing key is a 0600 file, so a
// root intruder can sign anything, and nothing in the signed content is a
// freshness token — a validly signed accounting from last month restores
// cleanly. That is inside the accepted model (deltastate.go:25-30: a root
// intruder can also stop the daemon). What closes the rollback and stale-mirror
// cases is the BEAT: it carries `baseline_taken_at`, and the host compares it
// with the `taken_at` of the mirror it verified — a mismatch is a finding.
//
// REUSING THE mTLS KEY IS SAFE, and here is why rather than only that it is:
// TLS 1.3's CertificateVerify signs sixty-four spaces, a context string and a
// transcript hash; this signs SHA-256 of a JSON object that always begins with
// `{`. Neither can be coerced into the other's shape, so the two uses are
// structurally domain-separated, and Go's hedged ECDSA nonce removes the
// classic key-reuse hazard. "No new key material" is the operational reason;
// this is the cryptographic one.
//
// The self-digest stays exactly as it was. It is the box's own quick integrity
// check and the key delta-state.json is filed under; the attestation is the
// host's proof of provenance. Two questions, two answers.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// baselineSigAlg names the scheme in the file, so a verifier that meets a
// different one refuses rather than guessing.
const baselineSigAlg = "ecdsa-p256-sha256"

// baselineAttestation is the provenance block on the accounting.
type baselineAttestation struct {
	Alg string `json:"alg"`
	// SignedBy is the host whose pairing key signed — the anchor on an anchored
	// box, the only host on a one-host box. Named so a reader knows which
	// certificate to expect without parsing one.
	SignedBy string `json:"signed_by"`
	// SignerCert is the operator certificate, PEM, followed by the intermediate
	// that issued it (the pairing's operator_cert as the bridge returned it).
	// Carried IN the file because
	// the host does not store the certificates it issues; it stores the CA and
	// the bound fingerprint, which is all it needs to judge this one.
	SignerCert string `json:"signer_cert"`
	// Signature is base64 of the DER-encoded ECDSA signature over
	// SHA-256(baselineCanonical(file)).
	Signature string `json:"signature"`
}

// baselineUnsignedReason is recorded on the file when no key could sign, so
// "unsigned" is never ambiguous between "this build cannot sign" and "this
// machine had no key that speaks for it".
const (
	baselineUnsignedNoPairing  = "no active pairing holds a key to sign with"
	baselineUnsignedNoAnchor   = "several hosts are paired and none is the anchor, so no one key speaks for this machine"
	baselineUnsignedNoKey      = "the pairing that speaks for this machine holds no operator key (an older pairing?)"
	baselineUnsignedAnchorGone = "the anchor host's pairing is not active on this machine"
)

// baselineCanonical is the byte string both sides sign and verify.
//
// SEVEN places encoding/json and Python's json.dumps differ on this data,
// measured by the reviewer against this very function over 33 inputs;
// everything else (HTML characters, quotes, backslashes, control characters,
// non-BMP, nested ordering) agrees exactly. Each is closed, and how:
//
//  1. U+2028 / U+2029: Go escapes them, Python does not. The HOST re-escapes.
//  2. Integers beyond 2^53 (float64 round-trip). REFUSED, both sides.
//  3. Floats with an integral value (1 vs 1.0). REFUSED, both sides.
//  4. Small exponents (1e-7 vs 1e-07). REFUSED, both sides.
//  5. `-0`: Python's parser makes it 0, this decoder keeps the literal. REFUSED
//     here — the only side that REFUSES it; the host prints 0 — so it is never
//     signed, and a hand-edited `-0` lands as bad_signature there.
//  6. A number inside `digest`/`attestation`: this side used to check before
//     dropping the keys, the host after. Dropped first now — ALIGNED.
//  7. A lone surrogate escape: this decoder folds it to U+FFFD; the host used
//     to refuse. The host now folds the same way — same bytes.
//
// The accounting has exactly one numeric field, Unreadable, a small count — so
// 2-4 are unreachable today and the refusal exists so that adding a float or a
// nanosecond timestamp later fails LOUDLY here rather than as a false
// "tampered" verdict on every host. A refusal is an error from signing, never
// an unsigned file.
func baselineCanonical(f baselineFile) ([]byte, error) {
	f.Digest = ""
	f.Attestation = nil
	structured, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return baselineCanonicalBytes(structured)
}

// baselineCanonicalBytes canonicalises a document from its RAW JSON, the way
// the host does. The box verifies through this too — through baselineFile it
// verified through a LOSSY parse, so a field written by a newer bastion was
// dropped before canonicalisation and an older binary reported "its content
// has changed", the loudest possible message, for a version skew the host
// verified fine.
func baselineCanonicalBytes(raw []byte) ([]byte, error) {
	// UseNumber keeps every number as its source text so the check below sees
	// what was written, not what float64 made of it.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	// Drop the derived keys FIRST, then check numbers — the same order the
	// host uses. Checking first refused a document (a number inside
	// `attestation`) the host would have verified: an asymmetry in a function
	// pair whose whole contract is byte-identity.
	delete(m, "digest")
	delete(m, "attestation")
	if err := baselineCheckNumbers(m, "$"); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	// Encode appends a newline the Python side does not produce.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// baselineIntExact is the largest integer both encoders print identically.
const baselineIntExact = 1 << 53

// baselineCheckNumbers refuses any number the two encoders would not agree on:
// anything that is not a plain integer, and any integer beyond 2^53.
func baselineCheckNumbers(v any, path string) error {
	switch x := v.(type) {
	case json.Number:
		s := x.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("%s is not an integer (%s); the accounting may hold only "+
				"strings, small integers, booleans, lists and objects", path, s)
		}
		// `-0` is the one form NEITHER side otherwise catches: Python's parser
		// turns it into 0 and prints 0, this decoder keeps the literal and
		// prints -0, and the result is a false "tampered" verdict. This is the
		// only side that refuses it, and the only side that signs, so a signed
		// document can never carry one.
		//
		// (The `.eE` guard above is belt-and-braces: Int64() below refuses every
		// such literal anyway. It exists for the error message, not the verdict.)
		if s == "-0" || strings.HasPrefix(s, "-0") {
			return fmt.Errorf("%s = %s is a negative zero, which the two encoders print differently", path, s)
		}
		n, err := x.Int64()
		if err != nil || n > baselineIntExact || n < -baselineIntExact {
			return fmt.Errorf("%s = %s exceeds 2^53; the two encoders would not agree on it", path, s)
		}
	case map[string]any:
		for k, y := range x {
			if err := baselineCheckNumbers(y, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for i, y := range x {
			if err := baselineCheckNumbers(y, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// baselineSignerPairing picks the pairing whose key speaks for this machine.
// The second return is the reason none does, or "".
func baselineSignerPairing(cfgs []*Config) (*Config, string) {
	// ONE filter, applied on BOTH branches. The anchored branch used to resolve
	// the anchor by name alone (pairingFor matches host name and handle, never
	// state), so a box whose anchor pairing was pending or revoked signed with
	// it while the unanchored branch four lines down was filtering exactly that.
	isActive := func(c *Config) bool { return c.State == "" || c.State == pairingActive }
	if a := currentAnchor(); a != nil {
		c := pairingFor(cfgs, a.AnchorHost)
		if c == nil || !isActive(c) {
			return nil, baselineUnsignedAnchorGone
		}
		if strings.TrimSpace(c.OperatorKey) == "" {
			return nil, baselineUnsignedNoKey
		}
		return c, ""
	}
	var active []*Config
	for _, c := range cfgs {
		if isActive(c) {
			active = append(active, c)
		}
	}
	switch len(active) {
	case 0:
		return nil, baselineUnsignedNoPairing
	case 1:
		// A pairing with NO key is a reason to record, not an error to raise:
		// the accounting must still be written. (A key that is PRESENT and
		// unreadable is the error — baselineSign — because a reader cannot
		// tell "meant to be unsigned" from "failed to sign".)
		if strings.TrimSpace(active[0].OperatorKey) == "" {
			return nil, baselineUnsignedNoKey
		}
		return active[0], ""
	default:
		return nil, baselineUnsignedNoAnchor
	}
}

func parseECPrivateKeyPEM(keyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("no PEM block in the operator key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// baselineSign attests the accounting with the given pairing's operator key.
func baselineSign(f *baselineFile, signer *Config) error {
	if signer == nil || strings.TrimSpace(signer.OperatorKey) == "" {
		return errors.New(baselineUnsignedNoKey)
	}
	key, err := parseECPrivateKeyPEM(signer.OperatorKey)
	if err != nil {
		return fmt.Errorf("the operator key could not be read: %w", err)
	}
	canon, err := baselineCanonical(*f)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canon)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return err
	}
	f.Attestation = &baselineAttestation{
		Alg:        baselineSigAlg,
		SignedBy:   signer.HostName,
		SignerCert: signer.OperatorCert,
		Signature:  base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}

// baselineVerify checks an attestation with the SAME three tests the host
// makes, using this pairing's CA and fingerprint.
//
// Returns ok and a note. The note is what a person reads, so it names WHICH
// test failed: an unsigned file, a certificate this CA did not issue, a
// certificate for a different machine, and a signature that does not match are
// four different situations and only the last one means the content moved.
func baselineVerify(f *baselineFile, caPEM, expectFingerprint string) (bool, string) {
	raw, err := json.Marshal(f)
	if err != nil {
		return false, "this accounting could not be re-encoded: " + err.Error()
	}
	return baselineVerifyBytes(raw, caPEM, expectFingerprint)
}

// baselineVerifyBytes is the verifier proper, over the file's own bytes.
func baselineVerifyBytes(raw []byte, caPEM, expectFingerprint string) (bool, string) {
	var head struct {
		TakenAt     string               `json:"taken_at"`
		Attestation *baselineAttestation `json:"attestation"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return false, "this accounting cannot be read: " + err.Error()
	}
	a := head.Attestation
	if a == nil {
		return false, "this accounting is not signed"
	}
	if a.Alg != baselineSigAlg {
		return false, "this accounting is signed with " + a.Alg + ", which this bastion does not verify"
	}
	// THE SIGNER CERTIFICATE IS A CHAIN: the operator certificate first, then
	// the intermediate that issued it. The bridge issues operator certificates
	// from an intermediate, and a pairing holds only the root, so judging the
	// first block alone refused every real accounting as "not issued by this
	// pairing's CA". Everything after the first block is offered as an
	// intermediate; Verify still requires the path to end at the pairing's root
	// and every hop to be a CA.
	chain, note := baselineSignerChain(a.SignerCert)
	if note != "" {
		return false, note
	}
	cert := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return false, "this pairing holds no CA to judge the signer certificate against"
	}
	// VALIDITY IS JUDGED AT THE MOMENT THE ACCOUNTING WAS TAKEN, not now. This
	// is provenance over a document at rest: an accounting taken in March under
	// a certificate that expired in June is still that machine's word, and
	// judging at time.Now() made every accounting unverifiable at the next cert
	// rotation — reported, worse, as "not issued by this CA". A certificate
	// that was not valid WHEN THE ACCOUNTING WAS TAKEN is still refused, and by
	// name. An unparseable taken_at falls back to now, the stricter choice.
	at := time.Now()
	if t, ok := parseStamp(head.TakenAt); ok {
		at = t
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		var inv x509.CertificateInvalidError
		if errors.As(err, &inv) && inv.Reason == x509.Expired {
			return false, "the signer certificate was not valid at the time this accounting was taken (" + head.TakenAt + ")"
		}
		return false, "the signer certificate was not issued by this pairing's CA: " + err.Error()
	}
	// AT MOST ONE INTERMEDIATE, the shape the bridge issues and the only one
	// the host accepts. A longer path verifying here and failing there would
	// leave the box and the host disagreeing about the same accounting.
	short := false
	for _, c := range chains {
		if len(c) <= 3 {
			short = true
		}
	}
	if !short {
		return false, "the signer certificate was not issued by this pairing's CA: its chain is longer than one intermediate"
	}
	// The fingerprint may sit under either name (pair.go fpURIs); a
	// certificate naming two different machines is refused, not resolved.
	fp := ""
	for _, u := range cert.URIs {
		s := u.String()
		for _, p := range []string{fpSANPrefix, hostFPSANPrefix} {
			if !strings.HasPrefix(s, p) {
				continue
			}
			got := strings.TrimPrefix(s, p)
			if fp != "" && got != fp {
				return false, "the signer certificate carries two different device fingerprints"
			}
			fp = got
		}
	}
	if fp == "" {
		return false, "the signer certificate carries no device fingerprint"
	}
	if expectFingerprint != "" && fp != expectFingerprint {
		return false, "the signer certificate belongs to a different machine"
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, "the signer certificate does not hold an EC key"
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return false, "the signature on this accounting is not base64"
	}
	canon, err := baselineCanonicalBytes(raw)
	if err != nil {
		return false, "this accounting could not be canonicalised: " + err.Error()
	}
	sum := sha256.Sum256(canon)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return false, "the signature does not match this accounting — its content has changed since " +
			a.SignedBy + "'s key signed it"
	}
	return true, "signed by " + a.SignedBy + "'s pairing key; verified against its CA and this machine's fingerprint"
}

// baselineSignerChain reads the signer certificate text as [leaf,
// intermediates...], or says why it cannot.
//
// THE TEXT MUST BE THE CANONICAL PEM OF ITS OWN CERTIFICATES, byte for byte:
// every block a CERTIFICATE with no headers, each re-encoded exactly as
// pem.EncodeToMemory writes it, concatenated, equal to what was carried. The
// host applies the same test to the same bytes. Two PEM parsers never agree
// on every malformed input (pem.Decode skips a block it cannot decode and
// promotes the next one to leaf; others refuse), so neither side interprets a
// non-canonical text at all. What the bridge issues and every pairing holds
// is canonical, so nothing real is refused.
func baselineSignerChain(text string) ([]*x509.Certificate, string) {
	const bad = "the signer certificate on this accounting cannot be parsed"
	var chain []*x509.Certificate
	var canon []byte
	rest := []byte(text)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, bad
		}
		chain = append(chain, c)
		canon = append(canon, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes})...)
	}
	if len(chain) == 0 {
		return nil, "the signer certificate on this accounting is not PEM"
	}
	if string(canon) != text {
		return nil, bad + ": it is not the canonical PEM of its certificates"
	}
	return chain, ""
}

// baselineAttestationNote judges the accounting on disk the way the host will,
// for `observe:baseline:show` and the delta's notes. "" when it verifies.
func baselineAttestationNote(f *baselineFile) string {
	if f == nil {
		return ""
	}
	p, err := baselinePath()
	if err != nil {
		return "the attestation could not be checked: no state dir"
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "the attestation could not be checked: " + err.Error()
	}
	return baselineAttestationNoteBytes(raw, f.Attestation != nil)
}

// baselineAttestationNoteBytes is the note over the file's own bytes (see
// baselineCanonicalBytes for why not through the struct). `signed` says whether
// the caller's parse saw an attestation, so an honestly-unsigned file is "" and
// not a problem.
//
// loadPairings runs on every pass here (60 s). It reads a directory and N small
// files, and it FAILS THE WHOLE LOAD if any one file is mid-write or malformed
// (config.go) — so a concurrent pair/unpair can produce "pairings unreadable"
// on one beat. Transient and self-correcting; it is a torn read, not an
// attestation problem, and this note says which.
func baselineAttestationNoteBytes(raw []byte, signed bool) string {
	cfgs, err := loadPairings()
	if err != nil {
		return "the attestation could not be checked this pass: pairings unreadable (a pairing " +
			"file may be mid-write; this clears on the next pass)"
	}
	signer, _ := baselineSignerPairing(cfgs)
	if signer == nil {
		if !signed {
			return "" // unsigned and nothing could have signed it; the file says why
		}
		return "this accounting is signed but no pairing on this machine can check it"
	}
	ok, note := baselineVerifyBytes(raw, signer.CACert, signer.Fingerprint)
	if ok {
		return ""
	}
	return note
}

// baselineMirror writes the accounting into the machine store, where the host
// reads it through dcn beside the findings it stands behind, mirrored to the
// anchor host. The bytes are identical to the state-dir copy; the store
// copy is the one the host verifies, and a host that finds them different has
// found something.
func baselineMirror(b []byte) error {
	root, err := storeDir()
	if err != nil {
		return err
	}
	p := filepath.Join(root, "baseline.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(p, 0o600)
	return nil
}
