package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func parseTestCSR(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil {
		t.Fatalf("not PEM: %q", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("the CSR must be self-signed by the device key: %v", err)
	}
	return csr
}

func csrURIs(csr *x509.CertificateRequest) []string {
	var out []string
	for _, u := range csr.URIs {
		out = append(out, u.String())
	}
	return out
}

// A platform redeem's CSR names the fingerprint once, under the platform's
// name. A redeem with a Host that has no platform names it under the
// platform's name first and the Host's second.
func TestTheOperatorCSRNamesTheFingerprintForItsSigner(t *testing.T) {
	for _, c := range []struct {
		local bool
		want  []string
	}{
		{false, []string{fpSANPrefix + "fp-test"}},
		{true, []string{fpSANPrefix + "fp-test", hostFPSANPrefix + "fp-test"}},
	} {
		_, csrPEM, err := genOperatorCSR("fp-test", c.local)
		if err != nil {
			t.Fatal(err)
		}
		if got := csrURIs(parseTestCSR(t, csrPEM)); strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("local=%v: URIs = %v, want %v", c.local, got, c.want)
		}
	}
}

// platformSignerRefusal is the platform's rule for the SANs of an operator
// CSR it signs (the bridge's _checked_operator_csr): one name, a URI,
// urn:skema:hwfp: and a fingerprint of 16 to 128 base64url characters.
// Anything else is refused before anything is signed.
var platformFPRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func platformSignerRefusal(csr *x509.CertificateRequest) string {
	n := len(csr.URIs) + len(csr.DNSNames) + len(csr.EmailAddresses) + len(csr.IPAddresses)
	if n == 0 {
		return ""
	}
	if n != 1 || len(csr.URIs) != 1 {
		return "operator_csr may name only its device fingerprint (urn:skema:hwfp:<fp>)"
	}
	s := csr.URIs[0].String()
	if !strings.HasPrefix(s, fpSANPrefix) || !platformFPRe.MatchString(strings.TrimPrefix(s, fpSANPrefix)) {
		return "operator_csr may name only its device fingerprint (urn:skema:hwfp:<fp>)"
	}
	return ""
}

// A platform pairing's CSR is one the platform signs. It reached the platform
// with a second fingerprint name in 0.52.1, and the platform refuses any
// second name, so every platform pair, --replace and claim-anchor failed at
// the redeem. The redeem here is served on loopback and refuses as the
// platform does.
func TestAPlatformRedeemSendsACSRThePlatformSigns(t *testing.T) {
	uiTestConfigDir(t)
	old := markerPathOverride
	markerPathOverride = filepath.Join(t.TempDir(), "machine.json")
	t.Cleanup(func() { markerPathOverride = old })
	var mu sync.Mutex
	var got []string
	refusal := "no request"
	redeem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req redeemReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		defer mu.Unlock()
		refusal = "the CSR does not parse"
		if blk, _ := pem.Decode([]byte(req.OperatorCSR)); blk != nil {
			if csr, err := x509.ParseCertificateRequest(blk.Bytes); err == nil {
				got, refusal = csrURIs(csr), platformSignerRefusal(csr)
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "the test stops here: " + refusal})
	}))
	defer redeem.Close()
	oldBase := redeemURLBase
	redeemURLBase = redeem.URL
	t.Cleanup(func() { redeemURLBase = oldBase })
	token := "skb_" + base64.RawURLEncoding.EncodeToString([]byte("acme.secret"))
	if _, _, err := pairWithToken(token, false, false); err == nil {
		t.Fatal("the stand-in redeem answers 400; the pairing must fail")
	}
	mu.Lock()
	defer mu.Unlock()
	if refusal != "" {
		t.Fatalf("the platform would refuse this CSR: %s (URIs %v)", refusal, got)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], fpSANPrefix) {
		t.Fatalf("a platform CSR names the fingerprint once, under %s: %v", fpSANPrefix, got)
	}
}
