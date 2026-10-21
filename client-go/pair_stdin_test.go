package main

// `pair` with the token on standard input, beside the argument it always
// took. Every token and secret here is invented.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// readsNothing fails the test if anything reads it.
type readsNothing struct{ t *testing.T }

func (r readsNothing) Read([]byte) (int, error) {
	r.t.Error("standard input was read, but the token was given as the argument")
	return 0, io.EOF
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("input/output error") }

func TestThePositionalTokenIsTakenAsGivenAndStandardInputIsLeftAlone(t *testing.T) {
	for _, console := range []bool{false, true} {
		var prompt bytes.Buffer
		got, err := pairToken("skb_argument", readsNothing{t}, console, &prompt)
		if err != nil || got != "skb_argument" {
			t.Fatalf("console=%v: got %q, %v", console, got, err)
		}
		if prompt.Len() != 0 {
			t.Fatalf("console=%v: prompted %q for a token already given", console, prompt.String())
		}
	}
}

func TestATokenOnStandardInputIsReadWithDash(t *testing.T) {
	for _, c := range []struct {
		name, arg, in string
		console       bool
		prompted      bool
	}{
		{"dash, from a pipe", "-", "skb_piped\n", false, false},
		{"dash, Windows line ending and spaces", "-", "  skb_piped \r\n", false, false},
		{"dash, no line ending", "-", "skb_piped", false, false},
		{"dash, only the first line", "-", "skb_piped\nsomething else\n", false, false},
		{"dash, at a terminal", "-", "skb_piped\n", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var prompt bytes.Buffer
			got, err := pairToken(c.arg, strings.NewReader(c.in), c.console, &prompt)
			if err != nil || got != "skb_piped" {
				t.Fatalf("got %q, %v", got, err)
			}
			if (prompt.Len() > 0) != c.prompted {
				t.Fatalf("prompted %q; a prompt belongs on a terminal only", prompt.String())
			}
		})
	}
}

// No token is the usage error whether or not standard input looks like a
// terminal: mintty and `ssh host cmd` without -t look like a pipe, and reading
// there would wait silently for a person who only forgot the token.
func TestNoTokenIsTheUsageErrorAndReadsNothingWhateverStandardInputIs(t *testing.T) {
	for _, console := range []bool{true, false} {
		_, err := pairToken("", readsNothing{t}, console, io.Discard)
		if err == nil || err.Error() != pairUsage {
			t.Fatalf("console=%v: want the usage text, got %v", console, err)
		}
	}
	if !strings.Contains(pairUsage, "<token> | -") {
		t.Fatalf("the usage must name the - form: %s", pairUsage)
	}
}

func TestARefusedStandardInputIsNeverRepeated(t *testing.T) {
	const secret = "Sx7qDistinctSecret"
	for name, in := range map[string]io.Reader{
		"empty":            strings.NewReader(""),
		"blank line":       strings.NewReader("   \n"),
		"two words":        strings.NewReader("skb_" + secret + " skb_" + secret + "2\n"),
		"longer than any":  strings.NewReader(strings.Repeat("A", pairTokenMax) + secret + "\n"),
		"a failing reader": failingReader{},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := pairToken(pairStdinArg, in, false, io.Discard)
			if err == nil {
				t.Fatalf("must refuse, got the token %q", got)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "AAAA") {
				t.Fatalf("the refusal repeats what was read: %v", err)
			}
		})
	}
}

// Both forms through parsePairArgs, pairToken and cmdPair, as main runs them,
// to a redeem served on loopback that refuses. The secret must reach the
// redeem, and the error a person reads must not hold the token or the secret.
func TestBothFormsRedeemTheTokenAndNeitherPrintsIt(t *testing.T) {
	const secret = "Kq9wInventedPairSecret"
	token := "skb_" + base64.RawURLEncoding.EncodeToString([]byte("acme."+secret))
	for _, c := range []struct {
		name  string
		args  []string
		stdin io.Reader
	}{
		{"argument", []string{token}, readsNothing{t}},
		{"dash", []string{pairStdinArg}, strings.NewReader(token + "\n")},
	} {
		t.Run(c.name, func(t *testing.T) {
			uiTestConfigDir(t)
			withMarkerPath(t, filepath.Join(t.TempDir(), "machine.json"))
			var mu sync.Mutex
			var gotSecret, gotHandle string
			redeem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req redeemReq
				_ = json.NewDecoder(r.Body).Decode(&req)
				mu.Lock()
				gotSecret, gotHandle = req.Secret, req.Handle
				mu.Unlock()
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "the test refuses every redeem"})
			}))
			defer redeem.Close()
			old := redeemURLBase
			redeemURLBase = redeem.URL
			t.Cleanup(func() { redeemURLBase = old })

			tok, redeemURL, hostCA, replace, err := parsePairArgs(c.args)
			if err == nil {
				tok, err = pairToken(tok, c.stdin, false, io.Discard)
			}
			if err != nil {
				t.Fatalf("the token was not taken: %v", err)
			}
			err = cmdPair(tok, redeemURL, hostCA, replace)
			if err == nil {
				t.Fatal("the stand-in redeem refuses; the pairing must fail")
			}
			mu.Lock()
			defer mu.Unlock()
			if gotSecret != secret || gotHandle != "acme" {
				t.Fatalf("the redeem got secret %q handle %q; the token did not reach it", gotSecret, gotHandle)
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), secret) {
				t.Fatalf("the error a person reads holds the token: %v", err)
			}
		})
	}
}

// A malformed token from standard input is refused without being repeated.
func TestAMalformedTokenOnStandardInputIsNotRepeated(t *testing.T) {
	uiTestConfigDir(t)
	withMarkerPath(t, filepath.Join(t.TempDir(), "machine.json"))
	const bad = "skb_!!Pv3InventedNotBase64!!"
	tok, err := pairToken(pairStdinArg, strings.NewReader(bad+"\n"), false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	err = cmdPair(tok, "", "", false)
	if err == nil || strings.Contains(err.Error(), "Pv3InventedNotBase64") {
		t.Fatalf("want a refusal that does not repeat the token, got %v", err)
	}
}

func withMarkerPath(t *testing.T, p string) {
	t.Helper()
	old := markerPathOverride
	markerPathOverride = p
	t.Cleanup(func() { markerPathOverride = old })
}
