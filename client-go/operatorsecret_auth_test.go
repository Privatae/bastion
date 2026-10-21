package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The loopback /dcn/propose handler must refuse every request when no operator
// secret is configured, and refuse a wrong one, before it reads the body or
// touches the tunnel. The upstream client is nil on purpose: reaching it panics.
func TestDcnProposeLocalOperatorSecret(t *testing.T) {
	cases := []struct {
		name, secret, header string
	}{
		{"empty secret, bare Bearer", "", "Bearer "},
		{"empty secret, no header", "", ""},
		{"empty secret, Bearer word", "", "Bearer"},
		{"wrong secret", "s3cret", "Bearer nope"},
		{"secret without Bearer prefix still needs the right value", "s3cret", "nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := dcnProposeLocal(nil, "box", "bearer", c.secret)
			r := httptest.NewRequest(http.MethodPost, "/dcn/propose", strings.NewReader("{}"))
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			w := httptest.NewRecorder()
			h(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", w.Code)
			}
		})
	}
}

// The right secret passes the gate: the handler moves on to validating the
// body, so whatever it answers, it is not the 401.
func TestDcnProposeLocalOperatorSecretAccepts(t *testing.T) {
	h := dcnProposeLocal(nil, "box", "bearer", "s3cret")
	r := httptest.NewRequest(http.MethodPost, "/dcn/propose", strings.NewReader("not json"))
	r.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("right secret was refused")
	}
}
