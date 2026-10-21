package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// piiProbe is opt-in: no PRIVATAE_PII_ADDR means no probe, no capability, no
// heartbeat fields — a box without the service is unaffected by this lane.
func TestPiiProbeRequiresEnv(t *testing.T) {
	t.Setenv("PRIVATAE_PII_ADDR", "")
	if adv, ok := piiProbe(); adv || ok {
		t.Errorf("piiProbe(no env) = (%v, %v), want (false, false)", adv, ok)
	}
}

func TestPiiProbeHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("probe hit %s, want /health", r.URL.Path)
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	t.Setenv("PRIVATAE_PII_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	if adv, ok := piiProbe(); !adv || !ok {
		t.Errorf("piiProbe(healthy) = (%v, %v), want (true, true)", adv, ok)
	}
}

// Env set but upstream dead: still advertised (the forwarder runs), with
// pii_ok=false as the distinct dead-upstream signal for the host.
func TestPiiProbeDeadUpstreamStillAdvertised(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // connection refused from here on
	t.Setenv("PRIVATAE_PII_ADDR", addr)
	if adv, ok := piiProbe(); !adv || ok {
		t.Errorf("piiProbe(dead upstream) = (%v, %v), want (true, false)", adv, ok)
	}
}

func TestHeartbeatAdvertisesPii(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	t.Setenv("PRIVATAE_PII_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("PRIVATAE_LLM_ADDR", "")

	raw := buildHeartbeatBody("", "h", "linux", "test", "pk", "fp", "100.64.0.9", "ep", false, nil, nil, nil)
	var body struct {
		Capabilities []string `json:"capabilities"`
		PiiPort      *int     `json:"pii_port"`
		PiiOK        *bool    `json:"pii_ok"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("heartbeat body: %v", err)
	}
	found := false
	for _, c := range body.Capabilities {
		if c == "pii" {
			found = true
		}
	}
	if !found {
		t.Errorf("capabilities = %v, want to include \"pii\"", body.Capabilities)
	}
	if body.PiiPort == nil || *body.PiiPort != piiForwardPort {
		t.Errorf("pii_port = %v, want %d (the port servePIIForward listens on)", body.PiiPort, piiForwardPort)
	}
	if body.PiiOK == nil || !*body.PiiOK {
		t.Errorf("pii_ok = %v, want true", body.PiiOK)
	}
}

// Absence semantics: unset env produces NO pii fields at all — the host
// reads a missing pii_port as "service not present", so an always-present
// field (like llm_port's style) would break the honest disabled state.
func TestHeartbeatOmitsPiiWhenUnset(t *testing.T) {
	t.Setenv("PRIVATAE_PII_ADDR", "")
	t.Setenv("PRIVATAE_LLM_ADDR", "")
	raw := buildHeartbeatBody("", "h", "linux", "test", "pk", "fp", "100.64.0.9", "ep", false, nil, nil, nil)
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("heartbeat body: %v", err)
	}
	if _, present := body["pii_port"]; present {
		t.Error("pii_port present with PRIVATAE_PII_ADDR unset; want omitted")
	}
	if _, present := body["pii_ok"]; present {
		t.Error("pii_ok present with PRIVATAE_PII_ADDR unset; want omitted")
	}
	caps, _ := body["capabilities"].([]interface{})
	for _, c := range caps {
		if c == "pii" {
			t.Error("capability \"pii\" present with PRIVATAE_PII_ADDR unset")
		}
	}
}
