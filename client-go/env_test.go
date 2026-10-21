package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The lane addresses are read under their PRIVATAE_* names only. These drive
// the REAL readers — the probe that advertises a lane, the resolver its
// forwarder shares, the detection table — from the environment, because a
// lane read under a second name is invisible from outside: the box advertises
// the lane and nothing in its unit file says why.

// oldLaneName is a lane variable under the platform's former internal name,
// assembled from oldName so the published source does not carry the word.
func oldLaneName(suffix string) string { return strings.ToUpper(oldName) + "_" + suffix }

func TestOldLaneNamesAreNotRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"m","object":"model"}]}`))
	}))
	defer srv.Close()

	for _, n := range []string{
		"OLLAMA_ADDR", "PRIVATAE_PII_ADDR", "PRIVATAE_LLM_ADDR",
		"PRIVATAE_BASTION_AGENT_ADDR", "PRIVATAE_BASTION_AGENT_CERT",
		"PRIVATAE_BASTION_AGENT_KEY", "PRIVATAE_BASTION_AGENT_CA",
	} {
		t.Setenv(n, "")
	}
	t.Setenv(oldLaneName("PII_ADDR"), "127.0.0.1:18081")
	t.Setenv(oldLaneName("LLM_ADDR"), strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv(oldLaneName("FREEAGENT_ADDR"), "127.0.0.1:1")
	t.Setenv(oldLaneName("FREEAGENT_CERT"), "/tmp/cert.pem")
	t.Setenv(oldLaneName("FREEAGENT_KEY"), "/tmp/key.pem")
	t.Setenv(oldLaneName("FREEAGENT_CA"), "/tmp/ca.pem")

	if got := piiTarget(); got != "" {
		t.Errorf("piiTarget() = %q with only the old name set, want empty", got)
	}
	if advertised, _ := piiProbe(); advertised {
		t.Error("piiProbe advertises the sterilizer lane from the old name")
	}
	if got := llmTarget(); got != "" {
		t.Errorf("llmTarget() = %q with only the old name set, want empty", got)
	}
	if ok, models := openAICompatModels(); ok || len(models) > 0 {
		t.Errorf("openAICompatModels = (%v, %v) from the old name, want no lane", ok, models)
	}
	p := portOfAddr(strings.TrimPrefix(srv.URL, "http://"))
	if p <= 0 {
		t.Fatalf("portOfAddr(%q) = %d", srv.URL, p)
	}
	if strong, _ := localLLMPorts(); strong[p] != "" {
		t.Errorf("port %d is a declared inference endpoint from the old name", p)
	}
	if c, ok := freeagentEnv(); ok || c.Cert != "" || c.Key != "" || c.CA != "" {
		t.Errorf("freeagentEnv = (%+v, %v) from the old names, want no lane", c, ok)
	}
}

// The forwarders are the halves that carry traffic. They share a resolver with
// their probe, so this pins the resolver: the advertise-but-never-listen state
// cannot be reached by repairing one call site and missing the other.
func TestLaneTargetsResolveTheNewNameForBothHalves(t *testing.T) {
	t.Setenv("PRIVATAE_PII_ADDR", "127.0.0.1:18081")
	t.Setenv("PRIVATAE_LLM_ADDR", "127.0.0.1:18080")
	if got := piiTarget(); got != "127.0.0.1:18081" {
		t.Errorf("piiTarget() = %q, want 127.0.0.1:18081", got)
	}
	if got := llmTarget(); got != "127.0.0.1:18080" {
		t.Errorf("llmTarget() = %q, want 127.0.0.1:18080", got)
	}
}

func TestAgentTokenEnvNamesPrefersTheNewSpelling(t *testing.T) {
	if len(agentTokenEnvNames) != 2 {
		t.Fatalf("agentTokenEnvNames = %v, want exactly the new name and the one the host mints", agentTokenEnvNames)
	}
	if agentTokenEnvNames[0] != "PRIVATAE_AGENT_TOKEN" || agentTokenEnvNames[1] != "SKEMA_AGENT_TOKEN" {
		t.Errorf("agentTokenEnvNames = %v, want [PRIVATAE_AGENT_TOKEN SKEMA_AGENT_TOKEN]", agentTokenEnvNames)
	}
	// Both spellings must parse out of a process environment block: the host
	// mints tags under the second, so an agent launched with one reads as
	// requested only if that name is read.
	for _, name := range agentTokenEnvNames {
		env := []byte("PATH=/usr/bin\x00" + name + "=del_abc123\x00")
		if got := parseEnvToken(env, name); got != "del_abc123" {
			t.Errorf("%s: parseEnvToken = %q, want del_abc123", name, got)
		}
	}
}
