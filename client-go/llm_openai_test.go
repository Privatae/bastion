package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// openAICompatModels is opt-in: no PRIVATAE_LLM_ADDR means no probe and no
// capability, so a box that runs only ollama is unaffected by this lane.
func TestOpenAICompatModelsRequiresEnv(t *testing.T) {
	t.Setenv("PRIVATAE_LLM_ADDR", "")
	if ok, models := openAICompatModels(); ok || models != nil {
		t.Errorf("openAICompatModels(no env) = (%v, %v), want (false, nil)", ok, models)
	}
}

func TestOpenAICompatModelsParsesV1Models(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("probed %q, want /v1/models", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[
			{"id":"/models/qwen3.6-35b-a3b-q4km.gguf","object":"model"},
			{"id":"","object":"model"},
			{"id":"second-model","object":"model"}]}`))
	}))
	defer srv.Close()

	t.Setenv("PRIVATAE_LLM_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	ok, models := openAICompatModels()
	if !ok {
		t.Fatal("openAICompatModels = false, want true for a live /v1/models")
	}
	// Empty ids are dropped; the rest survive in order.
	want := []string{"/models/qwen3.6-35b-a3b-q4km.gguf", "second-model"}
	if len(models) != len(want) {
		t.Fatalf("models = %v, want %v", models, want)
	}
	for i := range want {
		if models[i] != want[i] {
			t.Errorf("models[%d] = %q, want %q", i, models[i], want[i])
		}
	}
}

// A 200 means the server is alive even if the body is unparseable — same rule
// ollamaModels applies to /api/tags.
func TestOpenAICompatModelsAliveOnBadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	t.Setenv("PRIVATAE_LLM_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	if ok, _ := openAICompatModels(); !ok {
		t.Error("openAICompatModels(200, bad body) = false, want true (200 is alive)")
	}
}

func TestOpenAICompatModelsIgnoresNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("PRIVATAE_LLM_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	if ok, _ := openAICompatModels(); ok {
		t.Error("openAICompatModels(404) = true, want false")
	}
}

// THE REGRESSION THIS LANE EXISTS TO PREVENT: the OpenAI-compatible server's
// models must NEVER land in `models`. That field is ollama-only — the host
// derives ollama's port for it AND feeds it to the embedding picker, so a
// merged list both dials the wrong server and offers chat models as embedding
// models on a box running both.
func TestHeartbeatKeepsLLMModelsOutOfOllamaField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"qwen3.6-gguf"}]}`))
	}))
	defer srv.Close()
	t.Setenv("PRIVATAE_LLM_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	// Point ollama detection at a dead address so `models` stays empty and any
	// leakage is unambiguous.
	t.Setenv("OLLAMA_ADDR", "127.0.0.1:1")

	var body struct {
		Models    []string `json:"models"`
		LLMModels []string `json:"llm_models"`
		LLMPort   int      `json:"llm_port"`
		Caps      []string `json:"capabilities"`
	}
	raw := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("heartbeat body is not JSON: %v", err)
	}

	for _, m := range body.Models {
		if strings.Contains(m, "qwen3.6-gguf") {
			t.Errorf("llm model leaked into `models`: %v", body.Models)
		}
	}
	if len(body.LLMModels) != 1 || body.LLMModels[0] != "qwen3.6-gguf" {
		t.Errorf("llm_models = %v, want [qwen3.6-gguf]", body.LLMModels)
	}
	if body.LLMPort != llmForwardPort {
		t.Errorf("llm_port = %d, want %d (the port serveLLMForward listens on)", body.LLMPort, llmForwardPort)
	}
	var sawCap bool
	for _, c := range body.Caps {
		if c == "llm-openai" {
			sawCap = true
		}
	}
	if !sawCap {
		t.Errorf("capabilities = %v, want llm-openai present", body.Caps)
	}
}

// With no OpenAI-compatible server the fields must still be present and empty —
// the host distinguishes "no server" from "absent field" by the empty list.
func TestHeartbeatLLMFieldsEmptyWithoutServer(t *testing.T) {
	t.Setenv("PRIVATAE_LLM_ADDR", "")
	var body struct {
		LLMModels []string `json:"llm_models"`
	}
	raw := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("heartbeat body is not JSON: %v", err)
	}
	if body.LLMModels == nil || len(body.LLMModels) != 0 {
		t.Errorf("llm_models = %v, want [] (present and empty)", body.LLMModels)
	}
}
