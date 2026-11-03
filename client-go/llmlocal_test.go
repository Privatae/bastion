package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withLLMCandidates points the discovery at addrs (in order) with the real
// probe, and starts from no answer.
func withLLMCandidates(t *testing.T, addrs ...string) {
	t.Helper()
	prevC, prevP := llmCandidates, llmProbe
	llmCandidates = nil
	for i, a := range addrs {
		llmCandidates = append(llmCandidates, llmCandidate{Addr: a, Server: []string{"llama.cpp", "vLLM", "LM Studio"}[i%3]})
	}
	llmProbe = probeOpenAIShaped
	resetLLMDiscovery()
	t.Cleanup(func() { llmCandidates, llmProbe = prevC, prevP; resetLLMDiscovery() })
	t.Setenv("PRIVATAE_LLM_ADDR", "")
}

func resetLLMDiscovery() {
	llmLocal.Lock()
	llmLocal.found, llmLocal.probed, llmLocal.said = llmFound{}, false, ""
	llmLocal.Unlock()
}

// openAIServer answers /v1/models with body.
func openAIServer(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// deadAddr is a loopback port nothing listens on.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	_ = ln.Close()
	return a
}

const oneModel = `{"object":"list","data":[{"id":"qwen3-4b-q4_k_m.gguf","object":"model"}]}`

// None answering: no lane, and status says where it looked.
//
// MUTATION: return the first candidate whatever it answers. RESULT: red.
func TestNoLocalModelServerMeansNoLane(t *testing.T) {
	withLLMCandidates(t, deadAddr(t), deadAddr(t))
	if got := llmTarget(); got != "" {
		t.Fatalf("llmTarget = %q with nothing answering", got)
	}
	if ok, _ := openAICompatModels(); ok {
		t.Error("the beat would advertise a model server that is not there")
	}
	if l := llmStatus(); l.Source != "none" || !strings.Contains(l.words(), "no OpenAI-compatible model server found") {
		t.Errorf("status: %+v %q", l, l.words())
	}
}

// One answering: the lane names it, the beat's probe and the forward agree,
// and status says which server it is.
//
// MUTATION: have llmTarget return only the variable. RESULT: red.
func TestALocalModelServerIsFound(t *testing.T) {
	a := openAIServer(t, oneModel)
	withLLMCandidates(t, deadAddr(t), a)
	if got := llmTarget(); got != a {
		t.Fatalf("llmTarget = %q, want %q", got, a)
	}
	ok, models := openAICompatModels()
	if !ok || strings.Join(models, ",") != "qwen3-4b-q4_k_m.gguf" {
		t.Errorf("the beat's probe: %v %v", ok, models)
	}
	if s, _ := serveServiceNamed("llm"); s.target() != a {
		t.Error("the serve lane reads another address than the beat")
	}
	l := llmStatus()
	if l.Source != "found" || l.Addr != a || !strings.Contains(l.words(), "found an OpenAI-compatible model server on "+a) {
		t.Errorf("status: %+v %q", l, l.words())
	}
	raw, _ := json.Marshal(statusRead{LLM: l})
	if !strings.Contains(string(raw), `"source":"found"`) {
		t.Errorf("status --json: %s", raw)
	}
}

// Several answering: the first in the order wins (llama.cpp, vLLM, LM Studio).
//
// MUTATION: keep looking after the first answer and take the last. RESULT: red.
func TestTheFirstLocalModelServerInOrderWins(t *testing.T) {
	first, second := openAIServer(t, oneModel), openAIServer(t, `{"data":[{"id":"other"}]}`)
	withLLMCandidates(t, first, second)
	if got := llmTarget(); got != first {
		t.Fatalf("llmTarget = %q, want the first, %q", got, first)
	}
}

// The variable overrides what is found.
//
// MUTATION: look before reading the variable. RESULT: red.
func TestTheVariableOverridesTheLocalModelServer(t *testing.T) {
	a := openAIServer(t, oneModel)
	withLLMCandidates(t, a)
	t.Setenv("PRIVATAE_LLM_ADDR", "127.0.0.1:18080")
	if got := llmTarget(); got != "127.0.0.1:18080" {
		t.Fatalf("llmTarget = %q", got)
	}
	if l := llmStatus(); l.Source != "PRIVATAE_LLM_ADDR" {
		t.Errorf("status: %+v", l)
	}
}

// Something else on the port (a web app, a server whose list is not OpenAI's)
// is not taken for a model server.
//
// MUTATION: accept any 200 in probeOpenAIShaped. RESULT: red.
func TestAnAnswerThatIsNotOpenAIShapedIsIgnored(t *testing.T) {
	for _, body := range []string{`<html>hello</html>`, `{"models":[{"name":"x"}]}`, `{"data":[]}`, `{"data":[{"name":"x"}]}`, `{"data":"x"}`} {
		bad := openAIServer(t, body)
		good := openAIServer(t, oneModel)
		withLLMCandidates(t, bad, good)
		if got := llmTarget(); got != good {
			t.Errorf("%s: llmTarget = %q, want the OpenAI-shaped one", body, got)
		}
	}
}

// Only loopback is ever asked.
//
// MUTATION: add a LAN address to llmCandidates. RESULT: red.
func TestOnlyLoopbackIsAskedForAModelServer(t *testing.T) {
	want := []string{"127.0.0.1:8080", "127.0.0.1:8000", "127.0.0.1:1234"}
	if len(llmCandidates) != len(want) {
		t.Fatalf("%+v", llmCandidates)
	}
	for i, c := range llmCandidates {
		if c.Addr != want[i] || !loopbackAddr(c.Addr) {
			t.Errorf("candidate %d is %q", i, c.Addr)
		}
	}
}

// A found server that goes away is asked for again at once after a failure,
// not served for the rest of the interval; one that starts later is found at
// the next interval.
//
// MUTATION: drop llmTargetFailed from openAICompatModels. RESULT: red.
func TestAModelServerThatWentAwayIsAskedForAgain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(oneModel)) }))
	a := strings.TrimPrefix(srv.URL, "http://")
	withLLMCandidates(t, a)
	if llmTarget() != a {
		t.Fatal("not found")
	}
	srv.Close()
	if ok, _ := openAICompatModels(); ok {
		t.Fatal("a closed server answered")
	}
	if got := llmTarget(); got != "" {
		t.Errorf("after a failed probe llmTarget still names %q", got)
	}
	// Later: the cached "none" is asked again once the interval is over.
	b := openAIServer(t, oneModel)
	llmCandidates = []llmCandidate{{Addr: b, Server: "llama.cpp"}}
	llmLocal.Lock()
	llmLocal.at = time.Now().Add(-llmReprobeEvery - time.Second)
	llmLocal.Unlock()
	if got := llmTarget(); got != b {
		t.Errorf("a server that started later is not found: %q", got)
	}
}
