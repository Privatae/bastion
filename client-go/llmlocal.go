package main

// llmlocal.go — finding the OpenAI-compatible model server on this machine
// when PRIVATAE_LLM_ADDR names none.
//
// Before 0.63.0 that lane existed only when someone set the variable in the
// bastion's environment, which no installer does, so a machine running
// llama.cpp on its usual port served no model to its Host. Now, with the
// variable unset, the bastion looks on this machine's loopback, and nowhere
// else, at the ports the common servers
// listen on by default: 127.0.0.1:8080 (llama.cpp's llama-server), :8000
// (vLLM), :1234 (LM Studio), in that order. Each is asked GET /v1/models with a
// short timeout, and the first whose answer is OpenAI-shaped (a "data" list of
// models, each with an "id") is the server. Something else answering on one of
// those ports (a web app on 8080, say) is not taken for a model server, nor,
// on Linux, a server another account runs (llmListenerTrusted).
//
// The answer is kept and asked again every llmReprobeEvery, and at once after
// it failed (llmTargetFailed: the beat's probe of it, a dial of it), so the
// heartbeat that advertises the lane and the forward that serves it read the
// same address: both call llmTarget (env.go), the one function for the lane.
// The variable, when set, overrides all of this, as before. What was found, or
// that nothing was, is logged once per change and shown by `status` and
// `doctor`.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// llmCandidate is one place a local OpenAI-compatible server listens by
// default. Loopback only, by construction: the addresses are fixed here.
type llmCandidate struct {
	Addr   string
	Server string // whose default port it is, for the words
}

var llmCandidates = []llmCandidate{
	{"127.0.0.1:8080", "llama.cpp"},
	{"127.0.0.1:8000", "vLLM"},
	{"127.0.0.1:1234", "LM Studio"},
}

const (
	llmReprobeEvery = 60 * time.Second
	llmProbeTimeout = 800 * time.Millisecond
)

// llmProbe asks addr for its models; ok only for an OpenAI-shaped answer. A
// seam for the suite.
var llmProbe = probeOpenAIShaped

// llmTrusted: the program on that port may be handed the Host's prompts
// (llmlocal_linux.go: root's, this bastion's user's or the owner's). A seam.
var llmTrusted = llmListenerTrusted

// probeOpenAIShaped is GET http://addr/v1/models: a 200 whose body is
// {"data": [{"id": "..."}, ...]} with at least one model and an id on each.
func probeOpenAIShaped(addr string) ([]string, bool) {
	cl := &http.Client{Timeout: llmProbeTimeout}
	resp, err := cl.Get("http://" + addr + "/v1/models")
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	return openAIShapedModels(io.LimitReader(resp.Body, 1<<20))
}

// openAIShapedModels reads an OpenAI /v1/models answer: the model ids, and
// whether it is one.
func openAIShapedModels(r io.Reader) ([]string, bool) {
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(r).Decode(&list); err != nil || len(list.Data) == 0 {
		return nil, false
	}
	var ids []string
	for _, m := range list.Data {
		id, _ := m["id"].(string)
		if strings.TrimSpace(id) == "" {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

// llmFound is what the bastion found on this machine.
type llmFound struct {
	Addr   string   `json:"addr,omitempty"`
	Server string   `json:"server,omitempty"` // whose default port it answered on
	Models []string `json:"models,omitempty"`
}

var llmLocal = struct {
	sync.Mutex
	found  llmFound
	at     time.Time
	probed bool
	said   string // what was last logged
}{}

// discoveredLLM is the server found on this machine, asked again when the
// last answer is older than llmReprobeEvery or was marked failed.
func discoveredLLM() llmFound {
	llmLocal.Lock()
	defer llmLocal.Unlock()
	if llmLocal.probed && time.Since(llmLocal.at) < llmReprobeEvery {
		return llmLocal.found
	}
	f := llmFound{}
	for _, c := range llmCandidates {
		if models, ok := llmProbe(c.Addr); ok && llmTrusted(c.Addr) {
			f = llmFound{Addr: c.Addr, Server: c.Server, Models: models}
			break
		}
	}
	llmLocal.found, llmLocal.at, llmLocal.probed = f, time.Now(), true
	// Said in the running bastion's log, once per change; a command such as
	// `status` shows it in its own words instead.
	if line := llmFoundWords(f); line != llmLocal.said && daemonRunningHere() {
		llmLocal.said = line
		fmt.Printf("[llm] %s\n", line)
	}
	return f
}

// daemonRunningHere: this process is the running bastion (cmdRun set up its
// supervisor), not a command beside it.
func daemonRunningHere() bool {
	supervisor.Lock()
	defer supervisor.Unlock()
	return supervisor.ctx != nil
}

// llmTargetFailed marks the found server as failed when addr is it, so the
// next llmTarget asks again rather than serve a server that went away.
func llmTargetFailed(addr string) {
	if addr == "" || os.Getenv("PRIVATAE_LLM_ADDR") != "" {
		return
	}
	llmLocal.Lock()
	defer llmLocal.Unlock()
	if llmLocal.found.Addr == addr {
		llmLocal.probed = false
	}
}

// llmCandidateList is the places looked, for the words.
func llmCandidateList() string {
	var out []string
	for _, c := range llmCandidates {
		out = append(out, c.Addr+" ("+c.Server+")")
	}
	return strings.Join(out, ", ")
}

func llmFoundWords(f llmFound) string {
	if f.Addr == "" {
		return "no OpenAI-compatible model server found on this machine (looked on " + llmCandidateList() +
			"); set PRIVATAE_LLM_ADDR to name another on this machine"
	}
	s := fmt.Sprintf("found an OpenAI-compatible model server on %s, %s's port", f.Addr, f.Server)
	if len(f.Models) > 0 {
		s += ": " + strings.Join(f.Models, ", ")
	}
	return s
}

// statusLLM is the model-server line `status` and `doctor` show.
type statusLLM struct {
	Addr   string   `json:"addr,omitempty"`
	Source string   `json:"source"` // "PRIVATAE_LLM_ADDR", "found" or "none"
	Server string   `json:"server,omitempty"`
	Models []string `json:"models,omitempty"`
}

func llmStatus() *statusLLM {
	if v := os.Getenv("PRIVATAE_LLM_ADDR"); v != "" {
		return &statusLLM{Addr: v, Source: "PRIVATAE_LLM_ADDR"}
	}
	f := discoveredLLM()
	if f.Addr == "" {
		return &statusLLM{Source: "none"}
	}
	return &statusLLM{Addr: f.Addr, Source: "found", Server: f.Server, Models: f.Models}
}

func (l *statusLLM) words() string {
	switch l.Source {
	case "PRIVATAE_LLM_ADDR":
		return l.Addr + " (set by PRIVATAE_LLM_ADDR)"
	case "found":
		return llmFoundWords(llmFound{Addr: l.Addr, Server: l.Server, Models: l.Models})
	}
	return llmFoundWords(llmFound{})
}
