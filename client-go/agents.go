package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// The OBSERVE plane. The bastion (root, on the server) watches for AI/agent activity two ways
// and correlates by pid: the PROCESS signal (known agent binaries) and the NETWORK
// signal (outbound connections to inference endpoints). A process disguised at the process
// layer still betrays itself by talking to a model. Detection is SOFT + evadable — visibility +
// early-warning, NEVER relied on for security (containment is the host-local NAC). The report
// serves the user's OWN host on the user's OWN infra; the platform never sees it.
//
// PLATFORM SPLIT. This file holds every JUDGEMENT — what counts as an agent, what
// counts as an inference endpoint — so the rules are identical on every OS and testable from any
// one of them. Each platform supplies only raw enumeration, in agents_<goos>.go:
//
//	scanProcesses() (map[int]agentObs, error)   the running processes that match an agent
//	                                   signature; an error is a walk that did not happen
//	scanConnections() []connObs        established outbound TCP, with the owning pid
//	procUser / procCmdline / procEnvToken (pid int) string
//	procExe (pid int) string           the KERNEL's executable path, or "" — never argv[0]
//
// Before this, both enumerators were Linux-only (/proc + `ss`), so a Windows or macOS bastion
// enforced its grants while observing NOTHING. A bastion that cannot see is the gap this closes:
// the machines nobody has visibility of are the ones most likely to be running something.

// agentBinaries: argv[0] basename (the binary IS the agent) -> signature. Exact-match keeps false
// positives near zero. Compared after binBase(), which lowercases and drops a ".exe" suffix, so
// one entry covers `claude`, `/usr/local/bin/claude` and `C:\...\claude.exe`.
var agentBinaries = map[string]string{
	"claude":       "claude-code",
	"claude-code":  "claude-code",
	"aider":        "aider",
	"goose":        "goose",
	"cline":        "cline",
	"cursor-agent": "cursor",
	"interpreter":  "open-interpreter",
	"opencode":     "opencode",
	"codex":        "codex",
	"gemini":       "gemini-cli",
	"agy":          "antigravity",
	"crush":        "crush",
}

// agentSubstrings: distinctive cmdline markers for interpreter-wrapped agents (argv[0] is node/python).
var agentSubstrings = []struct{ Sub, Sig string }{
	{"claude-code", "claude-code"},
	{"@anthropic-ai/claude", "claude-code"},
	{"continuedev", "continue"},
	{"open-interpreter", "open-interpreter"},
	{"cursor-tunnel", "cursor"},
	{"@openai/codex", "codex"},
	{"@google/gemini-cli", "gemini-cli"},
	{"opencode-ai", "opencode"},
}

// automationBinaries (kind `automation`): tools that drive a
// machine with NO model of their own — input injection, browser drivers, RPA
// runtimes. Every automation has to be identifiable, because the subtle agent
// is the one worth detecting, not the big loud harness. An automation is inventory,
// never an alert; the moment model traffic joins it, it is an agent.
var automationBinaries = map[string]string{
	"xdotool":       "xdotool",
	"ydotool":       "ydotool",
	"cliclick":      "cliclick",
	"chromedriver":  "chromedriver",
	"geckodriver":   "geckodriver",
	"msedgedriver":  "msedgedriver",
	"safaridriver":  "safaridriver",
	"autohotkey":    "autohotkey",
	"autohotkey64":  "autohotkey",
	"autohotkeyu64": "autohotkey",
	"autohotkeyu32": "autohotkey",
	"autoit3":       "autoit",
	"sikulix":       "sikulix",
}

// automationSubstrings: interpreter-wrapped automation frameworks, gated the
// same way as agentSubstrings (argv[0] must be an interpreter).
var automationSubstrings = []struct{ Sub, Sig string }{
	{"playwright", "playwright"},
	{"puppeteer", "puppeteer"},
	{"selenium", "selenium"},
	{"pyautogui", "pyautogui"},
	{"browser-use", "browser-use"},
	{"browser_use", "browser-use"},
}

// interpreters: argv[0] basenames that run a script — only THESE get the cmdline-substring check,
// so a shell command that merely MENTIONS a marker (a grep, an echo, this very test) isn't flagged.
// Windows ships the same runtimes as node.exe/python.exe; binBase() has already dropped ".exe".
var interpreters = map[string]bool{
	"node": true, "nodejs": true, "python": true, "python3": true,
	"bun": true, "deno": true, "npx": true, "uv": true, "uvx": true,
	"pythonw": true, "py": true,
}

// llmEndpoints: REMOTE inference API hostnames. Resolved to IPs (cached) and matched against
// outbound connections. Maintained + updatable (EDR-style). Imperfect by nature (shared CDN IPs) —
// a soft signal, correlated with the process signal, never the security wall.
var llmEndpoints = []string{
	"api.anthropic.com", "api.openai.com", "openrouter.ai", "api.mistral.ai",
	"api.cohere.ai", "generativelanguage.googleapis.com", "api.groq.com",
	"api.together.xyz", "api.deepseek.com", "api.x.ai", "api.perplexity.ai",
	"api.moonshot.cn", "api.moonshot.ai", "api.fireworks.ai",
	"api.deepinfra.com", "api.cerebras.ai", "api.sambanova.ai",
	"bedrock-runtime.us-east-1.amazonaws.com", "api.z.ai",
}

// ── LOCAL inference ─────────────────────────────────────────────────────────
// The endpoint list above is cloud APIs only, so an agent driven by a model on
// this box (Ollama, LM Studio, llama.cpp) or on the LAN produced NO network
// signal at all. On a restricted or air-gapped network that is the LIKELIER
// case, which made it the blind spot worth closing first.
//
// Matched by DESTINATION PORT rather than address: the address of a local model
// is whatever the user chose (loopback, a LAN GPU box, a tunnel address), but
// the port is the server's published default. Three tiers, because a false
// "unrequested agent" alert costs the user more than a missed one — it teaches
// them to ignore the alert:
//
//	verified  — read from THIS box's own configuration (OLLAMA_ADDR,
//	            PRIVATAE_LLM_ADDR). The operator told us an inference server
//	            listens there, so a connection to it is evidence on its own.
//	known     — published defaults distinctive enough to stand alone.
//	ambiguous — defaults that collide with ordinary web development. These
//	            ANNOTATE a process the process signal already matched, and can
//	            never promote an unknown process to "llm-client" on their own.
//
// Reported as "local:<port> (<what>)" so the host can say WHICH local server,
// and so the string never looks like a cloud hostname the user could block.
var knownLocalLLMPorts = map[int]string{
	11434: "ollama",
	11435: "ollama",
	1234:  "lm-studio",
	1337:  "jan",
	5001:  "koboldcpp",
	30000: "sglang",
	8321:  "llama-stack",
}

var ambiguousLocalLLMPorts = map[int]string{
	8080: "llama.cpp/localai",
	8000: "vllm",
	5000: "text-generation-webui",
	7860: "gradio/text-generation-webui",
}

// connObs — one established outbound TCP connection and the pid that owns it.
// The platform layer produces these; classification happens here.
type connObs struct {
	PID        int
	RemoteIP   string
	RemotePort int
	// ViaHelper: the socket belongs to a GUI helper process and PID has been
	// rewritten to the app that owns it (scanAgents). The connection then
	// describes an APP, never a disguised agent.
	ViaHelper bool
}

type agentObs struct {
	PID  int `json:"pid"`
	PPID int `json:"ppid,omitempty"` // parent pid — what contain walks, and how a helper finds its app
	// Kind: WHAT the process is, not just what it matched.
	//   agent  — a coding/automation agent (the signature tables): acts on its own.
	//   app    — interactive software the user is running that happens to talk
	//            to a model (the Claude desktop app, an IDE, a browser).
	//   client — an unknown process caught by the network signal alone.
	// Measured origin: one Windows box reported the Claude DESKTOP app as nine
	// "claude-code" agents (eight of them Chromium helper processes), and the
	// host raised nine alerts with nine kill buttons. An app is visibility, never
	// an alert and never a contain target.
	Kind      string `json:"kind,omitempty"`
	User      string `json:"user"`
	Signature string `json:"signature"`
	Cmdline   string `json:"cmdline"`
	// Exe is the KERNEL's record of which file this process is
	// running. It is what a local sanction is keyed on (sanction.go), and it is
	// the only field here a process cannot choose for itself.
	//
	// NEVER DERIVED FROM Cmdline, and the two are not the same fact. Measured:
	// `bash -c 'exec -a /home/user/.local/bin/claude sleep 25'`
	// reported "/home/user/.local/bin/claude 25" in /proc/<pid>/cmdline while
	// /proc/<pid>/exe still read /usr/lib/cargo/bin/coreutils/sleep. argv[0] is a
	// string the launcher picks; this is the path the kernel opened.
	//
	// EMPTY when the platform could not supply one — another user's process, a
	// handle the bastion may not open, a build with no enumerator. Empty is
	// never back-filled from argv[0]: a guessed identity is exactly the forgery
	// this field exists to stop, and sanction.go refuses to mark an observation
	// that has none. Absolute or empty, nothing in between (sanitizeExePath).
	//
	// It travels on the heartbeat. The host reads its agent rows key by key
	// (the host's agent-detection reader), so an unknown key is ignored by
	// every host that predates it rather than rejected.
	Exe             string   `json:"exe,omitempty"`
	LLMEndpoints    []string `json:"llm_endpoints,omitempty"`
	DelegationToken string   `json:"delegation_token,omitempty"` // host-issued tag, if the agent carries one
	// Origin: how the process was started — interactive, remote,
	// scheduler, service, agent, unknown (origin.go). Evidence is every typed
	// reason behind kind and origin; the host shows the list, never a verdict.
	Origin string `json:"origin,omitempty"`
	// Unit is what OWNS this process — the systemd slice/unit on linux. It is
	// already read for classification (origin_linux.go:82, via cgroupUnit) and
	// was discarded after; the baseline's fingerprint needs it, because that is
	// what makes a service RESTART the same entry rather than a new one
	// (baseline.go). Empty where the platform does not supply one: darwin and
	// windows never populate procFacts.Unit, so those fall back to the origin.
	Unit string `json:"unit,omitempty"`
	// The account behind User (agentowner.go): domain_user, local_user,
	// service, system or unknown; whether it administers this machine; and
	// whether it has a login session now. yes, no or unknown each — unknown
	// is what an unreadable token or group list says, never no. Empty only on
	// an observation made outside scanAgents.
	OwnerClass       string     `json:"owner_class,omitempty"`
	OwnerAdmin       string     `json:"owner_admin,omitempty"`
	OwnerInteractive string     `json:"owner_interactive,omitempty"`
	Evidence         []evidence `json:"evidence,omitempty"`
	raw              string     // the UNTRUNCATED command line, for classification only; never reported
	// automation: the signature came from the automation tables, so the
	// classifier gives this kind `automation` unless model traffic promotes it.
	automation bool
}

// localLLMPorts returns the destination ports that mean "local inference" on
// this box: strong (stands alone as evidence) and weak (corroborating only).
// The strong set starts from this box's OWN configuration, so an operator
// running llama.cpp on :8080 gets that port treated as real evidence — the
// same number stays weak on a box that never declared it.
func localLLMPorts() (strong map[int]string, weak map[int]string) {
	strong = map[int]string{}
	for p, name := range knownLocalLLMPorts {
		strong[p] = name
	}
	for _, e := range []struct{ env, name string }{
		{"OLLAMA_ADDR", "ollama"},
		{"PRIVATAE_LLM_ADDR", "openai-compatible"},
	} {
		if p := portOfAddr(os.Getenv(e.env)); p > 0 {
			strong[p] = e.name // configured beats both tables: the operator declared it
		}
	}
	weak = map[int]string{}
	for p, name := range ambiguousLocalLLMPorts {
		if _, taken := strong[p]; !taken {
			weak[p] = name
		}
	}
	return strong, weak
}

// scanAgents merges the process + network signals into one snapshot keyed by pid: a known agent
// binary, an interpreter-wrapped agent, OR a process the process-signal missed that is talking to
// a model (signature "llm-client").
//
// The bastion's OWN managed local agent children are excluded: they embed against the local model by
// design, so without this every box running one reports its own component as an unsanctioned agent.
//
// An error is the walk NOT happening — /proc unreadable, `ps` failing, the
// Toolhelp snapshot refused — and it must not come back as an empty list:
// the host reads an empty list from a box that can enumerate as "looked and
// found nothing", which clears a containment the user ordered. The heartbeat
// withholds the key instead (buildHeartbeatBody), and the host holds.
//
// scanProcessesFn is the seam a test uses to make the walk fail; production
// never reassigns it.
var scanProcessesFn = scanProcesses

func scanAgents() ([]agentObs, error) {
	byPid, err := scanProcessesFn()
	if err != nil {
		return nil, err
	}
	// Kind + helper collapse: a GUI app's helper processes are
	// dropped and their parent is classified as an app; each surviving
	// observation carries its kind and parent. A helper's connections still
	// count — they are re-attributed to the app that owns the helper, so
	// "Claude desktop, talking to api.anthropic.com" is one observation, not
	// nine, and the network-service helper that actually holds the socket is
	// credited to the app rather than reported on its own.
	helperRoot := classifyObservations(byPid, procParent)
	conns := scanConnections()
	for i := range conns {
		if root, ok := helperRoot[conns[i].PID]; ok {
			conns[i].PID = root
			conns[i].ViaHelper = true
		}
	}
	strong, weak := localLLMPorts()
	mergeConnections(byPid, conns, resolveLLMIPs(), strong, weak,
		func(pid int) procDetail {
			return procDetail{User: procUser(pid), Cmdline: procCmdline(pid),
				Token: procEnvToken(pid), Exe: procExe(pid)}
		}, procParent)
	// Origin + evidence. The observed set is every agent and
	// automation in this snapshot, so a process forked by one of them reads
	// as origin `agent`. Apps get an origin too — it costs nothing and "the
	// Claude desktop app, started by launchd" is a true sentence — but their
	// origin never changes what the host does with them.
	observed := map[int]bool{}
	for pid, a := range byPid {
		if a.Kind == kindAgent || a.Kind == kindAutomation {
			observed[pid] = true
		}
	}
	extra := originExtras()
	facts := procFactsReader()
	owners := ownerFactsReader()
	out := make([]agentObs, 0, len(byPid))
	for pid, a := range byPid {
		if faIsOwnChild(pid) {
			continue
		}
		origin, ev := classifyOrigin(pid, facts, observed, extra)
		a.Origin = origin
		// The owning unit, read from the same facts the classifier used. It is
		// already in hand on linux and was being thrown away; the baseline
		// fingerprint needs it so a service restart is the SAME entry.
		if f, ok := facts(pid); ok {
			a.Unit = f.Unit
		}
		// Who the owning account is, beside who it is called. Read here
		// rather than in each platform's walk so a process the network
		// signal alone caught (mergeConnections) gets the same answer.
		o := owners(pid, a.User)
		a.OwnerClass, a.OwnerAdmin, a.OwnerInteractive = o.Class, o.Admin, o.Interactive
		a.Evidence = append([]evidence{signatureEvidence(a)}, endpointEvidence(a.LLMEndpoints)...)
		if a.DelegationToken != "" {
			a.Evidence = append(a.Evidence, evidence{Signal: "delegation-tag", Tier: tierKnown, Value: "present"})
		}
		a.Evidence = append(a.Evidence, ev...)
		out = append(out, a)
	}
	return out, nil
}

// scanMCPProcessesFn is the seam a test uses to hand the correlation a
// process list; production never reassigns it.
var scanMCPProcessesFn = scanMCPProcesses

// mcpServersReport reads the declared tool servers and correlates them with
// the process list. It lives here, not in mcpconfig.go, because reading the
// process list runs `ps` on macOS: the config reader itself starts nothing,
// and the claims test holds it to that.
func mcpServersReport() ([]mcpServerObs, mcpConfigScan) {
	declared, scan, read := cachedMCPConfigs()
	if !scan.Supported {
		scan.ProcessScan = "unsupported"
		return []mcpServerObs{}, scan
	}
	procs, err := scanMCPProcessesFn(mcpWantedBases(declared))
	switch {
	case err == nil:
		scan.ProcessScan = "ok"
	case agentScanSupported:
		scan.ProcessScan = "failed"
	default:
		scan.ProcessScan = "unsupported"
	}
	if !read {
		// No read of the files has finished yet (timed_out says so). With
		// nothing known to be declared, every tool-server-looking process
		// would read as running_not_declared, which nobody has checked.
		return []mcpServerObs{}, scan
	}
	out := correlateMCP(declared, procs, err == nil)
	if out == nil {
		out = []mcpServerObs{}
	}
	if len(out) >= mcpMaxServers {
		scan.Truncated = true
	}
	return out, scan
}

// mcpCache holds the last complete read of the config files. The heartbeat
// is every 60 s and the read is up to a thousand files across every account;
// like the scheduler inventory (schedCacheFor) it is redone every ten
// minutes, while the process correlation above runs on every beat. One read
// runs at a time, and the beats wait for it at most mcpReadTimeout IN TOTAL,
// counted from when it started: a home on a network mount that stopped
// answering holds that one goroutine, delays one beat by at most that much,
// never the beats after it, and never starts a second read.
var mcpCache struct {
	sync.Mutex
	at       time.Time
	have     bool
	declared []mcpServerObs
	scan     mcpConfigScan
	inflight chan struct{}
	started  time.Time // when the read in flight began
	gen      int
}

const mcpCacheFor = 10 * time.Minute

// mcpReadTimeout is how long one beat waits for a read in progress.
var mcpReadTimeout = 20 * time.Second

// cachedMCPConfigs is the last complete read. read is false when no read has
// finished yet, so the list says nothing about what is declared.
func cachedMCPConfigs() (declared []mcpServerObs, scan mcpConfigScan, read bool) {
	mcpCache.Lock()
	if mcpCache.have && time.Since(mcpCache.at) < mcpCacheFor {
		d, s := mcpCache.declared, mcpCache.scan
		mcpCache.Unlock()
		return d, s, true
	}
	done := mcpCache.inflight
	if done == nil {
		done = make(chan struct{})
		mcpCache.inflight, mcpCache.started = done, time.Now()
		gen := mcpCache.gen
		go func() {
			d, s := readMCPConfigs()
			mcpCache.Lock()
			if mcpCache.gen == gen {
				mcpCache.declared, mcpCache.scan, mcpCache.at, mcpCache.have = d, s, time.Now(), true
				mcpCache.inflight = nil
			}
			mcpCache.Unlock()
			close(done)
		}()
	}
	wait := mcpReadTimeout - time.Since(mcpCache.started)
	mcpCache.Unlock()
	timedOut := false
	if wait <= 0 {
		// An earlier beat already waited the whole time for this read.
		select {
		case <-done:
		default:
			timedOut = true
		}
	} else {
		t := time.NewTimer(wait)
		select {
		case <-done:
		case <-t.C:
			timedOut = true
		}
		t.Stop()
	}
	mcpCache.Lock()
	defer mcpCache.Unlock()
	if !mcpCache.have {
		// Nothing read yet: say so, rather than "no servers".
		return nil, mcpConfigScan{Supported: true, TimedOut: true}, false
	}
	s := mcpCache.scan
	s.TimedOut = timedOut
	return mcpCache.declared, s, true
}

// resetMCPConfigCache forgets the last read; a read still running is
// ignored when it finishes. Tests use it to start clean.
func resetMCPConfigCache() {
	mcpCache.Lock()
	defer mcpCache.Unlock()
	mcpCache.gen++
	mcpCache.have, mcpCache.declared, mcpCache.scan, mcpCache.inflight = false, nil, mcpConfigScan{}, nil
}

var (
	llmIPCache   map[string]string
	llmIPCacheAt time.Time
	llmIPMu      sync.Mutex
)

// resolveLLMIPs resolves the endpoint list to an ip->hostname map, cached for 5 min.
func resolveLLMIPs() map[string]string {
	llmIPMu.Lock()
	defer llmIPMu.Unlock()
	if llmIPCache != nil && time.Since(llmIPCacheAt) < 5*time.Minute {
		return llmIPCache
	}
	m := map[string]string{}
	for _, host := range llmEndpoints {
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			m[ip.String()] = host
		}
	}
	llmIPCache = m
	llmIPCacheAt = time.Now()
	return m
}

// buildHeartbeatBody marshals the heartbeat payload, now including the observed-agent snapshot.
// `endpoint` is the WG endpoint this bastion currently DIALS (config truth) — the host compares
// it against the authoritative desired endpoint and answers with a rotate_endpoint directive
// when they differ (the concentrator→relay migration path; see maybeRotateEndpoint).
// `savePending` is true while this pairing runs on an entry and Hub key it moved to
// but has not saved yet (rotate.go, persistEndpoints).
// `mirror` is this pairing's replica state, or nil when the box holds no mirror
// for this host. Passed in rather than read from package state: one daemon
// serves several hosts and each has its own mirror, so a global would report
// one host's replica under another host's heartbeat.
//
// `self` is the pairing this beat is for (its host_name). It decides one thing:
// the full pairings list (every pairing on the box, with states) travels ONLY
// to the anchor host, because approving is the anchor's job. "" = no pairing
// identity (tests, tools): mode, anchor and unapproved attempts still travel.
func buildHeartbeatBody(self, hostname, platform, version, wgPub, fingerprint, tunnelIP, endpoint string,
	savePending bool, mirror *mirrorReport, enforcing map[string]any, peers []peerAnnounce) string {
	caps := []string{}
	// WHY SOME CAPABILITIES ARE WITHHELD HERE AND OTHERS ARE NOT — the asymmetry
	// is real and was undocumented, which is why it reads as an oversight. The
	// rule, stated so the next person does not have to re-derive it:
	//
	//   ADVERTISE what the machine CAN do. WITHHOLD what it will refuse to
	//   CONNECT.
	//
	// The inference lanes are listening ports. A pairing outside the family is
	// refused at accept (run.go inferenceRefuser), so advertising them would be a
	// lie about REACHABILITY — the host would route embeddings at a socket that
	// hangs up. Withholding is the honest answer.
	//
	// observe / mirror / freeagent are op families gated at the mgmt lane, which
	// refuses with a sentence naming the fix. Withholding those would tell the
	// host this machine CANNOT observe or mirror, when the truth is that it is
	// not yet governed — and "capability-poor" is a worse lie than "ungoverned",
	// because the second is recoverable by reading the anchor state that rides
	// the same beat. So they keep advertising on an unanchored networked box, and
	// the refusal explains itself if the control is used.
	//
	// The inference lanes (embed, llm-openai, pii) are one caps family on an
	// anchored box (anchor.go opFamily "inference"). A pairing outside it is
	// refused at the forwards' accept, so its heartbeat must not advertise
	// them either: the host offers embedding routes and PII writes on these
	// capabilities, and an offer the box will refuse is a control that fails
	// after the user has already chosen it. Withheld = the probes are skipped.
	inference := capsAllow(self, "inference") == ""
	// The same honesty rule one level finer. A grant may narrow
	// `inference` to NAMED models (modelscope.go); the forward refuses every
	// other one, so every list that leaves here is filtered to the scope and a
	// lane with nothing left in it is not advertised at all. An unscoped
	// pairing — every anchor, and every grant signed before the field existed —
	// gets exactly what it got before: scope.filterModels is the identity then.
	scope := pairingModelScope(self)
	reachable, models := false, []string(nil)
	if inference {
		reachable, models = ollamaModels(tunnelIP)
		models = scope.filterModels(models)
		// Reachable but nothing shared: advertising `embed` would put this box
		// in the host's embedding picker and every call would then be refused.
		if scope.scoped && len(models) == 0 {
			reachable = false
		}
	}
	if reachable {
		caps = []string{"embed"}
	}
	// OpenAI-compatible server (llama.cpp/vLLM via PRIVATAE_LLM_ADDR) — additive
	// capability; hosts that predate it ignore unknown caps.
	//
	// Its models go in their OWN field, never merged into `models`. Two reasons,
	// both load-bearing: (1) this server answers on a DIFFERENT port, and the
	// host derives an endpoint per list — a merged list makes it dial ollama's
	// port for a model only llama.cpp serves; (2) `models` feeds the host's
	// EMBEDDING picker, so merging offers chat models as embedding models on a
	// box running both.
	llmModels := []string{}
	llmPort := llmForwardPort
	if !inference {
		// The host stores 0 as NULL; with llm-openai withheld and
		// llm_models empty nothing on the host resolves a port for this row.
		llmPort = 0
	} else if ok, oaModels := openAICompatModels(); ok {
		oaModels = scope.filterModels(oaModels)
		if scope.scoped && len(oaModels) == 0 {
			// Same rule as `embed` above: an empty shared list means this
			// pairing has no reachable model here, so the lane is withheld
			// and llm_port goes back to the "no port" value.
			llmPort = 0
		} else {
			caps = append(caps, "llm-openai")
			if oaModels != nil {
				llmModels = oaModels
			}
		}
	}
	// PII sterilization lane (PRIVATAE_PII_ADDR; servePIIForward, :18081).
	// Additive, and ABSENT-when-unset rather than always-present like
	// llm_port: the host gates PII features on pii_port being reported at
	// all, so a bastion with no service must produce no fields — absence
	// IS the honest "not present" signal. pii_ok is the last /health
	// probe: an up forwarder with a dead upstream is a distinct state the
	// host wants before committing a fail-closed write path to it.
	piiAdvertised, piiOK := false, false
	if inference && scope.allowsPII() {
		piiAdvertised, piiOK = piiProbe()
	}
	if piiAdvertised {
		caps = append(caps, "pii")
	}
	// local agent lane (PRIVATAE_BASTION_AGENT_ADDR; freeagent.go). Same absence
	// semantics as pii: unset env → no capability, no field. freeagent_ok is
	// the last mTLS /health probe — "serving" per the local agent's own gate.
	// The capability means SERVING, not merely configured: the platform has
	// no column for freeagent_ok (schema is not this lane's to change), so the
	// store card's "freeagent: true" must be true at the moment it is read.
	// freeagent_ok still travels for the operator's eyes.
	faAdvertised, faOK := freeagentProbe()
	// managed instances (freeagent_managed.go) count the same way: any
	// serving instance advertises the capability; all must serve for ok
	if mAdv, mOK := faManagedProbe(); mAdv {
		if !faAdvertised {
			faAdvertised, faOK = true, mOK
		} else {
			faOK = faOK && mOK
		}
	}
	if faAdvertised && faOK {
		caps = append(caps, "freeagent")
	}
	// Memory mirror: advertise ONLY when this box could actually hold
	// one, which means a container runtime is installed. The host gates its
	// enable path on this capability, so a box without Docker or Podman never
	// gets offered a control that would fail after the user had already spent a
	// two-factor code on it. Re-probed every beat, so installing a runtime makes
	// the option appear without restarting anything.
	if mirrorCapable() {
		caps = append(caps, mirrorCapability)
	}
	// Service slots (service.go): advertised only when this pairing holds the
	// "services" family AND a container runtime is installed — the host offers
	// "build a server on this machine" on it, and an offer the box would refuse
	// is a control that fails after the user chose it. The slot list rides with
	// it, withheld (absent, not empty) from a pairing outside the family.
	servicesOn := servicesCapable(self)
	if servicesOn {
		caps = append(caps, serviceCapability)
	}
	// Coder runs (coders.go): the capability and its block travel together,
	// only when this machine would accept a run-up from this pairing — Linux,
	// root, coders on, a runtime, the family, and (anchored) a standing coder
	// grant. Absent, never empty, otherwise.
	coders := coderHeartbeat(self)
	if coders != nil {
		caps = append(caps, coderCapability)
	}
	// THE OBSERVE PLANE'S PAYLOAD IS GATED ON `observe`.
	//
	// `agents` is what is RUNNING on someone's computer and `schedulers` is what
	// is set to run on it. Both rode every beat to every paired host regardless
	// of its ceiling — scanAgents() takes no pairing identity at all — so a host
	// approved for one model still received the machine's process list. That
	// makes the sentence this feature exists for ("the only thing we can do with
	// this machine is use the qwen4 model") false, and it is the same separation
	// prep_tools already keeps on `dcn` and model:* on `models`.
	//
	// Both the CAPABILITY and the DATA are withheld together, and the fields are
	// OMITTED rather than emptied: an empty agents list from a box that is
	// watching perfectly well would read as "nothing running", which is a worse
	// lie than saying nothing. What tells the host which it is looking at is
	// enforcing.pairing_caps, already on this same beat — a host that can see it
	// holds no `observe` knows the box is not blind, it is not telling THEM.
	//
	// The anchor pairing holds every family, and an unanchored box (every local
	// bastion) gates nothing, so this narrows exactly one case: a member pairing
	// on an anchored box whose grant does not name observe.
	observing := capsAllow(self, "observe:host") == ""
	// Agent OBSERVE plane: say whether this box can actually watch
	// itself. Every platform enforces grants, but only a platform with both
	// enumerators reports agents — and "no agents observed" from a box that
	// CANNOT observe reads identically to a genuinely quiet box unless this
	// says otherwise. The host uses it to distinguish quiet from blind.
	if agentScanSupported && observing {
		caps = append(caps, "agent-observe")
	}
	// Computer OBSERVE rung (computer.go): the same quiet-vs-
	// blind distinction for the machine map — apps and windows. A build with no
	// enumerator withholds it, so the host never reads "no apps" from a box that
	// cannot look.
	if computerObserveSupported {
		caps = append(caps, "computer-observe")
	}
	// Scheduler inventory (schedulers.go): the standing jobs on
	// this box that would run an agent or an automation. Same quiet-vs-blind
	// rule: the capability travels only from a build that can enumerate.
	// Not probed at all when withheld — the same rule the inference lanes
	// follow above ("withheld = the probes are skipped"). Walking every crontab
	// and unit on the box to build a list nobody is entitled to read is work
	// done for nothing, on the user's own hardware.
	var schedEntries []schedEntry
	var schedScan schedScanReport
	// Declared tool servers (mcpconfig.go): the agent clients' own config
	// files, correlated with the process list. Same gate and same
	// quiet-vs-blind rule as the schedulers: read only for a pairing entitled
	// to observe, and the capability travels only from a build that can.
	var mcpServers []mcpServerObs
	var mcpScan mcpConfigScan
	if observing {
		schedEntries, schedScan = scanSchedulers()
		if schedScan.Supported {
			caps = append(caps, "scheduler-observe")
		}
		mcpServers, mcpScan = mcpServersReport()
		if mcpScan.Supported {
			caps = append(caps, "tool-server-observe")
		}
	}
	// Context preparation (contextprep.go): the tools on this box that
	// turn a user's bytes into their content — a PDF's text, an image's OCR.
	// Gated on the dcn family like the ctx_* ops it serves, so a member pairing
	// that would be refused at the op is never offered the feature; withheld
	// skips the probe entirely, exactly as the inference lanes do above.
	// Model management (modelswap.go): could this box have a model
	// PULLED onto it by this host. Its own family ("models"), so a pairing that
	// holds `inference` — the right to USE what is already loaded — is not
	// offered this and its probe is skipped, exactly as the lanes above do.
	// COULD, never WILL — and here that is narrower than it sounds: holding the
	// family buys the host the right to ASK, not to download. Every pull ALSO
	// needs the user's approval on this machine, bound to that exact model, role
	// and byte ceiling, good for one use (modelPullApproved, modelswap.go). So
	// this capability means "you may propose a model to this user", never "you
	// may write to their disk".
	if modelSwapCapable(self) {
		caps = append(caps, modelSwapCapability)
	}
	prepTools, prepScan, prepOK := prepCapable(self)
	if prepOK {
		caps = append(caps, prepCapability)
	}
	if prepTools == nil {
		prepTools = []prepToolReport{}
	}
	if models == nil {
		models = []string{}
	}
	body := map[string]interface{}{
		"hostname":        hostname,
		"platform":        platform,
		"gateway_version": version,
		"tunnel_status":   "up",
		"wg_pubkey":       wgPub,
		"device_health":   "healthy",
		// Which context-preparation tools this box actually has, and how many
		// were probed to find them — so "no tools" from a box that probed three
		// binaries is visibly different from one that probed none. The host's
		// question is "can this box turn this mime into text", which this list
		// answers as a lookup. Empty when the capability is withheld.
		"prep_tools":           prepTools,
		"prep_scan":            prepScan,
		"hardware_fingerprint": fingerprint,
		"capabilities":         caps,
		// The ollama models this box serves — the host stores these and offers
		// them in its embedding pickers, so model selection matches reality.
		"models": models,
		// The OpenAI-compatible server's models, and the TUNNEL-SIDE port the
		// host must dial to reach them (serveLLMForward proxies it to
		// PRIVATAE_LLM_ADDR). The port is reported rather than assumed so the
		// constant lives in ONE place instead of being duplicated host-side.
		"llm_models":  llmModels,
		"llm_port":    llmPort,
		"reported_ip": tunnelIP,
		"endpoint":    endpoint,
		// True while this pairing runs on an entry and Hub key it moved to
		// but could not save: a restart would come up on the ones its file
		// still names. The host reads the key a machine runs from its Hub's
		// handshakes, which cannot see the disk, so it keeps the key the file
		// names served until this is false. On every beat; a host reads its
		// absence as a client too old to say.
		"endpoint_save_pending": savePending,
	}
	// The service slots this pairing may reach, with the tunnel port for each
	// (service.go). Absent when the capability is withheld, never empty-for-no.
	if servicesOn {
		body["services"] = serviceReports()
	}
	if coders != nil {
		body["coders"] = coders
	}
	// The observe plane's payload, for a pairing entitled to it. Absent — not
	// empty — for one that is not: see the `observing` note above. The box is
	// not retracting what it saw, it has stopped being allowed to say — and
	// what the HOST does with the absence differs per key, so this comment
	// used to overstate it ("the host COALESCEs an absent key"). Checked against
	// the host: `peers`, `posture`, `machine_record_dropped` and
	// `schedulers` are COALESCEd (the last reading survives); `scheduler_scan`
	// is overwritten with NULL — and NULL there is the quiet-vs-blind
	// discriminator, so that reads as "not looked", not as "nothing
	// scheduled"; a pending containment is HELD on a beat without `agents`.
	// Each host column states its own rule; none of them reads an absent key
	// as an all-clear.
	if observing {
		// WITHHELD, not emptied, when the walk fails. An empty list from a box
		// that advertises agent-observe means "looked, nothing there" to the
		// host — it clears a kill order the user placed. A walk that did not
		// happen sends no key; the host holds the order until one that did.
		if agents, err := scanAgents(); err == nil {
			body["agents"] = agents
			// The positive signal that this list was MEASURED. A build before
			// this one sent an empty list for a failed walk too, and the host
			// cannot tell those apart by the list alone; it clears a pending
			// containment only when this key says the walk happened, and
			// holds (then lapses) an order for a box that never says so.
			body["agent_scan_ok"] = true
		} else if agentScanSupported {
			// Printed only where a failure is news: a build with no enumerator
			// fails every beat by construction, and the withheld capability
			// already says so — a line per beat there would bury the real
			// transient failures this print exists for.
			fmt.Printf("observe: agent scan failed this beat (%v) — agents withheld from the heartbeat\n", err)
		}
		// Which enumerator produced that list ("proc+ss", "ps+lsof",
		// "toolhelp+iphlpapi", "unsupported"). The platform has no column for
		// it and ignores unknown fields; it travels for the operator's eyes
		// when debugging a box, the same way freeagent_ok does. The DECISION
		// signal is the "agent-observe" capability above, which IS stored.
		body["agent_scan"] = agentScanKind
		// Scheduled entries that match the agent/automation tables, and how
		// much was scanned to find them — so "no scheduled agents" from a box
		// that read 0 crontabs is visibly different from one that read 40.
		body["schedulers"] = schedEntries
		body["scheduler_scan"] = schedScan
		// The tool servers each agent client declares, and which are running
		// (or running with no declaration). Paths, server names and command
		// lines, so inside this gate with the agent list; env values and
		// header values never leave mcpconfig.go, only their names and
		// whether one looked like a secret.
		body["tool_servers"] = mcpServers
		body["tool_server_scan"] = mcpScan
		// Where this machine keeps its own record — the findings journal and
		// the signed accounting (machinestore.go, baselinesign.go). The host
		// drafts a machine store at this root for the user to approve, once;
		// until they do,
		// nothing reads it. A path, reported, not a grant.
		//
		// INSIDE THE `observing` GATE, with the other path-bearing keys. The
		// value is <os.UserConfigDir()>/privatae-bastion/store — which names
		// the operator's OS account (/home/<user>/…, /Users/<user>/…,
		// C:\Users\<user>\…). The rule the surrounding keys follow is that
		// material naming programs and paths travels only to a pairing
		// granted `observe`; the first version sent this ungated, on every
		// beat, to pairings the code above takes care to send no paths to.
		// Reading the record IS observing, so a pairing without it gets no
		// root and therefore no draft — which is the correct outcome.
		if root, err := storeRootPath(); err == nil && root != "" {
			body["machine_record_root"] = root
		}
		// Results the record could NOT keep, per shelf. ALWAYS present inside
		// this gate — an empty object when the record is whole — and absent
		// only when this pairing is not entitled to observe. The first version
		// omitted the key at zero, and the host then had two sources of
		// absence it could not tell apart: "whole" and "no longer allowed to
		// say" (the observe switch in the console, no restart, holes still
		// accumulating). It overwrote a populated column with NULL and called
		// the machine whole. This is the nil-vs-empty contract `peers` keeps
		// on this same beat (below): empty is a real state and must travel;
		// absent means not entitled, and the host keeps what it has.
		d := storeObserveDroppedSnapshot()
		if d == nil {
			d = map[string]int64{}
		}
		body["machine_record_dropped"] = d
	}
	// What this box did with the findings THIS pairing asked it to stop
	// (containfinding.go). Outside the observe gate: it carries fingerprints
	// the host itself sent and an outcome word, nothing the host did not
	// already hold. ALWAYS present, an empty list when there is nothing to
	// report, so the host can tell a box that has answered nothing from one
	// that predates the key (absent) — the second holds an order until it
	// lapses rather than reading silence as done.
	body["contain_results"] = containResultsReport(self)
	// Mirror state as THIS box sees it. The host does not trust this for lag —
	// it reads pg_stat_replication on the primary, the one place that cannot be
	// talked into a comforting number. What it carries is the set of states the
	// primary genuinely cannot observe: no runtime, image not downloaded,
	// container dead, version mismatch. Sent only once a mirror exists, so a
	// bastion that holds none adds no field.
	if mirror != nil && mirror.State != "absent" {
		body["mirror"] = *mirror
	}
	// NAC agent: what this box is ENFORCING, so the host's posture
	// is a comparison against what it granted, not this self-reported string.
	// device_health stays for hosts that predate the report.
	if enforcing != nil {
		body["enforcing"] = enforcing
	}
	// Peer announcement: the OTHER hosts this machine serves, so a
	// host learns it shares a box with them. Name and handle only — peers.go
	// says why that boundary is load-bearing.
	//
	// nil vs EMPTY is the whole contract, and both halves must agree on it:
	//   nil   — we could not enumerate the pairings. Say nothing; the host keeps
	//           what it has (peers = COALESCE(EXCLUDED.peers, stored)). An older
	//           bastion sends no key at all and lands here too, which is why
	//           absence can never be read as "serves only this host".
	//   empty — we DID enumerate and there are no others. That is a real state
	//           change (the user unpaired the last other host) and it must
	//           travel, or the host lists peers this machine no longer serves
	//           for good.
	// So the test is `peers != nil`, not `len(peers) > 0`.
	if peers != nil {
		body["peers"] = peers
	}
	// Machine ownership: who owns this box, if anyone has said.
	// Absent when nobody has, which is the normal state — the host just shows no
	// owner line. Grants nothing anywhere.
	if oc := currentOwnerClaim(); oc != nil {
		body["owner_claim"] = oc
	}
	// The detection plane's summary line (deltarun.go): how many
	// findings stand against this machine's accounting, and — just as important
	// — whether there IS an accounting to stand against. A box with no baseline
	// reports `baseline: none` rather than zero findings, so "nothing has
	// changed here" and "nobody ever said what normal was" can never read the
	// same on the host's card. Absent until the first pass completes, the way
	// posture is.
	if d := deltaPayload(); d != nil {
		body["findings"] = d
	}
	// Host posture (observe_ops.go): the sentinel HOST_PROBE fields,
	// folded in so SEEING posture costs no management grant. Cached for
	// 5 minutes (posturePayload says why, with the measured cost); Linux only,
	// and absent — no key — everywhere else, so a host never reads "ufw:
	// absent" from a box that could not have looked.
	if hp := posturePayload(); hp != nil {
		body["posture"] = hp
	}
	// The Alertmanager summary (observe_pull.go): how many alerts are
	// firing against the infrastructure this box sits on, folded in the way
	// findings and posture are, so the host learns of a critical without
	// spending a management op on every beat. The rows are pulled on demand
	// with observe:alerts; only the counts, the oldest start and up to twenty
	// fingerprints ride the beat.
	//
	// ABSENT — no key — when no endpoints file names an alertmanager, and
	// absent until the first successful refresh. That is the peers rule above
	// applied here, and it matters more: a zero `firing` from a box that has no
	// Alertmanager to ask would read as an all-clear from a machine nobody is
	// watching.
	//
	// UNGATED — outside `observing`, like posture and findings and unlike agents
	// and schedulers. Settled here so the next reader does not re-litigate it:
	//
	//   - What `observing` gates is the machine's CONTENT. `agents` is the
	//     process list of someone's computer and `schedulers` is what is set to
	//     run on it; both name programs and paths, so a host scoped to one model
	//     has no business receiving them.
	//   - This carries counts and opaque fingerprints. No alert names, no labels,
	//     no hostnames — a fingerprint is an Alertmanager hash that resolves to
	//     nothing without the Alertmanager. The ROWS, which do carry labels, live
	//     behind observe:alerts, and that op is grant-gated like every other.
	//   - The design's rule is that SEEING a machine's health costs no grant —
	//     §8 folds posture into the beat precisely so that "*seeing* posture
	//     costs no grant". A host told this box is unhealthy, and able to learn
	//     nothing more about why without a grant, is the intended shape.
	if al := alertsPayload(); al != nil {
		body["alerts"] = al
	}
	// Mode (2026-09-08, mode.go): local or networked, on EVERY beat, so a host
	// can never mistake one shape for the other when it reads the box's card.
	body["mode"] = boxMode()
	// Anchor (anchor.go): who approves pairings on this box. Absent when the
	// box is not anchored — every local bastion. The verify key stays home.
	anchor := currentAnchor()
	if anchor != nil {
		body["anchor"] = anchor
		// The anchor host alone gets the full list — every pairing including
		// the pending ones it is being asked to approve, and itself.
		if self != "" && anchor.AnchorHost == self {
			if list := pairingsReport(); list != nil {
				body["pairings"] = list
			}
		}
	}
	// A pairing left pending past unapprovedAfter is an attempt someone did
	// not approve. Every host on the box hears about it — that is the
	// intrusion signal. Same nil-vs-empty rule as peers: an enumerated
	// "none" travels as [] so the host's COALESCE can clear a past attempt;
	// the key is absent only when the pairings could not be read.
	if u := unapprovedAttempts(time.Now()); u != nil {
		body["unapproved_pairing_attempts"] = u
	}
	// Another bastion installed on this machine (otherbastions.go).
	// The singleton refuses new ones; this is how a host hears about
	// the ones already on disk, or any that got around the refusal. Every host
	// on the box is told, like unapproved attempts above — a second bastion
	// affects all of them, not only the anchor.
	//
	// Same nil-vs-empty contract, and here it carries extra weight: the key is
	// absent on any box that could not LOOK (not root, not Linux), so a host
	// never reads "no second bastion" off a box that never checked.
	if ob := otherBastionsPayload(); ob != nil {
		body["other_bastions"] = ob
		// WHEN it was looked at, beside what was found. A scan that stops
		// completing keeps publishing its last answer, and if that answer is []
		// the host would read "clean" for ever with nothing to say otherwise.
		if at := otherBastionsScannedAt(); at != "" {
			body["other_bastions_scanned_at"] = at
		}
	}
	if piiAdvertised {
		body["pii_port"] = piiForwardPort
		body["pii_ok"] = piiOK
	}
	if faAdvertised {
		body["freeagent_ok"] = faOK
		if st := faManagedStatus(); len(st) > 0 {
			body["freeagent_stores"] = st
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return `{"tunnel_status":"up","device_health":"healthy"}`
	}
	return string(data)
}

func splitNul(raw []byte) []string {
	out := []string{}
	for _, p := range strings.Split(string(raw), "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseEnvToken extracts ONE env var's value from a NUL-separated environment blob. Only
// the named var is ever returned — the rest of the process's environment is never read out.
func parseEnvToken(environ []byte, key string) string {
	pre := key + "="
	for _, kv := range strings.Split(string(environ), "\x00") {
		if strings.HasPrefix(kv, pre) {
			return kv[len(pre):]
		}
	}
	return ""
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
