package main

// modelswap.go — the host may SWAP MODELS on a granted machine.
//
// The host may change which models are on a granted machine, because a
// machine that serves inference is only useful if its models can follow the
// work.
//
// ── why a NEW caps family and not the inference one ────────────────────────
//
// The inference family already exists (anchor.go:430) and covers the three
// INBOUND forwards — ollama :11434, the OpenAI-compatible server, the PII
// sterilizer (anchor.go:401-407). Hanging these ops off it would have been one
// line, and it is the wrong line: every pairing already granted `inference`
// would have silently gained the ability to download gigabytes onto the user's
// disk and to delete models from it, with no one approving that. A grant means
// what it meant when it was given. So "models" is its own family, every
// existing grant lacks it, and TestModelOpsRefusedToAMemberGrantedInference
// pins that.
//
// ── why the op names begin "model:" ────────────────────────────────────────
//
// Same trap contextprep.go:60-73 documents: capsAllow maps an op to a family
// through opFamily (anchor.go:411-427), and opFamily returns "" for a name it
// does not recognise — whereupon capsAllow ALLOWS it (anchor.go:476-479). An op
// called "pull_model" would be UNGATED on an anchored box, silently. opFamily
// now maps the "model:" prefix to "models"; TestModelOpsResolveToTheModelsFamily
// fails if a rename ever breaks that, and also pins that "model:" does not
// collide with the "mode:" prefix directly above it (which means harness).
//
// ── never unload a model the host did not put there ────────────────────────
//
// Enforced by a LEDGER, not by a convention: modelsPlacedFile in the pairing's
// own state directory records every model this host successfully pulled onto
// this box. model:drop reads that ledger and refuses any model missing from it.
// A model the user pulled themselves — their local llama, the one their work
// depends on — is in no host's ledger and is therefore undroppable through this
// lane, by construction. The ledger is per-pairing (the root is the same
// per-pairing directory stepup_* uses, mgmt.go:68-71), so one host cannot drop
// what a different host placed either.
//
// ── probe before commit: a 200 from the pull is worth NOTHING ──────────────
//
// MEASURED 2026-09-12 against ollama 0.34.0 in a container, every line below
// executed, none copied from documentation:
//
//	POST /api/pull {"model":"all-minilm","stream":false}
//	  -> HTTP 200 {"status":"success"}              (1.6 s, 46 MB)
//	POST /api/pull {"model":"<nonexistent>"}        (stream defaulted to true)
//	  -> HTTP 200, body: {"status":"pulling manifest"}
//	                     {"error":"pull model manifest: file does not exist"}
//	POST /api/pull {"model":"<nonexistent>","stream":false}
//	  -> HTTP 500 {"error":"pull model manifest: file does not exist"}
//
// So a STREAMING failed pull answers 200 and reports the failure only in the
// body: the status line alone would have reported a model that was never
// downloaded as installed. modelPullStreaming therefore reads EVERY line of the
// stream for an "error" key and requires the daemon's own "success" before it
// calls a download finished — the status code is checked too, but it is the
// weakest of the three signals, not the deciding one.
//
// (The lane streams rather than sending stream:false, which an earlier draft
// did. The byte ceiling is why — the size is only knowable from the stream; see
// "THE SIZE IS A CEILING" below. Streaming is exactly the case that answers 200
// on failure, so the body check above is what makes it safe.)
//
// And a successful download still proves only that bytes arrived. The probe is
// BEHAVIOURAL, following the fix in the platform's media lane
// (the host's media probe): matching widths could not
// tell a text model from an image one, so the check became "send the same
// picture encoded two ways, it must answer the same; send a different picture,
// the answer must move". The same two gates in this lane's terms, both measured
// on all-minilm:
//
//	same input twice          cos 1.000000   (>= modelSameInputMinCos, 0.999)
//	a different input         cos 0.096444   (<= modelDiffInputMaxCos, 0.9999)
//
// The second gate is not decoration: without it an endpoint returning one fixed
// vector passes the first trivially, a constant being identical to itself.
//
// The role probes are genuinely different calls because ollama itself separates
// them, measured the same day:
//
//	POST /api/generate  on all-minilm  -> HTTP 400 "does not support generate"
//	POST /api/embed     on qwen3:0.6b  -> HTTP 501 "does not support embeddings"
//
// so asking for the behaviour we want is also what tells the two apart. The
// `capabilities` array in /api/tags claims the same thing, and it is a PROXY —
// the model's own metadata, not an answer from the running model. It is not
// consulted here.
//
// ── advertising is "could", never "will" ───────────────────────────────────
//
// The capability says a model daemon answers on this box and this pairing holds
// the family. Nothing in this file initiates a download on its own: every pull
// is a mgmt op somebody sent, and one the user approved on this machine.
//
// ── MACHINE-SIDE APPROVAL: what actually gates a pull ──────────────────────
//
// The user says yes on the very box whose disk is about to be filled, with the
// second factor enrolled THERE. The host proposes; it does not authorize.
//
// TWO GATES, and the caps family is only the first:
//
//  1. capsAllow at the mgmt boundary — does this pairing hold "models" at all.
//  2. modelPullApproved, below — has the user approved THIS pull, here, with
//     their code. handleModelPull touches no network before it passes.
//
// The second exists because the first is not sufficient and cannot be made so.
// A caps grant is given once, at pairing time, and names no models, and a standing
// grant broader than an exact list is a silent pull by another name. The capability buys the host the right to ASK, nothing more.
//
// THE FLOW — all of it already built for the DCN lanes, reused rather than
// reinvented (stepup.go):
//
//	host -> stepup_request  purpose "model_pull|<model>|<role>|<bytes>|<replaces>"
//	          the box REBUILDS that purpose from the details it was sent
//	          (purposeFromDetails) and refuses if the two disagree — so the words
//	          the user reads are the words the box will enforce
//	user -> privatae-bastion approvals      reads the plan, in their own words
//	        privatae-bastion approve <id>   their code, typed on this machine
//	host -> stepup_status <id>              -> the approval id
//	host -> model:pull {..., approval}      -> modelPullApproved re-derives the
//	                                           purpose from the OP's own fields
//
// WHY IT BINDS TO THIS PULL AND NOT TO "A PULL". The purpose is a field list
// built from the request itself, never taken from the wire, and
// stepupCheckApproval compares it exactly (stepup.go:503-505). Ask for another
// model, another role or a bigger ceiling and the purpose differs, so the
// approval does not match. It is single-use (stepup.go:500-502, burned by
// stepupMarkUsed once the download completes): one yes funds one download. Same
// shape the pull path's ticket got right — nothing on the wire the caller can
// change, single-use, bound to one machine (contextpull.go:23-32).
//
// THE SIZE IS A CEILING, NOT A CLAIM. MEASURED: /api/show on a model that is
// not local yet answers HTTP 404, so this box cannot learn a download's size
// before it begins, and a number the host merely asserts is one the user would
// have to take on trust. So the host's number is bound into the purpose the
// user approves, and modelPullStreaming holds the download to it — reading each
// layer's declared `total` as it is announced and stopping before those bytes
// move if the sum exceeds what was approved.
//
// AN UNENROLLED MACHINE IS REFUSED, which is stricter than stepupGate
// (stepup.go:524-529) and deliberately so — reasoning at modelPullApproved.
//
// REFUSED, IGNORED AND EXPIRED ARE NORMAL OUTCOMES. A user who says no, or who
// never walks over to their machine, has produced an ordinary result: exit 126
// and a sentence saying what happened. No model was downloaded and nothing is
// broken. A denial stands for 24h (stepup.go:572-574), so "no" is not something
// the host can wear down by asking again.
//
// ── ASYNC: start returns at once, status reports progress ──────────────────
//
// A pull is bounded at 20 minutes here and its worst case is 26 (the embed
// probe makes three modelProbeTimeout calls, probeEmbedModel below). Holding
// one management frame open for that long was wrong three ways, and sizing the
// host's wait — which is what shipped first on the host side
// the host's mgmt worker — only fixed the first of them:
//
//   1. the host gave up at 30 s and called a working machine a missing one;
//   2. POST /api/network/mgmt/run blocks for the whole download, behind
//      whatever ingress timeout sits in front of it;
//   3. it parks one of only TWO management workers (mgmtWorkerCount, mgmt.go:18)
//      for the duration, so half the lane is gone while a model downloads.
//
// Sizing the wait can only ever fix (1). So this lane takes the shape
// backup_fetch already has and backupfetch.go:24-28 already explains: `start`
// validates, spawns and returns a job id immediately; `status` reports
// progress. Each call is its own short dispatch. There is ONE async idiom in
// this binary, not two.
//
// BOTH OPS RIDE THE `model:pull` JOB NAME, for the reason backupfetch.go:127-128
// gives for doing the same: the user's signed grant names op ids exactly
// (its management decision), so a separate `model:status` op would be
// ungranted in every grant already written — a user whose grant says model:pull
// could start a download and then not be allowed to watch it finish. A weaker
// action must never need a second approval.
//
// A STATUS POLL IS NOT GATED BY AN APPROVAL, and cannot become a start: the
// dispatch at the top of handleModelPull sends it to modelPullStatusOp, which
// reads the job table and returns. It touches no network, writes no disk and
// names no model.
//
// WHAT THE ASYNC SPLIT PUTS AT RISK, and what holds it. The invariant is
// unchanged — stepupMarkUsed and recordPlaced still fire only after
// modelPullStreaming returns clean — but it now runs in runModelPull, off the
// frame. So:
//
//   * a start that succeeds and is NEVER polled still burns the approval
//     exactly when the bytes land, because the goroutine burns it, not the
//     poll. Nothing is stranded: model:list reports the model with
//     placed_by_this_host true and the host's reconcile reads that
//     (its pull reconcile) and says in words not to ask for a
//     second approval;
//   * a download that FAILS and is never polled leaves the approval intact and
//     the ledger unchanged, so the same approval still funds a retry;
//   * TWO STARTS INSIDE ONE DOWNLOAD is the genuinely new hole. stepupCheckApproval
//     passes while Used is still false (stepup.go:529-531), and Used is only set
//     when the download completes, so a host that re-starts instead of polling
//     would have had two downloads on one yes. modelPullLiveForApproval closes
//     it: a start whose approval already has a running job returns THAT job,
//     and begins nothing. Same idea as backup_fetch checking the disk before the
//     URL (backupfetch.go:192-208) — answer from what is already happening
//     before doing the work again.
//
// A BASTION RESTART loses the job table, exactly as it loses backupJobs. status
// then answers "unknown", which is deliberately not "failed": the approval was
// never burned (the goroutine died before stepupMarkUsed) so it is intact and
// single-use, and the host re-starts with the same approval and asks the user
// for nothing. If the download HAD completed before the restart, the approval is
// spent and the ledger has it, so the host's reconcile finds it through
// model:list — which is why the host treats "unknown" as "ask the ledger", not
// as a failure.
//
// A NOTE FOR WHOEVER READS THIS NEXT. An earlier draft of this block claimed
// "pulling anything remains an explicit act the user approves" while the
// handler beneath it went straight to POST /api/pull. Review caught it, and it
// is worth saying why it was dangerous: a comment asserting a property is what
// the next reviewer trusts INSTEAD of reading the handler. If you change this
// lane, re-read handleModelPull and make this block match it, or delete it.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// modelSwapCapability is the single additive token. agents.go:359-360 records
// that a host predating a capability ignores one it does not know, so this
// needs no host-side flag day.
const modelSwapCapability = "model-swap"

// modelGateOp is the op the capability is gated by, and modelGateOpFamily is
// the family it MUST resolve to. Both are asserted in the test — see the
// header: an op name outside opFamily's vocabulary is an ungated op.
const modelGateOp = "model:pull"
const modelGateOpFamily = "models"

// The two behavioural thresholds, taken from the platform's media probe
// (its media probe) rather than invented here, so one lane's idea of
// "the same answer" cannot drift from the other's.
const modelSameInputMinCos = 0.999
const modelDiffInputMaxCos = 0.9999

// The probe inputs. Two unrelated sentences: the first is sent twice (an
// endpoint must answer it identically), the second once (it must move the
// answer). Deliberately ordinary text — a degenerate input fails for the wrong
// reason, the same trap the host's own probe test pins for the probe
// image.
const modelProbeTextA = "the bastion probe sentence"
const modelProbeTextB = "a completely unrelated control string about oranges"

// The generate-role probe: two different prompts whose answers must differ.
// Measured on qwen3:0.6b — "apple" twice, then "orange".
const modelProbePromptA = "Reply with the single word: apple"
const modelProbePromptB = "Reply with the single word: orange"

// A pull is gigabytes over someone's home connection. This bounds ONE call, not
// the size of a model: 20 minutes is long enough for a 30 GB model on a slow
// line and short enough that a wedged daemon does not hold the lane for ever.
const modelPullTimeout = 20 * time.Minute

// ── how long a proposal and an approval live, and why no new number ────────
//
// This lane introduces NO TTL of its own. A proposal waits stepupRequestTTL and
// an approval lives stepupApprovalTTL — both 24h, both already in stepup.go:61-62,
// both shared with the DCN grant and move-plan lanes.
//
// Inheriting was the decision, not the default. What bounds the risk here is
// not the clock: an approval is SINGLE-USE and bound to an exact purpose, so
// the worst a stale one can do is download precisely the model, for precisely
// the role, at precisely the ceiling the user read and agreed to. Redeeming
// that later is not a different outcome from redeeming it at once.
//
// The precedents cluster where the credential is broader than one action, which
// is why their windows are tighter than this one needs to be: sudo's
// timestamp_timeout is 15 minutes and GitHub's sudo mode 3 hours, both
// authorizing a SESSION of privileged acts rather than one; RFC 8628's device
// authorization grant expires a user_code in 30 minutes because it yields a
// token; AWS STS MFA sessions run 12h by default and 36h at most, again a
// session. Windows UAC is the closest analogue to this shape — per-action, no
// clock at all — and it is the one this most resembles.
//
// The 24h on the PROPOSAL side is doing real work and is the reason not to
// shorten it: the point of machine-side approval is that the user walks to the
// machine, and a window that expires while they are out is a design that
// punishes the behaviour it is asking for. A proposal that lapses is a normal
// outcome (stepup_status answers "expired", stepup.go:685-690), and the host
// may simply propose again.
//
// Changing either constant would change the DCN lanes too, which is not this
// lane's call to make.

// modelPullMaxStreamBytes bounds the PROGRESS STREAM, not the download. A
// hostile or broken daemon that never stops emitting progress lines must not be
// able to hold this lane open for ever; 64 MiB of JSON progress is orders of
// magnitude past any real pull (the 46 MB model measured here produced a few
// kB of it).
const modelPullMaxStreamBytes = 64 << 20
const modelProbeTimeout = 2 * time.Minute
const modelListTimeout = 10 * time.Second

// ── how long a FINISHED job record is kept, and how many ───────────────────
//
// No new clock, for the same reason the TTL block above gives: a job record
// outliving the approval that authorized it can tell nobody anything they can
// act on. Once the approval is spent or expired, model:list is the durable
// record of what this host placed, and the reconcile path reads it.
// stepupApprovalTTL (stepup.go:61) is therefore the retention.
//
// The surveyed practice is a spread of CAPS with no minimum anywhere: Google's
// AIP-151 offers "a good rule of thumb for operation expiry is 30 days" and
// mandates nothing; AWS Textract keeps async results 7 days from job start;
// Transcribe 90; Kubernetes ships no ttlSecondsAfterFinished default at all.
// Every one of those is a DURABLE resource. This is an in-process map that a
// restart clears anyway, so borrowing 30 days would be theatre — 24h is longer
// than any pull and exactly as long as the thing that authorized it.
var modelPullJobRetention = stepupApprovalTTL

// modelPullJobsMax bounds the table so a long-lived daemon cannot accumulate
// records without limit. BuildKit ships the closest analogue as a real default
// — an in-process history of finished local build jobs, `[history] maxEntries`,
// 50 — so that is the number rather than one invented here. Eviction takes the
// OLDEST FINISHED job and never a running one.
const modelPullJobsMax = 50

// The poll cadence this box ASKS for, in poll_after_s on every running status.
// Not a new invention: it is exactly the cadence the host already runs against
// backup_fetch (first poll after 2 s, then x1.5, capped at 30 s), which also
// sits inside the band the survey found (Google's own LRO defaults in google/api/client.proto are
// initial 5 s, multiplier 1.5, max 45 s). One lane, one cadence.
const modelPullPollFirstS = 2.0
const modelPullPollGrowth = 1.5
const modelPullPollMaxS = 30.0

// modelDaemonCacheFor matches prepCacheFor (contextprep.go:77) for the same
// reason given there: the heartbeat is every 60 s and this is one HTTP call.
const modelDaemonCacheFor = 10 * time.Minute

// ── the ownership ledger ───────────────────────────────────────────────────

// modelsPlacedName lives in the pairing's own state directory, beside the
// stepup and DCN state that directory already holds.
const modelsPlacedName = "models_placed.json"

// placedModel is one model THIS host put on THIS box. Dim/Role are what the
// probe actually measured, not what was asked for.
type placedModel struct {
	PlacedAt string `json:"placed_at"`
	Role     string `json:"role"`
	Dim      int    `json:"dim,omitempty"`
	// Bytes is what the download actually moved, as the daemon declared it —
	// recorded so the user can later see what each model this host placed is
	// costing them, rather than only that it is here.
	Bytes int64 `json:"bytes,omitempty"`
}

var modelLedgerMu sync.Mutex

func modelsPlacedPath(root string) string { return filepath.Join(root, modelsPlacedName) }

// loadPlacedModels never invents an entry: an unreadable or absent ledger is an
// EMPTY one, which denies every drop. Failing open here would be failing open
// on "may I delete this".
func loadPlacedModels(root string) map[string]placedModel {
	out := map[string]placedModel{}
	raw, err := os.ReadFile(modelsPlacedPath(root))
	if err != nil {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

func savePlacedModels(root string, m map[string]placedModel) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(modelsPlacedPath(root), b)
}

// recordPlaced and forgetPlaced are the only writers.
func recordPlaced(root, model string, p placedModel) error {
	modelLedgerMu.Lock()
	defer modelLedgerMu.Unlock()
	m := loadPlacedModels(root)
	m[model] = p
	return savePlacedModels(root, m)
}

func forgetPlaced(root, model string) error {
	modelLedgerMu.Lock()
	defer modelLedgerMu.Unlock()
	m := loadPlacedModels(root)
	delete(m, model)
	return savePlacedModels(root, m)
}

// placedByThisHost is THE ownership question, and the only thing model:drop is
// allowed to consult.
func placedByThisHost(root, model string) bool {
	_, ok := loadPlacedModels(root)[model]
	return ok
}

// ── talking to the model daemon ────────────────────────────────────────────

var (
	modelDaemonMu   sync.Mutex
	modelDaemonUp   bool
	modelDaemonAt   time.Time
	modelDaemonAddr string // the address the cached answer is for
)

// modelDaemonReachable probes the SAME address the rest of this binary uses
// (localOllamaAddr, run.go:714-719) so the box can never advertise management
// of a daemon the forwards do not point at.
func modelDaemonReachable() bool { return modelDaemonReachableAt(localOllamaAddr()) }

// modelDaemonReachableAt is modelDaemonReachable's probe of one address. The
// cached answer is for the address it was asked of, so a pairing whose
// address is the vetted one (modelDaemonTarget) never reads another's answer.
func modelDaemonReachableAt(addr string) bool {
	modelDaemonMu.Lock()
	defer modelDaemonMu.Unlock()
	if !modelDaemonAt.IsZero() && modelDaemonAddr == addr && time.Since(modelDaemonAt) < modelDaemonCacheFor {
		return modelDaemonUp
	}
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get("http://" + addr + "/api/tags")
	up := false
	if err == nil {
		up = resp.StatusCode == http.StatusOK
		resp.Body.Close()
	}
	modelDaemonUp, modelDaemonAt, modelDaemonAddr = up, time.Now(), addr
	return up
}

// resetModelDaemonCache exists for the tests.
func resetModelDaemonCache() {
	modelDaemonMu.Lock()
	modelDaemonUp, modelDaemonAt, modelDaemonAddr = false, time.Time{}, ""
	modelDaemonMu.Unlock()
}

// modelSelf is the pairing a model:* job came from, or "" when the job was
// driven without one (modelDaemonTarget then keeps OLLAMA_ADDR, as before).
func modelSelf(ws *websocket.Conn) string {
	if a := mgmtAccountOf(ws); a != nil {
		return a.self
	}
	return ""
}

// modelSwapCapable answers the heartbeat's question: could this box have a
// model placed on it BY THIS PAIRING. Two conditions, and the caps one is
// first so a pairing outside the family costs no probe — the rule the
// inference lanes follow at agents.go:351-355.
func modelSwapCapable(self string) bool {
	if capsAllow(self, modelGateOp) != "" {
		return false
	}
	// A Host with no platform is offered management only of a model server on
	// this machine, and a refused one is not probed at all (modelDaemonTarget).
	addr, why := modelDaemonTarget(self)
	if why != "" {
		return false
	}
	return modelDaemonReachableAt(addr)
}

// modelPostJSON posts one JSON body and returns (status, body). The body is
// read whatever the status is: a streaming ollama reports a FAILED pull inside
// a 200 (measured, see the header), so the caller needs both.
func modelPostJSON(addr, method, path string, payload any, timeout time.Duration) (int, []byte, error) {
	var rdr io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+addr+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// modelBodyError pulls the "error" out of a response body, checking EVERY line:
// a streamed pull writes one JSON object per line and the failure is the last
// one, so decoding only the first would read {"status":"pulling manifest"} and
// call it a success.
func modelBodyError(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var v struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(line), &v) == nil && v.Error != "" {
			return v.Error
		}
	}
	return ""
}

// ── the behavioural probe ──────────────────────────────────────────────────

func modelCosine(a, b []float64) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return math.NaN()
	}
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return math.NaN()
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func modelEmbedOnce(addr, model, text string) ([]float64, error) {
	status, body, err := modelPostJSON(addr, http.MethodPost, "/api/embed",
		map[string]any{"model": model, "input": []string{text}}, modelProbeTimeout)
	if err != nil {
		return nil, err
	}
	if e := modelBodyError(body); e != "" {
		return nil, fmt.Errorf("%s", e)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	var out struct {
		Embeddings [][]float64 `json:"embeddings"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Embeddings) == 0 || len(out.Embeddings[0]) == 0 {
		return nil, fmt.Errorf("no vector in the answer")
	}
	return out.Embeddings[0], nil
}

func modelGenerateOnce(addr, model, prompt string) (string, error) {
	status, body, err := modelPostJSON(addr, http.MethodPost, "/api/generate",
		map[string]any{"model": model, "prompt": prompt, "stream": false, "think": false}, modelProbeTimeout)
	if err != nil {
		return "", err
	}
	if e := modelBodyError(body); e != "" {
		return "", fmt.Errorf("%s", e)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", status)
	}
	var out struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("unparsable answer")
	}
	return out.Response, nil
}

// probeEmbedModel proves the model EMBEDS: the same text twice must come back
// as one answer, and a different text must move it. Returns the measured width
// and "" , or 0 and the reason it is not usable.
func probeEmbedModel(addr, model string) (int, string) {
	v1, err := modelEmbedOnce(addr, model, modelProbeTextA)
	if err != nil {
		return 0, "it was downloaded but does not answer as an embedding model: " + err.Error()
	}
	v2, err := modelEmbedOnce(addr, model, modelProbeTextA)
	if err != nil {
		return 0, "it answered once and then failed: " + err.Error()
	}
	same := modelCosine(v1, v2)
	if !(same >= modelSameInputMinCos) {
		return 0, fmt.Sprintf("it gave two different answers to the SAME text (similarity %.4f) — "+
			"nothing routed at it would be reproducible", same)
	}
	v3, err := modelEmbedOnce(addr, model, modelProbeTextB)
	if err != nil {
		return 0, "the control text failed: " + err.Error()
	}
	if len(v3) != len(v1) {
		return 0, "it answered two texts at two different widths"
	}
	diff := modelCosine(v1, v3)
	if !(diff <= modelDiffInputMaxCos) {
		return 0, fmt.Sprintf("it gave the SAME answer to two unrelated texts (similarity %.4f) — "+
			"it is returning a fixed vector, not reading the input", diff)
	}
	return len(v1), ""
}

// probeGenerateModel proves the model GENERATES: a non-empty answer, and a
// different prompt must change it (the same constant-answer trap).
func probeGenerateModel(addr, model string) string {
	a, err := modelGenerateOnce(addr, model, modelProbePromptA)
	if err != nil {
		return "it was downloaded but does not answer as a text model: " + err.Error()
	}
	if strings.TrimSpace(a) == "" {
		return "it answered with nothing at all"
	}
	b, err := modelGenerateOnce(addr, model, modelProbePromptB)
	if err != nil {
		return "it answered once and then failed: " + err.Error()
	}
	if strings.TrimSpace(a) == strings.TrimSpace(b) {
		return "it gave the same answer to two different prompts — it is not reading the prompt"
	}
	return ""
}

// modelRoles is the vocabulary, and it is closed: a role with no probe is a
// model we would have to report as working without having checked, which is
// the whole thing this lane exists to avoid.
var modelRoles = map[string]bool{"embed": true, "generate": true}

// ── the ops ────────────────────────────────────────────────────────────────

type modelReq struct {
	// Op selects the sub-op on the `model:pull` job name: "start" begins a
	// download, "status" reports one. Absent means "start", which is how
	// backup_fetch spells the same choice (backupfetch.go:139-146). There is no
	// legacy caller to keep synchronous: the published host (v0.16.52) has no
	// models family at all, so the very first host that ever sends model:pull
	// is the one shipping alongside this.
	Op    string `json:"op,omitempty"`
	JobID string `json:"job_id,omitempty"` // status
	Model string `json:"model"`
	Role  string `json:"role"`
	// MaxBytes is the CEILING the user approved, in bytes. It is not a hint:
	// the streaming pull reads the daemon's declared `total` and aborts before
	// transferring anything bigger. See modelPullStreaming.
	MaxBytes int64 `json:"max_bytes"`
	// Replaces is the model this one is meant to take over from, or "". It
	// changes nothing by itself — removing the old model is a separate
	// model:drop with its own ledger check — but the user is TOLD about it, so
	// it is bound into the purpose like every other word they read.
	Replaces string `json:"replaces"`
	// Approval is the id stepup_status handed back after the user approved
	// THIS proposal, on this machine, with the factor enrolled there.
	Approval string `json:"approval"`
}

// purposeForModelPull binds every field the user reads. Same construction as
// purposeForGrant (stepup.go:210-224) and purposeForSessionRoot
// (session.go:310-318): a |-delimited field list rebuilt from the details the
// pod sent, so a host that shows the user one sentence and then asks for
// something else cannot produce a matching purpose.
//
// THE BYTE CEILING IS IN HERE DELIBERATELY. A user who approved "download
// qwen3" with no number approved an unbounded write to their own disk. With
// the number bound, the approval means "this model, for this role, at most
// this many bytes", and the download is held to it.
func purposeForModelPull(model, role string, maxBytes int64, replaces string) (string, error) {
	if err := purposeBad([]string{model, role, replaces}, nil); err != nil {
		return "", err
	}
	if model == "" || role == "" {
		return "", fmt.Errorf("a model pull needs a model and a role")
	}
	if maxBytes <= 0 {
		return "", fmt.Errorf("a model pull needs a byte ceiling the user can read")
	}
	return fmt.Sprintf("model_pull|%s|%s|%d|%s", model, role, maxBytes, replaces), nil
}

type modelEntry struct {
	Model      string `json:"model"`
	PlacedHere bool   `json:"placed_by_this_host"`
	PlacedAt   string `json:"placed_at,omitempty"`
	Role       string `json:"role,omitempty"`
	Dim        int    `json:"dim,omitempty"`
}

func modelFail(ws *websocket.Conn, msg string) {
	sendMgmt(ws, 'R', []byte(msg+"\n"))
	sendMgmtExit(ws, 1)
}

func modelReply(ws *websocket.Conn, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		modelFail(ws, "could not encode the answer: "+err.Error())
		return
	}
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// handleModelList answers what this box serves AND which of those this host put
// here — the two together are what makes an honest proposal possible: the host
// can see a model is present without being able to claim it may remove it.
func handleModelList(ws *websocket.Conn, root string, _ []string) {
	addr, why := modelDaemonTarget(modelSelf(ws))
	if why != "" {
		modelFail(ws, "model:list: "+why)
		return
	}
	status, body, err := modelPostJSON(addr, http.MethodGet, "/api/tags", nil, modelListTimeout)
	if err != nil {
		modelFail(ws, "model:list: no model daemon answering on this machine: "+err.Error())
		return
	}
	if status != http.StatusOK {
		modelFail(ws, fmt.Sprintf("model:list: the model daemon answered HTTP %d", status))
		return
	}
	var tags struct {
		Models []struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &tags); err != nil {
		modelFail(ws, "model:list: the model daemon's answer was unparsable")
		return
	}
	placed := loadPlacedModels(root)
	out := []modelEntry{}
	for _, m := range tags.Models {
		n := m.Name
		if n == "" {
			n = m.Model
		}
		if n == "" {
			continue
		}
		e := modelEntry{Model: n}
		if p, ok := placed[n]; ok {
			e.PlacedHere, e.PlacedAt, e.Role, e.Dim = true, p.PlacedAt, p.Role, p.Dim
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Model < out[j].Model })
	modelReply(ws, map[string]any{"models": out})
}

// ── the approval gate ──────────────────────────────────────────────────────

// modelRefuse reports a refusal. Exit 126 is the mgmt lane's "refused" (the
// same code capsAllow's ceiling uses, mgmt.go), NOT a failure: a user who says
// no, or who has not got to their machine yet, has produced a normal outcome.
// Nothing here should ever read as a broken machine or a failed download,
// because neither has happened.
func modelRefuse(ws *websocket.Conn, model, why string) {
	sendMgmt(ws, 'R', []byte("model:pull: "+model+" was not downloaded — "+why+"\n"))
	sendMgmtExit(ws, 126)
}

// modelPullApproved is the wall. It returns "" to proceed, or the reason in
// words the user's host can repeat to them.
//
// TWO DIFFERENCES FROM stepupGate (stepup.go:524-529), both deliberate:
//
//  1. stepupGate returns nil when the box holds NO second factor — for the DCN
//     lanes an unenrolled box is gated by the signed grant alone. This lane
//     refuses instead. A standing grant naming no models is a silent pull by
//     another name, and on an unenrolled box the
//     caps grant is the only thing left, so falling through to it would rebuild
//     precisely the hole this gate exists to close. An unenrolled machine
//     cannot have models pulled onto it, and the refusal says how to enroll.
//  2. The purpose is rebuilt HERE from the request's own fields, never taken
//     from the wire. That is what makes the approval bind to THIS pull: the
//     user approved a purpose naming a model, a role and a byte ceiling, and an
//     op asking for any other model, role or ceiling computes a different
//     purpose and fails stepupCheckApproval's comparison (stepup.go:503-505).
//     An approval for "a pull" is not a thing this shape can express.
func modelPullApproved(root string, req modelReq) string {
	if root == "" {
		return "this machine has no per-pairing state directory, so it cannot hold an approval"
	}
	purpose, err := purposeForModelPull(req.Model, req.Role, req.MaxBytes, req.Replaces)
	if err != nil {
		return err.Error()
	}
	// boxApproval (device.go): a factor here OR the person's device — and
	// never "unenrolled passes". The refusal names both ways to fix it.
	if err := boxApproval(root, req.Approval, purpose); err != nil {
		return "a model download " + err.Error()
	}
	return ""
}

// ── the job table: what a start leaves behind and a status reads ───────────

// modelPullJob is one download. The JSON field names follow backupJob
// (backupfetch.go:74-85) wherever the two mean the same thing — state,
// got_bytes, started_at, finished_at, error — so the host reads one shape for
// both lanes; the model-specific fields are the ones the synchronous reply
// already carried, unchanged, so nothing downstream has to learn a new word.
type modelPullJob struct {
	ID         string  `json:"id"`
	Model      string  `json:"model"`
	Role       string  `json:"role"`
	State      string  `json:"state"` // running | done | failed
	Downloaded bool    `json:"downloaded"`
	Available  bool    `json:"available"`
	PlacedHere bool    `json:"placed_by_this_host"`
	Want       int64   `json:"want_bytes,omitempty"`
	Got        int64   `json:"got_bytes"`
	Bytes      int64   `json:"bytes,omitempty"`
	Dim        int     `json:"dim,omitempty"`
	Why        string  `json:"why,omitempty"`
	Error      string  `json:"error,omitempty"`
	Note       string  `json:"note,omitempty"`
	PollAfter  float64 `json:"poll_after_s,omitempty"`
	Started    string  `json:"started_at"`
	Finished   string  `json:"finished_at,omitempty"`

	// Not on the wire. The approval id is deliberately never serialized: the
	// host chose it, so echoing it back teaches nobody anything and putting a
	// credential id in a progress reply is a habit worth not starting.
	approval   string
	finishedAt time.Time
	polls      int
	// done is closed by runModelPull once the job has left "running" and will
	// write nothing further — not the table, not the ledger, not the approval.
	// It exists so a caller can WAIT for a download it started rather than
	// poll for it; the tests need exactly that, because a job goroutine that
	// outlives the test writes into a directory the test is deleting. Nil on a
	// record that was never started (the retention test builds those by hand).
	done chan struct{}
}

var (
	modelPullJobsMu sync.Mutex
	modelPullJobs   = map[string]*modelPullJob{}
)

// resetModelPullJobs exists for the tests, like resetModelDaemonCache.
func resetModelPullJobs() {
	modelPullJobsMu.Lock()
	modelPullJobs = map[string]*modelPullJob{}
	modelPullJobsMu.Unlock()
}

// modelPullPrune drops finished records past their retention and, if the table
// is still over its cap, the oldest finished ones. A RUNNING job is never
// evicted: forgetting a live download is how a host ends up starting a second
// one. The caller holds modelPullJobsMu.
func modelPullPrune() {
	type aged struct {
		id string
		at time.Time
	}
	var finished []aged
	for id, j := range modelPullJobs {
		if j.State == "running" {
			continue
		}
		if !j.finishedAt.IsZero() && time.Since(j.finishedAt) > modelPullJobRetention {
			delete(modelPullJobs, id)
			continue
		}
		finished = append(finished, aged{id, j.finishedAt})
	}
	if len(modelPullJobs) <= modelPullJobsMax {
		return
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].at.Before(finished[j].at) })
	for _, f := range finished {
		if len(modelPullJobs) <= modelPullJobsMax {
			return
		}
		delete(modelPullJobs, f.id)
	}
}

// modelPullLiveForApproval is the wall against one yes funding two downloads.
// stepupCheckApproval passes for as long as Used is false, and Used is only set
// when a download completes — so without this a host that re-started instead of
// polling would have got a second download on the same approval. The caller
// holds modelPullJobsMu.
func modelPullLiveForApproval(approval string) *modelPullJob {
	if approval == "" {
		return nil
	}
	for _, j := range modelPullJobs {
		if j.approval == approval && j.State == "running" {
			return j
		}
	}
	return nil
}

// modelPullPollAfter is the cadence the box asks for: 2 s, growing x1.5 to 30 s,
// the same one the host already runs against backup_fetch.
func modelPullPollAfter(polls int) float64 {
	d := modelPullPollFirstS
	for i := 0; i < polls; i++ {
		d *= modelPullPollGrowth
		if d >= modelPullPollMaxS {
			return modelPullPollMaxS
		}
	}
	return d
}

// modelPullStatusOp answers a poll. It is the whole reason a status needs no
// approval: it reads the table and returns, touching no network and no disk.
func modelPullStatusOp(ws *websocket.Conn, id string) {
	modelPullJobsMu.Lock()
	modelPullPrune()
	j, ok := modelPullJobs[id]
	var snap modelPullJob
	if ok {
		j.polls++
		if j.State == "running" {
			j.PollAfter = modelPullPollAfter(j.polls)
			j.Note = modelPullRunningNote(j)
		}
		snap = *j
	}
	modelPullJobsMu.Unlock()
	if !ok {
		// "unknown", never "failed" — the same distinction backupfetch.go:168-172
		// draws, and here it carries more: a restart loses the table BEFORE
		// stepupMarkUsed could have run, so the approval is intact and the host
		// may simply start again with it. If the download had already landed,
		// the machine's own ledger has the model and model:list reveals it.
		modelReply(ws, map[string]any{"state": "unknown", "id": id,
			"note": "this machine has no record of that download. If it restarted, " +
				"nothing was spent — the same approval still funds it. Ask model:list " +
				"before proposing anything: if the model is there and this host placed " +
				"it, the download already finished."})
		return
	}
	modelReply(ws, snap)
}

// modelPullRunningNote is what the user is told while the bytes move. Spelled
// with modelBytesWords so the numbers read the way the approval text they said
// yes to read. The caller holds modelPullJobsMu.
func modelPullRunningNote(j *modelPullJob) string {
	if j.Want > 0 {
		return fmt.Sprintf("downloading %s — %s of %s so far", j.Model,
			modelBytesWords(j.Got), modelBytesWords(j.Want))
	}
	return "starting the download of " + j.Model + " — the model daemon has not announced its size yet"
}

// ── the download, held to the ceiling the user approved ────────────────────

// modelPullStreaming runs the pull and returns the bytes the daemon declared.
//
// MEASURED 2026-09-12 against ollama 0.34.0. The stream is one JSON object per
// line; after "pulling manifest" each layer announces its size before its bytes
// move:
//
//	{"status":"pulling manifest"}
//	{"status":"pulling 797b70c4edf8","digest":"sha256:797b...","total":45949216}
//	{"status":"pulling 797b70c4edf8","digest":"sha256:797b...","total":45949216,"completed":1572864}
//	...
//	{"status":"success"}
//
// So the ceiling is checked against `total` per distinct digest, summed — a
// model is several layers and the user approved the whole download, not the
// largest piece of it. The check runs on the announcement, which is why an
// oversized model is refused rather than downloaded and then complained about.
// Bytes may already have moved for earlier layers when a later one pushes the
// sum over; that is bounded by the ceiling itself, and the message says so.
//
// `note` is called as each layer announces its size and as its bytes move, with
// (declared total so far, completed so far). It is what a status poll reports,
// and it is a callback rather than a return value for the same reason
// runBackupFetch updates job.Got inside its read loop (backupfetch.go:309-311):
// progress that only exists when the transfer ends is not progress. nil is
// allowed — the direct-call tests pass it.
func modelPullStreaming(addr, model string, maxBytes int64, note func(want, got int64)) (int64, error) {
	body, err := json.Marshal(map[string]any{"model": model, "stream": true})
	if err != nil {
		return 0, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, "http://"+addr+"/api/pull",
		bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: modelPullTimeout}).Do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	seen := map[string]int64{}
	done := map[string]int64{}
	var sum, got int64
	ok := false
	sc := bufio.NewScanner(io.LimitReader(resp.Body, modelPullMaxStreamBytes))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev struct {
			Status    string `json:"status"`
			Error     string `json:"error"`
			Digest    string `json:"digest"`
			Total     int64  `json:"total"`
			Completed int64  `json:"completed"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if ev.Error != "" {
			return 0, fmt.Errorf("%s", ev.Error)
		}
		if ev.Digest != "" && ev.Completed > done[ev.Digest] {
			got += ev.Completed - done[ev.Digest]
			done[ev.Digest] = ev.Completed
		}
		if ev.Digest != "" && ev.Total > 0 && seen[ev.Digest] == 0 {
			seen[ev.Digest] = ev.Total
			sum += ev.Total
			if sum > maxBytes {
				// Abort by closing the body: the transfer stops here rather
				// than running to completion and being disowned afterwards.
				return 0, fmt.Errorf("it is larger than you approved — the download is %s and "+
					"you approved at most %s, so it was stopped. Nothing beyond the approved "+
					"amount was transferred, and no model was added",
					modelBytesWords(sum), modelBytesWords(maxBytes))
			}
		}
		if ev.Status == "success" {
			ok = true
		}
		if note != nil {
			note(sum, got)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("the download was interrupted: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("the model daemon answered HTTP %d", resp.StatusCode)
	}
	if !ok {
		return 0, fmt.Errorf("the download ended without the daemon confirming it finished")
	}
	return sum, nil
}

// modelBytesWords renders a byte count the way a person reads one. Used in the
// refusal above and in the approval text the user sees on the machine, so the
// number they approve and the number they are refused against are spelled the
// same way.
func modelBytesWords(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/float64(1<<20))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

// handleModelPull serves both sub-ops on the single `model:pull` job name, so
// the user's signed grant covers watching a download as well as starting one.
// See the header: a separate op id would be ungranted in every grant already
// written.
func handleModelPull(ws *websocket.Conn, root string, args []string) {
	if len(args) < 1 {
		modelFail(ws, "model:pull: need a JSON argument {model, role}")
		return
	}
	var req modelReq
	if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
		modelFail(ws, "model:pull: argument is not JSON: "+err.Error())
		return
	}
	// DISPATCH FIRST, before any field a start needs is read: a status carries a
	// job id and nothing else, and must never be able to fall into a start.
	switch strings.TrimSpace(req.Op) {
	case "status":
		modelPullStatusOp(ws, strings.TrimSpace(req.JobID))
		return
	case "start", "":
	default:
		modelFail(ws, "model:pull: unknown op "+req.Op)
		return
	}
	modelPullStart(ws, root, req)
}

// modelPullStart validates, gates on the user's approval, spawns the download
// and returns a job id. It touches no network itself — every network call is in
// runModelPull, which only exists once modelPullApproved has passed.
func modelPullStart(ws *websocket.Conn, root string, req modelReq) {
	req.Model = strings.TrimSpace(req.Model)
	req.Role = strings.TrimSpace(req.Role)
	if req.Model == "" {
		modelFail(ws, "model:pull: no model named")
		return
	}
	if !modelRoles[req.Role] {
		modelFail(ws, "model:pull: role must be 'embed' or 'generate' — a model with no "+
			"role has no probe, and this lane never reports a model working without checking it")
		return
	}

	// WHERE THE PULL GOES, decided once and held for the download and its
	// probe: a Host with no platform pulls only onto a model server on this
	// machine (modelDaemonTarget). Refused before the approval is read, so a
	// pull that cannot go here costs the person nothing. For such a pairing a
	// name in OLLAMA_ADDR is looked up here; nothing is dialled.
	addr, why := modelDaemonTarget(modelSelf(ws))
	if why != "" {
		modelRefuse(ws, req.Model, why)
		return
	}

	// THE APPROVAL GATE. Nothing above this line has touched the network; nothing
	// below it runs until the user has said yes to THIS proposal on this machine.
	// The async split moved the download off this frame and deliberately did NOT
	// move this: the goroutine is spawned after the gate, never before it.
	if why := modelPullApproved(root, req); why != "" {
		modelRefuse(ws, req.Model, why)
		return
	}

	modelPullJobsMu.Lock()
	modelPullPrune()
	// ONE APPROVAL, ONE DOWNLOAD — even under two starts. See the header.
	if live := modelPullLiveForApproval(req.Approval); live != nil {
		live.polls++
		live.PollAfter = modelPullPollAfter(live.polls)
		live.Note = "this download is already running on this machine — " +
			modelPullRunningNote(live) + ". Your approval funds it once; poll it rather " +
			"than starting it again."
		snap := *live
		modelPullJobsMu.Unlock()
		modelReply(ws, snap)
		return
	}
	id := fmt.Sprintf("mp-%d", time.Now().UnixNano())
	job := &modelPullJob{
		ID: id, Model: req.Model, Role: req.Role, State: "running",
		Started:   time.Now().UTC().Format(time.RFC3339),
		PollAfter: modelPullPollFirstS,
		approval:  req.Approval,
		done:      make(chan struct{}),
	}
	job.Note = modelPullRunningNote(job)
	modelPullJobs[id] = job
	// The reply is a COPY taken while the lock is still held, and the goroutine
	// is spawned only after the copy exists. It used to be `modelReply(ws,
	// *job)` after the spawn — an unlocked read of a record the goroutine was
	// already writing under modelPullJobsMu (Want/Got on every progress line),
	// which the race detector reported at exactly that line. Same shape as the
	// dedupe branch above and every snapshot in modelPullStatusOp: read under
	// the lock, encode outside it.
	snap := *job
	modelPullJobsMu.Unlock()

	go runModelPull(job, root, req, addr)
	modelReply(ws, snap)
}

// runModelPull is the old synchronous tail of handleModelPull, moved off the
// frame and otherwise unchanged. Read the ordering here against the header: the
// approval is burned and the ledger written only when modelPullStreaming
// returns clean, and that happens whether or not anyone ever polls — which is
// what keeps approval-burned and bytes-on-disk the same event.
//
// The ledger entry is written on a successful DOWNLOAD, before the probe result
// is known, and that ordering is deliberate: ownership is "this host put these
// bytes on this disk", which is true the moment the download succeeds. A model
// that downloaded but failed its probe must stay droppable, or a bad pull would
// leave dead weight on the user's machine that nothing is allowed to remove.
func runModelPull(job *modelPullJob, root string, req modelReq, addr string) {
	set := func(f func(j *modelPullJob)) {
		modelPullJobsMu.Lock()
		f(job)
		modelPullJobsMu.Unlock()
	}
	// finish is the LAST write this goroutine makes, on every path out: each
	// return below goes through it, and nothing after it touches the table, the
	// ledger or the approval. That is what lets `done` mean what its comment
	// says. Closed after the unlock so a waiter that then reads the table sees
	// the finished record, never the transition.
	finish := func(state string, f func(j *modelPullJob)) {
		modelPullJobsMu.Lock()
		job.State = state
		job.PollAfter = 0
		job.finishedAt = time.Now()
		job.Finished = job.finishedAt.UTC().Format(time.RFC3339)
		f(job)
		modelPullJobsMu.Unlock()
		close(job.done)
	}

	// STREAMING, not stream:false, and the reason is the byte ceiling. MEASURED:
	// /api/show on a model that is not local yet answers HTTP 404, so the size
	// cannot be learned before the download begins — but the streaming pull
	// emits `total` for each layer right after the manifest, before the bytes
	// move. Reading it there is what turns the host's declared number into a
	// promise this box holds it to, instead of a figure the user had to take on
	// trust. stream:false would hand back one summary line after the whole
	// download, which is far too late to refuse it.
	//
	// The 200-with-an-error-in-the-body case that stream:false was chosen for is
	// handled either way: modelBodyError reads EVERY line, so a failure on the
	// last line of a stream is caught exactly as before.
	total, err := modelPullStreaming(addr, req.Model, req.MaxBytes,
		func(want, got int64) { set(func(j *modelPullJob) { j.Want, j.Got = want, got }) })
	if err != nil {
		finish("failed", func(j *modelPullJob) {
			j.Error = req.Model + " was not downloaded: " + err.Error()
			j.Note = "nothing was added to this machine and your approval was not spent — " +
				"the same approval still funds a retry."
		})
		return
	}

	// The download is done and the disk is written, so the approval is spent —
	// whatever the probe says next. Burned here rather than after the probe for
	// the same reason the ledger is written here: what the user authorized was
	// the WRITE, and it has happened. Burning it only on a clean probe would let
	// one approval fund a second download.
	markApprovalUsed(root, req.Approval)

	entry := placedModel{PlacedAt: time.Now().UTC().Format(time.RFC3339), Role: req.Role, Bytes: total}
	// Record BEFORE probing — see the doc comment. A ledger write that fails is
	// fatal to the op: a model on the disk that no host may remove is worse than
	// a failed pull, so say so rather than leaving it.
	if err := recordPlaced(root, req.Model, entry); err != nil {
		finish("failed", func(j *modelPullJob) {
			j.Downloaded, j.Bytes = true, total
			j.Error = req.Model + " downloaded but this machine could not record that this " +
				"host placed it (" + err.Error() + ") — refusing to leave a model nothing may remove"
		})
		return
	}
	// Between the download and the probe a poll must read honestly: the bytes
	// ARE here and this host DID place them, and the probe has not answered yet.
	set(func(j *modelPullJob) {
		j.Downloaded, j.PlacedHere, j.Bytes, j.Got = true, true, total, total
		j.Note = "downloaded — checking that " + req.Model + " actually answers as a " +
			req.Role + " model before reporting it usable"
	})

	var dim int
	var why string
	if req.Role == "embed" {
		dim, why = probeEmbedModel(addr, req.Model)
	} else {
		why = probeGenerateModel(addr, req.Model)
	}
	if why != "" {
		finish("done", func(j *modelPullJob) {
			j.Available, j.Why = false, why
			j.Note = req.Model + " is on this machine and this host may remove it, " +
				"but it is not usable: " + why
		})
		return
	}
	entry.Dim = dim
	_ = recordPlaced(root, req.Model, entry)
	finish("done", func(j *modelPullJob) {
		j.Available, j.Dim = true, dim
		j.Note = req.Model + " is downloaded and answers as a " + req.Role + " model"
	})
}

// handleModelDrop removes a model — and ONLY one this host placed. The ledger
// is consulted before anything is deleted, and its absence denies.
func handleModelDrop(ws *websocket.Conn, root string, args []string) {
	if len(args) < 1 {
		modelFail(ws, "model:drop: need a JSON argument {model}")
		return
	}
	var req modelReq
	if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
		modelFail(ws, "model:drop: argument is not JSON: "+err.Error())
		return
	}
	req.Model = strings.TrimSpace(req.Model)
	if req.Model == "" {
		modelFail(ws, "model:drop: no model named")
		return
	}
	if !placedByThisHost(root, req.Model) {
		modelFail(ws, "refused: this host did not put "+req.Model+" on this machine, so it may "+
			"not remove it. Only a model this host pulled here is its to drop.")
		return
	}
	addr, why := modelDaemonTarget(modelSelf(ws))
	if why != "" {
		modelFail(ws, "model:drop: "+why)
		return
	}
	status, body, err := modelPostJSON(addr, http.MethodDelete, "/api/delete",
		map[string]any{"model": req.Model}, modelListTimeout)
	if err != nil {
		modelFail(ws, "model:drop: the model daemon did not answer: "+err.Error())
		return
	}
	if status == http.StatusNotFound {
		// Already gone from the daemon (measured: HTTP 404 {"error":"model ...
		// not found"}). The ledger is the thing that is now wrong, so fix it and
		// report the truth rather than an error the user cannot act on.
		_ = forgetPlaced(root, req.Model)
		modelReply(ws, map[string]any{"model": req.Model, "removed": false,
			"why": "it was already gone from this machine"})
		return
	}
	if e := modelBodyError(body); e != "" {
		modelFail(ws, "model:drop: "+req.Model+" was not removed: "+e)
		return
	}
	if status != http.StatusOK {
		modelFail(ws, fmt.Sprintf("model:drop: %s was not removed (HTTP %d)", req.Model, status))
		return
	}
	if err := forgetPlaced(root, req.Model); err != nil {
		modelFail(ws, "model:drop: "+req.Model+" was removed but the ledger could not be updated: "+err.Error())
		return
	}
	modelReply(ws, map[string]any{"model": req.Model, "removed": true})
}
