//go:build !windows

// A long model pull is an ASYNC JOB, not a long wait a parked download.
//
// Tagged to match anchor_test.go and modelswap_test.go, which is where
// setupBox, driveOp, driveModelOp, enrollFactor, proposeAndApprove and the fake
// daemon live. And note WHICH command catches a missing tag:
// `GOOS=windows go build ./...` PASSES, because build does not compile test
// files. Run `GOOS=windows go vet ./...`.
//
// EVERYTHING IN THIS FILE GOES THROUGH A REAL MANAGEMENT FRAME. driveModelOp
// opens a WebSocket, writes the `C` frame the pod writes and reads O/R/X back,
// so these exercise handleMgmtConnFor, the caps ceiling, the handler table and
// the approval gate. The checks that need the job table itself live in
// modelswap_async_internal_test.go — as does the one piece of table access
// these tests DO need, awaitModelPullsSince, and why: a job goroutine outlives
// the frame that started it by design, so a test must wait for its own job
// before its TempDir is deleted (see the block above modelPullJobIDs there).

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── helpers ────────────────────────────────────────────────────────────────

func startArg(model, role string, maxBytes int64, replaces, approval string) string {
	b, _ := json.Marshal(map[string]any{
		"op": "start", "model": model, "role": role,
		"max_bytes": maxBytes, "replaces": replaces, "approval": approval})
	return string(b)
}

func statusArg(jobID string) string {
	b, _ := json.Marshal(map[string]any{"op": "status", "job_id": jobID})
	return string(b)
}

// mustJSON decodes an O-frame body, failing with the raw bytes rather than a
// nil map — a silent empty decode is how an async test passes vacuously.
func mustJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("reply is not JSON (%v): %q", err, out)
	}
	return m
}

// startPull drives one `start` and returns the reply.
func startPull(t *testing.T, self, root, model, role string, maxBytes int64, approval string) map[string]any {
	t.Helper()
	out, errOut, code, _ := driveModelOp(t, self, "model:pull",
		[]string{startArg(model, role, maxBytes, "", approval)}, root)
	if code != 0 {
		t.Fatalf("start %s: want exit 0, got %d: %s", model, code, errOut)
	}
	return mustJSON(t, out)
}

// pollUntilFinished polls `status` through real frames until the job leaves
// "running". The interval is tiny on purpose: the CADENCE the box asks for is
// asserted separately, and paying it here would add seconds per gate.
func pollUntilFinished(t *testing.T, self, root, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last map[string]any
	for time.Now().Before(deadline) {
		out, errOut, code, _ := driveModelOp(t, self, "model:pull", []string{statusArg(id)}, root)
		if code != 0 {
			t.Fatalf("status: want exit 0, got %d: %s", code, errOut)
		}
		last = mustJSON(t, out)
		if last["state"] != "running" {
			return last
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the job never left 'running': %v", last)
	return nil
}

// pullToCompletion is start-then-poll in one call, for the gates that care
// about the OUTCOME of a pull rather than about the async shape itself. It is
// what the synchronous `driveModelOp(... model:pull ...)` used to be, and it is
// why those gates changed shape and not meaning when this lane went async.
func pullToCompletion(t *testing.T, self, root, model, role string, maxBytes int64, approval string) map[string]any {
	t.Helper()
	started := startPull(t, self, root, model, role, maxBytes, approval)
	id, _ := started["id"].(string)
	if id == "" {
		t.Fatalf("a start must hand back a job id: %v", started)
	}
	return pollUntilFinished(t, self, root, id)
}

// newPullRoot is the per-pairing root every pull in this file runs against:
// a TempDir with a factor enrolled, and a cleanup that RELEASES the daemon and
// then WAITS for every job this test started before the directory goes away.
//
// The order is the point. t.Cleanup runs last-registered first, so this must be
// registered AFTER the TempDir it protects — which is why the helper creates
// the directory itself rather than taking one. `release` may be nil for a
// daemon that does not hold its stream open.
func newPullRoot(t *testing.T, release func()) string {
	t.Helper()
	root := t.TempDir()
	enrollFactor(t, root)
	before := modelPullJobIDs()
	t.Cleanup(func() {
		if release != nil {
			release()
		}
		awaitModelPullsSince(t, before)
	})
	return root
}

// newSlowPullDaemon points OLLAMA_ADDR at a daemon whose /api/pull announces a
// size, emits progress, and then holds the stream open until the returned
// `release` is called. That is what a real multi-gigabyte download looks like
// from here. release is idempotent: a test calls it where the download is
// meant to finish, and newPullRoot's cleanup calls it again on every path out.
func newSlowPullDaemon(t *testing.T, f *fakeDaemon) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	mux := http.NewServeMux()
	mux.HandleFunc("/api/pull", func(w http.ResponseWriter, r *http.Request) {
		f.pulls++
		fl, _ := w.(http.Flusher)
		fmt.Fprint(w, "{\"status\":\"pulling manifest\"}\n")
		fmt.Fprint(w, "{\"status\":\"pulling sha256:aaa\",\"digest\":\"sha256:aaa\",\"total\":1000}\n")
		fmt.Fprint(w, "{\"status\":\"pulling sha256:aaa\",\"digest\":\"sha256:aaa\",\"total\":1000,\"completed\":400}\n")
		if fl != nil {
			fl.Flush()
		}
		<-gate
		fmt.Fprint(w, "{\"status\":\"pulling sha256:aaa\",\"digest\":\"sha256:aaa\",\"total\":1000,\"completed\":1000}\n")
		fmt.Fprint(w, "{\"status\":\"success\"}\n")
	})
	mux.HandleFunc("/api/embed", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		vec := []float64{1, 0, 0, 0}
		if len(req.Input) > 0 && req.Input[0] == modelProbeTextB {
			vec = []float64{0, 1, 0, 0}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"embeddings": [][]float64{vec}})
	})
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("OLLAMA_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	resetModelDaemonCache()
	return release
}

// ── 1. a start returns without waiting for the download ────────────────────

// THE POINT OF THE WHOLE CHANGE. The daemon below does not finish its stream
// until it is released, so with the synchronous handler this call cannot return
// until modelPullTimeout (20 minutes) expires. It must come back at once with a
// job id — and while it is blocked it is holding one of only TWO management
// workers (mgmtWorkerCount, mgmt.go:18).
func TestAStartReturnsWithoutWaitingForTheDownload(t *testing.T) {
	f := &fakeDaemon{}
	release := newSlowPullDaemon(t, f)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := newPullRoot(t, release)
	approval := proposeAndApprove(t, root, "slowmodel", "embed", 1<<30, "")

	type reply struct {
		out, errOut string
		code        int
	}
	done := make(chan reply, 1)
	go func() {
		out, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
			[]string{startArg("slowmodel", "embed", 1<<30, "", approval)}, root)
		done <- reply{out, errOut, code}
	}()

	// The daemon is released, and the job waited for, by newPullRoot's cleanup
	// on every path out of here — including the fatal ones.
	select {
	case r := <-done:
		if r.code != 0 {
			t.Fatalf("the start refused a pull the user approved: exit %d: %s", r.code, r.errOut)
		}
		got := mustJSON(t, r.out)
		if got["state"] != "running" {
			t.Fatalf("a start must report the download as running, got %v", got)
		}
		if id, _ := got["id"].(string); id == "" {
			t.Fatalf("a start must hand back a job id to poll, got %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the start BLOCKED on the download — this is the synchronous shape, " +
			"which parks one of two management workers for up to 26 minutes and blocks " +
			"POST /api/network/mgmt/run behind whatever ingress timeout sits in front of it")
	}
}

// ── 2. a status poll reports progress, then completion ─────────────────────

func TestAStatusPollReportsProgressThenCompletion(t *testing.T) {
	f := &fakeDaemon{}
	release := newSlowPullDaemon(t, f)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := newPullRoot(t, release)
	approval := proposeAndApprove(t, root, "slowmodel", "embed", 1<<30, "")

	started := startPull(t, tAnchor, root, "slowmodel", "embed", 1<<30, approval)
	id, _ := started["id"].(string)
	if id == "" {
		t.Fatalf("no job id to poll: %v", started)
	}

	// PROGRESS, while the bytes are still moving. This is the thing the host had
	// nothing to say about before.
	var running map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, _, code, _ := driveModelOp(t, tAnchor, "model:pull", []string{statusArg(id)}, root)
		if code != 0 {
			t.Fatalf("status exit %d", code)
		}
		running = mustJSON(t, out)
		if n, _ := running["got_bytes"].(float64); n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if running["state"] != "running" {
		t.Fatalf("the download is still going; the status must say so: %v", running)
	}
	if n, _ := running["got_bytes"].(float64); n != 400 {
		t.Fatalf("the status must report the bytes that have moved, got %v", running)
	}
	if n, _ := running["want_bytes"].(float64); n != 1000 {
		t.Fatalf("the status must report the declared size, got %v", running)
	}
	if note, _ := running["note"].(string); note == "" {
		t.Fatalf("the host has to have something to TELL the user during a 26-minute "+
			"download; the status carried no words: %v", running)
	}
	if p, _ := running["poll_after_s"].(float64); p <= 0 {
		t.Fatalf("the box must say when to ask again, got %v", running)
	}

	release()
	done := pollUntilFinished(t, tAnchor, root, id)
	if done["state"] != "done" {
		t.Fatalf("want state done, got %v", done)
	}
	if done["downloaded"] != true || done["available"] != true {
		t.Fatalf("a finished good pull is downloaded AND available: %v", done)
	}
	if done["placed_by_this_host"] != true {
		t.Fatalf("the completion must carry the ownership fact: %v", done)
	}
	if d, _ := done["dim"].(float64); d != 4 {
		t.Fatalf("the measured width must come back: %v", done)
	}
	if fin, _ := done["finished_at"].(string); fin == "" {
		t.Fatalf("a finished job says when: %v", done)
	}
	if f.pulls != 1 {
		t.Fatalf("exactly one download, got %d", f.pulls)
	}
}

// ── 3. an unapproved start downloads nothing ───────────────────────────────

// The property the whole lane rests on, re-asserted against the ASYNC shape:
// moving the download into a goroutine must not move it past the gate. The
// assertion is on the daemon's pull counter, not the exit code — an op can
// return an error having already downloaded a model, and that is the
// distinction that matters.
func TestAnUnapprovedStartDownloadsNothing(t *testing.T) {
	f := newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)

	_, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{startArg("qwen3", "generate", 1<<20, "", "")}, root)
	if code != 126 {
		t.Fatalf("an unapproved start must be refused (126), got %d %s", code, errOut)
	}
	// Give a goroutine that should not exist every chance to run.
	time.Sleep(200 * time.Millisecond)
	if f.pulls != 0 {
		t.Fatalf("THE DOWNLOAD HAPPENED (%d pulls) without the user's approval", f.pulls)
	}
	if placedByThisHost(root, "qwen3") {
		t.Fatal("an unapproved pull reached the ownership ledger")
	}
}

// A STATUS IS NOT A START. It carries no model and no approval, and must never
// be able to become one.
func TestAStatusPollNeedsNoApprovalAndStartsNothing(t *testing.T) {
	f := newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)

	out, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{statusArg("mp-nothing-here")}, root)
	if code != 0 {
		t.Fatalf("a status for an unknown job is a normal answer, not a failure: %d %s", code, errOut)
	}
	got := mustJSON(t, out)
	if got["state"] != "unknown" {
		t.Fatalf("an unknown job is 'unknown', never 'failed' — the approval is intact: %v", got)
	}
	if note, _ := got["note"].(string); note == "" {
		t.Fatalf("the answer must say what the host should do next: %v", got)
	}
	time.Sleep(100 * time.Millisecond)
	if f.pulls != 0 {
		t.Fatalf("a status poll downloaded something (%d pulls)", f.pulls)
	}
}

// ── 4. a never-polled completion does not cost the user their approval ─────

// THE RISK THE ASYNC SPLIT CREATES, stated as a test. A start succeeds, the
// host never polls, and the download finishes in the goroutine. What must hold:
// the approval is burned exactly once and exactly when the bytes land; the
// ledger has the model; and the same approval cannot fund a second download.
func TestANeverPolledCompletionDoesNotCostTheApproval(t *testing.T) {
	f := newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// newPullRoot, not a bare TempDir: this test deliberately never polls, so
	// nothing below observes the job finishing — the ledger write it waits for
	// lands BEFORE the probe, and the probe's own ledger write comes after.
	root := newPullRoot(t, nil)
	approval := proposeAndApprove(t, root, "quiet", "embed", 1<<20, "")

	started := startPull(t, tAnchor, root, "quiet", "embed", 1<<20, approval)
	if started["state"] != "running" {
		t.Fatalf("the start must hand back a RUNNING job — otherwise there is no "+
			"never-polled case to reason about: %v", started)
	}
	if id, _ := started["id"].(string); id == "" {
		t.Fatalf("the start must hand back a job id: %v", started)
	}

	// Never a single status poll: watch the machine's own ledger, which is the
	// only evidence a host that lost the reply would have.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !placedByThisHost(root, "quiet") {
		time.Sleep(5 * time.Millisecond)
	}
	if !placedByThisHost(root, "quiet") {
		t.Fatal("the download never reached the ownership ledger — nothing could drop it")
	}
	if f.pulls != 1 {
		t.Fatalf("exactly one download, got %d", f.pulls)
	}
	// Approval burned — by the goroutine, not by a poll. This is what keeps
	// approval-spent and bytes-on-disk the same event.
	if a, ok := approvalsLoad(root)[approval]; !ok || !a.Used {
		t.Fatalf("a landed download must spend the approval whether or not anyone "+
			"polled it: %+v", a)
	}

	// Not double-spent either: the same approval cannot fund a second download.
	_, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull",
		[]string{startArg("quiet", "embed", 1<<20, "", approval)}, root)
	if code != 126 {
		t.Fatalf("a spent approval must not fund a second download: %d %s", code, errOut)
	}
	time.Sleep(100 * time.Millisecond)
	if f.pulls != 1 {
		t.Fatalf("a second download happened on one approval: %d pulls", f.pulls)
	}
}

// A FAILED download that is never polled leaves the approval INTACT, so the
// same yes still funds a retry and the user is asked for nothing.
func TestANeverPolledFailureLeavesTheApprovalIntact(t *testing.T) {
	// The measured shape of a failed streaming pull: HTTP 200, failure in the body.
	f := newFakeDaemon(t, &fakeDaemon{pullBody: "{\"status\":\"pulling manifest\"}\n" +
		"{\"error\":\"pull model manifest: file does not exist\"}\n"})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "ghost", "embed", 1<<20, "")

	started := startPull(t, tAnchor, root, "ghost", "embed", 1<<20, approval)
	id, _ := started["id"].(string)
	if id == "" {
		t.Fatalf("no job id to poll: %v", started)
	}
	got := pollUntilFinished(t, tAnchor, root, id)
	if got["state"] != "failed" {
		t.Fatalf("a pull that did not download must read as failed: %v", got)
	}
	if a, ok := approvalsLoad(root)[approval]; !ok || a.Used {
		t.Fatalf("a FAILED download must not spend the approval: %+v", a)
	}
	if placedByThisHost(root, "ghost") {
		t.Fatal("a failed download must not enter the ownership ledger")
	}
	// The same approval still works — the user is asked for nothing.
	f.pullBody = "{\"status\":\"pulling manifest\"}\n" +
		"{\"status\":\"pulling sha256:aaa\",\"digest\":\"sha256:aaa\",\"total\":1000}\n" +
		"{\"status\":\"success\"}\n"
	retry := startPull(t, tAnchor, root, "ghost", "embed", 1<<20, approval)
	rid, _ := retry["id"].(string)
	if rid == "" {
		t.Fatalf("no job id on the retry: %v", retry)
	}
	again := pollUntilFinished(t, tAnchor, root, rid)
	if again["state"] != "done" || again["available"] != true {
		t.Fatalf("the retry on the same approval must go through: %v", again)
	}
}

// ── 5. one approval funds one download, even under two starts ──────────────

// The hole the async split opens and the dedupe closes. stepupCheckApproval
// passes while Used is false (stepup.go:529-531), and Used is only set when a
// download completes — so a host that re-STARTS instead of polling would
// otherwise get a second download on one yes.
func TestTwoStartsOnOneApprovalDownloadOnce(t *testing.T) {
	f := &fakeDaemon{}
	release := newSlowPullDaemon(t, f)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := newPullRoot(t, release)
	approval := proposeAndApprove(t, root, "slowmodel", "embed", 1<<30, "")

	first := startPull(t, tAnchor, root, "slowmodel", "embed", 1<<30, approval)
	second := startPull(t, tAnchor, root, "slowmodel", "embed", 1<<30, approval)

	if first["id"] == nil || first["id"] != second["id"] {
		t.Fatalf("a second start on a live approval must answer with the SAME job, "+
			"not begin another download: %v vs %v", first["id"], second["id"])
	}
	release()
	pollUntilFinished(t, tAnchor, root, first["id"].(string))
	if f.pulls != 1 {
		t.Fatalf("one approval funded %d downloads", f.pulls)
	}
}

// ── 6. an unknown sub-op is refused, never silently treated as a start ─────

func TestAnUnknownSubOpIsRefusedNotTreatedAsAStart(t *testing.T) {
	f := newFakeDaemon(t, &fakeDaemon{})
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "qwen3", "generate", 1<<20, "")
	arg, _ := json.Marshal(map[string]any{
		"op": "cancel", "model": "qwen3", "role": "generate",
		"max_bytes": 1 << 20, "approval": approval})
	_, errOut, code, _ := driveModelOp(t, tAnchor, "model:pull", []string{string(arg)}, root)
	if code == 0 {
		t.Fatal("an unknown sub-op must not succeed")
	}
	time.Sleep(100 * time.Millisecond)
	if f.pulls != 0 {
		t.Fatalf("an unknown sub-op downloaded something (%d pulls): %s", f.pulls, errOut)
	}
}
