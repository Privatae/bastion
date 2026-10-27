//go:build linux

// Model management for a Host with no platform (modelswap.go through
// modelDaemonTarget): the model-swap probe, model:list, model:pull and
// model:drop reach only a model server on this machine, as the serve lane
// does, and the machine's console says why one is not used. Uses the
// fixtures of servelane_linux_test.go and modelswap_test.go.

package main

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// captureStdout collects what this process prints until the test ends, and
// returns a func that reads it so far.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	var mu sync.Mutex
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			if n > 0 {
				mu.Lock()
				buf.Write(b[:n])
				mu.Unlock()
				_, _ = old.Write(b[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		os.Stdout = old
		_ = w.Close()
		<-done
		_ = r.Close()
	})
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// SECURITY: a tcp pairing (a Host with no platform) is not given management of
// a model server on another computer. With OLLAMA_ADDR on TEST-NET, model:list,
// an approved model:pull and model:drop of a model this Host placed are each
// refused with the reason, before anything is dialled or downloaded, and the
// machine's console says in plain words that OLLAMA_ADDR is not used and what
// to set. With OLLAMA_ADDR on this machine the same pairing lists its models.
//
// MUTATION: modelDaemonTarget returns localOllamaAddr() for every pairing.
// RESULT: red — model:list fails dialling 192.0.2.10, the approved pull
// starts a download job (exit 0), and no line is printed at the machine.
func TestModelManagementOnALocalPairingReachesOnlyThisMachine(t *testing.T) {
	console := captureStdout(t)
	t.Setenv("OLLAMA_ADDR", "192.0.2.10:11434") // TEST-NET-1: never this machine
	t.Setenv("PRIVATAE_LLM_ADDR", "")
	t.Setenv("PRIVATAE_PII_ADDR", "")
	resetModelDaemonCache()
	h, cfg := serveLaneBox(t, "models.example.test")
	runInBackground(t, cfg)
	beat := h.beat(t)
	for _, c := range capsOf(beat) {
		if c == modelSwapCapability {
			t.Fatalf("a Host with no platform is offered management of a server on another computer: %q", capsOf(beat))
		}
	}

	root := t.TempDir()
	start := time.Now()
	_, errOut, code, _ := driveModelOp(t, cfg.HostName, "model:list", nil, root)
	if code == 0 || !strings.Contains(errOut, "OLLAMA_ADDR") || !strings.Contains(errOut, "192.0.2.10 is not this machine") {
		t.Fatalf("model:list: exit %d, %q; want a refusal naming OLLAMA_ADDR and why", code, errOut)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("model:list took %v: it waited on a dial instead of refusing first", d)
	}

	enrollFactor(t, root)
	approval := proposeAndApprove(t, root, "nomic-embed-text", "embed", 1<<30, "")
	_, errOut, code, _ = driveModelOp(t, cfg.HostName, "model:pull",
		[]string{pullArg("nomic-embed-text", "embed", 1<<30, "", approval)}, root)
	if code != 126 || !strings.Contains(errOut, "was not downloaded") || !strings.Contains(errOut, "192.0.2.10 is not this machine") {
		t.Fatalf("model:pull: exit %d, %q; want 126 and a refusal saying why", code, errOut)
	}
	modelPullJobsMu.Lock()
	for id, j := range modelPullJobs {
		if j.Model == "nomic-embed-text" {
			t.Errorf("a pull job %s was started for a server on another computer", id)
		}
	}
	modelPullJobsMu.Unlock()

	if err := recordPlaced(root, "placed-here", placedModel{PlacedAt: "now", Role: "embed"}); err != nil {
		t.Fatal(err)
	}
	_, errOut, code, _ = driveModelOp(t, cfg.HostName, "model:drop", []string{`{"model":"placed-here"}`}, root)
	if code == 0 || !strings.Contains(errOut, "192.0.2.10 is not this machine") {
		t.Fatalf("model:drop: exit %d, %q; want a refusal saying why", code, errOut)
	}
	if !placedByThisHost(root, "placed-here") {
		t.Error("a refused drop changed the ledger")
	}

	said := console()
	if !strings.Contains(said, "["+cfg.HostName+"] OLLAMA_ADDR=192.0.2.10:11434 is not used for the Host on this computer") ||
		!strings.Contains(said, "Set OLLAMA_ADDR to a server on this computer, or unset it.") {
		t.Errorf("the machine's console does not say why OLLAMA_ADDR is not used:\n%s", said)
	}
	// Counted for this pairing only: a pairing from an earlier test whose beat
	// is still ending can say it for itself.
	if n := strings.Count(said, "["+cfg.HostName+"] OLLAMA_ADDR=192.0.2.10:11434 is not used"); n != 1 {
		t.Errorf("the console said it %d times; once, until it changes", n)
	}

	// The control: a model server on this machine is listed for the same pairing.
	newFakeDaemon(t, &fakeDaemon{tags: []string{"here-model"}})
	out, errOut, code, _ := driveModelOp(t, cfg.HostName, "model:list", nil, root)
	if code != 0 || !strings.Contains(out, "here-model") {
		t.Fatalf("model:list of a server on this machine: exit %d, %q %q", code, out, errOut)
	}
}

// The beat and a model op can refuse the same target at the same moment. The
// machine's console still says it once: the reason is recorded and said by one
// caller, not checked by each and then said by all.
//
// MUTATION: in serveTargetNotice, Load the last reason, then Store and print
// (as it did).
// RESULT: red — more than one line for 32 callers released together (the
// count varies from run to run).
func TestTheConsoleSaysARefusedTargetOnceUnderConcurrentCallers(t *testing.T) {
	console := captureStdout(t)
	s, _ := serveServiceNamed("ollama")
	self := "notice-once.example.test"
	t.Cleanup(func() { serveTargetNoticeClear(self, s) })
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			serveTargetNotice(self, s, "192.0.2.10:11434", "192.0.2.10 is not this machine")
		}()
	}
	close(start)
	wg.Wait()
	serveTargetNotice(self, s, "192.0.2.10:11434", "another reason")
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(console(), "another reason") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	said := console()
	if n := strings.Count(said, "["+self+"] OLLAMA_ADDR=192.0.2.10:11434 is not used"); n != 2 {
		t.Fatalf("the console said it %d times; once for the first reason and once when it changed:\n%s", n, said)
	}
}

// A tunnel pairing keeps OLLAMA_ADDR wherever it points, as its forwards do:
// the rule is for a Host with no platform.
func TestModelDaemonTargetKeepsATunnelPairingsAddress(t *testing.T) {
	t.Setenv("OLLAMA_ADDR", "192.0.2.10:11434")
	if addr, why := modelDaemonTarget("tunnel.example.test"); addr != "192.0.2.10:11434" || why != "" {
		t.Fatalf("a tunnel pairing: %q %q", addr, why)
	}
	unmark := markLocalPairing("tunnel.example.test")
	if addr, why := modelDaemonTarget("tunnel.example.test"); addr != "" || !strings.Contains(why, "192.0.2.10 is not this machine") {
		t.Fatalf("the same name run as a local pairing: %q %q", addr, why)
	}
	unmark()
	unmark() // once only
	if isLocalPairing("tunnel.example.test") {
		t.Fatal("still marked local after its run ended")
	}
}

// SECURITY (this machine's resources): a Host that answers every parked serve
// worker with a job it knows is refused (a malformed frame, a name the lane
// does not carry) cannot make this machine dial, handshake and audit in a
// loop. Each refused worker waits before it parks again, so two workers cost
// at most a few dials a second.
//
// MUTATION: spawn the replacement when the first frame arrives (taken() before
// the hello is read), as the lane first did.
// RESULT: red — hundreds of workers park in the 2 s window.
func TestARefusingHostCannotSpinTheServeWorkers(t *testing.T) {
	t.Setenv("OLLAMA_ADDR", "")
	h, cfg := serveLaneBox(t, "spin.example.test")
	runInBackground(t, cfg)
	var answered atomic.Int32
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var ws *websocket.Conn
		select {
		case ws = <-h.workers:
		case <-time.After(time.Until(deadline)):
		}
		if ws == nil {
			break
		}
		frame := sFrame("nas")
		if answered.Load()%2 == 1 {
			frame = []byte("Dnot a hello")
		}
		_ = ws.WriteMessage(websocket.BinaryMessage, frame)
		_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = ws.ReadMessage()
		ws.Close()
		answered.Add(1)
	}
	// 2 parked at the start, then each worker once a second: about 6 in 2 s.
	if n := answered.Load(); n > 10 {
		t.Fatalf("%d serve workers parked in 2 s on a Host that refuses every job: the pool re-dials in a loop", n)
	}
	if answered.Load() < 2 {
		t.Fatalf("only %d workers parked: the pool did not run, so the count proves nothing", answered.Load())
	}
}
