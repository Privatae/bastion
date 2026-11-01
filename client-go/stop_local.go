package main

// stop_local.go — the machine's owner stops an agent, with no Host involved.
//
// Until this file only a Host could stop an agent (contain.go), so a bastion
// on its own could see an agent and not stop it. It was decided on 2026-10-30
// that the person at the machine may, confirmed with their own second factor
// (stepup_machine.go).
//
// HOW IT RUNS. Asking and doing are two processes:
//
//	`stop <pid>`  reads the agent from a fresh scan, files a request in the
//	              owner's factor directory naming the pid AND the agent's
//	              signature, and, at a terminal, takes the owner's code for it.
//	              Run by an agent (no terminal), it only files the request; the
//	              owner approves it with `approve --machine`.
//	the daemon    finds the approval (localStopLoop), burns it, scans again,
//	              and stops the agent only if that pid still wears the
//	              signature that was approved, through stopAgentTree: the same
//	              tree kill and the same spared set as a Host's order.
//
// The daemon does the stop, not the command, because the daemon holds the
// machine's record of what was stopped (events.go keeps it in memory, and a
// second process writing the same file would be overwritten) and thaws a
// half-done kill on its next start (killtree.go).
//
// An approval that is more than localStopWindow old when the daemon reads it
// is burned without acting: a stop runs when the person asked for it, never
// later, when the daemon happens to start and the pid may be someone else's.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	localStopKind   = "local_stop"
	localStopWindow = 2 * time.Minute
	localStopTick   = 2 * time.Second
	localStopWait   = 15 * time.Second
	localStopKeep   = 50
	stopUsage       = "usage: privatae-bastion stop <session name or pid> [--wait 5m] [--json]   " +
		"(as `privatae-bastion agents` lists them)"
)

// purposeForLocalStop binds an approval to one pid and the signature it wore
// when the owner was asked.
func purposeForLocalStop(pid int, signature string) (string, error) {
	if pid <= 1 {
		return "", fmt.Errorf("no pid to stop")
	}
	if strings.TrimSpace(signature) == "" {
		return "", fmt.Errorf("no agent signature to bind the stop to")
	}
	if err := purposeBad([]string{signature}, nil); err != nil {
		return "", err
	}
	return localStopKind + "|" + strconv.Itoa(pid) + "|" + signature, nil
}

func parseLocalStopPurpose(p string) (int, string, bool) {
	parts := strings.SplitN(p, "|", 3)
	if len(parts) != 3 || parts[0] != localStopKind {
		return 0, "", false
	}
	pid, err := strconv.Atoi(parts[1])
	if err != nil || pid <= 1 || parts[2] == "" {
		return 0, "", false
	}
	return pid, parts[2], true
}

// stopRefusal is why a scan does not let pid be stopped, or "". The same lines
// a Host's order holds (contain.go): never init or this bastion, never a
// process the scan did not see as an agent, never an app the person is using.
func stopRefusal(pid int, observed map[int]agentObs) string {
	if pid <= 1 || pid == os.Getpid() {
		return "that process is not an agent this machine may stop"
	}
	a, ok := observed[pid]
	if !ok {
		return "pid " + strconv.Itoa(pid) + " is not an agent this bastion sees running"
	}
	if a.Kind == kindApp {
		return a.Signature + " is an app you are running, not an agent"
	}
	return ""
}

// carryOutLocalStop is the daemon's half: scan, check the approved signature
// still holds the pid, stop through the shared path, record it.
func carryOutLocalStop(pid int, signature string) string {
	observed := observedAgentMap()
	if why := stopRefusal(pid, observed); why != "" {
		return "not stopped: " + why
	}
	if got := observed[pid].Signature; got != signature {
		return fmt.Sprintf("not stopped: pid %d is now %s, not the %s that was approved", pid, got, signature)
	}
	view, _ := processFindings()
	_, _, guard := containGuard(observed, view.protected)
	killed := stopAgentTree(pid, guard)
	if killed == 0 {
		return "not stopped: it had already exited, or it is one this bastion never stops"
	}
	sentence := stopSentence("You", signature, pid, killed-1)
	fmt.Printf("stop: terminated agent pid %d and %d child process(es) (the machine's owner)\n", pid, killed-1)
	recordLocalEvent(eventContain, sentence)
	return sentence
}

// existingMachineFactorDir is the owner's factor directory if it exists. The
// loop never creates it: no directory means no factor, so nothing to carry out.
func existingMachineFactorDir() string {
	d, err := configDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(d, "machine-factor")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return ""
	}
	return dir
}

func localStopLoop(ctx context.Context) {
	t := time.NewTicker(localStopTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			localStopOnce(existingMachineFactorDir(), time.Now())
		}
	}
}

// localStopOnce carries out every unused local-stop approval in dir, once.
// Each is burned BEFORE it acts (stepupConsumeApproval), so a second pass, or
// a second process, cannot act on it again.
func localStopOnce(dir string, now time.Time) {
	if dir == "" {
		return
	}
	stepupMu.Lock()
	m := approvalsLoad(dir)
	stepupMu.Unlock()
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := m[id]
		if a.Used {
			continue
		}
		pid, sig, ok := parseLocalStopPurpose(a.Purpose)
		if !ok {
			continue
		}
		if err := stepupConsumeApproval(dir, id, a.Purpose); err != nil {
			continue
		}
		at, err := time.Parse(time.RFC3339, a.At)
		var outcome string
		if err != nil || now.Sub(at) > localStopWindow {
			outcome = fmt.Sprintf("not stopped: the approval was more than %s old when this bastion read it; ask again",
				localStopWindow)
		} else {
			outcome = carryOutLocalStop(pid, sig)
		}
		dcnAuditWith(dir, localStopKind, 0, strconv.Itoa(pid)+" "+sig, outcome,
			askPartiesOf(requestForApproval(dir, id).Details))
		localStopRecordResult(dir, id, outcome, now)
	}
}

// requestForApproval is the request an approval answered, if one did (the
// owner at a terminal approves with no request in between).
func requestForApproval(dir, approval string) stepupRequest {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	for _, q := range requestsLoad(dir) {
		if q.Approval == approval {
			return q
		}
	}
	return stepupRequest{}
}

type localStopResult struct {
	Outcome string `json:"outcome"`
	At      string `json:"at"`
}

func localStopResultsPath(dir string) string { return filepath.Join(dir, "stop_results.json") }

func localStopResultsLoad(dir string) map[string]localStopResult {
	out := map[string]localStopResult{}
	if b, err := os.ReadFile(localStopResultsPath(dir)); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// localStopRecordResult keeps what happened to each approval for the command
// that is waiting on it, the newest localStopKeep.
func localStopRecordResult(dir, approval, outcome string, now time.Time) {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	m := localStopResultsLoad(dir)
	m[approval] = localStopResult{Outcome: outcome, At: now.UTC().Format(time.RFC3339)}
	if len(m) > localStopKeep {
		ids := make([]string, 0, len(m))
		for id := range m {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return m[ids[i]].At < m[ids[j]].At })
		for _, id := range ids[:len(m)-localStopKeep] {
			delete(m, id)
		}
	}
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = atomicWrite(localStopResultsPath(dir), b)
	}
}

// cmdStop is `privatae-bastion stop <pid>`.
func cmdStop(args []string) error {
	key, wait, asJSON, err := askFlags("stop", args)
	if err != nil {
		return errors.New(err.Error() + "\n" + stopUsage)
	}
	// An agent reading --json gets its refusal as JSON too.
	refused := func(why string) error {
		if asJSON {
			return printAsk(os.Stdout, askView{State: askRefused, Why: why}, true, false)
		}
		return errors.New("not stopped: " + why)
	}
	observed := observedAgentMap()
	pid, view, err := resolveStopTarget(strings.TrimSpace(key), observed)
	if err != nil {
		return refused(err.Error())
	}
	if why := stopRefusal(pid, observed); why != "" {
		return refused(why)
	}
	sig := observed[pid].Signature
	if asksGoThroughSock() {
		// The running bastion is not this account's (installed for the whole
		// machine): ask it over its socket, which names the asker from the
		// kernel. Only the owner answers.
		v, err := stopAskViaSock(pid)
		if err != nil {
			return err
		}
		return finishAsk(v, wait, asJSON)
	}
	t, err := resolveStepupTarget("", true)
	if err != nil {
		return err
	}
	if !stepupEnrolled(t.dir) {
		return errors.New("stopping an agent needs your code as this machine's owner, and none is set up yet: " +
			"run `privatae-bastion stepup-enroll --machine`")
	}
	purpose, err := purposeForLocalStop(pid, sig)
	if err != nil {
		return err
	}
	details := map[string]any{"kind": localStopKind, "pid": strconv.Itoa(pid), "signature": sig}
	// What the owner reads beside the pid: which session this is. Display
	// only; the purpose binds the pid and the signature.
	details["agent"] = familyLabel(sig)
	if view.Folder != "" {
		details["folder"] = view.Folder
	}
	if view.Self != nil {
		details["session"] = view.Self.Name
		details["title"] = view.Self.Title
	}
	details["asked_by"] = askerOf(os.Getppid(), observed)
	if !stdinIsConsole() {
		// An agent, a script, a pipe: it may ask, never answer. It runs as
		// the account that holds this bastion's state, so no hold applies:
		// it could rewrite the files a hold is kept in.
		acct := procUser(os.Getpid())
		details["asked_by_account"] = acct
		details["asker"], details["target"] = askParties(acct, os.Getpid(), pid, observed)
		id, err := stepupNewRequest(t.dir, purpose, details)
		if errors.Is(err, errRefusedRecently) {
			return refused("the machine's owner refused this same stop within the last 24 hours, so it " +
				"cannot be asked again yet")
		}
		if err != nil {
			return err
		}
		auditLocalStopAsk(t.dir, pid, sig, details)
		return finishAsk(askView{Request: id[:8], State: askWaiting, AskedAs: acct,
			Text: describeRequest(stepupRequest{Details: details})}, wait, asJSON)
	}
	// The owner at a terminal: the code is the approval, with no request in
	// between, so an agent's earlier ask for the same stop that the owner
	// denied (which blocks that request for a day) cannot block the owner.
	fmt.Println(describeRequest(stepupRequest{Details: details}))
	fmt.Print("Stop it? Enter the code from your authenticator (or leave empty to cancel): ")
	code, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(code) == "" {
		fmt.Println("cancelled — nothing stopped")
		return nil
	}
	approval, err := machineCodeSpend(t.dir, time.Now(), func() (string, error) {
		return stepupIssueApproval(t.dir, code, purpose)
	})
	if err != nil {
		return err
	}
	if !uiDaemonListening() {
		// Burn it: a stop runs now or not at all.
		_ = stepupConsumeApproval(t.dir, approval, purpose)
		return fmt.Errorf("the bastion is not running, so nothing was stopped. Start it with `%s` and ask again",
			runCommandHint())
	}
	if r, ok := waitStopResult(t.dir, approval, localStopWait); ok {
		fmt.Println(r.Outcome)
		return nil
	}
	return fmt.Errorf("approved, but the bastion has not carried it out after %s; `privatae-bastion status` says whether it is running. "+
		"The approval lapses %s after it was given", localStopWait, localStopWindow)
}

// resolveStopTarget takes a pid or a session's name as `agents` shows it. A
// name must match exactly one running session.
func resolveStopTarget(key string, observed map[int]agentObs) (int, agentView, error) {
	if key == "" {
		return 0, agentView{}, errors.New(stopUsage)
	}
	list := make([]agentObs, 0, len(observed))
	for _, a := range observed {
		list = append(list, a)
	}
	views := buildAgentViews(list, processTree())
	if pid, err := strconv.Atoi(key); err == nil {
		for _, v := range views {
			if v.PID == pid {
				return pid, v, nil
			}
		}
		return pid, agentView{}, nil // stopRefusal says why
	}
	var hits []agentView
	for _, v := range views {
		if v.Self != nil && v.Self.Name == key {
			hits = append(hits, v)
		}
	}
	switch len(hits) {
	case 0:
		return 0, agentView{}, fmt.Errorf("no running session is named %q; `privatae-bastion agents` lists them", key)
	case 1:
		return hits[0].PID, hits[0], nil
	}
	return 0, agentView{}, fmt.Errorf("%d sessions are named %q; give the pid instead", len(hits), key)
}

// describeStopTarget names the agent the way a person recognises it.
func describeStopTarget(d map[string]any) string {
	str := func(k string) string { s, _ := d[k].(string); return clean(s) }
	who := str("agent")
	if who == "" {
		who = str("signature")
	}
	if n := str("session"); n != "" {
		who += " session " + n
	}
	if t := str("title"); t != "" && t != str("session") {
		who += " \"" + t + "\""
	}
	if f := str("folder"); f != "" {
		who += " in " + f
	}
	return who + " (pid " + str("pid") + ")"
}

// askerOf names who ran this command: the agent among its ancestors when
// there is one (so the owner reads "asked from Claude Code session shop-a1",
// not a bare account), else the account at a terminal. It is what the
// command saw; on a per-account install the asker could have written the
// request file itself, so it is a description, not a proof.
func askerOf(ppid int, observed map[int]agentObs) string {
	if who, ok := askingAgent(ppid, observed); ok {
		return who
	}
	if u := procUser(os.Getpid()); u != "" {
		return "a terminal, as " + u
	}
	return "a terminal"
}

// askingAgent is the observed agent that pid descends from, named the way the
// owner knows it, if there is one.
func askingAgent(pid int, observed map[int]agentObs) (string, bool) {
	a, p, ok := askingAgentObs(pid, observed)
	if !ok {
		return "", false
	}
	v := buildAgentViews([]agentObs{a}, processTree())[0]
	who := familyLabel(a.Signature)
	if v.Self != nil && v.Self.Name != "" {
		who += " session " + v.Self.Name
	}
	return who + " (pid " + strconv.Itoa(p) + ")", true
}

func stopAskViaSock(pid int) (askView, error) {
	r, err := askViaSock(agentAskRequest{Op: "stop", PID: pid})
	if err != nil {
		return askView{}, fmt.Errorf("could not reach this machine's bastion to ask (%v); `privatae-bastion status` "+
			"says whether it is running", err)
	}
	return askViewOf(r, true), nil
}

// finishAsk prints a filed (or refused) ask, following it first for --wait.
func finishAsk(v askView, wait time.Duration, asJSON bool) error {
	if wait > 0 && v.State == askWaiting {
		var err error
		if v, err = askFollow(v, wait); err != nil {
			return err
		}
	}
	return printAsk(os.Stdout, v, asJSON, wait > 0)
}

// waitStopResult waits for the outcome of one approved stop. Whoever carries
// it out (the daemon's loop, or the console handler calling localStopOnce)
// writes the outcome; this only reads it, so a stop the loop picked up first
// is reported, not "not carried out".
func waitStopResult(dir, approval string, max time.Duration) (localStopResult, bool) {
	deadline := time.Now().Add(max)
	for {
		stepupMu.Lock()
		r, ok := localStopResultsLoad(dir)[approval]
		stepupMu.Unlock()
		if ok || time.Now().After(deadline) {
			return r, ok
		}
		time.Sleep(200 * time.Millisecond)
	}
}
