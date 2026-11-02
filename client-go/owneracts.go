package main

// owneracts.go — the machine's owner acts on its bastion from their own
// account (plan Addendum 6, slice 4).
//
// Installed for the whole machine, the bastion keeps its approvals and its
// local switch in root's state, so `approve`, `deny` and `switch` from the
// owner's account acted on an empty bastion of that account's own: an ask
// waiting for the owner was "not found", and a switch was refused for want of
// sudo. The owner's console session (consolelane.go) has always been able to
// do these, so ask.sock now does exactly the same for the same account, with
// the same rules:
//
//   - approve (the machine's own asks, or a Host's) takes the owner's code,
//     spent and counted as the console spends it (machineCodeSpend for the
//     machine's, codeSpend for a Host's), so wrong codes lock the same way;
//   - switching a family back on takes the owner's code (ownerCodeRefusal),
//     as the console's switch does;
//   - deny, and switching a family off, never do: they only take reach away.
//
// Only the owner's account is answered (readLaneRefusal), as for the reads.
// Each act is one line in the machine's audit log naming the account, beside
// the approve or deny row its own function writes.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type agentActReply struct {
	OK   bool   `json:"ok"`
	Why  string `json:"why,omitempty"`
	Done string `json:"done,omitempty"`
	// Failed: answered for this account, and not done (Why says why); the
	// administrator would be told the same, so it is not a refusal.
	Failed bool   `json:"failed,omitempty"`
	User   string `json:"user,omitempty"`
}

var actNow = time.Now

func serveAct(uid uint32, user string, req agentAskRequest) (r agentActReply) {
	r.User = user
	if why := readLaneRefusal(uid, user); why != "" {
		r.Why = actWording(why)
		return r
	}
	defer func() {
		// The root daemon serves every pairing: an act that panics is that
		// act's failure, never the daemon's end (as runMachineRead does).
		if p := recover(); p != nil {
			uilogf("owner act %q panicked: %v\n", req.Act, p)
			r = agentActReply{User: user, Failed: true, Why: "this act failed inside the machine's bastion; its log says why"}
		}
	}()
	done, what, err := runOwnerAct(req)
	if err != nil {
		r.Failed, r.Why = true, err.Error()
		return r
	}
	ownerActAudit(what, user)
	r.OK, r.Done = true, done
	return r
}

// runOwnerAct does one act; what names it, as resolved, for the audit row.
func runOwnerAct(req agentAskRequest) (done, what string, err error) {
	switch req.Act {
	case "approve", "deny":
		t, err := resolveStepupTarget(req.Host, req.Machine)
		if err != nil {
			return "", "", err
		}
		if !t.machine() {
			// The console's rule for a Host's request, approve and deny alike
			// (ui.go approve and deny both take approvalTarget): only a pairing
			// this machine serves is answered.
			if _, err := approvalTarget(t.host); err != nil {
				return "", "", err
			}
		}
		m := lockedRequests(t.dir)
		id, err := findRequest(m, req.ID)
		if err != nil {
			return "", "", err
		}
		target := "the machine's"
		if !t.machine() {
			target = "a Host's (" + t.host + ")"
		}
		what = req.Act + " " + target + " request " + id
		if req.Act == "deny" {
			if err := stepupDenyRequest(t.dir, id); err != nil {
				return "", "", err
			}
			return "denied.", what, nil
		}
		if !stepupEnrolled(t.dir) {
			return "", "", fmt.Errorf("no second factor is enrolled %s", t.forWhom())
		}
		code := strings.TrimSpace(req.Code)
		if code == "" {
			return "", "", errors.New("approving takes the code from your authenticator")
		}
		spend := func() (string, error) { return stepupApproveRequest(t.dir, id, code) }
		var err2 error
		if t.machine() {
			_, err2 = machineCodeSpend(t.dir, actNow(), spend)
		} else {
			_, err2 = codeSpend(t.dir, actNow(), hostCodeLockedHint, spend)
		}
		if err2 != nil {
			return "", "", err2
		}
		if t.machine() {
			return "approved.", what, nil
		}
		return "approved. " + t.host + " picks this up on its next check-in, within a minute.", what, nil
	case "switch":
		host, err := switchResolveHost(req.Host)
		if err != nil {
			return "", "", err
		}
		family := strings.TrimSpace(req.Family)
		if !req.Off {
			if why := ownerCodeRefusal(req.Code, "local_switch_on|"+host+"|"+family); why != "" {
				return "", "", errors.New(strings.TrimSuffix(why, "."))
			}
		}
		if err := localDenySet(host, family, req.Off); err != nil {
			return "", "", err
		}
		state := "on"
		if req.Off {
			state = "off"
		}
		return switchDoneText(host, family, req.Off), "switch " + cleanText(host, 80) + " " + cleanText(family, 40) + " " + state, nil
	case "approvals-drop", "grants-drop", "ops-drop", "device-deny":
		// Narrowing acts: each only takes reach away, so no code, and each
		// is the command's own core, run where the machine's state is.
		var run func() (string, error)
		switch req.Act {
		case "approvals-drop":
			run = func() (string, error) { return stepupDropText(req.Host, req.Machine, req.ID) }
		case "grants-drop":
			run = func() (string, error) { return grantsDropText(req.Host, req.ID) }
		case "ops-drop":
			run = func() (string, error) { return opsDropText(req.Host, req.ID) }
		default:
			run = func() (string, error) { return deviceDenyText(req.ID) }
		}
		done, err := run()
		if err != nil {
			return "", "", err
		}
		what = req.Act + " " + cleanText(req.ID, 40)
		if req.Host != "" {
			what += " for " + cleanText(req.Host, 80)
		}
		return done, what, nil
	}
	return "", "", fmt.Errorf("this bastion has no act called %q", cleanText(req.Act, 40))
}

// lockedRequests reads a factor's requests under stepupMu, released however
// the read ends: the daemon recovers a panicking act (serveAct), and a lock
// left held would hang every approval after it.
func lockedRequests(dir string) map[string]stepupRequest {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	requestsLoadHook()
	return requestsLoad(dir)
}

// requestsLoadHook is a seam for a test that makes the read panic.
var requestsLoadHook = func() {}

// switchDoneText is what a switch says it did, from the terminal or the lane.
func switchDoneText(host, family string, off bool) string {
	if off {
		return host + " " + family + " off: this machine now refuses it, and tells the host why. Its grant is untouched."
	}
	return host + " " + family + " on: the refusal is cleared, up to whatever its signed grant already allowed."
}

// ownerActAudit is the act's line in the machine's audit log. The owner's
// factor directory is made if it is not there yet (a deny or a switch off
// needs no code set up): dcnAuditWith joins its directory onto audit.jsonl,
// and "" would be the daemon's working directory.
func ownerActAudit(what, user string) {
	dir, err := machineFactorDir()
	if err != nil {
		uilogf("owner act not audited (%v): %s, from %s\n", err, what, user)
		return
	}
	dcnAuditWith(dir, "owner_lane_act", 0, "",
		what+", from the owner's account "+user+" through its ask socket", nil)
}

// ── the asking side ─────────────────────────────────────────────────────────

func actViaSock(req agentAskRequest) (string, error) {
	p := readSockPath()
	c, err := net.DialTimeout("unix", p, 3*time.Second)
	if err != nil {
		return "", &laneError{down: true, why: "nothing answers on " + p + " (" + err.Error() + ")"}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	req.Op = "act"
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return "", &laneError{down: true, why: "the act could not be sent (" + err.Error() + ")"}
	}
	var r agentActReply
	if err := json.NewDecoder(io.LimitReader(c, askMaxBytes)).Decode(&r); err != nil {
		return "", &laneError{down: true, why: "the machine's bastion did not answer (" + err.Error() + ")"}
	}
	if !r.OK && r.Failed {
		return "", errors.New(r.Why)
	}
	if !r.OK {
		return "", &laneError{why: r.Why}
	}
	return r.Done, nil
}

// ownerApproveViaLane shows the request the machine's bastion holds, takes
// the owner's code at this terminal, and asks the bastion to approve it.
func ownerApproveViaLane(host string, machine bool, prefix string) error {
	v, err := readMachine("approvals", readOpts{Host: host, Machine: machine}, readApprovals)
	if err != nil {
		// Refused, the read is refused as the approve it was read for.
		var le *laneError
		if errors.As(err, &le) && !le.down {
			err = &laneError{why: actWording(le.why)}
		}
		return laneRefusalError(stepupCommand("approve", host, machine, prefix), err)
	}
	if !v.CodeSetUp {
		return fmt.Errorf("no second factor is enrolled %s, so nothing can be approved yet", v.For)
	}
	var hit *approvalWaiting
	for i := range v.Waiting {
		if strings.HasPrefix(v.Waiting[i].ID, prefix) || strings.HasPrefix(prefix, v.Waiting[i].ID) {
			if hit != nil {
				return fmt.Errorf("more than one waiting request starts with %q; give more of its id", prefix)
			}
			hit = &v.Waiting[i]
		}
	}
	if hit == nil {
		return fmt.Errorf("nothing waiting %s starts with %q; `privatae-bastion approvals%s` lists them",
			v.For, prefix, map[bool]string{true: " --machine", false: ""}[machine])
	}
	fmt.Println(hit.Text)
	fmt.Println()
	code, ok := promptOwnerCode("Approve this? Enter the code from your authenticator (or leave empty to cancel): ")
	if !ok {
		return nil
	}
	// The bastion finds the request again by this id: the one shown, never
	// fewer characters of it than shown. Sent as typed, a short prefix would
	// approve whatever request matched it by then (one an agent filed while
	// the person typed, say), which is not what they read.
	id := hit.ID
	if len(prefix) > len(id) {
		id = prefix
	}
	done, err := actViaSock(agentAskRequest{Act: "approve", Host: host, Machine: machine, ID: id, Code: code})
	if err != nil {
		return laneRefusalError(stepupCommand("approve", host, machine, prefix), err)
	}
	fmt.Println(done)
	return nil
}

// actWording is the reads' refusal said of an act.
func actWording(why string) string {
	return strings.Replace(why, "answers reads only for", "acts only for", 1)
}

// stepupCommand is approve or deny as the administrator would type it here.
func stepupCommand(verb, host string, machine bool, id string) string {
	switch {
	case machine:
		return verb + " --machine " + id
	case host != "":
		return verb + " --host " + host + " " + id
	}
	return verb + " " + id
}

// promptOwnerCode reads a code from this terminal; ok is false when the
// person left it empty, and then nothing is done (said here).
var promptOwnerCode = func(prompt string) (string, bool) {
	fmt.Print(prompt)
	code, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	code = strings.TrimSpace(code)
	if code == "" {
		fmt.Println("cancelled — nothing done")
		return "", false
	}
	return code, true
}
