package main

// askstatus.go — the asking side follows its ask to the end. An agent that
// ran `stop` used to get a request id and nothing after it: the outcome was
// kept under the approval id, which only the owner's side ever sees, so the
// agent could not tell the person whether the stop happened.
//
//	privatae-bastion stop <pid|session> [--wait 5m] [--json]
//	privatae-bastion request <id> [--wait 5m] [--json]
//
// Where the bastion runs as another account (installed for the whole
// machine), both go through ask.sock (op "status"), which answers only the
// account that asked: any other account is told what it would be told for an
// id that never existed.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// What an ask can be, as an agent reads it.
const (
	askWaiting    = "waiting"     // the owner has not answered
	askApproved   = "approved"    // approved; the bastion is carrying it out
	askStopped    = "stopped"     // approved and done
	askNotStopped = "not_stopped" // approved, but it could not be done (outcome says why)
	askDenied     = "denied"      // the owner refused it
	askRefused    = "refused"     // nothing was asked (why says why)
	askUnknown    = "unknown"     // no such ask from this account, or it is older than a day
)

var askPollEvery = 2 * time.Second

// askStatus is where the ask with this id prefix stands. anyAccount is for a
// reader that holds the state itself (it could read the files anyway);
// ask.sock always passes false, so an account sees only its own asks.
func askStatus(dir, prefix, user string, anyAccount bool) agentAskReply {
	r := agentAskReply{User: user}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		r.Why = "which request? give the id `stop` printed"
		return r
	}
	if dir == "" || (!anyAccount && user == "") {
		r.State, r.Why = askUnknown, "no request "+prefix+" was asked from your account"
		return r
	}
	stepupMu.Lock()
	m := requestsLoad(dir)
	results := localStopResultsLoad(dir)
	stepupMu.Unlock()
	var hit string
	for id, q := range m {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		if kind, _ := q.Details["kind"].(string); kind != localStopKind {
			continue
		}
		if acct, _ := q.Details["asked_by_account"].(string); !anyAccount && acct != user {
			continue
		}
		if hit != "" {
			r.Why = "'" + prefix + "' matches more than one request; give more of the id"
			return r
		}
		hit = id
	}
	if hit == "" {
		r.State, r.Why = askUnknown, "no request "+prefix+" was asked from your account in the last day"
		return r
	}
	q := m[hit]
	r.OK, r.Request, r.Text = true, hit[:8], describeRequest(q)
	r.State, r.Outcome = askState(q, results)
	return r
}

func askState(q stepupRequest, results map[string]localStopResult) (state, outcome string) {
	switch q.State {
	case "pending":
		return askWaiting, ""
	case "denied":
		return askDenied, ""
	case "approved":
		res, ok := results[q.Approval]
		switch {
		case !ok:
			return askApproved, ""
		case strings.HasPrefix(res.Outcome, "not stopped"):
			return askNotStopped, res.Outcome
		default:
			return askStopped, res.Outcome
		}
	}
	return askUnknown, ""
}

// askView is what `stop` and `request` print, and their --json.
type askView struct {
	Request string `json:"request,omitempty"`
	State   string `json:"state"`
	Text    string `json:"text,omitempty"`    // what the owner reads
	Outcome string `json:"outcome,omitempty"` // once carried out
	AskedAs string `json:"asked_as,omitempty"`
	Why     string `json:"why,omitempty"` // refused or unknown
}

func (v askView) settled() bool { return v.State != askWaiting && v.State != askApproved }

func askViewOf(r agentAskReply, filing bool) askView {
	v := askView{Request: r.Request, State: r.State, Text: r.Text, Outcome: r.Outcome, AskedAs: r.User, Why: r.Why}
	switch {
	case !r.OK && filing:
		v.State = askRefused
	case !r.OK && v.State == "":
		v.State = askUnknown
	case filing:
		v.State = askWaiting
	}
	return v
}

// asksGoThroughSock: the running bastion is not this account's (installed
// for the whole machine), so asking and following an ask go over ask.sock,
// which names the asker from the kernel.
func asksGoThroughSock() bool { return !machineAuthorityHeld() && !uiDaemonListening() }

func askStatusFor(prefix string) (askView, error) {
	if asksGoThroughSock() {
		r, err := askViaSock(agentAskRequest{Op: "status", Request: prefix})
		if err != nil {
			return askView{}, fmt.Errorf("could not reach this machine's bastion (%v); `privatae-bastion status` "+
				"says whether it is running", err)
		}
		return askViewOf(r, false), nil
	}
	t, err := resolveStepupTarget("", true)
	if err != nil {
		return askView{}, err
	}
	return askViewOf(askStatus(t.dir, prefix, procUser(os.Getpid()), true), false), nil
}

// askFollow polls until the ask settles or wait runs out.
func askFollow(v askView, wait time.Duration) (askView, error) {
	deadline := time.Now().Add(wait)
	for !v.settled() && v.Request != "" && time.Now().Before(deadline) {
		time.Sleep(askPollEvery)
		nv, err := askStatusFor(v.Request)
		if err != nil {
			return v, err
		}
		v = nv
	}
	return v, nil
}

// quietExit ends a command with a status and nothing more printed: the
// command has already said what happened.
type quietExit struct{ code int }

func (q quietExit) Error() string { return fmt.Sprintf("exit status %d", q.code) }

// Exit statuses an agent can branch on: 0 stopped, or asked and not waited
// for; 1 refused, denied, not stopped or unknown; 3 still waiting when --wait
// ran out.
const askExitWaiting = 3

func printAsk(w io.Writer, v askView, asJSON bool, waited bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	} else {
		fmt.Fprintln(w, askSentence(v))
	}
	switch {
	case v.State == askStopped:
		return nil
	case !v.settled() && !waited:
		return nil
	case !v.settled():
		return quietExit{askExitWaiting}
	}
	return quietExit{1}
}

func askSentence(v askView) string {
	switch v.State {
	case askRefused:
		return "not asked: " + v.Why
	case askUnknown:
		return v.Why
	case askWaiting:
		s := "asked"
		if v.AskedAs != "" {
			s += ", as " + v.AskedAs
		}
		return s + ": " + v.Text + "\nIt waits for the machine owner's approval (request " + v.Request +
			"), on Waiting for you in the bastion console. Nothing is stopped until they approve it.\n" +
			"Follow it with `privatae-bastion request " + v.Request + " --wait 5m`."
	case askApproved:
		return "request " + v.Request + ": approved by the machine's owner; the bastion is carrying it out."
	case askStopped:
		return "request " + v.Request + ": approved by the machine's owner and done. " +
			strings.Replace(v.Outcome, "You stopped", "The bastion stopped", 1)
	case askNotStopped:
		return "request " + v.Request + ": approved by the machine's owner, but " + v.Outcome
	case askDenied:
		return "request " + v.Request + ": the machine's owner denied it. The same stop cannot be asked " +
			"again for 24 hours."
	}
	return "request " + v.Request + ": " + v.State
}

// askFlags parses what `stop` and `request` share. It returns the one
// positional argument.
func askFlags(name string, args []string) (string, time.Duration, bool, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	wait := fs.Duration("wait", 0, "")
	asJSON := fs.Bool("json", false, "")
	// The id or pid may come before the flags (`stop 1234 --wait 5m`), as
	// agents write it.
	var pos []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return "", 0, false, err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(pos) != 1 {
		return "", 0, false, errors.New("give exactly one " + map[bool]string{true: "request id",
			false: "pid or session name"}[name == "request"])
	}
	if *wait < 0 {
		return "", 0, false, errors.New("--wait cannot be negative")
	}
	return pos[0], *wait, *asJSON, nil
}

// cmdRequest is `privatae-bastion request <id> [--wait D] [--json]`.
func cmdRequest(args []string) error {
	id, wait, asJSON, err := askFlags("request", args)
	if err != nil {
		return fmt.Errorf("%v\nusage: %s", err, requestUsage)
	}
	v, err := askStatusFor(id)
	if err != nil {
		return err
	}
	if wait > 0 {
		if v, err = askFollow(v, wait); err != nil {
			return err
		}
	}
	return printAsk(os.Stdout, v, asJSON, wait > 0)
}

const requestUsage = "privatae-bastion request <id> [--wait 5m] [--json]"
