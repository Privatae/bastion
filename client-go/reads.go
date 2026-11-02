package main

// reads.go — what the machine's bastion knows, read by an agent the machine's
// owner runs (plan Addendum 6, slice 2).
//
// Installed for the whole machine, the bastion runs as root and keeps its
// records in root's state. An agent the person runs works in the person's
// account: `status`, `activity` and `report` sent it to sudo or a browser,
// and it has neither; `agents`, `schedules` and `tool-servers` showed it only
// what that account can read. ask.sock (agentask.go) already knows from the
// kernel which account connected. Asked for a read by the account recorded as
// the machine's owner (owner_account.go), the daemon builds it with the
// machine's own view and answers with it. That is what the owner's console
// lane (consolelane.go) already shows that account, and more that the console
// has no page for: posture (the machine's firewall checks, read as the
// administrator); the ops and op grants each Host holds here, its backup
// requests and the folders shared with it; this bastion's backup keys (public
// halves only); and doctor. All of it is about the owner's own machine, and
// the lane answers no other account. The delegation tag an agent carries,
// which the console never shows, is in no read at all (readAgents).
// Any other account is refused; where a read means something with its own
// permissions (the agents, schedules and tool servers it can see), it gets
// that, and is told so.
//
// Each read is one value, built where the machine's state is and printed by
// whoever asked: in words, or with --json as the value itself. The words and
// the JSON are never built apart, so they cannot say different things.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"time"
)

const (
	// readMaxBytes bounds one read's answer. A report on a busy machine is
	// a few hundred KB; this is room for a pathological one.
	readMaxBytes = 16 << 20
	// readEnvelope is room in readMaxBytes for the reply around the view.
	readEnvelope = 64 << 10
	// readDeadline is how long the daemon spends on one read. Comparing
	// against the baseline walks every process and digests their files.
	readDeadline = 90 * time.Second
	// readReuse is how long a heavy read's answer is handed out again
	// rather than run again: an agent polling it costs one pass, not one
	// pass per poll.
	readReuse = 30 * time.Second
)

// readOpts are the flags a read takes, the same ones on both sides.
type readOpts struct {
	Since   string `json:"since,omitempty"`   // activity, report: 12h, 7d
	Prompts bool   `json:"prompts,omitempty"` // agents: each session's last prompt
	Host    string `json:"host,omitempty"`    // approvals: a Host's requests
	Machine bool   `json:"machine,omitempty"` // approvals: the machine's own
}

func (o readOpts) since(def time.Duration) (time.Duration, error) {
	if o.Since == "" {
		return def, nil
	}
	return parseSince(o.Since)
}

type machineRead struct {
	build func(readOpts) (any, error)
	heavy bool // walks every process or runs the package manager
}

// machineReads are what the daemon answers over ask.sock, by name.
var machineReads = map[string]machineRead{
	"status":           {build: func(o readOpts) (any, error) { return readStatus(o) }},
	"agents":           {build: func(o readOpts) (any, error) { return readAgents(o) }},
	"schedules":        {build: func(o readOpts) (any, error) { return readSchedules(o) }},
	"tool-servers":     {build: func(o readOpts) (any, error) { return readToolServers(o) }},
	"posture":          {build: func(o readOpts) (any, error) { return readPosture(o) }, heavy: true},
	"baseline":         {build: func(o readOpts) (any, error) { return readBaseline(o) }},
	"baseline-diff":    {build: func(o readOpts) (any, error) { return readBaselineDiff(o) }, heavy: true},
	"activity":         {build: func(o readOpts) (any, error) { return readActivity(o) }},
	"report":           {build: func(o readOpts) (any, error) { return readReport(o) }, heavy: true},
	"approvals":        {build: func(o readOpts) (any, error) { return readApprovals(o) }},
	"switches":         {build: func(o readOpts) (any, error) { return readSwitches(o) }},
	"ops":              {build: func(o readOpts) (any, error) { return readOps(o) }},
	"device-approvals": {build: func(o readOpts) (any, error) { return readDeviceApprovals(o) }},
	"backup-keys":      {build: func(o readOpts) (any, error) { return readBackupKeys(o) }},
	"backup-requests":  {build: func(o readOpts) (any, error) { return readBackupRequests(o) }},
	"backup-shares":    {build: func(o readOpts) (any, error) { return readBackupShares(o) }},
	"doctor":           {build: func(o readOpts) (any, error) { return readDoctor(o) }, heavy: true},
}

// readsGoThroughLane: the machine's bastion is a system service this account
// does not administer, so its state is not this process's to read.
var readsGoThroughLane = func() bool {
	if machineAuthorityHeld() {
		return false // the administrator reads the service's state directly
	}
	if runtime.GOOS == "linux" {
		return linuxSystemUnitPresent()
	}
	return systemService.installed
}

// laneError is the machine's bastion not answering a read for this account:
// refused (not the owner's account), or nothing answering at all (down).
type laneError struct {
	why  string
	down bool
}

func (e *laneError) Error() string { return e.why }

// readMachine is the read `name`: built here when this process holds the
// machine's state, else asked of the machine's bastion.
func readMachine[T any](name string, o readOpts, build func(readOpts) (T, error)) (T, error) {
	if !readsGoThroughLane() {
		return build(o)
	}
	var v T
	err := readViaSock(name, o, &v)
	return v, err
}

// readOwnOrMachine is readMachine for a read that means something with this
// account's own permissions: refused by the machine's bastion, it reads what
// this account can see, and says so on stderr.
func readOwnOrMachine[T any](name string, o readOpts, build func(readOpts) (T, error)) (T, error) {
	v, err := readMachine(name, o, build)
	var le *laneError
	if !errors.As(err, &le) {
		return v, err
	}
	fmt.Fprintf(os.Stderr, "%s.\nShowing only what this account can read itself.\n", sentenceCase(le.why))
	return build(o)
}

// sentenceCase starts s with a capital, for a reason said as a sentence.
func sentenceCase(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

// laneRefusalError is a read that only the machine's bastion can answer,
// refused: why, and how the administrator reads it.
func laneRefusalError(cmd string, err error) error {
	var le *laneError
	if !errors.As(err, &le) {
		return err
	}
	return fmt.Errorf("%s\n  As the administrator:  %s", le.why, adminCommandFor(runtime.GOOS == "windows", cmd))
}

// ── the asking side ─────────────────────────────────────────────────────────

// readSockPath is where the machine's bastion answers; a variable so a test
// can stand one up elsewhere.
var readSockPath = askSockPath

func readViaSock(name string, o readOpts, v any) error {
	p := askLaneAddr(readSockPath())
	c, err := dialAskLane(readSockPath())
	if err != nil {
		return &laneError{down: true, why: "nothing answers on " + p + " (" + err.Error() + ")"}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(readDeadline + 10*time.Second))
	req := agentAskRequest{Op: "read", Read: name, Since: o.Since, Prompts: o.Prompts, Host: o.Host, Machine: o.Machine}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return &laneError{down: true, why: "the read could not be sent (" + err.Error() + ")"}
	}
	var r agentReadReply
	if err := json.NewDecoder(io.LimitReader(c, readMaxBytes)).Decode(&r); err != nil {
		return &laneError{down: true, why: "the machine's bastion did not answer the read (" + err.Error() + ")"}
	}
	if !r.OK && r.Failed {
		return errors.New(r.Why)
	}
	if !r.OK {
		return &laneError{why: r.Why}
	}
	if err := json.Unmarshal(r.View, v); err != nil {
		return fmt.Errorf("the machine's bastion answered %s in a form this one cannot read (%v); "+
			"the two may be different versions", name, err)
	}
	return nil
}

// ── the answering side (the daemon) ─────────────────────────────────────────

type agentReadReply struct {
	OK  bool   `json:"ok"`
	Why string `json:"why,omitempty"`
	// Failed: the read was answered for this account and could not be
	// built (Why says why): the administrator would be told the same, so it
	// is not a refusal. A bastion older than this field says it as one.
	Failed bool            `json:"failed,omitempty"`
	User   string          `json:"user,omitempty"`
	View   json.RawMessage `json:"view,omitempty"`
}

// readLaneRefusalFor says why peer may not read through the lane, or "".
// The owner's account only: the agents, folders and prompts of every
// account's sessions are the owner's to see, not another account's.
func readLaneRefusalFor(p askPeer) string {
	match, ownerName, present, err := laneOwnerMatch(p)
	switch {
	case err != nil:
		return "this machine's owner account cannot be read (" + err.Error() + ")"
	case !present:
		return "no account is recorded as this machine's owner, so its bastion answers reads only for the " +
			"administrator. To read from your own account, the administrator records it once: " +
			ownerRecordCommand(p)
	case !match:
		return "this machine's bastion answers reads only for its owner's account (" + ownerName + "), not " + p.Name
	}
	return ""
}

// heavyReads runs one heavy read at a time and hands its answer out again
// for readReuse.
var heavyReads struct {
	sync.Mutex
	last map[string]heavyAnswer
}

type heavyAnswer struct {
	at   time.Time
	view []byte
}

var readNow = time.Now

// readSlots is how many reads the daemon answers at once: fewer than
// ask.sock's connections (askSockInFlight), so reads that walk every process
// can never leave a stop ask with no connection to arrive on.
var readSlots = make(chan struct{}, 4)

func serveRead(uid uint32, user string, req agentAskRequest) agentReadReply {
	return serveReadFor(askPeer{UID: uid, Name: user}, req)
}

func serveReadFor(p askPeer, req agentAskRequest) agentReadReply {
	r := agentReadReply{User: p.Name}
	if why := readLaneRefusalFor(p); why != "" {
		r.Why = why
		return r
	}
	select {
	case readSlots <- struct{}{}:
		defer func() { <-readSlots }()
	default:
		r.Why = "this machine's bastion is answering " + strconv.Itoa(cap(readSlots)) +
			" reads already; ask again in a moment"
		return r
	}
	spec, ok := machineReads[req.Read]
	if !ok {
		r.Why = "this bastion has no read called " + strconv.Quote(cleanText(req.Read, 40))
		return r
	}
	o := readOpts{Since: req.Since, Prompts: req.Prompts, Host: req.Host, Machine: req.Machine}
	view, err := runMachineRead(req.Read, spec, o)
	if err != nil {
		r.Why, r.Failed = err.Error(), true
		return r
	}
	if len(view) > readMaxBytes-readEnvelope {
		// Cut off at readMaxBytes, the asker would read a bastion that
		// does not answer.
		r.Why = fmt.Sprintf("this read's answer is %d MiB, more than the %d MiB one answer may be; "+
			"ask for a shorter period with --since", (len(view)+(1<<20)-1)>>20, readMaxBytes>>20)
		return r
	}
	r.OK, r.View = true, view
	return r
}

func runMachineRead(name string, spec machineRead, o readOpts) ([]byte, error) {
	build := func() (b []byte, err error) {
		// A read runs inside the daemon that serves every pairing, from code
		// written for a command's own process: one that panics is that read's
		// failure, never the daemon's end.
		defer func() {
			if p := recover(); p != nil {
				uilogf("read %s panicked: %v\n%s", name, p, debug.Stack())
				b, err = nil, fmt.Errorf("the read %s failed inside this bastion (%v); its log has the trace", name, p)
			}
		}()
		v, err := spec.build(o)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)
	}
	if !spec.heavy {
		return build()
	}
	key, _ := json.Marshal(struct {
		N string
		O readOpts
	}{name, o})
	heavyReads.Lock()
	defer heavyReads.Unlock()
	if a, ok := heavyReads.last[string(key)]; ok && readNow().Sub(a.at) < readReuse {
		return a.view, nil
	}
	b, err := build()
	if err != nil {
		return nil, err
	}
	if heavyReads.last == nil {
		heavyReads.last = map[string]heavyAnswer{}
	}
	for k, a := range heavyReads.last {
		if readNow().Sub(a.at) >= readReuse {
			delete(heavyReads.last, k)
		}
	}
	heavyReads.last[string(key)] = heavyAnswer{at: readNow(), view: b}
	return b, nil
}

// ── flags ───────────────────────────────────────────────────────────────────

// jsonOnly reads a command's flags when --json is its only one.
func jsonOnly(usage string, args []string) (bool, error) {
	asJSON := false
	for _, a := range args {
		if a != "--json" {
			return false, errors.New(usage)
		}
		asJSON = true
	}
	return asJSON, nil
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
