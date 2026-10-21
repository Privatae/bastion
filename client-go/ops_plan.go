package main

// ops_plan.go — the signed ship plan: one approval for a whole ship.
//
// A ship is several action ops on several machines, in order: build and push
// on one, move a tree and restart on another, roll a workload on a third. One
// op_run per step would be one tap per step. So the person's device signs ONE
// statement listing every step of this run, and each
// machine runs only its own lines of it.
//
// What the device signs (a DSSE envelope, payload type shipPlanPayloadType):
//
//	the pipeline's name and a version that only increases, the commit being
//	shipped, a nonce, an expiry (4 h at most), whether the plan holds root
//	work and that the person's code was checked on the device for it, the key
//	of every machine in it — the keys the DEVICE pinned itself, never ones the
//	pod supplied — and the lines: step, machine, op and its sha256, the params
//	as text, the params a line takes from an earlier step's receipt, its
//	verbs, whether it may be undone, and whether a roll adopts the live image.
//
// What each machine checks before it runs a line (planLineCheck):
//
//	the envelope verifies under a device key pinned HERE; the plan is live
//	and not longer-lived than the cap; its version is not older than one this
//	machine already ran for that pipeline; the plan names this machine's own
//	key for its hostname (a device that pinned another key for this machine
//	is not talking about this machine); the line names this machine; the
//	line was not spent before (plan nonce + line, kept for the plan's life);
//	a root line comes from a plan that says the code was given; the held
//	op's manifest declares exactly the verbs the line shows.
//
// Values that do not exist at approval (the digest a build produces) come
// from a receipt: a line names, per param, the step whose receipt supplies it.
// The receipt must be signed by the key the plan names for its machine, name
// this plan's nonce and commit, be that step's, and say that step succeeded.
// So an image the pod pushed itself, or a receipt from another run, is never
// rolled, and a roll cannot run before its build.
//
// Attempts and undo (ops_plan_linux.go): a line's attempts run one at a
// time, the next only after the last failed. A line marked undoable may be
// reverted on this machine only to the state it recorded before the line's
// first attempt, on a signed receipt of a later line's failed check (its last
// allowed attempt) or of the line's own latest attempt failing.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	shipPlanPayloadType = "application/vnd.privatae.ship-plan.v1+json"
	shipPlanKind        = "ship_plan"
	shipPlanTTLMax      = 4 * time.Hour
	shipPlanLinesMax    = 64
	shipPlanVersion     = 1
	planSpentFile       = "plan_spent.json"
	planVersionsFile    = "plan_versions.json"
)

var (
	planStepRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	planInputRe  = regexp.MustCompile(`^([a-z][a-z0-9-]{0,31})\.digest(?::([a-z0-9][a-z0-9._:/-]{0,254}))?$`)
	planHostRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	planMu       sync.Mutex
	planNonceMin = 16
)

// shipPlanLine is one step of a ship on one machine.
type shipPlanLine struct {
	N        int    `json:"n"` // 1..len(lines), in order
	Step     string `json:"step"`
	Machine  string `json:"machine"` // hostname
	Op       string `json:"op"`
	OpSHA256 string `json:"op_sha256"`
	// Params: the JSON text of the op's params, bound verbatim; Inputs names
	// the params filled at run time from an earlier step's receipt, as
	// "<step>.digest" (the one image that step pushed) or
	// "<step>.digest:<image>".
	Params string            `json:"params"`
	Inputs map[string]string `json:"inputs,omitempty"`
	// Verbs: what the op's manifest declares, shown to the person and checked
	// against the held op by the machine.
	Verbs []opVerbLine `json:"verbs,omitempty"`
	// Undo: the line may be reverted after a failed later line (ops_plan_linux.go).
	Undo bool `json:"undo,omitempty"`
	// AdoptLive: a k8s.set_image on this line takes the live image as its
	// starting point when this machine has no record of it (the first roll),
	// instead of refusing. The person reads this on the device.
	AdoptLive bool `json:"adopt_live,omitempty"`
	// Attempts: how many times the line may run (1 when unset, at most
	// planAttemptsMax): a pipeline's retry rule, approved with the plan.
	Attempts int `json:"attempts,omitempty"`
}

const planAttemptsMax = 4

// planTextOK: printable ASCII and spaces only — what a person reads on the
// device has no control character, line break or Unicode trick in it.
func planTextOK(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// planParamsOK: the params are one JSON object, printable, with no key twice
// (the device shows the text; the machine and the program must read the
// same values from it).
func planParamsOK(text string) error {
	if !planTextOK(text) || len(text) > opParamsMaxBytes {
		return errors.New("params must be printable ASCII JSON")
	}
	dec := json.NewDecoder(strings.NewReader(text))
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 8 {
			return errors.New("params nest too deep")
		}
		tok, err := dec.Token()
		if err != nil {
			return errors.New("params are not JSON")
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				seen := map[string]bool{}
				for dec.More() {
					kt, err := dec.Token()
					k, ok := kt.(string)
					if err != nil || !ok {
						return errors.New("params are not JSON")
					}
					if seen[k] {
						return fmt.Errorf("params name %q twice", k)
					}
					seen[k] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			case '[':
				for dec.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			}
		}
		return nil
	}
	if !strings.HasPrefix(strings.TrimSpace(text), "{") {
		return errors.New("params must be a JSON object")
	}
	if err := walk(0); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("params hold more than one JSON value")
	}
	return nil
}

// planVerbsShapeOK: the verbs a line shows are verbs this bastion runs,
// with only their own argument names and printable values (the machine
// compares them with its op anyway; this is what keeps the device's words
// honest before it signs).
func planVerbsShapeOK(verbs []opVerbLine) error {
	if len(verbs) > opVerbsMax {
		return fmt.Errorf("at most %d verbs", opVerbsMax)
	}
	for _, v := range verbs {
		spec, ok := opVerbSpecs[v.Verb]
		if !ok {
			return fmt.Errorf("%q is not a verb this bastion runs", v.Verb)
		}
		allowed := map[string]bool{}
		for _, k := range append(append([]string{}, spec.required...), spec.optional...) {
			allowed[k] = true
		}
		for k, val := range v.Args {
			if !allowed[k] {
				return fmt.Errorf("%s takes no argument %q", v.Verb, k)
			}
			if !planTextOK(val) || len(val) > 2000 || (k != "must" && k != "must_not" && strings.Contains(val, " ")) {
				return fmt.Errorf("%s %s is not printable", v.Verb, k)
			}
		}
	}
	return nil
}

// shipPlan is the statement the device signs.
type shipPlan struct {
	V         int               `json:"v"`
	Kind      string            `json:"kind"`
	Pipeline  string            `json:"pipeline"`
	Version   int64             `json:"version"`
	Commit    string            `json:"commit"`
	Nonce     string            `json:"nonce"`
	Expires   string            `json:"expires"`
	Root      bool              `json:"root"`
	CodeGiven bool              `json:"code_given"`
	Device    string            `json:"device"`   // the signing device's key, b64
	Machines  map[string]string `json:"machines"` // hostname -> machine key (owner.go), b64
	Lines     []shipPlanLine    `json:"lines"`
}

// shipPlanEnvelope is DSSE: the plan's exact bytes and the device's signature
// over their pre-authentication encoding.
type shipPlanEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

func dssePAE(payloadType string, body []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(body), body))
}

// planShape judges a plan's form, wherever it is read (the device before it
// signs, each machine before it runs a line). It does not judge keys.
func planShape(p *shipPlan) error {
	if p.V != shipPlanVersion || p.Kind != shipPlanKind {
		return errors.New("not a ship plan this bastion reads")
	}
	if !opNameRe.MatchString(p.Pipeline) {
		return errors.New("the plan names no pipeline")
	}
	if p.Version < 1 {
		return errors.New("the plan's version must be 1 or more")
	}
	if !opCommitRe.MatchString(p.Commit) {
		return errors.New("the plan's commit is not a full commit id")
	}
	if len(p.Nonce) < planNonceMin || !printableASCII(p.Nonce) {
		return errors.New("the plan carries no nonce")
	}
	exp, err := time.Parse(time.RFC3339, p.Expires)
	if err != nil {
		return errors.New("the plan states no expiry")
	}
	if exp.After(time.Now().Add(shipPlanTTLMax + deviceClockSkew)) {
		return fmt.Errorf("a ship plan may not live longer than %s", shipPlanTTLMax)
	}
	if len(p.Lines) == 0 || len(p.Lines) > shipPlanLinesMax {
		return fmt.Errorf("a ship plan holds 1..%d lines", shipPlanLinesMax)
	}
	steps := map[string]int{}
	root := false
	for i, l := range p.Lines {
		if l.N != i+1 {
			return fmt.Errorf("line %d is numbered %d", i+1, l.N)
		}
		if !planStepRe.MatchString(l.Step) {
			return fmt.Errorf("line %d: a step is [a-z][a-z0-9-]{0,31}", l.N)
		}
		if _, dup := steps[l.Step]; dup {
			return fmt.Errorf("line %d: step %s appears twice", l.N, l.Step)
		}
		steps[l.Step] = l.N
		if !planHostRe.MatchString(l.Machine) {
			return fmt.Errorf("line %d names no machine", l.N)
		}
		if _, ok := p.Machines[l.Machine]; !ok {
			return fmt.Errorf("line %d's machine %s has no key in the plan", l.N, l.Machine)
		}
		if !opNameRe.MatchString(l.Op) || len(l.OpSHA256) != 64 {
			return fmt.Errorf("line %d names no op", l.N)
		}
		if _, err := hex.DecodeString(l.OpSHA256); err != nil {
			return fmt.Errorf("line %d's op sha256 is malformed", l.N)
		}
		if err := planParamsOK(l.Params); err != nil {
			return fmt.Errorf("line %d: %v", l.N, err)
		}
		var params map[string]any
		if err := json.Unmarshal([]byte(l.Params), &params); err != nil || params == nil {
			return fmt.Errorf("line %d's params are not a JSON object", l.N)
		}
		if err := planVerbsShapeOK(l.Verbs); err != nil {
			return fmt.Errorf("line %d: %v", l.N, err)
		}
		if l.Attempts < 0 || l.Attempts > planAttemptsMax {
			return fmt.Errorf("line %d may run 1..%d times", l.N, planAttemptsMax)
		}
		for name, from := range l.Inputs {
			if !opParamRe.MatchString(name) {
				return fmt.Errorf("line %d: input %q is not a param name", l.N, name)
			}
			m := planInputRe.FindStringSubmatch(from)
			if m == nil {
				return fmt.Errorf("line %d: input %s must be <step>.digest or <step>.digest:<image>", l.N, name)
			}
			at, ok := steps[m[1]]
			if !ok || at >= l.N {
				return fmt.Errorf("line %d: input %s comes from %s, which is not an earlier step", l.N, name, m[1])
			}
			if _, bound := params[name]; bound {
				return fmt.Errorf("line %d: %s is both bound and an input", l.N, name)
			}
		}
		if len(l.Verbs) > 0 {
			root = true
		}
	}
	if root != p.Root {
		return errors.New("the plan's root flag does not match its lines")
	}
	return nil
}

// planOpen verifies an envelope under the device keys pinned on THIS machine
// and returns the plan and its sha256.
func planOpen(env shipPlanEnvelope) (*shipPlan, string, error) {
	if env.PayloadType != shipPlanPayloadType {
		return nil, "", errors.New("not a ship plan envelope")
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, "", errors.New("the plan does not decode")
	}
	var p shipPlan
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, "", errors.New("the plan does not parse")
	}
	pinned := false
	for _, k := range deviceKeys() {
		pinned = pinned || k == p.Device
	}
	if !pinned {
		return nil, "", errors.New("the plan is signed by a device this machine has not pinned (pin-device, with machine authority)")
	}
	pub, err := base64.StdEncoding.DecodeString(p.Device)
	sig, err2 := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(pub), dssePAE(shipPlanPayloadType, body), sig) {
		return nil, "", errors.New("the plan's signature does not verify")
	}
	if err := planShape(&p); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return &p, hex.EncodeToString(sum[:]), nil
}

// planLineFor is the line n of a verified plan, checked as THIS machine's to
// run now: live, not stale, this machine's key, this machine's line.
func planLineFor(p *shipPlan, n int) (*shipPlanLine, error) {
	exp, _ := time.Parse(time.RFC3339, p.Expires)
	if !exp.After(time.Now()) {
		return nil, errors.New("the plan has expired")
	}
	if n < 1 || n > len(p.Lines) {
		return nil, fmt.Errorf("the plan has no line %d", n)
	}
	l := &p.Lines[n-1]
	hn, _ := os.Hostname()
	if l.Machine != hn {
		return nil, fmt.Errorf("line %d is for %s, and this machine is %s", n, l.Machine, hn)
	}
	pub, _, err := loadOrCreateOwnerKey()
	if err != nil {
		return nil, err
	}
	if p.Machines[hn] != base64.StdEncoding.EncodeToString(pub) {
		return nil, errors.New("the plan names another key for this machine than its own: the device pinned a different machine under this name")
	}
	if len(l.Verbs) > 0 && !p.CodeGiven {
		return nil, errors.New("a root line runs only from a plan approved with your code on your device")
	}
	if seen := planVersionSeen(p.Pipeline); p.Version < seen {
		return nil, fmt.Errorf("this machine already ran version %d of %s; version %d is older", seen, p.Pipeline, p.Version)
	}
	return l, nil
}

// ── the ledgers: spent lines, versions seen ─────────────────────────────────

func planLedgerPath(name string) (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

func planLedgerLoad(name string) map[string]string {
	out := map[string]string{}
	if p, err := planLedgerPath(name); err == nil {
		if raw, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(raw, &out)
		}
	}
	return out
}

func planLedgerSave(name string, m map[string]string) error {
	p, err := planLedgerPath(name)
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	return atomicWrite(p, raw)
}

// planSpendAttempt spends the next of a line's attempts and returns its
// number (1-based); refuses when all are spent.
func planSpendAttempt(p *shipPlan, l *shipPlanLine) (int, error) {
	max := l.Attempts
	if max < 1 {
		max = 1
	}
	for k := 1; k <= max; k++ {
		key := strconv.Itoa(l.N) + "#" + strconv.Itoa(k)
		err := planSpend(p, key)
		if err == nil {
			return k, nil
		}
		if !strings.Contains(err.Error(), "ran already") {
			return 0, err
		}
	}
	return 0, fmt.Errorf("line %d of this plan ran already (%d time(s), all it may)", l.N, max)
}

// planSpend records a line (or its undo) as spent, before it runs, for the
// plan's life; refuses one spent already. A spend that cannot be written
// refuses: an unrecorded spend is a reusable one.
func planSpend(p *shipPlan, key string) error {
	planMu.Lock()
	defer planMu.Unlock()
	m := planLedgerLoad(planSpentFile)
	now := time.Now()
	for k, exp := range m {
		if t, err := time.Parse(time.RFC3339, exp); err != nil || !t.After(now) {
			delete(m, k)
		}
	}
	full := p.Nonce + ":" + key
	if _, spent := m[full]; spent {
		return fmt.Errorf("line %s of this plan ran already", key)
	}
	m[full] = p.Expires
	if err := planLedgerSave(planSpentFile, m); err != nil {
		return fmt.Errorf("could not record this line's use (%v); refused rather than reusable", err)
	}
	return nil
}

func planVersionSeen(pipeline string) int64 {
	planMu.Lock()
	defer planMu.Unlock()
	var v int64
	_, _ = fmt.Sscan(planLedgerLoad(planVersionsFile)[pipeline], &v)
	return v
}

func planRecordVersion(pipeline string, v int64) error {
	planMu.Lock()
	defer planMu.Unlock()
	m := planLedgerLoad(planVersionsFile)
	var seen int64
	_, _ = fmt.Sscan(m[pipeline], &seen)
	if v > seen {
		m[pipeline] = fmt.Sprint(v)
		return planLedgerSave(planVersionsFile, m)
	}
	return nil
}

// ── line receipts ───────────────────────────────────────────────────────────

const lineReceiptPayloadType = "application/vnd.privatae.line-receipt.v1+json"

// lineReceipt is what a machine signs after it ran a line of a plan: which
// line of which plan, the op and its exact params, what it pushed, and
// whether it and its checks succeeded. The pod relays receipts and cannot
// write one.
type lineReceipt struct {
	V            int             `json:"v"`
	Plan         string          `json:"plan"` // the plan's nonce
	PlanSHA256   string          `json:"plan_sha256"`
	Pipeline     string          `json:"pipeline"`
	Commit       string          `json:"commit"`
	N            int             `json:"n"`
	Step         string          `json:"step"`
	Machine      string          `json:"machine"`
	Key          string          `json:"key"`
	OpSHA256     string          `json:"op_sha256"`
	ParamsSHA256 string          `json:"params_sha256"` // of the params as run, inputs filled
	At           string          `json:"at"`
	Attempt      int             `json:"attempt,omitempty"`
	OK           bool            `json:"ok"`
	Undo         bool            `json:"undo,omitempty"` // this receipt is for the line's undo
	Error        string          `json:"error,omitempty"`
	VerifyError  string          `json:"verify_error,omitempty"`
	Images       []opResultImage `json:"images,omitempty"`
	Verbs        []opVerbResult  `json:"verbs,omitempty"`
	Checks       []opVerbResult  `json:"checks,omitempty"`
}

// failed: the line, or a check after it, did not succeed.
func (r *lineReceipt) failed() bool { return !r.OK || r.VerifyError != "" }

func lineReceiptSign(r lineReceipt) (opSignedReceipt, error) {
	pub, priv, err := loadOrCreateOwnerKey()
	if err != nil {
		return opSignedReceipt{}, err
	}
	r.V, r.Key = 1, base64.StdEncoding.EncodeToString(pub)
	raw, _ := json.Marshal(r)
	return opSignedReceipt{PayloadType: lineReceiptPayloadType, Payload: base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, dssePAE(lineReceiptPayloadType, raw)))}, nil
}

// lineReceiptVerify checks a line receipt against a plan: signed by the key
// the plan names for the machine the receipt names (the key the device
// pinned), of this plan (nonce, sha256, commit), and of the line it names.
func lineReceiptVerify(s opSignedReceipt, p *shipPlan, planSHA string) (*lineReceipt, error) {
	if s.PayloadType != lineReceiptPayloadType {
		return nil, errors.New("not a line receipt")
	}
	raw, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return nil, errors.New("a receipt does not decode")
	}
	var r lineReceipt
	if err := json.Unmarshal(raw, &r); err != nil || r.V != 1 {
		return nil, errors.New("a receipt does not parse")
	}
	want, ok := p.Machines[r.Machine]
	if !ok || r.Key != want {
		return nil, fmt.Errorf("a receipt is signed by a key the plan does not name for %s", r.Machine)
	}
	pub, err := base64.StdEncoding.DecodeString(want)
	sig, err2 := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(pub), dssePAE(lineReceiptPayloadType, raw), sig) {
		return nil, errors.New("a receipt's signature does not verify")
	}
	if r.Plan != p.Nonce || r.PlanSHA256 != planSHA || r.Commit != p.Commit || r.Pipeline != p.Pipeline {
		return nil, errors.New("a receipt is from another plan")
	}
	if r.N < 1 || r.N > len(p.Lines) || p.Lines[r.N-1].Step != r.Step || p.Lines[r.N-1].Machine != r.Machine {
		return nil, errors.New("a receipt names a line the plan does not hold")
	}
	return &r, nil
}

// planInputs fills a line's inputs from the receipts handed with it and
// returns the params text to run with. Each input needs its step's receipt:
// successful, and naming exactly one image (or the image the input names).
func planInputs(p *shipPlan, planSHA string, l *shipPlanLine, receipts []opSignedReceipt) (string, map[string]*lineReceipt, error) {
	byStep := map[string]*lineReceipt{}
	for _, s := range receipts {
		r, err := lineReceiptVerify(s, p, planSHA)
		if err != nil {
			return "", nil, err
		}
		if r.Undo {
			continue
		}
		// A successful receipt of a step wins over a failed attempt of it.
		if prev, ok := byStep[r.Step]; !ok || (prev.failed() && !r.failed()) {
			byStep[r.Step] = r
		}
	}
	// IN ORDER: a line runs only after every line before it succeeded, shown
	// by their signed receipts. So a check cannot run (and fail) before the
	// step it checks, and a failed later line is always one that ran after.
	for i := 1; i < l.N; i++ {
		prior := p.Lines[i-1]
		r, ok := byStep[prior.Step]
		if !ok || r.failed() {
			return "", nil, fmt.Errorf("line %d runs only after line %d (%s) succeeded, and no successful receipt of it came", l.N, i, prior.Step)
		}
	}
	if len(l.Inputs) == 0 {
		return l.Params, byStep, nil
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(l.Params), &params); err != nil {
		return "", nil, errors.New("the line's params do not parse")
	}
	names := make([]string, 0, len(l.Inputs))
	for n := range l.Inputs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		m := planInputRe.FindStringSubmatch(l.Inputs[name])
		r, ok := byStep[m[1]]
		if !ok {
			return "", nil, fmt.Errorf("%s comes from step %s, and no receipt of it came with this line: it runs after that step, never before", name, m[1])
		}
		if r.failed() {
			return "", nil, fmt.Errorf("%s comes from step %s, which did not succeed", name, m[1])
		}
		var hit []opResultImage
		for _, im := range r.Images {
			if m[2] == "" || im.Image == m[2] {
				hit = append(hit, im)
			}
		}
		if len(hit) != 1 {
			return "", nil, fmt.Errorf("step %s's receipt names %d matching images, not one", m[1], len(hit))
		}
		if hit[0].Commit != p.Commit {
			return "", nil, fmt.Errorf("step %s built %s, not the plan's commit %s", m[1], truncate(hit[0].Commit, 12), truncate(p.Commit, 12))
		}
		params[name] = hit[0].Digest
	}
	out, _ := json.Marshal(params)
	return string(out), byStep, nil
}

// planLineMatchesOp: the line runs the held op it names, with params the op
// accepts, and shows exactly the verbs that op declares (with the params
// bound at approval put in), so a device never approves one list while the
// machine runs another.
func planLineMatchesOp(l *shipPlanLine, m *opManifest, params string) error {
	if !m.isAction() {
		return errors.New("a ship plan line runs an action op")
	}
	if m.Name != l.Op {
		return errors.New("the held op is not the one the line names")
	}
	if _, err := checkParams(m, params); err != nil {
		return err
	}
	a, _ := json.Marshal(planVerbsForShow(m, l))
	b, _ := json.Marshal(l.Verbs)
	if string(a) != string(b) {
		return errors.New("the line shows other verbs than the held op declares")
	}
	return nil
}

// planVerbsForShow is the verb list a line shows: the manifest's verbs, with
// each param bound in the line's params put in, and each input left as
// `{{name}}`. The pod builds it, the device shows it, the machine rebuilds it
// from the held op and compares.
func planVerbsForShow(m *opManifest, l *shipPlanLine) []opVerbLine {
	lines, err := opParseVerbs(m)
	if err != nil || len(lines) == 0 {
		return nil
	}
	var params map[string]any
	_ = json.Unmarshal([]byte(l.Params), &params)
	for i, v := range lines {
		for k, val := range v.Args {
			if ref := opParamRefRe.FindStringSubmatch(val); ref != nil {
				if s, ok := params[ref[1]].(string); ok {
					lines[i].Args[k] = s
				}
			}
		}
	}
	return lines
}

// ── the device's own pins of machine keys ───────────────────────────────────

// The device keeps, beside its own key, the key of each machine it may sign a
// plan for — typed in by the person from what the machine printed when they
// pinned this device there (cmdPinDevice prints it), never taken from the pod.
func machinePinsPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "machine_pins.json"), nil
}

func machinePinsLoad() map[string]string {
	out := map[string]string{}
	if p, err := machinePinsPath(); err == nil {
		if raw, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(raw, &out)
		}
	}
	return out
}

func pinMachineKey(host, key string) error {
	host, key = strings.TrimSpace(host), strings.TrimSpace(key)
	if !planHostRe.MatchString(host) {
		return errors.New("usage: privatae-bastion pin-machine <hostname> <key>, as the machine printed it")
	}
	pub, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad machine key (want the base64 key the machine printed)")
	}
	deviceMu.Lock()
	defer deviceMu.Unlock()
	m := machinePinsLoad()
	if prev, ok := m[host]; ok && prev != key {
		return fmt.Errorf("%s is pinned here with another key; unpin it first (unpin-machine %s) if the machine really changed", host, host)
	}
	m[host] = key
	p, err := machinePinsPath()
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := atomicWrite(p, raw); err != nil {
		return err
	}
	_ = os.Chmod(p, 0o600)
	return nil
}

func unpinMachineKey(host string) error {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	m := machinePinsLoad()
	if _, ok := m[host]; !ok {
		return fmt.Errorf("%s is not pinned here", host)
	}
	delete(m, host)
	p, err := machinePinsPath()
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	return atomicWrite(p, raw)
}

// opPlanCtx is what a plan line's run hands its verbs: the plan's commit,
// whether the line adopts the live image, and the line receipts of the
// earlier steps it takes inputs from (verified, planInputs).
type opPlanCtx struct {
	Commit    string
	AdoptLive bool
	Steps     map[string]*lineReceipt
	// beforeVerb records a verb, where it starts and where it is to end, for
	// the line's undo, before it runs; a verb it cannot record does not run.
	beforeVerb func(v opVerbLine, from, to string) error
}

// receiptFor is the image a successful earlier step of this plan built with
// this digest, as an opReceipt, or nil.
func (pc *opPlanCtx) receiptFor(digest string) *opReceipt {
	for _, r := range pc.Steps {
		if r.failed() {
			continue
		}
		for _, im := range r.Images {
			if im.Digest == digest {
				return &opReceipt{Image: im.Image, Digest: im.Digest, Source: opCleanRepoURL(im.Source), Commit: im.Commit}
			}
		}
	}
	return nil
}
