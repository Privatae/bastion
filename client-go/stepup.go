package main

// Second factor ON THE BOX: the host must not be able to elevate or bypass
// the second factor. The host's own TOTP secret lives in the pod;
// code running in the pod could compute a valid code, and a pod that merely
// FORWARDS a code the user typed could attach it to something else. So both
// the secret AND the confirmation live here:
//
//	pod → stepup_request <purpose> <details>   (over the mgmt lane; no code)
//	box: checks that details really produce that purpose, stores the request
//	     PENDING, shows nothing to the pod but an id
//	user, ON THIS MACHINE: `privatae-bastion approvals` prints each pending
//	     request in plain words (folder, ops, moves); `privatae-bastion approve`
//	     asks for the code from the authenticator enrolled HERE, verifies +
//	     burns it, and records {approval id, purpose}
//	pod → stepup_status <request id>   → approved → puts `approval` into the
//	     terms, signs, syncs / applies
//	box: on dcn_grant_sync / dcn_plan_apply, recomputes the purpose from the
//	     signed terms and requires a matching, live approval
//
// The pod never sees the code and never chooses what the user confirms: the
// words on the screen come from details the box has verified against the
// purpose it will later enforce. A compromised pod can still SIGN anything —
// it holds the entity key — but this box will not enforce it.
//
// The purpose is a plain string both sides derive the same way (never JSON
// canonicalization across two languages):
//	store grant: dcn_store_grant|<server>|<root>|<mask sorted ,>|<excludes sorted ,>|<sweep>|<sensitive>|ttl:<days>
//	move plan:   dcn_move_plan|<store_id>|<plan_id>|<root>|<archive>|<sha256 of "from\tto\n" lines>
//
// Not enrolled here = today's behavior (the pod verifies its own factor).

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	stepupDigits      = 6
	stepupPeriod      = 30
	stepupDrift       = 1 // ± windows for clock skew (RFC 6238 §5.2)
	stepupApprovalTTL = 24 * time.Hour
	stepupRequestTTL  = 24 * time.Hour
)

var stepupMu sync.Mutex // serializes verify+burn, approvals and requests per process

type stepupFile struct {
	SecretB32   string `json:"secret_b32"`
	EnrolledAt  string `json:"enrolled_at,omitempty"`
	LastCounter int64  `json:"last_counter"`
}

type stepupApproval struct {
	Purpose string `json:"purpose"`
	At      string `json:"at"`
	Used    bool   `json:"used"`
}

// stepupRequest is what the pod asked the user to confirm, in the box's words.
type stepupRequest struct {
	Purpose  string         `json:"purpose"`
	Details  map[string]any `json:"details"`
	At       string         `json:"at"`
	State    string         `json:"state"` // pending | approved | denied
	Approval string         `json:"approval,omitempty"`
	// Delivered: the approval id was handed to the pod once. The same ask
	// again after that is a new act (a new request), not a spent id.
	Delivered bool `json:"delivered,omitempty"`
}

func stepupPath(dir string) string    { return filepath.Join(dir, "stepup.json") }
func approvalsPath(dir string) string { return filepath.Join(dir, "approvals.json") }
func requestsPath(dir string) string  { return filepath.Join(dir, "stepup_requests.json") }

func stepupLoad(dir string) (*stepupFile, error) {
	raw, err := os.ReadFile(stepupPath(dir))
	if err != nil {
		return nil, err
	}
	var f stepupFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func stepupSave(dir string, f *stepupFile) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(stepupPath(dir), raw)
}

// stepupEnrolled reports whether this pairing holds a CONFIRMED second factor.
func stepupEnrolled(dir string) bool {
	if dir == "" {
		return false
	}
	f, err := stepupLoad(dir)
	return err == nil && f.SecretB32 != "" && f.EnrolledAt != ""
}

// ── TOTP (RFC 6238, HMAC-SHA1) — mirrors the host's implementation exactly ──

func hotp(secret []byte, counter int64) string {
	mac := hmac.New(sha1.New, secret)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(counter))
	mac.Write(b[:])
	h := mac.Sum(nil)
	off := h[len(h)-1] & 0x0f
	code := (binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

func b32decode(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(s)
}

// stepupMatchedCounter returns the window a code matches (±drift), or -1.
func stepupMatchedCounter(secretB32, code string, at time.Time) int64 {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != stepupDigits {
		return -1
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return -1
		}
	}
	raw, err := b32decode(secretB32)
	if err != nil {
		return -1
	}
	now := at.Unix() / stepupPeriod
	hit := int64(-1)
	for w := int64(-stepupDrift); w <= stepupDrift; w++ {
		if hmac.Equal([]byte(hotp(raw, now+w)), []byte(code)) {
			hit = now + w // no early return: keep the timing flat
		}
	}
	return hit
}

// stepupVerifyAndBurn accepts a code once: the matched window must be newer
// than the last accepted one, and is recorded.
func stepupVerifyAndBurn(dir, code string, at time.Time) (int64, error) {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	f, err := stepupLoad(dir)
	if err != nil || f.SecretB32 == "" || f.EnrolledAt == "" {
		return -1, fmt.Errorf("no second factor enrolled on this machine (privatae-bastion stepup-enroll)")
	}
	c := stepupMatchedCounter(f.SecretB32, code, at)
	if c < 0 {
		return -1, fmt.Errorf("code refused")
	}
	if c <= f.LastCounter {
		return -1, fmt.Errorf("code already used")
	}
	f.LastCounter = c
	if err := stepupSave(dir, f); err != nil {
		return -1, err
	}
	return c, nil
}

// ── purposes — the same strings the host builds ──

// purposeBad reports a component that would collide with the purpose's own
// delimiters — "|" between fields, "," between list entries, "\t"/"\n" between
// move parts. Such terms are refused outright (a pod could otherwise sign
// excludes [".env,.ssh"] under an approval the user read as two patterns).
func purposeBad(fields []string, entries []string) error {
	for _, f := range fields {
		if strings.ContainsAny(f, "|\t\n") {
			return fmt.Errorf("a term contains a reserved character (|)")
		}
	}
	for _, e := range entries {
		if strings.ContainsAny(e, "|,\t\n") {
			return fmt.Errorf("a list entry contains a reserved character (| or ,)")
		}
	}
	return nil
}

func purposeForGrant(t *dcnTerms) (string, error) {
	mask := append([]string(nil), t.Mask...)
	excl := append([]string(nil), t.Excludes...)
	sort.Strings(mask)
	sort.Strings(excl)
	if err := purposeBad([]string{t.Server, t.Root, t.Sweep}, append(append([]string(nil), mask...), excl...)); err != nil {
		return "", err
	}
	sens := "false"
	if t.Sensitive {
		sens = "true"
	}
	return "dcn_store_grant|" + t.Server + "|" + t.Root + "|" + strings.Join(mask, ",") + "|" +
		strings.Join(excl, ",") + "|" + t.Sweep + "|" + sens + "|ttl:" + strconv.Itoa(t.TTLDays), nil
}

func purposeForPlan(p *dcnPlanTerms) (string, error) {
	if err := purposeBad([]string{p.Root, p.Archive}, nil); err != nil {
		return "", err
	}
	h := sha256.New()
	for _, m := range p.Moves {
		if strings.ContainsAny(m.From+m.To, "\t\n") {
			return "", fmt.Errorf("a move path contains a reserved character")
		}
		h.Write([]byte(m.From + "\t" + m.To + "\n"))
	}
	return fmt.Sprintf("dcn_move_plan|%d|%d|%s|%s|%s", p.StoreID, p.PlanID, p.Root, p.Archive,
		hex.EncodeToString(h.Sum(nil))), nil
}

// criticalActionTerms is a platform CRITICAL_ACTION awaiting the user's second
// factor — capability_grant, constitutional_*, frontend_deploy, entity_*.
//
// Unlike the dcn kinds, the box is NOT the enforcer here: the platform executes
// the action after it sees an approval. So the box's whole job is to make the
// approval bind to one specific action, and to show the user the same words the
// platform will act on. Summary is hashed rather than carried in the purpose
// because it is free text and the purpose is a |-delimited field list.
type criticalActionTerms struct {
	Action   string // the CRITICAL_ACTIONS type
	EntityID int64  // the entity the action runs against
	ActionID string // outbox action id
	Target   string // short subject of the action (host name, capability, route)
	Summary  string // the one-line the user reads — bound by hash below
}

func purposeForCriticalAction(t *criticalActionTerms) (string, error) {
	if err := purposeBad([]string{t.Action, t.ActionID, t.Target}, nil); err != nil {
		return "", err
	}
	if t.Action == "" || t.ActionID == "" {
		return "", fmt.Errorf("a critical action needs an action type and an action id")
	}
	// Every field the user reads is bound: the three plain ones directly, the
	// free-text summary by digest. A pod that shows one sentence and asks the
	// platform to run something else cannot produce a matching purpose.
	h := sha256.Sum256([]byte(t.Summary))
	return fmt.Sprintf("critical_action|%s|%d|%s|%s|%s", t.Action, t.EntityID, t.ActionID,
		t.Target, hex.EncodeToString(h[:])), nil
}

// ── the caps ceiling for a step-up ─────────────────────────────────────────

// stepupOpFamily is the capability family a step-up op must be gated on.
//
// A step-up is not a capability of its own. It is the approval step of another
// one, and purposeFromDetails below already enumerates exactly which: a DCN
// store grant or move plan, a root shell, a model download, or a platform
// critical action. So the ceiling for raising one is the ceiling of the thing
// being approved — a pairing that may not do DCN work may not ask the user to
// authorize DCN work either.
//
// Gating all of them as ONE family would be wrong in both directions, which is
// why this exists rather than a line in opFamily. Too loose: a pairing granted
// "dcn" could raise a ROOT SHELL prompt, which is the session family's to give.
// Too tight, and this is the one that would have broken the fleet: a pairing
// granted "session" and not "dcn" could no longer raise the step-up that
// session:root REQUIRES (session.go:412-417), and one granted "models" could no
// longer raise the one model:pull requires (modelswap.go:796). The
// families are independently grantable on purpose — see the note in opFamily
// about why "model:" was kept out of "inference" — so folding the approval step
// into any single one of them silently disarms the others.
//
// critical_action is the one kind that maps to capsFamilyNone rather than to a
// family, and deliberately: the box is NOT the enforcer there (see
// criticalActionTerms above — the platform executes once it sees an approval),
// so there is no capability of this machine's being authorized and no family
// that could honestly be named. Holding a verified grant at all, which
// capsAllowIn has already checked by this point, is the whole ceiling.
//
// An input this cannot classify also returns capsFamilyNone, and that is safe
// rather than a hole: the classifiable set here is exactly purposeFromDetails's
// set, and stepupNewRequest calls purposeFromDetails FIRST and refuses anything
// outside it, so an unclassifiable request creates nothing. Deferring to the
// handler keeps its own error messages ("bad base64", "unknown request kind")
// instead of turning every malformed frame into a caps refusal that says
// nothing about what was actually wrong.
func stepupOpFamily(op, dir string, args []string) string {
	switch op {
	case "stepup_request":
		if len(args) < 2 {
			return capsFamilyNone
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args[1]))
		if err != nil {
			return capsFamilyNone
		}
		var details map[string]any
		if err := json.Unmarshal(raw, &details); err != nil {
			return capsFamilyNone
		}
		return stepupDetailsFamily(details)
	case "stepup_status":
		// The ceiling is the one the request was RAISED under, read back from
		// this pairing's own store. An id that is not there is left to the
		// handler, which answers "expired" — refusing instead would turn this
		// into an oracle for which ids exist.
		if dir == "" || len(args) < 1 {
			return capsFamilyNone
		}
		stepupMu.Lock()
		r, ok := requestsLoad(dir)[strings.TrimSpace(args[0])]
		stepupMu.Unlock()
		if !ok {
			return capsFamilyNone
		}
		return stepupDetailsFamily(r.Details)
	}
	return capsFamilyNone
}

// stepupDetailsFamily is stepupKindFamily for a whole request: a `mgmt_op`
// ask is gated on the family of the op it would approve (writes.go), read
// from the details — an op in no family stays in no family and capsAllowIn
// refuses it, and a directive (self-update, contain, mirror) is the anchor's
// alone, so a member asking for its approval is refused at the ask.
func stepupDetailsFamily(details map[string]any) string {
	kind, _ := details["kind"].(string)
	if kind != "mgmt_op" {
		return stepupKindFamily(kind)
	}
	op, _ := details["op"].(string)
	if isDirectiveOp(op) {
		return capsFamilyAnchor
	}
	return opFamily(op)
}

// stepupKindFamily maps a request kind to the family of the op it authorizes.
// The kinds are purposeFromDetails's; an unknown one gets capsFamilyNone, which
// the handler then refuses on its own as "unknown request kind".
func stepupKindFamily(kind string) string {
	switch kind {
	case "dcn_store_grant", "dcn_move_plan":
		return "dcn"
	case "session_root":
		return "session"
	case "model_pull":
		return modelGateOpFamily
	case reachKind:
		return "services"
	case coderGrantKind:
		return "harness"
	case opKindRun, opKindGrant:
		return opsFamily
	}
	return capsFamilyNone
}

// purposeFromDetails rebuilds the purpose from the plain details the pod sent —
// the words the user will read are the words the box will enforce, or the
// request is refused.
func purposeFromDetails(d map[string]any) (string, error) {
	strs := func(v any) []string {
		var out []string
		if l, ok := v.([]any); ok {
			for _, x := range l {
				if s, ok := x.(string); ok {
					out = append(out, s)
				}
			}
		}
		return out
	}
	str := func(k string) string { s, _ := d[k].(string); return s }
	num := func(k string) int64 {
		switch v := d[k].(type) {
		case float64:
			return int64(v)
		case string:
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
		return 0
	}
	switch str("kind") {
	case "dcn_store_grant":
		sens, _ := d["sensitive"].(bool)
		return purposeForGrant(&dcnTerms{Server: str("server"), Root: str("root"), Mask: strs(d["mask"]),
			Excludes: strs(d["excludes"]), Sweep: str("sweep"), Sensitive: sens, TTLDays: int(num("ttl_days"))})
	case "dcn_move_plan":
		var moves []dcnMove
		if l, ok := d["moves"].([]any); ok {
			for _, x := range l {
				if m, ok := x.(map[string]any); ok {
					from, _ := m["from"].(string)
					to, _ := m["to"].(string)
					moves = append(moves, dcnMove{From: from, To: to})
				}
			}
		}
		if len(moves) == 0 || len(moves) > dcnPlanMaxMoves {
			return "", fmt.Errorf("plan details carry no moves")
		}
		return purposeForPlan(&dcnPlanTerms{StoreID: num("store_id"), PlanID: num("plan_id"),
			Root: str("root"), Archive: str("archive"), Moves: moves})
	case "session_root":
		return purposeForSessionRoot(str("server"), str("session_id"))
	case reachKind:
		var mirrors []mirrorSource
		if l, ok := d["mirrors"].([]any); ok {
			for _, x := range l {
				if m, ok := x.(map[string]any); ok {
					u, _ := m["url"].(string)
					r, _ := m["repo"].(string)
					mirrors = append(mirrors, mirrorSource{URL: u, Repo: r})
				}
			}
		}
		return purposeForReach(&reachTerms{Server: str("server"), Slot: str("slot"),
			Subject: str("subject"), TTLDays: int(num("ttl_days")), Mirrors: mirrors})
	case coderGrantKind:
		return purposeForCoderGrant(&coderTerms{Server: str("server"), Subject: str("subject"),
			Engines: strs(d["engines"]), Max: int(num("max")), TTLDays: int(num("ttl_days"))})
	case "critical_action":
		return purposeForCriticalAction(&criticalActionTerms{
			Action: str("action"), EntityID: num("entity_id"), ActionID: str("action_id"),
			Target: str("target"), Summary: str("summary")})
	case "model_pull":
		// See modelswap.go. The byte ceiling is part of the purpose, so the
		// number the user reads below is the number the download is held to.
		return purposeForModelPull(str("model"), str("role"), num("max_bytes"), str("replaces"))
	case opKindRun, opKindGrant:
		// An op the host wrote (ops.go): the details ARE the terms' fields,
		// and the purpose is the one the box recomputes at apply / install.
		t := &opTerms{Kind: str("kind"), Op: str("op"), Version: str("version"), SHA256: str("sha256"),
			Server: str("server"), Privilege: str("privilege"), Params: str("params"), Bounds: str("bounds"),
			Changes: str("changes_sha256"), Expires: str("expires"), Uses: int(num("uses"))}
		if t.Kind == opKindRun {
			return purposeForOpRun(t)
		}
		return purposeForOpGrant(t)
	case "mgmt_op":
		// One run of a write on this machine (writes.go): the op, this
		// machine, and the sha256 of exactly the args it will run with. The
		// server is checked against THIS box here rather than only at run
		// time, so a request for another machine is refused at the ask.
		op, server := str("op"), str("server")
		if op == "" || strings.ContainsAny(op, "|\n") {
			return "", fmt.Errorf("mgmt_op details name no op")
		}
		if server == "" || strings.ContainsAny(server, "|\n ") {
			return "", fmt.Errorf("mgmt_op details name no server")
		}
		var args []string
		if _, ok := d["args"]; ok {
			args = strs(d["args"])
		}
		return mgmtOpPurpose(op, server, args), nil
	}
	return "", fmt.Errorf("unknown request kind")
}

// argWordsMax is how much of one argument the card prints whole.
const argWordsMax = 2000

// argWords is one argument as the person reads it: whole up to argWordsMax
// bytes, then its full length and sha256 so the part they cannot see is at
// least named.
func argWords(a string) string {
	if len(a) <= argWordsMax {
		return a
	}
	sum := sha256.Sum256([]byte(a))
	return a[:argWordsMax] + fmt.Sprintf(" …[%d bytes in all, sha256 %s]", len(a), hex.EncodeToString(sum[:8]))
}

// describeRequest renders a request in the user's words — from details the box
// has already verified against the purpose it will enforce.
// clean strips control characters from pod-supplied text before it is printed —
// a note with an embedded newline must not be able to fake a "never:" line.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		// C0, DEL and C1 (0x80-0x9F — U+009B is a terminal control prefix that
		// could redraw what the person is reading).
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
}

func describeRequest(r stepupRequest) string {
	d := r.Details
	str := func(k string) string { s, _ := d[k].(string); return clean(s) }
	strs := func(k string) []string {
		var out []string
		if l, ok := d[k].([]any); ok {
			for _, x := range l {
				if s, ok := x.(string); ok {
					out = append(out, clean(s))
				}
			}
		}
		return out
	}
	switch str("kind") {
	case "dcn_store_grant":
		var b strings.Builder
		fmt.Fprintf(&b, "Your host asks to reach the folder  %s  on %s\n", str("root"), str("server"))
		fmt.Fprintf(&b, "  allowed: %s\n", strings.Join(strs("mask"), ", "))
		if ex := strs("excludes"); len(ex) > 0 {
			fmt.Fprintf(&b, "  never:   %s\n", strings.Join(ex, ", "))
		}
		if sw := str("sweep"); sw != "" {
			fmt.Fprintf(&b, "  index refresh: %s\n", sw)
		}
		if ttl, ok := d["ttl_days"].(float64); ok && ttl > 0 {
			fmt.Fprintf(&b, "  for: %d days\n", int(ttl))
		}
		if n := str("display_name"); n != "" {
			fmt.Fprintf(&b, "  shown as: %s\n", n)
		}
		// The pod's note is not shown: free text nothing binds, beside terms
		// the signature does bind, is the one thing this card must not carry.
		b.WriteString("  Your files stay here; the host gets an index and reads on request.")
		return b.String()
	case "dcn_move_plan":
		var b strings.Builder
		moves, _ := d["moves"].([]any)
		archive := str("archive")
		into := 0
		for _, x := range moves {
			if m, ok := x.(map[string]any); ok {
				to, _ := m["to"].(string)
				if archive != "" && (to == archive || strings.HasPrefix(to, archive+"/")) {
					into++
				}
			}
		}
		fmt.Fprintf(&b, "Your host asks to MOVE %d item(s) inside  %s", len(moves), str("root"))
		if t := str("title"); t != "" {
			fmt.Fprintf(&b, "  (%s)", t)
		}
		b.WriteString("\n")
		if archive != "" {
			fmt.Fprintf(&b, "  %d go into the archive folder %s/ — nothing is deleted; you empty it by hand\n", into, archive)
		}
		for i, x := range moves {
			if i == 12 {
				fmt.Fprintf(&b, "  … and %d more\n", len(moves)-12)
				break
			}
			if m, ok := x.(map[string]any); ok {
				from, _ := m["from"].(string)
				to, _ := m["to"].(string)
				fmt.Fprintf(&b, "  %s  →  %s\n", clean(from), clean(to))
			}
		}
		return strings.TrimRight(b.String(), "\n")
	case reachKind:
		var b strings.Builder
		fmt.Fprintf(&b, "The host  %s  asks to reach the server  %s  on this machine (%s)\n",
			clean(str("subject")), clean(str("slot")), clean(str("server")))
		if ttl, ok := d["ttl_days"].(float64); ok && ttl > 0 {
			fmt.Fprintf(&b, "  for: %d days\n", int(ttl))
		}
		if l, ok := d["mirrors"].([]any); ok && len(l) > 0 {
			b.WriteString("  and lets THIS machine fetch, over your own connection, into that server:\n")
			for _, x := range l {
				if m, ok := x.(map[string]any); ok {
					u, _ := m["url"].(string)
					r, _ := m["repo"].(string)
					fmt.Fprintf(&b, "    %s  →  %s\n", clean(u), clean(r))
				}
			}
		}
		b.WriteString("  The server has no network; this lets that host alone reach it over its tunnel.")
		return b.String()
	case "session_root":
		var b strings.Builder
		fmt.Fprintf(&b, "Your host asks to open a ROOT shell on this machine (%s)\n", str("server"))
		fmt.Fprintf(&b, "  session: %s\n", str("session_id"))
		if n := str("note"); n != "" {
			fmt.Fprintf(&b, "  why: %s\n", n)
		}
		b.WriteString("  Approving opens ONE root terminal, recorded to a transcript here. If you did not ask for it, deny.")
		return b.String()
	case "critical_action":
		var b strings.Builder
		fmt.Fprintf(&b, "Your host asks you to APPROVE a critical action:  %s\n", str("action"))
		if t := str("target"); t != "" {
			fmt.Fprintf(&b, "  on: %s\n", t)
		}
		if s := str("summary"); s != "" {
			fmt.Fprintf(&b, "  %s\n", s)
		}
		// Said plainly, because this is the one kind the box does not enforce:
		// approving here lets the PLATFORM run it. The user should treat an
		// action they did not ask for as the signal it is.
		b.WriteString("  Approving lets the platform run this now. If you did not ask for it, deny.")
		return b.String()
	case "model_pull":
		// Everything printed here is bound into the purpose
		// (purposeForModelPull), so the words the user reads are the words the
		// box enforces — including the size, which is a CEILING the download is
		// stopped at, not an estimate.
		var b strings.Builder
		fmt.Fprintf(&b, "Your host asks to DOWNLOAD a model onto this machine:  %s\n", str("model"))
		role := str("role")
		if role == "embed" {
			role = "embedding (searching your own words)"
		} else if role == "generate" {
			role = "text generation"
		}
		fmt.Fprintf(&b, "  for: %s\n", role)
		if n, ok := d["max_bytes"].(float64); ok && n > 0 {
			fmt.Fprintf(&b, "  size: up to %s, written to this machine's disk\n", modelBytesWords(int64(n)))
		}
		if r := str("replaces"); r != "" {
			fmt.Fprintf(&b, "  meant to replace: %s (still here afterwards — removing it is a separate ask)\n", r)
		}
		if n := str("note"); n != "" {
			fmt.Fprintf(&b, "  why: %s\n", n)
		}
		b.WriteString("  Approving downloads it ONCE, at that size or less. If you did not ask for it, deny.")
		return b.String()
	case opKindRun, opKindGrant:
		var b strings.Builder
		once := str("kind") == opKindRun
		if once {
			fmt.Fprintf(&b, "Your host asks to run its op  %s %s  ONCE on %s\n", str("op"), str("version"), str("server"))
		} else {
			fmt.Fprintf(&b, "Your host asks to run its op  %s %s  on %s FROM NOW ON\n", str("op"), str("version"), str("server"))
		}
		if sm := str("summary"); sm != "" {
			fmt.Fprintf(&b, "  what it does: %s\n", sm)
		}
		fmt.Fprintf(&b, "  as: %s\n", str("privilege"))
		if eff := strs("effects"); len(eff) > 0 {
			fmt.Fprintf(&b, "  may change: %s\n", strings.Join(eff, ", "))
		}
		if once {
			fmt.Fprintf(&b, "  with: %s\n", argWords(str("params")))
			if d := str("dry_run"); d != "" {
				fmt.Fprintf(&b, "  the dry run showed:\n%s\n", argWords(d))
			}
		} else {
			fmt.Fprintf(&b, "  within: %s\n", argWords(str("bounds")))
			if n, _ := d["uses"].(float64); n > 0 {
				fmt.Fprintf(&b, "  up to %d runs\n", int(n))
			}
		}
		fmt.Fprintf(&b, "  until: %s\n", str("expires"))
		fmt.Fprintf(&b, "  identity: sha256 %s\n", str("sha256"))
		if once {
			fmt.Fprintf(&b, "  the changes above, as a whole: sha256 %s\n", str("changes_sha256"))
			b.WriteString("  Approving applies exactly what the dry run showed, once — any other change lands nothing. If you did not ask for it, deny.")
		} else {
			b.WriteString("  Approving lets the host run it within these bounds until then, without asking again. If you did not ask for it, deny.")
		}
		return b.String()
	case "mgmt_op":
		// Every argument, whole, one per line: what the person reads IS what
		// is bound. A long one is shown to argWordsMax bytes and then named by
		// its length and digest, so a harmless start cannot hide a tail. The
		// pod's note is deliberately NOT shown: it is free text nothing binds,
		// and a sentence beside the arguments that the arguments do not carry
		// is the one thing this card must not have.
		var b strings.Builder
		fmt.Fprintf(&b, "Your host asks to run  %s  on %s\n", str("op"), str("server"))
		args := strs("args")
		if len(args) == 0 {
			b.WriteString("  with no arguments\n")
		}
		for i, a := range args {
			fmt.Fprintf(&b, "  arg %d: %s\n", i+1, argWords(a))
		}
		b.WriteString("  Approving runs it ONCE, with exactly these arguments. If you did not ask for it, deny.")
		return b.String()
	}
	return "(unknown request)"
}

// ── approvals — live 24h, bound to a purpose ──

func approvalsLoad(dir string) map[string]stepupApproval {
	out := map[string]stepupApproval{}
	raw, err := os.ReadFile(approvalsPath(dir))
	if err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	for id, a := range out { // forget expired ones
		if t, err := time.Parse(time.RFC3339, a.At); err != nil || time.Since(t) > stepupApprovalTTL {
			delete(out, id)
		}
	}
	return out
}

func approvalsSave(dir string, m map[string]stepupApproval) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(approvalsPath(dir), raw)
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// stepupIssueApproval verifies the code and records an approval for purpose.
// The code is spent only if the approval lands (stepupIssueLocked).
func stepupIssueApproval(dir, code, purpose string) (string, error) {
	if strings.TrimSpace(purpose) == "" {
		return "", fmt.Errorf("purpose required")
	}
	stepupMu.Lock()
	defer stepupMu.Unlock()
	return stepupIssueLocked(dir, code, purpose, nil)
}

// stepupLandingHook runs inside stepupApproveRequest after the approval is
// saved and before the request is read again, so the suite can answer the
// request from "another process" at exactly that point. Nothing outside tests
// sets it.
var stepupLandingHook func()

// stepupIssueLocked is the code check and the approval, under stepupMu (the
// caller holds it). A CODE IS SPENT ONLY WHEN THE APPROVAL LANDS. It is
// recorded as spent BEFORE the approval exists, so no crash can ever leave an
// approval standing on a code that still works; and if anything after that
// fails (the approval cannot be saved, or land refuses), the approval is
// withdrawn and the code is given back, unless something newer was spent
// meanwhile (another process). land, when not nil, finishes the act the
// approval is for; its error withdraws it.
func stepupIssueLocked(dir, code, purpose string, land func(approval string) error) (string, error) {
	f, err := stepupLoad(dir)
	if err != nil || f.SecretB32 == "" || f.EnrolledAt == "" {
		return "", fmt.Errorf("no second factor enrolled on this machine (privatae-bastion stepup-enroll)")
	}
	c := stepupMatchedCounter(f.SecretB32, code, time.Now())
	if c < 0 {
		return "", fmt.Errorf("code refused")
	}
	if c <= f.LastCounter {
		return "", fmt.Errorf("code already used")
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	prev := f.LastCounter
	f.LastCounter = c
	if err := stepupSave(dir, f); err != nil {
		return "", err
	}
	giveBack := func() {
		if cur, err := stepupLoad(dir); err == nil && cur.LastCounter == c {
			cur.LastCounter = prev
			_ = stepupSave(dir, cur)
		}
	}
	m := approvalsLoad(dir)
	m[id] = stepupApproval{Purpose: purpose, At: time.Now().UTC().Format(time.RFC3339)}
	if err := approvalsSave(dir, m); err != nil {
		giveBack()
		return "", err
	}
	if land != nil {
		if err := land(id); err != nil {
			am := approvalsLoad(dir)
			delete(am, id)
			_ = approvalsSave(dir, am)
			giveBack()
			return "", err
		}
	}
	return id, nil
}

// stepupCheckApproval — is `id` a live, unused approval for exactly this purpose?
func stepupCheckApproval(dir, id, purpose string) error {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	a, ok := approvalsLoad(dir)[id]
	if id == "" || !ok {
		return fmt.Errorf("this machine requires your approval for this: none was given here (privatae-bastion approvals)")
	}
	if a.Used {
		return fmt.Errorf("this approval was already used")
	}
	if a.Purpose != purpose {
		return fmt.Errorf("approval is for something else (purpose mismatch)")
	}
	return nil
}

// stepupConsumeApproval is stepupCheckApproval and the burn under ONE lock:
// the approval is marked used and saved before the caller acts, so two
// workers handed the same id cannot both pass. A store that cannot be written
// refuses, the same way the device ledger does (device.go).
func stepupConsumeApproval(dir, id, purpose string) error {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	m := approvalsLoad(dir)
	a, ok := m[id]
	if id == "" || !ok {
		return fmt.Errorf("this machine requires your approval for this: none was given here (privatae-bastion approvals)")
	}
	if a.Used {
		return fmt.Errorf("this approval was already used")
	}
	if a.Purpose != purpose {
		return fmt.Errorf("approval is for something else (purpose mismatch)")
	}
	a.Used = true
	m[id] = a
	if err := approvalsSave(dir, m); err != nil {
		return fmt.Errorf("could not record this approval's use (%v); refused rather than reusable", err)
	}
	return nil
}

// stepupMarkUsed burns an approval after the action it covered succeeded (a
// plan apply, or the gated install of a grant — see handleDcnGrantSync).
func stepupMarkUsed(dir, id string) {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	m := approvalsLoad(dir)
	if a, ok := m[id]; ok {
		a.Used = true
		m[id] = a
		_ = approvalsSave(dir, m)
	}
}

// stepupGate is the wall grant-sync and plan-apply call. Nothing to do on a
// LOCAL box with no factor enrolled (the pairing is the authorization on a
// person's own machine); on an anchored box, or once a factor is enrolled, the
// terms' approval must check out — from this console or the person's device
// (device.go boxApproval). "Unenrolled passes" is gone for anchored boxes:
// they refuse, naming the fix.
func stepupGate(dir, approval, purpose string) error {
	if !approvalRequired(dir) {
		return nil
	}
	return boxApproval(dir, approval, purpose)
}

// ── requests — what the user is asked to confirm, kept here, shown here ──

func requestsLoad(dir string) map[string]stepupRequest {
	out := map[string]stepupRequest{}
	raw, err := os.ReadFile(requestsPath(dir))
	if err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	for id, r := range out {
		if t, err := time.Parse(time.RFC3339, r.At); err != nil || time.Since(t) > stepupRequestTTL {
			delete(out, id)
		}
	}
	return out
}

func requestsSave(dir string, m map[string]stepupRequest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(requestsPath(dir), raw)
}

// stepupNewRequest records a pending request after proving the details match
// the purpose. Returns the existing pending id for a repeated identical ask.
func stepupNewRequest(dir, purpose string, details map[string]any) (string, error) {
	got, err := purposeFromDetails(details)
	if err != nil {
		return "", err
	}
	// A mgmt_op ask names the machine it is for; on THIS box's console it has
	// to be this box (the device, which files the same details for another
	// machine, checks nothing here — device.go). Checked at the ask, not in
	// purposeFromDetails, for exactly that reason.
	if kind, _ := details["kind"].(string); kind == "mgmt_op" {
		server, _ := details["server"].(string)
		if hn, _ := os.Hostname(); hn != "" && server != hn {
			return "", fmt.Errorf("this request is for server '%s', this box is '%s'", server, hn)
		}
	}
	if got != purpose {
		return "", fmt.Errorf("request details do not match the purpose (the words would not be what is enforced)")
	}
	stepupMu.Lock()
	defer stepupMu.Unlock()
	m := requestsLoad(dir)
	// A refusal wins over anything else for the same purpose, whatever order
	// the map is walked in: two passes, deny first.
	for _, r := range m {
		if r.Purpose == purpose && r.State == "denied" {
			return "", fmt.Errorf("you refused this on this machine; it cannot be asked again for 24h")
		}
	}
	for id, r := range m {
		if r.Purpose == purpose && r.State == "pending" {
			return id, nil
		}
		// An approved ask whose id was never handed out is the tap the pod
		// missed while it was away: the same request, answered approved by
		// the handler. Once delivered, the same ask is a new act.
		if r.Purpose == purpose && r.State == "approved" && !r.Delivered {
			return id, nil
		}
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	m[id] = stepupRequest{Purpose: purpose, Details: details,
		At: time.Now().UTC().Format(time.RFC3339), State: "pending"}
	if err := requestsSave(dir, m); err != nil {
		return "", err
	}
	return id, nil
}

// stepupApproveRequest — the user, on this machine, with the code: verify,
// issue the approval, mark the request approved, all under one hold of
// stepupMu. The code is spent only if the request ends up approved: a request
// answered meanwhile, or a store that cannot be written, gives it back
// (stepupIssueLocked).
func stepupApproveRequest(dir, id, code string) (string, error) {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	r, ok := requestsLoad(dir)[id]
	if !ok || r.State != "pending" {
		return "", fmt.Errorf("no pending request %s", id)
	}
	approval, err := stepupIssueLocked(dir, code, r.Purpose, func(approval string) error {
		if stepupLandingHook != nil {
			stepupLandingHook()
		}
		// Read again: another process (the service, an Administrator
		// terminal) shares these files but not this lock, and may have
		// answered the request since. Denied meanwhile: the approval must
		// not stand.
		m := requestsLoad(dir)
		cur := m[id]
		if cur.State != "pending" {
			return fmt.Errorf("request is no longer pending (%s)", cur.State)
		}
		cur.State, cur.Approval = "approved", approval
		m[id] = cur
		return requestsSave(dir, m)
	})
	if err != nil {
		return "", err
	}
	// A code was accepted, on whichever lane: the tray's count of wrong codes
	// starts again (approvalpipe.go).
	pipeThrottleReset(dir)
	dcnAudit(dir, "stepup_approve", 0, "", "approved: "+r.Purpose)
	return approval, nil
}

func stepupDenyRequest(dir, id string) error {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	m := requestsLoad(dir)
	r, ok := m[id]
	if !ok {
		return fmt.Errorf("no request %s", id)
	}
	if r.State != "pending" {
		return fmt.Errorf("request is %s, not pending", r.State)
	}
	r.State = "denied"
	m[id] = r
	dcnAudit(dir, "stepup_deny", 0, "", "denied: "+r.Purpose)
	return requestsSave(dir, m)
}

// ── the mgmt ops: stepup_request <purpose> <details_b64>, stepup_status <id> ──

func handleStepupRequest(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 2 {
		sendMgmt(ws, 'R', []byte("stepup_request: need <purpose> <details_b64>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if !stepupEnrolled(dir) {
		sendMgmt(ws, 'R', []byte("no second factor enrolled on this machine (privatae-bastion stepup-enroll)\n"))
		sendMgmtExit(ws, 126)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args[1]))
	if err != nil {
		sendMgmt(ws, 'R', []byte("bad base64\n"))
		sendMgmtExit(ws, 1)
		return
	}
	var details map[string]any
	if err := json.Unmarshal(raw, &details); err != nil || details == nil {
		sendMgmt(ws, 'R', []byte("bad details json\n"))
		sendMgmtExit(ws, 1)
		return
	}
	id, err := stepupNewRequest(dir, args[0], details)
	if err != nil {
		dcnAudit(dir, "stepup_request", 0, "", "refused: "+err.Error())
		sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
		sendMgmtExit(ws, 126)
		return
	}
	if approval, ok := stepupHandOut(dir, id); ok {
		out, _ := json.Marshal(map[string]any{"state": "approved", "request": id, "approval": approval})
		sendMgmt(ws, 'O', out)
		sendMgmtExit(ws, 0)
		return
	}
	dcnAudit(dir, "stepup_request", 0, "", "pending: "+args[0])
	out, _ := json.Marshal(map[string]any{"state": "pending", "request": id,
		"next": "on that machine: privatae-bastion approvals, then privatae-bastion approve " + id[:8]})
	sendMgmt(ws, 'O', out)
	sendMgmtExit(ws, 0)
}

// stepupHandOut gives an approved request's approval id to the pod ONCE
// (marks the request delivered). ("", false) for anything else.
func stepupHandOut(dir, id string) (string, bool) {
	stepupMu.Lock()
	defer stepupMu.Unlock()
	m := requestsLoad(dir)
	r, ok := m[id]
	if !ok || r.State != "approved" || r.Delivered || r.Approval == "" {
		return "", false
	}
	r.Delivered = true
	m[id] = r
	if err := requestsSave(dir, m); err != nil {
		return "", false
	}
	return r.Approval, true
}

func handleStepupStatus(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 1 {
		sendMgmt(ws, 'R', []byte("stepup_status: need <request_id>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	stepupMu.Lock()
	r, ok := requestsLoad(dir)[strings.TrimSpace(args[0])]
	stepupMu.Unlock()
	if !ok {
		out, _ := json.Marshal(map[string]any{"state": "expired"})
		sendMgmt(ws, 'O', out)
		sendMgmtExit(ws, 0)
		return
	}
	res := map[string]any{"state": r.State}
	if r.State == "approved" {
		if approval, ok := stepupHandOut(dir, strings.TrimSpace(args[0])); ok {
			res["approval"] = approval
		} else {
			res["state"] = "delivered" // handed out already; not repeated
		}
	}
	out, _ := json.Marshal(res)
	sendMgmt(ws, 'O', out)
	sendMgmtExit(ws, 0)
}

// ── CLI ──

func stepupPairing(host string) (*Config, error) {
	cfgs, err := loadPairings()
	if err != nil {
		return nil, err
	}
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("not paired yet — run `privatae-bastion pair <token>` first")
	}
	switch {
	case host != "":
		cfg, err := findPairing(cfgs, host)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			return nil, fmt.Errorf("no pairing matches --host '%s' — paired hosts:\n  %s",
				host, strings.Join(hostNames(cfgs), "\n  "))
		}
		return cfg, nil
	case len(cfgs) == 1:
		return cfgs[0], nil
	}
	return nil, fmt.Errorf("%d hosts are paired — say which one with --host <host>\npaired hosts:\n  %s",
		len(cfgs), strings.Join(hostNames(cfgs), "\n  "))
}

// enrolConsole and enrolServiceState are seams so the suite can drive
// --console-only on any machine; nothing outside tests assigns them.
var (
	enrolConsole      = stdioIsConsole
	enrolServiceState = func() string {
		return enrolServiceStateRefusal(runtime.GOOS, systemService.installed, systemService.authority, systemService.err)
	}
)

// enrolServiceStateRefusal says why this process's state is not the system
// service's, or "" when it is. --console-only enrols only into the service's
// state: anywhere else, the secret would sit in a profile the signed-in
// person's own processes can read.
//
//   - Windows and macOS: the service is installed and this process administers
//     the machine, which is when adoptSystemServiceState points the state
//     directory at the service's (sysservice.go).
//   - Linux: root, whose state the systemd unit reads (deploy/install.sh).
func enrolServiceStateRefusal(goos string, installed, authority bool, err error) string {
	if err != nil {
		return "cannot tell whether this machine runs the bastion as a system service (" + err.Error() + ")"
	}
	if !authority {
		return "this process does not administer the machine, so its state is not the service's; " + adminHowToFor(goos)
	}
	if (goos == "windows" || goos == "darwin") && !installed {
		return "the bastion is not installed as this machine's service yet (privatae-bastion service install)"
	}
	return ""
}

// privatae-bastion stepup-enroll [--host <host>] [--rotate] [--console-only]
//
// --console-only is how an installer enrols in its one elevated step: the
// secret is shown only on the console this elevated process owns, never
// written to a file or a pipe its output may have been sent to, and saved only
// in the system service's state. Both are checked BEFORE a secret exists.
func cmdStepupEnroll(host string, rotate, consoleOnly bool) error {
	if consoleOnly {
		if !enrolConsole() {
			return fmt.Errorf("stepup-enroll --console-only shows the secret only on a console, and this one's input or output " +
				"goes to a file or a pipe — nothing was enrolled; run it in a terminal window")
		}
		if why := enrolServiceState(); why != "" {
			return fmt.Errorf("stepup-enroll --console-only enrols only into the system service's state: %s — nothing was enrolled", why)
		}
	}
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	if dir == "" {
		return fmt.Errorf("cannot open this pairing's state directory")
	}
	if stepupEnrolled(dir) && !rotate {
		fmt.Println("a second factor is already enrolled for", cfg.HostName, "on this machine (use --rotate to replace it)")
		return nil
	}
	var secret [20]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	b32 := strings.TrimRight(base32.StdEncoding.EncodeToString(secret[:]), "=")
	hn, _ := os.Hostname()
	label := url.PathEscape("Privatae NAC:" + hn + " for " + cfg.HostName)
	uri := "otpauth://totp/" + label + "?secret=" + b32 + "&issuer=" + url.QueryEscape("Privatae NAC") +
		"&digits=6&period=30"
	fmt.Println("Add this second factor to your authenticator app — it lives on THIS machine only:")
	fmt.Println()
	// Scan beats retype. The URI and the key stay printed below it: a QR is
	// useless over a serial console, in a scrollback paste, or on a terminal
	// without the block glyphs, and this is the one moment in the whole flow
	// where being unable to enrol strands the user with no second factor.
	if code, err := qrTerminal(uri); err == nil {
		fmt.Print(code)
		fmt.Println()
		fmt.Println("  point your authenticator app at the square above")
		fmt.Println()
	}
	fmt.Println("  or open this link:  " + uri)
	fmt.Println()
	fmt.Println("  or enter the key by hand:  " + b32)
	fmt.Println()
	fmt.Print("Enter a code from the app to confirm: ")
	reader := bufio.NewReader(os.Stdin)
	code, _ := reader.ReadString('\n')
	if stepupMatchedCounter(b32, code, time.Now()) < 0 {
		return fmt.Errorf("that code did not match — nothing enrolled; run the command again")
	}
	f := &stepupFile{SecretB32: b32, EnrolledAt: time.Now().UTC().Format(time.RFC3339), LastCounter: -1}
	if err := stepupSave(dir, f); err != nil {
		return err
	}
	fmt.Println("enrolled. From now on, your host can only reach a folder or move files on this machine after")
	fmt.Println("you approve the request HERE: `privatae-bastion approvals` shows what it asks, `privatae-bastion approve` confirms it.")
	return nil
}

func sortedPending(m map[string]stepupRequest) []string {
	var ids []string
	for id, r := range m {
		if r.State == "pending" {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return m[ids[i]].At < m[ids[j]].At })
	return ids
}

// privatae-bastion approvals [--host <host>]
func cmdStepupApprovals(host string) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	if !stepupEnrolled(dir) {
		fmt.Println("no second factor enrolled on this machine for", cfg.HostName, "— run `privatae-bastion stepup-enroll` first")
		return nil
	}
	stepupMu.Lock()
	m := requestsLoad(dir)
	stepupMu.Unlock()
	ids := sortedPending(m)
	if len(ids) == 0 {
		fmt.Println("nothing waiting for your approval on this machine (for", cfg.HostName+")")
		return nil
	}
	for _, id := range ids {
		fmt.Printf("[%s]  asked %s\n%s\n\n", id[:8], m[id].At, describeRequest(m[id]))
	}
	fmt.Println("approve one:  privatae-bastion approve <id>      deny one:  privatae-bastion deny <id>")
	return nil
}

func findRequest(m map[string]stepupRequest, prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "", fmt.Errorf("which request? run `privatae-bastion approvals`")
	}
	var hit string
	for id, r := range m {
		if r.State == "pending" && strings.HasPrefix(id, prefix) {
			if hit != "" {
				return "", fmt.Errorf("'%s' matches more than one request; give more of the id", prefix)
			}
			hit = id
		}
	}
	if hit == "" {
		return "", fmt.Errorf("no pending request starts with '%s'", prefix)
	}
	return hit, nil
}

// privatae-bastion approve [--host <host>] <request id>
func cmdStepupApprove(host, prefix string) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	if !stepupEnrolled(dir) {
		return fmt.Errorf("no second factor enrolled on this machine — run `privatae-bastion stepup-enroll` first")
	}
	stepupMu.Lock()
	m := requestsLoad(dir)
	stepupMu.Unlock()
	id, err := findRequest(m, prefix)
	if err != nil {
		return err
	}
	fmt.Println(describeRequest(m[id]))
	fmt.Println()
	fmt.Print("Approve this? Enter the code from your authenticator (or leave empty to cancel): ")
	reader := bufio.NewReader(os.Stdin)
	code, _ := reader.ReadString('\n')
	if strings.TrimSpace(code) == "" {
		fmt.Println("cancelled — nothing approved")
		return nil
	}
	if _, err := stepupApproveRequest(dir, id, code); err != nil {
		return err
	}
	fmt.Println("approved. Your host picks this up on its next check-in (within a minute) — or click Approve again on your Host.")
	return nil
}

// privatae-bastion deny [--host <host>] <request id>
func cmdStepupDeny(host, prefix string) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	stepupMu.Lock()
	m := requestsLoad(dir)
	stepupMu.Unlock()
	id, err := findRequest(m, prefix)
	if err != nil {
		return err
	}
	if err := stepupDenyRequest(dir, id); err != nil {
		return err
	}
	fmt.Println("denied — the host is told on its next check-in")
	return nil
}
