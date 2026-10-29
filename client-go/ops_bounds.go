package main

// ops_bounds.go — what an op_grant bounds besides the params, and the record
// that lets this machine hold it there (bastion 0.58.0).
//
// The bounds text an op_grant carries (ops.go parseBounds) names params by
// their names, which match ^[a-z]. Two keys beginning with "_" bound the RUN
// rather than a param, so they can never collide with one:
//
//	"_window": {"days": ["mon", …, "sun"], "from": "HH:MM", "to": "HH:MM", "tz": "Europe/Berlin"}
//	           applies run only inside this window of the machine's clock, read
//	           in tz (an IANA name, "UTC" when absent). days is optional (every
//	           day when absent). from > to wraps midnight: the window opens on a
//	           listed day and closes the next morning.
//	"_rate":   {"per_day": n, "min_interval_s": s}
//	           at most n applies in any 24 hours, and s seconds between two.
//	           Either may be absent, not both.
//
// Either key may be null, which bounds nothing. Any other "_" key is refused:
// a bound this machine does not enforce would read on the card as a limit the
// person never got. An older box refuses both as "names no param", so a grant
// carrying them fails closed there.
//
// An apply outside the window or the rate is NOT NOW, not refused: nothing
// runs, no use is spent, and it is no strike toward the quarantine — the Host
// asked for something the person allows, at a time they do not. The answer is
// an 'O' frame {"state": "not_now", …} and exit 75 (sysexits EX_TEMPFAIL).
// Identity and argument failures stay refusals, as before.
//
// THE RECORD. ops.json keeps, for each grant, the times of the applies that
// spent a use (the run log, which the rate is counted from, so it holds across
// a restart), the key that approved it, and a MAC over the record under a key
// this machine derives from its own encryption key. A record edited outside
// the bastion — a run removed, a use given back, the approver changed — no
// longer checks out, and the grant is unusable until the person drops it and
// approves again. A grant installed by a bastion older than this one carries
// neither and is unusable too (none were held when it shipped).
//
// THE APPROVER. The device key that signed the approval, or the factor enrolled
// at this console. A grant whose approver is no longer pinned (the device key
// unpinned, the factor re-enrolled) is dead: unpinning a device drops every
// grant it approved, here and in every pairing.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	// The zone database is in the binary: a window's tz reads the same on a
	// machine with no tzdata installed, and a grant is never refused at one
	// box and accepted at another for want of a file.
	_ "time/tzdata"

	"github.com/gorilla/websocket"
)

const (
	opBoundWindow     = "_window"
	opBoundRate       = "_rate"
	opRateMinInterval = 30 * 24 * 60 * 60 // seconds: the longest a grant lives
	// opNotNowExit is the exit an apply that was held to its window or its
	// rate ends with (sysexits.h EX_TEMPFAIL: "try again later").
	opNotNowExit = 75
	opNotNow     = "not_now"
)

var (
	opHHMMRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	opTZRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
	opDays   = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"} // time.Weekday order
	// opNow is the machine's clock as the run gate reads it (a seam for the
	// tests, which move it).
	opNow = time.Now
)

type opWindow struct {
	Days []string `json:"days,omitempty"`
	From string   `json:"from"`
	To   string   `json:"to"`
	TZ   string   `json:"tz,omitempty"`

	loc      *time.Location
	from, to int // minutes past midnight
	day      [7]bool
}

type opRate struct {
	PerDay      *int `json:"per_day,omitempty"`
	MinInterval *int `json:"min_interval_s,omitempty"`
}

// opGrantBounds is the whole of what an op_grant's bounds text says.
type opGrantBounds struct {
	Params map[string]opBound
	Window *opWindow
	Rate   *opRate
}

func strictJSON(raw []byte, into any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func parseOpWindow(raw json.RawMessage) (*opWindow, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var w opWindow
	if err := strictJSON(raw, &w); err != nil {
		return nil, errors.New(`bound "_window": {"days": [mon..sun], "from": "HH:MM", "to": "HH:MM", "tz": "<IANA zone>"}`)
	}
	if !opHHMMRe.MatchString(w.From) || !opHHMMRe.MatchString(w.To) {
		return nil, errors.New(`bound "_window": from and to are 24-hour "HH:MM"`)
	}
	if w.From == w.To {
		return nil, errors.New(`bound "_window": from and to are the same minute, which is no window`)
	}
	hm := func(s string) int { h, _ := strconv.Atoi(s[:2]); m, _ := strconv.Atoi(s[3:]); return h*60 + m }
	w.from, w.to = hm(w.From), hm(w.To)
	if w.Days != nil {
		if len(w.Days) == 0 || len(w.Days) > 7 {
			return nil, errors.New(`bound "_window": days names 1..7 days, or is left out for every day`)
		}
		for _, d := range w.Days {
			i := opDayIndex(d)
			if i < 0 {
				return nil, fmt.Errorf(`bound "_window": %q is not a day (mon, tue, wed, thu, fri, sat, sun)`, d)
			}
			if w.day[i] {
				return nil, fmt.Errorf(`bound "_window": %q is named twice`, d)
			}
			w.day[i] = true
		}
	} else {
		for i := range w.day {
			w.day[i] = true
		}
	}
	tz := w.TZ
	if tz == "" {
		tz = "UTC"
	}
	if !opTZRe.MatchString(tz) || strings.EqualFold(tz, "local") {
		return nil, fmt.Errorf(`bound "_window": tz %q is not an IANA zone name`, w.TZ)
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf(`bound "_window": tz %q is not a zone this machine knows`, w.TZ)
	}
	w.loc = loc
	return &w, nil
}

func opDayIndex(d string) int {
	for i, s := range opDays {
		if s == d {
			return i
		}
	}
	return -1
}

func parseOpRate(raw json.RawMessage) (*opRate, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var r opRate
	if err := strictJSON(raw, &r); err != nil {
		return nil, errors.New(`bound "_rate": {"per_day": n, "min_interval_s": s}`)
	}
	if r.PerDay == nil && r.MinInterval == nil {
		return nil, errors.New(`bound "_rate": names per_day, min_interval_s or both`)
	}
	if r.PerDay != nil && (*r.PerDay < 1 || *r.PerDay > opGrantUsesMax) {
		return nil, fmt.Errorf(`bound "_rate": per_day is 1..%d`, opGrantUsesMax)
	}
	if r.MinInterval != nil && (*r.MinInterval < 1 || *r.MinInterval > opRateMinInterval) {
		return nil, fmt.Errorf(`bound "_rate": min_interval_s is 1..%d`, opRateMinInterval)
	}
	return &r, nil
}

// parseGrantBounds reads an op_grant's bounds text: the params (parseBounds'
// rules, each inside the schema) and the run bounds above.
func parseGrantBounds(m *opManifest, raw string) (*opGrantBounds, error) {
	if len(raw) > opParamsMaxBytes {
		return nil, errors.New("bounds too large")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil || top == nil {
		return nil, errors.New("bounds are not a JSON object of {param: {min, max | values | prefix | fixed}, _window, _rate}")
	}
	out := &opGrantBounds{}
	params := map[string]json.RawMessage{}
	for k, v := range top {
		var err error
		switch {
		case k == opBoundWindow:
			out.Window, err = parseOpWindow(v)
		case k == opBoundRate:
			out.Rate, err = parseOpRate(v)
		case strings.HasPrefix(k, "_"):
			err = fmt.Errorf("bound %q is not one this machine enforces (%s, %s)", k, opBoundWindow, opBoundRate)
		default:
			params[k] = v
		}
		if err != nil {
			return nil, err
		}
	}
	prest, _ := json.Marshal(params)
	p, err := parseParamBounds(m, string(prest))
	if err != nil {
		return nil, err
	}
	out.Params = p
	return out, nil
}

// inside: is t inside the window? A window that wraps midnight belongs to the
// day it opens on.
func (w *opWindow) inside(t time.Time) bool {
	l := t.In(w.loc)
	mins := l.Hour()*60 + l.Minute()
	today := int(l.Weekday())
	if w.from < w.to {
		return w.day[today] && mins >= w.from && mins < w.to
	}
	yesterday := (today + 6) % 7
	return (w.day[today] && mins >= w.from) || (w.day[yesterday] && mins < w.to)
}

// next is when the window next opens after t (zero when it never does, which
// a parsed window cannot be).
func (w *opWindow) next(t time.Time) time.Time {
	l := t.In(w.loc)
	for i := 0; i <= 8; i++ {
		d := l.AddDate(0, 0, i)
		open := time.Date(d.Year(), d.Month(), d.Day(), w.from/60, w.from%60, 0, 0, w.loc)
		if open.After(t) && w.day[int(open.Weekday())] {
			return open
		}
	}
	return time.Time{}
}

func (w *opWindow) words() string {
	days := "every day"
	if len(w.Days) > 0 && len(w.Days) < 7 {
		days = strings.Join(w.Days, ",")
	}
	return fmt.Sprintf("%s %s-%s %s", days, w.From, w.To, w.loc.String())
}

// opNotNowWhy is the run gate on window and rate: "" when an apply may run at
// now, else why not, which bound held it, and when it next could.
func opNotNowWhy(b *opGrantBounds, runs []time.Time, now time.Time) (why, bound string, next time.Time) {
	if b.Window != nil && !b.Window.inside(now) {
		return "outside the approved window (" + b.Window.words() + ")", opBoundWindow, b.Window.next(now)
	}
	if b.Rate == nil || len(runs) == 0 {
		return "", "", time.Time{}
	}
	last := runs[len(runs)-1]
	if b.Rate.MinInterval != nil {
		gap := time.Duration(*b.Rate.MinInterval) * time.Second
		if now.Sub(last) < gap {
			return fmt.Sprintf("the last run was %s ago; the approval keeps %s between runs",
				now.Sub(last).Round(time.Second), gap), opBoundRate, last.Add(gap)
		}
	}
	if b.Rate.PerDay != nil {
		var day []time.Time
		for _, r := range runs {
			if now.Sub(r) < 24*time.Hour {
				day = append(day, r)
			}
		}
		if len(day) >= *b.Rate.PerDay {
			return fmt.Sprintf("%d run(s) in the last 24 hours; the approval allows %d", len(day), *b.Rate.PerDay),
				opBoundRate, day[len(day)-*b.Rate.PerDay].Add(24 * time.Hour)
		}
	}
	return "", "", time.Time{}
}

// sendNotNow answers an apply that was held to its window or rate: recorded,
// never a strike, nothing spent.
func sendNotNow(ws *websocket.Conn, dir string, t *opTerms, why, bound string, next time.Time) {
	out := map[string]any{"state": opNotNow, "grant": t.Nonce, "op": t.Op, "why": why, "bound": bound}
	if !next.IsZero() {
		out["next"] = next.UTC().Format(time.RFC3339)
	}
	dcnAudit(dir, "op_grant_run", 0, t.Op+"@"+t.SHA256[:12], "not now "+t.Nonce[:8]+": "+truncate(why, mgmtAuditWhyMax))
	b, _ := json.Marshal(out)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, opNotNowExit)
}

// ── the record ──────────────────────────────────────────────────────────────

// opGrantMACKey is this machine's key for its grant records, derived from its
// encryption key (which lives in the machine's record, masked from every op,
// and is never silently replaced).
func opGrantMACKey() ([]byte, error) {
	_, priv, err := opEncKey()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("privatae-bastion op-grant record v1\x00"))
	h.Write(priv[:])
	return h.Sum(nil), nil
}

// opGrantRecMAC covers every field of the record, the grant's nonce with it,
// each framed by its length (argsDigest's framing).
func opGrantRecMAC(nonce string, rec *opGrantRec) (string, error) {
	key, err := opGrantMACKey()
	if err != nil {
		return "", err
	}
	parts := []string{"v1", nonce, rec.TermsCanonical, rec.Signature, rec.InstalledAt,
		strconv.Itoa(rec.UsesLeft), rec.Dropped, rec.Approver, strconv.Itoa(len(rec.Runs))}
	parts = append(parts, rec.Runs...)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(argsDigest(parts)))
	return hex.EncodeToString(m.Sum(nil)), nil
}

func opGrantRecSeal(nonce string, rec *opGrantRec) error {
	mac, err := opGrantRecMAC(nonce, rec)
	if err != nil {
		return fmt.Errorf("this machine cannot seal the grant's record: %v", err)
	}
	rec.MAC = mac
	return nil
}

const opGrantTampered = "the record of this grant on this machine does not check out (changed outside the bastion); " +
	"it is held unusable — drop it and approve it again"

// opGrantRecCheck: the record is this machine's own (its MAC), the run log
// reads in order and none of it is in the future, and the uses left are the
// uses granted less the runs logged. Returns the run times.
func opGrantRecCheck(nonce string, rec *opGrantRec, t *opTerms, now time.Time) ([]time.Time, error) {
	if rec.MAC == "" || rec.Approver == "" {
		return nil, errors.New("this grant was installed before this machine kept who approved it and what ran under it; approve it again")
	}
	want, err := opGrantRecMAC(nonce, rec)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(want), []byte(rec.MAC)) {
		return nil, errors.New(opGrantTampered)
	}
	runs := make([]time.Time, 0, len(rec.Runs))
	for _, s := range rec.Runs {
		r, err := time.Parse(time.RFC3339Nano, s)
		if err != nil || r.After(now.Add(deviceClockSkew)) || (len(runs) > 0 && r.Before(runs[len(runs)-1])) {
			return nil, errors.New(opGrantTampered)
		}
		runs = append(runs, r)
	}
	if t != nil && rec.UsesLeft != t.Uses-len(runs) {
		return nil, errors.New(opGrantTampered)
	}
	return runs, nil
}

// ── the approver ────────────────────────────────────────────────────────────

// stepupFactorFingerprint names the factor enrolled at this console for a
// pairing, without its secret: a re-enrolled factor is another one. "" when
// none is enrolled.
func stepupFactorFingerprint(dir string) string {
	f, err := stepupLoad(dir)
	if err != nil || f.SecretB32 == "" || f.EnrolledAt == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("privatae-bastion stepup factor v1\x00" + f.SecretB32 + "\x00" + f.EnrolledAt))
	return hex.EncodeToString(sum[:16])
}

// consumeApprovalKeyed is consumeApproval that also names the key that gave
// the approval: "device:<public key>" or "console:<factor fingerprint>".
func consumeApprovalKeyed(dir, approval, purpose string) (id, key string, err error) {
	if isDeviceApproval(approval) {
		var a deviceApproval
		_ = json.Unmarshal([]byte(strings.TrimSpace(approval)), &a)
		if id, err = consumeApproval(dir, approval, purpose); err != nil {
			return "", "", err
		}
		return id, "device:" + a.Key, nil
	}
	fp := stepupFactorFingerprint(dir)
	if id, err = consumeApproval(dir, approval, purpose); err != nil {
		return "", "", err
	}
	if fp == "" {
		return "", "", errors.New("the approval came from this console with no factor enrolled to keep it under")
	}
	return id, "console:" + fp, nil
}

// opApproverLive: is the key that approved a grant still pinned here?
func opApproverLive(dir, approver string) bool {
	kind, key, _ := strings.Cut(approver, ":")
	switch kind {
	case "device":
		for _, k := range deviceKeys() {
			if k == key && key != "" {
				return true
			}
		}
	case "console":
		return key != "" && key == stepupFactorFingerprint(dir)
	}
	return false
}

func opApproverWords(approver string) string {
	kind, key, _ := strings.Cut(approver, ":")
	if kind == "device" {
		return "approval device " + truncate(key, 12)
	}
	return "this console's factor " + truncate(key, 12)
}

// ── taking grants back ──────────────────────────────────────────────────────

// opsDropWhere drops every held grant in one pairing that match says to,
// sealing each record again. Returns the nonces dropped.
func opsDropWhere(dcnDir, why string, match func(nonce string, rec *opGrantRec) bool) ([]string, error) {
	opsMu.Lock()
	defer opsMu.Unlock()
	f := opsLoad(dcnDir)
	var dropped []string
	for nonce, rec := range f.Grants {
		if rec.Dropped != "" || !match(nonce, &rec) {
			continue
		}
		rec.Dropped = opNow().UTC().Format(time.RFC3339) + " " + why
		rec.UsesLeft = 0
		// A record that can no longer be sealed is still dropped: the drop is
		// what makes it unusable, and an unsealed record is unusable anyway.
		_ = opGrantRecSeal(nonce, &rec)
		f.Grants[nonce] = rec
		dropped = append(dropped, nonce)
	}
	if len(dropped) == 0 {
		return nil, nil
	}
	return dropped, opsSave(dcnDir, f)
}

// opsDropApprovedBy drops, in every pairing, the grants a device key approved
// (the key is being unpinned). Returns how many.
func opsDropApprovedBy(approver string) int {
	cfgs, err := loadPairings()
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range cfgs {
		if c == nil || c.dcnDir() == "" {
			continue
		}
		d, _ := opsDropWhere(c.dcnDir(), "its approving key was unpinned", func(_ string, rec *opGrantRec) bool {
			return rec.Approver == approver
		})
		n += len(d)
	}
	return n
}

// op_grant_drop <grant nonce | all>: the Host (or the app, through it) takes
// a grant back. A tighten (writes.go opTightens): never held by the
// quarantine, never waiting on an approval. A grant not held here is already
// gone, which is what was asked for.
func handleOpGrantDrop(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		opFail(ws, "op_grant_drop: need <grant> or all")
		return
	}
	which := strings.TrimSpace(args[0])
	dropped, err := opsDropWhere(dir, "taken back by the host", func(nonce string, _ *opGrantRec) bool {
		return which == "all" || nonce == which
	})
	if err != nil {
		opFail(ws, "op_grant_drop: could not record the drop: "+err.Error())
		return
	}
	if dropped == nil {
		dropped = []string{}
	}
	for _, n := range dropped {
		dcnAudit(dir, "op_grant_drop", 0, truncate(n, 8), "dropped by the host")
	}
	b, _ := json.Marshal(map[string]any{"state": "dropped", "dropped": dropped})
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}
