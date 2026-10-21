package main

// service_reach.go — the SERVICE REACH GRANT: which host may reach which
// server in this machine's service slot.
//
// A slot server has no network (service.go); the host's tunnel forward is the
// only way in. Holding the `services` caps family used to be enough to use
// that forward, so every host granted `services` here reached EVERY server on
// the machine, and the person never said which. A reach grant says it: host X
// may reach server S on this machine until a set date. The host signs it, the
// person approves it, and the forward checks it on EVERY connection
// (default-deny — no grant, no connection).
//
// It is built exactly like a DCN store grant (dcn.go), and shares its file,
// its lock and its pinned key: the same <pairing dir>/grants.json, a `reach`
// map beside `stores`, grantsMu around every load→modify→save, and the entity
// key pinned per pairing by pinVerifyKey. Two things a store grant does not
// do, and this one does:
//   - its KIND is checked, so a store grant (or any other signed record)
//     cannot be offered as a reach grant; and
//   - its SUBJECT is enforced: the grant names the host it is for, the box
//     installs it only from that host's own pairing, and the forward honours
//     it only for that pairing. A grant for host A never lets host B in.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const reachKind = "service_reach_grant"

// reachDroppedMax caps the dropped-because-stopped list each pairing reports.
const reachDroppedMax = 100

// reachTerms is parsed FROM the verified canonical bytes — never from anything else.
type reachTerms struct {
	Kind     string `json:"kind"`
	Server   string `json:"server"`  // this machine's hostname
	Slot     string `json:"slot"`    // the server's slot name (service.go)
	Subject  string `json:"subject"` // the host this grant is for — the pairing's host name
	Expires  string `json:"expires"`
	TTLDays  int    `json:"ttl_days,omitempty"`
	Approval string `json:"approval,omitempty"` // this box's approval, when the person confirmed it here
	// Mirrors (0.38.0, service_mirror.go): the upstream repos this machine may
	// fetch — over its OWN connection — into this server, each an https URL and
	// the repo it lands in. Part of what the person approves; empty = none.
	Mirrors []mirrorSource `json:"mirrors,omitempty"`
}

// mirrorSource is one approved upstream: fetch URL into server repo Repo.
type mirrorSource struct {
	URL  string `json:"url"`
	Repo string `json:"repo"`
}

// verifySignedRecord checks one record's signature under the pinned key and
// returns the exact bytes that were signed. The kind-specific verifiers parse
// those bytes and check their own kind; nothing else is trusted.
func verifySignedRecord(pinnedKeyB64 string, rec dcnGrantRec) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(pinnedKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad pinned verify key")
	}
	canonical, err := base64.StdEncoding.DecodeString(rec.TermsCanonical)
	if err != nil {
		return nil, fmt.Errorf("bad canonical terms")
	}
	sig, err := base64.StdEncoding.DecodeString(rec.Signature)
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sig) {
		return nil, fmt.Errorf("signature does not verify")
	}
	return canonical, nil
}

// verifySignedUnexpired is verifySignedRecord plus the rule every signed
// record here shares: it states an expiry, and it has not passed. Returns the
// signed bytes for the caller to parse and check the KIND of.
func verifySignedUnexpired(pinnedKeyB64 string, rec dcnGrantRec) ([]byte, error) {
	canonical, err := verifySignedRecord(pinnedKeyB64, rec)
	if err != nil {
		return nil, err
	}
	var e struct {
		Expires string `json:"expires"`
	}
	if err := json.Unmarshal(canonical, &e); err != nil {
		return nil, fmt.Errorf("signed terms unparsable")
	}
	exp, err := time.Parse(time.RFC3339, e.Expires)
	if err != nil {
		return nil, fmt.Errorf("grant states no expiry (open-ended terms are refused)")
	}
	if !exp.After(time.Now()) {
		return nil, fmt.Errorf("grant expired")
	}
	return canonical, nil
}

// reachVerifyRec verifies a reach grant: signature, KIND, a stated and future
// expiry, and a well-formed slot and subject. Re-run on every connection.
func reachVerifyRec(pinnedKeyB64 string, rec dcnGrantRec) (*reachTerms, error) {
	canonical, err := verifySignedRecord(pinnedKeyB64, rec)
	if err != nil {
		return nil, err
	}
	var t reachTerms
	if err := json.Unmarshal(canonical, &t); err != nil {
		return nil, fmt.Errorf("signed terms unparsable")
	}
	if t.Kind != reachKind {
		return nil, fmt.Errorf("signed record is a %q, not a %s", t.Kind, reachKind)
	}
	exp, err := time.Parse(time.RFC3339, t.Expires)
	if err != nil {
		return nil, fmt.Errorf("grant states no expiry (open-ended terms are refused)")
	}
	if !exp.After(time.Now()) {
		return nil, fmt.Errorf("grant expired")
	}
	if !serviceNameRe.MatchString(t.Slot) {
		return nil, fmt.Errorf("grant names no valid server")
	}
	if strings.TrimSpace(t.Subject) == "" || strings.ContainsAny(t.Subject, "|\n ") {
		return nil, fmt.Errorf("grant names no host")
	}
	if why := mirrorListRefusal(t.Mirrors); why != "" {
		return nil, fmt.Errorf("grant names a bad mirror list: %s", why)
	}
	return &t, nil
}

// purposeForReach is what the person approves for one reach grant, built the
// same way on the host (nac_stepup.purpose_for_reach_terms).
func purposeForReach(t *reachTerms) (string, error) {
	if why := mirrorListRefusal(t.Mirrors); why != "" {
		return "", fmt.Errorf("%s", why)
	}
	entries := make([]string, 0, len(t.Mirrors))
	for _, m := range t.Mirrors {
		entries = append(entries, m.URL+">"+m.Repo)
	}
	sort.Strings(entries)
	if err := purposeBad([]string{t.Server, t.Slot, t.Subject}, entries); err != nil {
		return "", err
	}
	p := reachKind + "|" + t.Server + "|" + t.Slot + "|" + t.Subject + "|ttl:" + strconv.Itoa(t.TTLDays)
	// Appended only when there are mirrors, so a grant without them is
	// byte-for-byte the 0.36.0 purpose.
	if len(entries) > 0 {
		p += "|mirrors:" + strings.Join(entries, ",")
	}
	return p, nil
}

// handleServiceGrantSync installs one signed reach grant pushed by the host.
// Payload (b64 JSON): {grant_id, terms_canonical, signature, verify_pubkey}.
func handleServiceGrantSync(ws *websocket.Conn, dir string, args []string) {
	refuse := func(id int64, why string) {
		dcnAudit(dir, "service_grant_sync", id, "", "refused: "+why)
		sendMgmt(ws, 'R', []byte("service_grant_sync refused: "+why+"\n"))
		sendMgmtExit(ws, 126)
	}
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("service_grant_sync: need <payload_b64>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args[0]))
	if err != nil {
		sendMgmt(ws, 'R', []byte("bad base64\n"))
		sendMgmtExit(ws, 1)
		return
	}
	var payload struct {
		GrantID        int64  `json:"grant_id"`
		TermsCanonical string `json:"terms_canonical"`
		Signature      string `json:"signature"`
		VerifyPubkey   string `json:"verify_pubkey"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || payload.GrantID <= 0 {
		sendMgmt(ws, 'R', []byte("bad payload json\n"))
		sendMgmtExit(ws, 1)
		return
	}
	grantsMu.Lock()
	defer grantsMu.Unlock()
	f, err := dcnLoadFile(dir)
	if err != nil {
		sendMgmt(ws, 'R', []byte("grant store unreadable\n"))
		sendMgmtExit(ws, 1)
		return
	}
	self := ""
	if a := mgmtAccountOf(ws); a != nil {
		self = a.self
	}
	if _, why := pinVerifyKey(f, self, payload.VerifyPubkey); why != "" {
		refuse(payload.GrantID, why)
		return
	}
	rec := dcnGrantRec{TermsCanonical: payload.TermsCanonical, Signature: payload.Signature}
	terms, err := reachVerifyRec(f.VerifyPubkey, rec)
	if err != nil {
		refuse(payload.GrantID, "grant does not verify: "+err.Error())
		return
	}
	if hn, _ := os.Hostname(); terms.Server == "" || terms.Server != hn {
		refuse(payload.GrantID, fmt.Sprintf("grant is for server '%s', this box is '%s'", terms.Server, hn))
		return
	}
	// A host installs only its OWN reach: the subject must be the pairing this
	// lane belongs to. A host cannot put a grant here that lets another host in.
	if self == "" || terms.Subject != self {
		refuse(payload.GrantID, fmt.Sprintf("grant is for host '%s', not the host that sent it", terms.Subject))
		return
	}
	gated := false
	if prev, held := f.Reach[fmt.Sprint(payload.GrantID)]; !held || prev.Signature != rec.Signature {
		if approvalRequired(dir) {
			purpose, perr := purposeForReach(terms)
			if perr != nil {
				refuse(payload.GrantID, "grant refused: "+perr.Error())
				return
			}
			if err := boxApproval(dir, terms.Approval, purpose); err != nil {
				refuse(payload.GrantID, err.Error())
				return
			}
			if terms.TTLDays <= 0 {
				refuse(payload.GrantID, "grant states no duration (ttl_days)")
				return
			}
			if exp, err := time.Parse(time.RFC3339, terms.Expires); err != nil ||
				exp.After(time.Now().Add(time.Duration(terms.TTLDays+1)*24*time.Hour)) {
				refuse(payload.GrantID, "grant expiry exceeds the approved duration")
				return
			}
			gated = true
		}
	}
	if f.Reach == nil {
		f.Reach = map[string]dcnGrantRec{}
	}
	f.Reach[fmt.Sprint(payload.GrantID)] = rec
	if err := dcnSaveFile(dir, f); err != nil {
		sendMgmt(ws, 'R', []byte("grant persist failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if gated {
		markApprovalUsed(dir, terms.Approval) // one approval installs it once; a revoke is final
	}
	dcnAudit(dir, "service_grant_sync", payload.GrantID, terms.Slot, "installed for "+terms.Subject)
	b, _ := json.Marshal(map[string]any{"state": "ok", "grant_id": payload.GrantID,
		"slot": terms.Slot, "subject": terms.Subject, "expires": terms.Expires})
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// reachDropLocked removes one reach grant; the caller holds grantsMu.
func reachDropLocked(dir string, id int64, why string) (bool, error) {
	f, err := dcnLoadFile(dir)
	if err != nil {
		return false, err
	}
	key := strconv.FormatInt(id, 10)
	if _, ok := f.Reach[key]; !ok {
		return false, nil
	}
	delete(f.Reach, key)
	if err := dcnSaveFile(dir, f); err != nil {
		return true, err
	}
	dcnAudit(dir, "service_grant_drop", id, "", why)
	return true, nil
}

// handleServiceGrantDrop — the host revoked a reach grant: forget it here, now.
// A tighten needs no verification: it can only remove reach.
func handleServiceGrantDrop(ws *websocket.Conn, dir string, args []string) {
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("service_grant_drop: need <grant_id>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil {
		sendMgmt(ws, 'R', []byte("service_grant_drop: bad grant_id\n"))
		sendMgmtExit(ws, 1)
		return
	}
	grantsMu.Lock()
	present, err := reachDropLocked(dir, id, "host-revoked")
	grantsMu.Unlock()
	if err != nil {
		sendMgmt(ws, 'R', []byte("grant drop failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	b, _ := json.Marshal(map[string]any{"state": "ok", "grant_id": id, "dropped": present})
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// serviceReachAllowed is the forward's per-connection wall: "" when pairing
// `self` holds a verified, unexpired reach grant for slot `slot` on this
// machine, else the refusal. Read from disk and re-verified every time — a
// revoke or an expiry takes effect on the next connection.
func serviceReachAllowed(dir, self, slot string) string {
	if dir == "" || self == "" {
		return "no pairing identity for this connection"
	}
	grantsMu.Lock()
	f, err := dcnLoadFile(dir)
	grantsMu.Unlock()
	if err != nil {
		return "grant store unreadable"
	}
	if f.VerifyPubkey == "" {
		return "no entity key pinned on this box yet (default-deny)"
	}
	hn, _ := os.Hostname()
	for _, rec := range f.Reach {
		t, err := reachVerifyRec(f.VerifyPubkey, rec)
		if err != nil {
			continue
		}
		if t.Slot == slot && t.Subject == self && t.Server == hn {
			return ""
		}
	}
	return "no reach grant for server '" + slot + "' held by " + self + " (default-deny)"
}

// reachDropForSlot removes every reach grant naming `slot` from every pairing's
// grant file on this machine — called when the server in that slot is stopped
// (serviceDown). Returns how many were dropped. Each host is told by its next
// heartbeat reconcile; its Host sees the grant gone and revokes its row.
func reachDropForSlot(slot string) int {
	cfgs, err := loadPairings()
	if err != nil {
		return 0
	}
	n := 0
	grantsMu.Lock()
	defer grantsMu.Unlock()
	for _, c := range cfgs {
		dir := c.dcnDir()
		if dir == "" {
			continue
		}
		f, err := dcnLoadFile(dir)
		if err != nil || len(f.Reach) == 0 {
			continue
		}
		changed := false
		for key, rec := range f.Reach {
			var t reachTerms
			raw, err := base64.StdEncoding.DecodeString(rec.TermsCanonical)
			if err != nil || json.Unmarshal(raw, &t) != nil || t.Slot != slot {
				continue
			}
			delete(f.Reach, key)
			changed = true
			n++
			if id, err := strconv.ParseInt(key, 10, 64); err == nil {
				dcnAudit(dir, "service_grant_drop", id, slot, "server stopped")
				f.ReachDropped = append(f.ReachDropped, id)
			}
		}
		if changed {
			if len(f.ReachDropped) > reachDroppedMax {
				f.ReachDropped = f.ReachDropped[len(f.ReachDropped)-reachDroppedMax:]
			}
			_ = dcnSaveFile(dir, f)
		}
	}
	return n
}

// droppedReachGrants is the enforcing report's list of reach grants this
// pairing lost because their server was stopped — the host revokes those rows.
func droppedReachGrants(dir string) []int64 {
	out := []int64{}
	if dir == "" {
		return out
	}
	if f, err := dcnLoadFile(dir); err == nil {
		out = append(out, f.ReachDropped...)
	}
	return out
}

// heldReachGrants is what the enforcing report tells the host this pairing
// holds: {grant_id, signature}, so it can re-sync what is missing or stale.
func heldReachGrants(dir string) []map[string]any {
	out := []map[string]any{}
	if dir == "" {
		return out
	}
	f, err := dcnLoadFile(dir)
	if err != nil {
		return out
	}
	ids := make([]int64, 0, len(f.Reach))
	for k := range f.Reach {
		if id, err := strconv.ParseInt(k, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		out = append(out, map[string]any{"grant_id": id, "signature": f.Reach[strconv.FormatInt(id, 10)].Signature})
	}
	return out
}

// maybeReconcileReach is maybeReconcileGrants (reconcile.go) for reach grants:
// the heartbeat reply may carry {"service_grants": {"grants": [{grant_id,
// signature}]}}. Held but unlisted on TWO consecutive replies → a revoke this
// box missed → dropped. ABSENT field → no instruction (never "drop all").
func maybeReconcileReach(heartbeatResponse []byte, dir string) []int64 {
	if dir == "" {
		return nil
	}
	var hb struct {
		ServiceGrants *struct {
			Grants []struct {
				GrantID   int64  `json:"grant_id"`
				Signature string `json:"signature"`
			} `json:"grants"`
		} `json:"service_grants"`
	}
	if json.Unmarshal(heartbeatResponse, &hb) != nil || hb.ServiceGrants == nil {
		return nil
	}
	expected := map[string]bool{}
	for _, g := range hb.ServiceGrants.Grants {
		if g.GrantID > 0 {
			expected[strconv.FormatInt(g.GrantID, 10)] = true
		}
	}
	grantsMu.Lock()
	defer grantsMu.Unlock()
	f, err := dcnLoadFile(dir)
	if err != nil {
		return nil
	}
	var dropped []int64
	for key := range f.Reach {
		ukey := "reach:" + key // its own counter namespace, apart from store ids
		if expected[key] {
			clearUnlisted(dir, ukey)
			continue
		}
		if bumpUnlisted(dir, ukey) < dropAfterUnlisted {
			continue
		}
		if id, err := strconv.ParseInt(key, 10, 64); err == nil {
			if ok, err := reachDropLocked(dir, id, "reconcile: not granted by host"); err == nil && ok {
				dropped = append(dropped, id)
			}
		}
		clearUnlisted(dir, ukey)
	}
	sort.Slice(dropped, func(i, j int) bool { return dropped[i] < dropped[j] })
	if len(dropped) > 0 {
		fmt.Printf("reconcile: dropped %d reach grant(s) the host no longer lists: %v\n", len(dropped), dropped)
	}
	return dropped
}
