package main

// coder_grant.go — the STANDING CODER GRANT on an anchored box.
//
// Before coder mode, every harness run on an anchored box spent a fresh
// approval from the person (harness.go harnessGate). A Host that places 20
// coding runs on a machine cannot ask its owner 20 times, so the person
// approves ONCE: this host may start coder runs here, of these engines, at most
// this many at a time, until this date. `privatae-bastion coders drop` (or the
// host's revoke, coder_grant_drop) takes it back.
//
// Built exactly like the service reach grant (service_reach.go): the same
// <pairing dir>/grants.json (a `coder` map), grantsMu, the pinned entity key,
// the KIND checked, the SUBJECT enforced (a host installs only its own grant),
// and the box's own approval spent once at install.

import (
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

const coderGrantKind = "coder_grant"

// coderTerms is parsed FROM the verified canonical bytes — never from anything else.
type coderTerms struct {
	Kind     string   `json:"kind"`
	Server   string   `json:"server"`
	Subject  string   `json:"subject"`
	Engines  []string `json:"engines"`
	Max      int      `json:"max"`
	Expires  string   `json:"expires"`
	TTLDays  int      `json:"ttl_days,omitempty"`
	Approval string   `json:"approval,omitempty"`
}

// coderVerifyRec verifies one coder grant: signature, kind, a stated future
// expiry, and well-formed terms. Re-run on every use.
func coderVerifyRec(pinnedKeyB64 string, rec dcnGrantRec) (*coderTerms, error) {
	canonical, err := verifySignedUnexpired(pinnedKeyB64, rec)
	if err != nil {
		return nil, err
	}
	var t coderTerms
	if err := json.Unmarshal(canonical, &t); err != nil {
		return nil, fmt.Errorf("signed terms unparsable")
	}
	if t.Kind != coderGrantKind {
		return nil, fmt.Errorf("signed record is a %q, not a %s", t.Kind, coderGrantKind)
	}
	if strings.TrimSpace(t.Subject) == "" || strings.ContainsAny(t.Subject, "|\n ") {
		return nil, fmt.Errorf("grant names no host")
	}
	if t.Max < 1 || t.Max > 100 {
		return nil, fmt.Errorf("grant max must be 1-100")
	}
	if len(t.Engines) == 0 {
		return nil, fmt.Errorf("grant names no engine")
	}
	for _, e := range t.Engines {
		if !isCoderEngine(e) {
			return nil, fmt.Errorf("grant names an engine that is not a coding engine")
		}
	}
	return &t, nil
}

// purposeForCoderGrant is what the person approves, the same string the host
// builds: coder_grant|<server>|<subject>|engines:<sorted,comma>|max:<n>|ttl:<days>.
func purposeForCoderGrant(t *coderTerms) (string, error) {
	eng := append([]string(nil), t.Engines...)
	sort.Strings(eng)
	if err := purposeBad([]string{t.Server, t.Subject}, eng); err != nil {
		return "", err
	}
	return coderGrantKind + "|" + t.Server + "|" + t.Subject + "|engines:" + strings.Join(eng, ",") +
		"|max:" + strconv.Itoa(t.Max) + "|ttl:" + strconv.Itoa(t.TTLDays), nil
}

// coderGrantFor is the valid coder grant pairing `self` holds on this machine
// (the newest one when there are several), or the refusal.
func coderGrantFor(dir, self string) (*coderTerms, string) {
	if dir == "" || self == "" {
		return nil, "no pairing identity for this request"
	}
	grantsMu.Lock()
	f, err := dcnLoadFile(dir)
	grantsMu.Unlock()
	if err != nil {
		return nil, "grant store unreadable"
	}
	if f.VerifyPubkey == "" || len(f.Coder) == 0 {
		return nil, "no standing coder grant for " + self + " on this machine (the person approves one once; `privatae-bastion coders drop` revokes it)"
	}
	hn, _ := os.Hostname()
	var best *coderTerms
	bestID := int64(-1)
	for k, rec := range f.Coder {
		t, err := coderVerifyRec(f.VerifyPubkey, rec)
		if err != nil || t.Subject != self || t.Server != hn {
			continue
		}
		id, _ := strconv.ParseInt(k, 10, 64)
		if id > bestID {
			best, bestID = t, id
		}
	}
	if best == nil {
		return nil, "no valid standing coder grant for " + self + " on this machine"
	}
	return best, ""
}

// handleCoderGrantSync installs one signed coder grant pushed by the host.
// Payload (b64 JSON): {grant_id, terms_canonical, signature, verify_pubkey}.
func handleCoderGrantSync(ws *websocket.Conn, dir string, args []string) {
	refuse := func(id int64, why string) {
		dcnAudit(dir, "coder_grant_sync", id, "", "refused: "+why)
		sendMgmt(ws, 'R', []byte("coder_grant_sync refused: "+why+"\n"))
		sendMgmtExit(ws, 126)
	}
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("coder_grant_sync: need <payload_b64>\n"))
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
	terms, err := coderVerifyRec(f.VerifyPubkey, rec)
	if err != nil {
		refuse(payload.GrantID, "grant does not verify: "+err.Error())
		return
	}
	if hn, _ := os.Hostname(); terms.Server == "" || terms.Server != hn {
		refuse(payload.GrantID, fmt.Sprintf("grant is for server '%s', this box is '%s'", terms.Server, hn))
		return
	}
	if self == "" || terms.Subject != self {
		refuse(payload.GrantID, fmt.Sprintf("grant is for host '%s', not the host that sent it", terms.Subject))
		return
	}
	if prev, held := f.Coder[fmt.Sprint(payload.GrantID)]; !held || prev.Signature != rec.Signature {
		if approvalRequired(dir) {
			purpose, perr := purposeForCoderGrant(terms)
			if perr != nil {
				refuse(payload.GrantID, "grant refused: "+perr.Error())
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
			if _, err := boxConsume(dir, terms.Approval, purpose); err != nil {
				refuse(payload.GrantID, err.Error())
				return
			}
		}
	}
	if f.Coder == nil {
		f.Coder = map[string]dcnGrantRec{}
	}
	f.Coder[fmt.Sprint(payload.GrantID)] = rec
	if err := dcnSaveFile(dir, f); err != nil {
		sendMgmt(ws, 'R', []byte("grant persist failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	dcnAudit(dir, "coder_grant_sync", payload.GrantID, "", "installed for "+terms.Subject)
	b, _ := json.Marshal(map[string]any{"state": "ok", "grant_id": payload.GrantID,
		"subject": terms.Subject, "engines": terms.Engines, "max": terms.Max, "expires": terms.Expires})
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// coderGrantDropLocked removes one coder grant; the caller holds grantsMu.
func coderGrantDropLocked(dir string, id int64, why string) (bool, error) {
	f, err := dcnLoadFile(dir)
	if err != nil {
		return false, err
	}
	key := strconv.FormatInt(id, 10)
	if _, ok := f.Coder[key]; !ok {
		return false, nil
	}
	delete(f.Coder, key)
	if err := dcnSaveFile(dir, f); err != nil {
		return true, err
	}
	dcnAudit(dir, "coder_grant_drop", id, "", why)
	return true, nil
}

// handleCoderGrantDrop — the host revoked a coder grant: forget it here, now.
// A tighten needs no verification: it can only remove reach.
func handleCoderGrantDrop(ws *websocket.Conn, dir string, args []string) {
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("coder_grant_drop: need <grant_id>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil {
		sendMgmt(ws, 'R', []byte("coder_grant_drop: bad grant_id\n"))
		sendMgmtExit(ws, 1)
		return
	}
	grantsMu.Lock()
	present, err := coderGrantDropLocked(dir, id, "host-revoked")
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

// coderGrantDropAll removes every coder grant this pairing dir holds (the
// owner's `coders drop`). Returns the ids dropped.
func coderGrantDropAll(dir, why string) ([]int64, error) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	f, err := dcnLoadFile(dir)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for k := range f.Coder {
		if id, err := strconv.ParseInt(k, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	if len(f.Coder) == 0 {
		return nil, nil
	}
	f.Coder = nil
	if err := dcnSaveFile(dir, f); err != nil {
		return nil, err
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		dcnAudit(dir, "coder_grant_drop", id, "", why)
	}
	return ids, nil
}

// heldCoderGrants is what the enforcing report tells the host this pairing
// holds: {grant_id, signature}, so it can re-sync what is missing or stale.
func heldCoderGrants(dir string) []map[string]any {
	out := []map[string]any{}
	if dir == "" {
		return out
	}
	f, err := dcnLoadFile(dir)
	if err != nil {
		return out
	}
	ids := make([]int64, 0, len(f.Coder))
	for k := range f.Coder {
		if id, err := strconv.ParseInt(k, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		out = append(out, map[string]any{"grant_id": id, "signature": f.Coder[strconv.FormatInt(id, 10)].Signature})
	}
	return out
}

// maybeReconcileCoderGrants: the heartbeat reply may carry
// {"coder_grants": {"grants": [{grant_id, signature}]}}. Held but unlisted on
// TWO consecutive replies → a revoke this box missed → dropped. ABSENT field →
// no instruction (never "drop all"). The pattern of maybeReconcileReach.
func maybeReconcileCoderGrants(heartbeatResponse []byte, dir string) []int64 {
	if dir == "" {
		return nil
	}
	var hb struct {
		CoderGrants *struct {
			Grants []struct {
				GrantID int64 `json:"grant_id"`
			} `json:"grants"`
		} `json:"coder_grants"`
	}
	if json.Unmarshal(heartbeatResponse, &hb) != nil || hb.CoderGrants == nil {
		return nil
	}
	expected := map[string]bool{}
	for _, g := range hb.CoderGrants.Grants {
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
	for key := range f.Coder {
		ukey := "coder:" + key
		if expected[key] {
			clearUnlisted(dir, ukey)
			continue
		}
		if bumpUnlisted(dir, ukey) < dropAfterUnlisted {
			continue
		}
		if id, err := strconv.ParseInt(key, 10, 64); err == nil {
			if ok, err := coderGrantDropLocked(dir, id, "reconcile: not granted by host"); err == nil && ok {
				dropped = append(dropped, id)
			}
		}
		clearUnlisted(dir, ukey)
	}
	sort.Slice(dropped, func(i, j int) bool { return dropped[i] < dropped[j] })
	return dropped
}
