package main

// DCN machine-store handlers — the box-side wall for the Distributed Context
// Network. Dedicated Go handlers, NO exec, NO shell — like the context-store
// handlers, these never touch p8AllowedOps. Wire framing reuses sendMgmt /
// sendMgmtExit: O = stdout (a JSON result object), R = stderr, X = exit code.
//
// THE TRUST MODEL, honestly: the pod gate already default-denies un-granted DCN ops,
// but for DCN the box must be its OWN wall — a Go handler on hardware you own
// refuses — so the signed grant is synced HERE (dcn_grant_sync), the
// entity's verify key is PINNED on first sync (TOFU over the mTLS+bearer lane the
// pairing already trusts; a later key change is refused), and every op re-verifies
// the stored grant's signature + expiry before touching a byte. A compromised pod
// can ask; an unsigned/expired/out-of-mask/out-of-root ask is refused on the box.
//
// The op vocabulary is read-only (list / stat / read_range). There is NO delete
// handler — the operation does not exist on this surface, by design.
//
// Exit convention (the mapping the host applies to a machine op's result):
//   0   — handled; O carries a JSON object whose "state" is ok|gone
//   126 — refused (no grant / bad signature / mask / excludes / path escape)
//   1   — handler error (bad input, IO failure)

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const dcnMaxRangeBytes = 512 * 1024
const dcnMaxListEntries = 1000

// dcnGrantFile is <pairing dcn dir>/grants.json — the box's copy of the user's signed
// store grants, plus the pinned entity verify key. 0600; the box's private state.
// The dir is PER PAIRING (Config.dcnDir): the pin is per-entity, and multi-homing
// (0.10.0) means several entities share this daemon — a shared pin would let one
// entity's key verify another's grants.
type dcnGrantFile struct {
	// b64 raw ed25519. PINNED by whichever writer reaches it first — a DCN store
	// sync was the only one until 0.24.3, when session.go added the session
	// frame's own key so a Terminal needs no folder grant. Both write this one
	// field, and a key that disagrees with the pin is REFUSED, never overwritten.
	VerifyPubkey string                 `json:"verify_pubkey"`
	Stores       map[string]dcnGrantRec `json:"stores"`
	// Reach grants (service_reach.go): which host may reach which server in
	// this machine's service slot. Same signed-record shape and the same pinned
	// key as a store grant; verified by reachVerifyRec, which checks its kind.
	Reach map[string]dcnGrantRec `json:"reach,omitempty"`
	// ReachDropped: reach grants this box dropped because their SERVER was
	// stopped (reachDropForSlot), reported in the enforcing report so the host
	// revokes its row instead of re-pushing a grant for a server that is gone.
	// Newest last, capped at reachDroppedMax.
	ReachDropped []int64 `json:"reach_dropped,omitempty"`
	// Coder grants (coder_grant.go): the standing grant that lets this host
	// start coder runs here without a per-run approval. Same signed-record
	// shape and pinned key; verified by coderVerifyRec, which checks its kind.
	Coder map[string]dcnGrantRec `json:"coder,omitempty"`
}

type dcnGrantRec struct {
	TermsCanonical string `json:"terms_canonical"` // b64 of the EXACT signed bytes
	Signature      string `json:"signature"`       // b64 ed25519 over those bytes
	// The user's registered backup key as an age recipient — carried OUTSIDE
	// the signed bytes (a public key; the terms stay exactly what was
	// signed). The managed local agent seals the store's catalog to it.
	SealRecipient string `json:"seal_recipient,omitempty"`
}

// dcnTerms is parsed FROM the verified canonical bytes — never from anything else.
type dcnTerms struct {
	Kind     string   `json:"kind"`
	Class    string   `json:"class"`
	Server   string   `json:"server"`
	Root     string   `json:"root"`
	Mask     []string `json:"mask"`
	Excludes []string `json:"excludes"`
	Expires  string   `json:"expires"`
	// The local agent's cadence + the sensitive flag — part of the approval purpose,
	// so a pod cannot change them under an approval the user gave.
	Sweep     string `json:"sweep,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
	TTLDays   int    `json:"ttl_days,omitempty"` // shown to the user; the signed expiry may not exceed it
	// Approval this box issued after the user confirmed the request HERE
	// (stepup.go). Required at sync when a second factor is enrolled on this
	// machine; ignored otherwise.
	Approval string `json:"approval,omitempty"`
}

func dcnLoadFile(dir string) (*dcnGrantFile, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "grants.json"))
	if os.IsNotExist(err) {
		return &dcnGrantFile{Stores: map[string]dcnGrantRec{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var f dcnGrantFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if f.Stores == nil {
		f.Stores = map[string]dcnGrantRec{}
	}
	return &f, nil
}

// pinVerifyKey decides which entity_sign key this pairing's grants are
// verified under, and pins it into f when it was not yet. Returns (pinned,
// refusal): pinned means f changed and the caller saves it.
//
// LOCAL box: TOFU from the first offer over the mTLS+bearer lane the pairing
// already trusts; an offer that disagrees with the pin is refused (the rule
// since the DCN lane existed).
//
// ANCHORED box: the key pinned AT ANCHORING (anchor.go pinnedKeyFor) — the
// anchor host's from claim-anchor, a member's from the anchor-signed pairing
// grant. A key the ANCHOR host offers on this lane is checked against its pin
// and never pinned from: a host that could pin its own key on first use could
// then sign its own grants, and the anchor host is the one that writes here.
//
// A MEMBER whose pairing grant carries no verify_key keeps first-use pinning
// for now: the anchor host does not hold another host's signing key today
// (a host signs only its own pairing grants), so refusing
// would strand every member pairing on the fleet. The grant field is read as
// soon as a host fills it, and the member's offer is then checked against it.
func pinVerifyKey(f *dcnGrantFile, pairing, offered string) (bool, string) {
	offered = strings.TrimSpace(offered)
	if offered != "" {
		if raw, err := base64.StdEncoding.DecodeString(offered); err != nil || len(raw) != ed25519.PublicKeySize {
			return false, "host offered a malformed verify key"
		}
	}
	if currentAnchor() != nil {
		want := pinnedKeyFor(pairing)
		switch {
		case want == "" && f.VerifyPubkey == "":
			if offered == "" {
				return false, "no entity key pinned on this box yet (default-deny)"
			}
			f.VerifyPubkey = offered // a member's first use, until its grant carries verify_key
			return true, ""
		case want != "" && f.VerifyPubkey == "":
			f.VerifyPubkey = want
			if offered != "" && offered != want {
				return false, "verify key mismatch — the host offered a key that is not the one pinned at anchoring"
			}
			return true, ""
		case want != "" && f.VerifyPubkey != want:
			return false, "verify key mismatch — the key pinned here is not the one pinned at anchoring (re-enrol this box to rotate keys)"
		}
		if offered != "" && offered != f.VerifyPubkey {
			return false, "verify key mismatch — refusing re-pin (re-enrol this box to rotate keys)"
		}
		return false, ""
	}
	if f.VerifyPubkey == "" && offered != "" {
		f.VerifyPubkey = offered // TOFU pin, first use only
		return true, ""
	}
	if offered != "" && f.VerifyPubkey != offered {
		return false, "verify key mismatch — refusing re-pin (re-enrol this box to rotate keys)"
	}
	return false, ""
}

func dcnSaveFile(dir string, f *dcnGrantFile) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "grants.json"), raw)
}

// dcnAudit appends one JSONL record to <pairing dcn dir>/audit.jsonl — the box-side
// accounting ("every read is logged for you"). Best-effort: auditing never blocks
// a result, but a refusal is still a refusal whether or not the line lands.
func dcnAudit(dir, op string, storeID int64, path, decision string) {
	rec, _ := json.Marshal(map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "op": op,
		"store_id": storeID, "path": path, "decision": decision,
	})
	auditToSystemLog(auditFilePairingD, auditPairingOfDir(dir), rec)
	fh, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	_, _ = fh.Write(append(rec, '\n'))
}

// dcnVerifyRec checks one stored grant record against the pinned key and returns its
// parsed terms. Re-verified on EVERY op — a tampered grants.json authorizes nothing.
func dcnVerifyRec(pinnedKeyB64 string, rec dcnGrantRec) (*dcnTerms, error) {
	canonical, err := verifySignedRecord(pinnedKeyB64, rec)
	if err != nil {
		return nil, err
	}
	var terms dcnTerms
	if err := json.Unmarshal(canonical, &terms); err != nil {
		return nil, fmt.Errorf("signed terms unparsable")
	}
	// ITS KIND, CHECKED. The entity key signs several kinds of record (store
	// grants, reach grants, …) and this verifier used to parse `kind` without
	// comparing it, so any record the key had signed could be offered as a
	// store grant. The host has signed "dcn_store_grant" on every store grant
	// since store grants existed, so none is refused by this.
	if terms.Kind != "dcn_store_grant" {
		return nil, fmt.Errorf("signed record is a %q, not a dcn_store_grant", terms.Kind)
	}
	// NO OPEN-ENDED TERMS. A grant with no expiry used to verify forever; the
	// host has always signed one (365 days by default), so refusing its absence
	// costs nothing real and closes a grant that could never lapse.
	exp, err := time.Parse(time.RFC3339, terms.Expires)
	if err != nil {
		return nil, fmt.Errorf("grant states no expiry (open-ended terms are refused)")
	}
	if !exp.After(time.Now()) {
		return nil, fmt.Errorf("grant expired")
	}
	return &terms, nil
}

// dcnResolvePath sandbox-checks rpath against the granted root: cleanRel (traversal
// wall) THEN symlink resolution — the final resolved target must stay under the
// resolved root (a symlink inside the store pointing outside it is an escape).
func dcnResolvePath(root, rpath string) (string, bool) {
	joined, ok := cleanRel(root, rpath)
	if !ok {
		return "", false
	}
	resolvedRoot, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return "", false
	}
	// Resolve the deepest existing ancestor of joined (the file itself may not exist
	// yet for stat-of-missing; a missing path can't be a symlink escape).
	probe := joined
	for {
		r, err := filepath.EvalSymlinks(probe)
		if err == nil {
			if r != resolvedRoot && !strings.HasPrefix(r, resolvedRoot+string(os.PathSeparator)) {
				return "", false
			}
			break
		}
		// Missing is fine, and so is a broken link as the last part of the path:
		// a stat of it reads as gone and a move renames the link itself. A path
		// that goes THROUGH a link that leads nowhere (or loops) is refused:
		// nothing can be reached through it, and where it would lead cannot be
		// shown to be inside the root.
		if _, lerr := os.Lstat(probe); lerr == nil && probe != joined {
			return "", false
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", false
		}
		probe = parent
	}
	return joined, true
}

// dcnExcluded reports whether rpath trips any exclude pattern. Patterns match the
// basename and every path segment (glob per segment: ".ssh", "*.key", ".env*"),
// compared the way this platform's file system compares names (dcnNameKey).
// rpath is a real relative path; a path a host sent goes through dcnExcludedAsSent.
func dcnExcluded(excludes []string, rpath string) bool {
	return dcnExcludedOn(runtime.GOOS, excludes, rpath)
}

func dcnExcludedOn(goos string, excludes []string, rpath string) bool {
	segs := strings.Split(filepath.ToSlash(rpath), "/")
	for _, pat := range excludes {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		pat = dcnNameKey(goos, pat)
		for _, seg := range segs {
			if ok, _ := filepath.Match(pat, dcnNameKey(goos, seg)); ok {
				return true
			}
		}
	}
	return false
}

// dcnNameKey is a name as the file system on goos tells names apart. Windows
// and macOS ignore case by default, so ".SSH" opens ".ssh" there. Windows also
// drops trailing dots and spaces from a name (".ssh." opens ".ssh") and reads
// "name:stream" as a stream of the file "name" (server.key::$DATA is server.key).
func dcnNameKey(goos, name string) string {
	switch goos {
	case "windows":
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		return strings.ToLower(strings.TrimRight(name, " ."))
	case "darwin":
		return strings.ToLower(name)
	}
	return name
}

// dcnExcludedAsSent is dcnExcluded for a path a host sent, and it judges what
// the path OPENS rather than its text, both ways it can differ:
//   - the spelling: cleanRel trims and cleans before it opens, so " .ssh/id_rsa"
//     or "a.key " would get past a check of the text as sent;
//   - the links: a link inside the store to an excluded folder ("keys" -> ".ssh")
//     makes "keys/id_rsa" open .ssh/id_rsa. So the path is also judged where it
//     leads, relative to the resolved root.
//
// A path cleanRel refuses is judged as sent (the sandbox refuses it anyway).
func dcnExcludedAsSent(excludes []string, root, rpath string) bool {
	joined, ok := cleanRel(root, rpath)
	if !ok {
		return dcnExcluded(excludes, rpath)
	}
	if rel, err := filepath.Rel(filepath.Clean(root), joined); err != nil || dcnExcluded(excludes, rel) {
		return true
	}
	resolvedRoot, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(resolvedRoot, dcnWhereItLeads(joined))
	if err != nil {
		return true
	}
	return dcnExcluded(excludes, rel)
}

// dcnWhereItLeads is p with its deepest existing part's links resolved and the
// rest (not there yet) appended: where a read of p opens, or a move to p lands.
func dcnWhereItLeads(p string) string {
	rest := ""
	for probe := p; ; {
		if r, err := filepath.EvalSymlinks(probe); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return p
		}
		rest = filepath.Join(filepath.Base(probe), rest)
		probe = parent
	}
}

func dcnHasMask(terms *dcnTerms, op string) bool {
	for _, m := range terms.Mask {
		if m == op {
			return true
		}
	}
	return false
}

func dcnRefuse(ws *websocket.Conn, dir, op string, storeID int64, path, why string) {
	dcnAudit(dir, op, storeID, path, "refused: "+why)
	sendMgmt(ws, 'R', []byte(why+"\n"))
	sendMgmtExit(ws, 126)
}

func dcnResult(ws *websocket.Conn, dir, op string, storeID int64, path string, obj map[string]any) {
	state, _ := obj["state"].(string)
	dcnAudit(dir, op, storeID, path, state)
	raw, err := json.Marshal(obj)
	if err != nil {
		sendMgmt(ws, 'R', []byte("result marshal failed\n"))
		sendMgmtExit(ws, 1)
		return
	}
	sendMgmt(ws, 'O', raw)
	sendMgmtExit(ws, 0)
}

// dcnLoadGrant fetches + re-verifies the grant for storeID and gates (op, rpath)
// against the 'read' mask — list/stat/read_range. dcnLoadGrantMask is the same
// wall with the mask named by the caller (search needs 'search').
func dcnLoadGrant(ws *websocket.Conn, dir, op string, storeID int64, rpath string) *dcnTerms {
	return dcnLoadGrantMask(ws, dir, op, storeID, rpath, "read")
}

func dcnLoadGrantMask(ws *websocket.Conn, dir, op string, storeID int64, rpath, mask string) *dcnTerms {
	f, err := dcnLoadFile(dir)
	if err != nil {
		dcnRefuse(ws, dir, op, storeID, rpath, "grant store unreadable")
		return nil
	}
	if f.VerifyPubkey == "" {
		dcnRefuse(ws, dir, op, storeID, rpath, "no grant synced to this box (default-deny)")
		return nil
	}
	rec, ok := f.Stores[fmt.Sprint(storeID)]
	if !ok {
		dcnRefuse(ws, dir, op, storeID, rpath, "no grant for this store on this box (default-deny)")
		return nil
	}
	terms, err := dcnVerifyRec(f.VerifyPubkey, rec)
	if err != nil {
		dcnRefuse(ws, dir, op, storeID, rpath, "grant refused: "+err.Error())
		return nil
	}
	if terms.Class != "machine" || terms.Root == "" {
		dcnRefuse(ws, dir, op, storeID, rpath, "grant is not a machine store")
		return nil
	}
	// list/stat/read_range are read-class ops; search (freeagent.go) needs the
	// 'search' mask the user granted separately.
	if !dcnHasMask(terms, mask) {
		dcnRefuse(ws, dir, op, storeID, rpath, "op '"+mask+"' not in the store's granted mask")
		return nil
	}
	if rpath != "" && dcnExcludedAsSent(terms.Excludes, terms.Root, rpath) {
		dcnRefuse(ws, dir, op, storeID, rpath, "path is excluded by the grant")
		return nil
	}
	return terms
}

type dcnOpArgs struct {
	Path      string `json:"path"`
	Prefix    string `json:"prefix"`
	StartByte int64  `json:"start_byte"`
	EndByte   int64  `json:"end_byte"`
	Limit     int    `json:"limit"`
	// local agent form (freeagent.go): a search query, and a document id for
	// read_range in place of a path. Absent on the classic file ops.
	Query  string `json:"query"`
	K      int    `json:"k"`
	Doc    string `json:"doc"`
	Kind   string `json:"kind"`   // catalog: "dirs" (default) | "files"
	Offset int    `json:"offset"` // catalog: page start
}

func dcnParseArgs(ws *websocket.Conn, args []string) (int64, *dcnOpArgs, bool) {
	if len(args) < 2 {
		sendMgmt(ws, 'R', []byte("need <store_id> <json_args>\n"))
		sendMgmtExit(ws, 1)
		return 0, nil, false
	}
	var storeID int64
	if _, err := fmt.Sscan(strings.TrimSpace(args[0]), &storeID); err != nil {
		sendMgmt(ws, 'R', []byte("bad store_id\n"))
		sendMgmtExit(ws, 1)
		return 0, nil, false
	}
	var a dcnOpArgs
	if err := json.Unmarshal([]byte(args[1]), &a); err != nil {
		sendMgmt(ws, 'R', []byte("bad json args\n"))
		sendMgmtExit(ws, 1)
		return 0, nil, false
	}
	return storeID, &a, true
}

// handleDcnGrantSync installs/updates ONE signed grant: args[0] = b64 JSON
// {store_id, terms_canonical, signature, verify_pubkey}. First sync pins the verify
// key; a different key later is REFUSED (re-pinning is a re-enrol level event, not
// an op). The record is verified before it is stored — the box never persists a
// grant it couldn't enforce.
func handleDcnGrantSync(ws *websocket.Conn, dir string, args []string) {
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("dcn_grant_sync: need <payload_b64>\n"))
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
		StoreID        int64  `json:"store_id"`
		TermsCanonical string `json:"terms_canonical"`
		Signature      string `json:"signature"`
		VerifyPubkey   string `json:"verify_pubkey"`
		SealRecipient  string `json:"seal_recipient"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		sendMgmt(ws, 'R', []byte("bad payload json\n"))
		sendMgmtExit(ws, 1)
		return
	}
	grantsMu.Lock() // one load→modify→save at a time (reconcile.go)
	defer grantsMu.Unlock()
	f, err := dcnLoadFile(dir)
	if err != nil {
		sendMgmt(ws, 'R', []byte("grant store unreadable\n"))
		sendMgmtExit(ws, 1)
		return
	}
	// The key this grant is verified under. On a LOCAL box: TOFU from this
	// first sync, over the mTLS+bearer lane the pairing already trusts. On an
	// ANCHORED box: the key pinned AT ANCHORING (anchor.go pinnedKeyFor) —
	// the anchor's from claim-anchor, a member's from the anchor-signed
	// pairing grant — and never one this sync offers. A host that could pin
	// its own key on its first sync could sign its own grants.
	self := ""
	if a := mgmtAccountOf(ws); a != nil {
		self = a.self
	}
	if _, why := pinVerifyKey(f, self, payload.VerifyPubkey); why != "" {
		dcnRefuse(ws, dir, "grant_sync", payload.StoreID, "", why)
		return
	}
	rec := dcnGrantRec{TermsCanonical: payload.TermsCanonical, Signature: payload.Signature,
		SealRecipient: strings.TrimSpace(payload.SealRecipient)}
	terms, err := dcnVerifyRec(f.VerifyPubkey, rec)
	if err != nil {
		dcnRefuse(ws, dir, "grant_sync", payload.StoreID, "", "grant does not verify: "+err.Error())
		return
	}
	if hn, _ := os.Hostname(); hn != "" && terms.Server != "" && terms.Server != hn {
		dcnRefuse(ws, dir, "grant_sync", payload.StoreID, "",
			fmt.Sprintf("grant is for server '%s', this box is '%s'", terms.Server, hn))
		return
	}
	// Second factor on THIS box (stepup.go): when enrolled here, the grant must
	// carry an approval this machine issued for exactly these terms, after the
	// user confirmed them HERE. A pod can sign anything; this box enforces only
	// what the user approved on it. A re-sync of the SAME signed record while it
	// is still held (drift repair) needs no gate: identical bytes, already
	// approved. The approval is BURNED once the grant is installed, so a revoke
	// is final: the pod cannot re-install a dropped grant under the old
	// approval. Consequence: a box that loses grants.json cannot be repaired by
	// the heartbeat resync — the user re-grants and approves on the machine.
	gated := false
	if prev, held := f.Stores[fmt.Sprint(payload.StoreID)]; !held || prev.Signature != rec.Signature {
		if approvalRequired(dir) {
			purpose, perr := purposeForGrant(terms)
			if perr != nil {
				dcnRefuse(ws, dir, "grant_sync", payload.StoreID, "", "grant refused: "+perr.Error())
				return
			}
			if err := boxApproval(dir, terms.Approval, purpose); err != nil {
				fmt.Printf("grant_sync store %d refused: %s (a re-grant approved on this machine is the repair)\n", payload.StoreID, err)
				dcnRefuse(ws, dir, "grant_sync", payload.StoreID, "", err.Error())
				return
			}
			// The user approved "for N days"; the signed expiry may not outrun it,
			// and a grant with no stated duration is not approvable here at all.
			if terms.TTLDays <= 0 {
				dcnRefuse(ws, dir, "grant_sync", payload.StoreID, "", "grant states no duration (ttl_days)")
				return
			}
			{
				if exp, err := time.Parse(time.RFC3339, terms.Expires); err != nil ||
					exp.After(time.Now().Add(time.Duration(terms.TTLDays+1)*24*time.Hour)) {
					dcnRefuse(ws, dir, "grant_sync", payload.StoreID, "", "grant expiry exceeds the approved duration")
					return
				}
			}
			gated = true
		}
	}
	f.Stores[fmt.Sprint(payload.StoreID)] = rec
	if err := dcnSaveFile(dir, f); err != nil {
		sendMgmt(ws, 'R', []byte("grant persist failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if gated {
		markApprovalUsed(dir, terms.Approval) // one approval installs the grant once; a revoke is final
	}
	// local agent, managed (freeagent_managed.go): a grant with 'search' means
	// this box installs and runs the store's local agent itself; one without it
	// stops any instance a previous grant started.
	if dcnHasMask(terms, "search") {
		faEnsureStore(dir, payload.StoreID, terms, sweepFromCanonical(rec.TermsCanonical), rec.SealRecipient)
	} else {
		faStop(payload.StoreID)
	}
	dcnResult(ws, dir, "grant_sync", payload.StoreID, "", map[string]any{
		"state": "ok", "root": terms.Root, "mask": terms.Mask,
		"freeagent": dcnHasMask(terms, "search")})
}

// dcnDropStore removes one store's grant from this box and stops its managed
// local agent. Two callers: the dcn_grant_drop op (the host pushes a revoke the
// moment it happens) and the heartbeat reconcile (a revoke the box missed while
// it was offline — reconcile.go). Before this existed a revoked grant stayed
// valid on the box until its signed expiry (default 365 days) and the local agent
// kept indexing. Returns whether the store was present.
func dcnDropStore(dir string, storeID int64, why string) (bool, error) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	return dcnDropStoreLocked(dir, storeID, why)
}

// dcnDropStoreLocked is dcnDropStore for a caller that already holds grantsMu
// (the reconcile loop, which walks the file it is modifying).
func dcnDropStoreLocked(dir string, storeID int64, why string) (bool, error) {
	f, err := dcnLoadFile(dir)
	if err != nil {
		return false, err
	}
	key := strconv.FormatInt(storeID, 10)
	if _, ok := f.Stores[key]; !ok {
		faStop(storeID) // nothing on disk, but never leave an orphan instance running
		return false, nil
	}
	delete(f.Stores, key)
	if err := dcnSaveFile(dir, f); err != nil {
		return true, err
	}
	faStop(storeID)
	dcnAudit(dir, "grant_drop", storeID, "", why)
	return true, nil
}

// handleDcnGrantDrop — the host revoked a store grant: forget it here, now.
// A tighten needs no verification (an attacker who can speak this lane can at
// most remove access, never widen it), so the op carries just the store id.
func handleDcnGrantDrop(ws *websocket.Conn, dir string, args []string) {
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("dcn_grant_drop: need <store_id>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	storeID, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil {
		sendMgmt(ws, 'R', []byte("dcn_grant_drop: bad store_id\n"))
		sendMgmtExit(ws, 1)
		return
	}
	present, err := dcnDropStore(dir, storeID, "host-revoked")
	if err != nil {
		sendMgmt(ws, 'R', []byte("grant drop failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	dcnResult(ws, dir, "grant_drop", storeID, "", map[string]any{
		"state": "ok", "dropped": present})
}

// handleDcnList walks the granted root (optionally under a prefix) and returns up to
// `limit` entries, excludes skipped. Read-only; never follows a path outside the root.
func handleDcnList(ws *websocket.Conn, dir string, args []string) {
	storeID, a, ok := dcnParseArgs(ws, args)
	if !ok {
		return
	}
	terms := dcnLoadGrant(ws, dir, "list", storeID, a.Prefix)
	if terms == nil {
		return
	}
	base := terms.Root
	if a.Prefix != "" {
		p, ok := dcnResolvePath(terms.Root, a.Prefix)
		if !ok {
			dcnRefuse(ws, dir, "list", storeID, a.Prefix, "prefix escapes the store root")
			return
		}
		base = p
	}
	limit := a.Limit
	if limit <= 0 || limit > dcnMaxListEntries {
		limit = dcnMaxListEntries
	}
	type entry struct {
		Path  string `json:"path"`
		Size  int64  `json:"size_bytes"`
		Mtime string `json:"mtime"`
	}
	var files []entry
	truncated := false
	_ = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip, never abort the listing
		}
		rel, rerr := filepath.Rel(terms.Root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		if dcnExcluded(terms.Excludes, rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if len(files) >= limit {
			truncated = true
			return filepath.SkipAll
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		files = append(files, entry{Path: filepath.ToSlash(rel), Size: info.Size(),
			Mtime: info.ModTime().UTC().Format(time.RFC3339)})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	dcnResult(ws, dir, "list", storeID, a.Prefix, map[string]any{
		"state": "ok", "files": files, "count": len(files), "truncated": truncated})
}

// handleDcnStat stats one path. Missing → state=gone (a typed fact, not an error).
func handleDcnStat(ws *websocket.Conn, dir string, args []string) {
	storeID, a, ok := dcnParseArgs(ws, args)
	if !ok {
		return
	}
	terms := dcnLoadGrant(ws, dir, "stat", storeID, a.Path)
	if terms == nil {
		return
	}
	abs, okp := dcnResolvePath(terms.Root, a.Path)
	if !okp {
		dcnRefuse(ws, dir, "stat", storeID, a.Path, "path escapes the store root")
		return
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			dcnResult(ws, dir, "stat", storeID, a.Path, map[string]any{
				"state": "gone", "path": a.Path})
			return
		}
		sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	dcnResult(ws, dir, "stat", storeID, a.Path, map[string]any{
		"state": "ok", "path": a.Path, "size_bytes": info.Size(),
		"mtime": info.ModTime().UTC().Format(time.RFC3339), "is_dir": info.IsDir()})
}

// handleDcnReadRange returns ONE scoped byte range of one file (b64). The range is
// capped box-side regardless of what was asked — the cap protects the lane.
func handleDcnReadRange(ws *websocket.Conn, dir string, args []string) {
	storeID, a, ok := dcnParseArgs(ws, args)
	if !ok {
		return
	}
	// A document id (from a local agent search hit) reads the SANITIZED text
	// through the local agent instead of file bytes from disk. Same op name,
	// same 'read' mask, a different — narrower — source.
	if strings.TrimSpace(a.Doc) != "" {
		handleDcnReadRangeDoc(ws, dir, storeID, a)
		return
	}
	terms := dcnLoadGrant(ws, dir, "read_range", storeID, a.Path)
	if terms == nil {
		return
	}
	if a.Path == "" {
		sendMgmt(ws, 'R', []byte("read_range: path required\n"))
		sendMgmtExit(ws, 1)
		return
	}
	abs, okp := dcnResolvePath(terms.Root, a.Path)
	if !okp {
		dcnRefuse(ws, dir, "read_range", storeID, a.Path, "path escapes the store root")
		return
	}
	fh, err := os.Open(abs)
	if err != nil {
		if os.IsNotExist(err) {
			dcnResult(ws, dir, "read_range", storeID, a.Path, map[string]any{
				"state": "gone", "path": a.Path})
			return
		}
		sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil || info.IsDir() {
		dcnRefuse(ws, dir, "read_range", storeID, a.Path, "not a readable file")
		return
	}
	start := a.StartByte
	if start < 0 {
		start = 0
	}
	end := a.EndByte
	if end <= start || end > start+dcnMaxRangeBytes {
		end = start + dcnMaxRangeBytes
	}
	if end > info.Size() {
		end = info.Size()
	}
	var buf []byte
	if end > start {
		buf = make([]byte, end-start)
		if _, err := fh.ReadAt(buf, start); err != nil && end < info.Size() {
			sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
			sendMgmtExit(ws, 1)
			return
		}
	}
	dcnResult(ws, dir, "read_range", storeID, a.Path, map[string]any{
		"state": "ok", "path": a.Path, "start_byte": start, "end_byte": end,
		"size_bytes":  info.Size(),
		"content_b64": base64.StdEncoding.EncodeToString(buf)})
}
