package main

// Pairing grant ops — the anchor host's lane onto this box.
// Dedicated Go handlers, NO exec, same framing as dcn.go (O = JSON result,
// R = stderr, X = exit; 126 = refused, 1 = handler error). Only ever reached
// on the anchor pairing's mgmt connection: handleMgmtConnFor refuses every
// pairing_* op from any other pairing before these run.
//
//   pairing_grant_sync     [terms_b64, signature_b64, (verify_pubkey_b64)]
//   pairing_grant_drop     [subject host_name, terms_b64, signature_b64]
//   pairing_list           []
//   pairing_anchor_consent [terms_b64, signature_b64]
//   pairing_redeem         [token]
//
// The optional third argument to grant_sync is the anchor host's verify key,
// accepted ONLY when this box holds no pin at all (neither anchor.json nor the
// anchor pairing's DCN pin). That is the same TOFU the DCN lane uses, over the
// same mTLS+bearer connection, and it exists because a fresh anchor host may
// approve its first member before it has ever synced a store grant here (an
// anchor host may well hold zero DCN grants).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// pairingAudit appends one line to <configDir>/pairing_audit.jsonl. Box-level,
// because these ops change the box's own membership, not one pairing's store.
// Best-effort, like dcnAudit: a refusal stands whether or not the line lands.
func pairingAudit(op, subject, decision string) {
	d, err := configDir()
	if err != nil {
		return
	}
	rec, _ := json.Marshal(map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "op": op,
		"subject": subject, "decision": decision,
	})
	auditToSystemLog(auditFilePairing, "", rec)
	fh, err := os.OpenFile(filepath.Join(d, "pairing_audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	_, _ = fh.Write(append(rec, '\n'))
}

func pairingRefuse(ws *websocket.Conn, op, subject, why string) {
	pairingAudit(op, subject, "refused: "+why)
	sendMgmt(ws, 'R', []byte(why+"\n"))
	sendMgmtExit(ws, 126)
}

func pairingResult(ws *websocket.Conn, op, subject string, obj map[string]any) {
	pairingAudit(op, subject, "ok")
	raw, err := json.Marshal(obj)
	if err != nil {
		sendMgmt(ws, 'R', []byte("result marshal failed\n"))
		sendMgmtExit(ws, 1)
		return
	}
	sendMgmt(ws, 'O', raw)
	sendMgmtExit(ws, 0)
}

// handlePairingGrantSync installs the anchor's grant for one pending pairing
// and opens its lanes without a restart. A re-sync for a pairing that is
// already active updates its caps ceiling in place (the anchor narrowing or
// widening what that host may be asked for); a revoked or unknown subject is
// refused — a revoke is final until the host is paired again.
func handlePairingGrantSync(ws *websocket.Conn, _ string, args []string) {
	if len(args) < 2 {
		sendMgmt(ws, 'R', []byte("pairing_grant_sync: need <terms_b64> <signature_b64> [verify_pubkey_b64]\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if len(args) >= 3 && strings.TrimSpace(args[2]) != "" {
		if err := pinAnchorVerifyKey(strings.TrimSpace(args[2])); err != nil {
			pairingRefuse(ws, "grant_sync", "", "verify key: "+err.Error())
			return
		}
	}
	t, err := verifyAnchorRecord(args[0], args[1], "pairing_grant")
	if err != nil {
		pairingRefuse(ws, "grant_sync", "", "grant does not verify: "+err.Error())
		return
	}
	if !validHostName(t.Subject) {
		pairingRefuse(ws, "grant_sync", t.Subject, "grant subject is not a valid host name")
		return
	}
	anchorMu.Lock()
	cfgs, err := loadPairings()
	if err != nil {
		anchorMu.Unlock()
		sendMgmt(ws, 'R', []byte("pairings unreadable: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	c := pairingFor(cfgs, t.Subject)
	if c == nil || c.HostName != t.Subject {
		anchorMu.Unlock()
		pairingRefuse(ws, "grant_sync", t.Subject, "subject is not paired on this box")
		return
	}
	if c.State == pairingRevoked {
		anchorMu.Unlock()
		pairingRefuse(ws, "grant_sync", t.Subject, "subject pairing was revoked — pair it again to re-approve")
		return
	}
	// Approving would mark it active and start it with the endpoint its file
	// holds, which this build refuses. The reason names a local file, so the
	// host is told only what to do.
	if c.invalid != "" {
		anchorMu.Unlock()
		pairingRefuse(ws, "grant_sync", t.Subject, "subject pairing is not served on this box: its file holds an endpoint this bastion refuses — pair it again to approve it")
		return
	}
	if a := currentAnchor(); a != nil && a.AnchorHost == c.HostName {
		anchorMu.Unlock()
		pairingRefuse(ws, "grant_sync", t.Subject, "subject is the anchor itself; the anchor holds no grant")
		return
	}
	wasPending := c.State == pairingPending
	g := &pairingGrantFile{TermsCanonical: strings.TrimSpace(args[0]), Signature: strings.TrimSpace(args[1]),
		SyncedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := savePairingGrant(c.HostName, g); err != nil {
		anchorMu.Unlock()
		sendMgmt(ws, 'R', []byte("grant persist failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	// The flip is a locked read-modify-write of the file as it is NOW, so a
	// concurrent endpoint save (or a CLI in another process) is never lost.
	c, err = updatePairingOnDisk(c.HostName, func(d *Config) { d.State = pairingActive })
	if err != nil {
		anchorMu.Unlock()
		sendMgmt(ws, 'R', []byte("pairing persist failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	anchorMu.Unlock()
	// Open the lanes now: the user approved on the anchor host and expects the
	// member host to come up, not to wait for someone to restart the service.
	started := false
	if wasPending {
		started = supervisorStart(c)
		// Every Host on this box reads this pairing's state from a beat, so
		// each beats now rather than up to a minute from now (beatnow.go). A
		// re-sync of an active pairing changes no state, so it beats nothing.
		kickBeats()
	}
	pairingResult(ws, "grant_sync", c.HostName, map[string]any{
		"state": "ok", "subject": c.HostName, "caps": sortedCaps(t.Caps),
		"started": started, "already_active": !wasPending,
	})
}

// handlePairingGrantDrop — the anchor revoked a member: mark it revoked, keep
// the file, and tear its tunnel and lanes down now. Unlike dcn_grant_drop this
// IS verified: a revoke record is the anchor's signed word, and the tighten
// removes a whole host, not one store.
func handlePairingGrantDrop(ws *websocket.Conn, _ string, args []string) {
	if len(args) < 3 {
		sendMgmt(ws, 'R', []byte("pairing_grant_drop: need <subject> <terms_b64> <signature_b64>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	subject := strings.TrimSpace(args[0])
	t, err := verifyAnchorRecord(args[1], args[2], "pairing_revoke")
	if err != nil {
		pairingRefuse(ws, "grant_drop", subject, "revoke does not verify: "+err.Error())
		return
	}
	if t.Subject != subject || !validHostName(subject) {
		pairingRefuse(ws, "grant_drop", subject, "revoke names a different subject")
		return
	}
	if a := currentAnchor(); a != nil && a.AnchorHost == subject {
		pairingRefuse(ws, "grant_drop", subject, "the anchor cannot revoke itself — rotate the anchor instead")
		return
	}
	anchorMu.Lock()
	cfgs, err := loadPairings()
	if err != nil {
		anchorMu.Unlock()
		sendMgmt(ws, 'R', []byte("pairings unreadable: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	c := pairingFor(cfgs, subject)
	if c == nil || c.HostName != subject {
		anchorMu.Unlock()
		pairingRefuse(ws, "grant_drop", subject, "subject is not paired on this box")
		return
	}
	g, err := loadPairingGrant(subject)
	if err != nil {
		g = &pairingGrantFile{}
	}
	g.RevokeTermsCanonical = strings.TrimSpace(args[1])
	g.RevokeSignature = strings.TrimSpace(args[2])
	g.RevokedAt = time.Now().UTC().Format(time.RFC3339)
	if err := savePairingGrant(subject, g); err != nil {
		anchorMu.Unlock()
		sendMgmt(ws, 'R', []byte("revoke persist failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if _, err := updatePairingOnDisk(c.HostName, func(d *Config) { d.State = pairingRevoked }); err != nil {
		anchorMu.Unlock()
		sendMgmt(ws, 'R', []byte("pairing persist failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	anchorMu.Unlock()
	stopped := stopPairing(subject)
	// Every other Host on this box learns of the revoke on its next beat, which
	// is now rather than up to a minute from now (beatnow.go).
	kickBeats()
	// A revoked pairing keeps no folder the person shared with it.
	sharesDropped := dropSharesOf(subject) == nil
	pairingResult(ws, "grant_drop", subject, map[string]any{
		"state": "ok", "subject": subject, "stopped": stopped, "backup_shares_dropped": sharesDropped,
	})
}

// handlePairingList answers what the anchor host's heartbeat already carries,
// on demand: every pairing with its state, and the anchor.
func handlePairingList(ws *websocket.Conn, _ string, _ []string) {
	list := pairingsReport()
	if list == nil {
		sendMgmt(ws, 'R', []byte("pairings unreadable\n"))
		sendMgmtExit(ws, 1)
		return
	}
	out := map[string]any{"state": "ok", "mode": boxMode(), "pairings": list}
	if a := currentAnchor(); a != nil {
		out["anchor"] = a
	}
	if u := unapprovedAttempts(time.Now()); u != nil {
		out["unapproved_pairing_attempts"] = u
	}
	pairingResult(ws, "list", "", out)
}

// handlePairingRedeem redeems a pairing token that the ANCHOR host handed
// down. Until this existed, a token could only be redeemed ON the machine —
// `privatae-bastion pair <token>` at a terminal, or the local setup page — so
// sharing a model with someone else's host meant somebody standing at the box.
// That is the whole point of the op: the anchor user shares one model from
// their own Circles and nobody touches the machine.
//
// IT GRANTS NOTHING. The redeem writes a pairing exactly as `pair` does, and on
// an anchored box pairPrecheck writes it PENDING with no tunnel and no lanes
// (pair.go). Admission is still the existing two-step the user already knows:
// the anchor approves with a caps ceiling and a step-up code
// (handlePairingGrantSync). Redeeming is the paperwork; approving is the
// decision, and they stay separate.
//
// WHY IT IS NAMED pairing_*, AND WHY THAT IS THE GATE. handleMgmtConnFor
// refuses every op whose name starts with "pairing_" unless the connection IS
// the anchor pairing's (mgmt.go), before any handler runs. Any other name would
// have fallen to capsAllow, where opFamily returns "" for an op it does not
// know and "" means ALLOW — so a new op id outside the family table is served
// to every member pairing on the box. Naming it into the existing anchor-only
// prefix is what makes the gate exist before the op does, rather than after
// someone remembers to add it. TestPairingRedeemIsAnchorOnly pins that.
//
// Belt, because the prefix gate lives in another file: an unanchored box is
// refused here too. A LOCAL bastion is unanchored by construction
// (claim-anchor refuses outside networked mode), so this op never serves one —
// a local box serves exactly one host, and a second host arriving through a
// remote op is precisely what that rule exists to prevent.
func handlePairingRedeem(ws *websocket.Conn, _ string, args []string) {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		sendMgmt(ws, 'R', []byte("pairing_redeem: need <token>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	token := strings.TrimSpace(args[0])
	// The handle is the only part of the token that may be logged or echoed:
	// the other half is a single-use secret. decodeToken first also means a
	// malformed token costs no network call.
	handle, _, err := decodeToken(token)
	if err != nil {
		pairingRefuse(ws, "redeem", "", "token is malformed")
		return
	}
	if currentAnchor() == nil {
		pairingRefuse(ws, "redeem", handle, "this machine is not anchored — a pairing token is only "+
			"redeemed remotely on a machine whose anchor host directs it")
		return
	}
	// A host the anchor REVOKED can be shared with again without anyone going
	// to the machine. `pair` needs --replace to touch an existing pairing, and
	// a revoked one is still an existing one, so the plain redeem below would
	// answer "already paired" and the second share would need a terminal —
	// which is the story this op exists to remove.
	//
	// Narrow on purpose: replace is used ONLY when the sole conflict is a
	// revoked pairing for that handle. It never rotates an ACTIVE or PENDING
	// one, because rotating a live host's credentials is not what an offer
	// asked for. pairPrecheck then writes it PENDING rather than active — a
	// revoked host presenting a fresh token is a new request for the anchor,
	// never a way back in (pair.go).
	replace := revokedPairingFor(handle)
	cfg, _, err := pairWithToken(token, replace, false)
	if err != nil {
		// pairWithToken's errors are already written for a person (already
		// paired, token rejected, singleton guard). They never contain the
		// secret: it is not echoed on any path out of that function.
		pairingRefuse(ws, "redeem", handle, "redeem failed: "+err.Error())
		return
	}
	// An anchored box cannot produce an active pairing from this call
	// (pairPrecheck), and if that ever changed this op would be admitting a
	// host with no approval. Say so rather than report success.
	if cfg.active() {
		pairingRefuse(ws, "redeem", cfg.HostName, "redeem produced an ACTIVE pairing on an anchored box — "+
			"refusing to report success; approve/revoke it explicitly")
		return
	}
	pairingResult(ws, "redeem", cfg.HostName, map[string]any{
		"state": "ok", "subject": cfg.HostName, "handle": handle,
		"pairing_state": cfg.stateName(),
		"note": "pending — it holds no lanes until the anchor approves it with a caps ceiling " +
			"(manage_pairing op='approve')",
	})
}

// revokedPairingFor reports whether the ONLY pairing this handle matches is one
// the anchor revoked. False for an active or pending pairing, and false when
// there is none at all — so the caller's `replace` can never rotate a live
// host's credentials, only re-open a door the anchor itself closed.
func revokedPairingFor(handle string) bool {
	cfgs, err := loadPairings()
	if err != nil {
		return false
	}
	c := pairingFor(cfgs, handle)
	return c != nil && c.State == pairingRevoked
}

// handlePairingAnchorConsent stores the current anchor's signed consent to a
// rotation at anchor.consent.json; claim-anchor --rotate reads and burns it.
func handlePairingAnchorConsent(ws *websocket.Conn, _ string, args []string) {
	if len(args) < 2 {
		sendMgmt(ws, 'R', []byte("pairing_anchor_consent: need <terms_b64> <signature_b64>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	t, err := verifyAnchorRecord(args[0], args[1], "anchor_consent")
	if err != nil {
		pairingRefuse(ws, "anchor_consent", "", "consent does not verify: "+err.Error())
		return
	}
	p, err := anchorConsentPath()
	if err != nil {
		sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	b, _ := json.MarshalIndent(map[string]string{
		"terms_canonical": strings.TrimSpace(args[0]), "signature": strings.TrimSpace(args[1]),
		"received_at": time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err := atomicWrite(p, b); err != nil {
		sendMgmt(ws, 'R', []byte("consent persist failed: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	pairingResult(ws, "anchor_consent", t.Subject, map[string]any{
		"state": "ok", "next_anchor": t.Subject, "issued_at": t.IssuedAt,
		"note": fmt.Sprintf("root may now run: privatae-bastion claim-anchor --rotate <token from %s>", t.Subject),
	})
}
