package main

// Anchoring — binding a networked bastion to ONE host that approves who pairs
// next: every new pairing on an anchored machine needs the anchor host's
// approval.
//
// What an anchor IS: the owner claim (owner.go) with one more field. The box
// key signs "<owner>\n<anchor_host>\n<claimed_at>", and the token that was
// redeemed to make it binds the claim to exactly one host — the anchor host.
// The owner.go header's warning still holds: this is trusted by THIS box, for
// ONE decision (who may pair next), and by nothing and nobody else. A root
// intruder can anchor an unanchored box; the defence is to anchor every
// machine while its owner is the only one who can, and to make every pairing
// state visible on the heartbeat so tampering is at least seen.
//
// What the anchor host holds: its entity_sign key, which this box PINS here on
// first contact (verify_pubkey), the same TOFU the DCN store grants use over
// the same mTLS+bearer lane (dcn.go:48). Every pairing grant, revoke and
// consent record is verified under that pinned key before it changes a state.
//
// The rules this file enforces without a host in the loop:
//   - a NETWORKED box with no anchor serves NOTHING, on every lane. The anchor
//     is what turns default-deny on; before it exists there is no one to ask.
//     Local boxes are exempt — they serve one host and cannot be anchored.
//   - a pending pairing is a FILE. run.go starts nothing for it.
//   - a pairing grant flips pending -> active; caps on it are a ceiling for that
//     host on this machine (opFamily / capsAllow). Deny beats allow.
//   - a revoke flips active -> revoked and the lanes come down at once.
//   - rotation needs root AND the old anchor's signed consent, or the old
//     anchor silent for anchorDeadAfter. Without the second path a lost anchor
//     host bricks the machine's network.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// pairingGrantSuffix: pairings/<host>.grant.json — the anchor's signed grant
	// (and later revoke) for that host. loadPairings skips this suffix.
	pairingGrantSuffix = ".grant.json"
	// unapprovedAfter is how long a pairing may sit pending before every
	// heartbeat also lists it as an unapproved attempt. Ten minutes covers the
	// normal "I paired, now I'll go approve it" gap; anything longer is either
	// forgotten or was never the anchor user's doing, and both deserve a line
	// the detection plane can act on.
	unapprovedAfter = 10 * time.Minute
	// anchorDeadAfter: with no heartbeat success on the anchor pairing for this
	// long, root alone may rotate the anchor. 14 days is the default
	// — long enough that a holiday does not open the door, short enough
	// that a lost host does not brick the machine's network for a quarter.
	anchorDeadAfter = 14 * 24 * time.Hour
	// consentMaxAge bounds how long a signed anchor consent stays usable, so a
	// record left on disk months ago cannot be replayed to re-home the box.
	consentMaxAge = 30 * 24 * time.Hour
)

// anchorMu guards every read-modify-write of anchor.json, the grant files and
// the pairing state file: the mgmt lane (grant sync/drop) and the heartbeat
// (last_ok) touch them from different goroutines.
var anchorMu sync.Mutex

// anchorClaim is what travels on the heartbeat. verify_pubkey stays home: it is
// the box's pin, not a claim about the box.
type anchorClaim struct {
	Owner        string `json:"owner"`
	AnchorHost   string `json:"anchor_host"`
	AnchorHandle string `json:"anchor_handle"`
	ClaimedAt    string `json:"claimed_at"`
	PublicKey    string `json:"public_key"`
	Signature    string `json:"signature"` // over "<owner>\n<anchor_host>\n<claimed_at>"
}

type anchorFile struct {
	anchorClaim
	// The anchor host's entity_sign key, b64 raw ed25519, pinned TOFU from the
	// anchor pairing's DCN pin (or the first pairing_grant_sync) — never typed
	// by hand, never from any other pairing.
	VerifyPubkey string `json:"verify_pubkey,omitempty"`
	// The person's approval devices (device.go): b64 raw ed25519 public keys
	// of their own bastions, pinned here with machine authority (pin-device).
	// A write a host asks of this machine runs on an approval one of these
	// signed, verified here. Same file, same authority as the anchor key.
	DeviceKeys []string `json:"device_keys,omitempty"`
}

func anchorPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "anchor.json"), nil
}

func anchorConsentPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "anchor.consent.json"), nil
}

// anchorSigningInput is the exact byte sequence signed and verified, in one
// place so signer and verifier cannot drift (same discipline as owner.go).
//
// Prefixed with a kind tag: the owner claim and the anchor claim are signed by
// the SAME box key, and without the tag an owner claim for the name
// "x\nhost" would be byte-identical to an anchor claim for owner "x" on
// "host" (or the reverse). The tag makes the two spaces disjoint; the names
// are also refused if they contain a newline (claimNameOK), belt and braces.
func anchorSigningInput(owner, anchorHost, claimedAt string) []byte {
	return []byte("anchor\n" + owner + "\n" + anchorHost + "\n" + claimedAt)
}

// claimNameOK refuses a name that could be read as more than one field of a
// signing input: no newline or carriage return, not empty, bounded.
func claimNameOK(name string) error {
	if name == "" {
		return errors.New("name is empty")
	}
	if len(name) > 120 {
		return errors.New("name too long (max 120)")
	}
	if strings.ContainsAny(name, "\n\r") {
		return errors.New("name must not contain a newline")
	}
	return nil
}

func loadAnchorFile() (*anchorFile, error) {
	p, err := anchorPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var f anchorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func saveAnchorFile(f *anchorFile) error {
	p, err := anchorPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b)
}

// anchorVerified checks the file's own signature under the box key it names.
// A hand-edited anchor (the obvious forgery) fails here and counts as no anchor
// — the same rule as currentOwnerClaim: unverifiable must be ABSENT.
func anchorVerified(f *anchorFile) bool {
	if f == nil || f.Owner == "" || f.AnchorHost == "" || f.ClaimedAt == "" || f.PublicKey == "" || f.Signature == "" {
		return false
	}
	pub, err := base64.StdEncoding.DecodeString(f.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), anchorSigningInput(f.Owner, f.AnchorHost, f.ClaimedAt), sig)
}

// currentAnchor returns the verified anchor claim, or nil when the box is not
// anchored (the normal state for every local bastion) or the file is
// malformed or tampered.
func currentAnchor() *anchorClaim {
	f, err := loadAnchorFile()
	if err != nil || !anchorVerified(f) {
		return nil
	}
	c := f.anchorClaim
	return &c
}

// anchorVerifyKey returns the pinned anchor verify key, pinning it on first
// use from the anchor pairing's DCN pin when anchor.json has none yet. The
// DCN pin was itself TOFU'd over the anchor pairing's own mTLS+bearer lane,
// so copying it widens nothing. "" when neither exists yet.
func anchorVerifyKey() string {
	anchorMu.Lock()
	defer anchorMu.Unlock()
	return anchorVerifyKeyLocked()
}

func anchorVerifyKeyLocked() string {
	f, err := loadAnchorFile()
	if err != nil || !anchorVerified(f) {
		return ""
	}
	if f.VerifyPubkey != "" {
		return f.VerifyPubkey
	}
	cfgs, err := loadPairings()
	if err != nil {
		return ""
	}
	ac := pairingFor(cfgs, f.AnchorHost)
	if ac == nil {
		return ""
	}
	dcn, err := dcnLoadFile(ac.dcnDir())
	if err != nil || dcn.VerifyPubkey == "" {
		return ""
	}
	f.VerifyPubkey = dcn.VerifyPubkey
	if saveAnchorFile(f) != nil {
		return ""
	}
	return f.VerifyPubkey
}

// pinAnchorVerifyKey pins key when the box has none (TOFU over the anchor's
// mgmt lane); refuses a different key once one is held. Re-pinning is a
// rotation-level event (claim-anchor --rotate), not an op.
func pinAnchorVerifyKey(key string) error {
	anchorMu.Lock()
	defer anchorMu.Unlock()
	have := anchorVerifyKeyLocked()
	if have == "" {
		if pub, err := base64.StdEncoding.DecodeString(key); err != nil || len(pub) != ed25519.PublicKeySize {
			return errors.New("bad verify key")
		}
		f, err := loadAnchorFile()
		if err != nil || !anchorVerified(f) {
			return errors.New("box is not anchored")
		}
		f.VerifyPubkey = key
		return saveAnchorFile(f)
	}
	if have != key {
		return errors.New("verify key mismatch — refusing re-pin (rotate the anchor to change keys)")
	}
	return nil
}

// ── signed records from the anchor host ─────────────────────────────────────

// pairingTerms is parsed FROM verified canonical bytes only. One struct for the
// three kinds (pairing_grant, pairing_revoke, anchor_consent): the fields a
// kind does not use stay empty.
//
// Two conventions the host side must share:
//   - expires == "" means NEVER. A grant with no expiry stands until revoked;
//     a revoke record's own expiry is ignored (a revoke is final).
//   - anchor_consent with subject == "" means ANY host may become the next
//     anchor; a non-empty subject (host_name or handle) restricts it to that
//     one, and claim-anchor --rotate compares it against the token's handle.
type pairingTerms struct {
	Kind          string   `json:"kind"`
	Server        string   `json:"server"`  // this box's os.Hostname()
	Anchor        string   `json:"anchor"`  // the anchor host_name
	Subject       string   `json:"subject"` // the host_name the record is about ("" on consent = any)
	SubjectHandle string   `json:"subject_handle,omitempty"`
	Caps          []string `json:"caps,omitempty"`
	// Models narrows the `inference` cap to NAMED models, and is the
	// only field here that is a ceiling INSIDE a family rather than a family.
	// Absent or empty = unscoped, which is what every grant signed before this
	// field existed means and what the anchor pairing always holds. The
	// reserved entry "pii" includes the sterilizer lane (modelscope.go).
	Models   []string `json:"models,omitempty"`
	IssuedAt string   `json:"issued_at"`
	Expires  string   `json:"expires,omitempty"` // RFC3339; "" = never
	// VerifyKey is the SUBJECT host's entity_sign key (b64 raw ed25519), signed
	// into the grant by the anchor. On an anchored box a member's key is pinned
	// from here — never from a key the member host offers on first use
	// (pinnedKeyFor). Absent on grants signed before the field existed.
	VerifyKey string `json:"verify_key,omitempty"`
}

// pinnedKeyFor is the entity_sign key this box holds for a pairing FROM
// ANCHORING, or "" when it holds none: the anchor host's from claim-anchor
// (anchor.json), a member's from the anchor-signed pairing grant. On an
// anchored box a key a host OFFERS on its first DCN sync or session is never
// pinned (session.go, dcn.go) — a key that arrives on the lane it is meant to
// verify proves only that someone holds the lane.
func pinnedKeyFor(pairing string) string {
	a := currentAnchor()
	if a == nil || pairing == "" {
		return ""
	}
	if a.AnchorHost == pairing {
		return anchorVerifyKey()
	}
	if t, ok := pairingGrantTerms(pairing); ok {
		return t.VerifyKey
	}
	return ""
}

// verifyAnchorRecord checks signature (under the pinned anchor key), kind,
// server and anchor binding, and expiry. Every wall a record must pass before
// it changes a state on this box, in one function, so grant / revoke /
// consent cannot drift apart.
func verifyAnchorRecord(termsB64, sigB64, wantKind string) (*pairingTerms, error) {
	a := currentAnchor()
	if a == nil {
		return nil, errors.New("this box is not anchored")
	}
	keyB64 := anchorVerifyKey()
	if keyB64 == "" {
		return nil, errors.New("anchor verify key not pinned yet — the anchor host must sync first")
	}
	pub, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("bad pinned anchor verify key")
	}
	canonical, err := base64.StdEncoding.DecodeString(strings.TrimSpace(termsB64))
	if err != nil {
		return nil, errors.New("bad canonical terms")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return nil, errors.New("bad signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sig) {
		return nil, errors.New("signature does not verify under the pinned anchor key")
	}
	var t pairingTerms
	if err := json.Unmarshal(canonical, &t); err != nil {
		return nil, errors.New("signed terms unparsable")
	}
	if t.Kind != wantKind {
		return nil, fmt.Errorf("record kind is %q, want %q", t.Kind, wantKind)
	}
	if hn, _ := os.Hostname(); hn != "" && t.Server != hn {
		return nil, fmt.Errorf("record is for server %q, this box is %q", t.Server, hn)
	}
	if t.Anchor != a.AnchorHost {
		return nil, fmt.Errorf("record names anchor %q, this box's anchor is %q", t.Anchor, a.AnchorHost)
	}
	if t.Expires != "" {
		exp, err := time.Parse(time.RFC3339, t.Expires)
		if err != nil || !exp.After(time.Now()) {
			return nil, errors.New("record expired")
		}
	}
	return &t, nil
}

// pairingGrantFile is pairings/<host>.grant.json: the anchor's grant for that
// host as the exact signed bytes, plus the revoke that ended it, if any. Both
// kept: the file is the record of what this box was told and when.
type pairingGrantFile struct {
	TermsCanonical       string `json:"terms_canonical"`
	Signature            string `json:"signature"`
	SyncedAt             string `json:"synced_at"`
	RevokeTermsCanonical string `json:"revoke_terms_canonical,omitempty"`
	RevokeSignature      string `json:"revoke_signature,omitempty"`
	RevokedAt            string `json:"revoked_at,omitempty"`
}

func pairingGrantPath(host string) (string, error) {
	if !validHostName(host) {
		return "", fmt.Errorf("unsafe host name %q", host)
	}
	pd, err := pairingsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(pd, host+pairingGrantSuffix), nil
}

func loadPairingGrant(host string) (*pairingGrantFile, error) {
	p, err := pairingGrantPath(host)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var g pairingGrantFile
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func savePairingGrant(host string, g *pairingGrantFile) error {
	p, err := pairingGrantPath(host)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b)
}

// pairingCaps returns the verified caps ceiling for host on this box. ok is
// false when the host holds no grant, the grant no longer verifies, it was
// revoked, or it names another subject — every one of those is default-deny.
// Re-verified on every call: a tampered grant file authorises nothing.
func pairingCaps(host string) (caps []string, ok bool) {
	t, ok := pairingGrantTerms(host)
	if !ok {
		return nil, false
	}
	return t.Caps, true
}

// pairingGrantTerms is the whole verified grant for host — the caps ceiling and
// the model scope inside it. Every wall pairingCaps documented above
// applies here: it IS the same read, and both callers get an answer only from
// signed bytes that still verify under the pinned anchor key.
func pairingGrantTerms(host string) (*pairingTerms, bool) {
	g, err := loadPairingGrant(host)
	if err != nil || g.RevokeSignature != "" {
		return nil, false
	}
	t, err := verifyAnchorRecord(g.TermsCanonical, g.Signature, "pairing_grant")
	if err != nil || t.Subject != host {
		return nil, false
	}
	return t, true
}

// opFamily maps an op id to the caps family a pairing grant names. The host
// side signs the same list (allCaps below):
//
//	observe    observe:* and the computer:* observe rung, plus `uptime` (the only
//	           exec op; read-only)
//	session    session:* (terminal)
//	dcn        dcn_* + ctx_* + backup_fetch (it writes to this machine's storage),
//	           backup_push, backup_reseal and backup_list (this machine's own backups)
//	harness    the harness LANE (harness.go H frames, gated as "harness:run") and
//	           mode:* — this is not a mgmt op; the lane gates itself
//	egress     the egress LANE (egress.go; requests leave this machine's own
//	           connection) — gated as "egress"; not a mgmt op either
//	models     model:* — CHANGING which models are on this machine (modelswap.go):
//	           pulling one onto the user's disk, dropping one this host
//	           put here. Separate from "inference", which is only the right to
//	           USE what is already loaded.
//	inference  the three INBOUND forwards the host dials over its own tunnel:
//	           ollama :11434 (embed), the OpenAI-compatible server :18080 and
//	           the PII sterilizer :18081 (run.go / pii.go) — gated as
//	           "inference" at accept, and the heartbeat withholds the embed /
//	           llm-openai / pii capabilities from a pairing outside it. These
//	           used to be the one lane every pairing got regardless of its
//	           ceiling.
//	services   the SERVICE SLOT (service.go): service:up / service:down /
//	           service:status on the harness lane, and the per-slot inbound
//	           forwards (18100-18199) the host dials to reach a server it built
//	           here — gated as "services" at accept, like inference.
//
// "" is returned only for an op NOBODY has classified, and that now
// means DENY at the gate (capsAllowIn) rather than allow. stepup_* and
// pairing_* used to land here; both now carry an explicit ungrantable family.
func opFamily(op string) string {
	switch {
	// stepup_* is the APPROVAL step of another op, never a capability of its
	// own, so its real ceiling is the ceiling of the thing being approved and is
	// resolved per request from the request's kind (stepupOpFamily, stepup.go).
	// What is returned here is the FLOOR that applies if that resolution is ever
	// bypassed: a family name no grant can carry, because capsFamilyStepup is
	// deliberately absent from allCaps. A caller that reaches the generic gate
	// without the per-kind resolution is therefore refused, not served.
	case strings.HasPrefix(op, "stepup_"):
		return capsFamilyStepup
	// pairing_* is anchor-only and is refused by handleMgmtConnFor before this
	// is ever consulted. It is classified anyway so that nothing on this lane is
	// unclassified, and classified into a family no grant can carry, so that if
	// that earlier refusal is ever moved or removed this fails closed.
	case strings.HasPrefix(op, "pairing_"):
		return capsFamilyAnchor
	// audit_fetch reads this box's own record of what has been asked of it
	// (mgmt_audit.go) — the same KIND of thing as observe:*, a read of the
	// machine's own state that changes nothing. It carries a second gate on top
	// of this one: handleMgmtConnFor answers it only for the anchor pairing on
	// an anchored box, because the file names every pairing.
	case strings.HasPrefix(op, "observe:"), strings.HasPrefix(op, "computer:"),
		op == "uptime", op == mgmtAuditFetchOp:
		return "observe"
	case strings.HasPrefix(op, "session:"):
		return "session"
	case strings.HasPrefix(op, "dcn_"), strings.HasPrefix(op, "ctx_"), op == "backup_fetch",
		op == "backup_push", op == "backup_reseal", op == "backup_list":
		return "dcn"
	case op == "harness:run", strings.HasPrefix(op, "mode:"):
		return "harness"
	// The standing coder grant (coder_grant.go) authorizes mode:coder runs,
	// so installing or dropping one is the harness family too.
	case op == "coder_grant_sync", op == "coder_grant_drop":
		return "harness"
	// "model:" is NOT a longer spelling of "mode:" above — "model:pull"[:5] is
	// "model", so the two prefixes cannot collide — and it is deliberately its
	// own family rather than part of "inference". See modelswap.go's header:
	// folding it into inference would have handed every pairing already granted
	// the forwards the power to download gigabytes onto the user's disk and to
	// delete models from it, which nobody approved when that grant was given.
	case strings.HasPrefix(op, "model:"):
		return "models"
	case op == "egress":
		return "egress"
	case op == "inference":
		return "inference"
	// device_* (device.go) is answered by the person's OWN bastion — the
	// approval device — and files or reads an ask there. It authorizes nothing
	// on the box that answers it: only the person, at that console, signs.
	case strings.HasPrefix(op, "device_"):
		return capsFamilyNone
	// The SERVICE SLOT (service.go): service:up/down/status on the harness lane
	// and the per-slot inbound forwards, gated as "services". Its own family
	// rather than "harness", because "harness" only ever meant "run a job here
	// and clean up", and a server that stays up holding the user's repos is a
	// different thing to grant. "service:" cannot collide with "session:".
	case strings.HasPrefix(op, "service:"), op == serviceCapability,
		op == "service_grant_sync", op == "service_grant_drop":
		return "services"
	// op_* (ops.go): the ops the host wrote and asks this machine to run — held,
	// dry-run in a sandbox, applied under signed terms. Its own family: running
	// a program the host wrote is neither a folder grant nor a shell.
	case strings.HasPrefix(op, "op_"):
		return opsFamily
	}
	return ""
}

// allCaps is the full ceiling — what the anchor pairing itself is held to.
var allCaps = []string{"dcn", "egress", "harness", "inference", "models", "observe", "ops", "services", "session"}

// anchorOnly is the gate for a host-directed action whose effect is BOX-WIDE
// rather than per-pairing: swapping the binary every pairing runs on
// (update.go), placing a memory mirror on the machine (mirror.go), and
// terminating processes on it (contain.go). No caps family fits — the anchor
// user is the machine's admin, and only the anchor host may direct these on an
// anchored box. An unanchored LOCAL box gates nothing, as capsAllow does; an
// unanchored NETWORKED one refuses these outright (unanchoredNetworkedRefusal
// below) — directing a binary swap is the least appropriate thing to serve a
// machine that cannot say who is entitled to direct it. An empty self on an
// anchored box is refused for the same reason it is there. Returns the refusal
// reason, or "" to proceed.
// unanchoredNetworkedRefusal is THE gate: a networked box with no anchor serves
// nothing. It lives here, in the two functions every lane already consults, and
// not in each lane, because the first cut put it only in handleMgmtConnFor and
// closed a fifth of what its own commit message claimed.
//
// Both callers below used to open with `if a == nil { return "" }`, so the
// anchor was not merely who approves later pairings — it was the switch that
// turned default-deny ON. Before it existed every host paired to a networked box
// held every op family AND the box-wide directives. What the mgmt-frame-only
// version still served: harness:run (harness.go),
// session:open (session.go), egress (egress.go), the inference forwards on
// :11434/:18080/:18081 (run.go) and their heartbeat advertisement (agents.go),
// self-update (update.go), contain (contain.go), mirror placement (mirror.go),
// context-prep (contextprep.go). All of them route through capsAllow or
// anchorOnly, so one predicate here closes every one at once.
//
// The reachable path, and why it is not theoretical: `set-mode networked`, host
// A pairs, host B pairs before anyone runs claim-anchor. pairPrecheck only
// writes a pairing PENDING when an anchor exists (pair.go), and state "" reads
// active (config.go), so B comes straight up with full lanes.
//
// LOCAL is exempt and must stay so: a local bastion serves the one host it was
// paired with, and a second only on a yes typed at the machine (pair_terminal.go),
// and it cannot be anchored at all (cmdClaimAnchor refuses outside networked
// mode), so the pairing IS the authorization there. Most bastions are local.
//
// self-update is deliberately INSIDE the refusal. Directing a binary swap is the
// most dangerous thing on the list, and an unanchored networked box cannot say
// who is entitled to direct it. Nothing is lost: anchoring is done at the
// machine as root, so whoever can fix the anchor is already standing there.
// SELF-CONTAINED — it reads BOTH conditions itself. The first cut checked only
// boxMode() and left the currentAnchor() test to its callers, which was true of
// capsAllow and anchorOnly (they call it inside their own `a == nil` branch) and
// false of handleMgmtConnFor, which calls it directly. So every networked box
// refused everything, anchored or not. Caught by running the suite as an
// unprivileged user, which is the run that had been skipped; as root the same
// build passed the one test written for it and nothing else was exercised. A
// predicate that is only correct at some call sites is a predicate that will
// be called wrongly.
func unanchoredNetworkedRefusal(what string) string {
	if boxMode() != modeNetworked || currentAnchor() != nil {
		return ""
	}
	return "refused: " + what + " — this machine is networked but NOT ANCHORED, so it serves " +
		"no host. Until it is anchored every paired host would hold every capability here. " +
		"Run `privatae-bastion claim-anchor` on the machine with machine authority to bind " +
		"it to the host that governs it."
}

func anchorOnly(self, what string) string {
	a := currentAnchor()
	if a == nil {
		return unanchoredNetworkedRefusal(what)
	}
	if self == "" {
		return "refused: " + what + " — no pairing identity (default-deny on an anchored box)"
	}
	if a.AnchorHost == self {
		return ""
	}
	return "refused: " + what + " is directed only by the anchor host (" + a.AnchorHost + ") on an anchored box; " + self + " is a member pairing"
}

// capsAllow is the ceiling check for one op on one pairing of an anchored
// box. The anchor pairing is unconstrained (its user IS the admin). Any other
// pairing needs a verified grant whose caps contain the op's family. Returns
// the refusal reason, or "" to proceed. An unanchored NETWORKED box refuses
// everything. An unanchored LOCAL box gates ONLY what the person at the machine
// has switched off — it used to gate nothing at all, and this sentence said
// so for longer than it was true, which is how the next reader re-derives a
// bug that has been fixed. On an anchored box an EMPTY self (no pairing
// identity) is default-deny — it can never be the anchor and holds no grant,
// the same rule handleMgmtConnFor applies.
func capsAllow(self, op string) string {
	return capsAllowIn(self, op, opFamily(op))
}

// The three family names that are NOT capabilities, and are deliberately absent
// from allCaps so that no grant can ever name one — and, because the local
// switch (localdeny.go) offers exactly the families a grant can name, absent
// from what the person at the machine can switch off too.
const (
	// capsFamilyStepup / capsFamilyAnchor are FLOORS: the op has a real ceiling
	// decided elsewhere (per request kind for stepup_*, the anchor rule for
	// pairing_*), and these are what applies if that decision is bypassed. Being
	// ungrantable is the point — bypassing the real gate refuses, never serves.
	capsFamilyStepup = "stepup"
	capsFamilyAnchor = "anchor"
	// capsFamilyNone is the opposite: a lane that genuinely authorizes NO
	// capability on this box, where holding a verified grant at all is the whole
	// ceiling. It exists because "no family" now means DENY, and without a way
	// to say "none is correct here" the only way to express it would be to
	// invent a family, which would then have to be granted to work.
	capsFamilyNone = "-"
)

// capsAllowIn is capsAllow against an EXPLICIT family — the form the one lane
// whose family is not a property of its op name needs (stepup_*, gated in
// handleMgmtConnFor on the family of the thing being approved).
//
// DEFAULT-DENY on an unclassified op. capsAllow used to
// return "" — allowed — for any op opFamily did not know, which meant a member
// pairing holding any verified grant could be asked for it regardless of what
// the anchor granted. The comment in handleMgmtConnFor had said so in writing
// since the unanchored case was patched; only that one case was closed, and on
// an ANCHORED box the hole stood. Nothing about an op having no family says the
// pairing may be asked for it; it says nobody decided, and an undecided
// permission is not a granted one.
//
// The anchor pairing returns below the local switch and above the family check,
// so an unclassified op does not touch it — its user is the admin of the
// machine and is unconstrained by construction.
func capsAllowIn(self, op, fam string) string {
	// An unanchored NETWORKED box refuses everything, and that refusal names the
	// fix. It comes first because a deny-list message would be true and useless
	// to someone whose real problem is that nothing governs this box yet.
	if why := unanchoredNetworkedRefusal("op '" + op + "'"); why != "" {
		return why
	}
	// THE LOCAL SWITCH IS CHECKED BEFORE ANY ANCHOR STATE AT ALL, and that
	// placement is the whole feature rather than a detail.
	//
	// The anchor pairing is otherwise unconstrained — its user IS the machine's
	// admin. But on a single-person machine the only pairing IS the anchor, so
	// a switch that exempted it would do nothing at all on exactly the computer
	// where it was asked for: the local control would be a button with no
	// effect on the one host that box serves.
	//
	// IT WAS BELOW THE `a == nil` RETURN AND THAT MADE IT A NO-OP ON EVERY LOCAL
	// BASTION — the box the switch is most of the point of. An unanchored box
	// left here before the list was ever read, so the
	// page offered the switch, wrote the denial, confirmed "can no longer read
	// your files" and tagged the card "switched off by you", while every op went
	// on being served. That is the worst possible version of a security control:
	// one that reports success. It also broke this page's own stated invariant —
	// "it cannot disagree with the gate, because it asks the gate"
	// (uigiven.go:32-41) — because `Held` came from capsAllow and the
	// switched-off tag came from the deny list, and on a local box those two
	// sources gave opposite answers.
	//
	// It stays deny-only wherever it sits: the only value this branch can
	// produce is a refusal. It cannot return "" and so cannot admit an op that
	// anything below would have refused.
	//
	// It reads the RESOLVED family, not opFamily(op), and that matters for
	// exactly one lane: a step-up is gated on the family of the thing being
	// approved, so a person who has switched "session" off here also stops the
	// host raising the root-shell approval prompt that session:root needs. Under
	// opFamily alone that prompt would have carried the ungrantable "stepup"
	// floor, which is in nobody's deny list, and the switch would have been
	// silently bypassable by asking for the approval instead of the op.
	if fam != "" && fam != capsFamilyNone && localDenied(self, fam) {
		return localDenyRefusal(fam)
	}
	a := currentAnchor()
	if a == nil {
		// Unanchored and LOCAL: the pairing itself is the authorization, which
		// is what a local bastion is. Nothing below applies.
		return ""
	}
	if self == "" {
		return "refused: no pairing identity on this lane (default-deny on an anchored box)"
	}
	if a.AnchorHost == self {
		return ""
	}
	caps, ok := pairingCaps(self)
	if !ok {
		return "refused: this pairing holds no verified pairing grant from the anchor (default-deny)"
	}
	if fam == capsFamilyNone {
		return ""
	}
	if fam == "" {
		return fmt.Sprintf("refused: op '%s' is in no capability family, so no pairing grant "+
			"can name it (default-deny). Give it a family in opFamily (anchor.go).", op)
	}
	for _, c := range caps {
		if c == fam {
			return ""
		}
	}
	return fmt.Sprintf("refused: op '%s' is family '%s', not in this pairing's caps %v", op, fam, caps)
}

// ── pairing liveness (last_ok) ─────────────────────────────────────────────

// pairingStatePath is <configDir>/pairing_state.json: last successful
// heartbeat per pairing. Box-level, not under pairings/, so loadPairings
// never sees it and a pairing's own file is only rewritten by pair/grant.
func pairingStatePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "pairing_state.json"), nil
}

type pairingState struct {
	LastOK string `json:"last_ok"` // RFC3339 of the last 2xx heartbeat
}

func loadPairingStates() map[string]pairingState {
	out := map[string]pairingState{}
	p, err := pairingStatePath()
	if err != nil {
		return out
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

// recordPairingOK is called by the heartbeat on every 2xx. Best-effort: a
// failure to note the time never fails a beat.
func recordPairingOK(host string) {
	anchorMu.Lock()
	defer anchorMu.Unlock()
	st := loadPairingStates()
	st[host] = pairingState{LastOK: time.Now().UTC().Format(time.RFC3339)}
	p, err := pairingStatePath()
	if err != nil {
		return
	}
	if b, err := json.MarshalIndent(st, "", "  "); err == nil {
		_ = atomicWrite(p, b)
	}
}

// lastOK returns the last successful heartbeat for host, zero when none.
func lastOK(host string) time.Time {
	if s, ok := loadPairingStates()[host]; ok && s.LastOK != "" {
		if t, err := time.Parse(time.RFC3339, s.LastOK); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ── what the heartbeat carries ─────────────────────────────────────────────

// pairingEntry is one pairing on this box as told to the ANCHOR host: name,
// handle, state, since. Same privacy line as peers.go — never keys or grants.
type pairingEntry struct {
	HostName string `json:"host_name"`
	Handle   string `json:"handle"`
	State    string `json:"state"`
	Since    string `json:"since,omitempty"`
}

// pairingsReport lists EVERY pairing on the box, including the one asking.
// "since" is first_seen — when the host was first paired here — kept across
// --replace, so a pending host re-presenting a token keeps its original age
// (the 10-minute unapproved clock does not restart). nil when the directory
// cannot be read — the host keeps what it has, as with peers.
//
// A pairing whose file this build refuses (Config.invalid) is left out: it is
// never served, so to a host it is not on this box. A host knows the states
// active, pending and revoked and may read any other as active, so "invalid"
// is never sent. The machine's own status and setup page still show it.
func pairingsReport() []pairingEntry {
	cfgs, err := loadPairings()
	if err != nil {
		return nil
	}
	out := make([]pairingEntry, 0, len(cfgs))
	for _, c := range cfgs {
		if c.HostName == "" || c.invalid != "" {
			continue
		}
		out = append(out, pairingEntry{HostName: c.HostName, Handle: handleOf(c.HostName),
			State: c.stateName(), Since: sinceOf(c)})
	}
	return out
}

// unapprovedAttempts is every pairing that has sat pending longer than
// unapprovedAfter. Goes on EVERY heartbeat, not only the anchor's: a host that
// shares the box should also see that someone is trying to join it.
//
// nil vs EMPTY is the same contract as peers.go, and for the same reason: the
// host keeps the stored list on an ABSENT key (COALESCE), so "none" must
// travel as an explicit [] or a box that once reported [X] would show X as an
// unapproved attempt forever after X was approved or revoked. nil is returned
// ONLY when the pairings could not be enumerated — then we say nothing.
func unapprovedAttempts(now time.Time) []peerAnnounce {
	list := pairingsReport()
	if list == nil {
		return nil
	}
	out := make([]peerAnnounce, 0)
	for _, e := range list {
		if e.State != pairingPending || e.Since == "" {
			continue
		}
		since, err := time.Parse(time.RFC3339, e.Since)
		if err != nil || now.Sub(since) < unapprovedAfter {
			continue
		}
		out = append(out, peerAnnounce(e))
	}
	return out
}

// pairingEnforcing is what the enforcing report adds for one pairing: its
// state, the caps ceiling it is held to, and the grant signature the host can
// match against what it signed (signatures, never terms — enforcing.go).
func pairingEnforcing(self string) map[string]any {
	out := map[string]any{}
	cfgs, err := loadPairings()
	if err != nil {
		return out
	}
	c := pairingFor(cfgs, self)
	if c == nil {
		return out
	}
	out["pairing_state"] = c.stateName()
	// The name THIS pairing is known by on this box — what a reach grant must
	// name as its subject (service_reach.go). A host can hold more than one name
	// (a legacy one and the current one); this says which one the box enforces.
	out["pairing_host"] = c.HostName
	a := currentAnchor()
	if a == nil {
		return out
	}
	out["anchored"] = true
	if a.AnchorHost == self {
		out["pairing_caps"] = allCaps
		out["is_anchor"] = true
		return out
	}
	caps, ok := pairingCaps(self)
	if !ok {
		out["pairing_caps"] = []string{}
		return out
	}
	if caps == nil {
		caps = []string{}
	}
	out["pairing_caps"] = caps
	if g, err := loadPairingGrant(self); err == nil {
		out["pairing_grant"] = map[string]any{"signature": g.Signature, "synced_at": g.SyncedAt}
	}
	return out
}

// ── claim-anchor ───────────────────────────────────────────────────────────

// cmdClaimAnchor is `sudo privatae-bastion claim-anchor [--rotate] [--owner <name>] <token>`.
//
// Fresh box: redeem the token (a real pairing, active), then sign the anchor
// under the box key. Box with ONE pairing that is the token's host: the token
// is redeemed as a rotation of that pairing (its port, stores and DCN pin
// survive) and it becomes the anchor. Box with a pairing for another host, or
// several pairings: refused — which of them the admin meant is not this
// command's guess to make, and an anchor next to an unapproved active pairing
// would be a hole on day one.
// cmdRepinAnchor re-signs anchor.json for the SAME host under a new host_name.
//
// WHY THIS EXISTS. A host's own name can change under the box — a move of
// the Host address to a new zone does exactly that. `pair
// --replace` updates the PAIRING to the new name but never touches anchor.json
// (writeAnchor is called from claim-anchor alone), so an anchored box goes on
// naming its anchor by the old name and refuses every signed record that names
// the new one (verifySignedTerms: "record names anchor %q, this box's anchor is
// %q"). And --rotate cannot do it: it exists to move the anchor to a DIFFERENT
// host and refuses a same-handle claim outright.
//
// So this is the third case, and it is deliberately the narrowest of the three:
// same owner, same handle, same host — only the DNS name it is reached by
// changes. It cannot move the anchor anywhere. Moving it still means --rotate,
// with the current anchor's consent or its silence.
//
// Walls: root (same as every other anchor write), an existing anchor to re-pin,
// and a live pairing on this box whose handle matches the current anchor's.
// The new name is taken from that pairing, never from an argument — nothing
// here is typed by hand.
//
// The pinned verify key is CARRIED OVER, unlike a fresh or rotated anchor. That
// is the whole difference: a rotation deliberately drops the pin because the
// anchor becomes a different host whose key must be learned again, while here
// the host is the same one it always was and dropping its pin would re-open a
// TOFU window for no reason.
func cmdRepinAnchor() error {
	if err := requireMachineAuthority("claim-anchor --repin"); err != nil {
		return err
	}
	if boxMode() != modeNetworked {
		return errors.New("--repin needs networked mode — a local bastion has no anchor")
	}
	prev := currentAnchor()
	if prev == nil {
		return errors.New("--repin: this box is not anchored — run claim-anchor with a token from the host that should hold it")
	}
	// currentAnchor returns the CLAIM; the pinned verify key lives on the file.
	prevFile, err := loadAnchorFile()
	if err != nil {
		return fmt.Errorf("--repin: could not read anchor.json: %w", err)
	}
	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	cfg := pairingFor(cfgs, handleOf(prev.AnchorHost))
	if cfg == nil {
		return fmt.Errorf("--repin: no pairing on this box belongs to %s — re-pair it first (`privatae-bastion pair --replace <token>`), then re-pin",
			prev.AnchorHost)
	}
	if cfg.HostName == prev.AnchorHost {
		fmt.Printf("anchor already names %s — nothing to re-pin.\n", prev.AnchorHost)
		return nil
	}
	owner := prev.Owner
	if oc := currentOwnerClaim(); oc != nil && oc.Owner != "" {
		owner = oc.Owner
	}
	if err := writeAnchorPreservingPin(owner, cfg.HostName, prevFile.VerifyPubkey); err != nil {
		return err
	}
	if _, err := writeOwnerClaim(owner); err != nil {
		return err
	}
	fmt.Printf("anchor re-pinned: %s -> %s (owner %q, pinned key kept)\n",
		prev.AnchorHost, cfg.HostName, owner)
	return nil
}

// anchorAlreadyHolds: the anchor names an active pairing here, and host
// (claim-anchor --host, "" for none) names that same pairing.
func anchorAlreadyHolds(cfgs []*Config, prev *anchorClaim, host string) bool {
	c := pairingFor(cfgs, prev.AnchorHost)
	if c == nil || !c.active() {
		return false
	}
	if host == "" {
		return true
	}
	named, err := pickPairing(cfgs, host)
	return err == nil && named.HostName == c.HostName
}

// pickPairing resolves --host against this box's pairings. It accepts the full
// host_name the box reports, or just the handle in front of it, because the
// name the user is looking at depends on which surface they read it from —
// `8abb770bbfde71d0` in Circles, `8abb770bbfde71d0.host.privatae.ai` in the
// claim-anchor error. Refusing the short form would mean refusing the thing the
// user most obviously typed.
func pickPairing(cfgs []*Config, want string) (*Config, error) {
	want = strings.TrimSpace(want)
	if c := pairingFor(cfgs, want); c != nil {
		return c, nil
	}
	if c := pairingFor(cfgs, handleOf(want)); c != nil {
		return c, nil
	}
	for _, c := range cfgs {
		if strings.EqualFold(c.HostName, want) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("--host %q is not one of this box's pairings (%s)",
		want, strings.Join(hostNames(cfgs), ", "))
}

func cmdClaimAnchor(token string, rotate bool, owner, host string) error {
	if err := requireMachineAuthority("claim-anchor"); err != nil {
		return err
	}
	// Before boxMode() below, which reaches configDir -> MkdirAll, and before
	// loadPairings, which reaches pairingsDir -> MkdirAll. pairWithToken carries
	// the same guard, so no pairing could be WRITTEN from a forked dir either way
	// — but both calls above would have CREATED that directory first, and this
	// file's own test treats creating it as the damage.
	if err := singletonGuardForPair(); err != nil {
		return err
	}
	if boxMode() != modeNetworked {
		return fmt.Errorf("claim-anchor needs networked mode — a local bastion serves only the Hosts its person said yes to and needs no anchor (%s, then `privatae-bastion set-mode networked`)", adminHowTo())
	}
	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	prev := currentAnchor()
	// Already anchored to the host this asks for (no token, no other host
	// named), and that host's pairing is active: done, not an error. `pair`
	// anchors a networked box to its first host by itself, and an installer
	// that runs claim-anchor after pairing must find that a success. An anchor
	// whose pairing is pending or revoked is not done, and is refused below as
	// before. --host takes the short handle as well as the full name
	// (pickPairing), so the same host named either way is the same request.
	if prev != nil && !rotate && token == "" && anchorAlreadyHolds(cfgs, prev, host) {
		fmt.Printf("already anchored to %s (owner %q)\n", prev.AnchorHost, prev.Owner)
		return nil
	}
	if prev != nil && !rotate {
		return fmt.Errorf("this box is already anchored to %s — `claim-anchor --rotate <token>` moves the anchor (needs the current anchor's consent, or %d days of silence from it)", prev.AnchorHost, int(anchorDeadAfter.Hours()/24))
	}
	if prev == nil && rotate {
		return errors.New("--rotate: this box is not anchored yet — run claim-anchor without --rotate")
	}
	// --host and a token both answer "which host", so taking both means one of
	// them is being ignored and the user cannot tell which. Refuse rather than
	// pick: the token is redeemable and silently discarding it would burn it.
	if host != "" && token != "" {
		return errors.New("--host and a token both name the anchor host — pass one. A token names it by itself; --host names a pairing this box already has")
	}
	var consent *pairingTerms
	var cfg *Config

	// NO TOKEN — the normal path for a box you have already paired.
	//
	// The token was the whole reason this command was incoherent: you pair the
	// machine to your host, then `set-mode networked`, and then the only way to
	// anchor was to go back to the dashboard, press "Set up a bastion" a SECOND
	// time and redeem a second pairing token against a machine that is already
	// paired (the first one is burned at redeem — the host consumes it in the
	// same UPDATE that validates it). Nothing in the product said so.
	//
	// And on a box with exactly one pairing the token proved nothing the pairing
	// did not already prove. It does not gate root: root on this machine can mint
	// tokens from their OWN host freely, so the token never stood between them and
	// the anchor — the one-pairing wall below is what does, and it still stands.
	// What the token gated was the legitimate owner, who had already proved the
	// same relationship by pairing.
	//
	// So: with exactly one pairing, anchor to that host. Deliberately NOT extended
	// to --rotate (handled above, still token-only): rotating names a DIFFERENT
	// host, which is a widen and needs that host to have issued something.
	if token == "" {
		if rotate {
			return errors.New("--rotate needs a token from the host taking the anchor — it names a different host, so that host has to issue it")
		}
		// A SHARED MACHINE IS THE NORMAL CASE, not the exception. This is the
		// machine several people's hosts pair to — that is what networked mode
		// MEANS — so "more than one pairing" describes the thing the anchor exists
		// to govern. The first cut of this refused a multi-pairing box outright and
		// sent the user to fetch a token, which put the second token back exactly
		// where it had just been removed, on the only box that really needs an
		// anchor. Hit on the first machine it was tried on, serving three hosts.
		//
		// The ambiguity is real: with three pairings the box cannot know which host
		// should hold the anchor. But the answer to an ambiguous choice is to let
		// the user name it, not to demand a credential. --host does that, and the
		// refusal below prints the names to choose from.
		//
		// Naming a host is NOT a widen, for the same reason the no-token path is
		// not: every candidate is already paired to this box. Choosing among hosts
		// that already have lanes here grants reach to nobody new — and it TIGHTENS,
		// because from then on every further pairing waits for that host's approval.
		switch {
		case host != "":
			c, err := pickPairing(cfgs, host)
			if err != nil {
				return err
			}
			cfg = c
		case len(cfgs) == 1:
			cfg = cfgs[0]
		case len(cfgs) == 0:
			return fmt.Errorf("this box has no pairing yet — pair it to your host first (`privatae-bastion pair <token>`, token from Network → Set up a bastion), then `privatae-bastion claim-anchor` with no token")
		default:
			return fmt.Errorf("this box serves %d hosts — say which one should hold the anchor:\n%s\n  e.g. `privatae-bastion claim-anchor --host %s`\nThe anchor host approves every pairing made here from then on; the other pairings keep the lanes they already have",
				len(cfgs), "    "+strings.Join(hostNames(cfgs), "\n    "), hostNames(cfgs)[0])
		}
		// A pairing whose file this build refuses is never served, so the box
		// could not reach the host it would be anchored to, and that host would
		// approve every pairing made here. Refused with the reason, before
		// anything is written.
		if cfg.invalid != "" {
			return fmt.Errorf("%s cannot hold the anchor: %s", cfg.HostName, cfg.invalid)
		}
		// REVOKED is not "waiting", it is a decision, and it must not be undone by
		// a command the user ran to do something else. pair.go holds the same line
		// for a re-pair (pending again, never straight back to active),
		// and cfg.active() is false for BOTH pending and revoked, so flipping on
		// !active() would have quietly reinstated it.
		if cfg.State == pairingRevoked {
			return fmt.Errorf("%s is REVOKED on this box — claim-anchor will not reinstate it; re-pair that host first (`privatae-bastion pair --replace <token>`)", cfg.HostName)
		}
		// Validate the owner BEFORE mutating anything. claimNameOK runs below for
		// both paths, and a bad --owner there would abort having already flipped
		// the pairing active — a half-applied command, and the one state change
		// this path makes. Resolve and check it here so the flip is the last thing
		// that happens and nothing is left behind on a refusal.
		owner = strings.TrimSpace(owner)
		if owner == "" {
			if oc := currentOwnerClaim(); oc != nil {
				owner = oc.Owner
			} else {
				owner = handleOf(cfg.HostName)
			}
		}
		if err := claimNameOK(owner); err != nil {
			return fmt.Errorf("owner: %w", err)
		}
		// The anchor never waits on itself — same rule as the forceActive redeem
		// below, applied to the pairing that is already here.
		if !cfg.active() {
			if err := cfg.updateOnDisk(func(d *Config) { d.State = pairingActive }); err != nil {
				return err
			}
		}
	} else {
		handle, _, derr := decodeToken(token)
		if derr != nil {
			return derr
		}
		if rotate {
			if handleOf(prev.AnchorHost) == handle {
				return fmt.Errorf("--rotate: %s is already the anchor — to rotate its credentials use `pair --replace`", prev.AnchorHost)
			}
			consent, err = rotationPermitted(prev, handle, time.Now())
			if err != nil {
				return err
			}
		} else {
			switch {
			case len(cfgs) == 0:
				// fresh box — the token makes the first pairing and it is the anchor
			case len(cfgs) == 1 && pairingFor(cfgs, handle) != nil:
				// the sole pairing is the token's host: it becomes the anchor
			case len(cfgs) == 1:
				return fmt.Errorf("this box already serves %s; the anchor must be that host — anchor with a token from it, or with no token at all (`privatae-bastion claim-anchor`), or remove that pairing first", cfgs[0].HostName)
			default:
				return fmt.Errorf("this box serves %d hosts (%s); an anchor can only be claimed on a box with one pairing or none — remove the others first", len(cfgs), strings.Join(hostNames(cfgs), ", "))
			}
		}
		// Redeem: a rotation of the pairing when the host is already here, a new
		// active pairing otherwise. forceActive: the anchor never waits on itself.
		c, _, perr := pairWithToken(token, pairingFor(cfgs, handle) != nil, true)
		if perr != nil {
			return perr
		}
		cfg = c
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		if oc := currentOwnerClaim(); oc != nil {
			owner = oc.Owner
		} else if prev != nil {
			owner = prev.Owner
		} else {
			owner = handleOf(cfg.HostName)
		}
	}
	if err := claimNameOK(owner); err != nil {
		return fmt.Errorf("owner: %w", err)
	}
	if err := writeAnchor(owner, cfg.HostName); err != nil {
		return err
	}
	// The owner claim is re-signed too: claim-anchor does what claim-owner does.
	if _, err := writeOwnerClaim(owner); err != nil {
		return err
	}
	if rotate {
		// The old anchor becomes an ordinary member that the NEW anchor must
		// approve — its user no longer holds the admin role on this box. Consent
		// is single-use: remove it so it cannot re-home the box a second time.
		if old := pairingFor(cfgs, prev.AnchorHost); old != nil && old.HostName != cfg.HostName {
			// A locked read-modify-write: the daemon may be saving this file's
			// endpoint at the same moment, and a whole-struct save from this
			// process's stale copy would lose one side or the other.
			if err := old.updateOnDisk(func(d *Config) { d.State = pairingPending }); err != nil {
				return err
			}
		}
		if consent != nil {
			if p, err := anchorConsentPath(); err == nil {
				_ = os.Remove(p)
			}
		}
	}
	// Anchoring is the act that claims the machine, so it records the marker too
	// (singleton.go). This also means anchoring a fleet of boxes creates the
	// singleton on each one as it goes, rather than needing a separate pass.
	_ = maybeWriteMarker()
	fmt.Printf("anchored to %s (owner %q)\n", cfg.HostName, owner)
	fmt.Println("  Every host paired from now on waits, pending, until this anchor host approves it.")
	fmt.Println("  " + restartHint())
	return nil
}

// writeAnchor signs and installs anchor.json under the box key. A fresh anchor
// (or a rotated one) starts with NO verify key: the new anchor host's key is
// pinned on first contact, never carried over from the previous host.
// writeAnchorPreservingPin is writeAnchor with the TOFU pin carried across.
// Only --repin uses it: same host, new name, so the key it pinned is still the
// right key. Every other path drops the pin on purpose.
func writeAnchorPreservingPin(owner, anchorHost, verifyPubkey string) error {
	if err := writeAnchor(owner, anchorHost); err != nil {
		return err
	}
	if verifyPubkey == "" {
		return nil
	}
	anchorMu.Lock()
	defer anchorMu.Unlock()
	f, err := loadAnchorFile()
	if err != nil || f == nil {
		return err
	}
	f.VerifyPubkey = verifyPubkey
	return saveAnchorFile(f)
}

func writeAnchor(owner, anchorHost string) error {
	if err := claimNameOK(owner); err != nil {
		return fmt.Errorf("owner: %w", err)
	}
	if !validHostName(anchorHost) {
		return fmt.Errorf("anchor host %q is not a valid host name", anchorHost)
	}
	anchorMu.Lock()
	defer anchorMu.Unlock()
	pub, priv, err := loadOrCreateOwnerKey()
	if err != nil {
		return err
	}
	claimedAt := time.Now().UTC().Format(time.RFC3339)
	sig := ed25519.Sign(priv, anchorSigningInput(owner, anchorHost, claimedAt))
	f := &anchorFile{anchorClaim: anchorClaim{
		Owner: owner, AnchorHost: anchorHost, AnchorHandle: handleOf(anchorHost),
		ClaimedAt: claimedAt,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}}
	return saveAnchorFile(f)
}

// rotationPermitted is the second wall for --rotate (root is the first):
// either a verified consent record from the current anchor naming the new
// host (or any host), or the current anchor silent past anchorDeadAfter.
// Returns the consent used (nil on the silence path).
func rotationPermitted(prev *anchorClaim, newHandle string, now time.Time) (*pairingTerms, error) {
	if p, err := anchorConsentPath(); err == nil {
		if raw, err := os.ReadFile(p); err == nil {
			var rec struct {
				TermsCanonical string `json:"terms_canonical"`
				Signature      string `json:"signature"`
			}
			if json.Unmarshal(raw, &rec) == nil {
				t, err := verifyAnchorRecord(rec.TermsCanonical, rec.Signature, "anchor_consent")
				switch {
				case err != nil:
					return nil, fmt.Errorf("anchor consent on disk does not verify: %w", err)
				case t.Subject != "" && t.Subject != newHandle && handleOf(t.Subject) != newHandle:
					return nil, fmt.Errorf("anchor consent names %q as the next anchor, the token is for %q", t.Subject, newHandle)
				}
				if issued, err := time.Parse(time.RFC3339, t.IssuedAt); err != nil || now.Sub(issued) > consentMaxAge {
					return nil, errors.New("anchor consent is too old (or has no issued_at) — ask the current anchor for a fresh one")
				}
				return t, nil
			}
		}
	}
	// No consent: the silence path. The reference is the last heartbeat the
	// anchor pairing got through; before any beat succeeded, the claim time.
	ref := lastOK(prev.AnchorHost)
	if ref.IsZero() {
		if t, err := time.Parse(time.RFC3339, prev.ClaimedAt); err == nil {
			ref = t
		}
	}
	if ref.IsZero() || now.Sub(ref) < anchorDeadAfter {
		return nil, fmt.Errorf("--rotate needs the current anchor's consent (a pairing_anchor_consent op from %s writes anchor.consent.json), or %d days without a successful heartbeat from it (last success %s)",
			prev.AnchorHost, int(anchorDeadAfter.Hours()/24), ref.UTC().Format(time.RFC3339))
	}
	return nil, nil
}

// sortedCaps normalises a caps list for reporting: sorted, deduplicated.
func sortedCaps(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
