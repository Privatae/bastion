package main

// device.go — the approval device, and the one check every write on a networked
// box runs.
//
// A write on a
// networked box needs an approval THIS box verified. Two ways to give one:
//
//   - at this console, with the factor enrolled here (stepup.go — a box-issued
//     approval id, single-use, bound to a purpose); or
//   - from the person's OWN bastion, the approval device: a key held there,
//     pinned on this box at anchoring with machine authority (pin-device), signs
//     {purpose, nonce, expires, uses}. This box verifies the signature under a
//     pinned device key, derives the purpose itself, refuses an expired or
//     replayed one, and burns the nonce. The pod relays the request and the
//     signed answer and can forge neither.
//
// Both land in approvalOK below, which is what the gates call. The person's own
// laptop's bastion is the device: it holds the key (device-init), shows what is
// being asked in the box's own words (device-approvals), and signs on a tap
// (device-approve). Pending asks reach it from the pod on its own mgmt lane
// (device_request / device_status).
//
// Every approval is bounded: expiry (a device approval lives at most
// deviceApprovalMaxTTL), uses (one), a nonce (never twice). "From now on" —
// a reusable, bounded op-grant — is rung 6's, and rides the same verification.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// The longest a device-signed approval may be valid for. One run, one tap,
	// and the run happens as soon as the pod has the answer; an hour covers a
	// slow relay many times over and keeps a leaked approval short-lived.
	deviceApprovalMaxTTL = time.Hour
	// How long a pending ask waits on the device before it lapses.
	deviceRequestTTL = 24 * time.Hour
	// deviceApprovalVersion is the format the signed bytes carry; a verifier
	// refuses any other, so a future shape cannot be read as this one.
	deviceApprovalVersion = 1
	// deviceClockSkew is how far a governed box's clock may lag the device's
	// before an approval signed for the full TTL reads as over-long here.
	// Kerberos' default tolerance; a fleet box a minute behind was refusing
	// every approval under the first cut's one-minute allowance.
	deviceClockSkew = 5 * time.Minute
)

var deviceMu sync.Mutex

// ── keys pinned on THIS box (the verifier's side) ───────────────────────────

// devicePinned reports whether this box holds at least one device key.
func devicePinned() bool {
	return len(deviceKeys()) > 0
}

// deviceKeys is the pinned device keys (b64 raw ed25519 public keys), from
// anchor.json — the same file, the same authority (machine authority at the
// box) that pins the anchor's verify key.
func deviceKeys() []string {
	anchorMu.Lock()
	defer anchorMu.Unlock()
	f, err := loadAnchorFile()
	if err != nil || f == nil {
		return nil
	}
	return append([]string(nil), f.DeviceKeys...)
}

// secondFactorAvailable: something on this box can vouch for the person — a
// TOTP enrolled here for this pairing, or a device key pinned for the box.
// Without either, a write on a networked box is refused outright (never
// "unenrolled passes").
func secondFactorAvailable(dir string) bool {
	return stepupEnrolled(dir) || devicePinned()
}

// pinDeviceKey adds a device key. Machine authority is the caller's to check
// (the CLI does); refuses a malformed key; idempotent for a key already held.
func pinDeviceKey(key string) error {
	key = strings.TrimSpace(key)
	pub, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad device key (want a base64 raw ed25519 public key, as device-init prints)")
	}
	anchorMu.Lock()
	defer anchorMu.Unlock()
	f, err := loadAnchorFile()
	if err != nil || f == nil {
		return errors.New("box is not anchored — pin-device belongs to an anchored, networked box")
	}
	for _, k := range f.DeviceKeys {
		if k == key {
			return nil
		}
	}
	f.DeviceKeys = append(f.DeviceKeys, key)
	return saveAnchorFile(f)
}

func unpinDeviceKey(key string) error {
	key = strings.TrimSpace(key)
	anchorMu.Lock()
	defer anchorMu.Unlock()
	f, err := loadAnchorFile()
	if err != nil || f == nil {
		return errors.New("box is not anchored")
	}
	kept := f.DeviceKeys[:0]
	found := false
	for _, k := range f.DeviceKeys {
		if k == key {
			found = true
			continue
		}
		kept = append(kept, k)
	}
	if !found {
		return errors.New("that device key is not pinned here")
	}
	f.DeviceKeys = kept
	return saveAnchorFile(f)
}

// ── the signed approval ──────────────────────────────────────────────────────

// deviceApproval is what the device signs. The canonical bytes are the fields
// joined by newlines in this order — the same on the signer and the verifier,
// never a JSON encoding of the struct.
type deviceApproval struct {
	V       int    `json:"v"`
	Purpose string `json:"purpose"`
	Nonce   string `json:"nonce"`
	Expires string `json:"expires"`
	Uses    int    `json:"uses"`
	Key     string `json:"key"`
	Sig     string `json:"sig"`
}

func (a *deviceApproval) canonical() []byte {
	return []byte(strings.Join([]string{
		fmt.Sprint(a.V), a.Purpose, a.Nonce, a.Expires, fmt.Sprint(a.Uses), a.Key,
	}, "\n"))
}

// isDeviceApproval tells a device-signed approval (a JSON object with a
// signature) from a box-issued approval id (an opaque token).
func isDeviceApproval(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{") && strings.Contains(s, "\"sig\"")
}

// verifyDeviceApproval — the whole wall, in one place: format, a pinned key,
// the signature, THIS purpose, not expired and not too long-lived, one use,
// nonce never seen. Returns the parsed approval so the caller can burn it.
func verifyDeviceApproval(raw, purpose string, now time.Time) (*deviceApproval, error) {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	return verifyDeviceApprovalLocked(raw, purpose, now)
}

func verifyDeviceApprovalLocked(raw, purpose string, now time.Time) (*deviceApproval, error) {
	var a deviceApproval
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &a); err != nil {
		return nil, errors.New("approval is not readable")
	}
	if a.V != deviceApprovalVersion {
		return nil, fmt.Errorf("approval format v%d is not one this box reads", a.V)
	}
	// The signed bytes are the fields joined by newlines, so a newline inside
	// one would let the same signature be read with the line moved to the next
	// field: an approval for "P\nX" with nonce N would also read as purpose P
	// with nonce "X\nN". The purposes this box builds never hold one; refusing
	// it here makes every signed approval read one way only.
	if strings.ContainsAny(a.Purpose+a.Nonce, "\r\n") {
		return nil, errors.New("approval has a line break inside a field")
	}
	pinned := false
	for _, k := range deviceKeys() {
		if k == a.Key {
			pinned = true
			break
		}
	}
	if !pinned {
		return nil, errors.New("approval is signed by a device this box has not pinned (pin-device, with machine authority)")
	}
	pub, err := base64.StdEncoding.DecodeString(a.Key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("bad device key")
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), a.canonical(), sig) {
		return nil, errors.New("approval signature does not verify")
	}
	if a.Purpose != purpose {
		return nil, errors.New("approval is for something else (purpose mismatch)")
	}
	if a.Uses != 1 {
		return nil, fmt.Errorf("approval claims %d uses; a device approval is one run", a.Uses)
	}
	exp, err := time.Parse(time.RFC3339, a.Expires)
	if err != nil {
		return nil, errors.New("approval has no readable expiry")
	}
	if !exp.After(now) {
		return nil, errors.New("approval expired")
	}
	if exp.After(now.Add(deviceApprovalMaxTTL + deviceClockSkew)) {
		return nil, fmt.Errorf("approval would live longer than %s; refused", deviceApprovalMaxTTL)
	}
	if len(a.Nonce) < 16 {
		return nil, errors.New("approval nonce too short")
	}
	if _, seen := nonceLoad()[a.Nonce]; seen {
		return nil, errors.New("approval already used (nonce seen)")
	}
	return &a, nil
}

// consumeDeviceApproval is verifyDeviceApproval and the burn as ONE step under
// the ledger lock: the nonce is recorded before the caller acts, so two
// workers handed the same approval cannot both pass (the check-then-burn gap
// the first cut had, with two management workers per pairing). A ledger that
// cannot be written refuses — an approval whose use cannot be recorded is
// reusable, and refusing is the only answer that keeps "single-use" true.
func consumeDeviceApproval(raw, purpose string, now time.Time) (*deviceApproval, error) {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	a, err := verifyDeviceApprovalLocked(raw, purpose, now)
	if err != nil {
		return nil, err
	}
	m := nonceLoad()
	m[a.Nonce] = a.Expires
	if err := nonceSave(m); err != nil {
		return nil, fmt.Errorf("could not record this approval's use (%v); refused rather than reusable", err)
	}
	return a, nil
}

// ── the nonce ledger (box-level) ─────────────────────────────────────────────

func noncePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "device_nonces.json"), nil
}

func nonceLoad() map[string]string {
	out := map[string]string{}
	p, err := noncePath()
	if err != nil {
		return out
	}
	raw, err := os.ReadFile(p)
	if err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	// Prune what can no longer be replayed: a nonce whose approval has expired.
	now := time.Now()
	for n, exp := range out {
		if t, err := time.Parse(time.RFC3339, exp); err != nil || !t.After(now) {
			delete(out, n)
		}
	}
	return out
}

func nonceSave(m map[string]string) error {
	p, err := noncePath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, raw)
}

func nonceSeen(nonce string) bool {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	_, ok := nonceLoad()[nonce]
	return ok
}

// burnNonce records the nonce until its approval's expiry (after which a
// replay fails on expiry anyway).
func burnNonce(a *deviceApproval) {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	m := nonceLoad()
	m[a.Nonce] = a.Expires
	_ = nonceSave(m)
}

// ── the one check the gates call ─────────────────────────────────────────────

// approvalOK: is `approval` a live approval for exactly `purpose` on this box?
// A device-signed one is verified here; a box-issued id is checked against the
// pairing's approvals file (stepup.go). Neither is burned by this call —
// markApprovalUsed does that once the act it covered has run.
func approvalOK(dir, approval, purpose string) error {
	if strings.TrimSpace(approval) == "" {
		return errors.New("this machine requires your approval for this: none was given " +
			"(approve it on your device, or here with `privatae-bastion approvals`)")
	}
	if isDeviceApproval(approval) {
		_, err := verifyDeviceApproval(approval, purpose, time.Now())
		return err
	}
	return stepupCheckApproval(dir, approval, purpose)
}

// approvalKind names how an approval was given, for the audit line.
func approvalKind(approval string) string {
	switch {
	case strings.TrimSpace(approval) == "":
		return ""
	case isDeviceApproval(approval):
		return "device"
	}
	return "console"
}

// approvalRequired: does a change on this box need the person's approval?
// Always on an anchored box (writes.go); on a local box only when the person
// enrolled a factor here — the rule the DCN lanes have had since stepup.go.
func approvalRequired(dir string) bool {
	return currentAnchor() != nil || stepupEnrolled(dir)
}

// boxApproval is the wall a change runs on this box: there must be SOME way
// to approve here (a device pinned, or a factor enrolled for this pairing) —
// never "unenrolled passes" — and then the approval must check out for this
// purpose. The refusal names the fix.
func boxApproval(dir, approval, purpose string) error {
	if !secondFactorAvailable(dir) {
		return errors.New(noWayToApprove)
	}
	return approvalOK(dir, approval, purpose)
}

// noWayToApprove is the refusal for a box that holds neither a device key nor
// a factor. Named so the quarantine can tell it apart: it is the box's own
// state, not a host probing, and does not count as a strike (quarantine.go).
const noWayToApprove = "needs your approval, and this machine holds no way to take one: " +
	"pin your approval device (`privatae-bastion device-init` on your own machine, then " +
	"`privatae-bastion pin-device <key>` here with machine authority), or enrol a factor " +
	"here (`privatae-bastion stepup-enroll`)"

// consumeApproval is approvalOK and the burn as one step: the approval is
// spent the moment it is accepted, before the act runs. This is what the
// write gate and the session lane call — a slow handler must not leave a
// window in which the same approval passes a second worker. A handler that
// then refuses on its own argument check has spent the approval; the host
// asks again, which is the safe direction. Returns the approval's identity
// (a device nonce or a console id) for the audit line.
func consumeApproval(dir, approval, purpose string) (string, error) {
	if strings.TrimSpace(approval) == "" {
		return "", errors.New("this machine requires your approval for this: none was given " +
			"(approve it on your device, or here with `privatae-bastion approvals`)")
	}
	if isDeviceApproval(approval) {
		a, err := consumeDeviceApproval(approval, purpose, time.Now())
		if err != nil {
			return "", err
		}
		return "device:" + a.Nonce, nil
	}
	if err := stepupConsumeApproval(dir, approval, purpose); err != nil {
		return "", err
	}
	return "console:" + strings.TrimSpace(approval), nil
}

// boxConsume is boxApproval with the burn (consumeApproval): the wall, then
// the spend, one call.
func boxConsume(dir, approval, purpose string) (string, error) {
	if !secondFactorAvailable(dir) {
		return "", errors.New(noWayToApprove)
	}
	return consumeApproval(dir, approval, purpose)
}

// markApprovalUsed burns whichever kind it was.
func markApprovalUsed(dir, approval string) {
	if isDeviceApproval(approval) {
		var a deviceApproval
		if json.Unmarshal([]byte(strings.TrimSpace(approval)), &a) == nil && a.Nonce != "" {
			burnNonce(&a)
		}
		return
	}
	stepupMarkUsed(dir, approval)
}

// ── the device's side: the person's OWN bastion ──────────────────────────────

type deviceKeyFile struct {
	Pub       string `json:"pub"`
	Priv      string `json:"priv"`
	CreatedAt string `json:"created_at"`
}

func deviceKeyPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "device_key.json"), nil
}

func deviceKeyLoad() (*deviceKeyFile, error) {
	p, err := deviceKeyPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var f deviceKeyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// deviceInit creates the device key here, once. Prints the public key the
// person pins on each machine they govern (`pin-device <key>` there).
func deviceInit() (string, error) {
	if f, err := deviceKeyLoad(); err == nil && f.Pub != "" {
		return f.Pub, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	f := deviceKeyFile{
		Pub:       base64.StdEncoding.EncodeToString(pub),
		Priv:      base64.StdEncoding.EncodeToString(priv),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	raw, _ := json.MarshalIndent(&f, "", "  ")
	p, err := deviceKeyPath()
	if err != nil {
		return "", err
	}
	if err := atomicWrite(p, raw); err != nil {
		return "", err
	}
	_ = os.Chmod(p, 0o600)
	return f.Pub, nil
}

// deviceSign issues a one-run approval for `purpose`, valid for ttl (clamped
// to deviceApprovalMaxTTL), from the key held here.
func deviceSign(purpose string, ttl time.Duration) (string, error) {
	f, err := deviceKeyLoad()
	if err != nil || f.Priv == "" {
		return "", errors.New("this machine holds no device key — run `privatae-bastion device-init` first")
	}
	priv, err := base64.StdEncoding.DecodeString(f.Priv)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("bad device key file")
	}
	if strings.ContainsAny(purpose, "\r\n") {
		return "", errors.New("a purpose with a line break cannot be signed: the box would refuse it")
	}
	if ttl <= 0 || ttl > deviceApprovalMaxTTL {
		ttl = deviceApprovalMaxTTL
	}
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	a := deviceApproval{
		V: deviceApprovalVersion, Purpose: purpose, Nonce: hex.EncodeToString(n),
		Expires: time.Now().Add(ttl).UTC().Format(time.RFC3339), Uses: 1, Key: f.Pub,
	}
	a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(priv), a.canonical()))
	raw, _ := json.Marshal(&a)
	return string(raw), nil
}

// A pending ask on the device: the box that wants the approval, the purpose
// it derived, and the words the person reads (from the box, relayed by the
// pod — the purpose is what binds, the words are for the person).
type deviceRequest struct {
	Purpose  string         `json:"purpose"`
	Words    string         `json:"words"`
	Server   string         `json:"server"`
	Details  map[string]any `json:"details,omitempty"`
	At       string         `json:"at"`
	State    string         `json:"state"` // pending | approved | denied
	Approval string         `json:"approval,omitempty"`
	// Delivered: the signed approval was handed to the pod once. A later ask
	// for the same purpose is a NEW act and files a new request — a spent or
	// expired approval is never handed back to be refused by the box.
	Delivered bool `json:"delivered,omitempty"`
	// A ship plan ask (device_plan.go), and whether it needs the code.
	Plan      bool `json:"plan,omitempty"`
	NeedsCode bool `json:"needs_code,omitempty"`
}

// deviceApprovalLive: the approval's own expiry has not passed.
func deviceApprovalLive(approval string, now time.Time) bool {
	var a deviceApproval
	if json.Unmarshal([]byte(strings.TrimSpace(approval)), &a) != nil {
		return false
	}
	exp, err := time.Parse(time.RFC3339, a.Expires)
	return err == nil && exp.After(now)
}

func deviceRequestsPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "device_requests.json"), nil
}

func deviceRequestsLoad() map[string]deviceRequest {
	out := map[string]deviceRequest{}
	p, err := deviceRequestsPath()
	if err != nil {
		return out
	}
	raw, err := os.ReadFile(p)
	if err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	for id, r := range out {
		if t, err := time.Parse(time.RFC3339, r.At); err != nil || time.Since(t) > deviceRequestTTL {
			delete(out, id)
		}
	}
	return out
}

func deviceRequestsSave(m map[string]deviceRequest) error {
	p, err := deviceRequestsPath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, raw)
}

// deviceNewRequest files an ask from its DETAILS — the same plain fields the
// box's own console flow takes (stepup.go purposeFromDetails). The device
// derives the purpose it will sign and the words it will show from those one
// fields, so a pod cannot show one sentence and have another signed: the
// purpose IS the words (stepup.go's doctrine, kept here). A repeat of the same
// pending purpose from the same box returns the existing id; one the person
// denied is not asked again for the request TTL.
//
// A root shell is never signed here: root is approved at the machine with
// the code (session.go), on top of any tap.
func deviceNewRequest(details map[string]any) (string, error) {
	kind, _ := details["kind"].(string)
	// ONLY A KIND WHOSE PURPOSE NAMES THE MACHINE is signed here. mgmt_op and
	// dcn_store_grant carry the server inside the purpose, so an approval for
	// one box is no use on another. A move plan's and a model pull's purposes
	// do not (purposeForPlan, purposeForModelPull) — an approval for either
	// would run once on whichever of the person's machines the pod chose — so
	// those stay on that machine's console until their purposes carry it. Root
	// is never signed on a device.
	switch kind {
	// service_reach_grant names the machine too (purposeForReach: server|slot|
	// subject|ttl), so an approval for one box is no use on another; so do
	// op_run and op_grant (ops.go).
	case "mgmt_op", "dcn_store_grant", reachKind, opKindRun, opKindGrant:
	case "session_root":
		return "", errors.New("a root shell is approved at that machine with your code, not from a device")
	default:
		return "", fmt.Errorf("a %q ask is approved at the machine's own console, not from a device", kind)
	}
	server, _ := details["server"].(string)
	server = strings.TrimSpace(server)
	if server == "" || strings.ContainsAny(server, " \n\r\t|") {
		return "", errors.New("the ask names no machine")
	}
	purpose, err := purposeFromDetails(details)
	if err != nil {
		return "", err
	}
	words := describeRequest(stepupRequest{Details: details})
	deviceMu.Lock()
	defer deviceMu.Unlock()
	m := deviceRequestsLoad()
	// A refusal wins over anything else for the same purpose, whatever order
	// the map is walked in: two passes, deny first.
	for _, r := range m {
		if r.Purpose == purpose && r.Server == server && r.State == "denied" {
			return "", errors.New("you refused this on your device; it cannot be asked again for 24h")
		}
	}
	for id, r := range m {
		if r.Purpose == purpose && r.Server == server {
			switch r.State {
			case "pending":
				return id, nil
			case "approved":
				// An approved one is handed back ONCE and while it is live, so
				// a pod that files, waits out its turn and files again finds
				// the tap it missed instead of raising a second card — and a
				// pod asking again after that (a new act) gets a new card, not
				// a spent or expired approval the box would refuse.
				if !r.Delivered && deviceApprovalLive(r.Approval, time.Now()) {
					return id, nil
				}
			}
		}
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	m[id] = deviceRequest{Purpose: purpose, Words: words, Server: server, Details: details,
		At: time.Now().UTC().Format(time.RFC3339), State: "pending"}
	// (Server is the details' own server — the same one the purpose names.)
	if err := deviceRequestsSave(m); err != nil {
		return "", err
	}
	return id, nil
}

func deviceApprove(id string) (string, error) { return deviceApproveWithCode(id, "") }

// deviceApproveWithCode signs an ask; a ship plan with root work needs the
// person's code, checked here (device_plan.go).
func deviceApproveWithCode(id, code string) (string, error) {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	m := deviceRequestsLoad()
	r, ok := m[id]
	if !ok || r.State != "pending" {
		return "", fmt.Errorf("no pending request %s", id)
	}
	var approval string
	var err error
	if r.Plan {
		approval, err = devicePlanSign(r, code)
	} else {
		approval, err = deviceSign(r.Purpose, deviceApprovalMaxTTL)
	}
	if err != nil {
		return "", err
	}
	r.State, r.Approval = "approved", approval
	m[id] = r
	if err := deviceRequestsSave(m); err != nil {
		return "", err
	}
	return approval, nil
}

func deviceDeny(id string) error {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	m := deviceRequestsLoad()
	r, ok := m[id]
	if !ok {
		return fmt.Errorf("no request %s", id)
	}
	if r.State != "pending" {
		return fmt.Errorf("request is %s, not pending", r.State)
	}
	r.State = "denied"
	m[id] = r
	return deviceRequestsSave(m)
}

func sortedDeviceRequests(m map[string]deviceRequest) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return m[ids[i]].At < m[ids[j]].At })
	return ids
}

// ── the device's mgmt ops (the pod → the person's own bastion) ───────────────

// deviceLaneOnly: the device's ops are answered only for the PERSON'S OWN
// host — the anchor pairing on an anchored device, the one pairing on a local
// one (anchorOnly). A member host paired to the device could otherwise file
// asks on it or read back a signed approval by its id.
func deviceLaneOnly(ws *websocket.Conn, what string) bool {
	self := ""
	if a := mgmtAccountOf(ws); a != nil {
		self = a.self
	}
	if why := anchorOnly(self, what); why != "" {
		refuseMgmt(ws, why)
		return false
	}
	return true
}

// device_request <details_b64>: file an ask on this device from the plain
// details of what a machine is being asked for — the machine is the one the
// details name, and nothing else. Answers {id, state}. The pod cannot
// approve — only the person, here.
func handleDeviceRequest(ws *websocket.Conn, _ string, args []string) {
	if !deviceLaneOnly(ws, "device_request") {
		return
	}
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("device_request: need <details_b64>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	if _, err := deviceKeyLoad(); err != nil {
		sendMgmt(ws, 'R', []byte("this machine is not an approval device (privatae-bastion device-init)\n"))
		sendMgmtExit(ws, 126)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args[0]))
	if err != nil {
		sendMgmt(ws, 'R', []byte("device_request: bad details_b64\n"))
		sendMgmtExit(ws, 1)
		return
	}
	var details map[string]any
	if err := json.Unmarshal(raw, &details); err != nil || details == nil {
		sendMgmt(ws, 'R', []byte("device_request: bad details json\n"))
		sendMgmtExit(ws, 1)
		return
	}
	var id string
	if kind, _ := details["kind"].(string); kind == shipPlanKind {
		id, err = deviceNewPlanRequest(details)
	} else {
		id, err = deviceNewRequest(details)
	}
	if err != nil {
		sendMgmt(ws, 'R', []byte(err.Error()+"\n"))
		sendMgmtExit(ws, 126)
		return
	}
	v := map[string]any{"id": id, "state": "pending"}
	if approval, ok := deviceHandOut(id); ok {
		v["state"], v["approval"] = "approved", approval
	} else {
		notifyDeviceRequest(id)
	}
	out, _ := json.Marshal(v)
	sendMgmt(ws, 'O', out)
	sendMgmtExit(ws, 0)
}

// deviceHandOut gives the approval for an approved request to the pod ONCE
// (marks it delivered). ("", false) for anything else.
func deviceHandOut(id string) (string, bool) {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	m := deviceRequestsLoad()
	r, ok := m[id]
	if !ok || r.State != "approved" || r.Delivered ||
		!(deviceApprovalLive(r.Approval, time.Now()) || devicePlanLive(r.Approval, time.Now())) {
		return "", false
	}
	r.Delivered = true
	m[id] = r
	if err := deviceRequestsSave(m); err != nil {
		return "", false
	}
	return r.Approval, true
}

// device_status <id>: {state, approval?} — the signed approval only once the
// person tapped.
func handleDeviceStatus(ws *websocket.Conn, _ string, args []string) {
	if !deviceLaneOnly(ws, "device_status") {
		return
	}
	if len(args) < 1 {
		sendMgmt(ws, 'R', []byte("device_status: need <id>\n"))
		sendMgmtExit(ws, 1)
		return
	}
	id := strings.TrimSpace(args[0])
	deviceMu.Lock()
	r, ok := deviceRequestsLoad()[id]
	deviceMu.Unlock()
	if !ok {
		out, _ := json.Marshal(map[string]any{"state": "expired"})
		sendMgmt(ws, 'O', out)
		sendMgmtExit(ws, 0)
		return
	}
	v := map[string]any{"state": r.State}
	if r.State == "approved" {
		// Handed out once; a second status read of an approved request says
		// "delivered" — the approval left already and is not repeated.
		if approval, ok := deviceHandOut(id); ok {
			v["approval"] = approval
		} else {
			v["state"] = "delivered"
		}
	}
	out, _ := json.Marshal(v)
	sendMgmt(ws, 'O', out)
	sendMgmtExit(ws, 0)
}

// notifyDeviceRequest says on this machine's console that a box is asking.
// On Windows the tray also raises a notification for it and opens the
// approvals popup on a click (uidevice.go); the console stays the answer
// everywhere else.
func notifyDeviceRequest(id string) {
	fmt.Printf("device: approval requested (%s) — privatae-bastion device-approvals\n", id)
}

// ── the console ──────────────────────────────────────────────────────────────

func cmdDeviceInit() error {
	pub, err := deviceInit()
	if err != nil {
		return err
	}
	fmt.Println("This machine is an approval device. Pin its key on each machine you govern,")
	fmt.Println("there, with machine authority:")
	fmt.Println()
	fmt.Println("  privatae-bastion pin-device " + pub)
	fmt.Println()
	fmt.Println("Every write a host asks of those machines then needs your tap here.")
	return nil
}

// deviceShownPath records the ids `device-approvals` last PRINTED, so that
// `device-approve all` signs exactly the asks the person read and nothing a
// pod filed after they looked.
func deviceShownPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "device_shown.json"), nil
}

func cmdDeviceApprovals() error {
	deviceMu.Lock()
	m := deviceRequestsLoad()
	deviceMu.Unlock()
	shown := []string{}
	for _, id := range sortedDeviceRequests(m) {
		r := m[id]
		if r.State != "pending" {
			continue
		}
		shown = append(shown, id)
		fmt.Printf("[%s]  on %s, asked %s\n%s\n\n", id[:8], r.Server, r.At, r.Words)
	}
	if p, err := deviceShownPath(); err == nil {
		raw, _ := json.Marshal(shown)
		_ = atomicWrite(p, raw)
	}
	if len(shown) == 0 {
		fmt.Println("nothing is waiting for your approval")
		return nil
	}
	fmt.Printf("approve one:  privatae-bastion device-approve <id>      all of the above:  privatae-bastion device-approve all\n")
	return nil
}

func cmdDeviceApprove(prefix string) error { return cmdDeviceApproveCode(prefix, "") }

func cmdDeviceApproveCode(prefix, code string) error {
	deviceMu.Lock()
	m := deviceRequestsLoad()
	deviceMu.Unlock()
	// `all`: every ask the person was SHOWN by the last `device-approvals`
	// and nothing else — a fleet roll files one ask per machine, and
	// twenty-three taps for one decision was refused as a design for the
	// update button (Network app 1.9.0), but a pod can file an ask at any
	// moment, and "all" must not sign one that arrived after the person read
	// the list. An ask filed since is left pending and named.
	if strings.TrimSpace(prefix) == "all" {
		var shown []string
		if p, err := deviceShownPath(); err == nil {
			if raw, err := os.ReadFile(p); err == nil {
				_ = json.Unmarshal(raw, &shown)
			}
		}
		if len(shown) == 0 {
			return errors.New("nothing was shown: run `privatae-bastion device-approvals` first, then approve what it printed")
		}
		wasShown := map[string]bool{}
		for _, id := range shown {
			wasShown[id] = true
		}
		n, later, coded := 0, 0, 0
		for _, id := range sortedDeviceRequests(m) {
			if m[id].State != "pending" {
				continue
			}
			if !wasShown[id] {
				later++
				continue
			}
			if m[id].NeedsCode {
				// Root work is approved one at a time, with the code.
				coded++
				continue
			}
			if _, err := deviceApprove(id); err != nil {
				return err
			}
			fmt.Printf("approved %s — on %s\n", id[:8], m[id].Server)
			n++
		}
		if p, err := deviceShownPath(); err == nil {
			_ = os.Remove(p)
		}
		if n == 0 {
			fmt.Println("nothing you were shown is still waiting")
		}
		if later > 0 {
			fmt.Printf("%d ask(s) arrived after you looked and were NOT approved — run device-approvals to read them\n", later)
		}
		if coded > 0 {
			fmt.Printf("%d ship plan(s) run root work and need your code: privatae-bastion device-approve <id> --code <code>\n", coded)
		}
		return nil
	}
	id, err := findDeviceRequest(m, prefix)
	if err != nil {
		return err
	}
	if _, err := deviceApproveWithCode(id, code); err != nil {
		return err
	}
	if m[id].Plan {
		fmt.Printf("approved %s — each machine in it runs its own lines, once\n", id[:8])
		return nil
	}
	fmt.Printf("approved %s — it may run once on %s\n", id[:8], m[id].Server)
	return nil
}

func cmdDeviceDeny(prefix string) error {
	deviceMu.Lock()
	m := deviceRequestsLoad()
	deviceMu.Unlock()
	id, err := findDeviceRequest(m, prefix)
	if err != nil {
		return err
	}
	if err := deviceDeny(id); err != nil {
		return err
	}
	fmt.Printf("denied %s\n", id)
	return nil
}

func findDeviceRequest(m map[string]deviceRequest, prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "", errors.New("which request? (privatae-bastion device-approvals lists them)")
	}
	var hits []string
	for id := range m {
		if strings.HasPrefix(id, prefix) {
			hits = append(hits, id)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no request starts with %q", prefix)
	case 1:
		return hits[0], nil
	}
	return "", fmt.Errorf("%d requests start with %q — give more of the id", len(hits), prefix)
}

func cmdPinDevice(key string, unpin bool) error {
	act := "pin-device"
	if unpin {
		act = "unpin-device"
	}
	if err := requireMachineAuthority(act); err != nil {
		return err
	}
	if unpin {
		if err := unpinDeviceKey(key); err != nil {
			return err
		}
		fmt.Println("device key unpinned; approvals signed by it are refused from now on")
		return nil
	}
	if err := pinDeviceKey(key); err != nil {
		return err
	}
	fmt.Println("device key pinned; a write a host asks of this machine may now be approved from that device")
	if line := machineKeyLine(); line != "" {
		fmt.Println()
		fmt.Println("So that device can sign ship plans that include this machine, run this on the device:")
		fmt.Println()
		fmt.Println("  " + line)
	}
	return nil
}
