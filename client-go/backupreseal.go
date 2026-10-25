package main

// backupreseal.go — a host asks this machine to reseal one backup's key to
// it, and the person decides here.
//
// The host restoring a backup needs that backup's own key and nothing more.
// It sends the sealed sidecar and its own public key (backup_reseal start).
// This machine files the request and answers only "pending": nothing is
// opened yet. The person sees the request here (`privatae-bastion backup
// requests`), in this machine's words — which backup, which host, which key
// it would be sealed to — and approves it (`backup approve <id>`). Approving
// runs on this machine as the person, with the backup key held here: the
// sidecar is opened, checked to be the backup it claims, and the same record
// is sealed to the host's key alone. The host collects it (backup_reseal
// status). Refusing leaves the host nothing.
//
// Why a request queue of its own and not the generic per-run approval
// (writes.go): that approval gates CHANGES to this machine on an anchored box
// and passes everything on a local one. A reseal changes nothing here, but it
// hands a host the key to one backup, and that is the person's decision on
// every box. And the act needs this bastion's backup key, which only the
// person's own session here can read. So the approval and the act are the same step, taken
// here. When this pairing has a second factor enrolled, approving also asks
// for its code, as `approve` does.
//
// WHOSE BACKUP. A request is bound to the pairing it came in on, and to the
// host number that pairing was given at pairing: the host's tunnel address,
// fd00:9::e:<number>, which the platform derives from the host's own entity
// and which this machine stored at `pair`.
// Nothing the host sends can change it. Every host that shares this
// bastion's key holds sidecars of every other such host's backups (a shared
// folder, the platform), so a label or a stamp is no proof of whose backup a
// sidecar is: the host number inside it is, once opened here. A sidecar of
// another host's backup is REFUSED, not shown for the person to catch: host A,
// taken over and calling itself B, never gets B's backup key sealed to A.
// Restoring a lost host's backups onto the one that replaces it (a different
// number) is the person's own act at this machine, `backup restore-plan`
// (backupcli.go), not a request a host can file.

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/gorilla/websocket"
)

const (
	resealRequestTTL = 24 * time.Hour
	// A host files requests into this machine's state; these bound how much
	// it can file. A restore needs one request per backup it restores, and
	// the person answers them. They bound the requests WAITING for an
	// answer: answering one (approve or deny) frees its room at once, as a
	// request that lapses (a day) does.
	resealMaxRequests = 16
	resealMaxBytes    = 512 << 10
	resealLabelMax    = 120
	// An answered request is kept, without the sidecar it came with, so the
	// host can read the outcome (and a resealed key) until it lapses. Only
	// the person's answers make them, and at most this many are kept, the
	// oldest answered going first.
	resealMaxAnswered = 64
)

type resealRequest struct {
	ID    string `json:"id"`
	Stamp string `json:"stamp"`
	// Pairing and HostNumber are this machine's record of who sent it, taken
	// from the pairing the request came in on; HostLabel is the host's words.
	Pairing    string `json:"pairing"`
	HostNumber int64  `json:"host_number"`
	HostLabel  string `json:"host_label"`
	To         string `json:"to"`      // age1 recipient of the restoring host
	ToFP       string `json:"to_fp"`   // its fingerprint, shown to the person
	Sidecar    string `json:"sidecar"` // armored, as the host sent it
	SidecarSH  string `json:"sidecar_sha256"`
	At         string `json:"at"`
	State      string `json:"state"` // pending | done | refused | failed
	Resealed   string `json:"resealed,omitempty"`
	Error      string `json:"error,omitempty"`
	DecidedAt  string `json:"decided_at,omitempty"`
}

type resealReq struct {
	Op        string `json:"op"` // start | status
	JobID     string `json:"job_id"`
	Sidecar   string `json:"sidecar"`
	To        string `json:"to"`
	Stamp     string `json:"stamp"`
	HostLabel string `json:"host_label"`
}

var resealMu sync.Mutex

// resealWho is a pairing as this machine knows it: its name and the host
// number it was paired with.
type resealWho struct {
	Name   string
	Number int64
}

// hostNumberOf reads the host number out of a pairing's tunnel address,
// fd00:9::e:<number in hex>, as the platform assigns it.
// false for any other address: such a pairing cannot be matched to a
// backup's host number, and its requests are refused.
func hostNumberOf(tunnelIP string) (int64, bool) {
	a, err := netip.ParseAddr(tunnelIP)
	if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
		return 0, false
	}
	b := a.As16()
	prefix := [14]byte{0xfd, 0x00, 0x00, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x0e}
	if [14]byte(b[:14]) != prefix {
		return 0, false
	}
	n := int64(b[14])<<8 | int64(b[15])
	return n, n > 0
}

// resealPairing is the pairing self as this machine has it on disk. An
// anonymous caller, a pairing that is not here, not active, or has no host
// number is refused: a request must be bound to a host.
func resealPairing(self string) (resealWho, error) {
	if self == "" {
		return resealWho{}, errors.New("a restore request is taken only from a paired host")
	}
	cfgs, err := loadPairings()
	if err != nil {
		return resealWho{}, fmt.Errorf("the pairings on this machine are unreadable: %w", err)
	}
	for _, c := range cfgs {
		if c.HostName == self {
			return resealWhoOf(c)
		}
	}
	return resealWho{}, fmt.Errorf("%s is not paired with this machine", self)
}

func resealWhoOf(c *Config) (resealWho, error) {
	if !c.active() {
		return resealWho{}, fmt.Errorf("the pairing %s is %s", c.HostName, c.stateName())
	}
	n, ok := hostNumberOf(c.HostTunnelIP)
	if !ok {
		return resealWho{}, fmt.Errorf("the pairing %s has no host number (its tunnel address is %q), so no backup "+
			"can be matched to it; pair it again", c.HostName, c.HostTunnelIP)
	}
	return resealWho{Name: c.HostName, Number: n}, nil
}

// resealBindingProblem is a refusal when the request was not filed by the
// pairing who, or the backup the sidecar holds is not that host's own.
func resealBindingProblem(r *resealRequest, sc *backupSidecar, who resealWho) string {
	if r.Pairing != who.Name || r.HostNumber != who.Number || who.Number <= 0 {
		return fmt.Sprintf("refused: this request was filed by the pairing %q (host number %d), not by %s "+
			"(host number %d)", r.Pairing, r.HostNumber, who.Name, who.Number)
	}
	if sc != nil && sc.EntityID != who.Number {
		return fmt.Sprintf("refused: this is the backup of host number %d, and the request came from %s, which is "+
			"host number %d. A host is given only its own backups' keys. To restore another host's backup onto "+
			"this one, run `privatae-bastion backup restore-plan` here yourself", sc.EntityID, who.Name, who.Number)
	}
	return ""
}

func resealPath(dir string) string { return filepath.Join(dir, "backup_reseal.json") }

// withResealLock runs fn holding the pairing's request file for itself. Two
// processes write that file: the daemon files requests, and `backup approve`
// and `deny` decide them in the person's own process. resealMu covers the
// goroutines of one process; the lock file (flock, LockFileEx on Windows)
// covers both processes, so a request filed while the person decides is not
// dropped, and a decision is not reverted by a stale copy. Every write is
// atomic (atomicWrite: temp file, then rename), so a reader never sees half
// a file.
func withResealLock(dir string, fn func() error) error {
	resealMu.Lock()
	defer resealMu.Unlock()
	lf, err := os.OpenFile(filepath.Join(dir, "backup_reseal.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close() // closing releases the lock
	if err := flockFile(lf); err != nil {
		return err
	}
	return fn()
}

// resealAsideSuffix names a request file set aside as unreadable.
const resealAsideSuffix = ".unreadable-"

// resealLoad reads the pairing's requests, less those that lapsed; the
// caller holds withResealLock. A file that cannot be parsed is not dropped
// and not overwritten: it is set aside beside it, under a name that says so,
// and the error says where. The next request starts a new file.
func resealLoad(dir string) (map[string]*resealRequest, error) {
	m := map[string]*resealRequest{}
	p := resealPath(dir)
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the record of restore requests cannot be read: %w", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		aside := p + resealAsideSuffix + time.Now().UTC().Format("20060102T150405.000000000Z")
		if rerr := os.Rename(p, aside); rerr != nil {
			return nil, fmt.Errorf("the record of restore requests %s is unreadable (%v) and could not be set aside (%v); "+
				"nothing was changed", p, err, rerr)
		}
		return nil, fmt.Errorf("the record of restore requests was unreadable (%v). It is kept as %s and a new "+
			"one is started: the requests in it must be asked again", err, aside)
	}
	if m == nil {
		m = map[string]*resealRequest{}
	}
	now := time.Now()
	for id, r := range m {
		if r == nil {
			delete(m, id)
			continue
		}
		at, err := time.Parse(time.RFC3339, r.At)
		if err != nil || now.Sub(at) > resealRequestTTL {
			delete(m, id)
		}
	}
	return m, nil
}

// resealRead is resealLoad under the lock, for a caller that only reads.
func resealRead(dir string) (map[string]*resealRequest, error) {
	var m map[string]*resealRequest
	err := withResealLock(dir, func() error {
		var err error
		m, err = resealLoad(dir)
		return err
	})
	return m, err
}

// resealSave writes the requests: an answered one no longer carries the
// sidecar it came with, and past resealMaxAnswered answered ones the oldest
// answered are dropped.
func resealSave(dir string, m map[string]*resealRequest) error {
	var answered []*resealRequest
	for _, r := range m {
		if r.State != "pending" {
			r.Sidecar = ""
			answered = append(answered, r)
		}
	}
	if len(answered) > resealMaxAnswered {
		sort.Slice(answered, func(i, j int) bool { return answered[i].DecidedAt < answered[j].DecidedAt })
		for _, r := range answered[:len(answered)-resealMaxAnswered] {
			delete(m, r.ID)
		}
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(resealPath(dir), raw)
}

// handleBackupReseal answers backup_reseal start and status on the pairing's
// own state directory, so one host never sees another's requests.
func handleBackupReseal(ws *websocket.Conn, dir string, args []string) {
	if len(args) < 1 {
		backupFail(ws, "backup_reseal: need a JSON argument")
		return
	}
	var req resealReq
	if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
		backupFail(ws, "backup_reseal: argument is not JSON: "+err.Error())
		return
	}
	switch req.Op {
	case "status":
		m, err := resealRead(dir)
		if err != nil {
			backupFail(ws, "backup_reseal: "+err.Error())
			return
		}
		r, ok := m[req.JobID]
		if !ok {
			backupOK(ws, map[string]string{"job_id": req.JobID, "state": "unknown"})
			return
		}
		out := map[string]string{"job_id": r.ID, "state": r.State}
		if r.State == "done" {
			out["sidecar"] = r.Resealed
		}
		if r.Error != "" {
			out["error"] = r.Error
		}
		backupOK(ws, out)
	case "start", "":
		who, err := resealPairing(mgmtSelf(ws))
		if err != nil {
			backupFail(ws, "backup_reseal: "+err.Error())
			return
		}
		r, err := resealFile(dir, who, req)
		if err != nil {
			backupFail(ws, "backup_reseal: "+err.Error())
			return
		}
		backupOK(ws, map[string]string{"job_id": r.ID, "state": r.State})
	default:
		backupFail(ws, "backup_reseal: unknown op "+req.Op)
	}
}

// resealFile validates and files a request. The same sidecar for the same
// key while one is still open returns that one: a host that lost the reply
// asks again and must not fill the person's list with copies. who is the
// pairing the request came in on, recorded with it.
func resealFile(dir string, who resealWho, req resealReq) (*resealRequest, error) {
	if who.Name == "" || who.Number <= 0 {
		return nil, errors.New("a restore request is taken only from a paired host with a host number")
	}
	if len(req.Sidecar) == 0 || len(req.Sidecar) > sidecarMaxBytes {
		return nil, errors.New("sidecar is missing or too large")
	}
	if !strings.Contains(req.Sidecar, "-----BEGIN AGE ENCRYPTED FILE-----") {
		return nil, errors.New("sidecar must be an armored age file")
	}
	if !backupStampRe.MatchString(req.Stamp) {
		return nil, errors.New("stamp must name a backup (YYYYMMDDTHHMMSSZ)")
	}
	to, err := parseBackupRecipient(req.To)
	if err != nil {
		return nil, err
	}
	raw, err := recipientRaw(to)
	if err != nil {
		return nil, err
	}
	label := strings.TrimSpace(req.HostLabel)
	if !resealLabelOK(label) {
		return nil, fmt.Errorf("host_label must be one line of at most %d bytes of printable text", resealLabelMax)
	}
	sum := sha256.Sum256([]byte(req.Sidecar))
	sh := hex.EncodeToString(sum[:])

	var filed *resealRequest
	err = withResealLock(dir, func() error {
		m, err := resealLoad(dir)
		if err != nil {
			return err
		}
		waiting, held := 0, 0
		for _, r := range m {
			if r.State != "pending" {
				continue
			}
			if r.SidecarSH == sh && r.To == to.String() && r.Pairing == who.Name && r.HostNumber == who.Number {
				filed = r
				return nil
			}
			waiting++
			held += len(r.Sidecar)
		}
		if waiting >= resealMaxRequests || held+len(req.Sidecar) > resealMaxBytes {
			return fmt.Errorf("this bastion already holds %d restore requests from this host waiting for an answer "+
				"(%d KiB; at most %d requests or %d KiB). Answer them on this machine (privatae-bastion backup "+
				"requests), or wait for them to lapse after a day, then ask again", waiting, held>>10,
				resealMaxRequests, resealMaxBytes>>10)
		}
		idb := make([]byte, 6)
		if _, err := rand.Read(idb); err != nil {
			return err
		}
		r := &resealRequest{
			ID: "br-" + hex.EncodeToString(idb), Stamp: req.Stamp, Pairing: who.Name, HostNumber: who.Number, HostLabel: label,
			To: to.String(), ToFP: backupKeyFingerprint(raw), Sidecar: req.Sidecar, SidecarSH: sh,
			At: time.Now().UTC().Format(time.RFC3339), State: "pending",
		}
		m[r.ID] = r
		if err := resealSave(dir, m); err != nil {
			return err
		}
		filed = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return filed, nil
}

// resealDecide carries out the person's answer for the pairing who (whose
// state directory dir is). Approve opens the sidecar with the keys held here,
// refuses it unless it is the backup of that pairing's own host number, and
// seals it to the requesting host's key; any failure is recorded as the
// request's outcome for the host to read.
func resealDecide(dir string, who resealWho, id string, approve bool) (*resealRequest, error) {
	return resealDecideWith(dir, who, id, approve, "")
}

// resealRefuse refuses a request with the reason given, for the host to read.
func resealRefuse(dir string, who resealWho, id, why string) (*resealRequest, error) {
	return resealDecideWith(dir, who, id, false, why)
}

func resealDecideWith(dir string, who resealWho, id string, approve bool, why string) (*resealRequest, error) {
	var out *resealRequest
	err := withResealLock(dir, func() error {
		var err error
		out, err = resealDecideLocked(dir, who, id, approve, why)
		return err
	})
	return out, err
}

func resealDecideLocked(dir string, who resealWho, id string, approve bool, why string) (*resealRequest, error) {
	m, err := resealLoad(dir)
	if err != nil {
		return nil, err
	}
	r, ok := m[id]
	if !ok {
		return nil, fmt.Errorf("no reseal request %s (requests lapse after a day)", id)
	}
	if r.State != "pending" {
		return nil, fmt.Errorf("request %s is already %s", id, r.State)
	}
	r.DecidedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if !approve {
		r.State, r.Error = "refused", why
		return r, resealSave(dir, m)
	}
	if p := resealBindingProblem(r, nil, who); p != "" {
		r.State, r.Error = "refused", p
		return r, resealSave(dir, m)
	}
	ids, err := backupIdentities()
	if err != nil {
		return nil, err
	}
	to, err := parseBackupRecipient(r.To)
	if err != nil {
		return nil, err
	}
	plain, sc, err := openSidecar([]byte(r.Sidecar), ids, r.Stamp)
	switch {
	case err != nil:
		r.State, r.Error = "failed", err.Error()
	case resealBindingProblem(r, sc, who) != "":
		r.State, r.Error = "refused", resealBindingProblem(r, sc, who)
	default:
		out, err := sealSidecarTo(plain, to)
		if err != nil {
			r.State, r.Error = "failed", err.Error()
		} else {
			r.State, r.Resealed = "done", string(out)
		}
	}
	if serr := resealSave(dir, m); serr != nil {
		return nil, serr
	}
	return r, nil
}

// resealLabelOK: the label is shown to the person on this machine as the
// host's own words, so it must not be able to move the cursor, recolour the
// terminal, reverse text or break the line: no control or format character
// of any kind, valid UTF-8, one short line.
func resealLabelOK(label string) bool {
	if len(label) > resealLabelMax || !utf8.ValidString(label) {
		return false
	}
	for _, r := range label {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

// resealPreview is what the person reads before approving: which pairing
// sent it (this machine's record), what the host says it wants, and what the
// sidecar itself says, opened here with this bastion's key. The returned
// refusal is not "" when approving cannot go through: the sidecar is not the
// backup of that pairing's own host (refused, whatever the person answers),
// or it does not open here, or names another backup.
func resealPreview(r *resealRequest, ids []age.Identity, who resealWho) (string, string) {
	var b strings.Builder
	b.WriteString(describeReseal(r))
	b.WriteString("\n\n  What the sidecar says (opened here with this bastion's key):\n")
	if p := resealBindingProblem(r, nil, who); p != "" {
		fmt.Fprintf(&b, "    not opened: %s\n", p)
		return b.String(), p
	}
	_, sc, err := openSidecar([]byte(r.Sidecar), ids, "")
	if err != nil {
		fmt.Fprintf(&b, "    it does not open here: %q\n    Approving will fail and the host is told so.\n", err.Error())
		return b.String(), ""
	}
	// Every field that came out of the sidecar is printed quoted: the sidecar
	// was written by a host, and what it says must not be able to move the
	// cursor or pass for this machine's own words.
	fmt.Fprintf(&b, "    host number  %d\n    made at      %q\n    backup       %q (%q)\n",
		sc.EntityID, sc.MadeAt, sc.Object, sc.Stamp)
	if p := resealBindingProblem(r, sc, who); p != "" {
		fmt.Fprintf(&b, "    %s.\n", p)
		return b.String(), p
	}
	if sc.Stamp != r.Stamp {
		fmt.Fprintf(&b, "    This is the backup of %q, not the %q the host asked for: approving will fail.\n",
			sc.Stamp, r.Stamp)
	}
	return b.String(), ""
}

// resealApprove is the person's approval, checked: when this pairing has a
// second factor enrolled, the code must verify (and is spent) before
// anything is opened. A wrong or missing code leaves the request pending.
func resealApprove(dir string, who resealWho, id, code string) (*resealRequest, error) {
	if stepupEnrolled(dir) {
		code = strings.TrimSpace(code)
		if code == "" {
			return nil, errors.New("this machine has a second factor enrolled: approving needs its code")
		}
		if _, err := stepupVerifyAndBurn(dir, code, time.Now()); err != nil {
			return nil, err
		}
	}
	return resealDecide(dir, who, id, true)
}

func findResealRequest(m map[string]*resealRequest, prefix string) (string, error) {
	var hits []string
	for id := range m {
		if strings.HasPrefix(id, prefix) {
			hits = append(hits, id)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no reseal request starts with %q", prefix)
	case 1:
		return hits[0], nil
	}
	return "", fmt.Errorf("%q matches %d requests; give more of the id", prefix, len(hits))
}

func describeReseal(r *resealRequest) string {
	host := r.HostLabel
	if host == "" {
		host = "your host"
	}
	// The pairing name was checked as a host name at `pair` (validHostName)
	// and the number is this machine's own; the label is the host's words and
	// printed quoted.
	return fmt.Sprintf("%s  [%s]\n  Sent by the pairing %s, host number %d (this machine's record).\n"+
		"  What the host says: %q asks for the key to the backup of %s,\n"+
		"  sealed to its own key %s (fingerprint %s). Approving lets that host\n"+
		"  open this one backup and no other, and only if it is that host's own.",
		r.ID, r.State, r.Pairing, r.HostNumber, host, r.Stamp, r.To, r.ToFP)
}

// ── the person's side, on this machine ──────────────────────────────────────

func cmdBackupRequests(host string) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	// Request files set aside as unreadable (resealLoad) are named here, so
	// the person learns of them whichever process found them.
	if aside, _ := filepath.Glob(resealPath(dir) + resealAsideSuffix + "*"); len(aside) > 0 {
		fmt.Println("set aside as unreadable (kept, not read):")
		for _, a := range aside {
			fmt.Println("  " + a)
		}
		fmt.Println()
	}
	m, err := resealRead(dir)
	if err != nil {
		return err
	}
	if len(m) == 0 {
		fmt.Println("no backup requests from", cfg.HostName)
		return nil
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return m[ids[i]].At < m[ids[j]].At })
	for _, id := range ids {
		fmt.Println(describeReseal(m[id]))
		fmt.Println()
	}
	return nil
}

func cmdBackupDecide(host, prefix string, approve bool) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	m, err := resealRead(dir)
	if err != nil {
		return err
	}
	id, err := findResealRequest(m, prefix)
	if err != nil {
		return err
	}
	var r *resealRequest
	if approve {
		who, err := resealWhoOf(cfg)
		if err != nil {
			return err
		}
		ids, _ := backupIdentities()
		text, refusal := resealPreview(m[id], ids, who)
		fmt.Println(text)
		if refusal != "" {
			// Refused whatever the person answers, and needs no code: a
			// refusal hands nothing over.
			if _, err := resealRefuse(dir, who, id, refusal); err != nil {
				return err
			}
			return errors.New(refusal)
		}
		code := ""
		if stepupEnrolled(dir) {
			fmt.Print("Approve this? Enter the code from your authenticator (or leave empty to cancel): ")
			code, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(code) == "" {
				fmt.Println("cancelled — nothing approved")
				return nil
			}
		}
		r, err = resealApprove(dir, who, id, code)
		if err != nil {
			return err
		}
	} else {
		r, err = resealRefuse(dir, resealWho{Name: cfg.HostName}, id, "")
	}
	if err != nil {
		return err
	}
	switch r.State {
	case "done":
		fmt.Println("approved — the key to that one backup is sealed to your host; it collects it on its next check.")
	case "refused":
		if approve {
			return errors.New(r.Error)
		}
		fmt.Println("refused — your host is told on its next check.")
	default:
		return fmt.Errorf("the reseal failed: %s", r.Error)
	}
	return nil
}
