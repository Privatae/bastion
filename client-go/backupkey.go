package main

// backupkey.go — this bastion's backup key, kept on this machine, and the
// sealed "sidecar" that carries each backup's own key.
//
// WHY THE KEY LIVES HERE. A host encrypts every backup, before it leaves the
// host, to the public keys registered with it: the host's recovery key (which
// its owner keeps) and any bastion keys like this one. Only a matching private
// key opens one, and the platform the host runs on holds none of them. So
// this key is made here, stays here (0600, in this bastion's own state
// directory), and only its PUBLIC half is ever shown: the owner registers it
// on the host as a bastion key.
//
// WHY A SIDECAR. Each backup is also encrypted to a key made for that backup
// alone, and that key's private half is sealed, in a small file beside the
// backup, to the registered keys. Restoring a host means handing it that one
// backup's key and nothing else: this machine opens the sidecar and seals the
// same contents again to the restoring host's own key (reseal). This
// bastion's key never leaves this machine and the host never gets a key that
// opens any other backup. Gigabytes never cross this machine's connection for
// it.
//
// Every encryption here is age (filippo.io/age); nothing is hand-rolled. The
// one piece of code written here that touches key material is bech32, which
// is an encoding: it turns a raw 32-byte public key into the "age1..." string
// age parses (and validates) itself.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// backupStampRe is a backup's name: its UTC time, to the second. The host
// names every backup this way; anything else is not a backup of ours.
var backupStampRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

const (
	sidecarKind = "privatae-backup-key"
	// A sidecar is one short JSON document, armored. Anything larger is not
	// one, and reading an unbounded input from a host into memory is refused.
	sidecarMaxBytes = 64 << 10
)

// ── bech32 (BIP-173), the encoding of age's key strings ─────────────────────

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc, bits uint32
	maxv := uint32(1)<<to - 1
	var out []byte
	for _, b := range data {
		if uint32(b)>>from != 0 {
			return nil, errors.New("bech32: value out of range")
		}
		acc = acc<<from | uint32(b)
		bits += uint32(from)
		for bits >= uint32(to) {
			bits -= uint32(to)
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(uint32(to)-bits)&maxv))
		}
	} else if bits >= uint32(from) || acc<<(uint32(to)-bits)&maxv != 0 {
		return nil, errors.New("bech32: bad padding")
	}
	return out, nil
}

// bech32Encode encodes data under a lowercase human-readable part.
func bech32Encode(hrp string, data []byte) (string, error) {
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	poly := bech32Polymod(append(append(bech32HRPExpand(hrp), values...), 0, 0, 0, 0, 0, 0)) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range values {
		sb.WriteByte(bech32Charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(bech32Charset[(poly>>uint(5*(5-i)))&31])
	}
	return sb.String(), nil
}

// bech32Decode returns (hrp, data) of a bech32 string in one case.
func bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("bech32: mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("bech32: no separator or too short")
	}
	hrp := s[:pos]
	var values []byte
	for i := pos + 1; i < len(s); i++ {
		d := strings.IndexByte(bech32Charset, s[i])
		if d < 0 {
			return "", nil, errors.New("bech32: invalid character")
		}
		values = append(values, byte(d))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("bech32: bad checksum")
	}
	data, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}

// recipientRaw is the raw 32-byte X25519 public key inside an age1 recipient.
func recipientRaw(r *age.X25519Recipient) ([]byte, error) {
	hrp, data, err := bech32Decode(r.String())
	if err != nil {
		return nil, err
	}
	if hrp != "age" || len(data) != 32 {
		return nil, errors.New("not an age X25519 recipient")
	}
	return data, nil
}

// backupKeyFingerprint is sha256(raw public key), first 16 hex characters —
// the same string the host shows beside the key it holds, so a person can
// check the two are the same key.
func backupKeyFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

// parseBackupRecipient accepts what a host or a person hands over as "the key
// to seal to": an age1 recipient, or the raw 32-byte public key in base64 (the
// form the host's backup settings take).
func parseBackupRecipient(s string) (*age.X25519Recipient, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "age1") {
		r, err := age.ParseX25519Recipient(strings.ToLower(s))
		if err != nil {
			return nil, fmt.Errorf("that is not a valid age recipient: %w", err)
		}
		return r, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("the key to seal to must be an age1 recipient or a 32-byte public key in base64")
	}
	enc, err := bech32Encode("age", raw)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Recipient(enc)
}

// ── the key store on this machine ───────────────────────────────────────────
//
// Each key is a standard age identity file (<fingerprint>.txt, the format
// age-keygen writes), 0600 in this bastion's state directory. `active` names the one key this bastion shows and registers. A replaced key
// stays beside it: backups sealed to it still need it.

type backupKeyFile struct {
	Identity    string `json:"-"` // AGE-SECRET-KEY-1..., never printed
	Recipient   string `json:"recipient"`
	PubB64      string `json:"pubkey_b64"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
	Path        string `json:"path"`
}

// backupKeysDir is overridable only so tests do not write into the real
// state directory of whoever runs them.
var backupKeysDir = func() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "backup-keys")
	return p, os.MkdirAll(p, 0o700)
}

var backupKeyFileRe = regexp.MustCompile(`^[0-9a-f]{16}\.txt$`)

func backupKeyFromIdentityFile(path string) (*backupKeyFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k := &backupKeyFile{Path: path}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "# created: "):
			k.CreatedAt = strings.TrimPrefix(line, "# created: ")
		case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
			k.Identity = line
		}
	}
	id, err := age.ParseX25519Identity(k.Identity)
	if err != nil {
		return nil, fmt.Errorf("backup key file %s holds no usable key", filepath.Base(path))
	}
	pub, err := recipientRaw(id.Recipient())
	if err != nil {
		return nil, err
	}
	k.Recipient = id.Recipient().String()
	k.PubB64 = base64.StdEncoding.EncodeToString(pub)
	k.Fingerprint = backupKeyFingerprint(pub)
	return k, nil
}

func backupKeysLoad() (active *backupKeyFile, all []*backupKeyFile, err error) {
	dir, err := backupKeysDir()
	if err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	activeFP := ""
	if raw, err := os.ReadFile(filepath.Join(dir, "active")); err == nil {
		activeFP = strings.TrimSpace(string(raw))
	}
	for _, e := range entries {
		if !backupKeyFileRe.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		k, err := backupKeyFromIdentityFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, nil, err
		}
		all = append(all, k)
		if k.Fingerprint == activeFP {
			active = k
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt > all[j].CreatedAt })
	return active, all, nil
}

// backupKeyInit makes this bastion's backup key. An existing key is never
// overwritten: backups already sealed to it would become unopenable. With
// replace, a new key becomes the active one and the old one stays in the
// folder, still opening the backups made with it.
func backupKeyInit(replace bool) (*backupKeyFile, error) {
	active, _, err := backupKeysLoad()
	if err != nil {
		return nil, err
	}
	if active != nil && !replace {
		return nil, fmt.Errorf("this bastion already holds a backup key (fingerprint %s). Replacing it "+
			"means backups made from now on need the new key; the old key is kept so older "+
			"backups still open. Run again with --replace if that is what you want", active.Fingerprint)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	raw, err := recipientRaw(id.Recipient())
	if err != nil {
		return nil, err
	}
	dir, err := backupKeysDir()
	if err != nil {
		return nil, err
	}
	fp := backupKeyFingerprint(raw)
	now := time.Now().UTC().Format(time.RFC3339)
	body := "# created: " + now + "\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	path := filepath.Join(dir, fp+".txt")
	if err := atomicWrite(path, []byte(body)); err != nil {
		return nil, err
	}
	if err := atomicWrite(filepath.Join(dir, "active"), []byte(fp+"\n")); err != nil {
		return nil, err
	}
	return &backupKeyFile{Identity: id.String(), Recipient: id.Recipient().String(),
		PubB64: base64.StdEncoding.EncodeToString(raw), Fingerprint: fp, CreatedAt: now, Path: path}, nil
}

// backupIdentities is every backup key this machine holds, newest first: a
// backup made before a replacement is still opened by the key it was sealed to.
func backupIdentities() ([]age.Identity, error) {
	_, all, err := backupKeysLoad()
	if err != nil {
		return nil, err
	}
	var ids []age.Identity
	for _, k := range all {
		id, err := age.ParseX25519Identity(k.Identity)
		if err != nil {
			return nil, fmt.Errorf("backup key %s does not parse: %w", k.Fingerprint, err)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("this machine holds no backup key — make one with `privatae-bastion backup key init`")
	}
	return ids, nil
}

// identitiesFromFile reads an age identity file the person names.
func identitiesFromFile(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("%s holds no usable age identity: %w", path, err)
	}
	return ids, nil
}

// ── the sidecar ─────────────────────────────────────────────────────────────

type backupSidecar struct {
	V        int    `json:"v"`
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Object   string `json:"object"`
	EntityID int64  `json:"entity_id"`
	Stamp    string `json:"stamp"`
	MadeAt   string `json:"made_at"`
}

// openSidecar decrypts an armored sidecar and checks it is one of ours and
// names the backup it claims to. Returns the plaintext exactly as sealed, so
// a reseal hands on the same bytes and not a re-encoding of them.
func openSidecar(armored []byte, ids []age.Identity, wantStamp string) ([]byte, *backupSidecar, error) {
	if len(armored) > sidecarMaxBytes {
		return nil, nil, errors.New("the sidecar is larger than a sidecar can be")
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(armored)), ids...)
	if err != nil {
		return nil, nil, fmt.Errorf("the sidecar does not open with the keys given: %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, sidecarMaxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("the sidecar is damaged: %w", err)
	}
	if len(plain) > sidecarMaxBytes {
		return nil, nil, errors.New("the sidecar holds more than a sidecar can")
	}
	var sc backupSidecar
	if err := json.Unmarshal(plain, &sc); err != nil {
		return nil, nil, errors.New("the sidecar does not hold a backup key record")
	}
	if sc.V != 1 || sc.Kind != sidecarKind {
		return nil, nil, fmt.Errorf("the sidecar is not a backup key record (v=%d kind=%q)", sc.V, sc.Kind)
	}
	if !backupStampRe.MatchString(sc.Stamp) {
		return nil, nil, fmt.Errorf("the sidecar names no valid backup (stamp %q)", sc.Stamp)
	}
	if !sidecarObjectOK(sc.Object, sc.Stamp) {
		return nil, nil, fmt.Errorf("the sidecar's object %q does not match its stamp %s", sc.Object, sc.Stamp)
	}
	if wantStamp != "" && sc.Stamp != wantStamp {
		return nil, nil, fmt.Errorf("the sidecar is for the backup of %s, not %s", sc.Stamp, wantStamp)
	}
	if _, err := time.Parse(time.RFC3339, sc.MadeAt); err != nil {
		return nil, nil, fmt.Errorf("the sidecar's made_at %q is not a time", sc.MadeAt)
	}
	if _, err := age.ParseX25519Identity(sc.Identity); err != nil {
		return nil, nil, errors.New("the sidecar's backup key does not parse")
	}
	return plain, &sc, nil
}

// sidecarObjectOK: the object a sidecar names is the backup of its own stamp,
// in one of the two places the platform keeps one: b/ (a backup kept in
// platform storage) or s/ (a copy staged there only until a second copy
// exists, which is how a backup kept only on the person's bastion is
// written). Nothing else: no other folder, no deeper path, no other stamp.
func sidecarObjectOK(object, stamp string) bool {
	name := stamp + ".tar.zst.age"
	return object == "b/"+name || object == "s/"+name
}

// resealSidecar opens a sidecar with this machine's keys and seals the same
// record to exactly one recipient: the host that is restoring. Armored, so it
// travels as text.
func resealSidecar(armored []byte, ids []age.Identity, to *age.X25519Recipient, wantStamp string) ([]byte, *backupSidecar, error) {
	plain, sc, err := openSidecar(armored, ids, wantStamp)
	if err != nil {
		return nil, nil, err
	}
	out, err := sealSidecarTo(plain, to)
	if err != nil {
		return nil, nil, err
	}
	return out, sc, nil
}

// sealSidecarTo seals an opened sidecar's record, byte for byte, to exactly
// one recipient, armored.
func sealSidecarTo(plain []byte, to *age.X25519Recipient) ([]byte, error) {
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, to)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
