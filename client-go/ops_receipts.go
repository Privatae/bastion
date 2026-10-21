package main

// ops_receipts.go — what an action op's apply produced, signed by this
// machine, and what this machine rolled.
//
// A build step's program reports the images it pushed in its work folder's
// privatae-result.json:
//
//	{"images": [{"image": "forge.example.com/acme/web",
//	             "digest": "sha256:…",
//	             "source": "https://forge.example.com/acme/app.git",
//	             "commit": "<40 hex>"}]}
//
// The bastion turns each into a RECEIPT: which machine, which run of which op
// (its sha256 and its params' sha256), the image, digest, source repository
// and commit. It is signed with this machine's own key (owner.go) as a DSSE
// envelope of its own payload type, and held in the machine's record by
// digest. k8s.set_image rolls only a digest a receipt names, of the image the
// receipt names, and only forward: the receipt's commit must descend from the
// commit behind the live image, which this machine knows only from the roll
// that put it there (opRolledCommit). A live image it did not roll is refused,
// and says so, never guessed at.
//
// This machine accepts only its own receipts. Receipts from another machine
// (a build on one, a roll on another) are verified under keys the person's
// device pins, which is the signed ship plan's rung.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	opReceiptsDirName = "receipts"
	opRolledFileName  = "rolled.json"
	opResultMaxBytes  = 64 << 10
	opResultMaxImages = 8
)

var opReceiptsMu sync.Mutex

type opReceipt struct {
	V            int    `json:"v"`
	Machine      string `json:"machine"`
	Key          string `json:"key"` // this machine's public key, b64
	Run          string `json:"run"`
	Op           string `json:"op"`
	OpSHA256     string `json:"op_sha256"`
	ParamsSHA256 string `json:"params_sha256"`
	At           string `json:"at"`
	Image        string `json:"image"`
	Digest       string `json:"digest"`
	Source       string `json:"source"`
	Commit       string `json:"commit"`
}

// opSignedReceipt is a DSSE envelope: the receipt's exact bytes, base64, and
// this machine's signature over DSSE's pre-authentication encoding of them,
// so a verifier never re-serialises what it checks and the type is signed.
type opSignedReceipt struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

const opReceiptPayloadType = "application/vnd.privatae.receipt.v1+json"

// opReceiptSigningInput is DSSE's PAE: "DSSEv1 <len> <type> <len> <body>".
func opReceiptSigningInput(raw []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(opReceiptPayloadType), opReceiptPayloadType, len(raw), raw))
}

// opResultImage is one image a program says it pushed.
type opResultImage struct {
	Image  string `json:"image"`
	Digest string `json:"digest"`
	Source string `json:"source"`
	Commit string `json:"commit"`
}

// opParseResult judges a program's result file.
func opParseResult(raw []byte) ([]opResultImage, error) {
	var r struct {
		Images []opResultImage `json:"images"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, errors.New("the program's result does not parse")
	}
	if len(r.Images) > opResultMaxImages {
		return nil, fmt.Errorf("the program's result names more than %d images", opResultMaxImages)
	}
	for _, im := range r.Images {
		if !opImageRe.MatchString(im.Image) || !opDigestRe.MatchString(im.Digest) || !opCommitRe.MatchString(im.Commit) {
			return nil, errors.New("an image in the program's result is not image, sha256 digest and full commit")
		}
		if err := opRepoURLOK(im.Source); err != nil {
			return nil, errors.New("an image's source in the program's result is not a repository URL")
		}
	}
	return r.Images, nil
}

// opIssueReceipts signs one receipt per image and holds each by digest.
func opIssueReceipts(run, op, opSHA, params string, images []opResultImage) ([]opSignedReceipt, error) {
	pub, priv, err := loadOrCreateOwnerKey()
	if err != nil {
		return nil, err
	}
	hn, _ := os.Hostname()
	ps := sha256.Sum256([]byte(params))
	var out []opSignedReceipt
	for _, im := range images {
		r := opReceipt{V: 1, Machine: hn, Key: base64.StdEncoding.EncodeToString(pub), Run: run, Op: op,
			OpSHA256: opSHA, ParamsSHA256: hex.EncodeToString(ps[:]), At: time.Now().UTC().Format(time.RFC3339),
			Image: im.Image, Digest: im.Digest, Source: opCleanRepoURL(im.Source), Commit: im.Commit}
		raw, _ := json.Marshal(r)
		s := opSignedReceipt{PayloadType: opReceiptPayloadType, Payload: base64.StdEncoding.EncodeToString(raw),
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, opReceiptSigningInput(raw)))}
		if err := opHoldReceipt(s); err != nil {
			return out, err
		}
		out = append(out, s)
	}
	return out, nil
}

// opVerifyReceipt checks a receipt: signed by THIS machine's key, well formed.
func opVerifyReceipt(s opSignedReceipt) (*opReceipt, error) {
	raw, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil || s.PayloadType != opReceiptPayloadType {
		return nil, errors.New("a receipt is not a receipt envelope")
	}
	var r opReceipt
	if err := json.Unmarshal(raw, &r); err != nil || r.V != 1 {
		return nil, errors.New("a receipt does not parse")
	}
	pub, _, err := loadOrCreateOwnerKey()
	if err != nil {
		return nil, err
	}
	if r.Key != base64.StdEncoding.EncodeToString(pub) {
		return nil, errors.New("a receipt signed by another machine's key (receipts from other machines come with the signed ship plan)")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(pub, opReceiptSigningInput(raw), sig) {
		return nil, errors.New("a receipt's signature does not verify")
	}
	if !opDigestRe.MatchString(r.Digest) || !opImageRe.MatchString(r.Image) || !opCommitRe.MatchString(r.Commit) {
		return nil, errors.New("a receipt names no image, digest and commit")
	}
	return &r, nil
}

func opReceiptsDir() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, opReceiptsDirName)
	return p, os.MkdirAll(p, 0o700)
}

func opReceiptPath(digest string) (string, error) {
	if !opDigestRe.MatchString(digest) {
		return "", errors.New("not a sha256 digest")
	}
	d, err := opReceiptsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, strings.TrimPrefix(digest, "sha256:")+".json"), nil
}

func opHoldReceipt(s opSignedReceipt) error {
	r, err := opVerifyReceipt(s)
	if err != nil {
		return err
	}
	p, err := opReceiptPath(r.Digest)
	if err != nil {
		return err
	}
	opReceiptsMu.Lock()
	defer opReceiptsMu.Unlock()
	// The first receipt for a digest stands: a later run naming the same
	// digest with another image, source or commit is refused, never allowed
	// to rewrite what the digest was built from.
	if prevRaw, err := os.ReadFile(p); err == nil {
		var prev opSignedReceipt
		if json.Unmarshal(prevRaw, &prev) == nil {
			if pr, err := opVerifyReceipt(prev); err == nil {
				if pr.Image != r.Image || pr.Source != r.Source || pr.Commit != r.Commit {
					return fmt.Errorf("this machine already holds a receipt for %s built from %s, not %s", truncate(r.Digest, 19), truncate(pr.Commit, 12), truncate(r.Commit, 12))
				}
				return nil
			}
		}
	}
	raw, _ := json.MarshalIndent(s, "", "  ")
	return atomicWrite(p, raw)
}

// opReceiptFor is the verified receipt this machine holds for a digest, or nil.
func opReceiptFor(digest string) (*opReceipt, error) {
	p, err := opReceiptPath(digest)
	if err != nil {
		return nil, err
	}
	opReceiptsMu.Lock()
	raw, err := os.ReadFile(p)
	opReceiptsMu.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s opSignedReceipt
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errors.New("a held receipt does not parse")
	}
	r, err := opVerifyReceipt(s)
	if err != nil {
		return nil, err
	}
	if r.Digest != digest {
		return nil, errors.New("a held receipt names another digest")
	}
	return r, nil
}

// ── what this machine rolled ────────────────────────────────────────────────

// opRollRec is the commit behind a digest this machine rolled, from the
// receipt it rolled it under.
type opRollRec struct {
	Image    string `json:"image"`
	Source   string `json:"source"`
	Commit   string `json:"commit"`
	Workload string `json:"workload"`
	At       string `json:"at"`
}

func opRolledPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, opRolledFileName), nil
}

func opRolledLoad() map[string]opRollRec {
	out := map[string]opRollRec{}
	p, err := opRolledPath()
	if err != nil {
		return out
	}
	if raw, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func opRecordRoll(digest string, r opRollRec) error {
	opReceiptsMu.Lock()
	defer opReceiptsMu.Unlock()
	m := opRolledLoad()
	m[digest] = r
	p, err := opRolledPath()
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	return atomicWrite(p, raw)
}

// opRolledCommit is the commit behind a digest this machine itself rolled.
// Only a roll counts, never a receipt alone: a program could report the live
// digest as something it built, and give an image this machine never rolled
// a history it does not have. ok=false: nothing.
func opRolledCommit(digest string) (image, source, commit string, ok bool) {
	opReceiptsMu.Lock()
	r, held := opRolledLoad()[digest]
	opReceiptsMu.Unlock()
	if held && opCommitRe.MatchString(r.Commit) {
		return r.Image, r.Source, r.Commit, true
	}
	return "", "", "", false
}
