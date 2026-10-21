package main

// ops_seal.go — this machine's encryption key, and the credentials an action
// op is handed sealed to it.
//
// An action op names the credentials its program needs (`credentials:
// [registry]`), never their values. The host's vault seals each value to this
// machine's X25519 key (NaCl sealed box, libsodium crypto_box_seal), bound to
// the run: the sealed record carries the credential's name and the nonce of
// the terms it rides with — an op_run's own nonce, or, for a run under a
// standing grant (privilege user, so no verbs), the grant's, which any run of
// that grant within its bounds may use. The bastion opens them at the run's start, hands
// them to the program in its environment, scrubs them from its output, and
// keeps them only on the run's own tmpfs, which is unmounted when the run ends
// (and by the startup sweep if the bastion died mid-run). The pod relays
// sealed bytes; only this machine can open them.
//
// The public key travels on every heartbeat, signed by this machine's own key
// (owner.go), which is the key the person's device pins for receipts. The host
// pins the encryption key the first time it sees it after anchoring, the same
// trust-on-first-use the entity key has here, and a key that changes after
// that is a different machine answering.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	opEncKeyFile = "encryption_key.json"
	// opSealedMaxBytes bounds one sealed credential on the wire.
	opSealedMaxBytes = 16 << 10
)

var opEncKeyMu sync.Mutex

type opEncKeyFileRec struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	CreatedAt  string `json:"created_at"`
}

// opEncKey returns this machine's encryption key pair, creating it on first
// use. It lives in the machine's record (masked from every op), 0600.
func opEncKey() (*[32]byte, *[32]byte, error) {
	opEncKeyMu.Lock()
	defer opEncKeyMu.Unlock()
	d, err := configDir()
	if err != nil {
		return nil, nil, err
	}
	p := filepath.Join(d, opEncKeyFile)
	if raw, err := os.ReadFile(p); err == nil {
		var f opEncKeyFileRec
		if json.Unmarshal(raw, &f) == nil {
			pub, e1 := base64.StdEncoding.DecodeString(f.PublicKey)
			priv, e2 := base64.StdEncoding.DecodeString(f.PrivateKey)
			if e1 == nil && e2 == nil && len(pub) == 32 && len(priv) == 32 {
				var a, b [32]byte
				copy(a[:], pub)
				copy(b[:], priv)
				return &a, &b, nil
			}
		}
		// A key file that does not read is never silently replaced: the host
		// pinned the key it held, and a new one would read as another machine.
		return nil, nil, fmt.Errorf("this machine's %s does not read; move it aside to make a new key (the host will see a new machine key)", opEncKeyFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	raw, _ := json.MarshalIndent(opEncKeyFileRec{
		PublicKey:  base64.StdEncoding.EncodeToString(pub[:]),
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err := atomicWrite(p, raw); err != nil {
		return nil, nil, err
	}
	_ = os.Chmod(p, 0o600)
	return pub, priv, nil
}

// opEncKeySigningInput is what this machine's own key signs to vouch for its
// encryption key, tagged like every other input that key signs (owner.go).
func opEncKeySigningInput(pubB64 string) []byte {
	return []byte("encryption-key\n" + pubB64)
}

// opEncKeyClaim is the heartbeat's statement of the encryption key: the key,
// and this machine's signature over it. Nil when either key cannot be had.
func opEncKeyClaim() map[string]any {
	pub, _, err := opEncKey()
	if err != nil {
		return nil
	}
	mpub, mpriv, err := loadOrCreateOwnerKey()
	if err != nil {
		return nil
	}
	b64 := base64.StdEncoding.EncodeToString(pub[:])
	return map[string]any{
		"public_key":  b64,
		"machine_key": base64.StdEncoding.EncodeToString(mpub),
		"signature":   base64.StdEncoding.EncodeToString(ed25519.Sign(mpriv, opEncKeySigningInput(b64))),
	}
}

// opSealedCred is what the host seals: one credential, for one run.
type opSealedCred struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Nonce   string `json:"nonce"`   // the terms' nonce: this run and no other
	Expires string `json:"expires"` // RFC3339; the run's terms bound it too
}

// opOpenCreds opens the sealed credentials a run was handed and checks them
// against the op: each is one the op declares, each is sealed for this run,
// none is expired, none arrives twice, and every declared one is there.
// dryRun: a dry run is handed none, and refuses any.
func opOpenCreds(blobs []string, m *opManifest, nonce string, dryRun bool) (map[string]string, error) {
	if dryRun {
		if len(blobs) > 0 {
			return nil, errors.New("a dry run is never handed a credential")
		}
		return map[string]string{}, nil
	}
	declared := map[string]bool{}
	for _, c := range m.Credentials {
		declared[c] = true
	}
	if len(blobs) > len(declared) {
		return nil, errors.New("the run was handed more credentials than the op declares")
	}
	pub, priv, err := opEncKey()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, b := range blobs {
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil || len(raw) > opSealedMaxBytes {
			return nil, errors.New("a sealed credential is malformed")
		}
		plain, ok := box.OpenAnonymous(nil, raw, pub, priv)
		if !ok {
			return nil, errors.New("a sealed credential does not open with this machine's key")
		}
		var c opSealedCred
		if err := json.Unmarshal(plain, &c); err != nil {
			return nil, errors.New("a sealed credential does not parse")
		}
		if !declared[c.Name] {
			return nil, fmt.Errorf("the credential %q is not one this op declares", c.Name)
		}
		if c.Nonce != nonce {
			return nil, fmt.Errorf("the credential %q was sealed for another run", c.Name)
		}
		exp, err := time.Parse(time.RFC3339, c.Expires)
		if err != nil || !exp.After(time.Now()) {
			return nil, fmt.Errorf("the credential %q has expired", c.Name)
		}
		if _, dup := out[c.Name]; dup {
			return nil, fmt.Errorf("the credential %q arrived twice", c.Name)
		}
		if c.Value == "" {
			return nil, fmt.Errorf("the credential %q is empty", c.Name)
		}
		out[c.Name] = c.Value
	}
	for c := range declared {
		if _, ok := out[c]; !ok {
			return nil, fmt.Errorf("the op declares the credential %q and the run was not handed it", c)
		}
	}
	return out, nil
}

// opSealCredFor seals a credential to a public key: the host's side, kept
// here for the tests and for a person sealing by hand at the machine.
func opSealCredFor(pub *[32]byte, c opSealedCred) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	out, err := box.SealAnonymous(nil, raw, pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out), nil
}
