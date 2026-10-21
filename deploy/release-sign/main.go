// release-sign signs bastion, bastion-agent and C-Series Cloud release
// manifests, and the C-Series App Store catalog, with the offline release key,
// on the computer that holds it.
//
//	release-sign new [--out <file>]           make a key (asks for a passphrase)
//	release-sign pub [--key <file>]           print the key's public half
//	release-sign sign <kind> <version> <sha256> [--key <file>]
//	release-sign verify <kind> <manifest> <sig-file> <public-key>...
//	release-sign pinned <release_sign.go>     print the keys a bastion source pins
//
// <kind> is "bastion", "bastion-agent", "cseries-cloud" or "cseries-store".
// cseries-cloud is the manifest a C-Series Cloud machine's updater reads before
// it moves to new images or a new overlay, and cseries-store is the App Store
// catalog a C-Series Host reads before it lists or installs an app. Both are
// signed with the same key so that control of the code host alone cannot roll
// those machines or change what a Host installs. A release waits at the publish step
// for the line `sign` prints; the private key never leaves this computer and
// is stored encrypted under the passphrase, so a copy of the file alone does
// not sign anything.
//
// What is signed is a short statement, not the manifest itself, so the person
// signing can read it:
//
//	privatae-release-signature-v1
//	<kind>
//	<version>
//	<sha256 of the manifest's exact bytes, hex>
//
// The bastion rebuilds that statement from the manifest it downloaded
// (client-go/release_sign.go) and checks the signature against it.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

// Statement is the exact text a release signature covers. The bastion builds
// the same text in client-go/release_sign.go; the two must never differ.
func Statement(kind, version, sha256hex string) []byte {
	return []byte("privatae-release-signature-v1\n" + kind + "\n" + version + "\n" + sha256hex + "\n")
}

var (
	kinds     = map[string]bool{"bastion": true, "bastion-agent": true, "cseries-cloud": true, "cseries-store": true}
	versionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
	shaRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// keyFile is the encrypted private key on disk. The 32-byte ed25519 seed is
// sealed with XChaCha20-Poly1305 under a key derived from the passphrase with
// argon2id.
type keyFile struct {
	V      int    `json:"v"`
	Pub    string `json:"pub"`
	Salt   string `json:"salt"`
	Time   uint32 `json:"argon2_time"`
	Memory uint32 `json:"argon2_memory_kib"`
	Thread uint8  `json:"argon2_threads"`
	Nonce  string `json:"nonce"`
	Sealed string `json:"sealed"`
}

// argon2id parameters: OWASP's first recommended setting is 19 MiB, t=2. This
// key is opened once per release on one person's computer, so it can afford
// far more; 256 MiB, t=4 takes about a second on a current laptop.
const (
	kdfTime    = 4
	kdfMemory  = 256 * 1024
	kdfThreads = 4
)

// defaultKeyPath keeps the key in the LOCAL profile. On Windows that is
// %LocalAppData%, not the Roaming %AppData% os.UserConfigDir returns: a
// roaming profile is copied to the domain's servers, and this key is meant
// to stay on this one computer.
func defaultKeyPath() string {
	dir := os.Getenv("LOCALAPPDATA")
	if dir == "" {
		var err error
		if dir, err = os.UserConfigDir(); err != nil {
			dir = "."
		}
	}
	return filepath.Join(dir, "privatae-release", "release-key.json")
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "release-sign:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New(`usage:
  release-sign new [--out <file>]
  release-sign pub [--key <file>]
  release-sign sign <kind> <version> <sha256> [--key <file>]
  release-sign verify <kind> <manifest> <sig-file> <public-key>...
  release-sign pinned <release_sign.go>`)
}

// flagValue removes "--name value" from args and returns the value.
func flagValue(args []string, name string) ([]string, string) {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return append(append([]string{}, args[:i]...), args[i+2:]...), args[i+1]
		}
	}
	return args, ""
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "new":
		rest, out := flagValue(rest, "--out")
		if len(rest) != 0 {
			return usage()
		}
		if out == "" {
			out = defaultKeyPath()
		}
		return cmdNew(out)
	case "pub":
		rest, path := flagValue(rest, "--key")
		if len(rest) != 0 {
			return usage()
		}
		if path == "" {
			path = defaultKeyPath()
		}
		kf, err := readKeyFile(path)
		if err != nil {
			return err
		}
		fmt.Println(kf.Pub)
		return nil
	case "sign":
		rest, path := flagValue(rest, "--key")
		if len(rest) != 3 {
			return usage()
		}
		if path == "" {
			path = defaultKeyPath()
		}
		return cmdSign(path, rest[0], rest[1], strings.ToLower(rest[2]))
	case "pinned":
		if len(rest) != 1 {
			return usage()
		}
		keys, err := PinnedKeys(rest[0])
		if err != nil {
			return err
		}
		fmt.Println(strings.Join(keys, " "))
		return nil
	case "verify":
		if len(rest) < 4 {
			return usage()
		}
		return cmdVerify(rest[0], rest[1], rest[2], rest[3:])
	}
	return usage()
}

func readPassphrase(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("run this in PowerShell, Command Prompt or Windows Terminal: it asks for the passphrase and cannot read one piped in")
	}
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return p, err
}

func deriveKey(pass, salt []byte, t, m uint32, p uint8) []byte {
	return argon2.IDKey(pass, salt, t, m, p, chacha20poly1305.KeySize)
}

func cmdNew(out string) error {
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("%s already exists; a release key is never overwritten", out)
	}
	pass, err := readPassphrase("New passphrase for the release key: ")
	if err != nil {
		return err
	}
	if len(pass) < 12 {
		return errors.New("use a passphrase of at least 12 characters")
	}
	again, err := readPassphrase("Same passphrase again: ")
	if err != nil {
		return err
	}
	if string(again) != string(pass) {
		return errors.New("the two passphrases differ; nothing was written")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	kf, err := seal(priv.Seed(), pub, pass)
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Key written to %s\nPublic key (this is what gets pinned in the bastion):\n", out)
	fmt.Println(kf.Pub)
	return nil
}

func seal(seed []byte, pub ed25519.PublicKey, pass []byte) (*keyFile, error) {
	salt := make([]byte, 16)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(deriveKey(pass, salt, kdfTime, kdfMemory, kdfThreads))
	if err != nil {
		return nil, err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	return &keyFile{
		V: 1, Pub: pubB64,
		Salt: base64.StdEncoding.EncodeToString(salt), Time: kdfTime, Memory: kdfMemory, Thread: kdfThreads,
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		Sealed: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, seed, []byte(pubB64))),
	}, nil
}

func readKeyFile(path string) (*keyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil || kf.V != 1 {
		return nil, fmt.Errorf("%s is not a release key file", path)
	}
	return &kf, nil
}

func open(kf *keyFile, pass []byte) (ed25519.PrivateKey, error) {
	// The settings come from the file. Out-of-range ones would make argon2
	// panic (time or threads of 0) or try to allocate without bound, so a
	// damaged or edited file is refused instead.
	if kf.Time < 1 || kf.Time > 64 || kf.Thread < 1 || kf.Thread > 64 ||
		kf.Memory < 64*1024 || kf.Memory > 4*1024*1024 {
		return nil, errors.New("key file is damaged: its key-derivation settings are out of range")
	}
	salt, e1 := base64.StdEncoding.DecodeString(kf.Salt)
	nonce, e2 := base64.StdEncoding.DecodeString(kf.Nonce)
	sealed, e3 := base64.StdEncoding.DecodeString(kf.Sealed)
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, errors.New("key file is damaged")
	}
	aead, err := chacha20poly1305.NewX(deriveKey(pass, salt, kf.Time, kf.Memory, kf.Thread))
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, sealed, []byte(kf.Pub))
	if err != nil {
		return nil, errors.New("wrong passphrase, or the key file was changed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) != kf.Pub {
		return nil, errors.New("key file is damaged")
	}
	return priv, nil
}

func checkStatement(kind, version, sha string) error {
	if !kinds[kind] {
		return fmt.Errorf("kind must be bastion, bastion-agent, cseries-cloud or cseries-store, not %q", kind)
	}
	if !versionRe.MatchString(version) {
		return fmt.Errorf("%q is not a release version", version)
	}
	if !shaRe.MatchString(sha) {
		return errors.New("the sha256 must be 64 hex characters")
	}
	return nil
}

func cmdSign(path, kind, version, sha string) error {
	if err := checkStatement(kind, version, sha); err != nil {
		return err
	}
	kf, err := readKeyFile(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Signing the %s %s release (manifest sha256 %s…%s).\n", kind, version, sha[:8], sha[56:])
	pass, err := readPassphrase("Passphrase: ")
	if err != nil {
		return err
	}
	priv, err := open(kf, pass)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Paste this line back into the release:")
	fmt.Println(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Statement(kind, version, sha))))
	return nil
}

// cmdVerify checks a signature over a manifest file the way the bastion does,
// against any of the given public keys. The publish and verify scripts use it.
func cmdVerify(kind, manifestPath, sigPath string, pubs []string) error {
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	pub, err := VerifyManifest(kind, body, sig, pubs)
	if err != nil {
		return err
	}
	fmt.Println(pub)
	return nil
}

// VerifyManifest mirrors client-go/release_sign.go verifyReleaseSignature and
// returns the key that verified.
func VerifyManifest(kind string, body, sig []byte, pubs []string) (string, error) {
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return "", errors.New("manifest is not JSON")
	}
	sum := sha256.Sum256(body)
	if err := checkStatement(kind, m.Version, hex.EncodeToString(sum[:])); err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return "", errors.New("signature is malformed")
	}
	msg := Statement(kind, m.Version, hex.EncodeToString(sum[:]))
	for _, k := range pubs {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, raw) {
			return k, nil
		}
	}
	return "", errors.New("signature does not verify against any of the given keys")
}
