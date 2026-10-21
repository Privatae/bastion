package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The managed install signs the agent's manifest in Go (faSignManifest): the
// agent prints `payload`, the bastion signs it with the key it minted, the
// agent records it with `sign --value`. No openssl anywhere — Windows ships
// none, and every Windows agent used to stop at `missing-openssl`.

const fakeAgent = `import base64, sys
args = sys.argv[1:]
if args[0] == "payload":
    sys.stdout.buffer.write(open(args[1], "rb").read())
elif args[0] == "sign":
    path = args[1]
    val = args[args.index("--value") + 1]
    cert = args[args.index("--cert") + 1]
    base64.b64decode(val, validate=True)
    open(path + ".sig", "w").write(val + "\n" + cert)
else:
    sys.exit(2)
`

func findPython(t *testing.T) string {
	for _, n := range []string{"python3", "python"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	t.Skip("no python on PATH")
	return ""
}

// pythonOnlyPath: a PATH holding a link to python and NOTHING else, so a step
// that reached for openssl would fail here the way it does on Windows.
func pythonOnlyPath(t *testing.T, py string) string {
	d := t.TempDir()
	if err := os.Symlink(py, filepath.Join(d, filepath.Base(py))); err != nil {
		t.Skip("cannot link python: " + err.Error())
	}
	if _, err := exec.LookPath("openssl"); err == nil {
		old := os.Getenv("PATH")
		os.Setenv("PATH", d)
		defer os.Setenv("PATH", old)
		if _, err := exec.LookPath("openssl"); err == nil {
			t.Fatal("openssl still resolvable on the python-only PATH")
		}
	}
	return d
}

func TestFaSignManifestSignsPayloadWithMintedKey(t *testing.T) {
	py := findPython(t)
	dir := t.TempDir()
	cert, key, _, err := faEnsureIdentity(dir, "desk-example")
	if err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(dir, "agent.py")
	if err := os.WriteFile(agent, []byte(fakeAgent), 0o600); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "manifest.yaml")
	body := []byte("freeagent: 1\nid: t\n")
	if err := os.WriteFile(staged, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// PATH without openssl: the step must not need it.
	env := []string{"PATH=" + pythonOnlyPath(t, py)}
	if err := faSignManifest(py, nil, agent, staged, key, cert, env); err != nil {
		t.Fatalf("faSignManifest: %v", err)
	}
	rec, err := os.ReadFile(staged + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(rec), "\n", 2)
	if parts[1] != cert {
		t.Fatalf("recorded cert %q, want %q", parts[1], cert)
	}
	sig, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := os.ReadFile(cert)
	blk, _ := pem.Decode(cb)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if !ecdsa.VerifyASN1(c.PublicKey.(*ecdsa.PublicKey), sum[:], sig) {
		t.Fatal("signature does not verify against the minted cert over the payload")
	}
}

func TestFaSignManifestReportsAgentFailure(t *testing.T) {
	py := findPython(t)
	dir := t.TempDir()
	cert, key, _, err := faEnsureIdentity(dir, "desk-example")
	if err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(dir, "agent.py")
	_ = os.WriteFile(agent, []byte("import sys\nsys.stderr.write('bad manifest')\nsys.exit(1)\n"), 0o600)
	err = faSignManifest(py, nil, agent, filepath.Join(dir, "m.yaml"), key, cert, nil)
	if err == nil || !strings.Contains(err.Error(), "bad manifest") {
		t.Fatalf("want the agent's own error, got %v", err)
	}
}

// With FA_TEST_AGENT_PYZ pointing at a built agent (bastion_agent/build.py),
// the real `payload` / `sign --value` / gate round-trip runs, openssl-free.
func TestFaSignManifestWithRealAgent(t *testing.T) {
	pyz := os.Getenv("FA_TEST_AGENT_PYZ")
	if pyz == "" {
		t.Skip("FA_TEST_AGENT_PYZ not set")
	}
	py := findPython(t)
	dir := t.TempDir()
	cert, key, _, err := faEnsureIdentity(dir, "desk-example")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root")
	_ = os.MkdirAll(root, 0o700)
	staged := filepath.Join(dir, "manifest.yaml")
	text := "freeagent: 1\nid: t\nowner:\n  host: desk-example\nscope:\n  roots:\n  - " + root +
		"\nmask:\n- read\n- index\nstages:\n- walk\nsweep: manual\nsink:\n  catalog: local\n  vectors: local\n  plaintext: never\n"
	_ = os.WriteFile(staged, []byte(text), 0o600)
	env := []string{"PATH=" + pythonOnlyPath(t, py), "FREEAGENT_CA_ROOT=" + cert}
	if err := faSignManifest(py, nil, pyz, staged, key, cert, env); err != nil {
		t.Fatalf("faSignManifest: %v", err)
	}
	cmd := exec.Command(py, pyz, "sweep", staged, "--out", filepath.Join(dir, "out"), "--once")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the real agent's gate refused the Go-signed manifest: %v\n%s", err, out)
	}
}

func TestFaVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{
		{"0.1.10", "0.1.11", true}, {"0.1.9", "0.1.11", true}, {"0.1.11", "0.1.11", false},
		{"0.1.12", "0.1.11", false}, {"0.2", "0.1.11", false}, {"1.0.0", "0.1.11", false},
		{"", "0.1.11", true}, {"dev", "0.1.11", true},
	} {
		if got := faVersionLess(c.a, c.b); got != c.less {
			t.Errorf("faVersionLess(%q, %q) = %v, want %v", c.a, c.b, got, c.less)
		}
	}
}
