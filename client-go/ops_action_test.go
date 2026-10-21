//go:build !windows

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// opActionManifest is a valid action op; the tests change one thing at a time.
const opActionManifest = `name: web-roll
version: 1.0.0
summary: Move the web tree forward and restart it.
kind: action
target: machine
privilege: root
interpreter: /bin/sh
time_limit: 30
params:
  commit: {type: string, max_len: 64}
  digest: {type: string, max_len: 71}
  count: {type: integer, min: 1, max: 3}
destinations: ["forge.example.com:443", "[2001:db8::1]:5000"]
credentials: [forge-read, "registry:acme"]
verbs:
  - {verb: tree.checkout, path: /opt/acme, repo: "https://forge.example.com/acme/app.git", commit: "{{commit}}", credential: forge-read}
  - {verb: unit.restart, unit: acme-web.service}
  - {verb: k8s.set_image, namespace: ds, kind: deployment, name: web, container: web, image: forge.example.com/acme/web, digest: "{{digest}}", repo: "https://forge.example.com/acme/app.git"}
  - {verb: logs.check, unit: acme-web.service, must_not: "Traceback", lines: 200}
modes: [dry_run, apply, verify]
undo: none
`

func TestActionManifestParses(t *testing.T) {
	setupBox(t)
	m, err := parseOpManifest([]byte(opActionManifest))
	if err != nil {
		t.Fatal(err)
	}
	if !m.isAction() || len(m.Verbs) != 4 || len(m.Credentials) != 2 {
		t.Fatalf("parsed: %+v", m)
	}
	lines, err := opResolveVerbs(m, map[string]any{"commit": strings.Repeat("a", 40), "digest": "sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if lines[0].Args["commit"] != strings.Repeat("a", 40) || lines[2].Args["digest"] != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("the params land in the lines that name them: %+v", lines)
	}
	if lines[2].target() != "ds/deployment/web:web" {
		t.Fatalf("target: %s", lines[2].target())
	}
	// A param resolved to something the argument may not be is refused.
	if _, err := opResolveVerbs(m, map[string]any{"commit": "main", "digest": "sha256:" + strings.Repeat("b", 64)}); err == nil ||
		!strings.Contains(err.Error(), "never a branch") {
		t.Fatalf("a branch name is not a commit: %v", err)
	}
	if opCredEnv("registry:acme") != "PRIVATAE_CRED_REGISTRY_ACME" {
		t.Fatal(opCredEnv("registry:acme"))
	}
}

// Every way a manifest could reach past what its verbs and destinations
// declare is refused when the op arrives, with the sentence.
func TestActionManifestRefusesWhatIsNotDeclaredOrNotBounded(t *testing.T) {
	setupBox(t)
	sub := func(old, new string) string {
		if !strings.Contains(opActionManifest, old) {
			t.Fatalf("fixture has no %q", old)
		}
		return strings.Replace(opActionManifest, old, new, 1)
	}
	verbs := func(v string) string {
		i := strings.Index(opActionManifest, "verbs:\n")
		j := strings.Index(opActionManifest, "modes:")
		return opActionManifest[:i] + "verbs:\n" + v + opActionManifest[j:]
	}
	for name, c := range map[string]struct{ man, want string }{
		"an unknown verb":                       {verbs("  - {verb: shell.run, cmd: id}\n"), "not a verb"},
		"an argument the verb does not take":    {verbs("  - {verb: unit.restart, unit: a.service, signal: KILL}\n"), "takes no argument"},
		"a workload named by a param":           {sub("name: web,", `name: "{{commit}}",`), "fixed in the manifest"},
		"a container named by a param":          {sub("container: web,", `container: "{{commit}}",`), "fixed in the manifest"},
		"a unit named by a param":               {sub("unit: acme-web.service}", `unit: "{{commit}}"}`), "fixed in the manifest"},
		"a tree path named by a param":          {sub("path: /opt/acme,", `path: "{{commit}}",`), "fixed in the manifest"},
		"a param that is not a string":          {sub(`commit: "{{commit}}"`, `commit: "{{count}}"`), "not a string param"},
		"a param that does not exist":           {sub(`commit: "{{commit}}"`, `commit: "{{nope}}"`), "not a string param"},
		"a credential the op does not declare":  {sub("credential: forge-read}", "credential: other}"), "does not declare"},
		"verbs under privilege user":            {sub("privilege: root", "privilege: user"), "privilege root exactly when"},
		"root with no verbs":                    {verbs(""), "privilege root exactly when"},
		"file effects":                          {sub("kind: action", "kind: action\neffects:\n  files: [/srv/x/]"), "effects must be empty"},
		"an undo":                               {sub("modes: [dry_run, apply, verify]\nundo: none", "modes: [dry_run, apply, verify, undo]\nundo: run"), "undo: none"},
		"a destination on localhost":            {sub(`"forge.example.com:443"`, `"localhost:443"`), "never localhost"},
		"a destination on loopback":             {sub(`"forge.example.com:443"`, `"127.0.0.1:443"`), "loopback"},
		"a destination with no port":            {sub(`"forge.example.com:443"`, `"forge.example.com"`), "host:port"},
		"the metadata service":                  {sub(`"forge.example.com:443"`, `"169.254.169.254:80"`), "link-local"},
		"a link-local IPv6 address":             {sub(`"forge.example.com:443"`, `"[fe80::1]:80"`), "link-local"},
		"a metadata service outside link-local": {sub(`"forge.example.com:443"`, `"100.100.100.200:80"`), "metadata"},
		"AWS's IPv6 metadata service":           {sub(`"forge.example.com:443"`, `"[fd00:ec2::254]:80"`), "metadata"},
		"the metadata service through NAT64":    {sub(`"forge.example.com:443"`, `"[64:ff9b::a9fe:a9fe]:80"`), "link-local"},
		"loopback through IPv4-mapped IPv6":     {sub(`"forge.example.com:443"`, `"[::ffff:127.0.0.1]:80"`), "loopback"},
		"a roll with no repository":             {sub(`, repo: "https://forge.example.com/acme/app.git"}`, "}"), "needs repo"},
		"the bastion's own unit":                {sub("unit: acme-web.service}", "unit: privatae-bastion.service}"), "never restarts itself"},
		"a tree on a credential store":          {sub("path: /opt/acme,", "path: /etc/ssh,"), "sensitive"},
		"a tree at /":                           {sub("path: /opt/acme,", "path: /,"), "not /"},
		"an image with a tag":                   {sub("image: forge.example.com/acme/web,", "image: \"forge.example.com/acme/web:latest\","), "no tag or digest"},
		"a kind the verb does not roll":         {sub("kind: deployment,", "kind: cronjob,"), "deployment, statefulset or daemonset"},
		"a literal commit that is a branch":     {sub(`commit: "{{commit}}"`, `commit: main`), "never a branch"},
		"a repo that is not https":              {sub(`repo: "https://forge.example.com/acme/app.git"`, `repo: "ssh://forge.example.com/acme/app.git"`), "https"},
		"a log check on two things":             {sub("must_not: \"Traceback\"", "namespace: ds, kind: deployment, name: b, must_not: \"Traceback\""), "either one unit or one workload"},
		"a log check with nothing to look for":  {sub("must_not: \"Traceback\", ", ""), "must, must_not or both"},
		"a tree moved twice": {sub("  - {verb: tree.checkout, path: /opt/acme, repo: \"https://forge.example.com/acme/app.git\", commit: \"{{commit}}\", credential: forge-read}\n",
			"  - {verb: tree.checkout, path: /opt/acme, repo: \"https://forge.example.com/acme/app.git\", commit: \"{{commit}}\", credential: forge-read}\n  - {verb: tree.checkout, path: /opt/acme, repo: \"https://forge.example.com/acme/app.git\", commit: \"{{commit}}\", credential: forge-read}\n"), "moved twice"},
		"a container rolled twice": {sub("  - {verb: k8s.set_image, namespace: ds, kind: deployment, name: web, container: web, image: forge.example.com/acme/web, digest: \"{{digest}}\", repo: \"https://forge.example.com/acme/app.git\"}\n",
			"  - {verb: k8s.set_image, namespace: ds, kind: deployment, name: web, container: web, image: forge.example.com/acme/web, digest: \"{{digest}}\", repo: \"https://forge.example.com/acme/app.git\"}\n  - {verb: k8s.set_image, namespace: ds, kind: deployment, name: web, container: web, image: forge.example.com/acme/web, digest: \"{{digest}}\", repo: \"https://forge.example.com/acme/app.git\"}\n"), "moved twice"},
		"a log check with a bad pattern":  {sub(`must_not: "Traceback"`, `must_not: "("`), "not a valid pattern"},
		"a log check reading too much":    {sub("lines: 200", "lines: 999999"), "1..2000"},
		"two credentials in one variable": {sub(`credentials: [forge-read, "registry:acme"]`, `credentials: [forge-read, "registry:acme", "registry-acme"]`), "same variable"},
		"a verb missing its argument":     {verbs("  - {verb: unit.restart}\n"), "needs unit"},
		"a read of a credential store":    {sub("kind: action", "kind: action\nreads: [/root/.docker/config.json]"), "sensitive"},
	} {
		_, err := parseOpManifest([]byte(c.man))
		if err == nil || (c.want != "" && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: want a refusal saying %q, got %v", name, c.want, err)
		}
	}
	// A files op carrying an action op's fields is refused, not read as one.
	files := strings.Replace(opTestManifest, "modes:", "verbs:\n  - {verb: unit.restart, unit: a.service}\nmodes:", 1)
	if _, err := parseOpManifest([]byte(strings.Replace(files, "%s/", "/srv/work/optest/x/", 1))); err == nil || !strings.Contains(err.Error(), "belong to an action op") {
		t.Fatalf("a files op with verbs: %v", err)
	}
}

func TestSealedCredentialsOpenOnlyForThisRunAndThisOp(t *testing.T) {
	setupBox(t)
	m, err := parseOpManifest([]byte(opActionManifest))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := opEncKey()
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	seal := func(name, value, nonce, expires string) string {
		b, err := opSealCredFor(pub, opSealedCred{Name: name, Value: value, Nonce: nonce, Expires: expires})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	nonce := "n-0123456789abcdef"
	good := []string{seal("forge-read", "tok-1", nonce, exp), seal("registry:acme", "tok-2", nonce, exp)}
	got, err := opOpenCreds(good, m, nonce, false)
	if err != nil || got["forge-read"] != "tok-1" || got["registry:acme"] != "tok-2" {
		t.Fatalf("both open: %v %v", got, err)
	}
	other, _, _ := opEncKeyPairForTest()
	for name, c := range map[string]struct {
		blobs []string
		want  string
	}{
		"sealed for another run":         {[]string{seal("forge-read", "t", "n-other-run-000000", exp), good[1]}, "another run"},
		"a name the op does not declare": {[]string{good[0], seal("root-ssh", "t", nonce, exp)}, "not one this op declares"},
		"expired":                        {[]string{seal("forge-read", "t", nonce, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)), good[1]}, "expired"},
		"one missing":                    {good[:1], "was not handed it"},
		"twice":                          {[]string{good[0], good[0]}, "arrived twice"},
		"too many":                       {append(append([]string{}, good...), good[0]), "more credentials"},
		"sealed to another machine":      {[]string{sealTo(t, other, opSealedCred{Name: "forge-read", Value: "t", Nonce: nonce, Expires: exp}), good[1]}, "does not open"},
		"tampered":                       {[]string{flipB64(good[0]), good[1]}, "does not open"},
	} {
		if _, err := opOpenCreds(c.blobs, m, nonce, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, err)
		}
	}
	if _, err := opOpenCreds(good, m, nonce, true); err == nil || !strings.Contains(err.Error(), "never handed") {
		t.Fatalf("a dry run is handed nothing: %v", err)
	}
}

func opEncKeyPairForTest() (*[32]byte, *[32]byte, error) {
	d := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", d+"-other")
	defer os.Setenv("XDG_CONFIG_HOME", d)
	return opEncKey()
}

func sealTo(t *testing.T, pub *[32]byte, c opSealedCred) string {
	b, err := opSealCredFor(pub, c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func flipB64(s string) string {
	raw, _ := base64.StdEncoding.DecodeString(s)
	raw[len(raw)-1] ^= 1
	return base64.StdEncoding.EncodeToString(raw)
}

// The encryption key is stable, travels signed by the machine's own key, and
// a key file that does not read is never quietly replaced.
func TestEncryptionKeyIsStableSignedAndNeverSilentlyReplaced(t *testing.T) {
	setupBox(t)
	c1, c2 := opEncKeyClaim(), opEncKeyClaim()
	if c1 == nil || c1["public_key"] != c2["public_key"] {
		t.Fatalf("stable: %v %v", c1, c2)
	}
	mk, _ := base64.StdEncoding.DecodeString(c1["machine_key"].(string))
	sig, _ := base64.StdEncoding.DecodeString(c1["signature"].(string))
	if !ed25519.Verify(mk, opEncKeySigningInput(c1["public_key"].(string)), sig) {
		t.Fatal("the claim verifies under the machine's key")
	}
	if ed25519.Verify(mk, []byte(c1["public_key"].(string)), sig) {
		t.Fatal("the signature is over the tagged input only")
	}
	d, _ := configDir()
	_ = os.WriteFile(filepath.Join(d, opEncKeyFile), []byte("{broken"), 0o600)
	if _, _, err := opEncKey(); err == nil {
		t.Fatal("a broken key file is refused, not replaced")
	}
}

func TestReceiptsAreThisMachinesAndBindTheCommit(t *testing.T) {
	setupBox(t)
	digest := "sha256:" + strings.Repeat("c", 64)
	images := []opResultImage{{Image: "forge.example.com/acme/web", Digest: digest,
		Source: "https://forge.example.com/acme/app.git", Commit: strings.Repeat("d", 40)}}
	rs, err := opIssueReceipts("run1", "web-build", strings.Repeat("e", 64), `{"commit":"x"}`, images)
	if err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	r, err := opReceiptFor(digest)
	if err != nil || r == nil || r.Commit != strings.Repeat("d", 40) || r.Op != "web-build" {
		t.Fatalf("held: %+v %v", r, err)
	}
	// A receipt alone is never a record of what is live: only a roll is.
	if _, _, _, ok := opRolledCommit(digest); ok {
		t.Fatal("a receipt made the digest look rolled")
	}
	// The first receipt for a digest stands: the same again is fine, another
	// commit for it is refused and changes nothing.
	if _, err := opIssueReceipts("run2", "web-build", strings.Repeat("e", 64), `{}`, images); err != nil {
		t.Fatalf("the same receipt again: %v", err)
	}
	conflict := []opResultImage{{Image: images[0].Image, Digest: digest, Source: images[0].Source, Commit: strings.Repeat("0", 40)}}
	if _, err := opIssueReceipts("run3", "web-build", strings.Repeat("e", 64), `{}`, conflict); err == nil || !strings.Contains(err.Error(), "already holds a receipt") {
		t.Fatalf("a conflicting receipt: %v", err)
	}
	if r, _ := opReceiptFor(digest); r == nil || r.Commit != strings.Repeat("d", 40) {
		t.Fatal("the first receipt was rewritten")
	}
	if r, _ := opReceiptFor("sha256:" + strings.Repeat("0", 64)); r != nil {
		t.Fatal("no receipt for a digest never built here")
	}
	// A receipt whose bytes changed does not verify.
	var raw map[string]any
	body, _ := base64.StdEncoding.DecodeString(rs[0].Payload)
	_ = json.Unmarshal(body, &raw)
	raw["commit"] = strings.Repeat("f", 40)
	forged, _ := json.Marshal(raw)
	if _, err := opVerifyReceipt(opSignedReceipt{PayloadType: opReceiptPayloadType, Payload: base64.StdEncoding.EncodeToString(forged), Signature: rs[0].Signature}); err == nil {
		t.Fatal("a changed receipt is refused")
	}
	// Nor one relabelled as another type.
	if _, err := opVerifyReceipt(opSignedReceipt{PayloadType: "application/json", Payload: rs[0].Payload, Signature: rs[0].Signature}); err == nil {
		t.Fatal("the payload type is part of what is signed")
	}
	// Nor one another machine signed.
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw["key"] = base64.StdEncoding.EncodeToString(pub)
	other, _ := json.Marshal(raw)
	s := opSignedReceipt{PayloadType: opReceiptPayloadType, Payload: base64.StdEncoding.EncodeToString(other),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, opReceiptSigningInput(other)))}
	if _, err := opVerifyReceipt(s); err == nil || !strings.Contains(err.Error(), "another machine") {
		t.Fatalf("a foreign receipt is refused here: %v", err)
	}
	// What a roll recorded is known too.
	d2 := "sha256:" + strings.Repeat("9", 64)
	_ = opRecordRoll(d2, opRollRec{Image: "forge.example.com/acme/web", Source: "s", Commit: strings.Repeat("8", 40)})
	if _, _, c, ok := opRolledCommit(d2); !ok || c != strings.Repeat("8", 40) {
		t.Fatal("a rolled digest's commit is known")
	}
}

func TestProgramResultIsJudged(t *testing.T) {
	good := `{"images":[{"image":"forge.example.com/acme/web","digest":"sha256:` + strings.Repeat("a", 64) +
		`","source":"https://forge.example.com/acme/app.git","commit":"` + strings.Repeat("b", 40) + `"}]}`
	if im, err := opParseResult([]byte(good)); err != nil || len(im) != 1 {
		t.Fatal(im, err)
	}
	for _, bad := range []string{
		`{"images":[{"image":"forge.example.com/acme/web:latest","digest":"sha256:` + strings.Repeat("a", 64) + `","source":"https://forge.example.com/a/b.git","commit":"` + strings.Repeat("b", 40) + `"}]}`,
		`{"images":[{"image":"forge.example.com/acme/web","digest":"sha256:short","source":"https://forge.example.com/a/b.git","commit":"` + strings.Repeat("b", 40) + `"}]}`,
		`{"images":[{"image":"forge.example.com/acme/web","digest":"sha256:` + strings.Repeat("a", 64) + `","source":"file:///etc","commit":"` + strings.Repeat("b", 40) + `"}]}`,
		`not json`,
	} {
		if _, err := opParseResult([]byte(bad)); err == nil {
			t.Errorf("refused: %s", bad)
		}
	}
}
