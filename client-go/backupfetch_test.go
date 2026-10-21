package main

// Gate: backup_fetch delivers the right bytes to the right place, and refuses
// everything else. Each case is one way a backup could silently be wrong or one
// way the host could point this machine somewhere it has no business going.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// drive runs one backup_fetch job through the real mgmt frame path and returns
// (stdout, stderr, exit) the way the host's management worker collects them.
func drive(t *testing.T, backupRoot string, req backupFetchReq) (string, string, int) {
	t.Helper()
	arg, _ := json.Marshal(req)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConn(ws, "", "", backupRoot)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	job, _ := json.Marshal(mgmtJob{Op: "backup_fetch", Args: []string{string(arg)}})
	if err := c.WriteMessage(websocket.BinaryMessage, append([]byte("C"), job...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errOut string
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch data[0] {
		case 'O':
			out += string(data[1:])
		case 'R':
			errOut += string(data[1:])
		case 'X':
			var code int
			fmt.Sscanf(string(data[1:]), "%d", &code)
			return out, errOut, code
		}
	}
}

func awaitJob(t *testing.T, backupRoot, id string) backupJob {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, _, code := drive(t, backupRoot, backupFetchReq{Op: "status", JobID: id})
		if code != 0 {
			t.Fatalf("status exited %d", code)
		}
		var j backupJob
		if err := json.Unmarshal([]byte(out), &j); err != nil {
			t.Fatalf("status is not JSON: %v (%s)", err, out)
		}
		if j.State != "running" {
			return j
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("job never left running")
	return backupJob{}
}

func startAndAwait(t *testing.T, root string, req backupFetchReq) backupJob {
	t.Helper()
	out, errOut, code := drive(t, root, req)
	if code != 0 {
		t.Fatalf("start exited %d: %s", code, errOut)
	}
	var started struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(out), &started); err != nil {
		t.Fatalf("start reply is not JSON: %v (%s)", err, out)
	}
	if started.State == "done" { // already-present short circuit
		var j backupJob
		_ = json.Unmarshal([]byte(out), &j)
		return j
	}
	return awaitJob(t, root, started.ID)
}

func artifactServer(t *testing.T, body []byte) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(body)
	return srv, hex.EncodeToString(sum[:])
}

// The SSRF wall refuses httptest's 127.0.0.1 URLs, which is exactly right and
// also makes a happy-path test impossible against a local server. So the happy
// path drives runBackupFetch directly (the same function the goroutine runs),
// and the wall gets its own tests through the full frame path.
func TestBackupFetchWritesVerifiedArtifact(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	body := []byte(strings.Repeat("the user's backup, 2026-08-18. ", 5000))
	srv, want := artifactServer(t, body)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = nil // keep other tests clean

	dest := filepath.Join(root, "privatae", "tenant-42", "backup.tar.zst.age")
	job := &backupJob{ID: "t1", SHA256: want, Want: int64(len(body)), State: "running"}
	// srv.Client() trusts the test cert; runBackupFetch builds its own client, so
	// point it at the server through the same transport by installing the cert.
	oldTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()

	runBackupFetch(job, srv.URL+"/artifact", dest, int64(len(body))+1)
	if job.State != "done" {
		t.Fatalf("state=%s error=%s", job.State, job.Error)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("destination not written: %v", err)
	}
	if string(got) != string(body) {
		t.Fatal("delivered bytes differ from the source")
	}
	if job.Got != int64(len(body)) {
		t.Fatalf("progress says %d bytes, file has %d", job.Got, len(body))
	}
	fi, _ := os.Stat(dest)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("artifact mode is %v, want 0600 — a backup is not world-readable", fi.Mode().Perm())
	}
	// No .part left behind.
	entries, _ := os.ReadDir(filepath.Dir(dest))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".part") {
			t.Fatalf("temp file survived: %s", e.Name())
		}
	}
}

func TestBackupFetchRefusesWrongDigest(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	body := []byte("a backup that got tampered with")
	srv, _ := artifactServer(t, body)
	oldTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()

	dest := filepath.Join(root, "x.bin")
	wrong := strings.Repeat("00", 32)
	job := &backupJob{ID: "t2", SHA256: wrong, Want: int64(len(body)), State: "running"}
	runBackupFetch(job, srv.URL+"/a", dest, 1<<20)
	if job.State != "failed" {
		t.Fatalf("a wrong digest must fail, got %s", job.State)
	}
	if !strings.Contains(job.Error, "sha256 mismatch") {
		t.Fatalf("error should name the mismatch, got %q", job.Error)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("a failed fetch must leave NOTHING at the destination path")
	}
}

func TestBackupFetchRefusesOversizeBody(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	body := []byte(strings.Repeat("x", 4096))
	srv, want := artifactServer(t, body)
	oldTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()

	dest := filepath.Join(root, "big.bin")
	job := &backupJob{ID: "t3", SHA256: want, Want: 100, State: "running"}
	runBackupFetch(job, srv.URL+"/a", dest, 100) // declared 100, serves 4096
	if job.State != "failed" || !strings.Contains(job.Error, "larger than the declared") {
		t.Fatalf("oversize body must stop the stream, got state=%s err=%q", job.State, job.Error)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("nothing should be published")
	}
}

func TestBackupFetchRefusesHTTPError(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "expired", http.StatusForbidden)
	}))
	defer srv.Close()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()

	job := &backupJob{ID: "t4", SHA256: strings.Repeat("ab", 32), State: "running"}
	runBackupFetch(job, srv.URL+"/a", filepath.Join(root, "e.bin"), 1<<20)
	if job.State != "failed" || !strings.Contains(job.Error, "HTTP 403") {
		t.Fatalf("an expired signed URL must surface its status, got %q", job.Error)
	}
}

// ── the SSRF wall, through the full frame path ───────────────────────────────

func TestBackupFetchRefusesPrivateAndLocalTargets(t *testing.T) {
	root := t.TempDir()
	cases := []struct{ url, why string }{
		{"http://example.com/a", "plain http"},
		{"https://127.0.0.1/a", "loopback"},
		{"https://localhost/a", "loopback by name"},
		{"https://192.168.1.1/a", "the user's router"},
		{"https://10.0.0.5/a", "private range"},
		{"https://172.16.4.4/a", "private range"},
		{"https://100.64.1.1/a", "carrier-grade NAT / tailnet"},
		{"https://169.254.169.254/a", "cloud metadata"},
		{"https://[fd00:1::10]/a", "a private ULA mesh"},
		{"https://[::1]/a", "IPv6 loopback"},
	}
	for _, c := range cases {
		_, errOut, code := drive(t, root, backupFetchReq{
			Op: "start", URL: c.url, RPath: "a.bin",
			SHA256: strings.Repeat("ab", 32), Size: 10,
		})
		if code == 0 {
			t.Errorf("%s (%s) was ACCEPTED — the wall is open", c.url, c.why)
			continue
		}
		if !strings.Contains(errOut, "backup_fetch:") {
			t.Errorf("%s: refusal should say why, got %q", c.url, errOut)
		}
	}
}

func TestBackupFetchRefusesBadArguments(t *testing.T) {
	root := t.TempDir()
	good := backupFetchReq{Op: "start", URL: "https://s3.example.com/a",
		RPath: "a.bin", SHA256: strings.Repeat("ab", 32), Size: 10}

	bad := map[string]backupFetchReq{}
	b := good
	b.RPath = "../../etc/cron.d/pwn"
	bad["path traversal"] = b
	b = good
	b.RPath = "/etc/passwd"
	bad["absolute path"] = b
	b = good
	b.SHA256 = "abc"
	bad["short digest"] = b
	b = good
	b.SHA256 = strings.Repeat("zz", 32)
	bad["non-hex digest"] = b
	b = good
	b.Size, b.MaxBytes = 0, 0
	bad["no size"] = b
	b = good
	b.Size, b.MaxBytes = 0, backupFetchMaxBytes+1
	bad["absurd size"] = b

	for name, req := range bad {
		_, errOut, code := drive(t, root, req)
		if code == 0 {
			t.Errorf("%s was ACCEPTED", name)
		}
		if !strings.Contains(errOut, "backup_fetch:") {
			t.Errorf("%s: refusal should name the op, got %q", name, errOut)
		}
	}
}

func TestBackupFetchRefusedWithoutADestination(t *testing.T) {
	// No backup root configured = the op does not exist here, reported the same
	// way an un-allowlisted op is (126), not as a crash.
	_, errOut, code := drive(t, "", backupFetchReq{Op: "start", URL: "https://s3.example.com/a",
		RPath: "a.bin", SHA256: strings.Repeat("ab", 32), Size: 10})
	if code != 126 {
		t.Fatalf("want exit 126 with no destination configured, got %d", code)
	}
	if !strings.Contains(errOut, "backup destination not configured") {
		t.Fatalf("refusal should say what is missing, got %q", errOut)
	}
}

func TestBackupFetchIsIdempotent(t *testing.T) {
	root := t.TempDir()
	body := []byte("already here")
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(root, "a.bin"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	// URL is deliberately unreachable: if the short circuit does not fire, this
	// fails, which is the point — a retry must not re-download gigabytes.
	out, errOut, code := drive(t, root, backupFetchReq{
		Op: "start", URL: "https://s3.example.invalid/a", RPath: "a.bin",
		SHA256: want, Size: int64(len(body)),
	})
	if code != 0 {
		t.Fatalf("an already-correct artifact must report done, got %d: %s", code, errOut)
	}
	var j backupJob
	if err := json.Unmarshal([]byte(out), &j); err != nil || j.State != "done" {
		t.Fatalf("want state=done, got %s (%v)", out, err)
	}
}

func TestBackupFetchStatusOfUnknownJob(t *testing.T) {
	// After a bastion restart the in-memory job is gone. "unknown" lets the host
	// re-start (which is idempotent); "failed" would make it give up.
	out, _, code := drive(t, t.TempDir(), backupFetchReq{Op: "status", JobID: "bf-nope"})
	if code != 0 || !strings.Contains(out, `"state":"unknown"`) {
		t.Fatalf("want a clean unknown, got %d %s", code, out)
	}
}

func TestIsPublicIPClassification(t *testing.T) {
	// The table the wall rests on. Named separately so a regression here points
	// at the classifier rather than at ten URL cases.
	private := []string{"127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.0.1",
		"169.254.1.1", "100.64.0.1", "100.127.255.255", "::1", "fd00:1::10", "fe80::1", "0.0.0.0"}
	public := []string{"1.1.1.1", "8.8.8.8", "51.68.1.1", "100.63.255.255",
		"100.128.0.1", "2606:4700::1111"}
	for _, s := range private {
		if isPublicIP(mustIP(t, s)) {
			t.Errorf("%s classified PUBLIC — the wall would let it through", s)
		}
	}
	for _, s := range public {
		if !isPublicIP(mustIP(t, s)) {
			t.Errorf("%s classified private — a real backup source would be refused", s)
		}
	}
}

// The backup lanes judge an address the way a coder run's proxy does: the IPv4
// address inside a NAT64, 6to4, IPv4-compatible or IPv4-translated address,
// and the site-local, benchmarking and reserved ranges. The classifier took
// every address in `refused` as public before; each is now refused at the
// classifier, the address wall and the URL check. Public addresses in the
// same forms, and the addresses either side of 198.18.0.0/15, still pass.
//
// MUTATION: restore isPublicIP's own list (no unwrapping, no fec0::/10,
// 198.18.0.0/15 or 240.0.0.0/4).
// RESULT: red — every address in `refused` is classified public.
func TestBackupWallJudgesTheIPv4InsideAndTheReservedRanges(t *testing.T) {
	refused := []string{
		"64:ff9b::a00:1",               // NAT64 of 10.0.0.1
		"64:ff9b::7f00:1",              // NAT64 of 127.0.0.1
		"64:ff9b:1::a00:1",             // local-use NAT64 (RFC 8215): not readable here
		"2002:a00:1::1",                // 6to4 of 10.0.0.1
		"2002:a9fe:a9fe::",             // 6to4 of 169.254.169.254
		"::a00:1",                      // IPv4-compatible 10.0.0.1
		"::ffff:0:a00:1",               // IPv4-translated 10.0.0.1
		"fec0::1",                      // site-local
		"198.18.0.1", "198.19.255.255", // benchmarking
		"240.0.0.1", "255.255.255.255", // reserved, limited broadcast
		"::ffff:198.18.0.1", "64:ff9b::f000:1", // the same, inside IPv6
	}
	for _, s := range refused {
		ip := mustIP(t, s)
		if isPublicIP(ip) {
			t.Errorf("%s classified PUBLIC — the wall would let it through", s)
		}
		if backupAddrAllowed(ip) {
			t.Errorf("%s passes the backup lanes' address wall", s)
		}
		if err := validateBackupURL("https://" + net.JoinHostPort(s, "443") + "/b.tar"); err == nil {
			t.Errorf("%s passes the backup lanes' URL check", s)
		}
	}
	for _, s := range []string{"64:ff9b::808:808", "2002:808:808::1", "::ffff:8.8.8.8", "198.17.255.255", "198.20.0.1"} {
		if !isPublicIP(mustIP(t, s)) {
			t.Errorf("%s classified private — a real backup source would be refused", s)
		}
	}
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}

// allowLoopbackFetch lets the dial-time wall (backupDialAllowed) accept the
// loopback test server for one test; validateBackupURL is not touched.
func allowLoopbackFetch(t *testing.T) {
	t.Helper()
	prev := backupDialAllowed
	backupDialAllowed = func(net.IP) bool { return true }
	t.Cleanup(func() { backupDialAllowed = prev })
}
