package main

// Gate: backup_push sends exactly the named backup file, from this pairing's
// backup folder or a folder the person shared with it, to a signed upload
// URL, and nothing else anywhere else. Start answers at once; the digest is
// checked in the job, before anything is sent.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const fixtureData = fixtureStamp + ".tar.zst.age"

func pushFixture(t *testing.T, root string, body []byte) (string, string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, fixtureData), body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return "./" + fixtureData, hex.EncodeToString(sum[:])
}

func uploadServer(t *testing.T, status int) (*httptest.Server, *[]byte, *string) {
	t.Helper()
	var got []byte
	var method string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	old := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	return srv, &got, &method
}

func pushJob(root, sum string) *backupPushJob {
	return &backupPushJob{ID: "p", SHA256: sum, State: "pending", root: root}
}

func TestBackupPushSendsExactlyTheNamedFile(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	body := []byte(strings.Repeat("ciphertext of a backup ", 4000))
	_, sum := pushFixture(t, root, body)
	srv, got, method := uploadServer(t, 200)
	job := pushJob(root, sum)
	runBackupPush(job, srv.URL+"/signed-put", filepath.Join(root, fixtureData))
	if job.State != "done" {
		t.Fatalf("state=%s error=%s", job.State, job.Error)
	}
	if *method != http.MethodPut || string(*got) != string(body) {
		t.Fatalf("the destination received %s of %d bytes, not the file", *method, len(*got))
	}
}

func TestBackupPushFailsWhenTheDestinationRefuses(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	_, sum := pushFixture(t, root, []byte("a backup"))
	srv, _, _ := uploadServer(t, 403)
	job := pushJob(root, sum)
	runBackupPush(job, srv.URL+"/expired", filepath.Join(root, fixtureData))
	if job.State != "failed" || !strings.Contains(job.Error, "403") {
		t.Fatalf("a refused upload reads %s %q", job.State, job.Error)
	}
}

// The digest is checked in the job before anything is sent.
func TestBackupPushSendsNothingWhenTheFileIsNotTheOneNamed(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	_, sum := pushFixture(t, root, []byte("the backup that was named"))
	_ = os.WriteFile(filepath.Join(root, fixtureData), []byte("the backup that is there"), 0o600)
	srv, got, method := uploadServer(t, 200)
	job := pushJob(root, sum)
	runBackupPush(job, srv.URL+"/put", filepath.Join(root, fixtureData))
	if job.State != "failed" || !strings.Contains(job.Error, "sha256 differs") {
		t.Fatalf("a file that is not the named one: %s %q", job.State, job.Error)
	}
	if *method != "" || len(*got) != 0 {
		t.Fatal("bytes were sent before the digest was checked")
	}
}

// Bytes changed while they are being sent are caught by the hash taken as
// they go: the job fails rather than reporting the named backup sent.
func TestBackupPushFailsWhenTheFileChangesWhileSending(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	body := make([]byte, 32<<20)
	_, sum := pushFixture(t, root, body)
	path := filepath.Join(root, fixtureData)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64<<10)
		_, _ = io.ReadFull(r.Body, buf)
		// The tail of the file changes in place while the upload is under way.
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			_, _ = f.WriteAt([]byte(strings.Repeat("X", 4096)), int64(len(body)-4096))
			_ = f.Close()
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	old := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	job := pushJob(root, sum)
	runBackupPush(job, srv.URL+"/put", path)
	if job.State != "failed" || !strings.Contains(job.Error, "changed while it was being sent") {
		t.Fatalf("a file changed mid-send reads %s %q", job.State, job.Error)
	}
}

func TestBackupPushNeverFollowsARedirect(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	_, sum := pushFixture(t, root, []byte("a backup"))
	var second bool
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second = true
	}))
	t.Cleanup(elsewhere.Close)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 303 is the redirect an HTTP client follows even for an upload
		// (as a GET); a client that follows redirects at all would go.
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusSeeOther)
	}))
	t.Cleanup(srv.Close)
	old := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	job := pushJob(root, sum)
	runBackupPush(job, srv.URL+"/put", filepath.Join(root, fixtureData))
	if second {
		t.Fatal("the backup followed a redirect to a place the host did not name")
	}
	if job.State != "failed" {
		t.Fatalf("a redirect was reported as sent: %s", job.State)
	}
}

// A job's error never quotes the signed URL's query.
func TestBackupPushErrorsCarryNoSignature(t *testing.T) {
	root := t.TempDir()
	_, sum := pushFixture(t, root, []byte("a backup"))
	// The dial wall is left up: 127.0.0.1 is refused at connect, and the
	// client's error quotes the URL.
	job := pushJob(root, sum)
	runBackupPush(job, "https://127.0.0.1:1/b/x?X-Amz-Signature=SECRETSIG&X-Amz-Credential=CRED", filepath.Join(root, fixtureData))
	if job.State != "failed" {
		t.Fatalf("state %s", job.State)
	}
	if strings.Contains(job.Error, "SECRETSIG") || strings.Contains(job.Error, "CRED") {
		t.Fatalf("the job's error quotes the signature: %s", job.Error)
	}
}

// stubPublicDNS answers every name with a public address, so start's URL
// check passes without the network; nothing is dialled in these tests.
func stubPublicDNS(t *testing.T) {
	t.Helper()
	prev := backupLookupIP
	backupLookupIP = func(name string) ([]net.IP, error) {
		if ip := net.ParseIP(name); ip != nil {
			return []net.IP{ip}, nil
		}
		return []net.IP{net.ParseIP("203.0.113.9")}, nil
	}
	t.Cleanup(func() { backupLookupIP = prev })
}

func awaitPush(t *testing.T, root, id string) map[string]string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, _, _ := driveBackupOp(t, "backup_push", "", root, backupPushReq{Op: "status", JobID: id})
		var st map[string]string
		_ = json.Unmarshal([]byte(out), &st)
		if st["state"] != "pending" {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("push never left pending")
	return nil
}

// Start answers at once without reading the file: a wrong digest is not a
// refusal at start but the job's failure, and the job is this pairing's own.
func TestBackupPushStartAnswersAtOnceAndStatusIsPerPairing(t *testing.T) {
	stubPublicDNS(t)
	root := t.TempDir()
	rel, _ := pushFixture(t, root, []byte("a backup"))
	out, errOut, code := driveBackupOp(t, "backup_push", "", root,
		backupPushReq{Op: "start", Path: rel, URL: "https://storage.example/put?sig=1", SHA256: strings.Repeat("ab", 32), Headers: signedPut})
	if code != 0 {
		t.Fatalf("start refused: %s", errOut)
	}
	var started map[string]string
	if json.Unmarshal([]byte(out), &started) != nil || started["state"] != "pending" || !strings.HasPrefix(started["job_id"], "bp-") {
		t.Fatalf("start reply: %s", out)
	}
	if !regexp.MustCompile(`^bp-[0-9a-f]{24}$`).MatchString(started["job_id"]) {
		t.Fatalf("job id %q is short enough to guess", started["job_id"])
	}
	st := awaitPush(t, root, started["job_id"])
	if st["state"] != "failed" || !strings.Contains(st["error"], "sha256 differs") || st["job_id"] != started["job_id"] {
		t.Fatalf("the job: %v", st)
	}
	other, _, _ := driveBackupOp(t, "backup_push", "", t.TempDir(), backupPushReq{Op: "status", JobID: started["job_id"]})
	var o map[string]string
	if json.Unmarshal([]byte(other), &o) != nil || o["state"] != "unknown" || o["error"] != "" {
		t.Fatalf("another pairing read this job: %s", other)
	}
}

// Through the real frame path: each refusal happens at start, before any job.
func TestBackupPushStartRefuses(t *testing.T) {
	stubPublicDNS(t)
	root := t.TempDir()
	rel, sum := pushFixture(t, root, []byte("a backup"))
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "20260101T000000Z.tar.zst.age")
	_ = os.WriteFile(outside, []byte("not this host's"), 0o600)
	_ = os.Symlink(outside, filepath.Join(root, "20260101T000000Z.tar.zst.age"))
	_ = os.Symlink(filepath.Join(root, fixtureData), filepath.Join(root, "20260102T000000Z.tar.zst.age"))
	_ = os.WriteFile(filepath.Join(root, "notes.txt"), []byte("mine"), 0o600)
	_ = os.MkdirAll(filepath.Join(root, "sub"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "sub", fixtureData), []byte("a backup"), 0o600)
	_ = os.Symlink(outsideDir, filepath.Join(root, "linkdir"))
	type want struct {
		req backupPushReq
		why string
	}
	u := "https://storage.example/x"
	cases := map[string]want{
		"parent escape":         {backupPushReq{Op: "start", Path: "../x/" + fixtureData, URL: u, SHA256: sum, Headers: signedPut}, "path rejected"},
		"absolute path":         {backupPushReq{Op: "start", Path: outside, URL: u, SHA256: sum, Headers: signedPut}, "path rejected"},
		"not a backup name":     {backupPushReq{Op: "start", Path: "notes.txt", URL: u, SHA256: sum, Headers: signedPut}, "path rejected"},
		"a subfolder":           {backupPushReq{Op: "start", Path: "sub/" + fixtureData, URL: u, SHA256: sum, Headers: signedPut}, "path rejected"},
		"through a linked dir":  {backupPushReq{Op: "start", Path: "linkdir/20260101T000000Z.tar.zst.age", URL: u, SHA256: sum, Headers: signedPut}, "path rejected"},
		"link out of the root":  {backupPushReq{Op: "start", Path: "20260101T000000Z.tar.zst.age", URL: u, SHA256: sum, Headers: signedPut}, "path rejected"},
		"link inside the root":  {backupPushReq{Op: "start", Path: "20260102T000000Z.tar.zst.age", URL: u, SHA256: sum, Headers: signedPut}, "no backup file"},
		"missing file":          {backupPushReq{Op: "start", Path: "20260103T000000Z.tar.zst.age", URL: u, SHA256: sum, Headers: signedPut}, "no backup file"},
		"a folder not shared":   {backupPushReq{Op: "start", Path: "shared/other/" + fixtureData, URL: u, SHA256: sum, Headers: signedPut}, "path rejected"},
		"dot segments":          {backupPushReq{Op: "start", Path: "./x/../" + fixtureData, URL: u, SHA256: sum, Headers: signedPut}, "path rejected"},
		"bad digest":            {backupPushReq{Op: "start", Path: rel, URL: u, SHA256: "abc", Headers: signedPut}, "64 hex"},
		"plain http":            {backupPushReq{Op: "start", Path: rel, URL: "http://storage.example/x", SHA256: sum, Headers: signedPut}, "must be https"},
		"this machine":          {backupPushReq{Op: "start", Path: rel, URL: "https://127.0.0.1/x", SHA256: sum, Headers: signedPut}, "on this machine"},
		"private network":       {backupPushReq{Op: "start", Path: rel, URL: "https://10.1.2.3/x", SHA256: sum, Headers: signedPut}, "on this machine"},
		"unparseable signature": {backupPushReq{Op: "start", Path: rel, URL: "https://a%zz/x?X-Amz-Signature=SECRETSIG", SHA256: sum, Headers: signedPut}, "backup_push:"},
	}
	for name, c := range cases {
		out, errOut, code := driveBackupOp(t, "backup_push", "", root, c.req)
		if code == 0 {
			t.Errorf("%s: started (%s)", name, out)
		} else if !strings.Contains(errOut, "backup_push:") || !strings.Contains(errOut, c.why) {
			t.Errorf("%s: refused for the wrong reason: %s", name, errOut)
		}
		if strings.Contains(errOut, "SECRETSIG") {
			t.Errorf("%s: the refusal quotes the signature: %s", name, errOut)
		}
	}
}

// A folder the person shared with this pairing can be sent from; the same
// path from a pairing it was not shared with is refused.
func TestBackupPushFromASharedFolder(t *testing.T) {
	allowLoopbackFetch(t)
	const newHost = "new.host.privatae.ai"
	lost := t.TempDir()
	body := []byte("the lost host's backup")
	_, sum := pushFixture(t, lost, body)
	root := t.TempDir()
	s, err := addBackupShare(newHost, root, lost, "old-host.example")
	if err != nil {
		t.Fatal(err)
	}
	p := "shared/" + s.Slug + "/" + fixtureData
	abs, why := backupResolveFile(newHost, root, p)
	if why != "" || abs != filepath.Join(lost, fixtureData) {
		t.Fatalf("the shared file does not resolve: %q %q", abs, why)
	}
	other := t.TempDir()
	if _, err := addBackupShare(newHost, root, other, "another"); err != nil {
		t.Fatal(err)
	}
	if _, why := backupResolveFile(newHost, root, "shared/another/"+fixtureData); why == "" {
		t.Fatal("a file named under one shared folder resolved from another")
	}
	if _, why := backupResolveFile(newHost, root, "shared/nope/"+fixtureData); why == "" {
		t.Fatal("a folder that is not shared resolved")
	}
	for _, who := range []string{"other.host.privatae.ai", ""} {
		if _, why := backupResolveFile(who, root, p); why == "" {
			t.Fatalf("pairing %q, which the folder was not shared with, resolved it", who)
		}
	}
	srv, got, _ := uploadServer(t, 200)
	job := pushJob(root, sum)
	runBackupPush(job, srv.URL+"/put", abs)
	if job.State != "done" || string(*got) != string(body) {
		t.Fatalf("%s %s", job.State, job.Error)
	}
	if err := dropBackupShare(newHost, s.Slug); err != nil {
		t.Fatal(err)
	}
	if _, why := backupResolveFile(newHost, root, p); why == "" {
		t.Fatal("a folder taken back still resolves")
	}
}

// signedPut is what the platform's backup.put_url hands over with every
// upload address, and so what every start in these tests carries.
var signedPut = map[string]string{"If-None-Match": "*"}
