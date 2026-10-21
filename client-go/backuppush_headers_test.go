package main

// Gate: the headers an upload URL was signed with go on the PUT. The
// platform's backup.put_url signs If-None-Match: * into every single-PUT URL
// and returns it under
// `headers`; the storage answers 403 to a PUT without it and 412 to a second
// PUT to the same key. The test server below answers the same way.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// s3LikeServer answers a PUT as a presigned S3 PUT signed with
// If-None-Match: * does: 403 without the header, 412 when the key is there,
// else 200 and the key is written.
func s3LikeServer(t *testing.T) (*httptest.Server, map[string][]byte) {
	t.Helper()
	var mu sync.Mutex
	stored := map[string][]byte{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPut || r.Header.Get("If-None-Match") != "*" {
			w.WriteHeader(http.StatusForbidden) // SignatureDoesNotMatch
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if _, ok := stored[r.URL.Path]; ok {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		stored[r.URL.Path] = body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	old := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	return srv, stored
}

// The platform's reply, as backup.put_url returns it.
const putURLReply = `{"url": "https://x/put", "key": "k", "expires_at": "t", "size": 8, "headers": {"If-None-Match": "*"}}`

func TestBackupPushSendsTheSignedHeaders(t *testing.T) {
	allowLoopbackFetch(t)
	root := t.TempDir()
	body := []byte("a backup")
	_, sum := pushFixture(t, root, body)
	srv, stored := s3LikeServer(t)
	var reply struct {
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal([]byte(putURLReply), &reply); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(root, fixtureData)

	// Without the headers the storage refuses the PUT: the old behaviour.
	bare := pushJob(root, sum)
	runBackupPush(bare, srv.URL+"/b", abs)
	if bare.State != "failed" || !strings.Contains(bare.Error, "403") {
		t.Fatalf("a PUT without the signed header: %s %s", bare.State, bare.Error)
	}

	h, err := backupPushHeaders(reply.Headers)
	if err != nil {
		t.Fatal(err)
	}
	job := pushJob(root, sum)
	job.headers = h
	runBackupPush(job, srv.URL+"/s/obj", abs)
	if job.State != "done" || string(stored["/s/obj"]) != string(body) {
		t.Fatalf("with the signed header: %s %s", job.State, job.Error)
	}
	// A second PUT to the same key is refused by the storage, and the job says so.
	again := pushJob(root, sum)
	again.headers = h
	runBackupPush(again, srv.URL+"/s/obj", abs)
	if again.State != "failed" || !strings.Contains(again.Error, "412") || !strings.Contains(again.Error, "nothing was replaced") {
		t.Fatalf("a second PUT: %s %s", again.State, again.Error)
	}
}

// Through the management lane: start keeps the one header the platform signs
// (If-None-Match: *) for the job, and refuses every other header name, and
// any other value for that one, before a job starts.
func TestBackupPushStartTakesTheHeaders(t *testing.T) {
	stubPublicDNS(t)
	root := t.TempDir()
	rel, sum := pushFixture(t, root, []byte("a backup"))
	start := func(h map[string]string) (string, string, int) {
		return driveBackupOp(t, "backup_push", "", root,
			backupPushReq{Op: "start", Path: rel, URL: "https://storage.example/put?sig=1", SHA256: sum, Headers: h})
	}
	jobHeaders := func(out string) http.Header {
		var started map[string]string
		_ = json.Unmarshal([]byte(out), &started)
		backupJobsMu.Lock()
		defer backupJobsMu.Unlock()
		if j := backupPushJobs[started["job_id"]]; j != nil {
			return j.headers.Clone()
		}
		return nil
	}
	for name, h := range map[string]map[string]string{
		"as put_url returns it":  {"If-None-Match": "*"},
		"the name in lower case": {"if-none-match": "*"},
	} {
		out, errOut, code := start(h)
		if code != 0 {
			t.Fatalf("%s: start refused the signed header: %s", name, errOut)
		}
		if got := jobHeaders(out); len(got) != 1 || got.Get("If-None-Match") != "*" {
			t.Fatalf("%s: the job carries %v", name, got)
		}
	}
	// No headers at all is refused too: the platform always signs
	// If-None-Match: * into the URL and hands it over, so a start without it
	// comes from a broken or tampered host. The refusal says so in a sentence.
	for name, h := range map[string]map[string]string{
		"no headers":          nil,
		"an empty header set": {},
	} {
		out, errOut, code := start(h)
		if code == 0 {
			t.Errorf("%s: accepted (%s)", name, out)
			continue
		}
		if !strings.Contains(errOut, "backup_push: no headers came with the upload address") {
			t.Errorf("%s: refused without saying why: %s", name, errOut)
		}
	}
	for name, h := range map[string]map[string]string{
		"an unexpected header":         {"X-Amz-Meta-Note": "hello"},
		"an unexpected header as well": {"If-None-Match": "*", "Authorization": "Bearer x"},
		"another If-None-Match value":  {"If-None-Match": `"etag"`},
		"a padded value":               {"If-None-Match": " *"},
		"an empty value":               {"If-None-Match": ""},
		"If-Match":                     {"If-Match": "*"},
		"Host":                         {"host": "elsewhere.example"},
		"Content-Length":               {"Content-Length": "1"},
		"Transfer-Encoding":            {"Transfer-Encoding": "chunked"},
		"Connection":                   {"Connection": "close"},
		"a split line":                 {"If-None-Match": "*\r\nX-Evil: 1"},
		"a bad name":                   {"If None Match": "*"},
		"an empty name":                {"": "*"},
		"a long name":                  {strings.Repeat("X", 4096): "*"},
	} {
		_, errOut, code := start(h)
		if code == 0 || !strings.Contains(errOut, "backup_push:") {
			t.Errorf("%s: accepted (%s)", name, errOut)
		}
		if len(errOut) > 400 {
			t.Errorf("%s: the refusal quotes %d bytes", name, len(errOut))
		}
	}
}
