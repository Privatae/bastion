package main

// Gate: a fetch job is its pairing's own — random id, and a status call from
// another pairing reads it as unknown — and no job error or refusal quotes a
// signed URL's query.

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestBackupFetchStatusIsPerPairing(t *testing.T) {
	stubPublicDNS(t)
	root := t.TempDir()
	out, errOut, code := drive(t, root, backupFetchReq{Op: "start", URL: "https://storage.example/o?sig=1",
		RPath: fixtureData, SHA256: strings.Repeat("ab", 32), Size: 10})
	if code != 0 {
		t.Fatalf("start refused: %s", errOut)
	}
	var started struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(out), &started)
	if !regexp.MustCompile(`^bf-[0-9a-f]{24}$`).MatchString(started.ID) {
		t.Fatalf("job id %q is short enough to guess", started.ID)
	}
	backupJobsMu.Lock()
	j := backupJobs[started.ID]
	backupJobsMu.Unlock()
	if j == nil {
		t.Fatal("no job")
	}
	mine, _, _ := drive(t, root, backupFetchReq{Op: "status", JobID: started.ID})
	if !strings.Contains(mine, started.ID) || strings.Contains(mine, `"unknown"`) {
		t.Fatalf("the pairing that started it cannot read it: %s", mine)
	}
	theirs, _, _ := drive(t, t.TempDir(), backupFetchReq{Op: "status", JobID: started.ID})
	var st map[string]string
	if json.Unmarshal([]byte(theirs), &st) != nil || st["state"] != "unknown" || strings.Contains(theirs, "rpath") {
		t.Fatalf("another pairing read this job: %s", theirs)
	}
}

func TestBackupFetchErrorsCarryNoSignature(t *testing.T) {
	root := t.TempDir()
	// The dial wall is up: the connection is refused and the client's error
	// quotes the URL.
	job := &backupJob{ID: "s1", SHA256: strings.Repeat("00", 32), State: "running", root: root}
	runBackupFetch(job, "https://127.0.0.1:1/b/x?X-Amz-Signature=SECRETSIG&X-Amz-Credential=CRED", root+"/x", 10)
	if job.State != "failed" {
		t.Fatalf("state %s", job.State)
	}
	if strings.Contains(job.Error, "SECRETSIG") || strings.Contains(job.Error, "CRED") || !strings.Contains(job.Error, "127.0.0.1") {
		t.Fatalf("the job's error: %s", job.Error)
	}
	_, errOut, code := drive(t, root, backupFetchReq{Op: "start", URL: "https://a%zz/x?X-Amz-Signature=SECRETSIG",
		RPath: fixtureData, SHA256: strings.Repeat("ab", 32), Size: 10})
	if code == 0 || strings.Contains(errOut, "SECRETSIG") {
		t.Fatalf("the refusal quotes the signature: %s", errOut)
	}
}
