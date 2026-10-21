package main

// Gate: the pairing's request file is written by two processes (the daemon
// files, the person's `backup approve`/`deny` decides), and neither loses
// the other's write; an unreadable file is set aside, never wiped; and an
// answer frees the room its request took.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func junkSidecar(tag string, i int) string {
	return "-----BEGIN AGE ENCRYPTED FILE-----\n" + tag + "-" + strconv.Itoa(i) + "\n-----END AGE ENCRYPTED FILE-----\n"
}

// TestResealHelperProcess is not a test on its own: the concurrency test
// below runs this binary again with these variables set, so each writer is a
// separate process, as the daemon and the CLI are.
func TestResealHelperProcess(t *testing.T) {
	dir := os.Getenv("PRIVATAE_RESEAL_HELPER_DIR")
	if dir == "" {
		t.Skip("run by TestResealFileKeepsEveryWriteAcrossProcesses")
	}
	tag := os.Getenv("PRIVATAE_RESEAL_HELPER_TAG")
	rounds, _ := strconv.Atoi(os.Getenv("PRIVATAE_RESEAL_HELPER_ROUNDS"))
	to := mustRecipient(t)
	for i := 0; i < rounds; i++ {
		r, err := resealFile(dir, fixtureWho, resealReq{Sidecar: junkSidecar(tag, i), To: to, Stamp: fixtureStamp})
		if err != nil {
			t.Fatalf("%s: file %d: %v", tag, i, err)
		}
		if _, err := resealRefuse(dir, fixtureWho, r.ID, tag); err != nil {
			t.Fatalf("%s: deny %d: %v", tag, i, err)
		}
	}
}

// Several processes each file a request and deny it, over and over, on one
// pairing's file. Every request filed is there at the end, and every one is
// refused: none was dropped by a stale save, and no answer was reverted to
// pending.
func TestResealFileKeepsEveryWriteAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	const procs, rounds = 4, 15 // 60 answered requests: under resealMaxAnswered, so none is dropped
	if procs*rounds > resealMaxAnswered {
		t.Fatal("the test would lose answered requests to the bound, not to a race")
	}
	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make([]error, procs)
	outs := make([][]byte, procs)
	for p := 0; p < procs; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestResealHelperProcess$", "-test.count=1")
			cmd.Env = append(os.Environ(), "PRIVATAE_RESEAL_HELPER_DIR="+dir,
				fmt.Sprintf("PRIVATAE_RESEAL_HELPER_TAG=p%d", p), fmt.Sprintf("PRIVATAE_RESEAL_HELPER_ROUNDS=%d", rounds))
			outs[p], errs[p] = cmd.CombinedOutput()
		}(p)
	}
	wg.Wait()
	for p := range errs {
		if errs[p] != nil {
			t.Fatalf("writer %d: %v\n%s", p, errs[p], outs[p])
		}
	}
	m, err := resealRead(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != procs*rounds {
		t.Fatalf("%d of %d requests are on file: writes were lost", len(m), procs*rounds)
	}
	for _, r := range m {
		if r.State != "refused" || !strings.HasPrefix(r.Error, "p") {
			t.Fatalf("an answer was lost: %+v", r)
		}
	}
}

// A request file that does not parse is set aside whole, the error says
// where, and the next request starts a new file.
func TestResealUnreadableFileIsSetAsideNotWiped(t *testing.T) {
	dir := t.TempDir()
	junk := []byte(`{"br-1": {"id": "br-1", "state": "pending"` + "\x00 torn")
	if err := os.WriteFile(resealPath(dir), junk, 0o600); err != nil {
		t.Fatal(err)
	}
	to := mustRecipient(t)
	_, err := resealFile(dir, fixtureWho, resealReq{Sidecar: junkSidecar("a", 0), To: to, Stamp: fixtureStamp})
	if err == nil || !strings.Contains(err.Error(), "kept as") {
		t.Fatalf("an unreadable request file was not reported: %v", err)
	}
	aside, _ := filepath.Glob(resealPath(dir) + resealAsideSuffix + "*")
	if len(aside) != 1 {
		t.Fatalf("the unreadable file was not set aside: %v", aside)
	}
	if got, _ := os.ReadFile(aside[0]); string(got) != string(junk) {
		t.Fatal("the file set aside is not the file that was there")
	}
	if !strings.Contains(err.Error(), aside[0]) {
		t.Errorf("the error does not say where the file is: %v", err)
	}
	r, err := resealFile(dir, fixtureWho, resealReq{Sidecar: junkSidecar("a", 0), To: to, Stamp: fixtureStamp})
	if err != nil || r.State != "pending" {
		t.Fatalf("a new file was not started: %v", err)
	}
	// "null" is an empty record, not a crash.
	_ = os.WriteFile(resealPath(dir), []byte("null"), 0o600)
	if _, err := resealFile(dir, fixtureWho, resealReq{Sidecar: junkSidecar("a", 1), To: to, Stamp: fixtureStamp}); err != nil {
		t.Fatalf("a null record: %v", err)
	}
}

// The bound is on requests waiting for an answer: answering one, either
// way, frees its room at once, and an answered request no longer holds the
// sidecar it came with.
func TestResealAnswerFreesRoom(t *testing.T) {
	dir := t.TempDir()
	to := mustRecipient(t)
	var ids []string
	for i := 0; i < resealMaxRequests; i++ {
		r, err := resealFile(dir, fixtureWho, resealReq{Sidecar: junkSidecar("q", i), To: to, Stamp: fixtureStamp})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		ids = append(ids, r.ID)
	}
	next := resealReq{Sidecar: junkSidecar("q", 100), To: to, Stamp: fixtureStamp}
	if _, err := resealFile(dir, fixtureWho, next); err == nil {
		t.Fatal("a request past the bound was filed")
	}
	if _, err := resealRefuse(dir, fixtureWho, ids[0], ""); err != nil {
		t.Fatal(err)
	}
	if _, err := resealFile(dir, fixtureWho, next); err != nil {
		t.Fatalf("a deny did not free room: %v", err)
	}
	// An approval frees room too, whatever its outcome (this sidecar does not
	// open, so it fails).
	withBackupKeysDir(t)
	newBackupFixture(t, "").installAsBastionKey(t)
	if _, err := resealDecide(dir, fixtureWho, ids[1], true); err != nil {
		t.Fatal(err)
	}
	if _, err := resealFile(dir, fixtureWho, resealReq{Sidecar: junkSidecar("q", 101), To: to, Stamp: fixtureStamp}); err != nil {
		t.Fatalf("an approval did not free room: %v", err)
	}
	m, _ := resealRead(dir)
	for _, id := range ids[:2] {
		if m[id].State == "pending" || m[id].Sidecar != "" {
			t.Fatalf("an answered request still holds its sidecar: %+v", m[id])
		}
	}
}

// Answered requests are kept for the host to read, at most resealMaxAnswered
// of them, the oldest answered going first.
func TestResealAnsweredRequestsAreBounded(t *testing.T) {
	dir := t.TempDir()
	to := mustRecipient(t)
	var first string
	for i := 0; i < resealMaxAnswered+5; i++ {
		r, err := resealFile(dir, fixtureWho, resealReq{Sidecar: junkSidecar("z", i), To: to, Stamp: fixtureStamp})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = r.ID
		}
		if _, err := resealRefuse(dir, fixtureWho, r.ID, ""); err != nil {
			t.Fatal(err)
		}
	}
	m, _ := resealRead(dir)
	if len(m) != resealMaxAnswered {
		t.Fatalf("%d answered requests kept, want %d", len(m), resealMaxAnswered)
	}
	if _, ok := m[first]; ok {
		t.Fatal("the oldest answered request was kept and a newer one dropped")
	}
}
