package main

// A machine store is the folder the person granted, for as long as the grant
// lives. The bastion often runs as root and the folder belongs to someone who
// is not, so whoever can write in it, or above it, must not be able to point
// a read or a move somewhere else: by turning the granted folder into a link
// after the grant (no race needed), or by swapping a file for a link between
// the check and the open.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// dcnRunOp runs one DCN handler on the far side of a real WebSocket and
// returns what it sent: the O payload, the R text and the exit code.
func dcnRunOp(t *testing.T, h func(ws *websocket.Conn)) (out, errText string, exit int) {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		h(ws)
	}))
	defer srv.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	exit = -1
	for {
		_, data, err := ws.ReadMessage()
		if err != nil || len(data) == 0 {
			return
		}
		switch data[0] {
		case 'O':
			out += string(data[1:])
		case 'R':
			errText += string(data[1:])
		case 'X':
			exit, _ = strconv.Atoi(string(data[1:]))
			return
		}
	}
}

type dcnStoreFixture struct {
	dir   string // the pairing's dcn dir
	base  string
	store string // the granted folder
	other string // a folder the grant never named
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

func newDcnStoreFixture(t *testing.T) *dcnStoreFixture {
	t.Helper()
	fx := &dcnStoreFixture{dir: t.TempDir(), base: t.TempDir()}
	fx.store = filepath.Join(fx.base, "store")
	fx.other = filepath.Join(fx.base, "other")
	for _, d := range []string{fx.store, fx.other, filepath.Join(fx.store, "docs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(fx.store, "a.txt"), []byte("MINE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.other, "a.txt"), []byte("OTHER"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx.pub, fx.priv, _ = ed25519.GenerateKey(nil)
	return fx
}

// sync installs a read grant for the store through the real grant_sync op.
func (fx *dcnStoreFixture) sync(t *testing.T, mask ...string) {
	t.Helper()
	if len(mask) == 0 {
		mask = []string{"read"}
	}
	rec := signedRec(t, fx.priv, map[string]any{"kind": "dcn_store_grant", "class": "machine",
		"root": fx.store, "mask": mask,
		"expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	payload, _ := json.Marshal(map[string]any{"store_id": 1, "terms_canonical": rec.TermsCanonical,
		"signature": rec.Signature, "verify_pubkey": base64.StdEncoding.EncodeToString(fx.pub)})
	_, why, exit := dcnRunOp(t, func(ws *websocket.Conn) {
		handleDcnGrantSync(ws, fx.dir, []string{base64.StdEncoding.EncodeToString(payload)})
	})
	if exit != 0 {
		t.Fatalf("grant_sync: exit %d: %s", exit, why)
	}
}

func (fx *dcnStoreFixture) op(t *testing.T, h func(*websocket.Conn, string, []string), args map[string]any) (map[string]any, string, int) {
	t.Helper()
	raw, _ := json.Marshal(args)
	out, why, exit := dcnRunOp(t, func(ws *websocket.Conn) {
		h(ws, fx.dir, []string{"1", string(raw)})
	})
	var obj map[string]any
	_ = json.Unmarshal([]byte(out), &obj)
	return obj, why, exit
}

func (fx *dcnStoreFixture) read(t *testing.T, path string) (string, string, int) {
	t.Helper()
	obj, why, exit := fx.op(t, handleDcnReadRange, map[string]any{"path": path})
	b, _ := base64.StdEncoding.DecodeString(func() string { s, _ := obj["content_b64"].(string); return s }())
	return string(b), why, exit
}

// repoint turns the granted folder into a link to the other one.
func (fx *dcnStoreFixture) repoint(t *testing.T) {
	t.Helper()
	if err := os.Rename(fx.store, fx.store+".was"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fx.other, fx.store); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestDcnStoreRepointedAfterTheGrantIsRefused(t *testing.T) {
	fx := newDcnStoreFixture(t)
	fx.sync(t)
	if got, why, exit := fx.read(t, "a.txt"); exit != 0 || got != "MINE" {
		t.Fatalf("the granted file must read: exit %d %q %s", exit, got, why)
	}
	fx.repoint(t)
	if got, _, exit := fx.read(t, "a.txt"); exit == 0 || got == "OTHER" {
		t.Fatalf("after the granted folder became a link elsewhere, read_range returned %q (exit %d); it must refuse", got, exit)
	}
	if obj, _, exit := fx.op(t, handleDcnStat, map[string]any{"path": "a.txt"}); exit == 0 {
		t.Fatalf("stat through the repointed folder must refuse, got %v", obj)
	}
	if obj, _, exit := fx.op(t, handleDcnList, map[string]any{}); exit == 0 {
		t.Fatalf("list through the repointed folder must refuse, got %v", obj)
	}
}

// A folder inside the store that becomes a link to somewhere else after the
// grant is the same escape one level down.
func TestDcnSubfolderRepointedIsRefused(t *testing.T) {
	fx := newDcnStoreFixture(t)
	fx.sync(t)
	if err := os.RemoveAll(filepath.Join(fx.store, "docs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fx.other, filepath.Join(fx.store, "docs")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got, _, exit := fx.read(t, "docs/a.txt"); exit == 0 || got == "OTHER" {
		t.Fatalf("a link inside the store to a folder outside it read %q (exit %d)", got, exit)
	}
}

// The race: a file swapped for a link to a file outside the store between the
// check and the open. Run for long enough that the old check-then-open loses.
func TestDcnReadRangeSwapRaceNeverLeavesTheStore(t *testing.T) {
	fx := newDcnStoreFixture(t)
	fx.sync(t)
	target := filepath.Join(fx.store, "a.txt")
	realTmp := filepath.Join(fx.store, ".real")
	linkTmp := filepath.Join(fx.store, ".link")
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			_ = os.Symlink(filepath.Join(fx.other, "a.txt"), linkTmp)
			_ = os.Rename(linkTmp, target)
			_ = os.WriteFile(realTmp, []byte("MINE"), 0o644)
			_ = os.Rename(realTmp, target)
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	n := 0
	for time.Now().Before(deadline) {
		n++
		if got, _, _ := fx.read(t, "a.txt"); got == "OTHER" {
			stop.Store(true)
			<-done
			t.Fatalf("read %d returned the file outside the store through a swapped link", n)
		}
	}
	stop.Store(true)
	<-done
}

// A move plan applies through the store too: a target folder that leads
// outside the store for an instant between the re-check and the rename must
// not receive the file.
func TestDcnPlanMoveRaceNeverLeavesTheStore(t *testing.T) {
	fx := newDcnStoreFixture(t)
	if err := os.Remove(filepath.Join(fx.other, "a.txt")); err != nil {
		t.Fatal(err)
	}
	docs := filepath.Join(fx.store, "docs")
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			_ = os.Rename(docs, docs+".real")
			_ = os.Symlink(fx.other, docs+".link")
			_ = os.Rename(docs+".link", docs)
			_ = os.Rename(docs, docs+".link")
			_ = os.Remove(docs + ".link")
			_ = os.Rename(docs+".real", docs)
		}
	}()
	defer func() { stop.Store(true); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		_ = os.WriteFile(filepath.Join(fx.store, "a.txt"), []byte("MINE"), 0o644)
		plan := &dcnPlanTerms{PlanID: int64(i), StoreID: 1, Root: fx.store,
			Moves: []dcnMove{{From: "a.txt", To: "docs/a.txt"}}}
		_ = dcnApplyPlan(fx.store, nil, plan)
		if _, err := os.Lstat(filepath.Join(fx.other, "a.txt")); err == nil {
			t.Fatalf("move %d landed outside the store, through a folder that was a link for an instant", i)
		}
		_ = os.Remove(filepath.Join(fx.store, "docs.real", "a.txt"))
		_ = os.Remove(filepath.Join(docs, "a.txt"))
	}
}

// The plan report is written beside its name and renamed into place. Whoever
// can write in the store could plant a link at that side name; the write must
// never follow it, or the root bastion truncates whatever file the link names
// (an excluded .ssh/authorized_keys included) and fills it with the report.
func TestDcnReportWriteNeverFollowsAPlantedSideName(t *testing.T) {
	store := t.TempDir()
	victim := filepath.Join(store, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(victim), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("ssh-ed25519 AAAAexample user@example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plans := filepath.Join(store, ".agent", "plans")
	if err := os.MkdirAll(plans, 0o700); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(".agent", "plans", "7.json")
	// Every side name a writer could guess: this process's pid, and a spread
	// of others, all pointing at the victim.
	for _, pid := range []int{os.Getpid(), 1, 2, 100, 1000} {
		side := filepath.Join(store, rel+".tmp-"+strconv.Itoa(pid))
		if err := os.Symlink(filepath.Join("..", "..", ".ssh", "authorized_keys"), side); err != nil {
			t.Fatal(err)
		}
	}
	r, err := os.OpenRoot(store)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := dcnRootAtomicWrite(r, rel, []byte(`{"state":"ok"}`)); err != nil {
		t.Fatalf("report write: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "ssh-ed25519 AAAAexample user@example\n" {
		t.Fatalf("the report write followed a planted link: the victim now holds %q", got)
	}
	if got, err := os.ReadFile(filepath.Join(store, rel)); err != nil || string(got) != `{"state":"ok"}` {
		t.Fatalf("report not in place: %q %v", got, err)
	}
	if fi, err := os.Lstat(filepath.Join(store, rel)); err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("report is not a 0600 regular file: %v %v", fi, err)
	}
}

// A grant installed before pins existed has no root_real. It still works,
// pins where its folder leads at first use, keeps that pin, and a repoint
// after that is refused like any other.
func TestDcnGrantFromBeforePinsPinsAtFirstUse(t *testing.T) {
	fx := newDcnStoreFixture(t)
	fx.sync(t)
	f, err := dcnLoadFile(fx.dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := f.Stores["1"]
	rec.RootReal = ""
	f.Stores["1"] = rec
	if err := dcnSaveFile(fx.dir, f); err != nil {
		t.Fatal(err)
	}
	if got, why, exit := fx.read(t, "a.txt"); exit != 0 || got != "MINE" {
		t.Fatalf("a grant from before pins no longer reads: exit %d %q %s", exit, got, why)
	}
	f, err = dcnLoadFile(fx.dir)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(fx.store)
	if got := f.Stores["1"].RootReal; got != want {
		t.Fatalf("first use pinned %q, want %q", got, want)
	}
	fx.repoint(t)
	if got, _, exit := fx.read(t, "a.txt"); exit == 0 || got == "OTHER" {
		t.Fatalf("after the first-use pin a repointed folder was read: exit %d %q", exit, got)
	}
}
