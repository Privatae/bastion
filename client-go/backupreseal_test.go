package main

// Gate: a reseal hands a host the key to ONE backup, sealed to that host
// alone, only after the person approves it here; and it refuses anything that
// is not the backup it claims to be. The fixture sidecar was written by the
// real age command (testdata/backup), in the shape hosts write.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/gorilla/websocket"
)

func armorSeal(t *testing.T, plain []byte, to age.Recipient) []byte {
	t.Helper()
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, to)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(plain)
	_ = w.Close()
	_ = aw.Close()
	return out.Bytes()
}

func armorOpen(t *testing.T, armored []byte, id age.Identity) []byte {
	t.Helper()
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(armored)), id)
	if err != nil {
		t.Fatalf("the resealed sidecar does not open with the host's key: %v", err)
	}
	b, _ := io.ReadAll(r)
	return b
}

// Cross-language, both directions: a sidecar the age command wrote is opened
// and resealed here, and what this code wrote opens with the age command.
func TestResealOpensAnAgeWrittenSidecarAndSealsToTheHostAlone(t *testing.T) {
	bin := ageBinary(t)
	fx := newBackupFixture(t, bin)
	host, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	out, sc, err := resealSidecar(fx.sidecar(t), []age.Identity{fx.recovery}, host.Recipient(), fixtureStamp)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Stamp != fixtureStamp || sc.EntityID != 42 {
		t.Fatalf("read the wrong record: %+v", sc)
	}
	if got := armorOpen(t, out, host); !bytes.Equal(got, fx.plain) {
		t.Fatalf("the resealed record is not the sealed one, byte for byte:\n%s\n%s", got, fx.plain)
	}
	if _, err := age.Decrypt(armor.NewReader(bytes.NewReader(out)), other); err == nil {
		t.Fatal("a host that was not asked for opened the resealed key")
	}
	if _, err := age.Decrypt(armor.NewReader(bytes.NewReader(out)), fx.recovery); err == nil {
		t.Fatal("the resealed copy is also sealed to the key that opened it; it must go to the host alone")
	}
	if strings.Contains(string(out), "AGE-SECRET-KEY") {
		t.Fatal("the identity travels in clear")
	}
	dir := t.TempDir()
	idFile := filepath.Join(dir, "host.txt")
	_ = os.WriteFile(idFile, []byte(host.String()+"\n"), 0o600)
	scFile := filepath.Join(dir, "resealed.age")
	_ = os.WriteFile(scFile, out, 0o600)
	got, err := exec.Command(bin, "-d", "-i", idFile, scFile).Output()
	if err != nil {
		t.Fatalf("the age command cannot open the resealed sidecar: %v", err)
	}
	if !bytes.Equal(got, fx.plain) {
		t.Fatal("the age command reads a different record")
	}
}

func TestResealRefusesWhatIsNotTheBackupItClaims(t *testing.T) {
	user, _ := age.GenerateX25519Identity()
	host, _ := age.GenerateX25519Identity()
	pb, _ := age.GenerateX25519Identity()
	ids := []age.Identity{user}
	good := backupSidecar{V: 1, Kind: sidecarKind, Identity: pb.String(),
		Object: "b/" + fixtureStamp + ".tar.zst.age", EntityID: 7, Stamp: fixtureStamp, MadeAt: "2026-09-28T02:00:00Z"}
	seal := func(sc any) []byte {
		b, _ := json.Marshal(sc)
		return armorSeal(t, b, user.Recipient())
	}
	if _, _, err := resealSidecar(seal(good), ids, host.Recipient(), fixtureStamp); err != nil {
		t.Fatalf("a good sidecar was refused: %v", err)
	}
	cases := map[string][]byte{}
	b := good
	b.Kind = "something-else"
	cases["wrong kind"] = seal(b)
	b = good
	b.V = 2
	cases["unknown version"] = seal(b)
	b = good
	b.Object = "b/20260101T000000Z.tar.zst.age"
	cases["object names another backup"] = seal(b)
	b = good
	b.Stamp = "yesterday"
	b.Object = "b/yesterday.tar.zst.age"
	cases["stamp is not a stamp"] = seal(b)
	b = good
	b.MadeAt = "yesterday\x1b[2J"
	cases["made_at is not a time"] = seal(b)
	b = good
	b.MadeAt = ""
	cases["no made_at"] = seal(b)
	b = good
	b.Identity = "AGE-SECRET-KEY-1NOTAKEY"
	cases["identity does not parse"] = seal(b)
	cases["not JSON"] = armorSeal(t, []byte("hello"), user.Recipient())
	cases["sealed to someone else"] = armorSeal(t, sidecarJSON(good), host.Recipient())
	cases["too large"] = bytes.Repeat([]byte("A"), sidecarMaxBytes+1)
	for name, in := range cases {
		if _, _, err := resealSidecar(in, ids, host.Recipient(), ""); err == nil {
			t.Errorf("%s: resealed", name)
		}
	}
	// A sidecar for one backup cannot be resealed as another.
	if _, _, err := resealSidecar(seal(good), ids, host.Recipient(), "20250101T000000Z"); err == nil {
		t.Error("a sidecar was resealed for a backup it does not name")
	}
}

// A host writes a backup's key file naming b/<stamp> when the backup is kept
// in platform storage and s/<stamp> when it is staged there only until a
// second copy exists (a backup kept only on a bastion). Both open and reseal,
// written by the age command and by this code alike.
func TestResealTakesBothPlacesABackupIsKept(t *testing.T) {
	bins := []string{""}
	if p, err := exec.LookPath("age"); err == nil {
		bins = append(bins, p)
	} else if p := os.Getenv("AGE_BIN"); p != "" {
		bins = append(bins, p)
	} else if os.Getenv("PRIVATAE_REQUIRE_AGE") != "" {
		t.Fatal("PRIVATAE_REQUIRE_AGE is set and no age binary was found (AGE_BIN or PATH)")
	}
	for _, bin := range bins {
		for _, sub := range []string{"b", "s"} {
			fx := newBackupFixtureAs(t, bin, sub, fixtureEntity)
			host, _ := age.GenerateX25519Identity()
			out, sc, err := resealSidecar(fx.sidecar(t), []age.Identity{fx.recovery}, host.Recipient(), fixtureStamp)
			if err != nil {
				t.Fatalf("%s/ key file (age command: %v) refused: %v", sub, bin != "", err)
			}
			if sc.Object != sub+"/"+fixtureStamp+".tar.zst.age" {
				t.Fatalf("read the wrong record: %+v", sc)
			}
			if !bytes.Equal(armorOpen(t, out, host), fx.plain) {
				t.Fatalf("%s/: the resealed record is not the sealed one", sub)
			}
		}
	}
}

// Only those two places, and only the sidecar's own stamp: any other folder,
// a path that climbs or nests, or another backup's name is refused.
func TestResealRefusesAnObjectOutsideBothPlaces(t *testing.T) {
	user, _ := age.GenerateX25519Identity()
	host, _ := age.GenerateX25519Identity()
	pb, _ := age.GenerateX25519Identity()
	name := fixtureStamp + ".tar.zst.age"
	for _, obj := range []string{
		"x/" + name, "../b/" + name, "b/../b/" + name, "s/../b/" + name, "b/b/" + name, "b//" + name,
		"/b/" + name, "./b/" + name, "B/" + name, "S/" + name, "bs/" + name, "exports/" + name,
		"b\\" + name, name, "b/", "s/", "", "b/20260101T000000Z.tar.zst.age", "s/" + fixtureStamp + ".tar.zst",
		"s/" + fixtureStamp + ".tar.zst.age/x", " s/" + name, "s/" + name + "\x00",
	} {
		sc := backupSidecar{V: 1, Kind: sidecarKind, Identity: pb.String(), Object: obj, EntityID: fixtureEntity,
			Stamp: fixtureStamp, MadeAt: "2026-09-28T02:00:00Z"}
		in := armorSeal(t, sidecarJSON(sc), user.Recipient())
		if _, _, err := resealSidecar(in, []age.Identity{user}, host.Recipient(), ""); err == nil ||
			!strings.Contains(err.Error(), "does not match its stamp") {
			t.Errorf("object %q: %v", obj, err)
		}
	}
}

func sidecarJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// driveBackupOp runs one job through the real management frame path, from
// an anonymous caller.
func driveBackupOp(t *testing.T, op, dcnDir, backupRoot string, arg any) (string, string, int) {
	t.Helper()
	return driveBackupOpAs(t, "", op, dcnDir, backupRoot, arg)
}

// driveBackupOpAs is driveBackupOp from the pairing self.
func driveBackupOpAs(t *testing.T, self, op, dcnDir, backupRoot string, arg any) (string, string, int) {
	t.Helper()
	raw, _ := json.Marshal(arg)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConnFor(ws, self, "", dcnDir, backupRoot)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	job, _ := json.Marshal(mgmtJob{Op: op, Args: []string{string(raw)}})
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

func resealStatus(t *testing.T, dcn, id string) map[string]string {
	t.Helper()
	out, errOut, code := driveBackupOp(t, "backup_reseal", dcn, "", resealReq{Op: "status", JobID: id})
	if code != 0 {
		t.Fatalf("status exited %d: %s", code, errOut)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("status is not JSON: %s", out)
	}
	return m
}

// The whole lane: the host files, nothing is opened until the person
// approves here, then the host collects a key only it can open.
func TestBackupResealWaitsForThePersonThenDeliversToTheHostOnly(t *testing.T) {
	fx := newBackupFixture(t, "")
	fx.installAsBastionKey(t)

	dcn := withFixturePairings(t, map[string]int64{fixtureHost: fixtureEntity})[fixtureHost]
	host, _ := age.GenerateX25519Identity()
	req := resealReq{Op: "start", Sidecar: string(fx.sidecar(t)), To: host.Recipient().String(),
		Stamp: fixtureStamp, HostLabel: "the host being restored"}
	out, errOut, code := driveBackupOpAs(t, fixtureHost, "backup_reseal", dcn, "", req)
	if code != 0 {
		t.Fatalf("start exited %d: %s", code, errOut)
	}
	var started map[string]string
	_ = json.Unmarshal([]byte(out), &started)
	if started["state"] != "pending" || !strings.HasPrefix(started["job_id"], "br-") {
		t.Fatalf("start did not file a pending request: %s", out)
	}
	// Asking again files nothing new.
	out2, _, _ := driveBackupOpAs(t, fixtureHost, "backup_reseal", dcn, "", req)
	var again map[string]string
	_ = json.Unmarshal([]byte(out2), &again)
	if again["job_id"] != started["job_id"] {
		t.Fatal("the same ask filed a second request")
	}
	st := resealStatus(t, dcn, started["job_id"])
	if st["state"] != "pending" || st["sidecar"] != "" {
		t.Fatalf("a key was handed out before the person approved: %v", st)
	}
	// Another pairing's state directory knows nothing of it.
	if o := resealStatus(t, t.TempDir(), started["job_id"]); o["state"] != "unknown" {
		t.Fatalf("another pairing read this request: %v", o)
	}

	if _, err := resealDecide(dcn, fixtureWho, started["job_id"], true); err != nil {
		t.Fatal(err)
	}
	st = resealStatus(t, dcn, started["job_id"])
	if st["state"] != "done" {
		t.Fatalf("approved request is %v", st)
	}
	if got := armorOpen(t, []byte(st["sidecar"]), host); !bytes.Equal(got, fx.plain) {
		t.Fatal("the host received a different record")
	}
	if _, err := resealDecide(dcn, fixtureWho, started["job_id"], true); err == nil {
		t.Fatal("a decided request was decided again")
	}

	// A refusal hands over nothing.
	req.To = mustRecipient(t)
	out, _, _ = driveBackupOpAs(t, fixtureHost, "backup_reseal", dcn, "", req)
	var second map[string]string
	_ = json.Unmarshal([]byte(out), &second)
	if _, err := resealDecide(dcn, fixtureWho, second["job_id"], false); err != nil {
		t.Fatal(err)
	}
	if st := resealStatus(t, dcn, second["job_id"]); st["state"] != "refused" || st["sidecar"] != "" {
		t.Fatalf("a refused request handed something over: %v", st)
	}
}

func mustRecipient(t *testing.T) string {
	id, _ := age.GenerateX25519Identity()
	return id.Recipient().String()
}

func TestBackupResealStartRefusesMalformedAsks(t *testing.T) {
	dcn := withFixturePairings(t, map[string]int64{fixtureHost: fixtureEntity})[fixtureHost]
	fx := newBackupFixture(t, "")
	good := resealReq{Op: "start", Sidecar: string(fx.sidecar(t)), To: mustRecipient(t), Stamp: fixtureStamp}
	bad := map[string]resealReq{}
	r := good
	r.Sidecar = "not armored"
	bad["unarmored sidecar"] = r
	r = good
	r.Sidecar = strings.Repeat("A", sidecarMaxBytes+1)
	bad["oversized sidecar"] = r
	r = good
	r.To = "age1notakey"
	bad["bad key"] = r
	r = good
	r.Stamp = "../etc"
	bad["bad stamp"] = r
	for name, label := range map[string]string{
		"multi-line label": "two\nlines", "escape sequence": "host\x1b[31m red", "C1 control": "ho\u0085st",
		"reversed text": "host\u202etxt.exe", "line separator": "a\u2028b", "bell": "ho\x07st",
		"too long": strings.Repeat("x", resealLabelMax+1),
	} {
		r = good
		r.HostLabel = label
		bad[name] = r
	}
	for name, req := range bad {
		if _, _, code := driveBackupOpAs(t, fixtureHost, "backup_reseal", dcn, "", req); code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	// Not from a pairing, or from one that is not paired here: refused too.
	for _, self := range []string{"", "other.host.privatae.ai"} {
		if _, _, code := driveBackupOpAs(t, self, "backup_reseal", dcn, "", good); code == 0 {
			t.Errorf("an ask from %q was accepted", self)
		}
	}
	if m, _ := resealRead(dcn); len(m) != 0 {
		t.Fatalf("refused asks were filed: %d", len(m))
	}
	// The same ask, well formed and from the pairing, is filed: the refusals
	// above were for what they say.
	if _, errOut, code := driveBackupOpAs(t, fixtureHost, "backup_reseal", dcn, "", good); code != 0 {
		t.Fatalf("a good ask was refused: %s", errOut)
	}
}

// The op table carries both new ops under the backup family, each with its
// own approval, so the generic per-run gate never asks twice for one act.
func TestBackupOpsAreClassified(t *testing.T) {
	for _, op := range []string{"backup_push", "backup_reseal", "backup_list"} {
		if _, ok := handlerOps[op]; !ok {
			t.Errorf("%s has no handler", op)
		}
		if opFamily(op) != "dcn" {
			t.Errorf("%s is in family %q", op, opFamily(op))
		}
	}
	for _, op := range []string{"backup_push", "backup_reseal"} {
		if !opWrites(op) || !ownApproval(op) {
			t.Errorf("%s: a write that carries its own approval (writes=%v own=%v)", op, opWrites(op), ownApproval(op))
		}
	}
	if opWrites("backup_list") {
		t.Error("backup_list is a read")
	}
	if handlerOps["backup_reseal"].root != rootDcn || handlerOps["backup_push"].root != rootBackup ||
		handlerOps["backup_list"].root != rootBackup {
		t.Error("the ops run against the wrong root")
	}
}

// A host cannot fill this machine's state with requests: past a count, or
// past a total size, start is refused with a sentence saying what to do.
func TestBackupResealQueueIsBounded(t *testing.T) {
	armored := func(i, size int) string {
		head := "-----BEGIN AGE ENCRYPTED FILE-----\n"
		body := fmt.Sprintf("%08d", i) + strings.Repeat("A", size-len(head)-8)
		return head + body
	}
	to := mustRecipient(t)

	dir := t.TempDir()
	for i := 0; i < resealMaxRequests; i++ {
		if _, err := resealFile(dir, fixtureWho, resealReq{Sidecar: armored(i, 200), To: to, Stamp: fixtureStamp}); err != nil {
			t.Fatalf("request %d refused: %v", i, err)
		}
	}
	_, err := resealFile(dir, fixtureWho, resealReq{Sidecar: armored(99, 200), To: to, Stamp: fixtureStamp})
	if err == nil || !strings.Contains(err.Error(), "backup requests") {
		t.Fatalf("request past the count was not refused as such: %v", err)
	}
	// The same ask again is still answered: it files nothing new.
	if _, err := resealFile(dir, fixtureWho, resealReq{Sidecar: armored(0, 200), To: to, Stamp: fixtureStamp}); err != nil {
		t.Fatalf("a repeated ask was refused: %v", err)
	}

	dir = t.TempDir()
	big := sidecarMaxBytes
	n := 0
	for ; (n+1)*big <= resealMaxBytes; n++ {
		if _, err := resealFile(dir, fixtureWho, resealReq{Sidecar: armored(n, big), To: to, Stamp: fixtureStamp}); err != nil {
			t.Fatalf("request %d of %d bytes refused: %v", n, big, err)
		}
	}
	if n >= resealMaxRequests {
		t.Fatalf("the size bound (%d) is never reached before the count (%d)", resealMaxBytes, resealMaxRequests)
	}
	if _, err := resealFile(dir, fixtureWho, resealReq{Sidecar: armored(n, big), To: to, Stamp: fixtureStamp}); err == nil ||
		!strings.Contains(err.Error(), "KiB") {
		t.Fatalf("request past the size bound was not refused: %v", err)
	}
}

// What the person reads before approving: the host's words, marked as the
// host's, beside what the sidecar itself says when opened here.
func TestResealPreviewShowsWhatTheSidecarSays(t *testing.T) {
	fx := newBackupFixture(t, "")
	r := &resealRequest{ID: "br-1", Stamp: fixtureStamp, Pairing: fixtureHost, HostNumber: fixtureEntity,
		HostLabel: "my new host", To: mustRecipient(t), Sidecar: string(fx.sidecar(t)), State: "pending"}
	p, refusal := resealPreview(r, []age.Identity{fx.recovery}, fixtureWho)
	if refusal != "" {
		t.Fatalf("the host's own backup is refused: %s", refusal)
	}
	for _, want := range []string{"Sent by the pairing " + fixtureHost + ", host number 42", "What the host says",
		`"my new host"`, "host number  42",
		`"2026-09-28T02:00:00Z"`, `"b/` + fixtureStamp + `.tar.zst.age"`} {
		if !strings.Contains(p, want) {
			t.Errorf("the preview does not show %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "approving will fail") {
		t.Errorf("a matching sidecar was flagged:\n%s", p)
	}
	r.Stamp = "20250101T000000Z"
	if p, _ := resealPreview(r, []age.Identity{fx.recovery}, fixtureWho); !strings.Contains(p, "approving will fail") {
		t.Errorf("a sidecar for another backup was not flagged:\n%s", p)
	}
	other, _ := age.GenerateX25519Identity()
	if p, _ := resealPreview(r, []age.Identity{other}, fixtureWho); !strings.Contains(p, "does not open here") {
		t.Errorf("a sidecar this bastion cannot open was not said so:\n%s", p)
	}
}

// With a second factor enrolled for the pairing, approving needs its code:
// no code or a wrong one opens nothing and leaves the request pending.
func TestBackupApproveNeedsTheEnrolledFactor(t *testing.T) {
	fx := newBackupFixture(t, "")
	fx.installAsBastionKey(t)
	dir := t.TempDir()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if err := stepupSave(dir, &stepupFile{SecretB32: secret, EnrolledAt: "2026-09-28T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	host, _ := age.GenerateX25519Identity()
	r, err := resealFile(dir, fixtureWho, resealReq{Sidecar: string(fx.sidecar(t)), To: host.Recipient().String(), Stamp: fixtureStamp})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b32decode(secret)
	now := time.Now()
	good := hotp(raw, now.Unix()/stepupPeriod)
	wrong := "000000"
	if wrong == good {
		wrong = "111111"
	}
	for _, code := range []string{"", wrong} {
		if _, err := resealApprove(dir, fixtureWho, r.ID, code); err == nil {
			t.Fatalf("approved with code %q", code)
		}
		m, _ := resealRead(dir)
		if st := m[r.ID]; st.State != "pending" || st.Resealed != "" {
			t.Fatalf("a refused approval changed the request: %+v", st)
		}
	}
	done, err := resealApprove(dir, fixtureWho, r.ID, good)
	if err != nil {
		t.Fatalf("the right code was refused: %v", err)
	}
	if done.State != "done" || !bytes.Equal(armorOpen(t, []byte(done.Resealed), host), fx.plain) {
		t.Fatalf("approved with the right code, but: %+v", done.State)
	}
}

// Labels that cannot ride the JSON frame intact are refused by the check
// itself: invalid UTF-8 is not a label.
func TestResealLabelCheck(t *testing.T) {
	for _, ok := range []string{"", "my new host", "hôte n°2 — été"} {
		if !resealLabelOK(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"host\xff", "ho\x1bst", "ho\u200bst", "ho\u2066st", "a\u2029b", strings.Repeat("é", 61)} {
		if resealLabelOK(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
