package main

// Fuzz the two walls a host's input meets on the backup lane: the reseal
// request it files, and the sidecar it hands over. Whatever the input, the
// request filed is well formed and the sidecar opened is the backup it names.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func FuzzBackupResealRequest(f *testing.F) {
	id, _ := age.GenerateX25519Identity()
	good := string(armorSealF(f, []byte(`{"v":1}`), id.Recipient()))
	f.Add(good, id.Recipient().String(), fixtureStamp, "the host")
	f.Add("-----BEGIN AGE ENCRYPTED FILE-----", "age1", "../x", "a\nb")
	f.Add(good, "AAAA", "20260928T020000Z", strings.Repeat("x", 200))
	f.Fuzz(func(t *testing.T, sidecar, to, stamp, label string) {
		dir := t.TempDir()
		r, err := resealFile(dir, fixtureWho, resealReq{Op: "start", Sidecar: sidecar, To: to, Stamp: stamp, HostLabel: label})
		if err != nil {
			if m, _ := resealRead(dir); len(m) != 0 {
				t.Fatal("a refused request was filed")
			}
			return
		}
		if !backupStampRe.MatchString(r.Stamp) {
			t.Fatalf("filed a request for %q", r.Stamp)
		}
		if _, err := age.ParseX25519Recipient(r.To); err != nil {
			t.Fatalf("filed a request to an unusable key %q", r.To)
		}
		if strings.ContainsAny(r.HostLabel, "\n\r\t\x00") || len(r.HostLabel) > 120 {
			t.Fatalf("filed a label that is not one short line: %q", r.HostLabel)
		}
		if len(r.Sidecar) > sidecarMaxBytes || r.State != "pending" {
			t.Fatal("filed an oversized or already-decided request")
		}
	})
}

func FuzzOpenSidecarNamesItsBackup(f *testing.F) {
	user, _ := age.GenerateX25519Identity()
	pb, _ := age.GenerateX25519Identity()
	good, _ := json.Marshal(backupSidecar{V: 1, Kind: sidecarKind, Identity: pb.String(),
		Object: "b/" + fixtureStamp + ".tar.zst.age", EntityID: 1, Stamp: fixtureStamp, MadeAt: "2026-09-28T02:00:00Z"})
	f.Add(good, "")
	f.Add(bytes.Replace(good, []byte(`"b/`), []byte(`"s/`), 1), fixtureStamp)
	f.Add(bytes.Replace(good, []byte(`"b/`), []byte(`"s/../b/`), 1), "")
	f.Add([]byte(`{"v":1,"kind":"privatae-backup-key","stamp":"x","object":"b/x.tar.zst.age"}`), fixtureStamp)
	f.Add([]byte("not json"), "")
	f.Fuzz(func(t *testing.T, plain []byte, want string) {
		sealed := armorSealF(t, plain, user.Recipient())
		_, sc, err := openSidecar(sealed, []age.Identity{user}, want)
		if err != nil {
			return
		}
		if sc.V != 1 || sc.Kind != sidecarKind || !backupStampRe.MatchString(sc.Stamp) ||
			(sc.Object != "b/"+sc.Stamp+".tar.zst.age" && sc.Object != "s/"+sc.Stamp+".tar.zst.age") ||
			(want != "" && sc.Stamp != want) {
			t.Fatalf("opened a sidecar that does not name its backup: %+v (want %q)", sc, want)
		}
		if _, err := age.ParseX25519Identity(sc.Identity); err != nil {
			t.Fatal("opened a sidecar whose key does not parse")
		}
		if _, err := time.Parse(time.RFC3339, sc.MadeAt); err != nil {
			t.Fatalf("opened a sidecar whose made_at %q is not a time", sc.MadeAt)
		}
	})
}

func armorSealF(tb testing.TB, plain []byte, to age.Recipient) []byte {
	tb.Helper()
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, to)
	if err != nil {
		tb.Fatal(err)
	}
	_, _ = w.Write(plain)
	_ = w.Close()
	_ = aw.Close()
	return out.Bytes()
}
