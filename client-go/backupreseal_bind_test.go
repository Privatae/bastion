package main

// Gate: a restore request is bound to the pairing that sent it. A host that
// was taken over holds the bastion key's sidecars of every host that shares
// this bastion's key (a shared folder, or the platform), so the request's own
// words cannot decide whose backup it is: the host number this machine paired
// with does. Host A asking for host B's backup key is refused, whatever it
// calls itself, and nothing is sealed to A.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// withFixturePairings pairs this machine (in a private config folder) with
// one host per name, host number n at fd00:9::e:<n hex>, as the platform
// hands the address out at pairing. Returns each pairing's DCN folder.
func withFixturePairings(t *testing.T, hosts map[string]int64) map[string]string {
	t.Helper()
	isolateConfigDir(t)
	dirs := map[string]string{}
	for name, n := range hosts {
		dir := filepath.Join(t.TempDir(), "dcn")
		c := &Config{HostName: name, HostTunnelIP: fmt.Sprintf("fd00:9::e:%x", n), DCNDir: dir,
			BackupRoot: filepath.Join(t.TempDir(), "backups")}
		if err := c.save(); err != nil {
			t.Fatal(err)
		}
		dirs[name] = c.dcnDir()
	}
	return dirs
}

func resealStatusAs(t *testing.T, self, dcn, id string) map[string]string {
	t.Helper()
	out, errOut, code := driveBackupOpAs(t, self, "backup_reseal", dcn, "", resealReq{Op: "status", JobID: id})
	if code != 0 {
		t.Fatalf("status exited %d: %s", code, errOut)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("status is not JSON: %s", out)
	}
	return m
}

func resealStartAs(t *testing.T, self, dcn string, req resealReq) string {
	t.Helper()
	out, errOut, code := driveBackupOpAs(t, self, "backup_reseal", dcn, "", req)
	if code != 0 {
		t.Fatalf("start from %s exited %d: %s", self, code, errOut)
	}
	var m map[string]string
	_ = json.Unmarshal([]byte(out), &m)
	if m["state"] != "pending" || m["job_id"] == "" {
		t.Fatalf("start from %s filed nothing: %s", self, out)
	}
	return m["job_id"]
}

// The attack: host A (number 7) was taken over. It holds host B's key file
// (B is number 42, the fixture's host), names itself "B", and asks for that
// backup's key sealed to its own key. The person approves at this machine.
// Nothing reaches A. B asking for its own backup still works.
func TestResealRefusesAnotherHostsBackupWhateverTheHostSays(t *testing.T) {
	const hostA, hostB = "a7.host.privatae.ai", fixtureHost
	dirs := withFixturePairings(t, map[string]int64{hostA: 7, hostB: fixtureEntity})
	fx := newBackupFixture(t, "") // host fixtureEntity's (B's) backup
	fx.installAsBastionKey(t)

	attacker, _ := age.GenerateX25519Identity()
	id := resealStartAs(t, hostA, dirs[hostA], resealReq{Op: "start", Sidecar: string(fx.sidecar(t)),
		To: attacker.Recipient().String(), Stamp: fixtureStamp, HostLabel: hostB})
	err := cmdBackupDecide(hostA, id, true)
	if err == nil {
		t.Fatal("the person's approval went through for another host's backup")
	}
	if !strings.Contains(err.Error(), "host number 42") || !strings.Contains(err.Error(), "host number 7") {
		t.Errorf("the refusal does not say whose backup it is and who asked: %v", err)
	}
	st := resealStatusAs(t, hostA, dirs[hostA], id)
	if st["state"] == "done" || st["sidecar"] != "" {
		t.Fatalf("host A was handed host B's backup key: %v", st)
	}
	if st["state"] != "refused" {
		t.Fatalf("the request reads %v, not refused", st)
	}

	// B, asking for its own backup, is served.
	own, _ := age.GenerateX25519Identity()
	idB := resealStartAs(t, hostB, dirs[hostB], resealReq{Op: "start", Sidecar: string(fx.sidecar(t)),
		To: own.Recipient().String(), Stamp: fixtureStamp, HostLabel: "B"})
	if err := cmdBackupDecide(hostB, idB, true); err != nil {
		t.Fatalf("a host's own backup was refused: %v", err)
	}
	if st := resealStatusAs(t, hostB, dirs[hostB], idB); st["state"] != "done" || st["sidecar"] == "" {
		t.Fatalf("host B did not get its own backup's key: %v", st)
	}
}

// The refusal does not rest on the CLI's preview: resealDecide itself opens
// the sidecar and refuses another host's backup, and a request filed by one
// pairing cannot be approved as another's.
func TestResealDecideRefusesWhatIsNotThePairingsOwn(t *testing.T) {
	fx := newBackupFixture(t, "")
	fx.installAsBastionKey(t)
	dir := t.TempDir()
	host, _ := age.GenerateX25519Identity()
	a := resealWho{Name: "a7.host.privatae.ai", Number: 7}
	r, err := resealFile(dir, a, resealReq{Sidecar: string(fx.sidecar(t)), To: host.Recipient().String(), Stamp: fixtureStamp})
	if err != nil {
		t.Fatal(err)
	}
	if r.Pairing != a.Name || r.HostNumber != 7 {
		t.Fatalf("the request is not bound to the pairing that filed it: %+v", r)
	}
	// Approved as if by host 42's pairing: the request is A's, refused.
	got, err := resealDecide(dir, fixtureWho, r.ID, true)
	if err != nil || got.State != "refused" || got.Resealed != "" || !strings.Contains(got.Error, "filed by") {
		t.Fatalf("a request was approved for a pairing that did not file it: %+v %v", got, err)
	}
	r, _ = resealFile(dir, a, resealReq{Sidecar: string(fx.sidecar(t)), To: mustRecipient(t), Stamp: fixtureStamp})
	got, err = resealDecide(dir, a, r.ID, true)
	if err != nil || got.State != "refused" || got.Resealed != "" || !strings.Contains(got.Error, "host number 42") {
		t.Fatalf("host 7 was given host 42's backup key: %+v %v", got, err)
	}
	if _, err := resealFile(dir, resealWho{Name: "x"}, resealReq{Sidecar: string(fx.sidecar(t)), To: mustRecipient(t),
		Stamp: fixtureStamp}); err == nil {
		t.Fatal("a request with no host number was filed")
	}
}

func TestHostNumberComesFromTheTunnelAddress(t *testing.T) {
	for ip, want := range map[string]int64{"fd00:9::e:2a": 42, "fd00:9::e:1": 1, "fd00:9::e:ffff": 0xffff,
		"FD00:0009:0000:0000:0000:0000:000E:0007": 7} {
		if n, ok := hostNumberOf(ip); !ok || n != want {
			t.Errorf("%s: %d %v, want %d", ip, n, ok, want)
		}
	}
	for _, ip := range []string{"", "fd00:9::e:0", "fd00:9::a:2a", "fd00:8::e:2a", "fd00:9:0:1::e:2a", "10.0.0.42",
		"::ffff:10.0.0.42", "fd00:9::e:2a%eth0", "fd00:9::1:e:2a", "not an address"} {
		if n, ok := hostNumberOf(ip); ok {
			t.Errorf("%q read as host number %d", ip, n)
		}
	}
}

// With a second factor enrolled, a wrong code is refused by resealApprove,
// and cmdBackupDecide returns that refusal. It once checked the outer err
// while the approval's error went to the one its `who, err :=` declared, so
// a wrong code fell through to r.State on a nil request and panicked.
func TestResealDecideWithAWrongCodeReturnsTheRefusal(t *testing.T) {
	dirs := withFixturePairings(t, map[string]int64{fixtureHost: fixtureEntity})
	fx := newBackupFixture(t, "")
	fx.installAsBastionKey(t)
	own, _ := age.GenerateX25519Identity()
	id := resealStartAs(t, fixtureHost, dirs[fixtureHost], resealReq{Op: "start", Sidecar: string(fx.sidecar(t)),
		To: own.Recipient().String(), Stamp: fixtureStamp, HostLabel: "B"})
	if err := stepupSave(dirs[fixtureHost], &stepupFile{SecretB32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		EnrolledAt: "2026-08-29T00:00:00Z", LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString("not-a-code\n")
	_ = w.Close()
	realStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = realStdin; _ = r.Close() })

	if err := cmdBackupDecide(fixtureHost, id, true); err == nil {
		t.Fatal("a wrong second-factor code approved the request")
	}
	if st := resealStatusAs(t, fixtureHost, dirs[fixtureHost], id); st["state"] == "done" || st["sidecar"] != "" {
		t.Fatalf("a wrong code handed the backup key over: %v", st)
	}
}
