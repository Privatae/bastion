package main

import (
	"encoding/binary"
	"testing"
)

// Every value below is invented. No account, group or SID here belongs to a
// real machine.

func TestClassifyUnixOwner(t *testing.T) {
	linux := func(o unixOwner) unixOwner {
		o.SystemUIDMax = linuxSystemUIDMax
		o.AdminGroups = linuxAdminGroups
		o.SudoApplies = true
		return o
	}
	cases := []struct {
		name string
		in   unixOwner
		want ownerFacts
	}{
		{"root is the system and an administrator",
			linux(unixOwner{UID: 0, Name: "root", LocalRecord: ownerYes, GroupsKnown: true, SudoKnown: true,
				Sessions: map[string]bool{}, SessionsKnown: true}),
			ownerFacts{ownerClassSystem, ownerYes, ownerNo}},
		{"a daemon account in the system range",
			linux(unixOwner{UID: 115, Name: "svc-demo", LocalRecord: ownerYes, GroupsKnown: true, SudoKnown: true,
				Sessions: map[string]bool{}, SessionsKnown: true}),
			ownerFacts{ownerClassService, ownerNo, ownerNo}},
		{"nobody is a service account",
			linux(unixOwner{UID: 65534, Name: "nobody", LocalRecord: ownerYes}),
			ownerFacts{ownerClassService, ownerUnknown, ownerUnknown}},
		{"a person in the sudo group, logged in",
			linux(unixOwner{UID: 1001, Name: "pat", LocalRecord: ownerYes, Groups: []string{"pat", "sudo"},
				GroupsKnown: true, Sessions: map[string]bool{"pat": true}, SessionsKnown: true}),
			ownerFacts{ownerClassLocal, ownerYes, ownerYes}},
		{"a person a sudo rule names directly",
			linux(unixOwner{UID: 1002, Name: "lee", LocalRecord: ownerYes, Groups: []string{"lee"},
				GroupsKnown: true, SudoNamed: true, SudoKnown: true}),
			ownerFacts{ownerClassLocal, ownerYes, ownerUnknown}},
		{"no admin group and the sudo rules read: no",
			linux(unixOwner{UID: 1003, Name: "kim", LocalRecord: ownerYes, Groups: []string{"kim"},
				GroupsKnown: true, SudoKnown: true, Sessions: map[string]bool{"pat": true}, SessionsKnown: true}),
			ownerFacts{ownerClassLocal, ownerNo, ownerNo}},
		{"no admin group but the sudo rules unreadable: unknown, never no",
			linux(unixOwner{UID: 1003, Name: "kim", LocalRecord: ownerYes, Groups: []string{"kim"}, GroupsKnown: true}),
			ownerFacts{ownerClassLocal, ownerUnknown, ownerUnknown}},
		{"groups unreadable: unknown, never no",
			linux(unixOwner{UID: 1004, Name: "ash", LocalRecord: ownerYes, SudoKnown: true}),
			ownerFacts{ownerClassLocal, ownerUnknown, ownerUnknown}},
		{"not in passwd on a machine that resolves from a directory",
			linux(unixOwner{UID: 501234, Name: "501234", LocalRecord: ownerNo, DirectorySource: true}),
			ownerFacts{ownerClassDomain, ownerUnknown, ownerUnknown}},
		{"not in passwd and no directory: a uid with no account, not a domain user",
			linux(unixOwner{UID: 501234, Name: "501234", LocalRecord: ownerNo}),
			ownerFacts{ownerUnknown, ownerUnknown, ownerUnknown}},
		{"a realm-qualified name is a directory account",
			linux(unixOwner{UID: 70001, Name: "pat@corp.example", LocalRecord: ownerUnknown}),
			ownerFacts{ownerClassDomain, ownerUnknown, ownerUnknown}},
		{"uid unread",
			linux(unixOwner{UID: -1, Name: ""}),
			ownerFacts{ownerUnknown, ownerUnknown, ownerUnknown}},
		{"macOS admin group member",
			unixOwner{UID: 501, Name: "sam", LocalRecord: ownerYes, Groups: []string{"staff", "admin"},
				GroupsKnown: true, SystemUIDMax: darwinSystemUIDMax, AdminGroups: darwinAdminGroups,
				Sessions: map[string]bool{"sam": true}, SessionsKnown: true},
			ownerFacts{ownerClassLocal, ownerYes, ownerYes}},
		{"macOS standard user: the admin group decides",
			unixOwner{UID: 502, Name: "jo", LocalRecord: ownerYes, Groups: []string{"staff"},
				GroupsKnown: true, SystemUIDMax: darwinSystemUIDMax, AdminGroups: darwinAdminGroups},
			ownerFacts{ownerClassLocal, ownerNo, ownerUnknown}},
		{"macOS daemon",
			unixOwner{UID: 88, Name: "_demo", LocalRecord: ownerYes, SystemUIDMax: darwinSystemUIDMax,
				AdminGroups: darwinAdminGroups},
			ownerFacts{ownerClassService, ownerUnknown, ownerUnknown}},
		{"macOS mobile account",
			unixOwner{UID: 1204567, Name: "rio", LocalRecord: ownerNo, DirectorySource: true,
				SystemUIDMax: darwinSystemUIDMax, AdminGroups: darwinAdminGroups},
			ownerFacts{ownerClassDomain, ownerUnknown, ownerUnknown}},
	}
	for _, c := range cases {
		if got := classifyUnixOwner(c.in); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestClassifyWinOwner(t *testing.T) {
	const box = "DESK-DEMO"
	user := "S-1-5-21-1111111111-2222222222-3333333333-1001"
	cases := []struct {
		name string
		in   winOwner
		want ownerFacts
	}{
		{"LocalSystem",
			winOwner{SID: sidLocalSystem, Domain: "NT AUTHORITY", Computer: box},
			ownerFacts{ownerClassSystem, ownerYes, ownerUnknown}},
		{"NetworkService",
			winOwner{SID: sidNetworkService, Domain: "NT AUTHORITY", Computer: box,
				Groups: map[string]bool{}, GroupsKnown: true},
			ownerFacts{ownerClassService, ownerNo, ownerUnknown}},
		{"a virtual service account",
			winOwner{SID: "S-1-5-80-1-2-3-4-5", Domain: "NT SERVICE", Computer: box},
			ownerFacts{ownerClassService, ownerUnknown, ownerUnknown}},
		{"local administrator, unelevated, at the desktop",
			winOwner{SID: user, Domain: box, Computer: box,
				Groups:      map[string]bool{sidAdministrators: true, sidInteractive: true},
				GroupsKnown: true, SessionSIDs: map[string]bool{user: true}, SessionsKnown: true},
			ownerFacts{ownerClassLocal, ownerYes, ownerYes}},
		{"domain user, not an administrator, no session now",
			winOwner{SID: user, Domain: "CORPDEMO", Computer: box,
				Groups: map[string]bool{"S-1-5-3": true}, GroupsKnown: true,
				SessionSIDs: map[string]bool{}, SessionsKnown: true},
			ownerFacts{ownerClassDomain, ownerNo, ownerNo}},
		{"the local-account group decides even with no domain name",
			winOwner{SID: user, Groups: map[string]bool{sidLocalAccount: true}, GroupsKnown: true},
			ownerFacts{ownerClassLocal, ownerNo, ownerUnknown}},
		{"no session list, but this process is an interactive logon",
			winOwner{SID: user, Domain: box, Computer: box,
				Groups: map[string]bool{sidRemoteInteractive: true, sidInteractive: true}, GroupsKnown: true},
			ownerFacts{ownerClassLocal, ownerNo, ownerYes}},
		{"no session list and a batch token: unknown, never no",
			winOwner{SID: user, Domain: box, Computer: box,
				Groups: map[string]bool{"S-1-5-3": true}, GroupsKnown: true},
			ownerFacts{ownerClassLocal, ownerNo, ownerUnknown}},
		{"token unreadable",
			winOwner{},
			ownerFacts{ownerUnknown, ownerUnknown, ownerUnknown}},
	}
	for _, c := range cases {
		if got := classifyWinOwner(c.in); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestOwnerFileParsers(t *testing.T) {
	status := "Name:\tdemo\nUid:\t1001\t0\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\nGroups:\t27 1001 \n"
	r, e, gids, ok := parseStatusIDs(status)
	if !ok || r != 1001 || e != 0 || len(gids) != 2 || gids[0] != 27 {
		t.Fatalf("status: %d %d %v %v", r, e, gids, ok)
	}
	if _, _, _, ok := parseStatusIDs("Name:\tdemo\n"); ok {
		t.Fatal("a status with no Uid line must not read as uid 0")
	}
	names := parseGroupNames("root:x:0:\nsudo:x:27:pat\n# comment\nbad\n")
	if names[27] != "sudo" || names[0] != "root" || len(names) != 2 {
		t.Fatalf("groups: %v", names)
	}
	uids := parsePasswdUIDs("root:x:0:0::/root:/bin/sh\npat:x:1001:1001::/home/pat:/bin/bash\n")
	if !uids[1001] || !uids[0] || uids[5] {
		t.Fatalf("passwd: %v", uids)
	}
	for body, want := range map[string]int{
		"":                                  linuxSystemUIDMax,
		"UID_MIN 500\n":                     499,
		"UID_MIN 1000\nSYS_UID_MAX   899\n": 899,
		"# SYS_UID_MAX 10\n":                linuxSystemUIDMax,
	} {
		if got := parseLoginDefsSysMax(body); got != want {
			t.Errorf("login.defs %q: %d, want %d", body, got, want)
		}
	}
	if !nsswitchHasDirectory("group: files\npasswd:  files sss systemd\n") ||
		nsswitchHasDirectory("passwd: files systemd\n") {
		t.Fatal("nsswitch directory detection")
	}
	for body, want := range map[string][2]bool{
		"UID=1001\nSTATE=active\nSESSIONS=3\n": {true, true},
		"STATE=lingering\n":                    {false, true},
		"STATE=something-new\n":                {false, false},
		"UID=1001\n":                           {false, false},
	} {
		got, ok := parseLogindUserState(body)
		if got != want[0] || ok != want[1] {
			t.Errorf("logind %q: %v %v", body, got, ok)
		}
	}
	if u := parseWhoUsers("sam      console  Oct 20 09:00\njo       ttys001  Oct 20 09:05\n"); !u["sam"] || !u["jo"] || len(u) != 2 {
		t.Fatalf("who: %v", u)
	}
	uid, mobile, ok := parseDsclUser("OriginalNodeName:\n /Active Directory/DEMO\nUniqueID: 1204567\n")
	if !ok || uid != 1204567 || !mobile {
		t.Fatalf("dscl: %d %v %v", uid, mobile, ok)
	}
	if g := parseIDGroups("staff admin everyone\n"); len(g) != 3 || g[1] != "admin" {
		t.Fatalf("id: %v", g)
	}
}

func TestParseUtmpUsersReadsOnlyLoginSessions(t *testing.T) {
	rec := func(typ uint16, user string) []byte {
		b := make([]byte, utmpRecordSize)
		binary.LittleEndian.PutUint16(b, typ)
		copy(b[utmpUserOffset:], user)
		return b
	}
	var blob []byte
	blob = append(blob, rec(utmpUserProcess, "pat")...)
	blob = append(blob, rec(8, "gone")...) // DEAD_PROCESS: a session that ended
	blob = append(blob, rec(utmpUserProcess, "lee")...)
	blob = append(blob, 1, 2, 3) // a torn tail is ignored, not misread
	got := parseUtmpUsers(blob)
	if !got["pat"] || !got["lee"] || got["gone"] || len(got) != 2 {
		t.Fatalf("utmp: %v", got)
	}
}
