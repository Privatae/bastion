package main

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestFaWinOwnerRefusalRunsOnlyAsAPerson(t *testing.T) {
	const user = winSidTypeUser
	const group = 2
	refused := []struct {
		sid  string
		typ  uint32
		want string
	}{
		{"S-1-5-18", 0, "SYSTEM"},
		{"S-1-5-19", 0, "service account"},
		{"S-1-5-20", 0, "service account"},
		{"S-1-5-32-544", 4, "machine's own identities"}, // BUILTIN\Administrators: the usual owner of what an elevated admin makes
		{"S-1-5-32-545", 4, "machine's own identities"},
		{"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", 5, "machine's own identities"}, // TrustedInstaller
		{"S-1-5-82-1036420768-1044797643-1061213386-2937092688-4282445334", user, "machine's own identities"},
		{"S-1-1-0", 5, "not a person"},  // Everyone
		{"S-1-5-11", 5, "not a person"}, // Authenticated Users
		{"S-1-5-21-1-2-3-1001", group, "not a person"},
		{"S-1-5-21-1-2-3-500", user, "built-in Administrator"},
		{"S-1-5-21-1-2-3-501", user, "built-in Guest"},
		{"S-1-5-21-1-2-3-502", user, "built-in account"}, // krbtgt
		{"S-1-5-21-1-2-3-503", user, "built-in account"}, // DefaultAccount (DSMA)
		{"S-1-5-21-1-2-3-504", user, "built-in account"}, // WDAGUtilityAccount
		{"S-1-5-21-1-2-3-999", user, "built-in account"}, // reserved RID below 1000
	}
	for _, c := range refused {
		why := faWinOwnerRefusal(c.sid, c.typ, "X")
		if why == "" || !strings.Contains(why, c.want) {
			t.Errorf("%s (type %d): refusal %q, want one naming %q", c.sid, c.typ, why, c.want)
		}
		if why != "" && !strings.Contains(why, "grant a folder owned by the user who should read it") {
			t.Errorf("%s: the refusal does not say what to do: %q", c.sid, why)
		}
	}
	for _, sid := range []string{
		"S-1-5-21-3623811015-3361044348-30300820-1001", // a local or domain account
		"S-1-5-21-1-2-3-1500",
		"S-1-12-1-1111111111-2222222222-3333333333-4444444444", // a Microsoft Entra ID account
	} {
		if why := faWinOwnerRefusal(sid, user, "alice"); why != "" {
			t.Errorf("%s: a person's account was refused: %s", sid, why)
		}
	}
}

func TestFaWinDropEnvIsTheOwnersNotTheService(t *testing.T) {
	set, keep := faWinDropEnv("alice", `C:\Users\alice`, `C:\state\leaf`)
	got := map[string]string{}
	for _, kv := range set {
		i := strings.IndexByte(kv, '=')
		got[kv[:i]] = kv[i+1:]
	}
	want := map[string]string{
		"USERNAME":     "alice",
		"HOME":         `C:\Users\alice`,
		"USERPROFILE":  `C:\Users\alice`,
		"APPDATA":      `C:\Users\alice\AppData\Roaming`,
		"LOCALAPPDATA": `C:\Users\alice\AppData\Local`,
		"TEMP":         `C:\Users\alice\AppData\Local\Temp`,
		"TMP":          `C:\Users\alice\AppData\Local\Temp`,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	kept := strings.Join(keep, " ")
	for _, k := range []string{"SystemRoot", "PATH", "PATHEXT", "ComSpec"} {
		if !strings.Contains(" "+kept+" ", " "+k+" ") {
			t.Errorf("%s is not kept; a Python child on Windows needs it", k)
		}
	}
	// The service's own profile must never leak through.
	for _, k := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "HOME"} {
		if strings.Contains(" "+kept+" ", " "+k+" ") {
			t.Errorf("%s is passed through from LocalSystem; it must be the owner's", k)
		}
	}

	// An owner with no profile here keeps everything in the state leaf.
	set, _ = faWinDropEnv("bob", "", `C:\state\leaf`)
	for _, kv := range set {
		if strings.HasPrefix(kv, "APPDATA=") || strings.HasPrefix(kv, "LOCALAPPDATA=") {
			t.Errorf("no profile, yet %s", kv)
		}
		if (strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "TEMP=")) && !strings.HasSuffix(kv, `C:\state\leaf`) {
			t.Errorf("no profile, yet %s is not the state leaf", kv)
		}
	}
}

func TestFaWinEnvBlockIsSortedDeduplicatedAndTerminated(t *testing.T) {
	b := faWinEnvBlock([]string{"path=a", "SystemRoot=C:\\Windows", "=C:=C:\\", "PATH=b", "Ünïcode=ç", "bad"})
	if len(b) < 2 || b[len(b)-1] != 0 || b[len(b)-2] != 0 {
		t.Fatalf("the block must end with two NULs: %v", b[len(b)-2:])
	}
	var entries []string
	start := 0
	for i, c := range b[:len(b)-1] {
		if c == 0 {
			entries = append(entries, string(utf16.Decode(b[start:i])))
			start = i + 1
		}
	}
	want := []string{"PATH=b", `SystemRoot=C:\Windows`, "Ünïcode=ç"}
	if strings.Join(entries, "|") != strings.Join(want, "|") {
		t.Fatalf("entries %q, want %q (sorted without case, a later duplicate wins, '=' entries and junk dropped)", entries, want)
	}
	if e := faWinEnvBlock(nil); len(e) != 2 || e[0] != 0 || e[1] != 0 {
		t.Fatalf("an empty block is two NULs, got %v", e)
	}
}

func TestFaAgentDirStaysOutOfTheFolderWhereTheHandOverIsAPermission(t *testing.T) {
	for _, c := range []struct{ drop, chown, want bool }{
		{false, false, true}, // nothing dropped: as before
		{false, true, true},
		{true, true, true},   // unix drop: .agent in the folder, chowned
		{true, false, false}, // Windows drop: nothing written into the folder
	} {
		if got := faAgentDirInFolderFor(c.drop, c.chown); got != c.want {
			t.Errorf("drop=%v chown=%v: %v, want %v", c.drop, c.chown, got, c.want)
		}
	}
}

func TestFaAgentDirNoteSaysByDesignNotBroken(t *testing.T) {
	if n := faAgentDirNote(false, errors.New(faAgentKeptInStateNote)); strings.Contains(n, "not usable") || n != faAgentKeptInStateNote {
		t.Errorf("by design, the card reads as a fault: %q", n)
	}
	if n := faAgentDirNote(true, errors.New("read-only file system")); !strings.Contains(n, "not usable") || !strings.Contains(n, "read-only file system") {
		t.Errorf("a folder that refused the agent dir must say why: %q", n)
	}
}
