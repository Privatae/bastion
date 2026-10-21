package main

import (
	"encoding/xml"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

// plistValues walks a launchd plist and returns each top-level key's value: a
// string, "true"/"false", a []string for an array of strings, or a
// map[string]string for a dict of strings. Decoding it, rather than searching
// the text, is what shows the file is well-formed XML that launchd can read.
func plistValues(t *testing.T, b []byte) map[string]any {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(string(b)))
	d.Strict = true
	out := map[string]any{}
	depth, key := 0, ""
	var arr []string
	var sub map[string]string
	subKey := ""
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				return out
			}
			t.Fatalf("the plist is not well-formed XML: %v\n%s", err, b)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case e.Name.Local == "key" && depth == 3:
				var s string
				if err := d.DecodeElement(&s, &e); err != nil {
					t.Fatal(err)
				}
				depth--
				key = s
			case e.Name.Local == "key" && depth == 4 && sub != nil:
				var s string
				if err := d.DecodeElement(&s, &e); err != nil {
					t.Fatal(err)
				}
				depth--
				subKey = s
			case e.Name.Local == "string":
				var s string
				if err := d.DecodeElement(&s, &e); err != nil {
					t.Fatal(err)
				}
				depth--
				switch {
				case arr != nil:
					arr = append(arr, s)
				case sub != nil:
					sub[subKey] = s
				default:
					out[key] = s
				}
			case e.Name.Local == "true" || e.Name.Local == "false":
				out[key] = e.Name.Local
			case e.Name.Local == "array" && depth == 3:
				arr = []string{}
			case e.Name.Local == "dict" && depth == 3:
				sub = map[string]string{}
			}
		case xml.EndElement:
			if e.Name.Local == "array" && arr != nil {
				out[key] = arr
				arr = nil
			}
			if e.Name.Local == "dict" && sub != nil && depth == 3 {
				out[key] = sub
				sub = nil
			}
			depth--
		}
	}
}

func TestLaunchdPlistRunsTheDaemonAsRootAtBootAndKeepsItAlive(t *testing.T) {
	bin := "/Library/Application Support/privatae/bin/privatae-bastion"
	b, err := launchdPlist(bin)
	if err != nil {
		t.Fatal(err)
	}
	v := plistValues(t, b)
	if v["Label"] != launchdLabel {
		t.Errorf("Label = %v, want %s", v["Label"], launchdLabel)
	}
	args, _ := v["ProgramArguments"].([]string)
	if len(args) != 2 || args[0] != bin || args[1] != "run" {
		t.Errorf("ProgramArguments = %q, want [%q run]", args, bin)
	}
	if v["UserName"] != "root" {
		t.Errorf("UserName = %v, want root", v["UserName"])
	}
	env, _ := v["EnvironmentVariables"].(map[string]string)
	if env["HOME"] != darwinRootHome {
		t.Errorf("HOME = %q, want %s: the daemon and `sudo -H` must agree on the state directory", env["HOME"], darwinRootHome)
	}
	for _, k := range []string{"RunAtLoad", "KeepAlive"} {
		if v[k] != "true" {
			t.Errorf("%s = %v, want true", k, v[k])
		}
	}
}

func TestLaunchdPlistEscapesThePathAndRefusesUnusableOnes(t *testing.T) {
	odd := `/Library/A & B <x> "q" 'y'/privatae-bastion`
	b, err := launchdPlist(odd)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := plistValues(t, b)["ProgramArguments"].([]string)
	if len(args) == 0 || args[0] != odd {
		t.Fatalf("a path with XML's special characters did not survive: %q", args)
	}
	for _, bad := range []string{"privatae-bastion", "./privatae-bastion", "/bin/x\nrun", "/bin/x\x00", "/bin/x\x7f"} {
		if _, err := launchdPlist(bad); err == nil {
			t.Errorf("launchdPlist(%q) accepted a path launchd would misread", bad)
		}
	}
}

func TestServiceStateEnvPointsAdministratorsAtTheServiceState(t *testing.T) {
	for _, c := range []struct {
		goos                 string
		installed, authority bool
		key, val             string
	}{
		{"darwin", true, true, "HOME", "/var/root"},
		{"windows", true, true, "APPDATA", `C:\Windows\System32\config\systemprofile\AppData\Roaming`},
		{"darwin", false, true, "", ""},
		{"windows", false, true, "", ""},
		{"darwin", true, false, "", ""},
		{"windows", true, false, "", ""},
		{"linux", true, true, "", ""},
	} {
		k, v := serviceStateEnv(c.goos, c.installed, c.authority, `C:\Windows`)
		if k != c.key || v != c.val {
			t.Errorf("serviceStateEnv(%s, installed=%v, authority=%v) = %q=%q, want %q=%q",
				c.goos, c.installed, c.authority, k, v, c.key, c.val)
		}
	}
}

func TestWindowsSystemAppDataIsLocalSystemsProfile(t *testing.T) {
	want := `D:\Win\System32\config\systemprofile\AppData\Roaming`
	for _, root := range []string{`D:\Win`, `D:\Win\`, ` D:\Win `} {
		if got := windowsSystemAppData(root); got != want {
			t.Errorf("windowsSystemAppData(%q) = %q, want %q", root, got, want)
		}
	}
	if got := windowsSystemAppData(""); !strings.HasPrefix(got, `C:\Windows\`) {
		t.Errorf("with no SystemRoot the default is %q", got)
	}
}

func TestServiceGuardRefusesAUserspaceBastionBesideTheService(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		for _, cmd := range []string{"pair", "run", "status", "switch"} {
			err := serviceGuard(goos, cmd, true, false)
			if err == nil {
				t.Errorf("%s: `%s` from an ordinary account beside a system service was allowed", goos, cmd)
				continue
			}
			msg := err.Error()
			if !strings.Contains(msg, "`"+cmd+"`") {
				t.Errorf("%s: the refusal does not name the command: %s", goos, msg)
			}
			if goos == "windows" && strings.Contains(msg, "sudo") {
				t.Errorf("windows: the refusal tells a Windows user to run sudo: %s", msg)
			}
			if goos == "darwin" && !strings.Contains(msg, "sudo -H") {
				t.Errorf("darwin: the refusal does not say how: %s", msg)
			}
			// The administrator, the service itself, and a machine with no
			// service are never refused.
			if err := serviceGuard(goos, cmd, true, true); err != nil {
				t.Errorf("%s: an administrator's `%s` was refused: %v", goos, cmd, err)
			}
			if err := serviceGuard(goos, cmd, false, false); err != nil {
				t.Errorf("%s: `%s` on a machine with no system service was refused: %v", goos, cmd, err)
			}
		}
		// Commands that do not start or show a bastion of the caller's own pass.
		for _, cmd := range []string{"context", "version", "approvals", "ui", "service"} {
			if err := serviceGuard(goos, cmd, true, false); err != nil {
				t.Errorf("%s: `%s` was refused but does not fork the bastion: %v", goos, cmd, err)
			}
		}
	}
	// Linux's service is its systemd unit; nothing here changes how it behaves.
	if err := serviceGuard("linux", "pair", true, false); err != nil {
		t.Errorf("linux: refused: %v", err)
	}
}

// fakeTree is a pathOwnerMode over a fixed table, standing in for a Mac's disk.
type fakeTree map[string]struct {
	uid  uint32
	mode fs.FileMode
}

func (f fakeTree) stat(p string) (uint32, fs.FileMode, error) {
	e, ok := f[p]
	if !ok {
		return 0, 0, fs.ErrNotExist
	}
	return e.uid, e.mode, nil
}

func TestBinaryChainMustBeRootOnly(t *testing.T) {
	good := func() fakeTree {
		return fakeTree{
			"/":                                     {0, fs.ModeDir | 0o755},
			"/Library":                              {0, fs.ModeDir | 0o755},
			"/Library/Application Support":          {0, fs.ModeDir | 0o755},
			"/Library/Application Support/privatae": {0, fs.ModeDir | 0o755},
			"/Library/Application Support/privatae/bin":                  {0, fs.ModeDir | 0o755},
			"/Library/Application Support/privatae/bin/privatae-bastion": {0, 0o755},
		}
	}
	bin := "/Library/Application Support/privatae/bin/privatae-bastion"
	if err := binaryChainRootOnly(bin, good().stat); err != nil {
		t.Fatalf("a root-only chain was refused: %v", err)
	}

	cases := map[string]func(fakeTree){
		"the program owned by a user": func(f fakeTree) {
			f[bin] = struct {
				uid  uint32
				mode fs.FileMode
			}{501, 0o755}
		},
		"a directory above it owned by a user (a package manager's /usr/local/bin)": func(f fakeTree) {
			f["/Library/Application Support/privatae/bin"] = struct {
				uid  uint32
				mode fs.FileMode
			}{501, fs.ModeDir | 0o755}
		},
		"a group-writable directory": func(f fakeTree) {
			f["/Library/Application Support/privatae"] = struct {
				uid  uint32
				mode fs.FileMode
			}{0, fs.ModeDir | 0o775}
		},
		"a world-writable program": func(f fakeTree) {
			f[bin] = struct {
				uid  uint32
				mode fs.FileMode
			}{0, 0o757}
		},
		"the program is a symlink": func(f fakeTree) {
			f[bin] = struct {
				uid  uint32
				mode fs.FileMode
			}{0, fs.ModeSymlink | 0o755}
		},
		"a directory that cannot be checked": func(f fakeTree) {
			delete(f, "/Library")
		},
	}
	for name, spoil := range cases {
		f := good()
		spoil(f)
		if err := binaryChainRootOnly(bin, f.stat); err == nil {
			t.Errorf("%s: accepted, so a non-root user could swap the program the daemon runs as root", name)
		}
	}
	if err := binaryChainRootOnly("privatae-bastion", good().stat); err == nil {
		t.Error("a relative path was accepted")
	}
}

func TestWindowsServiceBinaryMustLiveUnderProgramFiles(t *testing.T) {
	pf := `C:\Program Files`
	for _, ok := range []string{
		`C:\Program Files\Privatae\privatae-bastion.exe`,
		`c:\program files\privatae\PRIVATAE-BASTION.EXE`,
		`C:/Program Files/Privatae/privatae-bastion.exe`,
	} {
		if err := windowsServiceBinaryOK(ok, pf); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`C:\Users\pat\AppData\Local\Programs\privatae-bastion\privatae-bastion.exe`,
		`C:\Program Files Evil\privatae-bastion.exe`,
		`C:\Program Files\..\Users\pat\privatae-bastion.exe`,
		`C:\Program Files`,
		`D:\Program Files\Privatae\privatae-bastion.exe`,
	} {
		if err := windowsServiceBinaryOK(bad, pf); err == nil {
			t.Errorf("%s was accepted as a program only administrators can change", bad)
		}
	}
	if err := windowsServiceBinaryOK(`C:\Program Files\Privatae\privatae-bastion.exe`, ""); err == nil {
		t.Error("an unknown Program Files was treated as known")
	}
}

func TestWaitForPairingStartsOnThePairingOrStops(t *testing.T) {
	n := 0
	paired := func() bool { n++; return n >= 3 }
	if !waitForPairing(paired, make(chan struct{}), time.Millisecond) {
		t.Fatal("did not start once a pairing appeared")
	}
	if n != 3 {
		t.Fatalf("checked %d times, want 3", n)
	}
	stop := make(chan struct{})
	close(stop)
	if waitForPairing(func() bool { return false }, stop, time.Hour) {
		t.Fatal("started with no pairing after being asked to stop")
	}
}

func TestServiceHintsNameTheServiceManager(t *testing.T) {
	if h := serviceRestartHintFor("darwin"); !strings.Contains(h, "launchctl kickstart -k system/"+launchdLabel) {
		t.Errorf("darwin restart hint: %s", h)
	}
	if h := serviceRestartHintFor("windows"); !strings.Contains(h, "Restart-Service "+winServiceName) || strings.Contains(h, "sudo") {
		t.Errorf("windows restart hint: %s", h)
	}
	if h := serviceRunHintFor("windows"); !strings.Contains(h, "Start-Service "+winServiceName) {
		t.Errorf("windows run hint: %s", h)
	}
	if serviceRestartHintFor("linux") != restartHintFor("linux") {
		t.Error("linux's hint changed")
	}
}

// TestServiceStateIsAdoptedBeforeAnyCommand reads main(): the state redirect and
// the guard must run before the command switch, or a command reads the wrong
// state directory before either has a say.
func TestServiceStateIsAdoptedBeforeAnyCommand(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	body := s[strings.Index(s, "func main() {"):]
	sw := strings.Index(body, "switch os.Args[1] {")
	for _, call := range []string{"maybeRunAsWindowsService()", "adoptSystemServiceState()", "guardServiceFork(os.Args[1])"} {
		i := strings.Index(body, call)
		if i < 0 || sw < 0 || i > sw {
			t.Errorf("%s must be called in main before the command switch", call)
		}
	}
}

// TestServiceModeOpensNothingOnTheDesktop reads the three Windows functions that
// would put something on a desktop. A service has none: a dialog there waits
// for ever, and a detached relaunch is a second bastion beside the one the
// service manager restarts. Each must return first thing when running as a
// service. They are Windows-only files, so this reads them rather than runs them.
func TestServiceModeOpensNothingOnTheDesktop(t *testing.T) {
	for file, fn := range map[string]string{
		"tray_windows.go":     "func startTray(ctx context.Context) {",
		"notify_windows.go":   "func showBlockingNotice(n uiNotice) {",
		"relaunch_windows.go": "func relaunchAfterUpdate() {",
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		i := strings.Index(s, fn)
		if i < 0 {
			t.Fatalf("%s: %s not found", file, fn)
		}
		var code []string
		for _, line := range strings.Split(s[i+len(fn):], "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			code = append(code, line)
			if len(code) == 2 {
				break
			}
		}
		if len(code) < 2 || code[0] != "if runningAsService {" || code[1] != "return" {
			t.Errorf("%s: %s must begin with `if runningAsService { return }`, begins with %q", file, fn, code)
		}
	}
}

func TestKeepOneLogAsideEmptiesInPlaceAndKeepsTheLastOne(t *testing.T) {
	d := t.TempDir()
	p := d + "/bastion.log"
	if err := keepOneLogAside(p, 10); err != nil {
		t.Fatalf("a missing log is not an error: %v", err)
	}
	if err := os.WriteFile(p, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keepOneLogAside(p, 10); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "short" {
		t.Fatalf("a log under the limit was changed: %q", b)
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Fatal("a log under the limit was set aside")
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(" and now much longer"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	if err := keepOneLogAside(p, 10); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p + ".1"); string(b) != "short and now much longer" {
		t.Fatalf("the set-aside copy is %q", b)
	}
	after, _ := os.Stat(p)
	if after.Size() != 0 || !os.SameFile(before, after) {
		t.Fatalf("the log must be emptied in place (same file, size 0); size %d, same file %v", after.Size(), os.SameFile(before, after))
	}
	// A writer that already had it open keeps writing to the same file.
	if _, err := f.WriteString("next"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "next" {
		t.Fatalf("the open writer's next line went elsewhere: the log holds %q", b)
	}
}
