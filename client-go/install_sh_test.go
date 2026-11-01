//go:build !windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// installShFunc returns one shell function's text from deploy/install.sh.
func installShFunc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(name) + `\(\) \{\n.*?^\}\n`).Find(raw)
	if m == nil {
		t.Fatalf("install.sh defines no %s()", name)
	}
	return string(m)
}

// TestInstallShKeepsAPairedLocalMachineLocal: a root reinstall defaults to
// networked, except on a machine already paired in local mode, which keeps
// its mode (paired_local). Switched, its pairing would sit on an unanchored
// networked machine, which refuses every op until claim-anchor.
func TestInstallShKeepsAPairedLocalMachineLocal(t *testing.T) {
	fn := installShFunc(t, "paired_local")
	run := func(dirs ...string) bool {
		t.Helper()
		args := append([]string{"-c", fn + `paired_local "$@"`, "sh"}, dirs...)
		err := exec.Command("sh", args...).Run()
		if _, ok := err.(*exec.ExitError); err != nil && !ok {
			t.Fatal(err)
		}
		return err == nil
	}
	mk := func(t *testing.T, files map[string]string) string {
		t.Helper()
		d := t.TempDir()
		for name, body := range files {
			p := filepath.Join(d, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	missing := filepath.Join(t.TempDir(), "none")

	if !run(mk(t, map[string]string{"pairings/a.host.example.json": "{}"}), missing) {
		t.Fatal("a paired machine with no mode file is local and must stay local")
	}
	if !run(mk(t, map[string]string{"pairings/a.json": "{}", "mode.json": `{"mode":"local"}`})) {
		t.Fatal("a paired machine in local mode must stay local")
	}
	if !run(mk(t, map[string]string{"config.json": "{}"})) {
		t.Fatal("a pre-0.10 single pairing (config.json) is a pairing")
	}
	if !run(missing, mk(t, map[string]string{"pairings/a.json": "{}"})) {
		t.Fatal("a pairing in the second folder counts")
	}
	if run(mk(t, map[string]string{"pairings/a.json": "{}", "mode.json": "{\n  \"mode\": \"networked\"\n}"})) {
		t.Fatal("a networked machine is not kept local")
	}
	if run(mk(t, map[string]string{"pairings/.keep": ""}), missing) {
		t.Fatal("a machine with no pairing gets the networked default")
	}
}

// installShPrivatePIDs is what a test that reaches install.sh's
// start_bastion runs under. start_bastion stops every copy of this user's
// bastion it can see in /proc, and on a machine that runs a real bastion as
// this user (root on a server) that would be the real one. So the test must
// see only its own processes: nil when it already runs in a PID namespace of
// its own (CI's container), the unshare prefix that makes one when it can,
// and a skip otherwise.
//
// The machine's own PID namespace is the kernel's initial one, whose number
// is fixed (PROC_PID_INIT_INO, 0xEFFFFFFC); any other is a namespace of its
// own. NSpid in /proc/self/status cannot tell: inside a container /proc is
// the container's, so it shows one level there too.
func installShPrivatePIDs(t *testing.T) []string {
	t.Helper()
	ns, err := os.Readlink("/proc/self/ns/pid")
	if err == nil && ns != "pid:[4026531836]" {
		return nil
	}
	if err == nil && os.Geteuid() == 0 {
		if u, err := exec.LookPath("unshare"); err == nil {
			wrap := []string{u, "--pid", "--fork", "--mount-proc"}
			if exec.Command(wrap[0], append(wrap[1:], "true")...).Run() == nil {
				return wrap
			}
		}
	}
	t.Skip("install.sh's start_bastion stops every copy of this user's bastion; run this test in a PID namespace of its own (unshare --pid --fork --mount-proc, as root)")
	return nil
}

// installShHere is a copy of deploy/install.sh whose machine_install_present
// looks in dir instead of the machine running the test, which may well have
// the bastion installed for the whole machine. machine says whether the copy
// finds one there.
func installShHere(t *testing.T, dir string, machine bool) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	fn := installShFunc(t, "machine_install_present")
	unit := filepath.Join(dir, "machine-unit")
	if machine {
		if err := os.WriteFile(unit, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	here := "machine_install_present() {\n  [ -f '" + unit + "' ]\n}\n"
	out := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(out, []byte(strings.Replace(string(raw), fn, here, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// pairShSetup is a stand-in machine for install.sh: a log directory, a
// home, and a PATH directory of stand-ins for systemctl, loginctl and sleep,
// each logging what it was given. unit is how the stand-in systemd reports
// the user unit: "steady" (one process, running) or "flapping" (a new
// process on every look, auto-restarting).
type pairShSetup struct {
	dir, logs, bin, path, home string
}

func newPairShSetup(t *testing.T) *pairShSetup {
	t.Helper()
	d := t.TempDir()
	s := &pairShSetup{dir: d, logs: filepath.Join(d, "log"), bin: filepath.Join(d, "bin"), path: filepath.Join(d, "path"), home: filepath.Join(d, "home")}
	for _, p := range []string{s.logs, s.bin, s.path, s.home} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s.write(t, filepath.Join(s.path, "systemctl"), `#!/bin/sh
echo "$*" >> "$LOGS/systemctl"
case "$*" in
  *"show -p MainPID --value"*)
    if [ "$UNIT" = flapping ]; then n=$(cat "$LOGS/n" 2>/dev/null || echo 100); n=$((n + 1)); echo "$n" > "$LOGS/n"; echo "$n"; else echo 4242; fi ;;
  *"show -p ActiveState --value"*) if [ "$UNIT" = flapping ]; then echo activating; else echo active; fi ;;
  *"show -p SubState --value"*) if [ "$UNIT" = flapping ]; then echo auto-restart; else echo running; fi ;;
esac
exit 0
`)
	s.write(t, filepath.Join(s.path, "loginctl"), "#!/bin/sh\necho \"$*\" >> \"$LOGS/loginctl\"\nexit \"$LINGER_RC\"\n")
	s.write(t, filepath.Join(s.path, "sleep"), "#!/bin/sh\nexit 0\n")
	// sudo is ALWAYS a stand-in. The suite runs as root, and the installer run
	// as a pretend ordinary account installs for the whole machine through
	// sudo: the real one would hand the published installer to root on the
	// machine running the test. This one refuses, as sudo does for an account
	// that may not use it, unless a test says otherwise (sudoStandIn).
	s.write(t, filepath.Join(s.path, "sudo"), sudoRefuses)
	return s
}

// sudoRefuses is sudo for an account that may not use it.
const sudoRefuses = "#!/bin/sh\necho \"sudo $*\" >> \"${LOGS:-/dev/null}\"/sudo 2>/dev/null\necho \"Sorry, user tester may not run sudo.\" >&2\nexit 1\n"

func (s *pairShSetup) write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func (s *pairShSetup) env(extra ...string) []string {
	return append([]string{"PATH=" + s.path + ":/usr/bin:/bin", "HOME=" + s.home, "XDG_CONFIG_HOME=" + filepath.Join(s.home, ".config"),
		"LOGS=" + s.logs, "TMPDIR=" + s.dir}, extra...)
}

// standInCopy puts a copy of this test binary at dir/privatae-bastion: run
// with installShStandInRun it is a bastion that waits to be stopped, under
// the program name install.sh looks for.
func standInCopy(t *testing.T, dir string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "privatae-bastion")
	if err := os.WriteFile(p, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// pairShHarness runs install.sh's pairing functions against a stand-in
// bastion, systemctl and loginctl. It returns the run's output, the log
// directory and its error. With copyRunning, a copy of the bastion from another
// path is running when the functions start, and log/copy says whether it
// still was when they ended.
func pairShHarness(t *testing.T, root, pairRC, lingerRC string) (string, string, error) {
	t.Helper()
	return pairShHarnessWith(t, root, pairRC, lingerRC, "steady", false)
}

func pairShHarnessWith(t *testing.T, root, pairRC, lingerRC, unit string, copyRunning bool) (string, string, error) {
	t.Helper()
	wrap := installShPrivatePIDs(t)
	s := newPairShSetup(t)
	fake := filepath.Join(s.bin, "privatae-bastion")
	s.write(t, fake, `#!/bin/sh
echo "HOME=$HOME $*" >> "$LOGS/argv"
case "$1" in
  pair) cat > "$LOGS/stdin"; exit "$PAIR_RC" ;;
  status) echo "status: paired" ;;
esac
exit 0
`)
	copyPath := ""
	if copyRunning {
		other := filepath.Join(s.dir, "other-install")
		if err := os.MkdirAll(other, 0o700); err != nil {
			t.Fatal(err)
		}
		copyPath = standInCopy(t, other)
	}
	fns := installShFunc(t, "pair_as") + installShFunc(t, "bastion_copy") + installShFunc(t, "stop_user_copies") +
		installShFunc(t, "user_unit_stays_up") + installShFunc(t, "start_bastion") + installShFunc(t, "pair_and_start")
	script := fns + `
if [ -n "$COPY" ]; then
  "$COPY" ` + installShStandInRun + ` >/dev/null 2>&1 &
  copy=$!
  i=0
  while ! bastion_copy "$copy" && [ "$i" -lt 100 ]; do i=$((i + 1)); /bin/sleep 0.05; done
  bastion_copy "$copy" || { echo "the stand-in copy never started" >&2; exit 97; }
fi
rc=0
pair_and_start "$1" "$2" "$3" linux || rc=$?
if [ -n "$COPY" ]; then
  if bastion_copy "$copy"; then echo alive > "$LOGS/copy"; kill -9 "$copy"; else echo gone > "$LOGS/copy"; fi
fi
exit "$rc"
`
	args := append(append([]string{}, wrap...), "sh", "-c", script, "sh", fake, "skp_INVENTEDCODE", root)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = s.env("PAIR_RC="+pairRC, "LINGER_RC="+lingerRC, "UNIT="+unit, "COPY="+copyPath)
	out, err := cmd.CombinedOutput()
	return string(out), s.logs, err
}

func readPairShLog(t *testing.T, dir, name string) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, name))
	return string(b)
}

// The pairing functions hand the code to `pair -` on standard input, never
// as an argument, then write and start a systemd user unit, ask for
// lingering, and end with one plain sentence. Exit 3 (already paired with
// this Host) is success.
func TestInstallShPairsOverStdinAndStartsAUserUnit(t *testing.T) {
	out, logs, err := pairShHarness(t, "0", "0", "0")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	argv := readPairShLog(t, logs, "argv")
	if !strings.Contains(argv, " pair -\n") || strings.Contains(argv, "skp_") {
		t.Fatalf("the code must reach `pair -` on stdin and never an argument: %q", argv)
	}
	if got := readPairShLog(t, logs, "stdin"); got != "skp_INVENTEDCODE\n" {
		t.Fatalf("pair's standard input: %q", got)
	}
	home := strings.TrimPrefix(strings.Fields(argv)[0], "HOME=")
	unit, err := os.ReadFile(filepath.Join(home, ".config", "systemd", "user", "privatae-bastion.service"))
	if err != nil || !regexp.MustCompile(`(?m)^ExecStart=\S+/privatae-bastion run$`).Match(unit) || !strings.Contains(string(unit), "WantedBy=default.target") {
		t.Fatalf("the user unit: %v\n%s", err, unit)
	}
	sc := readPairShLog(t, logs, "systemctl")
	for _, want := range []string{"--user daemon-reload", "--user enable privatae-bastion", "--user restart privatae-bastion"} {
		if !strings.Contains(sc, want+"\n") {
			t.Fatalf("systemctl was not asked to %q: %q", want, sc)
		}
	}
	if !strings.Contains(readPairShLog(t, logs, "loginctl"), "enable-linger ") {
		t.Fatal("lingering was not asked for")
	}
	if !strings.Contains(out, "status: paired") || !strings.HasSuffix(strings.TrimSpace(out),
		"This machine is paired. The bastion runs as your systemd user service privatae-bastion, and starts at boot.") {
		t.Fatalf("the ending: %s", out)
	}

	out, _, err = pairShHarness(t, "0", "3", "1")
	if err != nil || !strings.Contains(out, "already paired with this Host") || !strings.Contains(out, "sudo loginctl enable-linger") {
		t.Fatalf("exit 3 is success, and a refused linger says how to get it: %v\n%s", err, out)
	}

	out, logs, err = pairShHarness(t, "0", "1", "0")
	if err == nil || strings.Contains(readPairShLog(t, logs, "systemctl"), "restart") || !strings.Contains(out, "pairing did not finish") {
		t.Fatalf("a failed pair must stop before starting anything: %v\n%s", err, out)
	}

	out, logs, err = pairShHarness(t, "1", "0", "0")
	if err != nil || !strings.Contains(readPairShLog(t, logs, "argv"), "HOME=/root ") ||
		readPairShLog(t, logs, "systemctl") != "restart privatae-bastion\n" || strings.Contains(out, "user service") {
		t.Fatalf("as root it pairs as the service's state and restarts the system service: %v\n%s\n%s", err, out, readPairShLog(t, logs, "systemctl"))
	}
}

// Linux, as yourself: a copy of the bastion already running outside the
// user unit (from a terminal, or another path) is stopped before the unit
// starts, so the unit's copy is the one that serves; and a unit that does not
// stay up is said plainly, with a failure, never reported as running.
func TestInstallShStopsAnOutsideCopyAndChecksTheUnitStaysUp(t *testing.T) {
	out, logs, err := pairShHarnessWith(t, "0", "0", "0", "steady", true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := strings.TrimSpace(readPairShLog(t, logs, "copy")); got != "gone" {
		t.Fatalf("the copy running outside the unit must be stopped, it is %q\n%s", got, out)
	}
	if !strings.Contains(out, "Stopped 1 copy(ies) of the bastion running outside its service") {
		t.Fatalf("the stop is said: %s", out)
	}
	sc := readPairShLog(t, logs, "systemctl")
	if i, j := strings.Index(sc, "--user stop privatae-bastion\n"), strings.Index(sc, "--user restart privatae-bastion\n"); i < 0 || j < i {
		t.Fatalf("the unit is stopped before the copies and started after: %q", sc)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "This machine is paired. The bastion runs as your systemd user service privatae-bastion, and starts at boot.") {
		t.Fatalf("the ending: %s", out)
	}

	out, _, err = pairShHarnessWith(t, "0", "0", "0", "flapping", false)
	if err == nil || !strings.Contains(out, "is not staying up") || !strings.Contains(out, "activating/auto-restart") ||
		!strings.Contains(out, "journalctl --user -u privatae-bastion") || strings.Contains(out, "The bastion runs as your systemd user service") {
		t.Fatalf("a unit that restarts must be reported as not running, and fail: %v\n%s", err, out)
	}
}

// The whole of install.sh, the card's way: the code in PRIVATAE_PAIR_CODE
// and no argument. Every program it starts (stand-ins for uname, id, curl,
// printf, systemctl, loginctl and sleep, and the downloaded bastion) records
// its own arguments, the command line of the shell that started it, and
// whether the code is in its environment. The code must reach `pair -` on
// standard input and appear in none of those. Nothing leaves this machine:
// curl is a stand-in serving a manifest and a stand-in bastion.
func TestInstallShTakesTheCodeOnlyFromTheEnvironment(t *testing.T) {
	wrap := installShPrivatePIDs(t)
	s := newPairShSetup(t)
	const code = "skp_eyJ2IjoxLCJ0IjoiSU5WRU5URUQtRU5WLUNPREUifQ"
	record := `echo "$(basename "$0") argv=[$*] parent=[$(tr '\0' ' ' < /proc/$PPID/cmdline)] env=[${PRIVATAE_PAIR_CODE+set}] envcode=[$(env | grep -c "` + code + `")]" >> "$LOGS/procs"
`
	bastion := "#!/bin/sh\n" + record + `case "$1" in
  pair) cat > "$LOGS/stdin" ;;
  status) echo "status: paired" ;;
esac
exit 0
`
	s.write(t, filepath.Join(s.dir, "bastion.bin"), bastion)
	sum := sha256.Sum256([]byte(bastion))
	s.write(t, filepath.Join(s.dir, "version.json"), "{\n  \"linux-amd64\": {\n    \"url\": \"https://dl.privatae.ai/dl/privatae-bastion-linux-amd64?v=0.0.0\",\n    \"sha256\": \""+hex.EncodeToString(sum[:])+"\"\n  }\n}\n")
	stand := map[string]string{
		"uname":  `case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac`,
		"id":     `case "$1" in -u) echo 1000 ;; -un) echo tester ;; *) echo "uid=1000(tester)" ;; esac`,
		"curl":   `for a; do o=$a; done; case "$2" in */version.json) cp "$STAND/version.json" "$o" ;; *) cp "$STAND/bastion.bin" "$o" ;; esac`,
		"printf": `exec /usr/bin/printf "$@"`,
	}
	for name, body := range stand {
		s.write(t, filepath.Join(s.path, name), "#!/bin/sh\n"+record+body+"\n")
	}
	for _, name := range []string{"systemctl", "loginctl", "sleep"} {
		p := filepath.Join(s.path, name)
		b, _ := os.ReadFile(p)
		s.write(t, p, strings.Replace(string(b), "#!/bin/sh\n", "#!/bin/sh\n"+record, 1))
	}
	sh := installShHere(t, s.dir, false)
	args := append(append([]string{}, wrap...), "sh", sh)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = s.env("PRIVATAE_PAIR_CODE="+code, "STAND="+s.dir, "LINGER_RC=0", "UNIT=steady")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := readPairShLog(t, s.logs, "stdin"); got != code+"\n" {
		t.Fatalf("pair's standard input: %q\n%s", got, out)
	}
	procs := readPairShLog(t, s.logs, "procs")
	for _, who := range []string{"uname argv=[-s]", "curl argv=[", "privatae-bastion argv=[pair -]", "privatae-bastion argv=[status]", "systemctl argv=[--user restart privatae-bastion]"} {
		if !strings.Contains(procs, who) {
			t.Fatalf("no record of %q: the stand-ins did not run as expected\n%s\n%s", who, procs, out)
		}
	}
	if strings.Contains(procs, code) || strings.Contains(procs, "INVENTED-ENV-CODE") {
		t.Fatalf("the code is in a program's arguments or its shell's command line:\n%s", procs)
	}
	if strings.Contains(procs, "env=[set]") || !strings.Contains(procs, "envcode=[0]") || strings.Contains(procs, "envcode=[1]") {
		t.Fatalf("a program the installer started inherited the code in its environment:\n%s", procs)
	}
	if strings.Contains(string(out), code) {
		t.Fatalf("the installer printed the code:\n%s", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(out)), "https://privatae.ai/bastion/LICENSE.txt") || !strings.Contains(string(out), "This machine is paired.") {
		t.Fatalf("the ending: %s", out)
	}
	// sudo refused (the stand-in), so it is installed for this account, and
	// the installer says what that means.
	if !strings.Contains(readPairShLog(t, s.logs, "sudo"), " true") || !strings.Contains(string(out), "installed for your account only") ||
		!strings.Contains(string(out), "in a terminal, from an account that may use sudo") {
		t.Fatalf("the fall back to this account is not said:\n%s", out)
	}
}

// A PRIVATAE_PAIR_CODE that is empty or not a whole pairing code is refused
// before anything is downloaded, and never echoed; so is any argument, a
// code given as one (the removed --pair, or the code alone) included.
//
// The script runs with stand-ins for id (not root) and curl (records that it
// was reached, fetches nothing), so an installer whose refusal broke can
// neither reach the network nor install anything as root on the machine
// running the test: it fails here instead.
func TestInstallShRefusesABadPairCodeBeforeDownloading(t *testing.T) {
	const code = "skp_eyJ2IjoxfQ"
	stand := t.TempDir()
	for name, body := range map[string]string{
		"id":   `case "$1" in -u) echo 1000 ;; -un) echo tester ;; *) echo "uid=1000(tester)" ;; esac`,
		"curl": `echo "REACHED-THE-DOWNLOAD" >&2; exit 1`,
		"sudo": `echo "REACHED-SUDO" >&2; exit 1`,
	} {
		if err := os.WriteFile(filepath.Join(stand, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		env  []string
		args []string
	}{
		{[]string{"PRIVATAE_PAIR_CODE="}, nil},
		{[]string{"PRIVATAE_PAIR_CODE=skp_"}, nil},
		{[]string{"PRIVATAE_PAIR_CODE=skb_aG9tZS5zZWNyZXQteA"}, nil},
		{[]string{"PRIVATAE_PAIR_CODE=" + code + " trailing"}, nil},
		{[]string{"PRIVATAE_PAIR_CODE=" + code + "%3D"}, nil},
		{nil, []string{"--pair", code}},
		{nil, []string{"--pair=" + code}},
		{nil, []string{code}},
		{nil, []string{"--networkd"}},
	} {
		home := t.TempDir()
		cmd := exec.Command("sh", append([]string{filepath.Join("..", "deploy", "install.sh")}, c.args...)...)
		cmd.Env = append([]string{"PATH=" + stand + ":/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + home}, c.env...)
		out, err := cmd.CombinedOutput()
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 2 || strings.Contains(string(out), "Fetching manifest") || strings.Contains(string(out), "REACHED-THE-DOWNLOAD") ||
			strings.Contains(string(out), "REACHED-SUDO") {
			t.Fatalf("%v %v: want exit 2 before the download, got %v\n%s", c.env, c.args, err, out)
		}
		if strings.Contains(string(out), code) || strings.Contains(string(out), "skb_") || strings.Contains(string(out), "networkd") {
			t.Fatalf("%v %v: the refusal echoes what it was given: %s", c.env, c.args, out)
		}
	}
}

// On a person's own account the installer installs for the whole machine
// through sudo: sudo true first, then root (sudo -H) fetches the installer and
// runs it with --personal, the pairing code on its standard input. sudo's
// arguments never hold the code. What an earlier install for this account
// alone left (never paired) is removed, so it does not run a second bastion.
//
// Nothing here runs as root on the machine running the test: the installer
// root fetches is a stand-in that records what it was given, and sudo runs
// it as the test's own account, in a PID namespace of its own.
func TestInstallShInstallsForTheWholeMachineThroughSudo(t *testing.T) {
	wrap := installShPrivatePIDs(t)
	s := newPairShSetup(t)
	const code = "skp_eyJ2IjoxLCJ0IjoiSU5WRU5URUQtV0hPTEUifQ"
	s.write(t, filepath.Join(s.dir, "root-step.sh"), "echo \"$*\" > \"$LOGS/root-args\"\ncat > \"$LOGS/root-stdin\"\nexit 0\n")
	s.write(t, filepath.Join(s.path, "sudo"), "#!/bin/sh\necho \"$*\" >> \"$LOGS/sudo\"\ncase \"$1\" in -p) exit 0 ;; -H) shift ;; esac\nexec \"$@\"\n")
	for name, body := range map[string]string{
		"uname": `case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac`,
		"id":    `case "$1" in -u) echo 1000 ;; -un) echo tester ;; *) echo "uid=1000(tester)" ;; esac`,
		"curl": `echo "$*" >> "$LOGS/curl"; for a; do o=$a; done; u=""; for a; do case "$a" in https://*) u=$a ;; esac; done
case "$u" in https://privatae.ai/bastion/install.sh) cp "$STAND/root-step.sh" "$o" ;; *) echo "REACHED-THE-DOWNLOAD" >&2; exit 1 ;; esac`,
	} {
		s.write(t, filepath.Join(s.path, name), "#!/bin/sh\n"+body+"\n")
	}
	unit := filepath.Join(s.home, ".config", "systemd", "user", "privatae-bastion.service")
	own := filepath.Join(s.home, ".local", "bin", "privatae-bastion")
	for _, p := range []string{unit, own} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		s.write(t, p, "an earlier install for this account\n")
	}
	sh := installShHere(t, s.dir, false)
	args := append(append([]string{}, wrap...), "sh", sh)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = s.env("PRIVATAE_PAIR_CODE="+code, "STAND="+s.dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := readPairShLog(t, s.logs, "root-args"); strings.TrimSpace(got) != "--personal --pair-code-on-stdin" {
		t.Fatalf("the root step was given %q\n%s", got, out)
	}
	if got := readPairShLog(t, s.logs, "root-stdin"); got != code+"\n" {
		t.Fatalf("the root step's standard input: %q", got)
	}
	sudo := readPairShLog(t, s.logs, "sudo")
	if !strings.HasPrefix(sudo, "-p [bastion] sudo password for %u:  true\n") || !strings.Contains(sudo, "/bin/sh -c ") {
		t.Fatalf("sudo was asked: %s\n%s", sudo, out)
	}
	if strings.Contains(sudo, code) || strings.Contains(string(out), code) {
		t.Fatalf("the code is in sudo's arguments or the output:\n%s\n%s", sudo, out)
	}
	// Root's step reads nothing from this account's home: sudo -H, so HOME is
	// root's, and curl -q, so no ~/.curlrc can point root's fetch elsewhere.
	if !strings.Contains(sudo, "\n-H /bin/sh -c ") {
		t.Errorf("the root step runs with this account's HOME (no sudo -H): %s", sudo)
	}
	if got := readPairShLog(t, s.logs, "curl"); !strings.HasPrefix(got, "-q ") {
		t.Errorf("root's fetch of the installer reads a curl config (no -q first): %q", got)
	}
	if strings.Contains(string(out), "Fetching manifest") || strings.Contains(string(out), "REACHED-THE-DOWNLOAD") {
		t.Fatalf("the installer also installed for this account:\n%s", out)
	}
	for _, p := range []string{unit, own} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	if !strings.Contains(readPairShLog(t, s.logs, "systemctl"), "--user disable --now privatae-bastion") {
		t.Error("this account's own unit was not stopped")
	}
}

// An account whose own bastion is already paired keeps it on an upgrade:
// sudo is never asked, and the installer goes on for this account.
func TestInstallShKeepsAPairedAccountInstallWhereItIs(t *testing.T) {
	s := newPairShSetup(t)
	for name, body := range map[string]string{
		"uname": `case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac`,
		"id":    `case "$1" in -u) echo 1000 ;; -un) echo tester ;; *) echo "uid=1000(tester)" ;; esac`,
		"curl":  `echo "REACHED-THE-DOWNLOAD" >&2; exit 1`,
	} {
		s.write(t, filepath.Join(s.path, name), "#!/bin/sh\n"+body+"\n")
	}
	pd := filepath.Join(s.home, ".config", "privatae-bastion", "pairings")
	if err := os.MkdirAll(pd, 0o700); err != nil {
		t.Fatal(err)
	}
	s.write(t, filepath.Join(pd, "member.host.privatae.ai.json"), "{}")
	cmd := exec.Command("sh", installShHere(t, s.dir, false))
	cmd.Env = s.env()
	out, _ := cmd.CombinedOutput()
	if got := readPairShLog(t, s.logs, "sudo"); got != "" {
		t.Fatalf("sudo was asked for a paired account install: %s", got)
	}
	if !strings.Contains(string(out), "Fetching manifest") {
		t.Fatalf("the installer did not go on for this account:\n%s", out)
	}
}

// Beside a bastion installed for the whole machine, an account that cannot
// use sudo gets no second bastion of its own (the machine's would refuse it),
// asked for with --just-me or fallen back to.
func TestInstallShInstallsNoSecondBastionBesideTheMachines(t *testing.T) {
	for _, args := range [][]string{nil, {"--just-me"}} {
		s := newPairShSetup(t)
		for name, body := range map[string]string{
			"uname": `case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac`,
			"id":    `case "$1" in -u) echo 1000 ;; -un) echo tester ;; *) echo "uid=1000(tester)" ;; esac`,
			"curl":  `echo "REACHED-THE-DOWNLOAD" >&2; exit 1`,
		} {
			s.write(t, filepath.Join(s.path, name), "#!/bin/sh\n"+body+"\n")
		}
		cmd := exec.Command("sh", append([]string{installShHere(t, s.dir, true)}, args...)...)
		cmd.Env = s.env()
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || strings.Contains(string(out), "REACHED-THE-DOWNLOAD") ||
			!strings.Contains(string(out), "installed for the whole machine") {
			t.Fatalf("%v: want a refusal before the download, got %v\n%s", args, err, out)
		}
	}
}

// The root step takes the pairing code on standard input only when told to,
// checks it before anything is downloaded, and never echoes it. --just-me is
// refused as root and beside --shared.
//
// "Root" here is a stand-in id; curl fails every download, so nothing past
// the checks can run.
func TestInstallShRootStepTakesTheCodeOnStdin(t *testing.T) {
	stand := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(stand, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write("curl", `echo "REACHED-THE-DOWNLOAD" >&2; exit 1`)
	write("sudo", `echo "REACHED-SUDO" >&2; exit 1`)
	write("uname", `case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac`)
	run := func(uid, stdin string, args ...string) (string, int) {
		write("id", `case "$1" in -u) echo `+uid+` ;; -un) echo tester ;; *) echo "uid=`+uid+`" ;; esac`)
		home := t.TempDir()
		cmd := exec.Command("sh", append([]string{filepath.Join("..", "deploy", "install.sh")}, args...)...)
		cmd.Env = []string{"PATH=" + stand + ":/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + home}
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode()
		}
		return string(out), 0
	}
	const code = "skp_eyJ2IjoxLCJ0IjoiU1RESU4ifQ"
	out, rc := run("0", code+"\n", "--personal", "--pair-code-on-stdin")
	if rc != 1 || !strings.Contains(out, "REACHED-THE-DOWNLOAD") || strings.Contains(out, code) {
		t.Fatalf("a good code on stdin did not reach the download, or was echoed (%d):\n%s", rc, out)
	}
	for _, bad := range []string{"", "skp_\n", "skb_aG9tZQ\n", code + " x\n"} {
		out, rc := run("0", bad, "--personal", "--pair-code-on-stdin")
		if rc != 2 || strings.Contains(out, "REACHED") || (bad != "" && strings.Contains(out, strings.TrimSpace(bad))) {
			t.Fatalf("stdin %q: want exit 2 before the download, unechoed (%d):\n%s", bad, rc, out)
		}
	}
	if out, rc := run("1000", code+"\n", "--pair-code-on-stdin"); rc != 2 || strings.Contains(out, "REACHED") {
		t.Fatalf("an ordinary account's --pair-code-on-stdin was taken (%d):\n%s", rc, out)
	}
	if out, rc := run("0", "", "--just-me"); rc != 2 || !strings.Contains(out, "without sudo") {
		t.Fatalf("--just-me as root (%d):\n%s", rc, out)
	}
	if out, rc := run("1000", "", "--just-me", "--shared"); rc != 2 || strings.Contains(out, "REACHED") {
		t.Fatalf("--just-me --shared (%d):\n%s", rc, out)
	}
}

// The owner's account is recorded on a person's own computer only. On a
// shared machine the console stays the administrator's.
func TestInstallShRecordsTheOwnerOnAPersonalInstallOnly(t *testing.T) {
	d := t.TempDir()
	bin := filepath.Join(d, "privatae-bastion")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"$*\" >> \""+filepath.Join(d, "log")+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	fns := installShFunc(t, "pair_as") + installShFunc(t, "record_owner")
	for _, c := range []struct {
		networked, sudoUID, want string
	}{{"0", "1000", "approvals-owner --account 1000\n"}, {"1", "1000", ""}, {"0", "0", ""}, {"0", "", ""}} {
		os.Remove(filepath.Join(d, "log"))
		cmd := exec.Command("sh", "-c", fns+`networked=$1; record_owner "$2" 1 linux`, "sh", c.networked, bin)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "SUDO_UID=" + c.sudoUID}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%+v: %v %s", c, err, out)
		}
		got, _ := os.ReadFile(filepath.Join(d, "log"))
		if string(got) != c.want {
			t.Errorf("networked=%s SUDO_UID=%q: recorded %q, want %q", c.networked, c.sudoUID, got, c.want)
		}
	}
}

// The root step's own failure, whatever its exit code, is never read as sudo
// refusing: the installer stops, and installs nothing for the account.
func TestInstallShRootStepFailureIsNotAFallBack(t *testing.T) {
	s := newPairShSetup(t)
	s.write(t, filepath.Join(s.dir, "root-step.sh"), "exit 3\n")
	s.write(t, filepath.Join(s.path, "sudo"), "#!/bin/sh\nwhile [ \"$1\" = -H ]; do shift; done\ncase \"$1\" in -p) exit 0 ;; esac\nexec \"$@\"\n")
	for name, body := range map[string]string{
		"uname": `case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac`,
		"id":    `case "$1" in -u) echo 1000 ;; -un) echo tester ;; *) echo "uid=1000(tester)" ;; esac`,
		"curl":  `for a; do o=$a; done; for a; do case "$a" in https://privatae.ai/bastion/install.sh) cp "$STAND/root-step.sh" "$o"; exit 0 ;; esac; done; echo "REACHED-THE-DOWNLOAD" >&2; exit 1`,
	} {
		s.write(t, filepath.Join(s.path, name), "#!/bin/sh\n"+body+"\n")
	}
	cmd := exec.Command("sh", installShHere(t, s.dir, false))
	cmd.Env = s.env("STAND=" + s.dir)
	out, err := cmd.CombinedOutput()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 || strings.Contains(string(out), "your account only") || strings.Contains(string(out), "REACHED-THE-DOWNLOAD") {
		t.Fatalf("want exit 1 and no install for the account, got %v\n%s", err, out)
	}
}
