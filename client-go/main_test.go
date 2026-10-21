package main

// TestMain — NO TEST IN THIS PACKAGE READS THE DEVELOPER'S REAL BASTION STATE.
//
// This happened, and it was not a theory. The machine the suite ran on got its
// own bastion anchored to a real host (it is a working machine like any other).
// Within the hour, three tests that had passed all day went red:
//
//	TestMaybeContainKillsTreeAndRefusesApps        killed [], want [101 102 103 202]
//	TestBackupFetchRefusesPrivateAndLocalTargets   "no verified pairing grant …"
//	TestBackupFetchRefusesBadArguments             the same
//
// Nothing in the code had changed. Those tests call handleMgmtConn and
// maybeContain, which reach capsAllow -> currentAnchor() -> configDir(), and
// configDir() is $HOME-derived. Before the box was anchored there was no
// anchor.json to find, so capsAllow took its unanchored path and gated nothing.
// The moment a REAL anchor existed on the machine, every one of those lanes
// went default-deny and the suite started failing for a reason that had nothing
// to do with the code under test.
//
// That is the worst shape a test failure can take, and this repo has seen it
// twice: a suite that accuses working code because of state outside the
// repository. The other one was a disk-map test walking the developer's
// actual disk. Same lesson both times —
// A TEST THAT READS THE MACHINE IT RUNS ON IS NOT A TEST, IT IS A MEASUREMENT
// OF THAT MACHINE.
//
// The per-test helper (uiTestConfigDir) already existed and is used widely; the
// failure was that using it was a CONVENTION, so any test that forgot it
// silently read the real thing. This makes it structural: the whole package
// runs against a temp config dir, and a test that wants its own still calls the
// helper on top. Nothing to remember and nothing to forget.

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// The op sandbox re-execs its own binary (ops_exec_linux.go); under
	// `go test` that binary is this one, so the child must be answered here
	// before the runner would start the suite again inside the namespaces.
	if len(os.Args) >= 3 && os.Args[1] == opSandboxSubcommand {
		os.Exit(opSandboxChildMain(os.Args[2]))
	}
	if len(os.Args) >= 3 && os.Args[1] == opActionSubcommand {
		os.Exit(opActionOuterMain(os.Args[2]))
	}
	if len(os.Args) >= 3 && os.Args[1] == opActionChildSubcommand {
		os.Exit(opActionChildMain(os.Args[2]))
	}
	if len(os.Args) >= 3 && os.Args[1] == opActionProbeSubcommand {
		os.Exit(opActionProbeMain(os.Args[2]))
	}
	// The root-command watch tests run this binary as the command that
	// connects (rootexec_watch_linux_test.go).
	if len(os.Args) >= 3 && os.Args[1] == rootExecConnectSubcommand {
		os.Exit(rootExecConnectMain(os.Args[2:]))
	}
	// Likewise when git runs this binary as the bastion's credential helper
	// (claims_git_test.go): answer as the helper, with the config dir the
	// test named, and never start the suite.
	if os.Getenv("PRIVATAE_TEST_GIT_HELPER_CONFIG") != "" {
		os.Exit(gitHelperChildMain(os.Getenv("PRIVATAE_TEST_GIT_HELPER_CONFIG"), os.Args[1:]))
	}
	dir, err := os.MkdirTemp("", "bastion-suite-config-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not make an isolated config dir: %v\n", err)
		os.Exit(1)
	}
	// The same three variables uiTestConfigDir sets, for the same reasons:
	// XDG_CONFIG_HOME is what os.UserConfigDir reads on linux, HOME on darwin,
	// AppData on windows. Setting all three means the isolation holds on every
	// platform this binary is built for rather than only the one CI runs.
	for _, kv := range [][2]string{
		{"XDG_CONFIG_HOME", dir},
		{"HOME", dir},
		{"AppData", dir},
	} {
		if err := os.Setenv(kv[0], kv[1]); err != nil {
			fmt.Fprintf(os.Stderr, "could not isolate %s: %v\n", kv[0], err)
			os.Exit(1)
		}
	}
	// THE GUARD HAS TO GUARD ITSELF. "Remove TestMain -> RED" only holds on a
	// machine that HAS an anchor: in a clean CI container there is no real
	// state directory to read, so the isolation could be
	// deleted and every test would stay green — the protection would rot
	// silently on exactly the machine nobody is watching.
	//
	// So assert the thing itself rather than a downstream symptom: whatever
	// os.UserConfigDir() resolves to on THIS platform must now sit under the
	// temp directory. A failure here is loud and immediate, and it does not
	// depend on the state of the box.
	if got, err := os.UserConfigDir(); err != nil {
		fmt.Fprintf(os.Stderr, "config dir is unresolvable, so the suite cannot prove "+
			"it is isolated: %v\n", err)
		os.Exit(1)
	} else if !strings.HasPrefix(got, dir) {
		fmt.Fprintf(os.Stderr, "THE SUITE IS NOT ISOLATED: os.UserConfigDir() is %q, "+
			"outside the temp dir %q. Tests reaching configDir() would read the real "+
			"bastion state on this machine.\n", got, dir)
		os.Exit(1)
	}

	// THE FREEZE IS A SIDE EFFECT TOO. Tests that stub killProcess with fake
	// pids (101, 102...) predate killTree's SIGSTOP; without this they would
	// stop whatever real process holds those numbers on the machine running
	// the suite. Tests that exercise the freeze set their own stubs.
	stopProcess = func(int) error { return nil }
	resumeProcess = func(int) error { return nil }
	// Fake pids have no identity: without this the real reader would consult
	// /proc/101 on the machine running the suite and the decision would depend
	// on whatever process holds that number. The real-signal test opts back in.
	procIdentity = func(int) (string, bool, bool) { return "", false, false }

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// gitHelperChildMain is this test binary acting as the bastion's credential
// helper, started by git in the end-to-end test below (TestMain routes to it),
// so git talks to the real cmdGitCredential.
func gitHelperChildMain(configHome string, args []string) int {
	_ = os.Setenv("XDG_CONFIG_HOME", configHome)
	action := "get"
	if len(args) > 0 {
		action = args[len(args)-1]
	}
	if err := cmdGitCredential("", action); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
