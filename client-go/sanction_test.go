package main

// The local sanction registry and the predicate a policy engine will be built
// on (sanction.go).
//
// NOT tagged !windows, for the same reason ui_test.go is not: the identity rules
// here are the ones that decide whether a Windows user's own editor survives an
// automatic policy, so they have to be proven on that build too.
//
// Every test below was MUTATION-CHECKED — the code it covers was broken, the
// test confirmed red, and the code was restored. The mutation is named in each
// comment so the next person can re-run it rather than take this on trust.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sanctionTestBox isolates the config dir the same way uiTestConfigDir does and
// returns the path the registry WOULD live at.
//
// IT CREATES NOTHING. ui_approvals_flow_test.go:9-15 records what a fixture that
// pre-creates the thing under test is worth: "A test whose fixture supplies the
// thing under test can only ever pass." The config dir is exactly that here,
// because whether asking a question creates a directory is one of the claims.
func sanctionTestBox(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", d) // os.UserConfigDir on linux
	t.Setenv("HOME", d)            // darwin
	t.Setenv("AppData", d)         // windows
	cfg := filepath.Join(d, "privatae-bastion")
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatalf("fixture is broken: %s exists before anything ran", cfg)
	}
	return cfg
}

// obs is an HONEST observation: the file the kernel says it runs is the same
// path its own argv[0] claims, which is what a program launched from where it
// actually lives looks like.
//
// A FORGER — argv[0] saying one thing while the kernel says another — is built
// with obsFrom, and the difference between the two is the subject of the first
// test in this file.
func obs(sig, cmd, user string) agentObs {
	return agentObs{Kind: kindAgent, Signature: sig, Cmdline: cmd, User: user, Exe: argv0(cmd)}
}

// obsFrom is an observation whose command line and executable DISAGREE. Every
// field is given explicitly because the whole point is that no one of them can
// be derived from another.
func obsFrom(sig, cmd, exe, user string) agentObs {
	a := obs(sig, cmd, user)
	a.Exe = exe
	return a
}

// ── the forgery this record exists to refuse ────────────────────────────────

// THE TEST THIS WHOLE CHANGE IS FOR. A process can choose the name it reports:
// argv[0] is a string handed to exec, not a path the kernel checks. Measured on
// this box, one line, no privileges:
//
//	$ bash -c 'exec -a /home/user/.local/bin/claude sleep 25'
//	/proc/<pid>/cmdline -> /home/user/.local/bin/claude 25
//	/proc/<pid>/exe     -> /usr/lib/cargo/bin/coreutils/sleep
//
// Before the exe identity the tuple was (Kind, Signature, argv[0], User), so that
// process matched a mark made for the real claude EXACTLY and read as
// sanctioned without ever touching that file. The kernel's path is the one
// field in an observation the process did not choose, and re-keying on it is
// what makes the two different identities.
//
// MUTATION: put Argv0 back — `Exe: argv0(a.Cmdline)` in sanctionIdentityOf.
// RESULT: red — "a process that only CLAIMS to be the marked program was
// sanctioned". That is the whole point; if this ever passes under that
// mutation, the identity has drifted back onto the command line.
func TestAForgedArgv0FromADifferentExecutableIsNotSanctioned(t *testing.T) {
	sanctionTestBox(t)
	const claimed = "/home/user/.local/bin/claude"

	real := obs("claude-code", claimed+" --resume abc", "user")
	if real.Exe != claimed {
		t.Fatalf("fixture is broken: the honest process must run from %q, got %q", claimed, real.Exe)
	}
	if _, err := addSanction(real, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	if sanctioned, why := agentSanction(real); !sanctioned || why != sanctionWhyLocal {
		t.Fatalf("fixture is broken: the real program is not marked: %v / %q", sanctioned, why)
	}

	// The forger. Same kind, same signature, same user, same command line down
	// to the byte — and a different file behind it.
	forged := obsFrom("claude-code", claimed+" --resume abc",
		"/usr/lib/cargo/bin/coreutils/sleep", "user")
	if forged.Cmdline != real.Cmdline {
		t.Fatalf("fixture is broken: the forgery must present the same command line")
	}
	sanctioned, why := agentSanction(forged)
	if sanctioned {
		t.Fatalf("a process that only CLAIMS to be the marked program was sanctioned "+
			"(why=%q). argv[0] is chosen by whoever called exec; a mark must be "+
			"recorded against the file the kernel loaded.", why)
	}
	if why != sanctionWhyNone {
		t.Errorf("why = %q, want %q — the forger is simply unvouched-for, not a "+
			"special case", why, sanctionWhyNone)
	}
	// ...and the reverse direction: marking the forger must not vouch for the
	// real program either. The identity is a path, and paths are not symmetric
	// with what a process says about itself.
	if _, err := addSanction(forged, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	recs, err := sanctionRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("two different executables must be two records, got %d", len(recs))
	}
}

// ── what a mark is recorded against ─────────────────────────────────────────

// A pid is worthless as an identity: it changes on every exec, and contain.go's
// header records the case that makes it worse than useless — an agent under a
// supervisor comes straight back with a new one.
//
// MUTATION: add a.PID to the fingerprint input in sanctionIdentity.fingerprint.
// RESULT: red — "the mark did not survive a restart at a new pid".
func TestAPidIsNotWhatAMarkIsRecordedAgainst(t *testing.T) {
	sanctionTestBox(t)
	first := obs("claude-code", "/home/user/.local/bin/claude", "user")
	first.PID = 4242
	if _, err := addSanction(first, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	again := first
	again.PID = 9931 // the same program, restarted
	sanctioned, why := agentSanction(again)
	if !sanctioned || why != sanctionWhyLocal {
		t.Fatalf("the mark did not survive a restart at a new pid: %v / %q", sanctioned, why)
	}
}

// Arguments change constantly; the program does not. `claude` and
// `claude --resume abc` are one thing a person would mark once.
//
// MUTATION: `Exe: a.Cmdline` in sanctionIdentityOf — the whole command line as
// the identity, which is what "record what I am looking at" naively means.
// RESULT: red — the same program with an argument read as unsanctioned.
func TestArgumentsDoNotChangeWhatWasMarked(t *testing.T) {
	sanctionTestBox(t)
	if _, err := addSanction(obs("claude-code", "/usr/local/bin/claude", "user"),
		sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	withArgs := obs("claude-code", "/usr/local/bin/claude --resume abc --verbose", "user")
	if sanctioned, why := agentSanction(withArgs); !sanctioned || why != sanctionWhyLocal {
		t.Fatalf("adding an argument un-marked the program: %v / %q", sanctioned, why)
	}
}

// The signature is in the identity because an agent that is a SCRIPT does not
// have an executable of its own: the kernel loads the interpreter, so
// /proc/<pid>/exe is `node` for every node-hosted agent on the box (measured
// here for a shell script: /usr/bin/bash, while its argv[0] said /bin/bash).
// Without the signature, marking one of them would vouch for every node process
// the plane observes for that user — the widest possible reading of a click the
// user thought was narrow.
//
// This is also the case where the kernel path buys the LEAST, and the test is
// written to show it rather than hide it: the two agents below are told apart
// by their signature, which is derived from argv (agents_parse.go:43-68).
//
// MUTATION: drop id.Signature from the fingerprint input.
// RESULT: red — marking the claude-code one also vouched for the codex one.
func TestMarkingOneInterpreterWrappedAgentDoesNotVouchForAnother(t *testing.T) {
	sanctionTestBox(t)
	claude := obsFrom("claude-code", "node /opt/claude/cli.js", "/usr/bin/node", "user")
	codex := obsFrom("codex", "node /opt/codex/cli.js", "/usr/bin/node", "user")
	// The kernel says both are /usr/bin/node — the thing that makes this case
	// dangerous, and the thing the exe identity cannot fix on its own.
	if claude.Exe != codex.Exe {
		t.Fatalf("fixture is broken: these must share an executable, got %q and %q",
			claude.Exe, codex.Exe)
	}
	if _, err := addSanction(claude, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	if sanctioned, _ := agentSanction(codex); sanctioned {
		t.Fatal("marking one node-hosted agent vouched for a different one")
	}
}

// A mark must not cross OS accounts: on a shared machine, "mine" is said by one
// person about their own processes.
//
// MUTATION: drop id.User from the fingerprint input.
// RESULT: red — another account's identical program read as sanctioned.
func TestAMarkDoesNotCrossOSAccounts(t *testing.T) {
	sanctionTestBox(t)
	if _, err := addSanction(obs("claude-code", "/usr/local/bin/claude", "user"),
		sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	if sanctioned, _ := agentSanction(obs("claude-code", "/usr/local/bin/claude", "someone-else")); sanctioned {
		t.Fatal("a mark made by one OS account vouched for another account's process")
	}
}

// Kind is in the identity so that vouching for the Claude desktop APP does not
// quietly also vouch for a claude-code AGENT — two different products behind one
// binary name, which is the whole reason kindApp exists (agents_parse.go:70-95).
//
// MUTATION: drop id.Kind from the fingerprint input.
// RESULT: red — marking the app vouched for the agent.
func TestMarkingAnAppDoesNotVouchForAnAgent(t *testing.T) {
	sanctionTestBox(t)
	app := obs("claude-desktop", "/Applications/Claude.app/Contents/MacOS/claude", "user")
	app.Kind = kindApp
	agent := app
	agent.Kind = kindAgent
	if _, err := addSanction(app, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	if sanctioned, _ := agentSanction(agent); sanctioned {
		t.Fatal("marking the desktop app vouched for an agent running the same binary")
	}
}

// ── an observation this machine could not identify ──────────────────────────

// A process whose executable this machine cannot read CANNOT BE MARKED. Not
// "falls back to the command line" — that fallback would be the forgery above,
// reintroduced exactly where the box is most blind.
//
// Three independent gates are asserted here, because a migration survives when
// one of them is subtly wrong: the write is refused, the match is refused, and
// the answer has its own reason so a policy engine can tell "I could not
// identify this" from "nobody vouched for this".
//
// MUTATION 1: drop the !id.usable() guard from addSanction.
// RESULT: red — a record with no file in it was written and then honoured.
// MUTATION 2: drop the !id.usable() branch from agentSanction.
// RESULT: red — why came back as the generic "nobody has vouched", losing the
// one distinction a caller that terminates things needs.
func TestAnObservationWithNoKernelPathCannotBeMarked(t *testing.T) {
	sanctionTestBox(t)
	unreadable := obsFrom("claude-code", "/usr/local/bin/claude", "", "user")

	if _, err := addSanction(unreadable, sanctionByLocalUI); err == nil {
		t.Fatal("a mark was recorded for a process whose file this machine could not read")
	} else if !strings.Contains(err.Error(), "could not read which file") {
		t.Errorf("the refusal does not say what went wrong: %q", err)
	}
	sanctioned, why := agentSanction(unreadable)
	if sanctioned {
		t.Error("an observation with no kernel path read as sanctioned")
	}
	if why != sanctionWhyNoExe {
		t.Errorf("why = %q, want the no-path reason. 'this machine could not identify "+
			"it' and 'nobody vouched for it' are different facts, and the caller that "+
			"terminates things is entitled to both", why)
	}
	recs, err := sanctionRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("the registry must stay empty, got %+v", recs)
	}
}

// The HOST's tag does not depend on this box reading anything about the
// executable: it is an environment variable the host fixed at exec
// (agents.go:203). So an observation with no kernel path can still be vouched
// for by the host — only the LOCAL half is refused.
//
// MUTATION: return (false, sanctionWhyNoExe) unconditionally in the
// !id.usable() branch, before the hostTagged check.
// RESULT: red — an agent the host itself launched read as unvouched-for on a
// machine that simply could not read its path.
func TestAHostTagIsHonouredWithoutAKernelPath(t *testing.T) {
	sanctionTestBox(t)
	a := obsFrom("claude-code", "/usr/local/bin/claude", "", "user")
	a.DelegationToken = "del_4jk-Lm9QzR_tUv2wXy7Bc1"
	if sanctioned, why := agentSanction(a); !sanctioned || why != sanctionWhyHostTag {
		t.Fatalf("the host's own tag was lost when the path could not be read: %v / %q",
			sanctioned, why)
	}
}

// PRECEDENCE, and it is a choice rather than an accident: with no kernel path
// AND a malformed tag, the answer is the no-path reason. "I could not identify
// this program" is the more honest headline than "your environment variable is
// the wrong shape", and it carries the instruction the caller needs.
//
// The unreadable-registry case is asserted in the same place for the same
// reason: with no path there is no local mark to find, so the registry is not
// even consulted and a corrupt one changes nothing.
//
// MUTATION: move the !id.usable() branch below the loadSanctions error return.
// RESULT: red — a corrupt registry turned an unidentifiable process into
// (true, unreadable), claiming a verdict the machine had no basis for.
func TestWithNoKernelPathTheReasonOutranksABadTagAndACorruptRegistry(t *testing.T) {
	cfg := sanctionTestBox(t)
	a := obsFrom("claude-code", "/usr/local/bin/claude", "", "user")
	a.DelegationToken = "yes" // set, and not shaped like anything a host mints

	if sanctioned, why := agentSanction(a); sanctioned || why != sanctionWhyNoExe {
		t.Fatalf("with no path and a bad tag: %v / %q, want false / the no-path reason",
			sanctioned, why)
	}

	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"),
		[]byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sanctioned, why := agentSanction(a); sanctioned || why != sanctionWhyNoExe {
		t.Fatalf("with no path and a corrupt registry: %v / %q — there is no mark to "+
			"be hidden by a bad file, so the file cannot change the answer", sanctioned, why)
	}
}

// The exe is taken from the OBSERVATION and never reconstructed. This is the
// rule that keeps every other guarantee in this file standing: the moment
// anything here falls back to the command line, the identity is argv[0] again
// under a different name.
//
// MUTATION: `if a.Exe == "" { id.Exe = argv0(a.Cmdline) }` in sanctionIdentityOf.
// RESULT: red — an observation with no kernel path produced a usable identity
// built out of the string the process chose.
func TestTheIdentityIsNeverBuiltFromTheCommandLine(t *testing.T) {
	sanctionTestBox(t)
	a := obsFrom("claude-code", "/usr/local/bin/claude --resume abc", "", "user")
	id := sanctionIdentityOf(a)
	if id.Exe != "" {
		t.Fatalf("the identity invented a path %q out of the command line", id.Exe)
	}
	if id.usable() {
		t.Fatal("an identity with no kernel path reported itself usable")
	}
	// And when there IS one, it is that one and not the command line's first token.
	b := obsFrom("claude-code", "/usr/local/bin/claude --resume abc", "/opt/claude/bin/claude", "user")
	if got := sanctionIdentityOf(b).Exe; got != "/opt/claude/bin/claude" {
		t.Fatalf("the identity used %q, want the kernel's path", got)
	}
}

// ── marks written before the exe identity ───────────────────────────────────

// A v1 registry may already be on a machine, and every record in it says "the
// thing that CALLS ITSELF this is mine". Honouring one would carry the forgery
// through the migration, which is the one outcome this change cannot allow.
// Deleting it silently would throw away the user's own record of a decision.
//
// So: not matched, not deleted, and described in words that say what it named.
//
// MUTATION: `marked := found` in agentSanction — drop the !rec.stale() gate.
// RESULT: red — the hand-edited record under the CURRENT key vouched for the
// live program.
// MUTATION: the same, plus the fingerprint domain reverted to
// "privatae-sanction-v1" so the old argv[0] key is reachable again.
// RESULT: red — the v1 record vouched too.
// The domain revert ALONE is not a usable mutation against this fixture, and
// saying why is worth more than a third bullet: under the v1 domain the two
// records below hash to the SAME key (v1 hashed argv[0] where v2 hashes the
// exe, and here they are the same string), so they collapse into one and the
// test fails on the record count rather than on a vouch. Both gates are real;
// only the stale gate is independently observable this way.
func TestAMarkWrittenBeforeTheExeIdentityDoesNotVouchAndIsNotDeleted(t *testing.T) {
	cfg := sanctionTestBox(t)
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	// The program that record was written for, running right now.
	live := obs("claude-code", "/usr/local/bin/claude --resume abc", "user")

	// Written by hand as BYTES, exactly as the old code would have left it: an
	// `argv0` field, no `exe`, under the key the OLD fingerprint really produced
	// (v1Fingerprint below). A made-up key would make this test pass for the
	// wrong reason — the record would simply never be looked up, and the rule
	// under test would never run.
	//
	// The second record is the same hazard from the other side: a hand-edited or
	// truncated entry sitting under the CURRENT key with no path in it. The key
	// matches; the record still must not vouch.
	v1ID := v1Fingerprint(kindAgent, "claude-code", "/usr/local/bin/claude", "user")
	v2ID := sanctionIdentityOf(live).fingerprint()
	registry := `{
	  "` + v1ID + `": {
	    "id": "` + v1ID + `",
	    "kind": "agent",
	    "signature": "claude-code",
	    "argv0": "/usr/local/bin/claude",
	    "user": "user",
	    "cmdline": "/usr/local/bin/claude --resume abc",
	    "at": "2026-09-01T10:00:00Z",
	    "by": "local-ui"
	  },
	  "` + v2ID + `": {
	    "id": "` + v2ID + `",
	    "kind": "agent",
	    "signature": "claude-code",
	    "exe": "",
	    "user": "user",
	    "at": "2026-09-02T10:00:00Z",
	    "by": "local-ui"
	  }
	}`
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"), []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}

	if sanctioned, why := agentSanction(live); sanctioned {
		t.Fatalf("a mark recorded against argv[0] still vouched for a live process "+
			"(why=%q) — the migration carried the forgery through", why)
	}

	recs, err := sanctionRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("the old records must be KEPT so the user can see and remove them, got %d", len(recs))
	}
	var old sanctionRecord
	for _, r := range recs {
		if r.ID == v1ID {
			old = r
		}
		if !r.stale() {
			t.Errorf("a record with no kernel path did not report itself expired: %+v", r)
		}
	}
	if old.ID == "" {
		t.Fatal("the v1 record is gone from the registry")
	}
	// The description must name what the old mark actually held, and must not
	// say "run from" — that phrasing is the claim the record cannot support.
	what := old.describeMark()
	if !strings.Contains(what, "/usr/local/bin/claude") || !strings.Contains(what, "called itself") {
		t.Errorf("an expired record describes itself as %q; it must say what it "+
			"named and that the name was self-reported", what)
	}
	if strings.Contains(what, "run from") {
		t.Errorf("an expired record claims %q — it never knew which file was run", what)
	}
	// It is still removable, by id alone.
	dropped, err := dropSanction(old.ID)
	if err != nil || !dropped {
		t.Fatalf("dropSanction on an expired mark = %v, %v", dropped, err)
	}
}

// Re-marking the same program after the migration writes a NEW record and
// LEAVES THE OLD ONE ALONE. There is no in-place upgrade, because nothing on
// this machine can turn a self-reported name into the file the kernel loaded —
// and the old record is not quietly swept up on the way past either, because it
// is the user's record of a decision and removing it is their call.
//
// MUTATION: have addSanction delete every stale record before writing (the
// "just expire them" alternative).
// RESULT: red — the user's own history disappeared on an unrelated click.
func TestRemarkingAfterTheMigrationWritesANewRecordAndKeepsTheOld(t *testing.T) {
	cfg := sanctionTestBox(t)
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	v1ID := v1Fingerprint(kindAgent, "claude-code", "/usr/local/bin/claude", "user")
	registry := `{"` + v1ID + `": {"id": "` + v1ID + `", "kind": "agent",
	  "signature": "claude-code", "argv0": "/usr/local/bin/claude", "user": "user",
	  "at": "2026-09-01T10:00:00Z", "by": "local-ui"}}`
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"), []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}

	a := obs("claude-code", "/usr/local/bin/claude", "user")
	rec, err := addSanction(a, sanctionByLocalUI)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Exe != "/usr/local/bin/claude" || rec.LegacyArgv0 != "" {
		t.Fatalf("a new mark must be keyed on the file and carry no legacy field: %+v", rec)
	}
	if rec.ID == v1ID {
		t.Fatal("the new mark reused the old key — the identity did not change")
	}
	if sanctioned, why := agentSanction(a); !sanctioned || why != sanctionWhyLocal {
		t.Fatalf("the re-made mark does not hold: %v / %q", sanctioned, why)
	}
	recs, err := sanctionRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("marking again must ADD a record, not replace the user's history: got %d", len(recs))
	}
}

// v1Fingerprint is sanctionIdentity.fingerprint AS IT STOOD before the exe identity —
// domain "v1", keyed on argv[0]. Reproduced here rather than imported because
// the function it copies is deliberately gone: the fixtures above need to be
// keyed the way the old code REALLY keyed them, or the migration tests pass
// because nothing was ever looked up.
func v1Fingerprint(kind, sig, argv0, user string) string {
	sum := sha256.Sum256([]byte("privatae-sanction-v1\x00" + kind + "\x00" +
		sig + "\x00" + argv0 + "\x00" + user))
	return hex.EncodeToString(sum[:16])
}

// ── the two mechanisms ──────────────────────────────────────────────────────

// "The host launched it" and "you marked it" are different facts, and a process
// carrying both must not lose one of them — a later policy may treat them
// differently, and it can only do that if both survive the predicate.
//
// MUTATION: return sanctionWhyHostTag for the hostTagged && marked case.
// RESULT: red — "both mechanisms collapsed into one reason".
func TestTheTwoMechanismsStayDistinguishable(t *testing.T) {
	sanctionTestBox(t)
	const goodTag = "del_AAAAAAAAAAAAAAAAAAAAAA"

	plain := obs("claude-code", "/usr/local/bin/claude", "user")
	tagged := obs("aider", "/usr/local/bin/aider", "user")
	tagged.DelegationToken = goodTag
	both := obs("goose", "/usr/local/bin/goose", "user")
	both.DelegationToken = goodTag

	for _, a := range []agentObs{plain, both} {
		if _, err := addSanction(a, sanctionByLocalUI); err != nil {
			t.Fatal(err)
		}
	}
	// `plain` and `both` are marked locally; `tagged` is not.
	if err := unmarkOne(tagged); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		a    agentObs
		want string
	}{
		{"host tag only", tagged, sanctionWhyHostTag},
		{"local mark only", plain, sanctionWhyLocal},
		{"both", both, sanctionWhyBoth},
		{"neither", obs("cline", "/usr/local/bin/cline", "user"), sanctionWhyNone},
	} {
		sanctioned, why := agentSanction(c.a)
		wantOK := c.want != sanctionWhyNone
		if sanctioned != wantOK {
			t.Errorf("%s: sanctioned = %v, want %v", c.name, sanctioned, wantOK)
		}
		if why != c.want {
			t.Errorf("%s: why = %q, want %q — both mechanisms must stay "+
				"distinguishable or a policy cannot treat them differently", c.name, why, c.want)
		}
	}
}

// unmarkOne is a test helper: make sure an identity is NOT in the registry.
func unmarkOne(a agentObs) error {
	_, err := dropSanction(sanctionIdentityOf(a).fingerprint())
	return err
}

// A tag that is not shaped like one the host mints is not evidence the host
// launched anything. A real host tag is `del_` + 24 base64url characters
// (the host mints it), so refusing a malformed one cannot
// refuse a real agent — what it catches is a variable somebody set by hand.
//
// MUTATION: make looksLikeHostTag return `tok != ""`.
// RESULT: red — PRIVATAE_AGENT_TOKEN=yes read as "the host launched it".
func TestAMalformedDelegationTagIsNotAVouch(t *testing.T) {
	sanctionTestBox(t)
	for _, tok := range []string{"yes", "1", "mine", "del_", "del_short", "sanctioned",
		"del_has spaces in it aaaaaaaaaa", "del_has/slashes+inaaaaaaaaaa"} {
		a := obs("claude-code", "/usr/local/bin/claude", "user")
		a.DelegationToken = tok
		sanctioned, why := agentSanction(a)
		if sanctioned {
			t.Errorf("PRIVATAE_AGENT_TOKEN=%q read as sanctioned — setting one environment "+
				"variable would be the whole evasion", tok)
		}
		if why != sanctionWhyBadTag {
			t.Errorf("PRIVATAE_AGENT_TOKEN=%q gave why %q, want the malformed-tag reason", tok, why)
		}
	}
	// The shape the host actually mints: del_ + token_urlsafe(18) = 24 chars.
	good := obs("claude-code", "/usr/local/bin/claude", "user")
	good.DelegationToken = "del_4jk-Lm9QzR_tUv2wXy7Bc1"
	if sanctioned, why := agentSanction(good); !sanctioned || why != sanctionWhyHostTag {
		t.Fatalf("a well-shaped host tag was not honoured: %v / %q", sanctioned, why)
	}
}

// ── the registry on disk ────────────────────────────────────────────────────

// A mark has to survive this program exiting, and the exit that matters is its
// own self-update (update.go:127). The proof that it does is that the READ path
// is the file: a registry written by something else entirely is honoured.
//
// MUTATION: make saveSanctionsLocked return nil without writing.
// RESULT: red — the record was not on disk at all.
func TestAMarkLivesOnDiskAtRestAndIsReadFromThere(t *testing.T) {
	cfg := sanctionTestBox(t)
	a := obs("claude-code", "/usr/local/bin/claude", "user")
	rec, err := addSanction(a, sanctionByLocalUI)
	if err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(cfg, "sanctions.json")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("the mark is not on disk: %v — it would not survive a self-update", err)
	}
	if runtimeIsPOSIX() && fi.Mode().Perm() != 0o600 {
		t.Errorf("sanctions.json is %v, want 0600 — it sits beside this machine's "+
			"pairing credentials", fi.Mode().Perm())
	}

	// What a FRESH process would read, decoded straight from the bytes.
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk map[string]sanctionRecord
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatalf("the registry on disk does not parse: %v", err)
	}
	stored, ok := onDisk[rec.ID]
	if !ok {
		t.Fatalf("the registry on disk has no record under %s", rec.ID)
	}
	if stored.Signature != "claude-code" || stored.Exe != "/usr/local/bin/claude" ||
		stored.User != "user" || stored.Kind != kindAgent {
		t.Errorf("the identity was not stored: %+v", stored.sanctionIdentity)
	}
	// The stored identity is the FILE, under a key that says so. A record whose
	// path lives in `argv0` is a v1 record and must never be written again —
	// see TestAMarkWrittenBeforeTheExeIdentityDoesNotVouchAndIsNotDeleted.
	if !strings.Contains(string(b), `"exe"`) || strings.Contains(string(b), `"argv0"`) {
		t.Errorf("the registry on disk must key the identity on exe, not argv0: %s", b)
	}
	if stored.Cmdline == "" || stored.By != sanctionByLocalUI || stored.At.IsZero() {
		t.Errorf("the record does not say what was marked, how, or when: %+v", stored)
	}
}

// A mark written by something that is not this process is honoured — which is
// what "survives a restart" means, and what proves nothing is answering from a
// cached copy.
//
// MUTATION: memoise loadSanctions into a package var after the first call.
// RESULT: red — the hand-written registry was never seen.
func TestAMarkWrittenByAnotherProcessIsHonoured(t *testing.T) {
	cfg := sanctionTestBox(t)
	a := obs("aider", "/usr/local/bin/aider", "user")

	// Ask first, so a cache would have been filled with "nothing".
	if sanctioned, _ := agentSanction(a); sanctioned {
		t.Fatal("fixture is broken: this was sanctioned before anything was written")
	}

	id := sanctionIdentityOf(a)
	blob, _ := json.Marshal(map[string]sanctionRecord{
		id.fingerprint(): {ID: id.fingerprint(), sanctionIdentity: id,
			At: time.Now().UTC(), By: sanctionByLocalUI},
	})
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if sanctioned, why := agentSanction(a); !sanctioned || why != sanctionWhyLocal {
		t.Fatalf("a registry written outside this process was not read: %v / %q", sanctioned, why)
	}
}

// Asking whether something is sanctioned must CREATE NOTHING. The predicate is
// what a policy engine calls in a loop over every observation, and
// ui_approvals_flow_test.go:53-84 exists because a page that asked a question created
// a directory — twice.
//
// MUTATION: build sanctionsPath on configDir() instead of configDirPath().
// RESULT: red — asking created the config directory.
func TestAskingWhetherSomethingIsMarkedCreatesNothing(t *testing.T) {
	cfg := sanctionTestBox(t)
	sanctioned, why := agentSanction(obs("claude-code", "/usr/local/bin/claude", "user"))
	if sanctioned || why != sanctionWhyNone {
		t.Fatalf("an empty machine answered %v / %q", sanctioned, why)
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatalf("asking the predicate a question created %s. configDirPath() "+
			"(config.go:129) resolves; configDir() (config.go:137) is "+
			"MkdirAll-on-read, and a predicate must not be the second one.", cfg)
	}
}

// An unreadable registry is NOT an all-clear. Treating it as empty would hand a
// policy engine a machine where every process looks unvouched-for — the one
// input that turns this feature into the thing it was built to prevent
// (the asymmetry the design rests on).
//
// MUTATION: return (false, sanctionWhyNone) from the loadSanctions error branch.
// RESULT: red — a corrupt file made a marked agent a candidate for termination.
func TestAnUnreadableRegistryIsNotAnAllClear(t *testing.T) {
	cfg := sanctionTestBox(t)
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "sanctions.json"),
		[]byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	sanctioned, why := agentSanction(obs("claude-code", "/usr/local/bin/claude", "user"))
	if !sanctioned {
		t.Error("a registry this machine could not read was reported as 'nothing is marked', " +
			"which is the answer that gets someone's work killed")
	}
	if why != sanctionWhyUnreadable {
		t.Errorf("why = %q, want the unreadable reason — a caller that renders this "+
			"must be able to tell it apart from a real vouch", why)
	}
}

// ── withdrawing a mark ──────────────────────────────────────────────────────

// A mark must be withdrawable for a program that is no longer running, or every
// record for something since uninstalled sits on the machine for ever with no
// way to reach it.
//
// MUTATION: make dropSanction return (false, nil) without deleting.
// RESULT: red — the mark was still honoured after being withdrawn.
func TestAMarkCanBeWithdrawnForSomethingNoLongerRunning(t *testing.T) {
	sanctionTestBox(t)
	a := obs("goose", "/usr/local/bin/goose", "user")
	rec, err := addSanction(a, sanctionByLocalUI)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is scanned, nothing is observed: only the id.
	dropped, err := dropSanction(rec.ID)
	if err != nil || !dropped {
		t.Fatalf("dropSanction = %v, %v — a withdrawal must not need a live process", dropped, err)
	}
	if sanctioned, _ := agentSanction(a); sanctioned {
		t.Fatal("the mark was still honoured after it was withdrawn")
	}
	// Withdrawing twice is not an error, it is simply nothing to do.
	if dropped, err := dropSanction(rec.ID); err != nil || dropped {
		t.Errorf("second dropSanction = %v, %v, want false, nil", dropped, err)
	}
}

// Marking something twice is not a new decision, so it must not rewrite when the
// first decision was made. The time is the audit fact.
//
// MUTATION: overwrite m[fp] unconditionally in addSanction.
// RESULT: red — the second click moved the recorded time.
func TestMarkingTwiceKeepsTheFirstDecisionsTime(t *testing.T) {
	sanctionTestBox(t)
	first := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	sanctionNow = func() time.Time { return first }
	t.Cleanup(func() { sanctionNow = time.Now })

	a := obs("claude-code", "/usr/local/bin/claude", "user")
	if _, err := addSanction(a, sanctionByLocalUI); err != nil {
		t.Fatal(err)
	}
	sanctionNow = func() time.Time { return first.Add(48 * time.Hour) }
	again, err := addSanction(a, sanctionByLocalUI)
	if err != nil {
		t.Fatal(err)
	}
	if !again.At.Equal(first) {
		t.Errorf("a second click moved the mark's time to %s — the first decision is "+
			"the one that was made", again.At)
	}
	recs, err := sanctionRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Errorf("marking twice left %d records, want 1", len(recs))
	}
}

// The record has to say BY WHAT MECHANISM, so a later surface writing marks is
// distinguishable from this one without anybody having to date it.
//
// MUTATION: drop the By field from the record addSanction builds.
// RESULT: red — the record could not say where it came from.
func TestTheRecordSaysByWhatMechanismItWasMade(t *testing.T) {
	sanctionTestBox(t)
	rec, err := addSanction(obs("cline", "/usr/local/bin/cline", "user"), sanctionByLocalUI)
	if err != nil {
		t.Fatal(err)
	}
	if rec.By != sanctionByLocalUI {
		t.Errorf("by = %q, want %q", rec.By, sanctionByLocalUI)
	}
	if rec.Cmdline != "/usr/local/bin/cline" {
		t.Errorf("the record does not carry what was marked: %q", rec.Cmdline)
	}
	if !strings.Contains(rec.sanctionIdentity.describe(), "cline") {
		t.Errorf("describe() does not name the program: %q", rec.sanctionIdentity.describe())
	}
}

// runtimeIsPOSIX reports whether file permission bits mean what this test
// assumes. Windows does not carry a POSIX mode, so the 0600 assertion is
// skipped there rather than asserted and quietly wrong.
func runtimeIsPOSIX() bool { return os.PathSeparator == '/' }
