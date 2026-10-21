package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Every value below is invented. Each case is a way a real config carries a
// credential on the command line; the record that leaves the machine must
// carry none of them, in any field.
func TestMCPRecordNeverCarriesASecretValue(t *testing.T) {
	cases := []struct {
		name    string
		e       mcpEntry
		secrets []string
	}{
		{"a database URL with a password", mcpEntry{command: "npx", args: []string{"-y", "@modelcontextprotocol/server-postgres", "postgresql://demo:PwDemo7731@localhost/demo"}}, []string{"PwDemo7731"}},
		{"a key in a URL query, and an Authorization header argument", mcpEntry{command: "npx", args: []string{"mcp-remote", "https://mcp.example.com/sse?api_key=QkeyDemo1234", "--header", "Authorization: Bearer HdrDemo45678"}}, []string{"QkeyDemo1234", "HdrDemo45678"}},
		{"a header given as --header=Name:value", mcpEntry{command: "npx", args: []string{"mcp-remote", "--header=X-Api-Key:HkeyDemo9999"}}, []string{"HkeyDemo9999"}},
		{"a short password after a secret flag", mcpEntry{command: "demo-srv", args: []string{"--password", "shrt1"}}, []string{"shrt1"}},
		{"a password that starts with a dollar sign", mcpEntry{command: "demo-srv", args: []string{"--password", "$DollarPw99x"}}, []string{"DollarPw99x"}},
		{"a short value in docker -e NAME=value", mcpEntry{command: "docker", args: []string{"run", "-e", "API_KEY=ab12", "demo/img"}}, []string{"ab12"}},
		{"NAME=value inside --env=", mcpEntry{command: "docker", args: []string{"run", "--env=API_TOKEN=TokDemo5678", "demo/img"}}, []string{"TokDemo5678"}},
		{"the whole command line in command", mcpEntry{command: "demo-srv --token CmdTokDemo42"}, []string{"CmdTokDemo42"}},
		{"a git URL with a password", mcpEntry{command: "uvx", args: []string{"--from", "git+https://demo:GitPwDemo31@git.example.com/o/r", "demo"}}, []string{"GitPwDemo31"}},
		{"a git URL with a token as the user", mcpEntry{command: "npx", args: []string{"-y", "git+https://GitUserTok55@git.example.com/o/r"}}, []string{"GitUserTok55"}},
		{"a token in a URL path", mcpEntry{command: "npx", args: []string{"mcp-remote", "https://hooks.example.com/api/s/PathTokDemo8812/sse"}}, []string{"PathTokDemo8812"}},
	}
	for _, c := range cases {
		b, _ := json.Marshal(mcpAnalyze(c.e))
		for _, s := range c.secrets {
			if strings.Contains(string(b), s) {
				t.Errorf("%s: the record carries %q: %s", c.name, s, b)
			}
		}
	}
	// A running server no file declares goes through the same redaction.
	out := correlateMCP(nil, []mcpProc{{PID: 7, PPID: 1, Argv: []string{"node", "/opt/demo/mcp-server.js",
		"postgresql://demo:ShadowPw77x@db.example.com/x"}}}, true)
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "ShadowPw77x") {
		t.Errorf("an undeclared server's record carries its password: %s", b)
	}
	// What is still kept: a reference to where the secret comes from, and
	// the URL's host.
	o := mcpAnalyze(mcpEntry{command: "demo-srv", args: []string{"--token", "${DEMO_TOKEN}", "https://mcp.example.com/sse"}})
	if !strings.Contains(o.Command, "${DEMO_TOKEN}") || !strings.Contains(o.Command, "https://mcp.example.com") {
		t.Errorf("redaction took more than the secret: %q", o.Command)
	}
}

// One record, and the list, stay bounded however large the file's names are
// and however many processes look like servers.
func TestMCPRecordAndListStayBounded(t *testing.T) {
	env := map[string]string{}
	for i := 0; i < 5000; i++ {
		env[fmt.Sprintf("DEMO_VAR_%04d_%s", i, strings.Repeat("x", 200))] = ""
	}
	o := mcpAnalyze(mcpEntry{name: strings.Repeat("n", 100000), command: "npx",
		args: []string{"-y", strings.Repeat("p", 100000)}, env: env})
	if b, _ := json.Marshal(o); len(b) > 8192 {
		t.Errorf("one stdio record is %d bytes", len(b))
	}
	o = mcpAnalyze(mcpEntry{name: "r", url: "https://" + strings.Repeat("a", 100000) + ".example.com/x"})
	if b, _ := json.Marshal(o); len(b) > 8192 {
		t.Errorf("one remote record is %d bytes", len(b))
	}
	var procs []mcpProc
	for i := 0; i < 3000; i++ {
		procs = append(procs, mcpProc{PID: 10 + i, PPID: 1, Argv: []string{"demo-mcp-server"}})
	}
	if out := correlateMCP(nil, procs, true); len(out) > mcpMaxServers {
		t.Errorf("%d records from undeclared servers; the list is capped at %d", len(out), mcpMaxServers)
	}
}

// A crafted config.toml nested thousands deep is refused, not walked on the
// stack; a realistic depth still parses.
func TestParseTOMLSubsetRefusesDeepNesting(t *testing.T) {
	for name, src := range map[string]string{
		"arrays":        "a = " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n",
		"inline tables": "a = " + strings.Repeat("{b = ", 5000) + "1" + strings.Repeat("}", 5000) + "\n",
	} {
		if _, err := parseTOMLSubset(src); err == nil {
			t.Errorf("%s nested 5000 deep parsed", name)
		}
	}
	if _, err := parseTOMLSubset("[mcp_servers.x]\nenv = { A = { B = [[1, 2], [3]] } }\n"); err != nil {
		t.Errorf("a realistic depth: %v", err)
	}
}

// macOS's nobody is uid -2 in its directory; it is a service account, not
// an unread uid.
func TestClassifyUnixOwnerNegativeDirectoryUID(t *testing.T) {
	f := classifyUnixOwner(unixOwner{UID: -2, Name: "nobody", SystemUIDMax: darwinSystemUIDMax, LocalRecord: ownerYes})
	if f.Class != ownerClassService {
		t.Errorf("uid -2: %+v", f)
	}
	if f := classifyUnixOwner(unixOwner{UID: -1, Name: "demo"}); f.Class != ownerUnknown {
		t.Errorf("an unread uid: %+v", f)
	}
}

// dscl that was killed by the timeout has not said the record is missing:
// only a real non-zero exit does.
func TestDsclRecordMissingOnlyOnARealExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	_, killed := exec.Command("sh", "-c", "kill -9 $$").Output()
	_, missing := exec.Command("sh", "-c", "exit 56").Output()
	if dsclRecordMissing(killed) {
		t.Error("a killed dscl read as no local record")
	}
	if !dsclRecordMissing(missing) {
		t.Error("dscl exiting 56 did not read as no local record")
	}
	if dsclRecordMissing(nil) {
		t.Error("success read as no local record")
	}
}

// A read that stops answering (a home on a network mount) holds neither the
// beat nor a second reader, and a finished read is reused for the cache
// window instead of redone on every 60-second beat.
func TestMCPServersReportNeverWaitsOnAStuckRead(t *testing.T) {
	oldH, oldS, oldP, oldT := mcpHomesFn, mcpSystemFn, scanMCPProcessesFn, mcpReadTimeout
	block := make(chan struct{})
	t.Cleanup(func() {
		close(block)
		mcpHomesFn, mcpSystemFn, scanMCPProcessesFn, mcpReadTimeout = oldH, oldS, oldP, oldT
		resetMCPConfigCache()
	})
	resetMCPConfigCache()
	var calls int32
	mcpHomesFn = func() ([]mcpHome, bool) {
		atomic.AddInt32(&calls, 1)
		<-block
		return nil, true
	}
	mcpSystemFn = func() []mcpSource { return nil }
	scanMCPProcessesFn = func(map[string]bool) ([]mcpProc, error) { return nil, nil }
	mcpReadTimeout = 100 * time.Millisecond

	for beat := 0; beat < 3; beat++ {
		done := make(chan mcpConfigScan, 1)
		go func() { _, s := mcpServersReport(); done <- s }()
		select {
		case s := <-done:
			if !s.TimedOut || !s.Supported {
				t.Fatalf("beat %d: a read that has not finished must say so: %+v", beat, s)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("beat %d waited on a stuck read", beat)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("%d reads started while one was stuck", n)
	}

	resetMCPConfigCache()
	atomic.StoreInt32(&calls, 0)
	home := t.TempDir()
	mcpHomesFn = func() ([]mcpHome, bool) {
		atomic.AddInt32(&calls, 1)
		return []mcpHome{{Dir: home, ConfigDir: home}}, true
	}
	for beat := 0; beat < 3; beat++ {
		if _, s := mcpServersReport(); s.TimedOut {
			t.Fatalf("beat %d timed out: %+v", beat, s)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("the files were read %d times in one cache window", n)
	}
}

// A read stuck on a home that stopped answering delays ONE beat by at most
// mcpReadTimeout; the beats after it do not wait on the same read again. And
// until a read has finished, nothing is known to be declared, so no running
// process may be reported as running_not_declared.
func TestMCPStuckReadDelaysOneBeatAndClaimsNoShadows(t *testing.T) {
	oldH, oldS, oldP, oldT := mcpHomesFn, mcpSystemFn, scanMCPProcessesFn, mcpReadTimeout
	block := make(chan struct{})
	t.Cleanup(func() {
		close(block)
		mcpHomesFn, mcpSystemFn, scanMCPProcessesFn, mcpReadTimeout = oldH, oldS, oldP, oldT
		resetMCPConfigCache()
	})
	resetMCPConfigCache()
	mcpHomesFn = func() ([]mcpHome, bool) { <-block; return nil, true }
	mcpSystemFn = func() []mcpSource { return nil }
	scanMCPProcessesFn = func(map[string]bool) ([]mcpProc, error) {
		return []mcpProc{{PID: 4242, PPID: 1, Argv: []string{"demo-mcp-server", "--stdio"}}}, nil
	}
	mcpReadTimeout = 400 * time.Millisecond

	start := time.Now()
	out, s := mcpServersReport()
	if took := time.Since(start); took < mcpReadTimeout/2 {
		t.Fatalf("the first beat did not wait for the read at all (%v)", took)
	}
	if !s.TimedOut || len(out) != 0 {
		t.Fatalf("before any read finished: timed_out %v, servers %+v", s.TimedOut, out)
	}
	for beat := 1; beat < 4; beat++ {
		start := time.Now()
		out, s := mcpServersReport()
		if took := time.Since(start); took > mcpReadTimeout/2 {
			t.Fatalf("beat %d waited %v on a read an earlier beat already waited out", beat, took)
		}
		if !s.TimedOut || len(out) != 0 {
			t.Fatalf("beat %d: timed_out %v, servers %+v", beat, s.TimedOut, out)
		}
	}
}
