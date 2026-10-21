package main

import (
	"strings"
	"testing"
)

func TestClassifySchedCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		sig  string
		auto bool
		ok   bool
	}{
		{"claude -p 'summarise inbox' >> /var/log/x", "claude-code", false, true},
		{"cd /srv/app && /usr/local/bin/aider --yes", "aider", false, true},
		{"HOME=/root PATH=/usr/bin:/bin python3 /opt/bot/run.py", "", false, false},
		{"HOME=/root nohup node /opt/x/node_modules/@openai/codex/bin/codex.js", "codex", false, true},
		{"/bin/sh -c \"cd /home/u && codex exec nightly\"", "codex", false, true},
		{"timeout 3600 /usr/bin/goose run", "goose", false, true},
		{"flock -n /tmp/l xdotool key ctrl+r", "xdotool", true, true},
		{"/usr/bin/python3 -m playwright codegen", "playwright", true, true},
		{"echo claude-code is great | mail -s hi root", "", false, false},
		{"/usr/bin/backup.sh --full", "", false, false},
		{"", "", false, false},
		{`"C:\Program Files\nodejs\node.exe" C:\Users\u\AppData\npm\@anthropic-ai\claude-code\cli.js -p go`, "claude-code", false, true},
		{`powershell.exe -NoProfile -Command "& 'C:\tools\chromedriver.exe' --port=9515"`, "chromedriver", true, true},
	}
	for _, c := range cases {
		sig, auto, ok := classifySchedCommand(c.cmd)
		if ok != c.ok || sig != c.sig || auto != c.auto {
			t.Errorf("classifySchedCommand(%q) = (%q,%v,%v), want (%q,%v,%v)", c.cmd, sig, auto, ok, c.sig, c.auto, c.ok)
		}
	}
}

func TestSplitShellSegments(t *testing.T) {
	got := splitShellSegments(`cd /x && echo "a && b" ; claude -p 'y | z' || true`)
	want := []string{"cd /x", `echo "a && b"`, `claude -p 'y | z'`, "true"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("splitShellSegments = %q, want %q", got, want)
	}
}

func TestParseCrontab(t *testing.T) {
	system := `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
0 2 * * *   deploy  claude -p "nightly report" >> /var/log/nightly.log 2>&1
@reboot     root    /usr/local/bin/xdotool key super
`
	got := parseCrontab(system, "/etc/crontab", "", true)
	if len(got) != 3 {
		t.Fatalf("system crontab: %d entries, want 3: %+v", len(got), got)
	}
	if got[1].User != "deploy" || got[1].Schedule != "0 2 * * *" || !strings.HasPrefix(got[1].Command, "claude -p") || got[1].Name != "/etc/crontab:5" {
		t.Errorf("system entry = %+v", got[1])
	}
	if got[2].Schedule != "@reboot" || got[2].User != "root" || got[2].Command != "/usr/local/bin/xdotool key super" {
		t.Errorf("@reboot entry = %+v", got[2])
	}
	user := `MAILTO=""
*/5 * * * * /home/u/bin/sync.sh
30 3 * * 1-5 cd /home/u/proj && aider --message "tidy" --yes
`
	got = parseCrontab(user, "/var/spool/cron/crontabs/u", "u", false)
	if len(got) != 2 || got[1].User != "u" || got[1].Schedule != "30 3 * * 1-5" || !strings.Contains(got[1].Command, "aider") {
		t.Errorf("user crontab = %+v", got)
	}
	matched, scan := matchScheduled(append(parseCrontab(system, "/etc/crontab", "", true), got...), []string{"cron"}, true)
	if scan.Entries != 5 || len(matched) != 3 {
		t.Errorf("matchScheduled: %d matched of %d, want 3 of 5: %+v", len(matched), scan.Entries, matched)
	}
	for _, m := range matched {
		if m.Signature == "" {
			t.Errorf("matched entry without signature: %+v", m)
		}
	}
}

func TestParseSystemdTimersAndExecStart(t *testing.T) {
	out := `Sat 2026-09-06 23:00:00 UTC 3h left     Fri 2026-09-05 23:00:00 UTC 21h ago     nightly-agent.timer     nightly-agent.service
Sun 2026-09-07 00:00:00 UTC 4h left     Sat 2026-09-06 00:00:00 UTC 20h ago     logrotate.timer         logrotate.service
-                                       -                                       stale.timer             stale.service
`
	m := parseSystemdTimers(out)
	if m["nightly-agent.service"] != "nightly-agent.timer" || m["logrotate.service"] != "logrotate.timer" || m["stale.service"] != "stale.timer" {
		t.Errorf("parseSystemdTimers = %v", m)
	}
	es := `{ path=/usr/local/bin/claude ; argv[]=/usr/local/bin/claude -p nightly --output-format json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`
	if got := parseExecStart(es); got != "/usr/local/bin/claude -p nightly --output-format json" {
		t.Errorf("parseExecStart = %q", got)
	}
	if got := parseExecStart("/usr/bin/true"); got != "/usr/bin/true" {
		t.Errorf("parseExecStart(plain) = %q", got)
	}
}

func TestParseLaunchdPlistJSON(t *testing.T) {
	j := `{"Label":"com.example.nightly","ProgramArguments":["/usr/local/bin/python3","/Users/u/bot/run.py"],"StartCalendarInterval":{"Hour":2,"Minute":0},"RunAtLoad":false}`
	e, ok := parseLaunchdPlistJSON([]byte(j), "/Users/u/Library/LaunchAgents/com.example.nightly.plist")
	if !ok || e.Name != "com.example.nightly" || e.Command != "/usr/local/bin/python3 /Users/u/bot/run.py" || e.Schedule != "calendar" {
		t.Errorf("launchd calendar = %+v %v", e, ok)
	}
	j = `{"Label":"com.example.keep","Program":"/opt/agent/goose","KeepAlive":true,"RunAtLoad":true,"StartInterval":300}`
	e, ok = parseLaunchdPlistJSON([]byte(j), "x.plist")
	if !ok || e.Command != "/opt/agent/goose" || e.Schedule != "every 300s, at load, keep alive" {
		t.Errorf("launchd keepalive = %+v %v", e, ok)
	}
	if _, ok := parseLaunchdPlistJSON([]byte(`{"Label":"noprog"}`), "y.plist"); ok {
		t.Error("plist without a program must be skipped")
	}
	if _, ok := parseLaunchdPlistJSON([]byte(`not json`), "z.plist"); ok {
		t.Error("bad json must be skipped")
	}
}

func TestParseWinTasksJSON(t *testing.T) {
	many := `[{"n":"NightlyAgent","p":"\\Custom\\","u":"DESKTOP\\user","s":"Ready","a":["\"C:\\Program Files\\nodejs\\node.exe\" C:\\Users\\user\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js -p go"],"t":["MSFT_TaskDailyTrigger"]},{"n":"OneDrive Update","p":"\\","u":"S-1-5-18","s":"Ready","a":["\"%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe\""],"t":["MSFT_TaskTimeTrigger","MSFT_TaskLogonTrigger"]}]`
	got := parseWinTasksJSON([]byte(many))
	if len(got) != 2 || got[0].Name != `\Custom\NightlyAgent` || got[0].Schedule != "DailyTrigger" || got[0].User != `DESKTOP\user` {
		t.Errorf("many = %+v", got)
	}
	matched, scan := matchScheduled(got, []string{"task-scheduler"}, true)
	if scan.Entries != 2 || len(matched) != 1 || matched[0].Signature != "claude-code" {
		t.Errorf("matched = %+v scan = %+v", matched, scan)
	}
	one := `{"n":"Solo","p":"\\","u":"u","s":"Ready","a":["\"chromedriver.exe\" --port=9515"],"t":[]}`
	got = parseWinTasksJSON([]byte(one))
	if len(got) != 1 || got[0].Command != "\"chromedriver.exe\" --port=9515" {
		t.Errorf("one = %+v", got)
	}
	if got := parseWinTasksJSON([]byte("   ")); got != nil {
		t.Errorf("empty = %+v", got)
	}
}
