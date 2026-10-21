package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SCHEDULER INVENTORY, the first phase of the agent-detection plane.
// The standing jobs on this box — crontabs, systemd timers, launchd jobs, the
// Windows Task Scheduler — that would run an agent or an automation. A job is
// inventoried BEFORE it fires, so the "it has been running every night for
// months" shape is visible from the schedule, not only from a lucky beat.
//
// Only entries whose command matches the agent/automation tables travel;
// everything else on the box is the user's business. What always travels is
// the SCAN: which scheduler kinds were read and how many entries they held,
// so an empty list from a box that read forty crontabs is a different
// sentence from an empty list from a box that could read none.
//
// Pure parsers live here with no build tag; each platform supplies only the
// file reads and the shell-outs (schedulers_<goos>.go), like the observe
// plane's own split.

type schedEntry struct {
	Kind       string `json:"kind"`               // cron | systemd-timer | launchd | task-scheduler
	Name       string `json:"name"`               // file:line, unit, label, task path
	Command    string `json:"command"`            // the command as written, truncated
	Schedule   string `json:"schedule,omitempty"` // the clock spec as written
	User       string `json:"user,omitempty"`
	Signature  string `json:"signature"`            // which table matched
	Automation bool   `json:"automation,omitempty"` // matched the automation table, not the agent table
}

type schedScanReport struct {
	Supported bool     `json:"supported"`
	Kinds     []string `json:"kinds"`   // scheduler kinds this scan could read
	Entries   int      `json:"entries"` // total entries read, matched or not
}

// classifySchedCommand decides whether a scheduled command would run an
// agent or an automation. The command is a shell line, so the rule is
// applied to every token that could be a program: after `env` assignments,
// after `cd x &&`, after `sh -c` — the first token of each `&&`/`;`/`|`
// segment, with the whole segment as the argv for the interpreter rule.
func classifySchedCommand(cmd string) (sig string, automation bool, ok bool) {
	for _, seg := range splitShellSegments(cmd) {
		argv := shellFields(seg)
		// drop leading VAR=value assignments and sudo/nohup/timeout wrappers
		for len(argv) > 0 {
			t := argv[0]
			if k, _, has := strings.Cut(t, "="); has && isEnvKey(k) {
				argv = argv[1:]
				continue
			}
			base := binBase(t)
			if base == "sudo" || base == "nohup" || base == "env" || base == "exec" || base == "timeout" || base == "flock" || base == "chronic" || base == "&" {
				argv = argv[1:]
				// skip that wrapper's own flags/args that are not the command;
				// -u/-k/-s take a value (sudo -u deploy, timeout -k 5, timeout -s TERM)
				for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
					flag := argv[0]
					argv = argv[1:]
					if (flag == "-u" || flag == "-k" || flag == "-s") && len(argv) > 0 {
						argv = argv[1:]
					}
				}
				if base == "timeout" || base == "flock" {
					if len(argv) > 0 {
						argv = argv[1:] // the duration / the lock file
					}
				}
				continue
			}
			break
		}
		if len(argv) == 0 {
			continue
		}
		// `sh -c "..."`, `bash -lc "..."`, `powershell -NoProfile -Command "..."`:
		// the real command is the first non-flag argument, itself a shell line.
		if b := binBase(argv[0]); b == "sh" || b == "bash" || b == "zsh" || b == "dash" || b == "cmd" || b == "powershell" || b == "pwsh" {
			for _, a := range argv[1:] {
				if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "/") && b == "cmd" {
					continue
				}
				if s, au, ok := classifySchedCommand(a); ok {
					return s, au, true
				}
				break
			}
		}
		if s, a, ok := matchSignature(argv); ok {
			return s, a, true
		}
	}
	return "", false, false
}

// isEnvKey: the left side of a `KEY=value` prefix is an identifier, so
// `HOME=/root` is an assignment and `--model=gpt` or `a/b=c` is not.
func isEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, c := range k {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// shellFields splits one segment into words, honouring single and double
// quotes (the quotes themselves are dropped), so a quoted Windows path with
// spaces stays one argv[0].
func shellFields(s string) []string {
	out := []string{}
	cur := strings.Builder{}
	var quote byte
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
			inWord = true
		case ' ', '\t', '\n':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

// splitShellSegments splits a shell line on && ; | || outside quotes.
func splitShellSegments(s string) []string {
	out := []string{}
	cur := strings.Builder{}
	var quote byte
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
			cur.WriteByte(c)
		case ';', '|':
			flush()
		case '&':
			if i+1 < len(s) && s[i+1] == '&' {
				i++
			}
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// ── cron ────────────────────────────────────────────────────────────────────

// parseCrontab reads one crontab. system=true is the /etc/crontab and
// /etc/cron.d format (five time fields, a user, then the command); false is a
// user's own crontab (no user column). `@reboot`-style specs are one field.
// Every entry is returned; the caller matches. name carries file:line.
func parseCrontab(text, file, user string, system bool) []schedEntry {
	out := []schedEntry{}
	for i, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if k, _, ok := strings.Cut(t, "="); ok && !strings.ContainsAny(k, " \t") && !strings.HasPrefix(t, "@") && !startsWithCronField(t) {
			continue // VAR=value line
		}
		f := strings.Fields(t)
		var schedFields int
		if strings.HasPrefix(t, "@") {
			schedFields = 1
		} else {
			schedFields = 5
		}
		need := schedFields + 1
		u := user
		if system {
			need++
		}
		if len(f) < need {
			continue
		}
		schedule := strings.Join(f[:schedFields], " ")
		rest := f[schedFields:]
		if system {
			u = rest[0]
			rest = rest[1:]
		}
		cmd := strings.Join(rest, " ")
		out = append(out, schedEntry{Kind: "cron", Name: file + ":" + strconv.Itoa(i+1), Command: truncate(cmd, 200),
			Schedule: schedule, User: u})
	}
	return out
}

func startsWithCronField(t string) bool {
	if t == "" {
		return false
	}
	c := t[0]
	return c == '*' || (c >= '0' && c <= '9')
}

// ── systemd timers ──────────────────────────────────────────────────────────

// parseSystemdTimers reads `systemctl list-timers --all --no-legend --plain`:
// the last two columns are UNIT and ACTIVATES. Returns activated unit ->
// timer unit.
func parseSystemdTimers(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		unit, activates := f[len(f)-2], f[len(f)-1]
		if !strings.HasSuffix(unit, ".timer") {
			continue
		}
		m[activates] = unit
	}
	return m
}

// parseExecStart pulls the argv out of `systemctl show -p ExecStart --value`:
// `{ path=/usr/bin/x ; argv[]=/usr/bin/x --flag ; ignore_errors=no ; ... }`.
// Several ExecStart lines come back one per `{ }` block; the first is enough.
func parseExecStart(v string) string {
	i := strings.Index(v, "argv[]=")
	if i < 0 {
		return strings.TrimSpace(v)
	}
	rest := v[i+len("argv[]="):]
	if j := strings.Index(rest, " ; "); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// ── launchd ─────────────────────────────────────────────────────────────────

// launchdJob is the subset of a LaunchAgent/LaunchDaemon plist that says what
// runs and on what clock, as `plutil -convert json` renders it.
type launchdJob struct {
	Label                 string            `json:"Label"`
	Program               string            `json:"Program"`
	ProgramArguments      []string          `json:"ProgramArguments"`
	StartInterval         json.Number       `json:"StartInterval"`
	StartCalendarInterval json.RawMessage   `json:"StartCalendarInterval"`
	RunAtLoad             bool              `json:"RunAtLoad"`
	KeepAlive             json.RawMessage   `json:"KeepAlive"`
	UserName              string            `json:"UserName"`
	WatchPaths            []string          `json:"WatchPaths"`
	EnvironmentVariables  map[string]string `json:"EnvironmentVariables"`
}

// parseLaunchdPlistJSON turns one plist (as JSON) into an entry. A plist with
// no program is skipped. The schedule string names what would start it.
func parseLaunchdPlistJSON(data []byte, file string) (schedEntry, bool) {
	var j launchdJob
	if err := json.Unmarshal(data, &j); err != nil {
		return schedEntry{}, false
	}
	cmd := strings.Join(j.ProgramArguments, " ")
	if cmd == "" {
		cmd = j.Program
	}
	if cmd == "" {
		return schedEntry{}, false
	}
	parts := []string{}
	if s := j.StartInterval.String(); s != "" && s != "0" {
		parts = append(parts, "every "+s+"s")
	}
	if len(j.StartCalendarInterval) > 0 && string(j.StartCalendarInterval) != "null" {
		parts = append(parts, "calendar")
	}
	if j.RunAtLoad {
		parts = append(parts, "at load")
	}
	if len(j.KeepAlive) > 0 && string(j.KeepAlive) != "null" && string(j.KeepAlive) != "false" {
		parts = append(parts, "keep alive")
	}
	if len(j.WatchPaths) > 0 {
		parts = append(parts, "watch paths")
	}
	name := j.Label
	if name == "" {
		name = file
	}
	return schedEntry{Kind: "launchd", Name: name, Command: truncate(cmd, 200),
		Schedule: strings.Join(parts, ", "), User: j.UserName}, true
}

// ── Windows Task Scheduler ──────────────────────────────────────────────────

// winTask is the shape schedulers_windows.go asks PowerShell to emit per task.
type winTask struct {
	Name     string   `json:"n"`
	Path     string   `json:"p"`
	User     string   `json:"u"`
	Actions  []string `json:"a"` // each `"<Execute>" <Arguments>` — the script quotes Execute
	Triggers []string `json:"t"`
	State    string   `json:"s"`
}

// parseWinTasksJSON decodes the task list. PowerShell's ConvertTo-Json emits
// a bare object for a single result and an array otherwise; both are read.
func parseWinTasksJSON(data []byte) []schedEntry {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil
	}
	var tasks []winTask
	if data[0] == '{' {
		var one winTask
		if err := json.Unmarshal(data, &one); err != nil {
			return nil
		}
		tasks = []winTask{one}
	} else if err := json.Unmarshal(data, &tasks); err != nil {
		return nil
	}
	out := []schedEntry{}
	for _, t := range tasks {
		for _, a := range t.Actions {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			trig := strings.Join(t.Triggers, ", ")
			out = append(out, schedEntry{Kind: "task-scheduler", Name: t.Path + t.Name,
				Command: truncate(a, 200), Schedule: strings.TrimPrefix(trig, "MSFT_Task"), User: t.User})
		}
	}
	return out
}

// matchScheduled keeps only entries that would run an agent or automation,
// filling the signature, and reports the scan. Sorted for a stable wire.
func matchScheduled(all []schedEntry, kinds []string, supported bool) ([]schedEntry, schedScanReport) {
	out := []schedEntry{}
	for _, e := range all {
		sig, auto, ok := classifySchedCommand(e.Command)
		if !ok {
			continue
		}
		e.Signature, e.Automation = sig, auto
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	if kinds == nil {
		kinds = []string{}
	}
	return out, schedScanReport{Supported: supported, Kinds: kinds, Entries: len(all)}
}

// schedCmdTimeout bounds every shell-out the origin walk and the scheduler
// inventory make. They sit on the heartbeat goroutine (run.go beat()), and
// systemctl talks to PID 1 over D-Bus, PowerShell's CIM queries talk to WMI:
// a wedged daemon must cost one beat a few seconds, never every beat forever
// — a box that stops beating never fetches a contain directive.
const schedCmdTimeout = 8 * time.Second

// runTimed is exec.Command(...).Output() under schedCmdTimeout.
//
// Both Windows heartbeat probes go through here (schedulers_windows.go,
// origin_windows.go), so hideConsole on this one line is what stops the pair of
// PowerShell windows flashing on screen every ten minutes. console_windows.go
// has the whole story.
func runTimed(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), schedCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd)
	return cmd.Output()
}

// schedCache: the inventory is files and shell-outs, and the heartbeat is
// every 60 s. Ten minutes is the same cadence the managed local agent
// reconciles on; a new crontab shows within that.
var schedCache = struct {
	sync.Mutex
	at      time.Time
	entries []schedEntry
	scan    schedScanReport
}{}

const schedCacheFor = 10 * time.Minute

// scanSchedulers is the heartbeat's entry point: the platform inventory,
// matched against the tables, cached.
func scanSchedulers() ([]schedEntry, schedScanReport) {
	schedCache.Lock()
	defer schedCache.Unlock()
	if !schedCache.at.IsZero() && time.Since(schedCache.at) < schedCacheFor {
		return schedCache.entries, schedCache.scan
	}
	all, kinds, supported := platformSchedulers()
	entries, scan := matchScheduled(all, kinds, supported)
	schedCache.at, schedCache.entries, schedCache.scan = time.Now(), entries, scan
	return entries, scan
}
