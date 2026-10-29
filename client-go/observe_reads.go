package main

// observe:folders / observe:journal / observe:logins / observe:cert — four
// questions people ask about a machine, answered by the machine.
//
// Each was a command a host could only hand to the person: du to find what
// fills a disk, journalctl -u for one service's log, the sshd lines for who
// has been trying to log in, a TLS client for the certificate a port serves.
// observe:logs reads a Loki, which most machines do not run, so a host with
// only this lane could not read one unit's log at all and asked the person to
// run journalctl instead. These four answer it here, read-only, the way the
// rest of the family does.
//
// They are the first ops in the family whose caller value is more than a name
// from a table, so the whole grammar of each is written down here and checked
// before anything is read or run:
//
//   - observe:folders <absolute path> [depth 1-3]. The path never reaches a
//     program: the sizing is a Go walk (observe_reads_linux.go).
//   - observe:journal <unit> [minutes 1-60]. The unit reaches journalctl's
//     argv, bound to its flag as --unit=, only after systemd's own unit-name
//     alphabet is checked AND only when this machine's unit list names it. A
//     value that fails either is refused before journalctl runs.
//   - observe:logins [hours 1-168]. A number in a fixed argv.
//   - observe:cert <port> [server name]. The port must be a TCP listener ss
//     reports on this machine, and the handshake goes only to loopback or to
//     one of this machine's own addresses that listener is bound to. The name
//     goes into the TLS hello, never to a program.
//
// A refusal never repeats a value that failed its check; it says which rule
// the value broke. Off Linux each op checks its arguments the same way and
// then answers {"unsupported": goos}, like the rest of the family.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

// refuseObserveArgs is the answer to arguments an op will not take: the reason
// on stderr and exit 2, the code observe:net and observe:logs have always used
// for a bad argument. 126 stays "not permitted": the op was allowed, the value
// was not.
func refuseObserveArgs(ws *websocket.Conn, msg string) {
	sendMgmt(ws, 'R', []byte(msg+"\n"))
	sendMgmtExit(ws, 2)
}

// parseBoundedInt reads one whole number in [lo, hi]. Out of range is REFUSED
// rather than clamped, for the reason parseLogMinutes gives: a host that asked
// for a week and silently got a day would draw a conclusion about the week.
func parseBoundedInt(s, what string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, errors.New(what + " must be a whole number")
	}
	if n < lo || n > hi {
		return 0, errors.New(what + " must be between " + strconv.Itoa(lo) + " and " + strconv.Itoa(hi))
	}
	return n, nil
}

// ── observe:folders ──────────────────────────────────────────────────────────

const (
	folderDepthDefault = 2
	folderDepthMax     = 3
	// folderTopN is how many folders the answer names. A person looking for
	// what fills a disk reads the first handful; 25 is room for the nested
	// chain (/var, /var/lib, /var/lib/docker) and the siblings beside it.
	folderTopN = 25
	// folderSkipCap bounds the skipped list. Skips are folded to the reported
	// depth first (folderAt), so a k8s node's hundreds of volume mounts read
	// as one row with a count, and 25 rows is past what that folding leaves.
	folderSkipCap = 25
	// folderSkipKeys bounds the map the skips are folded in, so a tree of
	// unreadable folders cannot grow it without bound; past it they are
	// still counted in skipped_total.
	folderSkipKeys = 1000
	// folderPathMax is PATH_MAX.
	folderPathMax = 4096
)

// folderRefusedRoots hold no files on any disk: they are the kernel's views
// of processes, devices and itself. Sizing them answers nothing about what
// fills a disk, and walking /proc on a busy box is millions of entries.
var folderRefusedRoots = []string{"/proc", "/sys", "/dev"}

const errFolderKernelTree = "/proc, /sys and /dev are not folders on a disk; ask about a folder elsewhere"

// reasonOtherFS is the skip reason for a filesystem mounted under the path,
// which the walk does not enter (du -x).
const reasonOtherFS = "another filesystem, not counted"

// checkFolderPath is the whole grammar of observe:folders' path. An absolute
// path only: a relative one would be relative to wherever the bastion was
// started, which the host cannot see. No ".." anywhere, not even inside a
// name: there is no folder a person asks about that needs one, and refusing
// the substring is a rule nobody has to reason about. No control characters,
// which no folder a person names contains and which would break a reader's
// line of output.
func checkFolderPath(p string) (string, error) {
	switch {
	case p == "":
		return "", errors.New("a folder path is required")
	case len(p) > folderPathMax:
		return "", errors.New("a folder path is at most " + strconv.Itoa(folderPathMax) + " bytes")
	case !utf8.ValidString(p):
		return "", errors.New("a folder path must be valid UTF-8")
	case !strings.HasPrefix(p, "/"):
		return "", errors.New("a folder path must be absolute (start with /)")
	case strings.Contains(p, ".."):
		return "", errors.New("a folder path cannot contain '..'")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("a folder path cannot contain control characters")
		}
	}
	// path, not filepath: these are Linux paths on every build, and the
	// Windows filepath.Clean would turn the slashes round.
	clean := path.Clean(p)
	if err := folderPathAllowed(clean); err != nil {
		return "", err
	}
	return clean, nil
}

// folderPathAllowed is asked twice: of the path as asked, and of where its
// symlinks lead (readFolders), so a link into /proc is refused like /proc.
func folderPathAllowed(clean string) error {
	for _, r := range folderRefusedRoots {
		if clean == r || strings.HasPrefix(clean, r+"/") {
			return errors.New(errFolderKernelTree)
		}
	}
	return nil
}

func parseFolderArgs(args []string) (string, int, error) {
	p, err := checkFolderPath(args[0])
	if err != nil {
		return "", 0, err
	}
	depth := folderDepthDefault
	if len(args) > 1 {
		if depth, err = parseBoundedInt(args[1], "depth", 1, folderDepthMax); err != nil {
			return "", 0, err
		}
	}
	return p, depth, nil
}

// folderSize is one folder's disk use: allocated blocks, as du reports it,
// which is what fills a disk (a sparse file's apparent size does not).
type folderSize struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	Depth int    `json:"depth"`
}

// folderSkip is a folder that holds something the walk could not size, at
// most the asked depth below the path, with how many such things it holds.
type folderSkip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type foldersReport struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Path      string `json:"path"`
	// Resolved is where the path's symlinks led, when that is elsewhere. Every
	// folder below is named under it.
	Resolved   string       `json:"resolved,omitempty"`
	Depth      int          `json:"depth"`
	TotalBytes int64        `json:"total_bytes"`
	Folders    []folderSize `json:"folders"`
	// Sized is how many folders down to the depth were sized; Folders is the
	// largest folderTopN of them.
	Sized        int          `json:"folders_sized"`
	Skipped      []folderSkip `json:"skipped"`
	SkippedTotal int          `json:"skipped_total"`
	// Complete is false when the op budget ran out mid-walk. Every size is
	// then a lower bound, and a folder the walk never reached is missing.
	Complete bool   `json:"complete"`
	Partial  string `json:"partial,omitempty"`
	Note     string `json:"note,omitempty"`
}

// folderTop keeps the largest folderTopN folders offered to it. The walk
// offers every folder down to the depth, and a deep tree has tens of thousands
// of them; holding 25 is the bound.
type folderTop struct{ rows []folderSize }

// folderLess orders by size, then by path backwards, so equal sizes come out
// in path order and two walks of an unchanged tree give the same list.
func folderLess(a, b folderSize) bool {
	if a.Bytes != b.Bytes {
		return a.Bytes < b.Bytes
	}
	return a.Path > b.Path
}

func (t *folderTop) offer(f folderSize) {
	if len(t.rows) < folderTopN {
		t.rows = append(t.rows, f)
		return
	}
	least := 0
	for i := range t.rows {
		if folderLess(t.rows[i], t.rows[least]) {
			least = i
		}
	}
	if folderLess(t.rows[least], f) {
		t.rows[least] = f
	}
}

func (t *folderTop) sorted() []folderSize {
	out := append([]folderSize{}, t.rows...)
	sort.Slice(out, func(i, j int) bool { return folderLess(out[j], out[i]) })
	return out
}

// folderAt is the folder that names p in the answer: p itself when it is at
// most depth below root, else its ancestor at depth. The op promises folders
// down to the asked depth and nothing deeper, and a skip deep in a tree is
// reported against the folder the person can see.
func folderAt(root, p string, depth int) string {
	var rel string
	switch {
	case p == root:
		return p
	case root == "/":
		rel = strings.TrimPrefix(p, "/")
	default:
		rel = strings.TrimPrefix(p, root+"/")
	}
	parts := strings.Split(rel, "/")
	if len(parts) <= depth {
		return p
	}
	if root == "/" {
		return "/" + strings.Join(parts[:depth], "/")
	}
	return root + "/" + strings.Join(parts[:depth], "/")
}

// folderSkips folds what the walk could not size by (folder, reason).
type folderSkips struct {
	by    map[[2]string]int
	total int
}

func (s *folderSkips) add(at, reason string) {
	s.total++
	if s.by == nil {
		s.by = map[[2]string]int{}
	}
	k := [2]string{at, reason}
	if _, ok := s.by[k]; ok || len(s.by) < folderSkipKeys {
		s.by[k]++
	}
}

func (s *folderSkips) list() []folderSkip {
	out := make([]folderSkip, 0, len(s.by))
	for k, n := range s.by {
		out = append(out, folderSkip{Path: k[0], Reason: k[1], Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Reason < out[j].Reason
	})
	if len(out) > folderSkipCap {
		out = out[:folderSkipCap]
	}
	return out
}

// parseMountPoints reads /proc/self/mountinfo into the set of mount points.
// The walk does not cross them (du -x), and it knows them BEFORE it stats a
// name, so a dead network or FUSE mount under the path is never touched: a
// stat of its root is the call that hangs, and nothing can cancel a hung
// syscall. Field 5 is the mount point, with space, tab, newline and backslash
// written as octal escapes.
func parseMountPoints(text string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		m[unescapeMountField(f[4])] = true
	}
	return m
}

func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// childPath joins a name onto a folder without doubling the root's slash.
func childPath(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

func handleObserveFolders(ws *websocket.Conn, _ string, args []string) {
	if len(args) < 1 || len(args) > 2 {
		refuseObserveArgs(ws, "observe:folders takes a folder path and optionally a depth (1-"+
			strconv.Itoa(folderDepthMax)+")")
		return
	}
	p, depth, err := parseFolderArgs(args)
	if err != nil {
		refuseObserveArgs(ws, "refused: "+err.Error())
		return
	}
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	rep, err := readFolders(p, depth)
	if err != nil {
		refuseObserveArgs(ws, "refused: "+err.Error())
		return
	}
	writeObserve(ws, rep)
}

// ── observe:journal ──────────────────────────────────────────────────────────

// unitSuffixes are systemd's unit types. A name without one is a service, the
// way systemctl itself reads `systemctl status nginx`.
var unitSuffixes = []string{".service", ".socket", ".device", ".mount", ".automount", ".swap",
	".target", ".path", ".timer", ".slice", ".scope"}

// unitNameRe is systemd's own unit-name alphabet: letters, digits, ":-_.\"
// (unit_name_is_valid's VALID_CHARS) and "@" before an instance. A backslash
// is in it because systemd escapes with it (dev-disk-by\x2duuid-….device);
// the value reaches journalctl as one argv element, never through a shell, and
// journalctl reads a name with no *, ? or [ as an exact unit, not a pattern.
var unitNameRe = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+$`)

// unitNameMax is systemd's UNIT_NAME_MAX less its terminating NUL.
const unitNameMax = 255

func hasUnitSuffix(s string) bool {
	for _, x := range unitSuffixes {
		if strings.HasSuffix(s, x) && len(s) > len(x) {
			return true
		}
	}
	return false
}

// normalizeUnitName is the whole grammar of observe:journal's unit. A leading
// '-' is refused even though one real unit has it (-.mount, the root
// filesystem, which logs nothing a person asks after): a value shaped like a
// flag never reaches a program, whatever flag it is bound to.
func normalizeUnitName(s string) (string, error) {
	if s == "" {
		return "", errors.New("a unit name is required")
	}
	if !unitNameRe.MatchString(s) {
		return "", errors.New(`a unit name uses only letters, digits and : - _ . \ @`)
	}
	if s[0] == '-' || s[0] == '.' || s[0] == '@' {
		return "", errors.New("a unit name cannot start with '-', '.' or '@'")
	}
	if !hasUnitSuffix(s) {
		s += ".service"
	}
	if len(s) > unitNameMax {
		return "", errors.New("a unit name is at most " + strconv.Itoa(unitNameMax) + " characters")
	}
	stem := s[:strings.LastIndexByte(s, '.')]
	if strings.Count(stem, "@") > 1 {
		return "", errors.New("a unit name has at most one '@'")
	}
	if strings.HasSuffix(stem, "@") {
		return "", errors.New("that names a template, which never runs itself; name one instance of it (name@instance.service)")
	}
	return s, nil
}

func parseJournalArgs(args []string) (string, int, error) {
	unit, err := normalizeUnitName(args[0])
	if err != nil {
		return "", 0, err
	}
	// The same window grammar observe:logs takes, read by the same function.
	minutes, err := parseLogMinutes(args)
	if err != nil {
		return "", 0, err
	}
	return unit, minutes, nil
}

// parseUnitList reads `systemctl list-units --all --no-legend --plain` —
// UNIT LOAD ACTIVE SUB DESCRIPTION — into unit name → LOAD state. --plain
// drops the status bullet; one is skipped anyway, should a systemd print it.
func parseUnitList(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:]
		}
		if len(f) < 2 {
			continue
		}
		m[f[0]] = f[1]
	}
	return m
}

// parseUnitFiles reads `systemctl list-unit-files --no-legend --plain` —
// UNIT FILE, STATE, PRESET — into the set of installed unit files.
func parseUnitFiles(out string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		m[f[0]] = true
	}
	return m
}

// unitKnown says whether this machine has the unit. Both lists are needed:
// list-units holds what systemd has loaded, including instances and units with
// no file of their own, and list-unit-files holds what is installed, including
// a oneshot that ran an hour ago and was unloaded since — the case a person
// asks about ("why did the backup fail?"), and one list-units no longer shows.
// A unit list-units knows only as "not-found" has no file and is not here.
func unitKnown(unit string, loaded map[string]string, files map[string]bool) bool {
	if st, ok := loaded[unit]; ok && st != "not-found" {
		return true
	}
	if files[unit] {
		return true
	}
	if i := strings.IndexByte(unit, '@'); i > 0 {
		if files[unit[:i+1]+unit[strings.LastIndexByte(unit, '.'):]] {
			return true
		}
	}
	return false
}

// unitSuggestions names up to ten units whose name holds the asked one's
// stem, so a host that guessed "ssh" where the unit is sshd.service can ask
// again without a second round of guessing.
func unitSuggestions(unit string, loaded map[string]string, files map[string]bool) []string {
	stem := unit[:strings.LastIndexByte(unit, '.')]
	if i := strings.IndexByte(stem, '@'); i >= 0 {
		stem = stem[:i]
	}
	stem = strings.ToLower(stem)
	if len(stem) < 2 {
		return nil
	}
	set := map[string]bool{}
	for u, st := range loaded {
		if st != "not-found" && strings.Contains(strings.ToLower(u), stem) {
			set[u] = true
		}
	}
	for u := range files {
		if strings.Contains(strings.ToLower(u), stem) {
			set[u] = true
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

// errUnknownUnit names the unit: it passed the alphabet check, so it is a
// unit name and nothing else, and the host needs to see what it asked for.
func errUnknownUnit(unit string, loaded map[string]string, files map[string]bool) error {
	msg := "this machine has no unit " + unit
	if s := unitSuggestions(unit, loaded, files); len(s) > 0 {
		msg += "; units with a similar name: " + strings.Join(s, ", ")
	}
	return errors.New(msg)
}

type journalReport struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Source    string `json:"source"`
	Unit      string `json:"unit"`
	Minutes   int    `json:"minutes"`
	Lines     int    `json:"lines"`
	Truncated bool   `json:"truncated"`
	Partial   string `json:"partial,omitempty"`
	// Note is set when the answer is empty, for the reason observe:logs sets
	// one: an empty log reads like "nothing happened" and has to say which
	// unit, over which window, came back with nothing.
	Note string `json:"note,omitempty"`
	Log  string `json:"log"`
}

func handleObserveJournal(ws *websocket.Conn, _ string, args []string) {
	if len(args) < 1 || len(args) > 2 {
		refuseObserveArgs(ws, "observe:journal takes a unit name and optionally minutes (1-"+
			strconv.Itoa(observeLogMinutesMax)+")")
		return
	}
	unit, minutes, err := parseJournalArgs(args)
	if err != nil {
		refuseObserveArgs(ws, "refused: "+err.Error())
		return
	}
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	rep, err := readJournal(unit, minutes)
	if err != nil {
		refuseObserveArgs(ws, "refused: "+err.Error())
		return
	}
	writeObserve(ws, rep)
}

// observeJournalAccess says why this account cannot read the whole system
// journal, or "" when it can. A seam so a test can answer either way. It
// matters because journalctl run by an account without access does not fail:
// it shows that account's own lines, which hold no sshd and no system unit, so
// an empty answer would read as a quiet machine when it is a blind one.
var observeJournalAccess = journalAccess

// ── observe:logins ───────────────────────────────────────────────────────────

const (
	loginsHoursDefault = 24
	loginsHoursMax     = 168
	// loginsLineCap is what journalctl is asked for (--lines=50000 in the argv
	// in observe_reads_linux.go; TestObserveLoginsRunsItsPinnedArgv holds the
	// two together). A week on a machine the internet is guessing passwords
	// at is tens of thousands of sshd lines; 50,000 of about 150 bytes is the
	// most this op will hold in memory. Past it the oldest are the ones
	// dropped, and the answer says from when it counted.
	loginsLineCap = 50000
	// loginsTopN is the size of each ranked list and of the accepted list.
	loginsTopN = 20
	// loginNameMax is the longest account name Linux tools create (useradd's
	// 32). The names in failed attempts are whatever the other side sent.
	loginNameMax = 32
)

func parseLoginsArgs(args []string) (int, error) {
	if len(args) == 0 {
		return loginsHoursDefault, nil
	}
	return parseBoundedInt(args[0], "hours", 1, loginsHoursMax)
}

type loginSource struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

type loginUser struct {
	User  string `json:"user"`
	Count int    `json:"count"`
	// Invalid is sshd's own word: no account by that name on this machine.
	Invalid bool `json:"invalid,omitempty"`
}

type acceptedLogin struct {
	User   string `json:"user"`
	Source string `json:"source"`
	Method string `json:"method"`
	At     string `json:"at"`
}

type loginsReport struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Source    string `json:"source"`
	Hours     int    `json:"hours"`
	// The totals read -1 when the journal could not be read: a 0 here would
	// clear a finding, and a machine that was not looked at has not said
	// nobody tried.
	FailedTotal    int             `json:"failed_total"`
	FailedSources  int             `json:"failed_sources"`
	FailedUsers    int             `json:"failed_users"`
	FailedBySource []loginSource   `json:"failed_by_source"`
	FailedByUser   []loginUser     `json:"failed_by_user"`
	AcceptedTotal  int             `json:"accepted_total"`
	Accepted       []acceptedLogin `json:"accepted"`
	EntriesRead    int             `json:"entries_read"`
	// OldestEntry is the time of the first sshd entry read. When Truncated
	// is set the counts cover from then, not the whole window.
	OldestEntry string `json:"oldest_entry,omitempty"`
	Truncated   bool   `json:"truncated"`
	Partial     string `json:"partial,omitempty"`
	Note        string `json:"note,omitempty"`
}

// The four OpenSSH messages this op reads. Every one is anchored at the END:
// the user name is whatever the other side sent, and a name like
// "x from 198.51.100.1 port 1" must not move the source. The greedy user
// group takes the longest name that still leaves a " from <addr> port <n>"
// before the end, so the source is always the last one on the line, the one
// sshd wrote. The source must then parse as an address (or, under UseDNS, a
// host name) or the line is not counted.
var (
	sshFailedRe   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh\d?)?(?:: .*)?$`)
	sshInvalidRe  = regexp.MustCompile(`^Invalid user (.*) from (\S+) port (\d+)$`)
	sshPreauthRe  = regexp.MustCompile(`^(?:Connection closed by|Connection reset by|Disconnected from) (authenticating|invalid) user (.*) (\S+) port (\d+)(?: \[preauth\])?$`)
	sshAcceptedRe = regexp.MustCompile(`^Accepted (\S+) for (.*) from (\S+) port (\d+)(?: ssh\d?)?(?:: .*)?$`)
	loginHostRe   = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
)

// loginSourceOf accepts an address, or a host name when sshd runs with
// UseDNS, and nothing else.
func loginSourceOf(s string) (string, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String(), true
	}
	if loginHostRe.MatchString(s) {
		return strings.ToLower(s), true
	}
	return "", false
}

// loginName bounds a user name the other side chose. At most loginNameMax
// bytes from the alphabet account names are made of; anything else is '?'.
// It goes to a host that reads text, and a "user name" with spaces in it is a
// sentence somebody wrote to it, not an account.
func loginName(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < loginNameMax; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-', c == '@', c == '$':
			b.WriteByte(c)
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

// sshMethodRe is the shape of sshd's own method names: publickey, password,
// keyboard-interactive/pam, gssapi-with-mic, hostbased.
var sshMethodRe = regexp.MustCompile(`^[a-z0-9@./-]{1,40}$`)

func loginMethod(s string) string {
	if sshMethodRe.MatchString(s) {
		return s
	}
	return "other"
}

// journalStamp turns short-iso's time into RFC3339 UTC. Older systemd writes
// the offset without a colon.
func journalStamp(ts string) string {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05-0700"} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ts
}

// splitJournalLine splits one `journalctl -o short-iso` line into its time,
// the process id and the message: "<time> <host> <ident>[<pid>]: <message>".
// Everything before the message is journald's, so nothing the other side sent
// can change where it splits.
func splitJournalLine(line string) (ts, pid, msg string, ok bool) {
	ts, rest, ok := strings.Cut(line, " ")
	if !ok || ts == "" {
		return "", "", "", false
	}
	if _, rest, ok = strings.Cut(rest, " "); !ok {
		return "", "", "", false
	}
	ident, msg, ok := strings.Cut(rest, ": ")
	if !ok {
		return "", "", "", false
	}
	if i := strings.IndexByte(ident, '['); i >= 0 && strings.HasSuffix(ident, "]") {
		pid = ident[i+1 : len(ident)-1]
	}
	return ts, pid, msg, true
}

// sshConn is one connection: a process, a source and its port.
type sshConn struct {
	src     string
	user    string
	named   bool
	invalid bool
	failed  int
	knocked bool
}

type sshTally struct {
	entries       int
	oldest        string
	failed        int
	bySource      map[string]int
	byUser        map[string]*loginUser
	accepted      []acceptedLogin
	acceptedTotal int
}

func (t *sshTally) fail(src, user string, invalid bool) {
	t.failed++
	t.bySource[src]++
	u := t.byUser[user]
	if u == nil {
		u = &loginUser{User: user}
		t.byUser[user] = u
	}
	u.Count++
	u.Invalid = u.Invalid || invalid
}

// parseSSHLogins counts what sshd logged. A failed attempt is:
//
//   - each "Failed <method> for …" line: one authentication refused; and
//   - a connection that named an account sshd does not have ("Invalid user")
//     or that gave up while authenticating, and has no Failed line of its own.
//     Scanners mostly do this: one try at "admin", then gone. Counting both it
//     and its Failed lines would count one password guess twice.
//
// A connection is its process id, source and port, all three: over a week the
// same source reuses ports, and one of them alone would merge two connections.
// Accepted logins are counted, and the last loginsTopN kept in the order they
// happened. PAM's duplicate lines and everything else sshd says are ignored.
func parseSSHLogins(out string) sshTally {
	t := sshTally{bySource: map[string]int{}, byUser: map[string]*loginUser{}}
	conns := map[string]*sshConn{}
	conn := func(pid, src, port string) *sshConn {
		k := pid + " " + src + " " + port
		c := conns[k]
		if c == nil {
			c = &sshConn{src: src}
			conns[k] = c
		}
		return c
	}
	for _, line := range strings.Split(out, "\n") {
		ts, pid, msg, ok := splitJournalLine(line)
		if !ok {
			continue
		}
		t.entries++
		if t.oldest == "" {
			t.oldest = journalStamp(ts)
		}
		msg = strings.TrimRight(msg, " \r")
		switch {
		case strings.HasPrefix(msg, "Failed "):
			m := sshFailedRe.FindStringSubmatch(msg)
			if m == nil {
				continue
			}
			src, ok := loginSourceOf(m[4])
			if !ok {
				continue
			}
			t.fail(src, loginName(m[3]), m[2] != "")
			conn(pid, src, m[5]).failed++
		case strings.HasPrefix(msg, "Invalid user "):
			m := sshInvalidRe.FindStringSubmatch(msg)
			if m == nil {
				continue
			}
			src, ok := loginSourceOf(m[2])
			if !ok {
				continue
			}
			c := conn(pid, src, m[3])
			c.knocked, c.named, c.invalid, c.user = true, true, true, loginName(m[1])
		case strings.HasPrefix(msg, "Connection closed by "), strings.HasPrefix(msg, "Connection reset by "),
			strings.HasPrefix(msg, "Disconnected from "):
			m := sshPreauthRe.FindStringSubmatch(msg)
			if m == nil {
				continue
			}
			src, ok := loginSourceOf(m[3])
			if !ok {
				continue
			}
			c := conn(pid, src, m[4])
			c.knocked = true
			if !c.named {
				c.named, c.invalid, c.user = true, m[1] == "invalid", loginName(m[2])
			}
		case strings.HasPrefix(msg, "Accepted "):
			m := sshAcceptedRe.FindStringSubmatch(msg)
			if m == nil {
				continue
			}
			src, ok := loginSourceOf(m[3])
			if !ok {
				continue
			}
			t.acceptedTotal++
			t.accepted = append(t.accepted, acceptedLogin{User: loginName(m[2]), Source: src,
				Method: loginMethod(m[1]), At: journalStamp(ts)})
			if len(t.accepted) > loginsTopN {
				t.accepted = t.accepted[1:]
			}
		}
	}
	for _, c := range conns {
		if c.knocked && c.failed == 0 {
			t.fail(c.src, c.user, c.invalid)
		}
	}
	return t
}

// fill writes the tally into the report: totals, and the top loginsTopN of
// each list by count, ties in name order so an unchanged journal reads the same.
func (t sshTally) fill(rep *loginsReport) {
	rep.FailedTotal = t.failed
	rep.FailedSources = len(t.bySource)
	rep.FailedUsers = len(t.byUser)
	rep.FailedBySource = make([]loginSource, 0, len(t.bySource))
	for s, n := range t.bySource {
		rep.FailedBySource = append(rep.FailedBySource, loginSource{Source: s, Count: n})
	}
	sort.Slice(rep.FailedBySource, func(i, j int) bool {
		a, b := rep.FailedBySource[i], rep.FailedBySource[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Source < b.Source
	})
	if len(rep.FailedBySource) > loginsTopN {
		rep.FailedBySource = rep.FailedBySource[:loginsTopN]
	}
	rep.FailedByUser = make([]loginUser, 0, len(t.byUser))
	for _, u := range t.byUser {
		rep.FailedByUser = append(rep.FailedByUser, *u)
	}
	sort.Slice(rep.FailedByUser, func(i, j int) bool {
		a, b := rep.FailedByUser[i], rep.FailedByUser[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.User < b.User
	})
	if len(rep.FailedByUser) > loginsTopN {
		rep.FailedByUser = rep.FailedByUser[:loginsTopN]
	}
	rep.AcceptedTotal = t.acceptedTotal
	rep.Accepted = append([]acceptedLogin{}, t.accepted...)
	rep.EntriesRead = t.entries
	rep.OldestEntry = t.oldest
}

func handleObserveLogins(ws *websocket.Conn, _ string, args []string) {
	if len(args) > 1 {
		refuseObserveArgs(ws, "observe:logins takes at most one argument: hours (1-"+
			strconv.Itoa(loginsHoursMax)+")")
		return
	}
	hours, err := parseLoginsArgs(args)
	if err != nil {
		refuseObserveArgs(ws, "refused: "+err.Error())
		return
	}
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	writeObserve(ws, readLogins(hours))
}

// ── observe:cert ─────────────────────────────────────────────────────────────

const (
	// certDialTimeout bounds one connect. Every address tried is this
	// machine's own, so a refused one answers at once and a slow one is the
	// listener's problem to report, not a reason to spend the op budget.
	certDialTimeout = 3 * time.Second
	// certHandshakeTimeout bounds the TLS handshake once connected.
	certHandshakeTimeout = 5 * time.Second
)

// serverNameRe is a DNS name or an IPv4 literal: what can go in a TLS hello
// and what a certificate can be verified against.
var serverNameRe = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)

func checkServerName(s string) (string, error) {
	if !serverNameRe.MatchString(s) || strings.HasPrefix(s, "-") || strings.HasPrefix(s, ".") ||
		strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return "", errors.New("a server name uses letters, digits, '.' and '-' only, like example.org")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("a server name's parts are at most 63 characters and do not start or end with '-'")
		}
	}
	return strings.ToLower(s), nil
}

func parseCertArgs(args []string) (int, string, error) {
	port, err := parseBoundedInt(args[0], "port", 1, 65535)
	if err != nil {
		return 0, "", err
	}
	name := ""
	if len(args) > 1 {
		if name, err = checkServerName(args[1]); err != nil {
			return 0, "", err
		}
	}
	return port, name, nil
}

type certReport struct {
	Supported  bool   `json:"supported"`
	Reason     string `json:"reason,omitempty"`
	Port       int    `json:"port"`
	ServerName string `json:"server_name"`
	// Listening is every local address ss reports for the port; Tried is
	// each address that did not connect, with why, in the order tried.
	Listening   []string `json:"listening"`
	Tried       []string `json:"tried"`
	ConnectedTo string   `json:"connected_to"`
	TLS         bool     `json:"tls"`
	TLSError    string   `json:"tls_error,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	DaysLeft    *int     `json:"days_left,omitempty"`
	ChainLength int      `json:"chain_length,omitempty"`
	// ChainVerified is whether the chain the listener sent verifies against
	// this machine's system roots for VerifiedFor — the server name asked,
	// or, with none, the chain alone and no name.
	ChainVerified *bool  `json:"chain_verified,omitempty"`
	VerifiedFor   string `json:"verified_for,omitempty"`
	VerifyError   string `json:"verify_error,omitempty"`
	CheckedAt     string `json:"checked_at"`
}

// ssLocalAddr reads one ss local address: "127.0.0.1", "[::1]",
// "127.0.0.53%lo", "[fe80::1]%eth0", "*". wild is a listener on every
// address, which loopback already reaches.
func ssLocalAddr(local string) (a netip.Addr, wild, ok bool) {
	if local == "*" {
		return netip.Addr{}, true, true
	}
	zone := ""
	if i := strings.LastIndexByte(local, '%'); i >= 0 {
		local, zone = local[:i], local[i+1:]
	}
	local = strings.TrimSuffix(strings.TrimPrefix(local, "["), "]")
	a, err := netip.ParseAddr(local)
	if err != nil {
		return netip.Addr{}, false, false
	}
	a = a.Unmap()
	if a.IsUnspecified() {
		return a, true, true
	}
	// The zone is kept only where it is one: a v6 link-local address does
	// not route without it. On "127.0.0.53%lo" it is the bound device.
	if zone != "" && a.Is6() && a.IsLinkLocalUnicast() {
		a = a.WithZone(zone)
	}
	return a, false, true
}

// certTargets is where observe:cert may connect for port, in order: loopback
// in both families, then each address a listener on that port is bound to,
// when it is loopback or one of this machine's own (own). A listener bound to
// an address this machine does not hold — a floating address another machine
// has at the moment — is never dialled: it would reach that other machine.
// listening is every local address ss reports for the port; empty means
// nothing listens there.
func certTargets(socks []listenSocket, port int, own map[netip.Addr]bool) (targets, listening []string) {
	p := strconv.Itoa(port)
	targets = []string{net.JoinHostPort("127.0.0.1", p), net.JoinHostPort("::1", p)}
	seen := map[string]bool{targets[0]: true, targets[1]: true}
	listening = []string{}
	for _, s := range socks {
		if s.Proto != "tcp" || s.Port != port {
			continue
		}
		listening = append(listening, s.Local)
		a, wild, ok := ssLocalAddr(s.Local)
		if !ok || wild {
			continue
		}
		if !a.IsLoopback() && !own[a.WithZone("")] {
			continue
		}
		t := net.JoinHostPort(a.String(), p)
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	return targets, listening
}

// observeOwnAddrs is this machine's interface addresses. A seam so a test can
// name an address as this machine's.
var observeOwnAddrs = func() map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return m
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				m[ip.Unmap()] = true
			}
		}
	}
	return m
}

// dialCert connects to the first target that accepts and reads the
// certificate it serves. The first TCP connection decides: that is the
// listener, and a TLS failure on it is the answer, not a reason to try the
// next address. InsecureSkipVerify because this reads the certificate rather
// than trusting it — an expired or self-signed one is exactly what a person
// asks about — and verification is reported on its own. TLS 1.0 is allowed
// for the same reason: a server that speaks nothing newer still has a
// certificate, and tls_version says what it spoke.
func dialCert(ctx context.Context, rep *certReport, targets []string, name string) {
	d := &net.Dialer{Timeout: certDialTimeout}
	for _, addr := range targets {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			rep.Tried = append(rep.Tried, err.Error())
			continue
		}
		rep.ConnectedTo = addr
		deadline := time.Now().Add(certHandshakeTimeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = conn.SetDeadline(deadline)
		tc := tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true, //nolint:gosec // reading, not trusting; verification reported below
			MinVersion: tls.VersionTLS10})
		if err := tc.HandshakeContext(ctx); err != nil {
			rep.TLSError = err.Error()
			_ = conn.Close()
			return
		}
		st := tc.ConnectionState()
		rep.TLS = true
		rep.TLSVersion = tls.VersionName(st.Version)
		summarizeCert(rep, st.PeerCertificates, name, time.Now())
		_ = tc.Close()
		return
	}
}

// summarizeCert fills the leaf's facts and the chain's verdict. days_left is
// probeNet's arithmetic, so the two ops agree on the same certificate.
func summarizeCert(rep *certReport, certs []*x509.Certificate, name string, now time.Time) {
	if len(certs) == 0 {
		rep.TLSError = "the listener sent no certificate"
		return
	}
	leaf := certs[0]
	rep.Subject = leaf.Subject.String()
	rep.SANs = append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		rep.SANs = append(rep.SANs, ip.String())
	}
	rep.Issuer = leaf.Issuer.String()
	rep.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	rep.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	rep.DaysLeft = &days
	rep.ChainLength = len(certs)
	err := verifyChain(certs, name)
	ok := err == nil
	rep.ChainVerified = &ok
	rep.VerifiedFor = name
	if err != nil {
		rep.VerifyError = err.Error()
	}
}

func handleObserveCert(ws *websocket.Conn, _ string, args []string) {
	if len(args) < 1 || len(args) > 2 {
		refuseObserveArgs(ws, "observe:cert takes a local tcp port and optionally a server name")
		return
	}
	port, name, err := parseCertArgs(args)
	if err != nil {
		refuseObserveArgs(ws, "refused: "+err.Error())
		return
	}
	if !observeHostSupported {
		writeObserve(ws, observeUnsupported())
		return
	}
	rep, err := readCert(port, name)
	if err != nil {
		refuseObserveArgs(ws, "refused: "+err.Error())
		return
	}
	writeObserve(ws, rep)
}
