package main

// notify_test.go — the notification rules, run on the platform the suite
// actually runs on.
//
// The Win32 calls in notify_windows.go cannot be exercised here and nobody on
// this project has a Windows desktop to exercise them on. What CAN be checked
// anywhere is the part that decides WHETHER to interrupt someone, which is where
// every interesting failure lives: a prompt that fires twelve times a minute is
// worse than the silence it replaced, because the user turns notifications off
// and never turns them back on. So the clock is injected and every rule below is
// a sequence of ticks, not a mock of the shell.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// recordingSink stands in for the notification area.
type recordingSink struct {
	tips    []string
	notices []uiNotice
	hides   int
}

func (r *recordingSink) show(tip string, n *uiNotice) {
	r.tips = append(r.tips, tip)
	if n != nil {
		r.notices = append(r.notices, *n)
	}
}

func (r *recordingSink) hide() { r.hides++ }

func notifyAsk(id, host, line string) uiApproval {
	return uiApproval{ID: id, Short: id, Host: host, Lines: []string{line}}
}

// notifyT0 is an arbitrary fixed instant. Nothing here depends on the wall clock.
var notifyT0 = time.Date(2026, 9, 13, 11, 0, 0, 0, time.UTC)

// THE ONE THE WHOLE FEATURE RESTS ON. The tray re-reads the machine's state
// every trayRefresh = 5 s and the request stays pending for as long as 24 h
// (stepupRequestTTL), so a notifier that announced what it saw would announce
// the same folder request seventeen thousand times.
func TestAPendingRequestIsAnnouncedExactlyOnce(t *testing.T) {
	var n approvalNotifier
	sink := &recordingSink{}
	pending := []uiApproval{notifyAsk("a1", "member", "Your host asks to reach the folder  C:\\Docs")}

	for i := 0; i < 40; i++ { // 40 ticks is well past approvalNotifyMinGap
		n.poll(notifyT0.Add(time.Duration(i)*trayRefresh), pending, sink)
	}
	if len(sink.notices) != 1 {
		t.Fatalf("announced %d times over 40 polls, want exactly 1: %+v", len(sink.notices), sink.notices)
	}
	if len(sink.tips) != 40 {
		t.Errorf("the waiting icon was updated %d times, want one per poll", len(sink.tips))
	}
	if sink.hides != 0 {
		t.Errorf("the icon was taken down %d times while a request was still pending", sink.hides)
	}
}

// "Never notify for a request the user has already answered" — and the icon has
// to come down with it, or the machine goes on claiming work that is done.
func TestAnAnsweredRequestIsNeverAnnouncedAgain(t *testing.T) {
	var n approvalNotifier
	sink := &recordingSink{}
	a := []uiApproval{notifyAsk("a1", "member", "Your host asks to reach the folder  C:\\Docs")}

	n.poll(notifyT0, a, sink)
	if len(sink.notices) != 1 {
		t.Fatalf("the first sighting must announce, got %d", len(sink.notices))
	}
	// Answered on the page: pendingApprovals stops returning it.
	for i := 1; i < 30; i++ {
		n.poll(notifyT0.Add(time.Duration(i)*trayRefresh), nil, sink)
	}
	if len(sink.notices) != 1 {
		t.Errorf("announced again after it was answered: %+v", sink.notices[1:])
	}
	if sink.hides == 0 {
		t.Error("the waiting icon was never taken down after the last request was answered")
	}
}

// "Do not storm the user when three arrive at once." Three in one poll is ONE
// notification, and it says three.
func TestThreeArrivingAtOnceAreOneNotification(t *testing.T) {
	var n approvalNotifier
	sink := &recordingSink{}
	n.poll(notifyT0, []uiApproval{
		notifyAsk("a1", "member", "Your host asks to reach the folder  C:\\Docs"),
		notifyAsk("a2", "member", "Your host asks to reach the folder  C:\\Pics"),
		notifyAsk("a3", "rex", "Your host asks to MOVE 4 item(s) inside  C:\\Docs"),
	}, sink)

	if len(sink.notices) != 1 {
		t.Fatalf("want 1 notification for 3 simultaneous requests, got %d", len(sink.notices))
	}
	got := sink.notices[0]
	if !strings.Contains(got.Title, "3 requests") {
		t.Errorf("title %q does not say how many are waiting", got.Title)
	}
	if !strings.Contains(got.Body, "member and rex") {
		t.Errorf("body %q does not name both hosts", got.Body)
	}
	if tip := sink.tips[0]; !strings.Contains(tip, "3 requests") {
		t.Errorf("tooltip %q does not carry the count", tip)
	}
}

// Three arriving on three consecutive ticks is the same storm spread out. They
// are HELD, and held is not dropped: the one that was suppressed goes out in the
// next notification and the count is right when it does.
func TestArrivalsInsideTheGapAreHeldAndThenSaidTogether(t *testing.T) {
	var n approvalNotifier
	sink := &recordingSink{}
	a1 := notifyAsk("a1", "member", "one")
	a2 := notifyAsk("a2", "member", "two")
	a3 := notifyAsk("a3", "member", "three")

	n.poll(notifyT0, []uiApproval{a1}, sink)
	n.poll(notifyT0.Add(trayRefresh), []uiApproval{a1, a2}, sink)
	n.poll(notifyT0.Add(2*trayRefresh), []uiApproval{a1, a2, a3}, sink)
	if len(sink.notices) != 1 {
		t.Fatalf("%d notifications inside approvalNotifyMinGap, want 1", len(sink.notices))
	}

	// Past the gap, with nothing new since: the two that were held go out.
	n.poll(notifyT0.Add(approvalNotifyMinGap+time.Second), []uiApproval{a1, a2, a3}, sink)
	if len(sink.notices) != 2 {
		t.Fatalf("the held requests were never announced: %d notifications", len(sink.notices))
	}
	if !strings.Contains(sink.notices[1].Title, "3 requests") {
		t.Errorf("second notification says %q; it must count everything waiting, not only what is new",
			sink.notices[1].Title)
	}

	// And now nothing is unannounced, so the gap expiring again says nothing.
	n.poll(notifyT0.Add(4*approvalNotifyMinGap), []uiApproval{a1, a2, a3}, sink)
	if len(sink.notices) != 2 {
		t.Errorf("announced %d times with nothing new", len(sink.notices))
	}
}

// THE MEASURED HAZARD. requestsLoad returns an EMPTY MAP on any read or
// unmarshal failure and reports no error (stepup.go:562-567), and
// collectUIStatus returns with no approvals at all when loadPairings fails
// (ui.go:140-145) — so "the list went empty" does not mean "the user answered
// it". A Windows virus scanner holding the file open for a moment is enough. If
// the memory of an id were tied to it staying visible, the blip would announce
// the same request twice.
//
// The gap is deliberately stepped past, so this proves the id is remembered
// rather than that the timer happened to suppress it.
func TestATransientlyEmptyListDoesNotAnnounceTheSameRequestTwice(t *testing.T) {
	var n approvalNotifier
	sink := &recordingSink{}
	a := []uiApproval{notifyAsk("a1", "member", "Your host asks to reach the folder  C:\\Docs")}

	n.poll(notifyT0, a, sink)
	n.poll(notifyT0.Add(trayRefresh), nil, sink) // the blip
	n.poll(notifyT0.Add(2*trayRefresh), a, sink) // and back

	// Well past approvalNotifyMinGap, so nothing here is the gap timer's doing.
	n.poll(notifyT0.Add(approvalNotifyMinGap+time.Minute), a, sink)
	if len(sink.notices) != 1 {
		t.Fatalf("announced %d times across a transient empty read, want 1: %+v",
			len(sink.notices), sink.notices)
	}
}

// The memory has to be bounded, and the bound is the request's own lifetime:
// requestsLoad deletes anything older than stepupRequestTTL on every read
// (stepup.go:562-573), so an id gone for longer than that can never come back.
// Shorter than that would re-announce across a long outage; unbounded would grow
// a map for the life of the daemon.
func TestAnIdIsRememberedForAsLongAsItsRequestCouldExist(t *testing.T) {
	var n approvalNotifier
	sink := &recordingSink{}
	a := []uiApproval{notifyAsk("a1", "member", "Your host asks to reach the folder  C:\\Docs")}

	n.poll(notifyT0, a, sink)
	// Gone for just under the request's lifetime, then back: still known.
	n.poll(notifyT0.Add(approvalForget-time.Minute), nil, sink)
	n.poll(notifyT0.Add(approvalForget-time.Minute+trayRefresh), a, sink)
	if len(sink.notices) != 1 {
		t.Fatalf("re-announced inside approvalForget: %d notifications", len(sink.notices))
	}
	if _, ok := n.seen["a1"]; !ok {
		t.Fatal("the id was dropped from memory while it could still be pending")
	}

	// Past it, the id is dropped and the map does not grow for ever.
	n.poll(notifyT0.Add(3*approvalForget), nil, sink)
	if _, ok := n.seen["a1"]; ok {
		t.Error("the id is still held long after the request it names expired (stepup.go:569)")
	}
}

// A request the machine cannot put into words gets different words. ui.go:221-234
// explains why the PAGE changes shape for these; a notification that read like
// any other would undo that before the user ever reached the page.
func TestAnUndescribableRequestSaysSoInTheNotification(t *testing.T) {
	n := approvalNoticeFor([]uiApproval{{
		ID: "a1", Host: "member", Lines: []string{uiUnknownRequest}, Unreadable: true,
	}})
	if !strings.Contains(n.Body, "cannot describe") {
		t.Errorf("body %q does not say the machine cannot describe the request", n.Body)
	}
	if !strings.Contains(n.Body, "refusing is the safe answer") {
		t.Errorf("body %q does not point at the safe direction", n.Body)
	}
	if strings.Contains(n.Body, uiUnknownRequest) {
		t.Errorf("body %q shows the raw %q placeholder", n.Body, uiUnknownRequest)
	}
}

func TestTheSingleRequestNoticeNamesTheHostAndWhatIsAsked(t *testing.T) {
	n := approvalNoticeFor([]uiApproval{
		notifyAsk("a1", "member", "Your host asks to reach the folder  C:\\Users\\user\\Documents"),
	})
	for _, want := range []string{"C:\\Users\\user\\Documents", "member"} {
		if !strings.Contains(n.Body, want) {
			t.Errorf("body %q does not contain %q", n.Body, want)
		}
	}
}

// NOTIFYICONDATAW carries fixed WCHAR arrays — szInfoTitle[64], szInfo[256] —
// and the shell reads each to its first NUL. Text that does not fit is not
// shortened for you.
//
// THE FIRST VERSION OF THIS TEST WAS TAUTOLOGICAL and the mutation check is what
// said so: its only multi-request case had twelve hosts, which takes the "from
// 12 hosts" branch and produces a SHORT body, so deleting the clip on that
// branch left the test green. The case that matters is two or three hosts with
// long names, because that is the branch that spells every name out.
func TestEveryNoticeFitsTheWindowsFields(t *testing.T) {
	long := strings.Repeat("Ünmöglich-lange-Ördnernamen/", 40)
	many := []uiApproval{}
	for i := 0; i < 12; i++ {
		many = append(many, notifyAsk(fmt.Sprintf("id%d", i), long+fmt.Sprintf("%d", i), long))
	}
	cases := map[string][]uiApproval{
		"one long request": {notifyAsk("a1", long, long)},
		"twelve hosts":     many,
		"one unreadable":   {{ID: "a1", Host: long, Unreadable: true}},
		"three hosts, every name spelled out": {
			notifyAsk("a1", long+"1", "one"),
			notifyAsk("a2", long+"2", "two"),
			notifyAsk("a3", long+"3", "three"),
		},
	}
	for name, in := range cases {
		n := approvalNoticeFor(in)
		if got := utf16Len(n.Title); got > noticeTitleMax {
			t.Errorf("%s: title is %d UTF-16 units, szInfoTitle holds %d plus a NUL", name, got, noticeTitleMax)
		}
		if got := utf16Len(n.Body); got > noticeBodyMax {
			t.Errorf("%s: body is %d UTF-16 units, szInfo holds %d plus a NUL", name, got, noticeBodyMax)
		}
	}
	if got := utf16Len(approvalTip(999999)); got > noticeTipMax {
		t.Errorf("tooltip is %d UTF-16 units, szTip holds %d plus a NUL", got, noticeTipMax)
	}
}

// A folder name outside the Basic Multilingual Plane is ONE rune and TWO UTF-16
// units. Counting in runes overruns the array; cutting between the halves of a
// surrogate pair produces something that is not a character. Folder names carry
// emoji, and the body of a notification is a path the host sent.
func TestClipUTF16CountsUnitsAndNeverSplitsAPair(t *testing.T) {
	rocket := "\U0001F680" // 2 UTF-16 units, 1 rune, 4 bytes
	cases := []struct {
		name string
		in   string
		max  int
	}{
		{"all astral", strings.Repeat(rocket, 20), 11},
		{"cut lands mid-pair", "abc" + strings.Repeat(rocket, 10), 6},
		{"mixed", "C:\\Fotos " + strings.Repeat(rocket, 10) + " 2026", 15},
		{"max of one", strings.Repeat(rocket, 4), 1},
		{"already fits", "short", 40},
	}
	for _, c := range cases {
		got := clipUTF16(c.in, c.max)
		if n := utf16Len(got); n > c.max {
			t.Errorf("%s: clipped to %d units, asked for at most %d (%q)", c.name, n, c.max, got)
		}
		for i, r := range got {
			if r == '\uFFFD' {
				t.Errorf("%s: a replacement character at byte %d — a pair was split: %q",
					c.name, i, got)
				break
			}
		}
	}
	if got := clipUTF16("short", 40); got != "short" {
		t.Errorf("text that fits was changed to %q", got)
	}
	if got := clipUTF16(strings.Repeat("a", 50), 10); !strings.HasSuffix(got, "…") {
		t.Errorf("clipped text %q does not show that it was cut", got)
	}
}

// putUTF16 is the last line of defence: whatever clipUTF16 did, what reaches the
// struct must be NUL-terminated and must not end on half a surrogate pair,
// because the shell decodes it and the array has no room to spare.
func TestPutUTF16TerminatesAndLeavesNoHalfCharacter(t *testing.T) {
	rocket := "\U0001F680"
	for _, c := range []struct {
		name string
		in   string
		size int
	}{
		{"exactly fits", "abcd", 5},
		{"one too long", "abcde", 5},
		{"astral overflow", strings.Repeat(rocket, 8), 6},
		{"cut lands mid-pair", "ab" + strings.Repeat(rocket, 8), 5},
		{"empty", "", 4},
	} {
		dst := make([]uint16, c.size)
		for i := range dst {
			dst[i] = 0xBEEF // poison, so a missing NUL is visible
		}
		putUTF16(dst, c.in)

		nul := -1
		for i, u := range dst {
			if u == 0 {
				nul = i
				break
			}
		}
		if nul < 0 {
			t.Errorf("%s: no NUL anywhere in the array — the shell reads past the end", c.name)
			continue
		}
		s := string(utf16.Decode(dst[:nul]))
		if strings.ContainsRune(s, '\uFFFD') {
			t.Errorf("%s: decoded to %q — an unpaired surrogate was left in the array", c.name, s)
		}
		if !strings.HasPrefix(c.in, s) {
			t.Errorf("%s: wrote %q, which is not a prefix of %q", c.name, s, c.in)
		}
	}
	putUTF16(nil, "anything") // must not panic
}

func TestJoinNames(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"member"}, "member"},
		{[]string{"member", "rex"}, "member and rex"},
		{[]string{"member", "rex", "ada"}, "member, rex and ada"},
	}
	for _, c := range cases {
		if got := joinNames(c.in); got != c.want {
			t.Errorf("joinNames(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// THE GUARD ON THE OTHER HALF. guardSingleRun's refusals go to stderr and then
// exit 1, which is nothing at all when the process has no console — the state
// 0.24.0 made normal by relaunching DETACHED (relaunch_windows.go:46-48). Every
// error return has to go through refuseVisibly, and the branch someone adds next
// year has to as well, which is what this reads the source to check.
//
// It reads the file from disk rather than being compiled into a Windows build,
// for the same reason console_test.go does: the platform that runs the suite is
// Linux.
func TestEveryRunGuardRefusalIsVisible(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "runguard_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if g, ok := d.(*ast.FuncDecl); ok && g.Recv == nil && g.Name.Name == "guardSingleRun" {
			fn = g
		}
	}
	if fn == nil {
		t.Fatal("guardSingleRun is not in runguard_windows.go any more — this check would " +
			"pass for ever while the refusal went silent again")
	}

	returns, guarded := 0, 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		if id, ok := ret.Results[0].(*ast.Ident); ok && id.Name == "nil" {
			return true // the success path
		}
		returns++
		call, ok := ret.Results[0].(*ast.CallExpr)
		if !ok {
			t.Errorf("runguard_windows.go:%d — this refusal is returned straight to main, which "+
				"prints it to stderr. A bastion started by double-clicking the exe, or relaunched "+
				"DETACHED after a self-update, has no console to print it into. Wrap it: "+
				"`return refuseVisibly(<title>, <err>)`.", fset.Position(ret.Pos()).Line)
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "refuseVisibly" {
			t.Errorf("runguard_windows.go:%d — this refusal does not go through refuseVisibly, so "+
				"it is invisible on a console-less start. See the comment above it.",
				fset.Position(ret.Pos()).Line)
			return true
		}
		guarded++
		return true
	})

	if returns < 3 {
		t.Fatalf("only %d refusal(s) examined in guardSingleRun — this check has stopped "+
			"finding them, which makes it a green light that proves nothing", returns)
	}
	if guarded != returns {
		t.Errorf("%d of %d refusals are shown to the user", guarded, returns)
	}
}
