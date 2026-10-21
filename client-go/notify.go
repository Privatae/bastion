package main

// notify.go — the two places this daemon has to INTERRUPT the person at the
// keyboard, and the rules about when it is allowed to.
//
// WHAT IS HERE AND WHY IT IS NOT BEHIND A BUILD TAG. Only the *mechanism* of a
// Windows notification is Windows-shaped (notify_windows.go). Deciding whether a
// request has already been announced, how many are waiting, and what the words
// are is ordinary logic — and logic behind `//go:build windows` is logic the
// suite never runs, because the suite runs on Linux. tray.go exists for exactly
// this reason and says so; this file is the same split for notifications.
//
// THE DEFECT. A host asks to reach a folder, stepupNewRequest writes the ask
// into that pairing's stepup_requests.json (stepup.go:586), and then nothing
// happens. `pendingApprovals` (ui.go:192) will show it — to whoever opens the
// page. It is meant to be a prompt, and without this file it is a poll. A
// consent gate the user is never told about
// is not a consent gate, and the whole security story of step-up rests on it.
//
// THE HARD PART IS NOT SHOWING ONE — it is showing it ONCE. The tray re-reads
// the machine's state every trayRefresh = 5 s (tray_windows.go:52), so the same
// pending request is in front of this code twelve times a minute, for as long as
// 24 h (stepupRequestTTL, stepup.go:62). Announcing what it sees would be a
// notification every five seconds until the user gave up and turned
// notifications off for the app — which is worse than the silence it replaced,
// because it is silence the user chose and will not undo.

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// uiNotice is one thing said to the person at this machine, in the shape every
// platform notification takes: a short title and a short body.
type uiNotice struct {
	Title string
	Body  string
}

// The Windows notification area is not a string API. NOTIFYICONDATAW carries
// FIXED WCHAR arrays and the shell reads each to its first NUL, so a caption
// that does not fit is not shortened for you — it overruns the array. Sizes
// verified against mingw-w64's shellapi.h (`WCHAR szTip[128]`, `szInfo[256]`,
// `szInfoTitle[64]`) and against fyne.io/systray's transcription of the same
// struct (systray_windows.go:116-129), which is the one reference here that is
// known to work in the field. One unit of each is reserved for the NUL.
//
// These are UTF-16 CODE UNITS, not bytes and not runes — see clipUTF16.
const (
	noticeTitleMax = 63
	noticeBodyMax  = 255
	noticeTipMax   = 127
)

// approvalNotifyMinGap is the floor between two notifications.
//
// Requests do not arrive on a schedule: a host setting itself up can propose
// several folders in a row, and each one is its own request id. Coalescing
// inside a single poll is free (they are all in one list), but three asks spread
// over three 5-second ticks would be three interruptions in fifteen seconds, and
// that is the shape of a notification people learn to dismiss without reading.
//
// 30 s is chosen, not inherited: the page a notification points at lists EVERY
// pending request on the machine, from every pairing (ui.go:164), so a second
// notification inside half a minute carries nothing the first one did not
// already carry. Anything new that lands inside the gap is HELD, never dropped —
// it goes out in the next notification, and until then it is already visible in
// the icon's tooltip and on the page.
const approvalNotifyMinGap = 30 * time.Second

// approvalForget is when a request id leaves this process's memory.
//
// It is the request's own lifetime and that is the whole derivation:
// requestsLoad deletes any request older than stepupRequestTTL on every read
// (stepup.go:562-573, stepupRequestTTL = 24h at stepup.go:62), so an id that has
// been out of the pending list for longer than that can never legitimately come
// back, and forgetting it cannot cause a second announcement.
//
// SHORTER WOULD BE A BUG, and this is the measurement behind that: the pending
// list goes empty for reasons that have nothing to do with the user answering
// anything. requestsLoad returns an EMPTY MAP on any read or unmarshal failure
// and reports no error (stepup.go:562-567 — `if err == nil` around both), and
// collectUIStatus returns with no approvals at all when loadPairings fails
// (ui.go:140-145). A Windows machine with a virus scanner holding the file open
// for a moment hits the first one. If the forget window were shorter than the
// blip, the id would come back looking brand new and be announced again.
const approvalForget = stepupRequestTTL

// approvalSeen is this process's memory of one request id.
type approvalSeen struct {
	lastSeen  time.Time
	announced bool
}

// approvalNotifier is that memory, plus the gap timer. One per process, driven
// from the tray's existing poll — it holds no lock because it is stepped from a
// single goroutine (tray_windows.go's refresh).
type approvalNotifier struct {
	seen       map[string]approvalSeen
	lastNotice time.Time
}

// approvalSink is the platform's half: what a notice actually DOES.
//
// An interface rather than a direct call into notify_windows.go, for one
// reason — it is the only way the DRIVE (below) gets tested on Linux. With a
// direct call, everything from "a second request arrived" to "the icon comes
// down" would be exercised only in a build nobody here can run.
type approvalSink interface {
	// show puts the waiting icon up with this tooltip, and when notice is
	// non-nil raises a notification through it.
	show(tip string, notice *uiNotice)
	// hide takes the waiting icon away: nothing is pending any more.
	hide()
}

// poll is one tick: fold what is pending into the memory, then tell the sink.
func (n *approvalNotifier) poll(now time.Time, pending []uiApproval, out approvalSink) {
	// step ALWAYS runs, including on an empty list — that is what ages the
	// memory out, and skipping it would make forgetting depend on there
	// happening to be traffic.
	notice := n.step(now, pending)
	if len(pending) == 0 {
		out.hide()
		return
	}
	out.show(approvalTip(len(pending)), notice)
}

// step folds one reading of the pending list into the memory and returns the
// notification to raise, or nil.
//
// NO GRACE WINDOW ON THE LIST ITSELF, and that is a decision rather than an
// omission. The obvious next move, once you know the list can go empty on a
// transient read failure (see approvalForget), is to keep treating it as pending
// for a few ticks. It was written and thrown away: it buys nothing the per-id
// memory does not already give — a re-appearing id is already known and already
// announced, so it cannot be announced twice — and it costs a tooltip that says
// "1 request is waiting" for half a minute AFTER the user answered the last one.
// A five-second flicker of an icon is a smaller lie than that.
func (n *approvalNotifier) step(now time.Time, pending []uiApproval) *uiNotice {
	if n.seen == nil {
		n.seen = map[string]approvalSeen{}
	}
	// Age out first, so an id that is pending right now is refreshed below and
	// can never be dropped while it is still being asked about.
	for id, e := range n.seen {
		if now.Sub(e.lastSeen) > approvalForget {
			delete(n.seen, id)
		}
	}

	fresh := 0
	for _, a := range pending {
		// An id never seen reads back the zero value, whose announced is false —
		// so a brand-new request and one that was held inside the gap take the
		// same path, which is what makes "held, not dropped" true.
		e := n.seen[a.ID]
		e.lastSeen = now
		n.seen[a.ID] = e
		if !e.announced {
			fresh++
		}
	}
	if fresh == 0 {
		return nil
	}
	// IsZero, not a subtraction: at process start lastNotice is the zero time,
	// and the first pending request must interrupt immediately rather than wait
	// out a gap that never started.
	if !n.lastNotice.IsZero() && now.Sub(n.lastNotice) < approvalNotifyMinGap {
		return nil // held, not dropped — they go out together next time
	}
	for _, a := range pending {
		e := n.seen[a.ID]
		e.announced = true
		n.seen[a.ID] = e
	}
	n.lastNotice = now
	notice := approvalNoticeFor(pending)
	return &notice
}

// approvalNoticeFor is what the notification says.
//
// It counts EVERYTHING pending, not only what is new since the last one. The
// number is meant to answer "how much is waiting on me", and a machine with two
// already-announced requests plus one new one has three waiting — saying "1"
// there would be true about the event and wrong about the queue, which is the
// same mistake trayStateLine avoids for the anchor (tray.go:36).
func approvalNoticeFor(pending []uiApproval) uiNotice {
	if len(pending) == 0 {
		return uiNotice{}
	}
	if len(pending) == 1 {
		a := pending[0]
		var body string
		switch {
		case a.Unreadable:
			// uiUnknownRequest (ui.go:234): this version does not know the kind
			// being asked about, which is the ordinary state of an install
			// mid-upgrade. The page turns that card red and demotes Approve; a
			// notification that read like any other would undo that before the
			// user ever got to the page.
			body = "This machine cannot describe what is being asked. " +
				"Click to see it — refusing is the safe answer."
		case len(a.Lines) > 0:
			body = a.Lines[0]
		default:
			body = "A host is asking this machine to allow something."
		}
		if a.Host != "" {
			body += "\nFrom " + a.Host + ". Click to approve or deny it."
		} else {
			body += "\nClick to approve or deny it."
		}
		// The title is not clipped and does not need to be: both titles here are
		// fixed text plus a count, so neither can reach noticeTitleMax — the
		// mutation check proved it by deleting the clip and finding no test that
		// could tell. TestEveryNoticeFitsTheWindowsFields asserts the property
		// instead of the call, so a title that DOES grow is caught. Anything
		// that slipped past both still cannot overrun the array: putUTF16 is the
		// wall.
		return uiNotice{
			Title: "Privatae — a request is waiting",
			Body:  clipUTF16(body, noticeBodyMax),
		}
	}

	hosts := distinctHosts(pending)
	var from string
	switch {
	case len(hosts) == 0:
		from = ""
	case len(hosts) > 3:
		// Past three, naming them all is a wall of text in a 255-unit field that
		// nobody reads. The page names every one.
		from = fmt.Sprintf(" from %d hosts", len(hosts))
	default:
		from = " from " + joinNames(hosts)
	}
	return uiNotice{
		Title: fmt.Sprintf("Privatae — %d requests are waiting", len(pending)),
		Body: clipUTF16(fmt.Sprintf("%d requests%s are waiting on you.\nClick to see what they ask.",
			len(pending), from), noticeBodyMax),
	}
}

// approvalTip is what the waiting icon says on hover. It is the one part of this
// that is true continuously rather than at a moment, so it carries the count and
// nothing else.
func approvalTip(n int) string {
	if n == 1 {
		return clipUTF16("Privatae — 1 request is waiting for you", noticeTipMax)
	}
	return clipUTF16(fmt.Sprintf("Privatae — %d requests are waiting for you", n), noticeTipMax)
}

// distinctHosts keeps the order the pairings were read in (collectUIStatus walks
// loadPairings and appends each pairing's approvals, ui.go:147-165), so the
// first host named is the first host configured rather than whichever one sorted
// first.
func distinctHosts(pending []uiApproval) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range pending {
		if a.Host == "" || seen[a.Host] {
			continue
		}
		seen[a.Host] = true
		out = append(out, a.Host)
	}
	return out
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// clipUTF16 shortens s to at most max UTF-16 code units — the unit the Windows
// arrays above are measured in, which is neither bytes nor runes.
//
// THE BUG IT EXISTS TO AVOID is a character outside the Basic Multilingual
// Plane. An emoji, or one of the rarer CJK ideographs, is ONE rune and TWO
// UTF-16 units (a surrogate pair). Counting in runes overruns the array;
// counting in units but cutting anywhere lands between the two halves of a pair,
// which is not a character at all and renders as a box or truncates the string
// at the shell's decoder. This is ordinary input, not an exotic case: the body
// of a notification is describeRequest's first line, which prints the host's
// requested path verbatim (stepup.go:363), and people name folders in their own
// language and put emoji in them.
//
// The ellipsis is U+2026, inside the BMP, so it costs exactly one unit.
func clipUTF16(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf16Len(s) <= max {
		return s
	}
	budget := max - 1 // room for the ellipsis
	var b strings.Builder
	n := 0
	for _, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		if n+w > budget {
			break
		}
		b.WriteRune(r)
		n += w
	}
	return strings.TrimRight(b.String(), " ") + "…"
}

// putUTF16 copies s into one of those fixed WCHAR arrays, always leaving it
// NUL-terminated and never leaving half a surrogate pair at the end.
//
// It is untagged because nothing about it is Windows-specific except where the
// destination came from, and because it is the LAST line of defence: clipUTF16
// above is what is supposed to make the text fit, and this is what makes a bug
// in that a short caption instead of a buffer the shell reads past the end of.
// `copy` alone is not enough — it silently truncates and would drop the NUL.
func putUTF16(dst []uint16, s string) {
	if len(dst) == 0 {
		return
	}
	u := utf16.Encode([]rune(s))
	if len(u) > len(dst)-1 {
		u = u[:len(dst)-1]
		// A high surrogate with its partner cut off is not a character. Drop it
		// rather than hand the shell an unpaired one.
		if n := len(u); n > 0 && u[n-1] >= 0xD800 && u[n-1] <= 0xDBFF {
			u = u[:n-1]
		}
	}
	n := copy(dst, u)
	dst[n] = 0
}

// utf16Len is len(utf16.Encode([]rune(s))) without building either slice.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// secondRunNotice is runguard_windows.go's refusal, written for a dialog box
// rather than for a terminal.
//
// It is deliberately NOT the same string as the error that goes to stderr. That
// one is laid out for a console — indented continuation lines, "you can close
// this window" meaning the console window — and the two media want different
// words for the same fact. They live next to each other (runguard_windows.go) so
// they are maintained together.
//
// The length caps above do NOT apply here: MessageBoxW takes an ordinary
// null-terminated string with no fixed buffer, unlike the notification-area
// struct.
func secondRunNotice() uiNotice {
	return uiNotice{
		Title: "Privatae bastion is already running",
		Body: "This machine is already serving your hosts.\r\n\r\n" +
			"A second copy would fight the first one for the same local ports, so this " +
			"one is stopping. Nothing is wrong and nothing has stopped working.\r\n\r\n" +
			"If you believe the running one is dead, end privatae-bastion.exe in Task " +
			"Manager and start this again.",
	}
}
