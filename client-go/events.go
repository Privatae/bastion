package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// events.go — what HAPPENED to this machine, kept where the person sitting at
// it can read it.
//
// THE DEFECT. contain.go's entire output was a line on stdout —
// `contain: terminated agent pid %d and %d child process(es) (host-directed)`,
// still printed at contain.go:106 — and it persisted nothing. A host had just
// killed the user's running programs and the box kept no trace of it, so a
// machine whose agents were contained thirty seconds ago renders exactly like
// one nothing has ever happened to. On Windows it relaunches with DETACHED_PROCESS
// after a self-update (relaunch_windows.go:47), so that line goes to a console
// that does not exist: the same defect the whole local UI exists to fix,
// landing on the one directive that takes something away from the user
// without asking them first.
//
// WHY THIS IS NOT directive_refusal.go, whose shape it otherwise copies.
// That file holds ONE slot, last-one-wins, cleared when the same directive
// later succeeds (directive_refusal.go:50). Correct there: a refusal is a
// STATE, it rides the enforcing report on every beat, and the gate that
// produced it re-asserts it on the next one. A containment is an EVENT — it
// cannot be resolved by a later success, the second one does not replace the
// first, and nothing regenerates it if it is lost. Same shape (package-level,
// one mutex, a clock seam for tests), different lifetime, so a list instead of
// a slot.
//
// IT SURVIVES A RESTART, and that is the deliberate half of the design.
// The cheaper choice — memory only, like directive_refusal.go, with no file, no
// cap and no corruption path — ties the record to the PROCESS, and this process
// exits on purpose on every self-update (update.go:127, `os.Exit(0)` right
// after relaunchAfterUpdate). That is the most common restart this binary has
// and it is the exact event that ate the console in the first place. A record
// of "your host killed the programs you were running" that a restart erases is
// not a record of it. Set against that, the file holds a host name, a pid and a
// signature NAME (agents.go:180 — the table entry that matched, not the command
// line), in the directory that already holds this machine's pairing
// credentials and TOTP seeds at 0700.
//
// THE DAEMON OPENS IT; the recorder never resolves the path by itself. A
// recordLocalEvent that called configDir() on demand would write into the real
// config dir of whoever runs `go test`: agents_kind_test.go:342 drives
// maybeContain with stubbed kills and no config isolation, so two forged "your
// host stopped an agent" events would appear in a developer's own live UI. That
// is not hypothetical here — freeagent_managed_test.go:61-68 records the same
// class of accident, measured on a machine with an active bastion. So the
// path is claimed once by the daemon (openLocalEventLog, called from
// startUIServer), and anything recorded before that instant is merged in when
// it is, which closes the window between the first heartbeat and the UI coming
// up rather than pretending it does not exist.

// localEvent is one thing that happened to this machine, already in the words
// the page will show. Text is composed by the CALLER, because the caller is the
// only place that still holds the host, the pid and the signature; this file
// never formats a sentence it would have to keep in step with contain.go.
type localEvent struct {
	// Kind is the family, so the page can style without parsing Text.
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}

// eventContain is the only kind today. Named rather than inlined because the
// page styles on it and a typo in a string literal is a silent miss.
const eventContain = "contain"

// localEventCap bounds the file. Every record rewrites the whole blob under the
// mutex, and the page renders all of it, so an uncapped log would grow for the
// life of the install and be re-serialised on each append. Twenty is roughly
// 2 KB and is far more containment than any healthy machine will ever see — if
// a box passes twenty, the oldest are not what its owner needs to read.
const localEventCap = 20

var (
	localEventMu sync.Mutex
	// localEventList is oldest-first, at most localEventCap.
	localEventList []localEvent
	// localEventFile is "" until the daemon claims it. See the header.
	localEventFile string
	// localEventNow is the clock seam: the test pins the timestamp, exactly as
	// directive_refusal.go:35 does.
	localEventNow = time.Now
)

// localEventPath is the record's home — beside ui.addr and the pairing state,
// in the config dir configDir() creates at 0700 (config.go:137).
func localEventPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "events.json"), nil
}

// openLocalEventLog binds the record to disk. Called once, by the daemon.
//
// It MERGES rather than replaces: events recorded before this call (the window
// between a pairing's first beat and the UI starting, run.go:120-131) are newer
// than anything on disk by construction, so they go after the loaded ones and
// the whole list is saved. A second call is a no-op, so the merge can never
// duplicate what it just wrote.
func openLocalEventLog() {
	p, err := localEventPath()
	if err != nil {
		return
	}
	localEventMu.Lock()
	defer localEventMu.Unlock()
	if localEventFile != "" {
		return
	}
	localEventFile = p
	pending := localEventList
	localEventList = append(loadLocalEvents(p), pending...)
	trimLocalEventsLocked()
	if len(pending) > 0 {
		saveLocalEventsLocked()
	}
}

// loadLocalEvents reads the file, or returns nothing. A missing, unreadable or
// corrupt file is NOT an error worth surfacing: this is an advisory record, and
// a bastion that refuses to run because its event log will not parse would turn
// a cosmetic problem into an outage. Starting empty loses history; refusing to
// start loses the machine.
func loadLocalEvents(path string) []localEvent {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []localEvent
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// recordLocalEvent appends one event. Best-effort by design: a write failure
// must never change what the caller did, because by the time this is called the
// processes are already dead.
func recordLocalEvent(kind, text string) {
	localEventMu.Lock()
	defer localEventMu.Unlock()
	localEventList = append(localEventList, localEvent{
		Kind: kind, At: localEventNow().UTC(), Text: text,
	})
	trimLocalEventsLocked()
	saveLocalEventsLocked()
}

func trimLocalEventsLocked() {
	if len(localEventList) > localEventCap {
		localEventList = append([]localEvent(nil), localEventList[len(localEventList)-localEventCap:]...)
	}
}

// saveLocalEventsLocked writes the whole list through atomicWrite (ctx.go:133 —
// temp file, 0600, rename), so a reader never sees a half-written blob and a
// crash mid-append leaves the previous list intact rather than an empty one.
func saveLocalEventsLocked() {
	if localEventFile == "" {
		return
	}
	if b, err := json.MarshalIndent(localEventList, "", "  "); err == nil {
		_ = atomicWrite(localEventFile, b)
	}
}

// localEventsNewestFirst is what the page renders: a copy, newest first,
// because a person reads "what just happened" before "what happened last
// month".
//
// Newest by the order things were RECORDED, not by their timestamps. The two
// agree whenever the clock moves forward, and when it does not — an NTP
// correction, a VM resuming from a snapshot — the recording order is the one
// that is true about what happened in what sequence, while sorting by At would
// reorder the page to agree with a clock that was wrong.
//
// A copy rather than the slice itself: the caller renders outside the mutex and
// the next containment appends in place.
func localEventsNewestFirst() []localEvent {
	localEventMu.Lock()
	defer localEventMu.Unlock()
	out := make([]localEvent, 0, len(localEventList))
	for i := len(localEventList) - 1; i >= 0; i-- {
		out = append(out, localEventList[i])
	}
	return out
}
