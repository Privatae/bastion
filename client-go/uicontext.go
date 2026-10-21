package main

// uicontext.go — the routes of the user-run context surface (contextui.go).
//
// There are five, and the shape of the list is the point: three reads, one walk
// of the person's own directory, and one ASK. Nothing here grants anything.
//
// The ask is the interesting one. Handing a folder to a bastion agent is not
// something this process can do on its own authority, and it must not be: a
// folder becomes a context store only when the paired host approves the draft
// with a step-up code (addfolder.go:13-15, "the draft lands INERT"). So this
// surface does exactly what the `add-folder` verb does — validate locally,
// where the box can actually check, and forward a draft — and then says so
// plainly. The person sees "asked for", never "done".

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (u *uiServer) contextRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/fragments/context", u.guarded(u.contextFragment))
	mux.HandleFunc("/context/scan", u.guarded(u.contextScan))
	mux.HandleFunc("/context/stop", u.guarded(u.contextStop))
	mux.HandleFunc("/context/ask", u.guarded(u.contextAsk))
	mux.HandleFunc("/", u.root)
}

// uiContext is the page. It carries the map view whole rather than re-deriving
// it, because the treemap, the escaping and the accounting of what the walk
// could NOT read are the same problem on both surfaces and solving it twice is
// how the two drift apart.
type uiContext struct {
	Version string
	Home    string
	Map     uiDiskMap

	// Held is the context that ALREADY EXISTS on this machine — the folders a
	// host has been granted and is indexing. Without it a page called "Your
	// context" showed a file browser and a list of requests, and answered every
	// question except the one its title asks.
	Held []uiContextHeld
	// HeldNote is why Held is empty or partial, in the box's own words. A page
	// that shows nothing and says nothing reads as "you have no context", which
	// on a machine whose records this process cannot read is a lie.
	HeldNote string

	// Asks is what this person has asked for, newest first, and it OUTLIVES the
	// window (contextAsksPath). It was session-only in memory at first, which
	// meant closing the page erased the only record that you had asked for
	// something at all — the request is still out there waiting on somebody,
	// and the person who made it could no longer see that they made it.
	Asks []uiContextAsk

	Flash      string
	FlashClass string
}

// uiContextAsk is one folder handed to a host, and what happened to the asking.
type uiContextAsk struct {
	Path string
	Name string
	Host string
	At   string
	// Sent distinguishes "the host has it" from "this machine could not even
	// pass it on". The second is not a failure of the request, and saying so
	// matters: the person did nothing wrong and there is nothing for them to
	// retry until the machine can reach its host.
	Sent bool
	Note string
}

// uiContextHeld is one folder that IS context: a host holds a signed grant for
// it and the agent indexes it here.
type uiContextHeld struct {
	Host     string
	Root     string
	What     []string // the mask, in plain words
	Sweep    string
	Expires  string
	Readable bool
	StoreID  string
}

// collectHeldContext reads what is already context on this machine.
//
// It reuses uiFoldersFor (uigiven.go) rather than re-reading the store file,
// because two readers of the same record drift and the admin console's version
// is the one with the pending/revoked guard in it — asking a non-active pairing
// for its directory CREATES that directory (config.go:115), which is the exact
// defect an earlier fix closed.
func collectHeldContext() ([]uiContextHeld, string) {
	ps, err := loadPairings()
	if err != nil {
		return nil, "This machine's pairing records cannot be read from here (" + err.Error() +
			"), so this page cannot say what is already context. That is a limit of what " +
			"this window can see, not a statement that nothing is shared."
	}
	var out []uiContextHeld
	var notes []string
	for _, c := range ps {
		if !c.active() {
			continue
		}
		folders, why := uiFoldersFor(c, true)
		if why != "" {
			notes = append(notes, c.HostName+": "+why)
			continue
		}
		for _, f := range folders {
			out = append(out, uiContextHeld{
				Host: c.HostName, Root: f.Root, What: f.MaskWords,
				Sweep: f.Sweep, Expires: f.Expires,
				Readable: f.Readable, StoreID: f.StoreID,
			})
		}
	}
	if len(out) == 0 && len(notes) == 0 {
		return nil, "Nothing on this machine is context yet. Pick a folder below and ask."
	}
	return out, strings.Join(notes, " ")
}

func (u *uiServer) contextPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderContext(w, "context.html", r.URL.Query().Get("p"), "", "")
}

func (u *uiServer) contextFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderContext(w, "context", r.URL.Query().Get("p"), "", "")
}

// contextScan walks the person's own directory. POST, so the Origin check
// applies: a walk is the one thing on this page that makes the machine work.
func (u *uiServer) contextScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// ALWAYS the home scope, and it is not a parameter. There is no form value
	// to widen here because there is nothing to widen TO: this process cannot
	// read other people's files, so a whole-machine option would be a button
	// that produced a map full of "permission denied" and told the person
	// something false about what this surface is for.
	if diskMap.dmStart(dmScopeHome) {
		u.renderContext(w, "context", r.FormValue("p"),
			"Counting up your files. It keeps going if you leave this page.", "ok")
		return
	}
	u.renderContext(w, "context", r.FormValue("p"), "Already counting — this is it.", "warn")
}

func (u *uiServer) contextStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	diskMap.dmStop()
	u.renderContext(w, "context", r.FormValue("p"),
		"Stopped. What it had already counted is kept and is labelled as partial.", "warn")
}

// contextAsk forwards a draft store to a paired host. It is the ONLY route on
// this surface that leaves the machine.
func (u *uiServer) contextAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimSpace(r.FormValue("path"))
	name := strings.TrimSpace(r.FormValue("name"))

	if why := u.contextRefuseOutsideHome(path); why != "" {
		u.renderContext(w, "context", r.FormValue("p"), why, "bad")
		return
	}
	// The same local validation the CLI verb does, in the same words: this box
	// can actually check a path, and the host cannot.
	if c := uiCheckFolder(path); c.Class == "bad" {
		line := c.Line
		if c.Note != "" {
			line += " " + c.Note
		}
		u.renderContext(w, "context", r.FormValue("p"), "Nothing was asked for: "+line, "bad")
		return
	}

	ask := uiContextAsk{Path: path, Name: name, At: uiNow().Format(uiEventTime)}
	// THE SOCKET FIRST, THE DIRECT PATH SECOND, and the order is the whole
	// design. If the daemon is serving a context socket, it can forward on this
	// person's behalf with their identity read from the kernel — which is the
	// only route that works when the daemon is not theirs. If it is not (an
	// older bastion, a platform without it, or simply not running), the direct
	// path is tried, and that one works exactly when the daemon IS theirs.
	// Between them they cover both machines, and neither invents an identity.
	sent, host, note, available := contextAskViaSock(path, name)
	if !available {
		sent, host, note = contextForwardDraft(path, name)
	}
	ask.Sent, ask.Host, ask.Note = sent, host, note
	u.contextRecord(ask)

	if sent {
		u.renderContext(w, "context", r.FormValue("p"),
			"Asked "+host+" for "+filepath.Base(path)+". It is not shared yet — somebody "+
				"has to approve it there with a code before anything is read.", "ok")
		return
	}
	u.renderContext(w, "context", r.FormValue("p"), note, "bad")
}

// contextRefuseOutsideHome is the one check this file makes about WHICH folder,
// and it is a courtesy rather than a control.
//
// The control is the kernel: this process runs as the person, so a path they
// cannot read produces a draft the bastion agent could never index, and the
// grant the host signs is enforced on the box against the same uid. What this
// adds is an honest refusal at the point of asking, instead of a request that
// travels to a host, waits for somebody to approve it, and only then fails.
func (u *uiServer) contextRefuseOutsideHome(path string) string {
	if strings.TrimSpace(path) == "" {
		return "No folder was named."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "That path cannot be resolved: " + err.Error()
	}
	home := u.contextHome
	if home == "" {
		return "This surface does not know which directory is yours, so it will not " +
			"forward anything."
	}
	if abs != home && !strings.HasPrefix(abs, ensureSep(home)) {
		return "That folder is outside " + home + ". This page only offers your own " +
			"files; a folder belonging to the machine as a whole is the machine " +
			"administrator's to share, from `privatae-bastion ui`."
	}
	// A folder you cannot read is not one you can hand over. Checked HERE, as
	// this user, which is the only place the answer is authoritative.
	f, err := os.Open(abs)
	if err != nil {
		return "That folder cannot be opened by you: " + err.Error()
	}
	_ = f.Close()
	return ""
}

// contextForwardDraft posts the draft to the running daemon, exactly as the
// `add-folder` verb and the setup page do.
//
// WHEN THIS CANNOT WORK, AND WHY THAT IS THE HONEST ANSWER FOR NOW. The
// daemon's loopback endpoint is guarded by the OperatorSecret, which lives in
// the daemon's own pairing file at 0600 (config.go). A person running this verb
// as themselves on a machine whose daemon runs as root cannot read it — and
// must not be able to, because that secret also opens the git-credential lane.
//
// So on a single-user machine, where the daemon is this person's own, the ask
// goes through. On a networked bastion it cannot yet, and the page says so in
// those words rather than failing vaguely. Closing that gap is a local socket
// where the daemon reads the asking user's identity from the KERNEL rather than
// from anything the client says — deliberately not bolted on here, because a
// new transport with a new identity check deserves its own review.
func contextForwardDraft(path, name string) (sent bool, host string, note string) {
	return contextForwardDraftAs(path, name, "")
}

// contextForwardDraftAs is the same forward with the asking user named.
//
// `asUser` is EMPTY when this process is the one that can reach the daemon
// directly — it is then the person's own daemon and the ask is theirs by
// construction. It is set only by the socket path (contextsock.go), where the
// daemon is forwarding on somebody else's behalf and the name came from the
// KERNEL, never from the request. The display name carries it so the person
// approving on the host can see who asked without this machine having to be
// believed about it.
func contextForwardDraftAs(path, name, asUser string) (sent bool, host string, note string) {
	ps, err := loadPairings()
	if err != nil {
		return false, "", "This machine's pairing records cannot be read from here (" +
			err.Error() + "), so there is no host to ask. On a machine where the bastion " +
			"runs as an administrator, ask its administrator — or run this on your own machine."
	}
	var cfg *Config
	for _, p := range ps {
		if p.active() {
			cfg = p
			break
		}
	}
	if cfg == nil {
		return false, "", "No host is paired with this machine yet, so there is nobody to " +
			"ask. Pairing happens in the machine's own console."
	}
	display := name
	if asUser != "" {
		// Named in the draft rather than in a side channel: the host shows the
		// display name to whoever approves, and "who asked" is the first thing
		// they need. The bastion's own hostname already travels as `server`.
		if display == "" {
			display = filepath.Base(path)
		}
		display += " (asked by " + asUser + ")"
	}
	body, _ := json.Marshal(map[string]string{"root": path, "display_name": display})
	req, err := http.NewRequest(http.MethodPost,
		"http://"+cfg.ListenAddr+"/dcn/propose", bytes.NewReader(body))
	if err != nil {
		return false, cfg.HostName, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.OperatorSecret)
	cl := &http.Client{Timeout: 20 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return false, cfg.HostName, "The bastion on this machine did not answer (" +
			err.Error() + "), so nothing was sent. It may not be running."
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b := make([]byte, 400)
		n, _ := resp.Body.Read(b)
		return false, cfg.HostName, fmt.Sprintf("The bastion refused to forward it (%d): %s",
			resp.StatusCode, strings.TrimSpace(string(b[:n])))
	}
	return true, cfg.HostName, ""
}

// ── the asks a person has made ──────────────────────────────────────────────

// THE ASKS OUTLIVE THE WINDOW, and the first version did not.
//
// They were kept in memory on the server object, with a comment arguing that
// the durable record lives on the host and a second copy here would be a second
// thing to be wrong. That reasoning was about the GRANT, and it answered the
// wrong question. A request that is waiting on somebody else is not a grant —
// it is a thing the person did, and closing the window erased the only evidence
// they had done it. They are then left asking a host they cannot see whether
// they already asked.
//
// So this is written in the asking user's OWN config dir, by the process that
// runs as them. It is a record of what YOU asked for, not a copy of what the
// host decided; the host remains the only authority on the second.
func contextAsksPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "context-asks.json"), nil
}

const contextAsksKept = 50

func (u *uiServer) contextRecord(a uiContextAsk) {
	u.contextMu.Lock()
	defer u.contextMu.Unlock()
	u.contextAsks = append([]uiContextAsk{a}, u.contextAsks...)
	if len(u.contextAsks) > contextAsksKept {
		u.contextAsks = u.contextAsks[:contextAsksKept]
	}
	// Best effort, and deliberately not fatal: failing to write the history of
	// a request must never fail the request itself, which has already reached
	// the host by the time this runs.
	p, err := contextAsksPath()
	if err != nil {
		return
	}
	b, err := json.MarshalIndent(u.contextAsks, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	if err := os.WriteFile(p, b, 0o600); err == nil {
		// Re-chmod for the reason uiauth.go:108-111 gives: os.WriteFile applies
		// its mode only on CREATE, so a file first written under a loose umask
		// keeps those permissions for ever. This one names folders a person
		// asked to share.
		_ = os.Chmod(p, 0o600)
	}
}

// contextLoadAsks reads the history back at start-up. An unreadable file is not
// an error the person needs: it means the list shows nothing, which is the same
// thing it showed before this existed.
func (u *uiServer) contextLoadAsks() {
	p, err := contextAsksPath()
	if err != nil {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var out []uiContextAsk
	if err := json.Unmarshal(b, &out); err != nil {
		return
	}
	u.contextMu.Lock()
	defer u.contextMu.Unlock()
	u.contextAsks = out
}

func (u *uiServer) contextAsked() []uiContextAsk {
	u.contextMu.Lock()
	defer u.contextMu.Unlock()
	return append([]uiContextAsk(nil), u.contextAsks...)
}

// renderContext sets the SAME four headers renderWith and renderDiskMap do. The
// duplication is made safe by the test that compares the responses header by
// header, for the reason uidiskmap.go gives.
func (u *uiServer) renderContext(w http.ResponseWriter, name, path, flash, class string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	held, heldNote := collectHeldContext()
	v := uiContext{
		Version:  clientVersion,
		Home:     u.contextHome,
		Map:      collectDiskMap(path),
		Held:     held,
		HeldNote: heldNote,
		Asks:     u.contextAsked(),
		Flash:    flash, FlashClass: class,
	}
	if err := u.tpl.ExecuteTemplate(w, name, v); err != nil {
		uilogf("render %s: %v\n", name, err)
	}
}
