package main

// uigiven.go — WHAT THIS MACHINE HAS GIVEN AWAY.
//
// WHY IT EXISTS. The local UI's design names the same gap twice, and it is
// the most uncomfortable fact in it. A
// host paired here can read the title of every window open on this screen and
// which one has focus (computer:windows), walk the controls inside one app
// (computer:tree), read the files in the folders it was granted (the thirteen
// dcn_* / ctx_* / backup_fetch ops, mgmt.go:103-115) and open a ROOT shell
// (session:root, session.go:127) — and the machine gives the person sitting at
// it no local way to see any of it. `dcn_list` answers the HOST. `pairing_list`
// is answered only on the anchor host's own lane (mgmt.go:224-230). There has
// been no verb here that answers "what did I agree to".
//
// Two views close it: the CEILING (which host may ask for what) and the
// FOLDERS (what it can actually reach). They are two views and not one because
// they are two different walls — holding the `dcn` family only means the caps
// ceiling will not refuse a dcn op; every individual read still needs a signed
// grant for that store (dcn.go:240-278). A page that showed only the ceiling
// would overstate, and one that showed only the folders would miss the shell.
//
// BOTH ARE READ-ONLY BY DECISION, NOT BY OMISSION. Whether the local UI gets an
// OFF switch for a granted capability is a product decision and is not this
// page's to take. So there is no toggle here, and the page is deliberately not
// shaped like a settings screen with the switches missing — no empty action
// column, no disabled controls. It states what is true and names the two things
// that DO end a grant today: removing the folder on your Host, which drops the
// grant here (dcn_grant_drop, mgmt.go:109), and `privatae-bastion unpair
// <host>` (main.go:193).
//
// THE MATRIX ASKS THE REAL GATE. Every "granted / refused" on this page is
// capsAllow(host, op) — the same function handleMgmtConnFor (mgmt.go:238),
// handleHarnessConn (harness.go:116), the egress lane (egress.go:57), the
// inference forwards (run.go:856) and sessionAllowedByCaps (session.go:214) ask
// before they serve. The rejected alternative was to re-derive the answer here
// from anchor.json plus the grant file, which is every branch of capsAllow
// (anchor.go — five of them now the local switch is inside it) copied into a
// template — and the first time one of them changed, this page would go on
// confidently saying what used to be true. A view that re-implements its
// subject is a second wall that drifts. This one cannot disagree with the gate,
// because it asks the gate.
//
// AND THE SWITCHED-OFF TAG HAS TO COME FROM THE GATE TOO, which is the half
// that was missing. `Held` asks capsAllow; the tag reads the deny list. On an
// unanchored box the gate did not consult that list, so the two sources gave
// opposite answers about the same capability on the most security-relevant page
// in the binary — the page said "switched off by you" and the machine served
// the op. Fixed in the gate rather than the page (anchor.go), because the page
// being right about a gate that is wrong is not the property this paragraph
// claims.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// ── the ceiling ─────────────────────────────────────────────────────────────

// uiCapFamily is one of allCaps (anchor.go:445), said in the words of what the
// host can actually do to this machine with it.
type uiCapFamily struct {
	Name string
	// Probe is an op in this family. It exists so the page ASKS capsAllow
	// rather than reasoning about it. Asserted against opFamily in the test:
	// a rename that moved an op out of its family would otherwise leave this
	// page probing the wrong gate and answering confidently.
	Probe string
	// Line is the whole capability in one sentence — what a person would say
	// they agreed to. Detail is the specifics.
	Line   string
	Detail string
	// Second is the wall BEYOND this ceiling, where one exists. Naming it
	// matters in both directions: without it the page overstates three
	// families, and a page that overstates gets discounted wholesale.
	Second string
	// Grave marks the three the design singles out — the shell, the files
	// and the screen. Nothing about the page's behaviour turns on it; it is
	// what the copy leads with.
	Grave bool

	// Filled per pairing.
	Held bool
	// SwitchedOff is the person at this machine having turned this family off
	// (localdeny.go). It is independent of Held: a family can be GRANTED by the
	// host and OFF here, which is the entire point of the control — the grant
	// is untouched and the machine refuses anyway.
	SwitchedOff bool
	Ops         []string
}

// uiGivenFamilies is allCaps in a deliberate order: the root shell, then the
// files, then the screen, then the rest. A list a person reads top-down should
// lead with what would frighten them, not with "egress".
//
// The set is asserted equal to allCaps in the test, so a family added to the
// ceiling cannot arrive on this page undescribed — which is the failure mode
// that matters here. A capability the machine gives away and does not mention
// is worse than no page at all: the page would be the reason nobody looked.
var uiGivenFamilies = []uiCapFamily{
	{
		Name: "session", Probe: sessionOpOpen, Grave: true,
		Line: "Open a shell on this machine.",
		Detail: "session:open runs a terminal here as an unprivileged user when the bastion " +
			"runs as root (a dedicated session account if one exists, else nobody), and as the " +
			"bastion's own user otherwise. session:root runs as root. Both are real shells, " +
			"streamed to the host over the tunnel this machine dialled out.",
		Second: "A shell is your own act in your Terminal app, and needs no standing grant from " +
			"the host: on a machine anchored to a host, opening one takes your approval on your " +
			"device or here, bound to that one session. A root shell needs three more things: the " +
			"bastion must be running as root, a second factor must be enrolled on this machine, " +
			"and you must approve that exact session here with your code. The host never sees the code.",
	},
	{
		Name: "dcn", Probe: "dcn_list", Grave: true,
		Line: "Read your files.",
		Detail: "List and read the files in the folders below, search them, and build an index " +
			"of them. The same family also lets the host write into this machine's own store — " +
			"ctx_put, ctx_del and backup_fetch land bytes in the bastion's private directory, " +
			"not in your folders.",
		Second: "Which of your files, exactly, is the second list on this page. This family only " +
			"means a request will not be refused for being the wrong KIND; every individual " +
			"read is still checked against a signed grant for that one folder.",
	},
	{
		Name: "observe", Probe: "observe:host", Grave: true,
		Line: "Read this machine, and what is on its screen.",
		Detail: "The machine itself: its firewall text, its listening sockets, its disks, its " +
			"kernel log, which services failed, a network probe from here, and — where a " +
			"read-only kubeconfig was placed here at install — the clusters it can reach. " +
			"And the screen in front of you: the title of every window open right now, which " +
			"application owns each one and which has focus, plus the names, text and state of " +
			"the controls inside one application. Text rather than pixels, which does not " +
			"make it less of a read.",
		Second: "Nothing. On this machine the grant is the only wall in front of these answers.",
	},
	{
		Name: "models", Probe: "model:list",
		Line:   "Change which models sit on this machine's disk.",
		Detail: "Pull a model onto it — gigabytes — list what is there, and delete one.",
		Second: "A host can only delete a model it placed here itself. One that was already on " +
			"the machine, or that another host put there, is not its to drop.",
	},
	{
		Name: "harness", Probe: "harness:run",
		Line:   "Run work on this machine.",
		Detail: "Harness jobs: the host dispatches a job over the tunnel and it executes here.",
	},
	{
		Name: "egress", Probe: "egress",
		Line: "Send traffic out through this machine's internet connection.",
		Detail: "Requests leave from here, over this connection, carrying this machine's " +
			"address rather than the host's.",
	},
	{
		Name: "services", Probe: "service:up",
		Line: "Run a server on this machine that stays up.",
		Detail: "A server your host built to your spec — a private code server, say — kept running " +
			"in a container here across restarts, with its data in the bastion's own directory. " +
			"It runs with NO network: it cannot reach this machine, your network or the internet. " +
			"The one way in is the host's tunnel, one port per server (18100-18199), spliced to " +
			"the server's socket. The host can start one, stop one and read their state.",
		Second: "Each start and each stop needs your approval on an anchored machine; reading " +
			"the list does not. Stopping a server keeps its data unless the request says to " +
			"delete it. Reaching a server needs more than this: a reach grant naming that host and that " +
			"server, which you approve, checked on every connection. A member host cannot replace or " +
			"stop a server another host built.",
	},
	{
		Name: "ops", Probe: "op_apply",
		Line: "Run programs the host wrote on this machine.",
		Detail: "An op is a program your host built and tested, sent here with signed terms and " +
			"held under them. It dry-runs in a sandbox first (an overlay over a read-only view of " +
			"this machine, no network) and the card shows exactly the files it would change; " +
			"applying commits that same run. Rung 6: file changes only, on Linux.",
		Second: "Every apply spends your approval (device or console), bound to the op's exact " +
			"bytes, arguments and the change list you saw; a standing grant is 'user' only, bounded " +
			"and counted, and `privatae-bastion ops drop` takes it back here. The dry run itself runs " +
			"before you are asked, as root for a root op: it can change nothing on this machine, but " +
			"what it reads and prints goes back to the host. This machine's own record (its keys, " +
			"grants and ledgers) is never an effect and never a change.",
	},
	{
		Name: "inference", Probe: "inference",
		Line: "Use the model servers already running here.",
		Detail: "The three inbound forwards the host dials over its own tunnel: ollama on " +
			"11434, the OpenAI-compatible server on 18080 and the PII sterilizer on 18081. " +
			"The right to use what is already loaded. Changing WHICH models are loaded is " +
			"the models capability above, and it is deliberately not the same grant.",
	},
}

// uiFamilyOps groups this binary's REAL op vocabulary by family, so the list
// under each heading is what this build will actually answer rather than a list
// somebody remembered to update.
//
// mgmtOpVocabulary (enforcing.go:67) is handlerOps + sessionOps + p8AllowedOps
// — every op that reaches handleMgmtConnFor. The three LANE gates are NOT in
// it: harness:run (harness.go:116), egress (egress.go:57) and inference
// (run.go:856) are passed to capsAllow at their own lane and never arrive as a
// mgmt job, so a list built from the vocabulary alone would show three families
// with nothing under them, which reads as "this grants nothing".
func uiFamilyOps() map[string][]string {
	ops := append(mgmtOpVocabulary(), "harness:run", "egress", "inference",
		serviceGateOp("up"), serviceGateOp("down"), serviceGateOp("status"), serviceCapability)
	out := map[string][]string{}
	for _, op := range ops {
		if fam := opFamily(op); fam != "" {
			out[fam] = append(out[fam], op)
		}
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

// ── the folders ─────────────────────────────────────────────────────────────

// uiSharedFolder is ONE entry of grants.json's Stores map (dcn.go:47-63),
// rendered as what it really contains rather than what a grant is assumed to
// hold. There is no folder NAME in a machine store grant and no label — the
// signed terms carry a root path, a mask, excludes and an expiry (dcn.go:66-83)
// — so this shows the path and says plainly when a field is absent instead of
// printing a default nobody signed.
type uiSharedFolder struct {
	StoreID string
	// Readable is false when the record's canonical bytes do not decode or do
	// not parse. Then only StoreID and the verdict below can be shown.
	Readable bool
	Root     string
	// Mask is the raw signed values; MaskWords is the same list said in plain
	// words, computed HERE rather than in the template because html/template
	// can only call functions registered on the template, and registering a
	// FuncMap means reaching into newUIServer (ui.go:246), which this unit does
	// not own. Both travel: a mask value this version cannot describe still has
	// to appear exactly as it was signed.
	Mask      []string
	MaskWords []string
	Excludes  []string
	Expires   string
	Sweep     string
	TTLDays   int
	Class     string
	Sensitive bool
	// Sealed: the record carries a seal recipient. Called out separately
	// because it is the one field that travels OUTSIDE the signed bytes
	// (dcn.go:59-62), so it is not part of what was approved.
	Sealed bool
	// InForce is the whole verdict: this folder is reachable by this host right
	// now. Why carries the reason when it is not.
	InForce bool
	Why     string
}

// uiFoldersFor answers "what of mine is shared with this host, from here".
//
// The verdict comes from dcnVerifyRec (dcn.go:130), the same function every
// dcn op re-runs before it touches a byte, plus the conditions dcnLoadGrantMask
// applies right after it: a machine-class grant with a root (dcn.go:264) whose
// mask names at least one operation (dcn.go:270). Nothing here re-implements
// the check. A SIGNATURE THAT VERIFIES IS NOT THE VERDICT — stopping there was
// the first cut and it showed two refused grants as live shares.
//
// dcnHeld IS PART OF THE VERDICT, and leaving it out was a real overstatement
// in the first cut of this page — caught by rendering it. The caps ceiling runs
// BEFORE any of that: capsAllow refuses dcn_list at mgmt.go:238 and the store
// grant is never consulted, so a host without the `dcn` family cannot read a
// folder however perfect the grant for it is. A page that showed that folder as
// "shared" would be frightening the user about something that cannot happen,
// which costs the page its credibility just as surely as missing a real one.
//
// The TERMS shown are decoded straight from the record's canonical bytes even
// when the verdict is a refusal, and that is deliberate. Showing only verified
// grants would make an expired or tampered record VANISH, which tells the user
// "nothing is shared" while a record sits on their disk — the misleading
// direction. So the bytes are shown with the verdict beside them, and an
// unverified record is labelled as granting nothing rather than dropped. The
// bytes are this machine's own 0600 file; anyone who can rewrite them can
// already do worse than put text on a page only they can open.
func uiFoldersFor(c *Config, dcnHeld bool) ([]uiSharedFolder, string) {
	// A PENDING OR REVOKED PAIRING IS NOT ASKED — the same guard, for the same
	// reason, as pendingApprovals (ui.go). dcnDir() is MkdirAll-on-read
	// (config.go:115), so asking CREATED the directory, and run.go:311-318
	// keeps every such call behind cfg.active() precisely so nothing leaks a
	// side effect for a host the anchor has not approved.
	//
	// This page reintroduced the defect the rest of this change exists to fix,
	// on the page whose own copy tells the user a pending pairing gets "no
	// tunnel, no lanes, no directories". The original
	// test could not catch it because the fixture pre-created the directory,
	// which is why the new one asserts on a path that was never created rather
	// than on rendered words.
	if !c.active() {
		return nil, "This pairing is not active, so nothing is shared with it and it holds no " +
			"store directory on this machine."
	}
	dir := c.dcnDir()
	if dir == "" {
		return nil, "This host has no store directory on this machine, so no folder can be " +
			"shared with it and every dcn op is refused."
	}
	f, err := dcnLoadFile(dir)
	if err != nil {
		return nil, "This machine's record of what it shared with this host cannot be read (" +
			err.Error() + "). Nothing is being served from it while that is true: every read " +
			"re-opens this file and refuses when it cannot."
	}
	if len(f.Stores) == 0 {
		return nil, "No folder of yours is shared with this host from this machine."
	}
	// Numeric order, the same way the enforcing report sorts them
	// (enforcing.go:112) — store 2 must not sit between 10 and 11.
	ids := make([]string, 0, len(f.Stores))
	for k := range f.Stores {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, errA := strconv.ParseInt(ids[i], 10, 64)
		b, errB := strconv.ParseInt(ids[j], 10, 64)
		if errA != nil || errB != nil {
			return ids[i] < ids[j]
		}
		return a < b
	})

	// No pinned key means nothing can be verified, and dcnLoadGrantMask refuses
	// every op before it looks at a store (dcn.go:250). Said once, above the
	// list, rather than repeated as a reason on every row.
	note := ""
	if f.VerifyPubkey == "" {
		note = "No key from this host has been pinned on this machine yet, so none of these " +
			"records can be verified and every read is refused."
	}
	// Deliberately REPLACES the pin note rather than joining it: the ceiling is
	// the outer wall, so "no key is pinned" is true but beside the point, and two
	// reasons for one outcome is how a user ends up fixing the wrong one.
	if !dcnHeld {
		note = "This host is refused every file operation on this machine, so it cannot " +
			"read any of these whatever their grants say. They are listed because the " +
			"records are here and a grant that stops being reachable does not stop existing."
	}

	out := make([]uiSharedFolder, 0, len(ids))
	for _, k := range ids {
		rec := f.Stores[k]
		sf := uiSharedFolder{StoreID: k, Sealed: rec.SealRecipient != ""}
		if t := uiDecodeDcnTerms(rec.TermsCanonical); t != nil {
			sf.Readable = true
			sf.Root, sf.Mask, sf.Excludes = t.Root, t.Mask, t.Excludes
			sf.Expires, sf.Sweep, sf.TTLDays = t.Expires, t.Sweep, t.TTLDays
			sf.Class, sf.Sensitive = t.Class, t.Sensitive
			for _, m := range t.Mask {
				sf.MaskWords = append(sf.MaskWords, uiMaskWords(m))
			}
		}
		switch terms, err := dcnVerifyRec(f.VerifyPubkey, rec); {
		case !dcnHeld:
			// The ceiling, not the grant — said as the reason so a user who fixes
			// the grant does not wonder why nothing changed.
			sf.Why = "this host holds no file capability on this machine"
		case err != nil:
			sf.Why = err.Error()
		case terms.Class != "machine" || terms.Root == "":
			// dcn.go:264 refuses these after the signature verifies, so a page
			// that stopped at "signature ok" would show a live share that is not.
			sf.Why = "this grant is not for a folder on this machine"
		case len(terms.Mask) == 0:
			sf.Why = "this grant allows no operation at all"
		default:
			sf.InForce = true
		}
		out = append(out, sf)
	}
	return out, note
}

// uiDecodeDcnTerms decodes a record's canonical bytes for DISPLAY ONLY. It is
// the same two steps dcnVerifyRec takes after the signature checks out
// (dcn.go:135-149), which is why the two can never show different content —
// but it deliberately skips the signature, because a record that fails to
// verify is exactly the one the user most needs to see written out. nil when
// the bytes are not a grant at all.
func uiDecodeDcnTerms(canonicalB64 string) *dcnTerms {
	raw, err := base64.StdEncoding.DecodeString(canonicalB64)
	if err != nil {
		return nil
	}
	var t dcnTerms
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil
	}
	return &t
}

// uiMaskWords says what one mask value lets a host do, and passes an UNKNOWN
// value through verbatim rather than dropping it.
//
// The three this box consults are read (dcn.go:241), search (freeagent.go:300)
// and index (freeagent.go:360). A grant may legitimately carry a value this
// version has never heard of when the host is newer than the machine — the
// ordinary state of a fleet mid-upgrade — and rendering "read, search" for a
// grant that also said something else would be a lie by omission on the one
// page whose whole job is not to have any.
func uiMaskWords(m string) string {
	switch m {
	case "read":
		return "read — list the files in it, and read what is in them"
	case "search":
		return "search — answer searches over it"
	case "index":
		return "index — build and hold an index of it"
	}
	return m + " — this version of the bastion does not know what this allows"
}

// ── one host ────────────────────────────────────────────────────────────────

type uiGivenHost struct {
	Host     string
	State    string
	Served   bool // active; run.go:194 starts nothing for anything else
	IsAnchor bool
	// Basis is WHY this host holds what it holds, in the words of the rule that
	// decided it. The held/refused marks come from capsAllow; this explains
	// them, and the test pins the two together so an explanation cannot survive
	// a gate that stopped agreeing with it.
	Basis      string
	Families   []uiCapFamily
	HeldCount  int
	Folders    []uiSharedFolder
	FolderNote string
}

type uiGiven struct {
	Flash      string
	FlashClass string
	// DenyNote is why the switched-off list could not be read, when it could
	// not. Without it the page renders every capability as GRANTED while the
	// person's switches are silently not in effect — showing them the opposite
	// of the truth, which is the outcome the whole control exists to prevent.
	DenyNote  string
	Version   string
	Mode      string
	Anchored  bool
	Hosts     []uiGivenHost
	CheckedAt string
	// NoPairings is its own field rather than len(Hosts)==0 in the template,
	// because "no host is paired" is the one genuinely reassuring state on this
	// page and it deserves to be said, not inferred from an empty list.
	NoPairings bool
	// ReadError is why the pairing list could not be read. It exists because
	// this page used to fold that error INTO NoPairings:
	// an unparseable pairing record printed "No host is paired with this
	// machine" — the most reassuring sentence on the box — about a machine
	// whose records it had just failed to read. The status page already refuses
	// to do that (ui.go:202-205); these two now match it.
	ReadError string
}

// uiGivenBasis is the branch of capsAllow (anchor.go:528-553) that decided this
// host's answer, said to the person whose machine it is.
//
// It reads the same three things capsAllow reads — the anchor, the box mode and
// the verified grant — in the same order, and the test drives all five
// situations through the real gate and asserts the basis and the held set agree.
// It is an explanation, never the decision: nothing on this page is held or
// refused because of what this function returns.
func uiGivenBasis(host string, isAnchor bool) string {
	a := currentAnchor()
	switch {
	case a == nil && boxMode() == modeNetworked:
		return "This machine is networked but not anchored, so it serves nothing at all. " +
			"No host may run an op, open a terminal or place anything here until one of " +
			"them is made the anchor."
	case a == nil:
		return "This machine is not anchored, so the pairing itself is the authorization: " +
			"pairing this host gave it everything below. That is what a local bastion is — " +
			"one machine, one host — and the way to take it back is to unpair."
	case isAnchor:
		return "This is the anchor host, and the anchor is unconstrained. It holds every " +
			"capability here, and it alone directs the three things that affect the whole " +
			"machine: replacing this program, containing this machine, and placing a memory " +
			"mirror on it."
	}
	if _, ok := pairingCaps(host); !ok {
		return "This host holds no verified grant from the anchor, so everything is refused. " +
			"A grant that was revoked, that expired, that names another machine or that was " +
			"edited on disk all land here."
	}
	return "The anchor host signed a grant naming exactly what is marked granted below. " +
		"Anything not named is refused on this machine, whatever the host asks for."
}

// collectGiven reads this machine's state once and answers both views.
//
// Re-read on every render rather than cached, for the same reason renderWith
// re-reads (ui.go:338-341): a grant that lands from the host while this page is
// open must appear, and a stale copy of a security page is worse than no page —
// it is the page the user trusted.
func collectGiven() uiGiven {
	// READ ONCE, AND KEEP THE ERROR. The page used to ask localDenied() per
	// family, which discards it — so an unreadable list rendered as "nothing is
	// switched off" and the person saw their switches as not existing rather
	// than as not working.
	off, denyNote := localDenyIndex()
	g := uiGiven{
		DenyNote:  denyNote,
		Version:   clientVersion,
		Mode:      boxMode(),
		Anchored:  currentAnchor() != nil,
		CheckedAt: uiNow().Format("15:04:05"),
	}
	anchorHost := ""
	if a := currentAnchor(); a != nil {
		anchorHost = a.AnchorHost
	}
	cfgs, err := loadPairings()
	if err != nil {
		g.ReadError = err.Error()
		return g
	}
	if len(cfgs) == 0 {
		g.NoPairings = true
		return g
	}
	byFamily := uiFamilyOps()
	for _, c := range cfgs {
		h := uiGivenHost{
			Host:     c.HostName,
			State:    c.stateName(),
			Served:   c.active(),
			IsAnchor: anchorHost != "" && c.HostName == anchorHost,
		}
		h.Basis = uiGivenBasis(c.HostName, h.IsAnchor)
		dcnHeld := false
		for _, fam := range uiGivenFamilies {
			f := fam // the description; Held and Ops are this pairing's
			f.Ops = byFamily[fam.Name]
			f.Held = capsAllow(c.HostName, fam.Probe) == ""
			// READ FROM THE DENY LIST, not inferred from Held. capsAllow
			// already refuses when this is switched off, so Held is false
			// either way — and the page has to tell the two APART: "the host
			// was never granted this" and "you switched it off" are different
			// facts, and only one of them has a way back.
			f.SwitchedOff = off[c.HostName+"/"+fam.Name]
			if f.Held {
				h.HeldCount++
			}
			// Read off the same loop rather than asking capsAllow a second time
			// with a hardcoded op: the folder list and the "Read your files" card
			// have to be answering the same question, or the page contradicts
			// itself two headings apart.
			if fam.Name == "dcn" {
				dcnHeld = f.Held
			}
			h.Families = append(h.Families, f)
		}
		// The box-wide directives (writes.go): not a caps family — no grant
		// names them and only the anchor host directs them — but a thing this
		// host may do to the machine, and since 0.33.0 a thing the person can
		// switch off here. Held is asked of the directives' own gate
		// (anchorOnly + the switch), never of capsAllow, so the card answers
		// the question the directives actually face.
		d := uiDirectivesCard
		d.Held = anchorOnly(c.HostName, localFamilyDirectives) == "" && !localDenied(c.HostName, localFamilyDirectives)
		d.SwitchedOff = off[c.HostName+"/"+localFamilyDirectives]
		if d.Held {
			h.HeldCount++
		}
		h.Families = append(h.Families, d)
		h.Folders, h.FolderNote = uiFoldersFor(c, dcnHeld)
		g.Hosts = append(g.Hosts, h)
	}
	return g
}

// ── the routes ──────────────────────────────────────────────────────────────

func (u *uiServer) givenPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderGiven(w, "given.html")
}

func (u *uiServer) givenFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderGiven(w, "given")
}

// renderGiven sets the SAME four headers renderWith does (ui.go:343-348) and
// not one fewer. They are repeated rather than shared because renderWith is
// typed to uiStatus and widening it belongs to whoever owns that file; the
// duplication is made safe by TestTheGivenPageCarriesTheSameHeadersAsTheStatusPage,
// which compares the two responses header by header, so a change there that
// this file misses is a red test rather than a page quietly served without a CSP.
func (u *uiServer) renderGiven(w http.ResponseWriter, name string) {
	u.renderGivenFlash(w, name, "", "")
}

// renderGivenFlash is renderGiven with the outcome of a switch carried into the
// fragment that replaces the page.
func (u *uiServer) renderGivenFlash(w http.ResponseWriter, name, flash, class string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	v := collectGiven()
	v.Flash, v.FlashClass = flash, class
	if err := u.tpl.ExecuteTemplate(w, name, v); err != nil {
		uilogf("render %s: %v\n", name, err)
	}
}

// givenSwitch turns one capability off for one host on this machine, or back
// on. POST, so the Origin check applies.
//
// IT CANNOT GRANT. The only thing this writes is a deny list; "on" removes an
// entry from it and the host's signed grant remains the ceiling it always was
// (localdeny.go, and TestTheLocalSwitchCanOnlyEverRemoveReach drives the real
// gate over the whole op vocabulary to hold that).
func (u *uiServer) givenSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	family := strings.TrimSpace(r.FormValue("family"))
	off := r.FormValue("off") == "1"

	if err := localDenySet(host, family, off); err != nil {
		u.renderGivenFlash(w, "given", "Nothing was changed: "+err.Error(), "bad")
		return
	}
	// The words say what the machine will now DO, not what was written to a
	// file. "Switched off" is a state; "will refuse" is the consequence, and
	// the consequence is what the person came here for.
	if off {
		u.renderGivenFlash(w, "given", host+" can no longer "+uiFamilyVerb(family)+
			" on this machine. Its grant is untouched — this machine simply refuses, "+
			"and tells it why.", "ok")
		return
	}
	u.renderGivenFlash(w, "given", host+" may "+uiFamilyVerb(family)+" again, up to whatever "+
		"its signed grant already allowed. Turning this back on clears a refusal; it "+
		"grants nothing.", "ok")
}

// uiDirectivesCard describes the three host-directed, box-wide actions
// (update.go, contain.go, mirror.go). Kept apart from uiGivenFamilies, which
// is asserted equal to allCaps: this is not a capability a grant can carry.
var uiDirectivesCard = uiCapFamily{
	Name: localFamilyDirectives,
	Line: "Change this machine as a whole: swap the bastion binary, stop a program, place a database mirror.",
	Detail: "Only the host this machine is anchored to may direct these, and since 0.33.0 each " +
		"one also needs your approval — from your approval device or this console — bound to " +
		"exactly what it would do (the version, the processes, the mirror slot). Since 0.44.0 an " +
		"update to a newer version is the exception: our signature on the release is the " +
		"approval, and a move to an older version still needs yours. Switching this off here " +
		"refuses all three, approved or not.",
	Ops: []string{directiveSelfUpdate, directiveContain, directiveMirror},
}

// uiFamilyVerb is the family said as an action, for the sentence above.
func uiFamilyVerb(family string) string {
	for _, f := range append(uiGivenFamilies, uiDirectivesCard) {
		if f.Name == family {
			return strings.TrimSuffix(strings.ToLower(f.Line), ".")
		}
	}
	return "use '" + family + "'"
}
