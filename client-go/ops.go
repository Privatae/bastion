package main

// ops.go — the OP: a program the host wrote, tested on its own harness pool,
// and asks this machine to run; and the two signed terms under which it may.
//
// An op is a directory:
//
//	op.yaml   the manifest — name, version, summary, privilege, interpreter,
//	          params (a typed schema), effects (the FILES it may touch),
//	          time_limit, undo
//	run       the program, run by one of a fixed set of interpreters with a
//	          fixed argv and the params as JSON on stdin
//	test/     what the host's build ran it against (not read here)
//
// Its identity is the sha256 of the directory's canonical form (opDirDigest):
// sorted paths, each framed path\0mode\0size\0 then the bytes. One changed
// byte is a different op. The pod computes the same (nac_ops.op_dir_digest).
//
// It reaches this box only WITH signed terms (op_sync): the terms name the
// sha256, the bundle must hash to it, and the manifest must parse — a fixed
// interpreter, absolute effects that are never "/", a time limit inside the
// box's ceiling. The box holds it under <dcnDir>/ops/<sha256>/.
//
// Two terms, both signed by the host's entity key (verified under the pinned
// key like a store grant) and both carrying the person's approval:
//
//	op_run    "Do it once": this op, this machine, these params (carried as
//	          the string the pod produced, hashed verbatim), expires ≤ 24 h,
//	          one use. Purpose  op_run|server|op|sha256|sha256(params)|expires
//	op_grant  "From now on": this op, this machine, param BOUNDS, expires ≤
//	          30 d, a use count; privilege user only — root is never reusable.
//	          Held in ops.json beside grants.json. Purpose
//	          op_grant|server|op|sha256|sha256(bounds)|expires|uses
//
// The executor (ops_exec_linux.go) runs the op inside an overlay sandbox and
// diffs what it changed; a files op has FILE effects only, and an op whose
// effects name anything else is refused at sync. An ACTION op (kind: action,
// ops_action.go) is a ship step: its program runs unprivileged in a systemd
// unit held to its declared destinations, and its root work is a few named
// verbs the bastion does itself. Windows and macOS boxes refuse every op with
// that sentence (ops_exec_other.go).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

const (
	opBundleMaxBytes  = 1 << 20          // the whole op directory, on the wire
	opTimeLimitMax    = 10 * time.Minute // the box's ceiling on one run
	opRunTTLMax       = 24 * time.Hour   // an op_run's expiry may not exceed this
	opGrantTTLMax     = 30 * 24 * time.Hour
	opGrantUsesMax    = 1000
	opParamsMaxBytes  = 64 << 10
	opOutputMaxBytes  = 256 << 10 // captured stdout+stderr per run
	opDiffMaxBytes    = 64 << 10  // a text diff shown per changed file
	opUpperMaxBytes   = 256 << 20 // the tmpfs the op writes into
	opsFileName       = "ops.json"
	opRunsKeep        = 200
	opsFamily         = "ops" // the caps family every op_* op is judged on
	opKindRun         = "op_run"
	opKindGrant       = "op_grant"
	opSandboxMount    = "/opt/bastion-op" // where the op directory appears inside the sandbox
	opModeDryRun      = "dry_run"
	opModeApply       = "apply"
	opModeVerify      = "verify"
	opModeUndo        = "undo"
	opsRunsDirName    = "runs"
	opsStoreDirName   = "ops"
	opsMaxHeldOps     = 200
	opsMaxEffects     = 64
	opsMaxParams      = 32
	opsMaxEnumValues  = 64
	opsMaxStringParam = 4096
)

var (
	opNameRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	opVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	opParamRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	opsMu       sync.Mutex
)

// opInterpreters is the fixed set. The bastion execs `<interpreter> <run>
// --mode <mode>`; nothing the host wrote chooses the program that runs.
var opInterpreters = map[string]string{
	"/bin/sh": "/bin/sh",
	"python3": "/usr/bin/python3",
}

// ── the manifest ────────────────────────────────────────────────────────────

type opParam struct {
	Type   string   `yaml:"type" json:"type"` // string | integer | boolean | enum | path
	Min    *int64   `yaml:"min,omitempty" json:"min,omitempty"`
	Max    *int64   `yaml:"max,omitempty" json:"max,omitempty"`
	Values []string `yaml:"values,omitempty" json:"values,omitempty"` // enum
	Root   string   `yaml:"root,omitempty" json:"root,omitempty"`     // path: must resolve under this absolute root
	MaxLen int      `yaml:"max_len,omitempty" json:"max_len,omitempty"`
}

type opEffects struct {
	// Files: absolute paths or globs (filepath.Match, so `*` never crosses a
	// `/`); an entry ending in "/" is a directory and everything under it.
	Files []string `yaml:"files" json:"files"`
	// Anything else is refused in rung 6 — named here so a manifest that
	// carries it is refused with the sentence, not silently ignored.
	Units    []string `yaml:"units,omitempty" json:"units,omitempty"`
	Packages []string `yaml:"packages,omitempty" json:"packages,omitempty"`
	Network  []string `yaml:"network,omitempty" json:"network,omitempty"`
}

type opManifest struct {
	Name        string             `yaml:"name" json:"name"`
	Version     string             `yaml:"version" json:"version"`
	Summary     string             `yaml:"summary" json:"summary"`
	Target      string             `yaml:"target" json:"target"`       // machine
	Privilege   string             `yaml:"privilege" json:"privilege"` // user | root
	Interpreter string             `yaml:"interpreter" json:"interpreter"`
	TimeLimit   int                `yaml:"time_limit" json:"time_limit"` // seconds
	Params      map[string]opParam `yaml:"params" json:"params"`
	Effects     opEffects          `yaml:"effects" json:"effects"`
	// Reads: paths or globs the op only reads, judged like effects. With the
	// effects they are all an op sees beyond the system base (ops_view.go).
	Reads []string `yaml:"reads,omitempty" json:"reads,omitempty"`
	Modes []string `yaml:"modes" json:"modes"` // must hold dry_run, apply, verify
	Undo  string   `yaml:"undo" json:"undo"`   // "run" | "none"
	// Kind: "files" (the default, rung 6) or "action" (ops_action.go). The
	// fields below belong to an action op and are refused on any other.
	Kind         string              `yaml:"kind,omitempty" json:"kind,omitempty"`
	Destinations []string            `yaml:"destinations,omitempty" json:"destinations,omitempty"` // host:port
	Credentials  []string            `yaml:"credentials,omitempty" json:"credentials,omitempty"`   // names; sealed values ride the apply
	Builder      bool                `yaml:"builder,omitempty" json:"builder,omitempty"`           // the machine's builder socket, in apply
	Verbs        []map[string]string `yaml:"verbs,omitempty" json:"verbs,omitempty"`
}

func (m *opManifest) isAction() bool { return m.Kind == opKindAction }

func (m *opManifest) hasMode(mode string) bool {
	for _, x := range m.Modes {
		if x == mode {
			return true
		}
	}
	return false
}

// parseOpManifest reads op.yaml and refuses everything rung 6 does not carry.
func parseOpManifest(raw []byte) (*opManifest, error) {
	var m opManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("op.yaml does not parse: %v", err)
	}
	if !opNameRe.MatchString(m.Name) {
		return nil, errors.New("op.yaml: name must be [a-z][a-z0-9-]{0,63}")
	}
	if !opVersionRe.MatchString(m.Version) {
		return nil, errors.New("op.yaml: version must be MAJOR.MINOR.PATCH")
	}
	m.Summary = strings.TrimSpace(m.Summary)
	if m.Summary == "" || len(m.Summary) > 200 || strings.ContainsAny(m.Summary, "\n\r") {
		return nil, errors.New("op.yaml: summary is one plain sentence (1-200 chars)")
	}
	if m.Target != "machine" {
		return nil, errors.New("op.yaml: target must be 'machine' (host-target ops are a later rung)")
	}
	if m.Privilege != "user" && m.Privilege != "root" {
		return nil, errors.New("op.yaml: privilege must be 'user' or 'root'")
	}
	if _, ok := opInterpreters[m.Interpreter]; !ok {
		return nil, fmt.Errorf("op.yaml: interpreter must be one of %s", strings.Join(opInterpreterNames(), ", "))
	}
	if m.TimeLimit <= 0 || time.Duration(m.TimeLimit)*time.Second > opTimeLimitMax {
		return nil, fmt.Errorf("op.yaml: time_limit must be 1..%d seconds", int(opTimeLimitMax.Seconds()))
	}
	for _, need := range []string{opModeDryRun, opModeApply, opModeVerify} {
		if !m.hasMode(need) {
			return nil, fmt.Errorf("op.yaml: modes must include %s", need)
		}
	}
	if m.Undo != "run" && m.Undo != "none" {
		return nil, errors.New("op.yaml: undo must be 'run' (the op has an undo mode) or 'none' (stated: cannot be undone)")
	}
	if m.Undo == "run" && !m.hasMode(opModeUndo) {
		return nil, errors.New("op.yaml: undo: run requires the undo mode")
	}
	if len(m.Params) > opsMaxParams {
		return nil, fmt.Errorf("op.yaml: at most %d params", opsMaxParams)
	}
	for name, p := range m.Params {
		if !opParamRe.MatchString(name) {
			return nil, fmt.Errorf("op.yaml: param %q: name must be [a-z][a-z0-9_]{0,31}", name)
		}
		switch p.Type {
		case "string":
			if p.MaxLen <= 0 || p.MaxLen > opsMaxStringParam {
				return nil, fmt.Errorf("op.yaml: param %q: a string needs max_len 1..%d", name, opsMaxStringParam)
			}
		case "integer":
			if p.Min == nil || p.Max == nil || *p.Min > *p.Max {
				return nil, fmt.Errorf("op.yaml: param %q: an integer needs min ≤ max", name)
			}
		case "boolean":
		case "enum":
			if len(p.Values) == 0 || len(p.Values) > opsMaxEnumValues {
				return nil, fmt.Errorf("op.yaml: param %q: an enum needs 1..%d values", name, opsMaxEnumValues)
			}
		case "path":
			if !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) == "/" {
				return nil, fmt.Errorf("op.yaml: param %q: a path needs an absolute root that is not /", name)
			}
		default:
			return nil, fmt.Errorf("op.yaml: param %q: type must be string|integer|boolean|enum|path", name)
		}
	}
	switch m.Kind {
	case opKindAction:
		if err := opActionManifestOK(&m); err != nil {
			return nil, err
		}
		return &m, nil
	case "", opKindFiles:
		if err := opFilesOnlyFields(&m); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("op.yaml: kind must be 'files' (the default) or 'action'")
	}
	if len(m.Effects.Units)+len(m.Effects.Packages)+len(m.Effects.Network) > 0 {
		return nil, errors.New("op.yaml: a files op changes files only — a unit, a workload or the network is an action op's verb or destination")
	}
	if len(m.Effects.Files) == 0 || len(m.Effects.Files) > opsMaxEffects {
		return nil, fmt.Errorf("op.yaml: effects.files must name 1..%d paths or globs", opsMaxEffects)
	}
	for _, f := range m.Effects.Files {
		if err := effectOK(f); err != nil {
			return nil, fmt.Errorf("op.yaml: effects.files %q: %v", f, err)
		}
	}
	if len(m.Reads) > opsMaxEffects {
		return nil, fmt.Errorf("op.yaml: reads may name at most %d paths or globs", opsMaxEffects)
	}
	for _, f := range m.Reads {
		if err := effectOK(f); err != nil {
			return nil, fmt.Errorf("op.yaml: reads %q: %v", f, err)
		}
	}
	return &m, nil
}

func opInterpreterNames() []string {
	out := make([]string, 0, len(opInterpreters))
	for k := range opInterpreters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// opOffLimits is where this box keeps its own record — the config dir (the
// pinned keys, the pairings, ops.json, the nonce ledger, the sandbox
// scratch), and every pairing's DCN dir and backup folder when it was
// configured elsewhere.
// No op may name them as an effect and no run may change them, whatever
// the manifest says: an op that could rewrite the pinned verify key would
// make every later signature check the host's own, which is the root of
// trust §10b says the host cannot reach.
//
// Each place is listed as spelled AND as it resolves (a symlinked home, an
// OSTree /root): the run's changes are real paths. A record that cannot be
// enumerated (the pairings unreadable) refuses every op rather than leave a
// DCN dir unprotected. Inside the sandbox each of these is masked with an
// empty read-only tmpfs (ops_exec_linux.go), so an op cannot read, write or
// remove it whatever this side's text checks miss.
func opOffLimits() ([]string, error) {
	out, _, err := opOffLimitsSplit()
	return out, err
}

// opOffLimitsSplit is opOffLimits with the entries that are hosts' backup
// folders marked: those can live on a network mount that stops answering,
// so they are resolved with a bound here and masked best-effort
// (opmask.go), while every text check still refuses naming them.
func opOffLimitsSplit() ([]string, map[string]bool, error) {
	var out []string
	backups := map[string]bool{}
	add := func(p string) {
		if p == "" {
			return
		}
		c := filepath.Clean(p)
		out = append(out, c)
		if r := resolveExisting(c); r != c {
			out = append(out, r)
		}
	}
	addBackup := func(p string) {
		if p == "" {
			return
		}
		c := filepath.Clean(p)
		out = append(out, c)
		backups[c] = true
		// As it resolves now, or, while it does not answer, as it last
		// resolved: the real place stays off limits through an outage.
		if r := opResolveBounded(c); r != "" && r != c {
			out = append(out, r)
			backups[r] = true
		}
	}
	d, err := configDirPath()
	if err != nil || d == "" {
		return nil, nil, errors.New("this machine's own record cannot be located; ops are refused")
	}
	add(d)
	// The other key material this daemon keeps on disk: the free-agent
	// stores' host keys and age recipients, the observe kubeconfig and
	// endpoints under /etc, and the singleton marker under /var/lib.
	add(faStateBase())
	add("/var/lib/privatae/freeagent")
	add(filepath.Dir(observeKubeconfig))
	add(markerDirLinux)
	cfgs, err := loadPairings()
	if err != nil {
		return nil, nil, errors.New("this machine's pairings cannot be read; ops are refused")
	}
	for _, c := range cfgs {
		if c != nil {
			add(c.DCNDir)
			// The backups this box holds for each host, wherever the person
			// put them (a NAS mount): an op that could change them could
			// replace a backup, or the file thinning is told arrived.
			addBackup(c.backupRootPath())
		}
	}
	return out, backups, nil
}

// resolveExisting resolves the links in a path whose deepest part may not
// exist yet (the record before first use): the longest existing ancestor
// is resolved and the rest re-appended.
func resolveExisting(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.Clean(r)
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p
	}
	return filepath.Join(resolveExisting(parent), filepath.Base(p))
}

// underOffLimits names the protected place a path is at or under, or that
// the path HOLDS (a folder above the record: removing or replacing it takes
// the record with it). "" when neither; an error when the record cannot be
// enumerated.
func underOffLimits(p string) (string, error) {
	return offLimitsMatch(p, true)
}

// offLimitsMatch is underOffLimits with the "holds" half optional.
func offLimitsMatch(p string, holds bool) (string, error) {
	offs, err := opOffLimits()
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(p)
	for _, off := range offs {
		if clean == off || strings.HasPrefix(clean, off+"/") || (holds && strings.HasPrefix(off, clean+"/")) {
			return off, nil
		}
	}
	return "", nil
}

// globReachesOffLimits: could this glob name a protected root, anything
// inside it, or a folder holding it? Segment by segment against each root
// over the shorter of the two — a `*` never crosses a `/`, but a later
// segment can (`/etc/*/observe.kubeconfig`), and `/etc/privatae-*` names
// the folder itself. `/etc/*.conf` and `/var/lib/*/state` pass: their
// segments match no root's. A bracket class holding a `/` is refused
// outright (filepath.Match lets it match one).
func globReachesOffLimits(glob string) (string, error) {
	offs, err := opOffLimits()
	if err != nil {
		return "", err
	}
	if strings.Contains(glob, "[") {
		for _, part := range strings.Split(glob, "[")[1:] {
			if i := strings.Index(part, "]"); i < 0 || strings.Contains(part[:i], "/") {
				return "", errors.New("a bracket class may not hold a /")
			}
		}
	}
	gsegs := pathSegments(glob)
	for _, off := range offs {
		if globCouldName(gsegs, off, true) {
			return off, nil
		}
	}
	return "", nil
}

// globCouldName: could a glob (split into segments) name root or something
// inside it — and, with holds, a folder holding root? Segment by segment over
// the root's own segments, or over the glob's when holds and it is shorter.
func globCouldName(gsegs []string, root string, holds bool) bool {
	rsegs := pathSegments(root)
	n := len(rsegs)
	if len(gsegs) < n {
		if !holds {
			return false
		}
		n = len(gsegs)
	}
	for i := 0; i < n; i++ {
		if ok, err := filepath.Match(gsegs[i], rsegs[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// effectOK: absolute, cleaned, never "/", never a param placeholder, and
// not one of the places this box keeps its own record or an op's sandbox
// scratch — those cannot be effects, whatever the manifest says.
func effectOK(f string) error {
	if !filepath.IsAbs(f) {
		return errors.New("must be absolute")
	}
	if strings.Contains(f, "{") || strings.Contains(f, "..") {
		return errors.New("no placeholders, no \"..\"")
	}
	if strings.Contains(f, "\\") {
		// A backslash is filepath.Match's escape: `\n` is a pattern the
		// literal checks would read as text, and `\/` a `/` no split sees.
		return errors.New("no backslash")
	}
	clean := filepath.Clean(f)
	if clean == "/" || clean == "." {
		return errors.New("never /")
	}
	// A glob is judged the same way the record is below: "/b*/*" names
	// /boot/vmlinuz as surely as "/boot/vmlinuz" does.
	for _, off := range []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/boot"} {
		if clean == off || strings.HasPrefix(clean, off+"/") ||
			(isGlob(clean) && globCouldName(pathSegments(clean), off, false)) {
			return errors.New("not under " + off)
		}
	}
	// A glob is judged segment by segment against the box's own record —
	// could it name the record, anything inside it, or a folder holding it
	// (globReachesOffLimits); a plain path is judged at, under or above.
	if isGlob(clean) {
		off, err := globReachesOffLimits(clean)
		if err != nil {
			return err
		}
		if off != "" {
			return errors.New("could name this machine's own record (" + off + ")")
		}
	} else {
		off, err := offLimitsMatch(clean, true)
		if err != nil {
			return err
		}
		if off != "" {
			return errors.New("never at, under or above this machine's own record (" + off + ")")
		}
	}
	if _, err := filepath.Match(f, ""); err != nil {
		return errors.New("bad glob")
	}
	// A credential store: refused until the rung that seals a dry run to the
	// person's device (ops_view.go). Checked again when the op runs, since a
	// path can come to resolve somewhere else after it was accepted.
	sens, err := opSensitiveMatch(clean)
	if err != nil {
		return err
	}
	if sens != "" {
		return opSensitiveRefusal("it", sens)
	}
	return nil
}

// effectCovers reports whether a changed path is inside the declared effects.
//
// A glob is matched SEGMENT BY SEGMENT with equal segment counts — the one
// definition effectOK's gate (globReachesOffLimits) also uses — so no class
// or escape can ever span a `/`: `[^a]` and `[.-0]` match one under
// filepath.Match, and a whole-path match would let `/etc/x[^a]y` cover
// `/etc/x/y`.
func effectCovers(effects []string, changed string) bool {
	csegs := pathSegments(changed)
	for _, e := range effects {
		if strings.HasSuffix(e, "/") {
			dir := filepath.Clean(e)
			if changed == dir || strings.HasPrefix(changed, dir+"/") {
				return true
			}
			continue
		}
		if isGlob(e) {
			esegs := pathSegments(e)
			if len(esegs) != len(csegs) {
				continue
			}
			all := true
			for i := range esegs {
				if ok, err := filepath.Match(esegs[i], csegs[i]); err != nil || !ok {
					all = false
					break
				}
			}
			if all {
				return true
			}
			continue
		}
		if e == changed {
			return true
		}
	}
	return false
}

func isGlob(e string) bool { return strings.ContainsAny(e, "*?[") }

func pathSegments(p string) []string {
	return strings.Split(strings.Trim(filepath.Clean(p), "/"), "/")
}

// ── params: the schema, the values, the bounds ──────────────────────────────

// checkParams validates one run's params (the JSON object the pod produced)
// against the manifest. Every declared param must be present, nothing
// undeclared may be, and every value must be of its type and inside its
// bounds. A path param must clean to something under its root.
func checkParams(m *opManifest, raw string) (map[string]any, error) {
	if len(raw) > opParamsMaxBytes {
		return nil, errors.New("params too large")
	}
	var vals map[string]any
	if err := json.Unmarshal([]byte(raw), &vals); err != nil || vals == nil {
		return nil, errors.New("params are not a JSON object")
	}
	for k := range vals {
		if _, ok := m.Params[k]; !ok {
			return nil, fmt.Errorf("param %q is not one the op declares", k)
		}
	}
	for name, p := range m.Params {
		v, ok := vals[name]
		if !ok {
			return nil, fmt.Errorf("param %q missing", name)
		}
		switch p.Type {
		case "string":
			s, ok := v.(string)
			if !ok || len(s) > p.MaxLen || strings.ContainsAny(s, "\x00") {
				return nil, fmt.Errorf("param %q: a string of at most %d bytes", name, p.MaxLen)
			}
		case "integer":
			f, ok := v.(float64)
			if !ok || f != float64(int64(f)) || int64(f) < *p.Min || int64(f) > *p.Max {
				return nil, fmt.Errorf("param %q: an integer in %d..%d", name, *p.Min, *p.Max)
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return nil, fmt.Errorf("param %q: true or false", name)
			}
		case "enum":
			s, ok := v.(string)
			found := false
			for _, x := range p.Values {
				if ok && x == s {
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("param %q: one of %s", name, strings.Join(p.Values, ", "))
			}
		case "path":
			s, ok := v.(string)
			if !ok || !filepath.IsAbs(s) {
				return nil, fmt.Errorf("param %q: an absolute path under %s", name, p.Root)
			}
			c := filepath.Clean(s)
			if c != filepath.Clean(p.Root) && !strings.HasPrefix(c, filepath.Clean(p.Root)+"/") {
				return nil, fmt.Errorf("param %q: must be under %s", name, p.Root)
			}
		}
	}
	return vals, nil
}

// opBounds is what an op_grant lets vary per run: for each param, the
// subset of its schema the person approved. Absent = the schema's own bound.
type opBound struct {
	Min    *int64   `json:"min,omitempty"`
	Max    *int64   `json:"max,omitempty"`
	Values []string `json:"values,omitempty"` // enum or string: one of these
	Prefix string   `json:"prefix,omitempty"` // path: must be under this (itself under the schema root)
	Fixed  *bool    `json:"fixed,omitempty"`  // boolean
}

// Strict: a field the param's type does not read is refused, not ignored —
// the card shows the bounds text as sent, so a bound the box would not
// enforce would read as a limit the person never got. Each bound must sit
// inside the schema's own.
func parseBounds(m *opManifest, raw string) (map[string]opBound, error) {
	if len(raw) > opParamsMaxBytes {
		return nil, errors.New("bounds too large")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var b map[string]opBound
	if err := dec.Decode(&b); err != nil || b == nil {
		return nil, errors.New("bounds are not a JSON object of {param: {min, max | values | prefix | fixed}}")
	}
	for k, bd := range b {
		p, ok := m.Params[k]
		if !ok {
			return nil, fmt.Errorf("bound %q names no param", k)
		}
		has := func(min, max, values, prefix, fixed bool) error {
			if (bd.Min != nil || bd.Max != nil) && !min {
				return fmt.Errorf("bound %q: min/max is not a bound for a %s", k, p.Type)
			}
			if bd.Values != nil && !values {
				return fmt.Errorf("bound %q: values is not a bound for a %s", k, p.Type)
			}
			if bd.Prefix != "" && !prefix {
				return fmt.Errorf("bound %q: prefix is not a bound for a %s", k, p.Type)
			}
			if bd.Fixed != nil && !fixed {
				return fmt.Errorf("bound %q: fixed is not a bound for a %s", k, p.Type)
			}
			return nil
		}
		switch p.Type {
		case "integer":
			if err := has(true, true, false, false, false); err != nil {
				return nil, err
			}
			if bd.Min == nil && bd.Max == nil {
				return nil, fmt.Errorf("bound %q: an integer bound is min and/or max", k)
			}
			if (bd.Min != nil && *bd.Min < *p.Min) || (bd.Max != nil && *bd.Max > *p.Max) ||
				(bd.Min != nil && bd.Max != nil && *bd.Min > *bd.Max) {
				return nil, fmt.Errorf("bound %q: must sit inside the op's own %d..%d", k, *p.Min, *p.Max)
			}
		case "enum", "string":
			if err := has(false, false, true, false, false); err != nil {
				return nil, err
			}
			if len(bd.Values) == 0 {
				return nil, fmt.Errorf("bound %q: a %s bound is a non-empty values list", k, p.Type)
			}
			for _, v := range bd.Values {
				if p.Type == "enum" {
					found := false
					for _, x := range p.Values {
						if x == v {
							found = true
						}
					}
					if !found {
						return nil, fmt.Errorf("bound %q: %q is not one of the op's values", k, v)
					}
				} else if len(v) > p.MaxLen {
					return nil, fmt.Errorf("bound %q: %q is longer than the op's %d bytes", k, v, p.MaxLen)
				}
			}
		case "path":
			if err := has(false, false, false, true, false); err != nil {
				return nil, err
			}
			c := filepath.Clean(bd.Prefix)
			if bd.Prefix == "" || !filepath.IsAbs(bd.Prefix) || (c != filepath.Clean(p.Root) && !strings.HasPrefix(c, filepath.Clean(p.Root)+"/")) {
				return nil, fmt.Errorf("bound %q: prefix must be an absolute path under the op's root %s", k, p.Root)
			}
		case "boolean":
			if err := has(false, false, false, false, true); err != nil {
				return nil, err
			}
			if bd.Fixed == nil {
				return nil, fmt.Errorf("bound %q: a boolean bound is fixed: true|false", k)
			}
		}
	}
	return b, nil
}

// checkBounds: the params, already valid for the schema, sit inside the grant's bounds.
func checkBounds(m *opManifest, bounds map[string]opBound, vals map[string]any) error {
	for name, b := range bounds {
		v := vals[name]
		switch m.Params[name].Type {
		case "integer":
			f, _ := v.(float64)
			if (b.Min != nil && int64(f) < *b.Min) || (b.Max != nil && int64(f) > *b.Max) {
				return fmt.Errorf("param %q is outside the approved range", name)
			}
		case "enum", "string":
			if len(b.Values) > 0 {
				s, _ := v.(string)
				ok := false
				for _, x := range b.Values {
					if x == s {
						ok = true
					}
				}
				if !ok {
					return fmt.Errorf("param %q is not one of the approved values", name)
				}
			}
		case "path":
			if b.Prefix != "" {
				s, _ := v.(string)
				c := filepath.Clean(s)
				p := filepath.Clean(b.Prefix)
				if c != p && !strings.HasPrefix(c, p+"/") {
					return fmt.Errorf("param %q is outside the approved folder", name)
				}
			}
		case "boolean":
			if b.Fixed != nil {
				x, _ := v.(bool)
				if x != *b.Fixed {
					return fmt.Errorf("param %q is fixed to %v in the approval", name, *b.Fixed)
				}
			}
		}
	}
	return nil
}

// ── the op directory: bundle, digest, store ─────────────────────────────────

type opFile struct {
	Path string `json:"path"` // relative, forward slashes
	Mode uint32 `json:"mode"` // permission bits only
	B64  string `json:"b64"`
}

// opDirDigest is the op's identity: sha256 over the files sorted by path,
// each framed "<path>\x00<mode octal>\x00<size>\x00" then the bytes.
func opDirDigest(files []opFile) (string, error) {
	sorted := append([]opFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	seen := map[string]bool{}
	for _, f := range sorted {
		if seen[f.Path] {
			return "", fmt.Errorf("duplicate path %q", f.Path)
		}
		seen[f.Path] = true
		raw, err := base64.StdEncoding.DecodeString(f.B64)
		if err != nil {
			return "", fmt.Errorf("file %q: bad base64", f.Path)
		}
		fmt.Fprintf(h, "%s\x00%04o\x00%d\x00", f.Path, f.Mode&0o777, len(raw))
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// opBundleOK checks the bundle's shape before anything is written: relative
// clean paths, no links, op.yaml and run present, bounded size.
func opBundleOK(files []opFile) error {
	total := 0
	have := map[string]bool{}
	for _, f := range files {
		p := f.Path
		if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, "\x00") ||
			path.Clean(p) != p || p == "." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") {
			return fmt.Errorf("bad path %q in the op bundle", f.Path)
		}
		raw, err := base64.StdEncoding.DecodeString(f.B64)
		if err != nil {
			return fmt.Errorf("file %q: bad base64", f.Path)
		}
		// The two modes an op directory has (opLoad re-hashes with exactly
		// these): a bundle claiming any other would never load once held.
		if want := uint32(0o644); (p == "run" && f.Mode&0o777 != 0o755) || (p != "run" && f.Mode&0o777 != want) {
			return fmt.Errorf("file %q: mode must be 0644 (0755 for run)", f.Path)
		}
		total += len(raw)
		if total > opBundleMaxBytes {
			return fmt.Errorf("op bundle exceeds %d bytes", opBundleMaxBytes)
		}
		have[p] = true
	}
	if !have["op.yaml"] || !have["run"] {
		return errors.New("an op bundle needs op.yaml and run")
	}
	return nil
}

func opsDir(dcnDir string) string      { return filepath.Join(dcnDir, opsStoreDirName) }
func opsRunsDir(dcnDir string) string  { return filepath.Join(dcnDir, opsStoreDirName, opsRunsDirName) }
func opsFilePath(dcnDir string) string { return filepath.Join(dcnDir, opsFileName) }
func opStoreDir(dcnDir, sha string) string {
	return filepath.Join(opsDir(dcnDir), sha)
}

// opInstall writes the bundle under <dcnDir>/ops/<sha256>/ (0700, files
// 0600 or the bundle's mode masked to 0755 for run) once the digest matched.
func opInstall(dcnDir, sha string, files []opFile) error {
	dir := opStoreDir(dcnDir, sha)
	if _, err := os.Stat(filepath.Join(dir, "op.yaml")); err == nil {
		return nil // already held: identical by construction (same sha)
	}
	tmp := dir + ".tmp"
	_ = os.RemoveAll(tmp)
	// World-readable: a user-privilege op runs as the session user and reads
	// its own files through the read-only bind; the op is signed content,
	// not a secret.
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		raw, _ := base64.StdEncoding.DecodeString(f.B64)
		abs := filepath.Join(tmp, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if f.Path == "run" {
			mode = 0o755
		}
		if err := os.WriteFile(abs, raw, mode); err != nil {
			return err
		}
	}
	return os.Rename(tmp, dir)
}

// opLoad reads a held op's manifest, re-hashing the directory so a store
// edited on disk is refused rather than run.
func opLoad(dcnDir, sha string) (*opManifest, error) {
	dir := opStoreDir(dcnDir, sha)
	var files []opFile
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("op store holds a non-regular file %q", p)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		mode := uint32(0o644)
		if filepath.ToSlash(rel) == "run" {
			mode = 0o755
		}
		files = append(files, opFile{Path: filepath.ToSlash(rel), Mode: mode, B64: base64.StdEncoding.EncodeToString(raw)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("op %s is not held here: %v", sha[:12], err)
	}
	got, err := opDirDigest(files)
	if err != nil || got != sha {
		return nil, errors.New("op store does not hash to the sha256 the terms name — refused")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "op.yaml"))
	if err != nil {
		return nil, err
	}
	return parseOpManifest(raw)
}

// ── the terms ───────────────────────────────────────────────────────────────

// opTerms is the signed record for either kind. Params and Bounds are the
// JSON TEXT the pod produced, carried verbatim and hashed verbatim (never
// re-canonicalized here), and handed to the op's stdin as they are.
type opTerms struct {
	Kind      string `json:"kind"`
	Entity    int64  `json:"entity"`
	Op        string `json:"op"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Server    string `json:"server"`
	Privilege string `json:"privilege"`
	Params    string `json:"params,omitempty"` // op_run
	Bounds    string `json:"bounds,omitempty"` // op_grant
	// Changes: op_run, the apply only — the changes_sha256 the box's own dry
	// run reported (opReport). What the person approved is that list; the
	// apply must reproduce it exactly or nothing lands.
	Changes  string `json:"changes_sha256,omitempty"`
	Expires  string `json:"expires"`
	Uses     int    `json:"uses"`
	Nonce    string `json:"nonce"`
	Approval string `json:"approval,omitempty"`
}

// purposeForOpRun is the apply's purpose: the machine, the op's bytes, the
// exact params, the expiry, and the sha256 of the change list the dry run
// showed — so the approval is for those changes and no others.
func purposeForOpRun(t *opTerms) (string, error) {
	if err := purposeBad([]string{t.Server, t.Op, t.SHA256, t.Expires, t.Changes}, nil); err != nil {
		return "", err
	}
	if len(t.Changes) != 64 {
		return "", errors.New("an op_run apply binds the dry run it showed: the terms carry no changes_sha256")
	}
	if _, err := hex.DecodeString(t.Changes); err != nil {
		return "", errors.New("the terms carry a malformed changes_sha256")
	}
	sum := sha256.Sum256([]byte(t.Params))
	return opKindRun + "|" + t.Server + "|" + t.Op + "|" + t.SHA256 + "|" + hex.EncodeToString(sum[:]) + "|" + t.Expires + "|" + t.Changes, nil
}

func purposeForOpGrant(t *opTerms) (string, error) {
	if err := purposeBad([]string{t.Server, t.Op, t.SHA256, t.Expires}, nil); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(t.Bounds))
	return opKindGrant + "|" + t.Server + "|" + t.Op + "|" + t.SHA256 + "|" + hex.EncodeToString(sum[:]) + "|" +
		t.Expires + "|" + strconv.Itoa(t.Uses), nil
}

// verifyOpTerms: signed under the pinned key, the kind asked for, this
// machine, an expiry inside the kind's ceiling, uses as the kind requires,
// a nonce, and a well-formed sha256.
func verifyOpTerms(dcnDir, termsB64, sigB64, wantKind string) (*opTerms, error) {
	f, err := dcnLoadFile(dcnDir)
	if err != nil {
		return nil, errors.New("grant store unreadable")
	}
	if f.VerifyPubkey == "" {
		return nil, errors.New("no entity key pinned on this box yet (default-deny)")
	}
	pub, err := base64.StdEncoding.DecodeString(f.VerifyPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("bad pinned verify key")
	}
	canonical, err := base64.StdEncoding.DecodeString(termsB64)
	if err != nil {
		return nil, errors.New("bad terms encoding")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("bad signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sig) {
		return nil, errors.New("terms signature does not verify on this box")
	}
	var t opTerms
	if err := json.Unmarshal(canonical, &t); err != nil {
		return nil, errors.New("signed terms unparsable")
	}
	if t.Kind != wantKind {
		return nil, fmt.Errorf("terms are %q, not %q", t.Kind, wantKind)
	}
	if hn, _ := os.Hostname(); hn != "" && t.Server != hn {
		return nil, fmt.Errorf("terms are for server '%s', this box is '%s'", t.Server, hn)
	}
	if !opNameRe.MatchString(t.Op) || len(t.SHA256) != 64 {
		return nil, errors.New("terms name no op")
	}
	if _, err := hex.DecodeString(t.SHA256); err != nil {
		return nil, errors.New("terms carry a malformed sha256")
	}
	if len(t.Nonce) < 16 {
		return nil, errors.New("terms carry no nonce")
	}
	exp, err := time.Parse(time.RFC3339, t.Expires)
	if err != nil {
		return nil, errors.New("terms state no expiry (open-ended terms are refused)")
	}
	if !exp.After(time.Now()) {
		return nil, errors.New("terms expired")
	}
	switch wantKind {
	case opKindRun:
		if t.Uses != 1 {
			return nil, errors.New("an op_run is one use")
		}
		if exp.After(time.Now().Add(opRunTTLMax + deviceClockSkew)) {
			return nil, fmt.Errorf("an op_run may not live longer than %s", opRunTTLMax)
		}
		if t.Params == "" {
			return nil, errors.New("an op_run carries its params")
		}
	case opKindGrant:
		if t.Uses < 1 || t.Uses > opGrantUsesMax {
			return nil, fmt.Errorf("an op_grant states uses 1..%d", opGrantUsesMax)
		}
		if exp.After(time.Now().Add(opGrantTTLMax + deviceClockSkew)) {
			return nil, fmt.Errorf("an op_grant may not live longer than %s", opGrantTTLMax)
		}
		if t.Privilege != "user" {
			return nil, errors.New("root is never reusable: an op_grant is privilege user only")
		}
		if t.Bounds == "" {
			return nil, errors.New("an op_grant carries its bounds")
		}
	}
	return &t, nil
}

// ── ops.json: the held grants ───────────────────────────────────────────────

type opGrantRec struct {
	TermsCanonical string `json:"terms_canonical"`
	Signature      string `json:"signature"`
	InstalledAt    string `json:"installed_at"`
	UsesLeft       int    `json:"uses_left"`
	Dropped        string `json:"dropped,omitempty"` // when and why, kept for the record
}

type opsFile struct {
	Grants map[string]opGrantRec `json:"grants"` // by the terms' nonce
}

func opsLoad(dcnDir string) *opsFile {
	f := &opsFile{Grants: map[string]opGrantRec{}}
	raw, err := os.ReadFile(opsFilePath(dcnDir))
	if err == nil {
		_ = json.Unmarshal(raw, f)
	}
	if f.Grants == nil {
		f.Grants = map[string]opGrantRec{}
	}
	return f
}

func opsSave(dcnDir string, f *opsFile) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(opsFilePath(dcnDir), raw)
}

// opsHeldGrant re-verifies a held grant record (a tampered ops.json holds
// nothing) and returns its terms and uses left.
func opsHeldGrant(dcnDir, nonce string) (*opTerms, *opGrantRec, error) {
	f := opsLoad(dcnDir)
	rec, ok := f.Grants[nonce]
	if !ok || rec.Dropped != "" {
		return nil, nil, errors.New("no such op grant is held here")
	}
	t, err := verifyOpTerms(dcnDir, rec.TermsCanonical, rec.Signature, opKindGrant)
	if err != nil {
		return nil, nil, fmt.Errorf("held op grant does not verify: %v", err)
	}
	if rec.UsesLeft <= 0 {
		return nil, nil, errors.New("op grant has no uses left")
	}
	return t, &rec, nil
}

// opsDropGrant — the console (or a host revoke) removes a held op grant.
func opsDropGrant(dcnDir, nonce, why string) (bool, error) {
	opsMu.Lock()
	defer opsMu.Unlock()
	f := opsLoad(dcnDir)
	rec, ok := f.Grants[nonce]
	if !ok || rec.Dropped != "" {
		return false, nil
	}
	rec.Dropped = time.Now().UTC().Format(time.RFC3339) + " " + why
	rec.UsesLeft = 0
	f.Grants[nonce] = rec
	return true, opsSave(dcnDir, f)
}

// ── the run record ──────────────────────────────────────────────────────────

// opAuditRun is the durable line per run: what ran, in which mode, and how
// it ended (the record under ops/runs/ is the detail and is pruned).
func opAuditRun(dir, op string, r *opRunRecord) {
	if r == nil {
		return
	}
	decision := "ok run=" + r.ID + " mode=" + r.Mode
	if r.Approval != "" {
		decision += " via " + r.Approval
	}
	if r.Error != "" {
		decision = "refused run=" + r.ID + " mode=" + r.Mode + ": " + truncate(r.Error, mgmtAuditWhyMax)
	} else if r.Report != nil {
		decision += fmt.Sprintf(" changes=%d", len(r.Report.Changes))
	}
	dcnAudit(dir, op, 0, r.Op+"@"+r.SHA256[:12], decision)
}

type opRunRecord struct {
	ID       string          `json:"id"`
	At       string          `json:"at"`
	Kind     string          `json:"kind"` // op_run | op_grant
	Op       string          `json:"op"`
	SHA256   string          `json:"sha256"`
	Mode     string          `json:"mode"`
	Params   string          `json:"params"`
	Nonce    string          `json:"nonce"`
	Approval string          `json:"approval,omitempty"` // device:<nonce> | console:<id>
	Report   *opReport       `json:"report,omitempty"`
	Error    string          `json:"error,omitempty"`
	Verify   *opReport       `json:"verify,omitempty"`
	Commit   []string        `json:"commit,omitempty"`
	Terms    json.RawMessage `json:"terms,omitempty"`
}

func opRecordRun(dcnDir string, r *opRunRecord) {
	dir := opsRunsDir(dcnDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	raw, _ := json.MarshalIndent(r, "", "  ")
	_ = atomicWrite(filepath.Join(dir, r.ID+".json"), raw)
	// Keep the newest opRunsKeep records; the audit line is the durable one.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= opRunsKeep {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names[:len(names)-opRunsKeep] {
		_ = os.Remove(filepath.Join(dir, n))
	}
}

// ── the mgmt ops ────────────────────────────────────────────────────────────

// opFail is refuseMgmt: the refusal goes on the box's ring and, for the op
// writes, counts toward the host's quarantine (a run that reached outside
// its effects is the host asking for what it could have known better than
// to ask for). A box that cannot sandbox at all is the box's own state, and
// never a strike (refusalCounts).
func opFail(ws *websocket.Conn, why string) {
	refuseMgmt(ws, why)
}

const noSandboxHere = "this machine cannot sandbox an op"

// op_sync <terms_b64> <sig_b64> <bundle_b64>: hold the op the terms name,
// once the bundle hashes to it and its manifest parses. For op_grant terms
// the grant is installed too (its approval consumed, like a store grant).
// For op_run terms nothing but the op is held: the run is asked for next.
func handleOpSync(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 3 {
		opFail(ws, "op_sync: need <terms_b64> <sig_b64> <bundle_b64>")
		return
	}
	var t *opTerms
	var err error
	for _, kind := range []string{opKindRun, opKindGrant} {
		if t, err = verifyOpTerms(dir, args[0], args[1], kind); err == nil {
			break
		}
	}
	if err != nil {
		opFail(ws, "op_sync refused: "+err.Error())
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(args[2]))
	if err != nil || len(raw) > opBundleMaxBytes*2 {
		opFail(ws, "op_sync: bad or oversize bundle")
		return
	}
	var files []opFile
	if err := json.Unmarshal(raw, &files); err != nil {
		opFail(ws, "op_sync: bundle is not a file list")
		return
	}
	if err := opBundleOK(files); err != nil {
		opFail(ws, "op_sync refused: "+err.Error())
		return
	}
	sha, err := opDirDigest(files)
	if err != nil {
		opFail(ws, "op_sync refused: "+err.Error())
		return
	}
	if sha != t.SHA256 {
		opFail(ws, "op_sync refused: the bundle does not hash to the sha256 the terms name")
		return
	}
	var manifestRaw []byte
	for _, f := range files {
		if f.Path == "op.yaml" {
			manifestRaw, _ = base64.StdEncoding.DecodeString(f.B64)
		}
	}
	m, err := parseOpManifest(manifestRaw)
	if err != nil {
		opFail(ws, "op_sync refused: "+err.Error())
		return
	}
	if m.Name != t.Op || m.Version != t.Version || m.Privilege != t.Privilege {
		opFail(ws, "op_sync refused: the manifest and the terms disagree on name, version or privilege")
		return
	}
	if entries, err := os.ReadDir(opsDir(dir)); err == nil && len(entries) > opsMaxHeldOps {
		opFail(ws, fmt.Sprintf("op_sync refused: this box holds %d ops already; drop some", opsMaxHeldOps))
		return
	}
	opsMu.Lock()
	err = opInstall(dir, sha, files)
	opsMu.Unlock()
	if err != nil {
		opFail(ws, "op_sync: could not hold the op: "+err.Error())
		return
	}
	out := map[string]any{"state": "held", "op": t.Op, "sha256": sha, "kind": t.Kind}
	if t.Kind == opKindGrant {
		if _, err := parseBounds(m, t.Bounds); err != nil {
			opFail(ws, "op_sync refused: "+err.Error())
			return
		}
		purpose, err := purposeForOpGrant(t)
		if err != nil {
			opFail(ws, "op_sync refused: "+err.Error())
			return
		}
		opsMu.Lock()
		f := opsLoad(dir)
		if prev, held := f.Grants[t.Nonce]; !held || prev.Dropped != "" {
			// THE PERSON'S APPROVAL, spent here: one approval installs the
			// grant once; a dropped grant cannot be re-installed under it.
			id, err := consumeApproval(dir, t.Approval, purpose)
			if err != nil {
				opsMu.Unlock()
				opFail(ws, "op_grant refused: "+err.Error())
				return
			}
			f.Grants[t.Nonce] = opGrantRec{TermsCanonical: args[0], Signature: args[1],
				InstalledAt: time.Now().UTC().Format(time.RFC3339), UsesLeft: t.Uses}
			if err := opsSave(dir, f); err != nil {
				opsMu.Unlock()
				opFail(ws, "op_grant: could not hold the grant: "+err.Error())
				return
			}
			setMgmtAccountApproval(ws, id)
			dcnAudit(dir, "op_grant", 0, t.Op, "installed "+t.Nonce[:8]+" uses="+strconv.Itoa(t.Uses)+" via "+id)
		}
		opsMu.Unlock()
		out["grant"] = t.Nonce
		out["uses"] = t.Uses
	}
	b, _ := json.Marshal(out)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// op_dry_run <terms_b64> <sig_b64>: run the op_run in the sandbox and report
// what it WOULD change. Nothing is committed and no approval is needed —
// the terms are signed by the host's key, the params are bound in them, and
// the sandbox is what makes the run harmless. The person approves the apply
// from this report.
func handleOpDryRun(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 2 {
		opFail(ws, "op_dry_run: need <terms_b64> <sig_b64>")
		return
	}
	t, err := verifyOpTerms(dir, args[0], args[1], opKindRun)
	if err != nil {
		opFail(ws, "op_dry_run refused: "+err.Error())
		return
	}
	rep, rec, err := opRunTerms(dir, t, opModeDryRun, "", args[0], args[2:])
	opRecordRun(dir, rec)
	opAuditRun(dir, "op_dry_run", rec)
	if err != nil {
		opFail(ws, "op_dry_run refused: "+err.Error())
		return
	}
	b, _ := json.Marshal(rep)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// op_apply <terms_b64> <sig_b64>: spend the person's approval, run the same
// sandbox run again, check it again, commit it, verify it, report.
func handleOpApply(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 2 {
		opFail(ws, "op_apply: need <terms_b64> <sig_b64>")
		return
	}
	t, err := verifyOpTerms(dir, args[0], args[1], opKindRun)
	if err != nil {
		opFail(ws, "op_apply refused: "+err.Error())
		return
	}
	purpose, err := purposeForOpRun(t)
	if err != nil {
		opFail(ws, "op_apply refused: "+err.Error())
		return
	}
	// The terms' nonce is its own single-use wall on top of the approval's:
	// the same signed op_run cannot be applied twice even if the approval
	// were somehow reissued.
	if opNonceSeen(dir, t.Nonce) {
		opFail(ws, "op_apply refused: this op_run was applied already")
		return
	}
	// An action op's sealed credentials (args after the signature) are
	// judged before the approval is spent: a run missing one, or handed one
	// sealed for another run, is refused with the approval still unused.
	creds := args[2:]
	if m, err := opLoad(dir, t.SHA256); err == nil && m.isAction() {
		if _, err := opOpenCreds(creds, m, t.Nonce, false); err != nil {
			opFail(ws, "op_apply refused: "+err.Error())
			return
		}
	} else if len(creds) > 0 {
		opFail(ws, "op_apply refused: only an action op is handed credentials")
		return
	}
	approvalID, err := boxConsume(dir, t.Approval, purpose)
	if err != nil {
		opFail(ws, "op_apply refused: "+err.Error())
		return
	}
	setMgmtAccountApproval(ws, approvalID)
	opBurnNonce(dir, t.Nonce, t.Expires)
	rep, rec, err := opRunTerms(dir, t, opModeApply, approvalID, args[0], creds)
	opRecordRun(dir, rec)
	opAuditRun(dir, "op_apply", rec)
	if err != nil {
		opFail(ws, "op_apply refused: "+err.Error())
		return
	}
	b, _ := json.Marshal(rep)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// op_grant_run <grant nonce> <mode> <params_json>: a run under a held grant —
// dry_run or apply — with the params checked against the schema AND the
// approved bounds; an apply spends one use.
func handleOpGrantRun(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 3 {
		opFail(ws, "op_grant_run: need <grant> <dry_run|apply> <params_json>")
		return
	}
	mode := strings.TrimSpace(args[1])
	if mode != opModeDryRun && mode != opModeApply {
		opFail(ws, "op_grant_run: mode must be dry_run or apply")
		return
	}
	opsMu.Lock()
	t, rec, err := opsHeldGrant(dir, strings.TrimSpace(args[0]))
	opsMu.Unlock()
	if err != nil {
		opFail(ws, "op_grant_run refused: "+err.Error())
		return
	}
	run := *t
	run.Kind = opKindRun
	run.Params = args[2]
	run.Uses = 1
	m, err := opLoad(dir, t.SHA256)
	if err != nil {
		opFail(ws, "op_grant_run refused: "+err.Error())
		return
	}
	vals, err := checkParams(m, run.Params)
	if err != nil {
		opFail(ws, "op_grant_run refused: "+err.Error())
		return
	}
	bounds, err := parseBounds(m, t.Bounds)
	if err != nil {
		opFail(ws, "op_grant_run refused: "+err.Error())
		return
	}
	if err := checkBounds(m, bounds, vals); err != nil {
		opFail(ws, "op_grant_run refused: "+err.Error())
		return
	}
	creds := args[3:]
	if m.isAction() {
		if _, err := opOpenCreds(creds, m, t.Nonce, mode == opModeDryRun); err != nil {
			opFail(ws, "op_grant_run refused: "+err.Error())
			return
		}
	} else if len(creds) > 0 {
		opFail(ws, "op_grant_run refused: only an action op is handed credentials")
		return
	}
	if mode == opModeApply {
		// Spend the use BEFORE the run (the same order the approval takes).
		opsMu.Lock()
		f := opsLoad(dir)
		r := f.Grants[t.Nonce]
		if r.UsesLeft <= 0 || r.Dropped != "" {
			opsMu.Unlock()
			opFail(ws, "op_grant_run refused: op grant has no uses left")
			return
		}
		r.UsesLeft--
		f.Grants[t.Nonce] = r
		if err := opsSave(dir, f); err != nil {
			opsMu.Unlock()
			opFail(ws, "op_grant_run refused: could not record the use; refused rather than unlimited")
			return
		}
		opsMu.Unlock()
		_ = rec
	}
	rep, record, err := opRunTerms(dir, &run, mode, "grant:"+t.Nonce, "", creds)
	record.Kind = opKindGrant
	opRecordRun(dir, record)
	opAuditRun(dir, "op_grant_run", record)
	if err != nil {
		opFail(ws, "op_grant_run refused: "+err.Error())
		return
	}
	b, _ := json.Marshal(rep)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// op_list: the ops held, the grants held, and whether this box can sandbox.
func handleOpList(ws *websocket.Conn, dir string, _ []string) {
	if dir == "" {
		opFail(ws, "op_list: dcn store not configured")
		return
	}
	held := []map[string]any{}
	if entries, err := os.ReadDir(opsDir(dir)); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Name() == opsRunsDirName || strings.HasSuffix(e.Name(), ".tmp") {
				continue
			}
			item := map[string]any{"sha256": e.Name()}
			if m, err := opLoad(dir, e.Name()); err == nil {
				item["op"], item["version"], item["summary"], item["privilege"] = m.Name, m.Version, m.Summary, m.Privilege
				item["kind"] = opKindFiles
				if m.isAction() {
					item["kind"] = opKindAction
				}
			} else {
				item["error"] = err.Error()
			}
			held = append(held, item)
		}
	}
	grants := []map[string]any{}
	opsMu.Lock()
	f := opsLoad(dir)
	opsMu.Unlock()
	for nonce, rec := range f.Grants {
		g := map[string]any{"grant": nonce, "uses_left": rec.UsesLeft, "installed_at": rec.InstalledAt, "dropped": rec.Dropped}
		if t, err := verifyOpTerms(dir, rec.TermsCanonical, rec.Signature, opKindGrant); err == nil {
			g["op"], g["sha256"], g["expires"], g["bounds"] = t.Op, t.SHA256, t.Expires, t.Bounds
		} else {
			g["error"] = err.Error()
		}
		grants = append(grants, g)
	}
	ok, why := opSandboxAvailable()
	b, _ := json.Marshal(map[string]any{"ops": held, "grants": grants, "sandbox": ok, "sandbox_reason": why})
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// op_run_status <nonce>: what became of an op_run whose answer the host
// lost. A read. The host burns nothing by asking, and it needs the answer
// because the box burns the run's nonce BEFORE the op runs (one attempt per
// approval): "applied already" on a re-send means the run was attempted,
// not that it landed. The states:
//
//	found=true, applied=true   the commit finished (verify may still have failed: verify_error)
//	found=true, applied=false  refused, or the commit stopped part-way (committed names what landed)
//	found=false, nonce_burned=false   the job never arrived; the same run may be sent again
//	found=false, nonce_burned=true    attempted — still running, or the record pruned or never
//	                                  written: unknown; never re-send
//
// Only op_run records answer here: a run under a grant carries the grant's
// nonce, which is never burned.
func handleOpRunStatus(ws *websocket.Conn, dir string, args []string) {
	if dir == "" || len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		opFail(ws, "op_run_status: need <nonce>")
		return
	}
	nonce := strings.TrimSpace(args[0])
	out := map[string]any{"nonce": nonce, "found": false, "nonce_burned": opNonceSeen(dir, nonce)}
	var best *opRunRecord
	if entries, err := os.ReadDir(opsRunsDir(dir)); err == nil {
		for _, e := range entries {
			raw, err := os.ReadFile(filepath.Join(opsRunsDir(dir), e.Name()))
			if err != nil {
				continue
			}
			var r opRunRecord
			if json.Unmarshal(raw, &r) != nil || r.Nonce != nonce || r.Mode != opModeApply || r.Kind != opKindRun {
				continue
			}
			if best == nil || r.At > best.At {
				rr := r
				best = &rr
			}
		}
	}
	if best != nil {
		out["found"] = true
		out["id"], out["at"], out["mode"], out["error"] = best.ID, best.At, best.Mode, best.Error
		out["committed"] = best.Commit
		// Applied = the commit finished. A verify that failed to start is
		// recorded as "verify: …" AFTER the commit and reported to the host
		// as a success with verify_error; here it reads the same way.
		out["applied"] = best.Error == "" || strings.HasPrefix(best.Error, "verify: ")
		if best.Report != nil {
			out["changes_sha256"] = best.Report.ChangesSHA256
			out["verify_error"] = best.Report.VerifyError
			out["exit"] = best.Report.Exit
		}
	}
	b, _ := json.Marshal(out)
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// ── the run nonce ledger (an op_run applies once) ───────────────────────────

func opNoncesPath(dir string) string { return filepath.Join(dir, "op_nonces.json") }

func opNonceSeen(dir, nonce string) bool {
	opsMu.Lock()
	defer opsMu.Unlock()
	_, ok := opNoncesLoad(dir)[nonce]
	return ok
}

func opNoncesLoad(dir string) map[string]string {
	out := map[string]string{}
	if raw, err := os.ReadFile(opNoncesPath(dir)); err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	now := time.Now()
	for n, exp := range out {
		if t, err := time.Parse(time.RFC3339, exp); err != nil || !t.After(now) {
			delete(out, n)
		}
	}
	return out
}

func opBurnNonce(dir, nonce, expires string) {
	opsMu.Lock()
	defer opsMu.Unlock()
	m := opNoncesLoad(dir)
	m[nonce] = expires
	raw, _ := json.MarshalIndent(m, "", "  ")
	_ = atomicWrite(opNoncesPath(dir), raw)
}

// ── running the terms ───────────────────────────────────────────────────────

// opRunTerms loads the op the terms name, checks the params, runs the mode,
// and returns the report and the run record. `apply` commits and verifies.
func opRunTerms(dir string, t *opTerms, mode, approvalID, termsB64 string, creds []string) (*opReport, *opRunRecord, error) {
	id, _ := newID()
	rec := &opRunRecord{ID: id, At: time.Now().UTC().Format(time.RFC3339), Kind: t.Kind, Op: t.Op,
		SHA256: t.SHA256, Mode: mode, Params: t.Params, Nonce: t.Nonce, Approval: approvalID}
	if termsB64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(termsB64); err == nil {
			rec.Terms = raw
		}
	}
	m, err := opLoad(dir, t.SHA256)
	if err != nil {
		rec.Error = err.Error()
		return nil, rec, err
	}
	if m.Name != t.Op || m.Version != t.Version || m.Privilege != t.Privilege {
		rec.Error = "the held op and the terms disagree on name, version or privilege"
		return nil, rec, errors.New(rec.Error)
	}
	if _, err := checkParams(m, t.Params); err != nil {
		rec.Error = err.Error()
		return nil, rec, err
	}
	if ok, why := opSandboxAvailable(); !ok {
		rec.Error = noSandboxHere + ": " + why
		return nil, rec, errors.New(rec.Error)
	}
	if m.isAction() {
		// An action op (ops_action.go): its program in a transient unit, its
		// verbs by the bastion, its change list bound like a files op's.
		rep, err := opRunAction(opStoreDir(dir, t.SHA256), m, t, mode, id, creds, nil)
		rec.Report = rep
		if rep != nil {
			rec.Commit = rep.Committed
		}
		if err != nil {
			rec.Error = err.Error()
			return rep, rec, err
		}
		return rep, rec, nil
	}
	if len(creds) > 0 {
		rec.Error = "only an action op is handed credentials"
		return nil, rec, errors.New(rec.Error)
	}
	rep, err := opRunSandboxed(opStoreDir(dir, t.SHA256), m, mode, t.Params)
	if rep != nil {
		defer rep.cleanup()
	}
	if err != nil {
		rec.Error = err.Error()
		return rep, rec, err
	}
	rec.Report = rep
	if why := opEffectsViolation(m, rep); why != "" {
		rec.Error = why
		return rep, rec, errors.New(why)
	}
	if mode != opModeApply {
		return rep, rec, nil
	}
	// APPLY IS A COMMITTED DRY RUN: the same run, checked again, then the
	// upper dir is what lands — file by file, the diff the person saw. For an
	// op_run the person approved a change list by its sha256; a run that
	// produced any other list (a nondeterministic op, a machine that moved
	// under it) lands nothing.
	// (A run under a grant carries no list: its bounds are what was approved.)
	if t.Changes != "" && rep.ChangesSHA256 != t.Changes {
		rec.Error = "refused before commit: the apply would change something other than what the dry run showed (" +
			truncate(rep.ChangesSHA256, 12) + " vs approved " + truncate(t.Changes, 12) + ") — dry-run again and approve that"
		return rep, rec, errors.New(rec.Error)
	}
	committed, err := opCommitUpper(rep)
	rec.Commit = committed
	if err != nil {
		rec.Error = "commit: " + err.Error()
		return rep, rec, fmt.Errorf("commit: %v (%d change(s) landed before it)", err, len(committed))
	}
	ver, verr := opRunSandboxed(opStoreDir(dir, t.SHA256), m, opModeVerify, t.Params)
	if ver != nil {
		defer ver.cleanup()
	}
	rec.Verify = ver
	if verr != nil {
		rec.Error = "verify: " + verr.Error()
		rep.VerifyError = verr.Error()
	} else if ver != nil && ver.Exit != 0 {
		rep.VerifyError = fmt.Sprintf("verify exited %d", ver.Exit)
	}
	rep.Committed = committed
	return rep, rec, nil
}

// opEffectsViolation names the first change outside the declared effects —
// and, whatever the effects say, any change to this machine's own record
// (opOffLimits).
func opEffectsViolation(m *opManifest, rep *opReport) string {
	for _, c := range rep.Changes {
		if c.Kind == "symlink" || c.Kind == "hardlink" || c.Kind == "opaque" || c.Kind == "special" {
			return "refused: the run left a " + c.Kind + " at " + c.Path + " — a link or a replaced directory is a path outside the effects in disguise"
		}
		off, err := underOffLimits(c.Path)
		if err != nil {
			return "refused: " + err.Error()
		}
		if off != "" {
			return "refused: the run changed " + c.Path + ", which is or holds this machine's own record (" + off + ") — never an effect"
		}
		if !effectCovers(m.Effects.Files, c.Path) {
			return "refused: the run changed " + c.Path + ", which is outside the op's declared effects"
		}
		if c.Kind == "removed_dir" || c.Kind == "opaque" {
			// The sandbox never looked inside a mount below this folder (an
			// overlay does not show them, and not every one is carried), so
			// removing it on the machine would reach what the run never saw.
			if under := opMountsUnder(c.Path); len(under) > 0 {
				return "refused: the run removed " + c.Path + ", which holds a mount at " + under[0] + " the sandbox did not carry"
			}
		}
	}
	return ""
}
