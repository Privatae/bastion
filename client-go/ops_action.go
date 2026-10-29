package main

// ops_action.go — the ACTION op: the kind of op a ship step is.
//
// A rung-6 op changes files, and the sandbox reads off what it changed. A ship
// step acts: it builds, pushes, moves a tree, restarts a service, rolls a
// workload. None of that can be captured in an overlay, so an action op is
// split in two:
//
//   - its PROGRAM runs unprivileged: a fresh uid every run, never reused, in a
//     systemd transient unit whose network, in an apply, reaches only the
//     addresses its declared destinations resolved to, and their TCP ports
//     (a dry run, which nobody approved, has no network at all). It
//     sees what a rung-6 op sees (the closed view, ops_view.go), with the
//     machine's filesystem read-only and a private work folder at /tmp. It is
//     handed the credentials the op declared, sealed to this machine's
//     encryption key (ops_seal.go), and nothing else (ops_action_linux.go);
//   - the effects that are root in practice are done by the bastion itself, as
//     a few named VERBS the manifest declares with their arguments fixed. The
//     program cannot ask for a verb: after its apply succeeds, the bastion runs
//     the manifest's list, in order (ops_verbs_linux.go).
//
// The verbs, and what bounds each:
//
//	tree.checkout  path, repo, commit[, credential]  an existing git tree moves
//	               FORWARD to an exact commit fetched from the named repository,
//	               which must be the tree's own origin
//	unit.reload    unit                              one systemd service
//	unit.restart   unit
//	k8s.set_image  namespace, kind, name, container, image, digest, repo[, credential]
//	               one container's image, to a digest this machine holds a
//	               receipt for (ops_receipts.go) from repo, whose commit
//	               descends from the one behind the live image this machine
//	               rolled
//	logs.check     unit | namespace+kind+name[+container], must and/or
//	               must_not, lines — a verdict and one line, after the apply,
//	               never in a dry run
//
// Only two arguments may name a param, as `{{name}}`: tree.checkout's commit
// and k8s.set_image's digest (the values that change every ship). Everything
// else is written into the manifest, so what a verb can reach is fixed when
// the op is approved.
//
// An action op may have no program at all (interpreter: none, no run file):
// its verbs are its whole work. Nothing the Host wrote executes, so it needs
// no sandbox and runs on a machine with no overlay; each verb needs only its
// own tool (systemctl, journalctl, git, kubectl), and the beat reports which
// this machine has (enforcing.verbs).
//
// Every verb line, with the state it moves from, is in the dry run's change
// list, so an approval binds that list and an apply refuses when the machine
// moved under it. An op with any verb is privilege root: its verbs run with
// the bastion's own root, and root is never a standing grant.
//
//	name: web-roll
//	version: 1.0.0
//	summary: Move the web tree forward and restart it.
//	kind: action
//	target: machine
//	privilege: root
//	interpreter: /bin/sh
//	time_limit: 300
//	params:
//	  commit: {type: string, max_len: 40}
//	destinations: ["forge.example.com:443"]
//	credentials: [forge-read]
//	verbs:
//	  - {verb: tree.checkout, path: /opt/acme, repo: "https://forge.example.com/acme/app.git", commit: "{{commit}}", credential: forge-read}
//	  - {verb: unit.restart, unit: acme-web.service}
//	  - {verb: logs.check, unit: acme-web.service, must_not: "Traceback", lines: 200}
//	modes: [dry_run, apply, verify]
//	undo: none

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	opKindFiles  = "files"
	opKindAction = "action"
	// opActionMount is where an action op's directory appears: inside the
	// sandbox's own fresh /run, because the machine's root is read-only there
	// and no mount point may be made on it.
	opActionMount = "/run/bastion-op"
	// opResultName is the file, in the program's work folder, where an apply
	// reports the images it pushed (ops_receipts.go).
	opResultName  = "privatae-result.json"
	opDestsMax    = 16
	opCredsMax    = 8
	opVerbsMax    = 16
	opLogLinesMax = 2000
	opPatternMax  = 200
	opVerbLogs    = "logs.check"
)

var (
	opCredNameRe = regexp.MustCompile(`^[a-z][a-z0-9:_-]{0,63}$`)
	opParamRefRe = regexp.MustCompile(`^\{\{([a-z][a-z0-9_]{0,31})\}\}$`)
	opUnitRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,200}\.service$`)
	opK8sLabelRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	opK8sNameRe  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	// An image is a registry host and a repository, never a tag or a digest:
	// the digest is its own argument, from a receipt.
	opImageRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)+$`)
	opDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	opCommitRe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	opHostRe   = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	opK8sKinds = map[string]bool{"deployment": true, "statefulset": true, "daemonset": true}
)

// opVerbSpec is one verb's argument set: which it needs, which it may take,
// and which may name a param.
type opVerbSpec struct {
	required []string
	optional []string
	param    map[string]bool
}

var opVerbSpecs = map[string]opVerbSpec{
	"tree.checkout": {required: []string{"path", "repo", "commit"}, optional: []string{"credential"},
		param: map[string]bool{"commit": true}},
	"unit.reload":  {required: []string{"unit"}},
	"unit.restart": {required: []string{"unit"}},
	"k8s.set_image": {required: []string{"namespace", "kind", "name", "container", "image", "digest", "repo"},
		optional: []string{"credential"}, param: map[string]bool{"digest": true}},
	opVerbLogs: {optional: []string{"unit", "namespace", "kind", "name", "container", "must", "must_not", "lines"}},
}

// opVerbLine is one verb with its arguments: as the manifest wrote it (a
// param still `{{name}}`), or resolved against a run's params.
type opVerbLine struct {
	Verb string            `json:"verb"`
	Args map[string]string `json:"args"`
}

// target names what the line acts on, for the change list and the card.
func (v opVerbLine) target() string {
	a := v.Args
	switch v.Verb {
	case "tree.checkout":
		return a["path"]
	case "unit.reload", "unit.restart":
		return a["unit"]
	case "k8s.set_image":
		return a["namespace"] + "/" + a["kind"] + "/" + a["name"] + ":" + a["container"]
	case opVerbLogs:
		if a["unit"] != "" {
			return a["unit"]
		}
		t := a["namespace"] + "/" + a["kind"] + "/" + a["name"]
		if a["container"] != "" {
			t += ":" + a["container"]
		}
		return t
	}
	return ""
}

// opRepoURLOK is what a repository argument must be: a plain https URL, no
// credentials, query or fragment. A seam only so the tests can use a local
// repository.
var opRepoURLOK = func(s string) error {
	if why := mirrorSourceRefusal(mirrorSource{URL: s, Repo: "x/y"}); why != "" {
		return errors.New("repo must be a plain https URL of a repository (no credentials, query or fragment)")
	}
	return nil
}

// opVerbArgOK judges one literal (or resolved) argument value.
func opVerbArgOK(m *opManifest, verb, key, val string) error {
	bad := func(what string) error { return fmt.Errorf("%s %s: %s", verb, key, what) }
	if key != "must" && key != "must_not" && !printableASCII(val) {
		return bad("must be printable ASCII with no spaces")
	}
	switch key {
	case "path":
		if !filepath.IsAbs(val) || filepath.Clean(val) != val || val == "/" {
			return bad("must be a clean absolute path that is not /")
		}
		if off, err := underOffLimits(val); err != nil {
			return bad(err.Error())
		} else if off != "" {
			return bad("is or holds this machine's own record (" + off + ")")
		}
		if sens, err := opSensitiveMatch(val); err != nil {
			return bad(err.Error())
		} else if sens != "" {
			return bad(opSensitiveRefusal(val, sens).Error())
		}
	case "repo":
		if err := opRepoURLOK(val); err != nil {
			return bad(err.Error())
		}
	case "commit":
		if !opCommitRe.MatchString(val) {
			return bad("must be a full commit id (40 or 64 hex), never a branch")
		}
	case "credential":
		found := false
		for _, c := range m.Credentials {
			found = found || c == val
		}
		if !found {
			return bad("names a credential the op does not declare")
		}
	case "unit":
		if !opUnitRe.MatchString(val) {
			return bad("must be one systemd .service name")
		}
		if strings.HasPrefix(val, "privatae-bastion") || strings.HasPrefix(val, "privatae-op-") {
			return bad("the bastion never restarts itself or an op's own unit")
		}
	case "namespace", "container":
		if !opK8sLabelRe.MatchString(val) {
			return bad("must be a Kubernetes name (lowercase, digits, -)")
		}
	case "name":
		if !opK8sNameRe.MatchString(val) {
			return bad("must be a Kubernetes object name")
		}
	case "kind":
		if !opK8sKinds[val] {
			return bad("must be deployment, statefulset or daemonset")
		}
	case "image":
		if !opImageRe.MatchString(val) || len(val) > 255 {
			return bad("must be a registry and repository, with no tag or digest")
		}
	case "digest":
		if !opDigestRe.MatchString(val) {
			return bad("must be sha256:<64 hex>")
		}
	case "must", "must_not":
		if len(val) == 0 || len(val) > opPatternMax || strings.ContainsAny(val, "\n\r\x00") {
			return bad(fmt.Sprintf("must be one line of 1..%d characters", opPatternMax))
		}
		if _, err := regexp.Compile(val); err != nil {
			return bad("is not a valid pattern: " + err.Error())
		}
	case "lines":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > opLogLinesMax {
			return bad(fmt.Sprintf("must be 1..%d", opLogLinesMax))
		}
	default:
		return bad("is not an argument of this verb")
	}
	return nil
}

// opParseVerbs judges the manifest's verb list. A value that names a param
// is kept as written and judged when a run resolves it.
func opParseVerbs(m *opManifest) ([]opVerbLine, error) {
	if len(m.Verbs) > opVerbsMax {
		return nil, fmt.Errorf("op.yaml: at most %d verbs", opVerbsMax)
	}
	out := make([]opVerbLine, 0, len(m.Verbs))
	// A tree or workload an op moves, it moves once: the change list is
	// read before the first verb runs, so a second move of the same target
	// would be approved from a state it is no longer in.
	moves := map[string]bool{}
	for i, raw := range m.Verbs {
		verb := raw["verb"]
		spec, ok := opVerbSpecs[verb]
		if !ok {
			return nil, fmt.Errorf("op.yaml: verbs[%d]: %q is not a verb this bastion runs (%s)", i, verb, strings.Join(opVerbNames(), ", "))
		}
		allowed := map[string]bool{"verb": true}
		for _, k := range append(append([]string{}, spec.required...), spec.optional...) {
			allowed[k] = true
		}
		line := opVerbLine{Verb: verb, Args: map[string]string{}}
		for k, v := range raw {
			if !allowed[k] {
				return nil, fmt.Errorf("op.yaml: verbs[%d]: %s takes no argument %q", i, verb, k)
			}
			if k == "verb" {
				continue
			}
			if ref := opParamRefRe.FindStringSubmatch(v); ref != nil {
				if !spec.param[k] {
					return nil, fmt.Errorf("op.yaml: verbs[%d]: %s %s is fixed in the manifest and may not name a param", i, verb, k)
				}
				p, ok := m.Params[ref[1]]
				if !ok || p.Type != "string" {
					return nil, fmt.Errorf("op.yaml: verbs[%d]: %s %s names %q, which is not a string param", i, verb, k, ref[1])
				}
			} else if err := opVerbArgOK(m, verb, k, v); err != nil {
				return nil, fmt.Errorf("op.yaml: verbs[%d]: %v", i, err)
			}
			line.Args[k] = v
		}
		for _, k := range spec.required {
			if line.Args[k] == "" {
				return nil, fmt.Errorf("op.yaml: verbs[%d]: %s needs %s", i, verb, k)
			}
		}
		if verb == opVerbLogs {
			if err := opLogsTargetOK(line.Args); err != nil {
				return nil, fmt.Errorf("op.yaml: verbs[%d]: %v", i, err)
			}
		}
		if verb == "tree.checkout" || verb == "k8s.set_image" {
			if moves[verb+" "+line.target()] {
				return nil, fmt.Errorf("op.yaml: verbs[%d]: %s %s is moved twice; an op moves a tree or a workload's container once", i, verb, line.target())
			}
			moves[verb+" "+line.target()] = true
		}
		out = append(out, line)
	}
	return out, nil
}

// opLogsTargetOK: a log check reads one unit's journal or one workload's
// pods, and says what must and/or must not appear.
func opLogsTargetOK(a map[string]string) error {
	unit := a["unit"] != ""
	wl := a["namespace"] != "" || a["kind"] != "" || a["name"] != "" || a["container"] != ""
	if unit == wl {
		return errors.New("logs.check reads either one unit or one workload (namespace, kind, name)")
	}
	if wl && (a["namespace"] == "" || a["kind"] == "" || a["name"] == "") {
		return errors.New("logs.check on a workload needs namespace, kind and name")
	}
	if a["must"] == "" && a["must_not"] == "" {
		return errors.New("logs.check needs must, must_not or both")
	}
	return nil
}

func opVerbNames() []string {
	out := make([]string, 0, len(opVerbSpecs))
	for k := range opVerbSpecs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// opResolveVerbs puts a run's params into the manifest's verb lines and
// judges each resolved value as if it had been written there.
func opResolveVerbs(m *opManifest, vals map[string]any) ([]opVerbLine, error) {
	lines, err := opParseVerbs(m)
	if err != nil {
		return nil, err
	}
	for i, l := range lines {
		for k, v := range l.Args {
			ref := opParamRefRe.FindStringSubmatch(v)
			if ref == nil {
				continue
			}
			s, ok := vals[ref[1]].(string)
			if !ok {
				return nil, fmt.Errorf("%s %s: the run gives no %s", l.Verb, k, ref[1])
			}
			if err := opVerbArgOK(m, l.Verb, k, s); err != nil {
				return nil, err
			}
			lines[i].Args[k] = s
		}
	}
	return lines, nil
}

// ── destinations ────────────────────────────────────────────────────────────

type opDest struct {
	Host string
	Port uint16
}

// opParseDest reads host:port ([v6]:port for an IPv6 literal).
func opParseDest(s string) (opDest, error) {
	if !printableASCII(s) || len(s) > 260 {
		return opDest{}, errors.New("must be printable ASCII host:port")
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return opDest{}, errors.New("must be host:port")
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return opDest{}, errors.New("port must be 1..65535")
	}
	if ip := net.ParseIP(h); ip == nil {
		if !opHostRe.MatchString(h) || strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
			return opDest{}, errors.New("host must be a DNS name or an IP address, never localhost")
		}
	} else if why := opForbiddenDest(ip); why != "" {
		return opDest{}, errors.New(why)
	} else if why := opLocalNetworkDest(ip); why != "" {
		return opDest{}, errors.New(why)
	}
	return opDest{Host: h, Port: uint16(port)}, nil
}

// opLocalNetworkDest: "" when an address may be a destination on this box as
// it stands, else why not. An anchored machine is a fleet's, and its ship
// steps reach the fleet's private control planes, so it keeps private
// destinations. On any other machine (a person's own, which no fleet has
// anchored) an op reaches the public internet and nothing around the
// machine: a private, ULA, CGNAT or reserved address (internalIP, the rule
// the egress lane holds every box to) is refused, by address here and, for a
// name, by every address it resolves to at apply (opResolveDests). Another
// computer of theirs is reached through a bastion on that computer.
func opLocalNetworkDest(ip net.IP) string {
	if currentAnchor() != nil || !internalIP(ip) {
		return ""
	}
	return "a destination is never an address on a private network (a home network, a VPN or a carrier NAT) " +
		"on a machine no fleet has anchored; to reach another computer on it, install a bastion on that computer"
}

// opMetadataAddrs are the cloud metadata services that do not sit in
// link-local space (Alibaba's, AWS's IPv6 one). They hand out the machine's
// own credentials to anything that asks from it.
var opMetadataAddrs = map[string]bool{"100.100.100.200": true, "fd00:ec2::254": true}

// opForbiddenDest: "" when an address may be a destination, else why not.
// Never this machine's loopback, the unspecified address, multicast, a
// link-local address (where 169.254.169.254, the metadata service of most
// clouds, lives), or a metadata service — as written, or carried inside an
// IPv6 address that reaches it (IPv4-mapped, NAT64, 6to4).
func opForbiddenDest(ip net.IP) string {
	check := []net.IP{ip}
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		switch {
		case v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b: // 64:ff9b::/96
			check = append(check, net.IP(v6[12:16]))
		case v6[0] == 0x20 && v6[1] == 0x02: // 2002::/16
			check = append(check, net.IP(v6[2:6]))
		}
	}
	for _, a := range check {
		switch {
		case a.IsLoopback() || a.IsUnspecified() || a.IsMulticast():
			return "a destination is never this machine's loopback, the unspecified address or multicast"
		case a.IsLinkLocalUnicast():
			return "a destination is never a link-local address, where a cloud's metadata service answers"
		case opMetadataAddrs[a.String()]:
			return "a destination is never a cloud's metadata service"
		}
	}
	return ""
}

// opCredEnv is the environment variable a declared credential arrives in.
func opCredEnv(name string) string {
	var b strings.Builder
	b.WriteString("PRIVATAE_CRED_")
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// verbsOnly: an action op with no program (interpreter: none). Its whole work
// is its verbs, done by the bastion with their arguments fixed in the
// manifest; nothing the Host wrote executes, so it needs no sandbox (a machine
// with no overlay runs it), only the tools its verbs run.
func (m *opManifest) verbsOnly() bool { return m.isAction() && m.Interpreter == opInterpreterNone }

// opActionManifestOK is parseOpManifest's judgement of an action op.
func opActionManifestOK(m *opManifest) error {
	if len(m.Effects.Files)+len(m.Effects.Units)+len(m.Effects.Packages)+len(m.Effects.Network) > 0 {
		return errors.New("op.yaml: an action op changes this machine only through its verbs, so effects must be empty")
	}
	if m.Undo != "none" {
		return errors.New("op.yaml: an action op states undo: none; undoing a ship step is the signed ship plan's (a later rung)")
	}
	if len(m.Reads) > opsMaxEffects {
		return fmt.Errorf("op.yaml: reads may name at most %d paths or globs", opsMaxEffects)
	}
	for _, f := range m.Reads {
		if err := effectOK(f); err != nil {
			return fmt.Errorf("op.yaml: reads %q: %v", f, err)
		}
	}
	if len(m.Destinations) > opDestsMax {
		return fmt.Errorf("op.yaml: at most %d destinations", opDestsMax)
	}
	for _, d := range m.Destinations {
		if _, err := opParseDest(d); err != nil {
			return fmt.Errorf("op.yaml: destination %q: %v", d, err)
		}
	}
	if len(m.Credentials) > opCredsMax {
		return fmt.Errorf("op.yaml: at most %d credentials", opCredsMax)
	}
	envs := map[string]string{}
	for _, c := range m.Credentials {
		if !opCredNameRe.MatchString(c) {
			return fmt.Errorf("op.yaml: credential %q: a name is [a-z][a-z0-9:_-]{0,63}", c)
		}
		if prev, dup := envs[opCredEnv(c)]; dup {
			return fmt.Errorf("op.yaml: credentials %q and %q would arrive in the same variable", prev, c)
		}
		envs[opCredEnv(c)] = c
	}
	verbs, err := opParseVerbs(m)
	if err != nil {
		return err
	}
	if (len(verbs) > 0) != (m.Privilege == "root") {
		return errors.New("op.yaml: an action op is privilege root exactly when it has verbs: they run with the bastion's own root")
	}
	if m.verbsOnly() {
		if len(verbs) == 0 {
			return errors.New("op.yaml: interpreter: none is an op whose verbs are its whole work, and it names none")
		}
		if len(m.Destinations) > 0 || m.Builder || len(m.Reads) > 0 {
			return errors.New("op.yaml: destinations, builder and reads are a program's, and interpreter: none has no program")
		}
		named := map[string]bool{}
		for _, v := range verbs {
			if c := v.Args["credential"]; c != "" {
				named[c] = true
			}
		}
		for _, c := range m.Credentials {
			if !named[c] {
				return fmt.Errorf("op.yaml: credential %q is named by no verb, and interpreter: none has no program to hand it to", c)
			}
		}
	}
	return nil
}

// opFilesOnlyFields refuses the action fields on a rung-6 op, so a manifest
// carrying them is refused with a sentence rather than silently ignored.
func opFilesOnlyFields(m *opManifest) error {
	if len(m.Destinations)+len(m.Credentials)+len(m.Verbs) > 0 || m.Builder {
		return errors.New("op.yaml: destinations, credentials, builder and verbs belong to an action op (kind: action)")
	}
	return nil
}

// opActionChange is one verb line of the change list: what it acts on, the
// state it moves from and to. Its sha256 covers the resolved line and both
// states, so an apply whose machine moved since the dry run
// produces a different list and lands nothing.
func opActionChange(v opVerbLine, from, to, note string) opChange {
	raw, _ := json.Marshal(struct {
		Line opVerbLine `json:"line"`
		From string     `json:"from"`
		To   string     `json:"to"`
	}{v, from, to})
	sum := sha256.Sum256(raw)
	c := opChange{Path: v.Verb + " " + v.target(), Kind: "verb", Digest: hex.EncodeToString(sum[:])}
	switch {
	case note != "":
		c.Note = note
	case from != "" && to != "":
		c.Note = from + " → " + to
	}
	return c
}

// opCleanRepoURL is a remote URL without the user part (a machine's clone
// may carry a user name for its credential helper).
func opCleanRepoURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return strings.TrimSpace(s)
	}
	u.User = nil
	return u.String()
}

// opVerbResult is one verb (or check) as it ran.
type opVerbResult struct {
	Verb   string `json:"verb"`
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Note   string `json:"note,omitempty"`
}
