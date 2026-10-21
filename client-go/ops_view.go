package main

// ops_view.go — what an op can see.
//
// An op's dry run needs no approval, so what it can READ is what keeps it
// harmless: a dry run's output and diff go back to the host. The view is
// closed by default. Inside the sandbox (dry run and apply alike) an op sees
// a fixed system base, the sandbox's own fresh mounts, and the paths its
// manifest declares — its effects and its reads. Everything else is covered
// with an empty read-only mount, files and directories alike
// (ops_exec_linux.go opCloseView), and a cover that cannot be put in place
// refuses the run.
//
// A declared path may not reach a sensitive path: a credential store this
// machine keeps (the built-in list below, plus any path the person adds at
// the machine in the record's sensitive_paths file). An op that names one is
// refused until the rung that seals its dry run to the person's own device,
// so the host never sees what such a file holds.

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// opViewBase is what every op sees besides what it declares: the programs
// and libraries an interpreter needs, and the /etc files that name users,
// hosts and certificates — none of them a secret.
var opViewBase = []string{
	"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
	"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libx32",
	"/usr/libexec", "/usr/share", "/usr/local/bin", "/usr/local/lib", "/usr/local/share",
	"/etc/passwd", "/etc/group", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
	"/etc/nsswitch.conf", "/etc/localtime", "/etc/os-release", "/etc/ld.so.cache",
	"/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ssl/certs", "/etc/alternatives",
	"/etc/protocols", "/etc/services", "/etc/mime.types",
}

// opViewSandbox is what the sandbox itself mounts fresh (proc, the empty
// scratch dirs, the op's own directory): always seen, never covered.
var opViewSandbox = []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", opSandboxMount}

// opSensitiveBuiltIn: the credential stores on a Linux machine. A `*` never
// crosses a `/`.
var opSensitiveBuiltIn = []string{
	"/root",
	"/home/*/.ssh", "/home/*/.docker", "/home/*/.git-credentials", "/home/*/.kube", "/home/*/.gnupg",
	"/home/*/.aws", "/home/*/.netrc", "/home/*/.pgpass", "/home/*/.config",
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-",
	"/etc/ssh", "/etc/wireguard", "/etc/privatae", "/etc/letsencrypt", "/etc/ssl/private", "/etc/pki",
	"/etc/systemd", // unit files and drop-ins carry database DSNs and tokens
	"/etc/credstore", "/etc/credstore.encrypted", "/etc/docker", "/var/lib/docker",
	"/etc/rancher", "/var/lib/rancher", "/etc/kubernetes", "/var/lib/kubelet",
	"/var/lib/postgresql", "/var/lib/mysql", "/var/lib/cloud",
}

// opSensitiveFileName, in this machine's record (masked from every op), lists
// more sensitive paths, one absolute path per line; '#' starts a comment.
const opSensitiveFileName = "sensitive_paths"

// opSensitivePaths is the built-in list plus the machine's own, each also as
// it resolves when it is a plain path. A machine list that cannot be read or
// holds a line that is not an absolute path refuses every op: a store the
// person named must never quietly fall out of the list.
func opSensitivePaths() ([]string, error) {
	out := []string{}
	add := func(p string) {
		c := filepath.Clean(p)
		out = append(out, c)
		if !isGlob(c) {
			if r := resolveExisting(c); r != c {
				out = append(out, r)
			}
		}
	}
	for _, p := range opSensitiveBuiltIn {
		add(p)
	}
	d, err := configDirPath()
	if err != nil || d == "" {
		return nil, errors.New("this machine's own record cannot be located; ops are refused")
	}
	f, err := os.Open(filepath.Join(d, opSensitiveFileName))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("this machine's %s cannot be read; ops are refused: %v", opSensitiveFileName, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if !filepath.IsAbs(line) || strings.Contains(line, "..") || filepath.Clean(line) == "/" {
			return nil, fmt.Errorf("this machine's %s line %d is not an absolute path; ops are refused", opSensitiveFileName, n)
		}
		add(line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("this machine's %s cannot be read; ops are refused: %v", opSensitiveFileName, err)
	}
	return out, nil
}

// opSegGlob: does one path segment carry a glob character?
func opSegGlob(s string) bool { return strings.ContainsAny(s, "*?[") }

// opSegMatch: does a pattern segment (a glob or a literal) match a name?
func opSegMatch(pat, name string) bool {
	if !opSegGlob(pat) {
		return pat == name
	}
	ok, err := filepath.Match(pat, name)
	return err == nil && ok
}

// opSegCouldMatch: could two segments, either of which may be a glob, name
// the same thing? Two globs are assumed to overlap: this decides a refusal,
// so it errs toward refusing.
func opSegCouldMatch(a, b string) bool {
	switch ga, gb := opSegGlob(a), opSegGlob(b); {
	case !ga && !gb:
		return a == b
	case ga && !gb:
		return opSegMatch(a, b)
	case !ga && gb:
		return opSegMatch(b, a)
	default:
		return true
	}
}

// opPathsOverlap: is one path (or glob) at, under or above the other?
// Segment by segment over the shorter of the two.
func opPathsOverlap(a, b string) bool {
	as, bs := pathSegments(a), pathSegments(b)
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if !opSegCouldMatch(as[i], bs[i]) {
			return false
		}
	}
	return true
}

// opSensitiveMatch names the sensitive path a declared path (or glob) is at,
// under or above — as written and, for a plain path, as it resolves here —
// or "" when it reaches none.
func opSensitiveMatch(p string) (string, error) {
	return opSensitiveMatchForms(opDeclaredForms(p))
}

// opSensitiveMatchForms judges spellings already resolved, as they are: the
// run judges exactly the list it hands the sandbox, so a link that moves
// between a check and the view cannot slip a store past the check.
func opSensitiveMatchForms(forms []string) (string, error) {
	sens, err := opSensitivePaths()
	if err != nil {
		return "", err
	}
	for _, f := range forms {
		for _, s := range sens {
			if opPathsOverlap(f, s) {
				return s, nil
			}
		}
	}
	return "", nil
}

// opDeclaredForms is a declared path as written and, for a plain path, as it
// resolves here now.
func opDeclaredForms(p string) []string {
	c := filepath.Clean(p)
	forms := []string{c}
	if !isGlob(c) {
		if r := resolveExisting(c); r != c {
			forms = append(forms, r)
		}
	}
	return forms
}

// opSensitiveRefusal is the sentence for an op that names a sensitive path.
func opSensitiveRefusal(declared, sensitive string) error {
	return fmt.Errorf("%s reaches a sensitive path on this machine (%s): an op that reads or changes a credential store is refused until its dry run can be sealed to your own device", declared, sensitive)
}

// opViewDeclared is what the op declared, each plain path resolved ONCE: as
// written and as it resolves now, so a declared path that is a link still
// shows what it names. The run checks exactly this list against the stores
// and hands exactly this list to the sandbox.
func opViewDeclared(m *opManifest) []string {
	var out []string
	for _, d := range append(append([]string{}, m.Effects.Files...), m.Reads...) {
		out = append(out, opDeclaredForms(d)...)
	}
	return out
}

// opViewVisible is everything an op may see: the base, the sandbox's own
// mounts, and the declared list (opViewDeclared).
func opViewVisible(declared []string) []string {
	out := append([]string{}, opViewBase...)
	out = append(out, opViewSandbox...)
	return append(out, declared...)
}

type opViewAction int

const (
	opViewHide    opViewAction = iota // cover it
	opViewKeep                        // it and everything under it are seen
	opViewDescend                     // a visible path lies below it: look inside
)

// opViewDecide says what the closed view does with one path, given the
// visible list split into segments. Everything under a visible path is seen;
// a folder on the way to one is entered; anything else is covered.
func opViewDecide(p string, visible [][]string) opViewAction {
	ps := pathSegments(p)
	descend := false
	for _, v := range visible {
		n := len(v)
		if len(ps) < n {
			n = len(ps)
		}
		ok := true
		for i := 0; i < n; i++ {
			if !opSegMatch(v[i], ps[i]) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if len(ps) >= len(v) {
			return opViewKeep
		}
		descend = true
	}
	if descend {
		return opViewDescend
	}
	return opViewHide
}

func opViewSegments(visible []string) [][]string {
	out := make([][]string, 0, len(visible))
	for _, v := range visible {
		out = append(out, pathSegments(v))
	}
	return out
}
