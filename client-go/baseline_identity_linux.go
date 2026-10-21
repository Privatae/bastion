//go:build linux

package main

// The Linux account reader. Everything here is a read; nothing in this file
// writes, and nothing it reads leaves the machine (baseline_identity.go says
// what does).

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// identityScan reads the accounts this machine can be logged into as.
//
// ONLY ACCOUNTS WITH A LOGIN SHELL. A stock Debian has some fifty system
// accounts — daemon, bin, sys, www-data — every one of them nologin, none of
// them a way in, and all of them noise that would bury the one account that
// matters. The filter is on the shell because that is the property that makes
// an account a route onto the box.
//
// A NON-ROOT RUN IS BLIND HERE AND SAYS SO. /etc/passwd is world-readable, so
// the account list comes out either way — but the sudo rules and every other
// user's authorized_keys do not, and an accounting that silently recorded
// "0 keys" for every account would report the truth backwards. deltaPass
// already refuses to run as a non-administrator; this is the second guard.
// This platform reads both classes, so a failed read while the accounting is
// taken is written `unread`, not `unsupported` (baselineCoverageRead).
const (
	listenersReadableHere  = true
	identitiesReadableHere = true
)

func identityScan() identityScanReport {
	f, err := os.Open(identityPath("/etc/passwd"))
	if err != nil {
		return identityScanReport{Reason: "the account database could not be read: " + err.Error()}
	}
	defer f.Close()

	sudoers, sudoPartial := sudoPrincipals()

	// WHERE SSHD ACTUALLY LOOKS FOR KEYS, which is not always the default pair.
	// A box with `AuthorizedKeysFile /etc/ssh/authorized_keys/%u` recorded "no
	// keys" for every account, silently — the class went narrow with no note,
	// and a new account holding central keys graded high instead of critical.
	keyPaths, keyNote := authorizedKeysPaths()

	r := identityScanReport{Supported: true, Partial: strings.TrimSpace(sudoPartial + " " + keyNote)}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		p := strings.Split(line, ":")
		if len(p) < 7 {
			continue
		}
		shell := strings.TrimSpace(p[6])
		if !identityIsLoginShell(shell) {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimSpace(p[2]))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(p[0])
		// THE PARTIAL IS NOW LOAD-BEARING. It was set here and read NOWHERE,
		// so unreadable sudo rules recorded sudo=false for
		// every account — and the next readable pass fired `sudoers_changed` at
		// CRITICAL for each one, saying a rule had been removed that had never
		// been seen.
		id := identityObs{Name: name, UID: uid, Shell: shell,
			Sudo: sudoers[name], SudoUnknown: sudoPartial != ""}
		keys, unread := authorizedKeysOf(strings.TrimSpace(p[5]), name, strconv.Itoa(uid), keyPaths)
		id.AuthKeys, id.KeyDigest, id.KeysUnread = identityCountKeys(keys), identityKeyDigest(keys), unread
		r.Accounts = append(r.Accounts, id)
	}
	if err := sc.Err(); err != nil {
		// UNSUPPORTED, NOT PARTIAL, and the difference is which half is short.
		// Partial means "some PROPERTY of these accounts is narrow" and the
		// entries are still compared. A scanner error drops ENTRIES — measured
		// with one 70 KB GECOS line, 2 accounts of 5 — and comparing that set
		// reports the tail as identity_gone and never sees an account created
		// after the long line at all. Same family as the failed `ss`, and the
		// same answer listenerScan gives: refuse the class.
		return identityScanReport{Reason: "the account database could not be read to the end: " + err.Error()}
	}
	return r
}

// authorizedKeysOf reads an account's keys. Returns the lines and, when it
// could not look, why — never an empty list standing in for both.
func authorizedKeysOf(home, user, uid string, paths []string) (keys []string, unread string) {
	if home == "" {
		return nil, "no home directory recorded"
	}
	// BOTH CONVENTIONAL PATHS. sshd's default AuthorizedKeysFile is
	// ".ssh/authorized_keys .ssh/authorized_keys2", and the second is still
	// honoured on a stock install — a key parked there would be a working way
	// in that an accounting reading only the first would never see.
	var missing int
	for _, rel := range paths {
		b, err := os.ReadFile(authorizedKeysPath(rel, home, user, uid))
		if err != nil {
			if os.IsNotExist(err) {
				missing++
				continue
			}
			// Permission denied is the interesting one: it means this account
			// HAS a key file this process may not read, which is not the same
			// as having none.
			return keys, err.Error()
		}
		keys = append(keys, strings.Split(string(b), "\n")...)
	}
	if missing == len(paths) && len(keys) == 0 {
		// BOTH FILES ABSENT MEANS ONE OF TWO THINGS, and they are not the same.
		// If the home directory itself is not there, this
		// box did not look — an unmounted /home, a network home not yet
		// available, an account whose home was never created. Reading that as
		// "no keys" makes every account report `authkeys_changed` the moment
		// the mount appears. A home that IS there with no .ssh is genuinely
		// none, and says nothing.
		if _, err := os.Stat(home); err != nil {
			return nil, "home directory not readable: " + err.Error()
		}
		return nil, ""
	}
	return keys, ""
}

// authorizedKeysPaths is what sshd_config says AuthorizedKeysFile is, or the
// default pair when it says nothing. Tokens are left in place and expanded per
// account by authorizedKeysPath.
//
// Returns a note when the setting is NOT the default, because a narrowed or
// relocated key lookup changes what this whole class can see and the person is
// entitled to know that rather than reading a confident "0 keys".
// sshdConfigPath is a var for the same reason as listenerSockets: a test must
// be able to hand this an sshd_config, and the machine's own is not one it may
// write.
var sshdConfigPath = "/etc/ssh/sshd_config"

// identityRoot is "/" in production and a fixture directory in a test. Without
// it nothing could execute identityScan itself, so its WIRING — that it sets
// SudoUnknown, that it feeds the sshd_config paths through, that it carries the
// narrowed-lookup note — was untestable and a mutation sweep found every one of
// those unguarded.
var identityRoot = "/"

func identityPath(p string) string {
	if identityRoot == "/" || identityRoot == "" {
		return p
	}
	return filepath.Join(identityRoot, p)
}

func authorizedKeysPaths() ([]string, string) {
	def := []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
	b, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return def, "" // no sshd here; the default pair is the right guess
		}
		return def, "sshd_config not readable, so authorized-key locations are assumed to be the default"
	}
	// INCLUDE IS THE DEBIAN 12 / UBUNTU 22.04 DEFAULT LAYOUT, and missing it put
	// this straight back to the "no keys" failure with no note: a drop-in under
	// /etc/ssh/sshd_config.d/*.conf sets AuthorizedKeysFile and nothing here saw
	// it. One level of Include, which is what the
	// stock layout uses; deeper nesting is named as a limit rather than walked.
	body := string(b)
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || !strings.EqualFold(f[0], "Include") {
			continue
		}
		for _, pat := range f[1:] {
			if !filepath.IsAbs(pat) {
				pat = filepath.Join(filepath.Dir(sshdConfigPath), pat)
			}
			if hits, err := filepath.Glob(pat); err == nil {
				for _, h := range hits {
					if ib, err := os.ReadFile(h); err == nil {
						body += "\n" + string(ib)
					}
				}
			}
		}
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		// A Match BLOCK SCOPES EVERYTHING AFTER IT to some users or addresses,
		// so an AuthorizedKeysFile inside one is NOT the global setting and
		// applying it to every account would be wrong in the confident
		// direction. Stop at the first Match and say the lookup may be narrower
		// than what was read.
		if strings.EqualFold(f[0], "Match") {
			break
		}
		if len(f) < 2 || !strings.EqualFold(f[0], "AuthorizedKeysFile") {
			continue
		}
		if strings.EqualFold(f[1], "none") {
			return nil, "sshd is configured with AuthorizedKeysFile none, so no account has ssh keys to account for"
		}
		// NO PATH IN THIS STRING. It reaches deltaSummary.Note, which rides the
		// heartbeat — so the first version of it put a line of the user's own
		// sshd configuration on the wire every pass. This file's header promises the class adds nothing that leaves
		// the machine, and it was written when every note was a fixed sentence.
		// The generic form does the note's whole job: it tells the person the
		// class is narrowed and to go look. The path is on their box already.
		return f[1:], "authorized keys are read from a location this platform " +
			"does not choose, so what this class can see depends on that setting"
	}
	return def, ""
}

// authorizedKeysPath expands sshd's tokens in one AuthorizedKeysFile entry.
// A relative path is relative to the account's home, which is sshd's own rule.
func authorizedKeysPath(pattern, home, user, uid string) string {
	// %% FIRST, VIA A PLACEHOLDER, or its own percent gets eaten by the token
	// that follows it. Measured: `%%h/.ssh/ak` expanded to
	// `/home/erin/%/home/erin/.ssh/ak`, because %h was substituted before %%
	// was collapsed. The path then does not exist, which
	// reads as ENOENT, which reads as "this account has no keys".
	const esc = "\x00pct\x00"
	p := strings.ReplaceAll(pattern, "%%", esc)
	p = strings.ReplaceAll(p, "%u", user)
	p = strings.ReplaceAll(p, "%U", uid)
	p = strings.ReplaceAll(p, "%h", home)
	p = strings.ReplaceAll(p, esc, "%")
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(home, p)
}

// sudoPrincipals is the set of account names a sudo rule names, directly or
// through a group.
//
// DELIBERATELY SHALLOW, and this is the honest limit of the class. It reads
// every name in the User_List on the left of a rule, comma-separated with or
// without spaces; it does not evaluate sudo's grammar, expand
// netgroups, follow #includedir recursion beyond one level, or decide what a
// rule actually permits. So `sudo=true` means "a rule names this account", not
// "this account can become root" — and a rule that grants nothing still sets
// it. That direction is the right one to be wrong in: a false true is a person
// reading one extra line, a false false is a missed privilege grant.
func sudoPrincipals() (map[string]bool, string) {
	out := map[string]bool{}
	var unreadable []string

	files := []string{identityPath("/etc/sudoers")}
	if ents, err := os.ReadDir(identityPath("/etc/sudoers.d")); err == nil {
		for _, e := range ents {
			if e.IsDir() || strings.HasSuffix(e.Name(), "~") || strings.Contains(e.Name(), ".") {
				// sudo itself ignores names containing a dot or ending in ~.
				continue
			}
			files = append(files, filepath.Join(identityPath("/etc/sudoers.d"), e.Name()))
		}
	} else if !os.IsNotExist(err) {
		unreadable = append(unreadable, "/etc/sudoers.d")
	}

	groups := map[string]bool{}
	var bodies []string
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			unreadable = append(unreadable, path)
			continue
		}
		bodies = append(bodies, string(b))
	}
	sudoParse(bodies, out, groups)
	for name := range groupMembers(groups) {
		out[name] = true
	}
	if len(unreadable) > 0 {
		return out, "sudo rules not readable: " + strings.Join(unreadable, ", ")
	}
	return out, ""
}

// sudoParse is the line reading, split out so it can be tested without an
// /etc — which is the only reason the comma-separated User_List bug
// could not be caught by a unit test before.
func sudoParse(bodies []string, out, groups map[string]bool) {
	for _, body := range bodies {
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 2 || !strings.Contains(line, "=") {
				continue
			}
			// A User_List IS COMMA-SEPARATED, and taking only the first name
			// was wrong in both directions.
			// `erin,dave ALL=(ALL:ALL) ALL` is ordinary sudoers: it recorded a
			// principal literally named "erin,dave" and left BOTH real
			// accounts reading sudo=false — a missed privilege grant, which is
			// the direction this function must never be wrong in. And adding a
			// second name to an existing rule then flipped the first account
			// from true to false, which surfaces as `sudoers_changed` at
			// CRITICAL carrying "no sudo rule names this account any more".
			// That sentence was untrue and it was on the page rung.
			// THE WHOLE User_List, WHICH IS NOT ALWAYS ONE FIELD. `visudo -c`
			// accepts `erin, dave ALL=(ALL:ALL) ALL` — a space after the
			// comma — and splitting only f[0] found `erin` and missed `dave`.
			// The list is everything up to the
			// first field that is not part of it, which is the one containing
			// the `=`.
			for _, who := range strings.Split(sudoUserList(f), ",") {
				who = strings.TrimSpace(who)
				if who == "" {
					continue
				}
				switch {
				case strings.HasPrefix(who, "%"):
					groups[strings.TrimPrefix(who, "%")] = true
				case strings.HasPrefix(who, "User_Alias"), strings.HasPrefix(who, "Runas_Alias"),
					strings.HasPrefix(who, "Host_Alias"), strings.HasPrefix(who, "Cmnd_Alias"):
					// An alias DEFINITION names no principal by itself; its
					// members are picked up where the alias is used, which this
					// shallow read does not follow. Named in the doc comment.
				default:
					out[who] = true
				}
			}
		}
	}
}

// sudoUserList is the principal list at the head of a rule, rejoined across the
// spaces a comma-separated list may contain. Everything before the field that
// holds the `=` belongs to it.
func sudoUserList(f []string) string {
	var head []string
	for _, tok := range f {
		if strings.Contains(tok, "=") {
			break
		}
		head = append(head, tok)
	}
	if len(head) == 0 {
		return f[0]
	}
	// "erin, dave" and "erin,dave" and "erin ,dave" all become "erin,dave".
	return strings.ReplaceAll(strings.Join(head, ""), " ", "")
}

// groupMembers expands the named groups to their member accounts, from
// /etc/group. A group's members also come from each account's primary gid,
// which is not read here — see the shallowness note on sudoPrincipals.
func groupMembers(want map[string]bool) map[string]bool {
	out := map[string]bool{}
	if len(want) == 0 {
		return out
	}
	b, err := os.ReadFile(identityPath("/etc/group"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.Split(strings.TrimSpace(line), ":")
		if len(p) < 4 || !want[p[0]] {
			continue
		}
		for _, m := range strings.Split(p[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				out[m] = true
			}
		}
	}
	return out
}

// listenerScan is the socket half, read through the observe plane's own reader
// so the accounting and `observe:sockets` can never disagree about what is
// listening — the same rule deltaListeningPIDs states.
// listenerSockets is readSockets as a var, so a test can hand this the states
// a real `ss` produces and nothing else can: a non-zero exit, a half table.
// The first test written for this reimplemented the logic inline instead, and a
// mutation proved it tested a copy rather than the code.
var listenerSockets = readSockets

func listenerScan() ([]listenSocket, bool, string) {
	r := listenerSockets()
	if !r.Supported {
		return nil, false, r.Reason
	}
	if r.Failed != "" {
		// AN `ss` THAT RAN AND FAILED IS NOT A MACHINE WITH NO LISTENERS. This
		// is the state that produced 54 false `listener_gone` in review, and
		// the reverse — an accounting TAKEN in this state records
		// `listeners=all` with zero entries, and the next healthy pass reports
		// every listener as new, 30 of them high, repeating every beat until
		// somebody retakes the accounting.
		return nil, false, "socket table could not be read (" + r.Failed + ")"
	}
	if r.Partial != "" {
		// HALF A TABLE IS NOT A TABLE, for the reason deltaListeningPIDs gives
		// and one more that is specific to the accounting: a baseline taken
		// from a partial table records fewer listeners than the machine has,
		// and every one it missed becomes a `listener_new` finding on the next
		// pass that CAN read the table. A partial read must not become the
		// definition of normal.
		return nil, false, "socket table read short (" + r.Partial + ")"
	}
	return r.Sockets, true, ""
}
