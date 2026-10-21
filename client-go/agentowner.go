package main

import (
	"bytes"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// WHO RUNS AN AGENT, NOT ONLY WHICH ACCOUNT.
//
// The process scan names the account an agent runs as (procUser on every
// platform, winTokenUser on Windows) and says nothing else about it. The
// question an assessment asks is about the account: is it an administrator, is
// it a person's own account or one that exists for a service, and is that
// person logged in right now. "An agent runs as a person, holds administrator
// rights, and nobody is at the keyboard" is a different finding from "an agent
// runs under a service account with no rights", and the account name alone
// cannot tell them apart.
//
// Three facts, each with an honest third value:
//
//	owner_class        domain_user, local_user, service, system, or unknown
//	owner_admin        yes, no, or unknown
//	owner_interactive  yes, no, or unknown
//
// UNKNOWN IS NEVER FOLDED INTO NO. A box that could not read the group list
// has not learned that the account is unprivileged, and saying "no" there is
// the confident-wrong answer this plane refuses everywhere else
// (baseline_identity.go draws the same line for sudo rules it could not read).
//
// Every decision is in this file, with no build tag, so the Linux test run
// exercises the macOS and Windows rules too. The platform files
// (agents_<goos>.go) only read: /proc and /etc on Linux, `id`, `dscl` and
// `who` on macOS, the process token and the session list on Windows.
//
// These ride on agentObs, so they travel only where `agents` does: inside the
// heartbeat's `observing` gate (agents.go).

const (
	ownerClassDomain  = "domain_user"
	ownerClassLocal   = "local_user"
	ownerClassService = "service"
	ownerClassSystem  = "system"
	ownerUnknown      = "unknown"
	ownerYes          = "yes"
	ownerNo           = "no"
)

// ownerFacts is the three answers for one account.
type ownerFacts struct {
	Class       string
	Admin       string
	Interactive string
}

// unknownOwner is the answer when nothing could be read: a process whose
// owner this bastion may not inspect, or a build with no reader.
var unknownOwner = ownerFacts{Class: ownerUnknown, Admin: ownerUnknown, Interactive: ownerUnknown}

func yesNo(b bool) string {
	if b {
		return ownerYes
	}
	return ownerNo
}

// ── Linux and macOS ─────────────────────────────────────────────────────────

// unixOwner is what a Linux or macOS reader collected about one account.
// Every field that can be unreadable carries its own "known" flag.
type unixOwner struct {
	UID  int // -1 when the uid could not be read
	Name string
	// LocalRecord: "yes" when the account is in this machine's own account
	// database (/etc/passwd; the macOS local directory node), "no" when it is
	// not, "unknown" when that could not be read.
	LocalRecord string
	// DirectorySource: this machine resolves accounts from a directory
	// (nsswitch names sss, ldap, winbind or nis; a macOS mobile account was
	// copied from one). Only then does "not in the local database" mean a
	// domain account rather than a uid with no account at all.
	DirectorySource bool
	// SystemUIDMax is the highest uid the platform hands to system accounts.
	SystemUIDMax int
	Groups       []string // group names the account or process holds
	GroupsKnown  bool
	AdminGroups  map[string]bool
	// SudoApplies: on this platform a sudo rule can grant administration to
	// any user or group (Linux), so "in no admin group" is only a "no" once
	// the rules were read as well. macOS leaves it false and decides on the
	// admin group, which is what its stock sudoers grants.
	// SudoNamed / SudoKnown: a sudo rule names the account directly or
	// through a group (sudoPrincipals), and whether the rules were readable.
	SudoApplies bool
	SudoNamed   bool
	SudoKnown   bool
	// Sessions is the set of account names with a login session now
	// (logind, utmp, `who`); SessionsKnown is false when none could be read.
	Sessions      map[string]bool
	SessionsKnown bool
}

// linuxSystemUIDMax is shadow-utils' default SYS_UID_MAX: accounts below
// UID_MIN (1000 by default) are system accounts. login.defs can move both;
// linuxUIDLimits reads it.
const linuxSystemUIDMax = 999

// darwinSystemUIDMax: macOS creates people's accounts from uid 501 up, and
// keeps the ids below for its own daemons (_www, _spotlight and the rest).
const darwinSystemUIDMax = 500

func classifyUnixOwner(o unixOwner) ownerFacts {
	f := ownerFacts{Class: ownerUnknown, Admin: ownerUnknown, Interactive: ownerUnknown}
	switch {
	case o.UID == 0:
		f.Class = ownerClassSystem
	case o.UID == -1:
		// Unread uid: the class cannot be told from a name alone. Other
		// negative ids are real: macOS's directory gives nobody -2.
	case o.UID == 65534 || o.UID <= o.SystemUIDMax:
		// nobody, and every uid in the system range, is an account that exists
		// for a program rather than a person.
		f.Class = ownerClassService
	case strings.ContainsAny(o.Name, `@\`):
		// user@realm (SSSD) and DOMAIN\user (winbind) are directory names.
		f.Class = ownerClassDomain
	case o.LocalRecord == ownerYes:
		f.Class = ownerClassLocal
	case o.LocalRecord == ownerNo && o.DirectorySource:
		f.Class = ownerClassDomain
	}

	switch {
	case o.UID == 0:
		f.Admin = ownerYes
	case o.GroupsKnown && hasAnyGroup(o.Groups, o.AdminGroups):
		f.Admin = ownerYes
	case o.SudoKnown && o.SudoNamed:
		f.Admin = ownerYes
	case o.GroupsKnown && (o.SudoKnown || !o.SudoApplies):
		f.Admin = ownerNo
	}

	if o.SessionsKnown && o.Name != "" {
		f.Interactive = yesNo(o.Sessions[o.Name])
	}
	return f
}

func hasAnyGroup(groups []string, want map[string]bool) bool {
	for _, g := range groups {
		if want[g] {
			return true
		}
	}
	return false
}

// linuxAdminGroups: the groups a stock distribution's sudoers grants
// administration to (sudo on Debian and Ubuntu, wheel on Fedora, RHEL and
// Arch, admin on older Ubuntu).
var linuxAdminGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true}

// darwinAdminGroups: macOS administrators are members of `admin`.
var darwinAdminGroups = map[string]bool{"admin": true}

// parseStatusIDs reads the real and effective uid and the supplementary gid
// list out of /proc/<pid>/status. ok is false when there is no Uid line.
func parseStatusIDs(status string) (realUID, effUID int, gids []int, ok bool) {
	realUID, effUID = -1, -1
	for _, line := range strings.Split(status, "\n") {
		switch {
		case strings.HasPrefix(line, "Uid:"):
			f := strings.Fields(line)
			if len(f) >= 3 {
				r, err1 := strconv.Atoi(f[1])
				e, err2 := strconv.Atoi(f[2])
				if err1 == nil && err2 == nil {
					realUID, effUID, ok = r, e, true
				}
			}
		case strings.HasPrefix(line, "Groups:"):
			for _, g := range strings.Fields(strings.TrimPrefix(line, "Groups:")) {
				if n, err := strconv.Atoi(g); err == nil {
					gids = append(gids, n)
				}
			}
		}
	}
	return realUID, effUID, gids, ok
}

// parseGroupNames maps gid -> name from an /etc/group body.
func parseGroupNames(body string) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(body, "\n") {
		p := strings.Split(strings.TrimSpace(line), ":")
		if len(p) < 3 || strings.HasPrefix(p[0], "#") {
			continue
		}
		if n, err := strconv.Atoi(p[2]); err == nil {
			out[n] = p[0]
		}
	}
	return out
}

// parsePasswdUIDs is the set of uids /etc/passwd itself lists.
func parsePasswdUIDs(body string) map[int]bool {
	out := map[int]bool{}
	for _, line := range strings.Split(body, "\n") {
		p := strings.Split(strings.TrimSpace(line), ":")
		if len(p) < 3 || strings.HasPrefix(p[0], "#") {
			continue
		}
		if n, err := strconv.Atoi(p[2]); err == nil {
			out[n] = true
		}
	}
	return out
}

// parseLoginDefsSysMax returns the highest system uid login.defs declares:
// SYS_UID_MAX when present, else UID_MIN-1, else the shadow-utils default.
func parseLoginDefsSysMax(body string) int {
	sysMax, uidMin := -1, -1
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		n, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		switch f[0] {
		case "SYS_UID_MAX":
			sysMax = n
		case "UID_MIN":
			uidMin = n
		}
	}
	switch {
	case sysMax >= 0:
		return sysMax
	case uidMin > 0:
		return uidMin - 1
	}
	return linuxSystemUIDMax
}

// nsswitchHasDirectory reports whether the passwd line of nsswitch.conf names
// a directory source, so an account missing from /etc/passwd is resolved from
// one rather than simply absent.
func nsswitchHasDirectory(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "passwd:") {
			continue
		}
		for _, src := range strings.Fields(strings.TrimPrefix(line, "passwd:")) {
			switch src {
			case "sss", "ldap", "winbind", "nis", "nisplus":
				return true
			}
		}
	}
	return false
}

// parseLogindUserState reads systemd-logind's per-user state file
// (/run/systemd/users/<uid>). active and online mean the user has a session
// now; lingering means services run for them with no session.
func parseLogindUserState(body string) (interactive bool, ok bool) {
	for _, line := range strings.Split(body, "\n") {
		if v, found := strings.CutPrefix(strings.TrimSpace(line), "STATE="); found {
			switch v {
			case "active", "online":
				return true, true
			case "lingering", "closing", "offline":
				return false, true
			}
			return false, false
		}
	}
	return false, false
}

// utmp record layout on glibc Linux (bits/utmp.h): 384 bytes, ut_type a
// 16-bit value at offset 0, ut_user 32 bytes at offset 44. USER_PROCESS (7)
// is a login session.
const (
	utmpRecordSize  = 384
	utmpUserOffset  = 44
	utmpUserSize    = 32
	utmpUserProcess = 7
)

// parseUtmpUsers is the set of account names with a USER_PROCESS record.
func parseUtmpUsers(b []byte) map[string]bool {
	out := map[string]bool{}
	for off := 0; off+utmpRecordSize <= len(b); off += utmpRecordSize {
		rec := b[off : off+utmpRecordSize]
		if int(rec[0])|int(rec[1])<<8 != utmpUserProcess {
			continue
		}
		name := rec[utmpUserOffset : utmpUserOffset+utmpUserSize]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		if len(name) > 0 {
			out[string(name)] = true
		}
	}
	return out
}

// parseWhoUsers is the set of account names `who` lists (macOS): the first
// field of every line.
func parseWhoUsers(out string) map[string]bool {
	users := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			users[f[0]] = true
		}
	}
	return users
}

// parseIDGroups reads `id -Gn <user>`: group names separated by spaces.
func parseIDGroups(out string) []string { return strings.Fields(out) }

// dsclRecordMissing: dscl ran to the end and exited non-zero, which is how it
// says the local node has no such record. A dscl the timeout killed has an
// exit code of -1 and has said nothing about the account.
func dsclRecordMissing(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() > 0
}

// parseDsclUser reads `dscl . -read /Users/<name> UniqueID OriginalNodeName`.
// A mobile account (cached from a directory) carries OriginalNodeName.
func parseDsclUser(out string) (uid int, mobile bool, ok bool) {
	uid = -1
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, found := strings.CutPrefix(line, "UniqueID:"); found {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				uid, ok = n, true
			}
		}
		if strings.HasPrefix(line, "OriginalNodeName:") {
			mobile = true
		}
	}
	return uid, mobile, ok
}

// ── Windows ─────────────────────────────────────────────────────────────────

// Well-known SIDs, from Microsoft's tables:
// https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids and
// https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
const (
	sidLocalSystem       = "S-1-5-18"
	sidLocalService      = "S-1-5-19"
	sidNetworkService    = "S-1-5-20"
	sidAdministrators    = "S-1-5-32-544"
	sidInteractive       = "S-1-5-4"
	sidRemoteInteractive = "S-1-5-14"
	sidLocalAccount      = "S-1-5-113"
	sidNTServicePrefix   = "S-1-5-80-"
	sidVirtualMachinePfx = "S-1-5-83-"
)

// winOwner is what the Windows reader collected from one process token.
type winOwner struct {
	SID      string
	Domain   string // the account's domain as LookupAccount names it
	Computer string // this machine's NetBIOS name
	// Groups are the token's group SIDs, deny-only ones included: an
	// administrator running without elevation holds Administrators as a
	// deny-only group, and is still an administrator account.
	Groups      map[string]bool
	GroupsKnown bool
	// SessionSIDs: accounts with a Remote Desktop Services session now
	// (WTSEnumerateSessions + WTSQueryUserToken, which needs LocalSystem).
	SessionSIDs   map[string]bool
	SessionsKnown bool
}

func classifyWinOwner(o winOwner) ownerFacts {
	f := ownerFacts{Class: ownerUnknown, Admin: ownerUnknown, Interactive: ownerUnknown}
	switch {
	case o.SID == "":
	case o.SID == sidLocalSystem:
		f.Class = ownerClassSystem
	case o.SID == sidLocalService || o.SID == sidNetworkService ||
		strings.HasPrefix(o.SID, sidNTServicePrefix) || strings.HasPrefix(o.SID, sidVirtualMachinePfx):
		f.Class = ownerClassService
	case o.GroupsKnown && o.Groups[sidLocalAccount]:
		f.Class = ownerClassLocal
	case o.Domain == "":
	case strings.EqualFold(o.Domain, o.Computer):
		f.Class = ownerClassLocal
	case strings.HasPrefix(o.SID, "S-1-5-21-") || strings.EqualFold(o.Domain, "AzureAD"):
		// A machine or domain account whose domain is not this computer:
		// an Active Directory or Entra ID account.
		f.Class = ownerClassDomain
	}

	switch {
	case o.SID == sidLocalSystem:
		// "System is a hidden member of Administrators" (the second page above).
		f.Admin = ownerYes
	case o.GroupsKnown:
		f.Admin = yesNo(o.Groups[sidAdministrators])
	}

	switch {
	case o.SessionsKnown && o.SID != "":
		f.Interactive = yesNo(o.SessionSIDs[o.SID])
	case o.GroupsKnown && (o.Groups[sidInteractive] || o.Groups[sidRemoteInteractive]):
		// No session list (the bastion is not LocalSystem), but this very
		// process was started by an interactive logon, so the account has
		// one. The converse proves nothing: a scheduled task's token is not
		// interactive while its owner may well be logged in.
		f.Interactive = ownerYes
	}
	return f
}
