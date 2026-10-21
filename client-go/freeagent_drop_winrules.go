package main

// The decisions behind the Windows drop (freeagent_drop_windows.go), kept in an
// untagged file so the suite checks them on every platform. The Windows calls
// that gather their inputs are in the tagged file.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// faDropSIDLane bounds the lookup of the granted folder's owner (sidnames.go).
// The start runs on the store's own goroutine and nothing waits on it, so the
// budget is generous enough for a slow directory that does answer. It is a
// bound all the same: the store is marked as ensuring for as long as the start
// runs, and every reconcile skips it while it is, so a lookup that never
// returned would hold the store as "installing" for good. Timed out, the store
// is failed with the reason and the reconcile tries again
// (faReconcileEvery), by when a late answer is in the cache.
var faDropSIDLane = sidLane{slots: make(chan struct{}, 1), budget: 10 * time.Second}

// faWinDropOwnerAccount is the folder owner's account from the directory. It
// fails closed: no account, or no answer in time, and no agent is started.
func faWinDropOwnerAccount(sid string, dir *sidDirectory, lane sidLane) (sidAccount, error) {
	acct, outcome := dir.resolve(sid, lane)
	switch outcome {
	case sidTimedOut:
		return sidAccount{}, fmt.Errorf("refusing to run the agent for now: this machine's account directory did not answer "+
			"for the granted folder's owner (%s) within %v; it is tried again at the next check", sid, lane.budget)
	case sidUnmapped:
		return sidAccount{}, fmt.Errorf("refusing to run the agent: the granted folder's owner (%s) has no account on this machine", sid)
	}
	return acct, nil
}

// winSidTypeUser is SidTypeUser: the SID names a person's account rather than
// a group, an alias or a well-known identity.
const winSidTypeUser = 1

// faWinOwnerRefusal says why a Windows account may NOT run a folder's agent,
// or "" when it may. It is the Windows reading of the unix rule (root, nobody,
// no account): the agent runs as the person who owns the folder, never as one
// of the machine's own identities, a group, or an account anyone can use.
//
//   - SYSTEM, LOCAL SERVICE, NETWORK SERVICE, the service and virtual accounts
//     (S-1-5-80, -82, -83, -90, -96) and the BUILTIN groups (S-1-5-32, which is
//     where Administrators is, and the usual owner of a folder an elevated
//     administrator made) are the machine's identities, not a person.
//   - Only a user account issued by the machine or its domain (S-1-5-21-) or by
//     Microsoft Entra ID (S-1-12-1-) is a person.
//   - The built-in Administrator (RID 500) runs with full rights and no UAC
//     split by default, so an agent under its token would be the machine's
//     administrator: the root case. The built-in Guest (RID 501) is shared.
//     Every RID below 1000 is reserved for a built-in account the machine or
//     its domain made (krbtgt 502, DefaultAccount 503, WDAGUtilityAccount 504,
//     and the rest); a person's account is issued a RID of 1000 or more. None
//     of the reserved ones is a person, so all are refused.
func faWinOwnerRefusal(sid string, sidType uint32, name string) string {
	grant := " — grant a folder owned by the user who should read it"
	switch sid {
	case "S-1-5-18":
		return "refusing to run the agent as SYSTEM: the granted folder is owned by the system" + grant
	case "S-1-5-19", "S-1-5-20":
		return "refusing to run the agent as a service account: the granted folder is owned by " + name + grant
	}
	for _, p := range []string{"S-1-5-32-", "S-1-5-80-", "S-1-5-82-", "S-1-5-83-", "S-1-5-90-", "S-1-5-96-"} {
		if strings.HasPrefix(sid, p) {
			return "refusing to run the agent as " + name + ": the granted folder is owned by one of the machine's own identities, not a person" + grant
		}
	}
	person := strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
	if !person || sidType != winSidTypeUser {
		return "refusing to run the agent as " + name + ": the granted folder's owner is not a person's account" + grant
	}
	if strings.HasPrefix(sid, "S-1-5-21-") {
		if rid, err := strconv.Atoi(sid[strings.LastIndex(sid, "-")+1:]); err == nil && rid < 1000 {
			switch rid {
			case 500:
				return "refusing to run the agent as the built-in Administrator: it runs with the machine's full rights" + grant
			case 501:
				return "refusing to run the agent as the built-in Guest: anyone may use it" + grant
			default:
				return "refusing to run the agent as " + name + ": the granted folder is owned by a built-in account, not a person" + grant
			}
		}
	}
	return ""
}

// winJoin joins Windows path parts with a backslash, whatever platform this
// runs on, so the environment below is tested off Windows.
func winJoin(parts ...string) string {
	out := strings.TrimRight(parts[0], `\`)
	for _, p := range parts[1:] {
		out += `\` + strings.Trim(p, `\`)
	}
	return out
}

// faWinDropEnv is what a Windows child is told about who it is, and which of
// the service's variables it keeps. The service runs as LocalSystem, so its
// USERPROFILE, APPDATA, LOCALAPPDATA and TEMP all name LocalSystem's profile,
// which the owner cannot open; they are replaced with the owner's own. A
// Python child on Windows also needs SystemRoot to open a socket, so that is
// kept, with the other machine-wide variables that say nothing about the
// account.
func faWinDropEnv(user, profile, stateDir string) (set []string, passthrough []string) {
	home := profile
	temp := stateDir
	if profile != "" {
		temp = winJoin(profile, `AppData\Local\Temp`)
	} else {
		home = stateDir
	}
	set = []string{"USERNAME=" + user, "HOME=" + home, "USERPROFILE=" + home, "TEMP=" + temp, "TMP=" + temp}
	if profile != "" {
		set = append(set, "APPDATA="+winJoin(profile, `AppData\Roaming`), "LOCALAPPDATA="+winJoin(profile, `AppData\Local`))
	}
	passthrough = []string{"PATH", "SystemRoot", "SYSTEMROOT", "windir", "WINDIR", "ComSpec", "PATHEXT",
		"PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "LANG", "LC_ALL"}
	return set, passthrough
}

// faWinEnvBlock is the environment block CreateProcessAsUser takes: each
// NAME=value NUL-terminated, the block ended by one more NUL, sorted by name
// without regard to case as Windows requires. A later duplicate of a name
// (in any case) wins, and the drive-letter entries that begin with '=' are
// left out.
func faWinEnvBlock(env []string) []uint16 {
	byName := map[string]string{}
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		byName[strings.ToUpper(kv[:i])] = kv
	}
	keys := make([]string, 0, len(byName))
	for k := range byName {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []uint16
	for _, k := range keys {
		out = append(out, utf16.Encode([]rune(byName[k]))...)
		out = append(out, 0)
	}
	if len(out) == 0 {
		out = append(out, 0)
	}
	return append(out, 0)
}
