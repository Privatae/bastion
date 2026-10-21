//go:build !linux

package main

// macOS and Windows keep accounts and listening sockets somewhere this plane
// does not read yet, and this file SAYS SO rather than leaving an absent
// symbol — the same shape baseline_all_other.go and delta_other.go use.
//
// Both return unsupported with a reason, which is what puts
// `identities=unsupported` / `listeners=unsupported` into the baseline's
// coverage line. That matters more than it looks: a delta computed against a
// baseline holding no identities must report that it cannot see identities, and
// must never report that this machine has none. Returning an empty list here
// would produce exactly the second sentence.
//
// What each would need, so the next person does not have to rediscover it:
//
//	darwin   accounts live in OpenDirectory, not /etc/passwd (`dscl . -list
//	         /Users`), sudo rules are in the same files as Linux, and the
//	         socket table comes from `lsof -iTCP -sTCP:LISTEN` or netstat
//	         rather than `ss`.
//	windows  accounts are local users / group membership (LocalAccounts), there
//	         is no sudoers, and the equivalent of a key grant is a service
//	         logon right. The listener half is `netstat -ano` or the
//	         iphlpapi tables.

// This platform reads neither class: its coverage says `unsupported`.
const (
	listenersReadableHere  = false
	identitiesReadableHere = false
)

func identityScan() identityScanReport {
	return identityScanReport{
		Reason: "this platform's account database is not read by the bastion yet",
	}
}

func listenerScan() ([]listenSocket, bool, string) {
	return nil, false, "this platform's socket table is not read by the bastion yet"
}
