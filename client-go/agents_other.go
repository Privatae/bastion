//go:build !linux && !darwin && !windows

package main

import "errors"

// Observe-plane stub for platforms with no enumerator. The bastion still runs
// — tunnel, grants, DCN, every lane — it simply reports that it cannot watch
// itself, rather than reporting an empty agent list that would be read as
// "nothing running here". agentScanSupported is what keeps those two apart:
// the heartbeat withholds the "agent-observe" capability, so the host can say
// "this box is not watching" instead of "this box is quiet".

const (
	agentScanSupported = false
	agentScanKind      = "unsupported"
)

// errNoEnumerator: the walk cannot happen here, so scanAgents fails and the
// heartbeat carries no `agents` key at all — the same absence a scan failure
// produces elsewhere, and the host reads both as "did not look".
var errNoEnumerator = errors.New("no process enumerator on this platform")

func scanProcesses() (map[int]agentObs, error) { return nil, errNoEnumerator }
func scanConnections() []connObs               { return []connObs{} }
func procUser(pid int) string                  { return "" }
func procCmdline(pid int) string               { return "" }
func procEnvToken(pid int) string              { return "" }

// procExe: no enumerator, so no kernel path — and an empty one is honest here
// in a way a guess never could be. sanction.go refuses to mark an observation
// that has none, which on this build means nothing can be marked at all; that
// is the same "cannot watch itself" answer agentScanSupported already gives.
func procExe(pid int) string      { return "" }
func procParent(pid int) int      { return 0 }
func processParents() map[int]int { return map[int]int{} }

// ownerFactsReader: no reader here, so every owner fact is unknown.
func ownerFactsReader() func(pid int, user string) ownerFacts {
	return func(int, string) ownerFacts { return unknownOwner }
}

// scanMCPProcesses: no enumerator, so running state is never measured here.
func scanMCPProcesses(map[string]bool) ([]mcpProc, error) { return nil, errNoEnumerator }
