//go:build !linux

package main

// Darwin and Windows do not have an unfiltered walk here yet, and the baseline
// SAYS SO rather than quietly recording less (see cmdObserveBaseline). On those
// platforms the accounting covers what the observe plane recognises, which is a
// smaller truth than "every process" and is named as such in the output and in
// the file.
//
// The walks exist — agents_darwin.go's psSweep and agents_windows.go's
// Toolhelp32 snapshot both enumerate everything before filtering — so this is a
// refactor of those two rather than new platform work.
func baselineAllProcesses() ([]agentObs, bool) { return nil, false }
