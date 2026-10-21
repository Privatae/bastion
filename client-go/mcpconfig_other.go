//go:build !linux && !darwin && !windows

package main

// No account list on this platform: the scan says unsupported rather than
// reporting a machine with no tool servers.
func mcpHomes() ([]mcpHome, bool) { return nil, false }

func mcpSystemFiles() []mcpSource { return nil }
