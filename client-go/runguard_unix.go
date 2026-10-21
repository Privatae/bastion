//go:build !windows && !darwin

package main

// guardSingleRun is a no-op on Linux: acquireSingletonLock (singleton.go)
// already holds the machine-wide exclusion lock there, and its semantics are
// deliberately different — the loser becomes a STANDBY blocked in the kernel
// until the primary dies, because systemd is holding the unit open and a
// standby taking over on death is the wanted behaviour. An ordinary Windows
// install has no service to do that, so it refuses instead; see
// runguard_windows.go. macOS refuses a `run` beside its system service; see
// runguard_darwin.go.
func guardSingleRun() error { return nil }
