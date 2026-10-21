//go:build !linux

package main

// observe:* stub for every platform but Linux. The ops are still in the
// table (so the enforcing vocabulary is the same everywhere and a grant can
// name them) and still answer — {"unsupported": "<goos>"}, exit 0 — because
// "this box cannot say" is a true answer and 126 means "not permitted".
// observe:net is pure Go and works here; the heartbeat carries no posture.

const observeHostSupported = false

func readHostPosture() hostPosture { return hostPosture{} }
func readSockets() any             { return observeUnsupported() }
func readFirewall() any            { return observeUnsupported() }
func readUnits() any               { return observeUnsupported() }
func readDisk() any                { return observeUnsupported() }
func readKernel() any              { return observeUnsupported() }
func readK8s() any                 { return observeUnsupported() }
