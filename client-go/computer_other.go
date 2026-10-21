//go:build !linux && !darwin && !windows

package main

// computer:* stub for platforms with no enumerator. The ops still answer — with
// supported:false and a reason — so the host reads "this box cannot see its
// apps/windows" and never an empty list that would pass for "nothing here".

const (
	computerObserveSupported = false
	computerInventoryKind    = "unsupported"
	computerWindowsKind      = "unsupported"
)

func listInstalledApps() ([]computerApp, error) { return nil, nil }
func listWindows() ([]computerWindow, error)    { return nil, nil }
