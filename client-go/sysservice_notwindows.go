//go:build !windows

package main

// maybeRunAsWindowsService is the Windows service entry point
// (sysservice_windows.go). Elsewhere a service manager simply runs `run`.
func maybeRunAsWindowsService() bool { return false }
