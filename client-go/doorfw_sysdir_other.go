//go:build !windows

package main

// systemDir is System32 on Windows; elsewhere the Windows firewall is never
// used, and the tests read the path the rule commands are built with.
func systemDir() string { return `C:\Windows\System32` }
