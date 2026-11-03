//go:build windows

package main

import "golang.org/x/sys/windows"

// systemDir is System32, from Windows itself rather than the environment.
func systemDir() string {
	if d, err := windows.GetSystemDirectory(); err == nil && d != "" {
		return d
	}
	return `C:\Windows\System32`
}
