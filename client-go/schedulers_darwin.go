//go:build darwin

package main

import (
	"path/filepath"
)

// macOS scheduler inventory: LaunchDaemons and LaunchAgents system-wide and
// per user, each plist rendered to JSON by plutil (ships with every macOS)
// so no plist parser enters the module. Apple's own jobs under /System are
// not read: they are the OS, not something a user or an agent installed.

const maxPlists = 800

var launchdDirs = []string{
	"/Library/LaunchDaemons/*.plist",
	"/Library/LaunchAgents/*.plist",
	"/Users/*/Library/LaunchAgents/*.plist",
}

func platformSchedulers() ([]schedEntry, []string, bool) {
	all := []schedEntry{}
	n := 0
	for _, pat := range launchdDirs {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			if n >= maxPlists {
				break
			}
			n++
			out, err := runTimed("plutil", "-convert", "json", "-o", "-", f)
			if err != nil {
				continue
			}
			if e, ok := parseLaunchdPlistJSON(out, f); ok {
				all = append(all, e)
			}
		}
	}
	return all, []string{"launchd"}, true
}
