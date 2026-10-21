//go:build darwin

package main

import (
	"os"
	"path/filepath"
)

// The accounts whose agent clients mcpconfig.go reads on macOS: the service's
// own home and every directory under /Users except Shared. The per-user
// configuration directory is ~/Library/Application Support.
func mcpHomes() ([]mcpHome, bool) {
	var homes []string
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		homes = append(homes, h)
	}
	if entries, err := os.ReadDir("/Users"); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Name() != "Shared" && e.Name()[0] != '.' {
				homes = append(homes, filepath.Join("/Users", e.Name()))
			}
		}
	}
	var out []mcpHome
	for _, h := range dedupeStrings(homes) {
		out = append(out, mcpHome{Dir: h, ConfigDir: filepath.Join(h, "Library", "Application Support")})
	}
	return out, true
}

func mcpSystemFiles() []mcpSource { return mcpSystemSources("darwin", "") }
