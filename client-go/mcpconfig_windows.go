//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// The accounts whose agent clients mcpconfig.go reads on Windows: every
// profile directory beside the Public one (normally C:\Users\*), except the
// templates and shared profiles Windows keeps there. %USERPROFILE% is not
// used to find them: under LocalSystem it is the system profile, not a
// person's. The per-user configuration directory is AppData\Roaming, which
// is what %APPDATA% names for that account.
func mcpHomes() ([]mcpHome, bool) {
	root := ""
	if pub := os.Getenv("PUBLIC"); pub != "" {
		root = filepath.Dir(pub)
	} else if drive := os.Getenv("SystemDrive"); drive != "" {
		root = drive + `\Users`
	}
	var homes []string
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		homes = append(homes, h)
	}
	if root != "" {
		if entries, err := os.ReadDir(root); err == nil {
			for _, e := range entries {
				switch strings.ToLower(e.Name()) {
				case "public", "default", "default user", "all users", "defaultapppool":
					continue
				}
				if e.IsDir() {
					homes = append(homes, filepath.Join(root, e.Name()))
				}
			}
		}
	}
	var out []mcpHome
	for _, h := range dedupeStrings(homes) {
		out = append(out, mcpHome{Dir: h, ConfigDir: filepath.Join(h, "AppData", "Roaming")})
	}
	return out, true
}

func mcpSystemFiles() []mcpSource { return mcpSystemSources("windows", os.Getenv("ProgramFiles")) }
