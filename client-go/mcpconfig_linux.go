//go:build linux

package main

import (
	"path/filepath"
)

// The accounts whose agent clients mcpconfig.go reads on Linux: the same
// homes the app inventory reads (userHomes: the service's own home and every
// directory under /home). A home this process may not enter yields files it
// counts as unreadable, never as empty. The per-user configuration directory
// is the XDG default, ~/.config; another account's XDG_CONFIG_HOME lives in
// its own environment, which a system service does not see.
func mcpHomes() ([]mcpHome, bool) {
	var out []mcpHome
	for _, h := range userHomes() {
		out = append(out, mcpHome{Dir: h, ConfigDir: filepath.Join(h, ".config")})
	}
	return out, true
}

func mcpSystemFiles() []mcpSource { return mcpSystemSources("linux", "") }
