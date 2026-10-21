//go:build !windows

package main

// relaunchAfterUpdate is a no-op off Windows: a Linux install is a systemd unit
// with Restart=always (deploy/install.sh writes it), so exiting IS the restart
// and starting a second process here would race the one systemd is about to
// bring up. See relaunch_windows.go for why Windows cannot rely on that.
func relaunchAfterUpdate() {}
