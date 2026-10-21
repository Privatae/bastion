//go:build !windows

package main

import (
	"context"
	"errors"
)

// No tray off Windows, and that is a decision rather than a gap — tray_windows.go
// carries the measurement behind it. Short version: fyne.io/systray needs cgo on
// darwin, which would end the single-container CGO_ENABLED=0 build for all six
// release targets; and a Linux bastion is a headless server under systemd, where
// `systemctl status` already answers liveness and there is no notification area
// to put an icon in.
//
// shutdownCh and trayStateLine are NOT here: they are ordinary logic and live in
// tray.go, untagged, so the suite actually runs them.
func startTray(context.Context) {}

// cmdTray is the person's tray beside a system service, which only Windows has.
func cmdTray() error {
	return errors.New("the tray is a Windows icon; on this system `privatae-bastion ui` opens the machine's page")
}
