//go:build !darwin && !windows

package main

import "errors"

// On Linux the system service is the systemd unit deploy/install.sh writes,
// and nothing here changes it. These answer the `service` command and the
// startup check (adoptSystemServiceState) for that platform.

var errLinuxServiceIsTheUnit = errors.New("on Linux the system service is the systemd unit the installer writes " +
	"(curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh); manage it with systemctl")

func systemServiceInstalled() (bool, error) { return false, nil }

func installSystemService() error { return errLinuxServiceIsTheUnit }

func uninstallSystemService() error { return errLinuxServiceIsTheUnit }

func printSystemServiceStatus() error { return errLinuxServiceIsTheUnit }
