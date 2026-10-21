//go:build !linux

package main

import (
	"net"
	"os"
	"path/filepath"
)

// Coder mode is Linux-only in this cut (coders.go); run-up refuses before
// either of these is reached, and the heartbeat never advertises it.

func coderSocketOwner(p string) (int, bool) { return -1, false }

// coderFileOwner: no owner is known here, so no runs directory passes.
func coderFileOwner(fi os.FileInfo) (int, bool) { return -1, false }

func coderReadMemInfo() (total, avail uint64, ok bool) { return 0, 0, false }

func coderReadPSIMem() (float64, bool) { return 0, false }

func coderListenUnix(dir, name string) (net.Listener, error) {
	return net.Listen("unix", filepath.Join(dir, name))
}
