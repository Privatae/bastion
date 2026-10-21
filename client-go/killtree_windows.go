//go:build windows

package main

import "errors"

// freezeSupported: Windows has no SIGSTOP. killTree kills as it walks instead
// (killtree.go).
const freezeSupported = false

var errNoFreeze = errors.New("this platform cannot stop a process without killing it")

func osStopProcess(int) error   { return errNoFreeze }
func osResumeProcess(int) error { return errNoFreeze }
