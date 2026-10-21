//go:build !linux && !darwin && !windows

package main

const computerTreeKind = "unsupported"

func readTree(pid, maxNodes int) ([]byte, error) { return nil, nil }
