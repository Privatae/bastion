//go:build !linux

package main

// Ops run only on Linux (ops_names_linux_test.go): elsewhere there are no
// units to keep apart.
func opIsolateOpsUnits()      {}
func opIsolatedOpsUnitsDone() {}
