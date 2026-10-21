//go:build !linux

package main

// osProcIdentity has no cheap, reliable source here, so it says so and the
// kill proceeds without identity checks, as it did before they existed.
func osProcIdentity(int) (string, bool, bool) { return "", false, false }
