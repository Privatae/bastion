//go:build !linux

package main

// llmListenerTrusted is Linux's check of who listens (llmlocal_linux.go). On
// Windows and macOS the found server is taken as it answers; who owns the
// port is not checked there yet.
func llmListenerTrusted(string) bool { return true }
