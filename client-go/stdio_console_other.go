//go:build !linux && !darwin && !windows

package main

// stdioIsConsole cannot be told here, so it answers no: a caller that needs a
// console refuses rather than guess.
func stdioIsConsole() bool { return false }

// stdinIsConsole cannot be told here either. No means `pair -` asks for the
// token with no prompt; `pair` with no token is the usage error regardless.
func stdinIsConsole() bool { return false }
