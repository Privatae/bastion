//go:build !linux

package main

// observe:folders, observe:journal, observe:logins and observe:cert off Linux:
// the handlers check the arguments the same way and answer
// {"unsupported": "<goos>"}, as observe_ops_other.go's ops do. These are
// never reached (the handlers ask observeHostSupported first) and exist so
// the package builds.

func journalAccess() string                { return "" }
func readFolders(string, int) (any, error) { return observeUnsupported(), nil }
func readJournal(string, int) (any, error) { return observeUnsupported(), nil }
func readLogins(int) any                   { return observeUnsupported() }
func readCert(int, string) (any, error)    { return observeUnsupported(), nil }
