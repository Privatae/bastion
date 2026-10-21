//go:build !linux && !darwin && !windows

package main

// A platform whose FileInfo this binary has no key for. Returning no key at all
// disables the cache rather than guessing one: deltacache.go only consults an
// entry whose key is non-empty, so such a box re-digests every pass and is slow
// rather than wrong.

import "os"

func statIdentity(os.FileInfo) (string, bool) { return "", false }
