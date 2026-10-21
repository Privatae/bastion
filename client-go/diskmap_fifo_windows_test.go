package main

import "errors"

// Windows has no mkfifo. TestTheWalkerDoesNotOpenAFifo skips on this error, so
// the behavioural half of the privacy line is unproven on Windows and the AST
// half (TestTheWalkerNeverOpensAFile) is what holds it there. Said plainly
// rather than left as a passing test that asserted nothing.
func dmMkfifo(string) error { return errors.New("no named pipes on windows") }
