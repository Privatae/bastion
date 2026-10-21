package main

// The pairing token on standard input.
//
// A token passed as an argument sits in /proc/<pid>/cmdline for as long as
// `pair` runs, where any account on the machine can read it, and in the shell's
// history afterwards. The token is single-use and short-lived, but until it is
// redeemed it is a whole enrolment. So `pair` also takes it on standard input,
// asked for with `-` in place of the token. Only `-` reads standard input:
// `pair` with no token is the usage error it always was, whatever standard
// input is, because some terminals (Git Bash's mintty, `ssh host cmd` without
// -t) do not register as one, and reading there would leave a person who
// forgot the token waiting with nothing said.
//
// No error here repeats what was read. A refusal names what was wrong with the
// input, never its content, so a log of a failed install does not hold the
// token either.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// pairStdinArg in place of the token says it comes on standard input.
const pairStdinArg = "-"

// pairTokenMax bounds the first line read. A token is a few dozen bytes; this
// is only so a wrong file piped in is refused rather than read whole.
const pairTokenMax = 4096

// pairToken returns the token `pair` redeems. arg is the token parsePairArgs
// found, pairStdinArg, or "" for none. stdinConsole says whether standard
// input is a terminal; when it is and `-` was given, a prompt goes to prompt.
func pairToken(arg string, stdin io.Reader, stdinConsole bool, prompt io.Writer) (string, error) {
	switch {
	case arg == "":
		return "", errors.New(pairUsage)
	case arg != "" && arg != pairStdinArg:
		return arg, nil
	}
	if stdinConsole {
		fmt.Fprint(prompt, "Paste the pairing token and press Enter: ")
	}
	return readPairToken(stdin)
}

// readPairToken reads the token as the first line of r: one word, surrounding
// spaces and the line ending dropped.
func readPairToken(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, pairTokenMax+1)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("could not read the pairing token from standard input (%v); nothing was paired", err)
	}
	if len(line) > pairTokenMax {
		return "", fmt.Errorf("the first line of standard input is longer than %d bytes, far longer than a pairing token; nothing was paired", pairTokenMax)
	}
	words := strings.Fields(line)
	switch len(words) {
	case 0:
		return "", errors.New("standard input held no pairing token: give it as the first line, or as the argument; nothing was paired")
	case 1:
		return words[0], nil
	}
	return "", fmt.Errorf("the first line of standard input holds %d words, and a pairing token is one; nothing was paired", len(words))
}
