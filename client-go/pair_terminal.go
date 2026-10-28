package main

// pair_terminal.go: the one question `pair` asks a person, on a local machine
// that already serves a Host: whether to add another.
//
// A local bastion used to serve one Host, full stop, because on a single-user
// machine a second Host appearing meant someone else had got a token onto the
// box. A person who uses two Hosts (a Cloud machine beside the platform one)
// could not pair the second at all. Now the second is added when the person at
// this machine says so, and only then: the answer is read from the controlling
// terminal, never from standard input, so a token piped in by a script or an
// installer (which feeds the pairing code through standard input) cannot add a
// Host by itself. With no terminal there is nobody to ask, and the pair is
// refused.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// errNoTerminal: this process has no controlling terminal to ask on.
var errNoTerminal = errors.New("no terminal")

// openTerminal opens the controlling terminal for one question: a reader for
// the answer, a writer for the question, and a close. A variable so a test can
// stand in a person; nothing else assigns it.
var openTerminal = openControllingTerminal

// terminalSafeName is a Host name as the question shows it. newHost is the
// handle the token carries, which nothing has checked yet: whoever made the
// token chose it, and a control character or an escape sequence in it could
// rewrite the question on the person's screen. A plain host name is shown as
// it is; anything else is quoted, every such byte escaped.
func terminalSafeName(name string) string {
	if validHostName(name) {
		return name
	}
	return strconv.QuoteToASCII(name)
}

// confirmAddHost asks whether to add newHost beside serving, the Host this
// local machine already serves. True only for a typed y or yes.
func confirmAddHost(serving, newHost string) (bool, error) {
	in, out, closeTerm, err := openTerminal()
	if err != nil {
		return false, fmt.Errorf("this computer already serves your Host %s, and adding another needs a yes typed "+
			"at this computer, but this run has no terminal to ask in. Run the same command in a terminal "+
			"window on this computer; nothing was paired", serving)
	}
	defer closeTerm()
	fmt.Fprintf(out, "This computer already serves your Host %s. Add %s as well? It gets a pairing of its own,\n"+
		"and `privatae-bastion ui` shows what each Host may do here. [y/N] ", terminalSafeName(serving), terminalSafeName(newHost))
	line, err := bufio.NewReader(io.LimitReader(in, 256)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("could not read the answer (%v); nothing was paired", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}
