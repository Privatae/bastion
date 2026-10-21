package main

// contextui.go — `privatae-bastion context`: YOUR files, on your machine, in a
// process that runs as YOU.
//
// WHY THIS IS A SECOND PROCESS AND NOT A PAGE ON THE DAEMON'S UI. The daemon's
// local UI is the machine-admin console: the pairing list, the anchor, the
// containment banner, the marks on automated programs, the dry-run policy. On a
// networked bastion that daemon runs as root (deploy/install.sh writes the unit
// with no User=), so its UI is root's, and that is correct — those are all
// machine-wide facts and machine-wide acts.
//
// But a person who is not the machine's admin still has to be able to look at
// their own files and hand a folder to a bastion agent. Serving that from the
// root daemon would mean root's process deciding, in our code, which files each
// caller may see — a permission model we would have to write, get right, and
// keep right, with a forged answer costing somebody their private files.
//
// So this process runs as the person instead. The walk it does is an ordinary
// walk by an ordinary user, so the only files it can possibly draw are the ones
// that user could already open in any file manager. THE KERNEL DRAWS THE
// BOUNDARY AND THIS CODE NEVER DECIDES IT — the same reason the sanction mark
// in sanction.go is keyed on the kernel's executable path rather than on
// anything a process says about itself.
//
// Two consequences worth stating out loud, because both are deliberate:
//
//   - There is NO whole-machine map here. The scope does not exist in this
//     surface, not because the button is hidden but because this process could
//     not read other people's files if it tried.
//   - The session lives in MEMORY and there is no secret file. The daemon needs
//     one because its UI is opened by a different process (the `ui` verb, the
//     tray); this verb serves and opens the browser itself, so a secret on disk
//     would be a thing to leak in exchange for nothing.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The context surface takes the sixteen ports BELOW the daemon's UI range, which
// itself sits below the per-pairing range counting up from 7878 (ui.go:58-65).
// So the three ranges can never collide however many hosts this machine serves,
// and several people signed into the same machine at once each get their own.
const (
	contextUIPortHigh = 7861
	contextUIPortLow  = 7846
)

// cmdContextUI runs the context surface until interrupted.
func cmdContextUI() error {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return fmt.Errorf("this account has no home directory, so there are no files of " +
			"your own to show. If you are trying to look at the whole machine, that is the " +
			"machine's own console: run `privatae-bastion ui` as its administrator")
	}
	home = filepath.Clean(home)

	var ln net.Listener
	var port string
	for p := contextUIPortHigh; p >= contextUIPortLow; p-- {
		// LOOPBACK ONLY, DELIBERATELY, and the same bind the daemon's UI uses
		// (ui.go:673). This page draws a person's own file names, which is the
		// most detailed thing about them in this binary; a wider bind would
		// publish it to their LAN. Nothing off-box is meant to reach it, and
		// nothing off-box can: the bastion dials OUT to its host and never the
		// other way.
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln, port = l, fmt.Sprint(p)
			break
		}
	}
	if ln == nil {
		return fmt.Errorf("no free port between %d and %d — something else is already "+
			"using all sixteen", contextUIPortLow, contextUIPortHigh)
	}

	// A secret nobody else ever sees: it is minted here, used here, and dies
	// with the process. It exists at all only because mintTicket compares
	// against one, and one code path for both surfaces is worth more than a
	// special case in the auth.
	secret, err := genSecret(32)
	if err != nil {
		_ = ln.Close()
		return err
	}
	srv, err := newUIServer(port, secret)
	if err != nil {
		_ = ln.Close()
		return err
	}
	srv.contextUI = true
	srv.contextHome = home
	srv.contextLoadAsks()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	h := &http.Server{Handler: srv.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.Shutdown(sh)
	}()

	// The ticket is minted directly rather than over loopback, because unlike
	// the `ui` verb there is no other process to ask: this one IS the server.
	tok, err := srv.tickets.mint()
	if err != nil {
		_ = ln.Close()
		return err
	}
	addr := ln.Addr().String()
	entry := "http://" + addr + "/?k=" + tok
	fmt.Printf("your context: http://%s\n", addr)
	fmt.Printf("showing %s — what this can see is exactly what you can open.\n", home)
	if err := openBrowser(entry); err != nil {
		fmt.Printf("\ncould not open a browser (%v).\nPaste this into one, within a minute:\n\n  %s\n\n",
			err, entry)
	}
	fmt.Println("leave this running while you use the page; ctrl-c closes it.")

	if err := h.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
