package main

// consolelane.go — the machine owner's own account opens the console of the
// bastion installed for the whole machine, without sudo (Linux and macOS).
//
// THE PROBLEM. Installed for the whole machine, the bastion runs as root and
// its console signs in with root's ui.secret. `privatae-bastion ui` run by the
// person reads their own account's state, and the console refuses that
// account's key, so the person reached their own machine's console only
// through sudo, and a browser started by sudo is root's, not theirs.
//
// THE LANE. ask.sock (agentask.go) already tells the daemon, from the kernel,
// which account connected. Asked for "console" by the account recorded as the
// machine's owner (owner_account.go), the daemon mints a one-use ticket of a
// LIMITED kind and answers with the link; `ui` opens it in the person's own
// browser. Any other account is refused, and no request text is trusted.
//
// WHAT A LIMITED SESSION MAY DO. Everything a person can see, everything that
// only narrows reach (deny, switch off, disconnect, unmark), and everything
// that takes the owner's code, which an agent running as the person cannot
// read on this install. It is refused what widens access with no code today:
// pairing a Host, setting up or rotating the owner's code, choosing the Host
// in charge, proposing a folder, and the approval device's approvals. Those
// stay with the administrator (`sudo -H privatae-bastion ui`). Codes typed for
// a Host's requests in a limited session are throttled as the owner's are
// (machineCodeSpend), because guessing is the only attack left there.

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
)

// consoleLaneTicketsMax is how many lane links may wait unopened at once.
const consoleLaneTicketsMax = 16

// consoleLaneServer is the running console, for ask.sock to mint a ticket
// on. nil until the console listens, and again after it stops.
var consoleLaneServer atomic.Pointer[uiServer]

// consoleLaneRefusal says why account uid may not open the console through
// the lane, or "" when it may.
func consoleLaneRefusal(uid uint32, who string) string {
	owner, ownerName, present, err := ownerAccountLoad()
	switch {
	case err != nil:
		return "this machine's owner account cannot be read (" + err.Error() + "); the administrator opens " +
			"the console with: sudo -H privatae-bastion ui"
	case !present:
		return "no account is recorded as this machine's owner, so the console opens only for the administrator: " +
			"sudo -H privatae-bastion ui. To open it from your own account, the administrator records it once: " +
			"sudo -H privatae-bastion approvals-owner --account " + accountForHint(who)
	case owner != uid:
		name := ownerName
		if name == "" {
			name = "uid " + strconv.FormatUint(uint64(owner), 10)
		}
		return "this machine's console opens without sudo only for its owner's account (" + name + "), not " + who
	}
	return ""
}

func accountForHint(who string) string {
	if who == "" || len(who) > 64 {
		return "<your account>"
	}
	return who
}

// consoleLaneEntry is what the daemon answers an owner's "console" ask with:
// the link that redeems a fresh limited ticket.
func consoleLaneEntry(uid uint32, who string) (string, error) {
	if why := consoleLaneRefusal(uid, who); why != "" {
		return "", errors.New(why)
	}
	u := consoleLaneServer.Load()
	if u == nil || u.addr == "" {
		return "", errors.New("the bastion's console is not listening (no free port, or it is still starting)")
	}
	// A cap, so asking over and over cannot grow root's memory: a link lasts a
	// minute, and a person opens one at a time.
	tok, ok, err := u.limitedTickets.mintCapped(consoleLaneTicketsMax)
	if err != nil {
		return "", errors.New("could not mint a ticket")
	}
	if !ok {
		return "", errors.New("too many console links are waiting to be opened; open one, or wait a minute")
	}
	return "http://" + u.addr + "/?k=" + tok, nil
}

// limitedSession reports whether the request's session came through the lane.
func (u *uiServer) limitedSession(r *http.Request) bool {
	return u.limitedSessions != nil && u.limitedSessions.valid(uiSessionFrom(r))
}

// signedIn reports whether the request carries either kind of session.
func (u *uiServer) signedIn(r *http.Request) bool {
	tok := uiSessionFrom(r)
	return u.sessions.valid(tok) || (u.limitedSessions != nil && u.limitedSessions.valid(tok))
}

const consoleLaneAdminOnly = "From your own account the console does not do this: it widens what reaches this machine " +
	"with no code, or reads beyond your own account. The machine's administrator does it: sudo -H privatae-bastion ui"

// adminOnly wraps a route a limited session may not use.
func (u *uiServer) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	return u.guarded(func(w http.ResponseWriter, r *http.Request) {
		if u.limitedSession(r) {
			http.Error(w, consoleLaneAdminOnly, http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

// consoleEntryForThisAccount is the link `ui` opens. An account with a
// bastion of its own signs in with its own key (localUIEntryURL). An ordinary
// account beside the machine's root bastion asks the lane, and is told why
// not when it is not the owner's.
func consoleEntryForThisAccount() (entry, addr string, err error) {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 && !uiDaemonListening() {
		p := askSockPath()
		if why := contextSockDialable(p); why != "" {
			return "", "", errors.New(why)
		}
		if _, statErr := os.Stat(p); statErr == nil {
			r, err := askViaSock(agentAskRequest{Op: "console"})
			if err != nil {
				return "", "", errors.New("could not reach this machine's bastion at " + p + ": " + err.Error())
			}
			if !r.OK {
				return "", "", errors.New(r.Why)
			}
			u, err := url.Parse(r.URL)
			if err != nil || u.Scheme != "http" || !uiLoopbackHost(u.Host, u.Port()) {
				return "", "", errors.New("this machine's bastion answered with a link that is not its own console")
			}
			return r.URL, u.Host, nil
		}
	}
	return localUIEntryURL()
}

// uiLimitedWriter marks a response as drawn for a limited session, so a page
// shows the administrator's command in place of a form the session would be
// refused (Settings, Approvals). It changes what is drawn, never what is
// allowed: adminOnly decides that, from the session itself.
type uiLimitedWriter struct{ http.ResponseWriter }

func limitedWriter(w http.ResponseWriter) bool {
	_, ok := w.(uiLimitedWriter)
	return ok
}
