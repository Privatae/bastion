package main

// contextsock.go — how a person's own context surface reaches the daemon, on a
// machine where the daemon is not theirs.
//
// THE PROBLEM, stated plainly. The context surface (contextui.go) runs as the
// person, which is what makes it safe: the files it can draw are the ones the
// kernel already lets them open. But ASKING for a folder to become context has
// to reach the host, and the only thing on the box with a tunnel is the daemon.
// Its loopback endpoint is guarded by the OperatorSecret, which lives at 0600
// in the daemon's own config dir — and a non-root person cannot read it, which
// is correct, because that same secret opens the git-credential lane.
//
// So on a single-user machine the ask works (the daemon is that person's) and
// on a networked bastion it does not. That gap shipped, and the page said so in
// words, which is better than failing silently and still not good enough.
//
// THE FIX, AND WHY IT IS THIS ONE. The daemon needs to know WHO is asking, and
// it must not learn it from anything the asker says — a client that states its
// own username is a client that can state somebody else's. Every local IPC on
// every platform this binary targets can ask the KERNEL who is on the other end
// of a connection:
//
//	linux    SO_PEERCRED on a unix socket           -> uid, gid, pid
//	darwin   LOCAL_PEERCRED / getpeereid            -> uid, gid
//	windows  GetNamedPipeClientProcessId + the
//	         process token                          -> the caller's SID
//
// That is the same principle as the sanction mark being keyed on the kernel's
// executable path rather than argv[0] (sanction.go), and as the context
// surface's file walk being done BY the user rather than filtered FOR them:
// where an answer can come from the kernel, this code does not decide it.
//
// WHAT THE DAEMON DOES WITH THE IDENTITY. It forwards the draft with the
// asking user's name attached, and the draft still lands INERT — a person on
// the host approves it with a step-up code before a single file is read
// (addfolder.go:13-15). Nothing here grants anything. The identity is what
// makes "the username is the ceiling for their own context folder" enforceable
// rather than asserted: the daemon knows who asked because the kernel told it,
// so the ask cannot be made in somebody else's name.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// contextSockName is the socket the daemon listens on. It sits in the DAEMON's
// config dir, and its permissions are the first gate: 0666 on the socket itself
// so any local user can connect, because the identity check is the kernel's and
// not the filesystem's. The DIRECTORY above it is 0700, so this is deliberate
// and needs saying — see contextSockListen.
const contextSockName = "context.sock"

// contextAskRequest is what a person's surface sends. NOTE WHAT IS NOT IN IT:
// no username, no uid, no token. Anything the client could put here is
// something the client could lie about, so the daemon reads the identity off
// the connection instead and this carries only the request itself.
type contextAskRequest struct {
	Root string `json:"root"`
	Name string `json:"display_name"`
}

type contextAskReply struct {
	OK   bool   `json:"ok"`
	Host string `json:"host,omitempty"`
	Why  string `json:"why,omitempty"`
	// User is the name the DAEMON resolved from the kernel, echoed back so the
	// person can see whose ask it was recorded as. If this ever disagrees with
	// who they think they are, that is worth them noticing.
	User string `json:"user,omitempty"`
}

// contextSockPath is MACHINE-WIDE, not per-user, and that was the bug that made
// the first version of this dead code.
//
// It lived under configDir(), which is os.UserConfigDir()-derived — so the root
// daemon bound a path inside /root/.config and the person dialled one inside
// their own home. Two different sockets that could never meet, in exactly the
// case this endpoint exists for. The client fell back silently every time and
// the daemon logged an address nothing was listening on.
//
// /var/run is the right home and it is not only about agreement:
//
//   - It is ROOT-OWNED on every unix this ships to, so only root can create the
//     directory. A non-root process cannot squat this path and pose as the
//     daemon, which a world-writable /tmp would have allowed outright.
//   - It is a tmpfs, so a stale socket does not survive a reboot.
//
// The client additionally requires the socket to be OWNED BY ROOT before it
// will send anything (contextSockDialable). Belt to the directory's brace: if
// the path is ever reachable by another uid, an impostor still cannot be
// mistaken for the daemon.
func contextSockPath() (string, error) {
	return filepath.Join(contextSockDir, contextSockName), nil
}

// ── the daemon side ─────────────────────────────────────────────────────────

// startContextSock serves asks from local users until ctx ends.
//
// It is started by the daemon, so it runs with the daemon's rights — which is
// the point: it can read the OperatorSecret and reach the tunnel, and the
// person asking cannot.
func startContextSock(done <-chan struct{}) {
	p, err := contextSockPath()
	if err != nil {
		uilogf("context socket: %v\n", err)
		return
	}
	ln, err := contextSockListen(p)
	if err != nil {
		// Not fatal to the daemon. A box with no local users asking for context
		// is the ordinary case, and the rest of the bastion must not stop
		// because an IPC endpoint could not bind.
		uilogf("context socket not available (%v) — `privatae-bastion context` "+
			"will say so rather than failing quietly\n", err)
		return
	}
	go func() {
		<-done
		_ = ln.Close()
		_ = os.Remove(p)
	}()
	go contextSockAccept(ln)
	uilogf("context socket listening on %s\n", p)
}

// The socket is 0666 and the daemon runs as root (or SYSTEM), so every user on
// the machine can make it read. These bound what they can make it hold: an ask
// is a folder path and a display name, far under contextAskMaxBytes, and no
// more than contextSockMaxInFlight asks are read at once. Past that a
// connection is told the daemon is busy and closed; the asker tries again.
//
// One person may hold at most contextSockMaxPerUser of those slots, keyed on
// the identity the kernel gives (never on anything the asker says): without
// it, one user opening contextSockMaxInFlight idle connections and dialling
// again as each deadline ran out kept every other user's asks "busy" for as
// long as they liked. A person adds a folder at a time; four at once is far
// past that.
const (
	contextAskMaxBytes     = 64 << 10
	contextSockMaxInFlight = 32
)

// contextSockMaxPerUser is a var only so the test of the overall cap can lift
// it (every test connection is the same user).
var contextSockMaxPerUser = 4

var contextSockUsers = struct {
	sync.Mutex
	held map[string]int
}{held: map[string]int{}}

// contextSockTakeUser takes one of user's slots, or reports there is none.
func contextSockTakeUser(user string) bool {
	contextSockUsers.Lock()
	defer contextSockUsers.Unlock()
	if contextSockUsers.held[user] >= contextSockMaxPerUser {
		return false
	}
	contextSockUsers.held[user]++
	return true
}

func contextSockReleaseUser(user string) {
	contextSockUsers.Lock()
	defer contextSockUsers.Unlock()
	if contextSockUsers.held[user]--; contextSockUsers.held[user] <= 0 {
		delete(contextSockUsers.held, user)
	}
}

// contextSockAccept serves ln until it is closed, at most
// contextSockMaxInFlight connections at a time.
func contextSockAccept(ln net.Listener) {
	slots := make(chan struct{}, contextSockMaxInFlight)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				contextSockServe(c)
			}()
		default:
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				_ = json.NewEncoder(c).Encode(contextAskReply{Why: "the bastion is busy " +
					"answering other asks on this machine; try again in a moment"})
			}()
		}
	}
}

func contextSockServe(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	// THE IDENTITY, FROM THE KERNEL, BEFORE THE REQUEST IS EVEN READ. Order
	// matters: nothing the client sends should be able to influence how it is
	// identified, and the surest way to guarantee that is to have the answer
	// already in hand.
	user, err := contextPeerUser(c)
	if err != nil {
		_ = json.NewEncoder(c).Encode(contextAskReply{Why: "this machine could not " +
			"establish who is asking (" + err.Error() + "), so it will not forward the " +
			"request. An ask that cannot be attributed is one nobody can approve."})
		return
	}

	if !contextSockTakeUser(user) {
		_ = json.NewEncoder(c).Encode(contextAskReply{User: user, Why: "the bastion is busy " +
			"answering other asks of yours; try again in a moment"})
		return
	}
	defer contextSockReleaseUser(user)

	var req contextAskRequest
	if err := json.NewDecoder(io.LimitReader(c, contextAskMaxBytes)).Decode(&req); err != nil {
		_ = json.NewEncoder(c).Encode(contextAskReply{User: user, Why: "the request could not be read"})
		return
	}
	sent, host, note := contextForwardDraftAs(req.Root, req.Name, user)
	_ = json.NewEncoder(c).Encode(contextAskReply{OK: sent, Host: host, Why: note, User: user})
}

// ── the asking side ─────────────────────────────────────────────────────────

// contextAskViaSock hands one draft to the daemon and returns what it said.
func contextAskViaSock(root, name string) (sent bool, host, note string, available bool) {
	p, err := contextSockPath()
	if err != nil {
		return false, "", err.Error(), false
	}
	if why := contextSockDialable(p); why != "" {
		// A socket at the right path that is NOT root's is not the daemon.
		// Refusing loudly rather than falling back: the fallback path would
		// send this person's folder somewhere, and "somewhere" is the problem.
		return false, "", why, true
	}
	c, err := net.DialTimeout("unix", p, 5*time.Second)
	if err != nil {
		// The daemon may be older than this socket, not running, or running as
		// somebody whose config dir this process cannot even see. All three
		// mean the same thing to the caller: this route is not available, try
		// the direct one.
		return false, "", "", false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(c).Encode(contextAskRequest{Root: root, Name: name}); err != nil {
		return false, "", err.Error(), true
	}
	var rep contextAskReply
	if err := json.NewDecoder(c).Decode(&rep); err != nil {
		return false, "", "the bastion did not answer: " + err.Error(), true
	}
	if !rep.OK {
		return false, rep.Host, rep.Why, true
	}
	return true, rep.Host, "", true
}

// errContextSockUnsupported is the note used where the platform has no
// implementation yet, so the reason a person sees names the platform rather
// than pretending the feature is merely broken.
var errContextSockUnsupported = errors.New("peer identity over a local socket is not " +
	"implemented for this platform yet")

func contextSockFmtUser(uid uint32, name string) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("uid %d", uid)
}
