package main

// contextpull.go — ctx_extract fetches the SOURCE instead of being handed it.
//
// WHY THIS EXISTS. contextextract.go's own header wrote down the wall and the
// reason it could not be climbed yet: a management job is ONE WebSocket frame
// with its payload base64 in args, the host's 16 MiB WebSocket frame ceiling is reached at
// just under 12 MiB of plaintext (measured, ctxcap_measure_test.go), and so
// ctxExtractMaxBytes caps a source at 8 MiB. Fine for the text PDFs that
// shipped; not fine for OCR, where a scanned PDF routinely exceeds it. The
// blocker named there was auth: the host route that serves a context row's
// bytes requires an APPLICATION token, which this box
// does not have. VERIFIED, and still true: the host still carries that
// dependency, and its one internal-auth bypass is allow-listed to a single
// unrelated route, so it is not reachable from here either.
//
// So the host grew a route this box CAN authenticate to, with the credential it
// already holds: GET /api/network/bastions/context-source, bearer-authed
// exactly like /bastions/heartbeat and /bastions/git-credential.
//
// ── WHAT STOPS THIS BOX READING THE USER'S OTHER FILES ──────────────────────
//
// The request carries no context id. It carries a TICKET: 256 opaque bits the
// host minted when it decided to extract one specific row on this specific
// machine, bound to this bastion's token id, single-use, and good for two
// minutes. There is no id field to change, so "fetch a different document" is
// not a request that can be expressed — it does not have to be refused. A
// second GET with the same ticket gets 404 because the host popped it; a ticket
// minted for another machine gets 404 without being consumed, so one box cannot
// even burn another's.
//
// ── WHY THERE IS NO URL ON THE WIRE, unlike backup_fetch ────────────────────
//
// backup_fetch takes a URL from the host and therefore needs an SSRF wall
// (validateBackupURL): the host picks the address and this process sits INSIDE
// the user's network. Here the host picks nothing. This box builds the URL
// itself from its OWN configured host name and dials it through the SAME mTLS
// client that carries the heartbeat — pinned by run.go's transport to the
// host's tunnel address, with the TLS ServerName pinned to the host name. A
// hostile host cannot point this at the user's router, because it never gets to
// name a destination at all. That is strictly stronger than the check
// backup_fetch has to make, and it is the reason this file has no allow/deny
// list of addresses in it.
//
// backup_fetch's other refusals ARE carried over, because they were written for
// this shape of op: a declared maximum so a hostile or buggy host cannot fill
// the user's disk, verification BEFORE the bytes are used, and streaming at
// constant memory rather than buffering the document whole.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ctxPullMaxBytes is THIS BOX'S wall on one pulled source, independent of
// whatever the host declares. The host proposes a max_bytes; the smaller of the
// two wins, so a host that asks for more gets this.
//
// 64 MiB, and the reasoning is the same on both sides of the wire (the host
// holds the same ceiling):
//
//   - it cannot bind on anything the platform stores today — the host's upload
//     cap is 25 MiB — so what a
//     user may upload stays a product decision and this stays a guard;
//   - it clears the case the pull path was built for: a scanned PDF at 150-300
//     dpi runs tens of MB, which is 8x past the inline cap and well inside this;
//   - production document-extraction services bracket it. AWS Textract takes
//     10 MB synchronously and 500 MB asynchronously; Google Document AI takes
//     20 MB online and 1 GB in batch; Azure AI Document Intelligence takes
//     500 MB on its paid tier. Every one of them draws a low line for "one
//     request, answer now" and a high line for "queued job". This lane is the
//     first kind, so it sits at the low end of that range with enough room for
//     the scanned-PDF case the 10-20 MB lines would refuse.
//
// It is a ceiling on the PLATFORM's reach into this machine's disk and network,
// never a throttle on the user: nothing a user does here goes through it.
const ctxPullMaxBytes = 64 << 20

// ── the deadline, which the HOST grants ─────────────────────────────────────
//
// THE ORDERING IS THE POINT: this box must give up before the host does. If the
// host quits first it reports "did not answer" about a machine that is
// downloading happily, then discards the text when it finally arrives — the
// work done, the bytes moved, nothing written, and the user told their machine
// is unresponsive by the component that quit first.
//
// This was a flat 4 minutes, with a comment here claiming the host waited
// longer. MEASURED against the host's formula, that was false at every size the
// ceiling permits: a 64 MiB document got 124s from the host against 240s here,
// and it would have taken a 180 MiB source — well past the 64 MiB wall — for the
// sentence to come true. Two constants in two repos, with a comment on each side
// asserting a relationship between them, is exactly the thing that rots.
//
// So the number is not ours any more. The host sends `pull_budget` in the job
// and this box uses it, clamping DOWN and never up. The host's own wait is that
// same number plus a fixed allowance (40 s on the host, covering
// ctxExtractTimeout plus the frame round trip and the reply), so the
// ordering holds by construction at every
// size rather than by agreement between two files.

// ctxPullMaxTimeout clamps whatever the host grants. It MIRRORS the host's
// own budget cap: equal, so a host running the matching
// formula is never silently shortened, while a host asking for an hour gets
// this. TestPullHonoursTheHostsGrant pins both halves.
const ctxPullMaxTimeout = 240 * time.Second

// ctxPullDefaultTimeout is what a job granting nothing gets — a host predating
// `pull_budget`, or one that sent 0. It matches the host's own floor,
// so even then this box is the one that gives up first.
const ctxPullDefaultTimeout = 30 * time.Second

// Read buffer. Nothing to do with the document size.
const ctxPullChunk = 1 << 20

// ctxSourcePuller performs one authenticated GET for a ticket. A function
// rather than an *http.Client so the test can stand up a real host without
// reconstructing the tunnel, and so this file never has to know what a bearer
// is.
type ctxSourcePuller func(ctx context.Context, ticket string) (*http.Response, error)

var (
	ctxPullMu sync.RWMutex
	ctxPullFn ctxSourcePuller
)

// setCtxSourcePuller is called ONCE at daemon start (run.go), with the same
// mTLS client that carries the heartbeat. Until then the pull path is
// UNCONFIGURED, which is a setup state and is reported as one — never as a
// failure of the document or of the machine.
func setCtxSourcePuller(p ctxSourcePuller) {
	ctxPullMu.Lock()
	ctxPullFn = p
	ctxPullMu.Unlock()
}

func ctxSourcePullerFn() ctxSourcePuller {
	ctxPullMu.RLock()
	defer ctxPullMu.RUnlock()
	return ctxPullFn
}

// ctxPullConfigured says whether this box can fetch a source at all. It is what
// the heartbeat advertises (contextprep.go), so a host never hands a ticket to
// a build that could not redeem it.
func ctxPullConfigured() bool { return ctxSourcePullerFn() != nil }

// newHostSourcePuller binds the fetch to THIS bastion's host.
//
// The URL is built here, from the configured host name, and never comes off the
// wire — see the header. `c` must be the tunnel-pinned client from run.go: its
// DialContext ignores the address in the URL and dials the host's tunnel
// endpoint, and its TLS config pins ServerName to the host name. Both together
// are why there is no address check in this file.
func newHostSourcePuller(c *http.Client, hostName, bearer string) ctxSourcePuller {
	return func(ctx context.Context, ticket string) (*http.Response, error) {
		u := fmt.Sprintf("https://%s:8443/api/network/bastions/context-source?ticket=%s",
			hostName, url.QueryEscape(ticket))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		return c.Do(req)
	}
}

// validCtxTicket is the shape check. The host mints 32 random bytes as hex, so
// anything else is a bug or a probe and is refused before a request is made.
func validCtxTicket(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// ctxPullBudget turns the host's granted seconds into this box's deadline.
// Clamps DOWN to ctxPullMaxTimeout and never up; 0 or negative means the host
// granted nothing, which is an older host and gets the floor.
func ctxPullBudget(granted float64) time.Duration {
	if granted <= 0 {
		return ctxPullDefaultTimeout
	}
	d := time.Duration(granted * float64(time.Second))
	if d > ctxPullMaxTimeout {
		return ctxPullMaxTimeout
	}
	return d
}

// pullSourceInto streams the ticket's document into w, stopping at max or when
// the host's granted budget runs out.
//
// Returns the byte count. Constant memory by construction — the document is
// never held whole, which is the difference between this and the inline path
// and the reason the ceiling can be 8x higher.
func pullSourceInto(w io.Writer, ticket string, max int64, budget time.Duration) (int64, error) {
	pull := ctxSourcePullerFn()
	if pull == nil {
		return 0, fmt.Errorf("this bastion has no host connection for fetching a " +
			"document yet — that is a setup state, not a failure; the lane comes up " +
			"with the daemon's tunnel")
	}
	if !validCtxTicket(ticket) {
		return 0, fmt.Errorf("fetch ticket is not the shape this host mints")
	}
	if max <= 0 || max > ctxPullMaxBytes {
		max = ctxPullMaxBytes
	}
	if budget <= 0 || budget > ctxPullMaxTimeout {
		budget = ctxPullMaxTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	resp, err := pull(ctx, ticket)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return 0, slowTransfer(0, budget)
		}
		return 0, fmt.Errorf("could not reach this host to fetch the document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The status IS the diagnosis and each one means something different:
		// 404 = the ticket was already used, expired, or was never ours; 401 =
		// this box's bearer is no longer good; 503 = the machine holding those
		// bytes is offline, which is not this machine's problem to solve.
		return 0, fmt.Errorf("this host answered HTTP %d for the document", resp.StatusCode)
	}
	buf := make([]byte, ctxPullChunk)
	var total int64
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > max {
				return total, fmt.Errorf(
					"the document is larger than the %d bytes this extraction was "+
						"authorized for — stopped, nothing was extracted", max)
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return total, slowTransfer(total, budget)
			}
			return total, rerr
		}
	}
}

// slowTransfer is the honest version of a deadline. A SLOW LINK IS NOT A BROKEN
// MACHINE, and the whole reason the budget now comes from the host is so this
// sentence — rather than the host's "your machine did not answer" — is what the
// user reads. It names how far it got, so "the link is slow" and "the transfer
// never started" are told apart.
func slowTransfer(got int64, budget time.Duration) error {
	return fmt.Errorf(
		"the document was still downloading after the %s this host allowed "+
			"(%d bytes in) — the transfer is slower than this lane waits, which is "+
			"a link speed and not a fault in this machine", budget, got)
}
