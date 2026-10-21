package main

// Endpoint rotation: host-directed, with a candidate list and a probe.
//
// The platform's registry (bastion_peers + the pod-Hub identity) says where this
// bastion should dial. The host answers the heartbeat with:
//
//	{"rotate_endpoint": {"endpoint": "host:port",            // the v4 port entry (always served)
//	                     "endpoints": ["[v6addr]:51820", "host:port"],  // preferred first
//	                     "endpoint_pubkey": "base64"}}          // the pod-Hub's key, never a relay's
//
// Trust: the directive rides the authenticated mTLS heartbeat RESPONSE from
// the bastion's OWN host — the same lane self-update (update.go) and
// containment (contain.go) already trust. This client only ever rotates to what
// its own host tells it, and only ever pins the pod-Hub's pubkey (relay CHOICE
// is a performance decision, not a trust decision — the relay holds no key).
//
// The relay uses an address-per-pairing model on its own IPv6 /64. An
// IPv4-only network cannot reach that entry at all, and a
// blind swap to an unreachable endpoint would strand the tunnel — the heartbeat
// that carries the correction rides the tunnel that just died. So a candidate is
// PROBED before it is committed: the peer is swapped, and the swap is kept only if
// a real WireGuard handshake completes within rotateProbeTimeout. That measures the
// path that will actually carry traffic and proves the relay forwards; a cheaper
// echo would prove neither. A candidate that fails is remembered and not retried
// for rotateRetryAfter, so the host repeating the directive every beat costs
// nothing. Failover works the same way with no platform round trip: if the live
// session's last handshake is older than WireGuard's own RejectAfterTime the path
// is dead by the protocol's rule, and the next candidate in the list is probed.
//
// The swap is IN-PROCESS (device.IpcSet with replace_peers), never a process
// exit: a desktop bastion often runs unsupervised (no systemd), so an
// exit-to-restart rotate would silently drop the tunnel until a human
// notices. Worker lanes (egress/mgmt/harness) ride WebSockets over the
// netstack; their keepalive/reconnect loops absorb the peer swap.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const (
	// rotateProbeTimeout: wireguard-go retransmits an unanswered initiation every
	// RekeyTimeout (5 s, device/constants.go). Two attempts plus the round trip is the
	// protocol's own "this path does not answer".
	rotateProbeTimeout = 12 * time.Second
	// A candidate that failed its probe is skipped for rotateRetryFirst, then for
	// rotateRetryAfter doubling on each further failure up to rotateRetryMax. The host
	// re-sends the directive on every 60 s beat while we are not on the preferred
	// entry, and every probe costs the tunnel up to rotateProbeTimeout — so for a
	// bastion on an IPv4-only network (which can never reach the v6 entry) the retry
	// has to become rare, not merely hourly.
	//
	// rotateRetryFirst exists because the FIRST failure is the one most likely to be
	// transient, and going straight to an hour made a single unlucky probe expensive.
	// Measured while pairing 20 machines at once: every v6 probe that failed
	// during the enrolment burst succeeded on its next attempt once the fleet was idle —
	// one host committed on its first probe after a plain service restart with nothing
	// else changed. Under the old schedule that bastion would have sat on its fallback
	// entry for up to SEVEN DAYS after a miss a two-minute retry would have cleared.
	// The ceiling drops from a week to a DAY, and the number is set by what a probe
	// costs rather than by taste: probing swaps the LIVE peer, so each attempt on a
	// candidate that cannot answer is up to 12 s with the tunnel pointed at nothing.
	// At a 6 h cap that is ~48 s a day, forever, for every bastion on an IPv4-only
	// network probing a v6 entry it will never reach — the steady-state cost the
	// original 7-day ceiling existed to avoid. 24 h keeps it at ~12 s a day while
	// still picking up a path that comes back within the day instead of the
	// following week.
	rotateRetryFirst = 2 * time.Minute
	rotateRetryAfter = time.Hour
	rotateRetryMax   = 24 * time.Hour
	// deadPathAfter: RejectAfterTime (180 s) is when WireGuard itself gives up on a
	// session — but only the INITIATOR rekeys proactively, so if the pod-Hub started
	// the current session an idle bastion can legitimately sit at 180 s until its next
	// keepalive (25 s) triggers a new initiation (RekeyTimeout 5 s). Margin on top of
	// that, or a live path is declared dead once an hour.
	deadPathAfter = 240 * time.Second
	// routeCheckTimeout bounds the dial in endpointRoutable. Every candidate is a
	// literal today — the host builds both entries from addresses, and wireguard-go's
	// UAPI parses an endpoint with netip.ParseAddrPort, which rejects a name outright
	// (conn/bind_std.go) — so the dial is a pure routing-table lookup, microseconds,
	// and this timeout never engages. It is here for the case where a name reaches
	// this path anyway: bounding it means one skipped beat rather than a stalled
	// heartbeat, and such a candidate could not be committed regardless, because
	// swapPeer would fail on the same parse. Measured on a v4-only box: ~50µs for a
	// literal, ~25ms for a name that does not resolve.
	routeCheckTimeout = 2 * time.Second
)

// errNoLocalPath marks a candidate this machine's own routing table cannot reach.
// It is deliberately distinct from a probe failure: a probe failure means "this
// path did not answer", which may be transient and earns the backoff in
// retryAfter; errNoLocalPath means "this machine has no way to even try", which is
// a property of the local network and costs nothing to re-test.
var errNoLocalPath = errors.New("no path to it from this machine")

// dialForRouteCheck is net.DialTimeout, indirected so a test can answer without a
// network. Nothing else in this package may replace it.
var dialForRouteCheck = net.DialTimeout

// The live-device steps of a probe (swap the peer, wait for its handshake, read the
// last one), indirected so a test can drive a probe through to a commit or a
// failover without a WireGuard peer. Nothing else in this package may replace them.
var (
	livePeerSwap      = swapPeer
	liveHandshake     = handshakeWithin
	liveLastHandshake = func(dev *device.Device) time.Time { return lastHandshake(dev) }
)

// endpointRoutable asks THIS MACHINE's kernel whether it can select a route and a
// source address for endpoint. Connecting a UDP socket sends no packet — it is a
// route lookup and a bind — so the answer is free, and it is the kernel's answer
// rather than an inference from the address's shape.
//
// It exists because probing is not free. probeAndCommit swaps the LIVE peer and
// waits up to rotateProbeTimeout for a handshake, so a candidate on an address
// family this machine does not have costs a real tunnel outage to rule out, and
// then costs it again on every retry. Measured on a real desktop:
// three pairings, three `no handshake within 12s` lines against the relay's
// per-pairing IPv6 entries, and no IPv6 path on that network at all — so each
// restart spent up to 36s with live tunnels pointed at addresses the kernel would
// have rejected instantly. The relay itself was healthy throughout (ten other
// bastions were committed on those same v6 entries at the time), which is exactly
// why the bastion cannot infer this from the candidate failing: the endpoint is
// fine, the local network is not.
//
// This is a PRE-FILTER, never a verdict. A route existing does not mean packets
// arrive, so a candidate that passes still gets the full handshake probe. Only the
// case where the kernel says it has nowhere to send is skipped, and it is skipped
// WITHOUT being marked failed, so a machine that gains IPv6 picks the preferred
// entry up on the next beat instead of waiting out a backoff.
func endpointRoutable(endpoint string) error {
	c, err := dialForRouteCheck("udp", endpoint, routeCheckTimeout)
	if err != nil {
		return fmt.Errorf("%w (%v)", errNoLocalPath, err)
	}
	return c.Close()
}

// probeFailure is the memory of one probe target that did not answer: when, and
// how many times in a row — the retry interval doubles with the count.
type probeFailure struct {
	at    time.Time
	count int
}

// probeTarget is what a probe actually tests: an entry AND the Hub key pinned for
// it. A host can move its machines to a new Hub key on the same entries, so one
// entry is probed under two keys, and the two answers are independent. Remembering
// failures per entry alone let a dead spell under the old key hold up the move to
// the new one for up to rotateRetryMax, and let a probe of a key the Hub did not
// answer yet keep the machine off its preferred entry under the key it runs.
func probeTarget(endpoint, pubkey string) string {
	return endpoint + " " + pubkey
}

// rotateState remembers probe failures per probe target (probeTarget). The entry is
// per pairing (each pairing has its own v6 address), so every pairing keeps its own
// memory.
type rotateState struct {
	mu     sync.Mutex
	failed map[string]probeFailure
	// noPath remembers which endpoints have already been reported as unreachable
	// from this machine, so a PERMANENT local condition (an IPv4-only network
	// against a v6 entry) is stated once rather than on every 60s beat. It is not
	// a backoff: the check itself still runs every beat, because it is free and
	// because a machine that gains IPv6 should move the same minute.
	noPath map[string]bool
	// mu also guards Config.savePending: whether a running copy's committed move
	// has not reached disk (setUnsaved). That state is the run's own, not the
	// host's: a run started again for the host loads the file and runs on what
	// it holds, so nothing the run before it left unsaved is pending for it.
}

var rotation = rotateState{failed: map[string]probeFailure{}}

// retryAfter is the skip interval for a candidate that has failed `count` times in a
// row: the first failure gets the short grace, every one after that starts at
// rotateRetryAfter and doubles, capped at rotateRetryMax.
func retryAfter(count int) time.Duration {
	if count <= 1 {
		return rotateRetryFirst
	}
	d := rotateRetryAfter
	for i := 2; i < count && d < rotateRetryMax; i++ {
		d *= 2
	}
	if d > rotateRetryMax {
		d = rotateRetryMax
	}
	return d
}

func (s *rotateState) failedRecently(target string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.failed[target]
	return ok && time.Since(f.at) < retryAfter(f.count)
}

func (s *rotateState) markFailed(target string) {
	s.mu.Lock()
	f := s.failed[target]
	s.failed[target] = probeFailure{at: time.Now(), count: f.count + 1}
	s.mu.Unlock()
}

func (s *rotateState) clear(target string) {
	s.mu.Lock()
	delete(s.failed, target)
	s.mu.Unlock()
}

// notePathless records that ep is unreachable from here and reports whether this
// is the FIRST time — which is the only time it is worth a log line. The map is
// created here rather than in a constructor because rotateState is also built
// literally (tests, and the package var below) with only `failed` set.
func (s *rotateState) notePathless(ep string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.noPath == nil {
		s.noPath = map[string]bool{}
	}
	if s.noPath[ep] {
		return false
	}
	s.noPath[ep] = true
	return true
}

// clearPathless forgets that ep was ever unreachable, so if the local network
// loses the path again it is reported again instead of staying silent.
func (s *rotateState) clearPathless(ep string) {
	s.mu.Lock()
	delete(s.noPath, ep)
	s.mu.Unlock()
}

// setUnsaved records whether the running copy cfg runs on a committed move its
// file does not hold yet. The heartbeat reports it (endpoint_save_pending).
func (s *rotateState) setUnsaved(cfg *Config, pending bool) {
	s.mu.Lock()
	cfg.savePending = pending
	s.mu.Unlock()
}

func (s *rotateState) isUnsaved(cfg *Config) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cfg.savePending
}

// persistEndpoints writes the entry and Hub key this pairing now runs on. A write
// that fails is retried on every beat (retryEndpointSave) until one lands: until
// then a restart reads the OLD entry and key from disk, and once the host retires
// that key the machine is stranded, because the heartbeat that would correct it
// rides the tunnel that no longer comes up. A pairing whose file is gone was
// unpaired, one whose file holds another WireGuard key was paired again, and a
// stopped run's copy writes nothing (errRunStopped): in each case there is
// nothing of this copy's to save and nothing to retry. The pending state is
// this copy's own, so none of this touches a run started again for the host.
func persistEndpoints(cfg *Config) error {
	err := cfg.saveEndpoints()
	rotation.setUnsaved(cfg, err != nil && !errors.Is(err, errPairingGone) &&
		!errors.Is(err, errPairingReplaced) && !errors.Is(err, errRunStopped))
	return err
}

// retryEndpointSave saves a committed move whose earlier save failed. Called on
// every beat; a no-op unless a save is pending.
func retryEndpointSave(cfg *Config) {
	if !rotation.isUnsaved(cfg) {
		return
	}
	if err := persistEndpoints(cfg); err == nil {
		fmt.Printf("rotate: endpoint %s and its Hub key saved on a later beat\n", cfg.Endpoint)
	}
}

// candidateList normalises a host-supplied candidate list: trimmed, de-duplicated,
// order kept, and the single "endpoint" appended if the list omits it (an older
// host sends no list at all — then the list is just that one entry).
func candidateList(endpoints []string, endpoint string) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range append(append([]string{}, endpoints...), endpoint) {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

// errPairingReplaced is saveEndpoints' answer when the file on disk is a newer
// pairing with the same host: `pair --replace`, or an unpair and a new pair,
// wrote it with its own WireGuard key, while this running copy still holds the
// one it replaced. The entry and Hub key this copy runs on were pinned for that
// old key, and the new pairing would come up on them at its next start.
var errPairingReplaced = errors.New("pairing file holds a newer pairing with this host — not writing the old one's entry and Hub key into it")

// saveEndpoints persists ONLY the endpoint fields of a running pairing. The
// heartbeat goroutine's Config was loaded at start; writing the whole struct
// would put its stale State back over a pending/revoked flip the mgmt lane or
// claim-anchor --rotate made since. It writes nothing into a file that holds a
// different WireGuard key (errPairingReplaced): only `pair` sets that key.
func (c *Config) saveEndpoints() error {
	return c.updateOnDiskIf(func(d *Config) error {
		if d.WGPrivateKey != c.WGPrivateKey {
			return errPairingReplaced
		}
		d.Endpoint, d.EndpointPubKey, d.Endpoints = c.Endpoint, c.EndpointPubKey, c.Endpoints
		return nil
	})
}

// parseRotateTarget extracts the rotate directive: the ordered candidates and the
// pod-Hub pubkey, or an empty list.
func parseRotateTarget(heartbeatResponse []byte) (candidates []string, pubkey string) {
	var hb struct {
		Rotate struct {
			Endpoint       string   `json:"endpoint"`
			Endpoints      []string `json:"endpoints"`
			EndpointPubKey string   `json:"endpoint_pubkey"`
		} `json:"rotate_endpoint"`
	}
	if json.Unmarshal(heartbeatResponse, &hb) != nil {
		return nil, ""
	}
	return candidateList(hb.Rotate.Endpoints, hb.Rotate.Endpoint), strings.TrimSpace(hb.Rotate.EndpointPubKey)
}

// maybeRotateEndpoint applies a pending endpoint rotation: walk the candidates in
// preference order down to the entry we are on, probe each one we have not recently
// proved dead, and commit the first that handshakes. No-op when we are already on the
// preferred entry. Failure leaves BOTH the device and the config on the old endpoint
// (consistent), logs, and the host will ask again on a later beat.
func maybeRotateEndpoint(heartbeatResponse []byte, cfg *Config, dev *device.Device) {
	candidates, pubkey := parseRotateTarget(heartbeatResponse)
	if len(candidates) == 0 || pubkey == "" {
		return
	}
	if candidates[0] == cfg.Endpoint && pubkey == cfg.EndpointPubKey {
		// Already on the preferred entry; keep the list current for failover.
		if !sameList(cfg.Endpoints, candidates) {
			cfg.Endpoints = candidates
			_ = persistEndpoints(cfg)
		}
		return
	}
	for _, cand := range candidates {
		if cand == cfg.Endpoint && pubkey == cfg.EndpointPubKey {
			// Every entry above the current one failed its probe (or was skipped as
			// recently failed): we are on the best reachable entry.
			if !sameList(cfg.Endpoints, candidates) {
				cfg.Endpoints = candidates
				_ = persistEndpoints(cfg)
			}
			return
		}
		if rotation.failedRecently(probeTarget(cand, pubkey)) {
			continue
		}
		if err := probeAndCommit(cfg, dev, cand, pubkey, candidates); err != nil {
			// A candidate this machine cannot route to is a standing fact about the
			// local network, not an event: say it once and stay quiet, or an
			// IPv4-only box prints the same line every minute forever.
			if errors.Is(err, errNoLocalPath) {
				if rotation.notePathless(cand) {
					fmt.Printf("rotate: candidate %s: %v — skipping it until that changes (staying on %s)\n", cand, err, cfg.Endpoint)
				}
				continue
			}
			fmt.Printf("rotate: candidate %s: %v (staying on %s)\n", cand, err, cfg.Endpoint)
			continue
		}
		return
	}
}

// maybeFailover is the platform-free half: called on every beat, it moves to the next
// reachable candidate when the live session's path is dead by WireGuard's own rule.
// It never runs while the tunnel has a handshake younger than deadPathAfter.
//
// It is also where a committed move whose save failed is saved: this runs on every
// beat whether or not the host answers, and a save needs only the disk.
func maybeFailover(cfg *Config, dev *device.Device, startedAt time.Time) {
	retryEndpointSave(cfg)
	if len(cfg.Endpoints) < 2 {
		return
	}
	lh := liveLastHandshake(dev)
	if lh.IsZero() {
		// Never handshaked since this process started: give the boot endpoint the
		// same grace before declaring it dead.
		if time.Since(startedAt) < deadPathAfter {
			return
		}
	} else if time.Since(lh) < deadPathAfter {
		return
	}
	fmt.Printf("rotate: no handshake on %s for %s — path dead, trying the other candidates\n",
		cfg.Endpoint, deadPathAfter)
	dead := cfg.Endpoint
	rotation.markFailed(probeTarget(dead, cfg.EndpointPubKey))
	for _, cand := range cfg.Endpoints {
		if cand == dead {
			continue
		}
		// A recent probe failure does not exempt a candidate here: the alternative is
		// a tunnel that stays dead.
		if err := probeAndCommit(cfg, dev, cand, cfg.EndpointPubKey, cfg.Endpoints); err != nil {
			fmt.Printf("rotate: failover candidate %s: %v\n", cand, err)
			continue
		}
		return
	}
	// Nothing answered; restore the original so a path that comes back is used.
	_ = livePeerSwap(cfg, dev, dead, cfg.EndpointPubKey)
}

// probeAndCommit swaps the live peer to endpoint, waits for a handshake to prove the
// path, and either persists the move or swaps back.
func probeAndCommit(cfg *Config, dev *device.Device, endpoint, pubkey string, list []string) error {
	// BEFORE the live peer moves: does this machine have anywhere to send? The
	// check is here rather than in the two callers so neither can forget it, and
	// so the live tunnel is never spent proving something the routing table
	// already knows. A candidate refused here is NOT marked failed (see
	// errNoLocalPath).
	if err := endpointRoutable(endpoint); err != nil {
		return err
	}
	rotation.clearPathless(endpoint)
	t0 := time.Now()
	target := probeTarget(endpoint, pubkey)
	if err := livePeerSwap(cfg, dev, endpoint, pubkey); err != nil {
		rotation.markFailed(target)
		return fmt.Errorf("live peer swap failed: %w", err)
	}
	if !liveHandshake(dev, t0, rotateProbeTimeout) {
		rotation.markFailed(target)
		if err := livePeerSwap(cfg, dev, cfg.Endpoint, cfg.EndpointPubKey); err != nil {
			return fmt.Errorf("no handshake within %s AND swap back failed: %w", rotateProbeTimeout, err)
		}
		return fmt.Errorf("no handshake within %s", rotateProbeTimeout)
	}
	old := cfg.Endpoint
	cfg.Endpoint = endpoint
	cfg.EndpointPubKey = pubkey
	cfg.Endpoints = list
	rotation.clear(target)
	if err := persistEndpoints(cfg); err != nil {
		again := ""
		if rotation.isUnsaved(cfg) {
			again = " (retried every beat)"
		}
		fmt.Printf("rotate: swapped live to %s but config save failed: %v%s\n", endpoint, err, again)
		return nil
	}
	fmt.Printf("rotate: endpoint %s -> %s applied (handshake-confirmed, config saved)\n", old, endpoint)
	return nil
}

// swapPeer replaces the device's single peer in one UAPI transaction — same shape as
// the boot-time config in run.go. AllowedIPs stays the host's tunnel alias ONLY.
func swapPeer(cfg *Config, dev *device.Device, endpoint, pubkey string) error {
	privHex, err := b64ToHex(cfg.WGPrivateKey)
	if err != nil {
		return fmt.Errorf("bad private key in config: %w", err)
	}
	pubHex, err := b64ToHex(pubkey)
	if err != nil {
		return fmt.Errorf("bad endpoint pubkey: %w", err)
	}
	hostCIDR, err := hostTunnelAllowedIP(cfg.HostTunnelIP)
	if err != nil {
		return err
	}
	uapi := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=%s\n",
		privHex, pubHex, endpoint, hostCIDR)
	return dev.IpcSet(uapi)
}

// handshakeWithin polls the device until the peer reports a handshake newer than t0.
func handshakeWithin(dev *device.Device, t0 time.Time, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if lh := lastHandshake(dev); !lh.IsZero() && !lh.Before(t0.Truncate(time.Second)) {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// lastHandshake reads the (single) peer's last_handshake_time_sec from the UAPI dump;
// zero when there is no peer or it never handshaked.
func lastHandshake(dev interface{ IpcGet() (string, error) }) time.Time {
	dump, err := dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(dump, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil || secs == 0 {
				return time.Time{}
			}
			return time.Unix(secs, 0)
		}
	}
	return time.Time{}
}

func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
