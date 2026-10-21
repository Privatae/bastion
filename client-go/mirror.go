package main

// Memory mirror — the bastion half.
//
// The rule: the user's host keeps a STREAMING REPLICA of its database on
// hardware the user owns, because a local copy is their continuity. This file
// is everything that happens on the user's machine to make that true.
//
// THE SHAPE, and why it is this shape:
//
//	replica container ──> forwarder (this process) ──WSS──> host :8443
//	  (postgres, standby)   <mirror-net gw>:5433       /bastion-pgwire
//
//   * The replica is PostgreSQL's own standby, running the SAME image the pod
//     runs — one artifact, both ends.
//   * It cannot reach the host itself: the tunnel is USERSPACE WireGuard on a
//     gVisor netstack inside this process, so no other process on this box has
//     a route, let alone a container. The forwarder is the bridge.
//   * The host end is a WebSocket because the pod's Hub splices the tunnel to
//     :8443 and nothing else.
//
// WHAT IS ON THE USER'S DISK. Ordinary PostgreSQL data files, unencrypted, at
// rest under their config dir. That is the point — it is their copy, openable
// with their own tools — but it must never be described as encrypted. Anyone
// with read access to that directory can read the memory in it. Full-disk
// encryption on their machine is the protection, and it is theirs to have.
//
// WHAT THE HOST CONTROLS AND WHAT THIS BOX CONTROLS. The host decides IF there
// is a mirror, WHICH database build it must run, and WHEN the copy is void (the
// reseed generation). It says so in the heartbeat response, the same
// authenticated channel that already carries self-update and containment. This
// box decides nothing about the data; PostgreSQL does the rest. No path here
// writes to the host.
//
// NO PORT PUBLISHING, deliberately, and the same rule harness.go follows: `-p`
// installs per-container DNAT that mutates this machine's iptables and has
// dropped this bastion's own relay tunnel before.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Advertised only when this box could actually hold a mirror (a container
	// runtime is installed). The host gates its enable path on it, so a box
	// without Docker or Podman is never offered a control that would fail after
	// the user had already spent a two-factor code on it.
	mirrorCapability = "mirror"

	// Where the artifact comes from. The registry is NOT an option: it requires
	// authentication and no registry credential goes onto user hardware. So the
	// image ships the way the bastion binary does — a checksummed artifact,
	// fetched and verified before it is trusted. Hardcoded for the same reason
	// install.sh hardcodes its base: anything that could redirect this could
	// redirect the manifest it is checked against.
	mirrorBase = "https://dl.privatae.ai/bastion/mirror"

	mirrorContainerPrefix = "privatae-mirror-"
	mirrorNetPrefix       = "privatae-mirror-net-"
	mirrorForwardPort     = 5433
	mirrorPollInterval    = 60 * time.Second
	mirrorFetchTimeout    = 30 * time.Minute // a cold image over a home line

	// Backoff ceiling after a failure that re-downloading will not fix. Without
	// this the manager re-fetched a ~600MB tarball every poll, forever, on
	// someone's home connection.
	mirrorBackoffMax = 60 * time.Minute
)

// ── directive (what the host told us) ───────────────────────────────────────

type mirrorImage struct {
	Known   bool   `json:"known"`
	Image   string `json:"image"`
	Tag     string `json:"tag"`
	Digest  string `json:"digest"`
	BuiltAt string `json:"built_at"`
}

type mirrorDirective struct {
	Enabled bool        `json:"enabled"`
	Reason  string      `json:"reason"`
	Slot    string      `json:"slot"`
	DBImage mirrorImage `json:"db_image"`
	// Bumped by the host when it recuts a slot the primary shed. A change means
	// the copy here can never catch up and must be taken again from scratch.
	ReseedGeneration int `json:"reseed_generation"`
}

// ── report (what we tell the host) ──────────────────────────────────────────

// mirrorReport carries ONLY what the primary cannot observe for itself: no
// runtime, image not downloaded, container dead, version mismatch, and the
// replayed LSN of a replica that is currently disconnected. Lag while connected
// comes from pg_stat_replication on the primary — the one source a compromised
// box cannot make comforting.
type mirrorReport struct {
	Runtime   string `json:"runtime,omitempty"`
	State     string `json:"state"` // absent|fetching|seeding|running|failed|mismatch
	Container string `json:"container,omitempty"`
	ImageTag  string `json:"image_tag,omitempty"` // the tag actually RUNNING
	OpenWith  string `json:"open_with,omitempty"` // how the user opens their copy
	Error     string `json:"error,omitempty"`
	ReplayLSN string `json:"replay_lsn,omitempty"`
}

// Per-pairing, never global: one daemon serves several hosts and each has its
// own mirror, so a global would report one host's replica under another's
// heartbeat and let a second pairing stomp the first's manager.
var (
	mirrorMu       sync.Mutex
	mirrorReports  = map[string]mirrorReport{}
	mirrorManagers = map[string]context.CancelFunc{}
	mirrorGens     = map[string]int{}
)

func setMirrorReport(host string, r mirrorReport) {
	mirrorMu.Lock()
	defer mirrorMu.Unlock()
	mirrorReports[host] = r
}

// currentMirrorReport returns this pairing's report, or nil when the box holds
// no mirror for that host — nil means "add no field to the heartbeat".
func currentMirrorReport(host string) *mirrorReport {
	mirrorMu.Lock()
	defer mirrorMu.Unlock()
	r, ok := mirrorReports[host]
	if !ok || r.State == "absent" {
		return nil
	}
	c := r
	return &c
}

// mirrorCapable gates what the host is allowed to OFFER. Two conditions, and
// the second is not pedantry:
//
//   - a container runtime exists, and
//   - we are on Linux.
//
// On Docker Desktop (macOS, Windows) the daemon runs inside a VM. The container
// bridge and its gateway live in that VM, so a listener this process opens on
// the host cannot be reached from a container, and the replica would sit there
// unable to dial the forwarder. Advertising the capability there would let the
// user spend an authenticator code on a mirror that can never connect. Better
// to not offer it than to fail after the ceremony.
//
// Native Linux podman/docker is the supported case; a Linux VM with the daemon
// inside it works because the daemon and this process share a network stack.
func mirrorCapable() bool {
	return runtime.GOOS == "linux" && detectRuntime() != ""
}

// ── storage ─────────────────────────────────────────────────────────────────

// mirrorDir is this pairing's mirror state. Per host, like contextRoot and
// dcnDir and for the same reason: one daemon serves several hosts and their
// databases must never share a directory. "" on failure.
func (c *Config) mirrorDir() string {
	base := mirrorStateBase()
	if base == "" || c.HostName == "" {
		return ""
	}
	dir := filepath.Join(base, c.HostName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	return dir
}

func mirrorStateBase() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "privatae-bastion", "mirror")
}

// ── image acquisition (swappable) ───────────────────────────────────────────

// imageFetcher makes the artifact present in the local runtime. An interface
// because HOW the image arrives is a posture decision that may change; a
// registry-pull implementation drops in here and nothing else changes.
type imageFetcher interface {
	Ensure(ctx context.Context, rt string, want mirrorImage) (string, error)
}

type tarballFetcher struct{}

type mirrorManifest struct {
	Images []struct {
		Version       string `json:"version"`
		Digest        string `json:"digest"`
		ServerVersion string `json:"server_version"`
		Artifact      string `json:"artifact"`
		SHA256        string `json:"sha256"`
	} `json:"images"`
}

// Ensure downloads, verifies and loads the image, then guarantees the local
// reference `image:tag` resolves to it.
//
// The tag part is not incidental. `docker save` of a digest reference writes a
// tarball whose manifest has RepoTags null (measured), so `docker
// load` produces an UNTAGGED image and any later `image inspect image:tag`
// misses. The publish step now saves by tag, but a tarball built the old way must
// still converge rather than loop: `load` prints "Loaded image ID: sha256:…",
// so when the tag is still absent afterwards we tag that ID ourselves.
func (tarballFetcher) Ensure(ctx context.Context, rt string, want mirrorImage) (string, error) {
	ref := want.Image + ":" + want.Tag
	if _, err := runCmd(20*time.Second, rt, "image", "inspect", ref); err == nil {
		return ref, nil
	}

	mf, err := fetchMirrorManifest(ctx)
	if err != nil {
		return "", err
	}
	var artifact, want256 string
	for _, e := range mf.Images {
		if e.Version == want.Tag || (want.Digest != "" && e.Digest == want.Digest) {
			artifact, want256 = e.Artifact, e.SHA256
			break
		}
	}
	if artifact == "" {
		return "", fmt.Errorf("database build %q is not published for mirrors — "+
			"nothing to download (the publish step for it was skipped)", want.Tag)
	}

	dir := filepath.Join(mirrorStateBase(), "_images")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mirror image dir: %w", err)
	}
	dst := filepath.Join(dir, artifact)

	// Reuse a previously verified tarball. The load step can fail for reasons a
	// re-download will never fix (no disk, runtime wedged); pulling hundreds of
	// megabytes again on every retry is pure harm on a home line.
	if sum, err := fileSHA256(dst); err == nil && sum == want256 {
		return loadAndTag(ctx, rt, dst, ref)
	}

	tmp := dst + ".part"
	got, err := downloadVerify(ctx, mirrorBase+"/"+artifact, tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if got != want256 {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("mirror image checksum mismatch (manifest %s, downloaded %s) — refusing to load",
			short(want256), short(got))
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", err
	}
	return loadAndTag(ctx, rt, dst, ref)
}

func loadAndTag(ctx context.Context, rt, tarPath, ref string) (string, error) {
	lctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	load := exec.CommandContext(lctx, rt, "load", "-i", tarPath)
	hideConsole(load) // console_windows.go
	out, err := load.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s load failed: %s", rt, truncate(strings.TrimSpace(string(out)), 200))
	}
	if _, err := runCmd(20*time.Second, rt, "image", "inspect", ref); err == nil {
		return ref, nil
	}
	// Untagged load (a save-by-digest tarball). Recover the ID it printed and
	// name it ourselves, so the idempotence check above succeeds next cycle.
	id := parseLoadedImageID(string(out))
	if id == "" {
		return "", fmt.Errorf("image %s not present after load, and no image ID was reported", ref)
	}
	if _, err := runCmd(30*time.Second, rt, "tag", id, ref); err != nil {
		return "", fmt.Errorf("could not tag loaded image %s as %s: %v", short(id), ref, err)
	}
	if _, err := runCmd(20*time.Second, rt, "image", "inspect", ref); err != nil {
		return "", fmt.Errorf("image %s still not present after tagging", ref)
	}
	return ref, nil
}

// parseLoadedImageID reads the ID out of `docker load` output. Two shapes:
// "Loaded image ID: sha256:…" (untagged) and "Loaded image: repo:tag" (tagged).
func parseLoadedImageID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "Loaded image ID:"); i >= 0 {
			return strings.TrimSpace(line[i+len("Loaded image ID:"):])
		}
	}
	return ""
}

func fetchMirrorManifest(ctx context.Context) (*mirrorManifest, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, mirrorBase+"/version.json", nil)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("mirror manifest unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mirror manifest HTTP %d", resp.StatusCode)
	}
	var mf mirrorManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&mf); err != nil {
		return nil, fmt.Errorf("mirror manifest unreadable: %w", err)
	}
	return &mf, nil
}

// downloadVerify streams to disk while hashing — a several-hundred-megabyte
// image is never held in memory on what may be a laptop.
func downloadVerify(ctx context.Context, src, dst string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	resp, err := (&http.Client{Timeout: mirrorFetchTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("mirror image download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mirror image download HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		return "", fmt.Errorf("mirror image download interrupted: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// ── the private network ─────────────────────────────────────────────────────
//
// The mirror gets its own network so its two containers have a stable subnet
// to be recognised by, and so we do not depend on the runtime's default network
// name (docker "bridge", podman "podman").
//
// It is NOT what isolates the forwarder, and it must not be described as if it
// were. MEASURED: a container on the DEFAULT bridge dialled this
// network's gateway on the forwarder port and CONNECTED. Docker's inter-network
// isolation is a FORWARD-chain rule — it separates container-to-container
// traffic across networks. The gateway address is an address of the HOST, so
// traffic to it is host-destined and never traverses FORWARD; every container
// on the box can reach it.
//
// The load-bearing control is therefore mirrorPeerAllowed below: an explicit
// source check on every accept. That check is the wall. Do not weaken it on the
// belief that the network already handles this — it does not, and the measured
// counter-example is one `docker run --network bridge` away.

func mirrorNetName(hostName string) string { return mirrorNetPrefix + safeName(hostName) }

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '-'
	}, s)
}

// networkInspect parses `network inspect` for BOTH runtimes.
//
// The two disagree on shape and a Go template written for one silently returns
// EMPTY on the other — which is worse than an error, because the capability is
// already advertised by then and the failure surfaces as an unexplained refusal.
// Docker: [{"IPAM":{"Config":[{"Subnet":…,"Gateway":…}]}}]
// Podman: [{"subnets":[{"subnet":…,"gateway":…}]}]
func networkInspect(rt, name string) (gw, subnet string, err error) {
	out, err := runCmd(15*time.Second, rt, "network", "inspect", name)
	if err != nil {
		return "", "", err
	}
	return parseNetworkInspect(out)
}

// parseNetworkInspect is the pure half, so both shapes can be pinned by a test
// without a container runtime present.
func parseNetworkInspect(out string) (gw, subnet string, err error) {
	var nets []struct {
		IPAM struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
		Subnets []struct {
			Subnet  string `json:"subnet"`
			Gateway string `json:"gateway"`
		} `json:"subnets"`
	}
	if err := json.Unmarshal([]byte(out), &nets); err != nil {
		return "", "", fmt.Errorf("could not parse network inspect: %w", err)
	}
	for _, n := range nets {
		for _, c := range n.IPAM.Config { // docker
			if ip := net.ParseIP(c.Gateway); ip != nil && ip.To4() != nil {
				return ip.String(), c.Subnet, nil
			}
		}
		for _, c := range n.Subnets { // podman
			if ip := net.ParseIP(c.Gateway); ip != nil && ip.To4() != nil {
				return ip.String(), c.Subnet, nil
			}
		}
	}
	return "", "", fmt.Errorf("no IPv4 gateway on the inspected network")
}

// ensureMirrorNet creates the private network if absent and returns its gateway
// and subnet. Both are required: an empty subnet would leave mirrorPeerAllowed
// with nothing to check against, and it refuses in that case rather than
// widening — so a parse failure here becomes a refusal, never an open port.
func ensureMirrorNet(rt, name string) (string, string, error) {
	if _, _, err := networkInspect(rt, name); err != nil {
		if _, err := runCmd(30*time.Second, rt, "network", "create", name); err != nil {
			return "", "", fmt.Errorf("could not create the mirror's private network: %v", err)
		}
	}
	gw, subnet, err := networkInspect(rt, name)
	if err != nil {
		return "", "", fmt.Errorf("could not read the mirror network: %v", err)
	}
	if subnet == "" {
		return "", "", fmt.Errorf("the mirror network reported no subnet, so the forwarder " +
			"could not tell an allowed peer from any other — refusing")
	}
	return gw, subnet, nil
}

// ── the forwarder: local TCP -> the host's /bastion-pgwire ──────────────────

// serveMirrorForward accepts the replica's connections and carries each one to
// the host over the tunnel. It binds the private network's gateway and
// loopback, never 0.0.0.0.
//
// The wall is mirrorPeerAllowed, called on every accept. Not the network: the
// gateway is a HOST address, so any container on the box can route to it
// regardless of which network it is on (measured — see the note above
// mirrorNetName). The source check is the only thing standing between another
// container and a BASE_BACKUP of the user's memory. Nothing here is defence in
// depth; this is the depth.
//
// One WebSocket per accepted connection, because `pg_basebackup -X stream`
// holds two replication connections at once and multiplexing them would mean
// inventing a framing layer for no gain.
func serveMirrorForward(ctx context.Context, gw, subnet, wsURL string,
	tlsCfg *tls.Config, dialHost func(ctx context.Context) (net.Conn, error), bearer string) {
	dialer := &websocket.Dialer{
		NetDialContext:   func(ctx context.Context, network, addr string) (net.Conn, error) { return dialHost(ctx) },
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 20 * time.Second,
	}
	var allowed *net.IPNet
	if subnet != "" {
		if _, n, err := net.ParseCIDR(subnet); err == nil {
			allowed = n
		}
	}
	for _, addr := range []string{
		net.JoinHostPort(gw, strconv.Itoa(mirrorForwardPort)),
		net.JoinHostPort("127.0.0.1", strconv.Itoa(mirrorForwardPort)),
	} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Printf("mirror: cannot listen on %s: %v\n", addr, err)
			continue
		}
		go func(ln net.Listener) { <-ctx.Done(); _ = ln.Close() }(ln)
		go func(ln net.Listener) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				if !mirrorPeerAllowed(c.RemoteAddr(), allowed) {
					_ = c.Close()
					continue
				}
				go pipeMirrorConn(ctx, c, dialer, wsURL, bearer)
			}
		}(ln)
	}
}

func mirrorPeerAllowed(addr net.Addr, allowed *net.IPNet) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true // the host itself, for diagnostics
	}
	return allowed != nil && allowed.Contains(ip)
}

func pipeMirrorConn(ctx context.Context, local net.Conn, dialer *websocket.Dialer,
	wsURL, bearer string) {
	defer local.Close()
	dctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	ws, _, err := dialer.DialContext(dctx, wsURL, http.Header{})
	cancel()
	if err != nil {
		return
	}
	defer ws.Close()
	if err := ws.WriteMessage(websocket.TextMessage, []byte("BEARER "+bearer)); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				break
			}
			if mt != websocket.BinaryMessage || len(data) == 0 {
				continue
			}
			if _, werr := local.Write(data); werr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
}

// ── the replica container ───────────────────────────────────────────────────

func mirrorContainerName(hostName string) string {
	return mirrorContainerPrefix + safeName(hostName)
}

// imageMajor is the PostgreSQL major the image ships. A standby's data
// directory is major-version-specific, so this decides whether an image roll is
// a restart or a full re-seed.
func imageMajor(rt, ref string) string {
	out, err := runCmd(30*time.Second, rt, "run", "--rm", "--entrypoint",
		"/usr/lib/postgresql/17/bin/postgres", ref, "-V")
	if err != nil {
		// The path above is version-pinned; fall back to whatever is on PATH.
		out, err = runCmd(30*time.Second, rt, "run", "--rm", "--entrypoint", "postgres", ref, "-V")
		if err != nil {
			return ""
		}
	}
	f := strings.Fields(strings.TrimSpace(out)) // "postgres (PostgreSQL) 17.10"
	if len(f) == 0 {
		return ""
	}
	return strings.SplitN(f[len(f)-1], ".", 2)[0]
}

func dataMajor(pgdata string) string {
	b, err := os.ReadFile(filepath.Join(pgdata, "PG_VERSION"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func runningImage(rt, container string) string {
	out, err := runCmd(10*time.Second, rt, "inspect", "-f", "{{.Config.Image}}", container)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func containerExists(rt, name string) (exists, running bool) {
	out, err := runCmd(10*time.Second, rt, "inspect", "-f", "{{.State.Running}}", name)
	if err != nil {
		return false, false
	}
	return true, strings.TrimSpace(out) == "true"
}

// ensureReplica converges the standby. Idempotent: a healthy, correctly-imaged
// running replica is a no-op.
func ensureReplica(ctx context.Context, rt, ref, hostName, dataDir, netName, gw, slot string) mirrorReport {
	name := mirrorContainerName(hostName)
	pgdata := filepath.Join(dataDir, "pgdata")
	rep := mirrorReport{Runtime: rt, State: "running", Container: name, ImageTag: ref}
	rep.OpenWith = fmt.Sprintf("%s exec -it %s psql -U entity", rt, name)

	// A base backup copies the primary's postgresql.conf, which sets
	// listen_addresses = '' — so the standby has NO TCP listener, and its
	// pg_hba only trusts local/loopback. That is the right posture and we do
	// not widen it: the user opens their copy through the runtime, on the
	// container's own socket. Saying "connect to <ip>:5432" would have been an
	// instruction that simply fails.

	// An image roll must move the standby onto the new build. Same major = stop,
	// remove, re-run on the new ref, data intact. Different major = the data
	// directory cannot be read by that binary at all, and starting it would
	// crash-loop; refuse and say what happened.
	exists, running := containerExists(rt, name)
	if exists {
		if cur := runningImage(rt, name); cur != "" && cur != ref {
			im, dm := imageMajor(rt, ref), dataMajor(pgdata)
			if im != "" && dm != "" && im != dm {
				return mirrorReport{Runtime: rt, State: "mismatch", Container: name, ImageTag: cur,
					Error: fmt.Sprintf("your host moved to PostgreSQL %s but this copy is %s — "+
						"a copy cannot be upgraded in place, so it has been left untouched and "+
						"is still readable. Turn the mirror off and on again to take a fresh one.",
						im, dm)}
			}
			_, _ = runCmd(60*time.Second, rt, "rm", "-f", name)
			exists, running = false, false
		}
	}
	if exists && running {
		rep.ImageTag = runningImage(rt, name)
		rep.ReplayLSN = replicaReplayLSN(rt, name)
		return rep
	}
	if exists {
		// Present but stopped: start it. The data is the point; discarding it
		// because a laptop rebooted would be absurd.
		if _, err := runCmd(60*time.Second, rt, "start", name); err != nil {
			return mirrorReport{Runtime: rt, State: "failed", Container: name, ImageTag: ref,
				Error: "could not restart the mirror: " + truncate(err.Error(), 160)}
		}
		rep.ImageTag = runningImage(rt, name)
		rep.ReplayLSN = replicaReplayLSN(rt, name)
		return rep
	}

	if _, err := os.Stat(filepath.Join(pgdata, "PG_VERSION")); err != nil {
		rep.State = "seeding"
		setMirrorReport(hostName, rep)
		if err := seedReplica(ctx, rt, ref, dataDir, netName, gw, slot); err != nil {
			return mirrorReport{Runtime: rt, State: "failed", ImageTag: ref,
				Error: truncate(err.Error(), 200)}
		}
	} else if im, dm := imageMajor(rt, ref), dataMajor(pgdata); im != "" && dm != "" && im != dm {
		return mirrorReport{Runtime: rt, State: "mismatch", ImageTag: ref,
			Error: fmt.Sprintf("your host runs PostgreSQL %s but the copy here is %s — "+
				"turn the mirror off and on again to take a fresh one", im, dm)}
	}
	if err := writeStandbyConfig(pgdata, gw, slot); err != nil {
		return mirrorReport{Runtime: rt, State: "failed", ImageTag: ref,
			Error: "could not write standby config: " + truncate(err.Error(), 160)}
	}
	args := []string{"run", "-d", "--name", name, "--restart", "unless-stopped",
		"--network", netName, "-v", pgdata + ":/app/pgdata", "--user", "1000:1000",
		"--entrypoint", "/usr/lib/postgresql/17/bin/postgres", ref, "-D", "/app/pgdata"}
	if _, err := runCmd(60*time.Second, rt, args...); err != nil {
		return mirrorReport{Runtime: rt, State: "failed", ImageTag: ref,
			Error: "could not start the mirror: " + truncate(err.Error(), 160)}
	}
	rep.ImageTag = runningImage(rt, name)
	rep.ReplayLSN = replicaReplayLSN(rt, name)
	return rep
}

// seedReplica takes the base backup into a STAGING directory and swaps it into
// place only on success, so a failed or interrupted seed never destroys the
// copy the user already has.
func seedReplica(ctx context.Context, rt, ref, dataDir, netName, gw, slot string) error {
	pgdata := filepath.Join(dataDir, "pgdata.new")
	_ = os.RemoveAll(pgdata) // a previous attempt's partial tree
	if err := os.MkdirAll(pgdata, 0o700); err != nil {
		return err
	}
	// uid 1000 is the image's `privatae` user; PostgreSQL refuses a PGDATA it
	// does not own. Best-effort: a rootless runtime maps this already.
	_ = os.Chown(pgdata, 1000, 1000)
	_ = os.Chmod(pgdata, 0o700)

	sctx, cancel := context.WithTimeout(ctx, mirrorFetchTimeout)
	defer cancel()
	base := exec.CommandContext(sctx, rt, "run", "--rm", "--user", "1000:1000",
		"--network", netName, "-v", pgdata+":/rep",
		"--entrypoint", "/usr/lib/postgresql/17/bin/pg_basebackup", ref,
		"-h", gw, "-p", strconv.Itoa(mirrorForwardPort), "-U", "entity",
		"-D", "/rep", "-X", "stream", "-c", "fast", "--slot="+slot, "--no-password")
	hideConsole(base) // console_windows.go
	out, err := base.CombinedOutput()
	if err != nil {
		// Leave the staging tree for inspection but never promote it.
		return fmt.Errorf("base backup failed: %s", truncate(strings.TrimSpace(string(out)), 240))
	}
	return promoteSeed(dataDir)
}

// writeStandbyConfig points recovery at the local forwarder and marks the
// cluster a standby. Rewritten every start so a renumbered gateway (a runtime
// restart can move it) does not strand the replica.
func writeStandbyConfig(pgdata, gw, slot string) error {
	conf := fmt.Sprintf(
		"primary_conninfo = 'host=%s port=%d user=entity application_name=mirror'\n"+
			"primary_slot_name = '%s'\n"+
			"hot_standby = on\n",
		gw, mirrorForwardPort, slot)
	if err := os.WriteFile(filepath.Join(pgdata, "postgresql.auto.conf"), []byte(conf), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(pgdata, "standby.signal"), nil, 0o600); err != nil {
		return err
	}
	_ = os.Chown(filepath.Join(pgdata, "postgresql.auto.conf"), 1000, 1000)
	_ = os.Chown(filepath.Join(pgdata, "standby.signal"), 1000, 1000)
	return nil
}

// replicaReplayLSN asks the standby how far it has replayed — the one number
// the primary cannot produce once the lane is down. "" whenever the answer
// would be a guess; an absent field is honest, a stale one is not.
//
// The socket path comes from the primary's postgresql.conf, which a base backup
// copies verbatim: /var/run/postgresql, not /tmp.
func replicaReplayLSN(rt, container string) string {
	out, err := runCmd(10*time.Second, rt, "exec", container,
		"psql", "-h", "/var/run/postgresql", "-U", "entity", "-d", "postgres", "-Atc",
		"select coalesce(pg_last_wal_replay_lsn()::text,'')")
	if err != nil {
		return ""
	}
	lsn := strings.TrimSpace(out)
	if lsn == "" || !strings.Contains(lsn, "/") {
		return ""
	}
	return lsn
}

// ── reseed generation ───────────────────────────────────────────────────────

func genFile(dataDir string) string { return filepath.Join(dataDir, ".mirror-generation") }

func readGeneration(dataDir string) int {
	b, err := os.ReadFile(genFile(dataDir))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func writeGeneration(dataDir string, n int) {
	_ = os.WriteFile(genFile(dataDir), []byte(strconv.Itoa(n)), 0o600)
}

// retireCopy stops the replica and moves its data ASIDE — it does not delete
// it. Called only when the host says this copy can never catch up (the primary
// shed its slot).
//
// Deleting first was wrong and would have hurt someone: the base backup that
// replaces it runs over a home connection and can take a long time and fail
// (host offline, disk full, laptop closed). Between the delete and a successful
// re-seed the user would have had NO copy at all — and the whole promise of
// this feature is that they always have one. So the old copy is renamed and
// only removed once a new one is complete.
func retireCopy(rt, hostName, dataDir string) {
	name := mirrorContainerName(hostName)
	_, _ = runCmd(60*time.Second, rt, "rm", "-f", name)
	cur := filepath.Join(dataDir, "pgdata")
	if _, err := os.Stat(cur); err != nil {
		return
	}
	prev := filepath.Join(dataDir, "pgdata.previous")
	_ = os.RemoveAll(prev) // only ever one generation back
	if err := os.Rename(cur, prev); err != nil {
		// Could not move it aside — leave it exactly where it is. A failed
		// rename must not become a delete.
		fmt.Printf("mirror: could not set the old copy aside (%v) — keeping it\n", err)
	}
}

// promoteSeed swaps a completed seed into place and retires the previous copy.
// Only called once pg_basebackup has returned success.
func promoteSeed(dataDir string) error {
	staging := filepath.Join(dataDir, "pgdata.new")
	cur := filepath.Join(dataDir, "pgdata")
	if _, err := os.Stat(cur); err == nil {
		prev := filepath.Join(dataDir, "pgdata.previous")
		_ = os.RemoveAll(prev)
		if err := os.Rename(cur, prev); err != nil {
			return err
		}
	}
	if err := os.Rename(staging, cur); err != nil {
		return err
	}
	// The new copy is complete and in place; now the old one is safe to drop.
	_ = os.RemoveAll(filepath.Join(dataDir, "pgdata.previous"))
	return nil
}

// ── the manager ─────────────────────────────────────────────────────────────

// maybeMirror reacts to the heartbeat response, mirroring maybeContain's shape:
// the host directs, this box carries it out. No directive means no change.
func maybeMirror(heartbeatResponse []byte, cfg *Config, wsURL string,
	tlsCfg *tls.Config, dialHost func(ctx context.Context) (net.Conn, error)) {
	var hb struct {
		Mirror *mirrorDirective `json:"mirror"`
	}
	if json.Unmarshal(heartbeatResponse, &hb) != nil || hb.Mirror == nil {
		return
	}
	host := cfg.HostName
	d := *hb.Mirror

	// A mirror is a container and a data directory on the machine: box-wide,
	// so on an anchored box only the anchor host may place one (anchor.go
	// anchorOnly). Reported, not silent: the host stores the
	// mirror state and error off the heartbeat (the host's mirror lane), so
	// the refusal is on record rather than a copy that never starts for no
	// stated reason. A disable from a member host falls through — stopping
	// what should not run is always fine.
	if d.Enabled {
		// directiveGate (writes.go): anchor-only, the local switch, then on
		// an anchored box an approval bound to this slot and image.
		if why := directiveGate(host, cfg.dcnDir(), directiveMirror,
			[]string{d.Slot, d.DBImage.Image, d.DBImage.Tag, d.DBImage.Digest},
			directiveApproval(heartbeatResponse, directiveMirror)); why != "" {
			setMirrorReport(host, mirrorReport{State: "failed", Error: truncate(why, 180)})
			// Also on the one channel all three directives now share, so an
			// operator has a single place to look rather than three.
			recordDirectiveRefusal("mirror placement", why)
			return
		}
		clearDirectiveRefusal("mirror placement")
	}

	// Disabled, or disowned while we were offline. Stop — otherwise the
	// walreceiver retries a lane the host will refuse, every five seconds,
	// forever. The DATA stays: it is the user's copy, not ours to delete.
	if !d.Enabled {
		// A placement the person approved is forgotten with it (writes.go
		// directiveGate): the mirror coming back is a new act to approve.
		forgetDirective(directiveMirror)
		mirrorMu.Lock()
		cancel, running := mirrorManagers[host]
		delete(mirrorManagers, host)
		delete(mirrorGens, host)
		mirrorMu.Unlock()
		if running {
			cancel()
			if rt := detectRuntime(); rt != "" {
				_, _ = runCmd(60*time.Second, rt, "stop", mirrorContainerName(host))
			}
			fmt.Printf("[%s] mirror: host says this machine no longer holds the mirror (%s) — "+
				"stopped. Your existing copy is untouched.\n", host, orUnknown(d.Reason))
			setMirrorReport(host, mirrorReport{State: "absent"})
		} else if r := currentMirrorReport(host); r != nil && r.State == "failed" {
			// Nothing ran, but a report says failed — a placement this box
			// refused (anchor-only, above) or one that never got a runtime.
			// The host has disabled it; clear the report or every later beat
			// carries "failed" and the host answers a no-op disable forever.
			setMirrorReport(host, mirrorReport{State: "absent"})
		}
		return
	}

	mirrorMu.Lock()
	_, running := mirrorManagers[host]
	mirrorGens[host] = d.ReseedGeneration
	if running {
		mirrorMu.Unlock()
		return // the manager re-reads the generation each cycle
	}
	ctx, cancel := context.WithCancel(context.Background())
	mirrorManagers[host] = cancel
	mirrorMu.Unlock()
	go runMirrorManager(ctx, cfg, d, wsURL, tlsCfg, dialHost)
}

func wantedGeneration(host string, fallback int) int {
	mirrorMu.Lock()
	defer mirrorMu.Unlock()
	if g, ok := mirrorGens[host]; ok && g > 0 {
		return g
	}
	return fallback
}

func runMirrorManager(ctx context.Context, cfg *Config, d mirrorDirective, wsURL string,
	tlsCfg *tls.Config, dialHost func(ctx context.Context) (net.Conn, error)) {
	host := cfg.HostName
	rt := detectRuntime()
	if rt == "" {
		setMirrorReport(host, mirrorReport{State: "failed",
			Error: "no container runtime — install Docker or Podman to hold a mirror"})
		return
	}
	dataDir := cfg.mirrorDir()
	if dataDir == "" {
		setMirrorReport(host, mirrorReport{Runtime: rt, State: "failed",
			Error: "could not create the mirror's data directory"})
		return
	}
	if !d.DBImage.Known || d.DBImage.Tag == "" {
		setMirrorReport(host, mirrorReport{Runtime: rt, State: "mismatch",
			Error: "the host did not say which database build to run — its database " +
				"container predates mirror support and needs a newer image"})
		return
	}
	netName := mirrorNetName(host)
	gw, subnet, err := ensureMirrorNet(rt, netName)
	if err != nil {
		// Refuse rather than bind wider. A mirror that works by exposing the
		// user's memory to every container on the box is not worth having.
		setMirrorReport(host, mirrorReport{Runtime: rt, State: "failed",
			Error: truncate(err.Error(), 180)})
		return
	}

	// The forwarder must exist before anything reaches the primary through it —
	// the base backup is the first thing that will.
	serveMirrorForward(ctx, gw, subnet, wsURL, tlsCfg, dialHost, cfg.Bearer)
	fmt.Printf("[%s] mirror: forwarder up on %s:%d (private network %s)\n",
		host, gw, mirrorForwardPort, netName)

	var fetch imageFetcher = tarballFetcher{}
	slot := d.Slot
	if slot == "" {
		slot = "mirror"
	}
	backoff := time.Duration(0)
	for {
		if backoff > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}

		// The host bumps the generation when it recuts a slot the primary shed.
		// A change means this copy can never catch up — take a fresh one.
		if want := wantedGeneration(host, d.ReseedGeneration); want > 0 {
			if have := readGeneration(dataDir); have != 0 && have != want {
				fmt.Printf("[%s] mirror: host reports this copy can no longer catch up "+
					"(generation %d -> %d) — taking a fresh one\n", host, have, want)
				retireCopy(rt, host, dataDir)
			}
			writeGeneration(dataDir, want)
		}

		setMirrorReport(host, mirrorReport{Runtime: rt, State: "fetching", ImageTag: d.DBImage.Tag})
		ref, err := fetch.Ensure(ctx, rt, d.DBImage)
		if err != nil {
			setMirrorReport(host, mirrorReport{Runtime: rt, State: "failed",
				ImageTag: d.DBImage.Tag, Error: truncate(err.Error(), 200)})
			backoff = nextBackoff(backoff)
			continue
		}
		rep := ensureReplica(ctx, rt, ref, host, dataDir, netName, gw, slot)
		setMirrorReport(host, rep)
		// A failure the next identical attempt cannot fix backs off; a healthy
		// pass returns to the normal poll.
		if rep.State == "failed" || rep.State == "mismatch" {
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = 0
		select {
		case <-ctx.Done():
			return
		case <-time.After(mirrorPollInterval):
		}
	}
}

func nextBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return mirrorPollInterval
	}
	n := cur * 2
	if n > mirrorBackoffMax {
		return mirrorBackoffMax
	}
	return n
}

// mirrorWSURL is the host endpoint the forwarder carries connections to.
func mirrorWSURL(hostName string) string {
	u := url.URL{Scheme: "wss", Host: net.JoinHostPort(hostName, "8443"), Path: "/bastion-pgwire"}
	return u.String()
}
