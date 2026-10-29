package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// clientVersion is stamped at build time via -ldflags "-X main.clientVersion=<ver>" (see
// deploy/publish.sh + deploy/VERSION). The "dev" default flags an unstamped local build.
var clientVersion = "dev"

// b64ToHex turns a base64 WireGuard key into the hex the device's
// configuration text takes. A key is 32 bytes; anything else is refused here
// rather than by the device.
func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("a WireGuard key is 32 bytes, this one is %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// cmdRun serves EVERY pairing from one process (multi-homing, 0.10.0). The old
// single-config daemon meant pairing to a new host silently unpaired the previous
// one — re-pairing a desktop to a second host killed the first host's embed lane. Now
// each pairing gets its own tunnel + local listener; the first fatal error (or a
// signal) takes the whole process down so the supervisor restarts all lanes
// together instead of limping half-homed.
func cmdRun() error {
	// THE machine-wide exclusion lock, taken before any pairing starts and never
	// inside runPairing. Holding it means primary; blocking on it means standby,
	// and the standby simply waits in the kernel until the primary dies.
	//
	// It replaces an ACCIDENTAL singleton that was already here and failed badly:
	// two daemons both allocate 127.0.0.1:7878, the loser dies on the bind and
	// restarts every two seconds forever, flapping its WireGuard handshake each
	// time, and which one wins is decided by boot order. A lock is atomic (no
	// check-then-act window), immune to a stale file, kernel-released on death
	// including SIGKILL, and — the property a socket probe cannot give — a HUNG
	// primary keeps it, so a standby never takes over from a process that is merely
	// unresponsive and leaves two daemons holding the same WireGuard keys.
	// Windows first, because acquireSingletonLock below is a no-op there
	// (singletonSupported() is linux-only) and a second process would otherwise
	// run all the way to a loopback port bind and die naming a port number.
	if err := guardSingleRun(); err != nil {
		return err
	}
	lock, err := acquireSingletonLock()
	if err != nil {
		return err
	}
	// Thaw anything a previous run froze for a kill it never finished
	// (killtree.go): the primary does it once, before any pairing can order
	// another.
	recoverFrozenTrees()
	defer lock.release()

	// Write the machine marker BEFORE the not-paired return below. A fresh box is
	// `enable --now` at install and crash-loops here until it is paired — and that
	// is exactly the window in which a `sudo`-without-`-H` pair happens. A marker
	// written after this return does not exist when it is needed.
	_ = maybeWriteMarker()

	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	if len(cfgs) == 0 {
		return fmt.Errorf("not paired — run `privatae-bastion pair <token>` first")
	}

	// Clear any leftover from a prior self-update swap (the superseded binary can't
	// delete itself while running, so it's removed on the next start).
	cleanupStaleBinaries()
	// An op run the last process died in the middle of: its tmpfs (with an
	// action run's opened credentials), its work folder, its unit.
	opStartupSweep()
	// A root command's connection watch the last process died in the middle
	// of: its nftables table (rootexec_watch_linux.go).
	rootExecWatchSweep()

	// Pairings from before the git lane (< 0.13.0) have no git proxy port: allocate
	// one now and persist it, so `git-setup` and `run` agree.
	for _, cfg := range cfgs {
		if cfg.GitProxyAddr == "" {
			cfg.GitProxyAddr = nextGitProxyAddr(cfgs)
			if err := cfg.updateOnDisk(func(d *Config) { d.GitProxyAddr = cfg.GitProxyAddr }); err != nil {
				return err
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 64)
	supervisor.Lock()
	supervisor.ctx, supervisor.errc = ctx, errc
	// Installed here, not at package init: the mgmt handler table refers to the
	// grant handler, which starts pairings, which run the enforcing report,
	// which reads the handler table — a static reference would be an
	// initialization cycle. A runtime hook is the same call without the loop.
	supervisor.start = startPairing
	supervisor.Unlock()
	fmt.Printf("mode: %s\n", boxMode())
	if a := currentAnchor(); a != nil {
		fmt.Printf("anchored to %s (owner %q)\n", a.AnchorHost, a.Owner)
	}
	started := 0
	for _, cfg := range cfgs {
		if startPairing(cfg) {
			started++
		}
	}
	if started == 0 {
		for _, cfg := range cfgs {
			if cfg.invalid != "" {
				return fmt.Errorf("no pairing can be served — %s", cfg.invalid)
			}
		}
		return fmt.Errorf("no active pairing — every pairing is pending or revoked; the anchor host must approve one")
	}
	go superviseLoop(ctx)
	// The local UI (ui.go): ONE per machine, not one per pairing, because it
	// shows the whole box. Started last so it renders a daemon that is already
	// up, and non-fatal by construction — a machine that cannot bind the UI port
	// must still serve its hosts.
	startUIServer(ctx)
	// The tray (tray_windows.go): Windows only, a no-op elsewhere. It is the
	// only part of this UI that answers "is it running" without the user
	// opening anything, which is the question that started all of it.
	startTray(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		fmt.Println("\nshutting down")
		cancel() // closes every pairing's server + WG device via runPairing's exits
		return nil
	case <-shutdownCh:
		// "Stop the bastion" in the tray menu. Deliberately the SAME path as a
		// signal rather than an os.Exit: a machine that stops serving must tear
		// its tunnels down, not vanish and leave the host waiting for a beat.
		fmt.Println("\nstopping — asked from the tray")
		cancel()
		return nil
	case err := <-errc:
		cancel()
		return err
	}
}

// The pairing supervisor: which pairings are running and how to
// stop one. Before anchoring, the set of running pairings was fixed at start;
// now a pairing grant opens a pending pairing's lanes while the daemon runs,
// and a revoke closes them, so each pairing gets its own child context here.
var supervisor struct {
	sync.Mutex
	ctx  context.Context // cmdRun's root context; nil when the daemon is not running
	errc chan error      // fatal pairing errors, forwarded to cmdRun
	runs map[string]*pairingRun
	// start is startPairing while the daemon runs; nil otherwise. The mgmt
	// grant handler calls through it (supervisorStart) so pairing_ops.go never
	// references runPairing directly — see cmdRun for why.
	start func(*Config) bool
}

// supervisorStart opens a pairing's lanes if the daemon is running. False from
// a CLI process (nothing to start; the next `run` picks the pairing up).
func supervisorStart(cfg *Config) bool {
	supervisor.Lock()
	start := supervisor.start
	supervisor.Unlock()
	if start == nil {
		return false
	}
	return start(cfg)
}

type pairingRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	// cfg is the copy the run was started with, and the one its tunnel, lanes
	// and heartbeat hold.
	cfg *Config
}

// startPairing spawns runPairing for cfg under the supervisor. Returns false
// when the pairing is not active (nothing is started for a pending or revoked
// pairing — it is a file), when it is already running, or when the daemon is
// not running (a CLI process handling a grant has nothing to start).
func startPairing(cfg *Config) bool {
	if cfg.invalid != "" {
		fmt.Printf("[%s] not started (no tunnel, no lanes, no dirs): %s\n", cfg.HostName, cfg.invalid)
		return false
	}
	if !cfg.active() {
		fmt.Printf("[%s] %s — not started (no tunnel, no lanes, no dirs) until the anchor host approves it\n", cfg.HostName, cfg.stateName())
		return false
	}
	supervisor.Lock()
	defer supervisor.Unlock()
	if supervisor.ctx == nil {
		return false
	}
	if supervisor.runs == nil {
		supervisor.runs = map[string]*pairingRun{}
	}
	if _, running := supervisor.runs[cfg.HostName]; running {
		return false
	}
	pctx, pcancel := context.WithCancel(supervisor.ctx)
	run := &pairingRun{cancel: pcancel, done: make(chan struct{}), cfg: cfg}
	supervisor.runs[cfg.HostName] = run
	errc := supervisor.errc
	go func() {
		defer close(run.done)
		err := runPairing(pctx, cfg)
		// Retired BEFORE it leaves the registry: leaving is what lets the
		// pairing start again, and this run's heartbeat may still be running.
		retireRun(cfg)
		supervisor.Lock()
		if supervisor.runs[cfg.HostName] == run {
			delete(supervisor.runs, cfg.HostName)
		}
		supervisor.Unlock()
		// nil is a clean exit (ctx cancelled: shutdown or a revoke) and must not
		// take the process down. Anything else is fatal for the whole daemon, as
		// before: the supervisor restarts all lanes together, never half-homed.
		if err != nil && errc != nil {
			errc <- fmt.Errorf("[%s] %w", cfg.HostName, err)
		}
	}()
	return true
}

// superviseLoop makes the daemon follow the pairing files on disk. Every
// supervisePeriod: a pairing whose file says active but which is not running
// is started; one that is running but whose file now says pending/revoked, or
// whose file is gone, is stopped; one whose file holds another WireGuard key
// than the run (paired again) is stopped and started from the new file. This
// is how a change made by ANOTHER process — claim-anchor --rotate demoting the
// old anchor, `unpair` deleting a file, `pair --replace` writing new
// credentials, a grant handled before a restart — reaches the running daemon
// without a restart. The in-process handlers still act at once; this is the
// catch-up.
const supervisePeriod = 15 * time.Second

func superviseLoop(ctx context.Context) {
	t := time.NewTicker(supervisePeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			superviseOnce()
		}
	}
}

func superviseOnce() {
	cfgs, err := loadPairings()
	if err != nil {
		return // cannot read the directory: change nothing on a read error
	}
	onDisk := map[string]*Config{}
	for _, c := range cfgs {
		onDisk[c.HostName] = c
	}
	supervisor.Lock()
	running := make(map[string]*pairingRun, len(supervisor.runs))
	for h, r := range supervisor.runs {
		running[h] = r
	}
	supervisor.Unlock()
	for h, r := range running {
		c, ok := onDisk[h]
		switch {
		case !ok || !c.active():
			fmt.Printf("[%s] no longer active on disk — stopping its tunnel and lanes\n", h)
			stopPairing(h)
		case r.cfg != nil && c.WGPrivateKey != r.cfg.WGPrivateKey:
			// Only `pair` writes the key, and always a fresh one, so this
			// is a pairing made again (`pair --replace` in another
			// process, or an unpair and a pair within one period). The run
			// still holds the credentials that pair rotated out; the start
			// below brings the new ones up, once the old run is gone.
			fmt.Printf("[%s] paired again on disk — restarting its tunnel and lanes with the new pairing\n", h)
			stopPairing(h)
		}
	}
	for _, c := range cfgs {
		if c.active() {
			startPairing(c) // no-op when already running
		}
	}
}

// stopPairing cancels one running pairing and waits (bounded) for its tunnel,
// listener and lanes to exit. Returns whether anything was running.
func stopPairing(host string) bool {
	supervisor.Lock()
	run, ok := supervisor.runs[host]
	supervisor.Unlock()
	if !ok {
		return false
	}
	retireRun(run.cfg)
	run.cancel()
	select {
	case <-run.done:
	case <-time.After(5 * time.Second):
	}
	return true
}

// retireRun marks the copy a run holds as stopped. Once it returns, nothing is
// written through that copy (updateOnDiskIf, errRunStopped): the run's
// heartbeat goroutine is not waited for, and a beat stuck on a dead tunnel can
// come back after the run is gone — even after the same pairing, same key, was
// started again — and save its copy's older entry and Hub key over the new
// run's. Set under saveMu, the lock every write of a pairing file holds, so a
// write already under way finishes first and none starts after. Called before
// a run is cancelled and again before it leaves the registry, so it is always
// done before the pairing can start again.
func retireRun(cfg *Config) {
	if cfg == nil {
		return
	}
	saveMu.Lock()
	cfg.retired = true
	saveMu.Unlock()
}

// errPairingNotActive is runPairing's answer to a pending or revoked pairing:
// it returns before creating anything. A guard, not the normal path —
// startPairing never calls it for one.
var errPairingNotActive = errors.New("pairing is not active — nothing started")

// runPairing is the entire single-host daemon for ONE pairing — tunnel, worker
// lanes, local control listener, heartbeat — exactly the pre-0.10.0 body, per cfg.
// It returns nil when ctx is cancelled (clean shutdown) or the pairing's fatal
// error. Log lines are prefixed with the host so interleaved pairings read apart.
func runPairing(ctx context.Context, cfg *Config) error {
	logf := func(format string, a ...any) { fmt.Printf("["+cfg.HostName+"] "+format, a...) }

	// A pending or revoked pairing (anchor.go) is a FILE and nothing more: no
	// WireGuard device, no worker lanes, no listener, and — because contextRoot()
	// and dcnDir() create on read — not even its directories. This guard sits
	// above every one of those so the order of the code below can never leak a
	// side effect for a host the anchor has not approved.
	if !cfg.active() {
		return errPairingNotActive
	}
	// A Host with no platform: the same lanes over its socket or its lane
	// port, no tunnel.
	if cfg.localTransport() {
		return runUnixPairing(ctx, cfg)
	}

	// 1. Userspace WireGuard (gVisor netstack): no TUN device, no root.
	gwIP, err := netip.ParseAddr(cfg.BastionTunnelIP)
	if err != nil {
		return fmt.Errorf("bad gateway tunnel ip %q: %w", cfg.BastionTunnelIP, err)
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{gwIP}, []netip.Addr{}, 1420)
	if err != nil {
		return fmt.Errorf("create userspace tun: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
	if err := configureTunnelPeer(dev, cfg); err != nil {
		return err
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("bring up wireguard: %w", err)
	}
	defer dev.Close()

	// 1b. Expose the bastion's LOCAL ollama to the host over the tunnel so the
	//     embed lane works end to end. The host dials <bastion tunnel IP>:11434;
	//     we accept on the netstack and proxy to ollama on loopback. Without this
	//     the heartbeat can advertise 'embed' but the host could never reach the
	//     embedder — the netstack tunnel otherwise only dials OUT (lanes/heartbeat).
	//     ollama just runs on its default loopback; no WG adapter / firewall dance.
	//     All three forwards are the `inference` caps family (anchor.go): on an
	//     anchored box a member pairing outside it is refused at accept.
	go serveOllamaForward(ctx, cfg.HostName, tnet, gwIP)
	// 1c. Same, for an OpenAI-compatible server (llama.cpp/vLLM) when
	//     PRIVATAE_LLM_ADDR is set: host dials <bastion tunnel IP>:18080.
	go serveLLMForward(ctx, cfg.HostName, tnet, gwIP)
	// 1d. Same, for the PII sterilization service when PRIVATAE_PII_ADDR is
	//     set: host dials <bastion tunnel IP>:18081. Unset = lane absent.
	go servePIIForward(ctx, cfg.HostName, tnet, gwIP)
	// 1d'. The service slots (service.go): one forward per server a host built
	//      on this machine, host dials <bastion tunnel IP>:<tunnel_port>. The
	//      "services" family is checked at every accept.
	go serveServiceForwards(ctx, cfg.HostName, cfg.dcnDir(), tnet, gwIP)
	// 1d''. Coder runs (coders.go): one forward per run this host started
	//       here, host dials <bastion tunnel IP>:<tunnel_port> (18200-18299)
	//       and is spliced to the run's control socket. The box-wide coder
	//       loop (egress proxies, reaper) starts once per daemon.
	coderInit(context.Background())
	go serveCoderForwards(ctx, cfg.HostName, cfg.HostTunnelIP, tnet, gwIP)
	// 1e. Managed local agents (freeagent_managed.go): bring up an instance for
	// every synced store grant carrying 'search', so a daemon restart never
	// loses a running local agent.
	go faReconcileLoop(ctx, cfg.dcnDir())

	// 2. mTLS client that dials the host's :8443 lanes THROUGH the tunnel
	//    (heartbeat, git-credential, DCN propose, the reverse-relay WebSockets).
	//    The bastion↔host session is end-to-end encrypted; the concentrator only
	//    ever sees ciphertext.
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(cfg.CACert)) {
		return fmt.Errorf("bad CA cert in config")
	}
	cert, err := tls.X509KeyPair([]byte(cfg.OperatorCert), []byte(cfg.OperatorKey))
	if err != nil {
		return fmt.Errorf("operator cert/key: %w", err)
	}
	hostAddr := net.JoinHostPort(cfg.HostTunnelIP, "8443")
	transport := &http.Transport{
		// Ignore the requested host; always dial the host's tunnel alias over WG.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tnet.DialContext(ctx, "tcp", hostAddr)
		},
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{cert},
			ServerName:   cfg.HostName, // SAN check against <handle>.host.privatae.ai
		},
	}
	upstream := &http.Client{Transport: transport}

	// 2a. The extraction PULL path (contextpull.go). ctx_extract used to
	//     take the document inline in the management frame, which caps a source
	//     at 8 MiB — fine for the text PDFs that shipped, not for the scanned
	//     ones OCR is for. The fetch reuses THIS client deliberately: its
	//     DialContext ignores the address in a URL and dials the host's tunnel
	//     endpoint, and its TLS config pins ServerName to the host name. That
	//     pinning is what lets contextpull.go build its own URL and carry no
	//     SSRF wall — unlike backup_fetch, the host never names a destination.
	//     Set BEFORE the mgmt workers come up, so a job cannot arrive to find
	//     the lane unconfigured.
	setCtxSourcePuller(newHostSourcePuller(upstream, cfg.HostName, cfg.Bearer))

	// Egress (reverse relay): the host can't reach the bastion's tunnel IP (the entity
	// pod has no WG iface), so we open worker WebSockets TO the host over the same
	// tunnel -> :8443 mTLS lane and serve egress over them — the host dispatches each
	// allowed request to a worker, and we dial it out the USER's own connection.
	go func() {
		realDialer := &net.Dialer{Timeout: egressDialTimeout}
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-egress", cfg.HostName)
		wsTLS := &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}, ServerName: cfg.HostName}
		dialHost := func(ctx context.Context) (net.Conn, error) { return tnet.DialContext(ctx, "tcp", hostAddr) }
		logf("egress workers up — outbound exits THIS machine's internet via %s\n", wsURL)
		runEgressWorkers(ctx, cfg.HostName, wsURL, wsTLS, dialHost, cfg.Bearer, realDialer.DialContext, egressWorkerCount)
	}()

	// Management (reverse relay): the same trick, a different job type — the host dispatches
	// a "run this op on the server" job onto a worker; the bastion runs it locally against its
	// OWN allowlist (the authoritative wall) and relays stdout/stderr/exit back. Default-DENY +
	// always-audited; even a compromised pod can't make this host run an ungranted op.
	go func() {
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-mgmt", cfg.HostName)
		wsTLS := &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}, ServerName: cfg.HostName}
		dialHost := func(ctx context.Context) (net.Conn, error) { return tnet.DialContext(ctx, "tcp", hostAddr) }
		// A process that died mid-extraction left one of the user's documents in
		// the context root. Nothing else would ever notice it, so sweep before
		// the lane that creates them comes up (contextextract.go).
		if n := sweepStaleScratch(cfg.contextRoot()); n > 0 {
			logf("context-prep: removed %d scratch file(s) left by a previous run\n", n)
		}
		logf("mgmt workers up — TACACS-style command lane via %s\n", wsURL)
		// The backup folder is passed as a path, not created here: it can be
		// a network mount that stopped answering, and the lane must come up
		// regardless. Each backup op checks and creates it, with a bound
		// (mgmt.go, backupRootReady).
		runMgmtWorkers(ctx, cfg.HostName, wsURL, wsTLS, dialHost, cfg.Bearer, cfg.contextRoot(), cfg.dcnDir(),
			cfg.backupRootPath(), mgmtWorkerCount)
	}()

	// Harness (harness-dispatch): the host runs its OWN agent on THIS box via the existing harness
	// container, dispatched over the same reverse relay — same image, different location. Echo mode
	// proves the lane; the real container lifecycle follows. NOT a homemade harness — the bastion runs
	// the platform's image + relays; the mgmt allowlist governs it.
	go func() {
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-harness", cfg.HostName)
		wsTLS := &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}, ServerName: cfg.HostName}
		dialHost := func(ctx context.Context) (net.Conn, error) { return tnet.DialContext(ctx, "tcp", hostAddr) }
		logf("harness workers up — host-dispatched agents land HERE via %s\n", wsURL)
		runHarnessWorkers(ctx, cfg.HostName, cfg.dcnDir(), wsURL, wsTLS, dialHost, cfg.Bearer, harnessWorkerCount)
	}()

	// Sessions (session.go): terminals on THIS box for the Terminal app. Same endpoint,
	// their OWN worker pool (hello `BEARER <bearer> lane=session`) so an open shell never holds
	// one of the harness workers for hours.
	go func() {
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-harness", cfg.HostName)
		wsTLS := &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}, ServerName: cfg.HostName}
		dialHost := func(ctx context.Context) (net.Conn, error) { return tnet.DialContext(ctx, "tcp", hostAddr) }
		srvName, _ := os.Hostname()
		logf("session workers up — terminals on this machine via %s (lane=session)\n", wsURL)
		runSessionWorkers(ctx, cfg.HostName, wsURL, wsTLS, dialHost, cfg.Bearer, sessionWorkerCount,
			sessionEnv{CtxRoot: cfg.contextRoot(), DcnDir: cfg.dcnDir(), HostName: cfg.HostName, Server: srvName})
	}()

	// 2d. Git lane: loopback HTTP proxy for git.privatae.ai only.
	//     Each local connection = one WebSocket to the host, which relays it on to
	//     the forge (gitlane.go). No credential rides this lane; git presents its
	//     own via the git-credential helper below.
	if cfg.GitProxyAddr != "" {
		if gitLn, err := net.Listen("tcp", cfg.GitProxyAddr); err != nil {
			// Optional lane: a port collision must not take the tunnel, lanes and
			// heartbeat down with it. Log and run without git.
			logf("git proxy NOT started — %s: %v (tunnel/lanes unaffected; free the port and restart)\n", cfg.GitProxyAddr, err)
		} else {
			// A revoked pairing must give its port back: closing the listener is
			// what makes runGitLane's Accept loop return.
			stopGit := context.AfterFunc(ctx, func() { _ = gitLn.Close() })
			defer stopGit()
			go func() {
				wsURL := fmt.Sprintf("wss://%s:8443/bastion-git", cfg.HostName)
				wsTLS := &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}, ServerName: cfg.HostName}
				dialHost := func(ctx context.Context) (net.Conn, error) { return tnet.DialContext(ctx, "tcp", hostAddr) }
				logf("git proxy up — http.proxy for git.privatae.ai is http://%s (privatae-bastion git-setup)\n", cfg.GitProxyAddr)
				runGitLane(gitLn, wsURL, wsTLS, dialHost, cfg.Bearer)
			}()
		}
	}

	// 3. Local control endpoint: the loopback listener the CLI verbs talk to
	//    (add-folder → /dcn/propose, git-credential → /git-credential). Guarded by
	//    a local secret so other processes on the box can't ride the tunnel.
	//    There is NO MCP relay here any more (removed deliberately): the
	//    bastion never forwards an operator client's requests to the host's
	//    /mcp. The host reaches this machine only through the lanes this box
	//    dials out and gates itself; nothing on this box drives the host.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	// git-credential helper backend: relays the host's answer (the user's platform-
	// minted forge token) to `privatae-bastion git-credential`. Local secret, then the
	// bastion bearer over the tunnel — nothing is stored on this machine.
	mux.HandleFunc("/git-credential", func(w http.ResponseWriter, r *http.Request) {
		if !uiSecretMatches(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), cfg.OperatorSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		req, err := http.NewRequest(http.MethodGet,
			fmt.Sprintf("https://%s:8443/api/network/bastions/git-credential", cfg.HostName), nil)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Bearer)
		resp, err := upstream.Do(req)
		if err != nil {
			http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	// DCN store onboarding: `privatae-bastion add-folder` lands here; the
	// draft rides the tunnel with the bearer and stays inert until the user approves
	// it in their host with their step-up code.
	mux.HandleFunc("/dcn/propose", dcnProposeLocal(upstream, cfg.HostName, cfg.Bearer, cfg.OperatorSecret))

	// 4. Liveness heartbeat — POST to the host over the tunnel (same mTLS client) so
	//    the Network app shows this bastion online and self-reports device_health
	//    (posture). The device fingerprint is NOT sent here: it is bound at
	//    pairing from the operator CSR; the reverse lanes are admitted on the bearer's
	//    binding to that cert, which the host enforces. Authed by the bearer.
	go func() {
		hbURL := fmt.Sprintf("https://%s:8443/api/network/bastions/heartbeat", cfg.HostName)
		hostname, _ := os.Hostname()
		wgPub := ""
		if raw, e := base64.StdEncoding.DecodeString(cfg.WGPrivateKey); e == nil && len(raw) == 32 {
			if pub, e2 := curve25519.X25519(raw, curve25519.Basepoint); e2 == nil {
				wgPub = base64.StdEncoding.EncodeToString(pub)
			}
		}
		beat := func() {
			payload := heartbeatPayload(cfg, dev, hostname, wgPub)
			req, err := http.NewRequest(http.MethodPost, hbURL, strings.NewReader(payload))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+cfg.Bearer)
			if resp, err := upstream.Do(req); err == nil {
				body, ok := readHeartbeatReply(resp)
				resp.Body.Close()
				if !ok {
					return // a reply past its bound is no answer (lane_bounds.go)
				}
				if resp.StatusCode < 300 {
					// last_ok per pairing (anchor.go): the anchor rotation's
					// silence path reads this — 14 days with no 2xx from the
					// anchor host lets root re-anchor without its consent.
					recordPairingOK(cfg.HostName)
				}
				// Box-wide directives (update, contain, mirror) are anchor-only
				// on an anchored box — each takes this pairing's identity and
				// refuses a member host's directive (anchor.go anchorOnly).
				maybeSelfUpdate(cfg.HostName, cfg.dcnDir(), body)      // host-directed, signed, sha256-verified, approved unless newer (update.go); no-op unless an update is pending
				maybeContain(cfg.HostName, cfg.dcnDir(), body)         // host-directed agent termination, approved; no-op unless a contain is pending
				maybeContainFindings(cfg.HostName, cfg.dcnDir(), body) // host-directed stop of a finding by fingerprint (containfinding.go)
				maybeReconcileGrants(body, cfg.dcnDir())               // drop store grants the host no longer lists (reconcile.go)
				maybeReconcileReach(body, cfg.dcnDir())                // and reach grants (service_reach.go)
				maybeReconcileCoderGrants(body, cfg.dcnDir())          // and coder grants (coder_grant.go)
				coderHeartbeatReply(cfg.HostName, body)                // coder_runs + the coder reaper (coders.go)
				maybeRotateEndpoint(body, cfg, dev)                    // host-directed WG endpoint rotation (concentrator→relay); live swap
				// Memory mirror: starts the standby + its forwarder the
				// first time the host says this box holds the mirror. No-op on
				// every other beat, and on every bastion that is not the mirror.
				maybeMirror(body, cfg, mirrorWSURL(cfg.HostName),
					&tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}, ServerName: cfg.HostName},
					func(ctx context.Context) (net.Conn, error) { return tnet.DialContext(ctx, "tcp", hostAddr) })
			}
		}
		startedAt := time.Now()
		// Host posture refreshes on its own goroutine (observe_ops.go): a beat
		// reads the last value and never waits on a probe, because a late
		// beat is what flips this box stale on the pod.
		go runPostureRefresh(ctx)
		// The Alertmanager summary (observe_pull.go): the same shape for
		// the same reason — one HTTP GET a minute against the box's own
		// neighbourhood, published for the beat to read. No-op on every box
		// whose endpoints file names no alertmanager.
		go runAlertsRefresh(ctx)
		// Second-bastion detection (otherbastions.go): same reason for the same
		// shape — the scan reads other users' home directories and the beat may
		// never wait on disk.
		go runOtherBastionRefresh(ctx)
		// The delta against the accounting (deltarun.go): the same
		// shape again, and here the reason is measured — the first pass on this
		// box costs 2.9 s because it hashes every executable once, and no beat
		// may ever wait on that.
		go runDeltaRefresh(ctx)
		beat() // first beat: flip online + bind fp now, don't wait a full interval
		// Every 60 s, and at once after a pairing on this box changes state
		// (beatnow.go), so this Host learns of it without waiting for the tick.
		// Path failover BEFORE a ticked beat: if the current relay entry has gone
		// dead (no handshake for RejectAfterTime) the beat could not reach the
		// host anyway; move to the next candidate first, no platform round trip.
		runBeatLoop(ctx, 60*time.Second, func() { maybeFailover(cfg, dev, startedAt) }, beat)
	}()

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}
	errc := make(chan error, 1)
	go func() {
		logf("privatae-bastion up — tunnel to %s, local control on http://%s\n", cfg.HostName, cfg.ListenAddr)
		logf("add folders to your network (files stay here; Privatae Host keeps only the index):\n")
		logf("  privatae-bastion add-folder ~/Documents/some-folder\n")
		errc <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		_ = srv.Close()
		return nil
	case err := <-errc:
		return err
	}
}

// unixLaneDialer is the transport of a pairing with a Host on this machine
// (pair_unix.go): a dial of the Host's lane socket, and the mutual TLS every
// lane runs inside it, exactly as over the tunnel. The Host's CA is the only
// root, its certificate must carry the pairing's host name, and this
// bastion presents its operator certificate. A pairing with no bearer gets
// no lane at all.
func unixLaneDialer(cfg *Config) (func(ctx context.Context) (net.Conn, error), *tls.Config, error) {
	if cfg.Bearer == "" {
		return nil, nil, errors.New("this pairing holds no bearer, and its lane never opens without one")
	}
	if !cleanAbsSocketPath(cfg.LaneSocket) {
		return nil, nil, fmt.Errorf("lane socket %q is not an absolute, clean path", cfg.LaneSocket)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(cfg.CACert)) {
		return nil, nil, fmt.Errorf("bad CA cert in config")
	}
	cert, err := tls.X509KeyPair([]byte(cfg.OperatorCert), []byte(cfg.OperatorKey))
	if err != nil {
		return nil, nil, fmt.Errorf("operator cert/key: %w", err)
	}
	sock := cfg.LaneSocket
	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{Timeout: egressDialTimeout}).DialContext(ctx, "unix", sock)
	}
	return dial, &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}, ServerName: cfg.HostName,
		MinVersion: tls.VersionTLS12}, nil
}

// runUnixPairing is runPairing for a pairing with a Host that has no
// platform: on this machine (unix), or in a VM on it (tcp, pair_tcp.go). It
// has no WireGuard device. Every lane that rides the tunnel to the host's
// :8443 rides the Host's lane socket or lane port instead, with the same
// URLs, the same mutual TLS and the same bearer: egress, management, the two
// parked harness workers, sessions, git, the heartbeat and what its reply
// directs. Absent, because they listen on the tunnel's stack or move the
// tunnel: the ollama, LLM and PII forwards, the service slots, and endpoint
// rotation and failover. The model servers the forwards reach are served
// over the serve lane instead (servelane.go), by service name. A unix
// pairing's coder run has its control plane on a socket in RunsDir
// (coder_socket.go), not a tunnel port; a tcp pairing has no coder runs. The
// heartbeat advertises only what runs here (agents.go, beatLanes).
func runUnixPairing(ctx context.Context, cfg *Config) error {
	logf := func(format string, a ...any) { fmt.Printf("["+cfg.HostName+"] "+format, a...) }
	if !cfg.active() {
		return errPairingNotActive
	}
	// Before any lane: model management for this pairing (modelDaemonTarget)
	// reaches only a model server on this machine, as the serve lane does.
	defer markLocalPairing(cfg.HostName)()
	dialHost, laneTLS, err := localLaneDialer(cfg)
	if err != nil {
		return err
	}
	lane := cfg.laneWhere()
	upstream := &http.Client{Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return dialHost(ctx) },
		TLSClientConfig: laneTLS.Clone(),
	}}

	// Coder runs: the box-wide loop, then a unix pairing's run sockets, which
	// are registered before the harness workers come up so a run-up that
	// arrives at once still gets its socket.
	coderInit(context.Background())
	if cfg.unixTransport() {
		setCoderSockLane(cfg.HostName, cfg.LaneSocket, dialHost, laneTLS)
		startCoderSockets(ctx, cfg.HostName, cfg.RunsDir)
	}
	go faReconcileLoop(ctx, cfg.dcnDir())
	setCtxSourcePuller(newHostSourcePuller(upstream, cfg.HostName, cfg.Bearer))

	go func() {
		realDialer := &net.Dialer{Timeout: egressDialTimeout}
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-egress", cfg.HostName)
		logf("egress workers up — outbound exits THIS machine's internet via %s on %s\n", wsURL, lane)
		runEgressWorkers(ctx, cfg.HostName, wsURL, laneTLS.Clone(), dialHost, cfg.Bearer, realDialer.DialContext, egressWorkerCount)
	}()
	// The serve lane: the model servers set on this machine, which the tunnel
	// forwards would carry, by service name and never by address.
	go func() {
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-serve", cfg.HostName)
		logf("serve workers up — the model servers set on this machine, by name, via %s on %s\n", wsURL, lane)
		runServeWorkers(ctx, cfg.HostName, cfg.dcnDir(), wsURL, laneTLS.Clone(), dialHost, cfg.Bearer, serveWorkerCount)
	}()
	go func() {
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-mgmt", cfg.HostName)
		if n := sweepStaleScratch(cfg.contextRoot()); n > 0 {
			logf("context-prep: removed %d scratch file(s) left by a previous run\n", n)
		}
		logf("mgmt workers up via %s on %s\n", wsURL, lane)
		runMgmtWorkers(ctx, cfg.HostName, wsURL, laneTLS.Clone(), dialHost, cfg.Bearer, cfg.contextRoot(), cfg.dcnDir(),
			cfg.backupRootPath(), mgmtWorkerCount)
	}()
	go func() {
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-harness", cfg.HostName)
		logf("harness workers up via %s on %s\n", wsURL, lane)
		runHarnessWorkers(ctx, cfg.HostName, cfg.dcnDir(), wsURL, laneTLS.Clone(), dialHost, cfg.Bearer, harnessWorkerCount)
	}()
	go func() {
		wsURL := fmt.Sprintf("wss://%s:8443/bastion-harness", cfg.HostName)
		srvName, _ := os.Hostname()
		logf("session workers up via %s on %s (lane=session)\n", wsURL, lane)
		runSessionWorkers(ctx, cfg.HostName, wsURL, laneTLS.Clone(), dialHost, cfg.Bearer, sessionWorkerCount,
			sessionEnv{CtxRoot: cfg.contextRoot(), DcnDir: cfg.dcnDir(), HostName: cfg.HostName, Server: srvName})
	}()
	if cfg.GitProxyAddr != "" {
		if gitLn, err := net.Listen("tcp", cfg.GitProxyAddr); err != nil {
			logf("git proxy NOT started — %s: %v (lanes unaffected; free the port and restart)\n", cfg.GitProxyAddr, err)
		} else {
			stopGit := context.AfterFunc(ctx, func() { _ = gitLn.Close() })
			defer stopGit()
			go runGitLane(gitLn, fmt.Sprintf("wss://%s:8443/bastion-git", cfg.HostName), laneTLS.Clone(), dialHost, cfg.Bearer)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/git-credential", func(w http.ResponseWriter, r *http.Request) {
		if !uiSecretMatches(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), cfg.OperatorSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		req, err := http.NewRequest(http.MethodGet,
			fmt.Sprintf("https://%s:8443/api/network/bastions/git-credential", cfg.HostName), nil)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Bearer)
		resp, err := upstream.Do(req)
		if err != nil {
			http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	mux.HandleFunc("/dcn/propose", dcnProposeLocal(upstream, cfg.HostName, cfg.Bearer, cfg.OperatorSecret))

	// The heartbeat: the same body (no WireGuard device, so no allowed IPs
	// and no endpoint) and every directive its reply carries except the two
	// that move a tunnel.
	go func() {
		hbURL := fmt.Sprintf("https://%s:8443/api/network/bastions/heartbeat", cfg.HostName)
		hostname, _ := os.Hostname()
		wgPub := ""
		if raw, e := base64.StdEncoding.DecodeString(cfg.WGPrivateKey); e == nil && len(raw) == 32 {
			if pub, e2 := curve25519.X25519(raw, curve25519.Basepoint); e2 == nil {
				wgPub = base64.StdEncoding.EncodeToString(pub)
			}
		}
		beat := func() {
			req, err := http.NewRequest(http.MethodPost, hbURL, strings.NewReader(heartbeatPayload(cfg, nil, hostname, wgPub)))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+cfg.Bearer)
			resp, err := upstream.Do(req)
			if err != nil {
				return
			}
			body, ok := readHeartbeatReply(resp)
			resp.Body.Close()
			if !ok {
				return // a reply past its bound is no answer (lane_bounds.go)
			}
			if resp.StatusCode < 300 {
				recordPairingOK(cfg.HostName)
			}
			maybeSelfUpdate(cfg.HostName, cfg.dcnDir(), body)
			maybeContain(cfg.HostName, cfg.dcnDir(), body)
			maybeContainFindings(cfg.HostName, cfg.dcnDir(), body)
			maybeReconcileGrants(body, cfg.dcnDir())
			maybeReconcileReach(body, cfg.dcnDir())
			maybeReconcileCoderGrants(body, cfg.dcnDir())
			coderHeartbeatReply(cfg.HostName, body)
			maybeMirror(body, cfg, mirrorWSURL(cfg.HostName), laneTLS.Clone(), dialHost)
		}
		go runPostureRefresh(ctx)
		go runAlertsRefresh(ctx)
		go runOtherBastionRefresh(ctx)
		go runDeltaRefresh(ctx)
		beat()
		// Every 60 s, and at once after a pairing on this box changes state
		// (beatnow.go).
		runBeatLoop(ctx, 60*time.Second, nil, beat)
	}()

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}
	errc := make(chan error, 1)
	go func() {
		logf("privatae-bastion up — lanes to %s over %s, local control on http://%s\n", cfg.HostName, lane, cfg.ListenAddr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		_ = srv.Close()
		return nil
	case err := <-errc:
		return err
	}
}

// heartbeatPayload is the body of one beat for the running pairing cfg; dev is
// that pairing's WireGuard device. A function of its own so a test can read
// what a beat would carry for a given running copy.
func heartbeatPayload(cfg *Config, dev interface{ IpcGet() (string, error) }, hostname, wgPub string) string {
	// The enforcing report gains this pairing's state and caps ceiling
	// (anchor.go), so the host sees what the box holds THIS host to.
	enforcing := buildEnforcingReport(cfg.dcnDir(), wgAllowedIPs(dev))
	for k, v := range pairingEnforcing(cfg.HostName) {
		enforcing[k] = v
	}
	return buildHeartbeatBodyOn(beatLanesFor(cfg), cfg.HostName, hostname, runtime.GOOS, clientVersion, wgPub, cfg.Fingerprint, cfg.BastionTunnelIP, cfg.Endpoint,
		rotation.isUnsaved(cfg), currentMirrorReport(cfg.HostName), enforcing,
		// Read fresh on every beat: a host paired a minute ago must
		// appear as a peer on the NEXT beat, not after a restart.
		peersFor(cfg.HostName))
}

// configureTunnelPeer gives the WireGuard device its one peer: the host's
// endpoint, with the host's tunnel alias as the only allowed address. A
// function of its own so a test can read back what a device holds after
// exactly the configuration runPairing applies.
func configureTunnelPeer(dev interface{ IpcSet(string) error }, cfg *Config) error {
	uapi, err := tunnelPeerUAPI(cfg, cfg.Endpoint, cfg.EndpointPubKey, false)
	if err != nil {
		return err
	}
	if err := dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	return nil
}

// tunnelPeerUAPI is the configuration text that gives the device its one
// peer: the host at endpoint under pubkey, with the host's tunnel alias as
// the only allowed address. Both the boot-time configuration and the live
// endpoint swap build it here. The text is one setting per line and every
// value in it comes from the host, so each is checked before it is written:
// a newline in any of them would add settings of its own.
func tunnelPeerUAPI(cfg *Config, endpoint, pubkey string, replacePeers bool) (string, error) {
	privHex, err := b64ToHex(cfg.WGPrivateKey)
	if err != nil {
		return "", fmt.Errorf("wg private key: %w", err)
	}
	pubHex, err := b64ToHex(pubkey)
	if err != nil {
		return "", fmt.Errorf("endpoint pubkey: %w", err)
	}
	if err := checkEndpoint(endpoint); err != nil {
		return "", err
	}
	hostCIDR, err := hostTunnelAllowedIP(cfg.HostTunnelIP)
	if err != nil {
		return "", err
	}
	replace := ""
	if replacePeers {
		replace = "replace_peers=true\n"
	}
	// AllowedIPs is the host's tunnel alias ONLY — the tunnel can reach nothing else.
	return fmt.Sprintf("private_key=%s\n%spublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=%s\n",
		privHex, replace, pubHex, endpoint, hostCIDR), nil
}

// checkEndpoint accepts one tunnel endpoint: an IP address and port
// ("203.0.113.7:51820", "[2001:db8::7]:51820") or an RFC 1123 host name and
// port, the port 1-65535. Anything else is refused, any space or control
// character included: the value is written into the configuration text.
func checkEndpoint(s string) error {
	bad := fmt.Errorf("the endpoint %q is not a host:port — refusing to configure the tunnel to it", s)
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return bad
		}
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 || ap.Addr().Zone() != "" || ap.Addr().IsUnspecified() {
			return bad
		}
		return nil
	}
	if strings.HasPrefix(s, "[") {
		return bad // brackets hold an IPv6 address, and this one did not parse
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || !rfc1123Host(host) || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
		return bad
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return bad
	}
	return nil
}

// checkEndpoints applies checkEndpoint to each non-empty entry: a pairing
// over a socket has no endpoint, and an empty list entry is dropped by
// candidateList.
func checkEndpoints(eps ...string) error {
	for _, e := range eps {
		if e == "" {
			continue
		}
		if err := checkEndpoint(e); err != nil {
			return err
		}
	}
	return nil
}

// rfc1123Host is a DNS host name: dot-separated labels of 1-63 letters,
// digits and hyphens, no label starting or ending with a hyphen.
func rfc1123Host(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// hostTunnelAllowedIP is the one allowed address the tunnel's peer gets: the
// host's tunnel alias as a single-address prefix (/128, or /32 for IPv4). The
// value arrives in the pairing response, and the platform sends one bare
// address there. Anything else — empty, a prefix, a zone, an address that is
// not one host's — is refused rather than narrowed: an allowed range wider
// than one address would let the tunnel carry traffic for every address in
// it, and a pairing response that asks for that is not one to act on.
func hostTunnelAllowedIP(s string) (string, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() {
		return "", fmt.Errorf("the host's tunnel address %q is not a single host address — refusing to configure the tunnel to it", s)
	}
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}

// bastionListening reports whether something is already serving a pairing's
// loopback control port — i.e. whether a bastion is RUNNING on this machine.
//
// A plain TCP connect, deliberately, because it is the one probe that works the
// same on every platform and needs no lock semantics, no pidfile and no
// privileges. It answers the question the operator actually asks.
func bastionListening(addr string) bool {
	if addr == "" {
		return false
	}
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func cmdStatus() error {
	cfgs, err := loadPairings()
	if err != nil || len(cfgs) == 0 {
		fmt.Println("not paired — run `privatae-bastion pair <token>`")
		return nil
	}
	// IS IT RUNNING, AND WHERE — the first thing status should answer and the
	// one thing it did not.
	//
	// A person with no terminal open has no way to tell where it is running.
	// On Windows that is a fair question with an uncomfortable answer:
	// relaunchAfterUpdate starts the replacement with DETACHED_PROCESS, so after
	// a self-update the bastion has NO console at all — it is serving, and there
	// is nothing on screen that says so. status printed pairings and mode and
	// never once said whether a daemon was alive.
	running := 0
	for _, cfg := range cfgs {
		if bastionListening(cfg.ListenAddr) {
			running++
		}
	}
	switch {
	case running == len(cfgs):
		fmt.Printf("RUNNING — serving %d host(s) on this machine.\n", len(cfgs))
	case running > 0:
		fmt.Printf("PARTLY RUNNING — %d of %d hosts are being served; the rest are not answering.\n",
			running, len(cfgs))
	default:
		fmt.Printf("NOT RUNNING — nothing is serving these pairings. Start it with `%s`.\n", runCommandHint())
	}
	if running > 0 && runtime.GOOS == "windows" {
		fmt.Println("  (No window? After a self-update it restarts itself detached, so it")
		fmt.Println("   has no console. Task Manager → privatae-bastion.exe is where it lives.)")
	}
	fmt.Println()
	for _, cfg := range cfgs {
		if cfg.invalid != "" {
			fmt.Printf("paired with: %s  [%s]\n  problem:  %s\n", cfg.HostName, cfg.stateName(), cfg.invalid)
			continue
		}
		live := "not answering"
		if bastionListening(cfg.ListenAddr) {
			live = "answering"
		}
		if cfg.unixTransport() {
			fmt.Printf("paired with: %s  [%s]\n  lanes:    %s (a Host on this machine)\n  runs:     %s\n  local:    http://%s  (%s)\n",
				cfg.HostName, cfg.stateName(), cfg.LaneSocket, cfg.RunsDir, cfg.ListenAddr, live)
			continue
		}
		if cfg.tcpTransport() {
			fmt.Printf("paired with: %s  [%s]\n  lanes:    %s (a Host over TCP, name %s)\n  runs:     none over TCP\n  local:    http://%s  (%s)\n",
				cfg.HostName, cfg.stateName(), cfg.LaneAddr, tcpServerName, cfg.ListenAddr, live)
			continue
		}
		fmt.Printf("paired with: %s  [%s]\n  tunnel:   %s  ->  %s  via  %s\n  local:    http://%s  (%s)\n",
			cfg.HostName, cfg.stateName(), cfg.BastionTunnelIP, cfg.HostTunnelIP, cfg.Endpoint,
			cfg.ListenAddr, live)
	}
	fmt.Printf("mode: %s\n", boxMode())
	if a := currentAnchor(); a != nil {
		fmt.Printf("anchor: %s (owner %q, since %s)\n", a.AnchorHost, a.Owner, a.ClaimedAt)
	}
	return nil
}

// ollamaModels reports whether a local ollama with the embeddings API answers
// AND which models it serves, so the bastion can advertise both the "embed"
// capability and its model list in the heartbeat — the host stores the list
// and offers it in the embedding pickers,
// so the user selects a model the box actually runs instead of guessing.
// Tries OLLAMA_ADDR, then the bastion's own tunnel IP (where the user may bind
// ollama for host reach over the WG tunnel), then loopback. Cheap (3s), per
// heartbeat. IPv6 tunnel IPs are bracketed (JoinHostPort) — the old raw
// concatenation produced an invalid authority for fd00::-style addresses.
func ollamaModels(tunnelIP string) (bool, []string) {
	addrs := []string{}
	if v := os.Getenv("OLLAMA_ADDR"); v != "" {
		addrs = append(addrs, v)
	}
	if tunnelIP != "" {
		addrs = append(addrs, net.JoinHostPort(tunnelIP, "11434"))
	}
	addrs = append(addrs, "127.0.0.1:11434")
	return ollamaModelsAt(addrs)
}

// ollamaModelsAt is ollamaModels' probe of the addresses given, in order. A
// local pairing's beat asks it about the one address its serve lane dials
// (servelane.go), so what the beat says is served is what the lane reaches.
func ollamaModelsAt(addrs []string) (bool, []string) {
	cl := &http.Client{Timeout: 3 * time.Second}
	for _, a := range addrs {
		resp, err := cl.Get("http://" + a + "/api/tags")
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var tags struct {
			Models []struct {
				Name  string `json:"name"`
				Model string `json:"model"`
			} `json:"models"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tags)
		resp.Body.Close()
		names := []string{}
		if err == nil {
			for _, m := range tags.Models {
				n := m.Name
				if n == "" {
					n = m.Model
				}
				if n != "" {
					names = append(names, n)
				}
			}
		}
		// A 200 from /api/tags is a live ollama even if the parse failed or
		// the box has no models pulled yet.
		return true, names
	}
	return false, nil
}

// llmForwardPort is the tunnel-side port the host dials to reach this box's
// OpenAI-compatible model server. Reported in the heartbeat (agents.go
// "llm_port") so the host never has to assume it — ONE definition, here.
const llmForwardPort = 18080

// openAICompatModels detects a non-ollama LLM server (llama.cpp llama-server,
// vLLM, anything OpenAI-compatible) via GET /v1/models. Only PRIVATAE_LLM_ADDR is
// probed — unlike ollama there is no conventional default port worth guessing,
// and the operator setting the env IS the opt-in. Same 200-is-alive rule as
// /api/tags: a live server with an unparseable list still counts.
func openAICompatModels() (bool, []string) {
	return openAICompatModelsAt(llmTarget())
}

// openAICompatModelsAt is openAICompatModels' probe of one address.
func openAICompatModelsAt(a string) (bool, []string) {
	if a == "" {
		return false, nil
	}
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get("http://" + a + "/v1/models")
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	names := []string{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list); err == nil {
		for _, m := range list.Data {
			if m.ID != "" {
				names = append(names, m.ID)
			}
		}
	}
	return true, names
}

// localOllamaAddr is where ollama actually listens ON THIS BOX — the proxy
// target. OLLAMA_ADDR if set, else loopback. Distinct from the tunnel IP the
// host reaches us at (that's the netstack listener below). Deliberately NOT
// PRIVATAE_LLM_ADDR-aware: a box can run ollama (embed) and an OpenAI-compat
// server (chat) side by side — :11434 stays ollama's, the OpenAI server gets
// its own tunnel-side listener (serveLLMForward, :18080).
func localOllamaAddr() string {
	if v := os.Getenv("OLLAMA_ADDR"); v != "" {
		return v
	}
	return "127.0.0.1:11434"
}

// serveLLMForward is serveOllamaForward's twin for the OpenAI-compatible
// server: host dials <bastion tunnel IP>:18080, we proxy raw TCP to
// PRIVATAE_LLM_ADDR. Only runs when the env is set (the operator's opt-in).
// The "llm-openai" heartbeat capability is the host's signal that this
// listener exists and speaks the /v1 dialect.
func serveLLMForward(ctx context.Context, self string, tnet *netstack.Net, gwIP netip.Addr) {
	target := llmTarget()
	if target == "" {
		return
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: gwIP.AsSlice(), Port: llmForwardPort})
	if err != nil {
		return
	}
	defer context.AfterFunc(ctx, func() { _ = ln.Close() })()
	refused := inferenceRefuser(self, "llm")
	for {
		in, err := ln.Accept()
		if err != nil {
			return
		}
		if refused(in) {
			continue
		}
		// A pairing whose grant NAMES models gets an HTTP-aware proxy
		// that checks the model on each request; one with a free hand gets the
		// raw splice this lane has always been (inferencefilter.go).
		go proxyInference(in, target, laneLLM, self)
	}
}

// inferenceRefuser is the accept-time gate the three inbound forwards share.
// The `inference` caps family is checked on EVERY accepted connection rather
// than once at start, because a pairing grant is re-signed while the daemon
// runs (a narrowed re-approval, a revoke) and the listener must follow it
// without a restart. capsAllow reads the grant file each call; a forward
// carries a handful of connections a minute, so that is cheap. Logged once per
// listener per refusal reason, not per connection.
func inferenceRefuser(self, lane string) func(in net.Conn) bool {
	lastWhy := ""
	return func(in net.Conn) bool {
		why := capsAllow(self, "inference")
		if why == "" {
			return false
		}
		_ = in.Close()
		if why != lastWhy {
			fmt.Printf("[%s] %s forward: %s\n", self, lane, why)
			lastWhy = why
		}
		return true
	}
}

// serveOllamaForward accepts host connections to <tunnel IP>:11434 over the
// netstack and proxies them to the local ollama, so the host's embed lane can
// reach the bastion's embedder. The Go client's tunnel is in-process (no OS WG
// adapter), so ollama can't bind the tunnel IP itself — this bridges it. ollama
// runs on its default loopback; nothing else to configure. Best-effort: if
// ollama is down, an accepted conn just fails to dial (host sees a refusal).
func serveOllamaForward(ctx context.Context, self string, tnet *netstack.Net, gwIP netip.Addr) {
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: gwIP.AsSlice(), Port: 11434})
	if err != nil {
		return
	}
	// A revoked pairing's netstack goes away with dev.Close(); closing the
	// listener too is what makes this Accept loop return instead of hanging.
	defer context.AfterFunc(ctx, func() { _ = ln.Close() })()
	refused := inferenceRefuser(self, "ollama")
	for {
		in, err := ln.Accept()
		if err != nil {
			return
		}
		if refused(in) {
			continue
		}
		// The model scope, and the store-mutating half of ollama's API
		// (/api/pull, /api/delete — the `models` family's own powers, reachable
		// through a raw splice until now). inferencefilter.go carries both.
		go proxyInference(in, localOllamaAddr(), laneOllama, self)
	}
}
