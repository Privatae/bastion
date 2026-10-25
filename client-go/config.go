package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config is what `pair` writes and `run` reads. Private keys (WG + operator) are
// the gateway's own — generated locally, never received from anyone. Only the
// signed operator cert, the CA, the bearer, and the routing come from the host.
//
// Since 0.10.0 one daemon serves MANY hosts: each pairing lives in its own file
// under pairings/<host_name>.json. The old single config.json meant pairing to a
// new host silently unpaired the previous one (re-pairing a desktop to a
// second host killed the first host's embed lane) — never again.
type Config struct {
	HostName        string   `json:"host_name"`           // <handle>.host.privatae.ai — TLS SAN + upstream URL
	WGPrivateKey    string   `json:"wg_private_key"`      // base64, gateway-generated
	BastionTunnelIP string   `json:"bastion_tunnel_ip"`   // fd00:9::a:N (this gateway's tunnel addr)
	HostTunnelIP    string   `json:"host_tunnel_ip"`      // fd00:9::e:E (the ONLY addr we may reach)
	Endpoint        string   `json:"endpoint"`            // the relay entry currently dialed (host:port)
	Endpoints       []string `json:"endpoints,omitempty"` // every relay entry this pairing is served on, preferred first (rotate.go)
	EndpointPubKey  string   `json:"endpoint_pubkey"`     // base64, the pod-Hub's WG pubkey (end-to-end peer)
	OperatorCert    string   `json:"operator_cert"`       // PEM, signed by CEIGAS from our CSR
	OperatorKey     string   `json:"operator_key"`        // PEM, gateway-generated EC key
	CACert          string   `json:"ca_cert"`             // PEM, CEIGAS CA
	Bearer          string   `json:"bearer"`              // mcp_… host-issued
	OperatorSecret  string   `json:"operator_secret"`     // local control-listener auth (CLI verbs only; never shown since the MCP relay was removed)
	Fingerprint     string   `json:"fingerprint"`         // stable device id, bound in the operator CSR at pairing
	ListenAddr      string   `json:"listen_addr"`         // loopback control port: 127.0.0.1:7878 (first pairing; next hosts get 7879, …)
	GitProxyAddr    string   `json:"git_proxy_addr"`      // loopback git proxy for this host's forge (127.0.0.1:7978, 7979, …)
	ContextRoot     string   `json:"context_root"`        // sandbox root for the context store (per host since 0.10.0)
	DCNDir          string   `json:"dcn_dir"`             // DCN state: pinned verify key + grants + audit (per host since 0.10.0)
	BackupRoot      string   `json:"backup_root"`         // where backup_fetch writes (per host; point it at a NAS mount to keep backups there)
	// State of the pairing on an ANCHORED box (anchor.go). "" or
	// "active" = serves; "pending" = written by `pair` but waiting for the anchor
	// host's grant, gets NOTHING (no tunnel, no lanes, no dirs); "revoked" = the
	// anchor dropped it, file kept for the record. Empty means active so every
	// pairing that predates the field keeps working unchanged.
	State string `json:"state,omitempty"`
	// When this host was FIRST paired here (RFC3339). Set by `pair` on a new
	// pairing and preserved across --replace, so "since" on a heartbeat is the
	// pairing's age and not the time its credentials were last rotated (the
	// file's mtime, which is what pairings from before this field fall back to).
	FirstSeen string `json:"first_seen,omitempty"`

	// How this pairing reaches its host (lane_socket.go). "" is WireGuard
	// through the relay to the host's tunnel address on :8443, which is every
	// pairing a platform redeem writes. "unix" is a Host on THIS machine with
	// no platform: the lanes dial LaneSocket, and coder runs are served as
	// sockets in RunsDir. "tcp" is a Host with no platform that shares no
	// kernel with this machine (in a VM on it, pair_tcp.go): the lanes dial
	// LaneAddr, and it has no coder runs. All four are omitted from a platform
	// pairing's file, so its bytes on disk are what they were before the
	// fields existed.
	Transport  string `json:"transport,omitempty"`
	LaneSocket string `json:"lane_socket,omitempty"`
	RunsDir    string `json:"runs_dir,omitempty"`
	LaneAddr   string `json:"lane_addr,omitempty"`

	// retired is set, under saveMu, once the run holding this copy has been
	// stopped or has ended (retireRun, run.go), and is never cleared; from then
	// on nothing is written through the copy (errRunStopped). A copy loaded
	// for anything else never has it. Unexported: never in the file.
	retired bool
	// savePending: this running copy committed a move of its entry and Hub key
	// that its file does not hold yet (rotate.go, setUnsaved; guarded by
	// rotation.mu). Unexported: never in the file.
	savePending bool
	// invalid is why loadPairings found this pairing's file unusable (an
	// endpoint that is not one host:port), naming the file; "" for a usable
	// one. Such a pairing is listed, so status shows it and unpair removes it,
	// but it never serves: active() is false. Unexported: never in the file.
	invalid string
}

const (
	pairingActive  = "active"
	pairingPending = "pending"
	pairingRevoked = "revoked"
	// pairingInvalid is reported, never stored: the file holds a value this
	// build refuses (Config.invalid).
	pairingInvalid = "invalid"

	// transportUnix is Config.Transport for a Host on this machine.
	transportUnix = "unix"
	// transportTCP is Config.Transport for a Host with no platform reached on
	// a TCP address of this machine (pair_tcp.go).
	transportTCP = "tcp"
)

// unixTransport says whether this pairing's lanes go over a local socket.
func (c *Config) unixTransport() bool { return c.Transport == transportUnix }

// tcpTransport says whether this pairing's lanes go to a Host's lane port.
func (c *Config) tcpTransport() bool { return c.Transport == transportTCP }

// localTransport: a Host with no platform, over either local transport. Its
// lanes run without a WireGuard device (run.go runUnixPairing).
func (c *Config) localTransport() bool { return c.unixTransport() || c.tcpTransport() }

// active is the ONE place the state field is interpreted: "" and "active" serve,
// anything else does not. run.go, the heartbeat and the mgmt lane all ask this.
func (c *Config) active() bool {
	return c.invalid == "" && (c.State == "" || c.State == pairingActive)
}

// stateName is the state as reported: the empty legacy value reads "active",
// and a pairing whose file is unusable reads "invalid" whatever its state.
func (c *Config) stateName() string {
	if c.invalid != "" {
		return pairingInvalid
	}
	if c.State == "" {
		return pairingActive
	}
	return c.State
}

// contextRoot returns the sandboxed root for the context store, defaulting to
// context/<host_name> under the bastion's config dir when unset (per host: one daemon
// serves many hosts, and their blobs must not mix; migrated legacy pairings carry the
// old shared path explicitly so existing blobs survive). The dir is created 0700 so
// the store stays the bastion's private state. On any failure to resolve/create it,
// returns "" — the mgmt lane treats an empty root as "context store not configured"
// and refuses ctx_* ops.
func (c *Config) contextRoot() string {
	root := c.ContextRoot
	if root == "" {
		d, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		root = filepath.Join(d, "privatae-bastion", "context", c.HostName)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return ""
	}
	return root
}

// dcnDir returns this pairing's DCN state dir (TOFU-pinned verify key + grants +
// audit), defaulting to dcn/<host_name> under the bastion's config dir. Per host by
// design: the pin is per-entity, and one shared dir would let one entity's pinned
// key verify another entity's grants — exactly the cross-host bleed multi-homing
// must not introduce. Migrated legacy pairings carry the old shared path explicitly
// so the existing pin/grants/audit survive. "" on failure; the mgmt lane refuses
// dcn_* ops on "".
func (c *Config) dcnDir() string {
	dir := c.DCNDir
	if dir == "" {
		d, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(d, "privatae-bastion", "dcn", c.HostName)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	return dir
}

// configDirPath is configDir WITHOUT the MkdirAll — the path this process
// WOULD use, asked without bringing it into existence.
//
// The singleton guard (singleton.go) needs exactly that. Calling configDir() to
// find out "which state dir am I?" creates the directory as a side effect, and
// on a second OS user that directory IS the forked state the guard exists to
// prevent: configDir() -> MkdirAll is the damage, so a check that calls it has
// already done the thing it was meant to refuse.
func configDirPath() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "privatae-bastion"), nil
}

func configDir() (string, error) {
	p, err := configDirPath()
	if err != nil {
		return "", err
	}
	return p, os.MkdirAll(p, 0o700)
}

func pairingsDir() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "pairings")
	return p, os.MkdirAll(p, 0o700)
}

// legacyConfigPath is the pre-0.10.0 single-pairing config.json, kept only so
// migrateLegacyConfig can retire it.
func legacyConfigPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// saveMu serialises every write of a pairing file within THIS process: the
// mgmt lane (grant/drop flip State), the heartbeat (endpoint rotation) and the
// supervisor all write the same files from different goroutines.
var saveMu sync.Mutex

// withPairingsLock runs fn holding both the in-process mutex and an exclusive
// flock on <configDir>/pairings.lock, so a read-modify-write of a pairing file
// cannot be lost between PROCESSES either: the daemon's endpoint save and a
// CLI `claim-anchor --rotate` or `unpair` racing on the same file was the
// lost-update this guards against. Not reentrant — nothing under it may
// call save/updateOnDisk; the locked variants exist for that.
func withPairingsLock(fn func() error) error {
	saveMu.Lock()
	defer saveMu.Unlock()
	d, err := configDir()
	if err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(d, "pairings.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close() // closing releases the lock on every platform
	if err := flockFile(lf); err != nil {
		return err
	}
	return fn()
}

// save writes the WHOLE struct. Only for callers that hold the authoritative
// copy: pair, writing a fresh file. A long-running goroutine's copy is NOT
// authoritative — it was loaded at start — so every later change goes through
// updateOnDisk, or it would write a stale State back over a pending/revoked
// flip made since.
func (c *Config) save() error {
	return withPairingsLock(c.saveLocked)
}

// saveLocked writes the file atomically (temp + fsync + rename, atomicWrite):
// a torn pairings/<host>.json fails loadPairings for EVERY pairing and cmdRun
// then refuses to start, so a crash mid-write must leave the old file whole.
func (c *Config) saveLocked() error {
	if c.HostName == "" {
		return fmt.Errorf("pairing has no host_name")
	}
	d, err := pairingsDir()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(d, c.HostName+".json"), b)
}

// errPairingGone is updateOnDisk's answer when the file is not there: the
// host was unpaired (or never paired) and a runtime save must NOT bring it
// back to life from a stale in-memory copy (a rotate/failover save inside
// the supervisor's 15 s window would have recreated an unpaired host's file
// with State active).
var errPairingGone = errors.New("pairing file is gone — not recreating it from memory")

// updateOnDisk is the read-modify-write for a running pairing, under the
// process + file lock: load the file as it is NOW, let apply change only the
// fields the caller owns, write it back atomically. The in-memory State is
// refreshed from disk so a flip by another writer is seen. Never creates a
// file: a missing or unreadable file is an error, not a fallback.
func (c *Config) updateOnDisk(apply func(disk *Config)) error {
	return c.updateOnDiskIf(func(d *Config) error { apply(d); return nil })
}

// errRunStopped is the answer to a write through the copy of a run that was
// stopped or has ended. Its heartbeat can outlive it — a beat stuck on a dead
// tunnel comes back after the run is gone, even after the same pairing was
// started again — and what that copy holds (its entry, its Hub key) is older
// than the new run's.
var errRunStopped = errors.New("this pairing's run was stopped — its copy writes nothing")

// updateOnDiskIf is updateOnDisk for a caller that may refuse once it sees the
// file: when apply returns an error nothing is written, the in-memory State is
// left as it was, and that error is returned. Nothing is written through a
// retired copy (errRunStopped); the check is under saveMu, the lock retireRun
// takes, so no write through it lands once retireRun has returned.
func (c *Config) updateOnDiskIf(apply func(disk *Config) error) error {
	return withPairingsLock(func() error {
		if c.retired {
			return errRunStopped
		}
		d, err := pairingsDir()
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(filepath.Join(d, c.HostName+".json"))
		if os.IsNotExist(err) {
			return errPairingGone
		}
		if err != nil {
			return err
		}
		disk := &Config{}
		if err := json.Unmarshal(raw, disk); err != nil || disk.HostName != c.HostName {
			return fmt.Errorf("pairing %s on disk is unreadable: %v", c.HostName, err)
		}
		if err := apply(disk); err != nil {
			return err
		}
		c.State = disk.State
		return disk.saveLocked()
	})
}

// updatePairingOnDisk is updateOnDisk for a caller that only has the host
// name (the mgmt handlers). Returns the pairing as written, or nil with
// errPairingGone when no such file exists.
//
// The copy is checked as loadPairings checks a file, so a caller that starts
// the pairing from it never serves one whose file this build refuses.
func updatePairingOnDisk(host string, apply func(disk *Config)) (*Config, error) {
	pd, err := pairingsDir()
	if err != nil {
		return nil, err
	}
	c := &Config{HostName: host}
	var out *Config
	err = c.updateOnDisk(func(d *Config) {
		apply(d)
		cp := *d
		cp.invalid = invalidReason(&cp, filepath.Join(pd, host+".json"))
		out = &cp
	})
	return out, err
}

// invalidReason is why the pairing c, read from file, is never served, naming
// the file, or "" when it may be served. It is the check the pairing response
// and the rotate directive get, for a file an older build saved from either.
func invalidReason(c *Config, file string) string {
	if err := checkEndpoints(append([]string{c.Endpoint}, c.Endpoints...)...); err != nil {
		return fmt.Sprintf("pairing %s: %v — it is not served; pair it again (`privatae-bastion pair --replace <token>`) or remove it (`privatae-bastion unpair %s`)",
			file, err, c.HostName)
	}
	return ""
}

// unpairHost tears down and deletes one pairing: its file and its grant file.
// The context store and DCN dir are the USER's data and are left in place —
// deleting a pairing must not delete what the user put on this machine.
// Root in networked mode (membership is the admin's); any user in local mode
// (there is only the user). The anchor cannot be unpaired: rotate it first,
// or the box would be anchored to a host it no longer serves.
//
// unpairNeedsRoot is a seam so both walls (needs-root, refuse-the-anchor) are
// testable whatever euid the suite runs under.
var unpairNeedsRoot = func() bool { return boxMode() == modeNetworked && !processIsRoot() }

func unpairHost(key string) (string, error) {
	if unpairNeedsRoot() {
		return "", errors.New("unpair needs root on a networked bastion — membership is the machine admin's")
	}
	cfgs, err := loadPairings()
	if err != nil {
		return "", err
	}
	c, err := findPairing(cfgs, key)
	if err != nil {
		return "", err
	}
	if c == nil {
		return "", fmt.Errorf("no pairing matches %q (paired: %s)", key, strings.Join(hostNames(cfgs), ", "))
	}
	if a := currentAnchor(); a != nil && a.AnchorHost == c.HostName {
		return "", fmt.Errorf("%s is the anchor — `claim-anchor --rotate` moves the anchor first", c.HostName)
	}
	// Stop it in THIS process if the daemon is this process; a separate daemon
	// notices the file is gone on its next supervise pass (run.go) and stops it.
	// Stopped BEFORE the lock: the pairing's heartbeat may be mid-save.
	stopPairing(c.HostName)
	err = withPairingsLock(func() error {
		pd, err := pairingsDir()
		if err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(pd, c.HostName+".json")); err != nil {
			return err
		}
		_ = os.Remove(filepath.Join(pd, c.HostName+pairingGrantSuffix))
		return nil
	})
	if err != nil {
		return "", err
	}
	// Folders the person shared with this pairing go with it: a later pairing
	// under the same name starts with none (backupstate.go).
	if err := dropSharesOf(c.HostName); err != nil {
		return c.HostName, fmt.Errorf("unpaired %s, but its shared backup folders could not be taken back: %w "+
			"(privatae-bastion backup unshare)", c.HostName, err)
	}
	return c.HostName, nil
}

func cmdUnpair(key string) error {
	host, err := unpairHost(key)
	if err != nil {
		return err
	}
	fmt.Printf("unpaired %s — its tunnel and lanes are down; the context store and DCN state stay on disk\n", host)
	return nil
}

// sinceOf is the pairing's age as reported: first_seen when the file carries
// it, else the file's mtime (pairings from before the field).
func sinceOf(c *Config) string {
	if c.FirstSeen != "" {
		return c.FirstSeen
	}
	if pd, err := pairingsDir(); err == nil {
		if st, err := os.Stat(filepath.Join(pd, c.HostName+".json")); err == nil {
			return st.ModTime().UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// migrateLegacyConfig moves a pre-0.10.0 config.json into pairings/<host_name>.json,
// making its IMPLICIT defaults EXPLICIT so existing state survives the layout change:
// the old daemon kept context blobs in <configDir>/context and the DCN pin/grants/
// audit in <configDir>/dcn, so the migrated pairing must keep pointing THERE while
// new pairings get per-host dirs. Idempotent (no-op once config.json is gone); runs
// on every command that loads pairings.
func migrateLegacyConfig() error {
	p, err := legacyConfigPath()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("legacy config.json unparsable: %w", err)
	}
	if c.HostName == "" {
		return fmt.Errorf("legacy config.json has no host_name")
	}
	d, err := configDir()
	if err != nil {
		return err
	}
	if c.ContextRoot == "" {
		c.ContextRoot = filepath.Join(d, "context")
	}
	if c.DCNDir == "" {
		c.DCNDir = filepath.Join(d, "dcn")
	}
	pd, err := pairingsDir()
	if err != nil {
		return err
	}
	target := filepath.Join(pd, c.HostName+".json")
	if _, err := os.Stat(target); err == nil {
		// A pairings/ file for this host already exists (written after the layout
		// change) — the new layout wins; just retire the legacy file.
		return os.Remove(p)
	}
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, b, 0o600); err != nil {
		return err
	}
	return os.Remove(p)
}

// loadPairings returns every paired host, sorted by host name, migrating any
// pre-0.10.0 single config.json first.
func loadPairings() ([]*Config, error) {
	if err := migrateLegacyConfig(); err != nil {
		return nil, err
	}
	pd, err := pairingsDir()
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(pd)
	if err != nil {
		return nil, err
	}
	var cfgs []*Config
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// pairings/<host>.grant.json is the anchor's signed pairing grant for that
		// host (anchor.go), kept beside the pairing it governs. It is not a
		// pairing and must never be parsed as one — a grant file read as a Config
		// would surface as a host with no name and fail the whole load.
		if strings.HasSuffix(e.Name(), pairingGrantSuffix) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(pd, e.Name()))
		if err != nil {
			return nil, err
		}
		var c Config
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("pairing %s: %w", e.Name(), err)
		}
		// One such file must not stop every other pairing, status or unpair:
		// it loads, never serves.
		c.invalid = invalidReason(&c, filepath.Join(pd, e.Name()))
		cfgs = append(cfgs, &c)
	}
	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].HostName < cfgs[j].HostName })
	return cfgs, nil
}

// hostNames lists the paired host names (for error messages).
func hostNames(cfgs []*Config) []string {
	names := make([]string, 0, len(cfgs))
	for _, c := range cfgs {
		names = append(names, c.HostName)
	}
	return names
}

// handleOf is the first DNS label of a host name — the handle the pair token names.
func handleOf(hostName string) string {
	return strings.SplitN(hostName, ".", 2)[0]
}

// pairingFor returns the existing pairing whose full host name or handle equals
// key, or nil.
func pairingFor(cfgs []*Config, key string) *Config {
	for _, c := range cfgs {
		if c.HostName == key || handleOf(c.HostName) == key {
			return c
		}
	}
	return nil
}

// findPairing resolves a user-supplied --host: exact host name or handle first,
// then a unique host-name prefix. Ambiguity is an error, no match is (nil, nil).
func findPairing(cfgs []*Config, key string) (*Config, error) {
	if c := pairingFor(cfgs, key); c != nil {
		return c, nil
	}
	var hits []*Config
	for _, c := range cfgs {
		if strings.HasPrefix(c.HostName, key) {
			hits = append(hits, c)
		}
	}
	switch len(hits) {
	case 0:
		return nil, nil
	case 1:
		return hits[0], nil
	default:
		return nil, fmt.Errorf("--host '%s' matches %d paired hosts — be more specific", key, len(hits))
	}
}

// checkPairConflict is the pre-redeem wall for cmdPair (the token is single-use, so
// this must run BEFORE redeeming): pairing an already-paired host without --replace
// is refused — the old behavior of silently overwriting the sole config is how
// a host got unpaired. --replace without an existing pairing is refused too, so
// a typo doesn't burn the token.
// removeStalePairingFile drops the pairing file (and its grant sidecar) left
// behind when a --replace renames a pairing — i.e. the host's own name changed
// between the two pairings. Narrow on purpose: unlike unpair() it does not stop
// a running pairing and does not refuse the anchor's own, because the
// replacement for that same host has already been written and the caller is
// mid-rotation. A file that is already gone is success.
func removeStalePairingFile(hostName string) error {
	if hostName == "" {
		return nil
	}
	return withPairingsLock(func() error {
		pd, err := pairingsDir()
		if err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(pd, hostName+".json")); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Remove(filepath.Join(pd, hostName+pairingGrantSuffix)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}

func checkPairConflict(cfgs []*Config, handle string, replace bool) (*Config, error) {
	existing := pairingFor(cfgs, handle)
	if existing != nil && !replace {
		return nil, fmt.Errorf("already paired with %s — this daemon serves multiple hosts, so pairing never overwrites; to rotate that host's credentials run `privatae-bastion pair --replace <token>`", existing.HostName)
	}
	if existing == nil && replace {
		return nil, fmt.Errorf("pair --replace: no existing pairing matches '%s' — pair it normally first", handle)
	}
	return existing, nil
}

// nextGitProxyAddr picks the first loopback port from 7978 up that no existing
// pairing claims: the per-host git proxy (git.privatae.ai is reachable only through
// the bastion → host → platform path). Allocated lazily for pairings that predate it.
func nextGitProxyAddr(cfgs []*Config) string {
	used := map[string]bool{}
	for _, c := range cfgs {
		used[c.GitProxyAddr] = true
		used[c.ListenAddr] = true
	}
	for port := 7978; ; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		if !used[addr] {
			return addr
		}
	}
}

// nextListenAddr picks the first loopback port from 7878 up that no existing
// pairing claims, so every host gets its own stable local control address.
func nextListenAddr(cfgs []*Config) string {
	used := map[string]bool{}
	for _, c := range cfgs {
		used[c.ListenAddr] = true
	}
	for port := 7878; ; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		if !used[addr] {
			return addr
		}
	}
}

// genSecret returns a url-safe random token used for the local operator secret
// and the stable device fingerprint.
func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
