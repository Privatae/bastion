package main

// service.go — the SERVICE SLOT: a long-running server a Host built for the
// user, running on the user's own machine.
//
// THE PRODUCT: a user asks their Host for, say, a private code server that
// mirrors the repos they name. With the user's approval the Host builds it to
// that spec and runs it HERE, on hardware the user owns, so the code never
// leaves their network. The platform does not run it and does not own its
// security posture — the user does. What this file owns is the PLACE and the
// WIRING: a container that stays up across reboots, a data directory on this
// disk, and a forward on the tunnel so the paired Host can reach it.
//
// WHY IT IS NOT A HARNESS MODE LIKE THE OTHERS. Every other harness mode is
// lifecycle-clean: it starts a container, uses it, and ALWAYS removes it
// (runContainer's deferred `rm -f`). A server that holds someone's repos is the
// opposite shape, so it gets its own verbs (up / down / status), its own
// state file, and its own caps family ("services") rather than riding
// "harness", which only ever meant "run a job here".
//
// NO NETWORK AT ALL (0.35.0). "AI on your network, not your machines": a server a
// host built here must not reach the user's machines, and the host reaches it only
// through a gated lane on this bastion. So the container runs with `--network none`
// and serves on a UNIX SOCKET in its own data directory; the forward below is the
// one way in. MEASURED on a Linux box with docker and a caps-dropped container:
//   - the default bridge reached the internet, the machine's LAN address and its
//     own services;
//   - an `--internal` network still reached the machine's own services through the
//     network's gateway (a HOST address — mirror.go measured the same);
//   - `--network none` reached nothing.
// Only a server that can listen on a unix socket can run here (Gitea and Forgejo
// can: PROTOCOL=http+unix). What a server needs from outside — mirroring the repos
// the user named — is a gated operation of this bastion, never the server's own
// network. And still no `-p`, for the mirror's reason: per-container DNAT mutates
// this machine's iptables and has dropped this bastion's own relay tunnel before.
//   - The data is ordinary files under this bastion's private config dir. It
//     is the user's copy, readable with their own tools, and it is NOT
//     encrypted by us; full-disk encryption on their machine is theirs to have.
//
// WHAT THE BOX DECIDES AND WHAT THE HOST DECIDES. The Host decides WHICH image
// and spec (its own signed grant pins the image, host-side). This box decides
// only the things that protect the machine: the name shape, that the one bind
// mount is this slot's own data dir, no new privileges, every capability
// dropped. It never runs a Host's coding harness images — the Host never sends
// them here — and nothing in this file widens what a granted image can do.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	// Advertised in the heartbeat when this pairing may use slots AND the box
	// could run one (a container runtime is installed) — the host gates its
	// "build a server here" offer on it, same honesty rule as mirrorCapability.
	serviceCapability = "services"

	serviceContainerPrefix = "privatae-svc-"
	serviceLabel           = "privatae.service"

	// Tunnel-side ports, one per slot, stable for the slot's life. Reported in
	// the heartbeat, so the host never assumes one. Clear of the inference
	// forwards (11434, 18080, 18081) and the mirror (5433).
	servicePortBase = 18100
	servicePortMax  = 18199

	// How often the forward manager re-reads the slot records. A slot brought
	// up by a harness job becomes reachable within this interval.
	serviceForwardPoll = 5 * time.Second
)

// serviceNameRe: a slot name becomes part of a container name, a directory
// name and a label, so it is held to the narrowest shape that works for all
// three. No dots, no slashes, no leading dash.
var serviceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// serviceImageRe is registry reference syntax and nothing else:
// [registry[:port]/]path[:tag][@sha256:digest]. It is what keeps an image
// argument from being one of podman's other TRANSPORTS (docker-archive:/path,
// oci-archive:, dir:, containers-storage:, docker-daemon:), which would load an
// image from a path on this machine rather than pull one.
var serviceImageRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?/)?` +
	`[a-z0-9]+([._-]+[a-z0-9]+)*(/[a-z0-9]+([._-]+[a-z0-9]+)*)*` +
	`(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

// serviceImageTransports are the non-registry sources a runtime accepts in the
// image position. "oci:foo" also parses as the image "oci" at tag "foo", so the
// syntax check alone cannot tell them apart; these prefixes are refused by name.
// ("docker:" is NOT in it: podman's registry transport is "docker://", which the
// syntax check already refuses, and a bare "docker:27" is the official docker image.)
var serviceImageTransports = []string{"docker-archive:", "oci-archive:", "oci:", "dir:",
	"containers-storage:", "docker-daemon:", "ostree:", "sif:"}

// serviceMu serialises the verbs that change slots. Harness workers run in
// parallel; without this two `up` jobs could take the same tunnel port, or
// both pass the owner check for the same name.
var serviceMu sync.Mutex

// serviceSocketRe: the socket is ONE file name directly in the slot's data dir —
// no separators, so it cannot name a path outside the directory the forward owns.
var serviceSocketRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// serviceEnvKeyRe: an environment NAME, nothing that could be read as a flag.
var serviceEnvKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// The container runtime seam. Package-level so the tests can run every verb
// without touching a real docker or podman on the machine running them.
var (
	serviceRun     = runCmd
	serviceRuntime = detectRuntime
)

// serviceRecord is one slot's desired state, written when a granted `up`
// lands and removed by `down`. The forward manager and the heartbeat read it.
type serviceRecord struct {
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	Socket     string            `json:"socket"`      // the server's unix socket, a file directly in its data dir
	DataUID    int               `json:"data_uid"`    // the server's own uid: the only peer the forward accepts
	TunnelPort int               `json:"tunnel_port"` // what the host dials on this box's tunnel IP
	DataPath   string            `json:"data_path"`   // where the data dir is mounted in the container
	Env        map[string]string `json:"env,omitempty"`
	Owner      string            `json:"owner"` // the pairing (host) that built it
	CreatedAt  string            `json:"created_at"`
}

// serviceReport is what the heartbeat carries per slot.
type serviceReport struct {
	Name       string `json:"name"`
	TunnelPort int    `json:"tunnel_port"`
	State      string `json:"state"` // running | stopped | missing
	Owner      string `json:"owner"`
}

// ── storage ─────────────────────────────────────────────────────────────────

// servicesDir is <configDir>/services — BOX-level, not per pairing: a slot is
// the user's server, and a team's hosts reach the same one through their own
// grants. Owner is recorded on each record instead.
func servicesDir() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "services")
	return p, os.MkdirAll(p, 0o700)
}

func serviceRecordPath(name string) (string, error) {
	d, err := servicesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name+".json"), nil
}

func serviceDataDir(name string) (string, error) {
	d, err := servicesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name, "data"), nil
}

func loadServiceRecord(name string) (*serviceRecord, error) {
	p, err := serviceRecordPath(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var r serviceRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// loadServiceRecords returns every readable slot record, sorted by name. A
// record that does not parse, or whose name does not match its file, is
// skipped rather than trusted.
func loadServiceRecords() []serviceRecord {
	d, err := servicesDir()
	if err != nil {
		return nil
	}
	ents, err := os.ReadDir(d)
	if err != nil {
		return nil
	}
	var out []serviceRecord
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".json") {
			continue
		}
		name := strings.TrimSuffix(n, ".json")
		if !serviceNameRe.MatchString(name) {
			continue
		}
		r, err := loadServiceRecord(name)
		if err != nil || r.Name != name {
			continue
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func saveServiceRecord(r *serviceRecord) error {
	p, err := serviceRecordPath(r.Name)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b)
}

// allocServicePort keeps an existing slot's port and otherwise takes the
// lowest free one in the range. 0 = the range is full.
func allocServicePort(name string, recs []serviceRecord) int {
	used := map[int]bool{}
	for _, r := range recs {
		if r.Name == name && r.TunnelPort >= servicePortBase && r.TunnelPort <= servicePortMax {
			return r.TunnelPort
		}
		used[r.TunnelPort] = true
	}
	for p := servicePortBase; p <= servicePortMax; p++ {
		if !used[p] {
			return p
		}
	}
	return 0
}

// ── the lane verbs ──────────────────────────────────────────────────────────

// serviceGateOp is the op the harness lane gates a service job on. Every verb
// is in the "services" family (anchor.go opFamily); an unknown verb still
// lands in that family and is refused by runService below, never by falling
// through to "harness".
func serviceGateOp(verb string) string {
	return "service:" + verb
}

// serviceArgs is what the person's approval for one service verb BINDS, in
// the order the pod derives it (the host's
// service_approval_args): the job id, the verb, the slot, the image, the
// server's port, where its data is mounted and for which uid, what it is told
// (envs as sorted k=v lines), and whether its data is deleted. A field left
// out is a field the pod could change under an approval given for another
// server. Separate from harnessArgs so every other mode's approval is
// byte-for-byte what it was.
func serviceArgs(spec harnessSpec) []string {
	envs := make([]string, 0, len(spec.Envs))
	for k, v := range spec.Envs {
		envs = append(envs, k+"="+v)
	}
	sort.Strings(envs)
	return []string{
		spec.HarnessID, spec.ServiceOp, spec.ServiceName, spec.Image,
		spec.Socket, spec.DataPath, strconv.Itoa(spec.DataUID),
		strings.Join(envs, "\n"), strconv.FormatBool(spec.Purge),
	}
}

// serviceOwnerRefusal: on an anchored box a member pairing may not replace or
// stop a slot another host built. The anchor pairing may (its user is the
// machine's admin), and an unanchored local box serves one host.
func serviceOwnerRefusal(self string, r *serviceRecord) string {
	if r == nil || r.Owner == "" || r.Owner == self {
		return ""
	}
	if why := anchorOnly(self, "changing a server another host built"); why != "" {
		return "refused: slot '" + r.Name + "' was built by " + r.Owner + "; " + why
	}
	return ""
}

func serviceFail(res map[string]interface{}, msg string) ([]byte, int) {
	res["ok"], res["error"] = false, msg
	b, _ := json.Marshal(res)
	return b, 1
}

// runService dispatches one service job. self is the pairing that sent it —
// set by handleHarnessConn, never by the host's JSON.
func runService(spec harnessSpec) ([]byte, int) {
	res := map[string]interface{}{"mode": "service", "service_op": spec.ServiceOp, "ran_on": orUnknown(hostnameSafe())}
	switch spec.ServiceOp {
	case "up":
		serviceMu.Lock()
		defer serviceMu.Unlock()
		return serviceUp(spec, res)
	case "down":
		serviceMu.Lock()
		defer serviceMu.Unlock()
		return serviceDown(spec, res)
	case "status":
		res["ok"] = true
		res["services"] = serviceReports()
		b, _ := json.Marshal(res)
		return b, 0
	case "mirror":
		return serviceMirror(spec, res)
	}
	return serviceFail(res, "service_op must be up, down, status or mirror")
}

// validateServiceSpec checks everything the box decides for itself before any
// runtime is touched. The image is the host's decision (pinned by its signed
// grant); here it only has to be one token that cannot be read as a flag.
func validateServiceSpec(spec harnessSpec) string {
	if !serviceNameRe.MatchString(spec.ServiceName) {
		return "service_name must be 1-31 of a-z, 0-9 and '-', starting with a letter or digit"
	}
	img := spec.Image
	if img == "" || !serviceImageRe.MatchString(img) {
		return "image must be a registry image reference ([registry/]name[:tag][@sha256:digest])"
	}
	for _, t := range serviceImageTransports {
		if strings.HasPrefix(img, t) {
			return "image must be pulled from a registry, not loaded from '" + strings.TrimSuffix(t, ":") + "'"
		}
	}
	if !serviceSocketRe.MatchString(spec.Socket) || spec.Socket == "." || spec.Socket == ".." {
		return "socket must be the server's unix socket file name, directly in its data dir " +
			"(e.g. gitea.sock) — the server has no network, so a socket is the only way in"
	}
	dp := spec.DataPath
	if dp == "" || !filepath.IsAbs(dp) || filepath.Clean(dp) != dp || dp == "/" || strings.Contains(dp, ":") {
		return "data_path must be a clean absolute path inside the container (not /)"
	}
	for k, v := range spec.Envs {
		if !serviceEnvKeyRe.MatchString(k) {
			return "env name '" + k + "' is not a plain variable name"
		}
		if strings.ContainsAny(v, "\x00\n") {
			return "env value for '" + k + "' contains a newline or NUL"
		}
	}
	if spec.DataUID < 1 || spec.DataUID > 65534 {
		// Non-root, and REQUIRED: the forward accepts the socket's far end only if
		// the kernel says it is this uid (servicePeerUID), so a server running as
		// root — or a file swapped for a link to a root-owned socket — is refused.
		return "data_uid must be the server's own non-root uid (1-65534)"
	}
	return ""
}

func serviceUp(spec harnessSpec, res map[string]interface{}) ([]byte, int) {
	res["service_name"] = spec.ServiceName
	if why := validateServiceSpec(spec); why != "" {
		return serviceFail(res, why)
	}
	existing, _ := loadServiceRecord(spec.ServiceName)
	if why := serviceOwnerRefusal(spec.owner, existing); why != "" {
		return serviceFail(res, why)
	}
	if runtime.GOOS != "linux" {
		// The forward can pin the server's socket only on Linux (service_sock_*.go),
		// so a server started elsewhere could never be reached — refuse, never
		// leave a container running that nothing can serve.
		return serviceFail(res, "servers run in a slot only on a Linux machine")
	}
	rt := serviceRuntime()
	res["runtime"] = rt
	if rt == "" {
		return serviceFail(res, "no container runtime (docker/podman/nerdctl) on this machine")
	}
	port := allocServicePort(spec.ServiceName, loadServiceRecords())
	if port == 0 {
		return serviceFail(res, fmt.Sprintf("every tunnel port %d-%d is taken; stop a server first", servicePortBase, servicePortMax))
	}
	data, err := serviceDataDir(spec.ServiceName)
	if err != nil {
		return serviceFail(res, "no data directory: "+err.Error())
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		return serviceFail(res, "cannot create data directory: "+err.Error())
	}
	if spec.DataUID > 0 {
		// The server inside the container runs as its own uid (a rootless
		// image); the data dir must be writable by it. Best-effort, like the
		// mirror's pgdata chown: a bastion not running as root cannot chown,
		// and the image then has to run as the bastion's own user.
		_ = os.Chown(data, spec.DataUID, spec.DataUID)
	}
	if out, err := serviceRun(10*time.Minute, rt, "pull", spec.Image); err != nil {
		return serviceFail(res, "pull failed: "+truncate(out, 220))
	}
	cname := serviceContainerPrefix + spec.ServiceName
	_, _ = serviceRun(30*time.Second, rt, "rm", "-f", cname) // replace, never duplicate
	args := []string{"run", "-d",
		"--name", cname,
		"--restart", "unless-stopped",
		"--label", serviceLabel + "=" + spec.ServiceName,
		"--network", "none",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"-v", data + ":" + spec.DataPath,
	}
	keys := make([]string, 0, len(spec.Envs))
	for k := range spec.Envs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+spec.Envs[k])
	}
	args = append(args, spec.Image)
	out, err := serviceRun(60*time.Second, rt, args...)
	if err != nil {
		return serviceFail(res, "run failed: "+truncate(out, 220))
	}
	rec := &serviceRecord{
		Name: spec.ServiceName, Image: spec.Image, Socket: spec.Socket, TunnelPort: port,
		DataPath: spec.DataPath, DataUID: spec.DataUID, Env: spec.Envs, Owner: spec.owner,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if existing != nil && existing.Owner != "" {
		rec.Owner = existing.Owner // the builder stays the builder across a re-up by the anchor
	}
	if err := saveServiceRecord(rec); err != nil {
		_, _ = serviceRun(30*time.Second, rt, "rm", "-f", cname)
		return serviceFail(res, "could not record the server, so it was removed: "+err.Error())
	}
	res["ok"] = true
	res["container"] = shortID(out)
	res["tunnel_port"] = port
	res["data_dir"] = data
	b, _ := json.Marshal(res)
	return b, 0
}

func serviceDown(spec harnessSpec, res map[string]interface{}) ([]byte, int) {
	res["service_name"] = spec.ServiceName
	if !serviceNameRe.MatchString(spec.ServiceName) {
		return serviceFail(res, "service_name is not a valid slot name")
	}
	existing, err := loadServiceRecord(spec.ServiceName)
	if err != nil {
		return serviceFail(res, "no server named '"+spec.ServiceName+"' on this machine")
	}
	if why := serviceOwnerRefusal(spec.owner, existing); why != "" {
		return serviceFail(res, why)
	}
	// The container must be GONE before the record is: a record removed while
	// its container runs (--restart unless-stopped) is a server nobody can see
	// in status, the heartbeat or the forwards, still holding the user's data.
	// So a failed removal fails the job and keeps the record.
	rt := serviceRuntime()
	if rt == "" {
		return serviceFail(res, "no container runtime answers on this machine, so the server cannot be confirmed stopped; nothing was changed")
	}
	cname := serviceContainerPrefix + spec.ServiceName
	if out, err := serviceRun(30*time.Second, rt, "rm", "-f", cname); err != nil {
		// Only a runtime that POSITIVELY says the container does not exist lets
		// the record go. A daemon that times out or errors is not proof of
		// absence, and dropping the record on a guess is how a server keeps
		// running unseen.
		if !serviceContainerGone(rt, spec.ServiceName) {
			return serviceFail(res, "could not stop the server; it may still be there: "+truncate(out, 220))
		}
	}
	p, _ := serviceRecordPath(spec.ServiceName)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return serviceFail(res, "container removed but its record could not be: "+err.Error())
	}
	// A stopped server's reach grants go with it, for EVERY host: a grant binds
	// a server by its slot name, so one left behind would open the next server
	// built under that name — possibly by another host — to whoever held it.
	res["reach_grants_dropped"] = reachDropForSlot(spec.ServiceName)
	// The data stays unless the user's request says purge: it is their repos.
	if spec.Purge {
		d, err := servicesDir()
		if err == nil {
			err = os.RemoveAll(filepath.Join(d, spec.ServiceName))
		}
		if err != nil {
			// The server is stopped and unrecorded; only the deletion failed
			// (a rootless runtime can leave files owned by a subordinate uid).
			res["purged"] = false
			res["purge_error"] = err.Error()
			return serviceFail(res, "the server is stopped but its data could not all be deleted: "+err.Error())
		}
		res["purged"] = true
	}
	res["ok"] = true
	b, _ := json.Marshal(res)
	return b, 0
}

// serviceContainerGone is true only when the runtime answers that the slot's
// container does not exist ("No such container" / "no such object" /
// "not found"). Any other failure is unknown, never absence.
func serviceContainerGone(rt, name string) bool {
	out, err := serviceRun(10*time.Second, rt, "inspect", serviceContainerPrefix+name)
	if err == nil {
		return false
	}
	o := strings.ToLower(out)
	return strings.Contains(o, "no such") || strings.Contains(o, "not found")
}

// serviceSpecRefusal is the check a service job must pass BEFORE the lane
// spends the person's approval on it (harness.go handleHarnessConn): a request
// the box would refuse anyway must not use up an approval first.
func serviceSpecRefusal(spec harnessSpec) string {
	switch spec.ServiceOp {
	case "up":
		return validateServiceSpec(spec)
	case "down":
		if !serviceNameRe.MatchString(spec.ServiceName) {
			return "service_name is not a valid slot name"
		}
	case "status":
	case "mirror":
		if !serviceNameRe.MatchString(spec.ServiceName) {
			return "service_name is not a valid slot name"
		}
		if strings.TrimSpace(spec.PushToken) == "" {
			return "push_token (the host's credential for its own server) is required"
		}
	default:
		return "service_op must be up, down, status or mirror"
	}
	return ""
}

// serviceState asks the runtime whether a slot's container is running.
func serviceState(rt, name string) string {
	if rt == "" {
		return "missing"
	}
	out, err := serviceRun(10*time.Second, rt, "inspect", "-f", "{{.State.Running}}", serviceContainerPrefix+name)
	if err != nil {
		return "missing"
	}
	if strings.TrimSpace(out) == "true" {
		return "running"
	}
	return "stopped"
}

func serviceReports() []serviceReport {
	recs := loadServiceRecords()
	out := make([]serviceReport, 0, len(recs))
	if len(recs) == 0 {
		return out
	}
	rt := serviceRuntime()
	for _, r := range recs {
		out = append(out, serviceReport{Name: r.Name, TunnelPort: r.TunnelPort, State: serviceState(rt, r.Name), Owner: r.Owner})
	}
	return out
}

// ── the forward ─────────────────────────────────────────────────────────────

// serviceUpstream resolves where a slot answers: its unix socket in the slot's
// own data dir. It answers only while the container is RUNNING WITH NO NETWORK,
// checked per connection: a container that somehow has a network (a record
// from a build before 0.35.0, or one changed by hand) is not served, because
// the forward would then be the door into a server that can reach the user's
// machines.
func serviceUpstream(name string) (string, bool) {
	r, err := loadServiceRecord(name)
	if err != nil || !serviceSocketRe.MatchString(r.Socket) || r.DataUID < 1 {
		return "", false
	}
	rt := serviceRuntime()
	if rt == "" {
		return "", false
	}
	if serviceNetworkMode(rt, name) != "none" {
		return "", false
	}
	data, err := serviceDataDir(name)
	if err != nil {
		return "", false
	}
	sock := filepath.Join(data, r.Socket)
	// The container OWNS its data dir, so it can put anything at this name. It
	// must be a socket itself — Lstat, so a symlink is seen as a symlink and
	// refused rather than followed to, say, the container runtime's own socket.
	// (The name is re-checked after connect by the peer's uid, which is what
	// closes the swap between this check and the dial.)
	if fi, err := os.Lstat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return "", false
	}
	return sock, true
}

// serviceNetworkMode is the slot container's network mode as the runtime
// reports it ("none" for an isolated slot), or "" when it cannot be read.
func serviceNetworkMode(rt, name string) string {
	out, err := serviceRun(10*time.Second, rt, "inspect", "-f", "{{.HostConfig.NetworkMode}}",
		serviceContainerPrefix+name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// spliceUnix carries one accepted tunnel connection to a slot's unix socket —
// only when the process on the far end is the server's own uid. The bastion
// often runs as root and dials this path inside a directory the container
// controls; without this check a socket swapped (or linked) to a root-owned
// one, like the container runtime's, would connect the host to THAT.
func spliceUnix(in net.Conn, sock string, wantUID int) {
	defer in.Close()
	if wantUID < 1 {
		return
	}
	out, err := serviceDialSocket(sock, 5*time.Second)
	if err != nil {
		return
	}
	defer out.Close()
	if uid, err := servicePeerUID(out); err != nil || int(uid) != wantUID {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, in); done <- struct{}{} }()
	go func() { _, _ = io.Copy(in, out); done <- struct{}{} }()
	<-done
}

// serveServiceForwards keeps one tunnel listener per slot for this pairing:
// the host dials <bastion tunnel IP>:<tunnel_port> and is spliced to the
// slot's container. It re-reads the records every serviceForwardPoll, so a
// slot brought up by a harness job appears and one taken down disappears
// without a restart. The "services" family is checked on EVERY accepted
// connection, same as the inference forwards: a grant can be narrowed or
// revoked while the daemon runs.
func serveServiceForwards(ctx context.Context, self, dir string, tnet *netstack.Net, gwIP netip.Addr) {
	type slot struct {
		port int
		ln   net.Listener
	}
	var mu sync.Mutex
	live := map[string]*slot{}
	closeAll := func() {
		mu.Lock()
		defer mu.Unlock()
		for n, s := range live {
			_ = s.ln.Close()
			delete(live, n)
		}
	}
	defer closeAll()
	var lastWhy string
	refused := func(in net.Conn, slot string) bool {
		// Two walls, both on EVERY connection: the pairing holds the `services`
		// family, AND a verified reach grant for THIS server names THIS host
		// (service_reach.go). Default-deny — no grant, no connection.
		why := capsAllow(self, serviceCapability)
		if why == "" {
			why = serviceReachAllowed(dir, self, slot)
		}
		if why == "" {
			return false
		}
		_ = in.Close()
		mu.Lock()
		if why != lastWhy {
			fmt.Printf("[%s] service forward: %s\n", self, why)
			lastWhy = why
		}
		mu.Unlock()
		return true
	}
	reconcile := func() {
		want := map[string]int{}
		for _, r := range loadServiceRecords() {
			want[r.Name] = r.TunnelPort
		}
		mu.Lock()
		defer mu.Unlock()
		for n, s := range live {
			if p, ok := want[n]; !ok || p != s.port {
				_ = s.ln.Close()
				delete(live, n)
			}
		}
		for n, p := range want {
			if _, ok := live[n]; ok {
				continue
			}
			ln, err := tnet.ListenTCP(&net.TCPAddr{IP: gwIP.AsSlice(), Port: p})
			if err != nil {
				continue // retried next poll
			}
			live[n] = &slot{port: p, ln: ln}
			go func(name string, ln net.Listener) {
				for {
					in, err := ln.Accept()
					if err != nil {
						return
					}
					if refused(in, name) {
						continue
					}
					up, ok := serviceUpstream(name)
					r, rerr := loadServiceRecord(name)
					if !ok || rerr != nil {
						_ = in.Close()
						continue
					}
					go spliceUnix(in, up, r.DataUID)
				}
			}(n, ln)
		}
	}
	reconcile()
	t := time.NewTicker(serviceForwardPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reconcile()
		}
	}
}

// servicesCapable is the heartbeat's honesty check: this pairing may use
// slots AND the machine could run one.
func servicesCapable(self string) bool {
	// Linux only: the forward pins the server's socket inode through
	// /proc/self/fd (service_sock_linux.go); elsewhere it refuses, so it is
	// never advertised.
	return runtime.GOOS == "linux" && capsAllow(self, serviceCapability) == "" && serviceRuntime() != ""
}
