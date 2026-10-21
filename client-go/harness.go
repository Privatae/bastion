package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const harnessWorkerCount = 2

// harnessSpec is the H-frame job: run a harness container locally + dispatch the prompt to it.
//   - mode "echo": no container — prove the lane end-to-end.
//   - mode "container": the lifecycle engine — pull/start the image, wait for its HTTP port,
//     stop + remove it, report metered wall-time. Image-generic; the host passes image + port.
//   - mode "worktree" / "git" add clone-in -> POST /run -> collect-out (the real harness contract), keyed server>worktree>Gitea.
type harnessSpec struct {
	HarnessID   string   `json:"harness_id"`
	Prompt      string   `json:"prompt"`
	Image       string   `json:"image"`
	Mode        string   `json:"mode"`
	Worktree    string   `json:"worktree"`
	WorktreeB64 string   `json:"worktree_b64"` // mode=worktree: the worktree tar in (clone-in)
	RepoURL     string   `json:"repo_url"`     // mode=git: clone URL carrying the per-run minted token
	Branch      string   `json:"branch"`       // mode=git: push target branch
	Command     []string `json:"command"`      // the stand-in agent command (legacy); the image's /run is driven instead
	AgentCreds  string   `json:"agent_creds"`  // the agent's OWN credential (claudeAiOauth JSON, pulled from the entity vault), delivered for THIS run only — mounted as the harness creds file, deleted after, never baked into the image
	Port        int      `json:"port"`
	MaxMinutes  int      `json:"max_minutes"`
	// Repo is the repository a mode=git run clones, as "forge-host/owner/name";
	// RepoURL above carries a per-run minted token and so differs on every
	// run. The approval binds this, forge included, so the person taps once
	// for a run the host may have to re-mint the URL for — and a URL on any
	// other server does not pass as the same repository.
	Repo string `json:"repo,omitempty"`
	// Approval: on an ANCHORED box a run is a write — a container, a clone, a
	// push — and spends the person's approval (writes.go), bound to the
	// harness id, mode, image, repo and branch of THIS run.
	Approval string `json:"approval,omitempty"`
	// mode=lab (the Lab Harness): build a sealed lab of N hardened
	// hosts on THIS box's lab cluster, put the app under test in each, drive the test runbook with
	// ONE coding-harness pod inside the lab, collect, tear down. Only a lab bastion answers it.
	Hosts  int               `json:"hosts"`  // how many lab hosts (Entity CRs) to build
	Envs   map[string]string `json:"envs"`   // app settings written to every lab host (.env)
	Tests  []string          `json:"tests"`  // the runbook: ordered steps, one governed /run each
	Engine string            `json:"engine"` // which coding harness drives the tests (PRIVATAE_APP_ID)
	Gate   string            `json:"gate"`   // "auto" (typed deliberately) | "ask" (the App lane; not built yet)
	App    string            `json:"app"`    // project name the worktree lands under in each host
	// mode=service (service.go): a long-running server in this machine's slot.
	// Reuses Image, Port and Envs above.
	ServiceOp   string `json:"service_op"`   // up | down | status
	ServiceName string `json:"service_name"` // the slot's name on this machine
	DataPath    string `json:"data_path"`    // where the slot's data dir is mounted in the container
	DataUID     int    `json:"data_uid"`     // uid the data dir is handed to (a rootless image's user); 0 = leave
	Purge       bool   `json:"purge"`        // down: also delete the slot's data (default keeps it)
	Socket      string `json:"socket"`       // up: the server's unix socket file in its data dir (it has no network)

	// mirror (0.38.0): the host's credential for ITS OWN server, used for the
	// push into it and never stored, logged or bound into an approval.
	PushToken string `json:"push_token"`

	// mode=coder (coders.go): one sealed coding run per container. Reuses
	// Engine, Image and MaxMinutes above.
	CoderOp    string            `json:"coder_op"`    // run-up | run-down | run-status
	RunID      string            `json:"run_id"`      // the kernel's run id, also the container's name
	UID        int               `json:"uid"`         // the engine's uid (10001-10099)
	CredsDir   string            `json:"creds_dir"`   // where the engine reads its credential, /home/privatae/.<name>
	Creds      map[string]string `json:"creds"`       // file name -> contents, this run only, never logged
	ControlCap string            `json:"control_cap"` // the run's control capability, handed to the harness as its cap
	Pull       *coderPull        `json:"pull"`        // the per-run registry credential

	// owner is the pairing this job arrived on, set by handleHarnessConn from
	// the lane itself. Unexported so no JSON from the host can set it.
	owner string
	// runImage is what a coder run's container starts from: Image, or the
	// local image ID it resolved to (coderLocalImage). Never from JSON.
	runImage string
	// dcnDir is that pairing's grant directory (reach grants live there).
	dcnDir string
}

// runHarnessWorkers opens a pool of worker WebSockets to the host's /bastion-harness lane and serves
// one harness job per worker, reconnecting after each. Mirrors runMgmtWorkers: the host can't reach
// the bastion's tunnel IP, so the bastion dials out to the host and parks until a harness job arrives.
//
// pctx is the pairing's context (run.go): a revoked pairing's workers exit
// instead of re-dialing a closed tunnel for the life of the process.
func runHarnessWorkers(pctx context.Context, self, dcnDir string, wsURL string, tlsCfg *tls.Config,
	dialHost func(ctx context.Context) (net.Conn, error), bearer string, n int) {
	dialer := &websocket.Dialer{
		NetDialContext:   func(ctx context.Context, network, addr string) (net.Conn, error) { return dialHost(ctx) },
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 20 * time.Second,
	}
	for i := 0; i < n; i++ {
		go func() {
			for pctx.Err() == nil {
				ctx, cancel := context.WithTimeout(pctx, 25*time.Second)
				ws, _, err := dialer.DialContext(ctx, wsURL, http.Header{})
				cancel()
				if err != nil {
					sleepCtx(pctx, 3*time.Second)
					continue
				}
				if err := ws.WriteMessage(websocket.TextMessage, []byte("BEARER "+bearer)); err != nil {
					_ = ws.Close()
					sleepCtx(pctx, time.Second)
					continue
				}
				stopKA := armWSKeepalive(ws) // ping/read-deadline: a dead tunnel unblocks the park
				unpark := context.AfterFunc(pctx, func() { _ = ws.Close() })
				handleHarnessConn(ws, self, dcnDir) // blocks until a job, serves it, then returns
				unpark()
				stopKA()
				_ = ws.Close()
			}
		}()
	}
}

// harnessArgs is what the approval for one run binds — EVERYTHING the run
// acts on, in the order the pod derives it (the host's
// harness_approval_args): the harness id, mode, image, repo NAME and branch;
// the prompt; the command; a digest of the worktree tar; the port and the
// minute cap; and the lab fields. A field left out of this list is a field
// the pod could change under an approval the person gave for another run.
func harnessArgs(spec harnessSpec) []string {
	envs := make([]string, 0, len(spec.Envs))
	for k, v := range spec.Envs {
		envs = append(envs, k+"="+v)
	}
	sort.Strings(envs)
	wt := ""
	if spec.WorktreeB64 != "" {
		sum := sha256.Sum256([]byte(spec.WorktreeB64))
		wt = hex.EncodeToString(sum[:])
	}
	return []string{
		spec.HarnessID, spec.Mode, spec.Image, spec.Repo, spec.Branch,
		spec.Prompt, strings.Join(spec.Command, "\x00"), wt,
		strconv.Itoa(spec.Port), strconv.Itoa(spec.MaxMinutes),
		strconv.Itoa(spec.Hosts), strings.Join(envs, "\n"), strings.Join(spec.Tests, "\n"),
		spec.Engine, spec.Gate, spec.App,
	}
}

// repoNameOf is "host/owner/name" from a clone URL — the forge and the path,
// without the userinfo (the per-run minted token), the scheme or ".git". The
// forge is part of it: a name alone would let a URL on any server pass as
// the repository the person approved, and the run clones from and pushes to
// that server with the agent's own credentials mounted.
func repoNameOf(repoURL string) string {
	u, err := url.Parse(strings.TrimSpace(repoURL))
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path == "" {
		return ""
	}
	return strings.ToLower(u.Host) + "/" + strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
}

// harnessGate: "" to run, else the refusal. Anchored boxes only. The repo
// the run would clone and push is checked against the name the approval
// bound, so an approval for owner/site cannot run against another remote.
// A quarantined pairing spends nothing here, and a refusal on this lane
// counts as a strike the way one on the management lane does.
func harnessGate(self, dcnDir string, spec harnessSpec) string {
	if currentAnchor() == nil {
		return ""
	}
	// Coder runs (coders.go) never spend a per-run approval: the person
	// approved a standing coder grant once (coder_grant.go).
	if spec.Mode == "coder" {
		return coderGate(self, dcnDir, spec)
	}
	why := ""
	op := "harness:run"
	if spec.Mode == "service" {
		op = serviceGateOp(spec.ServiceOp)
		// `status` is a READ: it names the slots and changes nothing, so it
		// spends no approval and, like every read, still answers a pairing
		// whose writes are quarantined (quarantine.go: "Reads still answer").
		if spec.ServiceOp == "status" {
			return ""
		}
		// `mirror` is STANDING WORK under the mirror list the person approved in
		// the reach grant (service_mirror.go): no per-run approval, but it
		// changes the server, so a quarantined pairing's writes stay closed.
		if spec.ServiceOp == "mirror" {
			if until := quarantinedUntil(self, time.Now()); !until.IsZero() {
				return quarantineRefusal(until)
			}
			return ""
		}
	}
	if until := quarantinedUntil(self, time.Now()); !until.IsZero() {
		why = quarantineRefusal(until)
	} else if spec.Mode == "service" {
		// The service slot (service.go). `up` and `down` change this machine
		// and spend an approval bound to exactly what they would do
		// (serviceArgs): which server, which image, which ports, where its
		// data is mounted, what it is told, and whether its data is deleted.
		hn, _ := os.Hostname()
		if _, err := boxConsume(dcnDir, spec.Approval, mgmtOpPurpose(op, hn, serviceArgs(spec))); err != nil {
			why = "refused: " + op + " changes this machine and " + err.Error()
		}
	} else if spec.Mode == "git" && (spec.Repo == "" || repoNameOf(spec.RepoURL) == "" ||
		repoNameOf(spec.RepoURL) != spec.Repo) {
		// A git run names a repository on a forge — never blank, never a local
		// path or a file: URL (repoNameOf is "" for those), and the URL it
		// clones must be that repository. A blank on both sides compared
		// equal once, and a local path passed as the approved repository.
		why = "refused: harness:run — the repository the run would clone (" + orUnknown(repoNameOf(spec.RepoURL)) +
			") is not the one the approval names (" + orUnknown(spec.Repo) + ")"
	} else {
		hn, _ := os.Hostname()
		if _, err := boxConsume(dcnDir, spec.Approval, mgmtOpPurpose("harness:run", hn, harnessArgs(spec))); err != nil {
			why = "refused: harness:run changes this machine and " + err.Error()
		}
	}
	if why != "" {
		noteRefusal(self, op, why, refusalCounts(op, why), time.Now())
	}
	return why
}

// handleHarnessConn serves ONE harness job: read the H frame, run it, reply J(result) + X(exit).
// self is the pairing this lane belongs to: on an anchored box a member's
// harness jobs are refused unless its pairing grant carries the "harness" cap
// (anchor.go capsAllow) — the lane runs containers on this machine, and the
// mgmt op table never sees it, so the gate has to sit here.
//
// An S frame (a terminal session) belongs on a SESSION worker (session.go, hello line
// `BEARER <bearer> lane=session`); a harness worker refuses it so a shell can never hold
// an agent worker for hours.
func handleHarnessConn(ws *websocket.Conn, self, dcnDir string) {
	mt, data, err := ws.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || len(data) == 0 {
		return
	}
	if data[0] == 'S' {
		sendHarness(ws, 'E', []byte("this is a harness worker; sessions go to a worker that said lane=session\n"))
		sendHarnessExit(ws, 1)
		return
	}
	if data[0] != 'H' {
		return
	}
	// The gate depends on WHAT is asked: a service-slot job (service.go) is the
	// "services" family, every other mode is "harness". So the spec is parsed
	// first — but a spec that does not parse is still gated as harness:run
	// before its parse error is reported, exactly as it always was, so an
	// unauthorized pairing learns nothing from a malformed frame.
	var spec harnessSpec
	perr := json.Unmarshal(data[1:], &spec)
	gateOp := "harness:run"
	if perr == nil && spec.Mode == "service" {
		gateOp = serviceGateOp(spec.ServiceOp)
	}
	if perr == nil && spec.Mode == "coder" {
		gateOp = coderGateOp
	}
	if why := capsAllow(self, gateOp); why != "" {
		b, _ := json.Marshal(map[string]any{"ok": false, "error": why})
		sendHarness(ws, 'J', b)
		sendHarnessExit(ws, 126)
		return
	}
	if perr != nil {
		sendHarness(ws, 'J', []byte(`{"ok":false,"error":"bad harness spec"}`))
		sendHarnessExit(ws, 126)
		return
	}
	// A service request the box would refuse anyway is refused BEFORE the
	// write gate below spends the person's approval on it.
	if spec.Mode == "service" {
		if why := serviceSpecRefusal(spec); why != "" {
			b, _ := json.Marshal(map[string]any{"ok": false, "mode": "service", "error": why})
			sendHarness(ws, 'J', b)
			sendHarnessExit(ws, 1)
			return
		}
	}
	if spec.Mode == "coder" {
		if why := coderSpecRefusal(spec); why != "" {
			b, _ := json.Marshal(map[string]any{"ok": false, "mode": "coder", "coder_op": spec.CoderOp, "error": why})
			sendHarness(ws, 'J', b)
			sendHarnessExit(ws, 1)
			return
		}
	}
	// THE WRITE GATE for this lane (writes.go): the caps ceiling above says the
	// pairing may be asked; on an anchored box the run itself spends the
	// person's approval, bound to what this run would do. A local box keeps
	// the pairing as its authorization.
	if why := harnessGate(self, dcnDir, spec); why != "" {
		b, _ := json.Marshal(map[string]any{"ok": false, "error": why})
		sendHarness(ws, 'J', b)
		sendHarnessExit(ws, 126)
		return
	}
	spec.owner = self
	spec.dcnDir = dcnDir
	// Run the (possibly slow) job in a goroutine and keep the lane warm: a read-pump auto-pongs the
	// host's keepalive pings + notices a close, and an O-frame ticker keeps traffic flowing — so
	// neither the WS ping-timeout nor the tunnel's TCP idle-timeout drops a long container/agent run.
	// (One reader + one writer = gorilla-safe: the pump only reads, this loop only writes.)
	type harnessRes struct {
		body []byte
		code int
	}
	fmt.Printf("harness: job %s mode=%s image=%s\n", spec.HarnessID, spec.Mode, spec.Image)
	resCh := make(chan harnessRes, 1)
	go func() { b, c := runHarness(spec); resCh <- harnessRes{b, c} }()
	closed := make(chan struct{})
	go func() {
		for {
			if _, _, err := ws.ReadMessage(); err != nil { // host close or drop
				close(closed)
				return
			}
		}
	}()
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case r := <-resCh:
			fmt.Printf("harness: job %s done exit=%d\n", spec.HarnessID, r.code)
			sendHarness(ws, 'J', r.body)
			sendHarnessExit(ws, r.code)
			return
		case <-ticker.C:
			sendHarness(ws, 'O', []byte("running\n")) // keepalive for long ops (worktree/git/lab runs)
		case <-closed:
			return // peer/tunnel gone; runHarness's deferred cleanup still removes the container
		}
	}
}

func runHarness(spec harnessSpec) ([]byte, int) {
	switch spec.Mode {
	case "echo", "":
		b, _ := json.Marshal(map[string]interface{}{
			"ok": true, "harness": spec.HarnessID, "mode": "echo",
			"echo": spec.Prompt, "ran_on": orUnknown(hostnameSafe()),
		})
		return b, 0
	case "container":
		return runContainer(spec)
	case "worktree":
		return runWorktree(spec)
	case "git":
		return runGit(spec)
	case "lab":
		return runLab(spec)
	case "service":
		return runService(spec)
	case "coder":
		return runCoder(spec)
	default:
		b, _ := json.Marshal(map[string]interface{}{"ok": false, "error": "mode '" + spec.Mode + "' not implemented"})
		return b, 1
	}
}

// runContainer is the lifecycle engine: detect a runtime, pull + start the image, wait for its
// HTTP port to answer, then ALWAYS stop + remove it (lifecycle-clean) and report metered wall-time.
// The image runs on THIS box's OCI boundary — the bastion manages the lifecycle, it is not the agent.
func runContainer(spec harnessSpec) ([]byte, int) {
	res := map[string]interface{}{"image": spec.Image, "ran_on": orUnknown(hostnameSafe()), "mode": "container"}
	rt := detectRuntime()
	res["runtime"] = rt
	if rt == "" {
		res["ok"], res["error"] = false, "no container runtime (docker/podman/nerdctl) on this host"
		b, _ := json.Marshal(res)
		return b, 1
	}
	if spec.Image == "" {
		res["ok"], res["error"] = false, "image required for mode=container"
		b, _ := json.Marshal(res)
		return b, 1
	}
	port := spec.Port
	if port == 0 {
		port = 80
	}
	start := time.Now()
	if out, err := runCmd(150*time.Second, rt, "pull", spec.Image); err != nil {
		res["ok"], res["error"] = false, "pull failed: "+truncate(out, 220)
		b, _ := json.Marshal(res)
		return b, 1
	}
	res["pulled_s"] = round2(time.Since(start).Seconds())
	// No -p (port publish): publishing adds per-container DNAT that mutates the host's iptables and
	// drops the bastion's own WG/Cilium relay tunnel. Reach the container on its bridge IP instead —
	// same result, no host-network mutation, and portable across any docker/podman bridge.
	out, err := runCmd(30*time.Second, rt, "run", "-d", spec.Image)
	if err != nil {
		res["ok"], res["error"] = false, "run failed: "+truncate(out, 220)
		b, _ := json.Marshal(res)
		return b, 1
	}
	cid := strings.TrimSpace(out)
	res["container"] = shortID(cid)
	defer func() { _, _ = runCmd(20*time.Second, rt, "rm", "-f", cid) }() // lifecycle-clean: always remove

	reachable, code := false, 0
	if ip := containerIP(rt, cid); ip != "" {
		res["ip"] = ip
		reachable, code = waitReachable("http://"+ip+":"+strconv.Itoa(port)+"/", 30*time.Second)
	}
	res["reachable"], res["http_code"] = reachable, code
	res["meter_s"] = round2(time.Since(start).Seconds())
	res["ok"] = reachable
	b, _ := json.Marshal(res)
	if reachable {
		return b, 0
	}
	return b, 1
}

// runWorktree (clone-in/collect-out): receive the worktree tar over the lane, run a container
// with it mounted at /work and drive the image's real harness agent against it,
// then send the modified worktree back. Only a bind mount — no -p, no port — so the WG relay is
// untouched. runGit (server>worktree>Gitea) clones the worktree from Gitea instead.
func runWorktree(spec harnessSpec) ([]byte, int) {
	res := map[string]interface{}{"mode": "worktree", "ran_on": orUnknown(hostnameSafe())}
	rt := detectRuntime()
	res["runtime"] = rt
	if rt == "" {
		res["ok"], res["error"] = false, "no container runtime"
		b, _ := json.Marshal(res)
		return b, 1
	}
	if spec.Image == "" {
		res["ok"], res["error"] = false, "image required for mode=worktree"
		b, _ := json.Marshal(res)
		return b, 1
	}
	tarIn, err := base64.StdEncoding.DecodeString(spec.WorktreeB64)
	if err != nil {
		res["ok"], res["error"] = false, "bad worktree_b64: "+err.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	dir, err := os.MkdirTemp("", "harness-wt-")
	if err != nil {
		res["ok"], res["error"] = false, "tempdir: "+err.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	defer os.RemoveAll(dir) // collect-out is over the lane; the box keeps nothing
	if err := extractTar(tarIn, dir); err != nil {
		res["ok"], res["error"] = false, "extract: "+err.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	start := time.Now()
	if out, err := runCmd(150*time.Second, rt, "pull", spec.Image); err != nil {
		res["ok"], res["error"] = false, "pull failed: "+truncate(out, 220)
		b, _ := json.Marshal(res)
		return b, 1
	}
	maxMin := spec.MaxMinutes
	if maxMin <= 0 {
		maxMin = 10
	}
	// Drive the harness image's REAL agent (its /run sidecar) with the prompt. The agent works
	// cwd in the bind-mounted /work, so the worktree is modified in place and collected below
	// (tar-out).
	agentRes, agentErr := driveHarnessAgent(rt, dir, spec, maxMin)
	if agentErr != nil {
		res["ok"], res["error"] = false, "agent run: "+agentErr.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	res["run_ok"] = agentRes["ok"] == true
	res["transcript"] = agentRes["transcript"]
	res["agent_diff"] = agentRes["diff"]
	res["usage"] = agentRes["usage"]
	tarOut, err := makeTar(dir)
	if err != nil {
		res["ok"], res["error"] = false, "repack: "+err.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	res["worktree_b64"] = base64.StdEncoding.EncodeToString(tarOut)
	res["meter_s"] = round2(time.Since(start).Seconds())
	res["ok"] = true
	b, _ := json.Marshal(res)
	return b, 0
}

// runGit (server>worktree>Gitea): clone the repo from Gitea into a worktree, drive the image's
// real harness agent against it, then commit + push to a
// branch. The diff rides git — lane-light, no large tar. spec.RepoURL carries the per-run minted
// token (the host mints it, dispatches, and revokes it after the run).
func runGit(spec harnessSpec) ([]byte, int) {
	res := map[string]interface{}{"mode": "git", "ran_on": orUnknown(hostnameSafe())}
	rt := detectRuntime()
	res["runtime"] = rt
	if rt == "" {
		res["ok"], res["error"] = false, "no container runtime"
		b, _ := json.Marshal(res)
		return b, 1
	}
	if spec.Image == "" || spec.RepoURL == "" {
		res["ok"], res["error"] = false, "image and repo_url required for mode=git"
		b, _ := json.Marshal(res)
		return b, 1
	}
	dir, err := os.MkdirTemp("", "harness-git-")
	if err != nil {
		res["ok"], res["error"] = false, "tempdir: "+err.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	defer os.RemoveAll(dir)
	repoDir := filepath.Join(dir, "repo")
	start := time.Now()
	if out, err := runCmd(120*time.Second, "git", "clone", "--", spec.RepoURL, repoDir); err != nil {
		res["ok"], res["error"] = false, "clone: "+truncate(scrubURL(out, spec.RepoURL), 220)
		b, _ := json.Marshal(res)
		return b, 1
	}
	branch := spec.Branch
	if branch == "" {
		branch = "harness/" + spec.HarnessID
	}
	_, _ = runCmd(15*time.Second, "git", "-C", repoDir, "checkout", "-b", branch)
	_, _ = runCmd(15*time.Second, "git", "-C", repoDir, "config", "user.email", "harness@privatae.ai")
	_, _ = runCmd(15*time.Second, "git", "-C", repoDir, "config", "user.name", "harness")
	maxMin := spec.MaxMinutes
	if maxMin <= 0 {
		maxMin = 10
	}
	// Drive the harness image's REAL agent against the cloned worktree (its /run sidecar);
	// the agent modifies /work in place, committed + pushed below.
	agentRes, agentErr := driveHarnessAgent(rt, repoDir, spec, maxMin)
	if agentErr != nil {
		res["ok"], res["error"] = false, "agent run: "+agentErr.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	res["run_ok"] = agentRes["ok"] == true
	res["transcript"] = agentRes["transcript"]
	_, _ = runCmd(15*time.Second, "git", "-C", repoDir, "add", "-A")
	commitOut, _ := runCmd(20*time.Second, "git", "-C", repoDir, "commit", "-m", "harness run: "+spec.HarnessID)
	res["commit_out"] = truncate(commitOut, 200)
	if out, err := runCmd(60*time.Second, "git", "-C", repoDir, "push", "origin", branch); err != nil {
		res["ok"], res["error"] = false, "push: "+truncate(scrubURL(out, spec.RepoURL), 220)
		b, _ := json.Marshal(res)
		return b, 1
	}
	sha, _ := runCmd(10*time.Second, "git", "-C", repoDir, "rev-parse", "HEAD")
	res["branch"], res["commit"] = branch, strings.TrimSpace(sha)
	res["meter_s"] = round2(time.Since(start).Seconds())
	res["ok"] = true
	b, _ := json.Marshal(res)
	return b, 0
}

// driveHarnessAgent runs the harness IMAGE as a sidecar server (PORT=8844, /work bind-mounted)
// and drives its REAL agent via POST /run with the prompt. The
// agent works cwd in /work, so the worktree is modified in place (the caller collects it). The agent's
// OWN per-run credential (mint->use->revoke, never baked into the image) is delivered via
// spec.AgentCreds; absent => the image's baked-in auth (the test path). Always rm's the container.
// Returns the harness /run JSON ({ok, exit_code, transcript, diff, usage, ...}).
func driveHarnessAgent(rt, dir string, spec harnessSpec, maxMin int) (map[string]interface{}, error) {
	const port = 8844
	// Run the SAME image the harness-pool Deployment runs, with the SAME bind env it
	// passes — not invented flags. The sidecar's bind defaults to 127.0.0.1
	// (the same-pod loopback model); the pool Deployment sets
	// PRIVATAE_SIDECAR_BIND=:: + PRIVATAE_APP_ID (both spellings below). On the box we reach the container by its
	// BRIDGE IP (containerIP below), so without the bind override the server listens on
	// loopback and waitReachable never connects ("not reachable on :8844"). `::`
	// serves the IPv4 bridge addr too (the sidecar leaves V6ONLY off) — verified on the box.
	// NOTE: the pool also sets HTTP_PROXY to the cluster's egress proxy because cluster pods
	// have NO direct egress; the box owns its own internet, so the box run egresses directly
	// (not via a platform proxy) — the one intentional difference from the pool env.
	//
	// The non-root harness (uid 10005) must READ AND WRITE the whole bind-mounted /work
	// tree — its cwd is /work and it edits files in place. The worktree dir is 0700
	// root-owned (MkdirTemp) with 0644/0755 root-owned contents, so the harness can't
	// even enter it: POST /run dies "Permission denied: /work" in seconds. Open the
	// ephemeral per-run tree the same way as the creds dir below (it's removed after).
	_ = filepath.Walk(dir, func(p string, _ os.FileInfo, werr error) error {
		if werr == nil {
			_ = os.Chmod(p, 0o777)
		}
		return nil
	})
	// Both spellings of the sidecar's two variables: the harness image is
	// published on its own schedule, so a box run must work against one that
	// reads either name. The older pair comes out once none does.
	args := []string{"run", "-d", "-v", dir + ":/work",
		"-e", "PORT=" + strconv.Itoa(port),
		"-e", "PRIVATAE_SIDECAR_BIND=::",
		"-e", "PRIVATAE_APP_ID=" + spec.HarnessID,
		"-e", "SKEMA_SIDECAR_BIND=::",
		"-e", "SKEMA_APP_ID=" + spec.HarnessID}
	// Deliver the agent's OWN credential as the FILE the harness sidecar reads
	// (/home/privatae/.claude/.credentials.json — the claudeAiOauth JSON) — NOT an env var (the
	// sidecar reads + self-refreshes the FILE, ignoring CLAUDE_CODE_OAUTH_TOKEN). Mount a temp
	// .claude dir holding it, then DELETE the dir after the run so nothing durable is left on the
	// box. The host pulls these creds from the entity vault per run.
	var credDir string
	if spec.AgentCreds != "" {
		if d, derr := os.MkdirTemp("", "harness-claude-*"); derr == nil {
			credDir = d
			// MkdirTemp is 0700 + root-owned; the harness container runs as a NON-root
			// user (uid 10005) that must both READ the token AND WRITE in this dir — the
			// bundled Claude Code SDK creates .claude/session-env for its Bash tool and the
			// in-container token refresh rewrites .credentials.json. 0755 only lets it read,
			// so Bash dies ("could not create session-env") and refresh can't persist. Make
			// the per-run temp dir world-writable (it's ephemeral, on the user's own box,
			// removed right after the run); the creds file itself stays 0644.
			_ = os.Chmod(d, 0o777)
			if werr := os.WriteFile(filepath.Join(d, ".credentials.json"), []byte(spec.AgentCreds), 0o644); werr == nil {
				args = append(args, "-v", credDir+":/home/privatae/.claude")
			}
		}
	}
	if credDir != "" {
		defer os.RemoveAll(credDir)
	}
	args = append(args, spec.Image)
	out, err := runCmd(60*time.Second, rt, args...)
	if err != nil {
		return nil, fmt.Errorf("harness server start: %s", truncate(out, 200))
	}
	cid := strings.TrimSpace(out)
	defer func() { _, _ = runCmd(20*time.Second, rt, "rm", "-f", cid) }()

	ip := containerIP(rt, cid)
	if ip == "" {
		return nil, fmt.Errorf("harness server: no container IP")
	}
	base := fmt.Sprintf("http://%s:%d", ip, port)
	if ok, _ := waitReachable(base+"/", 45*time.Second); !ok {
		return nil, fmt.Errorf("harness sidecar not reachable on :%d", port)
	}
	reqBody, _ := json.Marshal(map[string]interface{}{
		"prompt": spec.Prompt, "project_dir": "/work", "max_minutes": maxMin,
	})
	client := &http.Client{Timeout: time.Duration(maxMin+2) * time.Minute}
	resp, err := client.Post(base+"/run", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("harness /run: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var res map[string]interface{}
	if err := json.Unmarshal(rb, &res); err != nil {
		return nil, fmt.Errorf("harness /run bad json (HTTP %d): %s", resp.StatusCode, truncate(string(rb), 200))
	}
	return res, nil
}

// scrubURL removes a credential-bearing URL (and its token) from output, so a clone/push error
// never echoes the per-run token back over the lane.
func scrubURL(s, url string) string {
	if url == "" {
		return s
	}
	s = strings.ReplaceAll(s, url, "<repo>")
	if at := strings.LastIndex(url, "@"); at > 0 {
		if cut := strings.LastIndex(url[:at], ":"); cut > 0 {
			if tok := url[cut+1 : at]; len(tok) > 6 {
				s = strings.ReplaceAll(s, tok, "<token>")
			}
		}
	}
	return s
}

// extractTar unpacks a tar byte stream into dir (paths confined to dir; escapes skipped).
func extractTar(data []byte, dir string) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dir, hdr.Name)
		if target != filepath.Clean(dir) && !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
			continue // path escapes dir — skip (defense against a crafted tar)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(f, tr)
			f.Close()
			if cerr != nil {
				return cerr
			}
		}
	}
}

// makeTar packs dir (recursively; files + dirs, skipping .git) into a tar byte stream.
func makeTar(dir string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	root := filepath.Clean(dir)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(tw, f)
			f.Close()
			if cerr != nil {
				return cerr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// detectRuntime returns the first working container runtime, or "" if none.
func detectRuntime() string {
	for _, rt := range []string{"docker", "podman", "nerdctl"} {
		if _, err := runCmd(5*time.Second, rt, "ps", "-q"); err == nil {
			return rt
		}
	}
	return ""
}

// runCmd runs a command with a timeout; returns clean stdout on success, stdout+stderr on error.
func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd) // console_windows.go
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(out.String() + " " + errb.String()), err
	}
	return out.String(), nil
}

// containerIP returns the container's bridge IP — reachable from the host with no published port.
func containerIP(rt, cid string) string {
	out, err := runCmd(10*time.Second, rt, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// waitReachable polls url until it answers (any HTTP status = the server is up) or the deadline.
func waitReachable(url string, within time.Duration) (bool, int) {
	deadline := time.Now().Add(within)
	client := &http.Client{Timeout: 3 * time.Second}
	for time.Now().Before(deadline) {
		if resp, err := client.Get(url); err == nil {
			code := resp.StatusCode
			resp.Body.Close()
			return true, code
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false, 0
}

func hostnameSafe() string { h, _ := os.Hostname(); return h }

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

func shortID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

func sendHarness(ws *websocket.Conn, tag byte, payload []byte) {
	_ = ws.WriteMessage(websocket.BinaryMessage, append([]byte{tag}, payload...))
}

func sendHarnessExit(ws *websocket.Conn, code int) {
	sendHarness(ws, 'X', []byte(strconv.Itoa(code)))
}
