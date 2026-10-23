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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
			body, code := fitLane(r.body, r.code)
			fmt.Printf("harness: job %s done exit=%d\n", spec.HarnessID, code)
			sendHarness(ws, 'J', body)
			sendHarnessExit(ws, code)
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
	// The tree is a folder inside dir, as runGit's is: dir stays 0700, so the
	// tree opened for the agent is out of every other local user's reach.
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		res["ok"], res["error"] = false, "tempdir: "+err.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	if err := extractTar(tarIn, work); err != nil {
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
	agentRes, agentErr := driveHarnessAgent(rt, work, spec, maxMin)
	if agentErr != nil {
		res["ok"], res["error"] = false, "agent run: "+agentErr.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	res["run_ok"] = agentRes["ok"] == true
	res["transcript"] = agentRes["transcript"]
	res["agent_diff"] = agentRes["diff"]
	res["usage"] = agentRes["usage"]
	tarOut, skips, err := packWorktreeSkips(work)
	if errors.Is(err, errTreeTooLarge) {
		// No tree at all rather than part of one: a shorter tar would read as
		// the agent's whole work.
		res["ok"], res["worktree_too_large"] = false, true
		res["error"] = "the tree the agent left is not returned: " + err.Error() + ", the most this lane carries back"
		b, _ := json.Marshal(res)
		return b, 1
	}
	if err != nil {
		res["ok"], res["error"] = false, "repack: "+err.Error()
		b, _ := json.Marshal(res)
		return b, 1
	}
	res["worktree_b64"] = base64.StdEncoding.EncodeToString(tarOut)
	skips.report(res)
	res["meter_s"] = round2(time.Since(start).Seconds())
	res["ok"] = true
	b, _ := json.Marshal(res)
	return b, 0
}

// runGit (server>worktree>Gitea): clone the repo from Gitea into a worktree, drive the image's
// real harness agent against it, then commit + push to a
// branch. The diff rides git — lane-light, no large tar. spec.RepoURL carries the per-run minted
// token (the host mints it, dispatches, and revokes it after the run).
//
// The agent's tree, its .git included, is the agent's to write, and this
// process may be root: a hook, core.fsmonitor, a filter or a credential
// helper set in that .git would run here, and a changed remote would take the
// push and its token elsewhere. So git never runs in that tree after the
// agent has had it. The commit is made in a second clone, in a folder only
// this process can enter and that is mounted nowhere, which gets the agent's
// plain files and folders (mirrorTree) and nothing of its .git. The branch
// gets one commit holding the agent's final files.
func runGit(spec harnessSpec) ([]byte, int) {
	res := map[string]interface{}{"mode": "git", "ran_on": orUnknown(hostnameSafe())}
	fail := func(msg string) ([]byte, int) {
		res["ok"], res["error"] = false, msg
		b, _ := json.Marshal(res)
		return b, 1
	}
	rt := detectRuntime()
	res["runtime"] = rt
	if rt == "" {
		return fail("no container runtime")
	}
	if spec.Image == "" || spec.RepoURL == "" {
		return fail("image and repo_url required for mode=git")
	}
	dir, err := os.MkdirTemp("", "harness-git-")
	if err != nil {
		return fail("tempdir: " + err.Error())
	}
	defer os.RemoveAll(dir)
	// The push side: the clean clone and the empty HOME every git call runs
	// with. MkdirTemp makes it 0700, and it is never mounted.
	own, err := os.MkdirTemp("", "harness-push-")
	if err != nil {
		return fail("tempdir: " + err.Error())
	}
	defer os.RemoveAll(own)
	home := filepath.Join(own, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return fail("tempdir: " + err.Error())
	}
	// Every git call names the repository by its URL without the token and
	// gets the token from its environment, so neither clone's config holds it
	// and no process argument shows it.
	bareURL, auth, err := repoGitAuth(spec.RepoURL)
	if err != nil {
		return fail("repo_url: " + err.Error())
	}
	git := func(timeout time.Duration, in string, args ...string) (string, error) {
		return harnessGitAuth(timeout, home, auth, in, args...)
	}
	repoDir := filepath.Join(dir, "repo")
	start := time.Now()
	if out, err := git(120*time.Second, "", "clone", "--", bareURL, repoDir); err != nil {
		return fail("clone: " + truncate(scrubURL(out, spec.RepoURL), 220))
	}
	// The agent gets no push access of its own: the run's commit is made from
	// the clean clone below. Its clone was made with no token in its URL, and
	// is refused if the token is in any file of its .git all the same.
	if err := dropRepoCredential(git, repoDir, spec.RepoURL); err != nil {
		return fail("clone: " + truncate(scrubURL(err.Error(), spec.RepoURL), 220))
	}
	branch := spec.Branch
	if branch == "" {
		branch = "harness/" + spec.HarnessID
	}
	// The commit the agent starts from, read before it has the tree: the
	// clean clone commits on top of the same one. An empty repository has
	// none, and the run's commit is its first.
	base := ""
	if out, err := git(10*time.Second, repoDir, "rev-parse", "--verify", "-q", "HEAD^{commit}"); err == nil {
		base = strings.TrimSpace(out)
	}
	_, _ = git(15*time.Second, repoDir, "checkout", "-b", branch)
	_, _ = git(15*time.Second, repoDir, "config", "user.email", harnessGitEmail)
	_, _ = git(15*time.Second, repoDir, "config", "user.name", harnessGitName)
	maxMin := spec.MaxMinutes
	if maxMin <= 0 {
		maxMin = 10
	}
	// Drive the harness image's REAL agent against the cloned worktree (its /run sidecar);
	// the agent modifies /work in place, copied into the clean clone below.
	agentRes, agentErr := driveHarnessAgent(rt, repoDir, spec, maxMin)
	if agentErr != nil {
		return fail("agent run: " + agentErr.Error())
	}
	res["run_ok"] = agentRes["ok"] == true
	res["transcript"] = agentRes["transcript"]

	clean := filepath.Join(own, "repo")
	if out, err := git(120*time.Second, "", "clone", "--no-checkout", "--", bareURL, clean); err != nil {
		return fail("clone for the push: " + truncate(scrubURL(out, spec.RepoURL), 220))
	}
	checkout := []string{"checkout", "-b", branch}
	if base != "" {
		checkout = append(checkout, base)
	}
	if out, err := git(30*time.Second, clean, checkout...); err != nil {
		return fail("clone for the push: could not check out the commit the run started from (" + orUnknown(base) + "): " +
			truncate(scrubURL(out, spec.RepoURL), 160))
	}
	_, _ = git(15*time.Second, clean, "config", "user.email", harnessGitEmail)
	_, _ = git(15*time.Second, clean, "config", "user.name", harnessGitName)
	skips, err := mirrorTree(repoDir, clean, maxCopiedTreeBytes)
	if errors.Is(err, errTreeTooLarge) {
		res["tree_too_large"] = true
		return fail("nothing was pushed: " + err.Error() + ", the most a run copies (each file and folder counts 512 bytes and its name besides its content)")
	}
	if err != nil {
		return fail("copy the agent's tree: " + err.Error())
	}
	skips.report(res)
	if out, err := git(60*time.Second, clean, "add", "-A"); err != nil {
		return fail("nothing was pushed: add: " + truncate(scrubURL(out, spec.RepoURL), 220))
	}
	// A run that changed no file has nothing to commit and pushes nothing:
	// ok, with changed false and no branch, since none was made.
	dout, derr := git(60*time.Second, clean, "diff", "--cached", "--quiet")
	var exitErr *exec.ExitError
	switch {
	case derr == nil:
		res["changed"] = false
		res["note"] = "the agent changed no file; nothing was committed or pushed"
		res["meter_s"] = round2(time.Since(start).Seconds())
		res["ok"] = true
		b, _ := json.Marshal(res)
		return b, 0
	case !errors.As(derr, &exitErr) || exitErr.ExitCode() != 1:
		return fail("nothing was pushed: diff: " + truncate(scrubURL(dout, spec.RepoURL), 220))
	}
	commitOut, err := git(20*time.Second, clean, "commit", "-m", "harness run: "+spec.HarnessID)
	res["commit_out"] = truncate(scrubURL(commitOut, spec.RepoURL), 200)
	if err != nil {
		return fail("nothing was pushed: commit: " + truncate(scrubURL(commitOut, spec.RepoURL), 220))
	}
	res["changed"] = true
	// Hooks never run, so git-lfs's pre-push hook does not either: the large
	// files the commit points to are sent first, to the repository's own LFS
	// address, whatever a .lfsconfig in the agent's tree names.
	if harnessLFSConfig() != nil {
		args := append(lfsEndpointPins(bareURL), "lfs", "push", "origin", branch)
		if out, err := git(10*time.Minute, clean, args...); err != nil {
			return fail("nothing was pushed: lfs push: " + truncate(scrubURL(out, spec.RepoURL), 220))
		}
	}
	if out, err := git(60*time.Second, clean, "push", "origin", branch); err != nil {
		return fail("push: " + truncate(scrubURL(out, spec.RepoURL), 220))
	}
	sha, _ := git(10*time.Second, clean, "rev-parse", "HEAD")
	res["branch"], res["commit"] = branch, strings.TrimSpace(sha)
	res["meter_s"] = round2(time.Since(start).Seconds())
	res["ok"] = true
	b, _ := json.Marshal(res)
	return b, 0
}

// harnessGitSafe goes on every git the harness runs: no hook, no file
// system monitor and no ext:: transport, whatever a repository's config says.
var harnessGitSafe = []string{"-c", "core.hooksPath=" + os.DevNull, "-c", "core.fsmonitor=false",
	"-c", "protocol.ext.allow=never"}

// harnessGit runs git (in the folder in, if not "") with harnessGitSafe and
// an environment that brings no config of this machine's: no system file, no
// global file, HOME and XDG_CONFIG_HOME at home (an empty folder), and no
// GIT_ variable of this process's. Output as runCmd gives it.
func harnessGit(timeout time.Duration, home, in string, args ...string) (string, error) {
	return harnessGitAuth(timeout, home, nil, in, args...)
}

// harnessGitAuth is harnessGit with auth (repoGitAuth's environment) added to
// the environment, so a credential is never in a process argument, where any
// local user can read it.
func harnessGitAuth(timeout time.Duration, home string, auth []string, in string, args ...string) (string, error) {
	a := append(append([]string{}, harnessGitSafe...), harnessLFSConfig()...)
	if in != "" {
		a = append(a, "-C", in)
	}
	a = append(a, args...)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", a...)
	hideConsole(cmd)
	cmd.Env = append(harnessGitEnv(home), auth...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(out.String() + " " + errb.String()), err
	}
	return out.String(), nil
}

func harnessGitEnv(home string) []string {
	env := []string{}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k = strings.ToUpper(k); {
		case strings.HasPrefix(k, "GIT_"), k == "HOME", k == "XDG_CONFIG_HOME":
			continue
		}
		env = append(env, kv)
	}
	// The harness identity on every call, so git never makes one from this
	// machine's user and host name: that costs a host name lookup per call
	// (seconds where there is no resolver) and writes the name into the
	// reflog of the clone the agent is handed.
	return append(env, "HOME="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME="+harnessGitName, "GIT_AUTHOR_EMAIL="+harnessGitEmail,
		"GIT_COMMITTER_NAME="+harnessGitName, "GIT_COMMITTER_EMAIL="+harnessGitEmail)
}

// The name and address a harness run's commits carry.
const (
	harnessGitName  = "harness"
	harnessGitEmail = "harness@privatae.ai"
)

// harnessLFSConfig is the git-lfs filter, as `git lfs install` writes it,
// when git-lfs is installed here. No global config is read, so a repository
// that keeps files in LFS would otherwise be cloned as pointer files and its
// changed large files committed whole. It comes from this process only: a
// filter the repository or the agent names under any other name has no
// command, so it never runs.
func harnessLFSConfig() []string {
	if _, err := exec.LookPath("git-lfs"); err != nil {
		return nil
	}
	return []string{"-c", "filter.lfs.clean=git-lfs clean -- %f", "-c", "filter.lfs.smudge=git-lfs smudge -- %f",
		"-c", "filter.lfs.process=git-lfs filter-process", "-c", "filter.lfs.required=true"}
}

// lfsEndpointPins sets every LFS address git-lfs reads to the one it derives
// from repoURL itself, so a .lfsconfig in the agent's tree cannot send the
// push anywhere else. git config wins over .lfsconfig. repoURL is the URL
// without its credential (repoGitAuth sends that, to this repository only).
// Only an http(s) address is pinned; for any other, git-lfs is left to derive
// the address as it does.
func lfsEndpointPins(repoURL string) []string {
	u, err := url.Parse(repoURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil
	}
	ep := strings.TrimSuffix(repoURL, "/")
	if !strings.HasSuffix(ep, ".git") {
		ep += ".git"
	}
	ep += "/info/lfs"
	var a []string
	for _, k := range []string{"lfs.url", "lfs.pushurl", "remote.origin.lfsurl", "remote.origin.lfspushurl"} {
		a = append(a, "-c", k+"="+ep)
	}
	return a
}

// repoURLParts is repoURL without its user and password, and the secret it
// carried (the password, or a user name standing alone, which is how some
// forges take a token). A URL with no user part comes back as it is.
func repoURLParts(repoURL string) (bare, secret string, err error) {
	u, perr := url.Parse(repoURL)
	if perr != nil {
		if strings.Contains(repoURL, "://") {
			return "", "", errors.New("the repository URL does not parse")
		}
		return repoURL, "", nil // a local path or user@host:path, which holds no token
	}
	if u.User == nil {
		return repoURL, "", nil
	}
	secret = u.User.Username()
	if p, ok := u.User.Password(); ok && p != "" {
		secret = p
	}
	u.User = nil
	return u.String(), secret, nil
}

// repoGitAuth is how git reaches repoURL with no credential in a process
// argument or a config file: the URL without its user and password, and the
// environment that sends them as an Authorization header to that URL and the
// addresses under it only (http.<url>.extraHeader, which git and git-lfs both
// read, set through GIT_CONFIG_COUNT as the mirror's push sets its own). A
// URL with no user part needs no environment.
func repoGitAuth(repoURL string) (bare string, env []string, err error) {
	bare, secret, err := repoURLParts(repoURL)
	if err != nil || secret == "" {
		return bare, nil, err
	}
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", nil, err
	}
	pass, _ := u.User.Password()
	cred := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pass))
	return bare, []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http." + bare + ".extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: Basic " + cred}, nil
}

// dropRepoCredential makes the clone at repoDir name its origin without the
// token repoURL carries, then refuses it if the token is still in any file of
// its .git (objects aside, which hold only the repository's content).
func dropRepoCredential(git func(time.Duration, string, ...string) (string, error), repoDir, repoURL string) error {
	bare, secret, err := repoURLParts(repoURL)
	if err != nil || secret == "" {
		return err
	}
	if out, err := git(15*time.Second, repoDir, "remote", "set-url", "origin", bare); err != nil {
		return fmt.Errorf("remove the token from the agent's clone: %s", out)
	}
	if len(secret) < 8 {
		return nil // too short to be a token, and would match ordinary text
	}
	gitDir := filepath.Join(repoDir, ".git")
	return filepath.WalkDir(gitDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if p == filepath.Join(gitDir, "objects") || p == filepath.Join(gitDir, "lfs") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(secret)) {
			rel, _ := filepath.Rel(repoDir, p)
			return fmt.Errorf("the token is still in the agent's clone, in %s", filepath.ToSlash(rel))
		}
		return nil
	})
}

// driveHarnessAgent runs the harness IMAGE as a sidecar server (PORT=8844, /work bind-mounted)
// and drives its REAL agent via POST /run with the prompt. The
// agent works cwd in /work, so the worktree is modified in place (the caller collects it). The agent's
// OWN per-run credential (mint->use->revoke, never baked into the image) is delivered via
// spec.AgentCreds; absent => the image's baked-in auth (the test path). Always rm's the container.
// Returns the harness /run JSON ({ok, exit_code, transcript, diff, usage, ...}).
func driveHarnessAgent(rt, dir string, spec harnessSpec, maxMin int) (agentRes map[string]interface{}, runErr error) {
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
	// tree — its cwd is /work and it edits files in place. Its contents are 0644/0755
	// and this process's own, so the harness could not even enter it: POST /run dies
	// "Permission denied: /work" in seconds. So the ephemeral per-run tree is opened to
	// every user (it's removed after), and it must sit in a folder no other user can
	// enter: that folder is what keeps the rest of this machine out of the run's tree.
	if err := harnessTreeEnclosed(dir); err != nil {
		return nil, err
	}
	openHarnessTree(dir)
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
	if spec.AgentCreds != "" {
		credDir, credRemove, err := writeHarnessCreds(spec.AgentCreds)
		if credRemove != "" {
			defer os.RemoveAll(credRemove)
		}
		if err != nil {
			return nil, fmt.Errorf("agent credential: %w", err)
		}
		args = append(args, "-v", credDir+":/home/privatae/.claude")
	}
	args = append(args, spec.Image)
	out, err := runCmd(60*time.Second, rt, args...)
	if err != nil {
		return nil, fmt.Errorf("harness server start: %s", truncate(out, 200))
	}
	cid := strings.TrimSpace(out)
	// The caller reads the tree once this returns, so the agent must be gone
	// by then: one still running could go on writing it while it is read. A
	// container whose removal is not confirmed fails the run, and nothing of
	// its tree is used.
	defer func() {
		if out, err := runCmd(20*time.Second, rt, "rm", "-f", cid); err != nil {
			agentRes = nil
			runErr = fmt.Errorf("the agent's container %s could not be removed, so nothing of its tree was used: %s",
				shortID(cid), truncate(strings.TrimSpace(out), 160))
		}
	}()

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

// harnessAgentUID is the user the harness image runs its agent as, the owner
// of its home /home/privatae, where the credential folder is mounted.
const harnessAgentUID = 10005

// writeHarnessCreds puts the agent's credential in a new folder for one run,
// and returns the folder to mount and the folder to remove after the run (the
// second even with an error). The agent must read the file and write beside
// it (its Bash tool makes session-env there, and a token refresh rewrites the
// file). As root the folder (0700) and the file (0600) are handed to the
// agent's user. A process that is not root cannot do that, so it opens them
// to every user (0777, 0666) as it opens the run's tree; either way the
// folder sits in one only this process can enter, so no other local user can
// reach the credential.
func writeHarnessCreds(creds string) (mount, remove string, err error) {
	remove, err = os.MkdirTemp("", "harness-claude-*")
	if err != nil {
		return "", "", err
	}
	d := filepath.Join(remove, "claude")
	f := filepath.Join(d, ".credentials.json")
	dirMode, fileMode := os.FileMode(0o777), os.FileMode(0o666)
	if os.Geteuid() == 0 {
		dirMode, fileMode = 0o700, 0o600
	}
	if err := os.Mkdir(d, 0o700); err != nil {
		return "", remove, err
	}
	if err := os.WriteFile(f, []byte(creds), 0o600); err != nil {
		return "", remove, err
	}
	if os.Geteuid() == 0 {
		for _, p := range []string{f, d} {
			if err := os.Lchown(p, harnessAgentUID, harnessAgentUID); err != nil {
				return "", remove, err
			}
		}
	}
	if err := os.Chmod(f, fileMode); err != nil {
		return "", remove, err
	}
	if err := os.Chmod(d, dirMode); err != nil {
		return "", remove, err
	}
	return d, remove, nil
}

// harnessTreeEnclosed refuses a run tree whose folder another local user
// could enter: that folder must be a plain folder (never a link) and, where
// the system has file modes, have no access for group or others and, where
// it has owners, be this process's own. The tree itself is opened to every
// user for the agent (openHarnessTree), so this folder is all that keeps the
// rest of the machine out of it.
func harnessTreeEnclosed(dir string) error {
	parent := filepath.Dir(filepath.Clean(dir))
	fi, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("run tree: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("run tree: %s is not a folder (a link is never followed)", parent)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("run tree: %s is open to other users (%04o); the tree is opened to every user, so it must sit in a folder only this process can enter", parent, perm)
	}
	if uid, ok := coderFileOwner(fi); ok && uid != os.Geteuid() {
		return fmt.Errorf("run tree: %s belongs to uid %d, not to this process", parent, uid)
	}
	return nil
}

// openHarnessTree gives every user read and write on the run tree, for the
// agent's uid: folders 0777, files 0666, or 0777 for a file that was
// executable, so a run commits no mode change of its own. A link is left as
// it is: chmod follows it, and the tree comes from the repository or the
// host, so a link in it may name any file on this machine.
func openHarnessTree(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		mode := os.FileMode(0o777)
		switch {
		case d.IsDir():
		case d.Type().IsRegular():
			if fi, err := d.Info(); err != nil || fi.Mode().Perm()&0o111 == 0 {
				mode = 0o666
			}
		default:
			return nil // a link, a socket, a device: not opened, never followed
		}
		_ = os.Chmod(p, mode)
		return nil
	})
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

// makeTar packs dir (recursively; plain files and folders, skipping .git) into
// a tar byte stream. packWorktree also says what it left out.
func makeTar(dir string) ([]byte, error) {
	b, _, err := packWorktree(dir)
	return b, err
}

// uvicornWSMaxSize is the largest WebSocket message the host takes in: the
// uvicorn default, which the host's server does not override. A harness
// result is one such message, so this is the most a run can return.
const uvicornWSMaxSize = 16 << 20

// maxReturnedTreeBytes is the largest tar a run sends back. It rides base64
// in the result (4/3 of its size), so 9 MiB is 12 MiB on the lane and leaves
// 4 MiB of the 16 MiB message for the transcript, the diff and the rest.
var maxReturnedTreeBytes int64 = 9 << 20

// maxCopiedTreeBytes is the most a git run copies from the agent's tree into
// the clone it pushes. That push goes over git, not the lane, and the copy
// carries the whole tree, so the lane's limit does not fit it; it is set at
// what a large forge takes in one push (GitHub refuses a push over 2 GB),
// which also bounds the disk this process writes for a run.
var maxCopiedTreeBytes int64 = 2 << 30

// errTreeTooLarge is a tree with more in it than the run may carry.
var errTreeTooLarge = errors.New("too large")

// treeTooLarge says which entry took the tree over its limit.
func treeTooLarge(rel string, limit int64) error {
	return fmt.Errorf("%s takes the tree over %d MiB: %w", rel, limit>>20, errTreeTooLarge)
}

// packWorktree packs dir into a tar byte stream and lists, by their path in
// the tree, the entries it left out.
//
// A run's tree is written by the agent, which may still be writing it while
// it is packed, and this process may be root: a name seen as a plain file can
// be a link to any file on this machine by the time it is opened, and a folder
// seen as a folder can be a link to any folder. So the tree is walked by open
// folder (packTree, per system): each name is opened relative to the folder
// already open above it, a link is never followed, and what goes in is what
// was opened. Only a plain file or a folder goes in; a link, a pipe, a device,
// a socket, or a name that changed between the look and the open is left out
// and listed.
//
// Files are streamed from the opened file, never read whole, and the tar
// stops at maxReturnedTreeBytes: a tree larger than that is an error, never
// a shorter tar.
func packWorktree(dir string) ([]byte, []string, error) {
	b, skips, err := packWorktreeSkips(dir)
	return b, skips.names, err
}

// packWorktreeSkips is packWorktree with the count of left-out entries.
func packWorktreeSkips(dir string) ([]byte, treeSkips, error) {
	var buf bytes.Buffer
	cw := &treeCapWriter{w: &buf, limit: maxReturnedTreeBytes}
	sink := &tarSink{tw: tar.NewWriter(cw), cw: cw}
	if err := packTree(sink, filepath.Clean(dir)); err != nil {
		return nil, treeSkips{}, err
	}
	if err := sink.tw.Close(); err != nil {
		return nil, treeSkips{}, err
	}
	return buf.Bytes(), sink.treeSkips, nil
}

// treeSink takes what packTree opened, a folder before what is in it. rel is
// the entry's path in the tree with / between names. listed hears each name
// as the walk reads it from its folder, in batches of treeListBatch, and
// refuses it once the tree holds more entries than the sink takes; folder
// hears all the names in a folder, rel, once they are read and before any of
// them is put; skip hears each entry the walk leaves out.
type treeSink interface {
	listed(rel string) error
	put(f *os.File, fi os.FileInfo, rel string) error
	folder(rel string, names []string) error
	skip(rel string)
}

// treeListBatch is how many names the walk reads from a folder at a time, so
// a folder of any size is refused after at most this many names past the
// limit, never read whole first.
const treeListBatch = 512

// readTreeNames reads the names in the open folder d (rel in the tree, with /
// between names) treeListBatch at a time, handing each to sink.listed as it
// is read, and returns them sorted.
func readTreeNames(sink treeSink, d *os.File, rel string) ([]string, error) {
	var names []string
	for {
		batch, err := d.Readdirnames(treeListBatch)
		for _, n := range batch {
			p := n
			if rel != "" {
				p = rel + "/" + n
			}
			if lerr := sink.listed(p); lerr != nil {
				return nil, lerr
			}
		}
		names = append(names, batch...)
		if err == io.EOF || (err == nil && len(batch) == 0) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read folder %q: %w", rel, err)
		}
	}
	sort.Strings(names)
	return names, nil
}

// treeSkips counts the entries a walk left out and keeps the first
// maxSkippedReported of their paths, so a tree of any number of links holds
// no more than that in memory.
type treeSkips struct {
	names []string
	count int
}

func (s *treeSkips) skip(rel string) {
	s.count++
	if len(s.names) < maxSkippedReported {
		s.names = append(s.names, rel)
	}
}

// report puts the left-out entries in a run's result: the count in full and
// the names kept, sorted.
func (s treeSkips) report(res map[string]interface{}) {
	if s.count == 0 {
		return
	}
	names := append([]string(nil), s.names...)
	sort.Strings(names)
	res["worktree_skipped_count"], res["worktree_skipped"] = s.count, names
}

// treeEntryCost is what an entry costs a copy beside its content: a tar
// header block, as each entry costs the tar a worktree run returns, and its
// name. It bounds how many entries a tree may hold, empty files included.
func treeEntryCost(rel string) int64 { return 512 + int64(len(rel)) }

// treeCapWriter passes writes on until limit bytes have gone through, then
// refuses them with errTreeTooLarge (contextextract.go's capWriter drops
// them instead).
type treeCapWriter struct {
	w     io.Writer
	n     int64
	limit int64
}

func (c *treeCapWriter) Write(p []byte) (int, error) {
	if c.n+int64(len(p)) > c.limit {
		return 0, errTreeTooLarge
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// tarSink writes each entry into a tar. Every entry pays its header in the
// tar itself; listed also charges each name read against the tar's limit,
// so the names the walk holds stay within it.
type tarSink struct {
	tw       *tar.Writer
	cw       *treeCapWriter
	listCost int64
	treeSkips
}

func (s *tarSink) listed(rel string) error {
	if s.listCost += treeEntryCost(rel); s.listCost > s.cw.limit {
		return treeTooLarge(rel, s.cw.limit)
	}
	return nil
}

func (s *tarSink) folder(string, []string) error { return nil }

// put writes the header of an entry packTree opened and, for a file, its
// bytes, copied from the opened file. The size in the header is the opened
// file's size; a file over what is left of the limit is refused before a
// byte of it is read, and one that gets shorter while it is copied is an
// error, never a short entry.
func (s *tarSink) put(f *os.File, fi os.FileInfo, rel string) error {
	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	hdr.Name = rel
	if fi.IsDir() {
		if err := s.tw.WriteHeader(hdr); err != nil {
			return s.sized(rel, err)
		}
		return nil
	}
	// A header block, the content padded to a block, and the two blocks that
	// end the tar.
	if size := fi.Size(); size > s.cw.limit-s.cw.n-3*512 {
		return treeTooLarge(rel, s.cw.limit)
	}
	if err := s.tw.WriteHeader(hdr); err != nil {
		return s.sized(rel, err)
	}
	n, err := io.CopyN(s.tw, f, hdr.Size)
	if err == io.EOF {
		return fmt.Errorf("%s got shorter while it was packed (%d of %d bytes)", rel, n, hdr.Size)
	}
	if err != nil {
		return s.sized(rel, fmt.Errorf("read %s: %w", rel, err))
	}
	return nil
}

func (s *tarSink) sized(rel string, err error) error {
	if errors.Is(err, errTreeTooLarge) {
		return treeTooLarge(rel, s.cw.limit)
	}
	return err
}

// copySink copies each entry into the folder root, the clone a git run
// pushes. It writes only plain files and folders it makes itself: whatever is
// at a name in root before (a file, a folder, a link the repository holds) is
// removed first and never written through. A name .git in any letter case,
// at any depth, is left out, so nothing the agent wrote can stand in for the
// clone's own repository or a nested one.
//
// Every entry is charged treeEntryCost besides its bytes, and nothing is kept
// per entry, so neither the disk a copy writes nor the memory it holds grows
// past the limit however many files the tree has.
type copySink struct {
	root  string
	limit int64
	total int64
	treeSkips
}

// inDotGit says whether any name in rel is one dotGitName refuses.
func inDotGit(rel string) bool {
	for _, name := range strings.Split(rel, "/") {
		if dotGitName(name) {
			return true
		}
	}
	return false
}

// charge takes size bytes of rel's content from what is left of the limit.
func (s *copySink) charge(rel string, size int64) error {
	if size > s.limit-s.total {
		return treeTooLarge(rel, s.limit)
	}
	s.total += size
	return nil
}

// listed charges each name the walk reads its treeEntryCost, whether or not
// it is then copied.
func (s *copySink) listed(rel string) error {
	return s.charge(rel, treeEntryCost(rel))
}

// folder removes from the clone's folder rel every name the agent's folder
// does not hold, except the clone's own .git. A name the agent's folder holds
// but the copy leaves out (a link, a special file, a folder too deep) keeps
// what the clone has, the repository's version or nothing. It runs before any
// entry of the folder is copied, so a name that differs only in letter case
// on a system that ignores case is removed before the new one is written.
func (s *copySink) folder(rel string, names []string) error {
	if rel != "" && inDotGit(rel) {
		return nil
	}
	dir := filepath.Join(s.root, filepath.FromSlash(rel))
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	in := make(map[string]bool, len(names))
	for _, n := range names {
		in[n] = true
	}
	for _, e := range ents {
		if in[e.Name()] || (rel == "" && e.Name() == ".git") {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (s *copySink) put(f *os.File, fi os.FileInfo, rel string) error {
	if inDotGit(rel) {
		s.skip(rel)
		return nil
	}
	dst := filepath.Join(s.root, filepath.FromSlash(rel))
	if fi.IsDir() {
		if st, err := os.Lstat(dst); err == nil && !st.IsDir() {
			if err := os.RemoveAll(dst); err != nil {
				return err
			}
		}
		if err := os.Mkdir(dst, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		return nil
	}
	size := fi.Size()
	if err := s.charge(rel, size); err != nil {
		return err
	}
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if fi.Mode().Perm()&0o111 != 0 {
		mode = 0o755
	}
	// O_EXCL: the name was just emptied, so this makes a new file and opens
	// no link.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	n, err := io.CopyN(out, f, size)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == io.EOF {
		return fmt.Errorf("%s got shorter while it was copied (%d of %d bytes)", rel, n, size)
	}
	if err != nil {
		return fmt.Errorf("copy %s: %w", rel, err)
	}
	return os.Chmod(dst, mode) // the mode as asked, whatever the umask
}

// dotGitName says whether a file system may open name as .git: any letter
// case; on Windows also with dots or spaces after it, or a stream after a
// colon, or as its short name GIT~1; on HFS+ also with the code points it
// ignores in a name. These are the names git itself refuses in a tree
// (is_ntfs_dotgit, is_hfs_dotgit), checked on every system, since a name the
// agent made on one is copied by a bastion that may run on another.
func dotGitName(name string) bool {
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 0x200c && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x206a && r <= 0x206f, r == 0xfeff:
			return -1
		}
		return r
	}, name)
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimRight(name, ". ")
	return strings.EqualFold(name, ".git") || strings.EqualFold(name, "git~1")
}

// mirrorTree makes the clone at dst hold the agent's tree at src: every
// plain file and folder in src is copied in, and whatever the clone has that
// src does not is deleted, except the clone's own .git. An entry the copy
// leaves out (a link, a special file, a .git) keeps what the clone has at
// that name, the repository's own version or nothing, so a link the agent
// made is never committed and one the repository holds is not deleted by a
// run that could not copy it (copySink.folder). Returns the entries left out.
func mirrorTree(src, dst string, limit int64) (treeSkips, error) {
	sink := &copySink{root: dst, limit: limit}
	err := packTree(sink, filepath.Clean(src))
	return sink.treeSkips, err
}

// packTreeBeforeOpen, when set, runs between packTree's look at an entry and
// its open: the gap a concurrent writer aims for. Only tests set it.
var packTreeBeforeOpen func(rel string)

// maxTreeDepth bounds how deep packTree goes, since every level holds one
// folder open. A folder deeper than this is left out and listed.
const maxTreeDepth = 128

// maxSkippedReported bounds the left-out names a run reports; the count is
// always reported in full.
const maxSkippedReported = 100

// fitLane is the result a harness job sends: body, or, when body is more than
// one message on the lane can carry (uvicornWSMaxSize, less the frame's tag),
// a refusal that says so. The host would drop an oversized message and the
// run would read as lost.
func fitLane(body []byte, code int) ([]byte, int) {
	if len(body) < uvicornWSMaxSize {
		return body, code
	}
	var head struct {
		Mode string `json:"mode"`
	}
	_ = json.Unmarshal(body, &head)
	b, _ := json.Marshal(map[string]any{"ok": false, "mode": head.Mode, "result_too_large": true,
		"error": fmt.Sprintf("the run's result is %d MiB, more than the %d MiB the lane to the host carries; nothing from it was returned",
			len(body)>>20, uvicornWSMaxSize>>20)})
	if code == 0 {
		code = 1
	}
	return b, code
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
