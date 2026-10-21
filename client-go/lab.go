package main

// lab.go — mode=lab: the Lab Harness.
//
// A lab run builds a sealed lab of N hardened hosts on THIS box's own k3s cluster (the
// containment lab), puts the application under test into every host, places ONE coding
// harness pod inside the lab and drives the test runbook through it, collects the
// transcript + per-step verdicts + the runbook worktree, and tears everything down.
//
// THREE STRUCTURAL WALLS (the product claim "spun up in the lab, nowhere else"):
//   1. This mode only answers on a LAB bastion: the lab marker, the inert egress wall file
//      and the lab operator on loopback must all be present (labAvailable). A user's home
//      bastion returns exit 126 in the same shape as an ungranted op.
//   2. The host-side grant carries a `mode:lab` token, so a grant for a home
//      box never covers a lab run and a lab grant never covers a home box.
//   3. The lab cluster has no path out (cloud firewall + labguard per run + tripwire).
//
// What runs where: the lab HOSTS do not think — they hold and run the app under test. The
// coding harness pod thinks, with the per-run credential the host delivered, and its
// tools reach the lab hosts in-cluster. Nothing here talks to the platform.
//
// Gate: only gate="auto" is supported today (typed deliberately, exactly like the old bench's
// --auto). gate="ask" is the App lane (per-call y/n from outside the lab) and is not built
// yet; until then it is refused, never silently downgraded to auto.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	labMarkerPath     = "/etc/privatae-lab/marker"
	labGuardPath      = "/etc/nftables-labguard.nft"
	labOperatorURL    = "http://127.0.0.1:8011/healthz"
	labStorageRoot    = "/var/lib/rancher/k3s/storage"
	labWorkspace      = "/var/lib/skema/projects" // the harness image's workspace root (same image, same root)
	labHarnessPort    = 8844
	labHostIDFloor    = 9001 // lab host entity ids start here; 900 is the bench's own test entity
	labHostIDCeil     = 9899
	labTemplateEntity = 900 // the lab's bench entity; its registry row is the template for lab hosts
	labDefaultHosts   = 1
	labMaxHostsCap    = 8 // per-box cap — protects the LAB BOX, never a user's workflow; marker max_hosts= raises it
)

// labMarker holds the key=value lines of /etc/privatae-lab/marker. Written by the lab
// rebuild, never by this binary.
type labMarker struct {
	present   bool
	hostImage string // host_image= — the host image lab hosts run (must already be on the node)
	maxHosts  int    // max_hosts= — optional
}

func readLabMarker() labMarker {
	m := labMarker{}
	b, err := os.ReadFile(labMarkerPath)
	if err != nil {
		return m
	}
	m.present = true
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "host_image":
			m.hostImage = strings.TrimSpace(v)
		case "max_hosts":
			m.maxHosts, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return m
}

// labAvailable is wall #1. Every check is a thing only the lab box has.
func labAvailable() (labMarker, error) {
	m := readLabMarker()
	if !m.present {
		return m, fmt.Errorf("no lab marker")
	}
	if _, err := os.Stat(labGuardPath); err != nil {
		return m, fmt.Errorf("no egress wall file")
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(labOperatorURL)
	if err != nil {
		return m, fmt.Errorf("lab operator not on loopback")
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return m, fmt.Errorf("lab operator unhealthy (%d)", resp.StatusCode)
	}
	if _, err := runCmd(10*time.Second, "k3s", "kubectl", "version", "--client=true"); err != nil {
		return m, fmt.Errorf("no cluster tooling")
	}
	if m.hostImage == "" {
		return m, fmt.Errorf("marker has no host_image=")
	}
	return m, nil
}

// kc runs `k3s kubectl …` with a timeout.
func kc(timeout time.Duration, args ...string) (string, error) {
	return runCmd(timeout, "k3s", append([]string{"kubectl"}, args...)...)
}

// kcApply applies a manifest from a temp file (runCmd has no stdin).
func kcApply(manifest string) (string, error) {
	f, err := os.CreateTemp("", "lab-manifest-*.yaml")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(manifest); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	return kc(60*time.Second, "apply", "-f", f.Name())
}

func labFail(res map[string]interface{}, code int, msg string) int {
	res["ok"], res["error"] = false, msg
	return code
}

// runLab is the mode=lab entry point (harness.go runHarness). The result is marshalled
// AFTER the inner run's deferred teardown has recorded its log, so the caller always sees
// what happened including the cleanup.
func runLab(spec harnessSpec) ([]byte, int) {
	res := map[string]interface{}{"mode": "lab", "ran_on": orUnknown(hostnameSafe())}
	code := runLabInner(spec, res)
	b, _ := json.Marshal(res)
	return b, code
}

func runLabInner(spec harnessSpec, res map[string]interface{}) int {
	marker, err := labAvailable()
	if err != nil {
		// Same shape + exit as an ungranted op on the host side (exit 126).
		return labFail(res, 126, "mode 'lab' not available on this server — "+err.Error())
	}
	// ── validate the spec ─────────────────────────────────────────────────────
	if spec.Gate != "auto" {
		return labFail(res, 1, "gate='ask' (per-call y/n from the App) is not available yet — pass gate='auto', typed deliberately")
	}
	if spec.Image == "" {
		return labFail(res, 1, "image required for mode=lab (the coding harness that drives the tests)")
	}
	if len(spec.Tests) == 0 {
		return labFail(res, 1, "tests required for mode=lab (the runbook: ordered steps)")
	}
	hosts := spec.Hosts
	if hosts <= 0 {
		hosts = labDefaultHosts
	}
	maxHosts := labMaxHostsCap
	if marker.maxHosts > 0 {
		maxHosts = marker.maxHosts
	}
	if hosts > maxHosts {
		return labFail(res, 1, fmt.Sprintf("hosts=%d exceeds this lab box's max_hosts=%d", hosts, maxHosts))
	}
	app := spec.App
	if app == "" {
		app = "app"
	}
	if !validWSName(app) {
		return labFail(res, 1, "app must be a plain directory name")
	}
	engine := spec.Engine
	if engine == "" {
		engine = spec.HarnessID
	}
	maxMin := spec.MaxMinutes
	if maxMin <= 0 {
		maxMin = 10
	}
	var rb [4]byte
	_, _ = rand.Read(rb[:])
	runID := hex.EncodeToString(rb[:])
	res["run_id"] = runID
	start := time.Now()
	var log []string
	note := func(f string, a ...interface{}) {
		log = append(log, time.Now().UTC().Format("15:04:05 ")+fmt.Sprintf(f, a...))
	}

	// ── 0. one run at a time, and reap whatever a previous run left ──────────
	// The teardown below is a defer, so it covers every ordinary exit — but NOT a
	// SIGKILL or a power loss (measured: a killed self-test left its two
	// entity_registry rows behind). "The lab keeps nothing" has to hold after a crash
	// too, so a run starts by removing anything in the lab's own id range / name
	// prefixes. The lock is what makes that safe: without it a second concurrent run
	// would reap the first one's hosts.
	unlock, err := labLock()
	if err != nil {
		return labFail(res, 1, err.Error())
	}
	defer unlock()
	if reaped := labReapOrphans(); reaped != "" {
		note("reaped a previous run's leftovers: %s", reaped)
		res["reaped"] = reaped
	}

	// ── 1. lab hosts: N hardened Entity CRs on the lab cluster ────────────────
	ids, err := labAllocateIDs(hosts)
	if err != nil {
		return labFail(res, 1, "allocate host ids: "+err.Error())
	}
	res["hosts"] = ids
	// ALWAYS tear down, whatever happens below — the lab keeps nothing between runs.
	defer func() {
		note("teardown: %d hosts + namespace lab-%s", len(ids), runID)
		labTeardown(runID, ids)
		res["log"] = strings.Join(log, "\n")
	}()
	for i, id := range ids {
		name := fmt.Sprintf("lab-%s-%d", runID, i+1)
		if err := labRegistryRow(id, name); err != nil {
			return labFail(res, 1, fmt.Sprintf("host %d registry row: %v", id, err))
		}
		manifest := fmt.Sprintf(`apiVersion: privatae.ai/v1
kind: Entity
metadata:
  name: entity-%d
  namespace: default
  labels:
    privatae.ai/lab-run: "%s"
spec:
  entityId: %d
  lifecycleTier: always_on
  image: %s
  hardened: true
`, id, runID, id, marker.hostImage)
		if out, err := kcApply(manifest); err != nil {
			return labFail(res, 1, fmt.Sprintf("host %d apply: %s", id, truncate(out, 200)))
		}
		note("host %d (%s) applied", id, name)
	}
	for _, id := range ids {
		// The operator builds the namespace + StatefulSet asynchronously after the CR lands;
		// `kubectl wait` on a pod that does not exist yet fails at once, so poll for the pod
		// first, then wait for Ready.
		ns, pod := fmt.Sprintf("entity-%d", id), fmt.Sprintf("pod/entity-%d-0", id)
		appeared := false
		for i := 0; i < 60; i++ {
			if _, err := kc(15*time.Second, "-n", ns, "get", pod); err == nil {
				appeared = true
				break
			}
			time.Sleep(3 * time.Second)
		}
		if !appeared {
			ev, _ := kc(20*time.Second, "-n", ns, "get", "events", "--sort-by=.lastTimestamp")
			return labFail(res, 1, fmt.Sprintf("host %d: the operator never created its pod (3 min): %s", id, truncate(ev, 300)))
		}
		if out, err := kc(300*time.Second, "-n", ns, "wait", "--for=condition=Ready", pod, "--timeout=270s"); err != nil {
			ev, _ := kc(20*time.Second, "-n", ns, "get", "events", "--sort-by=.lastTimestamp")
			return labFail(res, 1, fmt.Sprintf("host %d never became Ready: %s | %s", id, truncate(out, 160), truncate(ev, 300)))
		}
	}
	hostIPs := map[int]string{}
	for _, id := range ids {
		ip, _ := kc(20*time.Second, "-n", fmt.Sprintf("entity-%d", id), "get", "pod",
			fmt.Sprintf("entity-%d-0", id), "-o", "jsonpath={.status.podIP}")
		hostIPs[id] = strings.TrimSpace(ip)
	}
	res["host_ips"] = hostIPs
	note("%d hosts Ready", len(ids))

	// ── 2. the app under test + its settings into every host ─────────────────
	if spec.WorktreeB64 != "" {
		tarIn, err := base64.StdEncoding.DecodeString(spec.WorktreeB64)
		if err != nil {
			return labFail(res, 1, "bad worktree_b64: "+err.Error())
		}
		for _, id := range ids {
			dir, err := labHostProjectDir(id, app)
			if err != nil {
				return labFail(res, 1, fmt.Sprintf("host %d projects dir: %v", id, err))
			}
			if err := extractTar(tarIn, dir); err != nil {
				return labFail(res, 1, fmt.Sprintf("host %d app extract: %v", id, err))
			}
			if err := labWriteEnv(dir, spec.Envs); err != nil {
				return labFail(res, 1, fmt.Sprintf("host %d envs: %v", id, err))
			}
			_ = filepath.Walk(dir, func(p string, _ os.FileInfo, werr error) error {
				if werr == nil {
					_ = os.Chown(p, 1000, 1000) // the entity uid — the host owns its own project
				}
				return nil
			})
		}
		note("app %q + %d settings placed in every host", app, len(spec.Envs))
	}

	// ── 3. the ONE harness pod inside the lab (same image + env as the pool) ──
	ns := "lab-" + runID
	if out, err := kc(30*time.Second, "create", "namespace", ns); err != nil {
		return labFail(res, 1, "namespace: "+truncate(out, 200))
	}
	if spec.AgentCreds != "" {
		f, err := os.CreateTemp("", "lab-creds-*")
		if err != nil {
			return labFail(res, 1, "creds temp: "+err.Error())
		}
		_ = os.WriteFile(f.Name(), []byte(spec.AgentCreds), 0o600)
		f.Close()
		out, err := kc(30*time.Second, "-n", ns, "create", "secret", "generic", "harness-creds",
			"--from-file=.credentials.json="+f.Name())
		_ = os.Remove(f.Name()) // per-run: nothing durable on the box
		if err != nil {
			return labFail(res, 1, "creds secret: "+truncate(out, 200))
		}
	}
	if out, err := kcApply(labHarnessPodManifest(ns, spec.Image, engine, spec.AgentCreds != "")); err != nil {
		return labFail(res, 1, "harness pod: "+truncate(out, 200))
	}
	if out, err := kc(240*time.Second, "-n", ns, "wait", "--for=condition=Ready", "pod/harness", "--timeout=210s"); err != nil {
		ev, _ := kc(20*time.Second, "-n", ns, "get", "events", "--sort-by=.lastTimestamp")
		return labFail(res, 1, "harness pod never Ready: "+truncate(out, 160)+" | "+truncate(ev, 400))
	}
	hip, _ := kc(20*time.Second, "-n", ns, "get", "pod", "harness", "-o", "jsonpath={.status.podIP}")
	hip = strings.TrimSpace(hip)
	if hip == "" {
		return labFail(res, 1, "harness pod has no IP")
	}
	base := fmt.Sprintf("http://[%s]:%d", hip, labHarnessPort)
	if !strings.Contains(hip, ":") {
		base = fmt.Sprintf("http://%s:%d", hip, labHarnessPort)
	}
	if ok, _ := waitReachable(base+"/", 60*time.Second); !ok {
		return labFail(res, 1, "harness sidecar not reachable on :"+strconv.Itoa(labHarnessPort))
	}
	note("harness pod %s Ready at %s", engine, hip)

	// ── 4. the runbook: one governed /run per step ────────────────────────────
	// The workspace the harness works in carries the runbook + a hosts file, so the
	// agent knows what it is testing and where each lab host answers.
	wsName := "lab-run"
	wsTar, err := labRunbookTar(app, spec.Tests, ids, hostIPs, spec.Envs)
	if err != nil {
		return labFail(res, 1, "runbook tar: "+err.Error())
	}
	if code, body := labPost(base+"/workspace/load?dir="+wsName, "application/x-tar", wsTar, 60*time.Second); code != 200 {
		return labFail(res, 1, fmt.Sprintf("workspace/load %d: %s", code, truncate(body, 200)))
	}
	projectDir := labWorkspace + "/" + wsName
	client := &http.Client{Timeout: time.Duration(maxMin+2) * time.Minute}
	steps := make([]map[string]interface{}, 0, len(spec.Tests))
	allOK := true
	for i, step := range spec.Tests {
		prompt := labStepPrompt(i+1, len(spec.Tests), step, app, ids, hostIPs)
		reqBody, _ := json.Marshal(map[string]interface{}{
			"prompt": prompt, "project_dir": projectDir, "max_minutes": maxMin,
		})
		t0 := time.Now()
		resp, err := client.Post(base+"/run", "application/json", bytes.NewReader(reqBody))
		st := map[string]interface{}{"step": i + 1, "test": step}
		if err != nil {
			st["ok"], st["error"] = false, "harness /run: "+err.Error()
			steps = append(steps, st)
			allOK = false
			note("step %d: /run failed: %v", i+1, err)
			break
		}
		rbody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var r map[string]interface{}
		_ = json.Unmarshal(rbody, &r)
		okv, _ := r["ok"].(bool)
		st["ok"] = okv
		st["exit_code"] = r["exit_code"]
		st["elapsed_s"] = round2(time.Since(t0).Seconds())
		if tr, _ := r["transcript"].(string); tr != "" {
			st["transcript"] = tr
		}
		if e, _ := r["error"].(string); e != "" {
			st["error"] = e
		}
		steps = append(steps, st)
		if !okv {
			allOK = false
		}
		note("step %d: ok=%v (%.0fs)", i+1, okv, time.Since(t0).Seconds())
	}
	res["steps"] = steps

	// ── 5. collect: the runbook worktree after (the agent's notes/results live there) ──
	if code, body := labGet(base+"/workspace/export?dir="+wsName, 60*time.Second); code == 200 {
		res["worktree_b64"] = base64.StdEncoding.EncodeToString([]byte(body))
	}
	res["meter_s"] = round2(time.Since(start).Seconds())
	res["ok"] = allOK
	if allOK {
		return 0
	}
	return 1
}

// ── helpers ──────────────────────────────────────────────────────────────────

func validWSName(s string) bool {
	if s == "" || len(s) > 64 || strings.ContainsAny(s, "/\\ ") || strings.HasPrefix(s, ".") {
		return false
	}
	return true
}

// labDeleteRows removes the lab's OWN entity_registry rows and reports how many.
// Three independent scopes, all required, so this can never reach a real entity:
// the `lab-` display-name prefix, the lab id range, and (for a run's own teardown)
// that run's id list. runID=="" + ids==nil is the orphan reap: every lab row in the range.
// Returns "" when it removed nothing.
func labDeleteRows(runID string, ids []int) string {
	where := fmt.Sprintf("display_name LIKE 'lab-%s%%' AND id BETWEEN %d AND %d",
		runID+map[bool]string{true: "-", false: ""}[runID != ""], labHostIDFloor, labHostIDCeil)
	if len(ids) > 0 {
		var in []string
		for _, id := range ids {
			in = append(in, strconv.Itoa(id)) // ints: nothing quotable reaches the SQL
		}
		where += " AND id IN (" + strings.Join(in, ",") + ")"
	} else if runID != "" {
		return "" // a run's teardown with no ids has nothing of its own to remove
	}
	sql := "DELETE FROM entity_registry WHERE " + where + ";"
	f, err := os.CreateTemp("", "lab-del-*.sql")
	if err != nil {
		return ""
	}
	defer os.Remove(f.Name())
	_ = os.Chmod(f.Name(), 0o644) // the postgres user reads it
	_, _ = f.WriteString(sql)
	f.Close()
	out, err := runCmd(20*time.Second, "sudo", "-u", "postgres", "psql", "-d", "parallax", "-q",
		"-v", "ON_ERROR_STOP=1", "-c", "\\set QUIET on", "-f", f.Name())
	if err != nil {
		return ""
	}
	out = strings.TrimSpace(out)
	if out == "" || strings.HasSuffix(out, "DELETE 0") {
		return ""
	}
	return out
}

// labLock serialises lab runs on this box. Returns the release func. An ordinary exit
// releases it; a killed run leaves a stale lock, so a lock whose pid is gone is taken over
// (and the takeover is what makes the reap below safe rather than racy).
func labLock() (func(), error) {
	const path = "/var/tmp/lab-run.lock"
	take := func() error {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		fmt.Fprintf(f, "%d\n", os.Getpid())
		return f.Close()
	}
	if err := take(); err != nil {
		if b, rerr := os.ReadFile(path); rerr == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil {
				if p, ferr := os.FindProcess(pid); ferr != nil || p.Signal(syscall.Signal(0)) != nil {
					_ = os.Remove(path) // stale: the holder is gone
					if err2 := take(); err2 == nil {
						return func() { _ = os.Remove(path) }, nil
					}
				} else {
					return nil, fmt.Errorf("another lab run is in flight on this box (pid %d) — labs are one at a time", pid)
				}
			}
		}
		return nil, fmt.Errorf("could not take the lab run lock: %v", err)
	}
	return func() { _ = os.Remove(path) }, nil
}

// labReapOrphans removes anything a PREVIOUS lab run left behind. Scoped three ways so it
// can only ever touch lab leavings: the `lab-` namespace prefix, the lab entity id range
// (the bench's own entity 900 is deliberately below it), and the `lab-` display-name prefix.
// Returns a short description of what it removed, or "".
func labReapOrphans() string {
	var did []string
	if out, err := kc(30*time.Second, "get", "ns", "-o", "name"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			ns := strings.TrimPrefix(strings.TrimSpace(l), "namespace/")
			if strings.HasPrefix(ns, "lab-") {
				_, _ = kc(60*time.Second, "delete", "namespace", ns, "--ignore-not-found", "--wait=false")
				did = append(did, "ns "+ns)
			}
		}
	}
	var ids []int
	if out, err := kc(30*time.Second, "get", "entity", "-A",
		"-o", "jsonpath={range .items[*]}{.spec.entityId}{\"\\n\"}{end}"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if v, e := strconv.Atoi(strings.TrimSpace(l)); e == nil && v >= labHostIDFloor && v <= labHostIDCeil {
				ids = append(ids, v)
			}
		}
	}
	if len(ids) > 0 {
		did = append(did, fmt.Sprintf("%d host(s) %v", len(ids), ids))
	}
	// Volumes + registry rows are cleaned for the id range even when no CR remains
	// (a crash can leave either half).
	labTeardown("", ids)
	orphans, _ := filepath.Glob(fmt.Sprintf("%s/pvc-*_entity-9[0-9][0-9][0-9]_*", labStorageRoot))
	for _, p := range orphans {
		_ = os.RemoveAll(p)
		did = append(did, "volume "+filepath.Base(p))
	}
	if n := labDeleteRows("", nil); n != "" {
		did = append(did, "registry rows "+n)
	}
	if len(did) == 0 {
		return ""
	}
	return strings.Join(did, ", ")
}

// labAllocateIDs picks N free entity ids in the lab range by reading the Entity CRs that exist.
func labAllocateIDs(n int) ([]int, error) {
	out, err := kc(30*time.Second, "get", "entity", "-A", "-o", "jsonpath={range .items[*]}{.spec.entityId}{\"\\n\"}{end}")
	if err != nil {
		return nil, fmt.Errorf("list entities: %s", truncate(out, 160))
	}
	used := map[int]bool{}
	for _, l := range strings.Split(out, "\n") {
		if v, e := strconv.Atoi(strings.TrimSpace(l)); e == nil {
			used[v] = true
		}
	}
	ids := []int{}
	for id := labHostIDFloor; id <= labHostIDCeil && len(ids) < n; id++ {
		if !used[id] {
			ids = append(ids, id)
		}
	}
	if len(ids) < n {
		return nil, fmt.Errorf("only %d free lab host ids", len(ids))
	}
	return ids, nil
}

// labRegistryRow gives the lab operator the registry row it resolves names from
// (the operator reads display_name off entity_registry). Lab-local postgres. entity_type is
// CHECK-constrained to parallax_native|operator, so lab rows are marked by their display_name
// prefix "lab-<run>-" (and confined to the lab id range) — teardown deletes exactly those.
func labRegistryRow(id int, name string) error {
	// Clone the lab's TEMPLATE entity row (entity 900, the bench's own test entity, restored
	// with the lab DB) rather than invent values: the table carries CHECKs and FKs
	// (mastercode_version → mastercode_versions) that a hand-written row keeps tripping.
	sql := fmt.Sprintf(`INSERT INTO entity_registry (id, entity_type, display_name, master_directive, license_tier,
  seed_weights, current_weights, envelope_bounds, mastercode_version, status)
SELECT %d, entity_type, '%s', 'lab host under test', 'standard',
       seed_weights, current_weights, envelope_bounds, mastercode_version, 'active'
FROM entity_registry WHERE id = %d
ON CONFLICT (id) DO NOTHING;`, id, name, labTemplateEntity)
	f, err := os.CreateTemp("", "lab-row-*.sql")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_ = os.Chmod(f.Name(), 0o644)
	if _, err := f.WriteString(sql); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if out, err := runCmd(20*time.Second, "sudo", "-u", "postgres", "psql", "-d", "parallax", "-v", "ON_ERROR_STOP=1", "-q", "-f", f.Name()); err != nil {
		return fmt.Errorf("%s", truncate(out, 200))
	}
	return nil
}

// labHostProjectDir resolves the host's entity-apps PVC on the node's local-path storage and
// returns <pvc>/projects/<app>, created. The node is root over its own storage — the lab box's
// privilege, and exactly why this mode is lab-only.
func labHostProjectDir(id int, app string) (string, error) {
	matches, _ := filepath.Glob(fmt.Sprintf("%s/pvc-*_entity-%d_entity-apps-entity-%d-0", labStorageRoot, id, id))
	if len(matches) != 1 {
		return "", fmt.Errorf("expected one entity-apps volume, found %d", len(matches))
	}
	dir := filepath.Join(matches[0], "projects", app)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// labWriteEnv writes the app settings as <dir>/.env (KEY=value, sorted, values single-quoted).
func labWriteEnv(dir string, envs map[string]string) error {
	if len(envs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(envs))
	for k := range envs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if !validEnvKey(k) {
			return fmt.Errorf("bad env key %q", k)
		}
		b.WriteString(k + "='" + strings.ReplaceAll(envs[k], "'", "'\\''") + "'\n")
	}
	return os.WriteFile(filepath.Join(dir, ".env"), []byte(b.String()), 0o640)
}

func validEnvKey(k string) bool {
	if k == "" || len(k) > 128 {
		return false
	}
	for i, r := range k {
		ok := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// labHarnessPodManifest mirrors the pool's harness pod (same image, same env, same floor:
// non-root uid, drop ALL, no privilege escalation, RO rootfs, the personal seccomp profile)
// with emptyDirs where the harness must write.
func labHarnessPodManifest(ns, image, engine string, withCreds bool) string {
	credsVol, credsMount, credsInit := "", "", ""
	if withCreds {
		credsVol = `  - name: creds-src
    secret:
      secretName: harness-creds
`
		credsMount = ""
		credsInit = `  initContainers:
  - name: creds
    image: busybox:1.36
    command: ["sh", "-c", "cp /src/.credentials.json /dst/.credentials.json && chown 10005:10005 /dst/.credentials.json && chmod 0644 /dst/.credentials.json"]
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      capabilities: {drop: ["ALL"], add: ["CHOWN", "FOWNER", "DAC_OVERRIDE"]}
    volumeMounts:
    - {name: creds-src, mountPath: /src, readOnly: true}
    - {name: home-claude, mountPath: /dst}
`
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: harness
  namespace: %s
  labels: {app: lab-harness, privatae.ai/lab-run: "%s"}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    seccompProfile: {type: Localhost, localhostProfile: seccomp-personal.json}
%s  containers:
  - name: harness
    image: %s
    imagePullPolicy: IfNotPresent
    env:
    - {name: PORT, value: "%d"}
    - {name: PRIVATAE_SIDECAR_BIND, value: "::"}
    - {name: PRIVATAE_APP_ID, value: "%s"}
    - {name: PRIVATAE_WORKSPACE, value: "%s"}
    # Both spellings, on purpose: the harness image is published on its own
    # schedule, so a lab run must work against one that reads either name.
    # The older three come out once no published image reads them.
    - {name: SKEMA_SIDECAR_BIND, value: "::"}
    - {name: SKEMA_APP_ID, value: "%s"}
    - {name: SKEMA_WORKSPACE, value: "%s"}
    - {name: HOME, value: "/home/privatae"}
    securityContext:
      runAsUser: 10005
      runAsGroup: 10005
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: {drop: ["ALL"]}
    resources:
      requests: {cpu: 250m, memory: 512Mi}
      limits: {memory: 2Gi}
    volumeMounts:
    - {name: workspace, mountPath: %s}
    - {name: home-claude, mountPath: /home/privatae/.claude}
    - {name: tmp, mountPath: /tmp}
%s  volumes:
  - {name: workspace, emptyDir: {}}
  - {name: home-claude, emptyDir: {}}
  - {name: tmp, emptyDir: {}}
%s`, ns, strings.TrimPrefix(ns, "lab-"), credsInit, image, labHarnessPort,
		engine, labWorkspace, engine, labWorkspace,
		labWorkspace, credsMount, credsVol)
}

// labRunbookTar packs the runbook the harness works from: a README naming the app, the hosts
// and their addresses, the settings, and the ordered tests; plus a results/ dir for the agent.
func labRunbookTar(app string, tests []string, ids []int, ips map[int]string, envs map[string]string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "lab-runbook-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	var b strings.Builder
	b.WriteString("# Lab run\n\nYou are the test harness inside a sealed lab. Nothing here can reach the internet or the platform.\n\n")
	b.WriteString("## Application under test\n\n`" + app + "` — placed in every lab host under " + labWorkspace + "/" + app + "\n\n")
	b.WriteString("## Lab hosts\n\n| host | pod address | kernel API |\n|---|---|---|\n")
	for i, id := range ids {
		b.WriteString(fmt.Sprintf("| lab host %d (entity-%d) | %s | http://[%s]:8800 |\n", i+1, id, ips[id], ips[id]))
	}
	if len(envs) > 0 {
		b.WriteString("\n## Settings (also written to every host's " + app + "/.env)\n\n")
		keys := make([]string, 0, len(envs))
		for k := range envs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString("- " + k + "\n")
		}
	}
	b.WriteString("\n## Tests (run in order; write each verdict to results/<n>.md)\n\n")
	for i, t := range tests {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, t))
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "results"), 0o755); err != nil {
		return nil, err
	}
	_ = os.WriteFile(filepath.Join(dir, "results", ".keep"), nil, 0o644)
	return makeTar(dir)
}

func labStepPrompt(n, total int, step, app string, ids []int, ips map[int]string) string {
	var hosts []string
	for i, id := range ids {
		hosts = append(hosts, fmt.Sprintf("lab host %d = entity-%d at %s", i+1, id, ips[id]))
	}
	return fmt.Sprintf("Lab test step %d of %d for the application `%s`.\n\nTEST: %s\n\nLab hosts: %s.\n\n"+
		"Read README.md first. Run the test against the lab hosts, then write a short verdict to results/%d.md "+
		"(first line PASS or FAIL, then the evidence). Do not modify the application; only test it.",
		n, total, app, step, strings.Join(hosts, "; "), n)
}

func labPost(url, ctype string, body []byte, timeout time.Duration) (int, string) {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Post(url, ctype, bytes.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}

func labGet(url string, timeout time.Duration) (int, string) {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}

// labTeardown removes everything a run created: the harness namespace, the lab hosts (Entity
// CRs → the operator deletes their namespaces), their volumes on local-path storage, and the
// lab-only registry rows. Best-effort, always runs, never raises.
func labTeardown(runID string, ids []int) {
	if runID != "" { // "" = the orphan reap, which deletes lab- namespaces itself
		_, _ = kc(120*time.Second, "delete", "namespace", "lab-"+runID, "--ignore-not-found", "--wait=false")
	}
	for _, id := range ids {
		_, _ = kc(60*time.Second, "-n", "default", "delete", "entity", fmt.Sprintf("entity-%d", id), "--ignore-not-found", "--wait=false")
	}
	// wait for the CR to go (finalizers) and the operator to drop the namespace before wiping storage
	for _, id := range ids {
		for i := 0; i < 40; i++ {
			if _, err := kc(15*time.Second, "-n", "default", "get", "entity", fmt.Sprintf("entity-%d", id)); err != nil {
				break
			}
			time.Sleep(3 * time.Second)
		}
		for i := 0; i < 40; i++ {
			if _, err := kc(15*time.Second, "get", "namespace", fmt.Sprintf("entity-%d", id)); err != nil {
				break
			}
			time.Sleep(3 * time.Second)
		}
		for _, m := range []string{"entity-apps", "entity-data"} {
			matches, _ := filepath.Glob(fmt.Sprintf("%s/pvc-*_entity-%d_%s-entity-%d-0", labStorageRoot, id, m, id))
			for _, p := range matches {
				_ = os.RemoveAll(p)
			}
		}
	}
	_ = labDeleteRows(runID, ids)
}

// cmdLabSelftest — `privatae-bastion lab-selftest <spec.json>`: run mode=lab from a spec file on
// THIS box without the host relay, print the result. Operator tooling for the lab box; on any
// other box it prints the same refusal the relay would (wall #1).
func cmdLabSelftest(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var spec harnessSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("spec: %w", err)
	}
	spec.Mode = "lab"
	if spec.HarnessID == "" {
		spec.HarnessID = "lab"
	}
	out, code := runLab(spec)
	var pretty bytes.Buffer
	if json.Indent(&pretty, out, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(out))
	}
	if code != 0 {
		return fmt.Errorf("lab run exit %d", code)
	}
	return nil
}
