//go:build !windows

// Uses setupBox / writePairingState / signTerms / grantTerms / driveOp /
// tAnchor / tMember from anchor_test.go, which are unix-only. buildtags_test.go
// enforces the tag.

package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeRuntime replaces the container runtime for one test. Every call is
// recorded; nothing touches a real docker or podman.
type fakeRuntime struct {
	mu      sync.Mutex
	calls   [][]string
	running map[string]bool
	netMode map[string]string // container -> reported network mode (default "none")
	failOn  string            // a verb ("pull", "run") that returns an error
}

func stubServiceRuntime(t *testing.T, rt string) *fakeRuntime {
	t.Helper()
	f := &fakeRuntime{running: map[string]bool{}, netMode: map[string]string{}}
	oldRun, oldRT := serviceRun, serviceRuntime
	serviceRuntime = func() string { return rt }
	serviceRun = func(_ time.Duration, name string, args ...string) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, append([]string{name}, args...))
		if len(args) == 0 {
			return "", nil
		}
		if args[0] == f.failOn {
			return "boom", os.ErrInvalid
		}
		switch args[0] {
		case "run":
			for i, a := range args {
				if a == "--name" && i+1 < len(args) {
					f.running[args[i+1]] = true
				}
			}
			return "0123456789abcdef0123\n", nil
		case "rm":
			delete(f.running, args[len(args)-1])
		case "inspect":
			c := args[len(args)-1]
			if f.failOn == "inspect" {
				return "Cannot connect to the Docker daemon", os.ErrDeadlineExceeded
			}
			if !f.running[c] {
				return "Error: No such container: " + c, os.ErrNotExist
			}
			if strings.Contains(strings.Join(args, " "), "State.Running") {
				return "true\n", nil
			}
			if strings.Contains(strings.Join(args, " "), "NetworkMode") {
				if m, ok := f.netMode[c]; ok {
					return m + "\n", nil
				}
				return "none\n", nil
			}
			return "172.17.0.9\n", nil
		}
		return "", nil
	}
	t.Cleanup(func() { serviceRun, serviceRuntime = oldRun, oldRT })
	return f
}

func (f *fakeRuntime) runArgs(t *testing.T) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if len(f.calls[i]) > 1 && f.calls[i][1] == "run" {
			return f.calls[i]
		}
	}
	t.Fatal("no `run` call was made")
	return nil
}

func forgeSpec(name string) harnessSpec {
	return harnessSpec{
		Mode: "service", ServiceOp: "up", ServiceName: name,
		Image: "gitea/gitea:1.26.2-rootless", Socket: "gitea.sock",
		DataPath: "/var/lib/gitea", DataUID: 1000,
		Envs: map[string]string{"GITEA__server__DISABLE_SSH": "true"},
	}
}

func decodeRes(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not JSON: %s", b)
	}
	return m
}

// The box refuses, before touching any runtime, every spec shape that could
// escape the slot: a name that is a path or a flag, an image that is a flag,
// a data path that is relative, the root, or a docker volume option.
func TestServiceSpecValidation(t *testing.T) {
	good := forgeSpec("forge")
	if why := validateServiceSpec(good); why != "" {
		t.Fatalf("a normal forge spec must pass: %s", why)
	}
	for _, img := range []string{
		"gitea/gitea:1.26.2-rootless", "codeberg.org/forgejo/forgejo:9", "localhost:5000/team/forge",
		"ghcr.io/owner/app@sha256:" + strings.Repeat("a", 64), "redis",
	} {
		sp := forgeSpec("forge")
		sp.Image = img
		if why := validateServiceSpec(sp); why != "" {
			t.Errorf("registry reference %q must pass: %s", img, why)
		}
	}
	bad := map[string]func(s *harnessSpec){
		"name with slash":      func(s *harnessSpec) { s.ServiceName = "../etc" },
		"name with dot":        func(s *harnessSpec) { s.ServiceName = "a.b" },
		"name leading dash":    func(s *harnessSpec) { s.ServiceName = "-x" },
		"name upper":           func(s *harnessSpec) { s.ServiceName = "Forge" },
		"name empty":           func(s *harnessSpec) { s.ServiceName = "" },
		"image as flag":        func(s *harnessSpec) { s.Image = "--privileged" },
		"image archive":        func(s *harnessSpec) { s.Image = "docker-archive:/home/u/x.tar" },
		"image oci dir":        func(s *harnessSpec) { s.Image = "oci:/srv/layout" },
		"image dir transport":  func(s *harnessSpec) { s.Image = "dir:/tmp/img" },
		"image local storage":  func(s *harnessSpec) { s.Image = "containers-storage:foo" },
		"image daemon":         func(s *harnessSpec) { s.Image = "docker-daemon:foo:latest" },
		"image url":            func(s *harnessSpec) { s.Image = "docker://gitea/gitea" },
		"image uppercase":      func(s *harnessSpec) { s.Image = "Gitea/Gitea" },
		"image with space":     func(s *harnessSpec) { s.Image = "a b" },
		"image empty":          func(s *harnessSpec) { s.Image = "" },
		"socket missing":       func(s *harnessSpec) { s.Socket = "" },
		"socket path":          func(s *harnessSpec) { s.Socket = "../../etc/x.sock" },
		"socket subdir":        func(s *harnessSpec) { s.Socket = "run/gitea.sock" },
		"socket dotdot":        func(s *harnessSpec) { s.Socket = ".." },
		"data path relative":   func(s *harnessSpec) { s.DataPath = "var/lib" },
		"data path root":       func(s *harnessSpec) { s.DataPath = "/" },
		"data path unclean":    func(s *harnessSpec) { s.DataPath = "/var/../etc" },
		"data path volume opt": func(s *harnessSpec) { s.DataPath = "/data:rw" },
		"env key flag":         func(s *harnessSpec) { s.Envs = map[string]string{"-e": "x"} },
		"env key equals":       func(s *harnessSpec) { s.Envs = map[string]string{"A=B": "x"} },
		"env value newline":    func(s *harnessSpec) { s.Envs = map[string]string{"A": "x\ny"} },
		"data uid negative":    func(s *harnessSpec) { s.DataUID = -1 },
		"data uid root":        func(s *harnessSpec) { s.DataUID = 0 },
	}
	for label, mut := range bad {
		s := forgeSpec("forge")
		mut(&s)
		if why := validateServiceSpec(s); why == "" {
			t.Errorf("%s: must be refused", label)
		}
	}
}

// `up` starts a container that STAYS: restart policy, the slot's own data dir
// as the only mount, no new privileges, all caps dropped, and never -p.
func TestServiceUpRunsAStayingContainerWithNoPublishedPort(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubServiceRuntime(t, "docker")
	spec := forgeSpec("forge")
	spec.owner = "anchor.host.privatae.ai"
	b, code := runService(spec)
	if code != 0 {
		t.Fatalf("up failed: %s", b)
	}
	res := decodeRes(t, b)
	if res["tunnel_port"] != float64(servicePortBase) {
		t.Fatalf("the first slot takes the first port, got %v", res["tunnel_port"])
	}
	args := f.runArgs(t)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--restart unless-stopped", "--security-opt no-new-privileges", "--cap-drop ALL", "--network none",
		"--name privatae-svc-forge", "-e GITEA__server__DISABLE_SSH=true",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("run args lack %q: %s", want, joined)
		}
	}
	for _, a := range args {
		if a == "-p" || a == "--publish" || strings.HasPrefix(a, "--publish=") || a == "--privileged" ||
			a == "--network=host" || a == "bridge" || a == "host" {
			t.Fatalf("run must never carry %q (it mutates the host network or widens the container): %s", a, joined)
		}
	}
	data, _ := serviceDataDir("forge")
	if !strings.Contains(joined, "-v "+data+":/var/lib/gitea") {
		t.Fatalf("the one mount must be the slot's data dir: %s", joined)
	}
	if args[len(args)-1] != spec.Image {
		t.Fatalf("the image must be the last argument, got %q", args[len(args)-1])
	}
	rec, err := loadServiceRecord("forge")
	if err != nil {
		t.Fatalf("no record written: %v", err)
	}
	if rec.Owner != spec.owner || rec.Socket != "gitea.sock" || rec.TunnelPort != servicePortBase {
		t.Fatalf("record wrong: %+v", rec)
	}
	if st, _ := os.Stat(data); st == nil || !st.IsDir() {
		t.Fatal("the data dir must exist")
	}
}

// A slot keeps its tunnel port across a re-up; a second slot takes the next.
func TestServicePortsAreStableAndDistinct(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubServiceRuntime(t, "docker")
	for _, n := range []string{"forge", "mirror-a"} {
		if b, code := runService(forgeSpec(n)); code != 0 {
			t.Fatalf("up %s: %s", n, b)
		}
	}
	b, code := runService(forgeSpec("forge"))
	if code != 0 {
		t.Fatalf("re-up: %s", b)
	}
	if got := decodeRes(t, b)["tunnel_port"]; got != float64(servicePortBase) {
		t.Fatalf("a re-up must keep the slot's port, got %v", got)
	}
	r2, _ := loadServiceRecord("mirror-a")
	if r2.TunnelPort != servicePortBase+1 {
		t.Fatalf("the second slot takes the next port, got %d", r2.TunnelPort)
	}
	recs := []serviceRecord{}
	for p := servicePortBase; p <= servicePortMax; p++ {
		recs = append(recs, serviceRecord{Name: "s" + strconv.Itoa(p), TunnelPort: p})
	}
	if allocServicePort("new", recs) != 0 {
		t.Fatal("a full range must report 0, never reuse a port")
	}
}

// `down` removes the container and the record and KEEPS the data — it is the
// user's repos — unless purge is asked for.
func TestServiceDownKeepsDataUnlessPurged(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubServiceRuntime(t, "docker")
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	data, _ := serviceDataDir("forge")
	_ = os.WriteFile(filepath.Join(data, "repo.git"), []byte("x"), 0o600)
	if b, code := runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge"}); code != 0 {
		t.Fatalf("down: %s", b)
	}
	if f.running["privatae-svc-forge"] {
		t.Fatal("down must remove the container")
	}
	if _, err := loadServiceRecord("forge"); err == nil {
		t.Fatal("down must remove the record")
	}
	if _, err := os.Stat(filepath.Join(data, "repo.git")); err != nil {
		t.Fatal("down without purge must keep the data")
	}
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up again: %s", b)
	}
	if b, code := runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge", Purge: true}); code != 0 {
		t.Fatalf("purge: %s", b)
	}
	if _, err := os.Stat(data); !os.IsNotExist(err) {
		t.Fatal("purge must delete the slot's data")
	}
	if b, code := runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge"}); code == 0 {
		t.Fatalf("down of a slot that does not exist must fail: %s", b)
	}
	sp := forgeSpec("forge")
	sp.Image = "docker:27"
	if why := validateServiceSpec(sp); why != "" {
		t.Fatalf("the official docker image by its short name must pass: %s", why)
	}
}

// A failed run leaves no record behind, so the forward never listens for a
// server that is not there; and no runtime means a clear refusal.
func TestServiceUpFailuresLeaveNothing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubServiceRuntime(t, "docker")
	f.failOn = "run"
	if _, code := runService(forgeSpec("forge")); code == 0 {
		t.Fatal("a failed run must fail the job")
	}
	if _, err := loadServiceRecord("forge"); err == nil {
		t.Fatal("a failed run must not leave a record")
	}
	stubServiceRuntime(t, "")
	b, code := runService(forgeSpec("forge"))
	if code == 0 || !strings.Contains(string(b), "no container runtime") {
		t.Fatalf("no runtime must refuse plainly: %s", b)
	}
	if b, code := runService(harnessSpec{Mode: "service", ServiceOp: "restart"}); code == 0 {
		t.Fatalf("an unknown verb must be refused: %s", b)
	}
}

// Status reports each slot's port and live state from the runtime.
func TestServiceStatusReportsSlots(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubServiceRuntime(t, "docker")
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	reps := serviceReports()
	if len(reps) != 1 || reps[0].State != "running" || reps[0].TunnelPort != servicePortBase {
		t.Fatalf("status wrong: %+v", reps)
	}
	delete(f.running, "privatae-svc-forge")
	if reps := serviceReports(); reps[0].State != "missing" {
		t.Fatalf("a vanished container must read missing, got %+v", reps)
	}
	up, ok := serviceUpstream("forge")
	if ok {
		t.Fatalf("no container, no upstream: %s", up)
	}
	f.running["privatae-svc-forge"] = true
	data, _ := serviceDataDir("forge")
	if up, ok := serviceUpstream("forge"); ok {
		t.Fatalf("no socket file yet: nothing to serve, got %q", up)
	}
	ln, err := net.Listen("unix", filepath.Join(data, "gitea.sock"))
	if err != nil {
		t.Skip("no unix sockets here: " + err.Error())
	}
	defer ln.Close()
	if up, ok := serviceUpstream("forge"); !ok || up != filepath.Join(data, "gitea.sock") {
		t.Fatalf("upstream must be the socket in the slot's own data dir, got %q", up)
	}
	// A slot container that has ANY network is not served: the forward must never
	// be the door into a server that can reach the user's machines.
	for _, mode := range []string{"bridge", "host", "privatae-net", ""} {
		f.netMode["privatae-svc-forge"] = mode
		if up, ok := serviceUpstream("forge"); ok {
			t.Fatalf("network mode %q must not be served, got %q", mode, up)
		}
	}
}

// The family: every service verb and the forward are "services", never
// "harness" — a grant for jobs is not a grant for a server that stays.
func TestServiceOpsAreTheirOwnFamily(t *testing.T) {
	for _, op := range []string{"service:up", "service:down", "service:status", "service:anything", serviceCapability} {
		if fam := opFamily(op); fam != "services" {
			t.Errorf("%s must be family services, got %q", op, fam)
		}
	}
	if opFamily("session:open") != "session" {
		t.Fatal("service: must not swallow session:")
	}
}

// driveHarness sends one H frame through the real harness lane as pairing
// `self` and returns the J body and X code.
func driveHarness(t *testing.T, self string, spec harnessSpec) (map[string]any, int) {
	t.Helper()
	up := websocket.Upgrader{}
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleHarnessConn(ws, self, "")
		<-done
	}))
	defer srv.Close()
	defer close(done)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	b, _ := json.Marshal(spec)
	if err := ws.WriteMessage(websocket.BinaryMessage, append([]byte{'H'}, b...)); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	code := -1
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	for code < 0 {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("lane closed before X: %v", err)
		}
		switch msg[0] {
		case 'J':
			_ = json.Unmarshal(msg[1:], &body)
		case 'X':
			code, _ = strconv.Atoi(string(msg[1:]))
		}
	}
	return body, code
}

// On an anchored box, a member pairing granted "harness" is NOT granted a
// server: the lane gates a service job on "services". Granted "services",
// the same job runs and the record names the member as owner. And a second
// member-built slot cannot be stopped by the anchor-less member path of
// another host.
func TestHarnessLaneGatesServiceJobsOnTheServicesFamily(t *testing.T) {
	priv := setupBox(t)
	stubServiceRuntime(t, "docker")
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	approved := func(sp harnessSpec) harnessSpec {
		sp.Approval = signService(t, sp)
		return sp
	}
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	grant := func(caps []string) {
		terms, sig := signTerms(t, priv, grantTerms(tMember, caps, future))
		if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
			t.Fatalf("grant: %d %s", code, errOut)
		}
	}

	grant([]string{"harness"})
	body, code := driveHarness(t, tMember, forgeSpec("forge"))
	if code != 126 || !strings.Contains(body["error"].(string), "services") {
		t.Fatalf("harness alone must not build a server: %d %v", code, body)
	}
	if _, err := loadServiceRecord("forge"); err == nil {
		t.Fatal("a refused job must leave no slot")
	}

	grant([]string{"services"})
	// Holding the family is the ceiling; the write itself still needs the
	// person's approval on an anchored box.
	body, code = driveHarness(t, tMember, forgeSpec("forge"))
	if code != 126 || !strings.Contains(body["error"].(string), "changes this machine") {
		t.Fatalf("an unapproved up must be refused: %d %v", code, body)
	}
	body, code = driveHarness(t, tMember, approved(forgeSpec("forge")))
	if code != 0 {
		t.Fatalf("a services grant must build the server: %d %v", code, body)
	}
	rec, _ := loadServiceRecord("forge")
	if rec == nil || rec.Owner != tMember {
		t.Fatalf("the owner must be the pairing the lane saw, not anything in the JSON: %+v", rec)
	}

	// A host cannot claim a slot by naming an owner: the field is unexported,
	// so this JSON key is ignored.
	raw := map[string]any{"mode": "service", "service_op": "down", "service_name": "forge", "owner": tMember}
	b, _ := json.Marshal(raw)
	var spec harnessSpec
	_ = json.Unmarshal(b, &spec)
	if spec.owner != "" {
		t.Fatal("owner must not be settable from the host's JSON")
	}

	// The ANCHOR may stop a member's slot (its user is the machine's admin).
	// status is a read: no approval.
	body, code = driveHarness(t, tMember, harnessSpec{Mode: "service", ServiceOp: "status"})
	if code != 0 {
		t.Fatalf("status needs no approval: %d %v", code, body)
	}
	body, code = driveHarness(t, tAnchor, approved(harnessSpec{HarnessID: "d1", Mode: "service", ServiceOp: "down", ServiceName: "forge"}))
	if code != 0 {
		t.Fatalf("the anchor must be able to stop a member's server: %d %v", code, body)
	}
}

// A member cannot replace or stop a slot another host built.
func TestServiceOwnerRuleOnAnAnchoredBox(t *testing.T) {
	setupBox(t)
	r := &serviceRecord{Name: "forge", Owner: tAnchor}
	if why := serviceOwnerRefusal(tMember, r); why == "" {
		t.Fatal("a member must not change the anchor's server")
	}
	if why := serviceOwnerRefusal(tAnchor, &serviceRecord{Name: "forge", Owner: tMember}); why != "" {
		t.Fatalf("the anchor may change any server: %s", why)
	}
	if why := serviceOwnerRefusal(tMember, &serviceRecord{Name: "forge", Owner: tMember}); why != "" {
		t.Fatalf("the builder may change its own server: %s", why)
	}
	// Local box: one host, no owner rule to apply.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if why := serviceOwnerRefusal(tMember, r); why != "" {
		t.Fatalf("a local bastion serves one host: %s", why)
	}
}

// signService signs the approval a service verb spends, the way the person's
// device would: this verb, on this machine, bound to serviceArgs.
func signService(t *testing.T, sp harnessSpec) string {
	t.Helper()
	hn, _ := os.Hostname()
	a, err := deviceSign(mgmtOpPurpose(serviceGateOp(sp.ServiceOp), hn, serviceArgs(sp)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// The approval binds the whole server: an approval for one image, port, data
// path or env cannot start another, and purge is part of what was approved.
func TestServiceApprovalBindsTheWholeServer(t *testing.T) {
	setupBox(t)
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	spec := forgeSpec("forge")
	spec.HarnessID = "s1"
	spec.Approval = signService(t, spec)
	if why := harnessGate(tAnchor, "", spec); why != "" {
		t.Fatalf("a matching up passes: %s", why)
	}
	if why := harnessGate(tAnchor, "", spec); why == "" {
		t.Fatal("an approval is spent once")
	}
	for label, mut := range map[string]func(s *harnessSpec){
		"image":     func(s *harnessSpec) { s.Image = "evil/image:latest" },
		"socket":    func(s *harnessSpec) { s.Socket = "other.sock" },
		"data path": func(s *harnessSpec) { s.DataPath = "/etc" },
		"data uid":  func(s *harnessSpec) { s.DataUID = 0 },
		"env":       func(s *harnessSpec) { s.Envs = map[string]string{"X": "y"} },
		"name":      func(s *harnessSpec) { s.ServiceName = "other" },
		"verb":      func(s *harnessSpec) { s.ServiceOp = "down" },
	} {
		sp := forgeSpec("forge")
		sp.HarnessID = "s2"
		sp.Approval = signService(t, sp)
		mut(&sp)
		if why := harnessGate(tAnchor, "", sp); why == "" {
			t.Errorf("a changed %s is a different server and must be refused", label)
		}
	}
	down := harnessSpec{HarnessID: "d1", Mode: "service", ServiceOp: "down", ServiceName: "forge"}
	down.Approval = signService(t, down)
	down.Purge = true
	if why := harnessGate(tAnchor, "", down); why == "" {
		t.Fatal("an approval to stop a server is not an approval to delete its data")
	}
	status := harnessSpec{Mode: "service", ServiceOp: "status"}
	if why := harnessGate(tAnchor, "", status); why != "" {
		t.Fatalf("status is a read: it spends nothing and answers even a pairing whose writes are quarantined: %s", why)
	}
	// Every other mode's approval is exactly what it was: harnessArgs does not
	// grow for this feature.
	if n := len(harnessArgs(harnessSpec{Mode: "git"})); n != 16 {
		t.Fatalf("harnessArgs must stay 16 fields for the existing modes, got %d", n)
	}
}

// A stop that cannot remove the container fails and keeps the record: a
// record dropped while its container runs is a server nobody can see.
func TestServiceDownThatCannotStopKeepsTheRecord(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubServiceRuntime(t, "docker")
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	f.failOn = "rm"
	b, code := runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge"})
	if code == 0 || !strings.Contains(string(b), "may still be there") {
		t.Fatalf("a failed stop must say the server is still there: %s", b)
	}
	if _, err := loadServiceRecord("forge"); err != nil {
		t.Fatal("a failed stop must keep the record")
	}
	stubServiceRuntime(t, "")
	b, code = runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge"})
	if code == 0 || !strings.Contains(string(b), "nothing was changed") {
		t.Fatalf("no runtime: the stop cannot be confirmed and must change nothing: %s", b)
	}
	if _, err := loadServiceRecord("forge"); err != nil {
		t.Fatal("no runtime must keep the record")
	}
}

// A purge that cannot delete everything says so instead of reporting purged.
func TestServicePurgeFailureIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		// Root (including the test namespace's mapped root) can remove a
		// read-only directory's entries, so the failure cannot be staged.
		t.Skip("needs a non-root uid to make a directory undeletable")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubServiceRuntime(t, "docker")
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	data, _ := serviceDataDir("forge")
	sub := filepath.Join(data, "locked")
	_ = os.MkdirAll(sub, 0o700)
	_ = os.WriteFile(filepath.Join(sub, "f"), []byte("x"), 0o600)
	_ = os.Chmod(sub, 0o500)
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	b, code := runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge", Purge: true})
	if code == 0 || decodeRes(t, b)["purged"] != false {
		t.Fatalf("a partial purge must not report purged: %s", b)
	}
}

// Parallel ups never share a tunnel port.
func TestConcurrentServiceUpsTakeDistinctPorts(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stubServiceRuntime(t, "docker")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if b, code := runService(forgeSpec("s" + strconv.Itoa(i))); code != 0 {
				t.Errorf("up %d: %s", i, b)
			}
		}(i)
	}
	wg.Wait()
	seen := map[int]string{}
	for _, r := range loadServiceRecords() {
		if other, dup := seen[r.TunnelPort]; dup {
			t.Fatalf("%s and %s share port %d", r.Name, other, r.TunnelPort)
		}
		seen[r.TunnelPort] = r.Name
	}
	if len(seen) != 8 {
		t.Fatalf("want 8 slots, got %d", len(seen))
	}
}

// A frame that does not parse, from a pairing outside every family, gets the
// caps refusal — never "bad harness spec" — so it learns nothing about the lane.
func TestMalformedServiceFrameIsGatedAsHarnessFirst(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleHarnessConn(ws, tMember, "")
	}))
	defer srv.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.WriteMessage(websocket.BinaryMessage, []byte(`H{"mode":"service","service_op":`))
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := ws.ReadMessage()
	if err != nil || msg[0] != 'J' {
		t.Fatalf("want a J frame: %v %q", err, msg)
	}
	if strings.Contains(string(msg), "bad harness spec") || !strings.Contains(string(msg), "caps") {
		t.Fatalf("an unauthorized malformed frame must get the caps refusal: %s", msg)
	}
}

// The pod and the box must derive the SAME purpose for a service verb, or
// every approval is refused. This vector is pinned on both sides: the pod's
// scripts/test_bastion_service_slot.py computes the same digest from
// nac_harness.service_approval_args.
func TestServiceArgsMatchThePodVector(t *testing.T) {
	sp := harnessSpec{HarnessID: "s1", Mode: "service", ServiceOp: "up", ServiceName: "forge",
		Image: "gitea/gitea:1.26.2-rootless", Socket: "gitea.sock", DataPath: "/var/lib/gitea", DataUID: 1000,
		Envs: map[string]string{"GITEA__server__DISABLE_SSH": "true", "B": "2"}}
	const want = "mgmt_op|service:up|box1|5cdcf7d1a0ff93ec85ed757e96c56aa80cf45f05018a56d52b07b6915d2318a3"
	if got := mgmtOpPurpose("service:up", "box1", serviceArgs(sp)); got != want {
		t.Fatalf("purpose drifted from the pod's:\n got  %s\n want %s", got, want)
	}
}

// A stop whose rm fails while the daemon cannot say whether the container
// exists keeps the record: an unknown is not an absence.
func TestServiceDownWithAnUnansweringDaemonKeepsTheRecord(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubServiceRuntime(t, "docker")
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	f.failOn = "rm"
	f.mu.Lock()
	f.running["privatae-svc-forge"] = true
	f.mu.Unlock()
	// rm fails AND inspect cannot reach the daemon.
	serviceRunInner := serviceRun
	serviceRun = func(d time.Duration, name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "inspect" {
			return "Cannot connect to the Docker daemon", os.ErrDeadlineExceeded
		}
		return serviceRunInner(d, name, args...)
	}
	b, code := runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge"})
	if code == 0 {
		t.Fatalf("an unanswering daemon must not read as a stopped server: %s", b)
	}
	if _, err := loadServiceRecord("forge"); err != nil {
		t.Fatal("the record must survive an unknown")
	}
	// And rm failing on a container the runtime says is gone lets it go.
	serviceRun = serviceRunInner
	f.mu.Lock()
	delete(f.running, "privatae-svc-forge")
	f.mu.Unlock()
	if b, code := runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: "forge"}); code != 0 {
		t.Fatalf("a container the runtime says is gone may be forgotten: %s", b)
	}
}

// An invalid service request is refused before the lane spends an approval.
func TestInvalidServiceRequestSpendsNoApproval(t *testing.T) {
	priv := setupBox(t)
	stubServiceRuntime(t, "docker")
	pub, _ := deviceInit()
	_ = pinDeviceKey(pub)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"services"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
	bad := forgeSpec("forge")
	bad.HarnessID = "b1"
	bad.DataPath = "relative"
	bad.Approval = signService(t, bad)
	body, code := driveHarness(t, tMember, bad)
	if code != 1 || !strings.Contains(body["error"].(string), "data_path") {
		t.Fatalf("an invalid up must be refused on its own terms: %d %v", code, body)
	}
	// The same approval was NOT spent: fixing nothing about the approval, the
	// gate still accepts it for the spec it was signed over.
	if why := harnessGate(tMember, "", bad); why != "" {
		t.Fatalf("the refused request must not have spent its approval: %s", why)
	}
}

// The container owns its data dir: a link at the socket's name, pointing at
// some other socket on the machine, is never followed.
func TestServiceUpstreamRefusesALinkInPlaceOfTheSocket(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := stubServiceRuntime(t, "docker")
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	f.running["privatae-svc-forge"] = true
	other := filepath.Join(t.TempDir(), "runtime.sock")
	ln, err := net.Listen("unix", other)
	if err != nil {
		t.Skip("no unix sockets here: " + err.Error())
	}
	defer ln.Close()
	data, _ := serviceDataDir("forge")
	if err := os.Symlink(other, filepath.Join(data, "gitea.sock")); err != nil {
		t.Fatal(err)
	}
	if up, ok := serviceUpstream("forge"); ok {
		t.Fatalf("a symlink at the socket name must not be served: %q", up)
	}
	_ = os.Remove(filepath.Join(data, "gitea.sock"))
	_ = os.WriteFile(filepath.Join(data, "gitea.sock"), []byte("x"), 0o600)
	if up, ok := serviceUpstream("forge"); ok {
		t.Fatalf("a plain file at the socket name must not be served: %q", up)
	}
}

// The far end must be the server's own uid: a socket answered by anyone else
// (root included) is closed without carrying a byte.
func TestSpliceUnixRefusesAPeerThatIsNotTheServer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets here: " + err.Error())
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SECRET"))
			_ = c.Close()
		}
	}()
	for _, want := range []int{0, os.Getuid() + 1} {
		a, b := net.Pipe()
		go spliceUnix(b, sock, want)
		_ = a.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 6)
		n, _ := io.ReadFull(a, buf)
		if n > 0 {
			t.Fatalf("wantUID %d: a peer that is not the server must get nothing through, got %q", want, buf[:n])
		}
		_ = a.Close()
	}
}

// The forward's last hop: a tunnel connection spliced to the slot's unix socket,
// both ways, when the peer IS the server's uid. Needs a non-root uid: root is 0
// and 0 is always refused, so under the test namespace's mapped root this skips
// and the positive case is run as an unprivileged user instead.
func TestSpliceUnixCarriesBothWays(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the server uid must be non-root; run as an unprivileged user")
	}
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets here: " + err.Error())
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write(append([]byte("echo:"), buf...))
		}
	}()
	a, b := net.Pipe()
	go spliceUnix(b, sock, os.Getuid())
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := a.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 10)
	if _, err := io.ReadFull(a, got); err != nil || string(got) != "echo:hello" {
		t.Fatalf("splice: %q %v", got, err)
	}
	_ = a.Close()
}
