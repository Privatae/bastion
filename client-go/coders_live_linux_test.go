//go:build linux && coderlive

// The coder-mode check against a REAL container runtime (plan section 8,
// slice 4): three runs up, a LAN/loopback request through egress.sock is
// refused and a public one works, the control socket answers through the
// owner-only forward, and run-down of one leaves two.
//
// Not part of the package tests: it needs root, docker, a harness image whose
// sidecar serves the two sockets, and the internet. Run it by hand:
//
//	CODER_LIVE_IMAGE=<image> go test -tags coderlive -run TestCoderLive -v .

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCoderLive(t *testing.T) {
	img := os.Getenv("CODER_LIVE_IMAGE")
	if img == "" || os.Getuid() != 0 {
		t.Skip("set CODER_LIVE_IMAGE and run as root")
	}
	if detectRuntime() != "docker" {
		t.Skip("needs docker")
	}
	base := os.Getenv("CODER_LIVE_DIR")
	if base == "" {
		base = t.TempDir()
	}
	t.Setenv("XDG_CONFIG_HOME", base)
	// The image is a local build tagged <prefix>harness-claude-code:<tag>.
	// It runs the way an owner's local image does: the prefix is set to its
	// repository's, and the run names it by its image ID (coderLocalImage).
	repo := coderTagRepo(img)
	prefix, ok := strings.CutSuffix(repo, "harness-claude-code")
	if !ok || coderPrefixRefusal(prefix) != "" {
		t.Skipf("CODER_LIVE_IMAGE must be tagged <prefix>harness-claude-code:<tag>, got %q", img)
	}
	id, err := runCmd(10*time.Second, "docker", "image", "inspect", "--format", "{{.Id}}", img)
	if err != nil {
		t.Fatalf("inspect %s: %v %s", img, err, id)
	}
	img = repo + "@" + strings.TrimSpace(id)
	if err := saveCoderConfig(coderConfig{Enabled: true, Max: 3, MemPerRun: 1024, CPUsPerRun: 1,
		Engines: append([]string(nil), coderEngines...), ImagePrefix: prefix}); err != nil {
		t.Fatal(err)
	}
	const owner = "live.host.privatae.ai"
	writePairing(t, owner)
	ids := []string{"live-run-0001", "live-run-0002", "live-run-0003"}
	defer func() {
		for _, id := range ids {
			_, _ = runCmd(30*time.Second, "docker", "rm", "-f", coderContainerPrefix+id)
		}
	}()
	spec := func(id string) harnessSpec {
		return harnessSpec{Mode: "coder", CoderOp: "run-up", RunID: id, Engine: "claude-code", Image: img,
			UID: 10005, CredsDir: "/home/privatae/.claude",
			Creds:      map[string]string{".credentials.json": `{"claudeAiOauth":{"accessToken":"x"}}`},
			ControlCap: strings.Repeat("k", 43), owner: owner}
	}
	ports := map[string]int{}
	for _, id := range ids {
		b, code := runCoder(spec(id))
		t.Logf("run-up %s: exit %d %s", id, code, b)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if code != 0 || m["started"] != true {
			out, _ := runCmd(10*time.Second, "docker", "logs", "--tail", "40", coderContainerPrefix+id)
			t.Fatalf("run-up %s failed; container log:\n%s", id, out)
		}
		ports[id] = int(m["tunnel_port"].(float64))
	}
	// A fourth is the full answer.
	b, code := runCoder(spec("live-run-0004"))
	t.Logf("run-up past max: exit %d %s", code, b)
	if !strings.Contains(string(b), `"reason":"full"`) || code != 0 {
		t.Fatalf("the fourth run is the full answer")
	}
	c0 := coderContainerPrefix + ids[0]
	insp, _ := runCmd(10*time.Second, "docker", "inspect", "-f",
		"net={{.HostConfig.NetworkMode}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}} sec={{len .HostConfig.SecurityOpt}} "+
			"mem={{.HostConfig.Memory}} swap={{.HostConfig.MemorySwap}} cpus={{.HostConfig.NanoCpus}} pids={{.HostConfig.PidsLimit}} user={{.Config.User}}", c0)
	t.Logf("container: %s", strings.TrimSpace(insp))
	for _, want := range []string{"net=none", "ro=true", "caps=[ALL]", "mem=1073741824", "swap=1073741824", "cpus=1000000000", "pids=4096", "user=10005:10005"} {
		if !strings.Contains(insp, want) {
			t.Fatalf("container lacks %s", want)
		}
	}
	secopt, _ := runCmd(10*time.Second, "docker", "inspect", "-f", "{{range .HostConfig.SecurityOpt}}{{printf \"%.40s\" .}}|{{end}}", c0)
	t.Logf("security opts (first 40 chars each): %s", strings.TrimSpace(secopt))

	sh := func(script string) string {
		out, _ := runCmd(60*time.Second, "docker", "exec", c0, "sh", "-c", script)
		return strings.TrimSpace(out)
	}
	// No network of its own: a direct connection fails.
	direct := sh(`python3 -c "import socket
try:
    socket.create_connection(('1.1.1.1',443),5); print('DIRECT-OPEN')
except Exception as e: print('DIRECT-BLOCKED', type(e).__name__)"`)
	t.Logf("direct connect from the container: %s", direct)
	if !strings.Contains(direct, "DIRECT-BLOCKED") {
		t.Fatal("the container must have no network of its own")
	}
	sock := "/run/privatae/egress/egress.sock"
	for _, target := range []string{"http://127.0.0.1:22/", "http://192.168.1.1/", "http://10.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]:22/", "http://localhost:8080/"} {
		out := sh(`curl -sS -o /dev/null -D - --max-time 15 --unix-socket ` + sock + ` ` + target + ` 2>&1 | head -6`)
		t.Logf("curl %s via egress.sock -> %s", target, strings.ReplaceAll(out, "\r\n", " | "))
		if !strings.Contains(out, "403") || !strings.Contains(out, "X-Privatae-Refused") {
			t.Fatalf("%s must be refused", target)
		}
	}
	connect := sh(`python3 -c "import socket
s=socket.socket(socket.AF_UNIX); s.connect('` + sock + `')
s.sendall(b'CONNECT 192.168.0.1:443 HTTP/1.1\r\n\r\n'); print(s.recv(200).split(b'\r\n')[0].decode())"`)
	t.Logf("CONNECT 192.168.0.1:443 -> %s", connect)
	if !strings.Contains(connect, "403") {
		t.Fatal("a LAN CONNECT must be refused")
	}
	plain := sh(`curl -sS -o /dev/null -w '%{http_code}' --max-time 30 --unix-socket ` + sock + ` http://example.com/ 2>&1`)
	t.Logf("curl http://example.com/ via egress.sock -> %s", plain)
	pub := sh(`python3 -c "import socket,ssl
s=socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect('` + sock + `')
s.sendall(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n')
print('proxy:', s.recv(200).split(b'\r\n')[0].decode())
t=ssl.create_default_context().wrap_socket(s, server_hostname='example.com')
t.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
print('origin:', t.recv(200).split(b'\r\n')[0].decode())" 2>&1`)
	t.Logf("CONNECT example.com:443 + TLS GET / via egress.sock -> %s", strings.ReplaceAll(pub, "\n", " | "))
	if plain != "200" || !strings.Contains(pub, "proxy: HTTP/1.1 200") || !strings.Contains(pub, "origin: HTTP/1.1 200") {
		t.Fatalf("a public URL must work through egress.sock")
	}

	// The control forward: owner-only, spliced to the run's control socket.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrCh := make(chan string, 4)
	go serveCoderForwardsOn(ctx, owner, "127.0.0.1", func(port int) (net.Listener, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0") // in-process stand-in for the tunnel netstack
		if err == nil {
			addrCh <- fmt.Sprintf("%d=%s", port, ln.Addr())
		}
		return ln, err
	})
	var fwd string
	deadline := time.After(5 * time.Second)
	for fwd == "" {
		select {
		case a := <-addrCh:
			if strings.HasPrefix(a, fmt.Sprintf("%d=", ports[ids[0]])) {
				fwd = strings.SplitN(a, "=", 2)[1]
			}
		case <-deadline:
			t.Fatal("no forward for the first run")
		}
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + fwd + "/health")
	if err != nil {
		t.Fatalf("GET /health through the forward: %v", err)
	}
	hb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("GET /health through the forward -> %d %s", resp.StatusCode, strings.TrimSpace(string(hb)))
	if resp.StatusCode != 200 {
		t.Fatal("/health through the forward must answer 200")
	}

	// run-down one: two stay up.
	time.Sleep(2 * time.Second)
	db, dcode := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: ids[0], owner: owner})
	t.Logf("run-down %s: exit %d %s", ids[0], dcode, db)
	var dm map[string]any
	_ = json.Unmarshal(db, &dm)
	if dcode != 0 || dm["stopped"] != true {
		t.Fatal("run-down failed")
	}
	ps, _ := runCmd(10*time.Second, "docker", "ps", "--filter", "label="+coderLabelRun, "--format", "{{.Names}} {{.Status}}")
	t.Logf("coder containers after run-down of one:\n%s", strings.TrimSpace(ps))
	st, _ := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-status", owner: owner})
	t.Logf("run-status: %s", st)
	if strings.Count(strings.TrimSpace(ps), "\n") != 1 || strings.Contains(ps, ids[0]) {
		t.Fatal("run-down of one must leave exactly the other two")
	}
	for _, id := range ids[1:] {
		b, code := runCoder(harnessSpec{Mode: "coder", CoderOp: "run-down", RunID: id, owner: owner})
		t.Logf("run-down %s: exit %d %s", id, code, b)
	}
	left, _ := runCmd(10*time.Second, "docker", "ps", "-aq", "--filter", "label="+coderLabelRun)
	if strings.TrimSpace(left) != "" {
		t.Fatalf("containers left: %s", left)
	}
}
