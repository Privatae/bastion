//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const serveNetnsEnv = "PRIVATAE_TEST_SERVE_NETNS"

// otherComputer is a computer on this machine's LAN, at 10.0.0.2 in a network
// namespace of its own, joined to this one by a veth that carries this
// machine's default route (so 10.0.0.2 is the LAN, not a container here). It
// listens on 80 and 11434 and counts what reaches it off the wire: IPv4
// packets addressed to it, TCP SYNs to any address (IPv4 and IPv6), and
// accepted connections.
type otherComputer struct {
	toIt    atomic.Int64
	syns    atomic.Int64
	accepts atomic.Int64
	stop    atomic.Bool
}

// startOtherComputer makes the namespace on one OS thread locked for good
// (the thread ends with its goroutine), so every socket it opens and every
// ip(8) it runs are the other computer's, and this test's are not.
func startOtherComputer(t *testing.T, ipBin string) *otherComputer {
	t.Helper()
	oc := &otherComputer{}
	t.Cleanup(func() { oc.stop.Store(true) })
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// This test's namespace, held open before the thread leaves it: the
		// veth's other end goes there. Not /proc/<pid>/ns/net, which is the
		// main thread's, and the main thread may be this one.
		here, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			errc <- err
			return
		}
		defer here.Close()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("unshare: %w", err)
			return
		}
		for _, a := range [][]string{
			{"link", "add", "vB", "type", "veth", "peer", "name", "vA", "netns", "/proc/self/fd/3"},
			{"link", "set", "lo", "up"},
			{"addr", "add", "10.0.0.2/24", "dev", "vB"},
			{"link", "set", "vB", "up"},
		} {
			cmd := exec.Command(ipBin, a...)
			cmd.ExtraFiles = []*os.File{here}
			if out, err := cmd.CombinedOutput(); err != nil {
				errc <- fmt.Errorf("ip %s: %v %s", strings.Join(a, " "), err, out)
				return
			}
		}
		for _, port := range []string{"80", "11434"} {
			ln, err := net.Listen("tcp", "10.0.0.2:"+port)
			if err != nil {
				errc <- err
				return
			}
			go func() {
				for !oc.stop.Load() {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					oc.accepts.Add(1)
					c.Close()
				}
			}()
			t.Cleanup(func() { ln.Close() })
		}
		ifi, err := net.InterfaceByName("vB")
		if err != nil {
			errc <- err
			return
		}
		proto := int(htons16(unix.ETH_P_ALL))
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, proto)
		if err != nil {
			errc <- fmt.Errorf("packet socket: %w", err)
			return
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
			unix.Close(fd)
			errc <- fmt.Errorf("bind the packet socket: %w", err)
			return
		}
		tv := unix.NsecToTimeval((200 * time.Millisecond).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		go oc.capture(fd)
		errc <- nil
	}()
	if err := <-errc; err != nil {
		t.Skipf("the other computer's namespace could not be made: %v", err)
	}
	return oc
}

func htons16(v uint16) uint16 { return v<<8 | v>>8 }

// capture counts the frames arriving on vB (its own replies are left out).
func (oc *otherComputer) capture(fd int) {
	defer unix.Close(fd)
	buf := make([]byte, 65536)
	for !oc.stop.Load() {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		f := buf[:n]
		if len(f) < 14 {
			continue
		}
		switch uint16(f[12])<<8 | uint16(f[13]) {
		case 0x0800:
			if len(f) < 34 {
				continue
			}
			ihl := int(f[14]&0x0f) * 4
			if net.IP(f[30:34]).Equal(net.IPv4(10, 0, 0, 2)) {
				oc.toIt.Add(1)
			}
			if f[23] == 6 && len(f) >= 14+ihl+14 && isSYN(f[14+ihl+13]) {
				oc.syns.Add(1)
			}
		case 0x86dd:
			if len(f) >= 14+40+14 && f[20] == 6 && isSYN(f[14+40+13]) {
				oc.syns.Add(1)
			}
		}
	}
}

func isSYN(flags byte) bool { return flags&0x02 != 0 && flags&0x10 == 0 }

// SECURITY, IN A REAL NETWORK NAMESPACE: a job that names an address instead
// of a service, a name the lane does not carry, and each service set on this
// machine to a computer on its LAN (OLLAMA_ADDR, PRIVATAE_LLM_ADDR and
// PRIVATAE_PII_ADDR all at 10.0.0.2) each answer 'E', and the other computer
// sees no packet addressed to it and no SYN at all, from the lane or from the
// beat that probes what the lane serves, the beat's model-management probe, or
// model:list. A direct dial from this machine
// afterwards is seen, so the count is real. Runs the test binary again in a
// private user and network namespace; skipped where one cannot be made.
//
// MUTATION: in serveVetTarget, skip the ownDestination check.
// RESULT: red — the other computer sees the lane's SYN on 11434 and 80.
// MUTATION: modelDaemonTarget returns localOllamaAddr() for every pairing.
// RESULT: red — the beat's model-swap probe and model:list SYN 10.0.0.2:11434.
func TestTheServeLaneSendsNoPacketForAnAddressInARealNamespace(t *testing.T) {
	if os.Getenv(serveNetnsEnv) != "1" {
		if _, err := exec.LookPath("ip"); err != nil {
			if _, err := os.Stat("/usr/sbin/ip"); err != nil {
				t.Skip("needs ip(8)")
			}
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestTheServeLaneSendsNoPacketForAnAddressInARealNamespace$",
			"-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), serveNetnsEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		out, err := cmd.CombinedOutput()
		if cmd.ProcessState == nil {
			t.Skipf("no private user and network namespace here: %v", err)
		}
		t.Logf("in a private network namespace:\n%s", out)
		if strings.Contains(string(out), "--- SKIP") {
			t.Skip("the namespaced run could not set up its network")
		}
		if err != nil {
			t.Fatalf("the namespaced run failed: %v", err)
		}
		if !strings.Contains(string(out), "--- PASS: TestTheServeLaneSendsNoPacketForAnAddressInARealNamespace") {
			t.Fatal("the namespaced run did not run")
		}
		return
	}

	ipBin, err := exec.LookPath("ip")
	if err != nil {
		ipBin = "/usr/sbin/ip"
	}
	if out, err := exec.Command(ipBin, "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Skipf("ip link set lo up: %v %s", err, out)
	}
	oc := startOtherComputer(t, ipBin)
	for _, a := range [][]string{
		{"addr", "add", "10.0.0.1/24", "dev", "vA"},
		{"link", "set", "vA", "up"},
		// This machine's way out: 10.0.0.2 is its LAN (and its router), not a
		// container on a veth of its own (ownaddr.go).
		{"route", "add", "default", "via", "10.0.0.2", "dev", "vA"},
	} {
		if out, err := exec.Command(ipBin, a...).CombinedOutput(); err != nil {
			t.Skipf("ip %s: %v %s", strings.Join(a, " "), err, out)
		}
	}
	t.Setenv("OLLAMA_ADDR", "10.0.0.2:11434")
	t.Setenv("PRIVATAE_LLM_ADDR", "10.0.0.2:80")
	t.Setenv("PRIVATAE_PII_ADDR", "10.0.0.2:80")
	h, cfg := serveLaneBox(t, "netns.example.test")
	// `models` stays on: the model-management probe in the beat and model:list
	// (modelswap.go, modelDaemonTarget) are held to this machine for a Host
	// with no platform too, so they are in the count.
	resetModelDaemonCache()
	runInBackground(t, cfg)
	beat := h.beat(t)
	if got := strsOf(beat["lane_serves"]); len(got) != 0 {
		t.Fatalf("nothing set here is this machine's, so nothing is served: %q", got)
	}
	for _, c := range capsOf(beat) {
		if c == modelSwapCapability {
			t.Fatalf("model management of the other computer is offered: %q", capsOf(beat))
		}
	}
	if _, errOut, code, _ := driveModelOp(t, cfg.HostName, "model:list", nil, ""); code == 0 ||
		!strings.Contains(errOut, "10.0.0.2 is not this machine") {
		t.Errorf("model:list of the other computer: exit %d, %q", code, errOut)
	}
	for service, want := range map[string]string{
		"10.0.0.2:80":    "never takes an address",
		"10.0.0.2:11434": "never takes an address",
		"nas":            "is not a service",
		"ollama":         "10.0.0.2 is not this machine",
		"llm":            "10.0.0.2 is not this machine",
		"pii":            "10.0.0.2 is not this machine",
	} {
		got := ask(t, h.take(t), service)
		if !strings.HasPrefix(got, "Erefused: ") || !strings.Contains(got, want) {
			t.Errorf("%q: answered %q, want E carrying %q", service, got, want)
		}
	}
	time.Sleep(500 * time.Millisecond)
	if a, s, c := oc.toIt.Load(), oc.syns.Load(), oc.accepts.Load(); a != 0 || s != 0 || c != 0 {
		t.Fatalf("the other computer saw %d packets addressed to it, %d SYNs and %d connections", a, s, c)
	}
	// The count is real: a dial from this machine is seen.
	c, err := net.DialTimeout("tcp", "10.0.0.2:80", 3*time.Second)
	if err != nil {
		t.Fatalf("the control dial to the other computer failed, so the count proves nothing: %v", err)
	}
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for oc.toIt.Load() == 0 || oc.syns.Load() == 0 || oc.accepts.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the control dial was not counted: %d packets, %d SYNs, %d connections",
				oc.toIt.Load(), oc.syns.Load(), oc.accepts.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
