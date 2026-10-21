package main

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// rootExecConnectSubcommand makes this test binary the command a watch test
// runs: each argument is proto:host:port, dialled once ("fork" first runs the
// rest in a child process of its own, so the connection is a grandchild's).
const rootExecConnectSubcommand = "rootexec-watch-connect"

func rootExecConnectMain(args []string) int {
	if len(args) > 0 && args[0] == "fork" {
		c := exec.Command(os.Args[0], append([]string{rootExecConnectSubcommand}, args[1:]...)...)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			return 1
		}
		return 0
	}
	for _, a := range args {
		proto, hostport, ok := strings.Cut(a, ":")
		if !ok {
			return 2
		}
		conn, err := net.DialTimeout(proto, hostport, 300*time.Millisecond)
		if err != nil {
			continue // a destination nobody answers on still had a connection opened to it
		}
		if proto == "udp" {
			_, _ = conn.Write([]byte("x"))
		}
		_ = conn.Close()
	}
	return 0
}
