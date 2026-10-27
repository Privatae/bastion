//go:build !windows

// Tagged !windows: it borrows localEgressFixture and answerEgressNames
// (egress_local_test.go).

package main

// The egress lane on a local (unanchored) box refuses the network around the
// machine as well as the machine itself: the LAN, the mesh and every other
// address that is not the public internet, by address and by any address a
// name resolves to. The Host's egress gate holds every dial to the same rule;
// a person's own machines are reached through their approved lanes.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// MUTATION: drop the local-box internalIP loop at the end of egressVettedAddrs.
// RESULT: red — 192.168.50.20, nas.example.test and the rest are handed to the
// dial, and the lane dials 192.168.50.30.
func TestLocalEgressRefusesTheLANAndTheMesh(t *testing.T) {
	localEgressFixture(t)
	answerEgressNames(t, map[string][]string{
		"nas.example.test":  {"192.168.50.30"},
		"half.example.test": {"198.51.100.8", "10.1.2.3"},
		"mesh.example.test": {"fd12:3456::9"},
		"nat.example.test":  {"64:ff9b::a01:203"}, // NAT64 for 10.1.2.3
		"pub.example.test":  {"198.51.100.8"},
	})
	ctx := context.Background()
	for _, hp := range []string{
		"192.168.50.20:8080", "10.1.2.3:443", "172.16.4.4:22", "[fd12:3456::9]:80", "100.64.0.9:80",
		"198.18.0.1:80", "[64:ff9b::a01:203]:443",
		"nas.example.test:443", "half.example.test:443", "mesh.example.test:80", "nat.example.test:443",
	} {
		if addrs, why := egressVettedAddrs(ctx, hp); why == "" || addrs != nil || !strings.Contains(why, "approved lanes") {
			t.Errorf("%s is not the public internet and must be refused on a local box, got dial %v %q", hp, addrs, why)
		}
	}
	if got, why := egressVettedAddrs(ctx, "pub.example.test:443"); why != "" || !reflect.DeepEqual(got, []string{"198.51.100.8:443"}) {
		t.Fatalf("the public internet passes at its vetted address: %v %q", got, why)
	}

	// Through the lane itself: 403, and nothing is dialled.
	var asked []string
	recording := func(_ context.Context, _, addr string) (net.Conn, error) {
		asked = append(asked, addr)
		return nil, errors.New("stop here")
	}
	for _, req := range []string{
		"CONNECT nas.example.test:443 HTTP/1.1\r\n\r\n",
		"GET http://10.1.2.3/ HTTP/1.1\r\nHost: 10.1.2.3\r\n\r\n",
		"CONNECT half.example.test:443 HTTP/1.1\r\n\r\n",
	} {
		srv, cli := net.Pipe()
		go handleEgressConn(srv, recording, "home.host.example")
		_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(cli, req)
		line, _ := bufio.NewReader(cli).ReadString('\n')
		cli.Close()
		if !strings.HasPrefix(line, "HTTP/1.1 403") {
			t.Errorf("a local box must refuse %q, answered %q", req, line)
		}
	}
	if len(asked) != 0 {
		t.Fatalf("nothing on the network around this machine is dialled: %v", asked)
	}
}
