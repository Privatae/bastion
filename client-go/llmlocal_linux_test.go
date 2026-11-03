//go:build linux

package main

import (
	"net"
	"os"
	"strconv"
	"testing"
)

// Found without PRIVATAE_LLM_ADDR, a model server another account runs on the
// port is not handed the Host's prompts; root's, this bastion's and its own
// listener are.
//
// MUTATION: accept any uid in listenersTrusted. RESULT: red.
func TestAModelServerOfAnotherAccountIsNotTaken(t *testing.T) {
	table := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 1 1 0 100 0 0 10 0\n" +
		"   1: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0 0 10 0\n" +
		"   2: 0100007F:1F40 0100007F:9999 01 00000000:00000000 00:00000000 00000000  1002        0 3 1 0 100 0 0 10 0\n"
	if got := loopbackListenerUIDs(table, 8080); len(got) != 1 || got[0] != 1001 {
		t.Errorf("8080: %v", got)
	}
	if got := loopbackListenerUIDs(table, 8000); len(got) != 1 || got[0] != 0 {
		t.Errorf("8000 (an established connection is not a listener): %v", got)
	}
	for _, c := range []struct {
		uids  []uint32
		owner bool
		want  bool
	}{
		{[]uint32{0}, false, true}, {[]uint32{1000}, false, true}, {[]uint32{1001}, true, true},
		{[]uint32{1001}, false, false}, {[]uint32{1002}, true, false}, {[]uint32{0, 1002}, true, false}, {nil, true, false},
	} {
		if got := listenersTrusted(c.uids, 1000, 1001, c.owner); got != c.want {
			t.Errorf("listeners %v (owner recorded %v): trusted %v, want %v", c.uids, c.owner, got, c.want)
		}
	}
	// A listener of this process's own is trusted, a port nobody listens on is not.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !llmListenerTrusted(ln.Addr().String()) {
		t.Errorf("this process's own listener (uid %d) is not trusted", os.Getuid())
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	_ = ln.Close()
	if llmListenerTrusted("127.0.0.1:" + strconv.Itoa(n)) {
		t.Error("a port nobody listens on is trusted")
	}
	// Discovery skips an untrusted server for the next one.
	bad, good := openAIServer(t, oneModel), openAIServer(t, oneModel)
	withLLMCandidates(t, bad, good)
	prev := llmTrusted
	llmTrusted = func(a string) bool { return a != bad }
	t.Cleanup(func() { llmTrusted = prev })
	if got := llmTarget(); got != good {
		t.Errorf("llmTarget = %q, want the trusted one", got)
	}
}
