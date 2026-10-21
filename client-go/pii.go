package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// piiForwardPort is the tunnel-side port the host dials to reach the PII
// sterilization service on this box's LAN (or this box). Reported in the
// heartbeat (agents.go "pii_port") so the host never has to assume it —
// ONE definition, here. Next in the forwarder series after llm's 18080.
const piiForwardPort = 18081

// piiProbe reports (advertised, healthy) for the PII sterilization lane.
// PRIVATAE_PII_ADDR unset means the service is absent — no probe, no
// capability, no heartbeat fields; a box without it is unaffected.
// When set, `advertised` is true even if the upstream is down: the
// forwarder is running, and pii_ok=false is the distinct, useful signal
// that the lane exists but its upstream is dead (the host gates writes
// on it instead of discovering the failure one request at a time).
//
// /health is the service's only unauthenticated route; 200 is alive.
// The bearer-authed surface is proxied opaquely — this client never
// holds the PII_API_KEY.
func piiProbe() (bool, bool) {
	a := piiTarget()
	if a == "" {
		return false, false
	}
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get("http://" + a + "/health")
	if err != nil {
		return true, false
	}
	defer resp.Body.Close()
	return true, resp.StatusCode == http.StatusOK
}

// servePIIForward is serveLLMForward's twin for the PII sterilization
// service: host dials <bastion tunnel IP>:18081, we proxy raw TCP to
// PRIVATAE_PII_ADDR. Only runs when the env is set (the operator's opt-in;
// unset = absent, nothing advertised). Raw TCP splice: no buffering, no
// body caps, no header rewrites — the service's own limits (2 MiB cap,
// bearer auth, fail-closed 502) pass through untouched, so moving the
// service to another machine is exactly one env change on this bastion.
func servePIIForward(ctx context.Context, self string, tnet *netstack.Net, gwIP netip.Addr) {
	target := piiTarget()
	if target == "" {
		return
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: gwIP.AsSlice(), Port: piiForwardPort})
	if err != nil {
		return
	}
	defer context.AfterFunc(ctx, func() { _ = ln.Close() })()
	refused := inferenceRefuser(self, "pii")
	scopeRefused := piiScopeRefuser(self)
	for {
		in, err := ln.Accept()
		if err != nil {
			return
		}
		if refused(in) || scopeRefused(in) {
			continue
		}
		go spliceConn(in, target)
	}
}

// piiScopeRefuser is the model-scope half of the accept gate, and the ONE place in
// this feature where a model scope really can be decided at accept time: the
// sterilizer is not a model, so a grant that names models says nothing about it
// and it is refused unless the reserved entry `pii` was named (modelscope.go).
// Same per-connection re-read and once-per-reason logging as inferenceRefuser.
func piiScopeRefuser(self string) func(in net.Conn) bool {
	logged := false
	return func(in net.Conn) bool {
		if pairingModelScope(self).allowsPII() {
			return false
		}
		_ = in.Close()
		if !logged {
			fmt.Printf("[%s] pii forward: refused — this pairing is scoped to named models and "+
				"the PII sterilizer was not one of them (approve with 'pii' in the model list to share it)\n", self)
			logged = true
		}
		return true
	}
}
