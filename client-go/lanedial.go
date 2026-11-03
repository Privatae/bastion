package main

// lanedial.go: the one place a lane turns the connection its pairing's
// transport hands it into the mutual TLS the lane runs inside.
//
// Every transport but one hands a lane a plain connection (the tunnel, the
// lane socket, a Host's lane port), and the TLS is done here exactly as the
// WebSocket library did it before: the pairing's lane configuration, the
// server name it names, the handshake under the dial's context, and the name
// checked once more. A Host that connects to this server (hostdoor.go) hands
// the lane a connection whose TLS the door already did, under the same
// configuration (the Host's CA pinned, host.cseries.internal, this bastion's
// operator certificate): that one is passed on as it is. So the lane code is
// the same for every pairing; only the dial differs.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// laneTLSDial is the TLS dial every lane uses: dialHost's connection with the
// lane's TLS done on it, or a Host-opened connection as the door left it.
func laneTLSDial(dialHost func(ctx context.Context) (net.Conn, error), tlsCfg *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		c, err := dialHost(ctx)
		if err != nil {
			return nil, err
		}
		if hc, ok := c.(*hostOpenedConn); ok {
			return hc, nil
		}
		cfg := tlsCfg.Clone()
		if cfg == nil {
			cfg = &tls.Config{}
		}
		if cfg.ServerName == "" {
			if h, _, err := net.SplitHostPort(addr); err == nil {
				cfg.ServerName = h
			} else {
				cfg.ServerName = addr
			}
		}
		tc := tls.Client(c, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			return nil, err
		}
		if !cfg.InsecureSkipVerify {
			if err := tc.VerifyHostname(cfg.ServerName); err != nil {
				_ = tc.Close()
				return nil, err
			}
		}
		return tc, nil
	}
}

// laneWSDialer is the WebSocket dialer every lane worker pool uses.
func laneWSDialer(tlsCfg *tls.Config, dialHost func(ctx context.Context) (net.Conn, error)) *websocket.Dialer {
	return &websocket.Dialer{
		NetDialContext:    func(ctx context.Context, network, addr string) (net.Conn, error) { return dialHost(ctx) },
		NetDialTLSContext: laneTLSDial(dialHost, tlsCfg),
		TLSClientConfig:   tlsCfg,
		HandshakeTimeout:  20 * time.Second,
	}
}

// laneHTTPTransport is the HTTP transport of a local pairing's requests (the
// heartbeat, git credentials, store proposals, context pulls).
func laneHTTPTransport(dialHost func(ctx context.Context) (net.Conn, error), tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return dialHost(ctx) },
		DialTLSContext:  laneTLSDial(dialHost, tlsCfg),
		TLSClientConfig: tlsCfg.Clone(),
	}
}
