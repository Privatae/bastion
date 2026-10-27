package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const egressWorkerCount = 4

// wsConn adapts a worker WebSocket into a net.Conn so the existing handleEgressConn drives
// it unchanged. The host frames the proxied client stream as binary messages: 'D'+payload =
// data, 'E' = end-of-stream. Reads surface the host's bytes; writes go back as 'D' frames;
// Close/CloseWrite send 'E'.
//
// A 'D' frame is STREAMED into the caller's buffer, never read whole: the host picks a
// frame's length, and one frame of any length must cost this machine no more memory
// than the read it is asked for.
type wsConn struct {
	ws  *websocket.Conn
	cur io.Reader // the rest of the 'D' frame being read, or nil
	wmu sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.cur != nil {
			n, err := c.cur.Read(p)
			if err == io.EOF {
				c.cur = nil
				err = nil
			}
			if n > 0 || err != nil {
				return n, err
			}
			continue
		}
		mt, r, err := c.ws.NextReader()
		if err != nil {
			return 0, err
		}
		if mt != websocket.BinaryMessage {
			continue // NextReader discards what is left of it
		}
		var tag [1]byte
		if _, err := io.ReadFull(r, tag[:]); err != nil {
			continue // an empty frame
		}
		switch tag[0] {
		case 'D':
			c.cur = r
		case 'E':
			return 0, io.EOF
		}
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, append([]byte{'D'}, p...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite signals end-of-stream to the host (half-close) without tearing the WS down,
// so the splice's half-close pattern works.
func (c *wsConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.ws.WriteMessage(websocket.BinaryMessage, []byte{'E'})
}

func (c *wsConn) Close() error {
	_ = c.CloseWrite()
	return c.ws.Close()
}

func (c *wsConn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error {
	_ = c.ws.SetReadDeadline(t)
	return c.ws.SetWriteDeadline(t)
}
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

// runEgressWorkers opens a pool of worker WebSockets TO the host (the host can't reach the
// bastion's tunnel IP) and serves one egress job per worker, reconnecting after each. Each
// worker authenticates with the bastion's bearer, then blocks until the host dispatches a
// request; handleEgressConn then dials it out the USER's connection (dialOut) and relays.
//
// pctx is the pairing's context (run.go): when the anchor revokes a pairing the
// workers must exit, not re-dial a closed tunnel every 3s for the process's life.
func runEgressWorkers(pctx context.Context, self string, wsURL string, tlsCfg *tls.Config,
	dialHost func(ctx context.Context) (net.Conn, error), bearer string,
	dialOut egressDialer, n int) {
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
				handleEgressConn(&wsConn{ws: ws}, dialOut, self) // blocks until a job, serves it, then returns
				unpark()
				stopKA()
				_ = ws.Close()
			}
		}()
	}
}
