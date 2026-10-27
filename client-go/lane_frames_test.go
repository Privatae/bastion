package main

// What the host sends down a lane is read at the size the bastion asks for,
// never at the size the host chooses: one frame of any length must not be
// held whole in this machine's memory, and an egress request head that never
// ends must not be either.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestEgressLaneDoesNotHoldAWholeHostFrame(t *testing.T) {
	const frame = 64 << 20
	payload := make([]byte, frame+1)
	payload[0] = 'D'
	for i := 1; i < len(payload); i++ {
		payload[i] = 'a'
	}
	start := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		<-start
		_ = ws.WriteMessage(websocket.BinaryMessage, payload)
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	c := &wsConn{ws: ws}
	buf := make([]byte, 4096)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	close(start)
	n, err := c.Read(buf)
	runtime.ReadMemStats(&after)
	if err != nil || n == 0 || buf[0] != 'a' {
		t.Fatalf("read: n=%d err=%v", n, err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("reading 4 KiB of a %d MiB host frame allocated %d MiB: the frame was held whole", frame>>20, grew>>20)
	}
}

func TestEgressRequestHeadIsBounded(t *testing.T) {
	bastionEnd, hostEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleEgressConn(bastionEnd, func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("no dial in this test")
		}, "test")
	}()
	chunk := []byte(strings.Repeat("a", 64<<10))
	_, _ = hostEnd.Write([]byte("GET http://example.invalid/"))
	sent := 0
	var werr error
	for sent < 8<<20 {
		_ = hostEnd.SetWriteDeadline(time.Now().Add(5 * time.Second))
		var n int
		n, werr = hostEnd.Write(chunk)
		sent += n
		if werr != nil {
			break
		}
	}
	_ = hostEnd.Close()
	<-done
	if werr == nil {
		t.Fatalf("the bastion read %d MiB of a request line with no end; it must stop at a bound", sent>>20)
	}
}

// Streaming a frame must not change what the reader sees: every byte of every
// 'D' frame in order, with empty frames, text frames and unknown tags skipped,
// a frame boundary never visible, and 'E' as the end, read through a buffer
// far smaller than the frames.
func TestEgressLaneFramesReadInOrderThroughASmallBuffer(t *testing.T) {
	var want []byte
	frames := [][]byte{{'D'}, {}, {'X', 'z', 'z'}}
	for i, size := range []int{1, 7, 4096, 70000, 3} {
		f := []byte{'D'}
		for j := 0; j < size; j++ {
			f = append(f, byte('a'+(i+j)%26))
		}
		want = append(want, f[1:]...)
		frames = append(frames, f, []byte{'D'})
	}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_ = ws.WriteMessage(websocket.TextMessage, []byte("Dnot data"))
		for _, f := range frames {
			_ = ws.WriteMessage(websocket.BinaryMessage, f)
		}
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte{'E'})
		time.Sleep(time.Second)
	}))
	defer srv.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	c := &wsConn{ws: ws}
	var got []byte
	buf := make([]byte, 13)
	for {
		n, err := c.Read(buf)
		if n == 0 && err == nil {
			t.Fatal("Read returned 0, nil")
		}
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read %d bytes, want %d; equal prefix %d", len(got), len(want), commonPrefix(got, want))
	}
}

func commonPrefix(a, b []byte) int {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return i
}

// A large upload through the lane still arrives whole: the head bound applies
// to the head alone, and the bytes the reader buffered past it go upstream
// first, in order.
func TestEgressLargeUploadPassesTheHeadBound(t *testing.T) {
	bastionEnd, hostEnd := net.Pipe()
	upBastion, upFar := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleEgressConn(bastionEnd, func(ctx context.Context, network, addr string) (net.Conn, error) {
			return upBastion, nil
		}, "")
	}()
	body := make([]byte, 3*egressMaxHeadBytes)
	for i := range body {
		body[i] = byte(i % 251)
	}
	head := "POST http://198.51.100.20/upload HTTP/1.1\r\nHost: 198.51.100.20\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n"
	// Head and body in ONE write, so the reader holds body bytes when the head ends.
	go func() {
		_, _ = hostEnd.Write(append([]byte(head), body...))
	}()
	// The lane rebuilds a plain-HTTP head (egress_http.go): this request comes
	// out the same, with `Connection: close` added as its last header.
	want := head[:len(head)-len("\r\n")] + "Connection: close\r\n\r\n"
	got := make([]byte, len(want)+len(body))
	_ = upFar.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(upFar, got); err != nil {
		t.Fatalf("upstream got %v", err)
	}
	if string(got[:len(want)]) != want || !bytes.Equal(got[len(want):], body) {
		t.Fatalf("upstream did not receive the head (%q) and the %d-byte body intact",
			got[:len(want)], len(body))
	}
	_ = hostEnd.Close()
	_ = upFar.Close()
	<-done
}
