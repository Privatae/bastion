package main

// MEASUREMENT, not a ratchet. Answers one question with numbers instead of a
// guess: how big a payload can ctx_put actually carry, and what does it cost?
//
// The whole management job is ONE WebSocket frame — the host sends
// `C` + json.Marshal({op, args}) (the host's mgmt worker),
// and the payload rides inside args[1] as base64. So the artifact is buffered
// whole, four times over: bytes -> base64 string -> JSON frame on the host,
// then frame -> decoded bytes here. Nothing streams.
//
// Kept because the delivery design rests on this number.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// uvicornWSMaxSize is the host's WebSocket frame ceiling: the server default,
// which nothing on the host overrides, so this is the live value.
const uvicornWSMaxSize = 16 << 20

func TestMeasureCtxPutCapacity(t *testing.T) {
	if os.Getenv("MEASURE_CTX_PUT") == "" {
		t.Skip("set MEASURE_CTX_PUT=1 to run the capacity measurement")
	}
	root := t.TempDir()
	up := websocket.Upgrader{}

	// Stand-in for the host's mgmt worker: send one C frame, collect O/R until X.
	// Mirrors the host's management worker frame for frame.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConn(ws, root, "", "")
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	sizes := []int{
		1 << 10, 1 << 20, 4 << 20, 8 << 20,
		12 << 20, 12_582_912, 16 << 20, 32 << 20, 64 << 20,
	}
	fmt.Printf("\n%-12s %-14s %-10s %-12s %-9s %s\n",
		"plaintext", "frame bytes", "vs 16MiB", "wall", "heap MiB", "result")
	for _, n := range sizes {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte('a' + i%26)
		}
		b64 := base64.StdEncoding.EncodeToString(payload)
		job, _ := json.Marshal(mgmtJob{Op: "ctx_put", Args: []string{fmt.Sprintf("m/%d.bin", n), b64}})
		frame := append([]byte("C"), job...)

		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		start := time.Now()

		c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		res := "ok"
		if err := c.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			res = "write: " + err.Error()
		} else {
			for {
				_, data, err := c.ReadMessage()
				if err != nil {
					res = "read: " + err.Error()
					break
				}
				if len(data) > 0 && data[0] == 'X' {
					if string(data[1:]) != "0" {
						res = "exit " + string(data[1:])
					}
					break
				}
				if len(data) > 0 && data[0] == 'R' {
					res = "stderr: " + strings.TrimSpace(string(data[1:]))
				}
			}
		}
		wall := time.Since(start)
		runtime.ReadMemStats(&m1)
		c.Close()

		verdict := "WITHIN uvicorn frame limit"
		if len(frame) > uvicornWSMaxSize {
			verdict = "OVER uvicorn ws_max_size — host would refuse"
		}
		fmt.Printf("%-12s %-14d %-10s %-12s %-9d %s | %s\n",
			human(n), len(frame),
			fmt.Sprintf("%.2fx", float64(len(frame))/float64(uvicornWSMaxSize)),
			wall.Round(time.Millisecond).String(),
			(m1.TotalAlloc-m0.TotalAlloc)/(1<<20), res, verdict)
	}

	// What a real export would cost: a real entity's staged tree measured
	// 12 GiB raw.
	const artifact = 13 * (1 << 30)
	frames := (artifact*4/3 + uvicornWSMaxSize - 1) / uvicornWSMaxSize
	fmt.Printf("\na 13 GiB artifact = %d base64 bytes = %d ctx_put frames at the 16 MiB cap\n",
		artifact*4/3, frames)
	fmt.Printf("at the measured 25s bastion / 30s host per-job timeout and ONE job per worker\n")
	fmt.Printf("connection, that is %d sequential dispatches.\n", frames)
}

func human(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}
