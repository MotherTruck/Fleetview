package live

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/jpeg"
	"log"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"fleetview-agent/internal/client"
	"fleetview-agent/internal/config"
	"fleetview-agent/internal/model"
	"fleetview-agent/internal/telemetry"
)

// TestScreenChannelEndToEnd drives the real agent live-channel code (runOnce,
// readLoop, screenHandler, and the screen package underneath it) through a
// fake WebSocket server standing in for server/app/live.py's agent-facing
// endpoint. It proves the full chain a browser message actually takes: JSON
// in over the wire -> readLoop's dispatch -> screenHandler -> the screen
// package -> a genuine X11 side effect (the real pointer moving on the
// sandbox's Xvfb display), and a genuine JPEG frame coming back out the same
// wire. It requires a real, discoverable graphical session (see the screen
// package's own tests) and is skipped otherwise.
func TestScreenChannelEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("xdotool"); err != nil {
		t.Skip("xdotool not available")
	}
	locBefore, err := xdotoolMouseLocation(t)
	if err != nil {
		t.Skipf("no discoverable X11 session to test against: %v", err)
	}

	type serverEvent struct {
		kind string // "info", "frame", "text"
		data []byte
	}
	events := make(chan serverEvent, 64)
	upgraded := make(chan *websocket.Conn, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		upgraded <- conn
		ctx := context.Background()
		for {
			msgType, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			switch msgType {
			case websocket.MessageBinary:
				events <- serverEvent{kind: "frame", data: data}
			default:
				events <- serverEvent{kind: "text", data: data}
			}
		}
	}))
	defer server.Close()

	api, err := client.New(config.Config{ServerURL: server.URL, RequestTimeout: 60 * time.Second}, model.State{DeviceID: "test-device", AgentToken: "test-token"})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	collector := telemetry.NewCollector()
	processes := telemetry.NewProcessSampler()
	var gpuEnabled, dockerEnabled atomic.Bool

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- runOnce(ctx, api, collector, processes, &gpuEnabled, &dockerEnabled, log.Default())
	}()

	var serverConn *websocket.Conn
	select {
	case serverConn = <-upgraded:
	case <-time.After(5 * time.Second):
		t.Fatal("agent never connected")
	}

	send := func(payload any) {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := serverConn.Write(context.Background(), websocket.MessageText, data); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	send(map[string]any{"type": "screen_start", "session": "sess-1"})

	var sawInfo, sawFrame bool
	var frameWidth, frameHeight int
	deadline := time.After(10 * time.Second)
	for !sawInfo || !sawFrame {
		select {
		case ev := <-events:
			switch ev.kind {
			case "text":
				var msg map[string]any
				if err := json.Unmarshal(ev.data, &msg); err == nil && msg["type"] == "screen_info" {
					sawInfo = true
					frameWidth = int(msg["width"].(float64))
					frameHeight = int(msg["height"].(float64))
				}
			case "frame":
				cfg, _, err := image.DecodeConfig(bytes.NewReader(ev.data))
				if err != nil {
					t.Fatalf("frame is not a valid image: %v", err)
				}
				if _, err := jpeg.Decode(bytes.NewReader(ev.data)); err != nil {
					t.Fatalf("frame is not a valid JPEG: %v", err)
				}
				if cfg.Width <= 0 || cfg.Height <= 0 {
					t.Fatalf("frame has non-positive dimensions: %dx%d", cfg.Width, cfg.Height)
				}
				sawFrame = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for screen_info/frame (sawInfo=%v sawFrame=%v)", sawInfo, sawFrame)
		}
	}
	t.Logf("received real screen_info+frame: %dx%d", frameWidth, frameHeight)

	// Move to a fraction distinct from wherever the pointer already sits
	// (locBefore), so a no-op MouseMove can't accidentally pass.
	targetXFrac, targetYFrac := 0.75, 0.75
	wantX := int(targetXFrac * float64(frameWidth))
	wantY := int(targetYFrac * float64(frameHeight))
	send(map[string]any{"type": "mouse_move", "session": "sess-1", "x": targetXFrac, "y": targetYFrac})

	deadline = time.After(5 * time.Second)
	moved := false
	for !moved {
		loc, err := xdotoolMouseLocation(t)
		if err == nil && abs(loc[0]-wantX) <= 2 && abs(loc[1]-wantY) <= 2 {
			moved = true
			break
		}
		select {
		case <-deadline:
			got, _ := xdotoolMouseLocation(t)
			t.Fatalf("real pointer never reached (%d,%d): started at (%d,%d), last seen at (%d,%d)", wantX, wantY, locBefore[0], locBefore[1], got[0], got[1])
		case <-time.After(50 * time.Millisecond):
		}
	}

	send(map[string]any{"type": "screen_stop", "session": "sess-1"})
	cancel()
	select {
	case <-runErrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("runOnce did not exit after context cancellation")
	}
}

func xdotoolMouseLocation(t *testing.T) ([2]int, error) {
	t.Helper()
	out, err := exec.Command("xdotool", "getmouselocation").Output()
	if err != nil {
		return [2]int{}, err
	}
	fields := strings.Fields(string(out))
	var x, y int
	for _, field := range fields {
		if v, ok := strings.CutPrefix(field, "x:"); ok {
			x, _ = strconv.Atoi(v)
		}
		if v, ok := strings.CutPrefix(field, "y:"); ok {
			y, _ = strconv.Atoi(v)
		}
	}
	return [2]int{x, y}, nil
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
