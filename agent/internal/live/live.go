// Package live maintains a persistent WebSocket connection to the server
// alongside the agent's existing poll-based job loop (see main.go). It is
// purely additive: a device with no live connection (server unreachable,
// an old server without this endpoint, a network path that blocks
// WebSocket upgrades) is still fully manageable through queued jobs
// exactly as before. The live channel carries two things: a fast metrics
// sample pushed on an interval for the dashboard's live view, and control
// messages for an admin-opened interactive terminal (queued jobs have no
// live/interactive channel by design; this is the one deliberate
// exception, gated admin-only server-side).
package live

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"

	"fleetview-agent/internal/client"
	"fleetview-agent/internal/containers"
	"fleetview-agent/internal/model"
	"fleetview-agent/internal/telemetry"
)

// wsMessage is one entry in the single outbound write queue every write to
// the connection funnels through (nhooyr's Conn.Write must never be called
// concurrently from multiple goroutines) -- JSON control messages
// (MessageText) and raw remote-control JPEG frames (MessageBinary) share
// this same queue and writer goroutine, just tagged with which framing to
// use.
type wsMessage struct {
	msgType websocket.MessageType
	data    []byte
}

// TopConsumersLimit bounds the merged process+container list sent with each
// metrics tick (see telemetry.TopConsumers): up to this many by CPU and up
// to this many by memory, deduplicated. Exported so the periodic HTTP
// metrics report (cmd/fleetview-agent/main.go) can populate the same field
// the same way, rather than leaving it unset.
const TopConsumersLimit = 12

const (
	metricsInterval  = 2 * time.Second
	writeQueueSize   = 32
	maxTerminalFrame = 64 * 1024
	minStableUp      = 10 * time.Second
)

// ptySession abstracts the platform-specific pseudo-terminal a live
// terminal session runs on: creack/pty on Linux (pty_linux.go), raw
// ConPTY syscalls on Windows (pty_windows.go).
type ptySession interface {
	io.ReadWriteCloser
	Resize(cols, rows int) error
}

type liveMetricsMessage struct {
	Type string `json:"type"`
	model.MetricsReport
}

type inboundMessage struct {
	Type    string  `json:"type"`
	Session string  `json:"session"`
	Cols    int     `json:"cols"`
	Rows    int     `json:"rows"`
	Data    string  `json:"data"`
	Code    int     `json:"code"`
	Reason  string  `json:"reason"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	Button  string  `json:"button"`
	Pressed bool    `json:"pressed"`
	DeltaX  float64 `json:"dx"`
	DeltaY  float64 `json:"dy"`
	Key     string  `json:"key"`
}

// Run dials the server's live endpoint and keeps it connected until ctx is
// cancelled, reconnecting with capped exponential backoff on any failure.
func Run(ctx context.Context, api *client.Client, collector *telemetry.Collector, processes *telemetry.ProcessSampler, gpuEnabled, dockerEnabled *atomic.Bool, logger *log.Logger) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		startedAt := time.Now()
		err := runOnce(ctx, api, collector, processes, gpuEnabled, dockerEnabled, logger)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.Printf("live channel: %v", err)
		}
		if time.Since(startedAt) >= minStableUp {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// GatherConsumers combines this tick's host-process sample with a Docker
// container stats snapshot (when Docker inventory is enabled). Container
// stats fetching is bounded to a few seconds so a hung Docker daemon can
// never stall the metrics ticker beyond that.
func GatherConsumers(ctx context.Context, processes *telemetry.ProcessSampler, dockerEnabled bool) []model.ResourceConsumer {
	all := processes.Sample()
	if !dockerEnabled {
		return all
	}
	statsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if list, err := containers.CollectStats(statsCtx); err == nil {
		all = append(all, list...)
	}
	return all
}

func webSocketURL(baseURL string) (string, error) {
	switch {
	case strings.HasPrefix(baseURL, "https://"):
		return "wss://" + strings.TrimPrefix(baseURL, "https://") + "/api/v1/agent/live", nil
	case strings.HasPrefix(baseURL, "http://"):
		return "ws://" + strings.TrimPrefix(baseURL, "http://") + "/api/v1/agent/live", nil
	default:
		return "", fmt.Errorf("unsupported server URL scheme: %s", baseURL)
	}
}

func runOnce(ctx context.Context, api *client.Client, collector *telemetry.Collector, processes *telemetry.ProcessSampler, gpuEnabled, dockerEnabled *atomic.Bool, logger *log.Logger) error {
	wsURL, err := webSocketURL(api.BaseURL())
	if err != nil {
		return err
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+api.AgentToken())
	header.Set("X-Device-ID", api.DeviceID())
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: api.HTTPClient(), HTTPHeader: header})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseNow()

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	writeCh := make(chan wsMessage, writeQueueSize)
	var writeWG sync.WaitGroup
	writeWG.Add(1)
	go func() {
		defer writeWG.Done()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case msg, ok := <-writeCh:
				if !ok {
					return
				}
				if err := conn.Write(sessionCtx, msg.msgType, msg.data); err != nil {
					return
				}
			}
		}
	}()

	send := func(payload any) {
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		select {
		case writeCh <- wsMessage{websocket.MessageText, data}:
		case <-sessionCtx.Done():
		default:
			// Backed up (a terminal is streaming heavily): drop this
			// metrics tick rather than block or grow unbounded. The next
			// tick supersedes it anyway.
		}
	}
	sendBinary := func(data []byte) {
		select {
		case writeCh <- wsMessage{websocket.MessageBinary, data}:
		case <-sessionCtx.Done():
		default:
			// Backed up: drop this remote-control frame rather than block
			// or grow unbounded. The next capture tick supersedes it.
		}
	}

	term := &terminalHandler{send: send, logger: logger}
	defer term.stop()
	scr := &screenHandler{send: send, sendBinary: sendBinary, logger: logger}
	defer scr.stop()

	writeWG.Add(1)
	go func() {
		defer writeWG.Done()
		ticker := time.NewTicker(metricsInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				report, err := collector.Collect(gpuEnabled.Load())
				if err != nil {
					continue
				}
				report.TopConsumers = telemetry.TopConsumers(GatherConsumers(sessionCtx, processes, dockerEnabled.Load()), TopConsumersLimit)
				send(liveMetricsMessage{Type: "metrics", MetricsReport: report})
			}
		}
	}()

	readErr := readLoop(sessionCtx, conn, term, scr)
	cancel()
	close(writeCh)
	writeWG.Wait()
	return readErr
}

func readLoop(ctx context.Context, conn *websocket.Conn, term *terminalHandler, scr *screenHandler) error {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if len(data) > maxTerminalFrame {
			continue
		}
		var message inboundMessage
		if err := json.Unmarshal(data, &message); err != nil {
			continue
		}
		switch message.Type {
		case "error":
			// The server accepted the handshake only to explain a
			// rejection (see server/app/live.py's _reject): treat it as a
			// hard failure so the reconnect loop's backoff applies rather
			// than spinning.
			return fmt.Errorf("server rejected live connection (%d): %s", message.Code, message.Reason)
		case "terminal_start":
			term.start(message.Session, message.Cols, message.Rows)
		case "terminal_input":
			term.write(message.Session, message.Data)
		case "terminal_resize":
			term.resize(message.Session, message.Cols, message.Rows)
		case "terminal_stop":
			term.stopSession(message.Session)
		case "screen_start":
			scr.start(message.Session)
		case "mouse_move":
			scr.mouseMove(message.Session, message.X, message.Y)
		case "mouse_button":
			scr.mouseButton(message.Session, message.X, message.Y, message.Button, message.Pressed)
		case "mouse_scroll":
			scr.mouseScroll(message.Session, message.DeltaX, message.DeltaY)
		case "key":
			scr.key(message.Session, message.Key, message.Pressed)
		case "screen_stop":
			scr.stopSession(message.Session)
		}
	}
}
