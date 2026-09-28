package live

import (
	"context"
	"log"
	"sync"
	"time"

	"fleetview-agent/internal/screen"
)

// screenFrameInterval paces remote-control frame capture: a periodic
// screenshot streamed over the same JSON-and-binary WebSocket the terminal
// uses, not a video codec. A few frames a second is enough to be usable
// over a home LAN without meaningfully loading a modest endpoint.
const screenFrameInterval = 250 * time.Millisecond

// screenHandler manages at most one active remote-control session at a
// time, the same single-session-per-device model terminalHandler already
// uses (and for the same reason: the server enforces it too, so this is
// just the agent side of that contract). A stale message from a session
// that already ended is ignored rather than acted on, matching
// terminalHandler's own session-scoping.
type screenHandler struct {
	send       func(payload any)
	sendBinary func(data []byte)
	logger     *log.Logger

	mu      sync.Mutex
	session string
	cancel  context.CancelFunc
	current screen.Session
}

type screenInfoMessage struct {
	Type    string `json:"type"`
	Session string `json:"session"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
}

type screenClosedMessage struct {
	Type    string `json:"type"`
	Session string `json:"session"`
	Reason  string `json:"reason"`
}

func (s *screenHandler) start(session string) {
	s.mu.Lock()
	if s.current != nil {
		s.closeLocked()
	}
	newSession, err := screen.NewSession()
	if err != nil {
		s.mu.Unlock()
		s.send(screenClosedMessage{Type: "screen_closed", Session: session, Reason: err.Error()})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.session = session
	s.current = newSession
	s.cancel = cancel
	s.mu.Unlock()
	go s.captureLoop(ctx, session, newSession)
}

func (s *screenHandler) captureLoop(ctx context.Context, session string, capture screen.Session) {
	lastWidth, lastHeight := -1, -1
	ticker := time.NewTicker(screenFrameInterval)
	defer ticker.Stop()
	for {
		frame, width, height, err := capture.Capture(ctx)
		if err != nil {
			s.logger.Printf("remote control: capture failed: %v", err)
			s.send(screenClosedMessage{Type: "screen_closed", Session: session, Reason: "capture failed: " + err.Error()})
			s.mu.Lock()
			if s.session == session {
				s.closeLocked()
			}
			s.mu.Unlock()
			return
		}
		if width != lastWidth || height != lastHeight {
			s.send(screenInfoMessage{Type: "screen_info", Session: session, Width: width, Height: height})
			lastWidth, lastHeight = width, height
		}
		s.sendBinary(frame)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *screenHandler) mouseMove(session string, x, y float64) {
	if capture, ok := s.currentFor(session); ok {
		_ = capture.MouseMove(x, y)
	}
}

func (s *screenHandler) mouseButton(session string, x, y float64, button string, pressed bool) {
	if capture, ok := s.currentFor(session); ok {
		_ = capture.MouseButton(x, y, button, pressed)
	}
}

func (s *screenHandler) mouseScroll(session string, dx, dy float64) {
	if capture, ok := s.currentFor(session); ok {
		_ = capture.MouseScroll(dx, dy)
	}
}

func (s *screenHandler) key(session, key string, pressed bool) {
	if capture, ok := s.currentFor(session); ok {
		_ = capture.Key(key, pressed)
	}
}

func (s *screenHandler) currentFor(session string) (screen.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session != session || s.current == nil {
		return nil, false
	}
	return s.current, true
}

func (s *screenHandler) stopSession(session string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == session {
		s.closeLocked()
	}
}

func (s *screenHandler) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

// closeLocked must be called with s.mu held. Cancelling the capture loop's
// context makes it exit (and stop sending frames) on its own; it never
// sends its own screen_closed for a session this deliberately stopped it,
// only for one that failed on its own -- same pattern terminalHandler uses
// to avoid two competing "closed" notifications racing each other.
func (s *screenHandler) closeLocked() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.current != nil {
		_ = s.current.Close()
	}
	s.session = ""
	s.current = nil
	s.cancel = nil
}
