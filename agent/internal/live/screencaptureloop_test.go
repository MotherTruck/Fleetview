package live

import (
	"context"
	"io"
	"log"
	"sync"
	"testing"
	"time"
)

// fakeCaptureSession is a screen.Session stand-in that fails a configured
// number of times before (optionally) succeeding, so captureLoop's
// failure-tolerance can be tested without any real screen backend.
type fakeCaptureSession struct {
	mu           sync.Mutex
	failuresLeft int
	alwaysFail   bool
	captureCalls int
	closed       bool
}

func (f *fakeCaptureSession) Capture(context.Context) ([]byte, int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captureCalls++
	if f.alwaysFail || f.failuresLeft > 0 {
		if f.failuresLeft > 0 {
			f.failuresLeft--
		}
		return nil, 0, 0, errTransientCapture
	}
	return []byte{0xFF, 0xD8, 0, 0}, 10, 10, nil
}
func (f *fakeCaptureSession) MouseMove(float64, float64) error                 { return nil }
func (f *fakeCaptureSession) MouseButton(float64, float64, string, bool) error { return nil }
func (f *fakeCaptureSession) MouseScroll(float64, float64) error               { return nil }
func (f *fakeCaptureSession) Key(string, bool) error                           { return nil }
func (f *fakeCaptureSession) Close() error                                     { f.mu.Lock(); f.closed = true; f.mu.Unlock(); return nil }

var errTransientCapture = &captureError{"capture failed: BitBlt failed"}

type captureError struct{ msg string }

func (e *captureError) Error() string { return e.msg }

func newTestScreenHandler() (*screenHandler, chan any, chan []byte) {
	sent := make(chan any, 64)
	binary := make(chan []byte, 64)
	return &screenHandler{
		send:       func(payload any) { sent <- payload },
		sendBinary: func(data []byte) { binary <- data },
		logger:     log.New(io.Discard, "", 0),
	}, sent, binary
}

func TestCaptureLoopToleratesTransientFailuresAndRecovers(t *testing.T) {
	originalInterval, originalMax := screenFrameInterval, maxConsecutiveCaptureFailures
	screenFrameInterval = 5 * time.Millisecond
	maxConsecutiveCaptureFailures = 5
	defer func() { screenFrameInterval, maxConsecutiveCaptureFailures = originalInterval, originalMax }()

	s, sent, binary := newTestScreenHandler()
	fake := &fakeCaptureSession{failuresLeft: 3} // fewer than the threshold of 5
	ctx, cancel := context.WithCancel(context.Background())
	s.session = "sess-1"
	s.current = fake
	s.cancel = cancel

	done := make(chan struct{})
	go func() { s.captureLoop(ctx, "sess-1", fake); close(done) }()

	select {
	case <-binary:
		// A real frame means it survived the transient failures.
	case msg := <-sent:
		// screen_info (the dimension-change notice sent alongside the
		// first frame) is expected here; only screen_closed would mean
		// the transient failures wrongly ended the session.
		if closedMsg, ok := msg.(screenClosedMessage); ok {
			t.Fatalf("session was wrongly closed after only transient failures: %#v", closedMsg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a frame after transient failures")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("captureLoop did not exit after context cancellation")
	}

	for {
		select {
		case msg := <-sent:
			if closedMsg, ok := msg.(screenClosedMessage); ok {
				t.Fatalf("expected no screen_closed message for a session that merely recovered, got %#v", closedMsg)
			}
		default:
			return
		}
	}
}

func TestCaptureLoopEndsSessionAfterSustainedFailure(t *testing.T) {
	originalInterval, originalMax := screenFrameInterval, maxConsecutiveCaptureFailures
	screenFrameInterval = 5 * time.Millisecond
	maxConsecutiveCaptureFailures = 5
	defer func() { screenFrameInterval, maxConsecutiveCaptureFailures = originalInterval, originalMax }()

	s, sent, _ := newTestScreenHandler()
	fake := &fakeCaptureSession{alwaysFail: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.session = "sess-1"
	s.current = fake
	s.cancel = cancel

	done := make(chan struct{})
	go func() { s.captureLoop(ctx, "sess-1", fake); close(done) }()

	select {
	case msg := <-sent:
		closedMsg, ok := msg.(screenClosedMessage)
		if !ok || closedMsg.Type != "screen_closed" || closedMsg.Session != "sess-1" {
			t.Fatalf("expected a screen_closed message for sess-1, got %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for screen_closed after sustained failure")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("captureLoop did not exit after giving up")
	}

	s.mu.Lock()
	closedSession := s.session == "" && s.current == nil
	s.mu.Unlock()
	if !closedSession {
		t.Fatalf("expected closeLocked to have cleared the session state")
	}

	fake.mu.Lock()
	calls := fake.captureCalls
	fake.mu.Unlock()
	if calls != maxConsecutiveCaptureFailures {
		t.Fatalf("expected exactly %d Capture calls before giving up, got %d", maxConsecutiveCaptureFailures, calls)
	}
}
