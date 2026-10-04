package screen

import (
	"bytes"
	"context"
	"testing"
)

// fakeSession records what was called on it, so applyInput's decoding can
// be checked without any real screen/input backend.
type fakeSession struct {
	moves    [][2]float64
	buttons  []struct {
		x, y    float64
		button  string
		pressed bool
	}
	scrolls [][2]float64
	keys    []struct {
		key     string
		pressed bool
	}
}

func (f *fakeSession) Capture(context.Context) ([]byte, int, int, error) { return nil, 0, 0, nil }
func (f *fakeSession) MouseMove(x, y float64) error {
	f.moves = append(f.moves, [2]float64{x, y})
	return nil
}
func (f *fakeSession) MouseButton(x, y float64, button string, pressed bool) error {
	f.buttons = append(f.buttons, struct {
		x, y    float64
		button  string
		pressed bool
	}{x, y, button, pressed})
	return nil
}
func (f *fakeSession) MouseScroll(dx, dy float64) error {
	f.scrolls = append(f.scrolls, [2]float64{dx, dy})
	return nil
}
func (f *fakeSession) Key(key string, pressed bool) error {
	f.keys = append(f.keys, struct {
		key     string
		pressed bool
	}{key, pressed})
	return nil
}
func (f *fakeSession) Close() error { return nil }

func TestApplyInputMouseMove(t *testing.T) {
	session := &fakeSession{}
	applyInput(session, inputMsgMouseMove, encodeMouseMove(0.25, 0.75))
	if len(session.moves) != 1 || session.moves[0] != [2]float64{0.25, 0.75} {
		t.Fatalf("unexpected moves: %#v", session.moves)
	}
}

func TestApplyInputMouseButton(t *testing.T) {
	session := &fakeSession{}
	applyInput(session, inputMsgMouseButton, encodeMouseButton(0.1, 0.9, "right", true))
	if len(session.buttons) != 1 {
		t.Fatalf("expected 1 button event, got %#v", session.buttons)
	}
	got := session.buttons[0]
	if got.x != 0.1 || got.y != 0.9 || got.button != "right" || !got.pressed {
		t.Fatalf("unexpected button event: %#v", got)
	}
}

func TestApplyInputMouseButtonUnknownCodeFallsBackToLeft(t *testing.T) {
	session := &fakeSession{}
	// A button code past the end of mouseButtonFromCode should fall back
	// to "left" rather than index out of range.
	payload := encodeMouseButton(0.5, 0.5, "left", false)
	payload[16] = 99
	applyInput(session, inputMsgMouseButton, payload)
	if len(session.buttons) != 1 || session.buttons[0].button != "left" {
		t.Fatalf("expected fallback to left, got %#v", session.buttons)
	}
}

func TestApplyInputMouseScroll(t *testing.T) {
	session := &fakeSession{}
	applyInput(session, inputMsgMouseScroll, encodeMouseScroll(-1, 3))
	if len(session.scrolls) != 1 || session.scrolls[0] != [2]float64{-1, 3} {
		t.Fatalf("unexpected scrolls: %#v", session.scrolls)
	}
}

func TestApplyInputKey(t *testing.T) {
	session := &fakeSession{}
	applyInput(session, inputMsgKey, encodeKey("Enter", true))
	if len(session.keys) != 1 || session.keys[0].key != "Enter" || !session.keys[0].pressed {
		t.Fatalf("unexpected keys: %#v", session.keys)
	}
	applyInput(session, inputMsgKey, encodeKey("a", false))
	if len(session.keys) != 2 || session.keys[1].key != "a" || session.keys[1].pressed {
		t.Fatalf("unexpected keys: %#v", session.keys)
	}
}

func TestApplyInputMalformedPayloadIsIgnoredNotFatal(t *testing.T) {
	session := &fakeSession{}
	// Too short for each type; applyInput must not panic and must leave
	// the session untouched -- a desync here must never take down the
	// whole remote-control session.
	applyInput(session, inputMsgMouseMove, []byte{1, 2, 3})
	applyInput(session, inputMsgMouseButton, []byte{1, 2, 3})
	applyInput(session, inputMsgMouseScroll, []byte{1, 2, 3})
	applyInput(session, inputMsgKey, []byte{})
	applyInput(session, 0xFF, []byte{1, 2, 3})
	if len(session.moves)+len(session.buttons)+len(session.scrolls)+len(session.keys) != 0 {
		t.Fatalf("expected no calls from malformed payloads, got moves=%v buttons=%v scrolls=%v keys=%v",
			session.moves, session.buttons, session.scrolls, session.keys)
	}
}

func TestEncodeInputMessageRoundTrip(t *testing.T) {
	message := encodeInputMessage(inputMsgKey, encodeKey("!", true))
	var buf bytes.Buffer
	buf.Write(message)
	header := make([]byte, 5)
	if _, err := readFull(&buf, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if header[0] != inputMsgKey {
		t.Fatalf("msgType = %d, want %d", header[0], inputMsgKey)
	}
	length := int(header[1]) | int(header[2])<<8 | int(header[3])<<16 | int(header[4])<<24
	payload := make([]byte, length)
	if _, err := readFull(&buf, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if payload[0] != 1 || string(payload[1:]) != "!" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestWriteFramedThenReadFramedRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFramed(&buf, 0, []byte("hello frame")); err != nil {
		t.Fatalf("writeFramed: %v", err)
	}
	status := make([]byte, 1)
	if _, err := readFull(&buf, status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status[0] != 0 {
		t.Fatalf("status = %d, want 0", status[0])
	}
	payload, err := readFramed(&buf)
	if err != nil {
		t.Fatalf("readFramed: %v", err)
	}
	if string(payload) != "hello frame" {
		t.Fatalf("payload = %q, want %q", payload, "hello frame")
	}
}

func TestWriteFramedErrorStatusCarriesMessage(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFramed(&buf, 1, []byte("capture failed: BitBlt failed")); err != nil {
		t.Fatalf("writeFramed: %v", err)
	}
	status := make([]byte, 1)
	readFull(&buf, status)
	payload, err := readFramed(&buf)
	if err != nil {
		t.Fatalf("readFramed: %v", err)
	}
	if status[0] != 1 || string(payload) != "capture failed: BitBlt failed" {
		t.Fatalf("status=%d payload=%q", status[0], payload)
	}
}
