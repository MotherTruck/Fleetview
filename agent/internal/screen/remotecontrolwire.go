package screen

import (
	"encoding/binary"
	"io"
	"math"
)

// This file is the wire protocol remoteScreenSession and RunHelper
// (both Windows-only: remotesession_windows.go, helper_windows.go) use to
// talk to each other across the two named pipes a spawned screen-capture
// helper process connects to. It's kept free of any build constraint,
// unlike the pipes and the Win32 session/process plumbing around them, so
// the framing and command dispatch are unit-testable without a real or
// emulated Windows host.

// Input message types sent from the service process down the input pipe
// to the helper; fire-and-forget, no response expected.
const (
	inputMsgMouseMove   byte = 1
	inputMsgMouseButton byte = 2
	inputMsgMouseScroll byte = 3
	inputMsgKey         byte = 4
)

var mouseButtonCode = map[string]byte{"left": 0, "right": 1, "middle": 2}
var mouseButtonFromCode = [...]string{"left", "right", "middle"}

func readFull(r io.Reader, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}

// writeFramed writes a 1-byte status plus a 4-byte little-endian length
// plus payload -- used both for the helper's frame responses (status 0
// ok/nonzero error) and could extend to any other response this protocol
// needs later.
func writeFramed(w io.Writer, status byte, payload []byte) error {
	header := make([]byte, 5)
	header[0] = status
	binary.LittleEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFramed reads the length-plus-payload half of writeFramed's format
// (the status byte is read separately by the caller, since
// remoteScreenSession.Capture needs to branch on it before deciding how
// to interpret what follows).
func readFramed(r io.Reader) ([]byte, error) {
	lengthBytes := make([]byte, 4)
	if _, err := readFull(r, lengthBytes); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(lengthBytes)
	payload := make([]byte, length)
	if _, err := readFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func encodeMouseMove(xFraction, yFraction float64) []byte {
	payload := make([]byte, 16)
	binary.LittleEndian.PutUint64(payload[0:8], math.Float64bits(xFraction))
	binary.LittleEndian.PutUint64(payload[8:16], math.Float64bits(yFraction))
	return payload
}

func encodeMouseButton(xFraction, yFraction float64, button string, pressed bool) []byte {
	payload := make([]byte, 18)
	binary.LittleEndian.PutUint64(payload[0:8], math.Float64bits(xFraction))
	binary.LittleEndian.PutUint64(payload[8:16], math.Float64bits(yFraction))
	code, ok := mouseButtonCode[button]
	if !ok {
		code = mouseButtonCode["left"]
	}
	payload[16] = code
	if pressed {
		payload[17] = 1
	}
	return payload
}

func encodeMouseScroll(deltaX, deltaY float64) []byte {
	payload := make([]byte, 16)
	binary.LittleEndian.PutUint64(payload[0:8], math.Float64bits(deltaX))
	binary.LittleEndian.PutUint64(payload[8:16], math.Float64bits(deltaY))
	return payload
}

func encodeKey(key string, pressed bool) []byte {
	keyBytes := []byte(key)
	payload := make([]byte, 1+len(keyBytes))
	if pressed {
		payload[0] = 1
	}
	copy(payload[1:], keyBytes)
	return payload
}

func encodeInputMessage(msgType byte, payload []byte) []byte {
	header := make([]byte, 5)
	header[0] = msgType
	binary.LittleEndian.PutUint32(header[1:], uint32(len(payload)))
	return append(header, payload...)
}

// applyInput decodes one input-pipe message and applies it to session. It
// never returns an error: a malformed message is skipped rather than
// treated as fatal, since losing one stray input event is far less
// disruptive than tearing down the whole remote-control session over it,
// and the two sides of this protocol should never actually disagree on
// its shape in the first place.
func applyInput(session Session, msgType byte, payload []byte) {
	switch msgType {
	case inputMsgMouseMove:
		if len(payload) != 16 {
			return
		}
		x := math.Float64frombits(binary.LittleEndian.Uint64(payload[0:8]))
		y := math.Float64frombits(binary.LittleEndian.Uint64(payload[8:16]))
		_ = session.MouseMove(x, y)
	case inputMsgMouseButton:
		if len(payload) != 18 {
			return
		}
		x := math.Float64frombits(binary.LittleEndian.Uint64(payload[0:8]))
		y := math.Float64frombits(binary.LittleEndian.Uint64(payload[8:16]))
		button := "left"
		if int(payload[16]) < len(mouseButtonFromCode) {
			button = mouseButtonFromCode[payload[16]]
		}
		_ = session.MouseButton(x, y, button, payload[17] != 0)
	case inputMsgMouseScroll:
		if len(payload) != 16 {
			return
		}
		dx := math.Float64frombits(binary.LittleEndian.Uint64(payload[0:8]))
		dy := math.Float64frombits(binary.LittleEndian.Uint64(payload[8:16]))
		_ = session.MouseScroll(dx, dy)
	case inputMsgKey:
		if len(payload) < 1 {
			return
		}
		_ = session.Key(string(payload[1:]), payload[0] != 0)
	}
}
