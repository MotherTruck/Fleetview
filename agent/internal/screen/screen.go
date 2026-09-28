// Package screen implements remote-desktop-style screen capture and input
// injection for the live remote-control channel (see agent/internal/live).
// It is only meaningful on an endpoint with an active graphical session --
// most of this fleet's Linux endpoints are headless servers with none, so
// Detect reports that plainly rather than a session ever silently failing
// to produce frames.
package screen

import (
	"bytes"
	"context"
	"image"
	_ "image/jpeg"
)

// Capability describes what remote control can and can't do on this
// endpoint right now. It's reported as part of inventory (a non-underscore
// key, so it flows straight through device_view like mac_addresses does)
// and the dashboard uses it to decide whether to offer the feature at all.
type Capability struct {
	Available          bool   `json:"available"`
	ViewOnly            bool   `json:"view_only"`
	Reason              string `json:"reason"`
	DesktopEnvironment  string `json:"desktop_environment"`
	DisplayServer       string `json:"display_server"`
}

// Session is one active remote-control connection: repeated frame capture
// plus (unless the capability is view-only) input injection. Wayland
// sessions implement Capture but return an error from the input methods --
// there's no universal, reliable input-injection path on Wayland the way
// xdotool provides for X11, so those sessions are view-only end to end.
type Session interface {
	// Capture returns one JPEG-encoded frame and its pixel dimensions.
	Capture(ctx context.Context) (jpeg []byte, width, height int, err error)
	// MouseMove/MouseButton report position as a 0..1 fraction of the
	// frame's width/height, not raw pixels -- the browser only ever knows
	// the frame's own dimensions, and this avoids any coordinate mismatch
	// if the remote resolution changes between frames.
	MouseMove(xFraction, yFraction float64) error
	MouseButton(xFraction, yFraction float64, button string, pressed bool) error
	MouseScroll(deltaX, deltaY float64) error
	Key(key string, pressed bool) error
	Close() error
}

// decodeJPEGSize reads a JPEG's dimensions from its header without
// decoding the full image -- image.DecodeConfig only parses the frame
// header, not the pixel data.
func decodeJPEGSize(data []byte) (width, height int, err error) {
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0, err
	}
	return config.Width, config.Height, nil
}
