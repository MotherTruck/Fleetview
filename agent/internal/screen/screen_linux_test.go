package screen

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bendahl/uinput"
)

// These tests need a real graphical session discoverable via /proc scanning
// (see findGraphicalSession) and the actual capture/input tools on PATH.
// They're skipped, not faked, when either is missing -- this package's
// whole point is real interaction with real tools, so a mock would test
// nothing meaningful.
func requireX11(t *testing.T) {
	t.Helper()
	if _, ok := findGraphicalSession("DISPLAY", "XAUTHORITY"); !ok {
		t.Skip("no active X11 session discoverable via /proc scanning")
	}
	if _, err := exec.LookPath("import"); err != nil {
		t.Skip("ImageMagick 'import' not installed")
	}
	if _, err := exec.LookPath("xdotool"); err != nil {
		t.Skip("xdotool not installed")
	}
}

func TestDetectFindsRealX11Session(t *testing.T) {
	requireX11(t)
	capability := Detect()
	if !capability.Available {
		t.Fatalf("expected Available=true, got %+v", capability)
	}
	if capability.ViewOnly {
		t.Fatalf("expected ViewOnly=false with xdotool present, got %+v", capability)
	}
	if capability.DisplayServer != "x11" {
		t.Fatalf("expected DisplayServer=x11, got %+v", capability)
	}
	if capability.DesktopEnvironment != "XFCE" {
		t.Fatalf("expected DesktopEnvironment=XFCE (from the fake session's env), got %+v", capability)
	}
}

func TestCaptureReturnsRealJPEGWithSaneDimensions(t *testing.T) {
	requireX11(t)
	session, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	data, width, height, err := session.Capture(context.Background())
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if len(data) < 100 {
		t.Fatalf("expected a real JPEG of meaningful size, got %d bytes", len(data))
	}
	if data[0] != 0xFF || data[1] != 0xD8 {
		t.Fatalf("expected a JPEG SOI marker (0xFFD8), got %x %x", data[0], data[1])
	}
	if width <= 0 || height <= 0 {
		t.Fatalf("expected positive dimensions, got %dx%d", width, height)
	}
	t.Logf("captured %dx%d JPEG, %d bytes", width, height, len(data))
}

func TestInputMethodsRunWithoutError(t *testing.T) {
	requireX11(t)
	session, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if err := session.MouseMove(0.5, 0.25); err != nil {
		t.Errorf("MouseMove: %v", err)
	}
	locationOutput, err := session.(*linuxSession).command(context.Background(), "xdotool", "getmouselocation").Output()
	if err != nil {
		t.Fatalf("getmouselocation: %v", err)
	}
	wantX, wantY := session.(*linuxSession).pixel(0.5, 0.25)
	wantPrefix := "x:" + strconv.Itoa(wantX) + " y:" + strconv.Itoa(wantY)
	if got := string(locationOutput); !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("expected mouse at %q after MouseMove(0.5, 0.25), got %q", wantPrefix, got)
	}
	if err := session.MouseButton(0.1, 0.1, "left", true); err != nil {
		t.Errorf("MouseButton down: %v", err)
	}
	if err := session.MouseButton(0.1, 0.1, "left", false); err != nil {
		t.Errorf("MouseButton up: %v", err)
	}
	if err := session.MouseScroll(0, 3); err != nil {
		t.Errorf("MouseScroll: %v", err)
	}
	for _, key := range []string{"a", "!", "Enter", "ArrowLeft", "Shift"} {
		if err := session.Key(key, true); err != nil {
			t.Errorf("Key down %q: %v", key, err)
		}
		if err := session.Key(key, false); err != nil {
			t.Errorf("Key up %q: %v", key, err)
		}
	}
}

// TestMouseButtonDeliversARealClickToTheRightWindow spawns a real X window
// via python-xlib that records the event it receives, and checks a
// MouseButton() click actually lands inside it -- not just that some xdotool
// command exited 0, but that a genuine ButtonPress reached the intended
// on-screen location. This is the test that originally caught a real bug:
// this environment's xdotool build silently doesn't move the reported
// pointer position via its default `mousemove` (confirmed separately with a
// raw XTestFakeMotionEvent call, which does), so every click landed wherever
// the pointer already was rather than where it was sent. Mouse handling was
// moved to a direct XTEST connection because of exactly this.
func TestMouseButtonDeliversARealClickToTheRightWindow(t *testing.T) {
	requireX11(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	const script = `
import sys, time
from Xlib import display, X
d = display.Display()
screen = d.screen()
window = screen.root.create_window(
    50, 50, 300, 300, 1, screen.root_depth, X.InputOutput, X.CopyFromParent,
    background_pixel=screen.white_pixel, event_mask=X.ButtonPressMask)
window.map()
d.sync()
print("READY", flush=True)
deadline = time.time() + 5
while time.time() < deadline:
    if d.pending_events():
        ev = d.next_event()
        if ev.type == X.ButtonPress:
            print("BUTTONPRESS", ev.event_x, ev.event_y, flush=True)
            sys.exit(0)
    time.sleep(0.02)
print("TIMEOUT", flush=True)
sys.exit(1)
`
	vars, _ := findGraphicalSession("DISPLAY", "XAUTHORITY")
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = append(os.Environ(), "DISPLAY="+vars["DISPLAY"])
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()

	buf := make([]byte, 4096)
	n, _ := stdout.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "READY") {
		t.Fatalf("target window did not become ready: %q", buf[:n])
	}
	time.Sleep(300 * time.Millisecond)

	session, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	// The window spans screen pixels (50,50)-(350,350); aim for its center.
	linux := session.(*linuxSession)
	xFraction, yFraction := 200.0/float64(linux.width), 200.0/float64(linux.height)
	if err := session.MouseButton(xFraction, yFraction, "left", true); err != nil {
		t.Fatalf("MouseButton down: %v", err)
	}
	if err := session.MouseButton(xFraction, yFraction, "left", false); err != nil {
		t.Fatalf("MouseButton up: %v", err)
	}

	n2, _ := stdout.Read(buf[n:])
	result := string(buf[:n+n2])
	t.Logf("target window reported: %q", result)
	if !strings.Contains(result, "BUTTONPRESS") {
		t.Fatalf("expected a real click to land inside the target window, got %q", result)
	}
}

func TestKeysymTranslation(t *testing.T) {
	cases := map[string]string{
		"a": "a", "1": "1", "F5": "F5",
		" ": "space", "Enter": "Return", "!": "exclam", "ArrowLeft": "Left",
	}
	for input, want := range cases {
		if got := keysymFor(input); got != want {
			t.Errorf("keysymFor(%q) = %q, want %q", input, got, want)
		}
	}
}

// requireUinput needs an actual writable /dev/uinput (and the module
// loaded), which this sandboxed build environment doesn't have -- real
// device creation is only exercised on a box that actually has one.
func requireUinput(t *testing.T) {
	t.Helper()
	if err := probeUinput(); err != nil {
		t.Skipf("no usable /dev/uinput: %v", err)
	}
}

func TestLinuxKeycodeTranslation(t *testing.T) {
	cases := []struct {
		key   string
		code  int
		shift bool
		ok    bool
	}{
		{"a", uinput.KeyA, false, true},
		{"A", uinput.KeyA, true, true},
		{"1", uinput.Key1, false, true},
		{"!", uinput.Key1, true, true},
		{"0", uinput.Key0, false, true},
		{")", uinput.Key0, true, true},
		{" ", uinput.KeySpace, false, true},
		{"Enter", uinput.KeyEnter, false, true},
		{"ArrowLeft", uinput.KeyLeft, false, true},
		{"Shift", uinput.KeyLeftshift, false, true},
		{"UnknownNamedKey", 0, false, false},
	}
	for _, c := range cases {
		code, shift, ok := linuxKeycodeFor(c.key)
		if ok != c.ok || (ok && (code != c.code || shift != c.shift)) {
			t.Errorf("linuxKeycodeFor(%q) = (%d, %v, %v), want (%d, %v, %v)", c.key, code, shift, ok, c.code, c.shift, c.ok)
		}
	}
}

func TestScrollClicksClamping(t *testing.T) {
	cases := map[float64]int{0: 1, 1: 1, -1: 1, 5: 5, -5: 5, 30: 20, -30: 20}
	for delta, want := range cases {
		if got := scrollClicks(delta); got != want {
			t.Errorf("scrollClicks(%v) = %d, want %d", delta, got, want)
		}
	}
}

// TestWaylandInputMethodsRunWithoutError mirrors
// TestInputMethodsRunWithoutError for a real Wayland session with a usable
// /dev/uinput -- skipped everywhere else, since there's no way to fake
// either meaningfully.
func TestWaylandInputMethodsRunWithoutError(t *testing.T) {
	if _, ok := findGraphicalSession("WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"); !ok {
		t.Skip("no active Wayland session discoverable via /proc scanning")
	}
	if _, err := exec.LookPath("grim"); err != nil {
		t.Skip("grim not installed")
	}
	requireUinput(t)

	session, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if err := session.MouseMove(0.5, 0.25); err != nil {
		t.Errorf("MouseMove: %v", err)
	}
	if err := session.MouseButton(0.1, 0.1, "left", true); err != nil {
		t.Errorf("MouseButton left down: %v", err)
	}
	if err := session.MouseButton(0.1, 0.1, "left", false); err != nil {
		t.Errorf("MouseButton left up: %v", err)
	}
	if err := session.MouseButton(0.1, 0.1, "right", true); err != nil {
		t.Errorf("MouseButton right down: %v", err)
	}
	if err := session.MouseButton(0.1, 0.1, "right", false); err != nil {
		t.Errorf("MouseButton right up: %v", err)
	}
	if err := session.MouseButton(0.1, 0.1, "middle", true); err != nil {
		t.Errorf("MouseButton middle down: %v", err)
	}
	if err := session.MouseButton(0.1, 0.1, "middle", false); err != nil {
		t.Errorf("MouseButton middle up: %v", err)
	}
	if err := session.MouseScroll(0, 3); err != nil {
		t.Errorf("MouseScroll vertical: %v", err)
	}
	if err := session.MouseScroll(3, 0); err != nil {
		t.Errorf("MouseScroll horizontal: %v", err)
	}
	for _, key := range []string{"a", "!", "Enter", "ArrowLeft", "Shift"} {
		if err := session.Key(key, true); err != nil {
			t.Errorf("Key down %q: %v", key, err)
		}
		if err := session.Key(key, false); err != nil {
			t.Errorf("Key up %q: %v", key, err)
		}
	}
}
