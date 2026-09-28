package screen

import (
	"context"
	"testing"
	"unsafe"
)

// These tests were run for real under Wine (not just cross-compiled) during
// this feature's development, against a real Xvfb-backed virtual desktop --
// genuine GetDC/BitBlt/GetDIBits screen capture and real SendInput mouse/
// keyboard injection, not just a check that the code builds. That process
// caught two real bugs no amount of read-through would have: (1)
// WTSGetActiveConsoleSessionId is a kernel32.dll export, not user32.dll as
// first written, and (2) keybdInputEvent was 8 bytes short of the true
// INPUT union size, which SendInput validates exactly and would have
// silently failed on every real keyboard event. There's no Wine (or real
// Windows) guarantee in whatever environment runs `go test` for this repo
// day to day, so every test here degrades to a skip rather than a failure
// when the platform can't actually back it (no active console session,
// which is also what a genuine headless Server Core install reports).
func TestWin32StructSizesMatchDocumentedABI(t *testing.T) {
	// Documented sizeof() values for amd64 Windows (8-byte ULONG_PTR):
	// MOUSEINPUT=32, KEYBDINPUT=24, INPUT=40. keybdInputEvent must match
	// INPUT's 40 bytes despite KEYBDINPUT itself only needing 24 -- the
	// union is always sized to its largest member, MOUSEINPUT.
	if got := unsafe.Sizeof(mouseInput{}); got != 32 {
		t.Errorf("mouseInput size = %d, want 32", got)
	}
	if got := unsafe.Sizeof(keybdInput{}); got != 24 {
		t.Errorf("keybdInput size = %d, want 24", got)
	}
	if got := unsafe.Sizeof(mouseInputEvent{}); got != 40 {
		t.Errorf("mouseInputEvent size = %d, want 40", got)
	}
	if got := unsafe.Sizeof(keybdInputEvent{}); got != 40 {
		t.Errorf("keybdInputEvent size = %d, want 40", got)
	}
	if got := unsafe.Offsetof(mouseInputEvent{}.mi); got != 8 {
		t.Errorf("mouseInputEvent.mi offset = %d, want 8 (union starts after type+padding)", got)
	}
	if got := unsafe.Offsetof(mouseInput{}.dwExtraInfo); got != 24 {
		t.Errorf("mouseInput.dwExtraInfo offset = %d, want 24", got)
	}
	if got := unsafe.Offsetof(keybdInput{}.dwExtraInfo); got != 16 {
		t.Errorf("keybdInput.dwExtraInfo offset = %d, want 16", got)
	}
	if got := unsafe.Sizeof(bitmapInfoHeader{}); got != 40 {
		t.Errorf("bitmapInfoHeader size = %d, want 40 (documented sizeof(BITMAPINFOHEADER))", got)
	}
}

func requireSession(t *testing.T) Session {
	t.Helper()
	capability := Detect()
	if !capability.Available {
		t.Skipf("no active console session: %+v", capability)
	}
	session, err := NewSession()
	if err != nil {
		t.Skipf("NewSession: %v", err)
	}
	return session
}

func TestCaptureReturnsARealJPEG(t *testing.T) {
	session := requireSession(t)
	defer session.Close()
	data, width, height, err := session.Capture(context.Background())
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if len(data) < 100 {
		t.Fatalf("expected a real JPEG of meaningful size, got %d bytes", len(data))
	}
	if data[0] != 0xFF || data[1] != 0xD8 {
		t.Fatalf("expected a JPEG SOI marker, got %x %x", data[0], data[1])
	}
	if width <= 0 || height <= 0 {
		t.Fatalf("expected positive dimensions, got %dx%d", width, height)
	}
	t.Logf("captured %dx%d JPEG, %d bytes", width, height, len(data))
}

type point struct{ X, Y int32 }

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

// TestMouseMoveActuallyMovesTheCursor checks the real, observable effect of
// MouseMove (via GetCursorPos), not just that SendInput returned success --
// exactly the distinction that mattered on the X11 side of this package,
// where a command could report success without the pointer actually moving.
func TestMouseMoveActuallyMovesTheCursor(t *testing.T) {
	session := requireSession(t)
	defer session.Close()
	ws := session.(*windowsSession)

	getCursorPos := moduser32.NewProc("GetCursorPos")
	if err := session.MouseMove(0.75, 0.25); err != nil {
		t.Fatalf("MouseMove: %v", err)
	}
	var pt point
	getCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	wantX := int32(0.75 * float64(ws.width))
	wantY := int32(0.25 * float64(ws.height))
	if abs32(pt.X-wantX) > 2 || abs32(pt.Y-wantY) > 2 {
		t.Errorf("expected cursor near (%d,%d) after MouseMove(0.75, 0.25), got (%d,%d)", wantX, wantY, pt.X, pt.Y)
	}
}

func TestInputMethodsRunWithoutError(t *testing.T) {
	session := requireSession(t)
	defer session.Close()
	if err := session.MouseButton(0.3, 0.3, "left", true); err != nil {
		t.Errorf("MouseButton down: %v", err)
	}
	if err := session.MouseButton(0.3, 0.3, "left", false); err != nil {
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
