package screen

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GDI (gdi32.dll) and SendInput (user32.dll) are not wrapped by
// golang.org/x/sys/windows, so they're bound directly here the same way
// this package's other Windows-specific calls already are: a
// LazyDLL/LazyProc pair per call, with struct layouts following the
// documented Win32 ABI (stable across Windows versions).
var (
	modgdi32                = windows.NewLazySystemDLL("gdi32.dll")
	moduser32               = windows.NewLazySystemDLL("user32.dll")
	modkernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetDC               = moduser32.NewProc("GetDC")
	procReleaseDC           = moduser32.NewProc("ReleaseDC")
	procGetSystemMetrics    = moduser32.NewProc("GetSystemMetrics")
	procSendInput           = moduser32.NewProc("SendInput")
	// WTSGetActiveConsoleSessionId shares the WTS prefix with the Terminal
	// Services API (wtsapi32.dll) but is actually a kernel32.dll export --
	// confirmed the hard way: the user32.dll binding this had originally
	// panicked with "Procedure not found" when this file's tests were run
	// for real under Wine.
	procWTSGetActiveConsole = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
	procCreateCompatibleDC  = modgdi32.NewProc("CreateCompatibleDC")
	procDeleteDC            = modgdi32.NewProc("DeleteDC")
	procCreateCompatibleBM  = modgdi32.NewProc("CreateCompatibleBitmap")
	procDeleteObject        = modgdi32.NewProc("DeleteObject")
	procSelectObject        = modgdi32.NewProc("SelectObject")
	procBitBlt              = modgdi32.NewProc("BitBlt")
	procGetDIBits           = modgdi32.NewProc("GetDIBits")
)

const (
	smCXScreen = 0
	smCYScreen = 1
	srcCopy    = 0x00CC0020
	biRGB      = 0
	dibRGBColors = 0
)

// bitmapInfoHeader mirrors BITMAPINFOHEADER. A negative biHeight requests a
// top-down DIB from GetDIBits, so the returned rows are already in the
// normal top-to-bottom order image.RGBA expects -- no manual row flip
// needed.
type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

func wtsGetActiveConsoleSessionId() uint32 {
	r, _, _ := procWTSGetActiveConsole.Call()
	return uint32(r)
}

func Detect() Capability {
	// 0xFFFFFFFF means no session is currently attached to the physical
	// console -- most commonly a Server Core install, or a machine nobody
	// has ever logged into locally. Anything else means there's an active
	// (or at least disconnected-but-existing) desktop session to capture.
	if wtsGetActiveConsoleSessionId() == 0xFFFFFFFF {
		return Capability{Reason: "No active console session was found on this device"}
	}
	return Capability{Available: true, DisplayServer: "windows"}
}

type windowsSession struct {
	width, height int
}

func NewSession() (Session, error) {
	if wtsGetActiveConsoleSessionId() == 0xFFFFFFFF {
		return nil, fmt.Errorf("no active console session was found")
	}
	width, _, _ := procGetSystemMetrics.Call(uintptr(smCXScreen))
	height, _, _ := procGetSystemMetrics.Call(uintptr(smCYScreen))
	if width == 0 || height == 0 {
		return nil, fmt.Errorf("GetSystemMetrics returned an empty screen size")
	}
	return &windowsSession{width: int(width), height: int(height)}, nil
}

func (s *windowsSession) Capture(ctx context.Context) ([]byte, int, int, error) {
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil, 0, 0, fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, screenDC)

	memDC, _, _ := procCreateCompatibleDC.Call(screenDC)
	if memDC == 0 {
		return nil, 0, 0, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(memDC)

	bitmap, _, _ := procCreateCompatibleBM.Call(screenDC, uintptr(s.width), uintptr(s.height))
	if bitmap == 0 {
		return nil, 0, 0, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(bitmap)

	previous, _, _ := procSelectObject.Call(memDC, bitmap)
	defer procSelectObject.Call(memDC, previous)

	ok, _, _ := procBitBlt.Call(memDC, 0, 0, uintptr(s.width), uintptr(s.height), screenDC, 0, 0, srcCopy)
	if ok == 0 {
		return nil, 0, 0, fmt.Errorf("BitBlt failed")
	}

	header := bitmapInfoHeader{
		biSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		biWidth:       int32(s.width),
		biHeight:      -int32(s.height), // negative: top-down DIB
		biPlanes:      1,
		biBitCount:    32,
		biCompression: biRGB,
	}
	pixels := make([]byte, s.width*s.height*4)
	rows, _, _ := procGetDIBits.Call(memDC, bitmap, 0, uintptr(s.height),
		uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&header)), dibRGBColors)
	if rows == 0 {
		return nil, 0, 0, fmt.Errorf("GetDIBits failed")
	}

	img := image.NewRGBA(image.Rect(0, 0, s.width, s.height))
	for i := 0; i < s.width*s.height; i++ {
		// The DIB is BGRA; image.RGBA wants RGBA.
		b, g, r, a := pixels[i*4], pixels[i*4+1], pixels[i*4+2], pixels[i*4+3]
		img.Pix[i*4], img.Pix[i*4+1], img.Pix[i*4+2], img.Pix[i*4+3] = r, g, b, a
	}

	var buffer bytes.Buffer
	if err := jpeg.Encode(&buffer, img, &jpeg.Options{Quality: 70}); err != nil {
		return nil, 0, 0, fmt.Errorf("encode JPEG: %w", err)
	}
	return buffer.Bytes(), s.width, s.height, nil
}

// mouseInput mirrors MOUSEINPUT. The trailing padding field keeps
// dwExtraInfo (a pointer-sized ULONG_PTR) 8-byte aligned on amd64, matching
// the real struct's compiler-inserted padding.
type mouseInput struct {
	dx, dy      int32
	mouseData   uint32
	dwFlags     uint32
	time        uint32
	_           uint32
	dwExtraInfo uintptr
}

// keybdInput mirrors KEYBDINPUT, padded the same way as mouseInput.
type keybdInput struct {
	wVk, wScan  uint16
	dwFlags     uint32
	time        uint32
	_           uint32
	dwExtraInfo uintptr
}

// mouseInputEvent and keybdInputEvent both mirror INPUT (a leading `type`
// discriminator plus a union of MOUSEINPUT/KEYBDINPUT/HARDWAREINPUT): two
// distinct Go types rather than one emulated union, since Go has no union
// type, but both are exactly sizeof(INPUT) == 40 bytes on amd64 (4 type +
// 4 padding to 8-align the union + 32 for the larger MOUSEINPUT member),
// which is all SendInput actually cares about.
type mouseInputEvent struct {
	inputType uint32
	_         uint32
	mi        mouseInput
}
type keybdInputEvent struct {
	inputType uint32
	_         uint32
	ki        keybdInput
	// INPUT's union is sized to its largest member (MOUSEINPUT, 32 bytes)
	// regardless of which one is actually populated -- KEYBDINPUT is only
	// 24 bytes, so this padding brings the union portion up to the same
	// 32 bytes MOUSEINPUT occupies. SendInput's cbSize parameter must equal
	// the real sizeof(INPUT) exactly (Windows validates this and silently
	// fails the call otherwise, confirmed via a real amd64 Windows binary
	// run under Wine during this feature's testing, which caught this
	// struct being 8 bytes short before this padding was added).
	_ [8]byte
}

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseEventFMove     = 0x0001
	mouseEventFAbsolute = 0x8000
	mouseEventFLeftDown = 0x0002
	mouseEventFLeftUp   = 0x0004
	mouseEventFRightDown = 0x0008
	mouseEventFRightUp   = 0x0010
	mouseEventFMiddleDown = 0x0020
	mouseEventFMiddleUp   = 0x0040
	mouseEventFWheel      = 0x0800

	keyEventFKeyUp    = 0x0002
	keyEventFUnicode  = 0x0004
)

func sendInput(pointer unsafe.Pointer, size uintptr) error {
	r, _, err := procSendInput.Call(1, uintptr(pointer), size)
	if r == 0 {
		return fmt.Errorf("SendInput: %w", err)
	}
	return nil
}

func (s *windowsSession) MouseMove(xFraction, yFraction float64) error {
	event := mouseInputEvent{
		inputType: inputMouse,
		mi: mouseInput{
			dx:      int32(xFraction * 65535),
			dy:      int32(yFraction * 65535),
			dwFlags: mouseEventFMove | mouseEventFAbsolute,
		},
	}
	return sendInput(unsafe.Pointer(&event), unsafe.Sizeof(event))
}

var mouseButtonFlags = map[string][2]uint32{
	"left":   {mouseEventFLeftDown, mouseEventFLeftUp},
	"right":  {mouseEventFRightDown, mouseEventFRightUp},
	"middle": {mouseEventFMiddleDown, mouseEventFMiddleUp},
}

func (s *windowsSession) MouseButton(xFraction, yFraction float64, button string, pressed bool) error {
	if err := s.MouseMove(xFraction, yFraction); err != nil {
		return err
	}
	flags, ok := mouseButtonFlags[button]
	if !ok {
		flags = mouseButtonFlags["left"]
	}
	flag := flags[1]
	if pressed {
		flag = flags[0]
	}
	event := mouseInputEvent{inputType: inputMouse, mi: mouseInput{dwFlags: flag}}
	return sendInput(unsafe.Pointer(&event), unsafe.Sizeof(event))
}

func (s *windowsSession) MouseScroll(deltaX, deltaY float64) error {
	// WHEEL_DELTA is 120 per notch; deltaY here is already in "notches"
	// (see the browser-side wheel handling), so this scales directly.
	amount := int32(-deltaY * 120)
	event := mouseInputEvent{inputType: inputMouse, mi: mouseInput{dwFlags: mouseEventFWheel, mouseData: uint32(amount)}}
	return sendInput(unsafe.Pointer(&event), unsafe.Sizeof(event))
}

var namedVirtualKeys = map[string]uint16{
	"Enter": 0x0D, "Backspace": 0x08, "Tab": 0x09, "Escape": 0x1B,
	"ArrowLeft": 0x25, "ArrowUp": 0x26, "ArrowRight": 0x27, "ArrowDown": 0x28,
	"Shift": 0x10, "Control": 0x11, "Alt": 0x12, "Meta": 0x5B, "OS": 0x5B,
	"CapsLock": 0x14, "Delete": 0x2E, "Home": 0x24, "End": 0x23,
	"PageUp": 0x21, "PageDown": 0x22, "Insert": 0x2D, "ContextMenu": 0x5D,
	"F1": 0x70, "F2": 0x71, "F3": 0x72, "F4": 0x73, "F5": 0x74, "F6": 0x75,
	"F7": 0x76, "F8": 0x77, "F9": 0x78, "F10": 0x79, "F11": 0x7A, "F12": 0x7B,
}

// Key injects either a named virtual key (arrows, Enter, function keys,
// modifiers -- keys with no printable character) or, for everything else,
// the literal Unicode character via KEYEVENTF_UNICODE. The latter needs no
// per-layout virtual-key/shift-state mapping at all: Windows synthesizes
// the character directly regardless of the active keyboard layout, unlike
// the X11 side of this package which has to name a keysym per punctuation
// character because X11 has no equivalent "just send this character"
// primitive.
func (s *windowsSession) Key(key string, pressed bool) error {
	flags := uint32(0)
	if !pressed {
		flags = keyEventFKeyUp
	}
	if vk, ok := namedVirtualKeys[key]; ok {
		event := keybdInputEvent{inputType: inputKeyboard, ki: keybdInput{wVk: vk, dwFlags: flags}}
		return sendInput(unsafe.Pointer(&event), unsafe.Sizeof(event))
	}
	units := utf16.Encode([]rune(key))
	if len(units) == 0 {
		return fmt.Errorf("empty key")
	}
	event := keybdInputEvent{inputType: inputKeyboard, ki: keybdInput{wScan: units[0], dwFlags: flags | keyEventFUnicode}}
	return sendInput(unsafe.Pointer(&event), unsafe.Sizeof(event))
}

func (s *windowsSession) Close() error { return nil }
