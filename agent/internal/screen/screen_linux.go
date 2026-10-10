package screen

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/BurntSushi/xgb"
	"github.com/BurntSushi/xgb/xproto"
	"github.com/BurntSushi/xgb/xtest"
	"github.com/bendahl/uinput"
)

// uinputPath is the kernel device node a uinput client opens to register a
// synthetic input device. It needs the uinput module loaded and (normally)
// root, which the agent already runs as.
const uinputPath = "/dev/uinput"

// probeUinput does a throwaway create+close of a keyboard device just to
// answer "can this process actually drive /dev/uinput right now" -- the
// cheapest of the three device types to stand up, and creating then
// instantly closing one has no visible effect on the real keyboard.
func probeUinput() error {
	kb, err := uinput.CreateKeyboard(uinputPath, []byte("fleetview-probe"))
	if err != nil {
		return err
	}
	return kb.Close()
}

// findGraphicalSession scans /proc for a running process that has both of
// the given environment variables set, and returns their values. The agent
// runs as a systemd *system* service, so its own environment never has
// DISPLAY/WAYLAND_DISPLAY -- those belong to whichever user is logged into
// a graphical session, which varies by display manager (GDM/LightDM/SDDM/
// startx) in ways not worth special-casing. Scanning already-running
// processes for the same variables a real session set is how several other
// Linux remote-access tools solve this same problem, and works regardless
// of which display manager put the session there. The agent runs as root,
// so it can read any process's /proc/<pid>/environ and any user's
// XAUTHORITY file it points at, without needing to run commands as that
// user.
func findGraphicalSession(required ...string) (map[string]string, bool) {
	vars, _, _, ok := findGraphicalSessionWithOwner(required...)
	return vars, ok
}

// findGraphicalSessionWithOwner is findGraphicalSession plus the uid/gid
// that actually owns the matched process -- needed to spawn the portal
// helper as that real user (see portal_linux.go): a D-Bus session bus and
// the desktop portal both key everything off the connecting process's real
// uid, not an env var, so the agent (root) can't just set the right
// environment and stay root the way it does for X11/grim.
func findGraphicalSessionWithOwner(required ...string) (vars map[string]string, uid, gid uint32, ok bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0, 0, false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", pid, "environ"))
		if err != nil {
			continue
		}
		candidate := parseEnviron(data)
		found := true
		for _, key := range required {
			if candidate[key] == "" {
				found = false
				break
			}
		}
		if !found {
			continue
		}
		info, err := os.Stat(filepath.Join("/proc", pid))
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		return candidate, stat.Uid, stat.Gid, true
	}
	return nil, 0, 0, false
}

func parseEnviron(data []byte) map[string]string {
	result := map[string]string{}
	for _, entry := range bytes.Split(data, []byte{0}) {
		key, value, ok := strings.Cut(string(entry), "=")
		if ok {
			result[key] = value
		}
	}
	return result
}

func Detect() Capability {
	if vars, ok := findGraphicalSession("DISPLAY", "XAUTHORITY"); ok {
		if _, err := exec.LookPath("import"); err != nil {
			return Capability{Reason: "An active X11 session was found, but ImageMagick's 'import' is not installed"}
		}
		desktop := vars["XDG_CURRENT_DESKTOP"]
		if _, err := exec.LookPath("xdotool"); err != nil {
			return Capability{Available: true, ViewOnly: true, DisplayServer: "x11", DesktopEnvironment: desktop,
				Reason: "xdotool is not installed; view-only until it is"}
		}
		return Capability{Available: true, DisplayServer: "x11", DesktopEnvironment: desktop}
	}
	if vars, ok := findGraphicalSession("WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"); ok {
		desktop := vars["XDG_CURRENT_DESKTOP"]
		if usesDesktopPortal(desktop) {
			return detectPortal(desktop)
		}
		if _, err := exec.LookPath("grim"); err != nil {
			return Capability{Reason: "An active Wayland session was found, but 'grim' is not installed"}
		}
		if err := probeUinput(); err != nil {
			return Capability{Available: true, ViewOnly: true, DisplayServer: "wayland", DesktopEnvironment: desktop,
				Reason: fmt.Sprintf("Wayland session found, but input injection needs /dev/uinput (try 'modprobe uinput'): %v", err)}
		}
		return Capability{Available: true, DisplayServer: "wayland", DesktopEnvironment: desktop}
	}
	return Capability{Reason: "No active graphical (X11 or Wayland) session was found on this device"}
}

// usesDesktopPortal reports whether desktop is one of the compositors that
// don't implement wlroots' screencopy protocol (what grim needs) at all --
// GNOME's Mutter and KDE's KWin only expose screen content through the XDG
// Desktop Portal, so those need the portal_linux.go path instead of
// grim+uinput. Everything else (Sway, Hyprland, and other wlroots-based
// compositors) keeps using grim+uinput, which already works there.
func usesDesktopPortal(desktop string) bool {
	upper := strings.ToUpper(desktop)
	return strings.Contains(upper, "GNOME") || strings.Contains(upper, "KDE")
}

type linuxSession struct {
	displayServer    string
	env              []string // for the capture/key subprocess (import/grim/xdotool)
	xdotoolAvailable bool
	width, height    int

	// Mouse motion/clicks go over a real XTEST connection rather than
	// `xdotool mousemove`: testing this against a real X server found that
	// this build of xdotool's absolute mousemove silently doesn't move the
	// reported pointer position at all (clicks landed wherever the pointer
	// already was, not where they were sent), while a direct
	// XTestFakeMotionEvent request works correctly. Keyboard input doesn't
	// have this problem -- xdotool's key/keydown/keyup were verified to
	// deliver real KeyPress/KeyRelease events -- so only mouse handling was
	// moved off it.
	xtestConn *xgb.Conn
	xtestRoot xproto.Window

	// Wayland input: a synthetic touchpad (absolute positioning, left/right
	// click) plus a synthetic relative mouse used only for its middle
	// button and scroll wheel -- a touchpad device has no wheel of its
	// own. Both nil when /dev/uinput isn't usable, in which case the
	// session is view-only even though Capture still works.
	uiTouchPad uinput.TouchPad
	uiMouse    uinput.Mouse
	uiKeyboard uinput.Keyboard
}

// xauthMu guards the brief window where XAUTHORITY is set to a specific
// user's cookie file for xgb's connection handshake (it reads the env var
// itself, with no way to pass a path directly). The auth cookie is only
// needed at connect time, not for the lifetime of the resulting
// connection, so the env var is restored immediately after.
var xauthMu sync.Mutex

func connectXTest(display, xauthority string) (*xgb.Conn, xproto.Window, error) {
	xauthMu.Lock()
	defer xauthMu.Unlock()
	previous, hadPrevious := os.LookupEnv("XAUTHORITY")
	os.Setenv("XAUTHORITY", xauthority)
	defer func() {
		if hadPrevious {
			os.Setenv("XAUTHORITY", previous)
		} else {
			os.Unsetenv("XAUTHORITY")
		}
	}()
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return nil, 0, fmt.Errorf("connect to X server: %w", err)
	}
	if err := xtest.Init(conn); err != nil {
		conn.Close()
		return nil, 0, fmt.Errorf("XTEST extension: %w", err)
	}
	root := xproto.Setup(conn).DefaultScreen(conn).Root
	return conn, root, nil
}

func NewSession() (Session, error) {
	if vars, ok := findGraphicalSession("DISPLAY", "XAUTHORITY"); ok {
		if _, err := exec.LookPath("import"); err != nil {
			return nil, fmt.Errorf("ImageMagick's 'import' is not installed")
		}
		session := &linuxSession{
			displayServer:    "x11",
			env:              []string{"DISPLAY=" + vars["DISPLAY"], "XAUTHORITY=" + vars["XAUTHORITY"]},
			xdotoolAvailable: false,
		}
		if _, err := exec.LookPath("xdotool"); err == nil {
			session.xdotoolAvailable = true
		}
		if conn, root, err := connectXTest(vars["DISPLAY"], vars["XAUTHORITY"]); err == nil {
			session.xtestConn = conn
			session.xtestRoot = root
		}
		width, height, err := session.geometry()
		if err != nil {
			session.Close()
			return nil, err
		}
		session.width, session.height = width, height
		return session, nil
	}
	if vars, uid, gid, ok := findGraphicalSessionWithOwner("WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"); ok {
		if usesDesktopPortal(vars["XDG_CURRENT_DESKTOP"]) {
			return newPortalSession(vars, uid, gid)
		}
		if _, err := exec.LookPath("grim"); err != nil {
			return nil, fmt.Errorf("'grim' is not installed")
		}
		session := &linuxSession{
			displayServer: "wayland",
			env:           []string{"WAYLAND_DISPLAY=" + vars["WAYLAND_DISPLAY"], "XDG_RUNTIME_DIR=" + vars["XDG_RUNTIME_DIR"]},
		}
		// The touchpad device's coordinate range is fixed at creation, so
		// the real screen size is needed up front -- unlike X11, there's no
		// cheap "just ask" call for it on Wayland, so this takes one real
		// capture before the session is usable at all.
		width, height, err := session.geometry()
		if err != nil {
			return nil, err
		}
		session.width, session.height = width, height
		if err := session.createUinputDevices(); err != nil {
			// Best-effort: Detect() already told the dashboard whether to
			// expect input, so a failure here just leaves the uiXxx fields
			// nil and the session silently stays capture-only.
			session.uiTouchPad, session.uiMouse, session.uiKeyboard = nil, nil, nil
		}
		return session, nil
	}
	return nil, fmt.Errorf("no active graphical session was found")
}

func (s *linuxSession) createUinputDevices() error {
	touchPad, err := uinput.CreateTouchPad(uinputPath, []byte("fleetview-touchpad"), 0, int32(s.width-1), 0, int32(s.height-1))
	if err != nil {
		return fmt.Errorf("create touchpad: %w", err)
	}
	mouse, err := uinput.CreateMouse(uinputPath, []byte("fleetview-mouse"))
	if err != nil {
		touchPad.Close()
		return fmt.Errorf("create mouse: %w", err)
	}
	keyboard, err := uinput.CreateKeyboard(uinputPath, []byte("fleetview-keyboard"))
	if err != nil {
		touchPad.Close()
		mouse.Close()
		return fmt.Errorf("create keyboard: %w", err)
	}
	s.uiTouchPad, s.uiMouse, s.uiKeyboard = touchPad, mouse, keyboard
	return nil
}

func (s *linuxSession) geometry() (int, int, error) {
	if s.displayServer == "wayland" {
		output, err := s.command(context.Background(), "grim", "-t", "jpeg", "-q", "70", "-").Output()
		if err != nil {
			return 0, 0, fmt.Errorf("grim: %w", err)
		}
		return decodeJPEGSize(output)
	}
	output, err := s.command(context.Background(), "xdotool", "getdisplaygeometry").Output()
	if err != nil {
		return 0, 0, fmt.Errorf("xdotool getdisplaygeometry: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("unexpected getdisplaygeometry output %q", output)
	}
	width, err1 := strconv.Atoi(fields[0])
	height, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("unexpected getdisplaygeometry output %q", output)
	}
	return width, height, nil
}

func (s *linuxSession) command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = s.env
	return cmd
}

func (s *linuxSession) Capture(ctx context.Context) ([]byte, int, int, error) {
	if s.displayServer == "wayland" {
		output, err := s.command(ctx, "grim", "-t", "jpeg", "-q", "70", "-").Output()
		if err != nil {
			return nil, 0, 0, fmt.Errorf("grim: %w", err)
		}
		width, height, err := decodeJPEGSize(output)
		if err != nil {
			return nil, 0, 0, err
		}
		s.width, s.height = width, height
		return output, width, height, nil
	}
	output, err := s.command(ctx, "import", "-window", "root", "-depth", "8", "jpg:-").Output()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("import: %w", err)
	}
	width, height, err := decodeJPEGSize(output)
	if err != nil {
		return nil, 0, 0, err
	}
	s.width, s.height = width, height
	return output, width, height, nil
}

var jsKeyToKeysym = map[string]string{
	" ": "space", "Enter": "Return", "Backspace": "BackSpace", "Tab": "Tab", "Escape": "Escape",
	"ArrowLeft": "Left", "ArrowRight": "Right", "ArrowUp": "Up", "ArrowDown": "Down",
	"Shift": "Shift_L", "Control": "Control_L", "Alt": "Alt_L", "Meta": "Super_L", "OS": "Super_L",
	"CapsLock": "Caps_Lock", "Delete": "Delete", "Home": "Home", "End": "End",
	"PageUp": "Prior", "PageDown": "Next", "Insert": "Insert", "ContextMenu": "Menu",
	"!": "exclam", "\"": "quotedbl", "#": "numbersign", "$": "dollar", "%": "percent",
	"&": "ampersand", "'": "apostrophe", "(": "parenleft", ")": "parenright", "*": "asterisk",
	"+": "plus", ",": "comma", "-": "minus", ".": "period", "/": "slash", ":": "colon",
	";": "semicolon", "<": "less", "=": "equal", ">": "greater", "?": "question", "@": "at",
	"[": "bracketleft", "\\": "backslash", "]": "bracketright", "^": "asciicircum",
	"_": "underscore", "`": "grave", "{": "braceleft", "|": "bar", "}": "braceright", "~": "asciitilde",
}

// keysymFor translates a browser KeyboardEvent.key value to an X11 keysym
// name. Single letters/digits and F-keys are already valid keysym names
// as-is; everything else that needs translating (whitespace, punctuation,
// and named keys spelled differently between the two conventions) is in
// jsKeyToKeysym.
func keysymFor(key string) string {
	if mapped, ok := jsKeyToKeysym[key]; ok {
		return mapped
	}
	return key
}

// uinput only accepts raw Linux keycodes (physical key positions), not
// Unicode characters, so a resolved KeyboardEvent.key has to be translated
// back to "which key, with Shift or not" assuming a US QWERTY layout -- the
// same assumption the X11 path makes implicitly via the X server's own
// keymap. Named keys (arrows, Enter, modifiers, function keys) aren't
// layout-dependent and always resolve the same way.
var namedKeyToLinuxKeycode = map[string]int{
	" ": uinput.KeySpace, "Enter": uinput.KeyEnter, "Backspace": uinput.KeyBackspace, "Tab": uinput.KeyTab,
	"Escape":    uinput.KeyEsc,
	"ArrowLeft": uinput.KeyLeft, "ArrowRight": uinput.KeyRight, "ArrowUp": uinput.KeyUp, "ArrowDown": uinput.KeyDown,
	"Shift": uinput.KeyLeftshift, "Control": uinput.KeyLeftctrl, "Alt": uinput.KeyLeftalt,
	"Meta": uinput.KeyLeftmeta, "OS": uinput.KeyLeftmeta,
	"CapsLock": uinput.KeyCapslock, "Delete": uinput.KeyDelete, "Home": uinput.KeyHome, "End": uinput.KeyEnd,
	"PageUp": uinput.KeyPageup, "PageDown": uinput.KeyPagedown, "Insert": uinput.KeyInsert, "ContextMenu": uinput.KeyCompose,
	"F1": uinput.KeyF1, "F2": uinput.KeyF2, "F3": uinput.KeyF3, "F4": uinput.KeyF4, "F5": uinput.KeyF5, "F6": uinput.KeyF6,
	"F7": uinput.KeyF7, "F8": uinput.KeyF8, "F9": uinput.KeyF9, "F10": uinput.KeyF10, "F11": uinput.KeyF11, "F12": uinput.KeyF12,
}

type linuxKey struct {
	code  int
	shift bool
}

var charToLinuxKeycode = map[rune]linuxKey{
	'!': {uinput.Key1, true}, '@': {uinput.Key2, true}, '#': {uinput.Key3, true}, '$': {uinput.Key4, true},
	'%': {uinput.Key5, true}, '^': {uinput.Key6, true}, '&': {uinput.Key7, true}, '*': {uinput.Key8, true},
	'(': {uinput.Key9, true}, ')': {uinput.Key0, true},
	'-': {uinput.KeyMinus, false}, '_': {uinput.KeyMinus, true},
	'=': {uinput.KeyEqual, false}, '+': {uinput.KeyEqual, true},
	'[': {uinput.KeyLeftbrace, false}, '{': {uinput.KeyLeftbrace, true},
	']': {uinput.KeyRightbrace, false}, '}': {uinput.KeyRightbrace, true},
	'\\': {uinput.KeyBackslash, false}, '|': {uinput.KeyBackslash, true},
	';': {uinput.KeySemicolon, false}, ':': {uinput.KeySemicolon, true},
	'\'': {uinput.KeyApostrophe, false}, '"': {uinput.KeyApostrophe, true},
	',': {uinput.KeyComma, false}, '<': {uinput.KeyComma, true},
	'.': {uinput.KeyDot, false}, '>': {uinput.KeyDot, true},
	'/': {uinput.KeySlash, false}, '?': {uinput.KeySlash, true},
	'`': {uinput.KeyGrave, false}, '~': {uinput.KeyGrave, true},
}

func init() {
	letterCodes := []int{
		uinput.KeyA, uinput.KeyB, uinput.KeyC, uinput.KeyD, uinput.KeyE, uinput.KeyF, uinput.KeyG, uinput.KeyH,
		uinput.KeyI, uinput.KeyJ, uinput.KeyK, uinput.KeyL, uinput.KeyM, uinput.KeyN, uinput.KeyO, uinput.KeyP,
		uinput.KeyQ, uinput.KeyR, uinput.KeyS, uinput.KeyT, uinput.KeyU, uinput.KeyV, uinput.KeyW, uinput.KeyX,
		uinput.KeyY, uinput.KeyZ,
	}
	for i, code := range letterCodes {
		lower := rune('a' + i)
		upper := rune('A' + i)
		charToLinuxKeycode[lower] = linuxKey{code, false}
		charToLinuxKeycode[upper] = linuxKey{code, true}
	}
	digitCodes := []int{
		uinput.Key0, uinput.Key1, uinput.Key2, uinput.Key3, uinput.Key4,
		uinput.Key5, uinput.Key6, uinput.Key7, uinput.Key8, uinput.Key9,
	}
	for i, code := range digitCodes {
		charToLinuxKeycode[rune('0'+i)] = linuxKey{code, false}
	}
}

// linuxKeycodeFor translates a browser KeyboardEvent.key value to a Linux
// uinput keycode plus whether Shift needs to be held for it.
func linuxKeycodeFor(key string) (code int, shift bool, ok bool) {
	if code, ok := namedKeyToLinuxKeycode[key]; ok {
		return code, false, true
	}
	runes := []rune(key)
	if len(runes) == 1 {
		if entry, ok := charToLinuxKeycode[runes[0]]; ok {
			return entry.code, entry.shift, true
		}
	}
	return 0, false, false
}

var mouseButtonNumber = map[string]byte{"left": 1, "middle": 2, "right": 3}

func (s *linuxSession) MouseMove(xFraction, yFraction float64) error {
	x, y := s.pixel(xFraction, yFraction)
	if s.displayServer == "wayland" {
		if s.uiTouchPad == nil {
			return fmt.Errorf("input is not supported for this session")
		}
		return s.uiTouchPad.MoveTo(int32(x), int32(y))
	}
	if s.xtestConn == nil {
		return fmt.Errorf("input is not supported for this session")
	}
	return xtest.FakeInputChecked(s.xtestConn, xproto.MotionNotify, 0, 0, s.xtestRoot, int16(x), int16(y), 0).Check()
}

func (s *linuxSession) MouseButton(xFraction, yFraction float64, button string, pressed bool) error {
	if s.displayServer == "wayland" {
		if s.uiTouchPad == nil {
			return fmt.Errorf("input is not supported for this session")
		}
		if err := s.MouseMove(xFraction, yFraction); err != nil {
			return err
		}
		switch button {
		case "right":
			if pressed {
				return s.uiTouchPad.RightPress()
			}
			return s.uiTouchPad.RightRelease()
		case "middle":
			if s.uiMouse == nil {
				return fmt.Errorf("input is not supported for this session")
			}
			if pressed {
				return s.uiMouse.MiddlePress()
			}
			return s.uiMouse.MiddleRelease()
		default:
			if pressed {
				return s.uiTouchPad.LeftPress()
			}
			return s.uiTouchPad.LeftRelease()
		}
	}
	if s.xtestConn == nil {
		return fmt.Errorf("input is not supported for this session")
	}
	if err := s.MouseMove(xFraction, yFraction); err != nil {
		return err
	}
	number := mouseButtonNumber[button]
	if number == 0 {
		number = 1
	}
	eventType := byte(xproto.ButtonRelease)
	if pressed {
		eventType = xproto.ButtonPress
	}
	return xtest.FakeInputChecked(s.xtestConn, eventType, number, 0, s.xtestRoot, 0, 0, 0).Check()
}

// scrollClicks turns a browser wheel delta into a (sign, click count) pair
// shared by both display-server backends: X11 fakes wheel motion as
// repeated button-4/5 clicks and uinput's relative mouse takes a signed
// REL_WHEEL/REL_HWHEEL click count directly, so both want the same
// clamped-magnitude integer.
func scrollClicks(delta float64) int {
	count := int(delta)
	if count < 0 {
		count = -count
	}
	if count == 0 {
		count = 1
	}
	if count > 20 {
		count = 20
	}
	return count
}

func (s *linuxSession) MouseScroll(deltaX, deltaY float64) error {
	if s.displayServer == "wayland" {
		if s.uiMouse == nil {
			return fmt.Errorf("input is not supported for this session")
		}
		// REL_WHEEL/REL_HWHEEL: positive is up/left, so a positive browser
		// deltaY (scrolling the view down) is the negative wheel value.
		if deltaY != 0 {
			count := int32(scrollClicks(deltaY))
			if deltaY > 0 {
				count = -count
			}
			if err := s.uiMouse.Wheel(false, count); err != nil {
				return err
			}
		}
		if deltaX != 0 {
			count := int32(scrollClicks(deltaX))
			if deltaX < 0 {
				count = -count
			}
			if err := s.uiMouse.Wheel(true, count); err != nil {
				return err
			}
		}
		return nil
	}
	if s.xtestConn == nil {
		return fmt.Errorf("input is not supported for this session")
	}
	// X11 has no analog scroll event; wheel motion is repeated clicks of
	// buttons 4/5 (up/down).
	button := byte(5)
	if deltaY < 0 {
		button = 4
	}
	count := scrollClicks(deltaY)
	for i := 0; i < count; i++ {
		if err := xtest.FakeInputChecked(s.xtestConn, xproto.ButtonPress, button, 0, s.xtestRoot, 0, 0, 0).Check(); err != nil {
			return err
		}
		if err := xtest.FakeInputChecked(s.xtestConn, xproto.ButtonRelease, button, 0, s.xtestRoot, 0, 0, 0).Check(); err != nil {
			return err
		}
	}
	return nil
}

func (s *linuxSession) Key(key string, pressed bool) error {
	if s.displayServer == "wayland" {
		if s.uiKeyboard == nil {
			return fmt.Errorf("input is not supported for this session")
		}
		code, shift, ok := linuxKeycodeFor(key)
		if !ok {
			return fmt.Errorf("unrecognized key %q", key)
		}
		if pressed {
			if shift {
				if err := s.uiKeyboard.KeyDown(uinput.KeyLeftshift); err != nil {
					return err
				}
			}
			return s.uiKeyboard.KeyDown(code)
		}
		err := s.uiKeyboard.KeyUp(code)
		if shift {
			if shiftErr := s.uiKeyboard.KeyUp(uinput.KeyLeftshift); err == nil {
				err = shiftErr
			}
		}
		return err
	}
	if !s.xdotoolAvailable {
		return fmt.Errorf("input is not supported for this session")
	}
	action := "keyup"
	if pressed {
		action = "keydown"
	}
	return s.command(context.Background(), "xdotool", action, keysymFor(key)).Run()
}

func (s *linuxSession) pixel(xFraction, yFraction float64) (int, int) {
	x := int(xFraction * float64(s.width))
	y := int(yFraction * float64(s.height))
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	return x, y
}

func (s *linuxSession) Close() error {
	if s.xtestConn != nil {
		s.xtestConn.Close()
	}
	if s.uiTouchPad != nil {
		s.uiTouchPad.Close()
	}
	if s.uiMouse != nil {
		s.uiMouse.Close()
	}
	if s.uiKeyboard != nil {
		s.uiKeyboard.Close()
	}
	return nil
}
