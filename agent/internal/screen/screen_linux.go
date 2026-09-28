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

	"github.com/BurntSushi/xgb"
	"github.com/BurntSushi/xgb/xproto"
	"github.com/BurntSushi/xgb/xtest"
)

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
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "environ"))
		if err != nil {
			continue
		}
		vars := parseEnviron(data)
		found := true
		for _, key := range required {
			if vars[key] == "" {
				found = false
				break
			}
		}
		if found {
			return vars, true
		}
	}
	return nil, false
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
		if _, err := exec.LookPath("grim"); err != nil {
			return Capability{Reason: "An active Wayland session was found, but 'grim' is not installed"}
		}
		return Capability{Available: true, ViewOnly: true, DisplayServer: "wayland", DesktopEnvironment: desktop,
			Reason: "Wayland has no universal input-injection tool the way X11 has xdotool; view-only"}
	}
	return Capability{Reason: "No active graphical (X11 or Wayland) session was found on this device"}
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
	if vars, ok := findGraphicalSession("WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"); ok {
		if _, err := exec.LookPath("grim"); err != nil {
			return nil, fmt.Errorf("'grim' is not installed")
		}
		return &linuxSession{
			displayServer: "wayland",
			env:           []string{"WAYLAND_DISPLAY=" + vars["WAYLAND_DISPLAY"], "XDG_RUNTIME_DIR=" + vars["XDG_RUNTIME_DIR"]},
		}, nil
	}
	return nil, fmt.Errorf("no active graphical session was found")
}

func (s *linuxSession) geometry() (int, int, error) {
	if s.displayServer == "wayland" {
		// No xdotool-equivalent on Wayland; the first captured frame's own
		// dimensions (set by Capture) are what MouseMove et al. would use,
		// but those are unsupported for Wayland sessions anyway.
		return 1, 1, nil
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

var mouseButtonNumber = map[string]byte{"left": 1, "middle": 2, "right": 3}

func (s *linuxSession) MouseMove(xFraction, yFraction float64) error {
	if s.xtestConn == nil {
		return fmt.Errorf("input is not supported for this session")
	}
	x, y := s.pixel(xFraction, yFraction)
	return xtest.FakeInputChecked(s.xtestConn, xproto.MotionNotify, 0, 0, s.xtestRoot, int16(x), int16(y), 0).Check()
}

func (s *linuxSession) MouseButton(xFraction, yFraction float64, button string, pressed bool) error {
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

func (s *linuxSession) MouseScroll(deltaX, deltaY float64) error {
	if s.xtestConn == nil {
		return fmt.Errorf("input is not supported for this session")
	}
	// X11 has no analog scroll event; wheel motion is repeated clicks of
	// buttons 4/5 (up/down).
	button, count := byte(5), int(deltaY)
	if deltaY < 0 {
		button = 4
	}
	if count < 0 {
		count = -count
	}
	if count == 0 {
		count = 1
	}
	if count > 20 {
		count = 20
	}
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
	return nil
}
