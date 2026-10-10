// Portal-based remote control for GNOME (Mutter) and KDE (KWin) Wayland
// sessions. grim (screen_linux.go's normal Wayland path) only works on
// wlroots-based compositors via the wlr-screencopy protocol; Mutter and
// KWin don't implement it at all, so on those two the only way to see or
// control the screen is the XDG Desktop Portal's ScreenCast + RemoteDesktop
// interfaces, which stream video over PipeWire and inject input over D-Bus.
//
// That portal is a per-user service, keyed off the real uid of whoever is
// asking -- unlike grim (a plain subprocess with DISPLAY/WAYLAND_DISPLAY
// set, which works fine run as root), the agent can't just set env vars and
// stay root. So this negotiates the whole session in a second process
// re-exec'd with the logged-in user's real uid/gid (see newPortalSession),
// talking to the parent (still root) over three channels: the helper's
// stdin carries input commands from the parent, its stdout carries a
// continuous multipart-JPEG video stream, and a third fd carries one line
// of JSON metadata (stream size, PipeWire node id, and a persistable
// restore token) once the portal session is actually up.
//
// The very first connection on a given device shows the user a real,
// compositor-drawn "Allow screen sharing?" dialog -- there's no way around
// that; it's what makes this safe to leave enabled on a device the agent
// doesn't control. The restore token issued after that first approval is
// saved to disk (see portalRestoreTokenPath) so every session after that
// reconnects silently.
package screen

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bendahl/uinput"
	"github.com/godbus/dbus/v5"
)

// PortalHelperFlag is the hidden argv[1] cmd/fleetview-agent checks for to
// dispatch into RunPortalHelper instead of normal agent startup -- the
// same pattern screen_windows.go's HelperFlag uses for the same reason:
// this invocation needs a real user's privileges (and here, a real D-Bus
// session), not a LocalSystem-equivalent root one.
const PortalHelperFlag = "--fleetview-portal-helper"

const (
	portalBusName         = "org.freedesktop.portal.Desktop"
	portalRestoreTokenDir = "/var/lib/fleetview-agent"

	portalDeviceKeyboard = 1
	portalDevicePointer  = 2
	portalSourceMonitor  = 1
	portalCursorEmbedded = 2

	// Linux evdev button codes (linux/input-event-codes.h), what
	// NotifyPointerButton expects -- the same convention uinput's
	// touchpad/mouse devices use at the kernel level.
	btnLeft   = 0x110
	btnRight  = 0x111
	btnMiddle = 0x112
)

var portalObjectPath = dbus.ObjectPath("/org/freedesktop/portal/desktop")

// detectPortal is Detect()'s Wayland branch for GNOME/KDE: it only checks
// for tools and plugins, never touches D-Bus, so it can't itself trigger
// the consent dialog (that only happens once a real session starts).
func detectPortal(desktop string) Capability {
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		return Capability{Reason: fmt.Sprintf(
			"%s's Wayland session needs GStreamer for screen capture (install gstreamer1.0-tools/gstreamer1.0-plugins-good on Debian/Ubuntu, or gstreamer/gst-plugins-good on Arch)", desktop)}
	}
	if _, err := exec.LookPath("gst-inspect-1.0"); err == nil {
		if err := exec.Command("gst-inspect-1.0", "pipewiresrc").Run(); err != nil {
			return Capability{Reason: fmt.Sprintf(
				"%s's Wayland session needs GStreamer's PipeWire plugin (gstreamer1.0-pipewire on Debian/Ubuntu, gst-plugin-pipewire on Arch)", desktop)}
		}
	}
	return Capability{Available: true, DisplayServer: "wayland", DesktopEnvironment: desktop}
}

func portalRestoreTokenPath(uid uint32) string {
	return filepath.Join(portalRestoreTokenDir, fmt.Sprintf("portal-restore-token-%d", uid))
}

func uniqueToken() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return "fv" + hex.EncodeToString(buf)
}

func sessionBusAddress(vars map[string]string) string {
	if addr := vars["DBUS_SESSION_BUS_ADDRESS"]; addr != "" {
		return addr
	}
	return "unix:path=" + vars["XDG_RUNTIME_DIR"] + "/bus"
}

// portalMetadata is the single JSON line the helper writes to its third fd
// once the portal session is live (or, with Error set, once it's given up).
type portalMetadata struct {
	NodeID       uint32 `json:"node_id"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	RestoreToken string `json:"restore_token"`
	Error        string `json:"error,omitempty"`
}

// portalSession is the parent (root) side: a still-root process talking to
// the privilege-dropped helper over three pipes.
type portalSession struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	frames    *bufio.Reader
	width     int
	height    int
	closeOnce sync.Once
}

func newPortalSession(vars map[string]string, uid, gid uint32) (Session, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate agent binary: %w", err)
	}
	existingToken, _ := os.ReadFile(portalRestoreTokenPath(uid))

	cmd := exec.Command(exePath, PortalHelperFlag)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + vars["HOME"],
		"DBUS_SESSION_BUS_ADDRESS=" + sessionBusAddress(vars),
		"WAYLAND_DISPLAY=" + vars["WAYLAND_DISPLAY"],
		"XDG_RUNTIME_DIR=" + vars["XDG_RUNTIME_DIR"],
		"FLEETVIEW_PORTAL_RESTORE_TOKEN=" + strings.TrimSpace(string(existingToken)),
	}
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("portal helper stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("portal helper stdout: %w", err)
	}
	metaRead, metaWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("portal helper metadata pipe: %w", err)
	}
	cmd.ExtraFiles = []*os.File{metaWrite}

	if err := cmd.Start(); err != nil {
		metaRead.Close()
		metaWrite.Close()
		return nil, fmt.Errorf("start portal helper: %w", err)
	}
	metaWrite.Close() // the child's post-fork copy is what actually gets written to

	// The first connection ever made on this device blocks here until
	// whoever is logged in answers the compositor's own consent dialog --
	// there is no way to skip or shorten that, and no way to know in
	// advance whether this will be instant (a saved restore token) or
	// take a couple of minutes (someone has to go click Allow).
	metaLine, err := readMetadataLine(metaRead, 3*time.Minute)
	metaRead.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("portal negotiation: %w", err)
	}
	var meta portalMetadata
	if err := json.Unmarshal(metaLine, &meta); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("portal helper sent malformed metadata: %w", err)
	}
	if meta.Error != "" {
		_ = cmd.Wait()
		return nil, fmt.Errorf("portal negotiation failed: %s", meta.Error)
	}
	if meta.RestoreToken != "" {
		if err := os.MkdirAll(portalRestoreTokenDir, 0700); err == nil {
			_ = os.WriteFile(portalRestoreTokenPath(uid), []byte(meta.RestoreToken), 0600)
		}
	}
	width, height := meta.Width, meta.Height
	if width <= 0 || height <= 0 {
		// The compositor didn't report a stream size (optional per the
		// portal spec); fall back to something sane rather than dividing
		// by zero in pixel() below. Clicks will be misaligned until a
		// real resolution is threaded through here.
		width, height = 1920, 1080
	}
	return &portalSession{cmd: cmd, stdin: stdin, frames: bufio.NewReader(stdout), width: width, height: height}, nil
}

func readMetadataLine(r *os.File, timeout time.Duration) ([]byte, error) {
	type result struct {
		line []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(r).ReadBytes('\n')
		ch <- result{line, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil && len(res.line) == 0 {
			return nil, res.err
		}
		return res.line, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out waiting for the on-screen consent dialog to be answered")
	}
}

func (s *portalSession) pixel(xFraction, yFraction float64) (int, int) {
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

func (s *portalSession) sendLine(line string) error {
	_, err := io.WriteString(s.stdin, line)
	return err
}

func (s *portalSession) Capture(ctx context.Context) ([]byte, int, int, error) {
	data, err := readMultipartJPEG(s.frames)
	if err != nil {
		return nil, 0, 0, err
	}
	return data, s.width, s.height, nil
}

func (s *portalSession) MouseMove(xFraction, yFraction float64) error {
	x, y := s.pixel(xFraction, yFraction)
	return s.sendLine(fmt.Sprintf("MOVE %d %d\n", x, y))
}

var portalButtonCode = map[string]int{"left": btnLeft, "middle": btnMiddle, "right": btnRight}

func (s *portalSession) MouseButton(xFraction, yFraction float64, button string, pressed bool) error {
	if err := s.MouseMove(xFraction, yFraction); err != nil {
		return err
	}
	code, ok := portalButtonCode[button]
	if !ok {
		code = btnLeft
	}
	state := 0
	if pressed {
		state = 1
	}
	return s.sendLine(fmt.Sprintf("BUTTON %d %d\n", code, state))
}

func (s *portalSession) MouseScroll(deltaX, deltaY float64) error {
	return s.sendLine(fmt.Sprintf("AXIS %f %f\n", deltaX, deltaY))
}

func (s *portalSession) Key(key string, pressed bool) error {
	code, shift, ok := linuxKeycodeFor(key)
	if !ok {
		return fmt.Errorf("unrecognized key %q", key)
	}
	state := 0
	if pressed {
		state = 1
	}
	if pressed {
		if shift {
			if err := s.sendLine(fmt.Sprintf("KEY %d 1\n", uinput.KeyLeftshift)); err != nil {
				return err
			}
		}
		return s.sendLine(fmt.Sprintf("KEY %d %d\n", code, state))
	}
	err := s.sendLine(fmt.Sprintf("KEY %d %d\n", code, state))
	if shift {
		if shiftErr := s.sendLine(fmt.Sprintf("KEY %d 0\n", uinput.KeyLeftshift)); err == nil {
			err = shiftErr
		}
	}
	return err
}

func (s *portalSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.sendLine("QUIT\n")
		_ = s.stdin.Close()
		done := make(chan struct{})
		go func() {
			_ = s.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = s.cmd.Process.Kill()
			<-done
		}
	})
	return nil
}

// readMultipartJPEG reads one part from the multipart/x-mixed-replace-style
// stream gst-launch-1.0's multipartmux element writes: a "--boundary" line,
// headers (only Content-Length matters here), a blank line, then exactly
// that many bytes of JPEG data followed by a trailing CRLF.
func readMultipartJPEG(r *bufio.Reader) ([]byte, error) {
	contentLength := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			if contentLength < 0 {
				continue
			}
			break
		}
		if strings.HasPrefix(trimmed, "--") {
			contentLength = -1
			continue
		}
		if name, value, ok := strings.Cut(trimmed, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			if n, convErr := strconv.Atoi(strings.TrimSpace(value)); convErr == nil {
				contentLength = n
			}
		}
	}
	buf := make([]byte, contentLength)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	_, _ = r.Discard(2) // the trailing CRLF after each part's payload
	return buf, nil
}

// -- helper process side (runs with the logged-in user's real uid/gid) --

func writeHelperMetadata(meta portalMetadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f := os.NewFile(3, "fleetview-portal-meta")
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func writeHelperError(err error) {
	_ = writeHelperMetadata(portalMetadata{Error: err.Error()})
}

// RunPortalHelper is the entire portal-helper process: negotiate a
// combined ScreenCast+RemoteDesktop session, hand the parent a PipeWire fd
// via gst-launch-1.0 piping JPEG frames to this process's own stdout, and
// relay input commands from stdin to the RemoteDesktop D-Bus interface
// until told to stop. Returns a process exit code.
func RunPortalHelper(args []string) int {
	logger := log.New(os.Stderr, "portal-helper: ", log.LstdFlags)

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		writeHelperError(fmt.Errorf("connect session bus: %w", err))
		return 1
	}
	defer conn.Close()

	session, err := portalCreateSession(conn)
	if err != nil {
		writeHelperError(fmt.Errorf("create session: %w", err))
		return 1
	}
	restoreToken := os.Getenv("FLEETVIEW_PORTAL_RESTORE_TOKEN")
	if err := portalSelectDevices(conn, session, restoreToken); err != nil {
		writeHelperError(fmt.Errorf("select devices: %w", err))
		return 1
	}
	if err := portalSelectSources(conn, session); err != nil {
		writeHelperError(fmt.Errorf("select sources: %w", err))
		return 1
	}
	streams, newToken, err := portalStart(conn, session)
	if err != nil {
		writeHelperError(fmt.Errorf("start session: %w", err))
		return 1
	}
	if len(streams) == 0 {
		writeHelperError(fmt.Errorf("no screencast stream was granted"))
		return 1
	}
	stream := streams[0]

	pwFile, err := portalOpenPipeWireRemote(conn, session)
	if err != nil {
		writeHelperError(fmt.Errorf("open pipewire remote: %w", err))
		return 1
	}
	defer pwFile.Close()

	if err := writeHelperMetadata(portalMetadata{
		NodeID: stream.NodeID, Width: stream.Width, Height: stream.Height, RestoreToken: newToken,
	}); err != nil {
		logger.Println("write metadata:", err)
		return 1
	}

	gst := exec.Command("gst-launch-1.0", "-e",
		"pipewiresrc", "fd=3", fmt.Sprintf("path=%d", stream.NodeID),
		"!", "videoconvert",
		"!", "jpegenc", "quality=70",
		"!", "multipartmux", "boundary=fleetview",
		"!", "fdsink", "fd=1")
	gst.ExtraFiles = []*os.File{pwFile}
	gst.Stdout = os.Stdout
	gst.Stderr = os.Stderr
	if err := gst.Start(); err != nil {
		logger.Println("start gst-launch-1.0:", err)
		return 1
	}

	go handlePortalCommands(conn, session, stream.NodeID, os.Stdin, gst, logger)

	_ = gst.Wait()
	return 0
}

func handlePortalCommands(conn *dbus.Conn, session dbus.ObjectPath, streamID uint32, stdin io.Reader, gst *exec.Cmd, logger *log.Logger) {
	rd := conn.Object(portalBusName, portalObjectPath)
	noOptions := map[string]dbus.Variant{}
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "MOVE":
			if len(fields) != 3 {
				continue
			}
			x, errX := strconv.ParseFloat(fields[1], 64)
			y, errY := strconv.ParseFloat(fields[2], 64)
			if errX != nil || errY != nil {
				continue
			}
			call := rd.Call("org.freedesktop.portal.RemoteDesktop.NotifyPointerMotionAbsolute", 0, session, noOptions, streamID, x, y)
			if call.Err != nil {
				logger.Println("NotifyPointerMotionAbsolute:", call.Err)
			}
		case "BUTTON":
			if len(fields) != 3 {
				continue
			}
			code, errC := strconv.Atoi(fields[1])
			state, errS := strconv.Atoi(fields[2])
			if errC != nil || errS != nil {
				continue
			}
			call := rd.Call("org.freedesktop.portal.RemoteDesktop.NotifyPointerButton", 0, session, noOptions, int32(code), uint32(state))
			if call.Err != nil {
				logger.Println("NotifyPointerButton:", call.Err)
			}
		case "KEY":
			if len(fields) != 3 {
				continue
			}
			code, errC := strconv.Atoi(fields[1])
			state, errS := strconv.Atoi(fields[2])
			if errC != nil || errS != nil {
				continue
			}
			call := rd.Call("org.freedesktop.portal.RemoteDesktop.NotifyKeyboardKeycode", 0, session, noOptions, int32(code), uint32(state))
			if call.Err != nil {
				logger.Println("NotifyKeyboardKeycode:", call.Err)
			}
		case "AXIS":
			if len(fields) != 3 {
				continue
			}
			dx, errX := strconv.ParseFloat(fields[1], 64)
			dy, errY := strconv.ParseFloat(fields[2], 64)
			if errX != nil || errY != nil {
				continue
			}
			call := rd.Call("org.freedesktop.portal.RemoteDesktop.NotifyPointerAxis", 0, session, noOptions, dx, dy)
			if call.Err != nil {
				logger.Println("NotifyPointerAxis:", call.Err)
			}
		case "QUIT":
			if gst.Process != nil {
				_ = gst.Process.Kill()
			}
			return
		}
	}
	if gst.Process != nil {
		_ = gst.Process.Kill()
	}
}

// callPortalRequest calls a portal method that returns a Request object
// path (CreateSession, SelectDevices, SelectSources, Start) and blocks for
// that Request's Response signal, subscribing before making the call per
// the spec's own recommendation (the response can in principle arrive
// before the method call even returns).
func callPortalRequest(conn *dbus.Conn, method string, args []interface{}, token string) (map[string]dbus.Variant, error) {
	sender := strings.ReplaceAll(strings.TrimPrefix(string(conn.Names()[0]), ":"), ".", "_")
	expectedPath := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/portal/desktop/request/%s/%s", sender, token))

	signalCh := make(chan *dbus.Signal, 1)
	conn.Signal(signalCh)
	defer conn.RemoveSignal(signalCh)
	matchRule := []dbus.MatchOption{
		dbus.WithMatchObjectPath(expectedPath),
		dbus.WithMatchInterface("org.freedesktop.portal.Request"),
		dbus.WithMatchMember("Response"),
	}
	if err := conn.AddMatchSignal(matchRule...); err != nil {
		return nil, fmt.Errorf("subscribe to Response: %w", err)
	}
	defer conn.RemoveMatchSignal(matchRule...)

	obj := conn.Object(portalBusName, portalObjectPath)
	var gotPath dbus.ObjectPath
	call := obj.Call(method, 0, args...)
	if call.Err != nil {
		return nil, call.Err
	}
	if err := call.Store(&gotPath); err != nil {
		return nil, err
	}
	if gotPath != expectedPath {
		_ = conn.RemoveMatchSignal(matchRule...)
		matchRule = []dbus.MatchOption{
			dbus.WithMatchObjectPath(gotPath),
			dbus.WithMatchInterface("org.freedesktop.portal.Request"),
			dbus.WithMatchMember("Response"),
		}
		if err := conn.AddMatchSignal(matchRule...); err != nil {
			return nil, err
		}
		defer conn.RemoveMatchSignal(matchRule...)
	}

	select {
	case sig := <-signalCh:
		if len(sig.Body) < 2 {
			return nil, fmt.Errorf("malformed Response signal")
		}
		response, _ := sig.Body[0].(uint32)
		results, _ := sig.Body[1].(map[string]dbus.Variant)
		if response != 0 {
			return nil, fmt.Errorf("request denied or cancelled (response=%d)", response)
		}
		return results, nil
	case <-time.After(3 * time.Minute):
		return nil, fmt.Errorf("timed out waiting for user response")
	}
}

func portalCreateSession(conn *dbus.Conn) (dbus.ObjectPath, error) {
	handleToken := uniqueToken()
	options := map[string]dbus.Variant{
		"handle_token":         dbus.MakeVariant(handleToken),
		"session_handle_token": dbus.MakeVariant(uniqueToken()),
	}
	results, err := callPortalRequest(conn, "org.freedesktop.portal.RemoteDesktop.CreateSession", []interface{}{options}, handleToken)
	if err != nil {
		return "", err
	}
	raw, ok := results["session_handle"]
	if !ok {
		return "", fmt.Errorf("response missing session_handle")
	}
	handleStr, ok := raw.Value().(string)
	if !ok {
		return "", fmt.Errorf("session_handle has unexpected type %T", raw.Value())
	}
	return dbus.ObjectPath(handleStr), nil
}

func portalSelectDevices(conn *dbus.Conn, session dbus.ObjectPath, restoreToken string) error {
	handleToken := uniqueToken()
	options := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(handleToken),
		"types":        dbus.MakeVariant(uint32(portalDeviceKeyboard | portalDevicePointer)),
		"persist_mode": dbus.MakeVariant(uint32(2)), // persist until the user explicitly revokes it
	}
	if restoreToken != "" {
		options["restore_token"] = dbus.MakeVariant(restoreToken)
	}
	_, err := callPortalRequest(conn, "org.freedesktop.portal.RemoteDesktop.SelectDevices", []interface{}{session, options}, handleToken)
	return err
}

func portalSelectSources(conn *dbus.Conn, session dbus.ObjectPath) error {
	handleToken := uniqueToken()
	options := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(handleToken),
		"types":        dbus.MakeVariant(uint32(portalSourceMonitor)),
		"cursor_mode":  dbus.MakeVariant(uint32(portalCursorEmbedded)),
		"multiple":     dbus.MakeVariant(false),
	}
	// Persistence for a combined RemoteDesktop+ScreenCast session is
	// carried entirely by SelectDevices above -- the spec explicitly says
	// ScreenCast's own persist_mode/restore_token must not be used here.
	_, err := callPortalRequest(conn, "org.freedesktop.portal.ScreenCast.SelectSources", []interface{}{session, options}, handleToken)
	return err
}

type portalStream struct {
	NodeID        uint32
	Width, Height int
}

func portalStart(conn *dbus.Conn, session dbus.ObjectPath) ([]portalStream, string, error) {
	handleToken := uniqueToken()
	options := map[string]dbus.Variant{"handle_token": dbus.MakeVariant(handleToken)}
	results, err := callPortalRequest(conn, "org.freedesktop.portal.RemoteDesktop.Start", []interface{}{session, "", options}, handleToken)
	if err != nil {
		return nil, "", err
	}
	streamsVariant, ok := results["streams"]
	if !ok {
		return nil, "", fmt.Errorf("response missing streams")
	}
	streams, err := decodePortalStreams(streamsVariant)
	if err != nil {
		return nil, "", err
	}
	restoreToken := ""
	if rt, ok := results["restore_token"]; ok {
		if s, ok := rt.Value().(string); ok {
			restoreToken = s
		}
	}
	return streams, restoreToken, nil
}

func decodePortalStreams(v dbus.Variant) ([]portalStream, error) {
	raw, ok := v.Value().([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected streams type %T", v.Value())
	}
	var streams []portalStream
	for _, entry := range raw {
		fields, ok := entry.([]interface{})
		if !ok || len(fields) < 2 {
			continue
		}
		nodeID, ok := fields[0].(uint32)
		if !ok {
			continue
		}
		props, _ := fields[1].(map[string]dbus.Variant)
		width, height := 0, 0
		if sizeVariant, ok := props["size"]; ok {
			if size, ok := sizeVariant.Value().([]interface{}); ok && len(size) == 2 {
				if w, ok := size[0].(int32); ok {
					width = int(w)
				}
				if h, ok := size[1].(int32); ok {
					height = int(h)
				}
			}
		}
		streams = append(streams, portalStream{NodeID: nodeID, Width: width, Height: height})
	}
	return streams, nil
}

func portalOpenPipeWireRemote(conn *dbus.Conn, session dbus.ObjectPath) (*os.File, error) {
	obj := conn.Object(portalBusName, portalObjectPath)
	call := obj.Call("org.freedesktop.portal.ScreenCast.OpenPipeWireRemote", 0, session, map[string]dbus.Variant{})
	if call.Err != nil {
		return nil, call.Err
	}
	var fd dbus.UnixFD
	if err := call.Store(&fd); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "pipewire-remote"), nil
}
