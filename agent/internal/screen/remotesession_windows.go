package screen

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// remoteScreenSession implements Session by relaying to a helper process
// running inside the target user's session (see NewSession in
// screen_windows.go for why that's necessary, and spawnHelperSession
// below for how it's launched). framePipe is a request/response channel
// (one capture request byte in, one JPEG frame or error back); inputPipe
// is one-way, service to helper. Both pipes are only ever driven by a
// single goroutine each in practice (screenHandler's capture loop owns
// Capture; its WS message-dispatch loop owns the input methods, serially),
// so neither needs its own lock.
type remoteScreenSession struct {
	framePipe *os.File
	inputPipe *os.File
	process   windows.Handle
}

func spawnHelperSession(sessionID uint32) (*remoteScreenSession, error) {
	tcbToken, err := enableTcbPrivilege()
	if err != nil {
		return nil, fmt.Errorf("enable SeTcbPrivilege (required to query another session's user token): %w", err)
	}
	defer tcbToken.Close()

	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &userToken); err != nil {
		return nil, fmt.Errorf("query user token for session %d: %w", sessionID, err)
	}
	defer userToken.Close()

	// WTSQueryUserToken returns the filtered, standard-rights token for
	// this session -- the same one Explorer and everything else in a
	// normal desktop session runs with, even when the logged-on user is
	// an administrator. Windows' UIPI then blocks a process at that
	// (medium) integrity level from sending input to any higher-integrity
	// window, such as Task Manager or PowerShell run elevated ("Run as
	// administrator"): screen capture still works (UIPI only restricts
	// input), but every click and keystroke into that window is silently
	// dropped. If this user is an administrator with UAC enabled, Windows
	// keeps a second, linked token for them -- the full elevated one,
	// same user, same login -- and GetLinkedToken returns it. Using it
	// here isn't a privilege escalation: it's the SYSTEM-level agent
	// service (already more privileged than any local admin) choosing
	// the already-logged-in user's OTHER already-available token so the
	// helper can reach elevated windows too. A standard, non-admin user
	// has no linked token; GetLinkedToken then just errors and the
	// original token is used as-is, exactly as before.
	tokenForHelper := userToken
	if linked, linkErr := userToken.GetLinkedToken(); linkErr == nil && linked != 0 {
		defer linked.Close()
		tokenForHelper = linked
	}

	var primaryToken windows.Token
	if err := windows.DuplicateTokenEx(tokenForHelper, 0, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primaryToken); err != nil {
		return nil, fmt.Errorf("duplicate user token as a primary token: %w", err)
	}
	defer primaryToken.Close()

	suffix, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generate pipe name: %w", err)
	}
	framePipeName := `\\.\pipe\fleetview-rc-` + suffix + `-frame`
	inputPipeName := `\\.\pipe\fleetview-rc-` + suffix + `-input`

	// The service runs as LocalSystem; the helper runs as whichever
	// ordinary user is logged into the target session. Named pipes default
	// to a DACL that only grants the creator (and admins) access, so
	// without this the helper could never open either pipe. The random
	// 16-byte name segment is the real access control here -- anyone who
	// could guess it could already do far more as that logged-in user.
	securityDescriptor, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;WD)")
	if err != nil {
		return nil, fmt.Errorf("build pipe security descriptor: %w", err)
	}
	pipeSecurity := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
	}

	frameHandle, err := createNamedPipe(framePipeName, windows.PIPE_ACCESS_DUPLEX, pipeSecurity)
	if err != nil {
		return nil, fmt.Errorf("create frame pipe: %w", err)
	}
	inputHandle, err := createNamedPipe(inputPipeName, windows.PIPE_ACCESS_OUTBOUND, pipeSecurity)
	if err != nil {
		windows.CloseHandle(frameHandle)
		return nil, fmt.Errorf("create input pipe: %w", err)
	}

	process, err := launchHelper(primaryToken, sessionID, framePipeName, inputPipeName)
	if err != nil {
		windows.CloseHandle(frameHandle)
		windows.CloseHandle(inputHandle)
		return nil, err
	}

	if err := waitForPipeConnection(frameHandle, 10*time.Second); err != nil {
		windows.TerminateProcess(process, 1)
		windows.CloseHandle(process)
		windows.CloseHandle(frameHandle)
		windows.CloseHandle(inputHandle)
		return nil, fmt.Errorf("screen helper did not connect its frame pipe: %w", err)
	}
	if err := waitForPipeConnection(inputHandle, 10*time.Second); err != nil {
		windows.TerminateProcess(process, 1)
		windows.CloseHandle(process)
		windows.CloseHandle(frameHandle)
		windows.CloseHandle(inputHandle)
		return nil, fmt.Errorf("screen helper did not connect its input pipe: %w", err)
	}

	return &remoteScreenSession{
		framePipe: os.NewFile(uintptr(frameHandle), framePipeName),
		inputPipe: os.NewFile(uintptr(inputHandle), inputPipeName),
		process:   process,
	}, nil
}

// enableTcbPrivilege enables SeTcbPrivilege ("act as part of the operating
// system") on this process's own token, required for WTSQueryUserToken to
// succeed. LocalSystem (the account the agent service runs as) holds this
// privilege by default, but a token's privileges start disabled until
// explicitly enabled. The returned token must be closed by the caller.
//
// Unverified edge case: AdjustTokenPrivileges reports success even when it
// couldn't enable every requested privilege (that detail is only available
// via a separate GetLastError() == ERROR_NOT_ALL_ASSIGNED check, which this
// does not make), so a token that genuinely lacks SeTcbPrivilege would
// still appear to succeed here and only fail later, at WTSQueryUserToken.
func enableTcbPrivilege() (windows.Token, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return 0, fmt.Errorf("open process token: %w", err)
	}
	namePtr, err := windows.UTF16PtrFromString("SeTcbPrivilege")
	if err != nil {
		token.Close()
		return 0, err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		token.Close()
		return 0, fmt.Errorf("look up SeTcbPrivilege: %w", err)
	}
	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil); err != nil {
		token.Close()
		return 0, fmt.Errorf("adjust token privileges: %w", err)
	}
	return token, nil
}

func createNamedPipe(name string, accessFlags uint32, sa *windows.SecurityAttributes) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateNamedPipe(namePtr,
		accessFlags, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		1, 1<<20, 1<<20, 0, sa)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

// waitForPipeConnection blocks (off the caller's goroutine, so it can be
// bounded by timeout) until a client connects to handle. ConnectNamedPipe
// has no built-in timeout and no cancellation short of closing the handle,
// which isn't safe to do from a second goroutine while the call is still
// in flight -- so on timeout this leaves the wait running in the
// background rather than forcing it to stop; it will exit on its own once
// the helper connects (and then just as that duplicate handle gets closed
// up the call stack) or the process exits.
func waitForPipeConnection(handle windows.Handle, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		err := windows.ConnectNamedPipe(handle, nil)
		if err == windows.ERROR_PIPE_CONNECTED {
			err = nil
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timed out after %s", timeout)
	}
}

// helperExecutablePath is a package var (rather than a direct
// os.Executable() call) purely so a test can point the spawned helper at
// a real, fully-wired agent binary instead of whatever test binary
// happens to be running -- a go test binary has no HelperFlag handling
// of its own (see cmd/fleetview-agent/screenhelper_windows.go), so using
// os.Executable() unconditionally would make an end-to-end spawn test
// launch something that can never actually behave like the helper.
var helperExecutablePath = os.Executable

func launchHelper(primaryToken windows.Token, sessionID uint32, framePipeName, inputPipeName string) (windows.Handle, error) {
	exe, err := helperExecutablePath()
	if err != nil {
		return 0, fmt.Errorf("find own executable: %w", err)
	}
	commandLine := fmt.Sprintf(`%q %s %s %s`, exe, HelperFlag, framePipeName, inputPipeName)
	cmdLinePtr, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return 0, err
	}
	desktopPtr, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return 0, err
	}

	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, primaryToken, false); err != nil {
		return 0, fmt.Errorf("create environment block for session %d: %w", sessionID, err)
	}
	defer windows.DestroyEnvironmentBlock(envBlock)

	startupInfo := &windows.StartupInfo{
		Cb:      uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop: desktopPtr,
	}
	// CREATE_NO_WINDOW, not CREATE_NEW_CONSOLE: the helper is a plain
	// console-subsystem Go binary (the agent isn't built with
	// -H=windowsgui), so it still needs a console allocated to run at
	// all, but CREATE_NEW_CONSOLE made that console a real visible
	// window on the user's desktop -- and closing it delivered
	// CTRL_CLOSE_EVENT, which Go's default console handler treats as a
	// request to exit, killing the helper and ending the remote-control
	// session right along with it. CREATE_NO_WINDOW allocates the same
	// console the process needs, just never shown.
	var procInfo windows.ProcessInformation
	err = windows.CreateProcessAsUser(primaryToken, nil, cmdLinePtr, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, envBlock, nil, startupInfo, &procInfo)
	if err != nil {
		return 0, fmt.Errorf("launch screen helper in session %d: %w", sessionID, err)
	}
	windows.CloseHandle(procInfo.Thread)
	return procInfo.Process, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Capture requests one frame from the helper and waits for its response.
// Framing on the wire: 1 status byte (0 ok, nonzero error) + a 4-byte LE
// length + that many bytes (a JPEG on success, a UTF-8 message on error).
func (s *remoteScreenSession) Capture(ctx context.Context) ([]byte, int, int, error) {
	if _, err := s.framePipe.Write([]byte{1}); err != nil {
		return nil, 0, 0, fmt.Errorf("request frame from screen helper: %w", err)
	}
	status := make([]byte, 1)
	if _, err := readFull(s.framePipe, status); err != nil {
		return nil, 0, 0, fmt.Errorf("read frame status from screen helper: %w", err)
	}
	payload, err := readFramed(s.framePipe)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read frame from screen helper: %w", err)
	}
	if status[0] != 0 {
		return nil, 0, 0, fmt.Errorf("screen helper: %s", payload)
	}
	width, height, err := decodeJPEGSize(payload)
	if err != nil {
		return nil, 0, 0, err
	}
	return payload, width, height, nil
}

func (s *remoteScreenSession) MouseMove(xFraction, yFraction float64) error {
	return s.sendInput(inputMsgMouseMove, encodeMouseMove(xFraction, yFraction))
}

func (s *remoteScreenSession) MouseButton(xFraction, yFraction float64, button string, pressed bool) error {
	return s.sendInput(inputMsgMouseButton, encodeMouseButton(xFraction, yFraction, button, pressed))
}

func (s *remoteScreenSession) MouseScroll(deltaX, deltaY float64) error {
	return s.sendInput(inputMsgMouseScroll, encodeMouseScroll(deltaX, deltaY))
}

func (s *remoteScreenSession) Key(key string, pressed bool) error {
	return s.sendInput(inputMsgKey, encodeKey(key, pressed))
}

func (s *remoteScreenSession) sendInput(msgType byte, payload []byte) error {
	if _, err := s.inputPipe.Write(encodeInputMessage(msgType, payload)); err != nil {
		return fmt.Errorf("send input to screen helper: %w", err)
	}
	return nil
}

func (s *remoteScreenSession) Close() error {
	s.framePipe.Close()
	s.inputPipe.Close()
	if s.process != 0 {
		windows.TerminateProcess(s.process, 0)
		windows.CloseHandle(s.process)
	}
	return nil
}
