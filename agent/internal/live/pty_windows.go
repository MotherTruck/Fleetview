package live

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsPTY runs a real interactive console (PowerShell, falling back to
// cmd.exe) attached to a Windows ConPTY pseudoconsole, following the same
// raw Win32-syscall approach (via golang.org/x/sys/windows) the rest of
// this agent's Windows support uses rather than pulling in a separate
// ConPTY wrapper dependency. Like all Windows-specific code in this
// project, this has been written against the documented Win32 ConPTY
// sequence (CreatePseudoConsole + an attribute-list-attached CreateProcess)
// but has not been run against real Windows hardware.
type windowsPTY struct {
	console       windows.Handle
	process       windows.Handle
	thread        windows.Handle
	input         *os.File
	output        *os.File
	attributeList *windows.ProcThreadAttributeListContainer
}

func startShell(cols, rows int) (ptySession, error) {
	inputRead, inputWrite, err := newPipe()
	if err != nil {
		return nil, fmt.Errorf("create input pipe: %w", err)
	}
	outputRead, outputWrite, err := newPipe()
	if err != nil {
		_ = windows.CloseHandle(inputRead)
		_ = windows.CloseHandle(inputWrite)
		return nil, fmt.Errorf("create output pipe: %w", err)
	}

	var console windows.Handle
	err = windows.CreatePseudoConsole(windows.Coord{X: int16(cols), Y: int16(rows)}, inputRead, outputWrite, 0, &console)
	// ConPTY duplicates the ends it needs; our copies of the ends it now
	// owns are closed either way, success or failure.
	_ = windows.CloseHandle(inputRead)
	_ = windows.CloseHandle(outputWrite)
	if err != nil {
		_ = windows.CloseHandle(inputWrite)
		_ = windows.CloseHandle(outputRead)
		return nil, fmt.Errorf("CreatePseudoConsole: %w", err)
	}

	attributeList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		windows.ClosePseudoConsole(console)
		_ = windows.CloseHandle(inputWrite)
		_ = windows.CloseHandle(outputRead)
		return nil, fmt.Errorf("NewProcThreadAttributeList: %w", err)
	}
	if err := attributeList.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(&console), unsafe.Sizeof(console)); err != nil {
		attributeList.Delete()
		windows.ClosePseudoConsole(console)
		_ = windows.CloseHandle(inputWrite)
		_ = windows.CloseHandle(outputRead)
		return nil, fmt.Errorf("attach pseudoconsole attribute: %w", err)
	}

	commandLine, err := windows.UTF16PtrFromString(shellCommandLine())
	if err != nil {
		attributeList.Delete()
		windows.ClosePseudoConsole(console)
		_ = windows.CloseHandle(inputWrite)
		_ = windows.CloseHandle(outputRead)
		return nil, err
	}

	startupInfo := &windows.StartupInfoEx{ProcThreadAttributeList: attributeList.List()}
	startupInfo.Cb = uint32(unsafe.Sizeof(*startupInfo))
	processInfo := &windows.ProcessInformation{}
	err = windows.CreateProcess(nil, commandLine, nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		nil, nil, &startupInfo.StartupInfo, processInfo)
	attributeList.Delete()
	if err != nil {
		windows.ClosePseudoConsole(console)
		_ = windows.CloseHandle(inputWrite)
		_ = windows.CloseHandle(outputRead)
		return nil, fmt.Errorf("CreateProcess: %w", err)
	}
	_ = windows.CloseHandle(processInfo.Thread)

	return &windowsPTY{
		console: console,
		process: processInfo.Process,
		input:   os.NewFile(uintptr(inputWrite), "conpty-input"),
		output:  os.NewFile(uintptr(outputRead), "conpty-output"),
	}, nil
}

func newPipe() (readHandle, writeHandle windows.Handle, err error) {
	err = windows.CreatePipe(&readHandle, &writeHandle, nil, 0)
	return readHandle, writeHandle, err
}

// shellCommandLine prefers PowerShell (present on every supported Windows
// release) and falls back to cmd.exe if it can't be found on PATH.
func shellCommandLine() string {
	if path, err := exec.LookPath("powershell.exe"); err == nil {
		return path + " -NoLogo"
	}
	return "cmd.exe"
}

func (p *windowsPTY) Read(buffer []byte) (int, error)  { return p.output.Read(buffer) }
func (p *windowsPTY) Write(buffer []byte) (int, error) { return p.input.Write(buffer) }

func (p *windowsPTY) Resize(cols, rows int) error {
	return windows.ResizePseudoConsole(p.console, windows.Coord{X: int16(cols), Y: int16(rows)})
}

func (p *windowsPTY) Close() error {
	// Closing the pseudoconsole first (mirroring the Linux side closing the
	// pty master) is what makes a well-behaved console process exit on its
	// own; TerminateProcess is the backstop for one that doesn't.
	windows.ClosePseudoConsole(p.console)
	_ = windows.TerminateProcess(p.process, 0)
	_ = windows.CloseHandle(p.process)
	inputErr := p.input.Close()
	outputErr := p.output.Close()
	if inputErr != nil {
		return inputErr
	}
	return outputErr
}
