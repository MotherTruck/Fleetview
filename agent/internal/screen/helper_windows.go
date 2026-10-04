package screen

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// HelperFlag is the hidden command-line flag cmd/fleetview-agent checks for
// at startup, before normal flag parsing, to decide whether this process
// invocation is the screen-capture helper spawnHelperSession just launched
// into a user's session (see remotesession_windows.go) rather than the
// agent itself. Exported so main.go's wiring and the spawn code that
// builds the helper's command line share one source of truth.
const HelperFlag = "--fleetview-screen-helper"

// RunHelper is the helper process's entire job: connect to the two pipes
// the spawning service process already created and is waiting on, then
// bridge them to a plain, local windowsSession -- the same GDI/SendInput
// code NewSession uses directly when this process already owns the
// session being captured. Running inside the target user's session is
// what makes that capture/injection actually reach their real desktop.
func RunHelper(framePipeName, inputPipeName string) error {
	framePipe, err := dialPipe(framePipeName, windows.GENERIC_READ|windows.GENERIC_WRITE)
	if err != nil {
		return fmt.Errorf("connect frame pipe: %w", err)
	}
	defer framePipe.Close()
	inputPipe, err := dialPipe(inputPipeName, windows.GENERIC_READ)
	if err != nil {
		return fmt.Errorf("connect input pipe: %w", err)
	}
	defer inputPipe.Close()

	session, err := newLocalSession()
	if err != nil {
		return fmt.Errorf("start local capture: %w", err)
	}
	defer session.Close()

	errs := make(chan error, 2)
	go func() { errs <- runFrameLoop(framePipe, session) }()
	go func() { errs <- runInputLoop(inputPipe, session) }()
	return <-errs
}

func dialPipe(name string, access uint32) (*os.File, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(namePtr, access, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

// runFrameLoop answers each "give me a frame" request byte from the
// service with a status byte and a length-prefixed payload (see Capture
// on remoteScreenSession for the exact wire format), until the pipe
// closes -- which happens when the remote-control session ends.
func runFrameLoop(pipe *os.File, session Session) error {
	request := make([]byte, 1)
	for {
		if _, err := readFull(pipe, request); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		frame, _, _, captureErr := session.Capture(context.Background())
		if captureErr != nil {
			if err := writeFramed(pipe, 1, []byte(captureErr.Error())); err != nil {
				return err
			}
			continue
		}
		if err := writeFramed(pipe, 0, frame); err != nil {
			return err
		}
	}
}

// runInputLoop applies each mouse/keyboard command the service sends until
// the pipe closes. Malformed messages are skipped rather than treated as
// fatal -- the two sides should never actually disagree on the protocol,
// but losing one stray input event is far less disruptive than tearing
// down the whole remote-control session over it.
func runInputLoop(pipe *os.File, session Session) error {
	header := make([]byte, 5)
	for {
		if _, err := readFull(pipe, header); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		msgType := header[0]
		length := binary.LittleEndian.Uint32(header[1:])
		payload := make([]byte, length)
		if _, err := readFull(pipe, payload); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		applyInput(session, msgType, payload)
	}
}

