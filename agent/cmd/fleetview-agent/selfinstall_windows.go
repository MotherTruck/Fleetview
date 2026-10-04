//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"fleetview-agent/internal/selfinstall"
)

// runSelfInstallIfPersonalized checks whether this running binary is a
// personalized installer (see internal/selfinstall and the server's
// /install/agent-windows-installer.exe route) and, if so, writes its
// embedded server URL + enrollment token to the standard agent config
// (internal/selfinstall.WriteConfig) and installs the service exactly as
// `-service install` does -- so downloading this one file from the
// dashboard and double-clicking it (as administrator) is the entire
// install, no command line needed. Returns handled=true if this
// process's job was to do that, whether it succeeded or not; false for
// an ordinary, unmodified binary (including the plain one published for
// the remote "Upgrade agent" job), which should fall through to normal
// flag/service dispatch untouched.
func runSelfInstallIfPersonalized() (handled bool) {
	selfPath, err := os.Executable()
	if err != nil {
		return false
	}
	payload, ok, err := selfinstall.Detect(selfPath)
	if err != nil || !ok {
		return false
	}

	configPath := defaultConfigPath()
	if writeErr := selfinstall.WriteConfig(configPath, programDataDir(), payload); writeErr != nil {
		showMessage("FleetView Agent", fmt.Sprintf("Could not write configuration: %v", writeErr), true)
		return true
	}
	if installErr := installService(configPath); installErr != nil {
		showMessage("FleetView Agent",
			fmt.Sprintf("Install failed: %v\n\nIf this says to run elevated, right-click this file and choose \"Run as administrator\", then try again.", installErr),
			true)
		return true
	}
	showMessage("FleetView Agent", "FleetView agent installed and enrolling now. You can close this window.", false)
	return true
}

// showMessage gives double-click execution (no console the user is
// already watching, unlike running install-agent.ps1 from a terminal)
// a visible result instead of a window that flashes and closes.
func showMessage(title, text string, isError bool) {
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	textPtr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	boxType := uint32(windows.MB_OK | windows.MB_ICONINFORMATION)
	if isError {
		boxType = windows.MB_OK | windows.MB_ICONERROR
	}
	_, _ = windows.MessageBox(0, textPtr, titlePtr, boxType)
}
