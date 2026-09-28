//go:build windows

package main

import "log"

// ensureRemoteControlDependencies is a no-op on Windows: agent/internal/
// screen's Windows capture/input path uses only GDI and SendInput (direct
// Win32 syscalls, see screen_windows.go), no external tool to install.
func ensureRemoteControlDependencies(*log.Logger) {}
