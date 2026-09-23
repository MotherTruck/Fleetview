//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// detachedProcess is windows.DETACHED_PROCESS; not exported as a named
// syscall constant, so it's used by its raw value like other Go code that
// needs to launch a process that survives its parent's exit.
const detachedProcess = 0x00000008

// applyUpgrade stages a downloaded agent binary and hands off to a
// detached helper process to complete the swap: unlike Linux, Windows
// keeps a running executable's backing file locked, so it cannot simply
// be renamed out from under the running service process. The helper is a
// standalone copy of the NEW binary itself, invoked with -finish-upgrade;
// it waits for this service to stop, overwrites the installed binary, and
// restarts the service. This process exits immediately after launching
// the helper — unverified on real Windows hardware, like the rest of this
// project's Windows support.
func applyUpgrade(data []byte) error {
	stagedPath := filepath.Join(os.TempDir(), fmt.Sprintf("fleetview-agent-upgrade-%d.exe", time.Now().UnixNano()))
	if err := os.WriteFile(stagedPath, data, 0700); err != nil {
		return fmt.Errorf("write staged binary: %w", err)
	}
	cmd := exec.Command(stagedPath, "-finish-upgrade", installedExePath()) // #nosec G204 -- launching our own just-verified, just-written binary
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess}
	if err := cmd.Start(); err != nil {
		_ = os.Remove(stagedPath)
		return fmt.Errorf("launch upgrade helper: %w", err)
	}
	os.Exit(0)
	return nil // unreachable
}

// finishUpgrade runs inside the detached helper process spawned by
// applyUpgrade above (the newly downloaded binary, running standalone,
// not yet installed anywhere). It waits for the old service process to
// stop, replaces the installed binary with itself, and restarts the
// service so the new version takes over.
func finishUpgrade(targetPath string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && serviceRunning() {
		time.Sleep(500 * time.Millisecond)
	}
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve helper executable: %w", err)
	}
	data, err := os.ReadFile(selfPath)
	if err != nil {
		return fmt.Errorf("read staged binary: %w", err)
	}
	// A few retries: the old process's file handle on targetPath can take
	// a moment to fully release even after the service reports stopped.
	var writeErr error
	for attempt := 0; attempt < 10; attempt++ {
		if writeErr = os.WriteFile(targetPath, data, 0755); writeErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if writeErr != nil {
		return fmt.Errorf("replace installed binary: %w", writeErr)
	}
	if err := startService(); err != nil {
		return fmt.Errorf("restart service: %w", err)
	}
	_ = os.Remove(selfPath)
	return nil
}

func serviceRunning() bool {
	manager, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return false
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return false
	}
	return status.State != svc.Stopped
}
