//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// applyUpgrade replaces the running agent binary and re-executes it in
// place. Linux allows a running process's backing file to be renamed out
// from under it (the kernel keeps serving the old inode to the already-open
// image), so this needs no service stop/start: syscall.Exec swaps the
// process image while keeping the same PID, which systemd sees as the
// same service instance continuing to run.
func applyUpgrade(data []byte) error {
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}
	// Write the replacement in the same directory as the target so the
	// rename below is same-filesystem (a temp dir on a different mount
	// would make os.Rename fail with "invalid cross-device link").
	staged := currentExe + ".upgrade.tmp"
	if err := os.WriteFile(staged, data, 0700); err != nil {
		return fmt.Errorf("write staged binary: %w", err)
	}
	if err := os.Rename(staged, currentExe); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("replace running binary: %w", err)
	}
	// Only returns on error; on success the process image is replaced and
	// this function never returns.
	return syscall.Exec(currentExe, os.Args, os.Environ()) // #nosec G204 -- re-executing our own just-verified binary
}
