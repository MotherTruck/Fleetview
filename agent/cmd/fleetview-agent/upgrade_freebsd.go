//go:build freebsd

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// applyUpgrade mirrors upgrade_linux.go exactly: FreeBSD allows the same
// rename-out-from-under-a-running-process trick, and syscall.Exec swaps
// the process image in place while keeping the same PID, which rc.d sees
// as the same service instance continuing to run.
func applyUpgrade(data []byte) error {
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}
	staged := currentExe + ".upgrade.tmp"
	if err := os.WriteFile(staged, data, 0700); err != nil {
		return fmt.Errorf("write staged binary: %w", err)
	}
	if err := os.Rename(staged, currentExe); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("replace running binary: %w", err)
	}
	return syscall.Exec(currentExe, os.Args, os.Environ()) // #nosec G204 -- re-executing our own just-verified binary
}
